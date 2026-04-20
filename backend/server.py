from dotenv import load_dotenv
from pathlib import Path
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import uuid
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict

import bcrypt
import jwt
from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, Query
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr, ConfigDict

from emergentintegrations.payments.stripe.checkout import (
    StripeCheckout,
    CheckoutSessionRequest,
)

from iso8583 import (
    NETWORK_SPECS,
    encode_message,
    decode_message,
    hex_to_base64,
    simulate_response,
    field_catalog,
    RESPONSE_CODES,
)
from samples import SAMPLES
from tcp_transport import send_over_tcp, LENGTH_HEADERS
from session_manager import (
    connect_session,
    disconnect_session,
    get_status as session_status,
    is_connected as session_is_connected,
    send_on_session,
)

# ---------------------------------------------------------------------------
# Config & globals
# ---------------------------------------------------------------------------
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
ACCESS_TTL_MIN = 60 * 24
REFRESH_TTL_DAYS = 7
FREE_LOG_LIMIT = int(os.environ.get("FREE_LOG_LIMIT", "50"))
PRO_PRICE_USD = float(os.environ.get("PRO_PRICE_USD", "29.00"))

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

app = FastAPI(title="ISO-8583 Lab API")
api = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TTL_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TTL_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def set_auth_cookies(response: Response, user_id: str, email: str):
    access = create_access_token(user_id, email)
    refresh = create_refresh_token(user_id)
    response.set_cookie(
        key="access_token", value=access, httponly=True,
        secure=True, samesite="none", max_age=ACCESS_TTL_MIN * 60, path="/",
    )
    response.set_cookie(
        key="refresh_token", value=refresh, httponly=True,
        secure=True, samesite="none", max_age=REFRESH_TTL_DAYS * 86400, path="/",
    )


def clear_auth_cookies(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def enforce_log_quota(user: dict):
    if user.get("plan") == "pro":
        return
    count = await db.transaction_logs.count_documents({"user_id": user["id"]})
    if count >= FREE_LOG_LIMIT:
        raise HTTPException(
            status_code=402,
            detail=f"Free tier limited to {FREE_LOG_LIMIT} transaction logs. Upgrade to Pro for unlimited logs.",
        )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TemplateCreate(BaseModel):
    name: str
    network_id: str
    mti: str
    data_elements: Dict[str, str]
    description: Optional[str] = None


class SendTransactionRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    mti: str
    network_id: str = "visa"
    data_elements: Dict[str, str]
    endpoint_url: Optional[str] = None


class CheckoutRequest(BaseModel):
    origin_url: str


class ConnectionProfileIn(BaseModel):
    name: str
    host: str
    port: int = Field(ge=1, le=65535)
    length_header: str = Field(default="2_byte")
    use_tls: bool = False
    timeout_sec: float = 10.0
    auto_heartbeat: bool = False
    heartbeat_interval_sec: int = 30
    description: Optional[str] = None


class TcpSendRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    connection_id: Optional[str] = None
    # ad-hoc override (take precedence if no connection_id)
    host: Optional[str] = None
    port: Optional[int] = None
    length_header: Optional[str] = None
    use_tls: Optional[bool] = None
    timeout_sec: Optional[float] = None
    mti: str
    network_id: str = "visa"
    data_elements: Dict[str, str]


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@api.post("/auth/register")
async def register(body: RegisterRequest, response: Response):
    email = body.email.lower().strip()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id,
        "email": email,
        "name": body.name or email.split("@")[0],
        "password_hash": hash_password(body.password),
        "role": "user",
        "plan": "free",
        "stripe_customer_id": None,
        "stripe_subscription_id": None,
        "subscription_status": None,
        "created_at": now_iso(),
    }
    await db.users.insert_one(user_doc)
    set_auth_cookies(response, user_id, email)
    user_doc.pop("password_hash", None)
    user_doc.pop("_id", None)
    return user_doc


@api.post("/auth/login")
async def login(body: LoginRequest, request: Request, response: Response):
    email = body.email.lower().strip()
    ip = request.client.host if request.client else "unknown"
    identifier = f"{ip}:{email}"
    attempts = await db.login_attempts.find_one({"identifier": identifier}, {"_id": 0})
    if attempts and attempts.get("count", 0) >= 5:
        last = datetime.fromisoformat(attempts["last_attempt"])
        if datetime.now(timezone.utc) - last < timedelta(minutes=15):
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")

    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user["password_hash"]):
        await db.login_attempts.update_one(
            {"identifier": identifier},
            {"$inc": {"count": 1}, "$set": {"last_attempt": now_iso()}},
            upsert=True,
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    await db.login_attempts.delete_one({"identifier": identifier})
    set_auth_cookies(response, user["id"], email)
    user.pop("password_hash", None)
    user.pop("_id", None)
    return user


@api.post("/auth/logout")
async def logout(response: Response, _user=Depends(get_current_user)):
    clear_auth_cookies(response)
    return {"ok": True}


@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


@api.post("/auth/refresh")
async def refresh(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        set_auth_cookies(response, user["id"], user["email"])
        return {"ok": True}
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


# ---------------------------------------------------------------------------
# Network specs & catalog
# ---------------------------------------------------------------------------
@api.get("/specs")
async def list_specs():
    return [
        {"network_id": s["network_id"], "name": s["name"], "description": s["description"]}
        for s in NETWORK_SPECS.values()
    ]


@api.get("/specs/{network_id}/fields")
async def get_spec_fields(network_id: str):
    if network_id not in NETWORK_SPECS:
        raise HTTPException(status_code=404, detail="Network spec not found")
    return {"network_id": network_id, "fields": field_catalog(network_id)}


@api.get("/response-codes")
async def response_codes():
    return RESPONSE_CODES


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
@api.get("/templates")
async def list_templates(user=Depends(get_current_user)):
    docs = await db.templates.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return docs


@api.post("/templates")
async def create_template(body: TemplateCreate, user=Depends(get_current_user)):
    if user.get("plan") != "pro":
        count = await db.templates.count_documents({"user_id": user["id"]})
        if count >= 10:
            raise HTTPException(
                status_code=402,
                detail="Free tier limited to 10 saved templates. Upgrade to Pro for unlimited templates.",
            )
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "name": body.name,
        "network_id": body.network_id,
        "mti": body.mti,
        "data_elements": body.data_elements,
        "description": body.description or "",
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.templates.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.delete("/templates/{template_id}")
async def delete_template(template_id: str, user=Depends(get_current_user)):
    res = await db.templates.delete_one({"id": template_id, "user_id": user["id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Template not found")
    return {"ok": True}


# ---------------------------------------------------------------------------
# ISO-8583 build / send / simulate
# ---------------------------------------------------------------------------
@api.post("/iso/preview")
async def preview_message(body: SendTransactionRequest, _user=Depends(get_current_user)):
    try:
        raw_hex, meta = encode_message(body.mti, body.data_elements, body.network_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"raw_hex": raw_hex, "raw_base64": hex_to_base64(raw_hex), "parsed": meta}


@api.post("/iso/send")
async def send_transaction(body: SendTransactionRequest, user=Depends(get_current_user)):
    await enforce_log_quota(user)
    try:
        req_hex, req_meta = encode_message(body.mti, body.data_elements, body.network_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    outbound_id = str(uuid.uuid4())
    outbound_log = {
        "id": outbound_id,
        "user_id": user["id"],
        "timestamp": now_iso(),
        "direction": "outbound",
        "network_id": body.network_id,
        "mti": body.mti,
        "raw_hex": req_hex,
        "raw_base64": hex_to_base64(req_hex),
        "parsed": req_meta,
        "status_code": None,
        "related_id": None,
        "endpoint_url": body.endpoint_url or "internal://simulator",
    }

    if body.endpoint_url:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http_client:
                resp = await http_client.post(body.endpoint_url, json={
                    "mti": body.mti,
                    "network_id": body.network_id,
                    "data_elements": body.data_elements,
                    "raw_hex": req_hex,
                })
                ctype = resp.headers.get("content-type", "")
                data = resp.json() if ctype.startswith("application/json") else {"raw": resp.text}
                rc = str(data.get("response_code") or data.get("rc") or ("00" if resp.is_success else "96"))
                resp_hex = str(data.get("raw_hex") or req_hex)
                resp_meta = data
        except Exception as e:
            rc = "96"
            resp_hex = ""
            resp_meta = {"error": str(e)}
    else:
        resp_hex, resp_meta = simulate_response(body.mti, body.data_elements, body.network_id)
        rc = resp_meta.get("response_code", "00")

    inbound_id = str(uuid.uuid4())
    inbound_log = {
        "id": inbound_id,
        "user_id": user["id"],
        "timestamp": now_iso(),
        "direction": "inbound",
        "network_id": body.network_id,
        "mti": resp_meta.get("mti") if isinstance(resp_meta, dict) else body.mti,
        "raw_hex": resp_hex,
        "raw_base64": hex_to_base64(resp_hex) if resp_hex else "",
        "parsed": resp_meta,
        "status_code": rc,
        "related_id": outbound_id,
        "endpoint_url": body.endpoint_url or "internal://simulator",
    }
    outbound_log["related_id"] = inbound_id
    outbound_log["status_code"] = rc

    await db.transaction_logs.insert_many([outbound_log, inbound_log])
    for doc in (outbound_log, inbound_log):
        doc.pop("_id", None)

    return {
        "outbound": outbound_log,
        "inbound": inbound_log,
        "response_code": rc,
        "response_description": RESPONSE_CODES.get(rc, "Unknown"),
    }


@api.post("/iso/simulate")
async def simulate(body: SendTransactionRequest):
    try:
        resp_hex, resp_meta = simulate_response(body.mti, body.data_elements, body.network_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"raw_hex": resp_hex, "parsed": resp_meta, "response_code": resp_meta.get("response_code")}


# ---------------------------------------------------------------------------
# Connection profiles (CBS / switch TCP endpoints)
# ---------------------------------------------------------------------------
@api.get("/connections")
async def list_connections(user=Depends(get_current_user)):
    docs = await db.connection_profiles.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return docs


@api.post("/connections")
async def create_connection(body: ConnectionProfileIn, user=Depends(get_current_user)):
    if body.length_header not in LENGTH_HEADERS:
        raise HTTPException(status_code=400, detail=f"length_header must be one of {LENGTH_HEADERS}")
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "name": body.name,
        "host": body.host.strip(),
        "port": body.port,
        "length_header": body.length_header,
        "use_tls": body.use_tls,
        "timeout_sec": body.timeout_sec,
        "auto_heartbeat": body.auto_heartbeat,
        "heartbeat_interval_sec": body.heartbeat_interval_sec,
        "description": body.description or "",
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.connection_profiles.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.put("/connections/{conn_id}")
async def update_connection(conn_id: str, body: ConnectionProfileIn, user=Depends(get_current_user)):
    if body.length_header not in LENGTH_HEADERS:
        raise HTTPException(status_code=400, detail=f"length_header must be one of {LENGTH_HEADERS}")
    res = await db.connection_profiles.update_one(
        {"id": conn_id, "user_id": user["id"]},
        {"$set": {
            "name": body.name,
            "host": body.host.strip(),
            "port": body.port,
            "length_header": body.length_header,
            "use_tls": body.use_tls,
            "timeout_sec": body.timeout_sec,
            "auto_heartbeat": body.auto_heartbeat,
            "heartbeat_interval_sec": body.heartbeat_interval_sec,
            "description": body.description or "",
            "updated_at": now_iso(),
        }},
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    doc = await db.connection_profiles.find_one({"id": conn_id}, {"_id": 0})
    return doc


@api.delete("/connections/{conn_id}")
async def delete_connection(conn_id: str, user=Depends(get_current_user)):
    # Make sure any live socket for this profile is torn down.
    if session_is_connected(conn_id):
        await disconnect_session(conn_id)
    res = await db.connection_profiles.delete_one({"id": conn_id, "user_id": user["id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    return {"ok": True}


@api.post("/connections/{conn_id}/connect")
async def connect_endpoint(conn_id: str, user=Depends(get_current_user)):
    profile = await db.connection_profiles.find_one({"id": conn_id, "user_id": user["id"]}, {"_id": 0})
    if not profile:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    try:
        sess = await connect_session(profile)
    except (asyncio.TimeoutError, TimeoutError):
        raise HTTPException(status_code=504, detail=f"Timeout contacting {profile['host']}:{profile['port']}")
    except (ConnectionRefusedError, OSError) as e:
        raise HTTPException(status_code=502, detail=f"Connection failed: {e}")
    except Exception as e:
        logger.exception("connect_session failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    return sess.public_status()


@api.post("/connections/{conn_id}/disconnect")
async def disconnect_endpoint(conn_id: str, user=Depends(get_current_user)):
    profile = await db.connection_profiles.find_one({"id": conn_id, "user_id": user["id"]}, {"_id": 0})
    if not profile:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    ok = await disconnect_session(conn_id)
    return {"ok": ok, "state": "idle"}


@api.get("/connections/{conn_id}/status")
async def connection_status(conn_id: str, user=Depends(get_current_user)):
    profile = await db.connection_profiles.find_one({"id": conn_id, "user_id": user["id"]}, {"_id": 0})
    if not profile:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    return await session_status(conn_id)


@api.post("/iso/send-tcp")
async def send_over_tcp_endpoint(body: TcpSendRequest, user=Depends(get_current_user)):
    """Encode an ISO-8583 message and send it over TCP (optionally TLS) to a
    user-configured CBS host. Request & response are both persisted as logs."""
    await enforce_log_quota(user)

    # Resolve connection settings
    host = body.host
    port = body.port
    length_header = body.length_header or "2_byte"
    use_tls = bool(body.use_tls) if body.use_tls is not None else False
    timeout_sec = float(body.timeout_sec) if body.timeout_sec else 10.0
    conn_name = None
    use_persistent = False
    if body.connection_id:
        conn = await db.connection_profiles.find_one(
            {"id": body.connection_id, "user_id": user["id"]}, {"_id": 0}
        )
        if not conn:
            raise HTTPException(status_code=404, detail="Connection profile not found")
        host = conn["host"]
        port = conn["port"]
        length_header = conn["length_header"]
        use_tls = bool(conn.get("use_tls"))
        timeout_sec = float(conn.get("timeout_sec") or 10.0)
        conn_name = conn["name"]
        # Require an active session — don't silently open a one-off socket.
        if not session_is_connected(body.connection_id):
            raise HTTPException(
                status_code=409,
                detail="Connection is not active. Open it from the Connections page before sending.",
            )
        use_persistent = True

    if not host or not port:
        raise HTTPException(status_code=400, detail="host and port are required")
    if length_header not in LENGTH_HEADERS:
        raise HTTPException(status_code=400, detail=f"length_header must be one of {LENGTH_HEADERS}")

    try:
        req_hex, req_meta = encode_message(body.mti, body.data_elements, body.network_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    outbound_id = str(uuid.uuid4())
    endpoint_label = f"tcp{'s' if use_tls else ''}://{host}:{port} [{length_header}]"
    outbound_log = {
        "id": outbound_id,
        "user_id": user["id"],
        "timestamp": now_iso(),
        "direction": "outbound",
        "network_id": body.network_id,
        "mti": body.mti,
        "raw_hex": req_hex,
        "raw_base64": hex_to_base64(req_hex),
        "parsed": req_meta,
        "status_code": None,
        "related_id": None,
        "endpoint_url": endpoint_label,
        "connection_id": body.connection_id,
        "connection_name": conn_name,
    }

    # Fire the socket (persistent session for saved profiles, one-off for ad-hoc)
    try:
        body_bytes = bytes.fromhex(req_hex)
        if use_persistent:
            framed, response_bytes = await send_on_session(body.connection_id, body_bytes)
        else:
            framed, response_bytes = await send_over_tcp(
                host=host,
                port=port,
                body=body_bytes,
                length_header=length_header,
                use_tls=use_tls,
                timeout=timeout_sec,
            )
        resp_hex = response_bytes.hex().upper()
        # Attempt to decode if response looks like ASCII ISO-8583
        try:
            resp_meta = decode_message(resp_hex, body.network_id)
            rc = "??"
            for fobj in resp_meta.get("fields", []):
                if fobj["field"] == 39:
                    rc = str(fobj["value"]).strip() or "??"
                    break
            resp_meta["response_code"] = rc
            resp_meta["response_code_description"] = RESPONSE_CODES.get(rc, "Unknown")
        except Exception as dec_err:
            resp_meta = {"error": f"decode failed: {dec_err}", "raw_ascii": response_bytes.decode("latin-1", errors="replace")}
            rc = "??"
        tcp_error = None
    except (asyncio.TimeoutError, TimeoutError) as e:
        resp_hex = ""
        resp_meta = {"error": f"timeout after {timeout_sec}s contacting {host}:{port}"}
        rc = "91"  # Issuer unavailable — closest standard code for timeout
        tcp_error = str(e) or "timeout"
    except (ConnectionRefusedError, OSError) as e:
        resp_hex = ""
        resp_meta = {"error": f"connection failed: {e}"}
        rc = "96"  # System malfunction
        tcp_error = str(e)
    except Exception as e:
        logger.exception("TCP send failed: %s", e)
        resp_hex = ""
        resp_meta = {"error": str(e)}
        rc = "96"
        tcp_error = str(e)

    inbound_id = str(uuid.uuid4())
    inbound_log = {
        "id": inbound_id,
        "user_id": user["id"],
        "timestamp": now_iso(),
        "direction": "inbound",
        "network_id": body.network_id,
        "mti": resp_meta.get("mti") if isinstance(resp_meta, dict) else body.mti,
        "raw_hex": resp_hex,
        "raw_base64": hex_to_base64(resp_hex) if resp_hex else "",
        "parsed": resp_meta,
        "status_code": rc,
        "related_id": outbound_id,
        "endpoint_url": endpoint_label,
        "connection_id": body.connection_id,
        "connection_name": conn_name,
        "error": tcp_error,
    }
    outbound_log["related_id"] = inbound_id
    outbound_log["status_code"] = rc

    await db.transaction_logs.insert_many([outbound_log, inbound_log])
    for doc in (outbound_log, inbound_log):
        doc.pop("_id", None)

    return {
        "outbound": outbound_log,
        "inbound": inbound_log,
        "response_code": rc,
        "response_description": RESPONSE_CODES.get(rc, "Unknown"),
        "error": tcp_error,
    }


# ---------------------------------------------------------------------------
# Sample template library (read-only)
# ---------------------------------------------------------------------------
@api.get("/samples")
async def list_samples():
    return SAMPLES


@api.post("/samples/{sample_id}/clone")
async def clone_sample(sample_id: str, user=Depends(get_current_user)):
    sample = next((s for s in SAMPLES if s["id"] == sample_id), None)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    if user.get("plan") != "pro":
        count = await db.templates.count_documents({"user_id": user["id"]})
        if count >= 10:
            raise HTTPException(
                status_code=402,
                detail="Free tier limited to 10 saved templates. Upgrade to Pro.",
            )
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "name": sample["name"],
        "network_id": sample["network_id"],
        "mti": sample["mti"],
        "data_elements": dict(sample["data_elements"]),
        "description": sample.get("description", ""),
        "cloned_from": sample["id"],
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.templates.insert_one(doc)
    doc.pop("_id", None)
    return doc



# ---------------------------------------------------------------------------
# Transaction logs
# ---------------------------------------------------------------------------
@api.get("/logs")
async def list_logs(
    user=Depends(get_current_user),
    q: Optional[str] = None,
    direction: Optional[str] = None,
    status: Optional[str] = None,
    network: Optional[str] = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
):
    filt: Dict = {"user_id": user["id"]}
    if direction in ("inbound", "outbound"):
        filt["direction"] = direction
    if status:
        filt["status_code"] = status
    if network:
        filt["network_id"] = network
    if q:
        filt["$or"] = [
            {"mti": {"$regex": q, "$options": "i"}},
            {"raw_hex": {"$regex": q, "$options": "i"}},
            {"status_code": {"$regex": q, "$options": "i"}},
        ]
    cursor = db.transaction_logs.find(filt, {"_id": 0}).sort("timestamp", -1).skip(offset).limit(limit)
    items = await cursor.to_list(limit)
    total = await db.transaction_logs.count_documents(filt)
    return {"items": items, "total": total}


@api.get("/logs/{log_id}")
async def get_log(log_id: str, user=Depends(get_current_user)):
    doc = await db.transaction_logs.find_one({"id": log_id, "user_id": user["id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Log not found")
    return doc


# ---------------------------------------------------------------------------
# Dashboard stats
# ---------------------------------------------------------------------------
@api.get("/stats")
async def stats(user=Depends(get_current_user)):
    base = {"user_id": user["id"]}
    total = await db.transaction_logs.count_documents(base)
    outbound = await db.transaction_logs.count_documents({**base, "direction": "outbound"})
    inbound = await db.transaction_logs.count_documents({**base, "direction": "inbound"})
    success = await db.transaction_logs.count_documents({**base, "direction": "inbound", "status_code": "00"})
    failed = await db.transaction_logs.count_documents({
        **base, "direction": "inbound",
        "status_code": {"$nin": ["00", None]},
    })

    since = datetime.now(timezone.utc) - timedelta(days=7)
    by_day: Dict[str, Dict[str, int]] = {}
    outbound_recent = await db.transaction_logs.find(
        {**base, "direction": "outbound", "timestamp": {"$gte": since.isoformat()}},
        {"_id": 0, "timestamp": 1},
    ).to_list(5000)
    for r in outbound_recent:
        day = (r.get("timestamp") or "")[:10]
        if not day:
            continue
        entry = by_day.setdefault(day, {"total": 0, "success": 0, "failed": 0})
        entry["total"] += 1
    inbound_recent = await db.transaction_logs.find(
        {**base, "direction": "inbound", "timestamp": {"$gte": since.isoformat()}},
        {"_id": 0, "timestamp": 1, "status_code": 1},
    ).to_list(5000)
    for r in inbound_recent:
        day = (r.get("timestamp") or "")[:10]
        if not day:
            continue
        entry = by_day.setdefault(day, {"total": 0, "success": 0, "failed": 0})
        if r.get("status_code") == "00":
            entry["success"] += 1
        else:
            entry["failed"] += 1

    volume = [{"date": d, **v} for d, v in sorted(by_day.items())]

    latest = await db.transaction_logs.find(base, {"_id": 0}).sort("timestamp", -1).limit(8).to_list(8)

    pipeline = [
        {"$match": {**base, "direction": "inbound"}},
        {"$group": {"_id": "$status_code", "count": {"$sum": 1}}},
    ]
    rc_breakdown_raw = await db.transaction_logs.aggregate(pipeline).to_list(50)
    rc_breakdown = [
        {"code": r["_id"] or "??", "description": RESPONSE_CODES.get(r["_id"] or "", "Unknown"), "count": r["count"]}
        for r in rc_breakdown_raw
    ]

    limit = None if user.get("plan") == "pro" else FREE_LOG_LIMIT
    return {
        "total": total,
        "outbound": outbound,
        "inbound": inbound,
        "success": success,
        "failed": failed,
        "success_rate": round((success / max(inbound, 1)) * 100, 2),
        "volume_by_day": volume,
        "recent": latest,
        "response_code_breakdown": rc_breakdown,
        "plan": user.get("plan", "free"),
        "log_limit": limit,
        "log_limit_used": total,
    }


# ---------------------------------------------------------------------------
# Stripe billing
# ---------------------------------------------------------------------------
PACKAGES = {"pro_monthly": {"amount": PRO_PRICE_USD, "currency": "usd"}}


@api.post("/billing/checkout")
async def billing_checkout(body: CheckoutRequest, request: Request, user=Depends(get_current_user)):
    amount = PACKAGES["pro_monthly"]["amount"]
    currency = PACKAGES["pro_monthly"]["currency"]

    host_url = str(request.base_url).rstrip("/")
    webhook_url = f"{host_url}/api/webhook/stripe"
    api_key = os.environ["STRIPE_API_KEY"]

    stripe = StripeCheckout(api_key=api_key, webhook_url=webhook_url)
    origin = body.origin_url.rstrip("/")
    success_url = f"{origin}/billing/return?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{origin}/app/pricing"

    req = CheckoutSessionRequest(
        amount=amount,
        currency=currency,
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={
            "user_id": user["id"],
            "email": user["email"],
            "package": "pro_monthly",
        },
    )
    session = await stripe.create_checkout_session(req)

    await db.payment_transactions.insert_one({
        "id": str(uuid.uuid4()),
        "session_id": session.session_id,
        "user_id": user["id"],
        "email": user["email"],
        "amount": amount,
        "currency": currency,
        "metadata": {"package": "pro_monthly"},
        "payment_status": "initiated",
        "status": "pending",
        "created_at": now_iso(),
        "updated_at": now_iso(),
    })
    return {"url": session.url, "session_id": session.session_id}


@api.get("/billing/status/{session_id}")
async def billing_status(session_id: str, request: Request, user=Depends(get_current_user)):
    existing = await db.payment_transactions.find_one(
        {"session_id": session_id, "user_id": user["id"]}, {"_id": 0}
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Session not found")

    host_url = str(request.base_url).rstrip("/")
    webhook_url = f"{host_url}/api/webhook/stripe"
    stripe = StripeCheckout(api_key=os.environ["STRIPE_API_KEY"], webhook_url=webhook_url)

    try:
        status = await stripe.get_checkout_status(session_id)
    except Exception as e:
        logger.warning("Stripe status fetch failed (test mode?): %s", e)
        # Graceful fallback: return pending so the poller keeps retrying / webhook catches up.
        return {
            "payment_status": existing.get("payment_status") or "pending",
            "status": existing.get("status") or "open",
            "amount_total": int(existing.get("amount", 0) * 100),
            "currency": existing.get("currency", "usd"),
            "note": "Live status temporarily unavailable; showing cached state.",
        }

    await db.payment_transactions.update_one(
        {"session_id": session_id},
        {"$set": {
            "payment_status": status.payment_status,
            "status": status.status,
            "updated_at": now_iso(),
        }},
    )

    if status.payment_status == "paid" and existing.get("payment_status") != "paid":
        await db.users.update_one(
            {"id": user["id"]},
            {"$set": {
                "plan": "pro",
                "subscription_status": "active",
                "upgraded_at": now_iso(),
            }},
        )

    return {
        "payment_status": status.payment_status,
        "status": status.status,
        "amount_total": status.amount_total,
        "currency": status.currency,
    }


@api.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    body = await request.body()
    sig = request.headers.get("Stripe-Signature", "")
    host_url = str(request.base_url).rstrip("/")
    webhook_url = f"{host_url}/api/webhook/stripe"
    stripe = StripeCheckout(api_key=os.environ["STRIPE_API_KEY"], webhook_url=webhook_url)
    try:
        evt = await stripe.handle_webhook(body, sig)
    except Exception as e:
        logger.exception("Webhook failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e))

    if evt.session_id:
        await db.payment_transactions.update_one(
            {"session_id": evt.session_id},
            {"$set": {"payment_status": evt.payment_status, "updated_at": now_iso()}},
        )
        if evt.payment_status == "paid":
            user_id = (evt.metadata or {}).get("user_id")
            if user_id:
                await db.users.update_one(
                    {"id": user_id},
                    {"$set": {"plan": "pro", "subscription_status": "active", "upgraded_at": now_iso()}},
                )
    return {"received": True}


# ---------------------------------------------------------------------------
# Startup / seed
# ---------------------------------------------------------------------------
async def seed_admin():
    email = os.environ.get("ADMIN_EMAIL", "admin@iso8583.dev")
    password = os.environ.get("ADMIN_PASSWORD", "admin12345")
    existing = await db.users.find_one({"email": email})
    if not existing:
        await db.users.insert_one({
            "id": str(uuid.uuid4()),
            "email": email,
            "name": "Admin",
            "password_hash": hash_password(password),
            "role": "admin",
            "plan": "pro",
            "subscription_status": "active",
            "stripe_customer_id": None,
            "stripe_subscription_id": None,
            "created_at": now_iso(),
        })
        logger.info("Seeded admin user: %s", email)
    elif not verify_password(password, existing["password_hash"]):
        await db.users.update_one({"email": email}, {"$set": {"password_hash": hash_password(password)}})


async def seed_specs():
    for spec in NETWORK_SPECS.values():
        await db.message_specs.update_one(
            {"network_id": spec["network_id"]},
            {"$set": {
                "network_id": spec["network_id"],
                "name": spec["name"],
                "description": spec["description"],
                "fields_count": len(spec["fields"]),
            }},
            upsert=True,
        )


@app.on_event("startup")
async def on_startup():
    await db.users.create_index("email", unique=True)
    await db.transaction_logs.create_index([("user_id", 1), ("timestamp", -1)])
    await db.templates.create_index([("user_id", 1), ("created_at", -1)])
    await db.payment_transactions.create_index("session_id", unique=True)
    await db.connection_profiles.create_index([("user_id", 1), ("created_at", -1)])
    await db.login_attempts.create_index("identifier")
    await seed_admin()
    await seed_specs()


@app.on_event("shutdown")
async def shutdown():
    client.close()


@api.get("/")
async def root():
    return {"message": "ISO-8583 Lab API", "status": "ok"}


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[os.environ.get("FRONTEND_URL", "http://localhost:3000"), "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)
