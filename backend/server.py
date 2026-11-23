from dotenv import load_dotenv
from pathlib import Path
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import uuid
import asyncio
import hmac
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Tuple

import bcrypt
import jwt
from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, Query
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr, ConfigDict

try:  # Emergent-hosted only; billing is disabled where this package is unavailable.
    from emergentintegrations.payments.stripe.checkout import (
        StripeCheckout as _StripeCheckout,
        CheckoutSessionRequest,
    )
except ImportError:  # pragma: no cover - depends on the hosting platform
    _StripeCheckout = None
    CheckoutSessionRequest = None


def StripeCheckout(*, api_key: Optional[str] = None, webhook_url: str):
    """Stripe client, or 503 when billing isn't available on this deployment."""
    key = api_key or os.environ.get("STRIPE_API_KEY")
    if _StripeCheckout is None or not key:
        raise HTTPException(status_code=503, detail="Billing is not configured on this deployment.")
    return _StripeCheckout(api_key=key, webhook_url=webhook_url)

from iso8583 import (
    NETWORK_SPECS,
    encode_message,
    decode_message,
    hex_to_base64,
    simulate_response,
    field_catalog,
    mandatory_catalog,
    validate_message,
    register_runtime_spec,
    build_user_spec,
    parse_spec_csv,
    RESPONSE_CODES,
)
from samples import SAMPLES
from tcp_transport import send_over_tcp, LENGTH_HEADERS
from net_probe import probe_tcp, normalise_host, host_port_from_ws_url
from pin_crypto import encrypt_pin_block, decrypt_pin_block, PIN_FORMATS, PIN_ALGORITHMS
from key_management import (
    compute_kcv, compute_cvv, compute_pvv,
    derive_icc_mk, compute_arqc,
    derive_session_key_cvn18, derive_icc_mk_aes, derive_session_key_aes, compute_arqc_aes,
    compute_arpc, compute_arpc_method2,
    derive_ac_keys, compute_ibm3624_offset, compute_ibm3624_pin, DEFAULT_DECIMALIZATION_TABLE,
)
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
    keyset_id: Optional[str] = None   # simulator only: verify cryptograms with this key set


class CheckoutRequest(BaseModel):
    origin_url: str


class ConnectionProfileIn(BaseModel):
    name: str
    transport: str = "tcp"            # "tcp" | "websocket"
    # TCP fields
    host: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    # WebSocket fields
    ws_url: Optional[str] = None
    auth_login_url: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_token: Optional[str] = None   # paste a pre-issued JWT directly (preferred)
    ws_text_mode: bool = False         # send hex text frames instead of binary
    # shared
    length_header: str = Field(default="2_byte")
    use_tls: bool = False
    timeout_sec: float = 10.0
    auto_heartbeat: bool = False
    heartbeat_interval_sec: int = 30
    wire_format: str = "native"        # "native" | "ascii"
    description: Optional[str] = None


class ProbeRequest(BaseModel):
    """Ad-hoc telnet-style test. `host` may include the port ("10.0.0.5:8583")."""
    host: str
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    use_tls: bool = False
    timeout_sec: float = Field(default=5.0, gt=0, le=30)


def _validated_tcp_target(body: "ConnectionProfileIn") -> Tuple[str, int]:
    """Normalise host/IP for a TCP profile; a port pasted into the host field fills an empty port."""
    try:
        host, pasted = normalise_host(body.host or "")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    port = body.port or pasted
    if not port:
        raise HTTPException(status_code=400, detail="TCP profiles require host and port")
    if pasted and body.port and pasted != body.port:
        raise HTTPException(status_code=400, detail=f"Host says port {pasted} but the port field says {body.port}.")
    return host, port


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


class PinEncryptRequest(BaseModel):
    pin: str
    pan: Optional[str] = None
    key_hex: str
    format: str = "ISO-0"
    algorithm: str = "3DES"


class KcvRequest(BaseModel):
    key_hex: str
    algorithm: str = "3DES"


class CvvRequest(BaseModel):
    pan: str
    expiry: str  # YYMM
    service_code: str  # 3 digits
    cvk_a_hex: str
    cvk_b_hex: str


class PvvRequest(BaseModel):
    pan: str
    pin: str
    pvki: str = "1"
    pvk_a_hex: str
    pvk_b_hex: str


class ArqcRequest(BaseModel):
    mdk_hex: str
    pan: str
    psn: str = "00"
    cdol_hex: str
    cvn: str = "CVN10"            # CVN10 | CVN18 | MC_CVN16 | MC_CVN17 | MC_CVN20 | MC_CVN21 | AES
    atc_hex: Optional[str] = None  # 9F36; required for every CVN except CVN10
    un_hex: Optional[str] = None   # 9F37; required for MC_CVN16 / MC_CVN17


class CvvVerifyRequest(CvvRequest):
    cvv: str


class PvvVerifyRequest(BaseModel):
    """Verify a PIN against a PVV. Give either the clear `pin`, or an encrypted
    `pin_block_hex` with the PEK that protects it (as received in F52)."""
    pan: str
    pvv: str
    pvki: str = "1"
    pvk_a_hex: str
    pvk_b_hex: str
    pin: Optional[str] = None
    pin_block_hex: Optional[str] = None
    pek_hex: Optional[str] = None
    pin_format: str = "ISO-0"
    pin_algorithm: str = "3DES"


class Ibm3624Request(BaseModel):
    """IBM 3624 PIN offset. Validation data = PAN[verify_offset : verify_offset + verify_length],
    right-padded to 16 hex digits with `pad`."""
    pan: str
    pin: str
    pvk_hex: str                                   # 8, 16 or 24 bytes
    decimalization_table: str = DEFAULT_DECIMALIZATION_TABLE
    verify_offset: int = 0
    verify_length: Optional[int] = None            # default: rest of the PAN, max 16
    pad: str = "F"


class Ibm3624VerifyRequest(BaseModel):
    """Verify a PIN against an IBM 3624 offset; PIN given clear or as an encrypted PIN block."""
    pan: str
    offset: str
    pvk_hex: str
    decimalization_table: str = DEFAULT_DECIMALIZATION_TABLE
    verify_offset: int = 0
    verify_length: Optional[int] = None
    pad: str = "F"
    pin: Optional[str] = None
    pin_block_hex: Optional[str] = None
    pek_hex: Optional[str] = None
    pin_format: str = "ISO-0"
    pin_algorithm: str = "3DES"


class ArqcVerifyRequest(ArqcRequest):
    arqc_hex: str


class ArpcRequest(BaseModel):
    sk_hex: str
    arqc_hex: str
    arc_hex: str = "3030"     # ASCII "00" by default = approved (Method 1)
    algorithm: str = "3DES"
    method: int = 1           # 1 = ARQC XOR ARC (CVN10, M/Chip); 2 = MAC over ARQC||CSU||PAD (CVN18)
    csu_hex: Optional[str] = None   # Method 2: 4-byte Card Status Update
    pad_hex: Optional[str] = None   # Method 2: 0-8 byte Proprietary Authentication Data


class BucketCreate(BaseModel):
    name: str
    description: Optional[str] = None
    template_ids: List[str]


class BucketRunRequest(BaseModel):
    """Run a saved bucket OR an ad-hoc list of templates against a target."""
    template_ids: Optional[List[str]] = None  # only used by /buckets/run-once
    target: str = "simulator"                 # "simulator" | <connection_profile_id>
    delay_ms: int = Field(default=0, ge=0, le=10_000)
    keyset_id: Optional[str] = None           # simulator only: verify cryptograms with this key set


class UserSpecCreate(BaseModel):
    """Lightweight payload — same shape `build_user_spec` accepts."""
    model_config = ConfigDict(extra="ignore")
    network_id: str
    name: str
    description: Optional[str] = None
    mti_encoding: Optional[str] = "ascii"
    bitmap_encoding: Optional[str] = "ascii_hex"
    default_an_charset: Optional[str] = "ascii"
    length_prefix_encoding: Optional[str] = "ascii"
    fields: Dict[str, Dict] = Field(default_factory=dict)
    mandatory_per_mti: Dict[str, List[int]] = Field(default_factory=dict)


class UserSpecImport(BaseModel):
    """Either a JSON spec or a CSV body (only one of `payload`/`csv_text`)."""
    network_id: str
    name: str
    description: Optional[str] = None
    mti_encoding: Optional[str] = "ascii"
    bitmap_encoding: Optional[str] = "ascii_hex"
    default_an_charset: Optional[str] = "ascii"
    length_prefix_encoding: Optional[str] = "ascii"
    csv_text: Optional[str] = None
    payload: Optional[Dict] = None  # alternative to csv_text — full spec object
    mandatory_per_mti: Dict[str, List[int]] = Field(default_factory=dict)


class KeySetIn(BaseModel):
    """A named key set saved per user (e.g. 'VISA Production', 'MC Test').

    Stores well-known EMV / VISA keys (MDK / CVK_A / CVK_B / PVK_A / PVK_B / PVKI),
    plus an open-ended `extras` dict for additional keys (ZPK, TMK, ZMK, etc).
    KCVs are recomputed on save and stored alongside each key for the UI.
    """
    name: str
    description: Optional[str] = None
    mdk_hex: Optional[str] = None
    cvk_a_hex: Optional[str] = None
    cvk_b_hex: Optional[str] = None
    pvk_a_hex: Optional[str] = None
    pvk_b_hex: Optional[str] = None
    pvki: Optional[str] = None        # 1-digit PVV Key Indicator
    extras: Dict[str, str] = Field(default_factory=dict)  # {alias_upper: hex}


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
async def list_specs(user=Depends(get_current_user)):
    builtin = [
        {"network_id": s["network_id"], "name": s["name"], "description": s.get("description", ""), "builtin": True}
        for s in NETWORK_SPECS.values() if s.get("builtin")
    ]
    custom_docs = await db.user_specs.find(
        {"user_id": user["id"]}, {"_id": 0, "network_id": 1, "name": 1, "description": 1}
    ).sort("name", 1).to_list(100)
    custom = [{**d, "builtin": False} for d in custom_docs]
    return builtin + custom


@api.get("/specs/{network_id}/fields")
async def get_spec_fields(network_id: str, user=Depends(get_current_user)):
    await _ensure_user_spec_loaded(network_id, user)
    if network_id not in NETWORK_SPECS:
        raise HTTPException(status_code=404, detail="Network spec not found")
    return {"network_id": network_id, "fields": field_catalog(network_id)}


@api.get("/specs/{network_id}/mandatory")
async def get_spec_mandatory(network_id: str, user=Depends(get_current_user)):
    """Return `{<mti>: [field, …]}` for the Builder spec-hint UI."""
    await _ensure_user_spec_loaded(network_id, user)
    if network_id not in NETWORK_SPECS:
        raise HTTPException(status_code=404, detail="Network spec not found")
    return {"network_id": network_id, "mandatory_per_mti": mandatory_catalog(network_id)}


async def _ensure_user_spec_loaded(network_id: str, user: dict) -> None:
    """If `network_id` is a custom spec id, hydrate it into the runtime registry."""
    if not network_id or network_id in NETWORK_SPECS or not network_id.startswith("user:"):
        return
    doc = await db.user_specs.find_one(
        {"network_id": network_id, "user_id": user["id"]}, {"_id": 0}
    )
    if not doc:
        return
    try:
        register_runtime_spec(build_user_spec(doc))
    except ValueError:
        # Corrupt spec — leave registry untouched; downstream will 404.
        return


@api.get("/response-codes")
async def response_codes():
    return RESPONSE_CODES


# ---------------------------------------------------------------------------
# User-defined specs (custom networks)
# ---------------------------------------------------------------------------
def _public_user_spec(doc: dict) -> dict:
    """Strip private fields and the resolved `fields` dict (frontend reads
    via `/specs/{nid}/fields` to get the catalog format)."""
    return {
        "id": doc.get("id"),
        "network_id": doc.get("network_id"),
        "name": doc.get("name"),
        "description": doc.get("description") or "",
        "mti_encoding": doc.get("mti_encoding"),
        "bitmap_encoding": doc.get("bitmap_encoding"),
        "default_an_charset": doc.get("default_an_charset"),
        "length_prefix_encoding": doc.get("length_prefix_encoding"),
        "fields": doc.get("fields") or {},
        "mandatory_per_mti": doc.get("mandatory_per_mti") or {},
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
    }


@api.get("/user-specs")
async def list_user_specs(user=Depends(get_current_user)):
    docs = await db.user_specs.find(
        {"user_id": user["id"]}, {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    return [_public_user_spec(d) for d in docs]


@api.get("/user-specs/template")
async def user_spec_template_csv():
    """Sample CSV the user can download, edit, and re-upload."""
    sample = (
        "field,name,format,length_type,max_length,encoding,length_encoding\n"
        "2,Primary Account Number,n,LLVAR,19,ascii,ascii\n"
        "3,Processing Code,n,fixed,6,ascii,ascii\n"
        "4,Amount Transaction,n,fixed,12,ascii,ascii\n"
        "7,Transmission Date Time,n,fixed,10,ascii,ascii\n"
        "11,System Trace Audit Number,n,fixed,6,ascii,ascii\n"
        "39,Response Code,an,fixed,2,ascii,ascii\n"
        "41,Card Acceptor Terminal ID,ans,fixed,8,ascii,ascii\n"
        "49,Currency Code,n,fixed,3,ascii,ascii\n"
    )
    return Response(
        content=sample,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="iso8583-spec-template.csv"'},
    )


@api.post("/user-specs")
async def create_user_spec(body: UserSpecCreate, user=Depends(get_current_user)):
    try:
        spec = build_user_spec(body.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    existing = await db.user_specs.find_one(
        {"user_id": user["id"], "network_id": spec["network_id"]}, {"_id": 1}
    )
    if existing:
        raise HTTPException(status_code=409, detail=f"Spec '{spec['network_id']}' already exists")
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "network_id": spec["network_id"],
        "name": spec["name"],
        "description": spec["description"],
        "mti_encoding": spec["mti_encoding"],
        "bitmap_encoding": spec["bitmap_encoding"],
        "default_an_charset": spec["default_an_charset"],
        "length_prefix_encoding": spec["length_prefix_encoding"],
        # store overrides only — the resolved fields are rebuilt on hydrate.
        "fields": body.fields or {},
        "mandatory_per_mti": spec["mandatory_per_mti"],
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.user_specs.insert_one(doc)
    register_runtime_spec(spec)
    return _public_user_spec(doc)


@api.post("/user-specs/import")
async def import_user_spec(body: UserSpecImport, user=Depends(get_current_user)):
    """Build a spec from either a JSON `payload` or a `csv_text` body."""
    if body.csv_text and body.payload:
        raise HTTPException(status_code=400, detail="Provide either csv_text OR payload, not both")
    if body.csv_text:
        try:
            fields = parse_spec_csv(body.csv_text)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"CSV parse error: {e}")
        merge = {
            "network_id": body.network_id,
            "name": body.name,
            "description": body.description,
            "mti_encoding": body.mti_encoding,
            "bitmap_encoding": body.bitmap_encoding,
            "default_an_charset": body.default_an_charset,
            "length_prefix_encoding": body.length_prefix_encoding,
            "fields": fields,
            "mandatory_per_mti": body.mandatory_per_mti,
        }
    elif body.payload:
        # `payload` carries encodings + fields + mandatory; explicit network_id/name win.
        merge = {
            **body.payload,
            "network_id": body.network_id,
            "name": body.name,
        }
        if body.description is not None:
            merge["description"] = body.description
    else:
        raise HTTPException(status_code=400, detail="Provide csv_text or payload")
    create_body = UserSpecCreate(**merge)
    return await create_user_spec(create_body, user)


@api.put("/user-specs/{spec_id}")
async def update_user_spec(spec_id: str, body: UserSpecCreate, user=Depends(get_current_user)):
    existing = await db.user_specs.find_one({"id": spec_id, "user_id": user["id"]}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Spec not found")
    # disallow renaming the network_id under the user (would invalidate templates)
    submitted_nid = (body.network_id or "").strip().lower()
    if submitted_nid and not submitted_nid.startswith("user:"):
        submitted_nid = f"user:{submitted_nid}"
    if submitted_nid and submitted_nid != existing["network_id"]:
        raise HTTPException(status_code=400, detail="network_id cannot change after create")
    try:
        spec = build_user_spec(body.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    update = {
        "name": spec["name"],
        "description": spec["description"],
        "mti_encoding": spec["mti_encoding"],
        "bitmap_encoding": spec["bitmap_encoding"],
        "default_an_charset": spec["default_an_charset"],
        "length_prefix_encoding": spec["length_prefix_encoding"],
        "fields": body.fields or {},
        "mandatory_per_mti": spec["mandatory_per_mti"],
        "updated_at": now_iso(),
    }
    await db.user_specs.update_one({"id": spec_id, "user_id": user["id"]}, {"$set": update})
    register_runtime_spec(spec)
    doc = await db.user_specs.find_one({"id": spec_id}, {"_id": 0})
    return _public_user_spec(doc)


@api.delete("/user-specs/{spec_id}")
async def delete_user_spec(spec_id: str, user=Depends(get_current_user)):
    doc = await db.user_specs.find_one({"id": spec_id, "user_id": user["id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Spec not found")
    await db.user_specs.delete_one({"id": spec_id, "user_id": user["id"]})
    NETWORK_SPECS.pop(doc["network_id"], None)
    return {"ok": True}


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


async def _load_keyset(user: dict, keyset_id: Optional[str], target: Optional[str] = None) -> Optional[dict]:
    """Fetch one of the caller's own key sets for simulator verification."""
    if not keyset_id:
        return None
    if target not in (None, "", "simulator"):
        raise HTTPException(status_code=400, detail="keyset_id is only used with the simulator.")
    doc = await db.user_keys.find_one({"id": keyset_id, "user_id": user["id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Key set not found")
    return doc


# ---------------------------------------------------------------------------
# Internal: execute a single template against a target (simulator or connection)
# ---------------------------------------------------------------------------
async def _execute_message(
    *,
    user: dict,
    mti: str,
    network_id: str,
    data_elements: Dict[str, str],
    target: str = "simulator",          # "simulator" | <connection_profile_id>
    bucket_run_id: Optional[str] = None,
    template_id: Optional[str] = None,
    template_name: Optional[str] = None,
    keyset: Optional[dict] = None,       # simulator only
) -> Dict:
    """Encode + send + persist outbound/inbound logs.

    Re-uses the same code paths as `/api/iso/send` (simulator) and
    `/api/iso/send-tcp` (TCP/WebSocket through a saved connection profile).
    Returns ``{outbound, inbound, response_code, error}``.
    """
    await enforce_log_quota(user)
    await _ensure_user_spec_loaded(network_id, user)

    # ---- Simulator branch -------------------------------------------------
    if not target or target == "simulator":
        try:
            req_hex, req_meta = encode_message(mti, data_elements, network_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        outbound_id = str(uuid.uuid4())
        outbound_log = {
            "id": outbound_id, "user_id": user["id"], "timestamp": now_iso(),
            "direction": "outbound", "network_id": network_id, "mti": mti,
            "raw_hex": req_hex, "raw_base64": hex_to_base64(req_hex),
            "parsed": req_meta, "status_code": None, "related_id": None,
            "endpoint_url": "internal://simulator",
            "bucket_run_id": bucket_run_id, "template_id": template_id, "template_name": template_name,
        }
        resp_hex, resp_meta = simulate_response(mti, data_elements, network_id, keyset)
        rc = resp_meta.get("response_code", "00")
        inbound_id = str(uuid.uuid4())
        inbound_log = {
            "id": inbound_id, "user_id": user["id"], "timestamp": now_iso(),
            "direction": "inbound", "network_id": network_id,
            "mti": resp_meta.get("mti") if isinstance(resp_meta, dict) else mti,
            "raw_hex": resp_hex, "raw_base64": hex_to_base64(resp_hex) if resp_hex else "",
            "parsed": resp_meta, "status_code": rc, "related_id": outbound_id,
            "endpoint_url": "internal://simulator",
            "bucket_run_id": bucket_run_id, "template_id": template_id, "template_name": template_name,
        }
        outbound_log["related_id"] = inbound_id
        outbound_log["status_code"] = rc
        await db.transaction_logs.insert_many([outbound_log, inbound_log])
        for d in (outbound_log, inbound_log): d.pop("_id", None)
        return {"outbound": outbound_log, "inbound": inbound_log, "response_code": rc, "error": None}

    # ---- Saved connection profile branch ---------------------------------
    conn = await db.connection_profiles.find_one({"id": target, "user_id": user["id"]}, {"_id": 0})
    if not conn:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    if not session_is_connected(target):
        raise HTTPException(
            status_code=409,
            detail=f"Connection '{conn['name']}' is not active. Open it from the Connections page.",
        )
    transport = conn.get("transport", "tcp")
    length_header = conn["length_header"]
    wire_format = conn.get("wire_format", "native")
    if transport == "tcp":
        endpoint_label = f"tcp{'s' if conn.get('use_tls') else ''}://{conn.get('host')}:{conn.get('port')} [{length_header}]"
    else:
        endpoint_label = f"{conn['ws_url']} [ws · {length_header} · {wire_format}]"

    try:
        req_hex, req_meta = encode_message(mti, data_elements, network_id, wire_format=wire_format)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    outbound_id = str(uuid.uuid4())
    outbound_log = {
        "id": outbound_id, "user_id": user["id"], "timestamp": now_iso(),
        "direction": "outbound", "network_id": network_id, "mti": mti,
        "raw_hex": req_hex, "raw_base64": hex_to_base64(req_hex),
        "parsed": req_meta, "status_code": None, "related_id": None,
        "endpoint_url": endpoint_label,
        "connection_id": target, "connection_name": conn["name"],
        "transport": transport, "wire_format": wire_format,
        "bucket_run_id": bucket_run_id, "template_id": template_id, "template_name": template_name,
    }

    tcp_error: Optional[str] = None
    try:
        body_bytes = bytes.fromhex(req_hex)
        framed, response_bytes = await send_on_session(target, body_bytes)
        resp_hex = response_bytes.hex().upper()
        try:
            resp_meta = decode_message(resp_hex, network_id, wire_format=wire_format)
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
    except (asyncio.TimeoutError, TimeoutError) as e:
        resp_hex = ""; resp_meta = {"error": "timeout"}; rc = "91"; tcp_error = str(e) or "timeout"
    except (ConnectionRefusedError, OSError) as e:
        resp_hex = ""; resp_meta = {"error": f"connection failed: {e}"}; rc = "96"; tcp_error = str(e)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("bucket send failed: %s", e)
        resp_hex = ""; resp_meta = {"error": str(e)}; rc = "96"; tcp_error = str(e)

    inbound_id = str(uuid.uuid4())
    inbound_log = {
        "id": inbound_id, "user_id": user["id"], "timestamp": now_iso(),
        "direction": "inbound", "network_id": network_id,
        "mti": resp_meta.get("mti") if isinstance(resp_meta, dict) else mti,
        "raw_hex": resp_hex, "raw_base64": hex_to_base64(resp_hex) if resp_hex else "",
        "parsed": resp_meta, "status_code": rc, "related_id": outbound_id,
        "endpoint_url": endpoint_label,
        "connection_id": target, "connection_name": conn["name"],
        "transport": transport, "wire_format": wire_format,
        "bucket_run_id": bucket_run_id, "template_id": template_id, "template_name": template_name,
        "error": tcp_error,
    }
    outbound_log["related_id"] = inbound_id
    outbound_log["status_code"] = rc
    await db.transaction_logs.insert_many([outbound_log, inbound_log])
    for d in (outbound_log, inbound_log): d.pop("_id", None)
    return {"outbound": outbound_log, "inbound": inbound_log, "response_code": rc, "error": tcp_error}


# ---------------------------------------------------------------------------
# ISO-8583 build / send / simulate
# ---------------------------------------------------------------------------
@api.post("/iso/preview")
async def preview_message(body: SendTransactionRequest, user=Depends(get_current_user)):
    await _ensure_user_spec_loaded(body.network_id, user)
    errors = validate_message(body.mti, body.data_elements, body.network_id)
    try:
        raw_hex, meta = encode_message(body.mti, body.data_elements, body.network_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"raw_hex": raw_hex, "raw_base64": hex_to_base64(raw_hex), "parsed": meta, "validation_errors": errors}


@api.post("/iso/validate")
async def validate_only(body: SendTransactionRequest, user=Depends(get_current_user)):
    await _ensure_user_spec_loaded(body.network_id, user)
    return {"errors": validate_message(body.mti, body.data_elements, body.network_id)}


@api.post("/iso/send")
async def send_transaction(body: SendTransactionRequest, user=Depends(get_current_user)):
    keyset = await _load_keyset(user, body.keyset_id, "endpoint" if body.endpoint_url else None)
    await enforce_log_quota(user)
    await _ensure_user_spec_loaded(body.network_id, user)
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
        resp_hex, resp_meta = simulate_response(body.mti, body.data_elements, body.network_id, keyset)
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


@api.get("/pin/options")
async def pin_options(_user=Depends(get_current_user)):
    return {"formats": list(PIN_FORMATS), "algorithms": list(PIN_ALGORITHMS)}


@api.post("/pin/encrypt")
async def pin_encrypt(body: PinEncryptRequest, _user=Depends(get_current_user)):
    try:
        clear_hex, encrypted_hex = encrypt_pin_block(
            pin=body.pin,
            pan=body.pan or "",
            key_hex=body.key_hex,
            fmt=body.format,
            algorithm=body.algorithm,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # KCV of the PEK so two parties can verify they share the same key.
    try:
        kcv = compute_kcv(body.key_hex, body.algorithm)
    except Exception:
        kcv = ""
    return {
        "clear_block_hex": clear_hex,
        "encrypted_block_hex": encrypted_hex,
        "format": body.format,
        "algorithm": body.algorithm,
        "key_kcv": kcv,
    }


# ---------------------------------------------------------------------------
# Key management tools (KCV / CVV / PVV / ARQC)
# ---------------------------------------------------------------------------
@api.post("/keys/kcv")
async def keys_kcv(body: KcvRequest, _user=Depends(get_current_user)):
    try:
        return {"kcv": compute_kcv(body.key_hex, body.algorithm), "algorithm": body.algorithm}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@api.post("/keys/cvv")
async def keys_cvv(body: CvvRequest, _user=Depends(get_current_user)):
    try:
        cvv = compute_cvv(body.pan, body.expiry, body.service_code, body.cvk_a_hex, body.cvk_b_hex)
        kcv = compute_kcv(body.cvk_a_hex + body.cvk_b_hex, "3DES")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"cvv": cvv, "cvk_kcv": kcv, "service_code": body.service_code}


@api.post("/keys/pvv")
async def keys_pvv(body: PvvRequest, _user=Depends(get_current_user)):
    try:
        pvv = compute_pvv(body.pan, body.pin, body.pvki, body.pvk_a_hex, body.pvk_b_hex)
        kcv = compute_kcv(body.pvk_a_hex + body.pvk_b_hex, "3DES")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"pvv": pvv, "pvki": body.pvki, "pvk_kcv": kcv}


def _compute_arqc(body: ArqcRequest) -> dict:
    """Shared by /keys/arqc and /keys/arqc/verify. Raises ValueError on bad input."""
    keys: dict = {}
    if body.cvn == "AES":
        icc_mk = derive_icc_mk_aes(body.mdk_hex, body.pan, body.psn)
        sk = derive_session_key_aes(icc_mk, body.atc_hex or "0000")
        arqc = compute_arqc_aes(sk, body.cdol_hex)
        algo = "AES"
    else:
        keys = derive_ac_keys(body.cvn, body.mdk_hex, body.pan, body.psn, body.atc_hex, body.un_hex)
        icc_mk, sk = keys["icc_mk"], keys["sk"]
        arqc = compute_arqc(sk, body.cdol_hex, padding=keys["padding"])
        algo = "3DES"
    return {
        "cvn": body.cvn,
        "algorithm": algo,
        "icc_mk_hex": icc_mk,
        "session_key_hex": sk,
        "arqc_hex": arqc,
        "mdk_kcv": compute_kcv(body.mdk_hex, algo),
        "icc_mk_kcv": compute_kcv(icc_mk, algo),
        "session_key_kcv": compute_kcv(sk, algo),
        # Key and method the issuer uses to answer with an ARPC (POST /keys/arpc).
        "arpc_key_hex": keys["arpc_key"] if algo == "3DES" else sk,
        "arpc_method": keys["arpc_method"] if algo == "3DES" else 1,
    }


def _same(a: str, b: str) -> bool:
    """Constant-time, case-insensitive comparison of two codes."""
    return hmac.compare_digest((a or "").replace(" ", "").upper().encode(),
                               (b or "").replace(" ", "").upper().encode())


@api.post("/keys/arqc")
async def keys_arqc(body: ArqcRequest, _user=Depends(get_current_user)):
    try:
        res = _compute_arqc(body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # Pre-built BER-TLV bytes for F55 (tag 9F26 = ARQC, length 08)
    res["f55_tlv_hex"] = _tlv("9F26", res["arqc_hex"])
    return res


# ---------------------------------------------------------------------------
# Verification (issuer side). Each returns {"valid": bool, ...}; the expected
# value is never returned, as with an HSM verify command.
# ---------------------------------------------------------------------------
@api.post("/keys/cvv/verify")
async def keys_cvv_verify(body: CvvVerifyRequest, _user=Depends(get_current_user)):
    try:
        if not (body.cvv.isdigit() and len(body.cvv) == 3):
            raise ValueError("CVV must be 3 digits.")
        expected = compute_cvv(body.pan, body.expiry, body.service_code, body.cvk_a_hex, body.cvk_b_hex)
        kcv = compute_kcv(body.cvk_a_hex + body.cvk_b_hex, "3DES")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"valid": _same(expected, body.cvv), "service_code": body.service_code, "cvk_kcv": kcv}


@api.post("/keys/pvv/verify")
async def keys_pvv_verify(body: PvvVerifyRequest, _user=Depends(get_current_user)):
    try:
        if not (body.pvv.isdigit() and len(body.pvv) == 4):
            raise ValueError("PVV must be 4 digits.")
        if body.pin_block_hex:
            if body.pin:
                raise ValueError("Give either pin or pin_block_hex, not both.")
            if not body.pek_hex:
                raise ValueError("pek_hex is required with pin_block_hex.")
            pin = decrypt_pin_block(body.pin_block_hex, body.pan, body.pek_hex,
                                    body.pin_format, body.pin_algorithm)
            source = "pin_block"
        elif body.pin:
            pin, source = body.pin, "clear"
        else:
            raise ValueError("Give pin or pin_block_hex.")
        expected = compute_pvv(body.pan, pin, body.pvki, body.pvk_a_hex, body.pvk_b_hex)
        kcv = compute_kcv(body.pvk_a_hex + body.pvk_b_hex, "3DES")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"valid": _same(expected, body.pvv), "pvki": body.pvki, "pin_source": source, "pvk_kcv": kcv}


def _ibm3624_args(body) -> dict:
    return dict(table=body.decimalization_table, verify_offset=body.verify_offset,
                verify_length=body.verify_length, pad=body.pad)


@api.post("/keys/ibm3624")
async def keys_ibm3624(body: Ibm3624Request, _user=Depends(get_current_user)):
    try:
        offset = compute_ibm3624_offset(body.pvk_hex, body.pin, body.pan, **_ibm3624_args(body))
        kcv = compute_kcv(body.pvk_hex, "3DES")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"offset": offset, "pvk_kcv": kcv}


@api.post("/keys/ibm3624/verify")
async def keys_ibm3624_verify(body: Ibm3624VerifyRequest, _user=Depends(get_current_user)):
    try:
        if body.pin_block_hex:
            if body.pin:
                raise ValueError("Give either pin or pin_block_hex, not both.")
            if not body.pek_hex:
                raise ValueError("pek_hex is required with pin_block_hex.")
            pin = decrypt_pin_block(body.pin_block_hex, body.pan, body.pek_hex,
                                    body.pin_format, body.pin_algorithm)
            source = "pin_block"
        elif body.pin:
            pin, source = body.pin, "clear"
        else:
            raise ValueError("Give pin or pin_block_hex.")
        expected = compute_ibm3624_pin(body.pvk_hex, body.offset, body.pan, **_ibm3624_args(body))
        kcv = compute_kcv(body.pvk_hex, "3DES")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # PIN length must equal offset length; compare in constant time.
    return {"valid": len(pin) == len(expected) and _same(expected, pin), "pin_source": source, "pvk_kcv": kcv}


@api.post("/keys/arqc/verify")
async def keys_arqc_verify(body: ArqcVerifyRequest, _user=Depends(get_current_user)):
    try:
        res = _compute_arqc(body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    valid = _same(res["arqc_hex"], body.arqc_hex)
    return {
        "valid": valid,
        "cvn": res["cvn"],
        "algorithm": res["algorithm"],
        "mdk_kcv": res["mdk_kcv"],
        "icc_mk_kcv": res["icc_mk_kcv"],
        "session_key_kcv": res["session_key_kcv"],
        # Needed by the issuer to build the ARPC once the ARQC is accepted.
        "session_key_hex": res["session_key_hex"] if valid else None,
        "arpc_key_hex": res["arpc_key_hex"] if valid else None,
        "arpc_method": res["arpc_method"],
    }


def _tlv(tag: str, value_hex: str) -> str:
    """Encode a short BER-TLV (value < 128 bytes)."""
    n = len(value_hex) // 2
    if n > 127:
        raise ValueError("TLV value too long for short-form length.")
    return f"{tag}{n:02X}{value_hex}"


@api.post("/keys/arpc")
async def keys_arpc(body: ArpcRequest, _user=Depends(get_current_user)):
    try:
        if body.method == 1:
            arpc = compute_arpc(body.sk_hex, body.arqc_hex, body.arc_hex, body.algorithm)
            arc4 = body.arc_hex.replace(" ", "").upper().ljust(4, "0")[:4]
            iad = arpc + arc4
        elif body.method == 2:
            if body.algorithm != "3DES":
                raise ValueError("ARPC Method 2 is only supported with 3DES.")
            if not body.csu_hex:
                raise ValueError("CSU is required for ARPC Method 2.")
            arpc = compute_arpc_method2(body.sk_hex, body.arqc_hex, body.csu_hex, body.pad_hex or "")
            arc4 = None
            iad = arpc + body.csu_hex.replace(" ", "").upper() + (body.pad_hex or "").replace(" ", "").upper()
        else:
            raise ValueError("method must be 1 or 2.")
        sk_kcv = compute_kcv(body.sk_hex, body.algorithm)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {
        "method": body.method,
        "arpc_hex": arpc,
        "arc_hex": arc4,
        "csu_hex": body.csu_hex.replace(" ", "").upper() if body.method == 2 else None,
        "pad_hex": (body.pad_hex or "").replace(" ", "").upper() if body.method == 2 else None,
        "session_key_kcv": sk_kcv,
        "algorithm": body.algorithm,
        # F55 tag 91 = Issuer Authentication Data:
        #   Method 1: ARPC(8) || ARC(2)    Method 2: ARPC(4) || CSU(4) || PAD(0-8)
        "f55_tlv_hex": _tlv("91", iad),
    }


# ---------------------------------------------------------------------------
# User key vault (saved keys + auto-KCV)
# ---------------------------------------------------------------------------
def _safe_kcv(key_hex: Optional[str], algorithm: str = "3DES") -> Optional[str]:
    """Compute KCV but return None for empty / malformed values (UI tolerates it)."""
    if not key_hex:
        return None
    try:
        return compute_kcv(key_hex, algorithm)
    except ValueError:
        return None


def _decorate_keyset(doc: dict) -> dict:
    """Attach a `kcv` map computed from the stored hex values."""
    out = {**doc}
    out.pop("_id", None)
    cvk_combined = (out.get("cvk_a_hex") or "") + (out.get("cvk_b_hex") or "")
    pvk_combined = (out.get("pvk_a_hex") or "") + (out.get("pvk_b_hex") or "")
    kcv: Dict[str, Optional[str]] = {
        "MDK": _safe_kcv(out.get("mdk_hex"), "3DES"),
        "CVK_A": _safe_kcv(out.get("cvk_a_hex"), "3DES"),
        "CVK_B": _safe_kcv(out.get("cvk_b_hex"), "3DES"),
        "CVK": _safe_kcv(cvk_combined, "3DES") if cvk_combined and len(cvk_combined) >= 16 else None,
        "PVK_A": _safe_kcv(out.get("pvk_a_hex"), "3DES"),
        "PVK_B": _safe_kcv(out.get("pvk_b_hex"), "3DES"),
        "PVK": _safe_kcv(pvk_combined, "3DES") if pvk_combined and len(pvk_combined) >= 16 else None,
    }
    extras_kcv: Dict[str, Optional[str]] = {}
    for alias, hex_val in (out.get("extras") or {}).items():
        extras_kcv[alias] = _safe_kcv(hex_val, "3DES")
    out["kcv"] = {k: v for k, v in kcv.items() if v is not None}
    out["extras_kcv"] = {k: v for k, v in extras_kcv.items() if v is not None}
    return out


def _normalise_hex(value: Optional[str]) -> Optional[str]:
    if not value:
        return ""
    cleaned = value.replace(" ", "").replace("-", "").upper()
    # validate hex characters but allow empty placeholder
    if cleaned and not all(c in "0123456789ABCDEF" for c in cleaned):
        raise HTTPException(status_code=400, detail=f"Key contains non-hex characters: {value!r}")
    if cleaned and len(cleaned) % 2 != 0:
        raise HTTPException(status_code=400, detail="Key hex length must be even")
    return cleaned


@api.get("/user-keys")
async def list_user_keys(user=Depends(get_current_user)):
    docs = await db.user_keys.find(
        {"user_id": user["id"]}, {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    return [_decorate_keyset(d) for d in docs]


@api.post("/user-keys")
async def create_user_keys(body: KeySetIn, user=Depends(get_current_user)):
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="name is required")
    pvki = (body.pvki or "").strip()
    if pvki and not (len(pvki) == 1 and pvki.isdigit()):
        raise HTTPException(status_code=400, detail="PVKI must be a single digit (0–9)")
    extras = {}
    for alias, hex_val in (body.extras or {}).items():
        alias_norm = (alias or "").strip().upper()
        if not alias_norm:
            continue
        extras[alias_norm] = _normalise_hex(hex_val) or ""
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "name": body.name.strip(),
        "description": (body.description or "").strip(),
        "mdk_hex": _normalise_hex(body.mdk_hex),
        "cvk_a_hex": _normalise_hex(body.cvk_a_hex),
        "cvk_b_hex": _normalise_hex(body.cvk_b_hex),
        "pvk_a_hex": _normalise_hex(body.pvk_a_hex),
        "pvk_b_hex": _normalise_hex(body.pvk_b_hex),
        "pvki": pvki,
        "extras": extras,
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.user_keys.insert_one(doc)
    return _decorate_keyset(doc)


@api.put("/user-keys/{keyset_id}")
async def update_user_keys(keyset_id: str, body: KeySetIn, user=Depends(get_current_user)):
    existing = await db.user_keys.find_one({"id": keyset_id, "user_id": user["id"]}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Key set not found")
    pvki = (body.pvki or "").strip()
    if pvki and not (len(pvki) == 1 and pvki.isdigit()):
        raise HTTPException(status_code=400, detail="PVKI must be a single digit (0–9)")
    extras = {}
    for alias, hex_val in (body.extras or {}).items():
        alias_norm = (alias or "").strip().upper()
        if not alias_norm:
            continue
        extras[alias_norm] = _normalise_hex(hex_val) or ""
    update = {
        "name": body.name.strip() or existing["name"],
        "description": (body.description or "").strip(),
        "mdk_hex": _normalise_hex(body.mdk_hex),
        "cvk_a_hex": _normalise_hex(body.cvk_a_hex),
        "cvk_b_hex": _normalise_hex(body.cvk_b_hex),
        "pvk_a_hex": _normalise_hex(body.pvk_a_hex),
        "pvk_b_hex": _normalise_hex(body.pvk_b_hex),
        "pvki": pvki,
        "extras": extras,
        "updated_at": now_iso(),
    }
    await db.user_keys.update_one({"id": keyset_id, "user_id": user["id"]}, {"$set": update})
    doc = await db.user_keys.find_one({"id": keyset_id}, {"_id": 0})
    return _decorate_keyset(doc)


@api.delete("/user-keys/{keyset_id}")
async def delete_user_keys(keyset_id: str, user=Depends(get_current_user)):
    res = await db.user_keys.delete_one({"id": keyset_id, "user_id": user["id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Key set not found")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Connection profiles (CBS / switch TCP endpoints)
# ---------------------------------------------------------------------------
@api.get("/connections")
async def list_connections(user=Depends(get_current_user)):
    docs = await db.connection_profiles.find(
        {"user_id": user["id"]}, {"_id": 0, "auth_password": 0}
    ).sort("created_at", -1).to_list(200)
    return docs


@api.post("/connections")
async def create_connection(body: ConnectionProfileIn, user=Depends(get_current_user)):
    if body.length_header not in LENGTH_HEADERS:
        raise HTTPException(status_code=400, detail=f"length_header must be one of {LENGTH_HEADERS}")
    if body.transport not in ("tcp", "websocket"):
        raise HTTPException(status_code=400, detail="transport must be 'tcp' or 'websocket'")
    if body.transport == "tcp":
        body.host, body.port = _validated_tcp_target(body)
    if body.transport == "websocket" and not body.ws_url:
        raise HTTPException(status_code=400, detail="WebSocket profiles require ws_url")
    if body.length_header not in LENGTH_HEADERS:
        raise HTTPException(status_code=400, detail=f"length_header must be one of {LENGTH_HEADERS}")
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "name": body.name,
        "transport": body.transport,
        "host": (body.host or "").strip(),
        "port": body.port,
        "ws_url": (body.ws_url or "").strip(),
        "auth_login_url": (body.auth_login_url or "").strip(),
        "auth_username": (body.auth_username or "").strip(),
        "auth_password": body.auth_password or "",
        "auth_token": (body.auth_token or "").strip(),
        "ws_text_mode": body.ws_text_mode,
        "length_header": body.length_header,
        "use_tls": body.use_tls,
        "timeout_sec": body.timeout_sec,
        "auto_heartbeat": body.auto_heartbeat,
        "heartbeat_interval_sec": body.heartbeat_interval_sec,
        "wire_format": body.wire_format,
        "description": body.description or "",
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.connection_profiles.insert_one(doc)
    doc.pop("_id", None)
    doc.pop("auth_password", None)  # never echo back the password
    return doc


@api.put("/connections/{conn_id}")
async def update_connection(conn_id: str, body: ConnectionProfileIn, user=Depends(get_current_user)):
    if body.length_header not in LENGTH_HEADERS:
        raise HTTPException(status_code=400, detail=f"length_header must be one of {LENGTH_HEADERS}")
    if body.transport == "tcp":
        body.host, body.port = _validated_tcp_target(body)
    update = {
        "name": body.name,
        "transport": body.transport,
        "host": (body.host or "").strip(),
        "port": body.port,
        "ws_url": (body.ws_url or "").strip(),
        "auth_login_url": (body.auth_login_url or "").strip(),
        "auth_username": (body.auth_username or "").strip(),
        "ws_text_mode": body.ws_text_mode,
        "length_header": body.length_header,
        "use_tls": body.use_tls,
        "timeout_sec": body.timeout_sec,
        "auto_heartbeat": body.auto_heartbeat,
        "heartbeat_interval_sec": body.heartbeat_interval_sec,
        "wire_format": body.wire_format,
        "description": body.description or "",
        "updated_at": now_iso(),
    }
    if body.auth_password:
        update["auth_password"] = body.auth_password
    if body.auth_token is not None:
        update["auth_token"] = body.auth_token.strip()
    res = await db.connection_profiles.update_one(
        {"id": conn_id, "user_id": user["id"]}, {"$set": update}
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    doc = await db.connection_profiles.find_one({"id": conn_id}, {"_id": 0, "auth_password": 0})
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


@api.post("/connections/probe")
async def connection_probe_adhoc(body: ProbeRequest, _user=Depends(get_current_user)):
    """Telnet-style reachability test for any host:port, before saving a profile.
    Sends no data; reports DNS, TCP, optional TLS and any greeting."""
    try:
        host, pasted = normalise_host(body.host)
        port = body.port or pasted
        if not port:
            raise ValueError("Port is required.")
        return await probe_tcp(host, port, body.use_tls, body.timeout_sec)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@api.post("/connections/{conn_id}/probe")
async def connection_probe(conn_id: str, user=Depends(get_current_user)):
    """Telnet-style reachability test for a saved profile (TCP host:port, or the
    host:port underneath a ws:// / wss:// URL). Does not touch the live session."""
    profile = await db.connection_profiles.find_one({"id": conn_id, "user_id": user["id"]}, {"_id": 0})
    if not profile:
        raise HTTPException(status_code=404, detail="Connection profile not found")
    timeout = min(float(profile.get("timeout_sec") or 5.0), 30.0)
    try:
        if profile.get("transport") == "websocket":
            host, port, tls = host_port_from_ws_url(profile.get("ws_url", ""))
        else:
            host, port, tls = profile.get("host", ""), int(profile.get("port") or 0), bool(profile.get("use_tls"))
        return await probe_tcp(host, port, tls, timeout)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


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


@api.post("/connections/{conn_id}/test")
async def connection_test(conn_id: str, user=Depends(get_current_user)):
    """Send a single 0800 echo to confirm the configured framing actually
    round-trips. Auto-opens the session if it isn't connected. Returns the
    decoded response code + raw hex on both sides for easy diagnosis."""
    profile = await db.connection_profiles.find_one({"id": conn_id, "user_id": user["id"]}, {"_id": 0})
    if not profile:
        raise HTTPException(status_code=404, detail="Connection profile not found")

    # Open the session if it isn't already.
    auto_opened = False
    if not session_is_connected(conn_id):
        try:
            await connect_session(profile)
            auto_opened = True
        except Exception as e:
            return {
                "ok": False,
                "stage": "connect",
                "error": str(e),
                "hint": "Failed to open the WebSocket / TCP handshake. Verify the URL, JWT and that the host is reachable.",
            }

    wire_format = profile.get("wire_format", "native")
    transport = profile.get("transport", "tcp")
    text_mode = bool(profile.get("ws_text_mode")) if transport == "websocket" else None
    length_header = profile.get("length_header", "2_byte")

    de = {
        "7": datetime.now(timezone.utc).strftime("%m%d%H%M%S"),
        "11": "999001",
        "70": "301",
    }
    try:
        req_hex, _ = encode_message("0800", de, "visa", wire_format=wire_format)
    except ValueError as e:
        return {"ok": False, "stage": "encode", "error": str(e)}

    try:
        framed, response_bytes = await send_on_session(conn_id, bytes.fromhex(req_hex))
    except Exception as e:
        # Build a hint based on common misconfiguration symptoms.
        hint = None
        msg = str(e).lower()
        if "timeout" in msg or "timed out" in msg:
            hint = (
                "No response within timeout. The most common cause for "
                "wss://iso8583-server.emergent.host is wire_format=native + ws_text_mode=off — "
                "that server expects ASCII payload + 2-byte length + WS hex-text frames."
            )
        elif "invalid hex" in msg:
            hint = "Server rejected the frame as 'invalid hex'. Toggle 'Send hex-text WS frames' OFF or set wire_format=ascii."
        return {
            "ok": False, "stage": "send",
            "framing": {"wire_format": wire_format, "length_header": length_header, "ws_text_mode": text_mode},
            "request_hex": req_hex,
            "error": str(e),
            "hint": hint,
            "auto_opened": auto_opened,
        }

    resp_hex = response_bytes.hex().upper()
    rc = "??"
    decode_error = None
    try:
        resp_meta = decode_message(resp_hex, "visa", wire_format=wire_format)
        for fobj in resp_meta.get("fields", []):
            if fobj["field"] == 39:
                rc = str(fobj["value"]).strip() or "??"
                break
    except Exception as dec_err:
        decode_error = str(dec_err)

    return {
        "ok": rc == "00" and decode_error is None,
        "stage": "complete",
        "framing": {"wire_format": wire_format, "length_header": length_header, "ws_text_mode": text_mode},
        "request_hex": req_hex,
        "response_hex": resp_hex,
        "response_code": rc,
        "response_description": RESPONSE_CODES.get(rc, "Unknown"),
        "decode_error": decode_error,
        "auto_opened": auto_opened,
    }


@api.post("/iso/send-tcp")
async def send_over_tcp_endpoint(body: TcpSendRequest, user=Depends(get_current_user)):
    """Encode an ISO-8583 message and send it over the profile's transport
    (raw TCP or WebSocket). Request & response are both persisted as logs."""
    await enforce_log_quota(user)
    await _ensure_user_spec_loaded(body.network_id, user)

    host = body.host
    port = body.port
    length_header = body.length_header or "2_byte"
    use_tls = bool(body.use_tls) if body.use_tls is not None else False
    timeout_sec = float(body.timeout_sec) if body.timeout_sec else 10.0
    conn_name = None
    use_persistent = False
    transport = "tcp"
    wire_format = "native"
    endpoint_label = ""
    if body.connection_id:
        conn = await db.connection_profiles.find_one(
            {"id": body.connection_id, "user_id": user["id"]}, {"_id": 0}
        )
        if not conn:
            raise HTTPException(status_code=404, detail="Connection profile not found")
        transport = conn.get("transport", "tcp")
        length_header = conn["length_header"]
        timeout_sec = float(conn.get("timeout_sec") or 10.0)
        wire_format = conn.get("wire_format", "native")
        conn_name = conn["name"]
        if transport == "tcp":
            host = conn.get("host"); port = conn.get("port")
            use_tls = bool(conn.get("use_tls"))
            endpoint_label = f"tcp{'s' if use_tls else ''}://{host}:{port} [{length_header}]"
        else:
            endpoint_label = f"{conn['ws_url']} [ws · {length_header} · {wire_format}]"
        if not session_is_connected(body.connection_id):
            raise HTTPException(
                status_code=409,
                detail="Connection is not active. Open it from the Connections page before sending.",
            )
        use_persistent = True

    if not use_persistent:
        if not host or not port:
            raise HTTPException(status_code=400, detail="host and port are required")
        endpoint_label = f"tcp{'s' if use_tls else ''}://{host}:{port} [{length_header}]"

    if length_header not in LENGTH_HEADERS:
        raise HTTPException(status_code=400, detail=f"length_header must be one of {LENGTH_HEADERS}")

    try:
        req_hex, req_meta = encode_message(body.mti, body.data_elements, body.network_id, wire_format=wire_format)
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
        "endpoint_url": endpoint_label,
        "connection_id": body.connection_id,
        "connection_name": conn_name,
        "transport": transport,
        "wire_format": wire_format,
    }

    try:
        body_bytes = bytes.fromhex(req_hex)
        if use_persistent:
            framed, response_bytes = await send_on_session(body.connection_id, body_bytes)
        else:
            framed, response_bytes = await send_over_tcp(
                host=host, port=port, body=body_bytes,
                length_header=length_header, use_tls=use_tls, timeout=timeout_sec,
            )
        resp_hex = response_bytes.hex().upper()
        try:
            resp_meta = decode_message(resp_hex, body.network_id, wire_format=wire_format)
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
        resp_hex = ""; resp_meta = {"error": f"timeout after {timeout_sec}s"}; rc = "91"; tcp_error = str(e) or "timeout"
    except (ConnectionRefusedError, OSError) as e:
        resp_hex = ""; resp_meta = {"error": f"connection failed: {e}"}; rc = "96"; tcp_error = str(e)
    except Exception as e:
        logger.exception("send failed: %s", e)
        resp_hex = ""; resp_meta = {"error": str(e)}; rc = "96"; tcp_error = str(e)

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
        "transport": transport,
        "wire_format": wire_format,
        "error": tcp_error,
    }
    outbound_log["related_id"] = inbound_id
    outbound_log["status_code"] = rc
    await db.transaction_logs.insert_many([outbound_log, inbound_log])
    for d in (outbound_log, inbound_log): d.pop("_id", None)

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
# Buckets — collections of saved templates that run sequentially
# ---------------------------------------------------------------------------
async def _hydrate_bucket(doc: dict) -> dict:
    """Add `templates` array (id+name+mti+network) for the UI."""
    tids = doc.get("template_ids") or []
    if not tids:
        doc["templates"] = []
        return doc
    cursor = db.templates.find(
        {"id": {"$in": tids}, "user_id": doc["user_id"]},
        {"_id": 0, "id": 1, "name": 1, "mti": 1, "network_id": 1},
    )
    found = {t["id"]: t async for t in cursor}
    # preserve user-defined order, mark missing items
    doc["templates"] = [
        found.get(tid, {"id": tid, "name": "(deleted)", "mti": "????", "network_id": "—"})
        for tid in tids
    ]
    return doc


@api.get("/buckets")
async def list_buckets(user=Depends(get_current_user)):
    docs = await db.buckets.find(
        {"user_id": user["id"]}, {"_id": 0}
    ).sort("created_at", -1).to_list(200)
    return [await _hydrate_bucket(d) for d in docs]


@api.post("/buckets")
async def create_bucket(body: BucketCreate, user=Depends(get_current_user)):
    if not body.template_ids:
        raise HTTPException(status_code=400, detail="At least one template_id required")
    # validate ownership
    own = await db.templates.count_documents(
        {"id": {"$in": body.template_ids}, "user_id": user["id"]}
    )
    if own != len(set(body.template_ids)):
        raise HTTPException(status_code=400, detail="One or more templates not found")
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "name": body.name.strip() or f"Bucket {now_iso()[:19]}",
        "description": (body.description or "").strip(),
        "template_ids": body.template_ids,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "last_run_at": None,
        "last_run_id": None,
    }
    await db.buckets.insert_one(doc)
    doc.pop("_id", None)
    return await _hydrate_bucket(doc)


@api.put("/buckets/{bucket_id}")
async def update_bucket(bucket_id: str, body: BucketCreate, user=Depends(get_current_user)):
    if not body.template_ids:
        raise HTTPException(status_code=400, detail="At least one template_id required")
    own = await db.templates.count_documents(
        {"id": {"$in": body.template_ids}, "user_id": user["id"]}
    )
    if own != len(set(body.template_ids)):
        raise HTTPException(status_code=400, detail="One or more templates not found")
    res = await db.buckets.update_one(
        {"id": bucket_id, "user_id": user["id"]},
        {"$set": {
            "name": body.name.strip(),
            "description": (body.description or "").strip(),
            "template_ids": body.template_ids,
            "updated_at": now_iso(),
        }},
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Bucket not found")
    doc = await db.buckets.find_one({"id": bucket_id}, {"_id": 0})
    return await _hydrate_bucket(doc)


@api.delete("/buckets/{bucket_id}")
async def delete_bucket(bucket_id: str, user=Depends(get_current_user)):
    res = await db.buckets.delete_one({"id": bucket_id, "user_id": user["id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Bucket not found")
    return {"ok": True}


async def _run_template_ids(
    *, user: dict, template_ids: List[str], target: str, delay_ms: int, bucket_run_id: str,
    keyset: Optional[dict] = None,
) -> List[Dict]:
    """Sequentially execute templates and return per-step result rows."""
    results: List[Dict] = []
    for idx, tid in enumerate(template_ids):
        tpl = await db.templates.find_one({"id": tid, "user_id": user["id"]}, {"_id": 0})
        if not tpl:
            results.append({"step": idx + 1, "template_id": tid, "template_name": "(deleted)",
                            "status_code": None, "error": "template not found"})
            continue
        try:
            r = await _execute_message(
                user=user, mti=tpl["mti"], network_id=tpl["network_id"],
                data_elements=tpl["data_elements"], target=target,
                bucket_run_id=bucket_run_id, template_id=tid, template_name=tpl["name"],
                keyset=keyset,
            )
            results.append({
                "step": idx + 1, "template_id": tid, "template_name": tpl["name"],
                "mti": tpl["mti"], "network_id": tpl["network_id"],
                "status_code": r["response_code"],
                "response_description": RESPONSE_CODES.get(r["response_code"], "Unknown"),
                "outbound_log_id": r["outbound"]["id"],
                "inbound_log_id": r["inbound"]["id"],
                "error": r.get("error"),
                "crypto_checks": (r["inbound"].get("parsed") or {}).get("crypto_checks")
                if isinstance(r["inbound"].get("parsed"), dict) else None,
            })
        except HTTPException as he:
            results.append({"step": idx + 1, "template_id": tid, "template_name": tpl["name"],
                            "status_code": None, "error": f"{he.status_code}: {he.detail}"})
            # If it's a quota / connection issue, abort the rest of the bucket.
            if he.status_code in (402, 409):
                break
        except Exception as e:
            logger.exception("bucket step failed for %s", tid)
            results.append({"step": idx + 1, "template_id": tid, "template_name": tpl["name"],
                            "status_code": None, "error": str(e)})
        if delay_ms and idx < len(template_ids) - 1:
            await asyncio.sleep(delay_ms / 1000.0)
    return results


@api.post("/buckets/{bucket_id}/run")
async def run_bucket(bucket_id: str, body: BucketRunRequest, user=Depends(get_current_user)):
    bucket = await db.buckets.find_one({"id": bucket_id, "user_id": user["id"]}, {"_id": 0})
    if not bucket:
        raise HTTPException(status_code=404, detail="Bucket not found")
    bucket_run_id = str(uuid.uuid4())
    started = now_iso()
    keyset = await _load_keyset(user, body.keyset_id, body.target)
    results = await _run_template_ids(
        user=user, template_ids=bucket["template_ids"],
        target=body.target, delay_ms=body.delay_ms, bucket_run_id=bucket_run_id, keyset=keyset,
    )
    finished = now_iso()
    await db.buckets.update_one(
        {"id": bucket_id},
        {"$set": {"last_run_at": finished, "last_run_id": bucket_run_id, "updated_at": finished}},
    )
    return {
        "bucket_run_id": bucket_run_id,
        "bucket_id": bucket_id,
        "bucket_name": bucket["name"],
        "started_at": started,
        "finished_at": finished,
        "target": body.target,
        "delay_ms": body.delay_ms,
        "total": len(bucket["template_ids"]),
        "succeeded": sum(1 for r in results if r.get("status_code") == "00"),
        "failed": sum(1 for r in results if r.get("status_code") not in (None, "00")),
        "errored": sum(1 for r in results if r.get("error")),
        "results": results,
    }


@api.post("/buckets/run-once")
async def run_bucket_once(body: BucketRunRequest, user=Depends(get_current_user)):
    if not body.template_ids:
        raise HTTPException(status_code=400, detail="template_ids required")
    own = await db.templates.count_documents(
        {"id": {"$in": body.template_ids}, "user_id": user["id"]}
    )
    if own != len(set(body.template_ids)):
        raise HTTPException(status_code=400, detail="One or more templates not found")
    bucket_run_id = str(uuid.uuid4())
    started = now_iso()
    keyset = await _load_keyset(user, body.keyset_id, body.target)
    results = await _run_template_ids(
        user=user, template_ids=body.template_ids,
        target=body.target, delay_ms=body.delay_ms, bucket_run_id=bucket_run_id, keyset=keyset,
    )
    finished = now_iso()
    return {
        "bucket_run_id": bucket_run_id,
        "bucket_id": None,
        "bucket_name": "(ad-hoc run)",
        "started_at": started,
        "finished_at": finished,
        "target": body.target,
        "delay_ms": body.delay_ms,
        "total": len(body.template_ids),
        "succeeded": sum(1 for r in results if r.get("status_code") == "00"),
        "failed": sum(1 for r in results if r.get("status_code") not in (None, "00")),
        "errored": sum(1 for r in results if r.get("error")),
        "results": results,
    }


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
    bucket_run_id: Optional[str] = None,
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
    if bucket_run_id:
        filt["bucket_run_id"] = bucket_run_id
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


def _format_log_block(doc: dict) -> str:
    """Render one transaction_log document as a human-readable .txt block."""
    ts = (doc.get("timestamp") or "").replace("T", " ").replace("+00:00", " UTC")
    direction = (doc.get("direction") or "?").upper().ljust(8)
    network = (doc.get("network_id") or "—")
    mti = doc.get("mti") or "????"
    rc = doc.get("status_code") or "—"
    rc_desc = RESPONSE_CODES.get(rc, "")
    endpoint = doc.get("endpoint_url") or "—"
    parsed = doc.get("parsed") or {}
    fields = parsed.get("fields") if isinstance(parsed, dict) else None
    bitmap_hex = parsed.get("bitmap_hex") if isinstance(parsed, dict) else None

    lines = [
        "=" * 78,
        f"[{ts}] {direction} {network:<10}  MTI={mti}  RC={rc} {rc_desc}".rstrip(),
        f"Endpoint : {endpoint}",
    ]
    if doc.get("connection_name"):
        lines.append(f"Profile  : {doc['connection_name']}  ({doc.get('transport') or 'tcp'} · {doc.get('wire_format') or 'native'})")
    if doc.get("template_name"):
        lines.append(f"Template : {doc['template_name']}")
    if doc.get("bucket_run_id"):
        lines.append(f"Bucket   : run {doc['bucket_run_id']}")
    if doc.get("error"):
        lines.append(f"Error    : {doc['error']}")
    if bitmap_hex:
        lines.append(f"Bitmap   : {bitmap_hex}")
    if isinstance(fields, list) and fields:
        lines.append("-- Parsed Data Elements --")
        for f in fields:
            num = f.get("field")
            name = (f.get("name") or "").strip()
            fmt = f.get("format") or ""
            ltype = f.get("length_type") or ""
            value = f.get("value")
            shown = ("…" if value is None else str(value))
            if len(shown) > 200:
                shown = shown[:197] + "…"
            lines.append(f"  DE{num:03d}  {name:<35.35} {fmt:<4} {ltype:<5}  {shown}")
    if isinstance(parsed, dict) and parsed.get("error"):
        lines.append(f"Parse error: {parsed['error']}")
    raw_hex = (doc.get("raw_hex") or "").upper()
    if raw_hex:
        lines.append("-- Raw hex --")
        # wrap hex into 48-char rows for readability
        for i in range(0, len(raw_hex), 48):
            lines.append("  " + raw_hex[i:i + 48])
    lines.append("")
    return "\n".join(lines)


@api.get("/logs/export")
async def export_logs(
    user=Depends(get_current_user),
    q: Optional[str] = None,
    direction: Optional[str] = None,
    status: Optional[str] = None,
    network: Optional[str] = None,
    bucket_run_id: Optional[str] = None,
    limit: int = Query(500, le=5000),
):
    """Plain-text export of captured transaction logs (ISO-8583 readable form)."""
    filt: Dict = {"user_id": user["id"]}
    if direction in ("inbound", "outbound"):
        filt["direction"] = direction
    if status:
        filt["status_code"] = status
    if network:
        filt["network_id"] = network
    if bucket_run_id:
        filt["bucket_run_id"] = bucket_run_id
    if q:
        filt["$or"] = [
            {"mti": {"$regex": q, "$options": "i"}},
            {"raw_hex": {"$regex": q, "$options": "i"}},
            {"status_code": {"$regex": q, "$options": "i"}},
        ]
    cursor = db.transaction_logs.find(filt, {"_id": 0}).sort("timestamp", 1).limit(limit)
    docs = await cursor.to_list(limit)
    header = [
        "ISO-8583 LAB · Transaction log export",
        f"Generated : {now_iso()}",
        f"User      : {user.get('email')}",
        f"Filters   : direction={direction or '*'}  status={status or '*'}  "
        f"network={network or '*'}  q={q or '*'}  bucket_run={bucket_run_id or '*'}",
        f"Total     : {len(docs)} entries (cap {limit})",
        "",
    ]
    body = "\n".join(header) + "\n".join(_format_log_block(d) for d in docs)
    fname = f"iso8583-logs-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.txt"
    return Response(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


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
    stripe = StripeCheckout(webhook_url=webhook_url)
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
    stripe = StripeCheckout(webhook_url=webhook_url)

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
    stripe = StripeCheckout(webhook_url=webhook_url)
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
    await db.buckets.create_index([("user_id", 1), ("created_at", -1)])
    await db.user_specs.create_index([("user_id", 1), ("network_id", 1)], unique=True)
    await db.user_keys.create_index([("user_id", 1), ("created_at", -1)])
    await db.transaction_logs.create_index([("user_id", 1), ("bucket_run_id", 1)])
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


# ---------------------------------------------------------------------------
# Single-service deployment: serve the built React app from the same origin.
# Enabled when FRONTEND_BUILD_DIR points at a CRA build (set in the Dockerfile).
# Same origin means first-party auth cookies and no CORS between UI and API.
# ---------------------------------------------------------------------------
_FRONTEND_DIR = os.environ.get("FRONTEND_BUILD_DIR")
if _FRONTEND_DIR and (Path(_FRONTEND_DIR) / "index.html").is_file():
    from fastapi.responses import FileResponse, JSONResponse

    _frontend_root = Path(_FRONTEND_DIR).resolve()

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        if full_path == "api" or full_path.startswith("api/"):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        candidate = (_frontend_root / full_path).resolve()
        # Real file inside the build (JS, CSS, images...) -> serve it; anything else -> SPA shell.
        if full_path and candidate.is_file() and _frontend_root in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(_frontend_root / "index.html", headers={"Cache-Control": "no-cache"})
