"""Persistent transport sessions for ISO-8583 connection profiles.

Two transports are supported:
  - **TCP** (raw socket, optional TLS) — for bare hosts that expose 8583 directly.
  - **WebSocket** (wss://…/api/ws/iso8583?token=<JWT>) — for hosted issuer
    simulators where raw TCP isn't reachable (e.g. behind ingress).

Both use the same length-framed payload (see `tcp_transport.frame_message`).
A 0800 echo heartbeat keeps the connection alive when enabled on the profile.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Any

from tcp_transport import frame_message, _read_framed, LENGTH_HEADERS, send_over_tcp
from ws_transport import open_ws_connection, send_over_ws
from iso8583 import encode_message
import ssl as ssl_mod

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Session:
    profile_id: str
    user_id: str
    transport: str                # "tcp" | "websocket"
    length_header: str
    timeout_sec: float
    wire_format: str = "native"
    # TCP
    reader: Any = None
    writer: Any = None
    host: str = ""
    port: int = 0
    use_tls: bool = False
    # WS
    ws: Any = None
    ws_url: str = ""
    ws_text_mode: bool = False
    # bookkeeping
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    connected_at: str = field(default_factory=_now)
    last_activity_at: str = field(default_factory=_now)
    last_heartbeat_at: Optional[str] = None
    last_heartbeat_rc: Optional[str] = None
    last_error: Optional[str] = None
    heartbeat_task: Optional[asyncio.Task] = None
    heartbeat_interval_sec: int = 0
    stan_counter: int = 0

    def next_stan(self) -> str:
        self.stan_counter = (self.stan_counter + 1) % 1_000_000
        return f"{self.stan_counter:06d}"

    def is_open(self) -> bool:
        if self.transport == "tcp":
            return bool(self.writer and not self.writer.is_closing())
        return bool(self.ws and not getattr(self.ws, "closed", False))

    def public_status(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "state": "connected" if self.is_open() else "idle",
            "transport": self.transport,
            "host": self.host or self.ws_url,
            "port": self.port,
            "length_header": self.length_header,
            "use_tls": self.use_tls,
            "wire_format": self.wire_format,
            "ws_text_mode": self.ws_text_mode if self.transport == "websocket" else None,
            "connected_at": self.connected_at,
            "last_activity_at": self.last_activity_at,
            "last_heartbeat_at": self.last_heartbeat_at,
            "last_heartbeat_rc": self.last_heartbeat_rc,
            "heartbeat_interval_sec": self.heartbeat_interval_sec,
            "last_error": self.last_error,
        }


_sessions: Dict[str, Session] = {}
_registry_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
async def get_status(profile_id: str) -> dict:
    sess = _sessions.get(profile_id)
    if not sess:
        return {"profile_id": profile_id, "state": "idle"}
    return sess.public_status()


def is_connected(profile_id: str) -> bool:
    sess = _sessions.get(profile_id)
    return bool(sess and sess.is_open())


async def connect_session(profile: dict) -> Session:
    pid = profile["id"]
    async with _registry_lock:
        existing = _sessions.get(pid)
        if existing and existing.is_open():
            return existing

    transport = profile.get("transport", "tcp")
    length_header = profile.get("length_header", "2_byte")
    if length_header not in LENGTH_HEADERS:
        raise ValueError(f"unsupported length_header: {length_header}")

    sess = Session(
        profile_id=pid,
        user_id=profile["user_id"],
        transport=transport,
        length_header=length_header,
        timeout_sec=float(profile.get("timeout_sec") or 10.0),
        wire_format=profile.get("wire_format", "native"),
        heartbeat_interval_sec=(
            int(profile.get("heartbeat_interval_sec") or 0) if profile.get("auto_heartbeat") else 0
        ),
    )

    if transport == "tcp":
        ssl_ctx: Optional[ssl_mod.SSLContext] = None
        if profile.get("use_tls"):
            ssl_ctx = ssl_mod.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl_mod.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=profile["host"], port=int(profile["port"]), ssl=ssl_ctx),
            timeout=sess.timeout_sec,
        )
        sess.reader = reader
        sess.writer = writer
        sess.host = profile["host"]
        sess.port = int(profile["port"])
        sess.use_tls = bool(profile.get("use_tls"))
    elif transport == "websocket":
        ws, _token = await open_ws_connection(
            ws_url=profile["ws_url"],
            token=(profile.get("auth_token") or None),
            auth_login_url=profile.get("auth_login_url") or None,
            username=profile.get("auth_username") or None,
            password=profile.get("auth_password") or None,
            timeout=sess.timeout_sec,
        )
        sess.ws = ws
        sess.ws_url = profile["ws_url"]
        sess.ws_text_mode = bool(profile.get("ws_text_mode"))
    else:
        raise ValueError(f"unsupported transport: {transport}")

    async with _registry_lock:
        _sessions[pid] = sess

    if sess.heartbeat_interval_sec > 0:
        sess.heartbeat_task = asyncio.create_task(_heartbeat_loop(pid))

    logger.info("[session] connected %s via %s (heartbeat=%ss)", pid, transport, sess.heartbeat_interval_sec)
    return sess


async def disconnect_session(profile_id: str) -> bool:
    async with _registry_lock:
        sess = _sessions.pop(profile_id, None)
    if not sess:
        return False
    if sess.heartbeat_task and not sess.heartbeat_task.done():
        sess.heartbeat_task.cancel()
        try:
            await sess.heartbeat_task
        except (asyncio.CancelledError, Exception):
            pass
    try:
        if sess.transport == "tcp" and sess.writer:
            sess.writer.close()
            await sess.writer.wait_closed()
        elif sess.transport == "websocket" and sess.ws:
            await sess.ws.close()
    except Exception as e:
        logger.warning("[session] close error %s: %s", profile_id, e)
    logger.info("[session] disconnected %s", profile_id)
    return True


async def send_on_session(profile_id: str, body: bytes) -> Tuple[bytes, bytes]:
    sess = _sessions.get(profile_id)
    if not sess or not sess.is_open():
        raise ConnectionError("Session is not connected")

    async with sess.lock:
        try:
            if sess.transport == "tcp":
                framed = frame_message(body, sess.length_header)
                sess.writer.write(framed)
                await sess.writer.drain()
                response = await _read_framed(sess.reader, sess.length_header, timeout=sess.timeout_sec)
            else:
                framed, response = await send_over_ws(
                    sess.ws,
                    body,
                    length_header=sess.length_header,
                    text_mode=sess.ws_text_mode,
                    timeout=sess.timeout_sec,
                )
        except Exception as e:
            sess.last_error = str(e)
            asyncio.create_task(_mark_dead(profile_id, str(e)))
            raise
        sess.last_activity_at = _now()
        sess.last_error = None
        return framed, response


async def _mark_dead(profile_id: str, err: str):
    logger.warning("[session] marking dead %s: %s", profile_id, err)
    await disconnect_session(profile_id)


async def _heartbeat_loop(profile_id: str):
    sess = _sessions.get(profile_id)
    if not sess:
        return
    interval = sess.heartbeat_interval_sec
    logger.info("[heartbeat] starting for %s every %ss", profile_id, interval)
    try:
        while True:
            await asyncio.sleep(interval)
            sess = _sessions.get(profile_id)
            if not sess or not sess.is_open():
                return
            try:
                stan = sess.next_stan()
                de = {
                    "7": datetime.now(timezone.utc).strftime("%m%d%H%M%S"),
                    "11": stan,
                    "70": "301",
                }
                req_hex, _ = encode_message("0800", de, "visa", wire_format=sess.wire_format)
                _, resp = await send_on_session(profile_id, bytes.fromhex(req_hex))
                rc = "00"
                try:
                    ascii_resp = resp.decode("latin-1", errors="replace")
                    rc_guess = ascii_resp[-2:]
                    if rc_guess.strip():
                        rc = rc_guess
                except Exception:
                    pass
                sess.last_heartbeat_at = _now()
                sess.last_heartbeat_rc = rc
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("[heartbeat] %s failed: %s", profile_id, e)
                if sess:
                    sess.last_error = f"heartbeat: {e}"
                return
    except asyncio.CancelledError:
        logger.info("[heartbeat] cancelled for %s", profile_id)
