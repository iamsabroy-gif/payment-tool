"""Persistent TCP sessions for ISO-8583 connection profiles.

Holds an in-process registry of open sockets so users can `connect` once
and send multiple transactions on the same connection, with an optional
background 0800 echo heartbeat keeping the socket alive.

All sessions are process-local — a server reload resets them.
"""
from __future__ import annotations

import asyncio
import logging
import ssl as ssl_mod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from tcp_transport import frame_message, _read_framed, LENGTH_HEADERS
from iso8583 import encode_message

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Session:
    profile_id: str
    user_id: str
    host: str
    port: int
    length_header: str
    use_tls: bool
    timeout_sec: float
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
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

    def public_status(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "state": "connected",
            "host": self.host,
            "port": self.port,
            "length_header": self.length_header,
            "use_tls": self.use_tls,
            "connected_at": self.connected_at,
            "last_activity_at": self.last_activity_at,
            "last_heartbeat_at": self.last_heartbeat_at,
            "last_heartbeat_rc": self.last_heartbeat_rc,
            "heartbeat_interval_sec": self.heartbeat_interval_sec,
            "last_error": self.last_error,
        }


# Module-level session registry {profile_id: Session}
_sessions: Dict[str, Session] = {}
_registry_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
async def get_status(profile_id: str) -> dict:
    sess = _sessions.get(profile_id)
    if not sess:
        return {"profile_id": profile_id, "state": "idle"}
    return sess.public_status()


def is_connected(profile_id: str) -> bool:
    sess = _sessions.get(profile_id)
    return bool(sess and not sess.writer.is_closing())


async def connect_session(profile: dict) -> Session:
    """Open a TCP (optionally TLS) socket to profile.host:port and store it."""
    pid = profile["id"]
    async with _registry_lock:
        existing = _sessions.get(pid)
        if existing and not existing.writer.is_closing():
            return existing

    length_header = profile.get("length_header", "2_byte")
    if length_header not in LENGTH_HEADERS:
        raise ValueError(f"unsupported length_header: {length_header}")

    ssl_ctx: Optional[ssl_mod.SSLContext] = None
    if profile.get("use_tls"):
        ssl_ctx = ssl_mod.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_mod.CERT_NONE

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            host=profile["host"], port=int(profile["port"]), ssl=ssl_ctx
        ),
        timeout=float(profile.get("timeout_sec") or 10.0),
    )

    sess = Session(
        profile_id=pid,
        user_id=profile["user_id"],
        host=profile["host"],
        port=int(profile["port"]),
        length_header=length_header,
        use_tls=bool(profile.get("use_tls")),
        timeout_sec=float(profile.get("timeout_sec") or 10.0),
        reader=reader,
        writer=writer,
        heartbeat_interval_sec=int(profile.get("heartbeat_interval_sec") or 0) if profile.get("auto_heartbeat") else 0,
    )
    async with _registry_lock:
        _sessions[pid] = sess

    if sess.heartbeat_interval_sec > 0:
        sess.heartbeat_task = asyncio.create_task(_heartbeat_loop(pid))

    logger.info("[session] connected %s to %s:%s (heartbeat=%ss)", pid, sess.host, sess.port, sess.heartbeat_interval_sec)
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
        sess.writer.close()
        await sess.writer.wait_closed()
    except Exception as e:
        logger.warning("[session] close error %s: %s", profile_id, e)
    logger.info("[session] disconnected %s", profile_id)
    return True


async def send_on_session(
    profile_id: str, body: bytes
) -> Tuple[bytes, bytes]:
    """Frame + send on existing session's socket under its lock, return (framed_sent, response_body)."""
    sess = _sessions.get(profile_id)
    if not sess or sess.writer.is_closing():
        raise ConnectionError("Session is not connected")

    async with sess.lock:
        framed = frame_message(body, sess.length_header)
        sess.writer.write(framed)
        await sess.writer.drain()
        try:
            response = await _read_framed(sess.reader, sess.length_header, timeout=sess.timeout_sec)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            sess.last_error = f"read error: {e}"
            # Socket is likely half-broken — mark it down.
            asyncio.create_task(_mark_dead(profile_id, str(e)))
            raise
        sess.last_activity_at = _now()
        sess.last_error = None
        return framed, response


async def _mark_dead(profile_id: str, err: str):
    """Close + remove a session that has errored out."""
    logger.warning("[session] marking dead %s: %s", profile_id, err)
    await disconnect_session(profile_id)


# ---------------------------------------------------------------------------
# Heartbeat loop (0800 network management echo)
# ---------------------------------------------------------------------------
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
            if not sess or sess.writer.is_closing():
                return
            try:
                stan = sess.next_stan()
                mti = "0800"
                de = {
                    "7": datetime.now(timezone.utc).strftime("%m%d%H%M%S"),
                    "11": stan,
                    "70": "301",  # keep-alive echo test
                }
                req_hex, _ = encode_message(mti, de, "visa")
                _, resp = await send_on_session(profile_id, bytes.fromhex(req_hex))
                # Extract RC if possible (F39 at a stable offset isn't guaranteed; best-effort)
                rc = "00"
                try:
                    ascii_resp = resp.decode("ascii", errors="replace")
                    # heuristic: find last 2 non-space chars that look like RC digits
                    rc_guess = ascii_resp[-2:]
                    if rc_guess and rc_guess.strip():
                        rc = rc_guess
                except Exception:
                    pass
                sess.last_heartbeat_at = _now()
                sess.last_heartbeat_rc = rc
                logger.debug("[heartbeat] %s rc=%s", profile_id, rc)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("[heartbeat] %s failed: %s", profile_id, e)
                sess = _sessions.get(profile_id)
                if sess:
                    sess.last_error = f"heartbeat: {e}"
                return  # terminate loop; socket likely dead
    except asyncio.CancelledError:
        logger.info("[heartbeat] cancelled for %s", profile_id)
