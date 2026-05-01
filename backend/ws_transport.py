"""WebSocket transport for ISO-8583 messages.

The server presents itself as `wss://<host>/api/ws/iso8583?token=<JWT>`.
Same length-framed payload as raw TCP: prefix the body with a 2-byte BE length
header (or 4-byte / ASCII-4 / none) and send as a binary WS frame, or hex-encode
the framed bytes and send as a text WS frame for easier debugging.

Authentication is a bearer JWT obtained from `POST /api/auth/login` on the same
host. We stash the token only in-memory inside the live session.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qsl

import httpx
import websockets

from tcp_transport import frame_message, _read_framed, LENGTH_HEADERS

logger = logging.getLogger(__name__)


def _http_base_from_ws(ws_url: str) -> str:
    """ws(s)://host[:port]/path?... → http(s)://host[:port]"""
    parts = urlsplit(ws_url)
    scheme = "https" if parts.scheme == "wss" else "http"
    return urlunsplit((scheme, parts.netloc, "", "", ""))


def _augment_token_query(ws_url: str, token: str) -> str:
    parts = urlsplit(ws_url)
    q = dict(parse_qsl(parts.query))
    q["token"] = token
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


async def fetch_jwt(login_url: str, username: str, password: str, timeout: float = 10.0) -> str:
    """POST {login_url} with {username,password} → {token}."""
    async with httpx.AsyncClient(timeout=timeout) as http:
        resp = await http.post(login_url, json={"username": username, "password": password})
        resp.raise_for_status()
        data = resp.json()
        token = data.get("token") or data.get("access_token") or data.get("jwt")
        if not token:
            raise ValueError(f"login response missing token: {data}")
        return token


async def open_ws_connection(
    ws_url: str,
    *,
    token: Optional[str] = None,
    auth_login_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 10.0,
):
    """Open a websocket. If `token` is None and credentials are given,
    perform login first and append `?token=` to the URL."""
    if not token and username and password:
        login_url = auth_login_url or (_http_base_from_ws(ws_url) + "/api/auth/login")
        token = await fetch_jwt(login_url, username, password, timeout=timeout)
    if token:
        ws_url = _augment_token_query(ws_url, token)
    ws = await asyncio.wait_for(
        websockets.connect(ws_url, max_size=2 ** 20, ping_interval=None),
        timeout=timeout,
    )
    return ws, token


async def send_over_ws(
    ws,
    body: bytes,
    *,
    length_header: str = "2_byte",
    text_mode: bool = False,
    timeout: float = 10.0,
) -> Tuple[bytes, bytes]:
    """Send framed body, receive one framed response.
    Returns (framed_sent, response_body_unframed).
    """
    if length_header not in LENGTH_HEADERS:
        raise ValueError(f"unsupported length_header: {length_header}")
    framed = frame_message(body, length_header)
    if text_mode:
        await ws.send(framed.hex())
    else:
        await ws.send(framed)

    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
    if isinstance(raw, str):
        raw_bytes = bytes.fromhex(raw)
    else:
        raw_bytes = raw

    # Strip the length prefix the server prepends.
    if length_header == "2_byte" and len(raw_bytes) >= 2:
        n = int.from_bytes(raw_bytes[:2], "big")
        return framed, raw_bytes[2:2 + n]
    if length_header == "4_byte" and len(raw_bytes) >= 4:
        n = int.from_bytes(raw_bytes[:4], "big")
        return framed, raw_bytes[4:4 + n]
    if length_header == "ascii_4" and len(raw_bytes) >= 4:
        n = int(raw_bytes[:4].decode("ascii"))
        return framed, raw_bytes[4:4 + n]
    return framed, raw_bytes
