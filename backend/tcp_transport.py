"""TCP transport for ISO-8583 messages to an external CBS / switch.

Supports four length-header framings used in real payment networks:
  - `2_byte`   : 2-byte big-endian unsigned length prefix (most common)
  - `4_byte`   : 4-byte big-endian unsigned length prefix
  - `ascii_4`  : 4-digit ASCII length prefix (e.g. '0128')
  - `none`     : raw stream; server closes socket to signal end-of-message
"""
import asyncio
import ssl as ssl_mod
from typing import Optional, Tuple

LENGTH_HEADERS = ("2_byte", "4_byte", "ascii_4", "none")


def frame_message(body: bytes, header: str) -> bytes:
    if header == "2_byte":
        return len(body).to_bytes(2, "big") + body
    if header == "4_byte":
        return len(body).to_bytes(4, "big") + body
    if header == "ascii_4":
        return f"{len(body):04d}".encode("ascii") + body
    return body


async def _read_framed(reader: asyncio.StreamReader, header: str, timeout: float) -> bytes:
    if header == "2_byte":
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        length = int.from_bytes(hdr, "big")
        return await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    if header == "4_byte":
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        length = int.from_bytes(hdr, "big")
        return await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    if header == "ascii_4":
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        length = int(hdr.decode("ascii"))
        return await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    # none: read until EOF / timeout
    try:
        return await asyncio.wait_for(reader.read(65535), timeout=timeout)
    except asyncio.TimeoutError:
        return b""


async def send_over_tcp(
    host: str,
    port: int,
    body: bytes,
    length_header: str = "2_byte",
    use_tls: bool = False,
    timeout: float = 10.0,
) -> Tuple[bytes, bytes]:
    """Open TCP (optionally TLS) socket, send framed body, receive one framed response.

    Returns (framed_bytes_sent, response_body_bytes).
    Raises on connection / timeout errors.
    """
    if length_header not in LENGTH_HEADERS:
        raise ValueError(f"unsupported length_header: {length_header}")

    ssl_ctx: Optional[ssl_mod.SSLContext] = None
    if use_tls:
        ssl_ctx = ssl_mod.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_mod.CERT_NONE  # dev-friendly; CBS sandboxes often use self-signed

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host=host, port=port, ssl=ssl_ctx),
        timeout=timeout,
    )
    try:
        framed = frame_message(body, length_header)
        writer.write(framed)
        await writer.drain()
        response = await _read_framed(reader, length_header, timeout=timeout)
        return framed, response
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
