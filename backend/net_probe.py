"""Telnet-style reachability probe and host validation for connection profiles.

`probe_tcp` does what `telnet <host> <port>` (or `openssl s_client`) tells an
operator, without sending any ISO-8583 data:

  1. DNS     resolve the host (skipped for IP literals) and list the addresses
  2. TCP     open a socket to host:port, timing the handshake
  3. TLS     optional handshake: protocol, cipher, certificate subject/issuer/expiry
             (certificates are reported, not verified, matching the transport)
  4. Banner  listen briefly for anything the host sends first

Every stage reports its outcome and duration; the first failure is classified
(dns_failed, refused, timeout, unreachable, tls_failed) with a hint.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl as ssl_mod
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

MAX_TIMEOUT_SEC = 30.0
BANNER_MAX_BYTES = 256

_HOST_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


# ---------------------------------------------------------------------------
# Host / IP validation
# ---------------------------------------------------------------------------
def normalise_host(raw: str) -> Tuple[str, Optional[int]]:
    """Validate a host field and return (host, port_if_pasted).

    Accepts an IPv4 address, an IPv6 address (optionally in [brackets]), or a
    DNS hostname. "10.0.0.5:8583" and "[fd00::1]:8583" are accepted and split.
    Rejects schemes, paths, spaces and malformed names with a clear message.
    """
    h = (raw or "").strip()
    if not h:
        raise ValueError("Host is required.")
    if "://" in h or "/" in h:
        raise ValueError("Enter just the IP address or hostname (no scheme such as tcp:// or path).")
    if any(c.isspace() for c in h):
        raise ValueError("Host must not contain spaces.")

    port: Optional[int] = None
    if h.startswith("["):                               # [IPv6] or [IPv6]:port
        end = h.find("]")
        if end == -1:
            raise ValueError("Unclosed '[' in IPv6 address.")
        rest = h[end + 1:]
        h = h[1:end]
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                raise ValueError("Use [IPv6]:port, for example [fd00::1]:8583.")
            port = int(rest[1:])
    elif h.count(":") == 1:                             # host:port or IPv4:port
        h, p = h.split(":")
        if not p.isdigit():
            raise ValueError("Port after ':' must be a number.")
        port = int(p)

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be 1-65535.")

    try:
        return str(ipaddress.ip_address(h)), port
    except ValueError:
        pass
    if ":" in h:
        raise ValueError(f"'{h}' is not a valid IPv6 address.")
    if re.fullmatch(r"[0-9.]+", h):
        raise ValueError(f"'{h}' is not a valid IPv4 address.")
    name = h.rstrip(".")
    if len(name) > 253 or not all(_HOST_LABEL.match(label) for label in name.split(".")):
        raise ValueError(f"'{h}' is not a valid hostname.")
    return name.lower(), port


def host_port_from_ws_url(url: str) -> Tuple[str, int, bool]:
    """(host, port, tls) for a ws:// or wss:// URL, for probing the socket underneath."""
    u = urlparse((url or "").strip())
    if u.scheme not in ("ws", "wss") or not u.hostname:
        raise ValueError("WebSocket URL must start with ws:// or wss:// and include a host.")
    tls = u.scheme == "wss"
    return u.hostname, u.port or (443 if tls else 80), tls


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------
def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


def _classify(exc: BaseException) -> Tuple[str, str]:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError, socket.timeout)):
        return "timeout", ("No answer before the timeout. Usually a firewall silently dropping packets, "
                           "a wrong IP, or your egress IP not yet whitelisted on the host side.")
    if isinstance(exc, ConnectionRefusedError):
        return "refused", ("The host answered but nothing is listening on that port "
                           "(or a firewall actively rejected it). Check the port number.")
    if isinstance(exc, OSError) and exc.errno in (101, 113, 65, 51):  # ENETUNREACH / EHOSTUNREACH (Linux, macOS)
        return "unreachable", "No route to that address from this server. Check the IP, VPN or routing."
    return "error", str(exc)


def _cert_summary(der: Optional[bytes]) -> Optional[Dict]:
    if not der:
        return None
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        try:
            not_after = cert.not_valid_after_utc.isoformat()
            not_before = cert.not_valid_before_utc.isoformat()
        except AttributeError:                       # older cryptography
            not_after = cert.not_valid_after.isoformat()
            not_before = cert.not_valid_before.isoformat()
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": not_before,
            "not_after": not_after,
            "self_signed": cert.subject == cert.issuer,
        }
    except Exception as e:                           # never fail the probe over cert parsing
        return {"error": f"could not parse certificate: {e}"}


async def probe_tcp(host: str, port: int, use_tls: bool = False, timeout: float = 5.0,
                    banner_wait: float = 0.5) -> Dict:
    """Run the probe. Never raises for network errors; returns a report dict."""
    host, _ = normalise_host(host)
    if not 1 <= int(port) <= 65535:
        raise ValueError("Port must be 1-65535.")
    timeout = max(0.5, min(float(timeout or 5.0), MAX_TIMEOUT_SEC))
    stages: List[Dict] = []
    report: Dict = {"host": host, "port": int(port), "use_tls": use_tls, "reachable": False,
                    "stages": stages, "error_kind": None, "hint": None}
    total = time.perf_counter()

    def fail(stage: str, exc: BaseException, started: float, kind: Optional[str] = None, hint: Optional[str] = None):
        k, h = _classify(exc)
        stages.append({"stage": stage, "ok": False, "ms": _ms(started), "detail": str(exc) or k})
        report.update(error_kind=kind or k, hint=hint or h, total_ms=_ms(total))
        return report

    # 1. DNS
    loop = asyncio.get_running_loop()
    is_ip = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip = False
    t = time.perf_counter()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, int(port), type=socket.SOCK_STREAM), timeout=timeout)
        addresses = sorted({i[4][0] for i in infos})
        stages.append({"stage": "dns", "ok": True, "ms": _ms(t),
                       "detail": "IP address given; no lookup needed" if is_ip else ", ".join(addresses),
                       "addresses": addresses})
        report["resolved"] = addresses
    except (socket.gaierror, asyncio.TimeoutError, TimeoutError) as e:
        return fail("dns", e, t, "dns_failed",
                    "The hostname did not resolve. Check the spelling, or use the IP address directly.")

    # 2. TCP connect
    t = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=timeout)
    except Exception as e:
        return fail("tcp", e, t)
    peer = writer.get_extra_info("peername")
    local = writer.get_extra_info("sockname")
    stages.append({"stage": "tcp", "ok": True, "ms": _ms(t),
                   "detail": f"connected to {peer[0]}:{peer[1]}" if peer else "connected"})
    report["peer"] = f"{peer[0]}:{peer[1]}" if peer else None
    report["local"] = f"{local[0]}:{local[1]}" if local else None

    try:
        # 3. TLS
        if use_tls:
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE            # same policy as the TCP transport
            t = time.perf_counter()
            try:
                await asyncio.wait_for(
                    writer.start_tls(ctx, server_hostname=None if is_ip else host), timeout=timeout)
            except Exception as e:
                return fail("tls", e, t, "tls_failed",
                            "TCP connected but the TLS handshake failed. The port may not speak TLS "
                            "(untick TLS), or it needs a client certificate / other TLS version.")
            sslobj = writer.get_extra_info("ssl_object")
            stages.append({"stage": "tls", "ok": True, "ms": _ms(t),
                           "detail": f"{sslobj.version()} · {sslobj.cipher()[0]}" if sslobj else "handshake ok"})
            report["tls"] = {
                "version": sslobj.version() if sslobj else None,
                "cipher": sslobj.cipher()[0] if sslobj else None,
                "certificate": _cert_summary(sslobj.getpeercert(binary_form=True) if sslobj else None),
            }

        # 4. Banner (optional; most ISO-8583 hosts stay silent until spoken to)
        t = time.perf_counter()
        try:
            data = await asyncio.wait_for(reader.read(BANNER_MAX_BYTES), timeout=banner_wait)
            if data:
                stages.append({"stage": "banner", "ok": True, "ms": _ms(t),
                               "detail": f"{len(data)} byte(s) received"})
                report["banner_hex"] = data.hex().upper()
                report["banner_text"] = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            else:
                stages.append({"stage": "banner", "ok": True, "ms": _ms(t),
                               "detail": "host closed the connection straight away"})
                report["closed_by_peer"] = True
        except (asyncio.TimeoutError, TimeoutError):
            stages.append({"stage": "banner", "ok": True, "ms": _ms(t),
                           "detail": "no greeting (normal for ISO-8583 hosts)"})
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass

    report.update(reachable=True, total_ms=_ms(total))
    return report
