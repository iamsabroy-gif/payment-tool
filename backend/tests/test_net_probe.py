"""Telnet-style probe and host validation, against real local sockets."""
import asyncio
import datetime
import os
import socket
import ssl
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import net_probe  # noqa: E402
from net_probe import normalise_host, probe_tcp, host_port_from_ws_url  # noqa: E402


# ---------------------------------------------------------------------------
# Host / IP validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("10.0.12.5", ("10.0.12.5", None)),
    ("  10.0.12.5  ", ("10.0.12.5", None)),
    ("10.0.12.5:8583", ("10.0.12.5", 8583)),
    ("fd00::1", ("fd00::1", None)),
    ("[fd00::1]", ("fd00::1", None)),
    ("[fd00::1]:8583", ("fd00::1", 8583)),
    ("CBS-UAT.Bank.example", ("cbs-uat.bank.example", None)),
    ("switch.example.com.", ("switch.example.com", None)),
    ("switch.example.com:9000", ("switch.example.com", 9000)),
    ("localhost", ("localhost", None)),
])
def test_normalise_host_accepts(raw, expected):
    assert normalise_host(raw) == expected


@pytest.mark.parametrize("raw,msg", [
    ("", "required"),
    ("tcp://10.0.0.1", "no scheme"),
    ("10.0.0.1/24", "no scheme"),
    ("10.0.0 .1", "spaces"),
    ("10.0.0.256", "not a valid IPv4"),
    ("10.0.0", "not a valid IPv4"),
    ("fd00::zz", "not a valid IPv6"),
    ("[fd00::1", "Unclosed"),
    ("[fd00::1]8583", "[IPv6]:port"),
    ("10.0.0.1:abc", "must be a number"),
    ("10.0.0.1:70000", "1-65535"),
    ("bad_host.example", "not a valid hostname"),
    ("-bad.example", "not a valid hostname"),
])
def test_normalise_host_rejects(raw, msg):
    with pytest.raises(ValueError) as e:
        normalise_host(raw)
    assert msg in str(e.value)


def test_ws_url_target():
    assert host_port_from_ws_url("wss://sim.example.com/api/ws") == ("sim.example.com", 443, True)
    assert host_port_from_ws_url("ws://10.0.0.5:8080/x") == ("10.0.0.5", 8080, False)
    with pytest.raises(ValueError):
        host_port_from_ws_url("https://sim.example.com")


# ---------------------------------------------------------------------------
# Local servers
# ---------------------------------------------------------------------------
async def _serve(handler, ssl_ctx=None):
    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ssl_ctx)
    return server, server.sockets[0].getsockname()[1]


async def _silent(reader, writer):
    try:
        await reader.read(1)            # stay quiet like an ISO-8583 host
    finally:
        writer.close()


async def _greeter(reader, writer):
    writer.write(b"220 CBS-UAT ready\r\n")
    await writer.drain()
    await asyncio.sleep(0.2)
    writer.close()


def _self_signed_ctx(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cbs-uat.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    cert_p, key_p = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_p, key_p)
    return ctx


def _run(coro):
    return asyncio.run(coro)


def _stage(report, name):
    return next(s for s in report["stages"] if s["stage"] == name)


# ---------------------------------------------------------------------------
# Probe outcomes
# ---------------------------------------------------------------------------
def test_reachable_silent_host():
    async def go():
        server, port = await _serve(_silent)
        async with server:
            return await probe_tcp("127.0.0.1", port, timeout=2, banner_wait=0.2)
    r = _run(go())
    assert r["reachable"] is True and r["error_kind"] is None
    assert [s["stage"] for s in r["stages"]] == ["dns", "tcp", "banner"]
    assert "no greeting" in _stage(r, "banner")["detail"]
    assert r["peer"].startswith("127.0.0.1:")


def test_banner_is_captured():
    async def go():
        server, port = await _serve(_greeter)
        async with server:
            return await probe_tcp("127.0.0.1", port, timeout=2, banner_wait=1)
    r = _run(go())
    assert r["reachable"] and r["banner_text"].startswith("220 CBS-UAT ready")
    assert r["banner_hex"].startswith("323230")


def test_closed_port_is_refused():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = _run(probe_tcp("127.0.0.1", port, timeout=2))
    assert r["reachable"] is False and r["error_kind"] == "refused"
    assert _stage(r, "tcp")["ok"] is False and "port" in r["hint"]


def test_connect_timeout(monkeypatch):
    async def hang(*a, **k):
        await asyncio.sleep(10)
    monkeypatch.setattr(net_probe.asyncio, "open_connection", hang)
    r = _run(probe_tcp("192.0.2.10", 8583, timeout=0.5))
    assert r["error_kind"] == "timeout" and "whitelisted" in r["hint"]


def test_dns_failure():
    r = _run(probe_tcp("no-such-host.invalid", 8583, timeout=3))
    assert r["reachable"] is False and r["error_kind"] == "dns_failed"
    assert [s["stage"] for s in r["stages"]] == ["dns"]


def test_tls_handshake_reports_certificate(tmp_path):
    ctx = _self_signed_ctx(tmp_path)

    async def go():
        server, port = await _serve(_silent, ssl_ctx=ctx)
        async with server:
            return await probe_tcp("127.0.0.1", port, use_tls=True, timeout=3, banner_wait=0.2)
    r = _run(go())
    assert r["reachable"] is True, r
    assert r["tls"]["version"].startswith("TLS")
    cert = r["tls"]["certificate"]
    assert "cbs-uat.test" in cert["subject"] and cert["self_signed"] is True


def test_tls_against_plain_port_fails_cleanly():
    async def go():
        server, port = await _serve(_silent)
        async with server:
            return await probe_tcp("127.0.0.1", port, use_tls=True, timeout=1)
    r = _run(go())
    assert r["reachable"] is False and r["error_kind"] == "tls_failed"
    assert _stage(r, "tcp")["ok"] is True and _stage(r, "tls")["ok"] is False


def test_timeout_is_capped():
    async def go():
        server, port = await _serve(_silent)
        async with server:
            return await probe_tcp("127.0.0.1", port, timeout=999, banner_wait=0.1)
    assert _run(go())["reachable"]


# ---------------------------------------------------------------------------
# Server endpoints and profile validation
# ---------------------------------------------------------------------------
def _server():
    os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
    os.environ.setdefault("DB_NAME", "test_db")
    os.environ.setdefault("JWT_SECRET", "test-only-secret")
    return pytest.importorskip("server")


def test_adhoc_probe_endpoint_with_port_in_host():
    server = _server()

    async def go():
        srv, port = await _serve(_silent)
        async with srv:
            return await server.connection_probe_adhoc(
                server.ProbeRequest(host=f"127.0.0.1:{port}", timeout_sec=2), None)
    assert _run(go())["reachable"] is True


@pytest.mark.parametrize("kw,msg", [
    (dict(host="tcp://10.0.0.1", port=8583), "no scheme"),
    (dict(host="10.0.0.1"), "Port is required"),
])
def test_adhoc_probe_endpoint_rejects(kw, msg):
    from fastapi import HTTPException
    server = _server()
    with pytest.raises(HTTPException) as e:
        _run(server.connection_probe_adhoc(server.ProbeRequest(**kw), None))
    assert e.value.status_code == 400 and msg in e.value.detail


def test_profile_host_validation():
    from fastapi import HTTPException
    server = _server()
    P = server.ConnectionProfileIn
    assert server._validated_tcp_target(P(name="a", host=" 10.0.0.5 ", port=8583)) == ("10.0.0.5", 8583)
    assert server._validated_tcp_target(P(name="a", host="10.0.0.5:9000")) == ("10.0.0.5", 9000)
    assert server._validated_tcp_target(P(name="a", host="[fd00::1]:8583")) == ("fd00::1", 8583)
    for kw, msg in [(dict(host="10.0.0.999", port=1), "IPv4"),
                    (dict(host="10.0.0.5:9000", port=8583), "port 9000"),
                    (dict(host="10.0.0.5"), "require host and port")]:
        with pytest.raises(HTTPException) as e:
            server._validated_tcp_target(P(name="a", **kw))
        assert msg in e.value.detail
