"""Mastercard M/Chip cryptograms and IBM 3624 PIN offsets, cross-checked
against pyemv (MasterCardCVN16/17/20/21) and psec (IBM 3624).

Pure unit tests; the endpoint tests import server.py with dummy settings.
"""
import asyncio
import os
import random
import sys
import warnings
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
warnings.filterwarnings("ignore", message=".*TripleDES.*")

import iso8583  # noqa: E402
import key_management as km  # noqa: E402
import sim_crypto  # noqa: E402

pyemv = pytest.importorskip("pyemv")
psec = pytest.importorskip("psec")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from pyemv import cvn, kd  # noqa: E402
from psec import pinblock  # noqa: E402

RNG = random.Random(16172021)
N = 100
MC = {"MC_CVN16": cvn.MasterCardCVN16, "MC_CVN17": cvn.MasterCardCVN17,
      "MC_CVN20": cvn.MasterCardCVN20, "MC_CVN21": cvn.MasterCardCVN21}
MC_BYTE = {"MC_CVN16": 0x10, "MC_CVN17": 0x11, "MC_CVN20": 0x14, "MC_CVN21": 0x15}
COUNTERS = ("MC_CVN17", "MC_CVN21")


def _rand(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


def _digits(n):
    return "".join(RNG.choice("0123456789") for _ in range(n))


def _server():
    os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
    os.environ.setdefault("DB_NAME", "test_db")
    os.environ.setdefault("JWT_SECRET", "test-only-secret")
    return pytest.importorskip("server")


def _call(handler, model, **kw):
    server = _server()
    return asyncio.run(getattr(server, handler)(getattr(server, model)(**kw), None))


class McTxn:
    """A Mastercard card plus one transaction, generated with pyemv."""

    def __init__(self, name, pan_len=16):
        self.name = name
        self.mdk, self.pan, self.psn = _rand(16), _digits(pan_len), f"{RNG.randint(0, 99):02d}"
        self.atc, self.un = _rand(2), _rand(4)
        self.tags = dict(tag_9f02=_rand(6), tag_9f03=_rand(6), tag_9f1a=_rand(2), tag_95=_rand(5),
                         tag_5f2a=_rand(2), tag_9a=_rand(3), tag_9c=_rand(1), tag_9f37=self.un,
                         tag_82=_rand(2), tag_9f36=self.atc)
        self.cvr, self.counters = _rand(6), _rand(8)
        self.card = MC[name](self.mdk, _rand(16), _rand(16), self.pan, self.psn)
        extra = {"counters": self.counters} if name in COUNTERS else {}
        self.arqc = self.card.generate_ac(**self.tags, cvr=self.cvr, **extra)
        # IAD: KDI | CVN | CVR(6) | DAC/IDN(2) | counters(8)
        self.iad = bytes([0x01, MC_BYTE[name]]) + self.cvr + _rand(2) + self.counters

    @property
    def mac_data(self):
        data = b"".join(self.tags.values()) + self.cvr
        return data + (self.counters if self.name in COUNTERS else b"")

    def ref_arpc(self, arc: bytes):
        if self.name in ("MC_CVN16", "MC_CVN17"):
            return self.card.generate_arpc(self.arqc, arc)
        return self.card.generate_arpc(self.arqc, self.atc, arc)

    def f55(self, tamper=False):
        arqc = bytes([self.arqc[0] ^ 1]) + self.arqc[1:] if tamper else self.arqc
        tlv = lambda t, v: f"{t}{len(v):02X}{v.hex().upper()}"  # noqa: E731
        out = tlv("9F26", arqc) + tlv("9F10", self.iad) + tlv("5F34", bytes.fromhex(self.psn))
        for k, v in self.tags.items():
            out += tlv(k[4:].upper(), v)
        return out


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
def test_mastercard_session_key_matches_pyemv():
    for _ in range(N):
        mk, atc, un = _rand(16), _rand(2), _rand(4)
        assert km.derive_session_key_mastercard(mk.hex(), atc.hex(), un.hex()) \
            == kd.derive_common_sk(mk, atc + b"\x00\x00" + un).hex().upper()


@pytest.mark.parametrize("name", list(MC))
@pytest.mark.parametrize("pan_len", [13, 16, 19])
def test_mc_arqc_endpoint_and_arpc_match_pyemv(name, pan_len):
    for _ in range(N // 5):
        t = McTxn(name, pan_len)
        res = _call("keys_arqc", "ArqcRequest", mdk_hex=t.mdk.hex(), pan=t.pan, psn=t.psn, cvn=name,
                    atc_hex=t.atc.hex(), un_hex=t.un.hex(), cdol_hex=t.mac_data.hex())
        assert res["arqc_hex"] == t.arqc.hex().upper(), (name, t.pan)
        assert res["arpc_method"] == 1
        arc = b"00"
        arpc = _call("keys_arpc", "ArpcRequest", sk_hex=res["arpc_key_hex"], arqc_hex=res["arqc_hex"],
                     arc_hex=arc.hex(), method=1)
        assert arpc["arpc_hex"] == t.ref_arpc(arc).hex().upper(), name


@pytest.mark.parametrize("name", list(MC))
def test_mc_arqc_verify_endpoint(name):
    for _ in range(N // 5):
        t = McTxn(name, RNG.choice([16, 19]))
        args = dict(mdk_hex=t.mdk.hex(), pan=t.pan, psn=t.psn, cvn=name, atc_hex=t.atc.hex(),
                    un_hex=t.un.hex(), cdol_hex=t.mac_data.hex())
        ok = _call("keys_arqc_verify", "ArqcVerifyRequest", arqc_hex=t.arqc.hex(), **args)
        assert ok["valid"] is True and ok["arpc_key_hex"] and ok["arpc_method"] == 1
        bad = bytes([t.arqc[0] ^ 1]) + t.arqc[1:]
        ko = _call("keys_arqc_verify", "ArqcVerifyRequest", arqc_hex=bad.hex(), **args)
        assert ko["valid"] is False and ko["arpc_key_hex"] is None


@pytest.mark.parametrize("name,kw,msg", [
    ("MC_CVN16", dict(atc_hex="0001"), "Unpredictable number is required"),
    ("MC_CVN20", dict(), "ATC is required"),
    ("MC_CVN99", dict(atc_hex="0001"), "cvn must be one of"),
])
def test_mc_arqc_endpoint_rejects_bad_input(name, kw, msg):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        _call("keys_arqc", "ArqcRequest", mdk_hex="00" * 16, pan="5413330000000000", cvn=name,
              cdol_hex="00", **kw)
    assert e.value.status_code == 400 and msg in e.value.detail


# ---------------------------------------------------------------------------
# Simulator with Mastercard chip data
# ---------------------------------------------------------------------------
@pytest.fixture
def no_random_decline(monkeypatch):
    monkeypatch.setattr(iso8583.random, "choices", lambda seq, k=1: ["00"])


def _mc_message(t, **over):
    de = {"2": t.pan, "3": "000000", "4": "000000001000", "11": "000001", "55": t.f55()}
    de.update(over)
    return de


@pytest.mark.parametrize("name", list(MC))
@pytest.mark.parametrize("network", ["mastercard", "rupay"])   # rupay: auto-detect fallback
def test_simulator_verifies_mc_arqc_and_returns_arpc(name, network, no_random_decline):
    for _ in range(10):
        t = McTxn(name, RNG.choice([16, 19]))
        _, meta = iso8583.simulate_response("0100", _mc_message(t), network, {"mdk_hex": t.mdk.hex()})
        check = meta["crypto_checks"][0]
        assert meta["response_code"] == "00" and check["result"] == "pass", check
        assert "Mastercard" in check["detail"]
        f55 = next(f["value"] for f in meta["fields"] if f["field"] == 55).upper()
        assert f55 == "910A" + t.ref_arpc(b"00").hex().upper() + "3030"


def test_simulator_bad_mc_arqc_declines_82(no_random_decline):
    t = McTxn("MC_CVN16")
    _, meta = iso8583.simulate_response("0100", _mc_message(t, **{"55": t.f55(tamper=True)}),
                                        "mastercard", {"mdk_hex": t.mdk.hex()})
    assert meta["response_code"] == "82" and meta["crypto_checks"][0]["result"] == "fail"


def test_iad_layout_follows_network():
    visa_iad = bytes.fromhex("06010A03A00000")
    mc_iad = bytes([0x01, 0x14]) + bytes(16)
    assert sim_crypto.detect_cvn(visa_iad, "visa")[0] == "CVN10"
    assert sim_crypto.detect_cvn(mc_iad, "mastercard")[0] == "MC_CVN20"
    assert sim_crypto.detect_cvn(visa_iad, "mastercard") is None
    assert sim_crypto.detect_cvn(mc_iad, "visa") is None
    assert sim_crypto.detect_cvn(mc_iad, "rupay")[0] == "MC_CVN20"
    # CVN17/21 need the counters, so an IAD too short to carry them is unsupported.
    assert sim_crypto.detect_cvn(bytes([0x01, 0x11]) + bytes(8), "mastercard") is None


# ---------------------------------------------------------------------------
# IBM 3624 PIN offset vs psec
# ---------------------------------------------------------------------------
def test_ibm3624_psec_doc_vectors():
    pvk, pan, table = "0123456789ABCDEFFEDCBA9876543210", "1122334455667788", "1234567890123456"
    assert km.compute_ibm3624_pin(pvk, "0000", pan, table, 0, 16, "F") == "4524"
    assert km.compute_ibm3624_offset(pvk, "4524", pan, table, 0, 16, "F") == "0000"


def test_ibm3624_matches_psec():
    for _ in range(N * 2):
        pvk = _rand(RNG.choice([8, 16, 24]))
        pan = _digits(RNG.randint(13, 19))
        table = _digits(16)
        vo = RNG.randint(0, len(pan) - 4)
        vl = RNG.randint(1, min(16, len(pan) - vo))
        pad = RNG.choice("0123456789ABCDEF")
        pin = _digits(RNG.randint(4, 12))
        offset = km.compute_ibm3624_offset(pvk.hex(), pin, pan, table, vo, vl, pad)
        assert offset == psec.pin.generate_ibm3624_offset(pvk, table, pin, pan, vo, vl, pad)
        assert km.compute_ibm3624_pin(pvk.hex(), offset, pan, table, vo, vl, pad) \
            == psec.pin.generate_ibm3624_pin(pvk, table, offset, pan, vo, vl, pad) == pin


def test_ibm3624_endpoints_clear_pin_and_pin_block():
    for _ in range(N // 2):
        pvk, pek = _rand(16), _rand(16)
        pan, pin = _digits(16), _digits(RNG.randint(4, 6))
        args = dict(pan=pan, pvk_hex=pvk.hex(), decimalization_table="0123456789012345", verify_length=12)
        offset = _call("keys_ibm3624", "Ibm3624Request", pin=pin, **args)["offset"]
        assert offset == psec.pin.generate_ibm3624_offset(pvk, "0123456789012345", pin, pan, 0, 12, "F")

        assert _call("keys_ibm3624_verify", "Ibm3624VerifyRequest", offset=offset, pin=pin, **args)["valid"]
        wrong = pin[:-1] + str((int(pin[-1]) + 1) % 10)
        assert not _call("keys_ibm3624_verify", "Ibm3624VerifyRequest", offset=offset, pin=wrong, **args)["valid"]

        clear = pinblock.encode_pinblock_iso_0(pin, pan)
        block = Cipher(algorithms.TripleDES(pek + pek[:8]), modes.ECB()).encryptor().update(clear).hex()
        r = _call("keys_ibm3624_verify", "Ibm3624VerifyRequest", offset=offset, pin_block_hex=block,
                  pek_hex=pek.hex(), **args)
        assert r["valid"] is True and r["pin_source"] == "pin_block"


def test_ibm3624_pin_length_must_match_offset():
    pvk, pan = "0123456789ABCDEFFEDCBA9876543210", "5413330000000000"
    offset = km.compute_ibm3624_offset(pvk, "1234", pan)
    r = _call("keys_ibm3624_verify", "Ibm3624VerifyRequest", pan=pan, pvk_hex=pvk, offset=offset, pin="12345")
    assert r["valid"] is False


@pytest.mark.parametrize("kw,msg", [
    (dict(decimalization_table="12345"), "16 decimal digits"),
    (dict(verify_offset=10, verify_length=12), "outside the PAN"),
    (dict(pad="G"), "one hex digit"),
    (dict(pin="12"), "4-12 digits"),
])
def test_ibm3624_rejects_bad_input(kw, msg):
    from fastapi import HTTPException
    args = dict(pan="5413330000000000", pvk_hex="0123456789ABCDEFFEDCBA9876543210", pin="1234") | kw
    with pytest.raises(HTTPException) as e:
        _call("keys_ibm3624", "Ibm3624Request", **args)
    assert e.value.status_code == 400 and msg in e.value.detail
