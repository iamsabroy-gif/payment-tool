"""Cross-check card cryptography in key_management.py against independent libraries.

  - pyemv : EMV ICC MK (Option A/B), session keys, ARQC (Visa CVN10/CVN18), ARPC Method 1
  - psec  : CVV / CVV2 / iCVV, Visa PVV

These are pure unit tests: no server or database needed.
Install the reference libraries with `pip install pyemv psec`.
"""
import os
import random
import sys
import warnings
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
warnings.filterwarnings("ignore", message=".*TripleDES.*")

import key_management as km  # noqa: E402

pyemv = pytest.importorskip("pyemv")
psec = pytest.importorskip("psec")
from pyemv import ac, cvn, kd  # noqa: E402

N = 200
RNG = random.Random(20261119)


def _digits(n):
    return "".join(RNG.choice("0123456789") for _ in range(n))


def _pan():
    return _digits(RNG.randint(13, 19))


def _psn():
    return f"{RNG.randint(0, 99):02d}"


def _rand(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


def _emv_tags(atc: bytes):
    return dict(
        tag_9f02=_rand(6), tag_9f03=_rand(6), tag_9f1a=_rand(2), tag_95=_rand(5),
        tag_5f2a=_rand(2), tag_9a=_rand(3), tag_9c=_rand(1), tag_9f37=_rand(4),
        tag_82=_rand(2), tag_9f36=atc,
    )


# ---------------------------------------------------------------------------
# Published vectors
# ---------------------------------------------------------------------------
CVK_A, CVK_B = "0123456789ABCDEF", "FEDCBA9876543210"


def test_vector_cvv_561():
    assert km.compute_cvv("4123456789012345", "8701", "101", CVK_A, CVK_B) == "561"


def test_vector_cvv_psec_doc():
    assert km.compute_cvv("1234567890123456", "9912", "220", CVK_A, CVK_B) == "170"


def test_vector_pvv_psec_doc():
    assert km.compute_pvv("1122334455667788", "4524", "3", CVK_A, CVK_B) == "4021"


def test_vector_icc_mk_option_a():
    assert km.derive_icc_mk("0123456789ABCDEFFEDCBA9876543210", "12345678901234567", "01") \
        == "73AD54688CEF2934B0979857E3C719F1"


def test_vector_common_session_key():
    assert km.derive_session_key_cvn18("0123456789ABCDEFFEDCBA9876543210", "001C") \
        == "E9FB384AF807B940FEDCEA613461B0C4"


# ---------------------------------------------------------------------------
# CVV / PVV vs psec
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("svc", [None, "000", "999"], ids=["cvv1", "cvv2", "icvv"])
def test_cvv_matches_psec(svc):
    for _ in range(N):
        a, b = _rand(8), _rand(8)
        pan = _pan()
        exp = f"{RNG.randint(0, 99):02d}{RNG.randint(1, 12):02d}"
        code = svc or _digits(3)
        assert km.compute_cvv(pan, exp, code, a.hex(), b.hex()) \
            == psec.cvv.generate_cvv(a + b, pan, exp, code), (pan, exp, code)


def test_pvv_matches_psec():
    for _ in range(N):
        a, b = _rand(8), _rand(8)
        pan, pin, pvki = _pan(), _digits(4), str(RNG.randint(0, 9))
        assert km.compute_pvv(pan, pin, pvki, a.hex(), b.hex()) \
            == psec.pin.generate_visa_pvv(a + b, pvki, pin, pan), (pan, pin, pvki)


# ---------------------------------------------------------------------------
# EMV key derivation vs pyemv
# ---------------------------------------------------------------------------
def test_icc_mk_option_a_matches_pyemv():
    for _ in range(N):
        mdk, pan, psn = _rand(16), _pan(), _psn()
        assert km.derive_icc_mk(mdk.hex(), pan, psn, option="A") \
            == kd.derive_icc_mk_a(mdk, pan, psn).hex().upper(), (pan, psn)


@pytest.mark.parametrize("pan_len", range(13, 20))
def test_icc_mk_option_b_matches_pyemv(pan_len):
    for _ in range(N // 4):
        mdk, pan, psn = _rand(16), _digits(pan_len), _psn()
        assert km.derive_icc_mk(mdk.hex(), pan, psn, option="B") \
            == kd.derive_icc_mk_b(mdk, pan, psn).hex().upper(), (pan, psn)


def test_session_key_matches_pyemv():
    for _ in range(N):
        mk, atc = _rand(16), _rand(2)
        assert km.derive_session_key_cvn18(mk.hex(), atc.hex()) \
            == kd.derive_common_sk(mk, atc + b"\x00" * 6).hex().upper()


@pytest.mark.parametrize("padding,ptype", [("EMV", ac.PaddingType.EMV), ("VISA", ac.PaddingType.VISA)])
def test_mac_padding_matches_pyemv(padding, ptype):
    for length in (1, 7, 8, 9, 16, 29, 32, 33, 40):
        for _ in range(10):
            sk, data = _rand(16), _rand(length)
            assert km.compute_arqc(sk.hex(), data.hex(), padding=padding) \
                == ac.generate_ac(sk, data, ptype).hex().upper(), (padding, length)


# ---------------------------------------------------------------------------
# End-to-end Visa CVN10 / CVN18 through the /api/keys/arqc handler logic
# ---------------------------------------------------------------------------
def _server():
    """Import server.py with dummy settings (no DB connection is made at import)."""
    os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
    os.environ.setdefault("DB_NAME", "test_db")
    os.environ.setdefault("JWT_SECRET", "test-only-secret")
    return pytest.importorskip("server")


def _endpoint_arqc(**kw):
    """Call the FastAPI handler directly, bypassing HTTP and auth."""
    import asyncio
    server = _server()
    body = server.ArqcRequest(**kw)
    return asyncio.run(server.keys_arqc(body, None))


def test_visa_cvn10_arqc_and_arpc_end_to_end():
    for _ in range(N):
        mdk, pan, psn = _rand(16), _pan(), _psn()
        tags, cvr, arc = _emv_tags(_rand(2)), _rand(4), _rand(2)
        card = cvn.VisaCVN10(mdk, _rand(16), _rand(16), pan, psn)
        ref_arqc = card.generate_ac(**tags, cvr=cvr)
        cdol = (b"".join(tags.values()) + cvr).hex()

        res = _endpoint_arqc(mdk_hex=mdk.hex(), pan=pan, psn=psn, cdol_hex=cdol, cvn="CVN10")
        assert res["arqc_hex"] == ref_arqc.hex().upper(), (pan, psn)
        assert res["f55_tlv_hex"] == "9F2608" + ref_arqc.hex().upper()

        ref_arpc = card.generate_arpc(ref_arqc, arc).hex().upper()
        assert km.compute_arpc(res["session_key_hex"], res["arqc_hex"], arc.hex(), "3DES") == ref_arpc


def test_visa_cvn18_arqc_end_to_end():
    for _ in range(N):
        mdk, pan, psn, atc = _rand(16), _pan(), _psn(), _rand(2)
        tags, iad = _emv_tags(atc), _rand(32)
        card = cvn.VisaCVN18(mdk, _rand(16), _rand(16), pan, psn)
        ref_arqc = card.generate_ac(**tags, tag_9f10=iad)
        cdol = (b"".join(tags.values()) + iad).hex()

        res = _endpoint_arqc(mdk_hex=mdk.hex(), pan=pan, psn=psn, cdol_hex=cdol,
                             cvn="CVN18", atc_hex=atc.hex())
        assert res["arqc_hex"] == ref_arqc.hex().upper(), (pan, psn)


# ---------------------------------------------------------------------------
# ARPC / F55 tag 91 encoding
# ---------------------------------------------------------------------------
def test_arpc_method1_matches_pyemv():
    for _ in range(N):
        sk, arqc, arc = _rand(16), _rand(8), _rand(2)
        assert km.compute_arpc(sk.hex(), arqc.hex(), arc.hex(), "3DES") \
            == ac.generate_arpc_1(sk, arqc, arc).hex().upper()


@pytest.mark.parametrize("algo,key_len", [("3DES", 16), ("AES", 16), ("AES", 32)])
def test_arpc_tag91_length_is_consistent(algo, key_len):
    import asyncio
    server = _server()
    body = server.ArpcRequest(sk_hex=_rand(key_len).hex(), arqc_hex=_rand(8).hex(),
                              arc_hex="3030", algorithm=algo)
    res = asyncio.run(server.keys_arpc(body, None))
    tlv = res["f55_tlv_hex"]
    assert tlv[:2] == "91"
    declared = int(tlv[2:4], 16)
    assert declared * 2 == len(tlv) - 4          # length byte matches the value
    assert 8 <= declared <= 16                   # EMV limit for tag 91
    assert tlv.endswith("3030")
