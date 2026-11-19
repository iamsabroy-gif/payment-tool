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


# ---------------------------------------------------------------------------
# ARPC Method 2 (Visa CVN18)
# ---------------------------------------------------------------------------
def test_vector_arpc_method2_pyemv_doc():
    assert km.compute_arpc_method2("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "1234567890ABCDEF", "00000000") \
        == "9308BEBC"


def test_arpc_method2_matches_pyemv():
    for _ in range(N):
        sk, arqc, csu = _rand(16), _rand(8), _rand(4)
        pad = _rand(RNG.randint(0, 8))
        assert km.compute_arpc_method2(sk.hex(), arqc.hex(), csu.hex(), pad.hex()) \
            == ac.generate_arpc_2(sk, arqc, csu, pad).hex().upper(), len(pad)


def _endpoint_arpc(**kw):
    import asyncio
    server = _server()
    return asyncio.run(server.keys_arpc(server.ArpcRequest(**kw), None))


def test_visa_cvn18_arqc_then_arpc2_end_to_end():
    """Issuer flow: ARQC endpoint gives the session key, ARPC endpoint answers with Method 2."""
    for _ in range(N // 4):
        mdk, pan, psn, atc = _rand(16), _pan(), _psn(), _rand(2)
        tags, iad = _emv_tags(atc), _rand(32)
        csu, pad = _rand(4), _rand(RNG.randint(0, 8))
        card = cvn.VisaCVN18(mdk, _rand(16), _rand(16), pan, psn)
        ref_arqc = card.generate_ac(**tags, tag_9f10=iad)
        ref_arpc = card.generate_arpc(ref_arqc, atc, csu, pad).hex().upper()

        q = _endpoint_arqc(mdk_hex=mdk.hex(), pan=pan, psn=psn, cvn="CVN18", atc_hex=atc.hex(),
                           cdol_hex=(b"".join(tags.values()) + iad).hex())
        r = _endpoint_arpc(sk_hex=q["session_key_hex"], arqc_hex=q["arqc_hex"], method=2,
                           csu_hex=csu.hex(), pad_hex=pad.hex())
        assert r["arpc_hex"] == ref_arpc
        value = ref_arpc + csu.hex().upper() + pad.hex().upper()
        assert r["f55_tlv_hex"] == f"91{len(value) // 2:02X}{value}"
        assert 8 <= len(value) // 2 <= 16


@pytest.mark.parametrize("kw,msg", [
    (dict(csu_hex=None), "CSU is required"),
    (dict(csu_hex="0000"), "CSU must be 4 bytes"),
    (dict(csu_hex="00000000", pad_hex="00" * 9), "0-8 bytes"),
    (dict(csu_hex="00000000", algorithm="AES"), "only supported with 3DES"),
    (dict(csu_hex="00000000", method=3), "method must be 1 or 2"),
])
def test_arpc_method2_rejects_bad_input(kw, msg):
    from fastapi import HTTPException
    args = dict(sk_hex="0123456789ABCDEFFEDCBA9876543210", arqc_hex="1234567890ABCDEF", method=2) | kw
    with pytest.raises(HTTPException) as e:
        _endpoint_arpc(**args)
    assert e.value.status_code == 400 and msg in e.value.detail


# ---------------------------------------------------------------------------
# PIN block decryption (pin_crypto) vs psec
# ---------------------------------------------------------------------------
import pin_crypto  # noqa: E402
from psec import pinblock as psec_pb  # noqa: E402


@pytest.mark.parametrize("fmt", ["ISO-0", "ISO-3"])
def test_clear_pin_block_decode_matches_psec(fmt):
    enc = psec_pb.encode_pinblock_iso_0 if fmt == "ISO-0" else psec_pb.encode_pinblock_iso_3
    for _ in range(N):
        pan, pin = _digits(16), _digits(RNG.randint(4, 12))
        assert pin_crypto.decode_clear_pin_block(enc(pin, pan).hex(), pan, fmt) == pin


@pytest.mark.parametrize("fmt", ["ISO-0", "ISO-1", "ISO-3"])
@pytest.mark.parametrize("algo,key_len", [("3DES", 16), ("3DES", 24), ("AES", 16)])
def test_pin_block_encrypt_decrypt_roundtrip(fmt, algo, key_len):
    for _ in range(50):
        pan, pin, key = _digits(16), _digits(RNG.randint(4, 12)), _rand(key_len).hex()
        _, enc = pin_crypto.encrypt_pin_block(pin, pan, key, fmt, algo)
        assert pin_crypto.decrypt_pin_block(enc, pan, key, fmt, algo) == pin


def test_pin_block_wrong_key_or_pan_is_rejected():
    pan, key = "4111111111111111", "0123456789ABCDEFFEDCBA9876543210"
    _, enc = pin_crypto.encrypt_pin_block("1234", pan, key, "ISO-0", "3DES")
    with pytest.raises(ValueError):
        pin_crypto.decrypt_pin_block(enc, pan, "FEDCBA9876543210" + "0123456789ABCDEF", "ISO-0", "3DES")
    with pytest.raises(ValueError):
        pin_crypto.decrypt_pin_block(enc, "5500000000000004", key, "ISO-0", "3DES")


# ---------------------------------------------------------------------------
# Verification endpoints
# ---------------------------------------------------------------------------
def _call(handler, model, **kw):
    import asyncio
    server = _server()
    return asyncio.run(getattr(server, handler)(getattr(server, model)(**kw), None))


def _wrong_digit(s):
    i = RNG.randrange(len(s))
    return s[:i] + str((int(s[i]) + RNG.randint(1, 9)) % 10) + s[i + 1:]


def test_cvv_verify_endpoint():
    for _ in range(N // 2):
        a, b = _rand(8), _rand(8)
        pan, exp, svc = _pan(), f"{RNG.randint(0, 99):02d}{RNG.randint(1, 12):02d}", RNG.choice(["101", "000", "999"])
        good = psec.cvv.generate_cvv(a + b, pan, exp, svc)
        args = dict(pan=pan, expiry=exp, service_code=svc, cvk_a_hex=a.hex(), cvk_b_hex=b.hex())
        assert _call("keys_cvv_verify", "CvvVerifyRequest", cvv=good, **args)["valid"] is True
        assert _call("keys_cvv_verify", "CvvVerifyRequest", cvv=_wrong_digit(good), **args)["valid"] is False


def test_pvv_verify_endpoint_clear_pin():
    for _ in range(N // 2):
        a, b = _rand(8), _rand(8)
        pan, pin, pvki = _pan(), _digits(4), str(RNG.randint(0, 9))
        pvv = psec.pin.generate_visa_pvv(a + b, pvki, pin, pan)
        args = dict(pan=pan, pvki=pvki, pvv=pvv, pvk_a_hex=a.hex(), pvk_b_hex=b.hex())
        r = _call("keys_pvv_verify", "PvvVerifyRequest", pin=pin, **args)
        assert r["valid"] is True and r["pin_source"] == "clear"
        assert _call("keys_pvv_verify", "PvvVerifyRequest", pin=_wrong_digit(pin), **args)["valid"] is False


@pytest.mark.parametrize("fmt", ["ISO-0", "ISO-3"])
def test_pvv_verify_endpoint_pin_block(fmt):
    """PIN block built and encrypted independently with psec, then verified by the endpoint."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms as alg, modes
    enc = psec_pb.encode_pinblock_iso_0 if fmt == "ISO-0" else psec_pb.encode_pinblock_iso_3
    for _ in range(N // 4):
        a, b, pek = _rand(8), _rand(8), _rand(16)
        pan, pin, pvki = _digits(16), _digits(4), "1"
        clear = enc(pin, pan)
        block = Cipher(alg.TripleDES(pek + pek[:8]), modes.ECB()).encryptor().update(clear).hex()
        pvv = psec.pin.generate_visa_pvv(a + b, pvki, pin, pan)
        args = dict(pan=pan, pvki=pvki, pvk_a_hex=a.hex(), pvk_b_hex=b.hex(),
                    pin_block_hex=block, pek_hex=pek.hex(), pin_format=fmt)
        r = _call("keys_pvv_verify", "PvvVerifyRequest", pvv=pvv, **args)
        assert r["valid"] is True and r["pin_source"] == "pin_block"
        assert _call("keys_pvv_verify", "PvvVerifyRequest", pvv=_wrong_digit(pvv), **args)["valid"] is False


def test_arqc_verify_endpoint_cvn10_and_cvn18():
    for _ in range(N // 4):
        mdk, pan, psn, atc = _rand(16), _pan(), _psn(), _rand(2)
        tags = _emv_tags(atc)
        cvr, iad = _rand(4), _rand(32)
        cases = [
            ("CVN10", cvn.VisaCVN10(mdk, _rand(16), _rand(16), pan, psn).generate_ac(**tags, cvr=cvr),
             b"".join(tags.values()) + cvr, None),
            ("CVN18", cvn.VisaCVN18(mdk, _rand(16), _rand(16), pan, psn).generate_ac(**tags, tag_9f10=iad),
             b"".join(tags.values()) + iad, atc.hex()),
        ]
        for name, arqc, data, atc_hex in cases:
            args = dict(mdk_hex=mdk.hex(), pan=pan, psn=psn, cdol_hex=data.hex(), cvn=name, atc_hex=atc_hex)
            ok = _call("keys_arqc_verify", "ArqcVerifyRequest", arqc_hex=arqc.hex(), **args)
            assert ok["valid"] is True and ok["session_key_hex"], name
            bad = bytes([arqc[0] ^ 0x01]) + arqc[1:]
            ko = _call("keys_arqc_verify", "ArqcVerifyRequest", arqc_hex=bad.hex(), **args)
            assert ko["valid"] is False and ko["session_key_hex"] is None, name


def test_verify_endpoints_never_return_expected_value():
    r = _call("keys_cvv_verify", "CvvVerifyRequest", pan="4123456789012345", expiry="8701",
              service_code="101", cvk_a_hex=CVK_A, cvk_b_hex=CVK_B, cvv="000")
    assert r["valid"] is False and "561" not in str(r)


@pytest.mark.parametrize("handler,model,kw,msg", [
    ("keys_cvv_verify", "CvvVerifyRequest", dict(pan="4123456789012345", expiry="8701", service_code="101",
                                                 cvk_a_hex=CVK_A, cvk_b_hex=CVK_B, cvv="56"), "3 digits"),
    ("keys_pvv_verify", "PvvVerifyRequest", dict(pan="4111111111111111", pvv="123", pvk_a_hex=CVK_A,
                                                 pvk_b_hex=CVK_B, pin="1234"), "4 digits"),
    ("keys_pvv_verify", "PvvVerifyRequest", dict(pan="4111111111111111", pvv="1234", pvk_a_hex=CVK_A,
                                                 pvk_b_hex=CVK_B), "Give pin or pin_block_hex"),
    ("keys_pvv_verify", "PvvVerifyRequest", dict(pan="4111111111111111", pvv="1234", pvk_a_hex=CVK_A,
                                                 pvk_b_hex=CVK_B, pin_block_hex="00" * 8), "pek_hex is required"),
    ("keys_pvv_verify", "PvvVerifyRequest", dict(pan="4111111111111111", pvv="1234", pvk_a_hex=CVK_A,
                                                 pvk_b_hex=CVK_B, pin="1234", pin_block_hex="00" * 8,
                                                 pek_hex=CVK_A + CVK_B), "not both"),
    ("keys_arqc_verify", "ArqcVerifyRequest", dict(mdk_hex=CVK_A + CVK_B, pan="4111111111111111",
                                                   cdol_hex="00", cvn="CVN18", arqc_hex="00" * 8), "ATC is required"),
])
def test_verify_endpoints_reject_bad_input(handler, model, kw, msg):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        _call(handler, model, **kw)
    assert e.value.status_code == 400 and msg in e.value.detail
