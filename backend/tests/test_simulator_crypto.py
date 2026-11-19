"""Simulator acting as issuer: cryptogram checks driven by a key set.

Every cryptogram here is produced independently with pyemv / psec, sent through
iso8583.simulate_response with a key set, and the verdicts and response codes
are checked. Pure unit tests: no server or database needed.
"""
import random
import sys
import warnings
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
warnings.filterwarnings("ignore", message=".*TripleDES.*")

import iso8583  # noqa: E402
import sim_crypto  # noqa: E402

pyemv = pytest.importorskip("pyemv")
psec = pytest.importorskip("psec")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from pyemv import cvn  # noqa: E402
from psec import pinblock  # noqa: E402

RNG = random.Random(4242)


def _rand(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


def _digits(n):
    return "".join(RNG.choice("0123456789") for _ in range(n))


@pytest.fixture(autouse=True)
def no_random_decline(monkeypatch):
    """The simulator declines ~10% of clean transactions at random; switch that off."""
    monkeypatch.setattr(iso8583.random, "choices", lambda seq, k=1: ["00"])


def _tlv(tag, value: bytes):
    return f"{tag}{len(value):02X}{value.hex().upper()}"


class Card:
    """A test card with issuer keys and an independently generated transaction."""

    def __init__(self, cvn_name="CVN10", pan_len=16):
        self.mdk = _rand(16)
        self.cvk = (_rand(8), _rand(8))
        self.pvk = (_rand(8), _rand(8))
        self.zpk = _rand(16)
        self.pan = _digits(pan_len)
        self.psn = f"{RNG.randint(0, 9):02d}"
        self.pin = _digits(4)
        self.pvki = "1"
        self.expiry = "3012"
        self.cvn = cvn_name
        self.keyset = {
            "mdk_hex": self.mdk.hex().upper(),
            "cvk_a_hex": self.cvk[0].hex(), "cvk_b_hex": self.cvk[1].hex(),
            "pvk_a_hex": self.pvk[0].hex(), "pvk_b_hex": self.pvk[1].hex(),
            "pvki": self.pvki, "extras": {"ZPK": self.zpk.hex().upper()},
        }

    def track2(self, chip=True, cvv=None, pvv=None):
        svc = "201"
        pvv = pvv or psec.pin.generate_visa_pvv(self.pvk[0] + self.pvk[1], self.pvki, self.pin, self.pan)
        cvv = cvv or psec.cvv.generate_cvv(self.cvk[0] + self.cvk[1], self.pan, self.expiry,
                                           "999" if chip else svc)
        return f"{self.pan}D{self.expiry}{svc}{self.pvki}{pvv}{cvv}000"

    def pin_block(self, pin=None, key=None):
        key = key or self.zpk
        clear = pinblock.encode_pinblock_iso_0(pin or self.pin, self.pan)
        return Cipher(algorithms.TripleDES(key + key[:8]), modes.ECB()).encryptor().update(clear).hex().upper()

    def icc(self, tamper=False):
        atc = _rand(2)
        tags = dict(tag_9f02=bytes.fromhex("000000001000"), tag_9f03=bytes(6), tag_9f1a=bytes.fromhex("0840"),
                    tag_95=bytes(5), tag_5f2a=bytes.fromhex("0840"), tag_9a=bytes.fromhex("261119"),
                    tag_9c=bytes(1), tag_9f37=_rand(4), tag_82=bytes.fromhex("1800"), tag_9f36=atc)
        if self.cvn == "CVN10":
            iad = bytes.fromhex("06010A03A00000")
            card = cvn.VisaCVN10(self.mdk, _rand(16), _rand(16), self.pan, self.psn)
            arqc = card.generate_ac(**tags, cvr=iad[3:7])
        else:
            iad = bytes.fromhex("06011203A00000")
            card = cvn.VisaCVN18(self.mdk, _rand(16), _rand(16), self.pan, self.psn)
            arqc = card.generate_ac(**tags, tag_9f10=iad)
        if tamper:
            arqc = bytes([arqc[0] ^ 1]) + arqc[1:]
        self.card, self.arqc, self.atc = card, arqc, atc
        out = _tlv("9F26", arqc) + _tlv("9F10", iad) + _tlv("5F34", bytes.fromhex(self.psn))
        for k, v in tags.items():
            out += _tlv(k[4:].upper(), v)
        return out

    def message(self, **over):
        de = {"2": self.pan, "3": "000000", "4": "000000001000", "11": "000123", "14": self.expiry,
              "35": self.track2(), "41": "TERM0001", "49": "840",
              "52": self.pin_block(), "55": self.icc()}
        de.update(over)
        return {k: v for k, v in de.items() if v is not None}


def _sim(card, de, keyset="default"):
    ks = card.keyset if keyset == "default" else keyset
    _, meta = iso8583.simulate_response("0100", de, "visa", ks)
    return meta


def _checks(meta):
    return {c["check"]: c["result"] for c in meta["crypto_checks"]}


def _field(meta, n):
    return next((f["value"] for f in meta["fields"] if f["field"] == n), None)


# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cvn_name,pan_len", [("CVN10", 16), ("CVN18", 16), ("CVN18", 19)])
def test_all_checks_pass_and_arpc_returned(cvn_name, pan_len):
    for _ in range(20):
        c = Card(cvn_name, pan_len)
        meta = _sim(c, c.message())
        assert meta["response_code"] == "00", meta["crypto_checks"]
        assert set(_checks(meta).values()) == {"pass"}
        arpc_tlv = _field(meta, 55)
        if cvn_name == "CVN10":
            ref = c.card.generate_arpc(c.arqc, b"00").hex().upper()
            assert arpc_tlv.upper() == "910A" + ref + "3030"
        else:
            ref = c.card.generate_arpc(c.arqc, c.atc, bytes(4)).hex().upper()
            assert arpc_tlv.upper() == "9108" + ref + "00000000"


def test_bad_arqc_declines_82():
    c = Card("CVN10")
    de = c.message()
    de["55"] = c.icc(tamper=True)
    meta = _sim(c, de)
    assert meta["response_code"] == "82" and _checks(meta)["ARQC (F55)"] == "fail"
    assert _field(meta, 55) is None


def test_bad_icvv_declines_82():
    c = Card()
    good = c.track2()
    cvv = good[-6:-3]
    bad = good[:-6] + f"{(int(cvv) + 1) % 1000:03d}" + "000"
    meta = _sim(c, c.message(**{"35": bad}))
    assert meta["response_code"] == "82" and _checks(meta)["CVV (track 2)"] == "fail"


def test_magstripe_uses_cvv1_not_icvv():
    c = Card()
    t2 = c.track2(chip=False)
    meta = _sim(c, c.message(**{"35": t2, "55": None}))
    assert _checks(meta)["CVV (track 2)"] == "pass" and meta["response_code"] == "00"
    # An iCVV on a magstripe (no F55) transaction must not pass.
    meta = _sim(c, c.message(**{"35": c.track2(chip=True), "55": None}))
    assert _checks(meta)["CVV (track 2)"] == "fail"


def test_wrong_pin_declines_55():
    c = Card()
    wrong = f"{(int(c.pin) + 1) % 10000:04d}"
    meta = _sim(c, c.message(**{"52": c.pin_block(pin=wrong)}))
    assert meta["response_code"] == "55" and _checks(meta)["PIN / PVV (F52)"] == "fail"


def test_pin_block_under_wrong_key_declines_81():
    c = Card()
    meta = _sim(c, c.message(**{"52": c.pin_block(key=_rand(16))}))
    assert meta["response_code"] in ("81", "55")   # wrong key usually breaks the block structure
    assert _checks(meta)["PIN / PVV (F52)"] == "fail"


def test_arqc_failure_takes_precedence():
    c = Card()
    wrong = f"{(int(c.pin) + 1) % 10000:04d}"
    de = c.message(**{"52": c.pin_block(pin=wrong)})
    de["55"] = c.icc(tamper=True)
    assert _sim(c, de)["response_code"] == "82"


def test_missing_keys_are_skipped_not_failed():
    c = Card()
    meta = _sim(c, c.message(), keyset={"mdk_hex": c.keyset["mdk_hex"]})
    r = _checks(meta)
    assert r == {"ARQC (F55)": "pass", "CVV (track 2)": "skipped", "PIN / PVV (F52)": "skipped"}
    assert meta["response_code"] == "00"


def test_missing_emv_tags_is_format_error():
    c = Card()
    de = c.message(**{"55": "9F2608" + _rand(8).hex()})
    meta = _sim(c, de)
    assert meta["response_code"] == "30" and "missing" in meta["crypto_checks"][0]["detail"]


def test_unsupported_cvn_is_format_error():
    c = Card()
    de = c.message()
    de["55"] = de["55"].replace("9F100706010A03A00000", "9F100706011603A00000")  # CVN 22
    meta = _sim(c, de)
    assert meta["response_code"] == "30" and "unsupported" in meta["crypto_checks"][0]["detail"]


def test_no_keyset_means_no_checks():
    c = Card()
    _, meta = iso8583.simulate_response("0100", c.message(), "visa", None)
    assert "crypto_checks" not in meta and meta["response_code"] == "00"


def test_network_management_is_not_checked():
    c = Card()
    _, meta = iso8583.simulate_response("0800", {"7": "1119120000", "11": "000001", "70": "301"}, "visa", c.keyset)
    assert meta["response_code"] == "00" and meta["crypto_checks"] == []


def test_parse_track2_and_tlv():
    t = sim_crypto.parse_track2(";4111111111111111=30122011123456789000?")
    assert t["pan"] == "4111111111111111" and t["service_code"] == "201"
    assert (t["pvki"], t["pvv"], t["cvv"]) == ("1", "1234", "567")
    assert sim_crypto.parse_tlv("9F2603AABBCC9503112233") == {"9F26": "AABBCC", "95": "112233"}
    with pytest.raises(ValueError):
        sim_crypto.parse_tlv("9F2608AABB")


def test_keyset_rejected_for_non_simulator_target():
    import asyncio
    import os
    from fastapi import HTTPException
    os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
    os.environ.setdefault("DB_NAME", "test_db")
    os.environ.setdefault("JWT_SECRET", "test-only-secret")
    server = pytest.importorskip("server")
    with pytest.raises(HTTPException) as e:
        asyncio.run(server._load_keyset({"id": "u1"}, "ks1", "some-connection-id"))
    assert e.value.status_code == 400
    assert asyncio.run(server._load_keyset({"id": "u1"}, None, "some-connection-id")) is None
