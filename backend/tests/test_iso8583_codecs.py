"""Pure-codec unit tests for iso8583 encoder/decoder.

Run alongside the API tests: `pytest -q tests/`.
These tests do not require the FastAPI server; they exercise the
in-process encoder/decoder for ASCII and native wire formats and
specifically guard against the secondary-bitmap regression where a
bit-1 primary bitmap caused `secondary bitmap truncated` errors in
ASCII decode mode.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from iso8583 import encode_message, decode_message


SAMPLE_DE = {
    "2": "4111111111111111",
    "3": "000000",
    "4": "000000010000",
    "7": "0226140000",
    "11": "012345",
    "41": "TERM0001",
    "49": "840",
}


def test_ascii_roundtrip_visa():
    hex_msg, _ = encode_message("0200", SAMPLE_DE, "visa", wire_format="ascii")
    parsed = decode_message(hex_msg, "visa", wire_format="ascii")
    assert parsed["mti"] == "0200"
    fields = {f["field"]: f["value"] for f in parsed["fields"]}
    assert fields[2] == "4111111111111111"
    assert fields[41] == "TERM0001"
    assert fields[49] == "840"


def test_native_roundtrip_visa():
    hex_msg, _ = encode_message("0200", SAMPLE_DE, "visa", wire_format="native")
    parsed = decode_message(hex_msg, "visa", wire_format="native")
    assert parsed["mti"] == "0200"
    fields = {f["field"]: f["value"] for f in parsed["fields"]}
    assert fields[2] == "4111111111111111"
    assert fields[7] == "0226140000"


def test_ascii_decode_with_secondary_bitmap():
    """Regression: real 0810 echo response from emergent issuer simulator
    sets bit 1 (secondary bitmap) and bit 70. The previous decoder raised
    `secondary bitmap truncated` because it fed only the primary 8 bytes
    to the binary helper.
    """
    ascii_payload = "081082200000020000000400000000000000022614000000000100301"
    hex_msg = ascii_payload.encode("ascii").hex()
    parsed = decode_message(hex_msg, "visa", wire_format="ascii")
    assert parsed["mti"] == "0810"
    assert parsed["active_fields"] == [7, 11, 39, 70]
    # bitmap_hex should be 32 hex chars (primary + secondary)
    assert len(parsed["bitmap_hex"]) == 32
    f = {x["field"]: x["value"] for x in parsed["fields"]}
    assert f[39] == "00"
    assert f[70] == "301"


def test_ascii_echo_request_encode():
    """An 0800 ECHO with F70=301 encodes to a payload whose ASCII MTI is '0800'."""
    de = {"7": "0226140000", "11": "000001", "70": "301"}
    hex_msg, _ = encode_message("0800", de, "visa", wire_format="ascii")
    payload = bytes.fromhex(hex_msg).decode("ascii", errors="replace")
    assert payload.startswith("0800")
    # Bitmap (16 hex chars) right after MTI – primary only since F70 is in secondary,
    # so bit 1 (secondary indicator) MUST be set in the primary bitmap.
    primary_hex = payload[4:20]
    assert int(primary_hex[0], 16) & 0x8, f"primary bitmap missing secondary flag: {primary_hex}"
