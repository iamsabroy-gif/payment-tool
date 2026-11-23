"""ISO-8583:1987 encoder / decoder with **full network fidelity**.

Per-network specs control:
  - MTI encoding (BCD vs ASCII)
  - Bitmap encoding (binary vs ASCII-hex)
  - Per-field encoding (BCD numeric, EBCDIC ans, ASCII ans, raw binary, track2)
  - Variable length prefix encoding (BCD vs ASCII)
  - Mandatory-field validation per MTI

User-facing data elements stay as **ASCII strings** in JSON (PAN "4111…", amount "000000012500",
auth code "512904"). The wire bytes are encoded according to the spec, and on decode they are
converted back to ASCII for display in the Log Viewer.
"""
from __future__ import annotations
from typing import Dict, List, Optional, Tuple
import random

from iso8583_codecs import (
    bcd_encode, bcd_decode, bcd_length_prefix, bcd_decode_length,
    ebcdic_encode, ebcdic_decode,
    binary_bitmap_encode, binary_bitmap_decode,
    track2_encode, track2_decode,
    parse_tlv,
)


# ===========================================================================
# Field catalogue (ISO-8583:1987 base)
# Each field defines:
#   format        : "n" | "an" | "ans" | "b" | "z"
#   length_type   : "fixed" | "LLVAR" | "LLLVAR"
#   max_length    : decimal digits (n) or characters (an/ans) or bytes (b)
# Networks override with `encoding` (bcd/ebcdic/ascii/binary/track2) and
# `length_encoding` (bcd/ascii) for variable fields, plus name overrides.
# ===========================================================================
BASE_FIELDS: Dict[int, Dict] = {
    2:  {"name": "Primary Account Number (PAN)",     "format": "n",   "length_type": "LLVAR",  "max_length": 19},
    3:  {"name": "Processing Code",                   "format": "n",   "length_type": "fixed",  "max_length": 6},
    4:  {"name": "Amount, Transaction",               "format": "n",   "length_type": "fixed",  "max_length": 12},
    5:  {"name": "Amount, Settlement",                "format": "n",   "length_type": "fixed",  "max_length": 12},
    6:  {"name": "Amount, Cardholder Billing",        "format": "n",   "length_type": "fixed",  "max_length": 12},
    7:  {"name": "Transmission Date & Time",          "format": "n",   "length_type": "fixed",  "max_length": 10},
    9:  {"name": "Conversion Rate, Settlement",       "format": "n",   "length_type": "fixed",  "max_length": 8},
    10: {"name": "Conversion Rate, Cardholder",       "format": "n",   "length_type": "fixed",  "max_length": 8},
    11: {"name": "System Trace Audit Number (STAN)",  "format": "n",   "length_type": "fixed",  "max_length": 6},
    12: {"name": "Time, Local Transaction",           "format": "n",   "length_type": "fixed",  "max_length": 6},
    13: {"name": "Date, Local Transaction",           "format": "n",   "length_type": "fixed",  "max_length": 4},
    14: {"name": "Date, Expiration",                  "format": "n",   "length_type": "fixed",  "max_length": 4},
    15: {"name": "Date, Settlement",                  "format": "n",   "length_type": "fixed",  "max_length": 4},
    16: {"name": "Date, Conversion",                  "format": "n",   "length_type": "fixed",  "max_length": 4},
    17: {"name": "Date, Capture",                     "format": "n",   "length_type": "fixed",  "max_length": 4},
    18: {"name": "Merchant Type (MCC)",               "format": "n",   "length_type": "fixed",  "max_length": 4},
    19: {"name": "Acquiring Country Code",            "format": "n",   "length_type": "fixed",  "max_length": 3},
    22: {"name": "POS Entry Mode",                    "format": "n",   "length_type": "fixed",  "max_length": 3},
    23: {"name": "Card Sequence Number",              "format": "n",   "length_type": "fixed",  "max_length": 3},
    24: {"name": "Network International ID (NII)",    "format": "n",   "length_type": "fixed",  "max_length": 3},
    25: {"name": "POS Condition Code",                "format": "n",   "length_type": "fixed",  "max_length": 2},
    26: {"name": "POS PIN Capture Code",              "format": "n",   "length_type": "fixed",  "max_length": 2},
    28: {"name": "Amount, Transaction Fee",           "format": "an",  "length_type": "fixed",  "max_length": 9},
    32: {"name": "Acquiring Institution ID",          "format": "n",   "length_type": "LLVAR",  "max_length": 11},
    33: {"name": "Forwarding Institution ID",         "format": "n",   "length_type": "LLVAR",  "max_length": 11},
    35: {"name": "Track 2 Data",                      "format": "z",   "length_type": "LLVAR",  "max_length": 37},
    37: {"name": "Retrieval Reference Number (RRN)",  "format": "an",  "length_type": "fixed",  "max_length": 12},
    38: {"name": "Authorization ID Response",         "format": "an",  "length_type": "fixed",  "max_length": 6},
    39: {"name": "Response Code",                     "format": "an",  "length_type": "fixed",  "max_length": 2},
    41: {"name": "Card Acceptor Terminal ID",         "format": "ans", "length_type": "fixed",  "max_length": 8},
    42: {"name": "Card Acceptor ID Code",             "format": "ans", "length_type": "fixed",  "max_length": 15},
    43: {"name": "Card Acceptor Name/Location",       "format": "ans", "length_type": "fixed",  "max_length": 40},
    44: {"name": "Additional Response Data",          "format": "an",  "length_type": "LLVAR",  "max_length": 25},
    45: {"name": "Track 1 Data",                      "format": "an",  "length_type": "LLVAR",  "max_length": 76},
    48: {"name": "Additional Data (Private)",         "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    49: {"name": "Currency Code, Transaction",        "format": "n",   "length_type": "fixed",  "max_length": 3},
    50: {"name": "Currency Code, Settlement",         "format": "n",   "length_type": "fixed",  "max_length": 3},
    51: {"name": "Currency Code, Cardholder",         "format": "n",   "length_type": "fixed",  "max_length": 3},
    52: {"name": "PIN Data",                          "format": "b",   "length_type": "fixed",  "max_length": 8},
    53: {"name": "Security Related Control Info",     "format": "n",   "length_type": "fixed",  "max_length": 16},
    54: {"name": "Additional Amounts",                "format": "an",  "length_type": "LLLVAR", "max_length": 120},
    55: {"name": "ICC / EMV Data",                    "format": "b",   "length_type": "LLLVAR", "max_length": 999},
    56: {"name": "Reserved (ISO)",                    "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    57: {"name": "Reserved (National)",               "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    58: {"name": "Reserved (National)",               "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    59: {"name": "Reserved (National)",               "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    60: {"name": "Advice/Reason Code",                "format": "n",   "length_type": "LLLVAR", "max_length": 999},
    61: {"name": "POS Data",                          "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    62: {"name": "Private Use",                       "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    63: {"name": "Private Use",                       "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    64: {"name": "Message Authentication Code (MAC)", "format": "b",   "length_type": "fixed",  "max_length": 8},
    70: {"name": "Network Management Info Code",      "format": "n",   "length_type": "fixed",  "max_length": 3},
    90: {"name": "Original Data Elements",            "format": "n",   "length_type": "fixed",  "max_length": 42},
    95: {"name": "Replacement Amounts",               "format": "an",  "length_type": "fixed",  "max_length": 42},
    100:{"name": "Receiving Institution ID",          "format": "n",   "length_type": "LLVAR",  "max_length": 11},
    102:{"name": "Account Identification 1",          "format": "ans", "length_type": "LLVAR",  "max_length": 28},
    103:{"name": "Account Identification 2",          "format": "ans", "length_type": "LLVAR",  "max_length": 28},
    120:{"name": "Record Data",                       "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    122:{"name": "Additional Record Data",            "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    123:{"name": "POS Data Code",                     "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    125:{"name": "Supporting Info / New Addr.",       "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    126:{"name": "Private Use",                       "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    127:{"name": "Private Use",                       "format": "ans", "length_type": "LLLVAR", "max_length": 999},
    128:{"name": "Message Auth Code (Secondary)",     "format": "b",   "length_type": "fixed",  "max_length": 8},
}


# Default per-format encoding choices applied unless network overrides.
def _default_encoding(format_code: str, network_default_an_charset: str) -> str:
    return {
        "n":   "bcd",
        "an":  network_default_an_charset,
        "ans": network_default_an_charset,
        "b":   "binary",
        "z":   "track2",
    }.get(format_code, "ascii")


def _build_network_fields(an_charset: str, length_prefix_encoding: str, name_overrides: Dict[int, str]) -> Dict[int, Dict]:
    """Project BASE_FIELDS into a network-specific dict with `encoding` + `length_encoding`."""
    out: Dict[int, Dict] = {}
    for f, meta in BASE_FIELDS.items():
        cell = dict(meta)
        cell["encoding"] = _default_encoding(meta["format"], an_charset)
        cell["length_encoding"] = length_prefix_encoding
        if f in name_overrides:
            cell["name"] = name_overrides[f]
        out[f] = cell
    return out


# ===========================================================================
# Network specifications
# ===========================================================================
NETWORK_SPECS: Dict[str, Dict] = {
    "visa": {
        "network_id": "visa",
        "name": "VISA",
        "description": "VISA Base I — binary bitmap, BCD numeric, EBCDIC alphanumeric.",
        "mti_encoding": "bcd",
        "bitmap_encoding": "binary",
        "default_an_charset": "ebcdic",
        "length_prefix_encoding": "bcd",
        "builtin": True,
        "fields": _build_network_fields(
            "ebcdic", "bcd",
            {18: "Merchant Category Code (MCC)", 62: "VISA Private Use", 63: "VISA Network Data"},
        ),
    },
    "mastercard": {
        "network_id": "mastercard",
        "name": "Mastercard",
        "description": "Mastercard CIS / DE Profile — binary bitmap, BCD numeric, EBCDIC alphanumeric.",
        "mti_encoding": "bcd",
        "bitmap_encoding": "binary",
        "default_an_charset": "ebcdic",
        "length_prefix_encoding": "bcd",
        "builtin": True,
        "fields": _build_network_fields(
            "ebcdic", "bcd",
            {48: "Mastercard Additional Data", 61: "Mastercard POS Extended", 63: "Mastercard Network Data"},
        ),
    },
    "amex": {
        "network_id": "amex",
        "name": "American Express",
        "description": "AMEX GCAG — binary bitmap, BCD numeric, EBCDIC alphanumeric.",
        "mti_encoding": "bcd",
        "bitmap_encoding": "binary",
        "default_an_charset": "ebcdic",
        "length_prefix_encoding": "bcd",
        "builtin": True,
        "fields": _build_network_fields(
            "ebcdic", "bcd",
            {62: "AMEX Transaction Identifier", 63: "AMEX Reserved Private"},
        ),
    },
    "rupay": {
        "network_id": "rupay",
        "name": "RuPay",
        "description": "RuPay (NPCI) — binary bitmap, BCD numeric, ASCII alphanumeric (INR=356).",
        "mti_encoding": "bcd",
        "bitmap_encoding": "binary",
        "default_an_charset": "ascii",
        "length_prefix_encoding": "bcd",
        "builtin": True,
        "fields": _build_network_fields(
            "ascii", "bcd",
            {18: "MCC", 32: "Acquiring BIN", 49: "Currency (356 = INR)",
             61: "RuPay POS Extended", 62: "RuPay Invoice/Addendum", 63: "RuPay Network Private",
             123: "RuPay POS Data Code"},
        ),
    },
}


# ===========================================================================
# Mandatory fields per MTI per network
# ===========================================================================
_COMMON_MANDATORY = {
    "0100": {2, 3, 4, 7, 11, 41, 42, 49},
    "0110": {3, 4, 11, 39, 41},
    "0200": {2, 3, 4, 7, 11, 41, 42, 49},
    "0210": {3, 4, 11, 37, 39, 41},
    "0220": {2, 3, 4, 7, 11, 41, 42, 49},
    "0400": {2, 3, 4, 7, 11, 41, 42, 49},
    "0410": {3, 4, 11, 39, 41},
    "0420": {2, 3, 4, 7, 11, 41, 42, 49, 90},
    "0430": {3, 4, 11, 39, 41},
    "0500": {7, 11, 41},
    "0510": {7, 11, 39, 41},
    "0800": {7, 11, 70},
    "0810": {7, 11, 39, 70},
}
MANDATORY_PER_MTI: Dict[str, Dict[str, set]] = {
    "visa":       dict(_COMMON_MANDATORY),
    "mastercard": dict(_COMMON_MANDATORY),
    "amex":       dict(_COMMON_MANDATORY),
    "rupay":      dict(_COMMON_MANDATORY),
}


# ===========================================================================
# Runtime spec registry (user-defined specs are registered on demand)
# ===========================================================================
def register_runtime_spec(spec: Dict) -> None:
    """Insert a user-defined spec into the in-memory registry.

    Idempotent: same `network_id` overwrites previous entry. The caller
    is expected to provide a fully-built spec dict matching the shape of
    the entries in NETWORK_SPECS (i.e. with `fields` already projected).
    """
    nid = spec.get("network_id")
    if not nid:
        raise ValueError("spec missing network_id")
    NETWORK_SPECS[nid] = spec
    if "mandatory_per_mti" in spec:
        MANDATORY_PER_MTI[nid] = {
            mti: set(int(f) for f in fnums)
            for mti, fnums in spec["mandatory_per_mti"].items()
        }


def known_network_ids() -> List[str]:
    return list(NETWORK_SPECS.keys())


# ===========================================================================
# Encoder
# ===========================================================================
def _spec(network_id: str) -> Dict:
    return NETWORK_SPECS.get(network_id) or NETWORK_SPECS["visa"]


_ASCII_OVERRIDES = {
    "mti_encoding": "ascii",
    "bitmap_encoding": "ascii_hex",
    "default_an_charset": "ascii",
    "length_prefix_encoding": "ascii",
}


def _resolve_spec(network_id: str, wire_format: str = "native") -> Dict:
    """Return a spec view, optionally with ASCII-compat overrides applied."""
    base = _spec(network_id)
    if wire_format != "ascii":
        return base
    spec = dict(base)
    spec.update(_ASCII_OVERRIDES)
    fields = _build_network_fields(
        "ascii", "ascii",
        {f: meta["name"] for f, meta in base["fields"].items()},
    )
    # ASCII-compat additionally forces numeric fields to ASCII (not BCD).
    for f, meta in fields.items():
        if meta["format"] == "n":
            meta["encoding"] = "ascii"
    spec["fields"] = fields
    return spec


def _encode_field(value: str, meta: Dict) -> bytes:
    fmt = meta["format"]
    enc = meta["encoding"]
    length_type = meta["length_type"]
    length_enc = meta.get("length_encoding", "bcd")
    max_len = meta["max_length"]

    # Build the field body bytes
    if fmt == "n" and enc == "bcd":
        if length_type == "fixed":
            body = bcd_encode(value, max_len, justify="right")
        else:
            digits = "".join(c for c in value if c.isdigit())[:max_len]
            body = bcd_encode(digits, len(digits), justify="left")
            length_value = len(digits)
            return _length_prefix(length_value, length_type, length_enc) + body
    elif fmt == "an" and enc == "ebcdic" or fmt == "ans" and enc == "ebcdic":
        if length_type == "fixed":
            body = ebcdic_encode(value, max_len)
        else:
            v = value[:max_len]
            body = ebcdic_encode(v, len(v))
            return _length_prefix(len(v), length_type, length_enc) + body
    elif fmt in ("an", "ans") and enc == "ascii":
        if length_type == "fixed":
            body = (value or "").ljust(max_len)[:max_len].encode("ascii", errors="replace")
        else:
            v = (value or "")[:max_len]
            body = v.encode("ascii", errors="replace")
            return _length_prefix(len(v), length_type, length_enc) + body
    elif fmt == "b":
        # interpret value as hex string
        hex_s = "".join(c for c in (value or "") if c in "0123456789abcdefABCDEF")
        if length_type == "fixed":
            need = max_len * 2  # max_length is in bytes
            hex_s = hex_s.ljust(need, "0")[:need]
            body = bytes.fromhex(hex_s)
        else:
            if len(hex_s) % 2 == 1:
                hex_s += "0"
            body = bytes.fromhex(hex_s)[:max_len]
            return _length_prefix(len(body), length_type, length_enc) + body
    elif fmt == "z":
        # track2: BCD with D separator
        body = track2_encode(value or "")
        if length_type == "fixed":
            need = (max_len + 1) // 2
            body = body.ljust(need, b"\xff")[:need]
        else:
            return _length_prefix(len(value or ""), length_type, length_enc) + body
    elif fmt == "n" and enc == "ascii":
        if length_type == "fixed":
            body = (value or "").zfill(max_len)[:max_len].encode("ascii")
        else:
            v = "".join(c for c in (value or "") if c.isdigit())[:max_len]
            body = v.encode("ascii")
            return _length_prefix(len(v), length_type, length_enc) + body
    else:
        # Fallback: treat as ASCII
        body = (value or "").ljust(max_len)[:max_len].encode("ascii", errors="replace")

    return body


def _length_prefix(value: int, length_type: str, length_encoding: str) -> bytes:
    digits = 2 if length_type == "LLVAR" else 3
    if length_encoding == "ascii":
        return f"{value:0{digits}d}".encode("ascii")
    # bcd (default): 1 byte for LLVAR, 2 bytes for LLLVAR
    return bcd_length_prefix(value, digits)


def _decode_length_prefix(data: bytes, offset: int, length_type: str, length_encoding: str) -> Tuple[int, int]:
    digits = 2 if length_type == "LLVAR" else 3
    if length_encoding == "ascii":
        n_bytes = digits
        v = int(data[offset:offset + n_bytes].decode("ascii", errors="replace") or "0")
        return v, n_bytes
    n_bytes = (digits + 1) // 2  # 1 byte for 2-digit, 2 bytes for 3-digit
    v = bcd_decode_length(data[offset:offset + n_bytes], digits)
    return v, n_bytes


def encode_message(mti: str, data_elements: Dict[str, str], network_id: str = "visa", wire_format: str = "native") -> Tuple[str, Dict]:
    """Encode a message per network spec. Returns (raw_hex, parsed_meta).
    `wire_format`: 'native' (per-network binary/EBCDIC) or 'ascii' (full ASCII compat)."""
    if not (len(mti) == 4 and mti.isdigit()):
        raise ValueError("MTI must be 4 numeric digits")

    spec = _resolve_spec(network_id, wire_format)
    fields_spec = spec["fields"]

    normalised: Dict[int, str] = {}
    for k, v in (data_elements or {}).items():
        try:
            f = int(k)
        except (TypeError, ValueError):
            continue
        if v is None or v == "":
            continue
        normalised[f] = str(v)

    active_fields = sorted(normalised.keys())

    # MTI
    if spec["mti_encoding"] == "bcd":
        mti_bytes = bcd_encode(mti, 4, justify="right")
    else:
        mti_bytes = mti.encode("ascii")

    # Bitmap
    if spec["bitmap_encoding"] == "binary":
        bitmap_bytes = binary_bitmap_encode(active_fields)
    else:
        # ASCII-hex bitmap (legacy compat)
        bitmap_bytes = binary_bitmap_encode(active_fields).hex().upper().encode("ascii")

    # Fields
    encoded_meta: List[Dict] = []
    body_bytes = bytearray()
    for f in active_fields:
        meta = fields_spec.get(f)
        if meta is None:
            raise ValueError(f"field {f} not defined in {network_id} spec")
        chunk = _encode_field(normalised[f], meta)
        body_bytes.extend(chunk)
        encoded_meta.append({
            "field": f,
            "name": meta["name"],
            "value": normalised[f],
            "encoding": meta["encoding"],
            "length_type": meta["length_type"],
            "wire_bytes": len(chunk),
        })

    raw = bytes(mti_bytes) + bitmap_bytes + bytes(body_bytes)
    return raw.hex().upper(), {
        "mti": mti,
        "network_id": network_id,
        "bitmap_hex": bitmap_bytes.hex().upper() if isinstance(bitmap_bytes, (bytes, bytearray)) else bitmap_bytes,
        "active_fields": active_fields,
        "fields": encoded_meta,
        "wire_bytes": len(raw),
    }


# ===========================================================================
# Decoder
# ===========================================================================
def _decode_field(data: bytes, offset: int, meta: Dict) -> Tuple[str, int, dict]:
    fmt = meta["format"]
    enc = meta["encoding"]
    length_type = meta["length_type"]
    length_enc = meta.get("length_encoding", "bcd")
    max_len = meta["max_length"]
    extras: dict = {}

    if length_type != "fixed":
        length_value, prefix_size = _decode_length_prefix(data, offset, length_type, length_enc)
        offset += prefix_size
    else:
        length_value = max_len
        prefix_size = 0

    if fmt == "n" and enc == "bcd":
        if length_type == "fixed":
            body_size = (max_len + 1) // 2
            value = bcd_decode(data[offset:offset + body_size], max_len, justify="right")
        else:
            body_size = (length_value + 1) // 2
            value = bcd_decode(data[offset:offset + body_size], length_value, justify="left")
    elif fmt in ("an", "ans") and enc == "ebcdic":
        body_size = max_len if length_type == "fixed" else length_value
        value = ebcdic_decode(data[offset:offset + body_size])
    elif fmt in ("an", "ans") and enc == "ascii":
        body_size = max_len if length_type == "fixed" else length_value
        value = data[offset:offset + body_size].decode("ascii", errors="replace").rstrip()
    elif fmt == "n" and enc == "ascii":
        body_size = max_len if length_type == "fixed" else length_value
        value = data[offset:offset + body_size].decode("ascii", errors="replace").lstrip("0") or "0"
    elif fmt == "b":
        body_size = max_len if length_type == "fixed" else length_value
        value = data[offset:offset + body_size].hex().upper()
        if meta.get("name", "").startswith("ICC") or meta.get("field") == 55:
            try:
                extras["tlv"] = parse_tlv(data[offset:offset + body_size])
            except Exception:
                pass
    elif fmt == "z":
        body_size = (length_value + 1) // 2 if length_type != "fixed" else (max_len + 1) // 2
        value = track2_decode(data[offset:offset + body_size])
    else:
        body_size = max_len if length_type == "fixed" else length_value
        value = data[offset:offset + body_size].decode("latin-1", errors="replace")

    return value, prefix_size + body_size, extras


def decode_message(raw_hex: str, network_id: str = "visa", wire_format: str = "native") -> Dict:
    spec = _resolve_spec(network_id, wire_format)
    fields_spec = spec["fields"]
    data = bytes.fromhex(raw_hex)
    pos = 0

    # MTI
    if spec["mti_encoding"] == "bcd":
        mti = bcd_decode(data[pos:pos + 2], 4, justify="right")
        pos += 2
    else:
        mti = data[pos:pos + 4].decode("ascii", errors="replace")
        pos += 4

    # Bitmap
    if spec["bitmap_encoding"] == "binary":
        active_fields, consumed = binary_bitmap_decode(data, pos)
        bitmap_hex = data[pos:pos + consumed].hex().upper()
        pos += consumed
    else:
        # ASCII hex — peek primary first, then maybe read secondary,
        # then run the binary decoder over the combined bytes.
        primary_hex = data[pos:pos + 16].decode("ascii", errors="replace")
        pos += 16
        primary_bytes = bytes.fromhex(primary_hex)
        has_secondary = bool(primary_bytes[0] & 0x80)
        bitmap_hex = primary_hex
        combined = primary_bytes
        if has_secondary:
            secondary_hex = data[pos:pos + 16].decode("ascii", errors="replace")
            pos += 16
            combined = primary_bytes + bytes.fromhex(secondary_hex)
            bitmap_hex += secondary_hex
        active_fields, _ = binary_bitmap_decode(combined, 0)

    parsed_fields: List[Dict] = []
    for f in active_fields:
        meta = fields_spec.get(f)
        if not meta:
            break
        try:
            value, consumed, extras = _decode_field(data, pos, meta)
        except Exception as e:
            parsed_fields.append({"field": f, "name": meta.get("name"), "error": str(e)})
            break
        pos += consumed
        entry = {
            "field": f,
            "name": meta["name"],
            "format": meta["format"],
            "encoding": meta["encoding"],
            "length_type": meta["length_type"],
            "value": value,
        }
        entry.update(extras)
        parsed_fields.append(entry)

    return {
        "mti": mti,
        "network_id": network_id,
        "bitmap_hex": bitmap_hex,
        "active_fields": active_fields,
        "fields": parsed_fields,
    }


# ===========================================================================
# Validation
# ===========================================================================
def validate_message(mti: str, data_elements: Dict[str, str], network_id: str = "visa") -> List[str]:
    errors: List[str] = []
    if not (len(mti) == 4 and mti.isdigit()):
        errors.append("MTI must be 4 numeric digits.")
        return errors

    spec = _spec(network_id)
    fields_spec = spec["fields"]
    mandatory = MANDATORY_PER_MTI.get(network_id, {}).get(mti, set())

    present = set()
    for k, v in (data_elements or {}).items():
        try:
            fnum = int(k)
        except (TypeError, ValueError):
            continue
        if v is None or v == "":
            continue
        present.add(fnum)
        meta = fields_spec.get(fnum)
        if meta is None:
            errors.append(f"F{fnum:03d} is not defined in {network_id} spec.")
            continue
        # Length / charset validation
        v = str(v)
        max_len = meta["max_length"]
        fmt = meta["format"]
        if fmt == "n" and not v.replace(".", "").isdigit():
            errors.append(f"F{fnum:03d} ({meta['name']}) must be numeric.")
        if meta["length_type"] == "fixed" and fmt == "n" and len(v.zfill(max_len)) > max_len:
            errors.append(f"F{fnum:03d} ({meta['name']}) exceeds fixed length {max_len}.")
        if meta["length_type"] in ("LLVAR", "LLLVAR") and len(v) > max_len:
            errors.append(f"F{fnum:03d} ({meta['name']}) exceeds max length {max_len}.")
        if fmt == "b":
            hex_part = "".join(c for c in v if c in "0123456789abcdefABCDEF")
            if hex_part != v:
                errors.append(f"F{fnum:03d} ({meta['name']}) must be hex characters only.")

    missing = sorted(mandatory - present)
    for fnum in missing:
        nm = fields_spec.get(fnum, {}).get("name", f"Field {fnum}")
        errors.append(f"F{fnum:03d} ({nm}) is mandatory for MTI {mti} on {spec['name']}.")

    return errors


# ===========================================================================
# Catalogue helpers
# ===========================================================================
def field_catalog(network_id: str = "visa") -> List[Dict]:
    spec = _spec(network_id)
    return [
        {"field": f, **{k: v for k, v in meta.items() if k != "encoding" or True}}
        for f, meta in sorted(spec["fields"].items())
    ]


def mandatory_catalog(network_id: str = "visa") -> Dict[str, List[int]]:
    """Return `{mti: [field_numbers...]}` for the Builder spec-hint UI."""
    table = MANDATORY_PER_MTI.get(network_id, MANDATORY_PER_MTI.get("visa", {}))
    return {mti: sorted(set(int(f) for f in fset)) for mti, fset in table.items()}


# ---------------------------------------------------------------------------
# Custom user spec builder — turns lightweight import payload into a full
# spec dict ready for `register_runtime_spec`.
# ---------------------------------------------------------------------------
_VALID_FORMATS = {"n", "an", "ans", "b", "z"}
_VALID_LENGTH_TYPES = {"fixed", "LLVAR", "LLLVAR"}
_VALID_AN_CHARSETS = {"ascii", "ebcdic"}
_VALID_LENGTH_PREFIX_ENCODINGS = {"ascii", "bcd"}
_VALID_BITMAP_ENCODINGS = {"binary", "ascii_hex"}
_VALID_MTI_ENCODINGS = {"ascii", "bcd"}


def build_user_spec(payload: Dict) -> Dict:
    """Validate + normalise a user-supplied spec into the runtime-ready shape.

    Required keys: `network_id` (slug, will be prefixed with `user:`), `name`.
    Optional encoding params default to ASCII-friendly values, which is the
    most common shape for sandboxes.
    The `fields` value is a dict ``{ "<field_num>": {name, format, length_type, max_length, encoding?} }``.
    `mandatory_per_mti` is ``{ "0200": [2, 3, 4, ...], ... }``.
    """
    if not isinstance(payload, dict):
        raise ValueError("spec payload must be a JSON object")
    raw_id = (payload.get("network_id") or "").strip().lower()
    if not raw_id or not all(c.isalnum() or c in "-_" for c in raw_id):
        raise ValueError("network_id must be a slug (a-z, 0-9, -, _)")
    if raw_id in {"visa", "mastercard", "amex", "rupay"}:
        raise ValueError(f"network_id '{raw_id}' is reserved for the built-in spec")
    network_id = raw_id if raw_id.startswith("user:") else f"user:{raw_id}"

    name = (payload.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")

    mti_enc = (payload.get("mti_encoding") or "ascii").lower()
    bitmap_enc = (payload.get("bitmap_encoding") or "ascii_hex").lower()
    an_charset = (payload.get("default_an_charset") or "ascii").lower()
    len_prefix_enc = (payload.get("length_prefix_encoding") or "ascii").lower()
    if mti_enc not in _VALID_MTI_ENCODINGS:
        raise ValueError(f"mti_encoding must be one of {sorted(_VALID_MTI_ENCODINGS)}")
    if bitmap_enc not in _VALID_BITMAP_ENCODINGS:
        raise ValueError(f"bitmap_encoding must be one of {sorted(_VALID_BITMAP_ENCODINGS)}")
    if an_charset not in _VALID_AN_CHARSETS:
        raise ValueError(f"default_an_charset must be one of {sorted(_VALID_AN_CHARSETS)}")
    if len_prefix_enc not in _VALID_LENGTH_PREFIX_ENCODINGS:
        raise ValueError(f"length_prefix_encoding must be one of {sorted(_VALID_LENGTH_PREFIX_ENCODINGS)}")

    # Start from BASE_FIELDS (so the user inherits the ISO catalogue), then
    # apply per-field overrides supplied in the payload.
    fields = _build_network_fields(an_charset, len_prefix_enc, {})
    raw_fields = payload.get("fields") or {}
    if not isinstance(raw_fields, dict):
        raise ValueError("fields must be a dict keyed by field number")
    for k, override in raw_fields.items():
        try:
            fnum = int(k)
        except (TypeError, ValueError):
            raise ValueError(f"field key '{k}' is not an integer")
        if not (1 <= fnum <= 128):
            raise ValueError(f"field {fnum} is outside the 1–128 range")
        if not isinstance(override, dict):
            raise ValueError(f"field {fnum} override must be an object")
        cell = dict(fields.get(fnum) or {})
        cell["name"] = (override.get("name") or cell.get("name") or f"Field {fnum}").strip()
        cell["format"] = (override.get("format") or cell.get("format") or "ans").lower()
        if cell["format"] not in _VALID_FORMATS:
            raise ValueError(f"field {fnum}: format must be one of {sorted(_VALID_FORMATS)}")
        cell["length_type"] = override.get("length_type") or cell.get("length_type") or "fixed"
        if cell["length_type"] not in _VALID_LENGTH_TYPES:
            raise ValueError(f"field {fnum}: length_type must be one of {sorted(_VALID_LENGTH_TYPES)}")
        try:
            cell["max_length"] = int(override.get("max_length") or cell.get("max_length") or 0)
        except (TypeError, ValueError):
            raise ValueError(f"field {fnum}: max_length must be an integer")
        if cell["max_length"] <= 0 or cell["max_length"] > 999:
            raise ValueError(f"field {fnum}: max_length must be 1..999")
        cell["encoding"] = (override.get("encoding") or _default_encoding(cell["format"], an_charset)).lower()
        cell["length_encoding"] = (override.get("length_encoding") or len_prefix_enc).lower()
        fields[fnum] = cell

    # Mandatory per MTI
    raw_mandatory = payload.get("mandatory_per_mti") or {}
    if not isinstance(raw_mandatory, dict):
        raise ValueError("mandatory_per_mti must be a dict")
    mandatory: Dict[str, List[int]] = {}
    for mti, flist in raw_mandatory.items():
        if not (isinstance(mti, str) and len(mti) == 4 and mti.isdigit()):
            raise ValueError(f"mandatory_per_mti key '{mti}' is not a 4-digit MTI string")
        try:
            mandatory[mti] = sorted(set(int(f) for f in flist or []))
        except (TypeError, ValueError):
            raise ValueError(f"mandatory_per_mti[{mti}] must be a list of integers")
        for fnum in mandatory[mti]:
            if fnum not in fields:
                raise ValueError(f"mandatory_per_mti[{mti}] references unknown field {fnum}")

    return {
        "network_id": network_id,
        "name": name,
        "description": (payload.get("description") or "").strip(),
        "mti_encoding": mti_enc,
        "bitmap_encoding": bitmap_enc,
        "default_an_charset": an_charset,
        "length_prefix_encoding": len_prefix_enc,
        "builtin": False,
        "fields": fields,
        "mandatory_per_mti": mandatory,
    }


def parse_spec_csv(text: str) -> Dict[str, Dict]:
    """Parse a CSV table of field overrides.

    Header row (case-insensitive):
        field,name,format,length_type,max_length,encoding,length_encoding
    Returns a `{ "<field_num>": {…} }` dict suitable for `build_user_spec`.
    """
    import csv
    import io
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV is empty / missing header")
    expected = {"field", "name", "format", "length_type", "max_length"}
    have = {(c or "").strip().lower() for c in reader.fieldnames}
    missing = expected - have
    if missing:
        raise ValueError(f"CSV header missing column(s): {sorted(missing)}")
    out: Dict[str, Dict] = {}
    for row in reader:
        norm = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        if not norm.get("field"):
            continue
        out[norm["field"]] = {
            "name": norm.get("name", ""),
            "format": norm.get("format", "ans"),
            "length_type": norm.get("length_type", "fixed"),
            "max_length": norm.get("max_length", "0"),
            "encoding": norm.get("encoding") or None,
            "length_encoding": norm.get("length_encoding") or None,
        }
    if not out:
        raise ValueError("CSV had a header but no data rows")
    return out


def hex_to_base64(raw_hex: str) -> str:
    import base64
    return base64.b64encode(bytes.fromhex(raw_hex)).decode("ascii")


# ===========================================================================
# Response simulator
# ===========================================================================
RESPONSE_CODES = {
    "00": "Approved",
    "01": "Refer to card issuer",
    "05": "Do not honour",
    "12": "Invalid transaction",
    "14": "Invalid card number",
    "30": "Format error",
    "41": "Lost card",
    "43": "Stolen card",
    "51": "Insufficient funds",
    "54": "Expired card",
    "55": "Incorrect PIN",
    "57": "Transaction not permitted to cardholder",
    "61": "Exceeds withdrawal limit",
    "81": "PIN cryptographic error",
    "82": "Negative CAM, dCVV, iCVV or CVV results",
    "91": "Issuer unavailable",
    "96": "System malfunction",
}


def simulate_response(
    request_mti: str,
    data_elements: Dict[str, str],
    network_id: str = "visa",
    keyset: Optional[Dict] = None,
) -> Tuple[str, Dict]:
    """Generate a response message in the same network's wire format.

    With `keyset` (a key set from the user's key vault), the simulator first acts
    as the issuer and verifies the ARQC (F55), track 2 CVV (F35) and PIN (F52)
    -- see sim_crypto.py. A failed check sets the response code; a verified
    ARQC is answered with an ARPC in F55 tag 91.
    """
    from sim_crypto import run_issuer_checks, build_arpc_tlv

    crypto = run_issuer_checks(request_mti, data_elements, keyset, network_id) if keyset else None
    last_two = request_mti[-2:]
    response_mti = request_mti[:2] + (f"{int(last_two) + 10:02d}" if last_two.isdigit() else "10")

    pan = str(data_elements.get("2", "") or data_elements.get(2, ""))
    amount_str = str(data_elements.get("4", "") or data_elements.get(4, "0"))
    try:
        amount_minor = int(amount_str or "0")
    except ValueError:
        amount_minor = 0

    if request_mti.startswith("08"):
        rc = "00"
    elif crypto and crypto["rc"]:
        rc = crypto["rc"]
    elif not pan or len(pan) < 12:
        rc = "14"
    elif amount_minor <= 0:
        rc = "12"
    elif amount_minor > 500_000:
        rc = "61"
    elif amount_minor > 50_000 and pan.startswith("5"):
        rc = "51"
    else:
        rc = random.choices(["00"] * 9 + ["05"], k=1)[0]

    auth_code = f"{random.randint(0, 999999):06d}" if rc == "00" else "      "
    rrn = f"{random.randint(0, 999999999999):012d}"

    response_de: Dict[str, str] = {
        "3":  str(data_elements.get("3", "000000")),
        "4":  amount_str if amount_str else None,
        "7":  str(data_elements.get("7", "")),
        "11": str(data_elements.get("11", "000000")),
        "37": rrn,
        "38": auth_code,
        "39": rc,
        "41": str(data_elements.get("41", "")),
        "49": str(data_elements.get("49", "")),
        "70": str(data_elements.get("70", "")) if request_mti.startswith("08") else None,
    }
    if crypto and crypto["arpc_ctx"]:
        response_de["55"] = build_arpc_tlv(crypto["arpc_ctx"], rc)
    response_de = {k: v for k, v in response_de.items() if v}

    response_hex, response_meta = encode_message(response_mti, response_de, network_id)
    if crypto is not None:
        response_meta["crypto_checks"] = crypto["checks"]
    response_meta["response_code"] = rc
    response_meta["response_code_description"] = RESPONSE_CODES.get(rc, "Unknown")
    response_meta["authorization_code"] = auth_code.strip()
    response_meta["retrieval_reference_number"] = rrn
    return response_hex, response_meta
