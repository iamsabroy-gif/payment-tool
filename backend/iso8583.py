"""
ISO-8583 message encoder, decoder, and network specifications.

Uses ASCII-encoded fields with LLVAR/LLLVAR length prefixes for simplicity.
Primary bitmap = 16 hex chars (64 bits). Secondary present when bit 1 set.
"""
from typing import Dict, List, Tuple, Optional


# ---------------------------------------------------------------------------
# Standard ISO-8583:1987 field catalogue used as base for all networks.
# Each entry: (name, format, length_type, max_length)
#   format: "n" numeric, "an" alphanumeric, "ans" alphanumeric+special, "b" binary
#   length_type: "fixed" | "LLVAR" | "LLLVAR"
# ---------------------------------------------------------------------------
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
    52: {"name": "PIN Data",                          "format": "b",   "length_type": "fixed",  "max_length": 16},
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
    64: {"name": "Message Authentication Code (MAC)", "format": "b",   "length_type": "fixed",  "max_length": 16},
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
    128:{"name": "Message Auth Code (Secondary)",     "format": "b",   "length_type": "fixed",  "max_length": 16},
}


def _merge_overrides(base: Dict[int, Dict], overrides: Dict[int, Dict]) -> Dict[int, Dict]:
    out = {k: dict(v) for k, v in base.items()}
    for k, v in overrides.items():
        if k in out:
            out[k].update(v)
        else:
            out[k] = dict(v)
    return out


NETWORK_SPECS: Dict[str, Dict] = {
    "visa": {
        "network_id": "visa",
        "name": "VISA",
        "description": "VISA Base I / ISO-8583:1987 profile (ASCII).",
        "fields": _merge_overrides(BASE_FIELDS, {
            18: {"name": "Merchant Category Code (MCC)"},
            62: {"name": "VISA Private Use – Invoice & Reserved"},
            63: {"name": "VISA Private Use – Network Data"},
        }),
    },
    "mastercard": {
        "network_id": "mastercard",
        "name": "Mastercard",
        "description": "Mastercard Customer Interface Spec (CIS) profile (ASCII).",
        "fields": _merge_overrides(BASE_FIELDS, {
            48: {"name": "Mastercard Additional Data"},
            61: {"name": "Mastercard POS Extended Data"},
            63: {"name": "Mastercard Network Data"},
        }),
    },
    "amex": {
        "network_id": "amex",
        "name": "American Express",
        "description": "AMEX GCAG / ISO-8583:1987 profile (ASCII).",
        "fields": _merge_overrides(BASE_FIELDS, {
            62: {"name": "AMEX Transaction Identifier"},
            63: {"name": "AMEX Reserved Private"},
        }),
    },
}


# ---------------------------------------------------------------------------
# Bitmap helpers
# ---------------------------------------------------------------------------
def _build_bitmap_hex(fields_present: List[int]) -> str:
    present = set(fields_present)
    has_secondary = any(f > 64 for f in present)
    if has_secondary:
        present.add(1)

    def bits_to_hex(size: int, offset: int) -> str:
        buf = bytearray(8)
        for f in present:
            if offset < f <= offset + size:
                bit_index = f - offset - 1
                buf[bit_index // 8] |= 1 << (7 - (bit_index % 8))
        return buf.hex().upper()

    primary = bits_to_hex(64, 0)
    if has_secondary:
        return primary + bits_to_hex(64, 64)
    return primary


def _parse_bitmap(bitmap_hex: str) -> List[int]:
    """Given a hex string (16 or 32 chars) return list of active field numbers."""
    fields: List[int] = []
    data = bytes.fromhex(bitmap_hex)
    for byte_idx, byte_val in enumerate(data):
        for bit in range(8):
            if byte_val & (1 << (7 - bit)):
                fields.append(byte_idx * 8 + bit + 1)
    return fields


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------
def encode_message(mti: str, data_elements: Dict[str, str], network_id: str = "visa") -> Tuple[str, Dict]:
    """
    Encode an ISO-8583 message.
    Returns (raw_hex_string, parsed_meta).
    """
    if len(mti) != 4 or not mti.isdigit():
        raise ValueError("MTI must be 4 numeric digits")

    spec = NETWORK_SPECS.get(network_id, NETWORK_SPECS["visa"])
    fields_spec = spec["fields"]

    # normalise keys -> int
    normalised: Dict[int, str] = {}
    for k, v in data_elements.items():
        try:
            f = int(k)
        except (TypeError, ValueError):
            continue
        if v is None or v == "":
            continue
        normalised[f] = str(v)

    active_fields = sorted(normalised.keys())
    bitmap_hex = _build_bitmap_hex(active_fields)

    # MTI + bitmap as ASCII hex payload. We emit the full message as a hex string
    # with MTI and bitmap stored as their ASCII bytes, then each field value
    # encoded per-spec.
    msg_ascii_parts: List[str] = [mti, bitmap_hex]

    encoded_fields: List[Dict] = []
    for f in active_fields:
        value = normalised[f]
        meta = fields_spec.get(f, {
            "name": f"Field {f}",
            "format": "ans",
            "length_type": "LLLVAR",
            "max_length": 999,
        })
        length_type = meta["length_type"]
        max_length = meta["max_length"]

        if length_type == "fixed":
            if meta.get("format") == "n":
                value = value.zfill(max_length)
            else:
                value = value.ljust(max_length)[:max_length]
            chunk = value
        elif length_type == "LLVAR":
            value = value[:max_length]
            chunk = f"{len(value):02d}" + value
        elif length_type == "LLLVAR":
            value = value[:max_length]
            chunk = f"{len(value):03d}" + value
        else:
            chunk = value

        msg_ascii_parts.append(chunk)
        encoded_fields.append({
            "field": f,
            "name": meta["name"],
            "value": value,
            "length": len(value),
        })

    raw_ascii = "".join(msg_ascii_parts)
    raw_hex = raw_ascii.encode("ascii", errors="replace").hex().upper()

    return raw_hex, {
        "mti": mti,
        "network_id": network_id,
        "bitmap_hex": bitmap_hex,
        "active_fields": active_fields,
        "fields": encoded_fields,
        "raw_ascii": raw_ascii,
    }


def hex_to_base64(raw_hex: str) -> str:
    import base64
    return base64.b64encode(bytes.fromhex(raw_hex)).decode("ascii")


# ---------------------------------------------------------------------------
# Decoder (ASCII payload)
# ---------------------------------------------------------------------------
def decode_message(raw_hex: str, network_id: str = "visa") -> Dict:
    spec = NETWORK_SPECS.get(network_id, NETWORK_SPECS["visa"])
    fields_spec = spec["fields"]
    raw_ascii = bytes.fromhex(raw_hex).decode("ascii", errors="replace")

    pos = 0
    mti = raw_ascii[pos:pos + 4]; pos += 4
    primary_bitmap = raw_ascii[pos:pos + 16]; pos += 16
    bitmap_hex = primary_bitmap
    fields_active = _parse_bitmap(primary_bitmap)
    if 1 in fields_active:
        secondary_bitmap = raw_ascii[pos:pos + 16]; pos += 16
        bitmap_hex += secondary_bitmap
        fields_active = [f for f in fields_active if f != 1] + [f + 64 for f in _parse_bitmap(secondary_bitmap)]
        fields_active.sort()

    parsed_fields: List[Dict] = []
    for f in fields_active:
        meta = fields_spec.get(f)
        if not meta:
            break
        length_type = meta["length_type"]
        if length_type == "fixed":
            length = meta["max_length"]
            value = raw_ascii[pos:pos + length]
            pos += length
        elif length_type == "LLVAR":
            length = int(raw_ascii[pos:pos + 2] or "0")
            pos += 2
            value = raw_ascii[pos:pos + length]
            pos += length
        elif length_type == "LLLVAR":
            length = int(raw_ascii[pos:pos + 3] or "0")
            pos += 3
            value = raw_ascii[pos:pos + length]
            pos += length
        else:
            value = ""
        parsed_fields.append({
            "field": f,
            "name": meta["name"],
            "format": meta["format"],
            "length_type": length_type,
            "value": value,
        })

    return {
        "mti": mti,
        "network_id": network_id,
        "bitmap_hex": bitmap_hex,
        "active_fields": fields_active,
        "fields": parsed_fields,
    }


# ---------------------------------------------------------------------------
# Simulator: mimic an issuer/authorization host.
# ---------------------------------------------------------------------------
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
    "91": "Issuer unavailable",
    "96": "System malfunction",
}


def simulate_response(request_mti: str, data_elements: Dict[str, str], network_id: str = "visa") -> Tuple[str, Dict]:
    """Produce a deterministic-ish response to an incoming auth request."""
    import random
    # Response MTI = request MTI + 0x10 on last nibble (e.g. 0200 -> 0210)
    response_mti_int = int(request_mti[-2:]) + 10 if request_mti[-2:].isdigit() else 10
    response_mti = request_mti[:2] + f"{response_mti_int:02d}"

    pan = str(data_elements.get("2", "") or data_elements.get(2, ""))
    amount_str = str(data_elements.get("4", "") or data_elements.get(4, "0"))
    try:
        amount_minor = int(amount_str or "0")
    except ValueError:
        amount_minor = 0

    # Deterministic decision rules
    if not pan or len(pan) < 12:
        rc = "14"
    elif amount_minor <= 0:
        rc = "12"
    elif amount_minor > 500_000:  # > $5,000.00
        rc = "61"
    elif amount_minor > 50_000 and pan.startswith("5"):
        rc = "51"
    else:
        # 90% approval baseline, with a sprinkle of declines for realism
        rc = random.choices(["00", "00", "00", "00", "00", "00", "00", "00", "00", "05"], k=1)[0]

    auth_code = f"{random.randint(0, 999999):06d}" if rc == "00" else "      "
    rrn = f"{random.randint(0, 999999999999):012d}"

    response_de: Dict[str, str] = {
        "3":  str(data_elements.get("3", "000000")),
        "4":  amount_str,
        "7":  str(data_elements.get("7", "")),
        "11": str(data_elements.get("11", "")),
        "37": rrn,
        "38": auth_code,
        "39": rc,
        "41": str(data_elements.get("41", "")),
        "49": str(data_elements.get("49", "840")),
    }
    # Drop empties
    response_de = {k: v for k, v in response_de.items() if v}

    response_hex, response_meta = encode_message(response_mti, response_de, network_id)
    response_meta["response_code"] = rc
    response_meta["response_code_description"] = RESPONSE_CODES.get(rc, "Unknown")
    response_meta["authorization_code"] = auth_code.strip()
    response_meta["retrieval_reference_number"] = rrn

    return response_hex, response_meta


def field_catalog(network_id: str = "visa") -> List[Dict]:
    spec = NETWORK_SPECS.get(network_id, NETWORK_SPECS["visa"])
    return [
        {"field": f, **meta}
        for f, meta in sorted(spec["fields"].items())
    ]
