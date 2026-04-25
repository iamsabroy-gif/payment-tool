"""Low-level codecs used by the ISO-8583 encoder/decoder.

  - BCD (binary-coded decimal) – numeric fields and length prefixes
  - EBCDIC (CP037) – alphanumeric fields on VISA/MC/AMEX
  - Binary bitmap – 8-byte primary + optional 8-byte secondary
  - Track2 BCD with 0xD separator
  - BER-TLV – sub-element parsing for F55 (EMV)
"""
from __future__ import annotations
from typing import List, Tuple


# ---------------------------------------------------------------------------
# BCD
# ---------------------------------------------------------------------------
def bcd_encode(value: str, length_digits: int, justify: str = "right", pad_nibble: int = 0x0) -> bytes:
    """Pack ASCII-decimal `value` into BCD bytes.

    `length_digits` is the *number of decimal digits* the field carries
    (so the byte length is ceil(length_digits / 2)). For amounts we
    right-justify and zero-pad; for PANs / dates we left-justify and
    pad with 0xF.
    """
    s = "".join(ch for ch in value if ch.isdigit())
    if len(s) > length_digits:
        s = s[:length_digits]
    if justify == "right":
        s = s.rjust(length_digits, "0")
    else:  # left
        s = s.ljust(length_digits, "F" if pad_nibble == 0xF else "0")

    if len(s) % 2 == 1:
        if justify == "right":
            s = ("F" if pad_nibble == 0xF else "0") + s
        else:
            s = s + ("F" if pad_nibble == 0xF else "0")

    out = bytearray()
    for i in range(0, len(s), 2):
        hi = _nibble(s[i])
        lo = _nibble(s[i + 1])
        out.append((hi << 4) | lo)
    return bytes(out)


def bcd_decode(data: bytes, length_digits: int, justify: str = "right") -> str:
    """Unpack BCD bytes back into ASCII-decimal of given digit length."""
    s = ""
    for b in data:
        hi = (b >> 4) & 0xF
        lo = b & 0xF
        s += _ch(hi) + _ch(lo)
    # Strip pad nibbles
    if justify == "right":
        # Take the rightmost length_digits, ignoring leading non-digits
        digits = "".join(c for c in s if c.isdigit() or c == "F")
        digits = digits.rjust(length_digits, "0")
        digits = digits[-length_digits:].replace("F", "")
        return digits
    else:
        digits = "".join(c for c in s if c.isdigit() or c == "F")
        digits = digits[:length_digits]
        return digits.rstrip("F")


def _nibble(c: str) -> int:
    if c.isdigit():
        return int(c)
    if c.upper() == "F":
        return 0xF
    if c.upper() == "D":
        return 0xD
    raise ValueError(f"non-BCD char: {c!r}")


def _ch(n: int) -> str:
    if 0 <= n <= 9:
        return str(n)
    return {0xA: "A", 0xB: "B", 0xC: "C", 0xD: "D", 0xE: "E", 0xF: "F"}.get(n, "?")


def bcd_length_prefix(length_value: int, prefix_digits: int) -> bytes:
    """Encode a length prefix as BCD (e.g. 16 with 2 digits → 0x16)."""
    return bcd_encode(str(length_value), prefix_digits, justify="right")


def bcd_decode_length(data: bytes, prefix_digits: int) -> int:
    return int(bcd_decode(data, prefix_digits, justify="right") or "0")


# ---------------------------------------------------------------------------
# EBCDIC (CP037 — US/Canadian, the most widely used variant for card networks)
# ---------------------------------------------------------------------------
def ebcdic_encode(value: str, length: int, pad_char: str = " ") -> bytes:
    s = (value or "").ljust(length, pad_char)[:length]
    return s.encode("cp037")


def ebcdic_decode(data: bytes) -> str:
    try:
        return data.decode("cp037").rstrip()
    except Exception:
        return data.decode("latin-1", errors="replace").rstrip()


# ---------------------------------------------------------------------------
# Binary bitmap (8 bytes per bitmap)
# ---------------------------------------------------------------------------
def binary_bitmap_encode(fields_present: List[int]) -> bytes:
    """Return primary (8B) + optional secondary (8B) bitmap."""
    present = set(fields_present)
    has_secondary = any(f > 64 for f in present)
    if has_secondary:
        present.add(1)
    primary = bytearray(8)
    for f in present:
        if 1 <= f <= 64:
            primary[(f - 1) // 8] |= 1 << (7 - ((f - 1) % 8))
    out = bytes(primary)
    if has_secondary:
        secondary = bytearray(8)
        for f in present:
            if 65 <= f <= 128:
                idx = f - 65
                secondary[idx // 8] |= 1 << (7 - (idx % 8))
        out += bytes(secondary)
    return out


def binary_bitmap_decode(data: bytes, offset: int = 0) -> Tuple[List[int], int]:
    """Decode binary bitmap starting at `offset`. Returns (active_fields, bytes_consumed).
    Always reads the 8-byte primary; if bit 1 is set, also reads the 8-byte secondary."""
    fields: List[int] = []
    primary = data[offset:offset + 8]
    if len(primary) < 8:
        raise ValueError("primary bitmap truncated")
    for i, b in enumerate(primary):
        for bit in range(8):
            if b & (1 << (7 - bit)):
                fields.append(i * 8 + bit + 1)
    consumed = 8
    if 1 in fields:
        secondary = data[offset + 8:offset + 16]
        if len(secondary) < 8:
            raise ValueError("secondary bitmap truncated")
        fields = [f for f in fields if f != 1]
        for i, b in enumerate(secondary):
            for bit in range(8):
                if b & (1 << (7 - bit)):
                    fields.append(64 + i * 8 + bit + 1)
        consumed = 16
    fields.sort()
    return fields, consumed


# ---------------------------------------------------------------------------
# Track 2 (BCD with 0xD as field separator)
# ---------------------------------------------------------------------------
def track2_encode(value: str) -> bytes:
    """Pack track2 (digits + 'D' separator) into BCD."""
    s = value.upper().replace("=", "D")
    if len(s) % 2 == 1:
        s += "F"
    out = bytearray()
    for i in range(0, len(s), 2):
        out.append((_nibble(s[i]) << 4) | _nibble(s[i + 1]))
    return bytes(out)


def track2_decode(data: bytes) -> str:
    s = ""
    for b in data:
        s += _ch((b >> 4) & 0xF) + _ch(b & 0xF)
    return s.rstrip("F").replace("D", "=")


# ---------------------------------------------------------------------------
# BER-TLV (used for F55 EMV tags)
# ---------------------------------------------------------------------------
def parse_tlv(data: bytes) -> List[dict]:
    """Parse a flat list of BER-TLV items. Returns [{tag, length, value_hex}, ...]."""
    out: List[dict] = []
    i = 0
    n = len(data)
    while i < n:
        tag_start = i
        # Tag: 1 or 2+ bytes (if low 5 bits of first byte = 0x1F continue)
        first = data[i]; i += 1
        if (first & 0x1F) == 0x1F:
            while i < n and (data[i] & 0x80):
                i += 1
            if i < n:
                i += 1
        tag = data[tag_start:i].hex().upper()
        if i >= n:
            break
        # Length: short form if MSB=0, else N following bytes
        l0 = data[i]; i += 1
        if l0 & 0x80:
            ln = l0 & 0x7F
            length = int.from_bytes(data[i:i + ln], "big") if ln else 0
            i += ln
        else:
            length = l0
        value = data[i:i + length]
        i += length
        out.append({"tag": tag, "length": length, "value_hex": value.hex().upper()})
    return out
