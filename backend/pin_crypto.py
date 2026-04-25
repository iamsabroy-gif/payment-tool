"""ISO-9564 PIN block formats + symmetric encryption for ISO-8583 F52.

Supported PIN block formats:
  - ISO-0 (ANSI X9.8) – PIN XOR PAN, the dominant format on real switches
  - ISO-1             – PIN with random padding (no PAN)
  - ISO-3             – PIN with random A-F padding XOR PAN

Supported algorithms:
  - 3DES (TDES EDE)  – 8-byte block; default for ISO-0/1/3
  - AES              – 16-byte block (used with ISO-4, kept here for completeness)

This implementation is for **simulation / testing** purposes; in production you
must call out to an HSM (Thales, Atalla, Utimaco …) and never handle clear PINs
or clear PIN-encryption keys in application memory.
"""
from __future__ import annotations

import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


PIN_FORMATS = ("ISO-0", "ISO-1", "ISO-3")
PIN_ALGORITHMS = ("3DES", "AES")


# ---------------------------------------------------------------------------
# Clear PIN block builders
# ---------------------------------------------------------------------------
def _validate_pin(pin: str) -> str:
    pin = (pin or "").strip()
    if not pin.isdigit():
        raise ValueError("PIN must be numeric digits.")
    if not (4 <= len(pin) <= 12):
        raise ValueError("PIN length must be between 4 and 12 digits.")
    return pin


def _pan_nibble(pan: str) -> str:
    """ISO-0/3 PAN-block: '0000' + rightmost 12 digits of PAN excluding check digit."""
    digits = "".join(c for c in (pan or "") if c.isdigit())
    if len(digits) < 13:
        raise ValueError("PAN must be at least 13 digits for ISO-0/ISO-3 PIN block.")
    pan12 = digits[-13:-1]  # exclude Luhn check digit, take 12
    return "0000" + pan12


def _xor_hex(a: str, b: str) -> str:
    if len(a) != len(b):
        raise ValueError("XOR operands must be equal length.")
    return "".join(f"{int(x, 16) ^ int(y, 16):X}" for x, y in zip(a, b))


def _random_hex_padding(length: int, alphabet: str) -> str:
    raw = os.urandom(length)
    return "".join(alphabet[b % len(alphabet)] for b in raw[:length])


def build_clear_pin_block(pin: str, pan: str, fmt: str = "ISO-0") -> str:
    """Return the 16-hex (8-byte) clear PIN block."""
    pin = _validate_pin(pin)
    L = len(pin)

    if fmt == "ISO-0":
        pin_part = f"0{L:X}{pin}".ljust(16, "F")
        pan_part = _pan_nibble(pan)
        return _xor_hex(pin_part, pan_part)

    if fmt == "ISO-1":
        # No PAN; 1L PPPP RRR...R (random hex)
        rand = _random_hex_padding(16 - 2 - L, "0123456789ABCDEF")
        return f"1{L:X}{pin}{rand}"

    if fmt == "ISO-3":
        # 3L PPPP RRR...R where R ∈ A-F, then XOR with PAN block (same as ISO-0)
        rand = _random_hex_padding(16 - 2 - L, "ABCDEF")
        pin_part = f"3{L:X}{pin}{rand}"
        pan_part = _pan_nibble(pan)
        return _xor_hex(pin_part, pan_part)

    raise ValueError(f"Unsupported PIN block format: {fmt}")


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------
def _normalise_3des_key(key_hex: str) -> bytes:
    """Accept single (8 byte / 16 hex), double (16 byte / 32 hex) or triple (24 byte / 48 hex)
    length keys. Single → expanded by repetition; double → K1-K2-K1 form."""
    h = key_hex.strip().replace(" ", "")
    if len(h) not in (16, 32, 48):
        raise ValueError("3DES key must be 8, 16 or 24 bytes (16, 32 or 48 hex chars).")
    raw = bytes.fromhex(h)
    if len(raw) == 8:
        return raw * 3
    if len(raw) == 16:
        return raw + raw[:8]  # K1 || K2 || K1
    return raw


def _normalise_aes_key(key_hex: str) -> bytes:
    h = key_hex.strip().replace(" ", "")
    if len(h) not in (32, 48, 64):
        raise ValueError("AES key must be 16, 24 or 32 bytes (32, 48 or 64 hex chars).")
    return bytes.fromhex(h)


def encrypt_pin_block(
    pin: str,
    pan: str,
    key_hex: str,
    fmt: str = "ISO-0",
    algorithm: str = "3DES",
) -> Tuple[str, str]:
    """Build the clear PIN block and encrypt it under the given key.

    Returns (clear_block_hex, encrypted_block_hex).
    """
    if fmt not in PIN_FORMATS:
        raise ValueError(f"format must be one of {PIN_FORMATS}")
    if algorithm not in PIN_ALGORITHMS:
        raise ValueError(f"algorithm must be one of {PIN_ALGORITHMS}")

    clear_hex = build_clear_pin_block(pin, pan, fmt)
    clear_bytes = bytes.fromhex(clear_hex)

    if algorithm == "3DES":
        key = _normalise_3des_key(key_hex)
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    else:  # AES
        key = _normalise_aes_key(key_hex)
        # ISO-4 PIN blocks are 16 bytes; pad clear to 16 if needed
        if len(clear_bytes) < 16:
            clear_bytes = clear_bytes + os.urandom(16 - len(clear_bytes))
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    enc = cipher.encryptor().update(clear_bytes)
    return clear_hex, enc.hex().upper()
