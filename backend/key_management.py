"""Payment-card key-management primitives:

  - KCV      – Key Check Value for any symmetric key
  - CVV      – Card Verification Value (IBM/VISA algorithm) under a CVK pair
  - PVV      – PIN Verification Value (VISA algorithm) under a PVK pair
  - ICC MK   – EMV ICC Master Key derivation Method A from an MDK
  - ARQC     – Application Cryptogram (ISO/IEC 9797-1 alg 3 retail MAC)

These helpers mirror what an issuer-side HSM does. **For dev / simulation only**.
Real production must run inside a PCI-PIN HSM.
"""
from __future__ import annotations

from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _normalise_3des_key(key_hex: str) -> bytes:
    h = (key_hex or "").strip().replace(" ", "")
    if len(h) not in (16, 32, 48):
        raise ValueError("3DES key must be 8, 16 or 24 bytes (16/32/48 hex chars).")
    raw = bytes.fromhex(h)
    if len(raw) == 8:
        return raw * 3                  # K1‖K1‖K1 (single-DES emulation)
    if len(raw) == 16:
        return raw + raw[:8]            # K1‖K2‖K1
    return raw                          # K1‖K2‖K3


def _normalise_aes_key(key_hex: str) -> bytes:
    h = (key_hex or "").strip().replace(" ", "")
    if len(h) not in (32, 48, 64):
        raise ValueError("AES key must be 16/24/32 bytes (32/48/64 hex chars).")
    return bytes.fromhex(h)


def _ecb_3des(key: bytes, data: bytes, *, encrypt: bool = True) -> bytes:
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    op = cipher.encryptor() if encrypt else cipher.decryptor()
    return op.update(data) + op.finalize()


def _ecb_aes(key: bytes, data: bytes, *, encrypt: bool = True) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    op = cipher.encryptor() if encrypt else cipher.decryptor()
    return op.update(data) + op.finalize()


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# KCV — Key Check Value
# ---------------------------------------------------------------------------
def compute_kcv(key_hex: str, algorithm: str = "3DES") -> str:
    """Return 6-hex (3-byte) KCV. Encrypt all-zero block with the key, take the leading 3 bytes.
    This is the standard ANSI X9 / TR-31 / Thales / Atalla KCV."""
    if algorithm == "3DES":
        key = _normalise_3des_key(key_hex)
        ct = _ecb_3des(key, b"\x00" * 8)
    elif algorithm == "AES":
        key = _normalise_aes_key(key_hex)
        ct = _ecb_aes(key, b"\x00" * 16)
    else:
        raise ValueError("algorithm must be 3DES or AES")
    return ct[:3].hex().upper()


# ---------------------------------------------------------------------------
# CVV — Card Verification Value (IBM/VISA algorithm)
# ---------------------------------------------------------------------------
def compute_cvv(pan: str, expiry: str, service_code: str, cvk_a_hex: str, cvk_b_hex: str) -> str:
    """Compute a 3-digit CVV (CVV1 if service_code is track-derived, CVV2 if 000, iCVV if 999).

    Algorithm:
      raw  = PAN || Expiry(YYMM) || ServiceCode(3) padded with '0' to 32 hex chars
      A    = first 16 hex chars (block A, 8 bytes)
      B    = last  16 hex chars (block B, 8 bytes)
      out  = 3DES_CVK( single_DES_CVKa(A) XOR B )
      CVV  = first 3 decimal digits of out (then hex-shifted A→0..F→5 if not enough)
    """
    pan = "".join(c for c in pan if c.isdigit())
    if not pan:
        raise ValueError("PAN must contain digits")
    expiry = "".join(c for c in expiry if c.isdigit()).zfill(4)[:4]
    service_code = "".join(c for c in service_code if c.isdigit()).zfill(3)[:3]

    raw = (pan + expiry + service_code).ljust(32, "0")[:32]
    block_a = bytes.fromhex(raw[:16])
    block_b = bytes.fromhex(raw[16:])

    cvk_a = bytes.fromhex(cvk_a_hex.replace(" ", ""))
    cvk_b = bytes.fromhex(cvk_b_hex.replace(" ", ""))
    if len(cvk_a) != 8 or len(cvk_b) != 8:
        raise ValueError("CVK_A and CVK_B must each be 8 bytes (16 hex chars).")

    # single-DES(CVKa, A) via 3DES with K1=K2=K3=CVKa
    inter = _ecb_3des(cvk_a * 3, block_a)
    xored = _xor(inter, block_b)
    out = _ecb_3des(cvk_a + cvk_b + cvk_a, xored)

    return _decimalise(out.hex().upper(), digits=3)


# ---------------------------------------------------------------------------
# PVV — PIN Verification Value (VISA algorithm)
# ---------------------------------------------------------------------------
def compute_pvv(pan: str, pin: str, pvki: str, pvk_a_hex: str, pvk_b_hex: str) -> str:
    """4-digit PVV.

    Algorithm:
      TSP = rightmost 11 digits of PAN (excluding Luhn check digit) || PVKI(1 digit) || PIN[:4]
            -> 16 hex digits = 8 bytes
      out = 3DES_PVK(TSP)
      PVV = first 4 decimal digits of out (hex-shift fallback)
    """
    pan_digits = "".join(c for c in pan if c.isdigit())
    if len(pan_digits) < 12:
        raise ValueError("PAN must have at least 12 digits.")
    pvki = "".join(c for c in (pvki or "1") if c.isdigit())[:1] or "1"
    pin_digits = "".join(c for c in pin if c.isdigit())
    if len(pin_digits) < 4:
        raise ValueError("PIN must have at least 4 digits.")

    pan11 = pan_digits[-12:-1]                  # 11 digits, excluding check digit
    tsp = (pan11 + pvki + pin_digits[:4]).ljust(16, "0")[:16]

    pvk_a = bytes.fromhex(pvk_a_hex.replace(" ", ""))
    pvk_b = bytes.fromhex(pvk_b_hex.replace(" ", ""))
    if len(pvk_a) != 8 or len(pvk_b) != 8:
        raise ValueError("PVK_A and PVK_B must each be 8 bytes (16 hex chars).")

    out = _ecb_3des(pvk_a + pvk_b + pvk_a, bytes.fromhex(tsp))
    return _decimalise(out.hex().upper(), digits=4)


def _decimalise(hex_str: str, digits: int) -> str:
    """First pass: take leftmost decimal (0–9) digits.
    Second pass: replace A–F with (hex - 10) and continue."""
    first = [c for c in hex_str if c.isdigit()]
    if len(first) >= digits:
        return "".join(first[:digits])
    second = [str(int(c, 16) - 10) for c in hex_str if not c.isdigit()]
    combined = first + second
    return "".join(combined[:digits])


# ---------------------------------------------------------------------------
# EMV ICC Master Key derivation (Method A) + ARQC
# ---------------------------------------------------------------------------
def derive_icc_mk(mdk_hex: str, pan: str, psn: str = "00") -> str:
    """EMV ICC Master Key, Method A.

      Y = rightmost 16 digits of (PAN || PSN), zero-padded on the left if needed
      Z = Y XOR 0xFFFFFFFFFFFFFFFF
      ICC MK left  = 3DES_MDK(Y)
      ICC MK right = 3DES_MDK(Z)
      ICC MK       = left || right   (16 bytes / 32 hex)
    """
    pan = "".join(c for c in pan if c.isdigit())
    psn = "".join(c for c in (psn or "00") if c.isdigit()).zfill(2)[:2]
    src = (pan + psn).rjust(16, "0")[-16:]
    Y = bytes.fromhex(src)
    Z = bytes(b ^ 0xFF for b in Y)

    mdk = _normalise_3des_key(mdk_hex)
    left = _ecb_3des(mdk, Y)
    right = _ecb_3des(mdk, Z)
    icc_mk = left + right

    # EMV requires odd parity on each key byte; force it.
    return _force_odd_parity(icc_mk).hex().upper()


def _force_odd_parity(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        ones = bin(b).count("1")
        if ones % 2 == 0:
            b ^= 0x01  # flip LSB to make odd parity
        out.append(b)
    return bytes(out)


def compute_arqc(icc_mk_hex: str, cdol_hex: str) -> str:
    """ARQC = retail MAC (ISO/IEC 9797-1 algorithm 3) over CDOL data using ICC MK as the key.

    For CVN10 the session key equals the ICC MK; we don't apply further session-key
    derivation here — pass the session key directly as `icc_mk_hex` if your scheme
    requires CVN18 derivation upstream.
    """
    sk = bytes.fromhex(icc_mk_hex.replace(" ", ""))
    if len(sk) != 16:
        raise ValueError("ICC MK / session key must be 16 bytes (32 hex chars).")
    K1 = sk[:8]
    K2 = sk[8:]

    data = bytes.fromhex((cdol_hex or "").replace(" ", ""))
    # Mandatory padding: 0x80 then zeros to 8-byte boundary
    data += b"\x80"
    while len(data) % 8 != 0:
        data += b"\x00"

    h = b"\x00" * 8
    for i in range(0, len(data), 8):
        block = _xor(h, data[i:i + 8])
        h = _ecb_3des(K1 * 3, block)         # single-DES(K1)
    h = _ecb_3des(K2 * 3, h, encrypt=False)   # single-DES decrypt with K2
    h = _ecb_3des(K1 * 3, h)                  # single-DES encrypt with K1
    return h.hex().upper()
