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

import hashlib
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
def derive_icc_mk(mdk_hex: str, pan: str, psn: str = "00", option: str = "A") -> str:
    """EMV ICC Master Key derivation (EMV Book 2, Annex A1.4).

    Option A:
      Y = rightmost 16 digits of (PAN || PSN), zero-padded on the left if needed
    Option B (used e.g. by Visa CVN18/CVN22; identical to Option A for PAN <= 16 digits):
      X = PAN || PSN, left-padded with one '0' if odd length
      Y = first 16 decimal digits of SHA-1(X) (hex A-F -> 0-5 used if fewer than 16)
    Then for both:
      Z = Y XOR 0xFFFFFFFFFFFFFFFF
      ICC MK = 3DES_MDK(Y) || 3DES_MDK(Z), odd parity (16 bytes / 32 hex)
    """
    pan = "".join(c for c in pan if c.isdigit())
    psn = "".join(c for c in (psn or "00") if c.isdigit()).zfill(2)[:2]
    option = (option or "A").upper()
    if option not in ("A", "B"):
        raise ValueError("option must be 'A' or 'B'")
    if option == "B" and len(pan) > 16:
        src = _option_b_y(pan, psn)
    else:
        src = (pan + psn).rjust(16, "0")[-16:]
    Y = bytes.fromhex(src)
    Z = bytes(b ^ 0xFF for b in Y)

    mdk = _normalise_3des_key(mdk_hex)
    left = _ecb_3des(mdk, Y)
    right = _ecb_3des(mdk, Z)
    icc_mk = left + right

    # EMV requires odd parity on each key byte; force it.
    return _force_odd_parity(icc_mk).hex().upper()


def _option_b_y(pan: str, psn: str) -> str:
    """EMV Option B: 16 decimal digits from SHA-1(PAN || PSN)."""
    x = pan + psn
    if len(x) % 2:
        x = "0" + x
    digest = hashlib.sha1(bytes.fromhex(x)).hexdigest().upper()
    digits = [c for c in digest if c.isdigit()]
    if len(digits) < 16:
        digits += [str(int(c, 16) - 10) for c in digest if not c.isdigit()]
    return "".join(digits[:16])


def _force_odd_parity(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        ones = bin(b).count("1")
        if ones % 2 == 0:
            b ^= 0x01  # flip LSB to make odd parity
        out.append(b)
    return bytes(out)


def compute_arqc(icc_mk_hex: str, cdol_hex: str, padding: str = "EMV") -> str:
    """ARQC = retail MAC (ISO/IEC 9797-1 algorithm 3) over CDOL data.

    `icc_mk_hex` is the key the MAC runs under: the ICC MK itself for Visa CVN10,
    or the session key (see derive_session_key_cvn18) for CVN18 / M/Chip.

    padding:
      "VISA" - ISO/IEC 9797-1 method 1: zero bytes to an 8-byte boundary, nothing
               added if already aligned (Visa CVN10).
      "EMV"  - ISO/IEC 9797-1 method 2: 0x80 then zeros (Visa CVN18, Mastercard).
    """
    sk = bytes.fromhex(icc_mk_hex.replace(" ", ""))
    if len(sk) != 16:
        raise ValueError("ICC MK / session key must be 16 bytes (32 hex chars).")
    K1 = sk[:8]
    K2 = sk[8:]

    data = bytes.fromhex((cdol_hex or "").replace(" ", ""))
    padding = (padding or "EMV").upper()
    if padding == "EMV":
        data += b"\x80"
    elif padding != "VISA":
        raise ValueError("padding must be 'EMV' or 'VISA'")
    if not data:
        data = b"\x00" * 8
    while len(data) % 8 != 0:
        data += b"\x00"

    h = b"\x00" * 8
    for i in range(0, len(data), 8):
        block = _xor(h, data[i:i + 8])
        h = _ecb_3des(K1 * 3, block)         # single-DES(K1)
    h = _ecb_3des(K2 * 3, h, encrypt=False)   # single-DES decrypt with K2
    h = _ecb_3des(K1 * 3, h)                  # single-DES encrypt with K1
    return h.hex().upper()


# ---------------------------------------------------------------------------
# Session key derivation (EMV Common Session Key — CVN18 / CVN16, 3DES)
# ---------------------------------------------------------------------------
def derive_session_key_cvn18(icc_mk_hex: str, atc_hex: str) -> str:
    """EMV CSK 3DES variant. Returns a 16-byte session key (odd parity)."""
    icc_mk = _normalise_3des_key(icc_mk_hex)
    atc = bytes.fromhex(atc_hex.replace(" ", "").rjust(4, "0"))[-2:]
    F = atc + b"\xF0" + b"\x00" * 5
    R = atc + b"\x0F" + b"\x00" * 5
    sk = _ecb_3des(icc_mk, F) + _ecb_3des(icc_mk, R)
    return _force_odd_parity(sk).hex().upper()


# ---------------------------------------------------------------------------
# AES ICC MK derivation + AES-CMAC ARQC (modern EMV-AES profiles)
# ---------------------------------------------------------------------------
def derive_icc_mk_aes(mdk_hex: str, pan: str, psn: str = "00") -> str:
    """EMV AES ICC MK = AES_MDK(pad16(PAN || PSN, right-aligned, zero-pad on left to 16 digits))."""
    pan_digits = "".join(c for c in pan if c.isdigit())
    psn_digits = "".join(c for c in (psn or "00") if c.isdigit()).zfill(2)[:2]
    src = (pan_digits + psn_digits).rjust(16, "0")[-16:]
    block = bytes.fromhex(src) + b"\x00" * 8       # 16 bytes
    mdk = _normalise_aes_key(mdk_hex)
    return _ecb_aes(mdk, block).hex().upper()       # 16-byte ICC MK


def derive_session_key_aes(icc_mk_hex: str, atc_hex: str) -> str:
    """AES session key (16-byte) using EMV CSK over a 16-byte derivation block."""
    icc_mk = _normalise_aes_key(icc_mk_hex)
    atc = bytes.fromhex(atc_hex.replace(" ", "").rjust(4, "0"))[-2:]
    block = atc + b"\xF0" + b"\x00" * 13
    return _ecb_aes(icc_mk, block).hex().upper()


def compute_arqc_aes(sk_hex: str, cdol_hex: str) -> str:
    """ARQC under AES = first 8 bytes of AES-CMAC over the CDOL data."""
    from cryptography.hazmat.primitives import cmac
    sk = _normalise_aes_key(sk_hex)
    c = cmac.CMAC(algorithms.AES(sk), backend=default_backend())
    c.update(bytes.fromhex((cdol_hex or "").replace(" ", "")))
    return c.finalize()[:8].hex().upper()


# ---------------------------------------------------------------------------
# ARPC — issuer-side response cryptogram (VAC / Mastercard ARPC, Method 1)
# ---------------------------------------------------------------------------
def compute_arpc(sk_hex: str, arqc_hex: str, arc_hex: str, algorithm: str = "3DES") -> str:
    """ARPC Method 1: encrypt(SK, ARQC XOR (ARC || zero-pad)). Always 8 bytes.

    `arc_hex` is the 2-byte (4-hex) Authorization Response Code, e.g.
    `3030` for ASCII "00" approved, `3035` for "05" decline, etc.
    """
    arqc = bytes.fromhex(arqc_hex.replace(" ", ""))
    arc = bytes.fromhex(arc_hex.replace(" ", "").ljust(4, "0"))[:2]
    if algorithm == "3DES":
        if len(arqc) != 8:
            raise ValueError("ARQC must be 8 bytes for 3DES ARPC.")
        sk = _normalise_3des_key(sk_hex)
        xored = _xor(arqc, arc + b"\x00" * 6)
        return _ecb_3des(sk, xored).hex().upper()
    elif algorithm == "AES":
        # For AES the ARQC is still 8 bytes (truncated CMAC). Pad to 16, XOR ARC at the front.
        if len(arqc) not in (8, 16):
            raise ValueError("ARQC must be 8 or 16 bytes for AES ARPC.")
        sk = _normalise_aes_key(sk_hex)
        block = (arqc + b"\x00" * 16)[:16]
        block = _xor(block, arc + b"\x00" * 14)
        # Keep the leftmost 8 bytes: tag 91 (ARPC || ARC) is limited to 16 bytes,
        # so a full 16-byte block plus the 2-byte ARC cannot be carried.
        return _ecb_aes(sk, block)[:8].hex().upper()
    else:
        raise ValueError("algorithm must be 3DES or AES")


# ---------------------------------------------------------------------------
# ARPC Method 2 — Visa CVN18/CVN22, EMV CSK-based profiles (EMV Book 2, 8.2.2)
# ---------------------------------------------------------------------------
def compute_arpc_method2(sk_hex: str, arqc_hex: str, csu_hex: str, pad_hex: str = "") -> str:
    """ARPC Method 2: leftmost 4 bytes of the ISO/IEC 9797-1 alg 3 MAC (EMV padding)
    over ARQC(8) || CSU(4) || Proprietary Authentication Data(0-8), under SK_AC.

    Tag 91 (Issuer Authentication Data) is then ARPC || CSU || PAD.
    3DES only.
    """
    arqc = bytes.fromhex((arqc_hex or "").replace(" ", ""))
    csu = bytes.fromhex((csu_hex or "").replace(" ", ""))
    pad = bytes.fromhex((pad_hex or "").replace(" ", ""))
    if len(arqc) != 8:
        raise ValueError("ARQC must be 8 bytes (16 hex chars).")
    if len(csu) != 4:
        raise ValueError("CSU must be 4 bytes (8 hex chars).")
    if len(pad) > 8:
        raise ValueError("Proprietary Authentication Data must be 0-8 bytes.")
    mac = compute_arqc(sk_hex, (arqc + csu + pad).hex(), padding="EMV")
    return mac[:8]


# ---------------------------------------------------------------------------
# Mastercard M/Chip session key (CVN16 / CVN17)
# ---------------------------------------------------------------------------
def derive_session_key_mastercard(icc_mk_hex: str, atc_hex: str, un_hex: str) -> str:
    """Mastercard proprietary SKD: EMV common session key derivation with the
    diversification value R = ATC(2) || 00 00 || UN(4), i.e.
      SK_L = 3DES_MK(ATC || F0 || 00 || UN),  SK_R = 3DES_MK(ATC || 0F || 00 || UN)
    """
    icc_mk = _normalise_3des_key(icc_mk_hex)
    atc = bytes.fromhex(atc_hex.replace(" ", "").rjust(4, "0"))[-2:]
    un = bytes.fromhex((un_hex or "").replace(" ", ""))
    if len(un) != 4:
        raise ValueError("Unpredictable number (9F37) must be 4 bytes (8 hex chars).")
    sk = _ecb_3des(icc_mk, atc + b"\xF0\x00" + un) + _ecb_3des(icc_mk, atc + b"\x0F\x00" + un)
    return _force_odd_parity(sk).hex().upper()


# ---------------------------------------------------------------------------
# Cryptogram profiles: which keys, padding and ARPC method each CVN uses
# ---------------------------------------------------------------------------
TDES_CVNS = ("CVN10", "CVN18", "MC_CVN16", "MC_CVN17", "MC_CVN20", "MC_CVN21")


def derive_ac_keys(cvn: str, mdk_hex: str, pan: str, psn: str = "00",
                   atc_hex: str | None = None, un_hex: str | None = None) -> dict:
    """Return the keys and rules for a 3DES cryptogram version:

      icc_mk      ICC master key
      sk          key the ARQC MAC runs under
      padding     "VISA" (zeros) or "EMV" (0x80)
      arpc_key    key the ARPC is computed under
      arpc_method 1 or 2

    Visa CVN10   Option A, SK = ICC MK, Visa padding, ARPC M1 under ICC MK
    Visa CVN18   Option B, EMV CSK(ATC), EMV padding, ARPC M2 under SK
    MC CVN16/17  Option A, Mastercard SKD(ATC, UN), EMV padding, ARPC M1 under ICC MK
    MC CVN20/21  Option A, EMV CSK(ATC), EMV padding, ARPC M1 under SK
    (CVN17/21 also MAC the IAD counters; the caller includes them in the data.)
    """
    if cvn not in TDES_CVNS:
        raise ValueError(f"cvn must be one of {', '.join(TDES_CVNS)} or AES.")
    needs_atc = cvn != "CVN10"
    if needs_atc and not atc_hex:
        raise ValueError(f"ATC is required for {cvn} (tag 9F36).")
    if cvn in ("MC_CVN16", "MC_CVN17") and not un_hex:
        raise ValueError(f"Unpredictable number is required for {cvn} (tag 9F37).")

    icc_mk = derive_icc_mk(mdk_hex, pan, psn, option="B" if cvn == "CVN18" else "A")
    if cvn == "CVN10":
        sk, padding, arpc_key, method = icc_mk, "VISA", icc_mk, 1
    elif cvn == "CVN18":
        sk = derive_session_key_cvn18(icc_mk, atc_hex)
        padding, arpc_key, method = "EMV", sk, 2
    elif cvn in ("MC_CVN16", "MC_CVN17"):
        sk = derive_session_key_mastercard(icc_mk, atc_hex, un_hex)
        padding, arpc_key, method = "EMV", icc_mk, 1
    else:  # MC_CVN20 / MC_CVN21
        sk = derive_session_key_cvn18(icc_mk, atc_hex)
        padding, arpc_key, method = "EMV", sk, 1
    return {"icc_mk": icc_mk, "sk": sk, "padding": padding, "arpc_key": arpc_key, "arpc_method": method}


# ---------------------------------------------------------------------------
# IBM 3624 PIN offset
# ---------------------------------------------------------------------------
DEFAULT_DECIMALIZATION_TABLE = "0123456789012345"


def _ibm3624_intermediate(pvk_hex: str, pan: str, table: str, verify_offset: int,
                          verify_length: int | None, pad: str) -> str:
    pan = "".join(c for c in pan if c.isdigit())
    table = (table or DEFAULT_DECIMALIZATION_TABLE).strip()
    if len(table) != 16 or not table.isdigit():
        raise ValueError("Decimalization table must be 16 decimal digits.")
    pad = (pad or "F").upper()
    if len(pad) != 1 or pad not in "0123456789ABCDEF":
        raise ValueError("PAN pad character must be one hex digit.")
    if verify_length is None:
        verify_length = min(len(pan) - verify_offset, 16)
    if verify_offset < 0 or verify_length < 1 or verify_length > 16:
        raise ValueError("Validation data length must be 1-16 digits.")
    data = pan[verify_offset:verify_offset + verify_length]
    if len(data) != verify_length:
        raise ValueError("Validation data offset/length fall outside the PAN.")
    block = bytes.fromhex(data.ljust(16, pad))
    enc = _ecb_3des(_normalise_3des_key(pvk_hex), block).hex().upper()
    return enc.translate(str.maketrans("0123456789ABCDEF", table))


def compute_ibm3624_offset(pvk_hex: str, pin: str, pan: str, table: str = DEFAULT_DECIMALIZATION_TABLE,
                           verify_offset: int = 0, verify_length: int | None = None, pad: str = "F") -> str:
    """Offset = (PIN - natural PIN) mod 10, digit by digit. Offset length = PIN length (4-12)."""
    pin = "".join(c for c in (pin or "") if c.isdigit())
    if not 4 <= len(pin) <= 12:
        raise ValueError("PIN must be 4-12 digits.")
    natural = _ibm3624_intermediate(pvk_hex, pan, table, verify_offset, verify_length, pad)
    return "".join(str((int(p) - int(n)) % 10) for p, n in zip(pin, natural))


def compute_ibm3624_pin(pvk_hex: str, offset: str, pan: str, table: str = DEFAULT_DECIMALIZATION_TABLE,
                        verify_offset: int = 0, verify_length: int | None = None, pad: str = "F") -> str:
    """PIN = (natural PIN + offset) mod 10, digit by digit."""
    offset = (offset or "").strip()
    if not (offset.isdigit() and 4 <= len(offset) <= 12):
        raise ValueError("Offset must be 4-12 digits.")
    natural = _ibm3624_intermediate(pvk_hex, pan, table, verify_offset, verify_length, pad)
    return "".join(str((int(o) + int(n)) % 10) for o, n in zip(offset, natural))
