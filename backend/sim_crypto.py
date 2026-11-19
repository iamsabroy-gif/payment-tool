"""Issuer-side cryptogram checks for the built-in simulator.

When a transaction is sent to the simulator together with a key set from the
user's key vault, `run_issuer_checks` verifies whatever cryptographic data the
request carries and `build_arpc_tlv` answers a verified ARQC:

  - Track 2 CVV  (F35)  : CVV1 under CVK_A/CVK_B, or iCVV (service code 999)
                          when the request also carries chip data (F55).
  - PIN          (F52)  : decrypt the ISO-0 3DES PIN block under the PEK
                          (key set extra ZPK, PEK or TPK) and check it against
                          the PVKI/PVV in track 2 under PVK_A/PVK_B.
  - ARQC         (F55)  : under the MDK. The CVN is read from IAD (9F10):
                            Visa (formats 0/1/3)  byte 2: 0A=CVN10, 12=CVN18,
                                                  CVR = bytes 3-6
                            Mastercard M/Chip     byte 1: 10/11/14/15 = CVN16/17/20/21,
                                                  CVR = bytes 2-7, counters = bytes 10-17
                          The request's network picks the layout; other networks
                          try Visa, then Mastercard.

Track 2 discretionary data uses the common Visa layout:
    PVKI(1) || PVV(4) || CVV(3) || ...

Each check yields {"check", "result": pass|fail|skipped, "detail"}. A failed
check sets the response code; skipped checks never do.
"""
from __future__ import annotations

import hmac
from typing import Dict, List, Optional, Tuple

from key_management import (
    compute_arpc, compute_arpc_method2, compute_arqc, compute_cvv, compute_pvv, derive_ac_keys,
)
from pin_crypto import decrypt_pin_block

RC_CRYPTO_FAIL = "82"     # Visa: negative CAM, dCVV, iCVV or CVV results
RC_PIN_WRONG = "55"       # Incorrect PIN
RC_PIN_CRYPTO = "81"      # PIN cryptographic error
RC_FORMAT = "30"          # Format error

PEK_ALIASES = ("ZPK", "PEK", "TPK")

# Terminal/card tags that make up the Visa and Mastercard ARQC input, in order.
AC_TAGS = ("9F02", "9F03", "9F1A", "95", "5F2A", "9A", "9C", "9F37", "82", "9F36")
VISA_CVNS = {0x0A: "CVN10", 0x12: "CVN18"}
MC_CVNS = {0x10: "MC_CVN16", 0x11: "MC_CVN17", 0x14: "MC_CVN20", 0x15: "MC_CVN21"}


def detect_cvn(iad: bytes, network_id: Optional[str] = None) -> Optional[Tuple[str, bytes]]:
    """Return (cvn, extra MAC data taken from the IAD) or None if unsupported."""
    def visa():
        if len(iad) >= 7 and iad[2] in VISA_CVNS:
            cvn = VISA_CVNS[iad[2]]
            return cvn, (iad[3:7] if cvn == "CVN10" else iad)
        return None

    def mastercard():
        if len(iad) >= 8 and iad[1] in MC_CVNS:
            cvn = MC_CVNS[iad[1]]
            extra = iad[2:8]                                  # CVR
            if cvn in ("MC_CVN17", "MC_CVN21"):
                if len(iad) < 18:
                    return None
                extra += iad[10:18]                           # counters
            return cvn, extra
        return None

    net = (network_id or "").lower()
    order = {"visa": (visa,), "mastercard": (mastercard,)}.get(net, (visa, mastercard))
    for fn in order:
        found = fn()
        if found:
            return found
    return None


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def parse_track2(track2: str) -> Optional[Dict[str, str]]:
    t = (track2 or "").strip().upper().lstrip(";").rstrip("?").rstrip("F")
    sep = "D" if "D" in t else ("=" if "=" in t else None)
    if not sep:
        return None
    pan, rest = t.split(sep, 1)
    if not pan.isdigit() or len(rest) < 7:
        return None
    disc = rest[7:]
    return {
        "pan": pan, "expiry": rest[:4], "service_code": rest[4:7], "discretionary": disc,
        "pvki": disc[0:1], "pvv": disc[1:5], "cvv": disc[5:8],
    }


def parse_tlv(hex_str: str) -> Dict[str, str]:
    """Minimal BER-TLV parser (primitive tags, one level). Returns {TAG: value_hex}."""
    data = bytes.fromhex((hex_str or "").replace(" ", ""))
    out: Dict[str, str] = {}
    i = 0
    while i < len(data):
        if data[i] in (0x00, 0xFF):        # padding between objects
            i += 1
            continue
        start = i
        i += 1
        if data[start] & 0x1F == 0x1F:     # multi-byte tag
            while i < len(data) and data[i] & 0x80:
                i += 1
            i += 1
        tag = data[start:i].hex().upper()
        if i >= len(data):
            raise ValueError(f"TLV truncated after tag {tag}")
        length = data[i]
        i += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(data[i:i + n], "big")
            i += n
        if i + length > len(data):
            raise ValueError(f"TLV value for {tag} runs past the end of the data")
        out[tag] = data[i:i + length].hex().upper()
        i += length
    return out


def _tlv(tag: str, value_hex: str) -> str:
    return f"{tag}{len(value_hex) // 2:02X}{value_hex}"


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").upper().encode(), (b or "").upper().encode())


def _get(de: Dict, n: int) -> str:
    return str(de.get(str(n)) or de.get(n) or "")


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
def _check_cvv(de: Dict, keyset: Dict, t2: Optional[Dict]) -> Dict:
    name = "CVV (track 2)"
    if not t2:
        return {"check": name, "result": "skipped", "detail": "no track 2 (F35)"}
    if not (keyset.get("cvk_a_hex") and keyset.get("cvk_b_hex")):
        return {"check": name, "result": "skipped", "detail": "key set has no CVK_A/CVK_B"}
    chip = bool(_get(de, 55))
    svc = "999" if chip else t2["service_code"]
    kind = "iCVV" if chip else "CVV1"
    if len(t2["cvv"]) != 3 or not t2["cvv"].isdigit():
        return {"check": name, "result": "fail", "detail": f"no {kind} at track 2 discretionary data offset 5"}
    try:
        expected = compute_cvv(t2["pan"], t2["expiry"], svc, keyset["cvk_a_hex"], keyset["cvk_b_hex"])
    except ValueError as e:
        return {"check": name, "result": "fail", "detail": str(e)}
    ok = _same(expected, t2["cvv"])
    return {"check": name, "result": "pass" if ok else "fail", "detail": f"{kind} {'matches' if ok else 'does not match'}"}


def _check_pin(de: Dict, keyset: Dict, t2: Optional[Dict]) -> Tuple[Dict, Optional[str]]:
    name = "PIN / PVV (F52)"
    block = _get(de, 52)
    if not block:
        return {"check": name, "result": "skipped", "detail": "no PIN block (F52)"}, None
    if not (keyset.get("pvk_a_hex") and keyset.get("pvk_b_hex")):
        return {"check": name, "result": "skipped", "detail": "key set has no PVK_A/PVK_B"}, None
    extras = keyset.get("extras") or {}
    alias = next((a for a in PEK_ALIASES if extras.get(a)), None)
    if not alias:
        return {"check": name, "result": "skipped", "detail": "key set has no PIN key (extra ZPK, PEK or TPK)"}, None
    if not t2 or not (t2["pvki"].isdigit() and len(t2["pvv"]) == 4 and t2["pvv"].isdigit()):
        return {"check": name, "result": "skipped", "detail": "no PVKI/PVV in track 2 to verify against"}, None
    pan = _get(de, 2) or t2["pan"]
    try:
        pin = decrypt_pin_block(block, pan, extras[alias], "ISO-0", "3DES")
    except ValueError as e:
        return {"check": name, "result": "fail", "detail": f"PIN block under {alias}: {e}"}, RC_PIN_CRYPTO
    try:
        expected = compute_pvv(pan, pin, t2["pvki"], keyset["pvk_a_hex"], keyset["pvk_b_hex"])
    except ValueError as e:
        return {"check": name, "result": "fail", "detail": str(e)}, RC_PIN_CRYPTO
    if _same(expected, t2["pvv"]):
        return {"check": name, "result": "pass", "detail": f"PIN matches PVV (PVKI {t2['pvki']})"}, None
    return {"check": name, "result": "fail", "detail": "PIN does not match PVV"}, RC_PIN_WRONG


def _check_arqc(de: Dict, keyset: Dict, t2: Optional[Dict],
                network_id: Optional[str] = None) -> Tuple[Dict, Optional[str], Optional[Dict]]:
    name = "ARQC (F55)"
    icc = _get(de, 55)
    if not icc:
        return {"check": name, "result": "skipped", "detail": "no chip data (F55)"}, None, None
    if not keyset.get("mdk_hex"):
        return {"check": name, "result": "skipped", "detail": "key set has no MDK"}, None, None
    try:
        tags = parse_tlv(icc)
    except ValueError as e:
        return {"check": name, "result": "fail", "detail": f"F55: {e}"}, RC_FORMAT, None
    if "9F26" not in tags:
        return {"check": name, "result": "skipped", "detail": "F55 has no ARQC (9F26)"}, None, None
    iad = bytes.fromhex(tags.get("9F10", ""))
    missing = [t for t in AC_TAGS if t not in tags] + ([] if iad else ["9F10"])
    if missing:
        return {"check": name, "result": "fail", "detail": f"F55 is missing {', '.join(missing)}"}, RC_FORMAT, None
    found = detect_cvn(iad, network_id)
    if not found:
        return {"check": name, "result": "fail",
                "detail": f"unsupported IAD / CVN (9F10={iad.hex().upper()}); supported: Visa CVN10/18, "
                          "Mastercard CVN16/17/20/21"}, RC_FORMAT, None
    cvn, iad_data = found

    pan = _get(de, 2) or (t2 or {}).get("pan", "")
    psn = tags.get("5F34") or _get(de, 23)[-2:] or "00"
    atc = tags["9F36"]
    data = "".join(tags[t] for t in AC_TAGS) + iad_data.hex()
    try:
        keys = derive_ac_keys(cvn, keyset["mdk_hex"], pan, psn, atc, tags["9F37"])
        expected = compute_arqc(keys["sk"], data, padding=keys["padding"])
    except ValueError as e:
        return {"check": name, "result": "fail", "detail": str(e)}, RC_FORMAT, None
    label = cvn.replace("MC_", "Mastercard ") if cvn.startswith("MC_") else f"Visa {cvn}"
    if _same(expected, tags["9F26"]):
        ctx = {"cvn": cvn, "sk": keys["sk"], "arpc_key": keys["arpc_key"],
               "arpc_method": keys["arpc_method"], "arqc": tags["9F26"]}
        return {"check": name, "result": "pass", "detail": f"{label} ARQC matches (ATC {atc})"}, None, ctx
    return {"check": name, "result": "fail", "detail": f"{label} ARQC does not match"}, RC_CRYPTO_FAIL, None


def run_issuer_checks(request_mti: str, de: Dict, keyset: Dict, network_id: Optional[str] = None) -> Dict:
    """Run every applicable check. Returns {"rc": str|None, "checks": [...], "arpc_ctx": dict|None}.

    `rc` is the response code of the first failing check in issuer order
    (ARQC, then CVV, then PIN), or None if nothing failed.
    """
    if request_mti.startswith("08"):
        return {"rc": None, "checks": [], "arpc_ctx": None}
    t2 = parse_track2(_get(de, 35))
    arqc_check, arqc_rc, ctx = _check_arqc(de, keyset, t2, network_id)
    cvv_check = _check_cvv(de, keyset, t2)
    pin_check, pin_rc = _check_pin(de, keyset, t2)
    cvv_rc = RC_CRYPTO_FAIL if cvv_check["result"] == "fail" else None
    rc = arqc_rc or cvv_rc or pin_rc
    return {"rc": rc, "checks": [arqc_check, cvv_check, pin_check], "arpc_ctx": ctx}


def build_arpc_tlv(ctx: Dict, response_code: str) -> str:
    """F55 response with tag 91 for a verified ARQC.

    Method 1 (Visa CVN10, Mastercard): ARC = ASCII of the response code ("00" -> 3030),
      under the ICC MK (CVN10, MC CVN16/17) or the session key (MC CVN20/21).
    Method 2 (Visa CVN18): CSU 00000000; CSU contents are not modelled.
    """
    if ctx["arpc_method"] == 1:
        arc = (response_code or "  ")[:2].encode("ascii").hex().upper()
        return _tlv("91", compute_arpc(ctx["arpc_key"], ctx["arqc"], arc, "3DES") + arc)
    csu = "00000000"
    return _tlv("91", compute_arpc_method2(ctx["sk"], ctx["arqc"], csu) + csu)
