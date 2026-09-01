"""Pure decoding functions, one per encoding type.

Each function takes a (clean) encoded string and returns DecodeResult | None.
These are the low-level decode primitives called by detectors and the runner.
"""
from __future__ import annotations

import base64
import codecs
import re
import urllib.parse
from dataclasses import dataclass


@dataclass
class DecodeResult:
    """Result of a successful decode attempt."""

    encoder: str  # "base64", "hex", "url", "rot13", "xor_single", "base58", "unicode_escape"
    original: str  # the encoded string
    decoded: str  # the decoded string
    confidence: float  # 0.0-1.0
    notes: str = ""  # extra info (e.g. "XOR key: 0x42")


# ---------------------------------------------------------------------------
# Helper: English‑likeness heuristic
# ---------------------------------------------------------------------------

_COMMON_ENGLISH = set("etaoinshrdluETAOINSHRDLU ")


def _english_ratio(text: str) -> float:
    """Fraction of characters that are common English letters + space.

    Used to judge ROT success and confidence weighting.
    """
    if not text:
        return 0.0
    return sum(1 for c in text if c in _COMMON_ENGLISH) / len(text)


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------

# Words that happen to match the base64 regex but are clearly not base64.
_BASE64_BLOCKLIST = frozenset(
    {
        # Common programming / config tokens
        "undefined",
        "null",
        "true",
        "false",
        "nan",
        "inf",
        "infinity",
        "base64",
        "base58",
        "encode",
        "decode",
        "string",
        "buffer",
        "length",
        "format",
        "value",
        "values",
        "object",
        "number",
        "status",
        "public",
        "private",
        "static",
        "import",
        "export",
        "default",
        "extends",
        "return",
        "throws",
        "throw",
        "class",
        "const",
        "finally",
        "instance",
        "interface",
        "namespace",
        "package",
        "require",
        "exception",
        "typeerror",
        "referenceerror",
        "syntaxerror",
        "assertionerror",
        "attributeerror",
        "keyerror",
        "valueerror",
        "zerodivisionerror",
        "localhost",
        "password",
        "username",
        "session",
        "timeout",
    }
)


def decode_base64(s: str) -> DecodeResult | None:
    """Try standard base64 then base64url decode.

    Returns confidence 0.9 if the decoded result is printable UTF‑8,
    0.5 (with a note) if it decodes to binary data.
    """
    s_stripped = s.strip()
    # Check both the full string and the string without trailing = padding
    check = s_stripped.rstrip("=").lower()
    if check in _BASE64_BLOCKLIST:
        return None

    # Pad to multiple of 4 if needed (lenient)
    def _pad(data: str) -> str:
        r = len(data) % 4
        if r:
            return data + "=" * (4 - r)
        return data

    for variant, b64decode in [("std", base64.b64decode), ("urlsafe", base64.urlsafe_b64decode)]:
        try:
            decoded = b64decode(_pad(s_stripped))
        except (Exception):  # noqa: BLE001
            continue

        try:
            text = decoded.decode("utf-8")
            # Only accept if there's at least one printable character
            if any(c.isprintable() for c in text):
                return DecodeResult("base64", s_stripped, text, 0.9)
        except UnicodeDecodeError:
            # Valid base64, but binary payload
            return DecodeResult("base64", s_stripped, decoded.hex(), 0.5, notes="binary data")

    return None


# ---------------------------------------------------------------------------
# Hex string
# ---------------------------------------------------------------------------

def decode_hex(s: str) -> DecodeResult | None:
    """Strip optional ``0x`` prefix and decode hex pairs.

    Returns the decoded text only if it is valid UTF‑8.
    Confidence 0.8.
    """
    raw = s.strip()
    if raw.startswith("0x") or raw.startswith("0X"):
        raw = raw[2:]
    if len(raw) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", raw):
        return None
    try:
        decoded = bytes.fromhex(raw)
    except ValueError:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return DecodeResult("hex", s.strip(), text, 0.8)


# ---------------------------------------------------------------------------
# URL encoding
# ---------------------------------------------------------------------------

def decode_url(s: str) -> DecodeResult | None:
    """URL‑decode via ``urllib.parse.unquote``.

    Confidence 0.95 when at least one %‑sequence was present and resolved.
    """
    try:
        result = urllib.parse.unquote(s, encoding="utf-8")
    except Exception:  # noqa: BLE001
        return None
    if result != s:
        return DecodeResult("url", s, result, 0.95)
    return None


# ---------------------------------------------------------------------------
# ROT13 / ROT‑N detection
# ---------------------------------------------------------------------------

def _rot_shift(s: str, n: int) -> str:
    out: list[str] = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - ord("a") + n) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - ord("A") + n) % 26 + ord("A")))
        else:
            out.append(c)
    return "".join(out)


def decode_rot_detect(s: str) -> DecodeResult | None:
    """Try ROT1‑ROT25 and return the best result if the improvement is significant.

    To avoid false positives on plain English words or base64 substrings:
    * original text has a low English‑letter ratio (< 0.55), meaning it looks
      *unlike* English;
    * the best ROT shift produces a *substantial* improvement (> 0.25);
    * case pattern is uniform (all-upper, all-lower, or title-case) — mixed
      case (common in base64) is rejected.
    """
    if not s or len(s) < 3:
        return None

    # ── case-pattern guard against base64-like strings ──────────────────
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    if has_upper and has_lower:
        # Allow only title-case: first char upper, rest lower
        if not (s[0].isupper() and all(c.islower() for c in s[1:])):
            return None

    input_score = _english_ratio(s)
    # If the input already looks English, do not attempt ROT
    if input_score >= 0.55:
        return None

    best_n = 0
    best_text = ""
    best_score = input_score

    for n in range(1, 26):
        shifted = _rot_shift(s, n)
        score = _english_ratio(shifted)
        if score > best_score:
            best_score = score
            best_text = shifted
            best_n = n

    improvement = best_score - input_score
    if improvement > 0.25 and best_score > 0.45:
        confidence = min(0.9, 0.4 + best_score * 0.4 + improvement * 0.2)
        label = f"ROT{best_n}" if best_n != 13 else "ROT13"
        return DecodeResult("rot13", s, best_text, confidence, notes=label)

    return None


# ---------------------------------------------------------------------------
# XOR single‑byte
# ---------------------------------------------------------------------------

def decode_xor_single(data: bytes) -> DecodeResult | None:
    """Try XOR with each byte 0x00‑0xFF and return the key producing the most printable UTF‑8.

    Among keys that produce 100 % printable output, the one with the highest
    English‑likeness ratio is chosen.  Confidence fixed at 0.7 per spec.
    """
    best_key = -1
    best_text = ""
    best_eng_score = -1.0

    for key in range(256):
        decoded = bytes(b ^ key for b in data)
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not text:
            continue
        printable = sum(1 for c in text if c.isprintable())
        ratio = printable / len(text)
        if ratio == 1.0:
            eng = _english_ratio(text)
            if eng > best_eng_score:
                best_eng_score = eng
                best_key = key
                best_text = text

    if best_key >= 0 and best_text:
        # Identity (0x00) and inversion (0xFF) are not meaningful XOR encoding
        if best_key in (0x00, 0xFF):
            return None
        return DecodeResult(
            "xor_single",
            data.hex(),
            best_text,
            0.7,
            notes=f"XOR key: 0x{best_key:02x}",
        )
    return None


# ---------------------------------------------------------------------------
# Base58
# ---------------------------------------------------------------------------

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_LOOKUP = {c: i for i, c in enumerate(_BASE58_ALPHABET)}


def decode_base58(s: str) -> DecodeResult | None:
    """Decode a base58 string (no external deps).

    Confidence 0.6 — many false positives possible.
    """
    n = 0
    for c in s.strip():
        idx = _BASE58_LOOKUP.get(c)
        if idx is None:
            return None
        n = n * 58 + idx
    try:
        byte_len = (n.bit_length() + 7) // 8
        if byte_len == 0:
            return None
        decoded = n.to_bytes(byte_len, "big")
    except (ValueError, OverflowError):
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    return DecodeResult("base58", s.strip(), text, 0.6, notes="base58 decoded (low confidence)")


# ---------------------------------------------------------------------------
# Unicode escape  (\\uXXXX, \\xXX)
# ---------------------------------------------------------------------------

def decode_unicode_escape(s: str) -> DecodeResult | None:
    """Decode ``\\uXXXX`` / ``\\xXX`` escape sequences via ``codecs.decode``.

    Confidence 0.9.
    """
    # Require at least one actual escape sequence in the input
    if not re.search(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|U[0-9a-fA-F]{8})", s):
        return None
    try:
        result = codecs.decode(s, "unicode_escape")  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001
        return None
    if result and result != s:
        return DecodeResult("unicode_escape", s, result, 0.9)
    return None
