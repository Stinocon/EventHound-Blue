"""Pattern‑detection functions.

Each function scans a text string for a specific encoding pattern,
extracts the candidate substring, calls the corresponding decoder in
``decoders``, and returns one or more ``DecodeResult``.

Detectors that require a pre‑decoded byte buffer (XOR) also live here;
they embed their own hex/base64 extraction logic.
"""
from __future__ import annotations

import re

from .decoders import (
    DecodeResult,
    decode_base58,
    decode_base64,
    decode_hex,
    decode_rot_detect,
    decode_unicode_escape,
    decode_url,
    decode_xor_single,
)

# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
# Minimum length after which a purely‑alpha string is suspicious
_BASE64_MIN_LEN = 16


def detect_base64(text: str) -> list[DecodeResult]:
    """Find candidate base64 strings and try decoding them."""
    results: list[DecodeResult] = []
    seen_originals: set[str] = set()
    for m in _BASE64_RE.finditer(text):
        s = m.group()
        # Skip short / purely‑alphabetic strings that happen to match the regex
        if s.isalpha() and len(s) < _BASE64_MIN_LEN:
            continue
        if s in seen_originals:
            continue
        seen_originals.add(s)
        r = decode_base64(s)
        if r is not None:
            results.append(r)
    return results


# ---------------------------------------------------------------------------
# Hex string
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")


def detect_hex(text: str) -> list[DecodeResult]:
    """Find candidate hex strings (min 16 hex chars = 8 bytes), even length."""
    results: list[DecodeResult] = []
    seen_originals: set[str] = set()
    for m in _HEX_RE.finditer(text):
        s = m.group()
        raw = s[2:] if s.startswith("0x") or s.startswith("0X") else s
        if len(raw) % 2 != 0:
            continue
        if s in seen_originals:
            continue
        seen_originals.add(s)
        r = decode_hex(s)
        if r is not None:
            results.append(r)
    return results


# ---------------------------------------------------------------------------
# URL encoding
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


def detect_url(text: str) -> list[DecodeResult]:
    """Detect URL‑encoded content — requires ≥2 ``%XX`` sequences."""
    if len(_URL_PATTERN.findall(text)) >= 2:
        r = decode_url(text)
        if r is not None:
            return [r]
    return []


# ---------------------------------------------------------------------------
# ROT13 / ROT‑N
# ---------------------------------------------------------------------------

_ROT_WORD_RE = re.compile(r"[A-Za-z]{4,}")
# Common short words that are very unlikely to be ROT-encoded
_COMMON_WORDS = frozenset(
    {
        "the", "and", "for", "are", "but", "not", "you", "all", "any", "can",
        "had", "her", "was", "one", "our", "out", "has", "have", "been",
        "some", "them", "than", "that", "this", "very", "just", "also",
        "more", "over", "such", "will", "with", "would", "could", "should",
        "from", "they", "what", "when", "where", "which", "their",
        "there", "each", "made", "said", "does", "down", "take", "into",
        "your", "then", "many",
    }
)


def detect_rot(text: str) -> list[DecodeResult]:
    """Scan short letter sequences and try ROT shifts on each."""
    results: list[DecodeResult] = []
    seen: set[str] = set()
    for m in _ROT_WORD_RE.finditer(text):
        word = m.group()
        if len(word) < 4:
            continue
        if word.lower() in _COMMON_WORDS:
            continue
        if word in seen:
            continue
        seen.add(word)
        r = decode_rot_detect(word)
        if r is not None:
            results.append(r)
    return results


# ---------------------------------------------------------------------------
# Base58
# ---------------------------------------------------------------------------

_BASE58_RE = re.compile(
    r"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{20,}"
)


def detect_base58(text: str) -> list[DecodeResult]:
    """Find base58‑looking strings (at least 20 chars)."""
    results: list[DecodeResult] = []
    seen: set[str] = set()
    for m in _BASE58_RE.finditer(text):
        s = m.group()
        if s in seen:
            continue
        seen.add(s)
        r = decode_base58(s)
        if r is not None:
            results.append(r)
    return results


# ---------------------------------------------------------------------------
# Unicode escape  (\\uXXXX, \\xXX)
# ---------------------------------------------------------------------------

_UNICODE_ESCAPE_RE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})")


def detect_unicode_escape(text: str) -> list[DecodeResult]:
    """Detect Unicode‑escaped strings — requires ≥2 escape sequences."""
    if len(_UNICODE_ESCAPE_RE.findall(text)) >= 2:
        r = decode_unicode_escape(text)
        if r is not None:
            return [r]
    return []


# ---------------------------------------------------------------------------
# XOR single‑byte (on hex candidates)
# ---------------------------------------------------------------------------

def detect_xor_from_hex(text: str) -> list[DecodeResult]:
    """Find hex strings, decode to bytes (even if not UTF‑8), try XOR."""
    results: list[DecodeResult] = []
    seen: set[str] = set()
    for m in _HEX_RE.finditer(text):
        s = m.group()
        if s in seen:
            continue
        seen.add(s)
        raw = s[2:] if s.startswith("0x") or s.startswith("0X") else s
        if len(raw) % 2 != 0:
            continue
        try:
            data = bytes.fromhex(raw)
        except ValueError:
            continue
        if not data:
            continue
        r = decode_xor_single(data)
        if r is not None:
            results.append(r)
    return results


# ---------------------------------------------------------------------------
# XOR single‑byte (on base64 candidates)
# ---------------------------------------------------------------------------

def detect_xor_from_base64(text: str) -> list[DecodeResult]:
    """Find base64 strings, decode to bytes (incl. binary), try XOR."""
    import base64 as b64mod

    results: list[DecodeResult] = []
    seen: set[str] = set()
    for m in _BASE64_RE.finditer(text):
        s = m.group()
        if s in seen:
            continue
        seen.add(s)
        # Pad
        r = len(s) % 4
        if r:
            padded = s + "=" * (4 - r)
        else:
            padded = s
        try:
            data = b64mod.b64decode(padded)
        except Exception:  # noqa: BLE001
            continue
        if not data:
            continue
        r = decode_xor_single(data)
        if r is not None:
            results.append(r)
    return results
