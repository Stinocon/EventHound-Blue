"""Orchestration — scan text or structured records for encoded content.

Usage::

    from decode.runner import scan_text, scan_fields

    results = scan_text("the password is SGVsbG8gV29ybGQ=")
    for r in results:
        print(f"{r.encoder:>12}  {r.decoded}")
"""
from __future__ import annotations

from .decoders import DecodeResult
from . import detectors


def scan_text(text: str, min_confidence: float = 0.5) -> list[DecodeResult]:
    """Scan *text* for encoded content using every available detector.

    Returns results sorted by **confidence descending**. Duplicate ``original``
    strings from different detectors are de‑duplicated — the highest‑confidence
    result wins.
    """
    candidates: list[DecodeResult] = []

    # ── primary detectors ────────────────────────────────────────────────
    candidates.extend(detectors.detect_base64(text))
    candidates.extend(detectors.detect_hex(text))
    candidates.extend(detectors.detect_url(text))
    candidates.extend(detectors.detect_rot(text))
    candidates.extend(detectors.detect_base58(text))
    candidates.extend(detectors.detect_unicode_escape(text))

    # ── XOR follow‑up (on hex / base64 candidates that decode to bytes) ─
    candidates.extend(detectors.detect_xor_from_hex(text))
    candidates.extend(detectors.detect_xor_from_base64(text))

    # ── deduplicate by (encoder, original) — keep highest confidence ────
    seen: dict[tuple[str, str], DecodeResult] = {}
    for r in candidates:
        key = (r.encoder, r.original)
        if key not in seen or r.confidence > seen[key].confidence:
            seen[key] = r

    results = list(seen.values())
    results.sort(key=lambda r: r.confidence, reverse=True)
    return [r for r in results if r.confidence >= min_confidence]


def scan_fields(
    record: dict,
    fields: list[str] | None = None,
    min_confidence: float = 0.5,
) -> dict[str, list[DecodeResult]]:
    """Scan specific *fields* of a structured record for encoded content.

    If *fields* is ``None``, every string field of *record* is scanned.
    Returns a dict mapping field names to their (possibly empty) result list.
    """
    out: dict[str, list[DecodeResult]] = {}
    for key, value in record.items():
        if fields is not None and key not in fields:
            continue
        if isinstance(value, str):
            decoded = scan_text(value, min_confidence=min_confidence)
            if decoded:
                out[key] = decoded
    return out
