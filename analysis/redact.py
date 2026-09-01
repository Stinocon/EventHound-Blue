"""Anonymization gate — pseudonymize real client identifiers before a result reaches an agent (§9).

The analysis MCP hands findings to an agent that may be a CLOUD model. §9 is non-negotiable:
hostnames, usernames, internal IPs, domains and emails are real client identifiers and must not
enter a cloud model's context. This gate pseudonymizes them BEFORE the MCP responds, exactly as for
a shareable report.

Map-based and deterministic: the authority on "what is a real client identifier and its stable
pseudonym" is `data/pseudonym-map.md` (private, gitignored) — the same SOT `tools/check-leaks.sh`
reads. We do NOT heuristically guess identifiers: a heuristic cannot tell a client IP (redact)
from a public malicious IP (must NOT be pseudonymized, §9), so guessing would corrupt indicators.

Honesty (§6/§9): if the map is empty/absent the gate is a NO-OP — `active` is False and the caller
must warn that real identifiers will not be pseudonymized. An empty map is not a safe map.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = REPO_ROOT / "data" / "pseudonym-map.md"

# Placeholder/header/separator cells to ignore — mirrors tools/check-leaks.sh so both read the
# map identically (one datum, one interpretation, §16 SOT).
_PLACEHOLDER = re.compile(r"da compilare|^reale$|^pseudonimo$|^\(es\.|^_\(|^[-:\s]+$", re.IGNORECASE)
_MIN_LEN = 4  # ignore very short values (like check-leaks): too collision-prone to substitute


def _parse_map(text: str) -> list[tuple[str, str]]:
    """Extract (real, pseudonym) pairs from the Markdown tables `| pseudonimo | reale |`.
    Same column convention as check-leaks: pseudonym = 1st visible cell, real = 2nd."""
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.split("|")]
        # "| a | b |".split("|") -> ["", "a", "b", ""]: [1]=pseudonym, [2]=real
        if len(cells) < 4:
            continue
        pseudo, real = cells[1], cells[2]
        if len(real) < _MIN_LEN or _PLACEHOLDER.search(real) or _PLACEHOLDER.search(pseudo):
            continue
        pairs.append((real, pseudo))
    return pairs


class Redactor:
    """Substitutes real client identifiers with their stable pseudonyms. Case-insensitive
    substring substitution (like the leak guard's `grep -i`), longest real value first so a
    longer identifier is replaced before a shorter one it may contain."""

    def __init__(self, pairs: list[tuple[str, str]]):
        uniq = sorted(set(pairs), key=lambda p: len(p[0]), reverse=True)
        self._patterns = [(re.compile(re.escape(real), re.IGNORECASE), pseudo)
                          for real, pseudo in uniq]
        self.count = len(uniq)

    @property
    def active(self) -> bool:
        return bool(self._patterns)

    def apply(self, text: str) -> str:
        if not text or not self._patterns:
            return text
        for pat, pseudo in self._patterns:
            text = pat.sub(pseudo, text)
        return text

    def apply_obj(self, obj):
        """Recursively pseudonymize every string in a JSON-like structure."""
        if isinstance(obj, str):
            return self.apply(obj)
        if isinstance(obj, list):
            return [self.apply_obj(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.apply_obj(v) for k, v in obj.items()}
        return obj


def load_redactor(map_path: str | Path = MAP_PATH) -> Redactor:
    """Build a Redactor from the pseudonym map. Absent/empty map → an inactive (no-op) Redactor."""
    p = Path(map_path)
    if not p.exists():
        return Redactor([])
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return Redactor([])
    return Redactor(_parse_map(text))
