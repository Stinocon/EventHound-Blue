"""Knowledge interface — ATT&CK map and compliance obligations, one door.

This is deliberately NOT a migration: the v1 engine already owns the data
and the queries, and copying them into a second store would be a duplicate
that drifts (``method/minimal-code.md``: does it already exist here? use it).
What v2 adds is the single entry point:

- ATT&CK — ``analytics/attack.py`` over the vendored ``attack_map.json``
  (lazy in-memory lookup; the official STIX bundle is the source of truth).
- GDPR/NIS2/DORA obligations — ``tools/compliance/compliance.py`` over
  ``obligations.yaml`` (golden-tested resolver; not legal advice, §6).

The ACN guidance under ``method/acn/`` is PDF-only: not machine-queryable
without OCR, so it stays a human-readable source and is not wrapped here.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from core.bootstrap import ensure_engine_path

ensure_engine_path()  # analytics (attack map) lives in analysis/

#: Technique ID in canonical form: T1059 or T1059.001 (after normalization).
_TECHNIQUE_SHAPE = re.compile(r"^T\d{4}(\.\d{3})?$")

_TOOLS_COMPLIANCE_DIR = (
    Path(__file__).resolve().parent.parent / "tools" / "compliance"
)
if str(_TOOLS_COMPLIANCE_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_COMPLIANCE_DIR))


# --- ATT&CK -----------------------------------------------------------------


def attack_version() -> str:
    """Version of the vendored ATT&CK map (e.g. ``'19.1'``)."""
    from analytics import attack

    return attack.attack_version()


def technique(tid: str) -> dict:
    """Name, tactics and kill-chain phases of one technique ID.

    Accepts the soft-hyphen spelling Hayabusa emits (``T1059-001``) and
    normalizes it; rejects anything that is not a technique ID in shape.
    """
    from analytics import attack

    tid = attack._norm_tid(tid)  # noqa: SLF001 — canonical spelling of the ID
    if not _TECHNIQUE_SHAPE.fullmatch(tid):
        raise ValueError(f"not a technique ID: {tid!r}")
    return {
        "id": tid,
        "name": attack.technique_name(tid),
        "tactics": attack.tactics_of(tid),
        "phases": attack.phases_of(tid),
    }


# --- GDPR / NIS2 / DORA obligations -------------------------------------------


def obligations_for(incident: dict) -> dict:
    """Notification obligations triggered by an incident.

    ``incident`` carries the trigger attributes (``personal_data_breach``,
    ``entity_type``, ``significant_incident``, ...). Returns the resolver's
    summary: every applicable obligation with its deadline, ordered by
    urgency. Deterministic oracle output (§6) — not legal advice.
    """
    import compliance

    return compliance.summary(incident)


__all__ = ["attack_version", "obligations_for", "technique"]
