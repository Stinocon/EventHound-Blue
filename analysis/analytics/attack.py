"""ATT&CK technique → tactic → kill-chain phase, for the correlation engine.

Two distinct things, deliberately kept apart:

1. **technique → tactic** is *fact*, owned by MITRE. It comes from `attack_map.json`, a
   mechanical projection of the official STIX bundle (see `build_attack_map.py`). Nothing here is
   hand-authored, so it cannot silently drift from the source (§6).

2. **tactic → kill-chain phase** is *interpretation*. The Lockheed Martin Cyber Kill Chain is a
   linear narrative grid; ATT&CK is a non-sequential matrix, and `method/framework/cyber-kill-chain.md`
   is explicit that the correspondence "is not one-to-one and should be treated as guidance, not as
   a rigid mapping". The table below therefore encodes the *conventional* reading, is documented
   inline with its reasoning, and every output that uses it is labelled as guidance — never as a
   verdict on how far an intrusion progressed.

The engine's job stays what it always was: it *signals* (technique T1021.002 on HOST-01, phases
Delivery→Installation covered), the analyst concludes.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).resolve().parent / "attack_map.json"

# The seven Lockheed Martin phases, in order. `ORDER` is what makes "how deep did this cluster get"
# expressible as a number; index 0 is reserved for "no ATT&CK evidence at all".
KILLCHAIN_PHASES = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command and Control", "Actions on Objectives",
]
PHASE_ORDER = {p: i + 1 for i, p in enumerate(KILLCHAIN_PHASES)}

# ATT&CK tactic (STIX phase_name) → kill-chain phase. Guidance, not doctrine — see the module
# docstring and method/framework/cyber-kill-chain.md.
#
# Reasoning for the non-obvious rows:
#   • resource-development → Weaponization: it is the attacker preparing infrastructure/payloads,
#     which is exactly what Weaponization narrates (and it is almost never observable in our data).
#   • execution → Exploitation: running attacker code on the victim is the observable face of it.
#   • privilege-escalation / persistence → Installation: both are "the foothold is being made to
#     last", the Installation block in the narrative.
#   • stealth, defense-impairment (v19 split of defense-evasion) → Installation: evasion serves the
#     foothold; it is not a phase of its own in the kill chain.
#   • credential-access, discovery → Exploitation: post-exploitation activity on the victim, for
#     which the seven-phase chain has no dedicated block.
#   • lateral-movement, collection, exfiltration, impact → Actions on Objectives: the chain ends at
#     "the attacker is doing what they came for", and lateral movement is conventionally folded there.
# The tactic is always reported alongside the phase, so this coarsening never hides the detail.
_TACTIC_TO_PHASE = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Weaponization",
    "initial-access": "Delivery",
    "execution": "Exploitation",
    "exploitation": "Exploitation",                  # non-standard spelling seen in some rule sets
    "privilege-escalation": "Installation",
    "persistence": "Installation",
    "defense-evasion": "Installation",               # legacy (pre-v19) spelling
    "stealth": "Installation",                       # v19 split of defense-evasion
    "defense-impairment": "Installation",            # v19 split of defense-evasion
    "credential-access": "Exploitation",
    "discovery": "Exploitation",
    "lateral-movement": "Actions on Objectives",
    "collection": "Actions on Objectives",
    "command-and-control": "Command and Control",
    "exfiltration": "Actions on Objectives",
    "impact": "Actions on Objectives",
}


@lru_cache(maxsize=1)
def _map() -> dict:
    """The generated ATT&CK map. Missing file is not fatal: the engine degrades to IDs only."""
    try:
        return json.loads(_DATA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"techniques": {}, "_attack_version": ""}


def attack_version() -> str:
    return _map().get("_attack_version", "")


def technique_name(tid: str) -> str:
    """Human name of a technique ID (`T1003.001` → `LSASS Memory`); '' when unknown."""
    return (_map()["techniques"].get(_norm_tid(tid)) or {}).get("name", "")


def _norm_tid(tid) -> str:
    """`t1003.001`, ` T1003.001 `, `T1003.001.` → `T1003.001`. Rule sets are not consistent."""
    s = str(tid or "").strip().strip(".").upper()
    return s


def tactics_of(tid: str) -> list[str]:
    """Tactics of a technique. A sub-technique with no tactics of its own inherits the parent's
    (rare, but a bundle-level gap must not silently drop the event from the kill-chain view)."""
    t = _norm_tid(tid)
    techs = _map()["techniques"]
    entry = techs.get(t)
    if entry and entry.get("tactics"):
        return list(entry["tactics"])
    if "." in t:                                  # sub-technique → fall back to the parent
        parent = techs.get(t.split(".", 1)[0])
        if parent and parent.get("tactics"):
            return list(parent["tactics"])
    return []


def phase_of_tactic(tactic: str) -> str:
    """Kill-chain phase for an ATT&CK tactic; '' when the tactic is unknown."""
    return _TACTIC_TO_PHASE.get(str(tactic or "").strip().lower().replace(" ", "-"), "")


def phases_of(tid: str) -> list[str]:
    """Kill-chain phases a technique maps to, deduplicated, in kill-chain order."""
    out = {phase_of_tactic(t) for t in tactics_of(tid)}
    out.discard("")
    return sorted(out, key=lambda p: PHASE_ORDER[p])


def split_techniques(value) -> list[str]:
    """Parse the stored `techniques` column: adapters write "T1021.002,T1078" (or a list)."""
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        parts = [str(v) for v in value]
    else:
        parts = str(value).replace("|", ",").replace(";", ",").split(",")
    seen, out = set(), []
    for p in parts:
        t = _norm_tid(p)
        # Guard against free text sneaking into the column: a technique is T#### [.###].
        if not t.startswith("T") or not t[1:].split(".")[0].isdigit():
            continue
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def annotate(value) -> dict:
    """Everything the engine needs for one event's technique field, in one pass.

    Returns {techniques, tactics, phases, max_phase, max_phase_order} — empty/0 when the event
    carries no (resolvable) ATT&CK evidence."""
    tids = split_techniques(value)
    tactics, phases = set(), set()
    for t in tids:
        tactics.update(tactics_of(t))
        phases.update(phases_of(t))
    ordered = sorted(phases, key=lambda p: PHASE_ORDER[p])
    return {
        "techniques": tids,
        "tactics": sorted(tactics),
        "phases": ordered,
        "max_phase": ordered[-1] if ordered else "",
        "max_phase_order": PHASE_ORDER[ordered[-1]] if ordered else 0,
    }
