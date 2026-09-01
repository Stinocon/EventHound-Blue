"""STIX source: parses the official MITRE ATT&CK bundle (enterprise-attack.json) into Documents.

Why STIX instead of crawling the site: the official bundle (github.com/mitre-attack/attack-stix-data)
is the complete, reproducible **primary source** of the entire ATT&CK matrix — techniques, tactics,
mitigations, groups, software, data sources — in a single LOCAL file. Indexing it avoids crawling
~500 pages (no scraping/VPN, §15), gives full coverage and stays stable over time.

One Document per relevant object (locator = ATT&CK ID, e.g. T1003.001), rendered as readable text
for the RAG. Revoked/deprecated objects and non-informative types (relationship,
identity, marking-definition, matrix, collection) are skipped.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..config import RAG_DIR
from ..document import Document

# STIX types → readable label. These are the only ones that become Documents.
_TYPE_LABEL = {
    "attack-pattern": "Technique",
    "x-mitre-tactic": "Tactic",
    "course-of-action": "Mitigation",
    "intrusion-set": "Group (APT)",
    "malware": "Software (malware)",
    "tool": "Software (tool)",
    "x-mitre-data-source": "Data source",
    "x-mitre-data-component": "Data component",
}


def _resolve(path_str: str) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else (RAG_DIR / p).resolve()


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _attack_url(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return None


def _render(obj: dict, attack_id: str, label: str) -> str:
    """Renders a STIX object as readable text (name, ID, salient metadata, description)."""
    lines = [f"{obj.get('name', '(unnamed)')} ({attack_id}) — {label} MITRE ATT&CK"]

    phases = [p.get("phase_name") for p in obj.get("kill_chain_phases", []) if p.get("phase_name")]
    if phases:
        lines.append("Tactics: " + ", ".join(phases))
    if obj.get("x_mitre_platforms"):
        lines.append("Platforms: " + ", ".join(obj["x_mitre_platforms"]))
    if obj.get("aliases"):
        lines.append("Aliases: " + ", ".join(obj["aliases"]))
    if obj.get("x_mitre_is_subtechnique"):
        lines.append("(sub-technique)")

    if obj.get("description"):
        lines.append("")
        lines.append(obj["description"].strip())
    if obj.get("x_mitre_detection"):
        lines.append("")
        lines.append("Detection: " + obj["x_mitre_detection"].strip())
    return "\n".join(lines)


def load_stix(source: dict) -> list[Document]:
    """Loads the STIX bundles of the source (one .json file, or a folder + glob)."""
    src = source.get("source", {})
    base = _resolve(src.get("path", "./sources_raw/mitre"))
    if base.is_file():
        files = [base]
    elif base.is_dir():
        files = sorted(base.glob(src.get("glob", "*.json")))
    else:
        print(f"    ! STIX source missing: {base}")
        return []

    docs: list[Document] = []
    for path in files:
        try:
            bundle = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"    ! unreadable STIX {path.name}: {exc}")
            continue
        kept = skipped = 0
        for obj in bundle.get("objects", []):
            label = _TYPE_LABEL.get(obj.get("type"))
            if not label:
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                skipped += 1
                continue
            attack_id = _attack_id(obj)
            if not attack_id:
                # without an ATT&CK ID the object isn't queryable by locator: skip it
                skipped += 1
                continue
            text = _render(obj, attack_id, label)
            if not text.strip():
                continue
            docs.append(Document(
                locator=attack_id,
                text=text,
                metadata={"document": attack_id, "attack_type": obj.get("type"),
                          "url": _attack_url(obj)},
            ))
            kept += 1
        print(f"    {path.name}: {kept} ATT&CK objects (skipped {skipped} revoked/deprecated)")
    return docs
