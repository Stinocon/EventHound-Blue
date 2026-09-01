"""Generator: official ATT&CK STIX bundle → `analytics/attack_map.json` (the engine's SOT).

Run it only when the STIX bundle is refreshed — the produced JSON is versioned, the 51 MB bundle is
not (it lives in the gitignored `rag/sources_raw/mitre/`, declared in `rag/sources.yaml` as the
`mitre-attack-stix` source and already used to build the `knowledge_cyber` collection).

    uv run python -m analytics.build_attack_map                  # default bundle path
    uv run python -m analytics.build_attack_map --stix <path>

Why generate instead of hand-writing: technique → tactic is factual data owned by MITRE, and a
hand-kept table drifts silently (§6 — no invented technical data). Everything here is a mechanical
projection of the bundle: technique id → {name, tactics, deprecated}.

NOTE on tactic names: they come from the bundle verbatim. ATT&CK v19 splits the old
`defense-evasion` into `stealth` + `defense-impairment`; the kill-chain mapping in `attack.py`
accepts both the current and the legacy spellings, because Sigma rules and older exports still emit
the legacy ones.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_STIX = HERE.parents[1] / "rag" / "sources_raw" / "mitre" / "enterprise-attack.json"
OUT = HERE / "attack_map.json"


def build(stix_path: Path) -> dict:
    bundle = json.loads(stix_path.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])

    version = ""
    for o in objects:
        if o.get("type") == "x-mitre-collection":
            version = str(o.get("x_mitre_version") or "")
            break

    techniques: dict[str, dict] = {}
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        tid = next((r.get("external_id") for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
        if not tid:
            continue
        tactics = sorted({p["phase_name"] for p in o.get("kill_chain_phases", [])
                          if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")})
        entry: dict = {"name": o.get("name", ""), "tactics": tactics}
        # Deprecated/revoked techniques are KEPT: old Sigma rules and archived exports still carry
        # those IDs, and resolving the name is better than showing a bare ID. Flagged, not dropped.
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            entry["deprecated"] = True
        techniques[tid] = entry

    return {
        "_source": "MITRE ATT&CK Enterprise, official STIX bundle (rag/sources.yaml: mitre-attack-stix)",
        "_attack_version": version,
        "_generated_by": "analytics/build_attack_map.py",
        "techniques": dict(sorted(techniques.items())),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate analytics/attack_map.json from the ATT&CK STIX bundle.")
    ap.add_argument("--stix", default=str(DEFAULT_STIX), help=f"STIX bundle path (default: {DEFAULT_STIX})")
    ap.add_argument("--out", default=str(OUT), help=f"output JSON (default: {OUT})")
    args = ap.parse_args(argv)

    stix = Path(args.stix)
    if not stix.exists():
        print(f"STIX bundle not found: {stix}\n"
              f"Fetch it into rag/sources_raw/mitre/ (see rag/sources.yaml, source mitre-attack-stix).")
        return 1
    data = build(stix)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False, sort_keys=False), encoding="utf-8")
    n = len(data["techniques"])
    subs = sum(1 for t in data["techniques"] if "." in t)
    print(f"{out}: {n} techniques ({subs} sub-techniques), ATT&CK v{data['_attack_version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
