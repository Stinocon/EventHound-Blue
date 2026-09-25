"""CLI: YARA rule scan -> analytics (via yara_scan adapter + DuckDB).

Compiles YARA rules and scans target files/directories; each match becomes
a common-schema record correlatable with EVTX/PCAP/other sources.
OPTIONAL: requires yara-python (`uv sync --extra yara`).

Usage:
    uv run python -m engine.run_yara --rules /path/to/rules.yar --target /path/to/scan
    uv run python -m engine.run_yara --rules rules/ --target suspicious.exe --json-out out.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import runner  # noqa: E402
from engine.cli_json import warn_if_deprecated_json_flag  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Analytics on a YARA rule scan.")
    ap.add_argument("--rules", required=True, help="YARA rules file or directory (.yar/.yara)")
    ap.add_argument("--target", required=True, help="target file or directory to scan")
    ap.add_argument("--json-out", dest="json_out", help="write full output as JSON to PATH")
    ap.add_argument("--json", dest="json_out", help=argparse.SUPPRESS)  # deprecated alias, same dest
    ap.add_argument("--top", type=int, default=15, help="rows per section in terminal")
    args = ap.parse_args(argv)
    warn_if_deprecated_json_flag(argv)

    for p in (args.rules, args.target):
        if p and not Path(p).exists():
            print(f"error: path not found: {p}", file=sys.stderr)
            return 2

    errors: list[str] = []
    records = runner.build_records(
        yara=[{"rules": args.rules, "target": args.target}], errors=errors)
    for err in errors:
        print(f"   ! skipped — {err}", file=sys.stderr)
    if not records:
        print("No YARA matches found (rules or target not recognized?).", file=sys.stderr)
        return 1

    result = runner.analyze(records)
    s = result["summary"]
    print(f"Matches: {s['events']} | by rule via rule.name\n")

    # Show matched rules
    from collections import Counter
    rule_counts = Counter(r.get("rule.name", "?") for r in result.get("records", []))
    if rule_counts:
        print("== Top rules by match count ==")
        for rule, count in rule_counts.most_common(args.top):
            techs = set()
            for r in result.get("records", []):
                if r.get("rule.name") == rule:
                    techs.update(r.get("attack.techniques") or [])
            tech_str = f" [{', '.join(sorted(techs))}]" if techs else ""
            print(f"   {count:4d}  {rule}{tech_str}")
        print()

    inds = result.get("shared_indicators", [])
    if inds:
        print(f"== Cross-source indicators ({len(inds)}) ==")
        for r in inds[:args.top]:
            print("   " + " | ".join(f"{k}={v}" for k, v in r.items() if v is not None))
        print()

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON: {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())