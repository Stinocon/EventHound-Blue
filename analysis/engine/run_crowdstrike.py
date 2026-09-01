"""CLI: CrowdStrike detection/investigation -> analytics (via crowdstrike adapter + DuckDB).

Parses CrowdStrike detection clipboard text or LogScale/CQL investigation JSON
and runs the same correlation as the other engines, so a CrowdStrike-detected
hash/IP/host lines up with EVTX/PCAP/other sources.

Usage:
    uv run python -m engine.run_crowdstrike detection.txt
    uv run python -m engine.run_crowdstrike investigation.json --json-out out.json
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
    ap = argparse.ArgumentParser(description="Analytics on CrowdStrike detection/investigation data.")
    ap.add_argument("files", nargs="+", help="CrowdStrike detection clipboard (.txt) or LogScale JSON (.json/.log)")
    ap.add_argument("--json-out", dest="json_out", help="write full output as JSON to PATH")
    ap.add_argument("--json", dest="json_out", help=argparse.SUPPRESS)  # deprecated alias, same dest
    ap.add_argument("--top", type=int, default=15, help="rows per section in terminal")
    args = ap.parse_args(argv)
    warn_if_deprecated_json_flag(argv)

    for p in args.files:
        if not Path(p).exists():
            print(f"error: file not found: {p}", file=sys.stderr)
            return 2

    errors: list[str] = []
    records = runner.build_records(crowdstrike=args.files, errors=errors)
    for err in errors:
        print(f"   ! skipped — {err}", file=sys.stderr)
    if not records:
        print("No CrowdStrike events produced (format not recognized?).", file=sys.stderr)
        return 1

    result = runner.analyze(records)
    s = result["summary"]
    print(f"Events: {s['events']} | by source via event.source\n")

    def show(title: str, rows: list[dict]):
        if not rows:
            return
        print(f"== {title} ({len(rows)}) ==")
        for r in rows[:args.top]:
            print("   " + " | ".join(f"{k}={v}" for k, v in r.items() if v is not None))
        print()

    show("Hosts", result.get("host_overview", []))
    show("Cross-source indicators", result.get("shared_indicators", []))

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON: {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())