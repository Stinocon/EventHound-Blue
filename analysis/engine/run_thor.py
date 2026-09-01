"""CLI: THOR / THOR Lite (Nextron) scan report -> analytics (via thor_scan adapter + DuckDB).

Normalizes THOR findings to the common schema and runs the same correlation as the other engines,
so a THOR-flagged hash/file/host lines up with EVTX/MFT/PCAP evidence. Useful standalone (no AI).

Usage:
    uv run python -m engine.run_thor report.txt
    uv run python -m engine.run_thor report.txt --csv files_md5s.csv --json-out out.json
    uv run python -m engine.run_thor --csv files_md5s.csv        # CSV-only fallback
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
    ap = argparse.ArgumentParser(description="Analytics on a THOR (Nextron) scan report.")
    ap.add_argument("report", nargs="?", help="THOR .txt report (authoritative source)")
    ap.add_argument("--csv", dest="md5s", help="the md5s CSV companion (fallback if no report)")
    ap.add_argument("--json-out", dest="json_out", help="write full output as JSON to PATH")
    ap.add_argument("--json", dest="json_out", help=argparse.SUPPRESS)  # deprecated alias, same dest
    ap.add_argument("--top", type=int, default=15, help="rows per section in terminal")
    args = ap.parse_args(argv)
    warn_if_deprecated_json_flag(argv)

    if not args.report and not args.md5s:
        print("error: provide a THOR report .txt or --csv md5s.csv", file=sys.stderr)
        return 2
    for p in (args.report, args.md5s):
        if p and not Path(p).exists():
            print(f"error: file not found: {p}", file=sys.stderr)
            return 2

    errors: list[str] = []
    records = runner.build_records(thor=[{"report": args.report, "md5s": args.md5s}], errors=errors)
    for err in errors:
        print(f"   ! skipped — {err}", file=sys.stderr)
    if not records:
        print("No THOR findings produced (report format not recognized?).", file=sys.stderr)
        return 1

    result = runner.analyze(records)
    s = result["summary"]
    print(f"Findings: {s['events']} | severity buckets from THOR level\n")

    findings = result.get("thor_findings", [])
    if findings:
        print(f"== Top findings by score ({len(findings)}) ==")
        for r in findings[:args.top]:
            print(f"   [{r.get('thor.score')}] {r.get('ioc.severity')} "
                  f"{r.get('file.name')} — {r.get('rule.title')} "
                  f"(sha256={ (r.get('file.hash') or '')[:12] }…)")
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
