"""CLI: generic log files → analytics (via logfile adapter + DuckDB).

Normalizes arbitrary logs (access logs, jsonl, regex, app-logs) to common schema and applies
the same long-tail/web recipes and correlation from other engines. Useful standalone (no AI)
and as a building block for "load logs + EVTX → correlated".

Usage:
    uv run python -m engine.run_logs access.log --fmt access
    uv run python -m engine.run_logs app.log --fmt regex --pattern '(?P<ts>\\S+ \\S+).*?(?P<file>sma1000_\\w+\\.sh)'
    uv run python -m engine.run_logs a.log b.log --json-out out.json
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
    ap = argparse.ArgumentParser(description="Analytics on generic log files.")
    ap.add_argument("logs", nargs="+", help="one or more log files")
    ap.add_argument("--fmt", default="auto", choices=["auto", "access", "jsonl", "regex", "syslog", "line"],
                    help="log format (default: auto-sniff)")
    ap.add_argument("--pattern", help="regex with named groups (for --fmt regex)")
    ap.add_argument("--json-out", dest="json_out", help="write full output as JSON to PATH")
    ap.add_argument("--json", dest="json_out", help=argparse.SUPPRESS)  # deprecated alias, same dest
    ap.add_argument("--top", type=int, default=15, help="rows per section in terminal")
    args = ap.parse_args(argv)
    warn_if_deprecated_json_flag(argv)

    for p in args.logs:
        if not Path(p).exists():
            print(f"error: log not found: {p}", file=sys.stderr)
            return 2

    specs = [{"path": p, "fmt": args.fmt, "pattern": args.pattern} for p in args.logs]
    errors: list[str] = []
    records = runner.build_records(logs=specs, errors=errors)
    for err in errors:
        print(f"   ! file skipped — {err}", file=sys.stderr)
    if not records:
        print("No records produced from logs (format not recognized?).", file=sys.stderr)
        return 1

    result = runner.analyze(records)
    s = result["summary"]
    print(f"Events: {s['events']} | sources: {s['by_source']}\n")

    def show(title: str, rows: list[dict]):
        if not rows:
            return
        print(f"== {title} ({len(rows)}) ==")
        for r in rows[:args.top]:
            print("   " + " | ".join(f"{k}={v}" for k, v in r.items() if v is not None))
        print()

    show("Source IPs by volume", result.get("top_source_ips", []))
    show("HTTP status distribution", result.get("http_status_summary", []))
    show("Most requested URLs/paths", result.get("web_targets", []))
    show("Cross-source indicators", result.get("shared_indicators", []))

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON: {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
