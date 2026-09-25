"""Phase 2 CLI: any combination of the eleven sources build_records() takes → long-tail
analytics + correlation (DuckDB).

Unlike run_evtx/run_pcap (single slice → report), here we load one or more sources
into a common DuckDB store and execute long-tail recipes and cross-source correlation.

Usage:
    uv run python -m engine.run_analytics --evtx a.evtx --evtx b.evtx --pcap c.pcap
    uv run python -m engine.run_analytics --pcap c.pcap --json-out out.json   # for the GUI
    uv run python -m engine.run_analytics --thor scan.txt --registry keys.reg --osquery log.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import recipes, runner  # noqa: E402
from engine.cli_json import warn_if_deprecated_json_flag  # noqa: E402
from engine.run_report import add_source_args, any_source_given, build_source_kwargs  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Long-tail analytics + correlation (Phase 2).")
    add_source_args(ap)
    ap.add_argument("--json-out", dest="json_out", help="write full output as JSON to PATH (for the GUI)")
    ap.add_argument("--json", dest="json_out", help=argparse.SUPPRESS)  # deprecated alias, same dest
    ap.add_argument("--top", type=int, default=10, help="rows shown per section in terminal")
    args = ap.parse_args(argv)
    warn_if_deprecated_json_flag(argv)

    if bool(args.yara_target) != bool(args.yara_rules):
        ap.error("--yara-target and --yara-rules must be given together")
    if not any_source_given(args):
        ap.error("specify at least one source (--evtx/--evtx-full/--pcap/--log/--registry/... "
                 "— see --help)")

    # Everything past EVTX/EVTX-full/PCAP is reported as one count: eight more per-source counters
    # here would restate build_source_kwargs() rather than orient the reader on what is running.
    other = (len(args.log) + len(args.registry) + len(args.registry_hives) + len(args.mft)
             + len(args.thor) + len(args.thor_csv) + len(args.osquery)
             + len(args.crowdstrike) + (1 if args.yara_target else 0))
    print(f"[1/2] Record construction (EVTX={len(args.evtx)}, EVTX-full={len(args.evtx_full)}, "
          f"PCAP={len(args.pcap)}, other={other})…")
    # No unhandled traceback: a corrupted EVTX causes Hayabusa to exit with non-zero code
    # (CalledProcessError) and its `cmd`/message field contains the customer file path
    # (§9/§10). Per-file failures degrade via `errors` (basename+type); the rest prints only
    # the exception type.
    errors: list[str] = []
    try:
        records = runner.build_records(evtx=args.evtx, evtx_full=args.evtx_full,
                                       pcap=args.pcap, errors=errors,
                                       **build_source_kwargs(args))
    except Exception as e:  # noqa: BLE001
        print(f"Record construction failed — {runner.describe_error(e)}", file=sys.stderr)
        return 1
    for err in errors:
        print(f"   ! file skipped — {err}", file=sys.stderr)
    print(f"[2/2] Analytics on {len(records)} records…\n")
    try:
        result = runner.analyze(records)
    except Exception as e:  # noqa: BLE001
        print(f"Analysis failed — {runner.describe_error(e)}", file=sys.stderr)
        return 1

    s = result["summary"]
    print(f"Events: {s['events']} | sources: {s['by_source']} | hosts: {s['distinct_hosts']} | users: {s['distinct_users']}")

    def show(title: str, rows: list[dict]):
        print(f"\n== {title} ({len(rows)}) ==")
        for r in rows[:args.top]:
            print("   " + " | ".join(f"{k}={v}" for k, v in r.items() if v is not None))

    # The timeline prints as a sequence, not through `show`: there the *order* is the message, and a
    # 20-field dump per row would bury it. `why` is the selection criterion, not a severity (§6).
    tl = result.get("timeline") or []
    print(f"\n== Timeline — notable events, chronological ({len(tl)}) ==")
    for r in tl[:args.top]:
        what = " · ".join(str(r[k]) for k in ("host", "user_name", "process_name", "action",
                                              "dns_query", "techniques") if r.get(k))
        print(f"   {r.get('ts')} [{r.get('why')}] {r.get('source')} — {what}")

    for name, (_fn, desc) in recipes.RECIPES.items():
        show(desc, result[name])
    show("Host Summary", result["host_overview"])
    show("Cross-source Indicators", result["shared_indicators"])

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nJSON: {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
