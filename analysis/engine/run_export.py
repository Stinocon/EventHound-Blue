"""CLI: heterogeneous sources (EVTX/PCAP/log) → re-importable analysis bundle (JSON).

Same ingestion path as run_report.py, but the output is the versioned snapshot described in
engine/bundle.py instead of a rendered report: it can be reopened later (GUI import, or
`run_report.py --from-bundle`) without touching the evidence again.

Usage:
    uv run python -m engine.run_export --evtx sec.evtx --out case.json
    uv run python -m engine.run_export --pcap c.pcap --log access.log --fmt access --out case.json
    uv run python -m engine.run_export --from-json report-full.json --out case.json

PRIVACY (§9/§10): the bundle contains real identifiers → save to data/ or analysis/reports/
(both gitignored), anonymize before sharing, NEVER publish as an Artifact.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import runner  # noqa: E402
from engine import bundle as bundle_mod  # noqa: E402
from engine.run_report import (add_source_args, any_source_given,  # noqa: E402
                               build_source_kwargs)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export an analysis as a re-importable bundle.")
    add_source_args(ap)
    ap.add_argument("--from-json", dest="from_json",
                    help="existing analysis JSON (report --format json --level full) to wrap, "
                         "instead of re-running the tools")
    ap.add_argument("--name", default="analysis", help="case name recorded in the bundle metadata")
    ap.add_argument("--out", help="bundle path (default: reports/bundle-<date>.json)")
    args = ap.parse_args(argv)

    if bool(args.yara_target) != bool(args.yara_rules):
        ap.error("--yara-target and --yara-rules must be given together")

    sources = any_source_given(args)
    if not sources and not args.from_json:
        ap.error("specify at least one source (--evtx/--evtx-full/--pcap/--log/--registry/... "
                 "— see --help) or --from-json")
    if sources and args.from_json:
        ap.error("--from-json is exclusive with the source options")

    if args.from_json:
        try:
            bundle = bundle_mod.load(args.from_json)
        except ValueError as e:
            print(f"Cannot read {args.from_json}: {e}", file=sys.stderr)
            return 1
        result = bundle_mod.analysis_of(bundle)
        # `records` is capped at 5000 in analyze(): the real count lives in _meta.
        n_records = (result.get("_meta") or {}).get("records", len(result.get("records") or []))
    else:
        errors: list[str] = []
        try:
            records = runner.build_records(evtx=args.evtx, evtx_full=args.evtx_full,
                                           pcap=args.pcap, errors=errors,
                                           **build_source_kwargs(args))
        except Exception as e:  # noqa: BLE001 — no traceback: it can carry client paths (§9/§10)
            print(f"Record construction failed — {runner.describe_error(e)}", file=sys.stderr)
            return 1
        for err in errors:
            print(f"   ! file skipped — {err}", file=sys.stderr)
        if not records:
            print("No records produced from sources.", file=sys.stderr)
            return 1
        result = runner.analyze(records)
        # Counted from the store rather than from the flags: with eleven sources a per-flag tally
        # would be a second, drifting description of what was ingested.
        result["_meta"] = {"records": len(records), "evtx": len(args.evtx),
                           "evtx_full": len(args.evtx_full), "pcap": len(args.pcap),
                           "logs": len(args.log),
                           "sources": (result.get("summary") or {}).get("by_source") or {},
                           "errors": errors}
        n_records = len(records)

    bundle = bundle_mod.build(result, name=args.name)

    out = Path(args.out) if args.out else (
        Path(__file__).resolve().parents[1] / "reports" / f"bundle-{_dt.date.today().isoformat()}.json"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(bundle_mod.dumps(bundle), encoding="utf-8")
    print(f"Bundle: {out}  ({n_records} records, bundle_version {bundle['bundle_version']})")
    print("Reopen it with: engine.run_report --from-bundle <file>, or the GUI Report view (Import).")
    print("Remember: real data → anonymize before sharing (§9); do not publish as an Artifact.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
