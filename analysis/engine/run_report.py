"""CLI: heterogeneous sources (EVTX/PCAP/log) → visual report (charts + tables + correlations).

A single command that normalizes all sources to common schema, executes analytics and
correlation, and generates a self-contained HTML report (no external dependencies) — or the same
content as Markdown/JSON. An already-exported bundle (engine/bundle.py) can be re-rendered with
--from-bundle, without touching the evidence again.

Usage:
    uv run python -m engine.run_report --evtx a.evtx --log access.log --fmt access --out report.html
    uv run python -m engine.run_report --evtx-full sec.evtx --pcap c.pcap --out report.html
    uv run python -m engine.run_report --from-bundle case.json --format markdown --out report.md

PRIVACY (§9/§10): report contains real identifiers → save to data/ (gitignored),
anonymize before sharing, NEVER publish as Artifact.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import runner  # noqa: E402
from engine import bundle as bundle_mod  # noqa: E402
from engine import report_html  # noqa: E402

# `case` renders the §17 investigation-case template (analytics/case.py) rather than a report: the
# same evidence, laid out as the deliverable the method asks for. That renderer had existed for
# months with no caller outside its own test — a document nobody could produce.
_EXT = {"html": "html", "markdown": "md", "json": "json", "case": "md"}


def add_source_args(ap: argparse.ArgumentParser) -> None:
    """Every input `runner.build_records()` can turn into records, declared once here and imported
    by run_analytics.py/run_export.py/run_case.py instead of copied — each of those CLIs used to
    keep its own subset of this eleven-source mapping, and every extra copy is exactly the drift
    SOT (§16) exists to prevent. `run_case.py`'s `new`/`add` subparsers call this directly."""
    ap.add_argument("--evtx", action="append", default=[], help="EVTX via Hayabusa (repeatable)")
    ap.add_argument("--evtx-full", dest="evtx_full", action="append", default=[],
                    help="EVTX via EvtxECmd, full stream (repeatable; requires dotnet)")
    ap.add_argument("--pcap", action="append", default=[], help="PCAP (repeatable)")
    ap.add_argument("--log", action="append", default=[], help="generic log file (repeatable)")
    ap.add_argument("--fmt", default="auto", help="log format (auto|access|jsonl|regex|syslog|line)")
    ap.add_argument("--pattern", help="regex with named groups (for --fmt regex)")
    ap.add_argument("--registry", action="append", default=[], help=".reg native export (repeatable)")
    ap.add_argument("--registry-hive", dest="registry_hives", action="append", default=[],
                    help="binary registry hive via RECmd (repeatable; requires dotnet)")
    ap.add_argument("--mft", action="append", default=[],
                    help="$MFT via MFTECmd (repeatable; requires dotnet)")
    ap.add_argument("--thor", action="append", default=[], help="THOR scan report .txt (repeatable)")
    ap.add_argument("--thor-csv", dest="thor_csv", action="append", default=[],
                    help="THOR md5s CSV, companion or standalone fallback (repeatable; "
                         "matches engine.run_thor's --csv)")
    ap.add_argument("--osquery", action="append", default=[],
                    help="osquery result log NDJSON (repeatable)")
    ap.add_argument("--crowdstrike", action="append", default=[],
                    help="CrowdStrike detection clipboard or LogScale export (repeatable)")
    ap.add_argument("--yara-target", dest="yara_target",
                    help="file/directory to scan, paired with --yara-rules (single scan per run, "
                         "like engine.run_yara)")
    ap.add_argument("--yara-rules", dest="yara_rules",
                    help="YARA rules file or directory, paired with --yara-target")


def any_source_given(args: argparse.Namespace) -> bool:
    """True if the command line named at least one of the ten sources `build_records()` takes."""
    return bool(
        args.evtx or args.evtx_full or args.pcap or args.log
        or args.registry or args.registry_hives or args.mft
        or args.thor or args.thor_csv or args.osquery or args.crowdstrike
        or args.yara_target or args.yara_rules
    )


def build_source_kwargs(args: argparse.Namespace) -> dict:
    """`args` -> the `runner.build_records()` kwargs for every source beyond evtx/evtx-full/pcap,
    which each caller already passes through by name unchanged."""
    kwargs: dict = {
        "logs": [{"path": p, "fmt": args.fmt, "pattern": args.pattern} for p in args.log],
        "registry": args.registry,
        "registry_hives": args.registry_hives,
        "mft": args.mft,
        "thor": [{"report": t} for t in args.thor] + [{"md5s": c} for c in args.thor_csv],
        "osquery": args.osquery,
        "crowdstrike": args.crowdstrike,
    }
    if args.yara_target or args.yara_rules:
        kwargs["yara"] = [{"target": args.yara_target, "rules": args.yara_rules}]
    return kwargs


def _render(result: dict, meta: dict, fmt: str, level: str, name: str) -> str:
    """Same renderers the GUI serves from /api/report — one implementation, two surfaces."""
    if fmt == "html":
        return report_html.render_html(result, meta, level=level)
    scanned_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    if fmt == "case":
        from analytics import case as case_doc
        return case_doc.render(result, {"title": name, "date": scanned_at[:10]})
    if fmt == "markdown":
        from engine.report_markdown import render_markdown
        return render_markdown(result, name=name, scanned_at=scanned_at, level=level)
    from engine.report_json import render_json
    return render_json(result, name=name, scanned_at=scanned_at, level=level)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Visual report (analytics + correlations).")
    add_source_args(ap)
    ap.add_argument("--from-bundle", dest="from_bundle",
                    help="re-render an exported bundle (engine.run_export) instead of re-parsing evidence")
    ap.add_argument("--format", default="html", choices=sorted(_EXT),
                    help="output format (default: html)")
    ap.add_argument("--level", default="detailed", choices=["summary", "detailed", "full"],
                    help="detail level (default: detailed)")
    ap.add_argument("--name", default="analysis", help="case name shown in the report header")
    ap.add_argument("--out", help="output path (default: reports/report-<date>.<ext>)")
    args = ap.parse_args(argv)

    if bool(args.yara_target) != bool(args.yara_rules):
        ap.error("--yara-target and --yara-rules must be given together")

    sources = any_source_given(args)
    if not sources and not args.from_bundle:
        ap.error("specify at least one source (--evtx/--evtx-full/--pcap/--log/--registry/... "
                 "— see --help) or --from-bundle")
    if sources and args.from_bundle:
        ap.error("--from-bundle is exclusive with the source options")

    if args.from_bundle:
        try:
            loaded = bundle_mod.load(args.from_bundle)
        except ValueError as e:
            print(f"Cannot read {args.from_bundle}: {e}", file=sys.stderr)
            return 1
        result = bundle_mod.analysis_of(loaded)
        meta = result.get("_meta") or loaded.get("meta") or {}
        n_records = meta.get("records", len(result.get("records") or []))
        name = args.name if args.name != "analysis" else (loaded.get("meta") or {}).get("name", "analysis")
    else:
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
        if not records:
            print("No records produced from sources.", file=sys.stderr)
            return 1
        result = runner.analyze(records)
        meta = {"records": len(records), "errors": errors}
        n_records = len(records)
        name = args.name

    content = _render(result, meta, args.format, args.level, name)

    out = Path(args.out) if args.out else (
        Path(__file__).resolve().parents[1] / "reports"
        / f"report-{_dt.date.today().isoformat()}.{_EXT[args.format]}"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    print(f"Report: {out}  ({n_records} records)")
    print("Remember: real data → anonymize before sharing (§9); do not publish as Artifact.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
