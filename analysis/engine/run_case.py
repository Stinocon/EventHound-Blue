"""Case management from the command line: create, feed, analyze, annotate, compare (CLI-first).

A case is an analysis that survives the process — the store is `analytics/case_store.py`, this is
the interface to it. Sources are added one at a time, so a case grows across sessions instead of
being rebuilt from evidence that may no longer be there.

    uv run python -m engine.run_case list
    uv run python -m engine.run_case new incident-042 --title "SMA compromise" --evtx sec.evtx
    uv run python -m engine.run_case add incident-042 --pcap perimeter.pcap
    uv run python -m engine.run_case show incident-042
    uv run python -m engine.run_case analyze incident-042 --json-out out.json
    uv run python -m engine.run_case note incident-042 "4624 type 3 from the same IP as the web log"
    uv run python -m engine.run_case diff incident-042 baseline-clean
    uv run python -m engine.run_case rm incident-042 --yes

PRIVACY (§9/§10): a case holds real client data. It lives under `analysis/cases/` (gitignored and
listed as a forbidden path in the leak guard) and nothing here sends it anywhere.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import baseline, case_store, runner  # noqa: E402
from engine.cli_json import warn_if_deprecated_json_flag  # noqa: E402
# Canonical eleven-source flag set, shared with run_report.py/run_export.py/run_analytics.py so a
# case can hold every source those CLIs can build records from (MFT/osquery/CrowdStrike/YARA were
# missing here before — a case-only third copy of the mapping, now retired in favor of the SOT).
from engine.run_report import add_source_args, build_source_kwargs  # noqa: E402

_PRIVACY = "Remember: a case holds real data — anonymize before sharing (§9); never commit it."


def _build(args) -> tuple[list[dict], str, list[str]]:
    """Records from whatever sources the command line named, plus a label and the soft errors."""
    errors: list[str] = []
    records = runner.build_records(
        evtx=args.evtx, evtx_full=args.evtx_full, pcap=args.pcap, errors=errors,
        **build_source_kwargs(args),
    )
    named = (args.evtx + args.evtx_full + args.pcap + args.log + args.registry
             + args.registry_hives + args.mft + args.thor + args.thor_csv + args.okta
             + args.osquery + args.crowdstrike
             + ([args.yara_target] if args.yara_target else []))
    label = ", ".join(Path(p).name for p in named) or "records"
    return records, label, errors


def _print_errors(errors: list[str]) -> None:
    for e in errors:
        print(f"   ! skipped — {e}", file=sys.stderr)


def cmd_list(args) -> int:
    cases = case_store.list_cases(args.root)
    if not cases:
        print(f"no cases in {case_store.root_dir(args.root)}")
        return 0
    for c in cases:
        size = case_store.size_bytes(c["id"], args.root) / 1e6
        print(f"{c['id']:<28} {c.get('record_count', 0):>9} records  {size:>7.1f} MB  "
              f"{len(c.get('notes', [])):>2} notes  updated {c.get('updated_at', '?')}")
    return 0


def cmd_new(args) -> int:
    case_store.create(args.case_id, title=args.title, root=args.root)
    records, label, errors = _build(args)
    _print_errors(errors)
    if records:
        meta = case_store.append(args.case_id, records, label=label, root=args.root)
        print(f"case {args.case_id}: {meta['record_count']} records from {label}")
    else:
        print(f"case {args.case_id} created (empty — add sources with `add`)")
    print(_PRIVACY)
    return 0


def cmd_add(args) -> int:
    """Add a source and, unless told not to, say what it changed.

    Appending used to stop at the append, leaving `analyze` as a separate command — so the ordinary
    path was to add evidence and not look at what it did. Correlation is the reason a case exists;
    running it is the default, and `--no-analyze` is there for the batch loop that adds several sources
    before looking at any of them."""
    records, label, errors = _build(args)
    _print_errors(errors)
    if not records:
        print("nothing to add: no source produced records", file=sys.stderr)
        return 1
    prior = case_store.load_analysis_digest(args.case_id, root=args.root)
    meta = case_store.append(args.case_id, records, label=label, root=args.root,
                             force=getattr(args, "force", False))
    print(f"case {args.case_id}: +{len(records)} records from {label} "
          f"({meta['record_count']} total)")
    if getattr(args, "no_analyze", False):
        return 0
    result = runner.analyze_case(args.case_id, root=args.root)
    d = baseline.delta(prior, result)
    print(baseline.delta_headline(d))
    for b in (d.get("strengthened_bridges") or [])[:6]:
        print(f"  corroborated: {b['kind']} {b['indicator']} — now {b['families']} tools "
              f"(was {b['families_before']}): {b.get('source_list', '')}")
    for b in (d.get("new_bridges") or [])[:6]:
        print(f"  new bridge:   {b['kind']} {b['indicator']} "
              f"({b.get('confidence')}, {b.get('source_list', '')})")
    case_store.save_analysis_digest(args.case_id, result, root=args.root)
    return 0


def cmd_show(args) -> int:
    meta = case_store.load_meta(args.case_id, args.root)
    print(f"{meta['id']} — {meta.get('title', '')}")
    print(f"  created {meta.get('created_at')}  ·  updated {meta.get('updated_at')}"
          f"  ·  tool {meta.get('tool_version')}")
    print(f"  {meta.get('record_count', 0)} records  ·  "
          f"{case_store.size_bytes(args.case_id, args.root) / 1e6:.1f} MB on disk")
    for s in meta.get("sources", []):
        print(f"  + {s.get('added_at')}  {s.get('records'):>8} records  {s.get('label')}")
    for n in meta.get("notes", []):
        print(f"  note {n.get('ts')}: {n.get('text')}")
    return 0


def cmd_analyze(args) -> int:
    result = runner.analyze_case(args.case_id, root=args.root)
    s = result["summary"]
    print(f"Events: {s['events']} | sources: {s['by_source']} | hosts: {s['distinct_hosts']} "
          f"| users: {s['distinct_users']}")
    print(f"Bridges: {len(result['shared_indicators'])} | clusters: {len(result['incident_clusters'])} "
          f"| timeline: {len(result['timeline'])} notable events")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
        print(f"JSON: {args.json_out}")
        print(_PRIVACY)
    return 0


def cmd_infra(args) -> int:
    """Declare (or clear) the case's infrastructure addresses.

    Not guessable from the data: a gateway is an ordinary unicast address. Declaring it demotes its
    indicator bridge — which stays visible — and keeps it out of the clustering, where a single
    universal connector merges every component into one blob."""
    ips = [] if args.clear else args.ips
    meta = case_store.set_infrastructure_ips(args.case_id, ips, root=args.root)
    cur = meta["infrastructure_ips"]
    print(f"case {args.case_id}: infrastructure = {', '.join(cur) if cur else '(none)'}")
    return 0


def cmd_note(args) -> int:
    meta = case_store.note(args.case_id, args.text, root=args.root)
    print(f"note added ({len(meta['notes'])} on this case)")
    return 0


def cmd_diff(args) -> int:
    """What is in the first case and not in the second — the reason baseline/diffing needed cases:
    both sides now survive the session that produced them."""
    cur = case_store.records_of(args.case_id, root=args.root)
    base = case_store.records_of(args.baseline_id, root=args.root)
    out = baseline.summary(cur, base)
    print(f"{args.case_id} ({out['current_events']} records) vs "
          f"{args.baseline_id} ({out['baseline_events']} records): {out['total_new']} new elements")
    for dim, values in out["diff"].items():
        if values:
            print(f"\n== {dim} ({len(values)}) ==")
            for v in values[:args.top]:
                print(f"   {v}")
    return 0


def cmd_rm(args) -> int:
    meta = case_store.load_meta(args.case_id, args.root)
    size = case_store.size_bytes(args.case_id, args.root) / 1e6
    print(f"About to delete case {args.case_id!r}: {meta.get('record_count', 0)} records, "
          f"{size:.1f} MB, {len(meta.get('notes', []))} notes — irreversible.")
    if not args.yes:
        if not sys.stdin.isatty():
            print("refusing to delete without --yes when stdin is not a terminal", file=sys.stderr)
            return 1
        if input("type the case id to confirm: ").strip() != args.case_id:
            print("aborted")
            return 1
    print(f"deleted {case_store.delete(args.case_id, args.root)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="EventHound case management (persistent analyses)")
    ap.add_argument("--root", help="case directory (default: analysis/cases, or EVENTHOUND_CASES_DIR)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list cases").set_defaults(func=cmd_list)

    p = sub.add_parser("new", help="create a case, optionally with a first source")
    p.add_argument("case_id"); p.add_argument("--title")
    add_source_args(p); p.set_defaults(func=cmd_new)

    p = sub.add_parser("add", help="add sources to an existing case, then report what changed")
    p.add_argument("case_id"); add_source_args(p)
    p.add_argument("--no-analyze", action="store_true",
                   help="append only; skip the analysis and the 'what changed' summary")
    p.add_argument("--force", action="store_true",
                   help="append even if this exact content was already added to the case")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("show", help="metadata, sources and notes")
    p.add_argument("case_id"); p.set_defaults(func=cmd_show)

    p = sub.add_parser("analyze", help="run analytics over the stored case")
    p.add_argument("case_id")
    p.add_argument("--json-out", dest="json_out", help="write full output as JSON to PATH")
    p.add_argument("--json", dest="json_out", help=argparse.SUPPRESS)  # deprecated alias, same dest
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("infra", help="declare the case's infrastructure addresses (gateway, proxy, resolver)")
    p.add_argument("case_id")
    p.add_argument("ips", nargs="*", help="addresses; replaces the current list")
    p.add_argument("--clear", action="store_true", help="clear the list instead")
    p.set_defaults(func=cmd_infra)
    p = sub.add_parser("note", help="append an analyst note")
    p.add_argument("case_id"); p.add_argument("text"); p.set_defaults(func=cmd_note)

    p = sub.add_parser("diff", help="what is in CASE and not in BASELINE")
    p.add_argument("case_id"); p.add_argument("baseline_id")
    p.add_argument("--top", type=int, default=20); p.set_defaults(func=cmd_diff)

    p = sub.add_parser("rm", help="delete a case (destructive)")
    p.add_argument("case_id"); p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_rm)

    args = ap.parse_args()
    warn_if_deprecated_json_flag(None)  # main() takes no argv; sniff sys.argv directly
    # Only new/add carry yara_target/yara_rules (via add_source_args); other subcommands don't.
    if bool(getattr(args, "yara_target", None)) != bool(getattr(args, "yara_rules", None)):
        ap.error("--yara-target and --yara-rules must be given together")
    try:
        return args.func(args)
    except case_store.CaseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
