"""CLI: run the whole suite against a simulated incident, with no real evidence involved.

    uv run python -m engine.run_demo                  # generate, ingest, correlate, report
    uv run python -m engine.run_demo --artifacts-only # just write the files, load them by hand
    uv run python -m engine.run_demo --reset          # start from an empty case

The artifacts are written by `demo/scenario.py` and then read back through the ordinary ingest
path, one source at a time into a persistent case — which is also the honest way to watch the
correlation grow as evidence arrives, rather than seeing it appear all at once.

WHAT THIS PROVES, AND WHAT IT DOES NOT. The demo exercises the adapters, the schema, the store and
every correlation; it does not exercise the binaries it has no way to feed. EVTX arrives as the
JSONL Hayabusa emits, so the adapter and everything after it run for real while Hayabusa itself
does not — pass `--evtx-dir` with a corpus of real `.evtx` to include it. PCAP needs tshark and the
YARA step needs `yara-python`; when either is missing the run says so instead of quietly producing
a smaller picture. The level is printed on every run for exactly that reason.

Everything here is synthetic and lives in documentation address space (§9): there is nothing to
anonymise, and the report it produces is safe to show.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adapters import evtx_hayabusa  # noqa: E402
from analytics import case_store, runner  # noqa: E402
from demo import scenario, triage_windows  # noqa: E402

# The scenarios the demo can run. `incident` is an estate seen from its logs; `triage-windows` is one
# endpoint seen twice, what it recorded and what it IS. Adding one is a module plus a line here —
# the ingest, the case, the correlation and the report are the same for both.
SCENARIOS = {"incident": scenario, "triage-windows": triage_windows}

DEFAULT_OUT = Path(__file__).resolve().parents[1] / "demo" / "out"
DEFAULT_CASE = "demo"

# Which external tool each generated source needs to be readable, and what is lost without it.
_NEEDS = {
    "pcap": ("tshark", "network evidence: the beacon, the DNS lookup and the transfer out"),
    "yara": ("yara-python", "the fourth tool on the artifact bridge"),
}


def available_tools() -> dict[str, bool]:
    """What is installed, as the demo's own capability report."""
    try:
        import yara  # noqa: F401
        has_yara = hasattr(yara, "compile")
    except Exception:
        has_yara = False
    return {
        "tshark": shutil.which("tshark") is not None,
        "zeek": shutil.which("zeek") is not None,
        "yara": has_yara,
        "hayabusa": (Path(__file__).resolve().parents[1] / ".tools" / "hayabusa").exists(),
    }



def demo_records(outdir: str | Path = DEFAULT_OUT, evtx_dir: str | Path | None = None,
                 errors: list[str] | None = None,
                 per_source: dict[str, list[dict]] | None = None,
                 only: str | None = None,
                 scenario_module=None) -> list[dict]:
    """Generate a scenario's artifacts and read them back through the normal adapters.

    `per_source`, when given, is filled with the records each source contributed — the demo appends
    them to the case one at a time, and a test that wants to check a single adapter can use the
    same split instead of re-parsing.

    `only` restricts the work to one source, which is what the stepwise load needs: the artifacts
    are regenerated (pure stdlib, deterministic, cheap) but only that source's adapter runs, so
    stepping through eight sources does not mean eight tshark invocations. It is also what lets a
    test ask the question that matters about a source — what is missing WITHOUT it (see
    `tests/test_triage.py`).

    The order comes from the scenario (`sc.ORDER`), because it is the story's order and not the
    adapters': the point of loading it stepwise is watching a bridge appear the moment a second tool
    names the same thing. The all-at-once path produces the same case either way.
    """
    sc = scenario_module or scenario
    if only is not None and only not in sc.ORDER:
        raise ValueError(f"scenario {sc.__name__!r} has no source {only!r} "
                         f"(it has: {', '.join(sc.ORDER)})")
    plan = sc.generate(outdir)
    kwargs = plan["build_records"]
    records: list[dict] = []

    for key in sc.ORDER:
        if only is not None and only != key:
            continue
        if key == "evtx":
            # EVTX is the spine of both scenarios, and the one source that does not go through a
            # binary here (see the module docstring).
            recs = evtx_hayabusa.load_records(plan["hayabusa_jsonl"])
            if evtx_dir:
                evtx_files = sorted(str(p) for p in Path(evtx_dir).rglob("*.evtx"))
                if evtx_files:
                    recs += runner.build_records(evtx=evtx_files, errors=errors)
        elif key in kwargs:
            recs = runner.build_records(errors=errors, **{key: kwargs[key]})
        else:
            continue
        records += recs
        if per_source is not None:
            per_source[key] = recs
    return records


def build_demo_case(case_id: str | None = None, *, only: str | None = None, reset: bool = False,
                    outdir: str | Path = DEFAULT_OUT, evtx_dir: str | None = None,
                    scenario_module=None) -> dict:
    """Put the simulated incident into a case — the one implementation the CLI and the GUI share.

    It exists because the two surfaces had each written the ingest loop out, and the GUI's copy was
    already behind: it never declared the scenario's infrastructure address, so the demo shown in
    the browser returned one cluster holding the whole estate while the same demo on the command
    line returned the incident. A demonstration that differs by surface demonstrates nothing.
    """
    sc = scenario_module or scenario
    case_id = case_id or sc.DEFAULT_CASE
    if reset and case_store.exists(case_id):
        case_store.delete(case_id)
    if not case_store.exists(case_id):
        case_store.create(case_id, title=sc.CASE_TITLE)
        # The scenario knows which of its addresses is infrastructure (in the incident the DC is
        # also the resolver, as on most Windows estates); declaring it is what an analyst would do,
        # and without it the resolver co-occurs with everything and the single cluster is the whole
        # network.
        case_store.set_infrastructure_ips(case_id, sc.INFRASTRUCTURE_IPS)

    errors: list[str] = []
    per_source: dict[str, list[dict]] = {}
    demo_records(outdir, evtx_dir=evtx_dir, errors=errors, per_source=per_source, only=only,
                 scenario_module=sc)
    for label in sc.ORDER:
        recs = per_source.get(label)
        if recs:
            case_store.append(case_id, recs, label=label)
    return {"case": case_id, "sources": {k: len(v) for k, v in per_source.items()},
            "errors": errors, "tools": available_tools(),
            "infrastructure_ips": list(sc.INFRASTRUCTURE_IPS)}


def _print_level(tools: dict[str, bool], evtx_dir: str | None) -> None:
    print("Sensors available for this run:")
    print(f"  EVTX     : {'Hayabusa, over ' + evtx_dir if evtx_dir else 'adapter only'}"
          f"{'' if evtx_dir else '  (level 1: the JSONL Hayabusa would emit, not the binary)'}")
    for key, (tool, lost) in _NEEDS.items():
        ok = tools.get(key if key != "pcap" else "tshark", False)
        print(f"  {key.upper():9}: {tool}{' found' if ok else ' MISSING → no ' + lost}")
    if tools.get("zeek"):
        print("  ZEEK     : found (application-layer enrichment on top of tshark)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the suite against a simulated incident.")
    ap.add_argument("--scenario", default="incident", choices=tuple(SCENARIOS),
                    help="which scenario to run (default: incident — an estate from its logs; "
                         "triage-windows is one endpoint, from its logs and its live state)")
    ap.add_argument("--out", default=None, help="where to write the artifacts")
    ap.add_argument("--case", default=None, help="case id to accumulate them into")
    # DEFAULT ON. The demo regenerates byte-identical artifacts, so `case_store.append`'s
    # already-added guard fires on the second invocation and every one after it — the README's own
    # command raised a traceback for anyone who ran it twice, which is the single most likely
    # second action after a successful first run. The GUI had already made this choice
    # (`gui/app.py`: `reset=(step in (None, 0))`); the CLI is now consistent with it.
    ap.add_argument("--reset", action=argparse.BooleanOptionalAction, default=True,
                    help="rebuild the demo case from scratch (default; --no-reset to accumulate)")
    ap.add_argument("--artifacts-only", action="store_true",
                    help="write the files and stop, to load them by hand from the GUI")
    ap.add_argument("--evtx-dir", help="also run Hayabusa over a directory of real .evtx")
    ap.add_argument("--no-report", action="store_true", help="skip the report")
    ap.add_argument("--format", default="html", choices=("html", "markdown", "json", "case"),
                    help="report format (same set as run_report)")
    ap.add_argument("--level", default="detailed", choices=("summary", "detailed", "full"),
                    help="report detail level (same set as run_report)")
    ap.add_argument("--report-out", help="where to write the report "
                                         "(default: reports/demo-<level>.<ext>)")
    args = ap.parse_args(argv)

    sc = SCENARIOS[args.scenario]
    args.case = args.case or sc.DEFAULT_CASE
    # Under `out/`, which is gitignored: the artifacts carry hostnames and addresses (documentation
    # range, but a generated file in the tree is a leak waiting for a `git add -A`). `DEFAULT_OUT.parent`
    # put them in `analysis/demo/<scenario>/`, which nothing ignores.
    out = Path(args.out) if args.out else DEFAULT_OUT / sc.DEFAULT_CASE
    tools = available_tools()
    _print_level(tools, args.evtx_dir)

    if args.artifacts_only:
        plan = sc.generate(out)
        print(f"\nArtifacts written to {plan['outdir']}:")
        for p in sorted(plan["outdir"].rglob("*")):
            if p.is_file():
                print(f"  {p.relative_to(plan['outdir'])}")
        print("\nLoad them from the GUI (or pass them to run_report) to watch the correlation grow.")
        return 0

    built = build_demo_case(args.case, reset=args.reset, outdir=out, evtx_dir=args.evtx_dir,
                            scenario_module=sc)
    per_source = built["sources"]

    print("\nIngested into case", args.case)
    for label in sc.ORDER:
        if label in per_source:
            print(f"  {label:11} {per_source[label]:5d} records")
    for e in built["errors"]:
        print(f"  ! {e}")
    print(f"  infrastructure declared: {', '.join(built['infrastructure_ips'])} "
          f"(demoted as a bridge, excluded from clustering)")

    result = runner.analyze_case(args.case)
    kc = result.get("killchain") or []
    print(f"\n{result['summary']['events']} events, "
          f"{len(result['shared_indicators'])} bridges, "
          f"{len(result['incident_clusters'])} clusters, "
          f"{len(result['timeline'])} timeline entries, "
          f"kill chain reaching {kc[-1]['phase'] if kc else 'nothing'}")
    # Per phase, both halves: the tools that carry a technique, and the tools that were merely
    # active in the same window. Printing only the first is what let the demo read "Command and
    # Control: 1 event, evtx" beside a capture holding a beacon to the C2.
    for row in kc:
        also = row.get("corroboration_families") or "—"
        # `source_list` is the list of TOOLS that carried a technique for this phase, not the
        # techniques themselves — the HTML report labels the same column "sources (with
        # techniques)" and the CLI, which is the first thing a stranger reads, called it
        # "techniques:". Both are printed now, because both are worth seeing.
        print(f"  {row['phase']:<22} {row['events']:>3} ev  sources: {row.get('source_list') or '—':<20} "
              f"techniques: {(row.get('techniques') or '—')[:28]:<28} also in window: {also}")
    _bridges = result["shared_indicators"]
    if len(_bridges) > 6:
        print(f"  (strongest 6 of {len(_bridges)} bridges — the rest are in the report)")
    for row in _bridges[:6]:
        print(f"  {row['confidence']:.2f} {row['confidence_label']:6} {row['kind']:10} "
              f"{row['indicator'][:40]:40} {row['source_list']}")

    if not args.no_report:
        # NOT into `out`: that directory is regenerated on every run, so a report written there sat
        # beside the evidence it was made from and outlived it — the next run left a stale report
        # next to fresh artifacts with nothing saying they disagreed.
        # run_report owns the format→renderer mapping and the GUI serves the same one; a second
        # dispatch here is exactly the drift the shared helper exists to prevent (§16.3).
        from engine import run_report
        report = (Path(args.report_out) if args.report_out
                  else Path(__file__).resolve().parents[1] / "reports"
                  / f"{args.scenario}-{args.level}.{run_report._EXT[args.format]}")
        report.parent.mkdir(parents=True, exist_ok=True)
        meta = {"name": "EventHound demo", "sources": sorted(per_source)}
        report.write_text(run_report._render(result, meta, args.format, args.level, meta["name"]),
                          encoding="utf-8")
        print(f"\nReport: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
