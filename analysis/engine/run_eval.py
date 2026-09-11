"""Evaluate the correlation engine against a labelled corpus (eval/correlation_corpus.json).

The correlation engine had no golden tests of its own, so every adjustment to the
confidence weights, the beaconing threshold or the episode session-gap was an act of faith. This
turns those knobs into measurements: each case declares records in the common schema and what the
engine MUST conclude from them, and this runner reports what holds and what does not.

    uv run python -m engine.run_eval                    # run the corpus, exit 1 on any failure
    uv run python -m engine.run_eval --case <id> -v     # one case, with every check listed
    uv run python -m engine.run_eval --sweep-gap        # episode expectations across session-gaps

The corpus is synthetic and offline (no binaries, no network): it measures the correlation logic,
not the wrapped tools. Its expectations are security claims — read the `rationale` of a case before
changing what it expects, and change the label only when the claim itself was wrong.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import correlate, recipes, store  # noqa: E402

CORPUS = Path(__file__).resolve().parents[1] / "eval" / "correlation_corpus.json"

# Session-gap values swept by --sweep-gap, around the 120 s default.
_SWEEP_GAPS = (30, 60, 120, 300, 600)


def _split(v) -> list[str]:
    """Cluster fields arrive as 'a, b, c' strings (they are rendered directly in the report)."""
    return [x.strip() for x in str(v or "").split(",") if x.strip()]


def _check_bridges(expect: list[dict], shared: list[dict]) -> list[tuple[bool, str]]:
    out = []
    for e in expect:
        row = next((r for r in shared
                    if r["indicator"] == e["indicator"] and r["kind"] == e["kind"]), None)
        if row is None:
            out.append((False, f"bridge missing: {e['kind']} {e['indicator']} "
                               f"(present: {sorted({r['indicator'] for r in shared})})"))
            continue
        ok, why = True, f"bridge {e['kind']} {e['indicator']}"
        if "min_families" in e and row["families"] < e["min_families"]:
            ok, why = False, f"{why}: families {row['families']} < {e['min_families']}"
        # An UPPER bound is not symmetry for its own sake: over-counting families is a real defect
        # with its own consequence — confidence rises with the count, so a bridge credited to more
        # tools than actually saw it reads as corroborated when it is not.
        if "max_families" in e and row["families"] > e["max_families"]:
            ok, why = False, f"{why}: families {row['families']} > {e['max_families']}"
        if "match_type" in e and row.get("match_type") != e["match_type"]:
            ok, why = False, f"{why}: match_type {row.get('match_type')!r} != {e['match_type']!r}"
        out.append((ok, why))
    return out


def _check_absent(expect: list[dict], shared: list[dict]) -> list[tuple[bool, str]]:
    out = []
    for e in expect:
        hit = next((r for r in shared
                    if r["indicator"] == e["indicator"] and r["kind"] == e["kind"]), None)
        out.append((hit is None,
                    f"excluded {e['kind']} {e['indicator']}" if hit is None else
                    f"NOT excluded: {e['kind']} {e['indicator']} reported as a bridge "
                    f"({hit['families']} families) — ubiquitous values link everything to everything"))
    return out


def _check_ranking(expect: list[list[str]], shared: list[dict]) -> list[tuple[bool, str]]:
    order = [r["indicator"] for r in shared]     # shared_indicators is already confidence-sorted
    out = []
    for a, b in expect:
        if a not in order or b not in order:
            out.append((False, f"ranking {a[:16]}… > {b}: one of the two is not a bridge"))
            continue
        ok = order.index(a) < order.index(b)
        out.append((ok, f"ranking {a[:16]}… > {b}" if ok else
                        f"ranking WRONG: {b} outranks {a[:16]}… (weights say otherwise)"))
    return out


def _check_episodes(expect: dict, eps: list[dict]) -> list[tuple[bool, str]]:
    multi = [e for e in eps if e.get("families", 0) > 1]
    lo, hi = expect.get("min", 0), expect.get("max")
    ok = len(multi) >= lo and (hi is None or len(multi) <= hi)
    bound = f"≥{lo}" + (f" and ≤{hi}" if hi is not None else "")
    return [(ok, f"multi-family episodes: {len(multi)} ({bound})")]


def _check_clusters(expect: list[dict], clusters: list[dict]) -> list[tuple[bool, str]]:
    out = []
    for e in expect:
        want = {k: [str(v).lower() for v in e.get(k, [])] for k in ("users", "hosts", "ips")}
        match = None
        for c in clusters:
            if all(set(want[k]) <= {x.lower() for x in _split(c.get(k))} for k in want):
                match = c
                break
        if match is None:
            out.append((False, "no single cluster holds "
                               + " + ".join(f"{k}={v}" for k, v in want.items() if v)
                               + f" (clusters found: {len(clusters)})"))
            continue
        ok, why = True, f"cluster holds {sum(len(v) for v in want.values())} expected entities"
        if match["sources"] < e.get("min_sources", 0):
            ok, why = False, f"cluster spans {match['sources']} sources < {e['min_sources']}"
        if match.get("hashes", 0) < e.get("min_hashes", 0):
            ok, why = False, f"cluster has {match.get('hashes')} hashes < {e['min_hashes']}"
        out.append((ok, why))
    return out


def _check_beaconing(expect: list[dict], beacons: list[dict]) -> list[tuple[bool, str]]:
    seen = {b["dst_ip"] for b in beacons}
    out = []
    for e in expect:
        present = e["dst_ip"] in seen
        ok = present == e["present"]
        out.append((ok, f"beaconing {e['dst_ip']}: {'detected' if present else 'not detected'}"
                        + ("" if ok else f" — expected {'detected' if e['present'] else 'not detected'}")))
    return out


def _check_timeline(expect: dict, tl: list[dict]) -> list[tuple[bool, str]]:
    out = []
    counts: dict[str, int] = {}
    for r in tl:
        counts[r["why"]] = counts.get(r["why"], 0) + 1
    for why, minimum in (expect.get("why_min") or {}).items():
        got = counts.get(why, 0)
        out.append((got >= minimum, f"timeline '{why}': {got} (≥{minimum})"))
    for why in expect.get("why_absent") or []:
        out.append((why not in counts,
                    f"timeline without '{why}'" if why not in counts else
                    f"timeline fell back to '{why}': the salience filter kept nothing"))
    if "max_events" in expect:
        out.append((len(tl) <= expect["max_events"],
                    f"timeline size {len(tl)} (≤{expect['max_events']}: routine events stay out)"))
    return out


def run_case(case: dict, gap_seconds: int = 120) -> list[tuple[bool, str]]:
    """Run one case and return its checks as (ok, description) pairs."""
    exp = case.get("expect") or {}
    con = store.from_records(case["records"])
    try:
        checks: list[tuple[bool, str]] = []
        if "bridges" in exp or "absent" in exp or "ranking" in exp:
            shared = correlate.shared_indicators(con)
            checks += _check_bridges(exp.get("bridges") or [], shared)
            checks += _check_absent(exp.get("absent") or [], shared)
            checks += _check_ranking(exp.get("ranking") or [], shared)
        if "episodes_multi_family" in exp:
            checks += _check_episodes(exp["episodes_multi_family"],
                                      correlate.episodes(con, gap_seconds=gap_seconds,
                                                         min_sources=1))
        if "clusters" in exp:
            checks += _check_clusters(exp["clusters"], correlate.incident_clusters(con))
        if "beaconing" in exp:
            checks += _check_beaconing(exp["beaconing"], recipes.beaconing(con))
        if "timeline" in exp:
            checks += _check_timeline(exp["timeline"], correlate.timeline(con))
        return checks
    finally:
        con.close()


def sweep_gap(cases: list[dict]) -> None:
    """Episode expectations across session-gap values: shows whether the default is defensible."""
    relevant = [c for c in cases if "episodes_multi_family" in (c.get("expect") or {})]
    if not relevant:
        print("no case declares episode expectations — nothing to sweep")
        return
    print(f"\nSession-gap sweep over {len(relevant)} case(s) with episode expectations:\n")
    band = []
    for gap in _SWEEP_GAPS:
        broken = []
        for c in relevant:
            con = store.from_records(c["records"])
            try:
                eps = correlate.episodes(con, gap_seconds=gap, min_sources=1)
            finally:
                con.close()
            if not _check_episodes(c["expect"]["episodes_multi_family"], eps)[0][0]:
                broken.append(c["id"])
        if not broken:
            band.append(gap)
        mark = "  <- default" if gap == 120 else ""
        detail = "" if not broken else "   broken: " + ", ".join(broken)
        print(f"  gap={gap:>4}s  {len(relevant) - len(broken)}/{len(relevant)} hold{mark}{detail}")
    if len(band) == len(_SWEEP_GAPS):
        print("\nEvery value holds, which is not the same as every value being right: the corpus does\n"
              "not yet separate them. Add a case that does before defending the default.")
    elif band:
        print(f"\nDefensible band: {band[0]}–{band[-1]}s. Below it a real chain gets split; above it\n"
              "unrelated activity merges into one episode. The default is only as good as this band.")


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate correlation against the labelled corpus")
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--case", help="run a single case by id")
    ap.add_argument("--gap", type=int, default=120, help="episode session-gap in seconds (default 120)")
    ap.add_argument("--sweep-gap", action="store_true", help="sweep the session-gap instead of a plain run")
    ap.add_argument("-v", "--verbose", action="store_true", help="list every check, not only failures")
    args = ap.parse_args()

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    cases = corpus.get("cases") or []
    if args.case:
        cases = [c for c in cases if c["id"] == args.case]
        if not cases:
            print(f"no case with id {args.case!r}", file=sys.stderr)
            return 2

    if args.sweep_gap:
        sweep_gap(cases)
        return 0

    total = failed = 0
    failed_cases = []
    for case in cases:
        checks = run_case(case, gap_seconds=args.gap)
        bad = [d for ok, d in checks if not ok]
        total += len(checks)
        failed += len(bad)
        status = "PASS" if not bad else "FAIL"
        print(f"[{status}] {case['id']}  ({len(checks) - len(bad)}/{len(checks)} checks)")
        if args.verbose:
            for ok, d in checks:
                print(f"         {'·' if ok else '✗'} {d}")
        elif bad:
            failed_cases.append(case)
            for d in bad:
                print(f"         ✗ {d}")
    # The rationale explains why the expectation exists at all — worth reading before "fixing" a
    # failure by relaxing the label.
    for case in failed_cases:
        print(f"\n{case['id']} — {case['title']}\n    {case['rationale']}\n    knob: {case.get('knob', 'n/a')}")

    print(f"\n{len(cases)} case(s), {total} checks, {total - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
