"""Performance profile of the analytics pipeline: where the time and memory actually go.

Two independent axes, selected by flag (default: run both).

    uv run python -m engine.run_bench --analytics                 # offline, synthetic, deterministic
    uv run python -m engine.run_bench --analytics --quick          # 1000 records, a few seconds
    uv run python -m engine.run_bench --analytics --sizes 1000,50000
    uv run python -m engine.run_bench --ingest                     # real Hayabusa throughput on the
                                                                    #   local EVTX-ATTACK-SAMPLES corpus
    uv run python -m engine.run_bench --json                       # machine-readable, no tables

The analytics axis never touches a binary: it generates synthetic records in the common schema and
times `store.from_records` plus every recipe and correlation call separately, because a single total
hides which stage is the one worth optimizing. The ingest axis is the opposite — it needs Hayabusa and
a real EVTX corpus, and degrades honestly (a clear skip line, exit 0) when either is missing rather
than failing or fabricating numbers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import resource
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import correlate, recipes, runner, store  # noqa: E402
from engine import hayabusa_runner, version  # noqa: E402

DEFAULT_SIZES = (1000, 10000, 100000)
QUICK_SIZES = (1000,)
CORPUS_DEFAULT = Path(__file__).resolve().parents[1] / ".tools" / "EVTX-ATTACK-SAMPLES"
INGEST_STEPS = (1, 8, 32)


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic record generation (analytics axis)
# ─────────────────────────────────────────────────────────────────────────────

# Shared entity pools: the SAME hosts/users/ips/hashes are used across evtx/pcap/log records.
# This is what makes the benchmark honest — if each source drew from disjoint pools, correlation
# (shared_indicators, incident_clusters, entity_graph) would see empty joins and the timings
# for those stages would measure nothing, not the real join cost on real-shaped data.
_HOSTS = [f"host-{i:02d}" for i in range(12)]
_USERS = [f"user{i:02d}" for i in range(20)]
# Private range on purpose: normalize.is_generic_ip() drops loopback/link-local/multicast/reserved,
# so a "public-looking" reserved block here would silently disappear from every correlation stage.
_IPS = [f"10.20.30.{i}" for i in range(11, 19)]
_HASHES = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(8)]

_EVTX_CODES = {
    4624: ("authentication", "logon-success", "success"),
    4625: ("authentication", "logon-failed", "failure"),
    4688: ("process", "process-create", None),
    4104: ("execution", "scriptblock-logging", None),
    7045: ("persistence", "service-installed", None),
}
_TECHNIQUES = ["T1003.001", "T1059.001", "T1021.002", "T1547.001", "T1071.004"]
_RULE_LEVELS = ["medium", "high", "critical"]
_COMMON_PROCESSES = ["svchost.exe", "explorer.exe", "chrome.exe", "cmd.exe", "powershell.exe", "lsass.exe"]
_COMMON_PARENTS = ["services.exe", "explorer.exe", "wininit.exe", "cmd.exe"]
_COMMON_DOMAINS = ["corp.example", "update.microsoft.com", "login.microsoftonline.com"]


def _zipf_pool(prefix: str, n: int, common: list[str]) -> tuple[list[str], list[float]]:
    """A small set of dominant names plus a long tail sized to the dataset.

    Real process/DNS distributions are Zipfian: a handful of names cover most events, and most
    distinct names appear once or twice (the long tail the `rare_*` recipes exist to surface). The
    tail is sized as a fraction of `n` (not a fixed constant) so the skew looks the same shape at
    every dataset size instead of vanishing at 100k or dominating at 1k.
    rare_count = max(20, n // 5) capped at 20_000: covers 1k..100k+ without runaway pool sizes.
    """
    rare_count = min(max(20, n // 5), 20_000)
    tail = [f"{prefix}{i}" for i in range(rare_count)]
    population = list(common) + tail
    # Dominant names get a flat high weight, the tail gets weight 1 each — a few dominate,
    # everything else is seen rarely, which is the property the recipes are built to find.
    weights = [50.0] * len(common) + [1.0] * len(tail)
    return population, weights


def _synthetic_records(n: int, seed: int = 1234) -> list[dict]:
    """Deterministic synthetic dataset in the common schema, mixing three sources that genuinely
    share entities (see the pool comment above) so correlation has real work to do, not empty joins.

    Composition: ~60% evtx, ~30% pcap, ~10% log — matches a typical mixed-source case where Windows
    telemetry dominates volume. Timestamps are grouped into bursts spaced 30 minutes apart (well
    above the default 120s episode session-gap) with events inside a burst jittered over ~90s (well
    below it): that gives `episodes` real multi-family clusters to find instead of one event per
    episode, without hand-crafting exact gaps.
    """
    rnd = random.Random(seed)
    n_evtx = int(n * 0.6)
    n_pcap = int(n * 0.3)
    n_log = n - n_evtx - n_pcap
    tags = ["evtx"] * n_evtx + ["pcap"] * n_pcap + ["log"] * n_log
    rnd.shuffle(tags)  # mixes the three sources across bursts, not segregated by generation order

    proc_pool, proc_w = _zipf_pool("tool", n, _COMMON_PROCESSES)
    parent_pool, parent_w = _zipf_pool("parent-tool", max(n // 4, 1), _COMMON_PARENTS)
    domain_pool, domain_w = _zipf_pool("sub", max(n // 10, 1), _COMMON_DOMAINS)

    num_bursts = max(5, n // 100)
    burst_spacing = timedelta(minutes=30)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    records: list[dict] = []
    for i, tag in enumerate(tags):
        burst = i % num_bursts
        ts = base + burst * burst_spacing + timedelta(seconds=rnd.uniform(0, 90))
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        if tag == "evtx":
            code = rnd.choice(list(_EVTX_CODES))
            category, action, outcome = _EVTX_CODES[code]
            rec: dict = {
                "@timestamp": ts_str, "event.source": "evtx", "event.category": category,
                "event.action": action, "event.code": code, "event.outcome": outcome,
                "host.name": rnd.choice(_HOSTS), "user.name": rnd.choice(_USERS),
                "process.name": rnd.choices(proc_pool, weights=proc_w, k=1)[0],
                "process.parent.name": rnd.choices(parent_pool, weights=parent_w, k=1)[0],
                "process.pid": str(rnd.randint(1000, 60000)),
            }
            if code in (4624, 4625) and rnd.random() < 0.3:
                rec["source.ip"] = rnd.choice(_IPS)
                rec["logon.type"] = rnd.choice(["3", "10"])
            if code == 4688 and rnd.random() < 0.4:
                rec["process.command_line"] = f"{rec['process.name']} /arg{rnd.randint(0, 9)}"
                if rnd.random() < 0.25:
                    rec["file.hash"] = rnd.choice(_HASHES)
            # A minority of events carry ATT&CK + Sigma metadata: enough for killchain/technique_catalog
            # /timeline's 'ATT&CK technique'/'Sigma' branches to have real rows, not empty ones.
            if rnd.random() < 0.2:
                rec["attack.techniques"] = [rnd.choice(_TECHNIQUES)]
                rec["rule.title"] = f"Suspicious {rec['process.name']}"
                rec["rule.level"] = rnd.choice(_RULE_LEVELS)
        elif tag == "pcap":
            rec = {
                "@timestamp": ts_str, "event.source": "pcap",
                "source.ip": rnd.choice(_IPS), "destination.ip": rnd.choice(_IPS),
                "destination.port": rnd.choice([80, 443, 22, 445, 3389, 8443, 51820, 4444]),
                "network.transport": rnd.choice(["tcp", "udp"]),
                "network.bytes": rnd.randint(60, 150000),
            }
            if rnd.random() < 0.3:
                rec["dns.question.name"] = rnd.choices(domain_pool, weights=domain_w, k=1)[0]
        else:  # log
            rec = {
                "@timestamp": ts_str, "event.source": "log",
                "source.ip": rnd.choice(_IPS),
                "message": f"session established for {rnd.choice(_USERS)} on {rnd.choice(_HOSTS)}",
            }
            if rnd.random() < 0.4:
                rec["url.original"] = f"/api/v1/{rnd.choices(domain_pool, weights=domain_w, k=1)[0]}"
            if rnd.random() < 0.15:
                rec["file.hash"] = rnd.choice(_HASHES)
        records.append(rec)

    records.sort(key=lambda r: r["@timestamp"])
    return records


# ─────────────────────────────────────────────────────────────────────────────
# Analytics axis
# ─────────────────────────────────────────────────────────────────────────────

def _peak_rss_mb() -> float:
    # ru_maxrss is a resident-set watermark since process start (not a per-call delta), and its unit
    # differs by platform: bytes on macOS/BSD, kilobytes on Linux. Reported here already normalized
    # to MB so callers never have to remember which OS they are reading the number on.
    #
    # Deliberately the ONLY memory figure here. tracemalloc was the obvious alternative and is the
    # wrong tool twice over: it traces Python allocations, so it cannot see DuckDB's C++ arena —
    # which is most of the footprint — and enabling it inflates every timing in this file roughly
    # threefold, so the profile would misreport its own subject to report a number that misses the
    # bulk of the memory.
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return raw / (1024 * 1024) if sys.platform == "darwin" else raw / 1024


def _peak_rss_with_children_mb() -> float:
    """Watermark including subprocesses — the only meaningful figure for the ingest axis, where the
    parsing happens in Hayabusa, not in this interpreter. RUSAGE_CHILDREN reports the largest single
    reaped child, so with files processed in parallel this is the biggest one, not their sum."""
    unit = (1024 * 1024) if sys.platform == "darwin" else 1024
    return (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            + resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss) / unit


def _run_one_size(n: int, seed: int = 1234) -> dict:
    """Times record generation + store build + every recipe + every correlation call, separately."""
    t0 = time.perf_counter()
    t = time.perf_counter()
    records = _synthetic_records(n, seed=seed)
    stages: list[tuple[str, float]] = [("synthetic.generate", time.perf_counter() - t)]

    t = time.perf_counter()
    con = store.from_records(records)
    stages.append(("store.from_records", time.perf_counter() - t))
    try:
        for name, (fn, _desc) in recipes.RECIPES.items():
            t = time.perf_counter()
            fn(con)
            stages.append((f"recipe.{name}", time.perf_counter() - t))
        corr_calls = [
            ("correlate.host_overview", lambda: correlate.host_overview(con)),
            ("correlate.shared_indicators", lambda: correlate.shared_indicators(con)),
            ("correlate.episodes", lambda: correlate.episodes(con)),
            ("correlate.incident_clusters", lambda: correlate.incident_clusters(con)),
            ("correlate.timeline", lambda: correlate.timeline(con, limit=500)),
            ("correlate.killchain", lambda: correlate.killchain(con)),
            ("correlate.technique_catalog", lambda: correlate.technique_catalog(con)),
            ("correlate.host_killchain", lambda: correlate.host_killchain(con)),
        ]
        for label, call in corr_calls:
            t = time.perf_counter()
            call()
            stages.append((label, time.perf_counter() - t))
    finally:
        con.close()

    total = time.perf_counter() - t0
    return {
        "n": n,
        "stages": [{"stage": s, "seconds": round(t, 6)} for s, t in stages],
        "total_seconds": round(total, 6),
        "peak_rss_mb": round(_peak_rss_mb(), 2),
    }


def _worst_scaling(results: list[dict]) -> str | None:
    """Names the stage whose time grew the most relative to how much the dataset grew.

    A total-time comparison tells you the run got slower; it does not tell you WHICH stage to fix.
    Normalizing by the size ratio surfaces the one growing faster than the data itself
    (superlinear) instead of the one that is simply large."""
    if len(results) < 2:
        return None
    small, large = results[0], results[-1]
    size_ratio = large["n"] / small["n"]
    if size_ratio <= 1:
        return None
    small_t = {s["stage"]: s["seconds"] for s in small["stages"]}
    worst_stage, worst_factor, worst_time_ratio = None, 0.0, 0.0
    for s in large["stages"]:
        name = s["stage"]
        # The generator is scaffolding, not pipeline: its pools grow with n by design, so it would
        # win this comparison and point at the benchmark instead of at the product.
        if name not in small_t or name == "synthetic.generate":
            continue
        # Floor tiny stage times so a near-zero denominator doesn't produce a meaningless spike.
        base = max(small_t[name], 1e-4)
        time_ratio = s["seconds"] / base
        factor = time_ratio / size_ratio
        if factor > worst_factor:
            worst_stage, worst_factor, worst_time_ratio = name, factor, time_ratio
    if worst_stage is None:
        return None
    shape = "superlinear" if worst_factor > 1.15 else ("sublinear" if worst_factor < 0.85 else "~linear")
    return (f"worst scaling: {worst_stage} grew {worst_time_ratio:.1f}x while data grew "
            f"{size_ratio:.1f}x ({worst_factor:.2f}x, {shape}) "
            f"[n={small['n']}→{large['n']}]")


def _print_analytics_table(results: list[dict]) -> None:
    for r in results:
        print(f"\n== analytics: n={r['n']} ==")
        print(f"{'stage':<32}{'seconds':>12}")
        for s in r["stages"]:
            print(f"{s['stage']:<32}{s['seconds']:>12.6f}")
        print(f"{'TOTAL':<32}{r['total_seconds']:>12.6f}")
        print(f"peak rss (process watermark, includes the interpreter): {r['peak_rss_mb']:.1f} MB")
    line = _worst_scaling(results)
    if line:
        print(f"\n{line}")


# ─────────────────────────────────────────────────────────────────────────────
# Ingest axis
# ─────────────────────────────────────────────────────────────────────────────

def _corpus_files(corpus: Path) -> list[Path]:
    return sorted(corpus.rglob("*.evtx"))


def _run_ingest(corpus_dir: Path, quiet: bool) -> list[dict]:
    """Real Hayabusa throughput on the local EVTX corpus. Degrades honestly: a missing binary or
    missing/empty corpus is a clean skip (printed, not JSON-mangled), never a failure."""
    def skip(msg: str) -> list[dict]:
        if not quiet:
            print(f"ingest: {msg}")
        return []

    if not corpus_dir.is_dir():
        return skip(f"corpus not found at {corpus_dir} — skipping (populate analysis/.tools/, see analysis/README.md)")
    try:
        hayabusa_runner.find_binary()
    except FileNotFoundError:
        return skip("Hayabusa binary not available — skipping (see analysis/README.md)")

    files = _corpus_files(corpus_dir)
    if not files:
        return skip(f"corpus dir {corpus_dir} contains no .evtx files — skipping")

    total = len(files)
    steps = [c for c in INGEST_STEPS if c <= total]
    if not steps or steps[-1] != total:
        steps.append(total)

    out: list[dict] = []
    for count in steps:
        subset = files[:count]
        mb_in = sum(p.stat().st_size for p in subset) / (1024 * 1024)
        errors: list[str] = []
        t0 = time.perf_counter()
        recs = runner.build_records(evtx=[str(p) for p in subset], errors=errors)
        seconds = time.perf_counter() - t0
        row = {
            "files": count, "mb_in": round(mb_in, 2), "seconds": round(seconds, 3),
            "mb_per_s": round(mb_in / seconds, 3) if seconds > 0 else 0.0,
            "records": len(recs),
            "records_per_s": round(len(recs) / seconds, 1) if seconds > 0 else 0.0,
            # Per-file cost is the number that actually explains this axis: Hayabusa is invoked once
            # per EVTX file and reloads the whole Sigma rule set each time, so seconds/file barely
            # moves with file size while MB/s swings with whatever the corpus happens to contain.
            "seconds_per_file": round(seconds / count, 3) if count else 0.0,
            "peak_rss_mb": round(_peak_rss_with_children_mb(), 2),
        }
        out.append(row)
        if not quiet:
            note = f"  ({len(errors)} file(s) skipped)" if errors else ""
            print(f"{row['files']:>6} files  {row['mb_in']:>9.2f} MB  {row['seconds']:>8.3f}s  "
                  f"{row['mb_per_s']:>9.3f} MB/s  {row['seconds_per_file']:>7.2f} s/file  "
                  f"{row['records']:>7} recs  {row['peak_rss_mb']:>8.1f} MB rss{note}")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _parse_sizes(spec: str) -> tuple[int, ...]:
    return tuple(int(x.strip()) for x in spec.split(",") if x.strip())


def main() -> int:
    ap = argparse.ArgumentParser(description="Performance profile of the analytics pipeline.")
    ap.add_argument("--analytics", action="store_true", help="run the synthetic-data analytics axis")
    ap.add_argument("--ingest", action="store_true", help="run the real Hayabusa ingest axis")
    ap.add_argument("--sizes", help="comma-separated record counts for --analytics (default 1000,10000,100000)")
    ap.add_argument("--quick", action="store_true", help="--analytics with a single small size (1000), for smoke tests")
    ap.add_argument("--corpus", default=str(CORPUS_DEFAULT), help="EVTX corpus directory for --ingest")
    ap.add_argument("--json", action="store_true", help="print only machine-readable JSON (no tables)")
    args = ap.parse_args()

    try:
        sizes = QUICK_SIZES if args.quick else (_parse_sizes(args.sizes) if args.sizes else DEFAULT_SIZES)
    except ValueError:
        print(f"--sizes must be a comma-separated list of integers, got {args.sizes!r}", file=sys.stderr)
        return 2

    run_analytics = args.analytics or not (args.analytics or args.ingest)
    run_ingest = args.ingest or not (args.analytics or args.ingest)

    analytics_results: list[dict] = []
    ingest_results: list[dict] = []

    if run_analytics:
        analytics_results = [_run_one_size(n) for n in sizes]
        if not args.json:
            _print_analytics_table(analytics_results)

    if run_ingest:
        if not args.json and run_analytics:
            print()
        ingest_results = _run_ingest(Path(args.corpus), quiet=args.json)

    if args.json:
        out = {
            "tool_version": version.APP_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "machine": {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "cpu_count": os.cpu_count(),
            },
        }
        if analytics_results:
            out["analytics"] = analytics_results
        if ingest_results:
            out["ingest"] = ingest_results
        print(json.dumps(out, ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
