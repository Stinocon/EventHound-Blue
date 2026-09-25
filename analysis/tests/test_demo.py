"""End-to-end: the simulated incident must produce the analysis it claims to produce.

This is the demo doing double duty. As a demo it makes the product runnable with no customer
evidence; as a test it is the only thing in the suite that goes all the way from FILES on disk,
through the real adapters, into the store and out the other side as bridges, clusters, episodes and
a timeline. Everything else either starts from records (so it never exercises an adapter) or covers
one adapter alone (so it never exercises correlation).

The expectations live in `demo/expectations.json`, in the same shape as the correlation corpus, so
`engine.run_eval`'s checkers are reused rather than reimplemented — one definition of what "the
bridge is missing" means, not two. A case naming a tool that is not installed is SKIPPED and said
to be skipped: a silently smaller picture reported as a pass is the failure mode this whole file
exists to avoid.

    uv run python tests/test_demo.py
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analytics import store  # noqa: E402
from engine import run_demo, run_eval  # noqa: E402

EXPECTATIONS = ROOT / "demo" / "expectations.json"

# The sample PCAP the adapter tests have always used, pinned by content. Its packet primitives moved
# to demo/pcap_writer.py so the scenario could share them; this proves the move changed no byte of
# the fixture, which no assertion about tshark's output ever could.
SAMPLE_PCAP_SHA256 = "46fd60df93286a61beb9cf8c6edd5eadb5c44fd59d72f34b4e31755fdba36417"


def _tool_available(name: str, tools: dict) -> bool:
    """Whether the tool a demo case declares in `requires` is present on this machine.

    It used to special-case "tshark" into itself, which is `tools.get(name)` written the long way —
    a no-op that read like a mapping and would have hidden a real one had a case ever needed a name
    that differs from its key in `available_tools()`. `run_demo.available_tools` is the SOT for
    those keys, so a name that is not among them is a mistake in the expectations, not an absence."""
    if name not in tools:
        raise KeyError(f"demo case requires {name!r}, which run_demo.available_tools() does not "
                       f"report on (it knows: {sorted(tools)})")
    return bool(tools[name])


def run() -> int:
    from tests import make_sample_pcap

    with tempfile.TemporaryDirectory(prefix="eventhound-demo-") as td:
        work = Path(td)

        # ── the promoted primitives still write the historical fixture, byte for byte ──
        sample = make_sample_pcap.write_sample(work / "sample.pcap")
        digest = hashlib.sha256(sample.read_bytes()).hexdigest()
        assert digest == SAMPLE_PCAP_SHA256, (
            f"make_sample_pcap changed: {digest} != {SAMPLE_PCAP_SHA256}. The PCAP primitives are "
            "shared with demo/pcap_writer.py — a change here silently rewrites an adapter fixture.")

        # ── generate the incident and read it back through the real adapters ──
        tools = run_demo.available_tools()
        errors: list[str] = []
        per_source: dict[str, list[dict]] = {}
        records = run_demo.demo_records(work / "out", errors=errors, per_source=per_source)

        # A source that produced nothing is a broken generator or a broken adapter, and either way
        # the expectations below would fail for a reason the failure text would not name.
        for src, recs in per_source.items():
            if src == "pcap" and not tools["tshark"]:
                continue
            if src == "yara" and not tools["yara"]:
                continue
            assert recs, f"source {src!r} contributed no records: {errors}"
        assert len(records) > 40, f"only {len(records)} records from nine sources: {errors}"

        # The whole result must survive plain json.dumps. Every consumer that leaves the process
        # serialises it that way — the GUI's SSE completion, the case endpoint, the exported bundle
        # — and `episodes` used to hand back DuckDB datetimes, so the pipeline raised a TypeError
        # exactly when the temporal correlation had something to say. This dataset is the one that
        # produces multi-family episodes, which is why the guard belongs here.
        from analytics import runner
        result = runner.analyze(records)
        assert result["episodes"], "no episode: the serialisation guard below would be vacuous"
        json.dumps(result)

        doc = json.loads(EXPECTATIONS.read_text(encoding="utf-8"))
        con = store.from_records(records)
        try:
            failures: list[str] = []
            ran = skipped = 0
            for case in doc["cases"]:
                missing = [t for t in case.get("requires", []) if not _tool_available(t, tools)]
                if missing:
                    print(f"SKIP  {case['id']}: needs {', '.join(missing)}")
                    skipped += 1
                    continue
                ran += 1
                for ok, detail in _run_case(case, con):
                    if not ok:
                        failures.append(f"{case['id']}: {detail}")
            if failures:
                for f in failures:
                    print("FAIL  " + f)
                for case in doc["cases"]:
                    if any(f.startswith(case["id"] + ":") for f in failures):
                        print(f"\n{case['id']} — {case['title']}\n    {case['rationale']}")
                raise AssertionError(f"{len(failures)} demo expectation(s) not met")
        finally:
            con.close()

    print(f"PASS  demo: {len(records)} records from ten generated sources, "
          f"{ran} expectation case(s) verified, {skipped} skipped for missing tools")
    return 0


def _run_case(case: dict, con) -> list[tuple[bool, str]]:
    """Run one case against an already-populated store, reusing run_eval's checkers.

    `run_eval.run_case` builds its own store from a case's `records`; here the records come from the
    generated files instead, so the checks are dispatched directly. Same functions, same meaning of
    a failure — the corpus and the demo do not get to disagree about what a bridge is."""
    from analytics import correlate, recipes, runner

    exp = case.get("expect") or {}
    checks: list[tuple[bool, str]] = []
    if "bridges" in exp or "absent" in exp or "ranking" in exp:
        shared = correlate.shared_indicators(con)
        checks += run_eval._check_bridges(exp.get("bridges") or [], shared)
        checks += run_eval._check_absent(exp.get("absent") or [], shared)
        checks += run_eval._check_ranking(exp.get("ranking") or [], shared)
    if "episodes_multi_family" in exp:
        checks += run_eval._check_episodes(
            exp["episodes_multi_family"], correlate.episodes(con, gap_seconds=120, min_sources=1))
    if "clusters" in exp:
        checks += run_eval._check_clusters(exp["clusters"], correlate.incident_clusters(con))
    if "beaconing" in exp:
        checks += run_eval._check_beaconing(exp["beaconing"], recipes.beaconing(con))
    if "timeline" in exp:
        # The same limit the pipeline applies (runner.analyze_con), not correlate.timeline's own
        # default of 200: the expectations bound the number of timeline rows, so checking a
        # differently-capped view means the test and the report can disagree about the same case.
        checks += run_eval._check_timeline(exp["timeline"],
                                           correlate.timeline(con, limit=runner.TIMELINE_LIMIT))
    return checks


def test_demo():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
