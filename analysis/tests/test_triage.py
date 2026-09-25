"""The Windows live triage: what the state source adds, asserted by removing it.

`demo/expectations.json` checks that the incident scenario concludes what it claims. This file
checks a different thing, and it is the argument that decides whether osquery earns a place in the
suite at all: it runs the triage WITH osquery, then rebuilds the identical evidence WITHOUT it, and
asserts that the address bridge and every artifact bridge are gone.

A number in an expectations file says a bridge exists. Rebuilding without the source says why, and
it is the only form of the claim that can fail when the answer changes. If a run of this file says
osquery adds nothing, the source should be removed — that is what the test is for.

    uv run python tests/test_triage.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analytics import store  # noqa: E402
from demo import triage_windows  # noqa: E402
from engine import run_demo  # noqa: E402
from tests.test_demo import _run_case  # noqa: E402

EXPECTATIONS = ROOT / "demo" / "triage_expectations.json"

# The bridges that exist ONLY because a state snapshot names the same things the logs do. If any of
# these survives without osquery, osquery is not carrying it and the scenario is claiming credit it
# has not earned.
OSQUERY_ONLY = (("198.51.100.13", "ip"), ("fontdrvhost.exe", "file"))


def _records(work: Path, without: str | None = None) -> list[dict]:
    """The triage evidence, optionally with one source withheld."""
    per_source: dict[str, list[dict]] = {}
    errors: list[str] = []
    if without is None:
        return run_demo.demo_records(work / "out", errors=errors, per_source=per_source,
                                     scenario_module=triage_windows)
    records: list[dict] = []
    for key in triage_windows.ORDER:
        if key == without:
            continue
        records += run_demo.demo_records(work / "out", errors=errors, per_source=per_source,
                                         only=key, scenario_module=triage_windows)
    return records


def _bridges(records: list[dict]) -> dict[tuple[str, str], dict]:
    from analytics import correlate
    con = store.from_records(records)
    try:
        return {(r["indicator"], r["kind"]): r for r in correlate.shared_indicators(con)}
    finally:
        con.close()


def test_the_triage_concludes_what_it_claims() -> None:
    with tempfile.TemporaryDirectory(prefix="eh-triage-") as td:
        work = Path(td)
        errors: list[str] = []
        per_source: dict[str, list[dict]] = {}
        records = run_demo.demo_records(work / "out", errors=errors, per_source=per_source,
                                        scenario_module=triage_windows)

        # A source that produced nothing is a broken generator or a broken adapter, and either way
        # the expectations below would fail for a reason the failure text would not name.
        for src, recs in per_source.items():
            assert recs, f"source {src!r} contributed no records: {errors}"

        con = store.from_records(records)
        try:
            failures: list[str] = []
            doc = json.loads(EXPECTATIONS.read_text(encoding="utf-8"))
            for case in doc["cases"]:
                for ok, detail in _run_case(case, con):
                    if not ok:
                        failures.append(f"{case['id']}: {detail}")
            assert not failures, "\n  ".join(failures)
        finally:
            con.close()
    print(f"PASS  triage: {len(records)} records from {len(per_source)} sources, "
          f"expectations met")


def test_osquery_is_what_carries_the_live_state_bridges() -> None:
    """The measurement that decides the source's place: withhold osquery and watch them go.

    Not a coverage number and not a code count — the same evidence, the same pipeline, one source
    fewer, and the question is whether anything the triage concluded survives."""
    with tempfile.TemporaryDirectory(prefix="eh-triage-no-osq-") as td:
        work = Path(td)
        with_all = _bridges(_records(work / "with"))
        without = _bridges(_records(work / "without", without="osquery"))

        survived = [f"{i} ({k})" for i, k in OSQUERY_ONLY if (i, k) in without]
        assert not survived, (
            "these bridges exist without osquery, so osquery is not what carries them: "
            + ", ".join(survived))

        for indicator, kind in OSQUERY_ONLY:
            assert (indicator, kind) in with_all, (
                f"{kind} {indicator} is missing even WITH osquery — the scenario's premise is wrong")
        # And the evidence is genuinely smaller, not merely re-attributed.
        assert len(without) < len(with_all), f"{len(without)} vs {len(with_all)}"
    print(f"PASS  triage: without osquery the evidence drops from {len(with_all)} bridges to "
          f"{len(without)} — the address and the artifact go with it")


def run() -> int:
    test_the_triage_concludes_what_it_claims()
    test_osquery_is_what_carries_the_live_state_bridges()
    return 0


def test_triage():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
