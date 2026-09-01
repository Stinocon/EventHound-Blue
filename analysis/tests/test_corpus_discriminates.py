"""The corpus must FAIL when the engine is wrong — otherwise it measures nothing.

`engine.run_eval` passing is only half the evidence: expectations written after the fact tend to
describe whatever the code already does. This test breaks one knob at a time and asserts that the
case guarding that knob turns red. It is the guard on the guard: a new case that cannot be made to
fail is decoration, and this is where that shows up.

    uv run python tests/test_corpus_discriminates.py

The mutations reach into module internals on purpose. If a rename breaks this test, the fix is to
update the mutation — not to delete it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analytics import correlate, normalize, recipes, store  # noqa: E402
from engine import run_eval  # noqa: E402

CASES = {c["id"]: c for c in
         json.loads((ROOT / "eval" / "correlation_corpus.json").read_text(encoding="utf-8"))["cases"]}


def _fails(case_id: str) -> list[str]:
    return [d for ok, d in run_eval.run_case(CASES[case_id]) if not ok]


def _mutation(name: str, case_id: str, apply_, undo_) -> str | None:
    """Apply a mutation, run the guarding case, restore. Returns an error string if it stayed green."""
    apply_()
    try:
        bad = _fails(case_id)
    finally:
        undo_()
    if not bad:
        return f"{name}: case {case_id} still passes — it does not actually guard this knob"
    return None


def run() -> int:
    problems: list[str] = []

    # 1. Beaconing threshold wide open: the deliberately jittery host must now be reported.
    _beacon = recipes.beaconing
    problems.append(_mutation(
        "beaconing max_jitter 0.25 -> 5.0", "beaconing-regular-vs-jittery",
        lambda: setattr(recipes, "beaconing", lambda con, **kw: _beacon(con, max_jitter=5.0)),
        lambda: setattr(recipes, "beaconing", _beacon)))

    # 2. Confidence weights inverted: a shared hash stops outranking a shared IP.
    _weights = dict(correlate._KIND_WEIGHT)
    problems.append(_mutation(
        # Below `ip`'s own band (0.10), or the two merely tie and the tie-break — which is the
        # kind weight itself — keeps the hash on top for the wrong reason.
        "_KIND_WEIGHT file_hash 0.85 -> 0.05", "hash-outranks-shared-ip",
        lambda: correlate._KIND_WEIGHT.update({"file_hash": 0.05}),
        lambda: (correlate._KIND_WEIGHT.clear(), correlate._KIND_WEIGHT.update(_weights))))

    # 3. Ubiquitous-account exclusion disabled: SYSTEM and machine accounts become "bridges".
    _generic = normalize.is_generic_user
    problems.append(_mutation(
        "is_generic_user disabled", "ubiquitous-entities-excluded",
        lambda: setattr(normalize, "is_generic_user", lambda v: False),
        lambda: setattr(normalize, "is_generic_user", _generic)))

    # 4. Realm conflict ignored: two different people named alice merge silently.
    _realms = normalize.realms_conflict
    problems.append(_mutation(
        "realms_conflict always False", "identity-realm-conflict",
        lambda: setattr(normalize, "realms_conflict", lambda d: False),
        lambda: setattr(normalize, "realms_conflict", _realms)))

    # 5. No high-signal actions: log clearing drops out of the timeline.
    _actions_sql, _why = correlate._NOTABLE_ACTIONS_SQL, correlate._TIMELINE_WHY
    problems.append(_mutation(
        "_NOTABLE_ACTIONS emptied", "log-clearing-without-detection",
        lambda: setattr(correlate, "_TIMELINE_WHY", _why.replace(_actions_sql, "['__none__']")),
        lambda: setattr(correlate, "_TIMELINE_WHY", _why)))

    # 6. Entity normalization off: three spellings of one account stop bridging.
    _canon = normalize.canon_user
    problems.append(_mutation(
        "canon_user without normalization", "identity-spelling-normalized",
        lambda: setattr(normalize, "canon_user",
                        lambda v: None if v is None else (str(v).strip() or None)),
        lambda: setattr(normalize, "canon_user", _canon)))

    # 7. Session-gap far too wide: unrelated activity merges into one episode. This one is a
    # parameter rather than a symbol, so it is exercised through run_case instead of a patch.
    if not [d for ok, d in run_eval.run_case(CASES["episode-unrelated-eight-minutes"],
                                             gap_seconds=3600) if not ok]:
        problems.append("session-gap 3600s: episode-unrelated-eight-minutes still passes — the "
                        "upper bound on the gap is not actually guarded")

    # 8. Family collapsed back onto the qualified source label: two captures from one sensor count
    #    as two corroborating tools again, and the IP bridge inflates past its true reach.
    _family = normalize.source_family
    problems.append(_mutation(
        "source_family returns the qualified label", "two-files-one-tool-is-one-corroboration",
        lambda: setattr(normalize, "source_family",
                        lambda v: None if not str(v or "").strip() else str(v).strip().lower()),
        lambda: setattr(normalize, "source_family", _family)))

    # 9. The file.hash.sha256 spelling stops being read: CrowdStrike and osquery hashes vanish from
    #    the store, and the strongest bridge in the case disappears with them.
    _cell = store._cell
    problems.append(_mutation(
        "file.hash.sha256 fallback removed", "sha256-under-either-spelling",
        lambda: setattr(store, "_cell", lambda rec, dotted, *a, **kw: (
            None if dotted == "file.hash" and rec.get("file.hash") is None
            else _cell(rec, dotted, *a, **kw))),
        lambda: setattr(store, "_cell", _cell)))

    # 10. canon_file stops falling back to file.path: a tool that reports only a full path (YARA,
    #     osquery file events) contributes no artifact at all and cannot bridge.
    problems.append(_mutation(
        "canon_file blind to file.path", "artifact-known-only-by-its-path",
        lambda: setattr(store, "_cell", lambda rec, dotted, *a, **kw: (
            _cell({**rec, "file.path": None}, dotted, *a, **kw)
            if dotted in ("__canon_file__", "__file_generic__") else _cell(rec, dotted, *a, **kw))),
        lambda: setattr(store, "_cell", _cell)))

    # 11. The source port stops reaching the store: every packet reads as its own connection again,
    #     so a single bulk transfer with evenly spaced segments is reported as command-and-control.
    problems.append(_mutation(
        "source.port dropped from the store", "beacon-is-a-connection-not-a-packet",
        lambda: setattr(store, "_cell", lambda rec, dotted, *a, **kw: (
            None if dotted == "source.port" else _cell(rec, dotted, *a, **kw))),
        lambda: setattr(store, "_cell", _cell)))

    # 12. The old confidence scale, restored exactly: kind weights topping out at 1.0, a
    #     corroboration bonus of up to 0.3, and a clamp at 1.0. Both bridges saturate, the tie falls
    #     through to the family count, and the account seen by five tools outranks the hash seen by
    #     two — which is what the case exists to forbid.
    _confidence = correlate._confidence

    def _saturating(row: dict):
        legacy = {"file_hash": 1.0, "user": 0.85, "domain": 0.7, "host": 0.65, "file": 0.5, "ip": 0.4}
        base = legacy.get(row.get("kind"), 0.5)
        boost = min((int(row.get("families", 2)) - 2) * 0.1, 0.3)
        mt = row.get("match_type")
        penalty = 0.35 if mt == "ambiguous" else (0.1 if mt == "normalized" else 0.0)
        if row.get("infrastructure"):
            penalty += 0.3
        return round(max(0.0, min(1.0, base + boost - penalty)), 2), "legacy"

    problems.append(_mutation(
        "confidence back to the saturating scale", "corroboration-cannot-outrank-the-stronger-kind",
        lambda: setattr(correlate, "_confidence", _saturating),
        lambda: setattr(correlate, "_confidence", _confidence)))

    problems = [p for p in problems if p]
    if problems:
        for p in problems:
            print("FAIL  " + p)
        return 1

    # The corpus must also be green as it stands: a mutation test over a broken baseline proves
    # nothing about the mutations.
    baseline = [cid for cid in CASES if _fails(cid)]
    if baseline:
        print(f"FAIL  corpus not green at baseline: {baseline}")
        return 1

    print(f"PASS  corpus discriminates: 12 mutations caught, {len(CASES)} cases green at baseline")
    return 0


def test_corpus_discriminates():
    assert run() == 0


if __name__ == "__main__":
    raise SystemExit(run())
