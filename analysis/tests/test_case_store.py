"""Case persistence: a stored analysis must answer exactly what the in-memory one answers.

Offline and synthetic (no binaries, no network): documentation-range addresses and pseudonyms only
(§9). The central assertion is the equivalence — if analyzing a persisted case diverged from
analyzing the same records in memory, persistence would quietly become a second, weaker engine.

    uv run python tests/test_case_store.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analytics import case_store, runner, store  # noqa: E402

RECORDS_A = [
    {"@timestamp": "2026-07-16T06:28:59Z", "event.source": "log:sma_access.log",
     "event.category": "web", "event.action": "http-request", "source.ip": "203.0.113.5",
     "url.original": "/wsproxy"},
    {"@timestamp": "2026-07-16T06:29:10Z", "event.source": "evtx",
     "event.category": "authentication", "event.action": "logon", "event.code": 4624,
     "host.name": "DC-01", "user.name": "CORP\\svc_backup", "source.ip": "203.0.113.5",
     "attack.techniques": ["T1021.002"]},
]
RECORDS_B = [
    {"@timestamp": "2026-07-16T07:00:00Z", "event.source": "evtx_full",
     "event.category": "configuration", "event.action": "audit-log-cleared",
     "event.code": 1102, "host.name": "DC-01"},
]
# Distinct from A and B: used to prove the dedup check compares content, not "one append per
# case" — a genuinely different batch must append with no complaint.
RECORDS_C = [
    {"@timestamp": "2026-07-16T08:00:00Z", "event.source": "evtx",
     "event.category": "process", "event.action": "start", "event.code": 4688,
     "host.name": "WKS-07", "user.name": "CORP\\jdoe"},
]


def run() -> int:
    with tempfile.TemporaryDirectory(prefix="eh-cases-") as tmp:
        root = Path(tmp)

        # --- creation, id validation, incremental append -------------------------------------
        meta = case_store.create("case-01", title="Test case", root=root)
        assert meta["record_count"] == 0 and meta["notes"] == [], meta
        assert meta["schema_fingerprint"] == store.schema_fingerprint(), meta

        try:
            case_store.create("case-01", root=root)
            raise AssertionError("creating an existing case must fail")
        except case_store.CaseError:
            pass
        for bad in ("../escape", "/etc/passwd", "Case With Spaces", ""):
            try:
                case_store.case_dir(bad, root=root)
                raise AssertionError(f"case id {bad!r} should have been refused")
            except case_store.CaseError:
                pass

        case_store.append("case-01", RECORDS_A, label="web+evtx", root=root)
        # a source that parsed to nothing is not an error, and must not corrupt the numbering
        case_store.append("case-01", [], label="empty source", root=root)
        meta = case_store.append("case-01", RECORDS_B, label="evtx_full", root=root)
        assert meta["record_count"] == 3, meta
        assert [s["label"] for s in meta["sources"]] == \
            ["web+evtx", "empty source", "evtx_full"], meta["sources"]

        # ids must continue across appends, or the second source would overwrite the first
        con = case_store.connect("case-01", root=root)
        try:
            ids = [r[0] for r in con.execute("SELECT id FROM events ORDER BY id").fetchall()]
        finally:
            con.close()
        assert ids == [0, 1, 2], ids

        # --- the equivalence that justifies the whole module ---------------------------------
        stored = runner.analyze_case("case-01", root=root)
        memory = runner.analyze(RECORDS_A + RECORDS_B)
        for key in ("summary", "shared_indicators", "episodes", "incident_clusters",
                    "timeline", "technique_catalog", "killchain"):
            assert stored[key] == memory[key], f"{key} differs between stored and in-memory analysis"

        # --- raw records survive, and drive what SQL cannot ----------------------------------
        recs = case_store.records_of("case-01", root=root)
        assert len(recs) == 3 and recs[0]["url.original"] == "/wsproxy", recs[0]
        assert recs[1]["attack.techniques"] == ["T1021.002"], recs[1]

        # --- a schema change rebuilds instead of answering with stale columns -----------------
        m = case_store.load_meta("case-01", root=root)
        m["schema_fingerprint"] = "0000stale000"
        case_store.save_meta("case-01", m, root=root)
        con = case_store.connect("case-01", root=root)
        try:
            assert con.execute("SELECT count(*) FROM events").fetchone()[0] == 3
        finally:
            con.close()
        assert case_store.load_meta("case-01", root=root)["schema_fingerprint"] \
            == store.schema_fingerprint(), "fingerprint not updated after rebuild"

        # --- dedup: a repeated append is a refusal, not a silent double-count -----------------
        before = case_store.load_meta("case-01", root=root)["record_count"]
        try:
            case_store.append("case-01", RECORDS_B, label="evtx_full again", root=root)
            raise AssertionError("appending the same records twice must be refused")
        except case_store.CaseError as exc:
            assert "evtx_full" in str(exc), str(exc)  # names the original label
        after = case_store.load_meta("case-01", root=root)["record_count"]
        assert after == before, "a refused append must not touch the record count"

        # force=True is the deliberate override, and it really does double the count
        meta = case_store.append("case-01", RECORDS_B, label="evtx_full forced",
                                  root=root, force=True)
        assert meta["record_count"] == before + len(RECORDS_B), meta

        # a different batch is unaffected by the check on an unrelated batch's signature — the
        # dedup check compares content, it is not a blanket "one append per case"
        meta = case_store.append("case-01", RECORDS_C, label="wks-07 process", root=root)
        assert meta["record_count"] == before + len(RECORDS_B) + len(RECORDS_C), meta

        # a case whose sources predate this change (no "signature" key) still appends cleanly,
        # without needing force=True: an absent signature must never crash and must never match
        m = case_store.load_meta("case-01", root=root)
        for src in m["sources"]:
            src.pop("signature", None)
        case_store.save_meta("case-01", m, root=root)
        meta = case_store.append("case-01", RECORDS_B, label="evtx_full old-meta", root=root)
        assert meta["record_count"] == before + 2 * len(RECORDS_B) + len(RECORDS_C), meta

        # --- notes and listing ---------------------------------------------------------------
        case_store.note("case-01", "the 4624 comes from the same IP as the web request", root=root)
        assert len(case_store.load_meta("case-01", root=root)["notes"]) == 1
        try:
            case_store.note("case-01", "   ", root=root)
            raise AssertionError("empty note must be refused")
        except case_store.CaseError:
            pass

        case_store.create("case-02", root=root)
        assert {c["id"] for c in case_store.list_cases(root)} == {"case-01", "case-02"}

        # --- deletion is bounded to the case root --------------------------------------------
        case_store.delete("case-02", root=root)
        assert not case_store.exists("case-02", root=root)
        try:
            case_store.delete("case-02", root=root)
            raise AssertionError("deleting a missing case must fail")
        except case_store.CaseError:
            pass
        assert case_store.exists("case-01", root=root), "unrelated case was touched"

    print("PASS  case store: persist, append, reopen, rebuild on schema change, notes, delete")
    return 0


def test_case_store():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
