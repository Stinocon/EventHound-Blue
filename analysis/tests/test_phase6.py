"""Phase 6 test: baseline/diffing + case (offline) and YARA (skip if yara-python absent).

Usage: uv run python tests/test_phase6.py
"""
from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ANALISI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALISI))

from analytics import baseline, case, store  # noqa: E402
from tests._helpers import skip_test  # noqa: E402


def _test_baseline():
    baseline_recs = [
        {"@timestamp": "2024-01-01T00:00:00Z", "event.source": "evtx", "host.name": "H1",
         "process.name": "svchost.exe", "process.parent.name": "services.exe"},
    ]
    current = baseline_recs + [
        {"@timestamp": "2024-01-02T00:00:00Z", "event.source": "evtx", "host.name": "H1",
         "process.name": "evil.exe", "process.parent.name": "winword.exe",
         "attack.techniques": ["T1059.001"]},
        {"@timestamp": "2024-01-02T00:01:00Z", "event.source": "pcap",
         "destination.ip": "203.0.113.50", "dns.question.name": "c2.example.org"},
    ]
    d = baseline.diff(current, baseline_recs)
    assert "evil.exe" in d["new_processes"] and "svchost.exe" not in d["new_processes"], d["new_processes"]
    assert "203.0.113.50" in d["new_dst_ips"], d["new_dst_ips"]
    assert "c2.example.org" in d["new_dns"], d["new_dns"]
    assert "T1059.001" in d["new_techniques"], d["new_techniques"]
    assert ("winword.exe", "evil.exe") in d["new_parent_child"], d["new_parent_child"]
    print("PASS  baseline: new processes/ip/dns/techniques/parent-child isolated")


def _test_case():
    analysis = {
        "summary": {"events": 10, "distinct_hosts": 2, "distinct_users": 1},
        "technique_frequency": [{"technique": "T1003.001", "hits": 2}],
        "beaconing": [{"src_ip": "10.0.0.5", "dst_ip": "203.0.113.10", "dst_port": 4444,
                       "mean_interval_s": 60.0, "jitter": 0.02}],
        "rare_processes": [{"process_name": "mimikatz.exe", "occurrences": 1}],
        "shared_indicators": [{"indicator": "203.0.113.10", "kind": "ip", "source_list": "evtx, pcap"}],
        "_meta": {"evtx": 1, "pcap": 1, "records": 10},
    }
    md = case.render(analysis, {"title": "Test", "analyst": "A", "date": "2026-06-21", "scope": "HOST-01"})
    for marker in ("# Case — Test", "## Summary", "T1003.001", "Beaconing", "203.0.113.10"):
        assert marker in md, f"missing section in case: {marker}"
    print("PASS  case: case render with expected sections and evidence")


def _test_yara():
    from adapters import yara_scan
    tmp = Path(tempfile.mkdtemp())
    try:
        target = tmp / "sample.txt"
        target.write_text("prefix YARA_TEST_MATCH_MARKER suffix", encoding="utf-8")
        try:
            recs = yara_scan.load_records(target, ANALISI / "yara_rules")
        except RuntimeError as ex:
            return skip_test(f"yara: {ex}")
        assert any(r.get("rule.name") == "analisi_test_marker" for r in recs), recs
        assert any("T1059" in (r.get("attack.techniques") or []) for r in recs), recs

        # A match used to carry no timestamp at all, so it was invisible in the timeline, the
        # episodes and every temporal recipe. The anchor is the artifact's own mtime — checked
        # against the file rather than against a literal, so the assertion stays true tomorrow.
        hit = next(r for r in recs if r.get("rule.name") == "analisi_test_marker")
        # The scanned FILE is not a process: it used to be stamped `process.name`, which made the
        # store mint a process entity for a file and never for the rule that actually matched.
        assert "process.name" not in hit, hit
        want = datetime.fromtimestamp(target.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert hit.get("@timestamp") == want, hit
        # ...and it must reach the store as a real time, not as NULL.
        con = store.from_records([hit])
        try:
            ts_parsed, canon, rule_name = con.execute(
                "SELECT ts_parsed, file_canon, rule_name FROM events").fetchone()
        finally:
            con.close()
        assert ts_parsed is not None, "YARA match still lands in the store without a usable time"
        # The artifact join key: yara names the file only by path, and that must still bridge.
        assert canon == "sample.txt", canon
        # The matched rule's name must survive to the store (it had no column and was dropped).
        assert rule_name == "analisi_test_marker", rule_name
        print(f"PASS  yara: test rule match ({len(recs)} records, technique + mtime + join key)")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def run() -> int:
    _test_baseline()
    _test_case()
    _test_yara()
    return 0


def test_phase6():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
