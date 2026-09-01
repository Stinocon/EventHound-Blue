"""Test Phase 2: long-tail recipes + correlation on synthetic records (no Hayabusa/tshark).

Targets signals, like golden_queries for the RAG: a carefully constructed dataset must surface
process stacking, rare parent-child pair, rare DNS, non-standard port, regular beaconing and
cross-source indicator. Execution: uv run python tests/test_analytics.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import correlate, recipes, store  # noqa: E402


def _records() -> list[dict]:
    recs: list[dict] = []
    # Noise: a common process repeated on multiple hosts (must NOT end up in rare queue).
    for h in range(5):
        recs.append({"@timestamp": f"2024-01-01T00:0{h}:00.000000Z", "event.source": "evtx",
                     "event.category": "process", "event.action": "process-create",
                     "host.name": f"HOST-0{h}", "user.name": "USER-01",
                     "process.name": "svchost.exe", "process.parent.name": "services.exe"})
    # Signal: rare process + anomalous parent-child pair + ATT&CK technique.
    recs.append({"@timestamp": "2024-01-01T01:00:00.000000Z", "event.source": "evtx",
                 "event.category": "process", "event.action": "process-create",
                 "host.name": "HOST-01", "user.name": "USER-09", "process.name": "mimikatz.exe",
                 "process.parent.name": "winword.exe", "attack.techniques": ["T1003.001"]})
    # Signal PCAP: regular beaconing to a C2 (~60s intervals, ~0 jitter) on non-standard port.
    for m in range(6):
        recs.append({"@timestamp": f"2024-01-01T02:0{m}:00.000000Z", "event.source": "pcap",
                     "event.category": "network", "network.transport": "tcp",
                     "source.ip": "10.0.0.5", "destination.ip": "203.0.113.10",
                     "destination.port": 4444, "network.bytes": 120})
    # Signal: rare/long DNS (possible tunneling).
    recs.append({"@timestamp": "2024-01-01T03:00:00.000000Z", "event.source": "pcap",
                 "event.category": "network", "source.ip": "10.0.0.5",
                 "destination.ip": "203.0.113.10",
                 "dns.question.name": "x" * 60 + ".exfil.example"})
    # Cross-source: same IP 203.0.113.10 appears in pcap AND in evtx event (Sysmon netconn).
    recs.append({"@timestamp": "2024-01-01T02:30:00.000000Z", "event.source": "evtx",
                 "event.category": "network", "event.action": "network-connect",
                 "host.name": "HOST-01", "destination.ip": "203.0.113.10", "destination.port": 4444})
    return recs


def run() -> int:
    con = store.from_records(_records())

    techs = {r["technique"] for r in recipes.technique_frequency(con)}
    assert "T1003.001" in techs, f"expected technique missing: {techs}"

    rare = {r["process_name"] for r in recipes.rare_processes(con, max_count=2)}
    assert "mimikatz.exe" in rare and "svchost.exe" not in rare, f"process stacking incorrect: {rare}"

    pc = {(r["parent_name"], r["process_name"]) for r in recipes.anomalous_parent_child(con)}
    assert ("winword.exe", "mimikatz.exe") in pc, f"parent-child pair missing: {pc}"

    dns = {r["dns_query"] for r in recipes.rare_dns(con)}
    assert any("exfil.example" in d for d in dns), f"rare/long DNS missing: {dns}"

    ports = {(r["dst_ip"], r["dst_port"]) for r in recipes.nonstandard_ports(con)}
    assert ("203.0.113.10", 4444) in ports, f"non-standard port missing: {ports}"

    beacons = recipes.beaconing(con, min_events=4)
    beacon = next((b for b in beacons if b["dst_ip"] == "203.0.113.10" and b["dst_port"] == 4444), None)
    assert beacon is not None, f"beaconing not detected: {beacons}"
    # Validates math, not the recipe filter (jitter <= 0.25 is the HAVING of the recipe:
    # re-asserting it is always true). 6 connections at ~60s, jitter ~0.
    assert beacon["connections"] == 6, f"connection count incorrect: {beacon}"
    assert abs(beacon["mean_interval_s"] - 60.0) < 1.0, f"mean interval incorrect: {beacon}"
    assert beacon["jitter"] < 0.05, f"jitter incorrect: {beacon}"

    shared = {r["indicator"] for r in correlate.shared_indicators(con)}
    assert "203.0.113.10" in shared, f"cross-source indicator missing: {shared}"

    tl = correlate.timeline(con, host="HOST-01")
    assert tl and all(r["host"] == "HOST-01" for r in tl), "host-filtered timeline incorrect"

    con.close()
    print("PASS  analytics: technique, process-stacking, parent-child, rare DNS, non-std port, "
          "beaconing, cross-source indicator, timeline")
    return 0


def test_store_load_leaves_sys_modules_intact() -> int:
    """The store's bulk insert negative-caches `pandas` to stop DuckDB probing for it once per bound
    value (store._without_probing_for_pandas, a 3.8x on the dominant stage). It is a deliberate poke
    at global state, so what must be pinned is that it does not outlive the insert — otherwise a
    later `import pandas` anywhere in the process would fail for a reason nobody could trace."""
    import sys as _sys

    from analytics import store as _store

    before = "pandas" in _sys.modules
    con = _store.from_records([{"@timestamp": "2026-01-01T00:00:00Z", "event.source": "evtx",
                                "host.name": "HOST-01"}])
    try:
        assert con.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    finally:
        con.close()
    assert ("pandas" in _sys.modules) == before, "the pandas negative-cache leaked out of the insert"
    # And the guard itself: entering it with pandas already present must change nothing.
    _sys.modules["pandas"] = object()
    try:
        with _store._without_probing_for_pandas():
            pass
        assert _sys.modules["pandas"] is not None, "an installed pandas must not be shadowed"
    finally:
        del _sys.modules["pandas"]
    print("PASS  store: the pandas negative-cache is scoped to the insert and never shadows a real one")
    return 0


def test_ts_parsed_honours_the_offset() -> int:
    """A timestamp that carries a UTC offset must be stored as the instant it names.

    `ts_parsed` is what every temporal view reads: episodes, the timeline, the kill-chain window.
    It used to be `TRY_CAST(replace(ts,'Z',''))`, which silently DROPPED an offset — a source
    two hours ahead landed two hours late, which moves it into or out of an episode and reorders
    the timeline — and turned epoch seconds into NULL, which removes the record from every
    temporal view without saying so. Both spellings reach the store today: the Okta adapter and
    the generic JSONL log adapter pass the source's own value straight through.
    """
    from datetime import datetime
    recs = [{"@timestamp": t, "event.source": "log:x", "event.action": "a"} for t in (
        "2026-03-12T10:30:00+02:00", "2026-03-12T09:00:00Z", "1773216000", "not-a-time")]
    con = store.from_records(recs)
    got = [r[0] for r in con.execute("SELECT ts_parsed FROM events ORDER BY id").fetchall()]
    con.close()
    assert got[0] == datetime(2026, 3, 12, 8, 30), f"offset dropped: {got[0]}"
    assert got[1] == datetime(2026, 3, 12, 9, 0), got[1]
    # The offset-bearing record is the EARLIER of the two: that ordering is the whole point.
    assert got[0] < got[1], "a +02:00 timestamp must sort before the same wall clock in UTC"
    assert got[2] is not None, "epoch seconds must not vanish from the temporal views"
    assert got[3] is None, "an unparseable timestamp stays NULL rather than failing the load"
    print("PASS  store: ts_parsed honours the UTC offset and reads epoch seconds")
    return 0


def test_analytics():
    run()


def test_ts_parsed_offset():
    test_ts_parsed_honours_the_offset()


def test_store_pandas_cache():
    test_store_load_leaves_sys_modules_intact()


if __name__ == "__main__":
    rc = run()
    raise SystemExit(rc or test_store_load_leaves_sys_modules_intact()
                     or test_ts_parsed_honours_the_offset())
