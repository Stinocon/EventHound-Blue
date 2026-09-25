"""Test of correlation confidence ranking + incident clusters (analytics/correlate) — offline.

SYNTHETIC records, doc-range IPs. Verifies (B) a shared hash outranks a shared IP by confidence,
and (C) transitive connected components link entities across tools into one incident cluster.
    uv run python tests/test_incident.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analytics import runner  # noqa: E402

H = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_confidence_hash_beats_ip():
    recs = [
        {"@timestamp": "2026-07-22T10:00:00Z", "event.source": "evtx", "file.hash": H, "source.ip": "203.0.113.5"},
        {"@timestamp": "2026-07-22T10:01:00Z", "event.source": "thor", "file.hash": H, "source.ip": "203.0.113.5"},
    ]
    inds = runner.analyze(recs)["shared_indicators"]
    hashrow = next(i for i in inds if i["kind"] == "file_hash")
    iprow = next(i for i in inds if i["kind"] == "ip")
    assert hashrow["confidence"] > iprow["confidence"], (hashrow, iprow)
    assert hashrow["confidence_label"] == "high" and iprow["confidence_label"] == "low"
    # sorted by confidence desc → the hash bridge is read before the noisy IP bridge
    assert inds.index(hashrow) < inds.index(iprow)


def test_incident_cluster_spans_three_tools():
    """EDR login (user) → EVTX (same user, host DC1) → THOR (host DC1, hash) = one cluster, 3 sources."""
    recs = [
        {"@timestamp": "2026-07-22T10:00:00Z", "event.source": "crowdstrike", "user.name": "alice@corp.example"},
        {"@timestamp": "2026-07-22T10:01:00Z", "event.source": "evtx", "user.name": "CORP\\alice", "host.name": "DC1"},
        {"@timestamp": "2026-07-22T10:02:00Z", "event.source": "thor", "host.name": "dc1.corp.example", "file.hash": H},
    ]
    clusters = runner.analyze(recs)["incident_clusters"]
    assert clusters, "expected at least one cross-tool incident cluster"
    c = clusters[0]
    assert c["sources"] == 3 and c["entities"] >= 3
    assert "alice" in c["users"] and "dc1" in c["hosts"] and c["hashes"] == 1
    assert set(c["source_list"].split(", ")) == {"crowdstrike", "evtx", "thor"}


def test_no_cluster_without_cross_source():
    """Entities all from a single source must NOT form a (cross-tool) cluster."""
    recs = [
        {"@timestamp": "2026-07-22T10:00:00Z", "event.source": "evtx", "user.name": "bob", "host.name": "H1"},
        {"@timestamp": "2026-07-22T10:01:00Z", "event.source": "evtx", "user.name": "bob", "host.name": "H2"},
    ]
    assert runner.analyze(recs)["incident_clusters"] == []


if __name__ == "__main__":
    test_confidence_hash_beats_ip()
    test_incident_cluster_spans_three_tools()
    test_no_cluster_without_cross_source()
    print("OK — incident: 3 tests passed")
