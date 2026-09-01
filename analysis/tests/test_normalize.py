"""Test of entity normalization (analytics/normalize) and its effect on correlation — offline.

SYNTHETIC records only. Verifies canon_user/canon_host (UPN/NetBIOS strip, IP-safe host, generic
accounts) and that cross-tool records with DIFFERENT spellings of the same user/host now correlate,
while ubiquitous machine accounts (SYSTEM) do NOT become a false bridge.
    uv run python tests/test_normalize.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analytics import normalize, runner  # noqa: E402


def test_canon_user():
    assert normalize.canon_user("CORP\\Alice") == "alice"
    assert normalize.canon_user("alice@corp.example") == "alice"
    assert normalize.canon_user("Alice") == "alice"
    assert normalize.canon_user("HOST\\admin") == "admin"
    assert normalize.canon_user(None) is None
    assert normalize.canon_user("   ") is None


def test_generic_user():
    assert normalize.is_generic_user(normalize.canon_user("NT AUTHORITY\\SYSTEM"))
    assert normalize.is_generic_user("local service")
    assert not normalize.is_generic_user("alice")


def test_canon_host():
    assert normalize.canon_host("DC1") == "dc1"
    assert normalize.canon_host("dc1.corp.example") == "dc1"
    assert normalize.canon_host("10.1.1.220") == "10.1.1.220"   # IPv4 must NOT be split on dots
    assert normalize.canon_host("FE80::1") == "fe80::1"          # IPv6 untouched
    assert normalize.canon_host(None) is None


def test_user_correlates_across_spellings():
    """Okta 'alice@corp.example' and EVTX 'CORP\\alice' → same actor, correlated."""
    recs = [
        {"@timestamp": "2026-07-22T10:00:00Z", "event.source": "okta",
         "user.name": "alice@corp.example", "source.ip": "203.0.113.5"},
        {"@timestamp": "2026-07-22T10:01:00Z", "event.source": "evtx",
         "user.name": "CORP\\alice", "host.name": "DC1"},
    ]
    res = runner.analyze(recs)
    users = [i for i in res["shared_indicators"] if i["kind"] == "user"]
    alice = next((i for i in users if i["indicator"] == "alice"), None)
    assert alice is not None, "normalized user 'alice' must bridge okta+evtx"
    assert alice["families"] == 2 and alice["match_type"] == "normalized"
    assert "alice@corp.example" in alice["variants"] and "CORP\\alice" in alice["variants"]


def test_host_correlates_fqdn_vs_short():
    recs = [
        {"@timestamp": "2026-07-22T10:00:00Z", "event.source": "evtx", "host.name": "DC1"},
        {"@timestamp": "2026-07-22T10:01:00Z", "event.source": "logs", "host.name": "dc1.corp.example"},
    ]
    res = runner.analyze(recs)
    hosts = [i for i in res["shared_indicators"] if i["kind"] == "host" and i["indicator"] == "dc1"]
    assert hosts and hosts[0]["families"] == 2 and hosts[0]["match_type"] == "normalized"


def test_generic_account_is_not_a_bridge():
    """SYSTEM on two sources must NOT show up as a correlation bridge (noise, not identity)."""
    recs = [
        {"@timestamp": "2026-07-22T10:00:00Z", "event.source": "evtx",
         "user.name": "NT AUTHORITY\\SYSTEM", "host.name": "H1"},
        {"@timestamp": "2026-07-22T10:01:00Z", "event.source": "logs",
         "user.name": "SYSTEM", "host.name": "H2"},
    ]
    res = runner.analyze(recs)
    sys_bridges = [i for i in res["shared_indicators"] if i["kind"] == "user" and i["indicator"] == "system"]
    assert not sys_bridges, "SYSTEM must be excluded from user correlation"


if __name__ == "__main__":
    test_canon_user()
    test_generic_user()
    test_canon_host()
    test_user_correlates_across_spellings()
    test_host_correlates_fqdn_vs_short()
    test_generic_account_is_not_a_bridge()
    print("OK — normalize: 6 tests passed")
