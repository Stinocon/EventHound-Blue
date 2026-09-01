"""Test of the Okta System Log adapter (adapters/okta_systemlog) — offline, always run.

SYNTHETIC LogEvent fixtures (fake actors, documentation-range IPs 203.0.113.0/24) — no real data.
Verifies the JSON-array and NDJSON parsing, the schema mapping (published→@timestamp, eventType→
action/category, outcome.result→outcome, actor→user, client.ipAddress→source.ip) and cross-source
correlation by user/IP.
    uv run python tests/test_okta.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters import okta_systemlog  # noqa: E402
from analytics import runner  # noqa: E402

EVENTS = [
    {
        "uuid": "e1", "published": "2026-07-22T10:00:00.000Z",
        "eventType": "user.session.start", "severity": "INFO",
        "displayMessage": "User login to Okta",
        "actor": {"id": "00u1", "type": "User", "alternateId": "alice@corp.example", "displayName": "Alice"},
        "client": {"ipAddress": "203.0.113.5", "userAgent": {"rawUserAgent": "Mozilla/5.0"},
                   "geographicalContext": {"city": "Rome", "country": "Italy"}},
        "outcome": {"result": "SUCCESS", "reason": None},
        "securityContext": {"isProxy": False, "isp": "ExampleISP"},
    },
    {
        "uuid": "e2", "published": "2026-07-22T10:01:00.000Z",
        "eventType": "user.authentication.auth_via_mfa", "severity": "WARN",
        "displayMessage": "Authentication of user via MFA",
        "actor": {"id": "00u1", "type": "User", "alternateId": "alice@corp.example"},
        "client": {"ipAddress": "203.0.113.99"},
        "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
        "target": [{"type": "AppInstance", "alternateId": "Salesforce", "displayName": "Salesforce"}],
    },
]


def _write(text: str, suffix: str = ".json") -> Path:
    f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w", encoding="utf-8")
    f.write(text)
    f.close()
    return Path(f.name)


def test_json_array_and_mapping():
    p = _write(json.dumps(EVENTS))
    recs = okta_systemlog.load_records(p)
    p.unlink(missing_ok=True)
    assert len(recs) == 2
    r = recs[0]
    assert r["@timestamp"] == "2026-07-22T10:00:00.000Z"
    assert r["event.source"] == "okta" and r["event.action"] == "user.session.start"
    assert r["event.category"] == "authentication"
    assert r["event.outcome"] == "success"
    assert r["user.name"] == "alice@corp.example"
    assert r["source.ip"] == "203.0.113.5"
    assert r["okta.country"] == "Italy"


def test_outcome_and_target():
    p = _write(json.dumps(EVENTS))
    r = okta_systemlog.load_records(p)[1]
    p.unlink(missing_ok=True)
    assert r["event.outcome"] == "failure"
    assert r["okta.outcome_reason"] == "INVALID_CREDENTIALS"
    assert r["okta.target"] == "Salesforce"


def test_ndjson():
    p = _write("\n".join(json.dumps(e) for e in EVENTS), suffix=".ndjson")
    recs = okta_systemlog.load_records(p)
    p.unlink(missing_ok=True)
    assert len(recs) == 2 and recs[0]["event.source"] == "okta"


def test_cross_source_correlation_by_user_ip():
    p = _write(json.dumps(EVENTS))
    okta = okta_systemlog.load_records(p)
    p.unlink(missing_ok=True)
    # An EVTX record for the same user → user correlates across sources.
    fake_evtx = {"@timestamp": "2026-07-22T10:05:00Z", "event.source": "evtx",
                 "user.name": "alice@corp.example", "host.name": "DC1"}
    res = runner.analyze(okta + [fake_evtx])
    users = [i for i in res.get("shared_indicators", []) if i["kind"] == "user"]
    # user is normalized to the canonical account (alice@corp.example → alice) for cross-tool join
    assert any(i["indicator"] == "alice" and i["families"] >= 2 for i in users)


if __name__ == "__main__":
    test_json_array_and_mapping()
    test_outcome_and_target()
    test_ndjson()
    test_cross_source_correlation_by_user_ip()
    print("OK — okta: 4 tests passed")
