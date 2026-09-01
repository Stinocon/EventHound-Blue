"""Adapter: Okta System Log events -> common schema (ECS subset).

Okta's System Log (the `LogEvent` object, exported from the `/api/v1/logs` API, the Admin console,
or a SIEM feed) records authentication, session, MFA, app-assignment and admin events. They correlate
with the other sources by user, source IP and time (identity layer of an incident).

Input: a `.json` file that is EITHER a JSON array of LogEvent objects, a single object, or NDJSON
(one JSON object per line — the common SIEM export). All three are accepted.

Field mapping is grounded on the documented Okta System Log `LogEvent` schema (not guessed):
    published            -> @timestamp
    eventType            -> event.action        (e.g. user.session.start)  + event.category (derived)
    outcome.result       -> event.outcome       (SUCCESS->success, FAILURE/DENY->failure)
    actor.alternateId    -> user.name           (login/email; displayName fallback)
    client.ipAddress     -> source.ip
    displayMessage       -> message
Namespaced `okta.*` extras (severity, outcome reason, actor type, targets, geo, ISP/proxy) travel in
the record for detail. Anonymization (§9) is downstream: user.name / internal IPs are pseudonymized
after parsing; public/malicious IPs and technical indicators are not.

NOTE: grounded on the documented schema; validate against a real export when one is available.
"""
from __future__ import annotations

import json
from pathlib import Path

_SOURCE = "okta"

# eventType namespace -> ECS event.category (light, documented Okta prefixes).
_CATEGORY = {
    "user.session": "authentication",
    "user.authentication": "authentication",
    "user.mfa": "authentication",
    "user.account": "iam",
    "user.lifecycle": "iam",
    "group": "iam",
    "application": "iam",
    "policy": "configuration",
    "system": "configuration",
}
_OUTCOME = {"SUCCESS": "success", "ALLOW": "success",
            "FAILURE": "failure", "DENY": "failure", "CHALLENGE": "unknown", "SKIPPED": "unknown"}


def _clean(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if v not in (None, "", [], {})}


def _category(event_type: str | None) -> str | None:
    if not event_type:
        return None
    parts = event_type.split(".")
    for n in (2, 1):  # try 'user.session' then 'user'
        key = ".".join(parts[:n])
        if key in _CATEGORY:
            return _CATEGORY[key]
    return None


def _get(d: dict, *path):
    """Safe nested get: _get(ev, 'client', 'ipAddress')."""
    cur = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _targets(ev: dict) -> str | None:
    tgt = ev.get("target")
    if not isinstance(tgt, list):
        return None
    labels = [t.get("alternateId") or t.get("displayName") for t in tgt if isinstance(t, dict)]
    labels = [x for x in labels if x]
    return ", ".join(labels) or None


def _record(ev: dict) -> dict | None:
    if not isinstance(ev, dict):
        return None
    event_type = ev.get("eventType")
    result = (_get(ev, "outcome", "result") or "")
    return _clean({
        "@timestamp": ev.get("published"),
        "event.source": _SOURCE,
        "event.action": event_type,
        "event.category": _category(event_type),
        "event.outcome": _OUTCOME.get(result.upper(), "unknown") if result else None,
        "user.name": _get(ev, "actor", "alternateId") or _get(ev, "actor", "displayName"),
        "source.ip": _get(ev, "client", "ipAddress"),
        "message": ev.get("displayMessage"),
        # Namespaced Okta extras (detail; not DuckDB columns).
        "okta.event_type": event_type,
        "okta.severity": ev.get("severity"),
        "okta.outcome_reason": _get(ev, "outcome", "reason"),
        "okta.actor_type": _get(ev, "actor", "type"),
        "okta.target": _targets(ev),
        "okta.city": _get(ev, "client", "geographicalContext", "city"),
        "okta.country": _get(ev, "client", "geographicalContext", "country"),
        "okta.isp": _get(ev, "securityContext", "isp"),
        "okta.is_proxy": _get(ev, "securityContext", "isProxy"),
        "okta.user_agent": _get(ev, "client", "userAgent", "rawUserAgent"),
    })


def _parse(text: str) -> list[dict]:
    """Accepts a JSON array, a single JSON object, or NDJSON (one object per line)."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        events = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        # NDJSON fallback: one object per non-empty line.
        events = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    out = []
    for ev in events:
        rec = _record(ev)
        if rec and rec.get("@timestamp"):
            out.append(rec)
    return out


def load_records(path: str | Path) -> list[dict]:
    """Okta System Log events (JSON array / single object / NDJSON) as common-schema records."""
    return _parse(Path(path).read_text(encoding="utf-8", errors="replace"))
