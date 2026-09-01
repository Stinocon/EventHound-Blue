"""Adapter: osquery result log -> common schema (ECS subset).

osquery's result log (NDJSON, one JSON object per line) records endpoint state: processes,
sockets, autoruns, users, file hashes. It fills the macOS/Linux endpoint gap (Windows-only
today via EVTX). Each line has top-level `name`, `hostIdentifier`, `unixTime`, `action`,
`columns{}` and optional `decorations{}`.

Input: a `.json` or `.jsonl` or `.log` file containing NDJSON (one JSON object per line).
The format is osquery's default result log output.

Field mapping:
    unixTime (epoch int)       -> @timestamp (ISO-8601 UTC)
    hostIdentifier             -> host.name
    name                       -> osquery.query (the table name, e.g. "processes")
    action                     -> event.action (added/removed/modified)
    columns.name               -> process.name (for process tables)
    columns.pid                -> process.pid
    columns.cmdline            -> process.command_line
    columns.path               -> process.path
    columns.uid                -> user.id
    columns.username           -> user.name
    columns.port               -> destination.port
    columns.address            -> source.ip (listening_ports: the local bind address)
    columns.remote_address     -> destination.ip (logged_in_users: the remote end)
    columns.md5                -> file.hash.md5
    columns.sha256             -> file.hash.sha256
    columns.target_path        -> file.path (for file_events)

Namespaced osquery.* extras carry the raw columns dict and decorations.

NOTE: based on the documented osquery result log format, not a real sample.
"""
from __future__ import annotations

import json
from pathlib import Path

_SOURCE = "osquery"

# osquery column name -> common schema field (dot-path).
_COLUMN_MAP = {
    "pid": "process.pid",
    "cmdline": "process.command_line",
    "path": "process.path",
    "parent": "process.parent.pid",
    "parent_path": "process.parent.name",
    "uid": "user.id",
    "username": "user.name",
    "port": "destination.port",
    "address": "source.ip",
    # `address` is the LOCAL bind address (listening_ports): source.ip. `remote_address` is the
    # OTHER end of a connection (logged_in_users: where the session came from), so it is
    # destination.ip — writing it to source.ip put a remote host's address in the field the store
    # reads as "this record is ABOUT this host", and bridged every logged_in_user to every other.
    "remote_address": "destination.ip",
    "md5": "file.hash.md5",
    "sha1": "file.hash.sha1",
    "sha256": "file.hash.sha256",
    "target_path": "file.path",
}
# Deliberately NOT mapped, though they look inviting:
#   `columns.name`     — table-dependent (a process in `processes`, a kext in `kernel_extensions`,
#                        a job in `launch_daemons`). Mapped to process.name only where the table is
#                        a process table, below.
#   `columns.category` — in `file_events` this is the FIM group the path belongs to ("homes"), not
#                        an ECS category; mapping it overwrote the correct table-derived value.
#   `columns.tty`      — "pts/0" or "console", not a port number.
# All three stay readable in the raw `osquery.columns` payload.

# osquery table name (query) -> ECS event.category.
_CATEGORY_MAP = {
    "processes": "process",
    "listening_ports": "network",
    "arp_cache": "network",
    "users": "iam",
    "logged_in_users": "authentication",
    "file_events": "file",
    "hash": "file",
    "crashes": "process",
    "launch_daemons": "configuration",
    "kernel_extensions": "driver",
    "authorized_keys": "iam",
    "shadow_hash": "iam",
}


def _clean(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if v not in (None, "", [], {})}


def _record(ev: dict) -> dict | None:
    if not isinstance(ev, dict):
        return None
    unix_time = ev.get("unixTime")
    if not unix_time:
        return None

    # Convert epoch to ISO-8601 UTC (lazy import, okta_systemlog pattern).
    from datetime import datetime, timezone
    try:
        ts = datetime.fromtimestamp(int(unix_time), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (ValueError, OSError, OverflowError):
        ts = None

    query_name = ev.get("name")
    action = ev.get("action")
    columns = ev.get("columns") or {}
    decorations = ev.get("decorations") or {}

    rec = {
        "@timestamp": ts,
        "event.source": _SOURCE,
        "event.action": action,
        "event.category": _CATEGORY_MAP.get(query_name),
        "host.name": ev.get("hostIdentifier"),
        "osquery.query": query_name,
    }

    # Map known columns to common schema.
    for col_name, schema_field in _COLUMN_MAP.items():
        val = columns.get(col_name)
        if val is not None and val != "":
            rec[schema_field] = val

    # `name` only where it really is a process name (see the note on _COLUMN_MAP).
    if columns.get("name") and (rec.get("event.category") == "process"
                                or "cmdline" in columns or "pid" in columns):
        rec["process.name"] = columns["name"]

    # Decorations: host enrichment.
    if decorations.get("username") and "user.name" not in rec:
        rec["user.name"] = decorations["username"]
    if decorations.get("host_uuid"):
        rec["osquery.host_uuid"] = decorations["host_uuid"]

    # Namespaced extras: raw columns + decorations.
    rec["osquery.columns"] = columns
    if decorations:
        rec["osquery.decorations"] = decorations

    # Derive event.category from columns if not in _CATEGORY_MAP.
    if not rec.get("event.category"):
        if "cmdline" in columns or "pid" in columns:
            rec["event.category"] = "process"
        elif "port" in columns or "address" in columns:
            rec["event.category"] = "network"
        elif "md5" in columns or "sha256" in columns:
            rec["event.category"] = "file"

    return _clean(rec)


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
    """osquery result log events (NDJSON) as common-schema records."""
    return _parse(Path(path).read_text(encoding="utf-8", errors="replace"))
