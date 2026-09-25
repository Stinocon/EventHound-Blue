"""Adapter: osquery result log -> common schema (ECS subset).

osquery's result log (NDJSON, one JSON object per line) records endpoint state: processes,
sockets, autoruns, users, file hashes. It fills the macOS/Linux endpoint gap (Windows-only
today via EVTX). Each line has top-level `name`, `hostIdentifier`, `unixTime`, `action`,
`columns{}` and optional `decorations{}`.

Input: a `.json` or `.jsonl` or `.log` file containing NDJSON (one JSON object per line).
The format is osquery's default result log output.

Field mapping (VERIFIED against a real 5.23.1 result log, not read off the documentation):
    unixTime (epoch int)       -> @timestamp (ISO-8601 UTC)
    hostIdentifier             -> host.name
    name                       -> osquery.query (the table name, e.g. "processes")
    action                     -> event.action (added/removed, or "snapshot")
    columns.name               -> process.name (process tables only)
    columns.path               -> process.path (process tables only)
    columns.pid                -> process.pid
    columns.cmdline            -> process.command_line
    columns.uid                -> user.id
    columns.username           -> user.name (`users`)
    columns.user               -> user.name (`logged_in_users`)
    columns.port               -> destination.port
    columns.address            -> source.ip (listening_ports: the local bind address)
    columns.remote_address     -> destination.ip (process_open_sockets: the other end)
    columns.remote_port        -> destination.port
    columns.local_address      -> source.ip
    columns.local_port         -> source.port
    columns.md5                -> file.hash.md5
    columns.sha1               -> file.hash.sha1
    columns.sha256             -> file.hash.sha256
    columns.target_path        -> file.path (for file_events)

Namespaced osquery.* extras carry the raw columns dict and decorations.

The capture this map was checked against is `tests/fixtures/osquery_result_5.23.1.jsonl`, a real
result log taken on macOS and pseudonymized (§9). It named four defects the documentation did not:
`logged_in_users` spells the account `user`, not `username`, so every recorded session lost its
user; `process_open_sockets` gives the other end as `remote_address`/`remote_port` and the near end
as `local_address`/`local_port`, none of which had a mapping, so a live connection contributed only
half an address; a socket with no port says `"0"`, which `recipes.nonstandard_ports` then reported
as traffic to a non-standard port; and `path` in the two socket tables is the path of a Unix-domain
socket, which was being written into `process.path`.
"""
from __future__ import annotations

import json
from pathlib import Path

_SOURCE = "osquery"

# osquery column name -> common schema field (dot-path).
#
# Column names VERIFIED against a real osquery 5.23.1 result log captured on macOS
# (tests/fixtures/osquery_result_5.23.1.jsonl, pseudonymized §9), not read off the documentation.
# What that capture showed is why this map is not what the documentation implies.
_COLUMN_MAP = {
    "pid": "process.pid",
    "cmdline": "process.command_line",
    "parent": "process.parent.pid",
    "parent_path": "process.parent.name",
    "uid": "user.id",
    "username": "user.name",      # `users` calls it `username`
    "user": "user.name",          # `logged_in_users` calls it `user` — and this was MISSING, so
                                   # every interactive session the capture recorded lost its user
                                   # entirely (5 of 5 rows on the real log).
    "port": "destination.port",
    "address": "source.ip",       # `listening_ports`: the LOCAL bind address
    "remote_address": "destination.ip",   # `process_open_sockets`: the OTHER end of a connection
    "remote_port": "destination.port",
    "local_port": "source.port",
    "local_address": "source.ip",
    "md5": "file.hash.md5",
    "sha1": "file.hash.sha1",
    "sha256": "file.hash.sha256",
    "target_path": "file.path",    # `file_events`
}
# Deliberately NOT mapped, though they look inviting:
#   `columns.name`     — table-dependent (a process in `processes`, a kext in `kernel_extensions`,
#                        a job in `launch_daemons`). Mapped to process.name only where the table is
#                        a process table, below.
#   `columns.path`     — same reason, and the real log proved the cost: in `listening_ports` and
#                        `process_open_sockets` this is the path of a Unix-domain SOCKET
#                        (`/var/folders/…/SingletonSocket`), and mapping it wrote that into
#                        `process.path` for 86 rows of the capture — a socket file reported as the
#                        binary a process is running.
#   `columns.category` — in `file_events` this is the FIM group the path belongs to ("homes"), not
#                        an ECS category; mapping it overwrote the correct table-derived value.
#   `columns.tty`      — "pts/0" or "console", not a port number.
#   `columns.host`     — `logged_in_users` carries the session's ORIGIN here. It is a hostname, not
#                        an IP, so it does not belong in `source.ip`; it stays readable in
#                        `osquery.columns`.
#   `columns.state`    — `process_open_sockets` says LISTEN/ESTABLISHED here. Useful, and outside
#                        the ECS subset; still in `osquery.columns`.
# All of them stay readable in the raw `osquery.columns` payload.

# The osquery tables whose `name` and `path` are a PROCESS. Aligned with the real capture: the two
# socket tables carry both columns and neither one means this.
_PROCESS_TABLES = frozenset({"processes", "process_events"})

# A port a socket does not have is reported as "0" (a Unix-domain socket in `listening_ports` and
# `process_open_sockets`, and the remote side of a socket that is only listening). Written through,
# it becomes `destination.port = 0` and `recipes.nonstandard_ports` — which is every port outside
# COMMON_PORTS — reports every Unix socket on the host as traffic to a non-standard port (86 of 120
# listening rows in the capture). A socket without a port is not a port.
_PORT_FIELDS = frozenset({"destination.port", "source.port"})


def _is_no_port(value) -> bool:
    """True for every spelling of "this socket has no port".

    Comparing to the string `"0"` covered what osquery emits today and would have missed `0`,
    `"00"` or `0.0`, all of which the store coerces to the same INTEGER 0 — the exact value the
    guard exists to keep out of `destination.port`. Port 0 is never a real TCP/UDP port, so the
    direction of this test can only be too permissive, never too eager.
    """
    try:
        return float(str(value).strip()) == 0
    except (TypeError, ValueError):
        return False


# osquery table name (query) -> ECS event.category. AN EXACT-NAME HINT ONLY: `name` in a result log
# is the SCHEDULED QUERY's name, which osquery never ties to the table it read. This map works when
# the analyst named the query after the table — the convention the demo fixtures use — and misses
# otherwise. The real capture named its queries `proc`, `listen`, `socks`, `logged`, `users`: four of
# five missed, and the old column fallback then labelled every one of them "process", because they
# all carry a `pid`. That is what `_SIGNATURE_CATEGORY` below is for.
_CATEGORY_MAP = {
    "processes": "process",
    "process_open_sockets": "network",
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

# The columns that identify the TABLE, used when the query name does not. Ordered, and the order is
# the correctness argument: two of these markers are carried by MORE than one table, so a signature
# tested too early steals a row from its own category.
#   * `gid` is in `processes` AND `users`, so the process rules must run before the iam one —
#     otherwise a full-column process row lands in `iam`.
#   * `directory` is in `users` AND `hash`, so `file` must run before `iam`.
#   * `state` is in `processes` as well as in `process_open_sockets`. It was in the network tuple on
#     the first pass and mislabelled every full-column process row as a network event; it is gone,
#     and it was redundant — the socket tables are caught by `socket`, which no process table has.
#   * `address` is what `arp_cache` and `listening_ports` carry.
# Every marker here was checked against the real column list of the table it serves
# (`SELECT *` on osquery 5.23.1), not against what the column was assumed to be.
_SIGNATURE_CATEGORY = (
    ("network", ("remote_address", "local_address", "socket", "address")),
    ("file", ("md5", "sha1", "sha256", "target_path")),
    ("authentication", ("tty",)),
    ("process", ("cmdline", "parent")),
    ("iam", ("directory", "shell", "gid")),
)


def _clean(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if v not in (None, "", [], {})}


def _record(ev: dict) -> dict | None:
    if not isinstance(ev, dict):
        return None
    unix_time = ev.get("unixTime")
    if not unix_time:
        return None

    # Epoch → ISO-8601 UTC. Imported here rather than at module scope for the same reason the
    # adapters always have: the module stays importable without dragging two datetime names in.
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
        if val is None or val == "":
            continue
        if schema_field in _PORT_FIELDS and _is_no_port(val):
            continue
        rec[schema_field] = val

    # `name` and `path` only where they really are a process: in the socket tables the same column
    # names hold a socket. `name` is not checked against the table alone, because a table outside
    # `_PROCESS_TABLES` whose row carries a pid and a command line is still a process row.
    if columns.get("name") and (rec.get("event.category") == "process"
                                or "cmdline" in columns or "pid" in columns):
        rec["process.name"] = columns["name"]
    if columns.get("path") and (query_name in _PROCESS_TABLES or "cmdline" in columns):
        rec["process.path"] = columns["path"]

    # Decorations: host enrichment.
    if decorations.get("username") and "user.name" not in rec:
        rec["user.name"] = decorations["username"]
    if decorations.get("host_uuid"):
        rec["osquery.host_uuid"] = decorations["host_uuid"]

    # Namespaced extras: raw columns + decorations.
    rec["osquery.columns"] = columns
    if decorations:
        rec["osquery.decorations"] = decorations

    # Derive event.category from the columns when the query name did not identify the table.
    if not rec.get("event.category"):
        for category, markers in _SIGNATURE_CATEGORY:
            if any(m in columns for m in markers):
                rec["event.category"] = category
                break

    # Last resort, and deliberately the loosest: a row that carries only a pid is more likely a
    # process than anything else. It used to run FIRST, which is how a socket and an interactive
    # session both came out labelled "process".
    if not rec.get("event.category") and "pid" in columns:
        rec["event.category"] = "process"

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
