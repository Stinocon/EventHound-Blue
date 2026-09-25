"""Test of the osquery result adapter (adapters/osquery_result).

There is no synthetic-only level any more: the adapter is checked against a REAL result log
(osquery 5.23.1, macOS, pseudonymized §9 — `tests/fixtures/osquery_result_5.23.1.jsonl`), because
the synthetic fixtures it used before had invented `logged_in_users` columns (`username`,
`remote_address`) that the real table does not have, and a test built on a guessed shape certifies
the guess. The real log named four defects the documentation did not; each one is pinned below.

Usage: uv run python tests/test_osquery.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FIXTURE = ROOT / "tests" / "fixtures" / "osquery_result_5.23.1.jsonl"


def _test_ndjson_parsing():
    from adapters import osquery_result
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        # Process event
        f.write(json.dumps({
            "name": "processes",
            "hostIdentifier": "testhost",
            "calendarTime": "Tue Jan 10 2023 12:00:00 GMT",
            "unixTime": 1673361600,
            "action": "added",
            "columns": {"pid": 1234, "name": "bash", "cmdline": "bash -c whoami", "path": "/bin/bash", "uid": 1000},
            "decorations": {"host_uuid": "abc-123", "username": "testuser"}
        }) + "\n")
        # Network event
        f.write(json.dumps({
            "name": "listening_ports",
            "hostIdentifier": "testhost",
            "unixTime": 1673361601,
            "action": "added",
            "columns": {"pid": 5678, "port": 8080, "address": "0.0.0.0", "protocol": "tcp"}
        }) + "\n")
        path = f.name
    try:
        recs = osquery_result.load_records(path)
        assert len(recs) == 2, f"expected 2 records, got {len(recs)}"

        proc = recs[0]
        assert proc["event.source"] == "osquery"
        assert proc["host.name"] == "testhost"
        assert proc["osquery.query"] == "processes"
        assert proc["event.action"] == "added"
        assert proc["process.name"] == "bash"
        assert proc["process.pid"] == 1234
        assert proc["process.command_line"] == "bash -c whoami"
        assert proc["user.name"] == "testuser"
        assert proc["osquery.host_uuid"] == "abc-123"
        assert "@timestamp" in proc

        net = recs[1]
        assert net["destination.port"] == 8080
        assert net["source.ip"] == "0.0.0.0"
        assert net["event.category"] == "network"

        print(f"PASS  osquery adapter: {len(recs)} records, fields mapped correctly")
    finally:
        import os
        os.unlink(path)


def _test_columns_do_not_overwrite_the_category():
    """A `file_events` row carries `columns.category` — the FIM group ("homes"), not an ECS
    category. Mapping it blindly replaced the correct table-derived "file" with a string nothing
    downstream knows, in the field the analytics group by. Same class: `columns.name` is a process
    only in process tables, and `tty` is not a port."""
    from adapters import osquery_result
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(json.dumps({
            "name": "file_events", "hostIdentifier": "testhost", "unixTime": 1673361600,
            "action": "added",
            "columns": {"target_path": "/etc/passwd", "category": "homes",
                        "sha256": "a" * 64, "tty": "pts/0"},
        }) + "\n")
        f.write(json.dumps({
            "name": "kernel_extensions", "hostIdentifier": "testhost", "unixTime": 1673361601,
            "action": "added", "columns": {"name": "com.apple.driver.AppleAPIC", "version": "1.7"},
        }) + "\n")
        path = f.name
    try:
        fim, kext = osquery_result.load_records(path)
        assert fim["event.category"] == "file", fim["event.category"]
        assert fim["file.path"] == "/etc/passwd"
        assert "source.port" not in fim, fim
        assert fim["osquery.columns"]["category"] == "homes"   # still readable, just not promoted
        assert "process.name" not in kext, kext
        print("PASS  osquery adapter: table-derived category survives the columns")
    finally:
        import os
        os.unlink(path)


def _test_empty_and_malformed():
    from adapters import osquery_result
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write("not json\n")                              # malformed JSON line → skipped
        f.write(json.dumps({"name": "processes"}) + "\n")  # no unixTime → filtered
        f.write("\n")                                       # empty line → skipped
        path = f.name
    try:
        recs = osquery_result.load_records(path)
        assert len(recs) == 0, f"expected 0 records from malformed input, got {len(recs)}"
        print("PASS  osquery adapter: empty/malformed input handled")
    finally:
        import os
        os.unlink(path)


def _test_remote_address_is_destination():
    """The near and far ends of a socket, on the table that actually has them.

    `remote_address` was written to source.ip — the field the store reads as "this record is about
    this host" — which made a host look like its own peer. The fixture here used to be a
    `logged_in_users` row, which does not HAVE `remote_address` (it has `host`): the mapping was
    tested against a column combination that no osquery table produces. `process_open_sockets` is
    the table this belongs to, and the columns below are the ones the real log carries."""
    from adapters import osquery_result
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(json.dumps({
            "name": "process_open_sockets", "hostIdentifier": "workstation", "unixTime": 1673361600,
            "action": "added",
            "columns": {"pid": "417", "local_address": "10.0.0.5", "local_port": "51000",
                        "remote_address": "203.0.113.7", "remote_port": "8443", "socket": "21",
                        "state": "ESTABLISHED"},
        }) + "\n")
        path = f.name
    try:
        r = osquery_result.load_records(path)[0]
        assert r.get("destination.ip") == "203.0.113.7", r
        assert r.get("destination.port") == "8443", f"remote_port is destination.port: {r}"
        assert r.get("source.ip") == "10.0.0.5", f"local_address is source.ip: {r}"
        assert r.get("source.port") == "51000", f"local_port is source.port: {r}"
        assert r.get("event.category") == "network", f"a socket is a network event: {r}"
        print("PASS  osquery adapter: both ends of a socket, on the table that has them")
    finally:
        import os
        os.unlink(path)


def _test_the_query_name_is_not_the_table():
    """`name` in a result log is the SCHEDULED QUERY's name, which osquery never ties to the table.

    The real capture named its queries `proc`, `listen`, `socks`, `logged`, `users`: the
    table-keyed map missed on four of five, and the old column fallback labelled every one of them
    "process" because they all carry a `pid` — so a socket and an interactive session both arrived
    as process events."""
    from adapters import osquery_result
    cases = [
        ({"address": "0.0.0.0", "port": "7000", "pid": "703", "socket": "0", "family": "2"},
         "network"),
        ({"pid": "417", "tty": "console", "type": "user", "user": "analyst"}, "authentication"),
        ({"uid": "278", "username": "_svc", "directory": "/var/empty", "shell": "/usr/bin/false"},
         "iam"),
        ({"pid": "1", "name": "launchd", "path": "/sbin/launchd", "parent": "0"}, "process"),
        ({"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha256": "e3b0c4" * 10},
         "file"),
        # FULL column lists, taken from `SELECT *` on the real 5.23.1 binary. The trimmed rows above
        # were hiding the defect these four catch: `processes` carries `state` and `gid`, and the
        # first version of the signature tested `state` for network and `gid` for iam — so a
        # full-column process row came out a network event, or an IAM one.
        ({"pid": "1", "name": "launchd", "path": "/sbin/launchd", "cmdline": "", "parent": "0",
          "state": "S", "gid": "0", "uid": "0", "nice": "0", "on_disk": "1"}, "process"),
        ({"address": "10.0.0.1", "interface": "en0", "mac": "00:11:22:33:44:55",
          "permanent": "1"}, "network"),
        ({"uid": "0", "gid": "0", "username": "root", "directory": "/var/root",
          "shell": "/bin/zsh", "is_hidden": "0"}, "iam"),
        ({"path": "/bin/ls", "directory": "/bin", "md5": "a" * 32, "sha1": "b" * 40,
          "sha256": "c" * 64}, "file"),
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        for i, (cols, _want) in enumerate(cases):
            f.write(json.dumps({"name": f"q{i}", "hostIdentifier": "h", "unixTime": 1673361600,
                                "action": "added", "columns": cols}) + "\n")
        path = f.name
    try:
        got = [r.get("event.category") for r in osquery_result.load_records(path)]
        want = [w for _, w in cases]
        assert got == want, f"category from columns: {got} != {want}"
        print("PASS  osquery adapter: the category comes from the columns, not the query name")
    finally:
        import os
        os.unlink(path)


def _test_the_real_result_log():
    """The whole mapping, against the pseudonymized real capture.

    Every assertion here is a defect the real log named and the documentation did not:
    `logged_in_users.user` (every session lost its user), the socket's near end and remote port,
    a socket with no port (`"0"`, which `recipes.nonstandard_ports` reported as non-standard
    traffic), and `path` in the socket tables being a Unix-domain SOCKET rather than a process."""
    from adapters import osquery_result
    recs = osquery_result.load_records(FIXTURE)
    assert len(recs) == 8, f"expected 8 records from the fixture, got {len(recs)}"
    by_query = {}
    for r in recs:
        by_query.setdefault(r["osquery.query"], []).append(r)

    # processes: unchanged, and the reason the adapter was trusted on it
    proc = by_query["proc"]
    assert proc[0]["process.name"] == "launchd" and proc[0]["process.path"] == "/sbin/launchd", proc[0]
    assert proc[1]["process.command_line"].endswith("loginwindow console"), proc[1]
    assert all(r["event.category"] == "process" for r in proc), proc

    # a connected socket: the far end AND the near end, all four fields
    socks = [r for r in by_query["socks"] if r.get("state") or r.get("destination.ip")]
    assert socks, by_query["socks"]
    s = socks[0]
    assert s["destination.ip"] and s["destination.port"] and s["source.ip"] and s["source.port"], s
    assert s["event.category"] == "network", s

    # a Unix-domain socket carries no port and no address, and its `path` is not a process path
    for r in by_query["listen"] + by_query["socks"]:
        assert "process.path" not in r, f"a socket file is not the binary a process runs: {r}"
    assert not any(r.get("destination.port") in ("0", 0) for r in recs), \
        "a port a socket does not have must not be written as destination.port = 0"

    # Every spelling of "this socket has no port" the store would coerce to the same 0.
    from adapters.osquery_result import _is_no_port
    for v in ("0", 0, "00", "0.0", " 0 ", 0.0):
        assert _is_no_port(v), v
    for v in ("22", 443, "8443", "", None, "abc"):
        assert not _is_no_port(v), v

    # logged_in_users: `user`, not `username`, and `host` is not an IP
    logged = by_query["logged"][0]
    assert logged["user.name"] == "analyst", logged
    assert logged["event.category"] == "authentication", logged
    assert "source.ip" not in logged, f"the session's origin host is not an IP: {logged}"

    # users: `username`, and it is an IAM record, not a process one
    u = by_query["users"][0]
    assert u["user.name"] and u["event.category"] == "iam", u
    print(f"PASS  osquery adapter: the real 5.23.1 result log maps as documented ({len(recs)} rows)")


def run() -> int:
    _test_ndjson_parsing()
    _test_columns_do_not_overwrite_the_category()
    _test_remote_address_is_destination()
    _test_the_query_name_is_not_the_table()
    _test_the_real_result_log()
    _test_empty_and_malformed()
    return 0


def test_osquery():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
