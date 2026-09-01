"""Test of the osquery result adapter (adapters/osquery_result).

Two levels:
- `run_synthetic()`: ALWAYS run. Validates field mapping on synthetic osquery NDJSON.
- `run()`: end-to-end (requires real osquery data, currently skipped).

Usage: uv run python tests/test_osquery.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


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
    """`remote_address` (logged_in_users) is the OTHER end of the session, not this host.

    It used to be written to source.ip — the field the store reads as "this record is about this
    host" — which bridged every logged_in_user record to every other, and made the local host look
    like the remote attacker."""
    from adapters import osquery_result
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(json.dumps({
            "name": "logged_in_users", "hostIdentifier": "workstation", "unixTime": 1673361600,
            "action": "added",
            "columns": {"username": "alice", "remote_address": "203.0.113.7", "host": "workstation"},
        }) + "\n")
        path = f.name
    try:
        r = osquery_result.load_records(path)[0]
        assert r.get("destination.ip") == "203.0.113.7", r
        assert "source.ip" not in r, f"remote_address must not become source.ip: {r}"
        print("PASS  osquery adapter: remote_address is destination.ip, not source.ip")
    finally:
        import os
        os.unlink(path)


def run() -> int:
    _test_ndjson_parsing()
    _test_columns_do_not_overwrite_the_category()
    _test_remote_address_is_destination()
    _test_empty_and_malformed()
    return 0


def test_osquery():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
