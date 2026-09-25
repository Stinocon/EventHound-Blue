"""The source CLIs, driven end to end on mock files — the Python-only roads in.

`test_cli_smoke` proves every entry point *starts*; coverage said that was all it proved. Four
entry points whose whole path is Python (no tshark, no Hayabusa, no MFTECmd) sat at ~35%: the
flags reached argparse and nothing else. A source CLI is complete when a file goes in and an
analysis comes out, so that is what is asserted here — records produced, the correlation run, the
JSON written.

The fixtures are synthetic and documentation-range (203.0.113.0/24, 198.51.100.0/24): a mock file
that looks like the real format is the only thing that catches a mapping that stopped matching it.

    uv run python tests/test_cli_sources.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests._helpers import subprocess_env  # noqa: E402


def _run(args: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    """Run an entry point the way a user would, from the engine's directory."""
    return subprocess.run([sys.executable, "-m", *args], cwd=ROOT, capture_output=True, text=True,
                          env=subprocess_env(ROOT), timeout=timeout)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


# --- mock fixtures -----------------------------------------------------------------------------
# One per format the adapter documents. Kept small, but shaped like the real thing: the keys are
# the adapter's input contract, so a fixture that drifts from the producer stops testing it.

CROWDSTRIKE_CLIPBOARD = """Description: A process has written a kernel driver to disk that CrowdStrike analysts have deemed vulnerable.
Customer ID: 1a2b3c4d5e6f708192a3b4c5d6e7f809
Detected: Jul. 24, 2026 16:11:20 local time, (2026-07-24 14:11:20 UTC)
Host name: WS-01
Agent ID: 0f1e2d3c4b5a69788796a5b4c3d2e1f0
File name: svcupdate.exe
File path: \\Device\\HarddiskVolume3\\Windows\\Temp\\svcupdate.exe
Command line: "C:\\Windows\\Temp\\svcupdate.exe" -install
SHA 256: 81e662c1666173f74e3c28bb94bf8ec2fb0c82871cccc6103907a4dbc37a0e85
MD5 Hash: de42e3780f52b9538f135a92dba88714
Platform: Windows
IP address: 198.51.100.20
User name: admin
"""

CROWDSTRIKE_LOGSCALE = json.dumps({
    "ComputerName": "WS-01",
    "SHA256HashData": "81e662c1666173f74e3c28bb94bf8ec2fb0c82871cccc6103907a4dbc37a0e85",
    "UserName": "admin",
    "LocalAddressIP4": "10.0.0.140",
    "event_simpleName": "EndOfProcess",
    "event_platform": "Win",
    "timestamp": "1784902228096",
    "RawProcessId": "3404",
    "aid": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    # `aip` is deliberately NOT the same address as the host's: it is the tenant NAT egress, and a
    # fixture that made it the host's own address would hide the mapping bug it exists to guard.
    "aip": "198.51.100.20",
    "cid": "1a2b3c4d5e6f708192a3b4c5d6e7f809",
})

OKTA_SYSTEM_LOG = json.dumps([
    {
        "uuid": "e1", "published": "2026-07-22T10:00:00.000Z",
        "eventType": "user.session.start", "severity": "INFO",
        "displayMessage": "User login to Okta",
        "actor": {"id": "00u1", "type": "User", "alternateId": "alice@corp.example"},
        "client": {"ipAddress": "203.0.113.5",
                   "geographicalContext": {"city": "Rome", "country": "Italy"}},
        "outcome": {"result": "SUCCESS"},
    },
    {
        "uuid": "e2", "published": "2026-07-22T10:01:00.000Z",
        "eventType": "user.authentication.auth_via_mfa", "severity": "WARN",
        "displayMessage": "Authentication of user via MFA",
        "actor": {"id": "00u1", "type": "User", "alternateId": "alice@corp.example"},
        "client": {"ipAddress": "203.0.113.99"},
        "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
    },
])

OSQUERY_NDJSON = "\n".join([
    json.dumps({
        "name": "processes", "hostIdentifier": "ws-01",
        "unixTime": 1784902228, "action": "added",
        "columns": {"pid": "3404", "name": "svcupdate.exe", "path": "C:\\Windows\\Temp\\svcupdate.exe",
                    "cmdline": "\"C:\\Windows\\Temp\\svcupdate.exe\" -install", "uid": "0"},
        "decorations": {"username": "admin"},
    }),
    json.dumps({
        "name": "listening_ports", "hostIdentifier": "ws-01",
        "unixTime": 1784902230, "action": "added",
        "columns": {"pid": "3404", "port": "8443", "address": "0.0.0.0", "protocol": "tcp"},
    }),
]) + "\n"

ACCESS_LOG = (
    '203.0.113.5 - - [16/Jul/2026:06:28:59 +0200] "GET /wsproxy?serviceType=SSH&port=1050 HTTP/1.1" 500 3270 "-" -\n'
    '203.0.113.9 - [16/Jul/2026:06:29:00 +0200] "POST /rollbackConfirm.action HTTP/1.1" 200 12 "-" -\n'
)


def _by_source(json_path: Path) -> dict:
    result = json.loads(json_path.read_text(encoding="utf-8"))
    assert result.get("summary", {}).get("events", 0) > 0, result.get("summary")
    return result["summary"].get("by_source") or {}


def test_run_crowdstrike_cli() -> None:
    """Both formats the adapter documents, through the CLI that correlates them."""
    with tempfile.TemporaryDirectory(prefix="eh-cs-") as td:
        d = Path(td)
        clip = _write(d / "detection.txt", CROWDSTRIKE_CLIPBOARD)
        logscale = _write(d / "investigation.json", CROWDSTRIKE_LOGSCALE)
        out = d / "cs.json"
        p = _run(["engine.run_crowdstrike", str(clip), str(logscale), "--json-out", str(out)])
        assert p.returncode == 0, (p.stdout[-500:], p.stderr[-500:])
        assert "Events:" in p.stdout, p.stdout[:400]
        # Both files reached ONE store: two records, one analysis.
        assert _by_source(out).get("crowdstrike", 0) == 2, _by_source(out)


def test_run_okta_cli() -> None:
    with tempfile.TemporaryDirectory(prefix="eh-okta-") as td:
        d = Path(td)
        log = _write(d / "system_log.json", OKTA_SYSTEM_LOG)
        out = d / "okta.json"
        p = _run(["engine.run_okta", str(log), "--json-out", str(out)])
        assert p.returncode == 0, (p.stdout[-500:], p.stderr[-500:])
        assert "Events:" in p.stdout, p.stdout[:400]
        assert _by_source(out).get("okta", 0) == 2, _by_source(out)


def test_run_osquery_cli() -> None:
    with tempfile.TemporaryDirectory(prefix="eh-osq-") as td:
        d = Path(td)
        log = _write(d / "osquery.jsonl", OSQUERY_NDJSON)
        out = d / "osquery.json"
        p = _run(["engine.run_osquery", str(log), "--json-out", str(out)])
        assert p.returncode == 0, (p.stdout[-500:], p.stderr[-500:])
        assert "Events:" in p.stdout, p.stdout[:400]
        assert _by_source(out).get("osquery", 0) == 2, _by_source(out)


def test_run_logs_cli_with_explicit_format() -> None:
    """`--fmt access` is the profile the CLI documents; auto-sniff is exercised by test_logfile."""
    with tempfile.TemporaryDirectory(prefix="eh-logs-") as td:
        d = Path(td)
        log = _write(d / "access.log", ACCESS_LOG)
        out = d / "logs.json"
        p = _run(["engine.run_logs", str(log), "--fmt", "access", "--json-out", str(out)])
        assert p.returncode == 0, (p.stdout[-500:], p.stderr[-500:])
        assert _by_source(out).get("log", 0) == 2, _by_source(out)


def test_cli_rejects_a_missing_file_without_a_traceback() -> None:
    """The error path reaches the user as a sentence: an unhandled exception here would print a
    traceback over whatever the analyst was reading, and §8 makes the path untrusted input."""
    for cli, flag in (("engine.run_crowdstrike", None), ("engine.run_okta", None),
                      ("engine.run_osquery", None), ("engine.run_logs", "--fmt")):
        args = [cli, "/nonexistent/evidence.file"] + ([flag, "access"] if flag else [])
        p = _run(args)
        assert p.returncode != 0, (cli, p.returncode)
        assert "Traceback" not in p.stderr, (cli, p.stderr[:400])


def run() -> int:
    test_run_crowdstrike_cli()
    test_run_okta_cli()
    test_run_osquery_cli()
    test_run_logs_cli_with_explicit_format()
    test_cli_rejects_a_missing_file_without_a_traceback()
    print("PASS  cli sources: crowdstrike (clipboard + LogScale), okta, osquery, logs — "
          "each end to end, and a missing file fails cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
