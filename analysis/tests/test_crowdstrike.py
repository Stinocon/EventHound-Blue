"""Test of the CrowdStrike adapter (adapters/crowdstrike).

Usage: uv run python tests/test_crowdstrike.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _test_clipboard_parsing():
    from adapters import crowdstrike
    text = """Description: A process has written a kernel driver to disk that CrowdStrike analysts have deemed vulnerable.
Customer ID: 1a2b3c4d5e6f708192a3b4c5d6e7f809
Full detection details: https://falcon.eu-1.crowdstrike.com/activity-v2/detections/test
Detected: Jul. 24, 2026 16:11:20 local time, (2026-07-24 14:11:20 UTC)
Host name: HOST-01
Agent ID: 0f1e2d3c4b5a69788796a5b4c3d2e1f0
File name: DellDockingStationFwUp_1.0.2_12052018_TB16.exe
File path: \\Device\\HarddiskVolume3\\Users\\USER-03\\Downloads\\DellDockingStationFwUp_1.0.2_12052018_TB16.exe
Command line: "C:\\Users\\USER-03\\Downloads\\DellDockingStationFwUp_1.0.2_12052018_TB16.exe"
SHA 256: 81e662c1666173f74e3c28bb94bf8ec2fb0c82871cccc6103907a4dbc37a0e85
MD5 Hash: de42e3780f52b9538f135a92dba88714
Platform: Windows
IP address: 198.51.100.20
User name: admin
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(text)
        path = f.name
    try:
        recs = crowdstrike.load_records(path)
        assert len(recs) == 1, f"expected 1 record, got {len(recs)}"
        r = recs[0]
        assert r["event.source"] == "crowdstrike"
        assert r["host.name"] == "HOST-01"
        assert r["file.name"] == "DellDockingStationFwUp_1.0.2_12052018_TB16.exe"
        assert r["file.hash.sha256"] == "81e662c1666173f74e3c28bb94bf8ec2fb0c82871cccc6103907a4dbc37a0e85"
        assert r["file.hash.md5"] == "de42e3780f52b9538f135a92dba88714"
        assert r["source.ip"] == "198.51.100.20"
        assert r["user.name"] == "admin"
        assert r["crowdstrike.agent_id"] == "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        assert r["crowdstrike.customer_id"] == "1a2b3c4d5e6f708192a3b4c5d6e7f809"
        assert "2026-07-24T14:11:20Z" in r["@timestamp"]
        assert r["host.os"] == "Windows"
        print(f"PASS  crowdstrike clipboard: {len(recs)} record, all fields mapped")
    finally:
        os.unlink(path)


def _test_logscale_parsing():
    from adapters import crowdstrike
    ev = {
        "ComputerName": "HOST-01",
        "SHA256HashData": "81e662c1666173f74e3c28bb94bf8ec2fb0c82871cccc6103907a4dbc37a0e85",
        "UserName": "admin",
        "LocalAddressIP4": "10.0.0.140",
        "event_simpleName": "EndOfProcess",
        "event_platform": "Win",
        "timestamp": "1784902228096",
        "RawProcessId": "3404",
        "ParentProcessId": "846672313273",
        "aid": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "aip": "198.51.100.20",
        "cid": "1a2b3c4d5e6f708192a3b4c5d6e7f809",
        "UserSid": "S-1-5-21-1111111111-2222222222-3333333333-1001",
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(json.dumps(ev))
        path = f.name
    try:
        recs = crowdstrike.load_records(path)
        assert len(recs) == 1, f"expected 1 record, got {len(recs)}"
        r = recs[0]
        assert r["event.source"] == "crowdstrike"
        assert r["host.name"] == "HOST-01"
        assert r["file.hash.sha256"] == "81e662c1666173f74e3c28bb94bf8ec2fb0c82871cccc6103907a4dbc37a0e85"
        assert r["user.name"] == "admin"
        assert r["source.ip"] == "10.0.0.140"
        assert r["event.action"] == "EndOfProcess"
        assert r["process.pid"] == "3404"
        assert r["process.parent.pid"] == "846672313273"
        assert r["crowdstrike.agent_id"] == "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        assert "2026-07-24" in r["@timestamp"]
        print(f"PASS  crowdstrike logscale: {len(recs)} record, all fields mapped")
    finally:
        os.unlink(path)


def _test_rawstring_wrapper():
    from adapters import crowdstrike
    raw = """@rawstring:{"ComputerName":"HOST-01","UserName":"admin","event_simpleName":"EndOfProcess","timestamp":"1784902228096","aid":"0f1e2d3c","cid":"1a2b3c4d","event_platform":"Win","aip":"198.51.100.20"}
timestamp:1784902228096
event_simpleName:EndOfProcess
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
        f.write(raw)
        path = f.name
    try:
        recs = crowdstrike.load_records(path)
        assert len(recs) == 1, f"expected 1 record from @rawstring wrapper, got {len(recs)}"
        assert recs[0]["host.name"] == "HOST-01"
        print(f"PASS  crowdstrike @rawstring wrapper: {len(recs)} record")
    finally:
        os.unlink(path)


def _test_through_build_records():
    """The path the CLI and the GUI actually take.

    The three tests above call the adapter directly, so they stayed green while
    `build_records(crowdstrike=...)` raised AttributeError on every call: the parameter shadowed the
    module of the same name, and the failure was swallowed into the `errors` list as an empty
    analysis. An adapter is only wired once something exercises the wiring.
    """
    from analytics import runner
    text = ("Description: Test detection\n"
            "Host name: HOST-02\n"
            "File name: evil.exe\n"
            "Detected: Jul. 24, 2026 16:11:20 local time, (2026-07-24 14:11:20 UTC)\n")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(text)
        path = f.name
    try:
        errors: list[str] = []
        recs = runner.build_records(crowdstrike=[path], errors=errors)
        assert not errors, f"build_records reported errors: {errors}"
        assert len(recs) == 1, f"expected 1 record through build_records, got {len(recs)}"
        assert recs[0]["host.name"] == "HOST-02"
        assert recs[0]["event.source"] == "crowdstrike"
        print("PASS  crowdstrike through build_records: wired, no swallowed error")
    finally:
        os.unlink(path)


def _test_agent_ip_is_not_a_bridge():
    """`aip` is the tenant's NAT egress: identical for every host, so it must not become source.ip."""
    from adapters import crowdstrike
    ev = {"ComputerName": "HOST-01", "aip": "198.51.100.20", "timestamp": "1784902228096"}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(json.dumps(ev))
        path = f.name
    try:
        r = crowdstrike.load_records(path)[0]
        assert "source.ip" not in r, f"aip leaked into source.ip: {r}"
        assert r["crowdstrike.agent_ip"] == "198.51.100.20"
        print("PASS  crowdstrike aip stays namespaced (no false IP bridge)")
    finally:
        os.unlink(path)


def _test_logscale_array_and_fields():
    """A LogScale export saved as a JSON ARRAY, and the fields the map used to drop.

    The array shape used to fall through to the clipboard parser (which reads `Key: Value` lines)
    and yield NOTHING, with no error. And the map omitted the image name, command line, domain and
    remote address the schema documents — so a ProcessRollup2 or DnsRequest event carried no
    process, no domain and no remote end into the store."""
    from adapters import crowdstrike
    events = [
        {"ComputerName": "HOST-01", "ImageFileName": "C:\\Windows\\Temp\\x.exe",
         "CommandLine": "\"C:\\Windows\\Temp\\x.exe\" -install", "timestamp": "1784902228096"},
        {"ComputerName": "HOST-01", "DomainName": "updates.cdn-corp.example",
         "RemoteAddressIP4": "203.0.113.90", "event_simpleName": "DnsRequest",
         "timestamp": "1784902228100"},
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(json.dumps(events))
        path = f.name
    try:
        recs = crowdstrike.load_records(path)
        assert len(recs) == 2, f"a JSON array export must parse: got {len(recs)}"
        proc, dns = recs
        assert proc["process.name"] == "C:\\Windows\\Temp\\x.exe", proc
        assert proc["process.command_line"] == "\"C:\\Windows\\Temp\\x.exe\" -install", proc
        assert proc["event.category"] == "process", proc
        assert dns["dns.question.name"] == "updates.cdn-corp.example", dns
        assert dns["destination.ip"] == "203.0.113.90", dns
        assert "source.ip" not in dns, dns
        print("PASS  crowdstrike LogScale array: parsed, image/cmdline/domain/remote mapped")
    finally:
        os.unlink(path)


def run() -> int:
    _test_clipboard_parsing()
    _test_logscale_parsing()
    _test_logscale_array_and_fields()
    _test_rawstring_wrapper()
    _test_through_build_records()
    _test_agent_ip_is_not_a_bridge()
    return 0


def test_crowdstrike():
    run()


if __name__ == "__main__":
    raise SystemExit(run())