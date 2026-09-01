"""Test of generic log adapter (adapters/logfile) — offline, always run.

SYNTHETIC fixtures in SonicWall SMA style (access + app-log + syslog-ng), IPs in documentation
range (203.0.113.0/24, 198.51.100.0/24): no real data. Verifies access/jsonl/regex/syslog/line
profiles, timestamp normalization to UTC (including timezone offset) and status→outcome mapping.
    uv run python tests/test_logfile.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters import logfile  # noqa: E402

ACCESS = (
    '203.0.113.5 - - [16/Jul/2026:06:28:59 +0200] "GET /wsproxy?serviceType=SSH&port=1050 HTTP/1.1" 500 3270 "-" -\n'
    '203.0.113.9 - - [16/Jul/2026:06:29:00 +0200] "POST /rollbackConfirm.action HTTP/1.1" 200 12 "-" -\n'
)
APPLOG = (
    "2026-07-15 06:28:56,421 - INFO - running hotfix removal for:../../../../../tmp/sma1000_847feb.sh\n"
    "2026-07-15 06:28:56,594 - ERROR - remove_hotfix exited with status 1\n"
)
# syslog-ng ISO format (SMA appliance auth.log/syslog/kern.iptables). Synthetic, doc-range IPs.
# The host token is templated as "program@hostname" (as the real appliance emits it).
SYSLOG = (
    "2026-07-16T14:20:48+02:00 kernel@sma-gw kern.warning kernel: IPTABLES:in:SSH_FILTER:IN=eth0 OUT= "
    "MAC=00:11:22:33:44:55 SRC=203.0.113.7 DST=198.51.100.2 LEN=52 TTL=118 ID=51526 DF PROTO=TCP "
    "SPT=56168 DPT=22 WINDOW=65535 SYN URGP=0\n"
    "2026-07-16T14:22:57+02:00 sshd-session@sma-gw auth.info sshd-session: Accepted password for root from 203.0.113.7 port 59998 ssh2\n"
    "2026-07-16T14:23:10+02:00 sshd-session@sma-gw auth.info sshd-session: Failed password for invalid user admin from 203.0.113.99 port 40001 ssh2\n"
)


def _write(text: str, suffix=".log") -> Path:
    f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w", encoding="utf-8")
    f.write(text)
    f.close()
    return Path(f.name)


def test_access_profile():
    p = _write(ACCESS)
    recs = logfile.load_records(p, fmt="access")
    p.unlink(missing_ok=True)
    assert len(recs) == 2, recs
    r = recs[0]
    assert r["source.ip"] == "203.0.113.5"
    assert r["url.original"].startswith("/wsproxy")
    assert r["http.request.method"] == "GET"
    assert r["http.response.status_code"] == 500
    assert r["event.outcome"] == "failure"          # 5xx
    # +0200 → UTC: 06:28:59 +0200 = 04:28:59Z
    assert r["@timestamp"] == "2026-07-16T04:28:59Z", r["@timestamp"]
    assert recs[1]["event.outcome"] == "success"     # 200
    assert r["event.source"].startswith("log:")


def test_line_profile_applog():
    p = _write(APPLOG)
    recs = logfile.load_records(p, fmt="line")
    p.unlink(missing_ok=True)
    assert len(recs) == 2, recs
    assert recs[0]["@timestamp"] == "2026-07-15T06:28:56.421Z", recs[0]["@timestamp"]
    assert "hotfix" in recs[0]["message"]


def test_regex_profile_extracts_file():
    p = _write(APPLOG)
    recs = logfile.load_records(
        p, fmt="regex",
        pattern=r"(?P<ts>\d{4}-\d{2}-\d{2} \S+).*?(?P<file>sma1000_\w+\.sh)",
    )
    p.unlink(missing_ok=True)
    assert recs[0]["file.name"] == "sma1000_847feb.sh", recs[0]
    assert recs[0]["@timestamp"].startswith("2026-07-15T06:28:56")


def test_jsonl_profile():
    p = _write('{"ip":"203.0.113.5","timestamp":"16/Jul/2026:06:29:01 +0200","url":"/x","status":200}\n',
               suffix=".json")
    recs = logfile.load_records(p, fmt="jsonl")
    p.unlink(missing_ok=True)
    r = recs[0]
    assert r["source.ip"] == "203.0.113.5" and r["url.original"] == "/x"
    assert r["http.response.status_code"] == 200 and r["event.outcome"] == "success"
    assert r["@timestamp"] == "2026-07-16T04:29:01Z"


def test_auto_sniff():
    p = _write(ACCESS)
    recs = logfile.load_records(p, fmt="auto")   # must recognize access
    p.unlink(missing_ok=True)
    assert recs and recs[0]["http.response.status_code"] == 500


def test_generic_ts_offset_to_utc():
    # timezone offset honored (was silently dropped, causing a 2h skew)
    assert logfile._generic_ts_to_iso("2026-07-16T14:20:48+02:00") == "2026-07-16T12:20:48Z"
    assert logfile._generic_ts_to_iso("2026-07-16T00:30:00+02:00") == "2026-07-15T22:30:00Z"  # date rollover
    assert logfile._generic_ts_to_iso("2026-07-16T14:20:48.798893+02:00") == "2026-07-16T12:20:48.798893Z"
    # no offset = assume UTC (unchanged); explicit Z = unchanged
    assert logfile._generic_ts_to_iso("2026-07-16 14:20:48") == "2026-07-16T14:20:48Z"
    assert logfile._generic_ts_to_iso("2026-07-16T14:20:48Z") == "2026-07-16T14:20:48Z"


def test_syslog_profile_iptables():
    p = _write(SYSLOG)
    recs = logfile.load_records(p, fmt="syslog")
    p.unlink(missing_ok=True)
    assert len(recs) == 3, recs
    fw = recs[0]
    assert fw["host.name"] == "sma-gw"
    assert fw["process.name"] == "kernel"
    assert fw["source.ip"] == "203.0.113.7"
    assert fw["destination.ip"] == "198.51.100.2"
    assert fw["destination.port"] == 22          # DPT: which service was hit (SSH)
    assert fw["network.transport"] == "tcp"
    assert fw["event.category"] == "network"
    assert fw["@timestamp"] == "2026-07-16T12:20:48Z", fw["@timestamp"]   # +0200 → UTC


def test_syslog_profile_sshd():
    p = _write(SYSLOG)
    recs = logfile.load_records(p, fmt="syslog")
    p.unlink(missing_ok=True)
    ok = recs[1]
    assert ok["event.category"] == "authentication"
    assert ok["event.outcome"] == "success"
    assert ok["user.name"] == "root"             # accepted root over SSH (the pre-compromise signal)
    assert ok["source.ip"] == "203.0.113.7"
    assert ok["@timestamp"] == "2026-07-16T12:22:57Z", ok["@timestamp"]
    bad = recs[2]
    assert bad["event.outcome"] == "failure"
    assert bad["user.name"] == "admin"           # "invalid user admin" → admin


def test_auto_sniff_syslog():
    p = _write(SYSLOG)
    recs = logfile.load_records(p, fmt="auto")   # must recognize syslog
    p.unlink(missing_ok=True)
    assert recs[0]["event.category"] == "network" and recs[1]["event.category"] == "authentication"


if __name__ == "__main__":
    test_access_profile()
    test_line_profile_applog()
    test_regex_profile_extracts_file()
    test_jsonl_profile()
    test_auto_sniff()
    test_generic_ts_offset_to_utc()
    test_syslog_profile_iptables()
    test_syslog_profile_sshd()
    test_auto_sniff_syslog()
    print("OK — logfile: 9 tests passed")
