"""Test of the THOR (Nextron) adapter (adapters/thor_scan) — offline, always run.

SYNTHETIC fixture in THOR .txt style: fake host/owner, documentation-range IP (198.51.100.0/24),
placeholder hashes — no real data (the real client report stays out of the repo, §9/§10). Verifies
the key-value parser (values with spaces/backslashes/colons), finding selection (scored lines only),
schema mapping, the CSV fallback, and the MD5+SHA256 cross-source correlation.
    uv run python tests/test_thor.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters import thor_scan  # noqa: E402
from analytics import runner  # noqa: E402

SHA256_A = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
MD5_A = "0123456789abcdef0123456789abcdef"

# Mirrors real THOR structure: values contain spaces, backslashes and colons (ACL, timestamp);
# keys are UPPERCASE + ": ". The Info line has no SCORE → not a finding (must be skipped).
REPORT = (
    "Jul 22 10:35:20 HOST-01/198.51.100.10 THOR: Warning: MODULE: Filescan "
    "MESSAGE: Possibly Dangerous file found SCANID: S-TESTaaaaa SCORE: 80 "
    "FILE: C:\\Windows\\Temp\\evil.exe EXT: .exe TYPE: EXE SIZE: 512 "
    f"MD5: {MD5_A} SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709 SHA256: {SHA256_A} "
    "FIRSTBYTES: 4d5a / MZ CREATED: Thu Nov 24 13:46:01.823 2022 "
    "MODIFIED: Thu Nov 24 13:46:01.823 2022 ACCESSED: Thu Nov 24 13:46:01.823 2022 "
    "PERMISSIONS: BUILTIN\\Administrators:F / NT AUTHORITY\\SYSTEM:F OWNER: NT AUTHORITY\\SYSTEM "
    "REASON_1: Filename IOC \\Temp\\evil.exe SUBSCORE_1: 80 REF_1: Test APT - SAMPLE (BACKDOOR) "
    "SIGTYPE_1: internal SIGCLASS_1: Filename IOC MATCHED_1: \\Temp\\evil.exe REASONS_COUNT: 1\n"
    "Jul 22 10:36:00 HOST-01/198.51.100.10 THOR: Notice: MODULE: Filescan MESSAGE: Suspicious file "
    "SCANID: S-TESTaaaaa SCORE: 45 FILE: C:\\Temp\\notes.txt EXT: .txt TYPE: TEXT SIZE: 12 "
    "MD5: ffffffffffffffffffffffffffffffff SHA256: aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888 "
    "OWNER: HOST-01\\alice REASON_1: Suspicious name SUBSCORE_1: 45 SIGCLASS_1: Filename "
    "MATCHED_1: notes REASONS_COUNT: 1\n"
    "Jul 22 10:36:30 HOST-01/198.51.100.10 THOR: Info: MODULE: Startup "
    "MESSAGE: Thor Version: 10.7.30 SCANID: S-TESTaaaaa\n"
    # A finding carrying a secondary (_1) file object → primary + one 'linked' record.
    "Jul 22 10:37:00 HOST-01/198.51.100.10 THOR: Warning: MODULE: Filescan MESSAGE: Linked file "
    "SCANID: S-TESTaaaaa SCORE: 70 FILE: C:\\Temp\\link.lnk EXT: .lnk TYPE: LNK SIZE: 100 "
    "MD5: 11111111111111111111111111111111 "
    "SHA256: bbbb1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb9999 "
    "OWNER: HOST-01\\bob REASON_1: Suspicious link SIGCLASS_1: Filename MATCHED_1: link "
    "FILE_1: C:\\Windows\\System32\\target.exe MD5_1: 22222222222222222222222222222222 "
    "SHA256_1: cccc1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbbaaaa EXISTS_1: true "
    "OWNER_1: NT AUTHORITY\\SYSTEM REASONS_COUNT: 1\n"
)
LINKED_MD5 = "22222222222222222222222222222222"


def _write_report(text: str) -> Path:
    # Filename carries the date so the year inference (_year_from_name) is deterministic.
    d = Path(tempfile.mkdtemp())
    p = d / "SRV_thor_2026-07-22_1035.txt"
    p.write_text(text, encoding="utf-8")
    return p


def test_parses_scored_findings_only():
    p = _write_report(REPORT)
    recs = thor_scan.load_records(report=p)
    # 3 scored primaries (Info skipped) + 1 linked from the secondary object = 4 records.
    assert len(recs) == 4, f"got {len(recs)}"
    primaries = [r for r in recs if r.get("event.action") != "thor-linked"]
    assert len(primaries) == 3


def test_secondary_linked_record():
    p = _write_report(REPORT)
    recs = thor_scan.load_records(report=p)
    linked = [r for r in recs if r.get("event.action") == "thor-linked"]
    assert len(linked) == 1
    lk = linked[0]
    assert lk["file.name"] == "target.exe" and lk["file.hash.md5"] == LINKED_MD5
    assert lk["thor.linked"] is True and lk["thor.linked_to"] == "link.lnk"
    assert lk.get("thor.score") is None                 # linked is not a scored finding


def test_field_mapping_and_kv_with_colons():
    p = _write_report(REPORT)
    r = thor_scan.load_records(report=p)[0]
    assert r["@timestamp"] == "2026-07-22T10:35:20Z", r["@timestamp"]
    assert r["event.source"] == "thor" and r["event.category"] == "malware"
    assert r["event.action"] == "thor-filescan"
    assert r["file.name"] == "evil.exe"                 # Windows basename
    assert r["file.hash"] == SHA256_A                   # SHA256 primary
    assert r["file.hash.md5"] == MD5_A                  # MD5 secondary
    assert r["host.name"] == "HOST-01"
    assert r["user.name"] == "NT AUTHORITY\\SYSTEM"     # OWNER value with a space survives
    assert r["rule.title"] == "\\Temp\\evil.exe"        # MATCHED_1
    assert r["ioc.description"].startswith("Filename IOC")
    assert r["ioc.severity"] == "medium"                # Warning
    assert r["thor.score"] == 80
    assert r["thor.ref"] == "Test APT - SAMPLE (BACKDOOR)"  # value with parens/dash not split


def test_notice_severity_and_owner_domain():
    p = _write_report(REPORT)
    r = thor_scan.load_records(report=p)[1]
    assert r["ioc.severity"] == "low" and r["thor.severity"] == "Notice"
    assert r["thor.score"] == 45 and r["file.name"] == "notes.txt"


def test_csv_fallback():
    d = Path(tempfile.mkdtemp())
    csv = d / "files_md5s.csv"
    csv.write_text(f"{MD5_A},C:\\Windows\\Temp\\evil.exe,80\n"
                   "deadbeefdeadbeefdeadbeefdeadbeef,C:\\Temp\\x.log,45\n", encoding="utf-8")
    recs = thor_scan.load_records(md5s=csv)
    assert len(recs) == 2
    assert recs[0]["file.hash.md5"] == MD5_A and recs[0]["file.name"] == "evil.exe"
    assert recs[0]["thor.score"] == 80 and recs[0]["event.source"] == "thor"


def test_cross_source_correlation_on_both_hashes():
    p = _write_report(REPORT)
    thor = thor_scan.load_records(report=p)
    # A synthetic EVTX record carrying the SAME MD5 in file.hash (Sysmon MD5 hashing).
    fake_evtx = {"@timestamp": "2026-07-22T10:00:00Z", "event.source": "evtx",
                 "host.name": "DC1", "file.hash": MD5_A}
    res = runner.analyze(thor + [fake_evtx])
    hash_hits = [i for i in res.get("shared_indicators", []) if i["kind"] == "file_hash"]
    assert any(i["indicator"] == MD5_A and i["sources"] >= 2 for i in hash_hits), \
        "THOR MD5 must correlate with an EVTX file.hash=MD5 across sources"
    assert len(res.get("thor_findings", [])) == 3    # primaries only, linked excluded


def test_linked_record_also_correlates():
    p = _write_report(REPORT)
    thor = thor_scan.load_records(report=p)
    # An EVTX record carrying the linked (secondary) file's MD5 must still correlate.
    fake_evtx = {"@timestamp": "2026-07-22T10:00:00Z", "event.source": "evtx",
                 "host.name": "DC1", "file.hash": LINKED_MD5}
    res = runner.analyze(thor + [fake_evtx])
    hits = [i for i in res.get("shared_indicators", []) if i["kind"] == "file_hash"]
    assert any(i["indicator"] == LINKED_MD5 and i["sources"] >= 2 for i in hits), \
        "the secondary (linked) file's hash must be a cross-source indicator too"


def test_year_without_filename_falls_back_to_mtime():
    """A report whose filename carries no year must not be stamped with the CURRENT year.

    The old fallback was `datetime.now().year`: a THOR report from any past year was silently
    re-dated to the year of analysis, so every finding landed in the wrong year. The honest anchor
    is the report file's own mtime — the moment it was written to disk, which is >= the scan."""
    import os
    from datetime import datetime, timezone
    d = Path(tempfile.mkdtemp())
    p = d / "thor_report.txt"          # no `_YYYY-MM-DD_` in the name
    p.write_text(REPORT, encoding="utf-8")
    past = datetime(2023, 11, 5, 12, 0, 0, tzinfo=timezone.utc)
    os.utime(p, (past.timestamp(), past.timestamp()))
    recs = thor_scan.load_records(report=p)
    assert recs, "no records parsed"
    # Jul 22, with the year taken from the mtime (2023), never from datetime.now().year.
    assert all(r["@timestamp"].startswith("2023-07-22T10:3") for r in recs), \
        [r["@timestamp"] for r in recs]
    print("PASS  thor: a year-less filename is anchored to the report's mtime, not now().year")


if __name__ == "__main__":
    test_parses_scored_findings_only()
    test_secondary_linked_record()
    test_field_mapping_and_kv_with_colons()
    test_notice_severity_and_owner_domain()
    test_csv_fallback()
    test_cross_source_correlation_on_both_hashes()
    test_linked_record_also_correlates()
    test_year_without_filename_falls_back_to_mtime()
    print("OK — thor: 8 tests passed")
