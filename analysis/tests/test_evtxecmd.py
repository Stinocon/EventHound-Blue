"""Test of EvtxECmd adapter (adapters/evtx_evtxecmd).

- run_synthetic(): Always run. EvtxECmd JSON → schema mapping (4624/4688), Payload parsing,
  timestamp normalization, LogonType fallback from PayloadData, BOM/broken line robustness.
- run(): end-to-end on LM_WMI via `dotnet` (auto-skip without dotnet/dataset/dll).
    uv run python tests/test_evtxecmd.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests._helpers import skip_test  # noqa: E402

SAMPLE_REL = "Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx"


def _payload(pairs: list[tuple[str, str | None]]) -> str:
    return json.dumps({"EventData": {"Data": [
        ({"@Name": n} if t is None else {"@Name": n, "#text": t}) for n, t in pairs
    ]}})


SYNTH_4624 = {
    "EventId": 4624, "Channel": "Security", "Computer": "SRV-01",
    "TimeCreated": "2019-03-18T22:15:36.0363760+00:00", "Keywords": "Audit Success",
    "Payload": _payload([("TargetUserName", "Administrator"), ("TargetDomainName", "CORP"),
                         ("LogonType", "3"), ("IpAddress", "10.0.0.9"), ("ProcessName", "-")]),
    "PayloadData2": "LogonType 3",
}
SYNTH_4688 = {
    "EventId": 4688, "Channel": "Security", "Computer": "SRV-01",
    "TimeCreated": "2019-03-18T22:16:00.0000000+00:00",
    "Payload": _payload([("SubjectUserName", "SRV-01$"),
                         ("NewProcessName", r"C:\Windows\System32\wbem\WmiPrvSE.exe"),
                         ("CommandLine", None)]),
}


def run_synthetic() -> None:
    from adapters import evtx_evtxecmd as a

    r = a._record_from_evtxecmd(SYNTH_4624)
    assert r["event.source"] == "evtx_full", r
    assert r["event.category"] == "authentication" and r["event.action"] == "logon", r
    assert r["event.code"] == 4624 and r["event.outcome"] == "success", r
    # The realm is carried IN the name now. It used to be dropped, so `normalize.user_domain`
    # returned None for every EVTX-full record and `realms_conflict` — the guard that flags
    # alice@corp against alice@partner as a possible FALSE merge — could never fire on this
    # source. `canon_user` still reduces this to "administrator", so the bridge is unchanged.
    from analytics import normalize
    assert r["host.name"] == "SRV-01" and r["user.name"] == "CORP\\Administrator", r
    assert normalize.canon_user(r["user.name"]) == "administrator", r["user.name"]
    assert normalize.user_domain(r["user.name"]) == "corp", r["user.name"]
    assert r["logon.type"] == "3" and r["source.ip"] == "10.0.0.9", r
    # timestamp normalized to ISO-UTC with Z and 6-digit fraction (for store TRY_CAST)
    assert r["@timestamp"] == "2019-03-18T22:15:36.036376Z", r["@timestamp"]
    # ProcessName '-' is empty marker → must not become process.name
    assert "process.name" not in r, r

    r2 = a._record_from_evtxecmd(SYNTH_4688)
    assert r2["event.category"] == "process" and r2["event.action"] == "process-create", r2
    assert r2["process.name"].endswith("WmiPrvSE.exe"), r2
    assert r2["user.name"] == "SRV-01$", r2

    # LogonType missing from EventData → fallback to PayloadData
    d = dict(SYNTH_4624)
    d["Payload"] = _payload([("TargetUserName", "Administrator"), ("IpAddress", "10.0.0.9")])
    assert a._record_from_evtxecmd(d)["logon.type"] == "3"

    # BOM + valid line + broken line + non-object: only valid survives
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        p = Path(tmp.name)
    p.write_bytes(b"\xef\xbb\xbf" + (json.dumps(SYNTH_4624) + "\n").encode()
                  + b"{ broken\n" + b"[1,2]\n")
    recs = a.load_records(p)
    p.unlink(missing_ok=True)
    assert len(recs) == 1, f"BOM/broken line not handled: {len(recs)}"
    print("PASS  evtxecmd mapping (synthetic, always run)")


def run_sysmon_hashes_and_user() -> None:
    """Sysmon's multi-hash field and its `User` key — both were read wrong.

    Sysmon writes `SHA1=…,MD5=…,SHA256=…,IMPHASH=…` into one `Hashes` field. The adapter copied the
    whole string into `file.hash`, and `normalize.canon_hash` takes the part after the LAST `=`, so
    the stored artifact hash was the **IMPHASH**. That is worse than losing the hash: an imphash is
    designed to be shared by unrelated binaries with the same import table, so the store asserted
    "same artifact" across different programs — while the SHA-256 that THOR, CrowdStrike and osquery
    put in `file.hash` was never corroborated, and the MD5 in the same string was thrown away.

    And `_USER_KEYS` had no `User`, which is how Sysmon spells it: on a Sysmon-heavy collection (the
    normal case for --evtx-full) every record entered the store with no user at all.
    """
    from adapters import evtx_evtxecmd as a
    from analytics import normalize

    payload = json.dumps({"EventData": {"Data": [
        {"@Name": "Image", "#text": "C:\\Windows\\Temp\\x.exe"},
        {"@Name": "User", "#text": "CORP\\bouss"},
        {"@Name": "Hashes", "#text": "SHA1=8A48,MD5=33FA55,SHA256=0AF6B3F8AA,"
                                     "IMPHASH=98526F50539626C2E9C93297FE2AF83B"},
    ]}})
    r = a._record_from_evtxecmd({
        "EventId": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "TimeCreated": "2020-10-05T20:43:58.3517448+00:00", "Computer": "WS-11",
        "UserName": "CORP\\bouss", "Payload": payload})

    assert r["file.hash"] == "0AF6B3F8AA", r.get("file.hash")
    assert r["file.hash.md5"] == "33FA55", r.get("file.hash.md5")
    # The imphash must appear in NEITHER hash field, under any canonicalisation.
    imphash = "98526f50539626c2e9c93297fe2af83b"
    assert normalize.canon_hash(r["file.hash"]) != imphash, r["file.hash"]
    assert normalize.canon_hash(r.get("file.hash.md5")) != imphash, r.get("file.hash.md5")
    assert r["user.name"] == "CORP\\bouss", r.get("user.name")

    # A bare hash (the plain `Hash` field of some EVTX events) still passes straight through.
    assert a._hashes("0AF6B3F8AA") == ("0AF6B3F8AA", None)
    assert a._hashes(None) == (None, None)
    assert a._hashes("") == (None, None)
    # SHA1 only, no SHA256: better than nothing, and still not the imphash.
    assert a._hashes("SHA1=ABC,IMPHASH=DEF") == ("ABC", None)
    print("PASS  Sysmon hashes split correctly (never the imphash) and the user survives")


def run() -> int:
    run_sysmon_hashes_and_user()
    from adapters import evtx_evtxecmd
    from engine import evtxecmd_runner

    run_synthetic()

    sample = ROOT / ".tools" / "EVTX-ATTACK-SAMPLES" / SAMPLE_REL
    if not sample.exists():
        return skip_test(f"end-to-end ({SAMPLE_REL} missing in .tools/)")
    if not evtxecmd_runner.dotnet_available():
        return skip_test("end-to-end (`dotnet` missing from PATH)")
    try:
        evtxecmd_runner.find_dll()
    except FileNotFoundError:
        return skip_test("end-to-end (EvtxECmd.dll missing from .tools/evtxecmd/)")

    with tempfile.TemporaryDirectory() as td:
        out = evtxecmd_runner.run_evtxecmd(sample, td)
        recs = evtx_evtxecmd.load_records(out)

    assert recs, "no records from EvtxECmd"
    assert all(r["event.source"] == "evtx_full" for r in recs), "source not evtx_full"
    logons = [r for r in recs if r.get("event.code") == 4624]
    assert logons, "no 4624 in stream"
    assert any(r.get("logon.type") == "3" for r in logons), "logon.type 3 not extracted"
    assert any(r.get("source.ip") == "10.0.2.17" for r in recs), "expected source IP not found"
    print(f"PASS  {SAMPLE_REL}: {len(recs)} full-stream events ({len(logons)} × 4624)")
    return 0


def test_evtxecmd():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
