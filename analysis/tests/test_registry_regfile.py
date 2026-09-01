"""Test of Registry .reg file adapter (adapters/registry_regfile).

- run_synthetic(): Always run. .reg parsing, ASEP classification, IOC extraction,
  schema, encoding detection, robustness on malformed input.
- run(): entry point that calls run_synthetic().

    uv run python tests/test_registry_regfile.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Synthetic .reg fixtures (anonymous, no real data)
# ---------------------------------------------------------------------------

SAMPLE_REG_BASIC = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"SecurityHealth"="C:\\Program Files\\Windows Defender\\MSASCuiL.exe"
"VBoxGuest"="C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxTray.exe"
"""

SAMPLE_REG_SERVICE = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DummySvc]
"ImagePath"=hex(2):43,00,3a,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,74,00,65,00,73,00,74,00,2e,00,65,00,78,00,65,00,00,00
"Start"=dword:00000002
"""

SAMPLE_REG_IFEO_IOC = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe]
"Debugger"="C:\\Windows\\System32\\cmd.exe"
"""

SAMPLE_REG_DELETE = r"""Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\EvilKey]
"""

SAMPLE_REG_NON_ASEP = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework]
"InstallRoot"="C:\\Windows\\Microsoft.NET\\Framework64"
"""

SAMPLE_REG_MULTILINE_HEX = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TestKey]
"BinaryVal"=hex:01,00,00,00,\
  02,00,00,00,\
  03,00
"""

SAMPLE_REG_MALFORMED = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Test]
not-a-value-line
another-junk
;"commented out"=somevalue
"GoodKey"="clean"
"""

SAMPLE_REG_EMPTY = r""""""

SAMPLE_REG_ONLY_COMMENTS = r"""; this is a comment
// this is also a comment
Windows Registry Editor Version 5.00

; empty aside from comments
"""

SAMPLE_REG_REGEDIT4 = r"""REGEDIT4

[HKEY_CURRENT_USER\Software\Test]
"val"="data"
"""

SAMPLE_REG_DELETED_VALUE = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"EvilEntry"=-
"""

SAMPLE_REG_UTF16_RAW = (
    b"\xff\xfe"
    + "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Test]\r\n\"Val\"=\"data\"\r\n".encode(
        "utf-16-le"
    )
)


# ---------------------------------------------------------------------------
# Synthetic tests (always runnable)
# ---------------------------------------------------------------------------


def run_synthetic() -> None:
    from adapters import registry_regfile as a

    # --- 1. Basic parse: correct record count ---
    records = a.parse_regfile(SAMPLE_REG_BASIC)
    assert len(records) == 2, f"expected 2 records, got {len(records)}"

    # --- 2. ASEP classification: Run key → "User ASEP - Run" ---
    run_descriptions = [r["rule.description"] for r in records]
    assert all(d == "User ASEP - Run" for d in run_descriptions), (
        f"expected User ASEP - Run, got {run_descriptions}"
    )

    # --- 3. ASEP classification: Services key → contains "Services" ---
    svc_records = a.parse_regfile(SAMPLE_REG_SERVICE)
    assert len(svc_records) == 2, f"expected 2 service records, got {len(svc_records)}"
    for r in svc_records:
        assert "Services" in r["rule.description"], (
            f"expected Services in rule.description, got {r['rule.description']}"
        )

    # --- 4. ASEP classification: IFEO Debugger ---
    ifeo_records = a.parse_regfile(SAMPLE_REG_IFEO_IOC)
    assert len(ifeo_records) == 1, f"expected 1 IFEO record, got {len(ifeo_records)}"
    assert "IFEO" in ifeo_records[0]["rule.description"], (
        f"expected IFEO in rule.description, got {ifeo_records[0]['rule.description']}"
    )

    # --- 5. Non-ASEP key → rule.description is None ---
    non_asep_records = a.parse_regfile(SAMPLE_REG_NON_ASEP)
    assert len(non_asep_records) == 1
    assert non_asep_records[0].get("rule.description") is None, (
        "non-ASEP key should not have rule.description"
    )
    assert non_asep_records[0]["event.action"] == "registry-read", (
        "non-ASEP key should have event.action = registry-read"
    )

    # --- 6. Deleted key → event.action = "registry-delete" ---
    del_records = a.parse_regfile(SAMPLE_REG_DELETE)
    assert len(del_records) == 1, f"expected 1 deleted-key record, got {len(del_records)}"
    assert del_records[0]["event.action"] == "registry-delete"

    # Deleted value
    del_val_records = a.parse_regfile(SAMPLE_REG_DELETED_VALUE)
    assert len(del_val_records) == 1
    assert del_val_records[0]["event.action"] == "registry-delete"
    assert del_val_records[0].get("rule.description") is None  # value is gone

    # --- 7. IOC extraction: IFEO debugger pointing to cmd.exe ---
    ifeo = ifeo_records[0]
    assert "ioc.severity" in ifeo, "IFEO record should have ioc.severity"
    assert ifeo["ioc.severity"] in ("low", "medium", "high"), (
        f"unexpected severity: {ifeo['ioc.severity']}"
    )
    assert "cmd.exe" in ifeo.get("ioc.description", ""), (
        f"unexpected ioc.description: {ifeo.get('ioc.description')}"
    )

    # --- 8. Non-suspicious entry → no IOC ---
    for r in records:
        assert r.get("ioc.description") is None, (
            f"expected no IOC for clean entry: {r.get('ioc.description')}"
        )
    for r in svc_records:
        assert r.get("ioc.description") is None, (
            f"expected no IOC for clean service entry: {r.get('ioc.description')}"
        )

    # --- 9. Record schema: required fields present ---
    for r in records:
        assert "@timestamp" in r, "missing @timestamp"
        assert r["event.source"] == "registry", f"bad event.source: {r['event.source']}"
        assert "registry.key" in r, "missing registry.key"
        assert "registry.hive" in r, "missing registry.hive"
        assert "registry.type" in r, "missing registry.type"
        assert "message" in r, "missing message"

    # --- 10. Hive guessing: SOFTWARE ---
    for r in records:
        assert r["registry.hive"] == "SOFTWARE", (
            f"expected SOFTWARE hive, got {r['registry.hive']}"
        )

    # --- 11. Hive guessing: SYSTEM ---
    for r in svc_records:
        assert r["registry.hive"] == "SYSTEM", (
            f"expected SYSTEM hive, got {r['registry.hive']}"
        )

    # --- 12. UTF-16LE BOM content ---
    utf16_content = a._detect_encoding(SAMPLE_REG_UTF16_RAW)
    utf16_records = a.parse_regfile(utf16_content)
    assert len(utf16_records) == 1, (
        f"expected 1 record from UTF-16LE, got {len(utf16_records)}"
    )
    assert utf16_records[0]["registry.value"] == "Val"
    assert utf16_records[0]["registry.data"] == "data"

    # --- 13. Malformed lines: skip without error ---
    mal_records = a.parse_regfile(SAMPLE_REG_MALFORMED)
    assert len(mal_records) == 1, (
        f"expected 1 record from malformed .reg, got {len(mal_records)}"
    )
    assert mal_records[0]["registry.value"] == "GoodKey"

    # --- 14. Empty file → empty list ---
    assert a.parse_regfile(SAMPLE_REG_EMPTY) == []
    assert a.parse_regfile(SAMPLE_REG_ONLY_COMMENTS) == []

    # --- Multiline hex continuation ---
    ml_records = a.parse_regfile(SAMPLE_REG_MULTILINE_HEX)
    assert len(ml_records) == 1, (
        f"expected 1 record from multiline hex, got {len(ml_records)}"
    )
    assert ml_records[0]["registry.value"] == "BinaryVal"
    assert ml_records[0]["registry.type"] == "REG_BINARY"
    assert "01,00,00,00,02,00,00,00,03,00" in ml_records[0]["registry.data"]

    # --- REGEDIT4 header (older format) ---
    regedit4_records = a.parse_regfile(SAMPLE_REG_REGEDIT4)
    assert len(regedit4_records) == 1, (
        f"expected 1 record from REGEDIT4, got {len(regedit4_records)}"
    )
    assert regedit4_records[0]["registry.value"] == "val"

    # --- _classify_key (same contract as registry_recmd) ---
    assert a._classify_key(r"Software\Microsoft\Windows\CurrentVersion\Run") == "User ASEP - Run"
    assert a._classify_key(r"System\CurrentControlSet\Services\Foo") == "Services"
    assert a._classify_key(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") == "Winlogon"
    assert (
        a._classify_key(
            r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
        )
        == "IFEO Debugger"
    )
    assert a._classify_key(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Foo") is None
    # Case-insensitive
    assert a._classify_key(r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN") == "User ASEP - Run"
    # Non-string
    assert a._classify_key(None) is None
    assert a._classify_key(123) is None  # type: ignore[arg-type]

    # --- _guess_hive ---
    assert a._guess_hive(r"System\CurrentControlSet\Services") == "SYSTEM"
    assert a._guess_hive(r"Software\Microsoft\Windows\CurrentVersion\Run") == "SOFTWARE"
    assert a._guess_hive(r"ControlSet001\Services") == "SYSTEM"
    # HKEY-prefixed paths
    assert (
        a._guess_hive(r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run")
        == "SOFTWARE"
    )
    assert (
        a._guess_hive(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services")
        == "SYSTEM"
    )

    # --- _norm_reg_type ---
    assert a._norm_reg_type(None) == "REG_SZ"
    assert a._norm_reg_type("") == "REG_SZ"
    assert a._norm_reg_type("dword") == "REG_DWORD"
    assert a._norm_reg_type("hex") == "REG_BINARY"
    assert a._norm_reg_type("hex(2)") == "REG_EXPAND_SZ"
    assert a._norm_reg_type("hex(7)") == "REG_MULTI_SZ"
    assert a._norm_reg_type("expand_sz") == "REG_EXPAND_SZ"
    assert a._norm_reg_type("multi_sz") == "REG_MULTI_SZ"
    assert a._norm_reg_type("binary") == "REG_BINARY"
    assert a._norm_reg_type("hex(0)") == "REG_NONE"
    assert a._norm_reg_type("hex(4)") == "REG_DWORD"
    assert a._norm_reg_type("hex(99)") == "REG_BINARY"  # unknown → fallback

    # --- 15. load_records() with a temp file (end-to-end) ---
    with tempfile.TemporaryDirectory() as td:
        fpath = Path(td) / "test.reg"
        fpath.write_text(SAMPLE_REG_BASIC, encoding="utf-8")
        loaded = a.load_records(fpath)
        assert len(loaded) == 2, f"expected 2 records from load_records, got {len(loaded)}"
        descriptions = [r["rule.description"] for r in loaded]
        assert all(d == "User ASEP - Run" for d in descriptions)

    # --- load_records with UTF-16LE file ---
    with tempfile.TemporaryDirectory() as td:
        fpath = Path(td) / "utf16.reg"
        fpath.write_bytes(SAMPLE_REG_UTF16_RAW)
        loaded = a.load_records(fpath)
        assert len(loaded) == 1, (
            f"expected 1 record from UTF-16LE load_records, got {len(loaded)}"
        )

    # --- Persistence vs. registry-read action ---
    for r in records:
        assert r["event.action"] == "persistence", (
            f"expected persistence, got {r['event.action']}"
        )
    for r in non_asep_records:
        assert r["event.action"] == "registry-read", (
            f"expected registry-read, got {r['event.action']}"
        )

    # --- _check_ioc with known pattern ---
    ioc_desc, ioc_sev = a._check_ioc(
        r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe",
        "Debugger",
        "C:\\Windows\\System32\\cmd.exe",
        None,
    )
    assert ioc_desc is not None, "expected IOC for cmd.exe IFEO debugger"
    assert ioc_sev in ("low", "medium", "high")

    # No IOC for clean entry
    clean_ioc_desc, clean_ioc_sev = a._check_ioc(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "SecurityHealth",
        "C:\\Program Files\\Windows Defender\\MSASCuiL.exe",
        None,
    )
    assert clean_ioc_desc is None, f"unexpected IOC: {clean_ioc_desc}"

    print("PASS  registry .reg mapping (synthetic, always run)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_observed_at() -> None:
    """A .reg export carries no timestamp, so the adapter has to supply one. It used to supply
    now(), which is both untrue and unstable: two analyses of the same file disagreed, and
    re-opening a six-month-old case moved its persistence entries to the current date. The
    observation time is the export's mtime — real, and the same on every run."""
    import os
    from datetime import datetime, timezone

    from adapters import registry_regfile

    content = (
        "Windows Registry Editor Version 5.00\r\n\r\n"
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
        '"Updater"="C:\\\\ProgramData\\\\svc-update.exe"\r\n'
    )
    tmp = Path(tempfile.mkdtemp())
    try:
        reg = tmp / "persistence.reg"
        reg.write_text(content, encoding="utf-8")
        # An export taken well in the past: the records must say so, not say "today".
        past = datetime(2026, 3, 12, 9, 40, 0, tzinfo=timezone.utc)
        os.utime(reg, (past.timestamp(), past.timestamp()))

        first = registry_regfile.load_records(reg)
        second = registry_regfile.load_records(reg)
        assert first, "no records parsed"
        stamps = {r.get("@timestamp") for r in first}
        assert stamps == {"2026-03-12T09:40:00Z"}, stamps
        assert [r.get("@timestamp") for r in first] == [r.get("@timestamp") for r in second], \
            "two reads of the same export disagree on when it was observed"
        # The record still says what it is: a state observation, not an event at that instant.
        assert all(r.get("event.kind") == "state" for r in first), first[0]
        print("PASS  registry .reg observed_at: export mtime, stable across runs")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def run_indicators() -> None:
    """The indicator layer, which was entirely dead until 2026-08-30.

    Both path patterns ended in `\\.exe` — a literal backslash, ANY character, then "exe", not an
    escaped dot — so they required a path shaped `...\\<char>exe` that no real value has. Neither
    had ever matched. `_norm_reg_type` compounded it: handed an already-standard `REG_SZ` it fell
    through to the REG_BINARY fallback, and `_check_ioc` only inspects string types, so passing the
    CORRECT type name switched the whole layer off.

    The cost was visible in the product's own demo and nobody could see it: a Run key and a service
    ImagePath both pointing at C:\\Windows\\Temp\\svcupdate.exe — the persistence of the
    simulated intrusion — carried no indicator at all. A dead rule is worse than a missing one; it
    says "nothing suspicious" in the same voice it would use for a clean key.
    """
    from adapters import registry_regfile

    RUN = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    SVC = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\evil"

    # A standard type name must survive normalization, or the indicator layer never runs.
    assert registry_regfile._norm_reg_type("REG_SZ") == "REG_SZ"
    assert registry_regfile._norm_reg_type("REG_expand_sz") == "REG_EXPAND_SZ"
    assert registry_regfile._norm_reg_type("dword") == "REG_DWORD"      # short form still works
    assert registry_regfile._norm_reg_type("hex(2)") == "REG_EXPAND_SZ"  # numeric form still works
    assert registry_regfile._norm_reg_type(None) == "REG_SZ"
    assert registry_regfile._norm_reg_type("junk") == "REG_BINARY"       # fallback unchanged

    def ioc(key, name, data, typ="REG_SZ"):
        return registry_regfile._check_ioc(key, name, data, typ)

    # The three Temp spellings that matter. C:\Windows\Temp is where a dropped binary actually
    # sits and is exactly the one the old service pattern (`%TEMP%|C:\Temp`) missed.
    for data in (r"C:\Windows\Temp\svcupdate.exe", r"C:\Temp\a.exe", r"D:\Temp\a.dll"):
        desc, sev = ioc(RUN, "Updater", data)
        assert sev == "high", (data, desc, sev)
        assert "Temp" in (desc or ""), (data, desc)
    desc, sev = ioc(SVC, "ImagePath", r"C:\Windows\Temp\svcupdate.exe")
    assert sev == "high" and "Temp" in (desc or ""), (desc, sev)

    # AppData is the lower-severity neighbour and must still be reached, and must not be
    # swallowed by the Temp rule when the path is AppData\Local\Temp (Run checks AppData first).
    desc, sev = ioc(RUN, "x", r"C:\Users\rossi\AppData\Roaming\x.exe")
    assert sev == "medium" and "AppData" in (desc or ""), (desc, sev)

    # And the other half of a detection rule: what it must NOT say.
    for clean in (r"C:\Program Files\Windows Defender\MSASCuiL.exe",
                  r"C:\Windows\System32\svchost.exe"):
        assert ioc(RUN, "SecurityHealth", clean) == (None, None), clean
        assert ioc(SVC, "ImagePath", clean) == (None, None), clean
    # A key that is not an ASEP is not annotated whatever its data says.
    assert ioc(r"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\App", "Path",
               r"C:\Windows\Temp\x.exe") == (None, None)

    # regedit writes REG_EXPAND_SZ as hex(2): UTF-16LE. The raw hex used to reach _check_ioc as
    # "43,00,3a,00,…", so a persistence value stored that way never matched anything. After
    # decoding, a Temp service ImagePath written as an expandable string fires like its plain
    # REG_SZ twin.
    hex_temp = r"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SvcUpdate]
"ImagePath"=hex(2):43,00,3a,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,00,54,00,65,00,6d,00,70,00,5c,00,73,00,76,00,63,00,75,00,70,00,64,00,61,00,74,00,65,00,2e,00,65,00,78,00,65,00,00,00
"""
    from adapters import registry_regfile
    recs = registry_regfile.parse_regfile(hex_temp)
    svc = next(r for r in recs if r.get("registry.value") == "ImagePath")
    assert svc["registry.data"] == r"C:\Windows\Temp\svcupdate.exe", svc["registry.data"]
    assert svc["registry.type"] == "REG_EXPAND_SZ", svc["registry.type"]
    assert svc["ioc.severity"] == "high", svc
    assert "Temp" in svc["ioc.description"], svc
    print("PASS  registry indicators fire on a hex(2) (REG_EXPAND_SZ) Temp path")
    print("PASS  registry indicators fire on Temp/AppData, stay silent on clean paths")


def run() -> int:
    run_synthetic()
    run_observed_at()
    run_indicators()
    return 0


def test_registry_regfile():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
