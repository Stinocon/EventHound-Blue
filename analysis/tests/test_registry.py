"""Test of RECmd Registry adapter (adapters/registry_recmd).

- run_synthetic(): Always run. ASEP paths classification, RECmd record parsing → schema,
  robustness on malformed input (non-array, broken lines, BOM), timestamp corner cases.
- run(): end-to-end on hive via `dotnet` (auto-skip without dotnet/dll/hive).

    uv run python tests/test_registry.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests._helpers import skip_test  # noqa: E402

# --- Synthetic fixtures for offline test ---

SYNTH_RUN_KEY = {
    "KeyPath": r"Software\Microsoft\Windows\CurrentVersion\Run",
    "ValueName": "MaliciousService",
    "ValueData": r"C:\Windows\system32\malware.exe",
    "LastWriteTimestamp": "2024-03-15 10:30:00.1234567",
}

SYNTH_SERVICE = {
    "KeyPath": r"System\CurrentControlSet\Services\MaliciousSvc",
    "ValueName": "ImagePath",
    "ValueData": r"C:\Windows\malware.exe",
    "LastWriteTimestamp": "2024-03-15 10:35:00.0000000",
}

SYNTH_WINLOGON = {
    "KeyPath": r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "ValueName": "Shell",
    "ValueData": "explorer.exe,evil.exe",
    "LastWriteTimestamp": "2024-03-15 11:00:00.0000000",
}

SYNTH_NON_ASEP = {
    "KeyPath": r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Foo",
    "ValueName": "DisplayName",
    "ValueData": "FooBar",
    "LastWriteTimestamp": "2024-03-15 12:00:00.0000000",
}

SYNTH_IFEO = {
    "KeyPath": r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
    "ValueName": "Debugger",
    "ValueData": r"C:\Windows\system32\cmd.exe",
    "LastWriteTimestamp": "2024-03-15 13:00:00.0000000",
}


def run_synthetic() -> None:
    from adapters import registry_recmd as a

    # --- _classify_key ---
    assert a._classify_key(r"Software\Microsoft\Windows\CurrentVersion\Run") == "User ASEP - Run"
    assert a._classify_key(r"System\CurrentControlSet\Services\Foo") == "Services"
    assert a._classify_key(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") == "Winlogon"
    assert a._classify_key(r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe") == "IFEO Debugger"
    assert a._classify_key(r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Foo") is None

    # Case-insensitive
    assert a._classify_key(r"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN") == "User ASEP - Run"

    # KeyPath non-string
    assert a._classify_key(None) is None
    assert a._classify_key(123) is None

    # --- _record_from_recmd ---
    r = a._record_from_recmd(SYNTH_RUN_KEY)
    assert r is not None, "run key should be ASEP"
    assert r["event.source"] == "registry"
    assert r["event.category"] == "configuration"
    assert r["event.action"] == "persistence"
    assert r["registry.key"] == SYNTH_RUN_KEY["KeyPath"]
    assert r["registry.value"] == "MaliciousService"
    assert r["registry.data"] == r"C:\Windows\system32\malware.exe"
    assert r["file.path"] == r"C:\Windows\system32\malware.exe", r
    assert r["rule.description"] == "User ASEP - Run"
    assert r["@timestamp"].endswith("Z"), f"timestamp not normalized: {r['@timestamp']}"

    r2 = a._record_from_recmd(SYNTH_SERVICE)
    assert r2 is not None
    assert r2["rule.description"] == "Services"
    # `ImagePath` holds the program; the artifact is what lets a hive bridge to the sources that
    # name the same binary.
    assert r2["file.path"] == r"C:\Windows\malware.exe", r2

    r3 = a._record_from_recmd(SYNTH_WINLOGON)
    assert r3 is not None
    assert r3["rule.description"] == "Winlogon"
    assert r3["registry.data"] == "explorer.exe,evil.exe"

    # Non-ASEP → None
    assert a._record_from_recmd(SYNTH_NON_ASEP) is None

    # IFEO
    r4 = a._record_from_recmd(SYNTH_IFEO)
    assert r4 is not None
    assert r4["rule.description"] == "IFEO Debugger"
    assert r4["registry.data"] == r"C:\Windows\system32\cmd.exe"
    assert r4["file.path"] == r"C:\Windows\system32\cmd.exe", r4

    # Timestamp missing → None
    no_ts = dict(SYNTH_RUN_KEY)
    no_ts["LastWriteTimestamp"] = None
    assert a._record_from_recmd(no_ts) is None

    # Empty record → None
    assert a._record_from_recmd({}) is None

    # --- _guess_hive ---
    assert a._guess_hive(r"System\CurrentControlSet\Services") == "SYSTEM"
    assert a._guess_hive(r"Software\Microsoft\Windows\CurrentVersion\Run") == "SOFTWARE"
    assert a._guess_hive(r"ControlSet001\Services") == "SYSTEM"

    # --- _norm_ts (shared: ez_json.norm_ez_ts) ---
    assert a._norm_ts("2024-03-15 10:30:00.1234567") == "2024-03-15T10:30:00.123456Z"
    assert a._norm_ts("2024-03-15T10:30:00.1234567Z") == "2024-03-15T10:30:00.123456Z"
    # An explicit offset is preserved so the store can convert it to UTC; the old normalizer
    # dropped it and appended Z, shifting a non-UTC value by its whole offset.
    assert a._norm_ts("2024-03-15 10:30:00+02:00") == "2024-03-15T10:30:00+02:00"
    assert a._norm_ts(None) is None
    assert a._norm_ts("") == ""

    # --- load_records with JSON array ---
    with tempfile.TemporaryDirectory() as td:
        json_file = Path(td) / "output.json"
        records = [SYNTH_RUN_KEY, SYNTH_NON_ASEP, SYNTH_SERVICE, SYNTH_IFEO]
        json_file.write_text(json.dumps(records), encoding="utf-8")

        loaded = a.load_records(td)
        # Only 3 ASEP (non-ASEP excluded)
        assert len(loaded) == 3, f"expected 3 ASEP, got {len(loaded)}"
        descriptions = [r["rule.description"] for r in loaded]
        assert "User ASEP - Run" in descriptions
        assert "Services" in descriptions
        assert "IFEO Debugger" in descriptions

    # --- load_records with dict + "Data" field ---
    with tempfile.TemporaryDirectory() as td:
        json_file = Path(td) / "output.json"
        data = {"Data": [SYNTH_RUN_KEY, SYNTH_SERVICE]}
        json_file.write_text(json.dumps(data), encoding="utf-8")

        loaded = a.load_records(td)
        assert len(loaded) == 2

    # --- load_records with BOM and broken line (JSON not line-delimited but single file) ---
    with tempfile.TemporaryDirectory() as td:
        json_file = Path(td) / "broken.json"
        # Write a proper array with BOM
        content = b"\xef\xbb\xbf" + json.dumps([SYNTH_RUN_KEY]).encode()
        json_file.write_bytes(content)

        loaded = a.load_records(td)
        assert len(loaded) == 1, f"BOM not handled: {len(loaded)} records"

    # --- NDJSON: what RECmd's batch mode (--bn) actually writes ---
    # This assertion used to read `assert len(loaded) == 0  # NDJSON unsupported`, which is the line
    # that made the defect permanent: it pinned the adapter's inability to read its own tool's
    # output as if it were a decision. json.load raised "Extra data", the caller caught it and
    # skipped the file in SILENCE, so a real hive ingested as zero records with an empty `errors`.
    with tempfile.TemporaryDirectory() as td:
        json_file = Path(td) / "lines.json"
        json_file.write_text(json.dumps(SYNTH_IFEO) + "\n" + json.dumps(SYNTH_WINLOGON))
        loaded = a.load_records(td)
        assert len(loaded) == 2, f"NDJSON must be read: got {len(loaded)}"

    # --- the nested SimpleKey document RECmd's --json mode writes ---
    # One key, its values inside it. Read flat it is a single key with no values, i.e. nothing:
    # the persistence lives in the values.
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "nested.json").write_text(json.dumps({
            "KeyPath": "ControlSet001\\Services\\MaliciousSvc",
            "KeyName": "MaliciousSvc",
            "LastWriteTimestamp": "2024-03-15T10:30:00+00:00",
            "Values": [{"ValueName": "ImagePath", "ValueType": "RegSz",
                        "ValueData": "C:\\Windows\\Temp\\svcupdate.exe"},
                       {"ValueName": "Start", "ValueType": "RegDword", "ValueData": "2"}],
            "SubKeys": [{"KeyPath": "ControlSet001\\Services\\MaliciousSvc\\Parameters",
                         "LastWriteTimestamp": "2024-03-15T10:30:00+00:00",
                         "Values": [{"ValueName": "ServiceDll", "ValueData": "C:\\Windows\\Temp\\x.dll"}]}],
        }))
        loaded = a.load_records(td, hive_name="SYSTEM")
        assert len(loaded) == 3, f"nested SimpleKey must flatten to one row per value: {len(loaded)}"
        got = {r["registry.value"]: r["registry.data"] for r in loaded}
        assert got["ImagePath"] == "C:\\Windows\\Temp\\svcupdate.exe", got
        assert got["ServiceDll"] == "C:\\Windows\\Temp\\x.dll", got  # SubKeys walked, not ignored
        # ControlSet001 is what an OFFLINE hive contains: CurrentControlSet is a boot-time symlink.
        # Every one of these classified as None before, and None means the record is discarded.
        assert all(r["rule.description"] == "Services" for r in loaded), loaded

    # --- load_records empty directory ---
    with tempfile.TemporaryDirectory() as td:
        loaded = a.load_records(td)
        assert loaded == []

    print("PASS  registry mapping (synthetic, always run)")


def run() -> int:
    from engine import recmd_runner

    run_synthetic()

    # End-to-end: skip without dotnet, dll or test hive file
    if not recmd_runner.dotnet_available():
        return skip_test("end-to-end (`dotnet` missing from PATH)")
    try:
        recmd_runner.find_dll()
    except FileNotFoundError:
        return skip_test("end-to-end (RECmd.dll missing from .tools/recmd/)")

    # Test hive: uses a minimal hive if available
    # For now skip — we don't have test hive in repository
    # Future: add minimal SAM/SOFTWARE to .tools/registry-samples/
    return skip_test("end-to-end (no test hive in .tools/)")


def test_registry():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
