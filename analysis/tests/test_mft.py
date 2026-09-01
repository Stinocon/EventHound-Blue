"""Test of MFTECmd adapter (adapters/mft_mftecmd) and its CLI (engine/run_mft).

- run_synthetic(): Always run. MFTECmd record parsing → common schema,
  timestamp extraction 0x10/0x30, sizes, attributes, path.
- run_cli(): Always run. `engine.run_mft` argument parsing and its missing-tool path — the
  latter forced via a stripped PATH (subprocess), not skipped, so it is exercised on every
  machine regardless of whether dotnet actually happens to be installed here.
- run(): end-to-end on $MFT via `dotnet` (auto-skip without dotnet/dll/MFT).

    uv run python tests/test_mft.py
"""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests._helpers import skip_test, subprocess_env  # noqa: E402

# --- Synthetic fixtures ---

SYNTH_FILE = {
    "EntryNumber": 12345,
    "SequenceNumber": 1,
    "ParentEntryNumber": 7890,
    "FileName": "malware",
    "Extension": "exe",
    "FullPath": r"\Windows\Temp\malware.exe",
    "Created0x10": "2024-03-15 10:30:00.1234567",
    "LastModified0x10": "2024-03-15 10:30:05.0000000",
    "LastAccess0x10": "2024-03-15 10:30:00.0000000",
    "LastRecordChange0x10": "2024-03-15 10:30:05.0000000",
    "Created0x30": "2024-03-15 10:30:00.1234567",
    "LastModified0x30": "2024-03-15 10:30:05.0000000",
    "LastAccess0x30": "2024-03-15 10:30:00.0000000",
    "LastRecordChange0x30": "2024-03-15 10:30:05.0000000",
    "FileSize": 204800,
    "AllocatedSize": 212992,
    "Attributes": 32,
    "IsDirectory": False,
    "IsDeleted": False,
}

SYNTH_DIR = {
    "EntryNumber": 56789,
    "SequenceNumber": 2,
    "ParentEntryNumber": 5,
    "FileName": "Temp",
    "Extension": "",
    "FullPath": r"\Windows\Temp",
    "Created0x10": "2024-01-01 00:00:00.0000000",
    "LastModified0x10": "2024-03-01 12:00:00.0000000",
    "FileSize": 0,
    "AllocatedSize": 0,
    "Attributes": 48,
    "IsDirectory": True,
    "IsDeleted": False,
}

SYNTH_DELETED_FILE = {
    "EntryNumber": 99999,
    "SequenceNumber": 3,
    "ParentEntryNumber": 7890,
    "FileName": "dropper.ps1",
    "Extension": "ps1",
    "FullPath": r"\Users\victim\AppData\Local\Temp\dropper.ps1",
    "Created0x10": "2024-03-15 14:00:00.0000000",
    "LastModified0x10": "2024-03-15 14:00:00.0000000",
    "FileSize": 4096,
    "AllocatedSize": 0,
    "Attributes": 32,
    "IsDirectory": False,
    "IsDeleted": True,
}

SYNTH_MINIMAL = {
    "EntryNumber": 1,
    "FileName": "README.txt",
    "FileSize": 1024,
    "IsDirectory": False,
}


def run_synthetic() -> None:
    from adapters import mft_mftecmd as a

    # --- _record_from_mftecmd ---
    r = a._record_from_mftecmd(SYNTH_FILE)
    assert r is not None
    assert r["event.source"] == "mft"
    assert r["event.category"] == "file"
    assert r["event.action"] == "file-metadata"
    assert r["file.name"] == "malware.exe"
    assert r["file.path"] == r"\Windows\Temp\malware.exe"
    assert r["file.extension"] == "exe"
    assert r["file.size"] == 204800
    assert r["file.allocated_size"] == 212992
    assert r["mft.entry"] == 12345
    assert r["mft.sequence"] == 1
    assert r["mft.parent_entry"] == 7890
    assert r["mft.is_directory"] is False
    assert r["mft.is_deleted"] is False
    # Main timestamp = created. MFTECmd writes `yyyy-MM-dd HH:mm:ss.fffffff`; the normalizer
    # converts it to ISO-8601 (`T` separator, six-digit fraction, `Z`). The old assertion pinned the
    # BUG — `…10:30:00.1234567Z`, a space separator and a 7-digit fraction that is not ISO-8601.
    assert r["@timestamp"] == "2024-03-15T10:30:00.123456Z"
    assert r["mft.timestamp_modified"] == "2024-03-15T10:30:05.000000Z"
    assert r["mft.timestamp_accessed"] == "2024-03-15T10:30:00.000000Z"
    assert r["mft.timestamp_changed"] == "2024-03-15T10:30:05.000000Z"

    # Directory
    r2 = a._record_from_mftecmd(SYNTH_DIR)
    assert r2 is not None
    assert r2["file.name"] == "Temp"
    assert r2["file.path"] == r"\Windows\Temp"
    assert r2["mft.is_directory"] is True
    assert r2["file.size"] == 0
    assert "file.extension" not in r2 or r2["file.extension"] == ""

    # Deleted file
    r3 = a._record_from_mftecmd(SYNTH_DELETED_FILE)
    assert r3 is not None
    assert r3["file.name"] == "dropper.ps1"
    assert r3["file.extension"] == "ps1"
    assert r3["mft.is_deleted"] is True
    assert r3["mft.timestamp_modified"] == "2024-03-15T14:00:00.000000Z"

    # Minimal record (only entry + filename, no timestamp)
    r4 = a._record_from_mftecmd(SYNTH_MINIMAL)
    assert r4 is not None
    assert r4["file.name"] == "README.txt"
    assert r4["file.size"] == 1024
    # Without timestamp, @timestamp must not be present
    assert "@timestamp" not in r4

    # Empty record → None (no entry, no filename)
    assert a._record_from_mftecmd({}) is None
    assert a._record_from_mftecmd({"Unknown": "data"}) is None

    # --- _ts_field ---
    d = {"Created0x10": "2024-01-01 00:00:00.0000000", "LastModified0x30": "2024-02-01 00:00:00.0000000"}
    assert a._ts_field(d, "0x10", "Created") == "2024-01-01T00:00:00.000000Z"
    assert a._ts_field(d, "0x30", "LastModified") == "2024-02-01T00:00:00.000000Z"
    assert a._ts_field(d, "0x30", "Created") is None

    # --- _norm_ts (shared: ez_json.norm_ez_ts) ---
    assert a._norm_ts("2024-03-15 10:30:00.1234567") == "2024-03-15T10:30:00.123456Z"
    assert a._norm_ts("2024-03-15T10:30:00.1234567Z") == "2024-03-15T10:30:00.123456Z"
    assert a._norm_ts("2024-03-15T10:30:00Z") == "2024-03-15T10:30:00Z"
    assert a._norm_ts(None) is None

    # --- load_records con array JSON ---
    with tempfile.TemporaryDirectory() as td:
        json_file = Path(td) / "mft_output.json"
        json_file.write_text(json.dumps([SYNTH_FILE, SYNTH_DIR, SYNTH_DELETED_FILE]), encoding="utf-8")
        loaded = a.load_records(td)
        assert len(loaded) == 3
        sources = set(r["event.source"] for r in loaded)
        assert sources == {"mft"}
        names = [r["file.name"] for r in loaded]
        assert "malware.exe" in names
        assert "Temp" in names
        assert "dropper.ps1" in names

    # --- load_records with dict + "Data" ---
    with tempfile.TemporaryDirectory() as td:
        json_file = Path(td) / "mft_data.json"
        json_file.write_text(json.dumps({"Data": [SYNTH_FILE, SYNTH_MINIMAL]}), encoding="utf-8")
        loaded = a.load_records(td)
        assert len(loaded) == 2

    # --- load_records with BOM ---
    with tempfile.TemporaryDirectory() as td:
        json_file = Path(td) / "mft_bom.json"
        content = b"\xef\xbb\xbf" + json.dumps([SYNTH_FILE]).encode()
        json_file.write_bytes(content)
        loaded = a.load_records(td)
        assert len(loaded) == 1

    # --- load_records with malformed JSON ---
    with tempfile.TemporaryDirectory() as td:
        json_file = Path(td) / "bad.json"
        json_file.write_text("{bad json", encoding="utf-8")
        loaded = a.load_records(td)
        assert loaded == []

    # --- load_records empty directory ---
    with tempfile.TemporaryDirectory() as td:
        loaded = a.load_records(td)
        assert loaded == []

    print("PASS  mft mapping (synthetic, always run)")


def run_real_output_shape() -> None:
    """The shape MFTECmd actually writes, and the extension it actually reports.

    Both were wrong and neither was visible. MFTECmd writes NDJSON — one record per line
    (`sWrite.WriteLine(mftOutRecord.ToJson())`) — and the adapter called `json.load`, caught the
    resulting "Extra data" and skipped the whole file in silence: a real `$MFT` ingested as ZERO
    records with an empty `errors` list, so the report said "no suspicious files" because nothing
    had been read. The tests fed a hand-written ARRAY, the one shape the tool never produces, and
    the end-to-end test self-skips without a real $MFT, so nothing ever noticed.

    And `Extension` comes from .NET's `Path.GetExtension`, which INCLUDES the leading period, while
    `FileName` already ends in it — so the "append the extension if missing" guard asked whether the
    name ended in `..exe` and, finding it did not, produced `malware.exe..exe`. That is the artifact
    key the whole source exists to join on.
    """
    import json as _json
    import tempfile as _tempfile
    from adapters import mft_mftecmd

    ndjson = "\n".join(_json.dumps(r) for r in [
        {"EntryNumber": 1, "FileName": "malware.exe", "Extension": ".exe",
         "ParentPath": ".\\Windows\\Temp", "Created0x10": "2024-03-15T10:30:00.0000000+00:00"},
        {"EntryNumber": 2, "FileName": "noext", "Extension": "",
         "ParentPath": ".\\a", "Created0x10": "2024-03-15T10:31:00.0000000+00:00"},
        {"EntryNumber": 3, "FileName": "weird", "Extension": ".bin",
         "ParentPath": ".\\a", "Created0x10": "2024-03-15T10:32:00.0000000+00:00"},
    ])
    with _tempfile.TemporaryDirectory() as td:
        (Path(td) / "m.json").write_text(ndjson + "\n")
        recs = mft_mftecmd.load_records(td)
    assert len(recs) == 3, f"NDJSON must be read: got {len(recs)}"
    names = [r.get("file.name") for r in recs]
    assert names == ["malware.exe", "noext", "weird.bin"], names
    print("PASS  MFT reads MFTECmd's NDJSON, and an extension is not appended twice")


def run_cli() -> None:
    """`engine.run_mft` parses its arguments and degrades honestly when MFTECmd cannot run.

    The missing-tool path is forced with an emptied PATH rather than skipped when dotnet happens to
    be installed: it is the path most users will hit, and a branch that only runs on machines
    without the tool is a branch nobody tests. A traceback here would print the customer's file
    path (§9); the contract is a clear message and exit code 1.
    """
    from engine import run_mft

    # No source at all: argparse refuses with 2, never a traceback. Its usage text is swallowed so
    # the suite's own output does not read like a failure.
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            run_mft.main([])
    except SystemExit as e:
        assert e.code == 2, e.code
    else:
        raise AssertionError("run_mft accepted an empty command line")

    with tempfile.TemporaryDirectory(prefix="mft-cli-") as td:
        fake = Path(td) / "$MFT"
        fake.write_bytes(b"FILE0" + b"\x00" * 64)
        env = subprocess_env(ROOT, {"PATH": ""})     # dotnet unreachable, whatever the machine has
        proc = subprocess.run([sys.executable, "-m", "engine.run_mft", str(fake)],
                              cwd=str(ROOT), env=env, capture_output=True, text=True)
        assert proc.returncode == 1, (proc.returncode, proc.stdout[-400:], proc.stderr[-400:])
        out = (proc.stdout + proc.stderr).lower()
        assert "dotnet" in out or "mftecmd" in out, (proc.stdout[-400:], proc.stderr[-400:])
        assert "traceback" not in out, proc.stderr[-600:]
        # §9: the message must not carry the evidence path back out.
        assert str(fake) not in proc.stdout + proc.stderr, "the CLI echoed the evidence path"

    print("PASS  run_mft: argument parsing and the missing-tool path")


def run() -> int:
    run_real_output_shape()
    from engine import mftcmd_runner

    run_synthetic()
    run_cli()

    # End-to-end: skip without dotnet, dll or test MFT file
    if not mftcmd_runner.dotnet_available():
        return skip_test("end-to-end (`dotnet` missing from PATH)")
    try:
        mftcmd_runner.find_dll()
    except FileNotFoundError:
        return skip_test("end-to-end (MFTECmd.dll missing from .tools/mftcmd/)")

    # Test MFT not available in repository
    return skip_test("end-to-end (no $MFT test file in .tools/)")


def test_mft():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
