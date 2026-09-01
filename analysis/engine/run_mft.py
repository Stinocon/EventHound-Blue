"""CLI: NTFS $MFT (via MFTECmd) -> analytics (via mft_mftecmd adapter + DuckDB).

Normalizes every FILE record in the MFT to the common schema and runs the same correlation as
the other engines, so an MFT-listed file/path lines up with EVTX (suspicious creation), registry
(file-based persistence) and PCAP (executable downloads) evidence. Useful standalone (no AI).

Goes through `analytics.runner.build_records(mft=...)` — the same road every other source takes —
rather than calling `adapters.mft_mftecmd` or `engine.mftcmd_runner` directly, so MFT records land
in the same schema, store and correlation as everything else instead of being a dead end reachable
only from the test suite.

Usage:
    uv run python -m engine.run_mft '$MFT'
    uv run python -m engine.run_mft '$MFT' another_host.mft --json-out out.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import runner  # noqa: E402
from engine import mftcmd_runner  # noqa: E402
from engine.cli_json import warn_if_deprecated_json_flag  # noqa: E402

# Attack payload extensions worth calling out among MFT hits — a small, static list (not a new
# schema field: `file.extension` already carries this, this just filters/labels it for the
# terminal summary).
_EXEC_EXTENSIONS = {
    "exe", "dll", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta", "scr", "msi", "com",
}

# Directories the suite already treats as attacker staging/persistence targets elsewhere
# (`adapters.registry_regfile._IOC_RUN_APPDATA_RE` / `_IOC_RUN_TEMP_RE` flag Run-key binaries
# launched from these paths). Here the same directories flag *any* MFT hit under them — an
# interesting file doesn't need an execution record to be worth a look, and a deleted one
# (`mft.is_deleted`) is often the more interesting case.
_SUSPICIOUS_DIR_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\programdata\\",
    "\\windows\\tasks\\",
    "\\users\\public\\",
    "$recycle.bin",
)


def _is_suspicious_path(path: str | None) -> bool:
    p = (path or "").lower()
    return any(marker in p for marker in _SUSPICIOUS_DIR_MARKERS)


def _fmt_file(r: dict) -> str:
    """One line per file: timestamp, path (or bare name if the adapter had no path), size, flags.

    Never the full local disk path of the host running this CLI — only `file.path`/`file.name` as
    MFTECmd reported them off the imaged volume, which is evidence, not a local filesystem leak."""
    ts = r.get("@timestamp") or r.get("mft.timestamp_modified") or "?"
    path = r.get("file.path") or r.get("file.name") or "?"
    size = r.get("file.size")
    size_s = f"  {size}B" if size is not None else ""
    deleted = "  [DELETED]" if r.get("mft.is_deleted") else ""
    return f"   {ts}  {path}{size_s}{deleted}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Analytics on an NTFS $MFT (via MFTECmd).")
    ap.add_argument("mft", nargs="+", help="one or more $MFT files (NTFS Master File Table)")
    ap.add_argument("--json-out", dest="json_out", help="write full output as JSON to PATH")
    ap.add_argument("--json", dest="json_out", help=argparse.SUPPRESS)  # deprecated alias, same dest
    ap.add_argument("--top", type=int, default=15, help="rows per section in terminal")
    args = ap.parse_args(argv)
    warn_if_deprecated_json_flag(argv)

    for p in args.mft:
        if not Path(p).exists():
            print(f"error: file not found: {p}", file=sys.stderr)
            return 2

    # Degrade honestly rather than let build_records swallow a per-file FileNotFoundError into a
    # generic "skipped" line: this names exactly what to install and stops before wasting a
    # MFTECmd invocation attempt on every file. `dotnet_available()`/`find_dll()` are the same
    # checks mftcmd_runner.run() makes internally — checked here first so the message is specific
    # instead of "0 records produced" with no clue why.
    if not mftcmd_runner.dotnet_available():
        print("error: `dotnet` not found in PATH — MFTECmd requires the .NET runtime "
              "(see analysis/README.md for install steps).", file=sys.stderr)
        return 1
    try:
        mftcmd_runner.find_dll()
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    errors: list[str] = []
    records = runner.build_records(mft=args.mft, errors=errors)
    for err in errors:
        print(f"   ! skipped — {err}", file=sys.stderr)
    if not records:
        print("No MFT records produced (parse failure or an empty/unsupported $MFT?).", file=sys.stderr)
        return 1

    result = runner.analyze(records)
    s = result["summary"]
    print(f"Files: {s['events']} | live + deleted, see mft.is_deleted per record\n")

    files = [r for r in result.get("records", []) if not r.get("mft.is_directory")]

    def show(title: str, rows: list[dict]):
        if not rows:
            return
        print(f"== {title} ({len(rows)}) ==")
        for r in rows[:args.top]:
            print(_fmt_file(r))
        print()

    recent = sorted(files, key=lambda r: r.get("@timestamp") or "", reverse=True)
    show("Recent files (by created/modified timestamp)", recent)

    suspicious = [r for r in files if _is_suspicious_path(r.get("file.path"))]
    show("Files in suspicious directories", suspicious)

    executables = [r for r in files if (r.get("file.extension") or "").lower() in _EXEC_EXTENSIONS]
    show("Executables and scripts", executables)

    inds = result.get("shared_indicators", [])
    if inds:
        print(f"== Cross-source indicators ({len(inds)}) ==")
        for r in inds[:args.top]:
            print("   " + " | ".join(f"{k}={v}" for k, v in r.items() if v is not None))
        print()

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON: {args.json_out}")
        print("Remember: MFT records carry real file paths/names off the imaged host — "
              "anonymize before sharing (§9); never commit the JSON.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
