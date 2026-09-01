"""Wrapper around MFTECmd (Eric Zimmerman, .NET) — $MFT parser (NTFS Master File Table).

MFTECmd extracts metadata of every file in an NTFS volume: name, path, timestamps (created,
modified, accessed, record change), size, attributes, parent directory.

The JSON output is consumed by `adapters.mft_mftecmd` which maps it to the common ECS schema
for correlation with EVTX and registry.

The binary (`MFTECmd.dll`, .NET 9 build) lives in analysis/.tools/mftcmd/ (gitignored).
On this Mac it runs via `dotnet` with major roll-forward (runtime .NET 10 on .NET 9 build).
No network calls.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1] / ".tools"
MFTCMD_DIR = TOOLS_DIR / "mftcmd"


def dotnet_available() -> bool:
    return shutil.which("dotnet") is not None


def find_dll() -> Path:
    """Locate MFTECmd.dll under analysis/.tools/mftcmd/ (any subdirectory)."""
    hits = sorted(MFTCMD_DIR.glob("**/MFTECmd.dll"))
    if not hits:
        raise FileNotFoundError(
            f"MFTECmd.dll not found in {MFTCMD_DIR}. Download MFTECmd (.NET 9) from "
            f"ericzimmerman.github.io and extract it there (see analysis/README.md)."
        )
    return hits[0]


def run(mft_path: str | Path, out_dir: str | Path,
        out_name: str = "mftecmd.json") -> Path:
    """Run MFTECmd on an $MFT file and return the path to the produced JSON.

    MFTECmd produces JSON for every FILE record in the MFT with complete metadata
    (names, timestamps, sizes, attributes).

    Requires `dotnet` in PATH. Uses DOTNET_ROLL_FORWARD=Major to run .NET 9 build on
    installed runtime."""
    if not dotnet_available():
        raise FileNotFoundError("`dotnet` not found in PATH: MFTECmd requires .NET runtime.")
    dll = find_dll()
    mft_path = Path(mft_path).resolve()
    out_dir = Path(out_dir).resolve()
    if not mft_path.exists():
        raise FileNotFoundError(f"$MFT not found: {mft_path}")
    out_dir.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ, DOTNET_ROLL_FORWARD="Major")
    cmd = [
        "dotnet", str(dll),
        "-f", str(mft_path),
        "--json", str(out_dir),
        "--jsonf", out_name,
    ]
    subprocess.run(cmd, cwd=str(dll.parent), check=True, capture_output=True, text=True, env=env)
    return out_dir / out_name
