"""Wrapper around RECmd (Eric Zimmerman, .NET) — Windows Registry parser.

RECmd extracts all keys and values from a registry hive (SAM, SYSTEM, SOFTWARE,
NTUSER.DAT, USRCLASS.DAT). The JSON output is consumed by `adapters/registry_recmd`
which filters ASEP entries (Auto-Start Extension Points) for persistence detection.

The binary (`RECmd.dll`, .NET 9 build) lives in analysis/.tools/recmd/ (gitignored).
On this Mac it runs via `dotnet` with major roll-forward (runtime .NET 10 on .NET 9 build).
No network calls.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1] / ".tools"
RECMD_DIR = TOOLS_DIR / "recmd"


def dotnet_available() -> bool:
    return shutil.which("dotnet") is not None


def find_dll() -> Path:
    """Locate RECmd.dll under analysis/.tools/recmd/ (any subdirectory)."""
    hits = sorted(RECMD_DIR.glob("**/RECmd.dll"))
    if not hits:
        raise FileNotFoundError(
            f"RECmd.dll not found in {RECMD_DIR}. Download RECmd (.NET 9) from "
            f"ericzimmerman.github.io and extract it there (see analysis/README.md)."
        )
    return hits[0]


def run(hive_path: str | Path, out_dir: str | Path,
        out_name: str = "recmd.json") -> Path:
    """Run RECmd on a registry hive and return the path to the produced JSON.

    Uses ``--kn \\`` to dump ALL keys and values from the hive root.

    Requires `dotnet` in PATH. Uses DOTNET_ROLL_FORWARD=Major to run .NET 9 build on
    installed runtime. Output JSON contains an array of records with keys, values, and metadata."""
    if not dotnet_available():
        raise FileNotFoundError("`dotnet` not found in PATH: RECmd requires .NET runtime.")
    dll = find_dll()
    hive_path = Path(hive_path).resolve()
    out_dir = Path(out_dir).resolve()
    if not hive_path.exists():
        raise FileNotFoundError(f"hive not found: {hive_path}")
    out_dir.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ, DOTNET_ROLL_FORWARD="Major")
    cmd = [
        "dotnet", str(dll),
        "-f", str(hive_path),
        "--kn", "\\",          # dump from root
        "--json", str(out_dir),
        "--jsonf", out_name,
    ]
    # cwd = dll dir: so its Plugins/ resolves relative.
    subprocess.run(cmd, cwd=str(dll.parent), check=True, capture_output=True, text=True, env=env)
    return out_dir / out_name
