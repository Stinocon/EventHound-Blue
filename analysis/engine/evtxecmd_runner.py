"""Wrapper around EvtxECmd (Eric Zimmerman, .NET) — full stream EVTX parser.

Unlike Hayabusa (Sigma + ATT&CK detection), EvtxECmd normalizes EVERY event with its "maps":
it is the source of the complete stream feeding long-tail analytics and correlation.

The binary (`EvtxECmd.dll`, .NET 9 build) lives in analysis/.tools/evtxecmd/ (gitignored).
On this Mac it runs via `dotnet` with major roll-forward (runtime .NET 10 on .NET 9 build —
verified at spike 2026-07-20). No network calls.

NOTE: EvtxECmd processes ONE file at a time (single `evtx_path`). Source tagging with
filename (e.g., ``f"evtx_full:{path.name}"``) is handled by the caller of
``evtx_evtxecmd.load_records()`` — the adapter accepts an optional ``source`` parameter.
The ``run_evtxecmd`` function here only produces the JSON output and does not tag records.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1] / ".tools"
EVTXECMD_DIR = TOOLS_DIR / "evtxecmd"


def dotnet_available() -> bool:
    return shutil.which("dotnet") is not None


def find_dll() -> Path:
    """Locate EvtxECmd.dll under analysis/.tools/evtxecmd/ (any subdirectory)."""
    hits = sorted(EVTXECMD_DIR.glob("**/EvtxECmd.dll"))
    if not hits:
        raise FileNotFoundError(
            f"EvtxECmd.dll not found in {EVTXECMD_DIR}. Download EvtxECmd (.NET 9) from "
            f"ericzimmerman.github.io and extract it there (see analysis/README.md)."
        )
    return hits[0]


def run_evtxecmd(evtx_path: str | Path, out_dir: str | Path,
                 out_name: str = "evtxecmd.json") -> Path:
    """Run EvtxECmd on an EVTX and return the path to the JSON (line-delimited) produced.

    Requires `dotnet` in PATH. Uses DOTNET_ROLL_FORWARD=Major to run .NET 9 build on
    installed runtime. Output JSON has a BOM and one line per event (handled by adapter)."""
    if not dotnet_available():
        raise FileNotFoundError("`dotnet` not found in PATH: EvtxECmd requires .NET runtime.")
    dll = find_dll()
    evtx_path = Path(evtx_path).resolve()
    out_dir = Path(out_dir).resolve()
    if not evtx_path.exists():
        raise FileNotFoundError(f"EVTX not found: {evtx_path}")
    out_dir.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ, DOTNET_ROLL_FORWARD="Major")
    cmd = ["dotnet", str(dll), "-f", str(evtx_path), "--json", str(out_dir), "--jsonf", out_name]
    # cwd = dll dir: so its Maps/ resolves relative.
    subprocess.run(cmd, cwd=str(dll.parent), check=True, capture_output=True, text=True, env=env)
    return out_dir / out_name
