"""Helper: runs Zeek on a PCAP and returns paths to generated logs.

Anonymization: client internal IPs must be pseudonymized *downstream* (malicious
public IPs are not) — see common-schema.md and §9 — method/conventions.md.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def zeek_path() -> str | None:
    """Where zeek is, or None when it is not installed.

    One place, because two callers need the answer for different reasons and a second
    `shutil.which("zeek")` elsewhere would be a second spelling of the same fact: this module runs
    it, and `analytics.runner` reports its absence to the analyst. Telling those two apart matters
    — the caller used to infer "Zeek is missing" from a FileNotFoundError that a missing *PCAP*
    raises just as readily, which turns a wrong path into a wrong diagnosis.
    """
    return shutil.which("zeek")


def run_zeek(pcap_path: Path, work_dir: Path) -> dict[str, Path]:
    """Run Zeek on a PCAP, return {log_type: log_path} for all generated logs.

    Args:
        pcap_path: Path to the PCAP file (local, never remote).
        work_dir:  Directory where Zeek writes logs (typically tempdir).

    Returns:
        Dict mapping log type (e.g., "conn", "dns", "http") to log file path.

    Raises:
        FileNotFoundError: zeek not found in PATH.
        RuntimeError: zeek fails on input (corrupt PCAP, internal error).
    """
    exe = zeek_path()
    if not exe:
        raise FileNotFoundError(
            "zeek not found in PATH (install Zeek: brew install zeek)."
        )

    # Resolved, because zeek runs with cwd set to the work dir: a RELATIVE path — which is what
    # every CLI gets when the analyst types `--pcap capture.pcap` — resolved against the temp
    # directory instead of theirs, and zeek exited with "unable to open". The PCAP analysis then
    # continued on tshark alone, so the whole application layer (HTTP, TLS/JA3, DNS answers,
    # notices) went missing behind one non-fatal error line.
    cmd = [exe, "-r", str(Path(pcap_path).resolve()), "-C"]  # -C: disable IP checksum
    try:
        subprocess.run(
            cmd, cwd=work_dir, check=True, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
        )
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or "").strip() or f"zeek exited with code {exc.returncode}"
        raise RuntimeError(f"zeek failed to process {pcap_path}: {msg}") from None

    logs: dict[str, Path] = {}
    for entry in sorted(work_dir.iterdir()):
        if entry.suffix == ".log" and not entry.name.startswith("_"):
            log_type = entry.stem  # "conn", "dns", "http", "ssl", "notice"
            logs[log_type] = entry

    return logs
