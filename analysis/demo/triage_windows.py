"""The Windows live triage — the second scenario, and the one that shows what a STATE source adds.

The incident scenario (`demo/scenario.py`) is an estate seen from its logs. This one is a single
endpoint seen twice: what the machine RECORDED, and what it IS.

The premise, and it is the initial-access premise of most real IR work: an analyst has a suspect
Windows host and a short window. The Security log was cleared while the intrusion was running
(T1070.001), so the authentication history is gone and the logon that started it cannot be
reconstructed. What survives is the Sysmon channel, a scanner's finding, and — the part nothing else
in the suite can supply — the machine's CURRENT state, captured live.

That is the whole argument for osquery here, and it is a different one from the macOS/Linux case:
on Windows it is not that EVTX is missing, it is that EVTX only answers "what happened". osquery
answers "what is happening now": the process is still running, the socket to the command-and-control
address is still ESTABLISHED, and the parent is `services.exe` — which is what makes the live process
the same object as the service the event log recorded being installed an hour earlier. YARA and
scanner output name a file on disk; only the state source can say whether that file is running.

SCOPE, DECLARED. The osquery tables used here are the cross-platform ones (`processes`,
`process_open_sockets`, `listening_ports`), whose columns were verified against a real result log
captured on macOS (`tests/fixtures/osquery_result_5.23.1.jsonl`). The Windows-specific tables a
triage would also want — `services`, `scheduled_tasks`, `autoruns` — are deliberately ABSENT: no
Windows result log exists here to verify their columns against, and a demo built on a guessed shape
would certify the guess. Persistence in this scenario is therefore evidenced by EVTX (the service
install and the Run key it recorded), not by a table nobody has checked.

Everything is synthetic and in documentation address space (§9): there is nothing to anonymise.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

# --- the estate --------------------------------------------------------------------------------
HOST = "ws-07"
DOMAIN = "corp.example"
USER = "m.bianchi"
IP_WS = "10.10.20.31"

# The other end of the socket, and the only reason it is in this scenario at all: it is named by the
# RECORDED connection (Sysmon EID 3, before the log was cleared) and by the LIVE one (osquery), and
# by nothing else. Nothing in this dataset resolves it to a name.
C2_IP = "198.51.100.13"
C2_PORT = 443

# A real Windows binary name, and the masquerade an operator pivots on: `fontdrvhost.exe` belongs in
# `System32`, so the same name under `ProgramData` is the finding. It is not in the ubiquitous-file
# set (normalize._GENERIC_FILES), which is why it can bridge at all.
MALWARE_NAME = "fontdrvhost.exe"
MALWARE_PATH = rf"C:\ProgramData\{MALWARE_NAME}"
MALWARE_SHA256 = "9c1e77b0a3d54f6e2b8a0c1d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071"
MALWARE_PID = "6180"
SERVICE_NAME = "WinFontCache"
BACKDOOR_PORT = 8443

BASE = datetime(2026, 3, 4, 9, 0, 0, tzinfo=timezone.utc)

# Relative offsets, so the story reads in order and a test can name one moment.
T_EXEC = 0                    # the payload runs
T_CONNECT = 5                 # and reaches out
T_FILE = 30                   # the installer drops a second file
T_LOG_CLEARED = 3600          # the Security log is cleared, an hour later
T_TRIAGE = 4200               # the live snapshot, ten minutes after that

# The order the evidence is offered in when the triage is loaded one source at a time: what the host
# recorded, then the artifact on disk, then the state that ties them together.
ORDER = ("evtx", "thor", "osquery")

DEFAULT_CASE = "triage-windows"
CASE_TITLE = "EventHound triage — Windows endpoint, live state"
INFRASTRUCTURE_IPS: tuple[str, ...] = ()


def at(off: int) -> datetime:
    return BASE + timedelta(seconds=off)


def iso(off: int) -> str:
    return at(off).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- what the host recorded ---------------------------------------------------------------------

def write_hayabusa_jsonl(out: Path) -> Path:
    """Hayabusa `json-timeline` output, the shape `evtx_hayabusa` consumes.

    Level 1 of the EVTX story, and the limit is declared rather than hidden: a `.evtx` is BinXML, no
    Python writer for it exists, and the extension is gitignored anyway — so this is the JSONL
    Hayabusa would have produced. Everything downstream of the binary runs for real.
    """
    path = out / f"{HOST}_hayabusa-timeline.jsonl"

    def det(off: int, eid: int, channel: str, title: str, level: str, details: dict,
            techniques: list[str] | None = None, tactics: list[str] | None = None) -> dict:
        return {
            "Timestamp": iso(off),
            "Computer": HOST.upper(),
            "Channel": channel,
            "EventID": eid,
            "Level": level,
            "RuleTitle": title,
            "RuleID": f"sigma-{eid}-{off}",
            "RuleFile": "sigma-community/windows/triage.yml",
            "MitreTags": techniques or [],
            "MitreTactics": tactics or [],
            "Details": details,
        }

    rows = [
        # The execution, and the parent that makes it a service rather than a user's mistake.
        det(T_EXEC, 1, "Sysmon", "Binary Executed From A User-Writable Directory", "high",
            {"Image": MALWARE_PATH, "CmdLine": f'"{MALWARE_PATH}" -service',
             "ParentImage": r"C:\Windows\System32\services.exe", "User": f"CORP\\{USER}"},
            ["T1204.002"], ["execution"]),
        # The connection that was recorded and can never be seen again: the Security log goes first.
        det(T_CONNECT, 3, "Sysmon", "Connection To An Untrusted Address", "medium",
            {"Image": MALWARE_PATH, "DestinationIp": C2_IP, "DestinationPort": str(C2_PORT),
             "User": f"CORP\\{USER}"},
            ["T1071.001"], ["command-and-control"]),
        det(T_FILE, 11, "Sysmon", "File Created In ProgramData", "medium",
            {"Image": MALWARE_PATH, "TargetFilename": rf"C:\ProgramData\{SERVICE_NAME}.dll"},
            ["T1105"], ["command-and-control"]),
        # Persistence, recorded — and the pair that makes the live process identifiable later.
        det(T_EXEC + 20, 7045, "System", "Service Installed With Binary In ProgramData", "high",
            {"ServiceName": SERVICE_NAME, "ImagePath": MALWARE_PATH, "User": "SYSTEM"},
            ["T1543.003"], ["persistence"]),
        # The reason the logon cannot be reconstructed, and the finding an analyst must notice
        # before trusting anything above it.
        det(T_LOG_CLEARED, 1102, "Security", "Audit Log Cleared", "critical",
            {"User": f"CORP\\{USER}", "SubjectLogonId": "0x3e7"},
            ["T1070.001"], ["defense-evasion"]),
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


# --- what the scan found ------------------------------------------------------------------------

def write_thor(out: Path) -> Path:
    """THOR scan report (`.txt`), the shape `thor_scan` consumes.

    One Alert on the payload and one Notice on a signed system binary: the second is the negative
    control the correlation needs, because `svchost.exe` appears in every family and must not bridge
    anything.
    """
    path = out / f"{HOST}_thor_2026-03-04_1130.txt"

    def line(off: int, sev: str, module: str, message: str, kv: str) -> str:
        stamp = at(off).strftime("%b %d %H:%M:%S")
        return (f"{stamp} {HOST}.{DOMAIN}/{IP_WS} THOR: {sev}: MODULE: {module} "
                f"MESSAGE: {message} {kv}")

    lines = [
        line(T_TRIAGE - 300, "Alert", "Filescan", "Malicious file found",
             f"SCANID: S-TRIAGE01 SCORE: 240 FILE: {MALWARE_PATH} EXT: .exe TYPE: EXE "
             f"SIZE: 892416 MD5: 4b1f0c9a8e7d6c5b4a39281706f5e4d3 SHA256: {MALWARE_SHA256} "
             f"OWNER: CORP\\{USER} REASON_1: YARA rule SUSP_Masquerade_FontDrvHost "
             "SIGCLASS_1: YARA MATCHED_1: SUSP_Masquerade_FontDrvHost REASONS_COUNT: 1"),
        line(T_TRIAGE - 295, "Notice", "Filescan", "Signed system binary",
             r"SCANID: S-TRIAGE01 SCORE: 40 FILE: C:\Windows\System32\svchost.exe EXT: .exe "
             "TYPE: EXE SIZE: 55320 OWNER: NT AUTHORITY\\SYSTEM "
             "REASON_1: Signed by Microsoft SIGCLASS_1: Info MATCHED_1: Microsoft Windows "
             "REASONS_COUNT: 1"),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# --- what the machine IS ------------------------------------------------------------------------

def write_osquery(out: Path) -> Path:
    """osquery result log (NDJSON) captured at the moment of triage.

    The tables are the cross-platform ones, and the columns are the ones the real capture showed.
    A Unix socket's `path` and a missing port are not in play here (this is TCP), but the shape is
    the same file the adapter was verified against.
    """
    path = out / f"{HOST}_osquery.jsonl"

    def row(off: int, name: str, columns: dict, action: str = "added") -> dict:
        return {"name": name, "hostIdentifier": HOST, "calendarTime": iso(off), "unixTime": int(
            at(off).timestamp()), "epoch": 0, "counter": 0, "numerics": False,
            "columns": columns, "action": action}

    rows = [
        # The payload, alive. The parent is what ties this row to the service the event log recorded
        # being installed an hour earlier — two sources, one object.
        row(T_TRIAGE, "processes", {
            "pid": MALWARE_PID, "name": MALWARE_NAME, "path": MALWARE_PATH,
            "cmdline": f'"{MALWARE_PATH}" -service',
            "parent": "664", "parent_path": r"C:\Windows\System32\services.exe", "uid": "0"}),
        # The socket, still up. This is the row that has no counterpart in the log: the connection
        # event was recorded before the clear, and this is the same connection, still open.
        row(T_TRIAGE, "process_open_sockets", {
            "pid": MALWARE_PID, "family": "2", "protocol": "6", "socket": "412",
            "local_address": IP_WS, "local_port": "51234",
            "remote_address": C2_IP, "remote_port": str(C2_PORT), "state": "ESTABLISHED"}),
        # And it is listening for the operator to come back.
        row(T_TRIAGE, "listening_ports", {
            "pid": MALWARE_PID, "family": "2", "protocol": "6", "socket": "0",
            "address": "0.0.0.0", "port": str(BACKDOOR_PORT)}),
        # File integrity monitoring saw the same binary land, and hashed it. This is the row that
        # turns "a scanner found a file" into "a scanner found the file, and it is the file that is
        # running" — the question a triage exists to answer, and one no event log can settle.
        row(T_TRIAGE, "file_events", {
            "target_path": MALWARE_PATH, "sha256": MALWARE_SHA256, "action": "CREATED",
            "category": "triage"}),
        # Noise, and the same negative control as the scanner's: a system binary running normally.
        row(T_TRIAGE, "processes", {
            "pid": "664", "name": "svchost.exe",
            "path": r"C:\Windows\System32\svchost.exe", "cmdline": "svchost.exe -k netsvcs",
            "parent": "628", "parent_path": r"C:\Windows\System32\services.exe", "uid": "0"}),
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def generate(outdir: str | Path) -> dict:
    """Write the scenario's artifacts and return the plan `run_demo` ingests."""
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)

    jsonl = write_hayabusa_jsonl(out)
    thor = write_thor(out)
    osquery = write_osquery(out)

    return {
        "outdir": out,
        "hayabusa_jsonl": jsonl,
        "build_records": {
            "thor": [{"report": str(thor)}],
            "osquery": [str(osquery)],
        },
    }
