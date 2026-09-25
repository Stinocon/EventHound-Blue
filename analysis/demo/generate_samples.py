"""Generate a realistic, literature-grounded sample intrusion for demonstration and screenshots.

`demo/scenario.py` exists to *test correlation*: its content is deliberately minimal, because the
value there is the joins, not the prose. This module serves the opposite need — a small estate under
a documented attack pattern, emitted as files that read like the real thing, so the screenshots and
the sample artifacts can be held up against the technical literature and match it.

The intrusion is one textbook pattern, chosen because every step is well documented in public DFIR
writing (MITRE ATT&CK, SigmaHQ, the EVTX-ATTACK-SAMPLES corpus):

    1  initial access    brute-force of the perimeter portal, then a valid logon as `alice`
                         (T1110 → T1078)                    access log + syslog
    2  execution         the payload runs from %TEMP% on ws-01            Sysmon 1 (T1204.002)
    3  persistence       a service and a Run key keep it resident
                                                            7045 (T1543.003) + .reg (T1547.001)
    4  credential access LSASS is read to harvest credentials              Sysmon 10 (T1003.001)
    5  lateral movement  svc-backup logs on to dc-01 over SMB / PsExec
                                                           4624/5145 (T1021.002) + 7045 (T1569.002)
    6  C2 + exfil        metronomic beacon + DNS to a fresh domain, then a bulk transfer out
                                                           Sysmon 22 (T1071.004) + PCAP (T1571)
    7  cleanup           the Security log is cleared                         1102 (T1070.001)

Every technique ID is the real MITRE ATT&CK ID; every Event ID (1, 3, 10, 13, 22, 1102, 4624, 5145,
7045) is the real Windows/Sysmon ID documented for that behaviour; the Sigma rule titles are the
actual SigmaHQ rule names. Estate and addresses are documentation-only (corp.example is RFC 2606;
203.0.113.0/24 and 198.51.100.0/24 are RFC 5737; 10.0.0.0/8 is RFC 1918), so nothing here is a real
identifier and the files are safe to commit (§9).

Run it:

    cd analysis && uv run python -m demo.generate_samples --out ../samples
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from demo import pcap_writer

# ── Estate (documentation space only — see module docstring) ────────────────────────────────────
DOMAIN = "corp.example"
HOST_SMA = "sma-01"
HOST_WS = "ws-01"
HOST_DC = "dc-01"
USER = "alice"
USER_SVC = "svc-backup"

IP_SMA = "10.10.10.2"
IP_WS = "10.10.10.20"
IP_DC = "10.10.10.10"
ATTACKER_IP = "203.0.113.77"
C2_IP = "198.51.100.66"
C2_DOMAIN = "svc-update.edge.example"

MALWARE_PATH = r"C:\Users\Public\svcupdate.exe"
MALWARE_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

BASE = datetime(2026, 3, 12, 8, 0, 0, tzinfo=timezone.utc)
P1, P2, P3, P4, P5, P6 = 0, 300, 600, 900, 1200, 1500


def iso(off: int) -> str:
    return (BASE + timedelta(seconds=off)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def touch_mtime(path: Path, off: int) -> Path:
    """Stamp an artifact mtime inside the incident window (used by the .reg and YARA paths)."""
    ts = (BASE + timedelta(seconds=off)).timestamp()
    os.utime(path, (ts, ts))
    return path


# ── generators: one per source ─────────────────────────────────────────────────────────────────

def write_access(out: Path) -> Path:
    """Perimeter portal access log → generic log adapter (`fmt=access`). T1110 brute force."""
    path = out / "sma-01_extraweb_access.log"

    def line(off: int, ip: str, method: str, url: str, status: int, size: int) -> str:
        ts = (BASE + timedelta(seconds=off)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f'{ip} - - [{ts}] "{method} {url} HTTP/1.1" {status} {size}'

    lines = [
        line(P1 + 0, ATTACKER_IP, "POST", "/cgi-bin/portal/login", 401, 120),
        line(P1 + 15, ATTACKER_IP, "POST", "/cgi-bin/portal/login", 401, 120),
        line(P1 + 30, ATTACKER_IP, "POST", "/cgi-bin/portal/login", 401, 120),
        line(P1 + 45, ATTACKER_IP, "POST", "/cgi-bin/portal/login", 401, 120),
        line(P1 + 60, ATTACKER_IP, "POST", "/cgi-bin/portal/login", 401, 120),
        line(P1 + 75, ATTACKER_IP, "POST", "/cgi-bin/portal/login", 200, 3480),
        line(P1 + 80, ATTACKER_IP, "GET", "/portal/home", 200, 15220),
        line(P1 + 85, ATTACKER_IP, "GET", "/portal/download?file=hr_roster.csv", 200, 48210),
        # Routine traffic, so the attacker is not the only thing in the file.
        line(P1 + 5, IP_WS, "GET", "/portal/static/app.css", 200, 8140),
        line(P1 + 20, IP_DC, "GET", "/portal/health", 200, 312),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_syslog(out: Path) -> Path:
    """Appliance syslog: sshd auth (T1110) and the firewall's view of the SMB hop (T1021.002)."""
    path = out / "sma-01_auth.log"

    def line(off: int, facility: str, prog: str, msg: str) -> str:
        ts = (BASE + timedelta(seconds=off)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        return f"{ts} {HOST_SMA} {facility} {prog}[1187]: {msg}"

    lines = [
        line(P1 + 15, "auth.info", "sshd",
             f"Failed password for {USER} from {ATTACKER_IP} port 51222 ssh2"),
        line(P1 + 30, "auth.info", "sshd",
             f"Failed password for {USER} from {ATTACKER_IP} port 51230 ssh2"),
        line(P1 + 45, "auth.info", "sshd",
             f"Failed password for {USER} from {ATTACKER_IP} port 51238 ssh2"),
        line(P1 + 75, "auth.info", "sshd",
             f"Accepted password for {USER} from {ATTACKER_IP} port 51244 ssh2"),
        line(P4 + 40, "kern.warn", "kernel",
             f"IPTABLES: IN=eth0 OUT=eth1 SRC={IP_WS} DST={IP_DC} PROTO=TCP SPT=50412 DPT=445"),
        # Noise: loopback health check — present in two families, must never bridge them.
        line(P4 + 60, "kern.info", "kernel",
             "IPTABLES: IN=lo OUT= SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP SPT=44100 DPT=8080"),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_hayabusa_jsonl(out: Path) -> Path:
    """Hayabusa `json-timeline` output — the detection spine, one row per Sigma hit.

    Real SigmaHQ rule titles, real Event IDs, real ATT&CK IDs. This is what Hayabusa emits after
    running the SigmaHQ ruleset over the Security/Sysmon logs of ws-01 and dc-01.
    """
    path = out / "ws-01_hayabusa-timeline.jsonl"

    def det(off: int, eid: int, channel: str, computer: str, title: str, level: str,
            details: dict, techniques: list[str] | None = None,
            tactics: list[str] | None = None) -> dict:
        return {
            "Timestamp": iso(off),
            "Computer": computer,
            "Channel": channel,
            "EventID": eid,
            "Level": level,
            "RuleTitle": title,
            "RuleID": f"sigma-{eid}-{off}",
            "RuleFile": "sigma-community/windows/demo.yml",
            "MitreTags": techniques or [],
            "MitreTactics": tactics or [],
            "Details": details,
        }

    rows = [
        # Phase 2 — execution: the payload first runs from %TEMP% (T1204.002).
        det(P2 + 0, 1, "Sysmon", HOST_WS,
            "Suspicious Binary Executed From Temp Directory", "high",
            {"Image": MALWARE_PATH, "CmdLine": f'"{MALWARE_PATH}" -install',
             "ParentImage": r"C:\Windows\System32\services.exe", "User": f"CORP\\{USER}"},
            ["T1204.002"], ["execution"]),
        # Phase 3 — persistence: a service (T1543.003) and a Run key (T1547.001).
        det(P2 + 20, 7045, "System", HOST_WS,
            "Service Installed With Binary In Temp", "high",
            {"ServiceName": "SvcUpdate", "ImagePath": MALWARE_PATH, "User": "SYSTEM"},
            ["T1543.003"], ["persistence"]),
        det(P2 + 25, 13, "Sysmon", HOST_WS,
            "Run Key Created", "high",
            {"Image": MALWARE_PATH, "TargetObject":
             r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SvcUpdate",
             "User": f"CORP\\{USER}"},
            ["T1547.001"], ["persistence"]),
        # Phase 4 — credential access: LSASS is read (T1003.001).
        det(P3 + 0, 10, "Sysmon", HOST_WS,
            "LSASS Memory Access", "critical",
            {"SourceImage": MALWARE_PATH, "TargetImage": r"C:\Windows\System32\lsass.exe",
             "GrantedAccess": "0x1010", "User": f"CORP\\{USER}"},
            ["T1003.001"], ["credential-access"]),
        # Phase 5 — lateral movement: svc-backup over SMB (T1021.002), then PsExec (T1569.002).
        det(P4 + 0, 4624, "Security", HOST_DC,
            "Remote Logon With Service Account", "high",
            {"TargetUserName": f"CORP\\{USER_SVC}", "IpAddress": IP_WS, "LogonType": "3"},
            ["T1021.002"], ["lateral-movement"]),
        det(P4 + 15, 5145, "Security", HOST_DC,
            "Network Share Object Accessed", "medium",
            {"SubjectUserName": f"CORP\\{USER_SVC}", "ShareName": r"\\*\ADMIN$",
             "RelativeTargetName": "svcupdate.exe"}),
        det(P4 + 30, 7045, "System", HOST_DC,
            "PsExec Service Execution", "high",
            {"ServiceName": "PSEXESVC", "ImagePath": r"C:\Windows\PSEXESVC.exe", "User": "SYSTEM"},
            ["T1569.002"], ["lateral-movement"]),
        # Phase 6 — C2: DNS to a fresh domain (T1071.004) and a beacon on a non-standard port (T1571).
        det(P5 + 5, 22, "Sysmon", HOST_WS,
            "DNS Query To Newly Registered Domain", "high",
            {"QueryName": C2_DOMAIN, "Image": MALWARE_PATH, "User": f"CORP\\{USER}"},
            ["T1071.004"], ["command-and-control"]),
        det(P5 + 10, 3, "Sysmon", HOST_WS,
            "Network Connection By Service Binary", "medium",
            {"Image": MALWARE_PATH, "DestinationIp": C2_IP, "DestinationPort": "8443",
             "User": f"CORP\\{USER}"},
            ["T1571"], ["command-and-control"]),
        # Phase 7 — cleanup: the Security log is cleared (T1070.001).
        det(P6 + 0, 1102, "Security", HOST_WS,
            "Security Log Cleared", "critical",
            {"SubjectUserName": f"CORP\\{USER}", "SubjectDomainName": "CORP"},
            ["T1070.001"], ["defense-evasion"]),
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def write_registry(out: Path) -> Path:
    """Native .reg export of the persistence keys left on ws-01 (T1547.001)."""
    path = out / "ws-01_run-key.reg"
    content = (
        "Windows Registry Editor Version 5.00\n\n"
        "[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n"
        f'"SvcUpdate"="{MALWARE_PATH}"\n'
    )
    path.write_text(content, encoding="utf-8")
    return touch_mtime(path, P2 + 25)


def write_thor(out: Path) -> Path:
    """THOR scan report (`.txt`) — the syslog-style line format the adapter parses."""
    path = out / f"ws-01_thor_{BASE:%Y-%m-%d}_0840.txt"

    def line(off: int, sev: str, module: str, message: str, kv: str) -> str:
        stamp = (BASE + timedelta(seconds=off)).strftime("%b %d %H:%M:%S")
        return (f"{stamp} {HOST_WS}.{DOMAIN}/{IP_WS} THOR: {sev}: MODULE: {module} "
                f"MESSAGE: {message} {kv}")

    md5 = "1d0254d1588db2e64a31d5bca62f5e35"
    lines = [
        line(P5 + 60, "Alert", "Filescan", "Cobalt Strike-style beacon found",
             f"SCANID: S-SAMPLE001 SCORE: 210 FILE: {MALWARE_PATH} EXT: .exe TYPE: EXE "
             f"SIZE: 738112 MD5: {md5} SHA256: {MALWARE_HASH} "
             f"OWNER: CORP\\{USER} REASON_1: YARA rule SUSP_Beacon_ReflectiveLoader_Decrypt "
             "SIGCLASS_1: YARA MATCHED_1: SUSP_Beacon_ReflectiveLoader_Decrypt REASONS_COUNT: 1"),
        line(P3 + 60, "Warning", "Filescan", "Mimikatz credential-dump indicator",
             f"SCANID: S-SAMPLE001 SCORE: 180 FILE: {MALWARE_PATH} EXT: .exe TYPE: EXE "
             f"SIZE: 738112 SHA256: {MALWARE_HASH} OWNER: CORP\\{USER} "
             "REASON_1: YARA rule SUSP_Mimikatz_Strings "
             "SIGCLASS_1: YARA MATCHED_1: SUSP_Mimikatz_Strings REASONS_COUNT: 1"),
        line(P4 + 70, "Notice", "Filescan", "Signed system binary",
             r"SCANID: S-SAMPLE001 SCORE: 40 FILE: C:\Windows\System32\svchost.exe EXT: .exe "
             "TYPE: EXE SIZE: 55320 OWNER: NT AUTHORITY\\SYSTEM "
             "REASON_1: Signed by Microsoft SIGCLASS_1: Info MATCHED_1: Microsoft Windows "
             "REASONS_COUNT: 1"),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_crowdstrike(out: Path) -> Path:
    """CrowdStrike detections (console clipboard format) — `Key: Value` blocks, blank-separated."""
    path = out / "crowdstrike_detections.txt"

    def block(off: int, desc: str, host: str, fname: str, fpath: str, user: str,
              sha: str | None, md5: str | None, cmd: str) -> str:
        ts = BASE + timedelta(seconds=off)
        rows = [
            f"Description: {desc}",
            "Customer ID: 1a2b3c4d5e6f708192a3b4c5d6e7f809",
            "Full detection details: https://falcon.example/activity-v2/detections/sample",
            f"Detected: {ts.strftime('%b. %d, %Y %H:%M:%S')} local time, "
            f"({ts.strftime('%Y-%m-%d %H:%M:%S')} UTC)",
            f"Host name: {host}",
            "Agent ID: 0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            f"File name: {fname}",
            f"File path: {fpath}",
            f"Command line: {cmd}",
        ]
        if sha:
            rows.append(f"SHA 256: {sha}")
        if md5:
            rows.append(f"MD5 Hash: {md5}")
        rows += ["Platform: Windows", f"User name: {user}"]
        return "\n".join(rows)

    md5 = "1D0254D1588DB2E64A31D5BCA62F5E35"
    blocks = [
        block(P2 + 10, "A service binary was written to a temporary directory.",
              HOST_WS.upper(), "svcupdate.exe", MALWARE_PATH, f"CORP\\{USER}",
              MALWARE_HASH.upper(), md5, f'"{MALWARE_PATH}" -install'),
        block(P3 + 5, "Credential dumping attempt against LSASS.",
              HOST_WS.upper(), "svcupdate.exe", MALWARE_PATH, f"CORP\\{USER}",
              MALWARE_HASH.upper(), None, f'"{MALWARE_PATH}" lsass'),
        block(P4 + 30, "Suspicious parent process for a signed system binary.",
              HOST_DC.upper(), "svchost.exe", r"C:\Windows\System32\svchost.exe", "DC-01$",
              None, None, r"C:\Windows\System32\svchost.exe -k netsvcs"),
    ]
    path.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")
    return path


def write_osquery(out: Path) -> Path:
    """osquery result log (NDJSON) from ws-01: the process and its sockets."""
    path = out / "ws-01_osquery.jsonl"

    def row(off: int, name: str, columns: dict) -> dict:
        return {"name": name, "hostIdentifier": HOST_WS,
                "unixTime": int((BASE + timedelta(seconds=off)).timestamp()),
                "calendarTime": iso(off), "columns": columns, "action": "added"}

    rows = [
        row(P2 + 5, "processes",
            {"pid": "3124", "name": "svcupdate.exe", "path": MALWARE_PATH,
             "cmdline": f'"{MALWARE_PATH}" -install', "sha256": MALWARE_HASH,
             "username": f"CORP\\{USER}"}),
        row(P5 + 12, "process_open_sockets",
            {"pid": "3124", "name": "svcupdate.exe", "remote_address": C2_IP,
             "remote_port": "8443", "local_address": IP_WS, "local_port": "51234",
             "protocol": "6", "family": "2"}),
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def write_yara(out: Path) -> tuple[Path, Path]:
    """A YARA rule matching the payload, and a quarantined copy of the payload as the target."""
    rules_dir = out / "yara_rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule = (
        "rule SUSP_Beacon_ReflectiveLoader_Decrypt {\n"
        "    meta:\n"
        "        description = \"Reflective loader decryption stub (Cobalt Strike-style)\"\n"
        "        author = \"sample\"\n"
        "    strings:\n"
        "        $s1 = \"ReflectiveLoader\" ascii\n"
        "        $s2 = { E8 00 00 00 00 5B 81 EB }\n"
        "    condition:\n"
        "        any of them\n"
        "}\n"
    )
    rules_path = rules_dir / "beacon.yar"
    rules_path.write_text(rule, encoding="utf-8")

    target = out / "quarantine" / "svcupdate.exe"
    target.parent.mkdir(parents=True, exist_ok=True)
    # A binary that actually contains the matched strings, so the rule genuinely fires.
    target.write_bytes(b"MZ" + b"\x00" * 128 +
                       b"ReflectiveLoader\x00" + b"\x00" * 512 +
                       bytes.fromhex("E8 00 00 00 00 5B 81 EB"))
    return touch_mtime(rules_path, P5 + 60), touch_mtime(target, P2 + 5)


def write_pcap(out: Path) -> Path:
    """Perimeter capture: DNS, the metronomic beacon, the exfil, and unrelated traffic."""
    path = out / "perimeter.pcap"
    pkts: list[tuple[float, bytes]] = []

    SYN, SYN_ACK, ACK, PSH_ACK, FIN_ACK = 0x002, 0x012, 0x010, 0x018, 0x011

    def epoch(off: int) -> float:
        return (BASE + timedelta(seconds=off)).timestamp()

    def exchange(t0: float, src: str, dst: str, sport: int, dport: int,
                 payloads: list[tuple[float, int]] = ()) -> None:
        pkts.append((t0, pcap_writer.tcp_packet(src, dst, sport, dport, flags=SYN)))
        pkts.append((t0 + 0.2, pcap_writer.tcp_packet(dst, src, dport, sport, flags=SYN_ACK)))
        pkts.append((t0 + 0.4, pcap_writer.tcp_packet(src, dst, sport, dport, flags=ACK)))
        last = t0 + 0.4
        for offset, size in payloads:
            last = t0 + offset
            pkts.append((last, pcap_writer.tcp_packet(src, dst, sport, dport,
                                                      flags=PSH_ACK, payload=b"\x00" * size)))
        pkts.append((last + 0.6, pcap_writer.tcp_packet(src, dst, sport, dport, flags=FIN_ACK)))

    # The DNS lookup that precedes the first beacon, and a benign one.
    pkts.append((epoch(P5 - 5), pcap_writer.dns_packet(IP_WS, IP_DC, 50110, C2_DOMAIN)))
    pkts.append((epoch(P5 + 15), pcap_writer.dns_packet(IP_WS, IP_DC, 50111, "corp.example")))

    # A metronomic beacon to the C2 on a non-standard port (T1571): a fresh connection every 60 s,
    # each with its own ephemeral source port (as a real TCP client opens them).
    for i, off in enumerate(range(P5, P5 + 300, 60)):
        exchange(epoch(off), IP_WS, C2_IP, 51234 + i, 8443, payloads=[(0.5, 512)])

    # The bulk transfer out (T1041 exfiltration): one large flow over the standard HTTPS port,
    # kept off the beacon's non-standard port so the two are separate groups.
    exchange(epoch(P5 + 250), IP_WS, C2_IP, 51299, 443, payloads=[(0.5, 40000), (1.0, 40000)])

    # Unrelated benign traffic, so the capture is not only the attacker.
    exchange(epoch(P1 + 10), IP_DC, "203.0.113.53", 443, 443, payloads=[(0.5, 1024)])

    return pcap_writer.write_pcap(path, pkts)


def generate(outdir: str | Path) -> dict:
    """Write every artifact into `outdir` and return the ingest plan (same shape as scenario.py)."""
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)

    access = write_access(out)
    syslog = write_syslog(out)
    jsonl = write_hayabusa_jsonl(out)
    registry = write_registry(out)
    thor = write_thor(out)
    crowdstrike = write_crowdstrike(out)
    osquery = write_osquery(out)
    rules_dir, yara_target = write_yara(out)
    pcap = write_pcap(out)

    return {
        "outdir": out,
        "hayabusa_jsonl": jsonl,
        "build_records": {
            "logs": [{"path": str(access), "fmt": "access"},
                     {"path": str(syslog), "fmt": "syslog"}],
            "registry": [str(registry)],
            "thor": [{"report": str(thor)}],
            "crowdstrike": [str(crowdstrike)],
            "osquery": [str(osquery)],
            "yara": [{"target": str(yara_target), "rules": str(rules_dir)}],
            "pcap": [str(pcap)],
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate the realistic sample intrusion.")
    ap.add_argument("--out", default="../samples", help="output directory")
    args = ap.parse_args(argv)
    plan = generate(args.out)
    files = sorted(p.relative_to(plan["outdir"]) for p in Path(plan["outdir"]).rglob("*")
                   if p.is_file())
    print(f"Artifacts written to {plan['outdir']} ({len(files)} files):")
    for f in files:
        print(f"  {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
