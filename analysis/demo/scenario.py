"""One simulated incident, declared once, emitted as the files the adapters actually read.

A fresh clone of this repository can analyse nothing: there is no `.evtx`, no `.pcap`, no `.reg`,
no export of anything, and the installer downloads tools rather than data. So the product could
only ever be demonstrated on a customer's evidence — which is precisely the material that must not
leave its case (§9/§10). This module removes that dependency: it writes a coherent, deterministic
intrusion across ten source formats, and the ordinary ingest path takes it from there.

**It generates FILES, not records.** `run_bench` already synthesises records and therefore measures
the store and the recipes; going through files is what puts the *adapters* — the part that reads a
real artifact — under the same test. Everything here is pure stdlib: no binary is needed to
produce the evidence (some are needed to read it back; `run_demo` says which).

The estate is fictional and stays inside documentation space: `corp.example` (RFC 2606),
203.0.113.0/24 and 198.51.100.0/24 (RFC 5737), 10.0.0.0/8 (RFC 1918). Nothing here has ever
existed, so nothing here needs pseudonymising.

The chain, in six phases. Steps inside a phase fall inside one episode (< 120 s apart); phases are
separated by more than 300 s, so they land in different ones — the demo therefore *exercises* the
measured session-gap band instead of assuming it.

    1  initial access   attacker brute-forces the appliance portal, then authenticates as a real
                        user                                     (access log + syslog + Okta)
    2  installation     the payload runs on ws-11, installs a service and a Run key, and is seen
                        on disk                    (EVTX + .reg + THOR + YARA + CrowdStrike)
    3  credential access LSASS is read                                              (EVTX + CS)
    4  lateral movement  a service account logs on to dc-01 over SMB          (EVTX + syslog)
    5  C2 and exfil      regular beaconing to the C2, then a bulk transfer out (PCAP + EVTX +
                        osquery)
    6  anti-forensics    the security log is cleared                                    (EVTX)

The bridges the correlation engine is expected to find are *designed*, not hoped for — each one
exercises a different mechanism, and `expectations.json` states them as claims. Equally designed is
the noise: `SYSTEM`, `DC-01$`, `127.0.0.1` and `svchost.exe` each appear in two different families
and must NOT become bridges. A scenario without them would make the engine look better than it is.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo import pcap_writer  # noqa: E402

# --- the estate -------------------------------------------------------------------------------
DOMAIN = "corp.example"
HOST_SMA = "sma-01"          # perimeter appliance
HOST_WS = "ws-11"            # patient zero
HOST_DC = "dc-01"            # domain controller
HOST_FS = "fs-02"            # file server

USER = "m.rossi"             # compromised account
USER_SVC = "svc_backup"      # service account abused for lateral movement

IP_SMA = "10.10.0.1"
IP_WS = "10.10.20.11"
IP_DC = "10.10.10.1"
IP_FS = "10.10.20.2"
IP_UNRELATED = "10.10.30.50"   # a host with no part in the incident

# The DC is also the DNS resolver, which is the ordinary shape of a Windows estate and the reason
# the demo can show what a universal connector does: ws-11 and the uninvolved host both query it,
# so without a declaration `incident_clusters` pulls the uninvolved host and the benign destination
# into the incident in two hops. Declared per case (run_demo does it), the ADDRESS is demoted as a
# bridge and excluded from clustering — while dc-01 stays in the incident as a HOST, which it is.
INFRASTRUCTURE_IPS = [IP_DC]

ATTACKER_IP = "203.0.113.77"
C2_IP = "203.0.113.90"
C2_DOMAIN = "updates.cdn-corp.example"
BENIGN_IP = "198.51.100.20"
BENIGN_DOMAIN = "ntp.corp.example"

MALWARE_NAME = "svcupdate.exe"
MALWARE_PATH = r"C:\Windows\Temp\svcupdate.exe"
MALWARE_PATH_FS = r"C:\ProgramData\svcupdate.exe"

# The payload's bytes, and the hashes DERIVED from them — not literals. The YARA target written
# below *is* this content, so the hash three tools report is genuinely the hash of the file the
# scanner matched: the strongest bridge in the scenario is real rather than asserted.
MALWARE_BYTES = (b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 48
                 + b"EVENTHOUND-DEMO-ARTIFACT-svcupdate" + b"\x00" * 64)
MALWARE_SHA256 = hashlib.sha256(MALWARE_BYTES).hexdigest()
MALWARE_MD5 = hashlib.md5(MALWARE_BYTES).hexdigest()
YARA_MARKER = "EVENTHOUND-DEMO-ARTIFACT"

# --- the clock --------------------------------------------------------------------------------
T0 = datetime(2026, 3, 12, 8, 0, 0, tzinfo=timezone.utc)

P1_ACCESS = 0        # initial access on the appliance
P2_INSTALL = 600     # installation on ws-11
P3_CREDS = 1300      # credential access
P4_LATERAL = 2000    # lateral movement to dc-01
P5_C2 = 2700         # C2 and exfiltration
P6_CLEANUP = 3900    # anti-forensics


def at(offset: int) -> datetime:
    return T0 + timedelta(seconds=offset)


def iso(offset: int) -> str:
    """ISO-8601 UTC with microseconds, the shape Hayabusa emits under `-O` and the store parses."""
    return at(offset).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def iso_s(offset: int) -> str:
    """Second-resolution ISO-8601 UTC (Okta, THOR-adjacent formats)."""
    return at(offset).strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def epoch(offset: int) -> int:
    return int(at(offset).timestamp())


def _stamp(path: Path, offset: int) -> None:
    """Set a file's mtime to its place in the story.

    Two adapters have no timestamp inside the artifact and take the file's mtime instead (a `.reg`
    export carries no date; a YARA match is a statement about the file on disk). Left alone, both
    would land at whatever moment the demo was generated — outside the incident, in an episode of
    their own. The mtime is the honest anchor, so the demo sets it deliberately.
    """
    ts = epoch(offset)
    os.utime(path, (ts, ts))


# --- generators: one per source ---------------------------------------------------------------

def write_sma_access(out: Path) -> Path:
    """Appliance web portal, combined access log → the generic log adapter (`fmt=access`)."""
    path = out / "sma-01_extraweb_access.log"

    def line(off: int, ip: str, method: str, url: str, status: int, size: int) -> str:
        ts = at(off).strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f'{ip} - - [{ts}] "{method} {url} HTTP/1.1" {status} {size}'

    lines = [
        line(P1_ACCESS + 0, ATTACKER_IP, "POST", "/cgi-bin/portal/login", 401, 120),
        line(P1_ACCESS + 20, ATTACKER_IP, "POST", "/cgi-bin/portal/login", 401, 120),
        line(P1_ACCESS + 40, ATTACKER_IP, "POST", "/cgi-bin/portal/login", 401, 120),
        line(P1_ACCESS + 70, ATTACKER_IP, "POST", "/cgi-bin/portal/login", 200, 3480),
        line(P1_ACCESS + 75, ATTACKER_IP, "GET", "/portal/home", 200, 15220),
        # routine traffic from inside, so the attacker is not the only thing in the file
        line(P1_ACCESS + 5, IP_WS, "GET", "/portal/static/app.css", 200, 8140),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_sma_syslog(out: Path) -> Path:
    """Appliance syslog-ng: sshd authentication and the iptables view of the SMB hop."""
    path = out / "sma-01_auth.log"

    def line(off: int, facility: str, prog: str, msg: str) -> str:
        ts = at(off).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        return f"{ts} {HOST_SMA} {facility} {prog}[1187]: {msg}"

    lines = [
        line(P1_ACCESS + 25, "auth.info", "sshd",
             f"Failed password for {USER} from {ATTACKER_IP} port 51222"),
        line(P1_ACCESS + 45, "auth.info", "sshd",
             f"Failed password for {USER} from {ATTACKER_IP} port 51230"),
        line(P1_ACCESS + 80, "auth.info", "sshd",
             f"Accepted password for {USER} from {ATTACKER_IP} port 51244"),
        # The SMB hop as the firewall saw it: the same movement EVTX records from the other side.
        line(P4_LATERAL + 40, "kern.warn", "kernel",
             f"IPTABLES: IN=eth0 OUT=eth1 SRC={IP_WS} DST={IP_DC} PROTO=TCP SPT=50412 DPT=445"),
        # Noise: loopback health check. Present in two families, must never bridge them.
        line(P4_LATERAL + 60, "kern.info", "kernel",
             "IPTABLES: IN=lo OUT= SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP SPT=44100 DPT=8080"),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_okta(out: Path) -> Path:
    """Okta System Log export (JSON array of LogEvent) → the identity layer of the intrusion."""
    path = out / "okta_system_log.json"

    def ev(off: int, etype: str, result: str, msg: str, ip: str = ATTACKER_IP) -> dict:
        return {
            "uuid": f"demo-{off}",
            "published": at(off).strftime("%Y-%m-%dT%H:%M:%S.000") + "Z",
            "eventType": etype,
            "severity": "WARN" if result == "FAILURE" else "INFO",
            "displayMessage": msg,
            "actor": {"id": "00udemo", "type": "User",
                      "alternateId": f"{USER}@{DOMAIN}", "displayName": "M. Rossi"},
            "client": {"ipAddress": ip, "userAgent": {"rawUserAgent": "python-requests/2.31"},
                       "geographicalContext": {"country": "n/a"}},
            "outcome": {"result": result,
                        "reason": "INVALID_CREDENTIALS" if result == "FAILURE" else None},
        }

    events = [
        ev(P1_ACCESS + 30, "user.session.start", "FAILURE", "User login to Okta"),
        ev(P1_ACCESS + 50, "user.session.start", "FAILURE", "User login to Okta"),
        ev(P1_ACCESS + 60, "user.session.start", "SUCCESS", "User login to Okta"),
        ev(P1_ACCESS + 65, "user.authentication.auth_via_mfa", "SUCCESS",
           "Authentication of user via MFA"),
    ]
    path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    return path


def write_hayabusa_jsonl(out: Path) -> Path:
    """Hayabusa `json-timeline` output, the shape `evtx_hayabusa` consumes.

    This is level 1 of the EVTX story and its limit is declared, not hidden: a `.evtx` is BinXML,
    no Python writer for it exists, and `.gitignore` excludes the extension anyway — so the demo
    hands the adapter the JSONL Hayabusa would have produced. Everything downstream of the binary
    is exercised for real; the binary itself is not. `run_demo --evtx-dir` runs the real thing over
    a corpus the operator supplies.
    """
    path = out / "ws-11_hayabusa-timeline.jsonl"

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
            "RuleID": f"demo-{eid}-{off}",
            "RuleFile": "sigma-community/windows/demo.yml",
            "MitreTags": techniques or [],
            "MitreTactics": tactics or [],
            "Details": details,
        }

    rows = [
        det(P2_INSTALL + 0, 1, "Sysmon", HOST_WS,
            "Suspicious Binary Executed From Temp Directory", "high",
            {"Image": MALWARE_PATH, "CmdLine": f'"{MALWARE_PATH}" -install',
             "ParentImage": r"C:\Windows\System32\services.exe",
             "User": f"CORP\\{USER}"},
            ["T1543.003"], ["persistence"]),
        det(P2_INSTALL + 20, 7045, "System", HOST_WS,
            "Service Installed With Binary In Temp", "high",
            {"ServiceName": "SvcUpdate", "ImagePath": MALWARE_PATH, "User": "SYSTEM"}),
        det(P3_CREDS + 0, 10, "Sysmon", HOST_WS,
            "LSASS Memory Access By Unusual Process", "critical",
            {"SrcProc": MALWARE_PATH, "TgtProc": r"C:\Windows\System32\lsass.exe",
             "User": f"CORP\\{USER}"},
            ["T1003.001"], ["credential-access"]),
        det(P4_LATERAL + 0, 4624, "Security", HOST_DC,
            "Remote Logon With Service Account", "high",
            {"TgtUser": f"CORP\\{USER_SVC}", "SrcIP": IP_WS, "LogonType": "3"},
            ["T1021.002"], ["lateral-movement"]),
        # Noise: the DC's own computer account touching a share. Machine accounts are never an
        # identity, and this one also shows up in the CrowdStrike export.
        det(P4_LATERAL + 20, 5145, "Security", HOST_DC,
            "Network Share Object Accessed", "medium",
            {"SubjectUserName": "DC-01$", "ShareName": r"\\*\ADMIN$"}),
        det(P5_C2 + 5, 22, "Sysmon", HOST_WS,
            "DNS Query To Newly Registered Domain", "high",
            {"Query": C2_DOMAIN, "Image": MALWARE_PATH, "User": f"CORP\\{USER}"},
            ["T1071.004"], ["command-and-control"]),
        det(P5_C2 + 10, 3, "Sysmon", HOST_WS,
            "Network Connection By Service Binary", "medium",
            {"Image": MALWARE_PATH, "DstIP": C2_IP, "DstPort": "443",
             "User": f"CORP\\{USER}"}),
        det(P6_CLEANUP + 0, 1102, "Security", HOST_WS,
            "Security Audit Log Cleared", "critical",
            {"SubjectUserName": f"CORP\\{USER}"},
            ["T1070.001"], ["defense-evasion"]),
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def write_registry(out: Path) -> Path:
    """Native `.reg` export of the persistence keys left on ws-11.

    Its records carry no host and no user — a bare `.reg` has neither — so they contribute nothing
    to the entity bridges. That is a real limit of the source, and the demo shows it rather than
    papering over it.
    """
    path = out / "ws-11_run-keys.reg"
    esc = MALWARE_PATH.replace("\\", "\\\\")
    content = "\n".join([
        "Windows Registry Editor Version 5.00",
        "",
        r"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]",
        r'"SecurityHealth"="C:\\Program Files\\Windows Defender\\MSASCuiL.exe"',
        f'"Updater"="{esc}"',
        "",
        r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SvcUpdate]",
        f'"ImagePath"="{esc}"',
        r'"Start"=dword:00000002',
        "",
    ])
    path.write_text(content, encoding="utf-8")
    _stamp(path, P2_INSTALL + 40)
    return path


def write_thor(out: Path) -> Path:
    """THOR scan report (`.txt`). The filename carries the year: the line format has none."""
    day = at(P2_INSTALL).strftime("%Y-%m-%d")
    path = out / f"ws-11_thor_{day}_0810.txt"

    def line(off: int, sev: str, module: str, message: str, kv: str) -> str:
        stamp = at(off).strftime("%b %d %H:%M:%S")
        return (f"{stamp} {HOST_WS}.{DOMAIN}/{IP_WS} THOR: {sev}: MODULE: {module} "
                f"MESSAGE: {message} {kv}")

    lines = [
        line(P2_INSTALL + 60, "Alert", "Filescan", "Malicious file found",
             f"SCANID: S-DEMO0001 SCORE: 210 FILE: {MALWARE_PATH} EXT: .exe TYPE: EXE "
             f"SIZE: {len(MALWARE_BYTES)} MD5: {MALWARE_MD5} SHA256: {MALWARE_SHA256} "
             f"OWNER: CORP\\{USER} REASON_1: YARA rule EventHound_Demo_SvcUpdate "
             "SIGCLASS_1: YARA MATCHED_1: EventHound_Demo_SvcUpdate REASONS_COUNT: 1"),
        line(P2_INSTALL + 65, "Warning", "Autoruns", "Suspicious autostart entry",
             f"SCANID: S-DEMO0001 SCORE: 90 FILE: {MALWARE_PATH} EXT: .exe TYPE: EXE "
             f"SIZE: {len(MALWARE_BYTES)} SHA256: {MALWARE_SHA256} OWNER: CORP\\{USER} "
             r"REASON_1: Autostart entry HKLM\...\Run\Updater "
             "SIGCLASS_1: Autoruns MATCHED_1: Run key Updater REASONS_COUNT: 1"),
        # Noise: a scored line on a binary present on every Windows host, owned by SYSTEM. Both the
        # file and the owner also appear in other families and must stay out of the bridges.
        line(P2_INSTALL + 70, "Notice", "Filescan", "Signed system binary",
             r"SCANID: S-DEMO0001 SCORE: 40 FILE: C:\Windows\System32\svchost.exe EXT: .exe "
             "TYPE: EXE SIZE: 55320 OWNER: NT AUTHORITY\\SYSTEM "
             "REASON_1: Signed by Microsoft SIGCLASS_1: Info MATCHED_1: Microsoft Windows "
             "REASONS_COUNT: 1"),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_crowdstrike(out: Path) -> Path:
    """CrowdStrike detections in the console's clipboard format (blocks separated by a blank line).

    The hash is written UPPERCASE here and lowercase by THOR, on purpose: the two only join because
    `canon_hash` folds the case. And it arrives under `SHA 256` → `file.hash.sha256`, the spelling
    that had no column until it was given one — so this block also guards that fix.
    """
    path = out / "crowdstrike_detections.txt"

    def block(off: int, desc: str, host: str, fname: str, fpath: str,
              user: str, sha: str | None, md5: str | None, cmd: str) -> str:
        rows = [
            f"Description: {desc}",
            "Customer ID: 1a2b3c4d5e6f708192a3b4c5d6e7f809",
            "Full detection details: https://falcon.example/activity-v2/detections/demo",
            f"Detected: {at(off).strftime('%b. %d, %Y %H:%M:%S')} local time, "
            f"({at(off).strftime('%Y-%m-%d %H:%M:%S')} UTC)",
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

    blocks = [
        block(P2_INSTALL + 80, "A service binary was written to a temporary directory.",
              "WS-11", MALWARE_NAME, MALWARE_PATH, f"CORP\\{USER}",
              MALWARE_SHA256.upper(), MALWARE_MD5.upper(), f'"{MALWARE_PATH}" -install'),
        block(P3_CREDS + 20, "Credential dumping attempt against LSASS.",
              "WS-11", MALWARE_NAME, MALWARE_PATH, f"CORP\\{USER}",
              MALWARE_SHA256.upper(), None, f'"{MALWARE_PATH}" -d'),
        # Noise: a benign detection on a ubiquitous binary, attributed to a machine account.
        block(P4_LATERAL + 30, "Suspicious parent process for a signed system binary.",
              "DC-01", "svchost.exe", r"C:\Windows\System32\svchost.exe", "DC-01$",
              None, None, r"C:\Windows\System32\svchost.exe -k netsvcs"),
    ]
    path.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")
    return path


def write_osquery(out: Path) -> Path:
    """osquery result log (NDJSON) from the file server: the payload running, its hash, its sockets."""
    path = out / "fs-02_osquery_result.log"

    def row(off: int, name: str, columns: dict, action: str = "added") -> dict:
        return {"name": name, "hostIdentifier": f"{HOST_FS}.{DOMAIN}",
                "unixTime": epoch(off), "action": action, "columns": columns,
                "decorations": {"host_uuid": "demo-fs-02"}}

    rows = [
        row(P5_C2 + 400, "processes",
            {"pid": 4812, "name": MALWARE_NAME, "path": MALWARE_PATH_FS,
             "cmdline": f"{MALWARE_PATH_FS} -collect", "username": USER_SVC}),
        row(P5_C2 + 410, "file_events",
            {"target_path": MALWARE_PATH_FS, "sha256": MALWARE_SHA256,
             "md5": MALWARE_MD5, "action": "CREATED"}),
        # Noise: a loopback listener. Same address the appliance logs on its own side.
        row(P5_C2 + 420, "listening_ports",
            {"pid": 940, "port": 8080, "address": "127.0.0.1", "protocol": "tcp"}),
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def write_yara(out: Path) -> tuple[Path, Path]:
    """A rule and the artifact it matches: returns (rules_dir, target_file).

    The target is the payload's actual bytes, so the match is a real match and the file's hash is
    the hash the other three tools report.
    """
    rules_dir = out / "yara_rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "eventhound_demo.yar").write_text(
        "rule EventHound_Demo_SvcUpdate\n"
        "{\n"
        "    meta:\n"
        '        description = "Demo payload dropped by the simulated intrusion"\n'
        '        attack = "T1543.003"\n'
        "    strings:\n"
        f'        $marker = "{YARA_MARKER}"\n'
        "    condition:\n"
        "        $marker\n"
        "}\n", encoding="utf-8")

    target_dir = out / "quarantine"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / MALWARE_NAME
    target.write_bytes(MALWARE_BYTES)
    _stamp(target, P2_INSTALL + 70)
    return rules_dir, target


def write_pcap(out: Path) -> Path:
    """Perimeter capture: the DNS lookup, the beacon, the transfer out, and unrelated traffic.

    Connections are written as real exchanges — handshake, data, close — not as lone SYNs. A capture
    of unanswered SYNs would be read by Zeek as a wall of failed connections and would crowd the
    timeline with an artefact of the fixture; it would also let `recipes.beaconing` pass for the
    wrong reason, since one packet per flow is exactly the shape that hides the difference between
    a packet and a connection.
    """
    path = out / "perimeter.pcap"
    pkts: list[tuple[float, bytes]] = []

    SYN, SYN_ACK, ACK, PSH_ACK, FIN_ACK = 0x002, 0x012, 0x010, 0x018, 0x011

    def exchange(t0: float, src: str, dst: str, sport: int, dport: int,
                 data: list[tuple[float, int]] = ()) -> None:
        """One TCP conversation: three-way handshake, optional data segments, orderly close."""
        pkts.append((t0, pcap_writer.tcp_packet(src, dst, sport, dport, flags=SYN)))
        pkts.append((t0 + 0.2, pcap_writer.tcp_packet(dst, src, dport, sport, flags=SYN_ACK)))
        pkts.append((t0 + 0.4, pcap_writer.tcp_packet(src, dst, sport, dport, flags=ACK)))
        last = t0 + 0.4
        for offset, size in data:
            last = t0 + offset
            pkts.append((last, pcap_writer.tcp_packet(src, dst, sport, dport,
                                                      flags=PSH_ACK, payload=b"\x00" * size)))
        pkts.append((last + 0.6, pcap_writer.tcp_packet(src, dst, sport, dport, flags=FIN_ACK)))

    # The lookup that precedes the first call-back, and a benign one for company.
    pkts.append((epoch(P5_C2 - 5),
                 pcap_writer.dns_packet(IP_WS, IP_DC, 50110, C2_DOMAIN)))
    pkts.append((epoch(P5_C2 + 15),
                 pcap_writer.dns_packet(IP_UNRELATED, IP_DC, 50111, BENIGN_DOMAIN)))

    # The beacon: six separate connections, exactly 60 s apart, each a full exchange. Zero jitter
    # and well above the four-connection floor.
    for i in range(6):
        exchange(epoch(P5_C2 + i * 60), IP_WS, C2_IP, 50200 + i, 443,
                 data=[(1.0, 64)])

    # Exfiltration: ONE long connection carrying bulk data. Its segments are regular too, which is
    # the point — a detector that counts packets would call this a beacon, and it is not one.
    exchange(epoch(P5_C2 + 400), IP_FS, ATTACKER_IP, 50300, 443,
             data=[(10.0 + i * 10, 1400) for i in range(5)])

    # Unrelated traffic: three connections at irregular intervals, below the beaconing floor, so
    # the detector has to discriminate rather than flag every repeated destination.
    for i, off in enumerate((P5_C2 + 30, P5_C2 + 190, P5_C2 + 500)):
        exchange(epoch(off), IP_UNRELATED, BENIGN_IP, 50400 + i, 443)

    pkts.sort(key=lambda p: p[0])
    return pcap_writer.write_pcap(path, pkts)


# --- the whole scenario -----------------------------------------------------------------------

def generate(outdir: str | Path) -> dict:
    """Write every artifact into `outdir` and return the ingest plan.

    The returned dict is split in two: `build_records` holds the keyword arguments the ordinary
    ingest path takes, and `hayabusa_jsonl` is handed to the EVTX adapter directly — see
    `write_hayabusa_jsonl` for why that path exists and what it does not prove.
    """
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)

    access = write_sma_access(out)
    syslog = write_sma_syslog(out)
    okta = write_okta(out)
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
            "okta": [str(okta)],
            "registry": [str(registry)],
            "thor": [{"report": str(thor)}],
            "crowdstrike": [str(crowdstrike)],
            "osquery": [str(osquery)],
            "yara": [{"target": str(yara_target), "rules": str(rules_dir)}],
            "pcap": [str(pcap)],
        },
    }
