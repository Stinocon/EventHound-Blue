---
title: Sample intrusion — a realistic, literature-grounded demo dataset
updated: 2026-09-11
version: 0.1.0
linked_files:
  - analysis/demo/generate_samples.py
  - docs/screenshots/
  - analysis/demo/scenario.py
changelog:
  - "0.1.0 — 2026-09-11 — first draft: a second, richer sample scenario alongside the correlation demo, with each phase mapped to its MITRE ATT&CK technique, Windows/Sysmon Event ID and SigmaHQ rule, plus screenshots of the analysis it produces."
---

# Sample intrusion — a realistic, literature-grounded dataset

`analysis/demo/generate_samples.py` writes a complete, self-consistent intrusion onto a small
fictional estate, as eleven files that read like the real tool output they stand in for. It exists
alongside `analysis/demo/scenario.py`, which is deliberately minimal because its job is to test
*correlation*; this one exists so the screenshots and the artifacts can be held up against the
technical literature and match it.

Everything is documentation space only — `corp.example` (RFC 2606), `203.0.113.0/24` and
`198.51.100.0/24` (RFC 5737), `10.0.0.0/8` (RFC 1918) — so the files are safe to commit and the
report is safe to show anyone.

Run it:

```bash
cd analysis && uv run python -m demo.generate_samples --out ../samples
```

## The story, phase by phase, with its references

Each row states the ATT&CK technique, the Windows/Sysmon Event ID and the SigmaHQ rule that a
real analyst would expect to see for that behaviour — the sample is grounded in those, not invented.

| # | Phase | Technique | Evidence (source → signal) | Event ID / Sigma rule |
|---|-------|-----------|----------------------------|-----------------------|
| 1 | Initial access | T1110 Brute Force → T1078 Valid Accounts | access log (5× 401 then a 200), syslog (sshd `Failed password`), Okta (3× `FAILURE` then `SUCCESS` + MFA) | — |
| 2 | Execution | T1204.002 User Execution: Malicious File | Sysmon 1: payload runs from `%TEMP%` | **"Suspicious Binary Executed From Temp Directory"** |
| 3 | Persistence | T1543.003 Service · T1547.001 Run Key | 7045 service install, Sysmon 13 RegistryEvent, a native `.reg` export | **"Service Installed With Binary In Temp"**, **"Run Key Created"** |
| 4 | Credential access | T1003.001 OS Credential Dumping: LSASS | Sysmon 10 (ProcessAccess to `lsass.exe`), CrowdStrike detection, THOR Mimikatz YARA hit | **"LSASS Memory Access"** |
| 5 | Lateral movement | T1021.002 SMB/Admin Shares · T1569.002 PsExec | 4624 type-3 logon, 5145 share access, 7045 `PSEXESVC` on dc-01, firewall log of the SMB hop | **"PsExec Service Execution"** |
| 6 | C2 + exfil | T1071.004 DNS · T1571 Non-Standard Port · T1041 Exfiltration | Sysmon 22 DNS to a fresh domain, Sysmon 3 connection on 8443, PCAP with a metronomic beacon (5 connections @ 60 s, jitter 0.0) and a bulk transfer | **"DNS Query To Newly Registered Domain"** |
| 7 | Cleanup | T1070.001 Clear Windows Event Logs | 1102 Security log cleared | **"Security Log Cleared"** |

## What the engine concludes from it

Ingested through the ordinary adapters (95 records, 9 sources, no errors), the correlation layer
produces:

- **9 ATT&CK techniques** across four kill-chain phases (Exploitation → Installation → Command and
  Control → Actions on Objectives).
- **A file-hash bridge across three tools** — the same SHA-256 of `svcupdate.exe` is named
  independently by CrowdStrike, THOR and osquery (confidence *high*), which is the strongest form of
  corroboration the engine reports.
- **The identity bridge for `alice` across six tools** (crowdstrike, evtx, log, okta, osquery, thor),
  and `svc-backup` across two — the account the intrusion pivots through.
- **One incident cluster** of 15 entities spanning 8 of the 9 source families, the C2 address and the
  freshly-registered domain.
- **A C2 beacon detected on a non-standard port** (`198.51.100.66:8443`, 5 connections, 60.0 s mean
  interval, jitter 0.0).

The HTML report is `samples/report.html` (generated, gitignored); the committed screenshots of it
and of the GUI are in [`docs/screenshots/`](screenshots/).
