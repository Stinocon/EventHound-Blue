---
title: Threat hunting on Windows Event Logs — EID playbook for the EventHound toolbox
updated: 2026-07-21
version: 0.1.0
linked_files:
  - analysis/adapters/windows_eventid.py
  - analysis/engine/hayabusa_runner.py
  - docs/analysis/correlation.md
  - method/fonti/riferimenti.md
changelog:
  - "0.1.0 — 2026-07-21 — first draft: analyst-facing hunting patterns per Event ID mapped to the Hayabusa toolbox commands, plus BloodHound/SpecterOps companion notes. Source: A. Kiraz, 'Threat Hunting with Windows Event Logs' (level 2-3), cross-checked against the project SOT and Microsoft auditing docs."
---

# Threat hunting on Windows Event Logs

`analysis/adapters/windows_eventid.py` is the **structural** source of truth: it classifies each Event ID
into an ECS `event.category`/`event.action`. This note adds the layer above it — *what to hunt for* on
each ID, and *which EventHound toolbox command* surfaces it. It is a reading key, not new code: the
detection runs through the already-wrapped Hayabusa subcommands (`hayabusa_runner.py`).

Patterns come from A. Kiraz, "Threat Hunting with Windows Event Logs" (community, level 2-3 — see
`method/fonti/riferimenti.md`), cross-checked against the SOT map and Microsoft Security Auditing
references. They are **hunting heuristics to validate in context**, not verdicts (§6): a match is a
lead, not proof.

## Toolbox commands (recap)

Grounded in `hayabusa_runner.py` — all local, no network:
- `run_logon_summary(evtx)` → enumerates **all** 4624/4625, with Logon Type and source/target
  account·host·IP. Authoritative source for logon/lateral-movement hunting (not rule-gated).
- `run_command("eid-metrics" | "log-metrics" | "computer-metrics", …)` → frequency/orientation:
  which EIDs, which hosts, how often. Long-tail triage.
- `run_command("search", …, keyword=… | regex=…)` → keyword/regex hunt across the full stream.
- `run_command("pivot-keywords-list", …)` → extracts IOCs (accounts, IPs, hosts) to pivot on.
- `run()` (json-timeline) → Sigma-rule detections with ATT&CK mapping.

## Credential access & authentication

| EID | Channel | Hunt for | How, in EventHound |
|-----|---------|----------|--------------------|
| 4625 + Logon Type 3 | Security | Password spraying / brute force (many failures, network logon) | `logon-summary` → *failed* CSV; spike of Type 3 failures against many accounts from one source |
| 4776 | Security | **Pass-the-Hash**: NTLM validation with *key length = 0* | `search` on `4776`, inspect key length; pair with 4624 Type 3 on the target |
| 4768 / 4769 | Security | **Golden/Silver Ticket**: 4769 (TGS) not preceded by 4768 (TGT); 4769 with status `0x1F`; abnormal ticket lifetimes | `search` on `4769` + `0x1F`; correlate TGT↔TGS timing |
| 4771 | Security | Kerberos pre-auth failures — AS-REP roasting / lockout precursor | `search`/`eid-metrics` on `4771` |
| 4648 | Security | Explicit-credential logon (`runas /netonly`) — credential theft, lateral prep | `search` on `4648`; SOT action `logon-explicit-credentials` |
| 4672 | Security | Special privileges assigned at logon — high-priv session start | correlate with 4624 for the same LogonId |

## Lateral movement

| EID | Channel | Hunt for | How, in EventHound |
|-----|---------|----------|--------------------|
| 4624 + Logon Type 10 | Security | **RDP** interactive logon; pair with 4778/4779 (reconnect/disconnect) | `logon-summary` → *successful* CSV, filter Type 10 |
| 4624 + Logon Type 3 | Security | Network logon — rare `source→dest` account·host pairs = lateral movement | `logon-summary`; the CLI already highlights rare pairs (`run_logons.py`) |
| 5145 | Security | Detailed file-share access — **PsExec** (`ADMIN$`, `\PSEXESVC`) | `search` on `5145` + share/relative-target names |
| 5140 | Security | Network share mount — access to `C$`/`ADMIN$` | `search`/`eid-metrics` on `5140` |
| Sysmon 1 | Microsoft-Windows-Sysmon | **WinRM** remote execution: parent `winrshost.exe`; also PsExec process lineage | `search` regex on `winrshost.exe`; requires Sysmon in the EVTX set |

Cross-source: join these with PCAP/log evidence per `docs/analysis/correlation.md` (shared indicators
IP/user/host, temporal episodes) to promote a lead to a reconstructed session.

## Execution, persistence, defense evasion

| EID | Channel | Hunt for | How, in EventHound |
|-----|---------|----------|--------------------|
| 4688 | Security | Process creation — suspicious lineage, LOLBins (needs command-line auditing on) | `search`; correlate parent/child |
| 4697 / 7045 | Security / System | **Service installation** — persistence / PsExec service | `eid-metrics` for rarity, `search` on service name/image path |
| 4698 (+ 106/200/201) | Security / TaskScheduler | **Scheduled task** creation/registration — persistence | `search` on `4698`; SOT action `scheduled-task-created` |
| 1102 | Security | **Security log cleared** — anti-forensics (T1070.001) | `eid-metrics`/`search`; SOT action `audit-log-cleared` |
| 4104 | Microsoft-Windows-PowerShell/Operational | PowerShell **script-block logging** — obfuscated/encoded payloads | `search` regex on script-block content / `-enc`; `extract-base64` on candidates |

> Note: the article centres on Security/System/Application and Sysmon; 4104 (script-block) lives in the
> PowerShell/Operational channel and is added here from the SOT/Microsoft docs because it is the natural
> companion for encoded-payload hunting (feeds `extract-base64`). Verify the channel is present in the
> collected EVTX set.

## AD reconnaissance — and the BloodHound bridge

| EID | Channel | Hunt for | How, in EventHound |
|-----|---------|----------|--------------------|
| 1644 | Directory Service (DC) | Expensive/inefficient **LDAP SearchRequests** — SharpHound / BloodHound / PowerView collection | Custom rule `analysis/sigma/custom/detection/ldap_recon_directory_service_1644.yaml` (DC-side, complements the community client-side `win_ldap_recon`); or `search` on `1644`. Requires `NTDS Diagnostics\Field Engineering=5` on the DC |

**BloodHound CE / SpecterOps as companion, not as an ingest** (§6, no speculative feature):
- EventHound and BloodHound answer different questions. EventHound builds a **timeline** of what
  *happened* (logons, services, tasks) across sources; BloodHound (SharpHound collector → Neo4j graph)
  maps the **attack-path structure** of Active Directory (what an attacker *could* traverse).
- Concrete bridge today, no new code: EID 1644 lets EventHound **detect the BloodHound/SharpHound
  collection itself** — the recon that precedes path abuse. The lateral-movement view (4624 Type 3 rare
  `source→dest` pairs) is the *observed* counterpart of a BloodHound *potential* attack path: a rare
  observed hop that also sits on a known BloodHound path is worth escalating.
- `queries.specterops.io` (BloodHound Cypher library) is a **reference for ideas**, not reusable code:
  Cypher/Neo4j ≠ DuckDB SQL. Use it to inspire correlation recipes (`analytics/correlate.py`), not to
  copy queries.
- Ingesting SharpHound JSON as an EventHound source (graph vs timeline) stays **deferred**: it is a
  large, mis-aligned feature and, without real AD data to validate against, would be speculative (§6).

## Caveats

- Several patterns depend on **audit configuration** (command-line process auditing for 4688, DS access
  for 1644, script-block logging for 4104, Sysmon deployment for EID 1). A missing EID is often a
  visibility gap, not absence of the activity.
- Level 2-3 source: treat every heuristic as a lead to confirm against the endpoint and, where relevant,
  the RAG/framework references (§6). Numbers and verdicts are never produced by hand.
