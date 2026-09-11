---
title: MITRE ATT&CK — tactics and techniques
updated: 2026-09-11
version: 0.1.2
linked_files:
  - method/framework/INDEX.md
  - method/security-instructions.md
  - method/framework/cyber-kill-chain.md
changelog:
  - "0.1.2 — 2026-09-11 — the RAG/knowledge_cyber sourcing notes become the vendored ATT&CK map: the tactics table says 'confirmed' (not 'confirmed by RAG'), and the sections no longer name the removed collection."
  - "0.1.0 — 2026-06-15 — first draft, sourced from RAG knowledge_cyber (MITRE ATT&CK)."
  - "0.1.1 — 2026-07-20 — English translation."
---

# MITRE ATT&CK

Taxonomy of adversary behaviors observed in the real world, organized into
**tactics** (the *why*: the adversary's objective at that moment) and
**techniques** (the *how*: the means to achieve it). It is the lingua franca for
describing suspicious behavior in a shared and verifiable manner.

## Structure of identifiers

- **Tactic**: `TAxxxx` (e.g., `TA0006` Credential Access).
- **Technique**: `Txxxx` (e.g., `T1059` Command and Scripting Interpreter).
- **Sub-technique**: `Txxxx.NNN` (e.g., `T1059.001` PowerShell). A sub-technique
  specializes the parent technique.

A technique can belong to multiple tactics (the same how serves multiple whys).

## Tactics (Enterprise)

Typical sequence along the intrusion (not rigidly linear):

| order | tactic | ID |
|-------|--------|-----|
| 1 | Reconnaissance | `TA0043` (confirmed) |
| 2 | Resource Development | `TA0042` (confirmed) |
| 3 | Initial Access | `TA0001` (ID to verify) |
| 4 | Execution | `TA0002` (confirmed) |
| 5 | Persistence | `TA0003` (confirmed) |
| 6 | Privilege Escalation | `TA0004` (confirmed) |
| 7 | Defense Evasion | `TA0005` (ID to verify) |
| 8 | Credential Access | `TA0006` (confirmed) |
| 9 | Discovery | `TA0007` (ID to verify) |
| 10 | Lateral Movement | `TA0008` (ID to verify) |
| 11 | Collection | `TA0009` (ID to verify) |
| 12 | Command and Control | `TA0011` (ID to verify) |
| 13 | Exfiltration | `TA0010` (ID to verify) |
| 14 | Impact | `TA0040` (ID to verify) |

IDs marked "confirmed" are cross-checked against the vendored ATT&CK map
(`analysis/analytics/attack_map.json`, generated from the official STIX bundle);
the others are the framework's standard values but **not**
found in local excerpts: validate them on attack.mitre.org before citing them
as certain.

## Techniques/sub-techniques confirmed locally

Useful as a repertoire of recurring examples in incident response (all
cross-checked against the vendored ATT&CK map):

- `T1566` Phishing (`.001` Attachment, `.002` Link)
- `T1078` Valid Accounts (`.001` Default, `.002` Domain, `.003` Local)
- `T1059` Command and Scripting Interpreter (`.001` PowerShell, `.008` Network
  Device CLI)
- `T1543.002` Create or Modify System Process: systemd service
- `T1547.001` Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- `T1053.005` Scheduled Task/Job: Scheduled Task
- `T1110.004` Brute Force: Credential Stuffing
- `T1548.002` Abuse Elevation Control Mechanism: Bypass UAC
- `T1070` Indicator Removal
- `T1486` Data Encrypted for Impact
- `T1218.003` System Binary Proxy Execution: CMSTP

Common in IR but **not** found in local excerpts (to verify before use): `T1003` OS Credential Dumping, `T1021` Remote Services.

## Use in analysis

Consistent with `method/security-instructions.md`:

1. Start from **observed evidence** (process, command line, parent, artifact).
2. Associate the most specific ATT&CK **technique/sub-technique** that the
   evidence supports — no more than the data says.
3. Trace back to the **tactic** to frame the adversary's objective.
4. Link to the **response phase** (SANS/NIST, see `sans-ir.md`, `nist.md`) and,
   as a narrative grid, to `cyber-kill-chain.md`.

Do not force a mapping when evidence is weak: better to flag it as a hypothesis
to be confirmed. IDs should be cited only if validated (rule §6 in `method/conventions.md`).
