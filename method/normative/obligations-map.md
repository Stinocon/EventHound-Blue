---
title: Incident → notification obligations mapping (GDPR/NIS2/DORA)
updated: 2026-09-11
version: 0.1.2
linked_files:
  - method/normative/INDEX.md
  - tools/compliance/obligations.yaml
changelog:
  - "0.1.2 — 2026-09-11 — `rag/sources.yaml` left `linked_files` after the RAG removal (2026-09-01)."
  - "0.1.0 — 2026-06-21 — initial draft: obligations/timing table + reference to resolver and RAG. Timings to be validated against official text."
  - "0.1.1 — 2026-07-20 — English translation."
---

# Incident → notification obligations mapping

From an incident, **what must be notified and by when**. Support to triage, **not legal advice**: timings must be confirmed against the **official text** under `method/normative/` (GDPR/NIS2/DORA). The applicability logic is automated in the **resolver** `tools/compliance/` (MCP tool `incident_obligations`), golden-tested; this note is the readable source of truth of the rules (SOT shared with `obligations.yaml`).

## Synthetic overview (to be validated against official text, §6)

| regulation | when triggered | obligation | timing | reference |
|-----------|-----------------|-----------|--------|-----------|
| **GDPR** | personal data breach | notification to supervisory authority | **≤ 72h** from awareness | Reg. (EU) 2016/679, art. 33 |
| **GDPR** | breach + high risk to rights | communication to data subjects | without undue delay | art. 34 |
| **NIS2** | essential/important entity, significant incident | pre-alert | **≤ 24h** | Dir. (EU) 2022/2555, art. 23 |
| **NIS2** | same | incident notification | **≤ 72h** | art. 23 |
| **NIS2** | same | final report | **≤ 1 month** | art. 23 |
| **DORA** | financial entity, serious ICT incident | initial / intermediate / final notification | details from **RTS/ITS** (to be confirmed) | Reg. (EU) 2022/2554, art. 19 |

## Usage notes

- The three regulations can cumulate: a bank hit by an attack with data exfiltration can fall together under GDPR (art. 33/34), NIS2 (art. 23) and DORA (art. 19). The resolver returns all of them, ordered by urgency (the shortest deadline, typically NIS2 24h).
- "Significant" (NIS2) and "serious" (DORA) have **their own criteria** in their respective text/implementing acts: must be evaluated, not assumed. Here they are input attributes of the incident.
- Always distinguish regulatory obligation from technical best practice (see `INDEX.md`).
