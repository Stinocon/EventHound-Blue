---
title: Regulations and compliance — index
updated: 2026-07-21
version: 0.2.2
linked_files:
  - method/conventions.md
  - rag/sources.yaml
  - method/fonti/riferimenti.md
  - method/normative/obligations-map.md
changelog:
  - "0.1.0 — 2026-06-14 — placeholder; NIS2 and GDPR, curated notes to populate. Normative RAG setup."
  - "0.2.0 — 2026-06-21 — DORA added (Reg. EU 2022/2554): official PDF indexed in normative collection; row in areas table."
  - "0.2.1 — 2026-07-20 — English translation."
  - "0.2.2 — 2026-07-21 — link the curated note obligations-map.md (incident→notification obligations, SOT for the compliance resolver) from the index."
---

# Regulations and compliance

Area for **regulatory knowledge** in the field of cybersecurity and data protection, useful for both analysis and **documentation writing** (policies, procedures, assessments). Distinct from technical knowledge and methodological frameworks (`method/framework/`).

Official texts and sources are indexed in the RAG in the dedicated collection **`normative`** (see `rag/sources.yaml`); here live the **curated notes** that summarize and link obligations.

**Curated notes**: [`obligations-map.md`](obligations-map.md) — incident → notification obligations (GDPR/NIS2/DORA): what must be notified and by when. It is the readable source of truth of the rules automated by the compliance resolver `tools/compliance/` (MCP tool `incident_obligations`).

## Areas (to populate)

| regulation | scope | reference | status |
|-----------|-------|-----------|--------|
| **NIS2** | network and information system security (essential/important entities, obligations, incident notification) | Directive (EU) 2022/2555; in Italy D.Lgs. 138/2024 *(to be confirmed)* | indexed (PDF) |
| **GDPR** | personal data protection (principles, legal bases, data breach, DPIA, roles) | Regulation (EU) 2016/679; in Italy D.Lgs. 196/2003 amended *(to be confirmed)* | indexed (PDF) |
| **DORA** | digital operational resilience of the financial sector (ICT risk management, reporting of serious incidents, TLPT testing, third-party ICT risk, information sharing) | Regulation (EU) 2022/2554; applicable from 17/01/2025 *(to be confirmed)* | indexed (PDF) |

## Usage notes

- Always distinguish **regulatory obligation** from **technical best practice**: frameworks (NIST/CIS) support compliance but do not replace it.
- For documentation writing: cite the exact source (article/recital) and mark as *to be validated* what is not derived from the official text (applies the golden rule of `method/conventions.md` §6).
- Validated precise references go to `method/fonti/riferimenti.md`.
