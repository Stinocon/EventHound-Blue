---
title: ACN — official documents (index)
updated: 2026-09-11
version: 0.1.3
linked_files:
  - method/framework/INDEX.md
  - method/normative/
changelog:
  - "0.1.3 — 2026-09-11 — `rag/sources.yaml` left `linked_files` and the 'Portal crawling' section rewritten after the RAG removal (2026-09-01)."
  - "0.1.0 — 2026-06-15 — initial index; 7 official ACN PDFs indexed in the RAG collection `acn`."
  - "0.1.1 — 2026-07-20 — English translation."
  - "0.1.2 — 2026-07-21 — fixed stale CLI reference (pipeline.query is a deprecated alias; use pipeline.retrieve, per method/conventions.md §14/§21)."
---

# ACN — Agenzia per la Cybersicurezza Nazionale

Official ACN documents used as national normative/methodological knowledge to support analysis and documentation writing. The PDFs (raw input) are **gitignored** (`method/acn/*.pdf`); this index remains versioned.

They are the raw PDFs in this directory; the curated notes below summarize them.

## Documents present

| document | theme |
|----------|-------|
| `ACN_Tassonomia_Cyber_CLEAR.pdf` | Taxonomy of cyber attacks/events (TLP:CLEAR) |
| `Definizione del processo di gestione degli incidenti di sicurezza informatica.pdf` | NIS Guidelines — incident management and notification process |
| `Linee guida per la definizione dei processi e delle procedure per la gestione degli incidenti di sicurezza.pdf` | Processes and procedures for incident management |
| `Linee guida per la definizione dei processi di cyber risk management e security by design.pdf` | CAD Guidelines — cyber risk management and security by design |
| `Linee guida ACN rafforzamento resilienza.pdf` | Strengthening resilience |
| `Linee guida config posta elettronica autenticazione_2604.pdf` | Email configuration and authentication (SPF/DKIM/DMARC) |
| `Guida alla lettura Specifiche di base.pdf` | Reading guide for Basic specifications |

## Use in analysis

Complementary national reference to EU texts (`method/normative/`): ACN provides the operational *how* for Italy (incident management and notification, risk management, email hardening) where GDPR/NIS2 provide the obligation. Particularly useful for writing documentation and procedures aligned with national guidelines.

## Adding documents

1. Save the new official PDF in `method/acn/` (it will be ignored by git).
2. Add a row to the table above and, where useful, a curated note summarizing what it changes.

## Web sources (opt-in, §15)

The official PDFs above are the primary path. Scraping the ACN portal (`acn.gov.it`) is deliberately
**not** done here: it would be bulk scraping of the national authority's website, which requires an
active VPN and explicit confirmation (§15 of `method/conventions.md`). Until that is warranted, the
curated notes in this index are maintained by hand from the official documents.
