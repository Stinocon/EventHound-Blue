---
title: ACN — official documents (index)
updated: 2026-07-21
version: 0.1.2
linked_files:
  - rag/sources.yaml
  - method/framework/INDEX.md
  - method/normative/
changelog:
  - "0.1.0 — 2026-06-15 — initial index; 7 official ACN PDFs indexed in the RAG collection `acn`."
  - "0.1.1 — 2026-07-20 — English translation."
  - "0.1.2 — 2026-07-21 — fixed stale CLI reference (pipeline.query is a deprecated alias; use pipeline.retrieve, per method/conventions.md §14/§21)."
---

# ACN — Agenzia per la Cybersicurezza Nazionale

Official ACN documents used as national normative/methodological knowledge to support analysis and documentation writing. The PDFs (raw input) are **gitignored** (`method/acn/*.pdf`); this index remains versioned.

They feed into the RAG collection **`acn`** (source `acn-pdf` in `rag/sources.yaml`). Queryable with:

```
cd rag && uv run python -m pipeline.retrieve "<question>" --collection acn
```

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

Complementary national reference to EU texts (`method/normative/`, collection `normative`): ACN provides the operational *how* for Italy (incident management and notification, risk management, email hardening) where GDPR/NIS2 provide the obligation. Particularly useful for writing documentation and procedures aligned with national guidelines.

## Adding documents

1. Save the new official PDF in `method/acn/` (it will be ignored by git).
2. Re-index: `cd rag && uv run python -m pipeline.ingest --source acn-pdf`.

## Portal crawling (opt-in)

`rag/sources.yaml` contains a source `acn-web` (seed `acn.gov.it`) **disabled**.
It should be activated only with an active VPN and explicit confirmation (§15 of `method/conventions.md`): it is scraping of the national authority website. Until needed, the primary path remains the official PDFs above.
