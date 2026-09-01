---
title: Framework and methodologies — index
updated: 2026-07-20
version: 0.2.1
linked_files:
  - method/security-instructions.md
  - method/fonti/riferimenti.md
changelog:
  - "0.1.0 — 2026-06-14 — initial index, notes to be populated."
  - "0.2.0 — 2026-06-15 — created files for MITRE ATT&CK, NIST, SANS, CIS Controls, Cyber Kill Chain; ATT&CK sourced from RAG, others with provenance notes and validation points. Updated status and links."
  - "0.2.1 — 2026-07-20 — English translation."
---

# Framework and methodologies

Curated notes on reference frameworks of "good practice" in cybersecurity. Each entry will become a dedicated file as needed.

| framework | purpose | status |
|-----------|---------|--------|
| **MITRE ATT&CK** | Taxonomy of adversary tactics and techniques (ID `Txxxx`). Reference for mapping observed behaviors. → [mitre-attack.md](mitre-attack.md) | draft (sourced from RAG) |
| **SANS** | Reference material and methodologies (Incident Response, threat hunting, forensics). 6-phase IR process (PICERL). → [sans-ir.md](sans-ir.md) | draft (to validate) |
| **NIST** | NIST CSF (Identify/Protect/Detect/Respond/Recover) and SP 800-61 (Computer Security Incident Handling). → [nist.md](nist.md) | draft (to validate) |
| **CIS Controls** | Prioritized controls for hardening and attack surface reduction. → [cis-controls.md](cis-controls.md) | draft (to validate) |
| **Cyber Kill Chain (Lockheed Martin)** | Phase-based model of the attack chain; useful as a narrative grid alongside ATT&CK. → [cyber-kill-chain.md](cyber-kill-chain.md) | draft (to validate) |

## Usage notes

- In analysis, map behaviors to **ATT&CK** (technique + tactic) when appropriate and link them to the response phase (SANS/NIST).
- Specific content and validated links live in `method/fonti/riferimenti.md`.
