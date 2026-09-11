---
title: SANS — Incident Response (PICERL)
updated: 2026-07-20
version: 0.1.1
linked_files:
  - method/framework/INDEX.md
  - method/framework/nist.md
  - method/security-instructions.md
changelog:
  - "0.1.0 — 2026-06-15 — first draft; SANS present in RAG as white papers/resources, but the 6 PICERL phases are to be validated on official source."
  - "0.1.1 — 2026-07-20 — English translation."
---

# SANS — Incident Response (PICERL)

> Provenance: SANS white papers and resources are referenced, but the six IR
> process phases are **not** directly distilled in local notes. The content
> below is the framework standard: **validate on official
> SANS material** before citing it as certain (rule §6 in `method/conventions.md`).

## The six phases (PICERL)

The SANS incident response process is commonly described in six phases
(acronym **PICERL**):

1. **Preparation** — tools, access, runbook, baseline: what is needed *before*
   the incident.
2. **Identification** — recognize that an incident is occurring and define its
   scope and severity.
3. **Containment** — limit propagation (short-term and long-term containment),
   preserving evidence.
4. **Eradication** — remove the cause (malware, compromised accounts, persistence).
5. **Recovery** — restore systems to production and monitor recovery.
6. **Lessons Learned** — post-mortem analysis and improvement.

## Relationship with NIST SP 800-61

Same substance, different segmentation: SP 800-61 (`nist.md`) combines
Containment/Eradication/Recovery into a single phase and concludes with
Post-Incident Activity. They can be used interchangeably as a process grid.

## Use in analysis

Consistent with `method/security-instructions.md`: the analyst places the
activity in the current phase to choose the appropriate step. Recurring
operational rule in the workspace: **triage before containment** — in
Identification we gather and observe (non-invasive steps) before moving to
Containment with actions that modify the endpoint's state (§12 of
`method/conventions.md`: state the impact of a command before proposing it).
Collected evidence must be anonymized (`method/anonymization.md`).
