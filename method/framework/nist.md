---
title: NIST — CSF and SP 800-61
updated: 2026-07-20
version: 0.1.1
linked_files:
  - method/framework/INDEX.md
  - method/framework/sans-ir.md
  - method/security-instructions.md
changelog:
  - "0.1.0 — 2026-06-15 — first draft; NIST present in RAG as CSRC, but the precise structure of CSF and SP 800-61 is to be validated on official source."
  - "0.1.1 — 2026-07-20 — English translation."
---

# NIST — CSF and SP 800-61

> Provenance: the `knowledge_cyber` collection indexes NIST CSRC (glossary, SP
> 800, publications), but the precise structure of CSF and SP 800-61 does
> **not** emerge as structured text from local excerpts. The contents below are
> the framework standard: **validate on `csrc.nist.gov`** before citing them as
> certain (rule §6 in `method/conventions.md`).

## NIST Cybersecurity Framework (CSF)

The CSF organizes cyber risk management into **high-level functions**, which
decompose into categories and sub-categories. The historical functions of CSF
1.1 are five:

- **Identify** — know assets, risks, context.
- **Protect** — safeguarding measures.
- **Detect** — identify security events.
- **Respond** — act on a detected incident.
- **Recover** — restore capabilities and services.

To verify: **CSF 2.0** introduces the cross-cutting function **Govern**
(bringing the functions to six) and redefines some categories. Confirm version
and structure on the official publication before relying on it for
documentation.

## SP 800-61 — Computer Security Incident Handling

NIST reference guide for incident management. It articulates the incident
response cycle into phases; the commonly cited structure (to verify on SP
800-61, incl. the applicable revision) is:

1. **Preparation**
2. **Detection and Analysis**
3. **Containment, Eradication, and Recovery**
4. **Post-Incident Activity**

It is the "institutional" reference complementary to the SANS 6-phase process
(`sans-ir.md`): same substance, different granularity.

## Use in analysis

Consistent with `method/security-instructions.md`: the CSF provides the
governance framework (where the control lies: Detect/Respond), SP 800-61
provides the operational response process. In an analysis, after mapping the
behavior to ATT&CK (`mitre-attack.md`), we place the action in the response
phase (Detection & Analysis → Containment → ...) to choose the right step,
prioritizing triage before containment.
