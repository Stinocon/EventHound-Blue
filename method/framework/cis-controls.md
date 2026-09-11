---
title: CIS Controls
updated: 2026-07-20
version: 0.1.1
linked_files:
  - method/framework/INDEX.md
  - method/security-instructions.md
changelog:
  - "0.1.0 — 2026-06-15 — first draft; not found in local `knowledge_cyber` collection (only generic references to 'critical controls' in ISC2 material). Standard framework content to validate on official source (CIS)."
  - "0.1.1 — 2026-07-20 — English translation."
---

# CIS Controls

> Provenance: CIS Controls are **not** present in the local knowledge base
> (only generic references to "critical controls" in ISC2 material).
> The content below is the framework standard: **validate on
> `cisecurity.org`** before citing it as certain (rule §6 in `method/conventions.md`).

## Purpose

CIS Controls are a **prioritized** set of defensive actions to reduce attack
surface and the most common risks. They are designed to provide an order of
implementation: "what to do first" to achieve maximum defensive benefit. They
are mappable to other frameworks (e.g., NIST CSF) and used as a hardening
checklist.

## Implementation Groups (IG)

Prioritization works through **Implementation Groups**, profiles that scale
effort based on organization size and maturity:

- **IG1** — basic hygiene (essential cyber hygiene), for small organizations
  or those with limited resources.
- **IG2** — organizations with greater complexity and more sensitive data.
- **IG3** — mature organizations exposed to advanced threats.

To be verified on official source: the **exact number of controls** (version 8
counts 18) and "safeguards" for each IG, which vary between framework versions.

## Use in analysis

Less relevant for triage of a single incident, more useful further downstream:
when an incident reveals a gap (e.g., lack of MFA, insufficient logging,
incomplete inventory), CIS Controls provide the corresponding hardening
recommendation, prioritized by IG. Particularly useful in writing documentation
and post-incident recommendations.
