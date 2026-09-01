---
title: Cyber Kill Chain (Lockheed Martin)
updated: 2026-07-20
version: 0.1.1
linked_files:
  - method/framework/INDEX.md
  - method/framework/mitre-attack.md
changelog:
  - "0.1.0 — 2026-06-15 — first draft; not found in local RAG, standard model content to validate on official source (Lockheed Martin)."
  - "0.1.1 — 2026-07-20 — English translation."
---

# Cyber Kill Chain (Lockheed Martin)

> Provenance: the Lockheed Martin Cyber Kill Chain is **not** present as
> direct content in the `knowledge_cyber` collection (the RAG provides MITRE
> tactics/phases). The content below is the model standard: **validate on
> Lockheed Martin source** before citing it as certain (rule §6 in `method/conventions.md`).

## The seven phases

Linear model of the attack chain from the attacker's perspective:

1. **Reconnaissance** — information gathering on the target.
2. **Weaponization** — payload preparation (e.g., document with exploit).
3. **Delivery** — payload delivery (email, web, USB).
4. **Exploitation** — exploit execution on the victim.
5. **Installation** — malware installation / persistence.
6. **Command and Control (C2)** — remote control channel.
7. **Actions on Objectives** — final objective (exfiltration, encryption, ...).

## Relationship with MITRE ATT&CK

The Kill Chain is a **narrative grid** of phases, linear and high-level; ATT&CK
(`mitre-attack.md`) is a **granular matrix** of tactics and techniques, non-
sequential. In practice: the Kill Chain tells *the story of the intrusion* in
broad strokes, while ATT&CK provides *verifiable details* (which technique,
which sub-technique) within each block. Different Kill Chain phases have
counterparts in ATT&CK tactics (e.g., Reconnaissance, Command and Control), but
the correspondence is not one-to-one and should be treated as guidance, not as
rigid mapping.

## Use in analysis

Useful for communicating to a non-specialist audience *how far* an attack has
progressed and for establishing the timeline of an incident. In detailed work
we drill down into ATT&CK; the Kill Chain remains the narrative level.
