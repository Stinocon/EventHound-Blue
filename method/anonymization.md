---
title: Anonymization rules and pseudonym convention
updated: 2026-07-24
version: 0.3.0
linked_files:
  - method/conventions.md
  - data/pseudonym-map.md
  - tools/check-leaks.sh
changelog:
  - "0.1.0 — 2026-06-14 — first draft of the anonymization rules."
  - "0.2.0 — 2026-07-20 — English translation."
  - "0.3.0 — 2026-07-24 — Two rules the existing text left implicit, added after a real CrowdStrike detection reached a versioned test fixture: the pseudonym map must be populated BEFORE the data is used, because check-leaks.sh matches against the map and an empty one silently disarms the content check; and pseudonymization covers test fixtures, doc examples and commit messages, not only reports — an identifier removed after the commit means rewriting history."
---

# Anonymization

**Public** (impersonal) policy on how to handle real client data. The real↔pseudonym mapping is sensitive data and lives **only** in `data/pseudonym-map.md` (private, never shared).

## Principle

On everything that can be shared (answers, notes, reports) **stable pseudonyms** are used: the same real element always has the same pseudonym, so the analysis stays consistent without exposing identifiers.

## What must be pseudonymized (client data)

| type | pseudonym convention | example |
|------|----------------------|---------|
| Client / organization name | `CLIENTE-A`, `CLIENTE-B` | ACME S.p.A. → `CLIENTE-A` |
| Hostname | `HOST-01`, `HOST-02` | `srv-dc01.acme.local` → `HOST-01` |
| Username / account | `USER-01`, `USER-02` | `m.rossi` → `USER-01` |
| Email | `user01@corp.example` | `m.rossi@acme.it` → `user01@corp.example` |
| Internal domain | `corp.example`, `corp.local` | `acme.local` → `corp.local` |
| Internal IP address (RFC1918) | placeholder `10.0.x.x`, keeping the network structure | `192.168.10.5` → `10.0.10.5` |
| Tenant ID / CID / org ID | `TENANT-01` | (real value) → `TENANT-01` |
| Paths with a real username | replace the user part | `C:\Users\m.rossi\...` → `C:\Users\USER-01\...` |

## What must NOT be pseudonymized (not client data)

It stays in plaintext because it is a technical indicator useful for the analysis and does not identify the client:

- File hashes (MD5/SHA1/SHA256), malware/family names, YARA/Sigma rules.
- CVEs, MITRE ATT&CK technique IDs (`Txxxx`), tool names and APT group names.
- **Malicious public** IPs/domains (external IoCs), C2 URLs.
- Legitimate system process/binary names (`powershell.exe`, `rundll32.exe`).

When in doubt: if the element helps identify *the client*, pseudonymize it; if it helps identify *the threat*, keep it in plaintext.

## Procedure

1. When ingesting a real input, identify the client's identifiers.
2. For each, reuse the existing pseudonym in `data/pseudonym-map.md` or assign a new one following the conventions above, and record it in the map. **Record it first, before the data is used for anything** — see below.
3. Work and answer using the pseudonyms.
4. The map stays in `data/` and is never quoted in full in shareable output.

### The map comes first, because it is what the guard shoots with

`tools/check-leaks.sh` does not detect client data by pattern: PII is not regex-able the way an IBAN is, and a `10.x` address is a legitimate placeholder. It looks for the **real identifiers listed in the map**. An empty or unfilled map therefore does not mean "nothing to find" — it means the content half of the guard has nothing to match and does not run. Populating the map is not bookkeeping to do afterwards; it is what arms the only automatic defence there is.

### A fixture is shareable output

Pseudonymization is easy to remember while writing a report and easy to forget everywhere else. It applies in full to **test fixtures, examples in documentation, and commit messages** — anything that gets versioned. Grounding an adapter on a real sample is the right call (`method/conventions.md` §6: no speculative code on guessed fields), but the sample must be pseudonymized *as it enters the repository*, not on the way out of it: a commit is not a draft, and removing an identifier afterwards means rewriting history everywhere the repository has been cloned or pushed.

## Limits

Anonymization reduces, it does not eliminate, the risk: context and correlations can still re-identify. Keep the minimization principle — do not reproduce real data that the analysis does not need.
