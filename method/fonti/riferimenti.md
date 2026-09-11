---
title: Curated sources and references
updated: 2026-09-11
version: 0.5.0
linked_files:
  - method/conventions.md
  - method/framework/INDEX.md
  - docs/analysis/threat-hunting-evtx.md
changelog:
  - "0.5.0 — 2026-09-11 — the crawler/RAG ingestion half is removed with the RAG (2026-09-01): 'seed list for the crawler' becomes 'curated references', and the ingestion-criteria section is rewritten as 'How knowledge enters the suite' (curated markdown, no pipeline)."
  - "0.1.0 — 2026-06-14 — initial inventory of official sources."
  - "0.2.0 — 2026-06-16 — specific URLs validated (HTTP 200) for framework/methodology; new section 'Detection engineering and forensic analysis' in support of analysis/ (Sigma, Zircolite, Hayabusa, DuckDB, ECS, OCSF, EVTX-ATTACK-SAMPLES, YARA)."
  - "0.2.1 — 2026-07-20 — English translation."
  - "0.3.0 — 2026-07-21 — new section 'Threat hunting and AD attack paths' (EVTX-hunting article, BloodHound CE, SpecterOps query library); closed the level 2-3 threat-hunting to-do."
  - "0.3.1 — 2026-07-22 — detection-engineering section: added license-verified permissive YARA rule-sets (ReversingLabs MIT, ESET BSD-2) + awesome-yara index, cross-linked to docs/analysis/yara-rules.md."
  - "0.3.2 — 2026-07-24 — URL validation (all HTTP 200); ingestion criteria defined; CrowdStrike adapter done."
  - "0.4.0 — 2026-08-27 — vendor product documentation dropped: the CrowdStrike section and the SonicWall to-do removed, and 'vendor documentation' removed from what to index. Both products move to a separate project built on their official MCP servers; the RAG keeps frameworks, regulations and ACN."
---

# Sources and references

Inventory of reliable technical sources, curated as a reference for manual validation. Sources remain material **to be validated**, not absolute authority.

## Reliability hierarchy

- **Level 1 — official/primary:** vendor documentation, MITRE, NIST, CISA, CVE/NVD.
- **Level 2 — authoritative/curated:** SANS, security vendor research, national CERTs.
- **Level 3 — community:** technical blogs, rule repositories, research threads. Useful as a starting point, to be validated against level 1-2.

## Framework and methodology

| resource | url | level | notes |
|----------|-----|-------|-------|
| MITRE ATT&CK | https://attack.mitre.org | 1 | techniques and tactics, mapping |
| NIST CSF 2.0 | https://www.nist.gov/cyberframework | 1 | security functions, framework |
| NIST SP 800-61 — incident handling | https://csrc.nist.gov | 1 | incident management (verify current revision: r2/r3) |
| CISA — KEV catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | 1 | known exploited vulnerabilities |
| NVD / CVE | https://nvd.nist.gov | 1 | vulnerability details and scoring |
| SANS — white paper / IR | https://www.sans.org | 2 | IR methodology, threat hunting, forensics |
| CIS Controls / Benchmarks | https://www.cisecurity.org/controls | 2 | hardening |

> URLs validated HTTP 200 on 2026-07-24.

## Detection engineering and forensic analysis (in support of `analysis/`)

Tools and schemas wrapped or used by the analysis engine (see `analysis/DESIGN.md`). URLs verified (HTTP 200) on 2026-06-16.

| resource | url | level | notes |
|----------|-----|-------|-------|
| Sigma (SigmaHQ) | https://github.com/SigmaHQ/sigma | 2-3 | generic detection rule format + community ruleset |
| pySigma / sigma-cli | https://github.com/SigmaHQ/pySigma | 2-3 | library and CLI for Sigma rule conversion |
| Zircolite | https://github.com/wagga40/Zircolite | 3 | applies Sigma rules to EVTX/JSON via SQLite; wrapped by the engine |
| Hayabusa | https://github.com/Yamato-Security/hayabusa | 3 | DFIR timeline and detection on Windows event log, with ATT&CK mapping |
| Chainsaw (WithSecure) | https://github.com/WithSecureLabs/chainsaw | 3 | rapid hunting on EVTX with Sigma rules |
| DuckDB | https://duckdb.org | 1 | in-process analytical SQL engine; backend for correlation/long-tail |
| Elastic Common Schema (ECS) | https://www.elastic.co/guide/en/ecs/current/index.html | 1 | common field schema adopted in `analysis/` |
| OCSF | https://schema.ocsf.io | 1 | security event schema; alternative/complement to ECS |
| EVTX-ATTACK-SAMPLES | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | 3 | ATT&CK-labeled EVTX datasets for detection testing |
| OTRF Security-Datasets | https://github.com/OTRF/Security-Datasets | 3 | dataset (formerly Mordor) for validation and replay |
| YARA (VirusTotal) | https://github.com/VirusTotal/yara | 1-2 | pattern matching on files/processes/memory |
| YARA-X (VirusTotal) | https://github.com/VirusTotal/yara-x | 1-2 | Rust rewrite of YARA, reference successor |
| ReversingLabs YARA rules | https://github.com/reversinglabs/reversinglabs-yara-rules | 2-3 | **MIT** — permissive operational rule-set for `yara_scan` (see `docs/analysis/yara-rules.md`) |
| ESET malware-ioc | https://github.com/eset/malware-ioc | 2-3 | **BSD-2-Clause** — permissive; APT/malware YARA + IOCs |
| awesome-yara | https://github.com/pedramamini/awesome-yara | 3 | curated index of YARA rule-sets/tools; license-verified selection in `docs/analysis/yara-rules.md` (signature-base=DRL, Yara-Rules=GPL, Elastic=ELv2 → avoided) |

## Threat hunting and AD attack paths (in support of `analysis/`)

Analyst-facing references for EVTX hunting and Active Directory attack-path context. The EVTX-hunting
patterns are distilled into the operational playbook `docs/analysis/threat-hunting-evtx.md` (EID →
hunting purpose → Hayabusa toolbox command).

| resource | url | level | notes |
|----------|-----|-------|-------|
| A. Kiraz — "Threat Hunting with Windows Event Logs" | https://alican-kiraz1.medium.com/threat-hunting-with-windows-event-logs-338255a0da4a | 2-3 | per-EID hunting patterns (4625 spray, 4776 PtH, 4769 golden ticket, 5145 PsExec, 1644 BloodHound recon, Sysmon 1 WinRM); source for `docs/analysis/threat-hunting-evtx.md` |
| BloodHound Community Edition (SpecterOps) | https://bloodhound.specterops.io | 2 | AD attack-path mapping (SharpHound → Neo4j graph). **Companion**, not ingested: complements EventHound's event timeline (§6); see the BloodHound bridge in `docs/analysis/threat-hunting-evtx.md` |
| SpecterOps — BloodHound query library | https://queries.specterops.io | 2-3 | curated Cypher queries for BloodHound. Reference for correlation-recipe *ideas* only (Cypher/Neo4j ≠ DuckDB SQL), not direct reuse |

## How knowledge enters the suite

Knowledge is **curated markdown**, not a machine index. A source earns its place when it answers a
recurring question the analyst actually asks; the distilled answer goes into the relevant `method/`
index (`framework/`, `normative/`, `acn/`), and the raw material stays offline (official PDF, STIX
bundle) or is linked above for validation. ATT&CK technique→tactic is the one machine-consumed piece:
it is vendored as `analysis/analytics/attack_map.json`, regenerated from the official STIX bundle by
`analysis/analytics/build_attack_map.py`.

### Format hierarchy (prefer offline over web)

1. **Official text / STIX bundle** — the primary source (MITRE ATT&CK, GDPR/NIS2/DORA, ACN PDFs).
2. **Markdown notes** — the curated distillation, kept under `method/`.
3. **Web** — only to validate a link or read a public source with no offline equivalent; never
   scraped in bulk (§15).

### Adding a new source

1. Verify the source is authoritative (Level 1-3 above) and answers a recurring question.
2. Add it to this file with level and notes.
3. If it changes an analysis-grounded fact (an ATT&CK mapping, a compliance obligation), update the
   corresponding `method/` note in the same change.

## To do

- [x] Replace generic references with specific validated URLs. *(2026-06-16: framework/detection engineering; 2026-07-24: all HTTP 200 confirmed.)*
- [x] Add level 2-3 blog/research useful for threat hunting. *(2026-07-21: EVTX-hunting article + BloodHound CE + SpecterOps queries; distilled into `docs/analysis/threat-hunting-evtx.md`.)*
- [x] Define how knowledge enters the suite (curation, formats). *(2026-07-24: ingestion criteria for the crawler; 2026-09-11: rewritten for the markdown knowledge base — see 'How knowledge enters the suite'.)*
- [x] ~~SonicWall: add official links~~ — dropped 2026-08-27: vendor product documentation is out of scope (see the changelog entry above).
