---
title: Curated YARA rule-sets — recommended sources and usage
updated: 2026-08-30
version: 0.2.0
linked_files:
  - analysis/adapters/yara_scan.py
  - NOTICE.md
  - method/fonti/riferimenti.md
changelog:
  - "0.2.0 (2026-08-30) — the \"pending\" section described a state two changes behind: `engine/run_yara.py` shipped on 2026-07-24 and `/api/yara-scan` was REMOVED on 2026-08-28 rather than wired, because `/api/analyze` already applies uploaded rules and puts the matches through the store, the correlation and the case. Rewritten as \"where it stands\", and the attribution pointer moved from the workspace-local register to `NOTICE.md`, which is the one that ships — found by `check-doc-paths.py` once it stopped being green only on the author's machine."
  - "0.1.0 — 2026-07-22 — first draft: permissive rule-set recommendations (from awesome-yara, license-verified) + how to point yara_scan at a local, gitignored rules dir. Document-only choice (no third-party rules vendored, §10)."
---

# Curated YARA rule-sets

EventHound scans files with YARA via `analysis/adapters/yara_scan.py`
(`load_records(target, rules)`): it compiles every `.yar`/`.yara` under a
rules directory (recursively) and emits one common-schema record per match
(`event.source=yara`, `file.name`, `file.hash`, ATT&CK technique from rule
meta when present). YARA adds **content**-based detection, complementing the
**filename/hash** IOC matching of the THOR source.

`yara-python` is an **optional** dependency (C extension): install on demand
with `uv sync --extra yara`; without it the adapter degrades to a clean skip.

## Policy: reference, do not vendor (§10)

Third-party YARA rules carry **their own licenses** and are **not vendored**
into this (public) repo — that would create a licensing, bloat and
supply-chain surface. Instead: clone the rule-sets you want **locally** into
`analysis/yara_rules/`, which is **gitignored** (except the sample starter and
`.gitkeep`), so your local rules never get committed. Point `yara_scan` at
that directory.

Check the license of each rule-set before use — some popular sets are **not**
permissive:

| Rule-set | URL | License | Use here |
|----------|-----|---------|----------|
| ReversingLabs YARA Rules | github.com/reversinglabs/reversinglabs-yara-rules | **MIT** | ✅ permissive |
| ESET malware-ioc | github.com/eset/malware-ioc | **BSD-2-Clause** | ✅ permissive |
| InQuest yara-rules | github.com/InQuest/yara-rules | mixed (per-rule) | ⚠️ verify per rule |
| Florian Roth signature-base | github.com/Neo23x0/signature-base | **DRL 1.1** (was CC BY-NC) | ⚠️ not OSS-permissive — read the terms |
| Yara-Rules/rules | github.com/Yara-Rules/rules | **GPL-2.0** (copyleft) | ⚠️ copyleft |
| Elastic protections-artifacts | github.com/elastic/protections-artifacts | **Elastic License 2.0** | ⚠️ source-available, restrictions |

Licenses verified 2026-07-22; re-check, they change (signature-base already
moved CC BY-NC → DRL). Source list: **awesome-yara**
(github.com/pedramamini/awesome-yara).

## Usage

```bash
# 1. one-time: enable YARA
cd analysis && uv sync --extra yara

# 2. clone a permissive rule-set into the gitignored local dir
git clone https://github.com/reversinglabs/reversinglabs-yara-rules \
    analysis/yara_rules/reversinglabs

# 3. scan (programmatic — see the adapter; a run_yara CLI is a pending wrapper)
python -c "from adapters import yara_scan; \
    print(len(yara_scan.load_records('<target-file-or-dir>', 'yara_rules')))"
```

`yara_scan` records flow into the common schema like any other source, so a
YARA hit correlates by `file.hash`/`file.name`/`host` with EVTX/MFT/THOR.

## Where it stands

- `engine/run_yara.py` is the CLI (`--rules` + `--target`), and `run_case add`
  takes the same pair, so a match enters a persistent case like any other source.
- The GUI has **no YARA view and deliberately no YARA endpoint**: upload `.yar`
  rules in the Logs view alongside the files to scan and `/api/analyze` applies
  them to whatever no other adapter claimed. A dedicated `/api/yara-scan` existed
  briefly and was removed — it returned raw match records, while this road puts
  them through the store, the correlation and the case. One road in.
- A small **permissive starter** could be vendored (MIT/BSD only, recorded in
  `NOTICE.md` like every other redistributed artifact) if a turnkey default is
  wanted; deferred by the document-only choice above.
