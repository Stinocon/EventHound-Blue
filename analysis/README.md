---
title: EventHound — analysis and correlation engine
updated: 2026-09-11
version: 0.13.1
related_files:
  - analysis/DESIGN.md
  - analysis/schema/common-schema.md
  - docs/analysis/correlation.md
  - docs/analysis/threat-hunting-evtx.md
  - docs/analysis/performance.md
changelog:
  - "0.13.1 — 2026-09-11 — the demo is described as nine source types, not 'ten real source files'."
  - "0.13.0 — 2026-09-11 — RAG/LLM removal reflected in the body, not only the changelog: the Validation section no longer frames itself as a mirror of the RAG golden queries; the performance section drops the tool-call corpus (the removed `run_toolbench`/`eval/toolcall_prompts.json`); packaging names the single-image `eventhound` compose stack and the platform-neutral `uninstall.sh`."
  - "0.12.0 — 2026-08-30 — `--json-out PATH` is the canonical way to write JSON from the nine CLIs that took a path (`--json PATH` still works, deprecated, and says so once on stderr); `run_case new|add` reached seven of the eleven sources and now shares `run_report.add_source_args`, so MFT, osquery, CrowdStrike and YARA evidence can enter a persistent case from the CLI. Adapter failures report the tool's own message instead of the bare exception class, and a missing Zeek is stated rather than passed over."
  - "0.11.0 — 2026-07-24 — benchmarks documented (engine/run_bench.py + engine/run_toolbench.py + eval/toolcall_prompts.json): the pipeline profile, the tool-call corpus and where the measured figures live."
  - "0.10.0 — 2026-07-23 — testing story rewritten: pytest + coverage alongside script mode, real skips (tests/_helpers.skip_test) instead of silent passes, CLI smoke test, and the measured coverage figure."
  - "0.9.0 — 2026-07-23 — cases documented (analytics/case_store.py + engine/run_case.py): persistent analyses, why there are two tables, the schema-change rebuild, incremental sources, and the equivalence test."
  - "0.8.0 — 2026-07-23 — the correlation corpus documented (eval/correlation_corpus.json + engine/run_eval.py + the discrimination test): labelled cases, the knob each one guards, and the session-gap sweep that turns the default into a measured band."
  - "0.7.0 — 2026-07-23 — analysis bundle documented (engine/bundle.py + run_export + run_report --from-bundle + GUI import); run_report gains --format/--level; packaging section rewritten native-first (setup-macos.sh/uninstall-macos.sh, Docker as the alternative)."
  - "0.6.0 — 2026-07-21 — doc-sync: Hayabusa toolbox (eid-metrics/log-metrics/computer-metrics/search/pivot-keywords-list/extract-base64 + logon-summary) documented; Zeek noted in the PCAP section (was changelog-only); registry (RECmd + native .reg) and MFT (MFTECmd) adapters added to 'Other components'; containerized packaging (docker-compose.yml) mentioned."
  - "0.5.0 — 2026-07-20 — Zeek integration (pcap_zeek adapter, automatic tshark+Zeek PCAP pipeline), SigmaHQ community rules (3142 rules + 2 custom), decode engine (decode/: Base64/hex/URL/ROT/XOR/Base58/unicode)."
  - "0.4.0 — 2026-07-20 — D2: renamed 'GUI locale' → 'EventHound' in titles and READMEs; C2: inline SVG charts in GUI (process stacking, top talkers, ATT&CK techniques)."
  - "0.3.0 — 2026-07-20 — aligned runbook to the current suite: full EVTX stream (EvtxECmd, --evtx-full), logon 4624/4625 view (engine.run_logons), generic logs (logfile adapter, engine.run_logs), visual HTML report (engine.run_report), extended correlation (temporal episodes + cross-source indicators). Tool is now named EventHound (the GUI is its face)."
  - "0.2.0 — 2026-06-16 — Phase 1 implemented: Hayabusa wrapped (engine/hayabusa_runner.py), EVTX→ECS adapter (adapters/evtx_hayabusa.py), ATT&CK report (engine/report.py), CLI engine.run_evtx, validation test (tests/test_evtx_slice.py: mimikatz sample → T1003.001 PASS). Runbook updated to actual usage."
  - "0.1.0 — 2026-06-15 — Phase 0 scaffolding and decisions; Phase 1 runbook (ready, tools to install)."
---

# EventHound — analysis and correlation engine

Component for **analysis on real client data**:
the engine *flags* (e.g. `T1558.003` on `HOST-01`), the knowledge base under `method/` *explains*.
Full design in `DESIGN.md`. This README records the **Phase 0 decisions** and the operational
runbook (Phase 1 implemented).

## I have a … — where do I go

This file grew as a development diary, section by phase. An analyst does not arrive with a phase,
they arrive with a file, so this is the index by source. Every one of them ends up in the same
schema, the same store and the same correlation — that is the point of the suite, not a detail.

| I have | Command | Section |
|---|---|---|
| a Windows event log (`.evtx`) | `run_evtx`, or `run_report --evtx` | [EVTX → ATT&CK](#phase-1--evtx--attck-slice-implemented), [full stream](#full-evtx-stream-evtxecmd), [logons](#logon-46244625-view-lateral-movement), [toolbox](#hayabusa-toolbox-triagehunting-beyond-sigma-detections) |
| a capture (`.pcap`) | `run_pcap`, or `run_report --pcap` | [PCAP / network](#pcap--network-traffic-analysis-tshark--zeek-adapters) |
| any other log | `run_logs FILE --fmt auto\|access\|jsonl\|regex\|syslog\|line` | [Generic logs](#generic-logs--common-schema) |
| a registry export (`.reg`) or a hive | `run_report --registry` / `--registry-hive` | [Extended correlation](#extended-correlation) |
| an `$MFT` | `run_mft` | [One road in](#one-road-in--every-source-reaches-the-correlation) |
| a THOR scan report | `run_thor` | [One road in](#one-road-in--every-source-reaches-the-correlation) |
| a CrowdStrike export | `run_crowdstrike` | [One road in](#one-road-in--every-source-reaches-the-correlation) |
| an Okta System Log export | `run_okta` | [One road in](#one-road-in--every-source-reaches-the-correlation) |
| an osquery result log | `run_osquery` | [One road in](#one-road-in--every-source-reaches-the-correlation) |
| YARA rules and something to scan | `run_yara` | [One road in](#one-road-in--every-source-reaches-the-correlation) |
| **several of the above at once** | `run_report --evtx a.evtx --pcap c.pcap --thor s.txt …` | [One road in](#one-road-in--every-source-reaches-the-correlation) |
| **nothing at all** | `run_demo` | [The demo](#the-demo--a-runnable-product-without-customer-evidence) |

Everything below is the reasoning and the detail. State and backlog live in
[`docs/roadmap.md`](../docs/roadmap.md); the component map and the flow live in
[`docs/architecture.md`](../docs/architecture.md). This file explains how to *use* the engine and why
it is built the way it is — where the three overlap, those two are the source of truth and this one
points at them.

## Phase 0 decisions (made)

- **Common schema**: **ECS** subset (not OCSF) — see `schema/common-schema.md`.
- **Sigma detection on EVTX**: **Hayabusa**. Zircolite was evaluated at Phase 0 and
  **not adopted** — Hayabusa covers detection and timeline in one wrapped binary. This line
  said the opposite for months while no code referenced Zircolite at all: a decision recorded
  as taken, that nothing implemented.
- **Timeline**: **Hayabusa** (Rust, fast) as timeline/triage layer.
- **Store/analytics**: **DuckDB** (long-tail and cross-source correlation).
- **File/memory matching**: **YARA** (later phase, `yara_rules/` directory).

Remaining open points are in §10 of `DESIGN.md` (e.g. when to introduce Chainsaw,
test dataset licensing).

## Structure

```
analysis/
├── adapters/   # parsers for source -> common schema (evtx, crowdstrike, okta, …)
├── schema/     # common ECS-subset schema (common-schema.md)
├── sigma/      # Sigma rules used/curated
├── yara_rules/ # YARA rules for file/memory (dir not named 'yara' to avoid shadowing `import yara`)
├── analytics/  # long-tail recipes and correlation in SQL/DuckDB
├── engine/     # orchestration: wraps tools, normalizes, executes logic
├── demo/       # the simulated incident: one scenario, ten generated source files
├── eval/       # labelled corpus: what correlation must (and must not) conclude
├── tests/      # detection test set (known datasets -> expected outcomes)
├── cases/      # persistent analyses (private, gitignored: the data itself)
└── reports/    # reports on real cases (private, anonymized; keep out of git)
```

Privacy/git: code/rules/analytics are **versionable**; real client EVTX and
reports are **private** (go in `data/`, gitignored). Public test datasets
(EVTX-ATTACK-SAMPLES) can be referenced rather than vendored.

## Phase 1 — EVTX → ATT&CK slice (implemented)

The first slice is operational: wraps **Hayabusa** (Rust, ~5000 Sigma rules with
MITRE ATT&CK mapping), normalizes detections into the common ECS schema and produces
a Markdown report. All local and offline.

**Toolchain (in `analysis/.tools/`, gitignored).** One-time setup:
- Hayabusa: platform release from github.com/Yamato-Security/hayabusa
  (binary + `rules/` and `config/` directories), made executable.
- Public test dataset: clone of
  github.com/sbousseaden/EVTX-ATTACK-SAMPLES.
- (Nothing else. An earlier draft listed a Zircolite clone as optional; it is not used by any code
  path in this repository and cloning it does nothing.)

**Usage.**
```
cd analysis
uv run python -m engine.run_evtx "<file.evtx>" [--out report.md] \
    [--profile super-verbose] [--min-level low]
```
Example on a public sample (detects `T1003.001` LSASS dumping, `T1059.001` PowerShell):
```
uv run python -m engine.run_evtx \
  ".tools/EVTX-ATTACK-SAMPLES/Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx"
```

**Components.**
- `engine/hayabusa_runner.py` — Hayabusa binary wrapper (`json-timeline`).
- `adapters/evtx_hayabusa.py` — Hayabusa JSONL → common schema record (ECS-subset).
- `engine/report.py` — record → Markdown report (context, ATT&CK techniques, timeline, next steps).
- `engine/run_evtx.py` — orchestration CLI.

The report ends up in `reports/` (gitignored): if the data is real, it must be
pseudonymized before sharing (§9).

## PCAP / network traffic analysis (tshark + Zeek adapters)

Complementary adapter to the EVTX slice, same common schema (network domain):
wraps **tshark** to extract from a PCAP the network fields (source/destination.ip,
source/destination.port, dns.question.name) and produces a report with conversations/flows,
top talkers, DNS queries and **ATT&CK signals as hypotheses** (e.g. non-standard port →
`T1571`, DNS query → `T1071.004`, outbound volumes → `T1041`).
Those three signals are produced by `run_pcap` **in its own Markdown output only**: they are not
attached to the records, so they do not reach the store, the correlation, the kill chain or the
attack map. Network evidence therefore corroborates by *entity* and by *time* — a shared address,
an episode, the beaconing recipe — and not by ATT&CK phase. Worth knowing before reading a
kill-chain narrative that names only the endpoint sources.
The pipeline also runs
**Zeek** on the same PCAP (application-layer visibility: HTTP, TLS/JA3, DNS responses,
notices) and merges its records per connection; Zeek is optional (silent skip if not
installed). Both carry `source.port`, which is what identifies a *connection*: tshark reports a
capture packet by packet and Zeek reports it connection by connection, and without that field
`recipes.beaconing` counted every packet of one exchange as a separate call-back (see
[`docs/analysis/correlation.md`](../docs/analysis/correlation.md)).
```
uv run python -m engine.run_pcap "<file.pcap>" [--out report.md]
```
Components: `adapters/pcap_tshark.py` (tshark → record), `adapters/pcap_zeek.py` (Zeek TSV logs →
record) and `engine/run_pcap.py` (analytics + report). Signals are *hypotheses* to validate against
evidence, never conclusions (§6).

## Phase 2 — long-tail analytics + correlation (DuckDB)

Loads one or more sources (EVTX/PCAP) into an in-memory **DuckDB** store on the common
schema records and runs long-tail recipes and cross-source correlation. Philosophy: in real
noise, malicious behavior is often *rare* (a process seen once, an anomalous parent-child
pair, a one-off DNS query, periodic beaconing) — the recipes isolate the tail. All local and
in memory; nothing is written unless the analysis is deliberately saved as a case (below).

```
uv run python -m engine.run_analytics --evtx a.evtx --pcap c.pcap        # terminal report
uv run python -m engine.run_analytics --pcap c.pcap --json-out out.json  # output for the GUI
```

Components: `analytics/store.py` (record → `events` table), `analytics/recipes.py` (process
stacking, first-seen host/user, rare parent-child, top talkers, rare DNS/long DNS, non-standard
ports, **beaconing** C2), `analytics/correlate.py` (unified timeline, per-host summary,
**shared indicators** across sources), `analytics/runner.py` (build records + `analyze`, reused
by the GUI). The same `analyze()` powers the web GUI (Phase 3).

## Full EVTX stream (EvtxECmd)

Hayabusa's Sigma-only detections are blind to long-tail: a benign event does not trigger a
rule, but it may be the anomaly that matters. With **EvtxECmd** the EVTX is read in **full stream** —
every event enters the common schema (source `evtx_full`), not only those that fire. Requires the
`dotnet` runtime and the dll in `.tools/evtxecmd/`.
```
uv run python -m engine.run_analytics --evtx-full a.evtx --pcap c.pcap
```
Components: `engine/evtxecmd_runner.py` (`dotnet` wrapper), `adapters/evtx_evtxecmd.py` (EvtxECmd CSV →
record) with the shared channel-aware Event ID map `adapters/windows_eventid.py`.

## Logon 4624/4625 view (lateral movement)

Dedicated lateral movement view: summarizes Windows logons highlighting **remote logons**
(Type 3/8/9/10) and **rare account→host pairs**, rather than detections only.
```
uv run python -m engine.run_logons "<file.evtx>" [--out report.md]
```
Component: `engine/run_logons.py` (uses `hayabusa_runner.run_logon_summary`, not just Sigma rules).

## Hayabusa toolbox (triage/hunting beyond Sigma detections)

Hayabusa ships several subcommands beyond `json-timeline` (Sigma detection): `hayabusa_runner.py`
exposes them through `run_command()` for frequency/orientation triage and keyword/regex hunting —
useful when a lead is not (yet) a Sigma rule:
- `eid_metrics()` / `log_metrics()` / `computer_metrics()` — which EIDs, which log channels, which
  hosts, how often (long-tail orientation).
- `search()` — keyword or regex hunt across the full EVTX stream.
- `pivot_keywords()` — extracts IOC-like values (accounts, IPs, hosts) to pivot on.
- `extract_base64()` — decodes Base64 blobs embedded in event fields.

In the GUI these are six `POST /api/hayabusa/*` endpoints living **inside** the EVTX view (single
shared upload, no separate view). `docs/analysis/threat-hunting-evtx.md` is the reading key: per-EID
hunting patterns mapped to the toolbox command that surfaces them.

## Generic logs → common schema

The `logfile` adapter brings arbitrary logs into the common schema, making them **correlatable**
with EVTX and PCAP (e.g. a SonicWall SMA log alongside host EVTX).
```
uv run python -m engine.run_logs "<file.log>" [--fmt auto|access|jsonl|regex|line]
```
Components: `adapters/logfile.py`, `engine/run_logs.py`. Enables web views (HTTP status
distribution, URLs under pressure, source IP by volume).

## Visual HTML report

From heterogeneous sources (EVTX/PCAP/log) to a **self-contained HTML report** — inline SVG
charts, tables and correlations, no external resources. Local, **never** an Artifact (contains
client data, §9-10).
```
uv run python -m engine.run_report --evtx a.evtx --pcap c.pcap --log w.log --out report.html
uv run python -m engine.run_report --evtx a.evtx --format markdown --level summary --out r.md
```
Components: `engine/report_html.py` (rendering), `engine/run_report.py` (CLI). The same rendering is
exposed by the GUI (`POST /api/report`); `--format html|markdown|json` and `--level` mirror it.

## Analysis bundle (export / re-import)

A **bundle** is the `analyze()` result plus provenance in one versioned JSON —
`{bundle_version, created_at, tool_version, meta, analysis}` — so a case can be reopened without
re-running the tools over evidence that may no longer be available. The evidence files are
deliberately **not** in it (client data, §9).

```
uv run python -m engine.run_export --evtx sec.evtx --name case-01 --out case.json
uv run python -m engine.run_export --from-json report-full.json --out case.json   # wrap an existing export
uv run python -m engine.run_report --from-bundle case.json --format markdown --out case.md
```

Components: `engine/bundle.py` (shape + validation, single source of truth), `engine/run_export.py`
(CLI). In the GUI: format **Bundle** in the Report & Bundle view to download, **Import bundle** to load
one back (client-side, the file never reaches the server). `engine/bundle.py:load()` also accepts a bare
`analyze()` JSON export, so an already-exported report is never a dead end. Tests: `tests/test_bundle.py`.

## Cases — an analysis that survives the process

A bundle is a snapshot of the *conclusions*; a **case** keeps the **data**. One directory per case
(`analysis/cases/<id>/`) holding a file-backed DuckDB and a small JSON of metadata and notes, which
is what makes reopening, annotating and comparing two analyses of the same host possible.

**Every analysis lands in a case, without being asked to.** The correlation that makes this product
worth using happens *between* uploads — a capture today and an EVTX tomorrow bridge only if both are
in the same store — so behind an opt-in checkbox the default experience was the one where nothing
correlates. The GUI mints `case-<today>-NN` on the first analysis and names it in the sidebar; the
browser sends it back on every further upload, so a session accumulates into one case. `no_case=true`
(a checkbox in the Cases view) is the opt-out for a one-off look at a single file.

Because each upload then re-analyses the *whole* case, each one also reports **what changed** —
new bridges, bridges that gained a corroborating tool, new techniques, a kill chain that now reaches
further, separate leads that turned out to be one incident. `run_case add` prints it; the GUI shows
it as a banner above the results.

**Infrastructure addresses are declared, never guessed.** A gateway, a proxy or a DNS resolver is
shared by every host on the network, so as a correlation bridge it links everything to everything —
and nothing in the data says which address it is, because a gateway is an ordinary unicast address.
Declaring them demotes those bridges (they stay visible: sometimes the proxy is where the
interesting thing happened) and keeps them out of the clustering, where a single universal connector
merges every lead into one useless blob:

```
uv run python -m engine.run_case infra incident-042 10.10.10.1 10.10.0.1
```

```
uv run python -m engine.run_case new incident-042 --title "SMA compromise" --evtx sec.evtx
uv run python -m engine.run_case add incident-042 --pcap perimeter.pcap     # accumulates, then says what changed
uv run python -m engine.run_case add incident-042 --mft \$MFT --osquery osq.log --crowdstrike det.txt
uv run python -m engine.run_case analyze incident-042 --json-out out.json
uv run python -m engine.run_case note incident-042 "4624 type 3 from the web log IP"
uv run python -m engine.run_case diff incident-042 baseline-clean           # what is new vs a baseline
uv run python -m engine.run_case list | show | rm
```

The DuckDB holds two tables on purpose: `events`, the analytic table every recipe queries, and
`raw_records`, the original common-schema dicts. The second is what lets a case outlive a schema
change — `connect()` compares a fingerprint of the column layout and rebuilds `events` from the raw
records when it moved, instead of querying columns that no longer exist. Without it, every change to
`store.py` would quietly rot every stored case.

Sources are appended one at a time, so peak memory is one source rather than the whole case, and the
analytics then run off the file. The parsing step upstream still materializes its own file: this
lifts the ceiling on the analytics side, not on the adapters'.

`new` and `add` take the **same eleven sources** as `run_report` — they share `add_source_args` and
`build_source_kwargs` rather than keeping a third copy of the list, which is how four of them (MFT,
osquery, CrowdStrike, YARA) had been reachable from the GUI and from `run_report` but not from a
case.

`tests/test_case_store.py` asserts the equivalence that justifies the module: analyzing a persisted
case returns exactly what analyzing the same records in memory returns. Writing that test is what
surfaced a latent non-determinism — `string_agg` without `ORDER BY` made `source_list` depend on row
order — now fixed, so two runs of the same data produce byte-identical output.

In the GUI: the **Cases** view lists, opens, annotates and deletes them, and an analysis can be
written straight into a case as it runs.

PRIVACY (§9/§10): a case *is* client data. `analysis/cases/` is gitignored and listed as a forbidden
path in `tools/check-leaks.sh`; nothing exports it anywhere.

## Extended correlation

Beyond shared indicators, `analytics/correlate.py` produces **temporal episodes**: clusters with
session-gap linking multiple *families* of sources in the same window — "these events belong to
the same incident". Entities acting as bridges (IP/domain/user/host/hash/file) emerge as
**cross-source indicators**. Reading guide, with end-to-end example, in
`docs/analysis/correlation.md`.

## One road in — every source reaches the correlation

Eleven adapters exist; for a long time three of them had no way to be used. `$MFT` had neither a CLI
nor an endpoint (while the GUI showed an availability badge for it), registry hives had an endpoint
that bypassed the pipeline and handed raw rows back, and an Okta export uploaded to the GUI fell
through to the generic log adapter — which reads top-level keys only, so the actor, the client
address and the outcome vanished. Meanwhile the three CLIs that *correlate* accepted four sources
out of eleven, which made the command line the surface where correlation was impossible.

Everything now goes through `analytics.runner.build_records()`:

```bash
uv run python -m engine.run_mft '$MFT'                                   # new: MFT via MFTECmd
uv run python -m engine.run_analytics --thor scan.txt --registry keys.reg --okta log.json
uv run python -m engine.run_report --pcap c.pcap --registry-hive SYSTEM --mft '$MFT' --out r.html
uv run python -m engine.run_export --crowdstrike detections.txt --osquery results.log --out b.json
uv run python -m engine.run_logs auth.log --fmt syslog                   # syslog was supported, not offered
```

`run_analytics`, `run_report` and `run_export` share one declaration of those flags
(`engine/run_report.add_source_args`) rather than three copies that would drift.

## The demo — a runnable product without customer evidence

A fresh clone can analyse nothing: there is no evidence in the repository and there never will be
(§9/§10). `demo/scenario.py` closes that gap by *declaring* one intrusion — estate, chain, timings,
the bridges it must produce — and writing it out as nine source types in pure stdlib: two
appliance logs, an Okta export, the JSONL Hayabusa emits, a `.reg`, a THOR report, a CrowdStrike
clipboard export, an osquery result log, a YARA rule with the artifact it matches, and a capture
built packet by packet. Files, not records: generating records would prove the store and the
recipes while leaving the adapters — the part that reads a real artifact — untested.

```bash
uv run python -m engine.run_demo                   # generate, ingest into a case, correlate, report
uv run python -m engine.run_demo --artifacts-only  # write the files and stop
uv run python -m engine.run_demo --evtx-dir DIR    # also run Hayabusa over real .evtx
uv run python -m engine.run_demo --format markdown --level summary   # any run_report format/level
```

The report lands in `reports/`, not among the generated artifacts: `demo/out/` is rewritten on every
run, so a report written there outlived the evidence it was made from.

The demo also **declares its own infrastructure address** — in this estate the DC is the DNS
resolver, as it is on most Windows networks — because that is what an analyst would do and the
product is being shown in use. Without the declaration the resolver co-occurs with everything and
`incident_clusters` returns one component holding the whole network, including a host with no part
in the incident: 18 entities instead of 14, technically correct and useless to read.

Every run prints which sensors it had. EVTX is level 1 — the adapter and everything after it run
for real, the Hayabusa binary does not — and PCAP needs tshark while the YARA step needs
`yara-python`; a missing one is reported, never quietly worked around.

The payload's bytes are declared once and its SHA-256 derived from them, so the hash THOR,
CrowdStrike and osquery each report is genuinely the hash of the file YARA matched. The noise is
declared just as deliberately: `SYSTEM`, `DC-01$`, `127.0.0.1` and `svchost.exe` each appear in two
families and must *not* bridge them.

`demo/expectations.json` states what the correlation must conclude, in the same shape as
`eval/correlation_corpus.json` so `engine/run_eval`'s checkers verify both, and `tests/test_demo.py`
runs it end to end. The expectations were written from the scenario before it was first run: an
expectation copied off the output certifies what the code does, not what it should do.

## Validation

Tests declare, for a known dataset, the expected outcome and verify that the engine
produces it — the engine's *logic* is pinned whenever a rule or adapter is added or modified.
- `tests/test_evtx_slice.py` — mimikatz sample → `T1003.001` (skip if the EVTX dataset
  is not in `.tools/`).
- `tests/test_pcap_slice.py` — deterministic synthetic PCAP (generated at runtime):
  DNS, flows and non-standard port expected (skip if `tshark` absent).
- `tests/test_analytics.py` — synthetic records → long-tail recipes + correlation (no Hayabusa/
  tshark): process stacking, rare parent-child, rare DNS, non-standard port, beaconing,
  cross-source indicator.
```
uv run pytest tests/                      # the whole suite
uv run pytest tests/ --cov                # ...with coverage
uv run pytest tests/test_analytics.py -v  # one file
uv run python tests/test_analytics.py     # or as a plain script, no runner needed
```

Both ways work by design: pytest gives collection, real skips and coverage, while every file stays
executable on its own so the suite never depends on a test runner being installed. `tools/check.sh`
uses pytest when it is there (`uv sync --extra dev`) and falls back to script mode when it is not.

**Skips are real skips.** A test whose binary or dataset is missing calls `tests/_helpers.skip_test`,
which prints and returns 0 as a script but raises a genuine `pytest.skip` under the runner. Before
that, a missing dependency made the test *pass* — three tests (MFT end-to-end, registry hives, YARA)
were reporting success for code that never ran.

**Coverage is measured, not assumed.** The first run said 62% and, more usefully, said that every
`engine/run_*.py` was at **0%**: the CLI — the surface this project calls primary — had never been
executed by a test. `tests/test_cli_smoke.py` fixes that: it discovers the entry points by glob (a
new CLI is covered the day it is written), asserts all of them start, and runs the offline ones for
real — decode, the full case lifecycle, the export → report bundle round trip, the corpus. Coverage
follows the subprocesses it spawns, otherwise the number would keep reporting 0% for code it was
demonstrably running. The suite sits at **70%** with the optional `yara` extra installed and
**69%** without it (89 tests, measured 2026-08-27) — the figure depends on which optional
dependencies are present, which is why it is quoted with that condition rather than as a single
number. It read 71% when the CLI smoke test landed in July; the value here is re-read from
`tools/check.sh` rather than carried forward, because a coverage number quoted from memory is
exactly the kind of claim this section exists to refuse.

### The correlation corpus

Tests answer "does this still work". The corpus answers the harder question — **is the tuning
right**. The confidence weights, the beaconing jitter threshold and the episode session-gap were set
by hand and never measured, so `eval/correlation_corpus.json` declares labelled cases (records in
the common schema plus what the engine *must* conclude) and `engine/run_eval.py` reports what holds.

```
uv run python -m engine.run_eval                 # 10 cases, exit 1 on any failed expectation
uv run python -m engine.run_eval --case <id> -v  # one case, every check listed
uv run python -m engine.run_eval --sweep-gap     # episode expectations across session-gaps
```

Every case names the **knob** it guards and carries a `rationale` — the security claim behind the
label — because relaxing an expectation to make a run green is exactly the failure mode this is
meant to prevent. The sweep turns the session-gap from a chosen number into a measured band: below
it a real chain gets split, above it unrelated activity merges into one episode.

`tests/test_corpus_discriminates.py` guards the guard: it breaks one knob at a time and asserts the
case protecting it turns red. A case that cannot be made to fail measures nothing.

### Performance

How the pipeline behaves on a large dataset, produced by a command rather than an impression.

```
uv run python -m engine.run_bench --analytics       # per-stage profile (synthetic, offline)
uv run python -m engine.run_bench --ingest          # real Hayabusa throughput on a local corpus
```

The figures, the hardware they were measured on, and the three defects that measuring exposed are
in [`docs/analysis/performance.md`](../docs/analysis/performance.md). The benchmark is not in the
default gate (`tools/check.sh --bench` runs the quick profile): it reports, it does not assert, and
a timing threshold would only encode the speed of the machine that wrote it.

## Other components (2026-06-21, extended 2026-07-21)

- **EventHound GUI** (local web) on top of \`analyze()\`: \`analysis/gui/\` (FastAPI + HTML), see its README.
- **Baseline/diffing**: `analytics/baseline.py` — what is NEW compared to a known-good baseline.
- **Case management**: `analytics/case.py` + template `reports/templates/caso-investigazione.template.md`.
- **YARA**: `adapters/yara_scan.py` (file→common schema), optional dep `uv sync --extra yara`,
  rules in `analysis/yara_rules/`.
- **Threat intel enrichment** (Shodan/VT, egress-gated): `tools/enrichment/`.
- **Compliance mapping** (incident→GDPR/NIS2/DORA obligations): `tools/compliance/`.
- **Registry**: two paths into the common schema — native `.reg` export parsing
  (`adapters/registry_regfile.py`, wired into the main analytics pipeline/GUI upload) and live-hive
  parsing via **RECmd** (`engine/recmd_runner.py` + `adapters/registry_recmd.py`, ASEP/persistence
  filtering, dedicated `POST /api/registry` in the GUI; requires `dotnet`).
- **MFT**: `engine/mftcmd_runner.py` + `adapters/mft_mftecmd.py` wrap **MFTECmd** (NTFS $MFT →
  common schema: path, timestamps, size, attributes). Adapter and runner are implemented and
  tested (`tests/test_mft.py`); GUI availability is health-checked but not yet wired to a
  dedicated analysis endpoint.
- **Packaging**: native-first — `../setup.sh` installs the binaries into `.tools/` and runs the
  stack on the host; `../uninstall.sh` removes it. Docker stays for reproducible / non-macOS
  deployments: the root `docker-compose.yml` builds a single self-contained `eventhound` image
  (`analysis/eventhound.Dockerfile`, `python:3.12-slim-trixie`) with Hayabusa/tshark/Zeek/`dotnet` +
  EZ-tools baked in. Code is baked in (no volume mount): rebuild the image to pick up changes.

## Next phases

Curated operational YARA rules, a YARA view in the GUI, and the remaining host-artifact spokes
(PECmd, LECmd/JLECmd, Amcache, SrumECmd). New products are not a standing backlog item: each waits
on a concrete need and a real sample (see `docs/roadmap.md`, "Closed decisions"). See `DESIGN.md`
§9/§13.
