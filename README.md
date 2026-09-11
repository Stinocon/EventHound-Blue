<!--
document: README — project map
version: 1.11
updated: 2026-09-11
changelog:
  - 1.11 (2026-09-11) — final release pass: the product version is v1.0.0 (`/api/health` and exported bundles report 1.0.0, matching the tag), and the demo is described as nine source types (the previous "ten" double-counted the two appliance logs).
  - 1.10 (2026-09-11) — the maturity section stops reading as "never tested, don't trust": it states plainly that this is a proof of concept, tested lightly on lab cases (public datasets, synthetic captures, the simulated incident), with the Okta/osquery adapters named as the least-exercised. A leftover Troubleshooting entry about the removed on-box assistant is gone, and a garbled `install`/Hayabusa bullet is repaired.
  - 1.9 (2026-09-11) — publication sweep after the RAG/on-box-LLM removal of 2026-09-01. The clone command now names this repository (`EventHound-Blue` — the old `EventHound` repo is deleted); a new section documents the analysis MCP server (`analyze` / `analyze_case` / `eid_lookup`, §9 pseudonymization and the `_privacy` warning); and the two known-gaps clauses that still described the removed RAG are gone — the changelogs above keep the removal in the past tense, where it belongs.
  - 1.8 (2026-08-30) — the README as a document for someone who did not write it. New **Development and tests** (the one runner, the two per-clone setup steps, the per-suite commands, the `uv sync --extra` trap where naming one extra uninstalls the other, and the clean-clone check — `git clone`, not `git archive`, which has no `.git` and answers a different question) and **Troubleshooting** (port, no-reload GUI, GitHub rate limit, the two guards that are meant to be loud on a fresh clone, the memory refusal, the shared Ollama daemon, a source that produced nothing). Three claims corrected against the code rather than reread: "Three interchangeable surfaces" survived in "Using it" after the opening paragraph was rewritten to stop saying it; the Licence section still listed **vendor documentation** among the RAG material, removed on 2026-08-27; and `./setup.sh all` was presented as "and you're done" while leaving Qdrant empty — the RAG index is built by a separate step, from PDFs that are not in this repository, and that is now said where the promise is made rather than 200 lines below it. The demo's `--reset` default is documented (it is what stopped the README's own first command from failing on its second run). Left alone deliberately: "three adversarial rounds, all dirty, counter at zero" is correct — the roadmap entries 1.30-1.32 are the four scopes INSIDE the third round, not three more rounds.
  - 1.7 (2026-08-27) — CrowdStrike and SonicWall product documentation removed from the RAG (collections `cs_falcon_docs` and `sonicwall_docs` deleted, `docs/crowdstrike/` and `docs/sonicwall/` removed): both products are moving to a separate project built on their official MCP servers. The RAG keeps what grounds the analysis itself — frameworks, regulations, ACN. The CrowdStrike *ingest adapter* stays: it parses an export the analyst already holds, like every other artifact source.
  - 1.6 (2026-07-24) — project licensed MIT (LICENSE) with NOTICE.md separating what is redistributed here (the Material Symbols icon paths, Apache-2.0) from the tools that are only driven and downloaded at install time; new "Licence" section.
  - 1.5 (2026-07-24) — native setup is no longer macOS-only: setup.sh dispatches to setup-macos.sh / setup-linux.sh over the shared tools/setup-common.sh, uninstall-macos.sh becomes the platform-neutral uninstall.sh, and the Linux caveats (vendor install scripts for uv/ollama, Zeek optional) are stated where the install is described.
  - 1.4 (2026-07-23) — persistent cases documented (engine.run_case, the Cases view, the footprint row); timeline and correlation corpus reflected in the CLI list.
  - 1.3 (2026-07-23) — added "Why there is documentation and regulation in here" (the regulatory and CrowdStrike strands, and why the latter is parked); RAG section now says what each collection is for.
  - 1.2 (2026-07-23) — disclaimer rewritten (proof of concept, AI-developed, no warranty) + "Why this exists" (a wrapper that makes existing tools talk, not a replacement for them) + "Using an AI assistant with EventHound" pointing at the new AGENTS.md onboarding file. Personal agent configuration removed from the repository.
  - 1.1 (2026-07-23) — native-first restructure: setup-macos.sh as the documented first run, Docker demoted to "alternative runtime", new "What lives where" footprint table + Uninstall + "Using it" (GUI/CLI/bundles) sections, backup section rewritten for the runtime-agnostic rag/backup.sh. Stale Docker-only instructions removed.
  - 1.0 (2026-07-21) — graphic banner (docs/brand/banner.svg) + disclaimer; doc-sync pass across the suite (Hayabusa toolbox in the EVTX view, threat-hunting playbook + DC-side 1644 rule, ThreatFox enrichment, RAG-as-service, Docker on slim-trixie). Repo prepared to go public.
-->

<p align="center">
  <img src="docs/brand/banner.svg" alt="EventHound" width="860">
</p>

# EventHound — cybersecurity analysis suite

> **Disclaimer — read this first.**
>
> This is a **personal project and a proof of concept**, not a finished product and not a commercial one — it never will be. It is published **as is, with no warranty of any kind**: it is still immature, it plausibly contains bugs, and there are certainly edge cases nobody has thought about yet. I have used it successfully on real cases, which is not the same as it being production software.
>
> It was **developed largely with AI**, across several assistants (Claude Code, Mistral Vibe), under my guidance and review. That was half the point: I wanted to go deeper into what these tools can actually do and into the concepts around them, and I wanted that exploration to end up as something useful in my day-to-day work rather than as a demo.
>
> The context is **defensive analysis and authorized incident response only** — not offensive tooling. Output may contain inaccuracies: validate against primary sources before acting on it operationally.

**EventHound** is a **local, offline** cybersecurity analysis suite that combines two main components:

1. **Analysis engine** (`analysis/`) — ingestion of EVTX, PCAP, registry, MFT, THOR, Okta, CrowdStrike and generic logs, normalization into a common ECS schema, detection (Hayabusa/Sigma) plus the full **Hayabusa toolbox** (metrics, keyword/regex search, keyword pivots, base64 extraction), long-tail analytics (DuckDB), cross-source correlation, YARA matching, baseline/diffing, case management, threat-intel enrichment (Shodan/VT/ThreatFox, egress-gated) and compliance mapping (GDPR/NIS2/DORA). CLI-first; the web GUI (`http://127.0.0.1:8700`) is a thin interface over the engine. The knowledge that grounds an analysis — MITRE ATT&CK, GDPR/NIS2/DORA, ACN — lives as plain markdown under `method/`, read directly.

2. **Deterministic tools** (`tools/`) — CVSS/EPSS scoring, compliance, Shodan/VT enrichment, workspace hygiene.

EventHound is built to run **fully offline**. Two surfaces do the whole job and either one is enough:
**100% via the GUI** and **100% via the terminal (CLI)**. There is no bundled LLM: reasoning about an
analysis is done by an external agentic harness (Pi, Claude Code, …) through the **analysis MCP
server** — `analysis/analysis_mcp_server.py` — which runs the pipeline and returns pseudonymized
findings (§9). Analysis data never leaves the machine: the only outbound traffic is **explicit,
opt-in fetches of public resources** — threat-intel / IoC lookups (Shodan, VirusTotal, ThreatFox) —
each egress-gated and restricted to public indicators (§9).

External AI assistants are **development tools**, not part of the shipped product and not required to run it. If you *want* to use one with EventHound, you can — see [Using an AI assistant with EventHound](#using-an-ai-assistant-with-eventhound) below. During development, real client data is handled under strict anonymization (§9); the product itself, being offline, has no cloud to send anything to.

## Why this exists

Nothing here tries to replace anyone's work, and nothing here is claimed as original where it is not. The forensic tools this suite drives — Hayabusa, the Eric Zimmerman tools, Zeek, tshark, THOR — are other people's excellent work, wrapped and credited, never reimplemented.

The gap I kept running into is a different one: there are plenty of good security tools, and **none of them talk to each other**. Each one answers its own question in its own format, and the analyst is left doing the joining by hand — the same host spelled three ways, the same hash in two cases, the same hour reconstructed across four exports. The products that solve that properly exist, and they cost more than a small operation can justify.

So this is a **wrapper**: something that takes those heterogeneous outputs, puts them on one schema, and lets me ask what actually happened in a given case. That is the whole ambition — not a new detection engine, not a SIEM, not a product.

### Why there is regulation in here

One other problem came from the same day job, and it explains the part of this repo that is not code.

Writing an incident report or a piece of technical documentation regularly means checking an obligation: does this qualify as notifiable, to whom, within how many hours, under which of GDPR / NIS2 / DORA. Re-reading a regulation from scratch every time is slow and, worse, error-prone. So the official texts and the ACN guidance are indexed locally and searchable (`normative`, `acn`), and `tools/compliance/` maps the characteristics of an incident onto the obligations it triggers — as a starting point to verify, never as legal advice.

Vendor product documentation used to live here too — CrowdStrike Falcon and SonicWall, indexed for query syntax and product behaviour. It has been removed: both vendors ship an official MCP server, which answers those questions against the live product instead of against a snapshot of its manual, so that work belongs in a separate project. What stays in EventHound is the *artifact* side of those products: the CrowdStrike adapter still parses a detection export into the common schema, exactly like an EVTX or a PCAP.

## The idea — tools as sensors, not the product

At the acquisition layer EventHound reinvents nothing: Hayabusa does the Sigma/ATT&CK matching, the Eric Zimmerman tools parse EVTX, MFT and registry, Zeek and tshark read the wire. These are existing, best-of-breed forensic tools — wrapped, not reimplemented (minimal code: reinvent nothing a tool already does well).

The value is the layer *above and between* them, which no single tool provides:

- **One schema.** Each tool emits a different format; the adapters (`analysis/adapters/`) map them all onto a single ECS-subset schema. That common ground is what makes heterogeneous outputs *comparable* — without it you have seven silos.
- **Correlation.** The DuckDB engine (`analysis/analytics/`) runs long-tail analytics (process stacking, rare parent-child, rare DNS, beaconing), builds temporal episodes and links indicators *across* sources — the same IP, user, host or hash seen in EVTX, PCAP and logs. This is analysis that operates over the tools' output; none of the wrapped binaries does it alone.
- **Interpretation.** The local knowledge base (`method/`, ATT&CK map) grounds findings: the engine *flags* (`T1558.003` on `HOST-01`), the knowledge base *explains*.

So EventHound is not a GUI over existing tools — it is a **normalization and correlation layer that uses those tools as sensors**. The tools are the probes; the work is putting them on one schema and surfacing the signal that only emerges by crossing them.

For the full component map, the end-to-end data flow and the offline boundary, see **[`docs/architecture.md`](docs/architecture.md)**.

## Scope of use

**What it does**
- **EventHound** — EVTX/PCAP/log ingestion, ECS normalization, detection (Hayabusa/Sigma), long-tail analytics (DuckDB), cross-source correlation, YARA, baseline/diffing, case management, HTML reports, local GUI.
- **Knowledge base** — MITRE ATT&CK (vendored as `analysis/analytics/attack_map.json`) and
  the GDPR/NIS2/DORA and ACN notes under `method/`, read directly as markdown.
- **Deterministic tools** — CVSS/EPSS scoring, GDPR/NIS2/DORA compliance, Shodan/VT/ThreatFox enrichment.
- **Agentic analysis** — the suite exposes itself to an external AI harness (Pi, Claude Code, …) through the **analysis MCP server** (`analysis/analysis_mcp_server.py`), which runs the pipeline and returns pseudonymized findings. External AI assistants are used to **develop** the suite too, under `method/conventions.md`; neither is needed to run it.

**What it is NOT**
- Not a cloud SIEM: it operates **locally and in batch** on the supplied datasets, not in real time.
- It does not run commands against remote systems: it **proposes** them, execution is up to the user (see [method/conventions.md §12](method/conventions.md)).
- Not offensive: the context is exclusively defensive analysis and authorized incident response.
- Not a cloud product: EventHound is **self-contained and offline by design** — not a hosted service, and it sends no analysis data anywhere (only opt-in public-indicator lookups reach the network).

## Using an AI assistant with EventHound

Optional, and entirely your choice — the suite is complete without it. If you want one, clone the
repo, start your assistant **inside the repository**, and it will pick up
[`AGENTS.md`](AGENTS.md): a briefing on what the tools are, how to call them, and the rules that
matter when the data is real (client data never leaves the machine, security scores come from the
deterministic oracle, commands are proposed and not executed). It works with any assistant that reads
the `AGENTS.md` convention — Claude Code, Cursor, Codex, Gemini CLI.

That file also documents the optional `.mcp.json` that exposes the suite's own tools — analysis,
CVSS/EPSS scoring, compliance mapping, threat-intel enrichment — as native MCP tools. It is **not**
shipped enabled: what your agent launches should be your decision, not a default.

My own assistant configuration is deliberately **not** in this repository: it is personal workflow,
not something you should have to download to use the suite.

## The analysis MCP server

EventHound ships **one** MCP server — `analysis/analysis_mcp_server.py` — that exposes the analysis
pipeline to an external agentic harness (Pi, Claude Code, Cursor, …). The reasoning lives in the
agent; EventHound stays a deterministic local tool:

```bash
cd analysis && uv run python analysis_mcp_server.py    # stdio MCP server
```

It exposes three tools:

- **`analyze`** — run the full pipeline over artifact paths and return the correlated findings
  (timeline, bridges, clusters, kill chain, host overview, technique catalogue).
- **`analyze_case`** — run the pipeline against a persistent case (`analysis/cases/`).
- **`eid_lookup`** — resolve a Windows Event ID against the channel-aware vocabulary.

Responses are **pseudonymized** (§9): hosts, users, internal IPs and domains are replaced with
stable pseudonyms via `data/pseudonym-map.md` before the payload reaches the agent. If the map is
empty the response carries a `_privacy` warning — treat that as a stop signal, not a formality.

The same three tools, plus the scoring, compliance and enrichment oracles, are also available as
native MCP tools; the full `.mcp.json` block is in [`AGENTS.md`](AGENTS.md). Nothing is enabled by
default — what your agent launches is your decision.

## Conventions

Comments across the codebase cite rules by number — `(§9/§10)` where client data is handled, `(§6)` where a security figure is produced, `(§12)` where a command is proposed rather than run. Those citations resolve in **[`method/conventions.md`](method/conventions.md)**: anonymization, source hierarchy, the git/privacy boundary, the posture on commands, hygiene. Reading it first makes the rest of the code read as intended. The engineering counterpart is [`method/minimal-code.md`](method/minimal-code.md).

Development of EventHound is done with AI assistants under those same rules; their configuration is personal workflow and is deliberately **not** part of this repository.

## Structure

| path | role | nature |
|------|------|--------|
| `method/` | how analysis is done and method knowledge: `conventions.md` (the § rules), `minimal-code.md`, `security-instructions.md`, `anonymization.md`, `glossary.md`, `framework/` (MITRE/NIST/SANS/CIS), `normative/` (GDPR/NIS2/DORA), `fonti/` | impersonal |
| `docs/` | analysis playbooks (`analysis/`), `architecture.md`, `roadmap.md`, `brand/` | impersonal |
| `CHANGELOG.md` | what changed between versions, one screen; the reasoning stays in `docs/roadmap.md` | impersonal |
| `data/` | real client data (anonymized) + `pseudonym-map.md` | **private** |
| `analysis/` | **EventHound**: EVTX/PCAP/log ingestion, ECS normalization, detection (Hayabusa/Sigma), long-tail (DuckDB), correlation, YARA, baseline/diffing, case management, threat-intel enrichment, compliance, GUI (`127.0.0.1:8700`), HTML reports | versioned (real data excluded) |
| `tools/` | deterministic tools: scoring (CVSS/EPSS), compliance (GDPR/NIS2/DORA), enrichment (Shodan/VT), workspace hygiene (`check.sh`, leak detection, injection scanning) | versioned |

## Privacy and anonymization
## Privacy and anonymization

Real data is sensitive. Work is done with **stable pseudonyms** (hosts, users, IPs, domains → `HOST-01`, `USER-01`, …); the real↔pseudonym mapping lives only in `data/pseudonym-map.md` (private). Full rules in `method/anonymization.md`.

Git/privacy model (the project uses git; `data/` and the other sensitive directories are excluded from versioning via `.gitignore`):
- **Versioned**: `method/`, `docs/`, `analysis/` (code), `tools/`.
- **Excluded** (`.gitignore`): `data/` (client data), `analysis/reports/`, `analysis/cases/`, `analysis/.tools/`, Python environments.

## Getting started (native — the recommended way)

The whole stack runs natively on **macOS and Linux** — **no part of EventHound requires Docker**.

```bash
git clone https://github.com/Stinocon/EventHound-Blue.git && cd EventHound-Blue
./setup.sh all              # install what's missing, start everything, then verify
```

Then open **http://127.0.0.1:8700**. That is enough to analyse evidence: the engine, the CLI and every
source view work from here.


## Using it

Two interchangeable surfaces over the same engine — the GUI is a thin layer, never a shortcut
around the CLI — and an external agentic harness on top of what they produce (see the paragraph at the
top of this file for what it can and cannot do).

**No evidence to hand? Run the demo first.** It generates one coherent intrusion as nine source types — appliance logs, an Okta export, an EVTX detection timeline, a `.reg`, a THOR report, a CrowdStrike export, an osquery log, a YARA match and a capture — then ingests them through the ordinary adapters and produces the full analysis and report. Nothing in it is real: the estate is `corp.example` and documentation address space, so it is safe to show anyone.

```bash
cd analysis
uv run python -m engine.run_demo                   # generate, ingest, correlate, report
uv run python -m engine.run_demo --artifacts-only  # write the files, then load them by hand in the GUI
uv run python -m engine.run_demo --format markdown --level summary   # any run_report format/level
uv run python -m engine.run_demo --no-reset        # accumulate into the existing demo case
```

The case is rebuilt from scratch on every run (`--reset`, the default): without that, a second run
re-added the same nine sources to the same case and the store refused the batch, so the README's own
first command failed the second time anyone tried it.

The report lands in `reports/`, and the demo declares its own infrastructure address — in this
estate the DC is also the DNS resolver, as on most Windows networks — so the incident cluster names
the four hosts that took part rather than the whole network.

Loading the evidence one source at a time is the better demonstration: the correlation grows as it
arrives, and the GUI's Cases view can step through it without touching the terminal. What the demo does **not** exercise is stated on every run — EVTX arrives as the JSONL Hayabusa emits rather than through the binary (pass `--evtx-dir` with real `.evtx` to include it), and a missing tshark or `yara-python` is reported, never quietly worked around.

**GUI** (`http://127.0.0.1:8700`): upload EVTX / PCAP / registry / logs / THOR reports per view, analyze, then read the **Attack Map** — entities and how they are linked, in kill-chain order, with a phase-by-phase account underneath and a click through to the timeline — plus the dashboard for cross-source correlation, and export from **Report & Bundle**. **Load Demo Case** in the Cases view fills it with the simulated incident described above, with nothing to upload. The in-app **Help** view is the per-view walkthrough; the correlation model (normalization → confidence → clusters) is documented in [`docs/analysis/correlation.md`](docs/analysis/correlation.md), and the hunting playbook in [`docs/analysis/threat-hunting-evtx.md`](docs/analysis/threat-hunting-evtx.md).

**CLI** (from `analysis/`, everything the GUI does):

```bash
uv run python -m engine.run_evtx sec.evtx --out report.md            # EVTX → ATT&CK detections
uv run python -m engine.run_logons sec.evtx                          # 4624/4625 logon view (lateral movement)
uv run python -m engine.run_pcap capture.pcap                        # flows, DNS, beaconing signals
uv run python -m engine.run_logs access.log --fmt access             # generic logs (syslog/access/jsonl/regex)
uv run python -m engine.run_mft '$MFT'                               # NTFS $MFT via MFTECmd
uv run python -m engine.run_analytics --evtx a.evtx --thor scan.txt  # long-tail + correlation, any source
uv run python -m engine.run_report --evtx a.evtx --out report.html   # visual report (also --format markdown|json)
uv run python -m engine.run_case new c1 --evtx sec.evtx               # persistent case (list/add/show/analyze/note/diff)
uv run python analysis_mcp_server.py                                  # MCP: analyze / analyze_case / eid_lookup
```

**Cases — work that survives the session, and the default.** A bundle keeps the conclusions; a **case** keeps the data. It is a directory under `analysis/cases/` with a DuckDB of the events plus notes, so sources can be added over several days, an analysis can be reopened as it was, and two cases can be compared. Every analysis lands in one without being asked to — the correlation worth having happens *between* uploads, so behind an opt-in checkbox the default was the experience where nothing correlates. Each upload then re-analyses the whole case and reports **what changed**, and the gateway/proxy/resolver addresses can be declared so they stop bridging every host to every other:

```bash
uv run python -m engine.run_case new incident-042 --title "SMA compromise" --evtx sec.evtx
uv run python -m engine.run_case add incident-042 --pcap perimeter.pcap
uv run python -m engine.run_case note incident-042 "4624 type 3 from the web log IP"
uv run python -m engine.run_case infra incident-042 10.10.10.1     # gateway/resolver: demoted, never a cluster link
uv run python -m engine.run_case diff incident-042 baseline-clean
```

The GUI has a **Cases** view for the same thing, and can write an analysis straight into a case while it runs. A case *is* client data: `analysis/cases/` is gitignored and refused by the leak guard.

**Bundles — reopening an analysis.** A bundle is one versioned JSON holding the analysis results, correlations and metadata, but **not** the evidence files. It exists so a case can be reopened without re-running Hayabusa/tshark/EvtxECmd over data you may no longer have:

```bash
uv run python -m engine.run_export --evtx sec.evtx --name case-01 --out case.json
uv run python -m engine.run_report --from-bundle case.json --format markdown --out case.md
```

In the GUI, choose format **Bundle (re-importable)** to download one, and **Import bundle** in the same view to load it back — the import is client-side, the file never leaves the browser. A bundle carries the same real identifiers as any report: anonymize before sharing (§9), and note that `analysis/reports/` is gitignored for exactly that reason.

### Configuration and API keys

Third-party threat-intel services need a key. Set it **once**, from either surface — both read the
same store, so a key entered in the GUI is already in place for the CLI and the MCP tools, and vice
versa:

```bash
python3 tools/eventhound_config.py list            # masked status of every service + settings
python tools/eventhound_config.py set virustotal   # prompts without echoing the key
python tools/eventhound_config.py set-setting allow_egress true
```

In the GUI: **Settings → API keys**. The store is `data/config.json` — inside the project's private,
gitignored area, written `0600`, untouched by the uninstaller (so a reinstall finds its keys), and
overridable with `EVENTHOUND_CONFIG=<path>`. An environment variable (`VT_API_KEY`,
`THREATFOX_API_KEY`) always wins over the stored value, and the GUI says so when it does. Keys are
never displayed again after saving — only their last four characters.

Storing a key does **not** enable network traffic: outbound lookups remain opt-in
(`allow_egress`), and only public indicators are ever sent (§9/§15).

## Docker — the alternative runtime

For non-macOS hosts or a reproducible deployment, the root `docker-compose.yml` brings up a single `eventhound` image with the engine, the GUI and every wrapped tool baked in.

## Backup and moving to another machine

The **code** travels with the repo; three things do not (all gitignored) and must be reprovisioned:

- **`data/`** (real client data + `pseudonym-map.md`) — private, never leaves the machine.

## Development and tests

One runner covers everything, and it is what "green" means here:

```bash
tools/check.sh                 # 16 sections: leak + input/trust guards, doc guards, engine suite,
                               # GUI (HTTP + JS), scoring/enrichment/compliance golden
tools/check.sh --props         # + Hypothesis property tests for the scoring oracle
tools/check.sh --bench         # + the quick performance profile
```

Two things to do once per clone:

```bash
git config core.hooksPath tools/git-hooks     # pre-commit leak scan (§9)
tools/check-config-integrity.sh --update      # snapshot the trust surface; the baseline is local,
                                              # not versioned, so it is absent until you make it
```

The individual suites, when you want one of them on its own:

```bash
cd analysis     && uv run pytest tests/ -q          # engine; without pytest the gate runs the same
                                                    # files as plain scripts, minus the coverage number
cd analysis/gui && uv run python tests/test_gui.py  # the HTTP layer, FastAPI TestClient
cd analysis/gui && node --test tests/*.test.js      # the pure JS in static/lib.js
```

`uv sync --extra dev` installs pytest and coverage; `--extra yara` installs `yara-python`. **Pass
both together** (`uv sync --extra yara --extra dev`) — `uv sync` resolves the environment to exactly
what you name, so asking for one extra alone uninstalls the other.

Two things the engine's own tests cannot tell you, and how to ask them instead:

```bash
cd analysis && uv run python -m engine.run_demo     # then READ the report — every serious defect
                                                    # of the last month surfaced by looking at it
d=$(mktemp -d) && git clone . "$d/EventHound" && (cd "$d/EventHound" && tools/check.sh)
```

That second line is not ceremony. A gate run in the tree where the installer has already run is a
gate run against a machine, not against the repository: it is how a hard check that fails in every
fresh clone stayed green here for weeks. Use `git clone` — a `git archive` extraction has no `.git`
and answers a different question.

## Troubleshooting

- **Port 8700 already in use.** `./setup.sh down gui` stops the one this project started (its pid is
  in `.run/gui.pid`). If something else owns the port, `analysis/gui/serve.sh` honours
  `ANALISI_GUI_PORT` — but `./setup.sh up gui` hardcodes 8700, so start it through `serve.sh`
  directly when you need another port.
- **Edited Python and the GUI did not change.** The server does not reload:
  `./setup.sh down gui && ./setup.sh up gui`. Editing `static/index.html` only needs a browser reload.
- **`install` could not fetch Hayabusa.** It names the cause: no network, GitHub's unauthenticated
  releases API rate-limiting you (60 requests an hour per address — wait, or download the release
  yourself into `analysis/.tools/`), or a release whose assets no longer match the expected name.
- **`install` ended with a FAILED list.** It prints a summary of what was installed, skipped and
  failed, and exits non-zero if anything failed — a half-installed system and a complete one used to
  end identically. `./setup.sh all` still starts what it has and still runs `doctor` afterwards: the
  the optional tools are not a reason for nothing to
  start. `doctor` then names what is missing and what it costs.
- **Which build of Hayabusa / the EZ tools is this?** `.run/install-manifest.json` records
  the version and sha256 of everything `install` downloaded. Nothing pins those downloads — that is
  an open question, not a solved one — but what was taken is written down.
- **The trust-surface guard complains on a fresh clone.** Expected: the baseline is local by design.
  Generate it once (above). It is a soft check and never blocks.
- **The leak guard reports PARTIAL.** Also expected until `data/pseudonym-map.md` exists — with no
  map there are no identifiers to search for, and the guard says so rather than reporting a pass it
  did not earn.
- **A source produced no records and no error.** Check the warnings line above the results: a missing
  tool now names itself and says what it costs. If Zeek is absent, PCAP analysis runs on tshark alone
  and the application layer is missing — that is reported, not silent.

## Status

[`docs/roadmap.md`](docs/roadmap.md) is the source of truth for what is built and what is open, and
[`docs/architecture.md`](docs/architecture.md) for how the pieces fit. This section used to be a
third hand-maintained inventory of the same facts; three copies of one list drift, and then nobody
knows which is current. In short:

- **EventHound** — the engine is operational across eleven sources, with correlation, the attack
  map, cases, reports and bundles, the local GUI, and a demo that runs the whole thing with no
  customer evidence at all.
- **Knowledge base** — markdown under `method/` that grounds *analysis*: `framework/` (MITRE
  ATT&CK notes), `normative/` (GDPR/NIS2/DORA), `acn`. ATT&CK technique→tactic is vendored in
  `analysis/analytics/attack_map.json`. Vendor product documentation is deliberately absent.

### How mature is it, concretely

The disclaimer at the top of this file is not modesty, and here is the measurement behind it. The
project's own release criterion is **two consecutive clean adversarial review rounds**. Four rounds
have run; all four came back dirty — 11 defects, then 16, then a third round across four scopes,
then a fourth round that found two of eleven sources had never worked on real data — and each round
found defects *created by the previous round's fixes*. The counter is at **zero**. That is the
honest state: the engine does real work on real evidence, and the rate at which review still finds
things says it is not finished.

What that means in practice, if you are deciding whether to point this at something that matters:

- **Tested, lightly, on lab cases.** The EVTX → Hayabusa/Sigma path, PCAP, generic logs, the
  correlation, the reports and the case model have all been run against lab inputs — the public
  EVTX-ATTACK-SAMPLES set, deterministic synthetic captures, and the simulated incident
  (`engine.run_demo`), which exercises nine sources end to end from files on disk. This is a proof
  of concept, not a hardened product: some function may be incomplete, inaccurate, or broken in a
  way no lab input has triggered.
- **Least-exercised**: the **Okta** and **osquery** adapters were built against a documented schema
  and synthetic fixtures rather than a real client export, and say so in their own docstrings.
- **Not covered on a fresh clone**: the EVTX/Hayabusa, MFT and registry-hive tests all SKIP without
  the binaries and a sample, so a green suite proves the adapters and the demo — not the headline
  source. `-rs` shows you which.
- **Known gaps carried deliberately**, each with its reasoning in [`docs/roadmap.md`](docs/roadmap.md):
  the kill chain derived only from ATT&CK evidence, which the endpoint sources are alone in carrying;
  registry findings stored but not yet contributing an artifact entity.

## Licence

EventHound is released under the **MIT licence** — see [`LICENSE`](LICENSE). Use it, change it, ship
it; keep the copyright notice, and expect no warranty (the disclaimer at the top of this file is not
a formality — read it before pointing this at anything that matters).

What is **not** covered by that licence is listed in [`NOTICE.md`](NOTICE.md), and the split is worth
understanding before you redistribute anything:

- **Redistributed here**: the Material Symbols icon paths inlined in the GUI (Google, Apache-2.0).
  That is the only piece of somebody else's work that arrives when you clone.
- **Not redistributed**: every tool EventHound drives — Hayabusa, the Sigma rules it bundles, the
  Eric Zimmerman tools, Zeek, tshark. `setup.sh install` downloads
  them into the gitignored `analysis/.tools/`; each keeps its own licence and its authors' terms,
  which you accept by installing them. The Sigma community rules in particular are under the
  **Detection Rule License**, not MIT.
- **Not redistributed**: the source material of the knowledge base (MITRE ATT&CK STIX, the official
  GDPR / NIS2 / DORA texts and ACN guidance). It is fetched or supplied locally and
  stays under its own terms; the regulatory answers this project produces are a starting point for
  verification, never legal advice.

Wrapping tools rather than reimplementing them is the design decision the whole project rests on
(`docs/roadmap.md`); this is the licensing consequence of it, stated rather than left implicit.
