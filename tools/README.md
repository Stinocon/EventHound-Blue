# `tools/` — workspace hygiene and deterministic oracles

Three families of tools, all **local and offline** unless otherwise noted:

1. **Hygiene guards** (shell): make the pipeline in method/conventions.md §16 *executable*, not just aspirational.
2. **Deterministic oracles** (uv projects with MCP servers): security scores and normative mappings come from a controlled, golden-tested source, never from model estimation (§6).
3. **Shared configuration** (`eventhound_config.py`, stdlib only): the one store the GUI, the CLI and the MCP tools all read, so the product is configured once — see below.

## Shared configuration (`eventhound_config.py`)

Third-party API keys and non-secret preferences, in `data/config.json` (private, gitignored, `0600`;
override with `EVENTHOUND_CONFIG`). Pure stdlib so every uv environment can import it by path, the
way `enrichment.py` and the GUI already do.

```bash
python tools/eventhound_config.py list                        # masked status + settings
python tools/eventhound_config.py set virustotal              # prompts, no echo, no shell history
python tools/eventhound_config.py set-setting allow_egress true
```

Precedence is **environment > stored value**: an explicit `VT_API_KEY=…` in front of a command is a
deliberate override and is reported as such (`overridden_by_env`). Keys are never printed in full,
and the GUI endpoint (`/api/config`) returns a masked hint only. Storing a key does not enable
network traffic — `allow_egress` does, and only for public indicators (§9/§15).

## Conventions

- **Shell**: `set -uo pipefail` (no `-e`) in *soft* guards, so a check that signals does not halt the rest of the run; *hard* gates handle failure explicitly. Each script `cd`'s to the repo root.
- **Python**: all via `uv run` (environment managed by uv, no global installation). Tests auto-skip when their external dependency is missing (dataset, tshark, VT key).
- **Single runner**: `tools/check.sh` orchestrates everything; it's the gate to run before a commit.

## Hygiene guards (shell)

| Script | What it does | Gate | Notes |
|---|---|---|---|
| `check.sh` | Workspace health run: leak + input guard + guard smoke + analysis tests (EVTX/PCAP/logon) + golden scoring/enrichment/compliance. `--props` runs property tests. | — | Exits !=0 on any *hard* failure. |
| `check-leaks.sh` | Output boundary: forbidden versioning paths + actual client identifiers (from `data/pseudonym-map.md`) in tracked/staged files. `--tracked` scans all tracked. | hard | Can be hooked as pre-commit (below). |
| `check-injection.sh` | Input boundary: prompt-injection patterns (IT+EN) and agent-config artifacts in untrusted areas (`data/`). With an argument, scans an ad-hoc file before ingestion. | soft | Signals, does not decide. See `method/conventions.md` §8. |
| `check-config-integrity.sh` | TRUST SURFACE integrity: hashes the scripts and MCP servers that run at session/commit/check time against a local baseline; signals any drift. `--update` re-snapshots. | soft | Supply-chain defense (§10). The baseline is **local** (untracked): generate it once per clone with `--update`. Env `CY_CONFIG_BASELINE`. |
| `check-doc-paths.py` | Every repository path a tracked `.md` names must exist. Markdown links plus code spans that clearly name a repo path; prose is never parsed. `--list` shows what it checked. | hard | Documentation rots by rename: `uninstall-macos.sh` outlived the file becoming `uninstall.sh`, a download script was promised under an analysis/scripts directory that never existed, and `docs/crowdstrike/` survived its own deletion in four places. (Named in prose here rather than as code spans — the checker cannot tell an example from a reference, and it is right not to try.) Glob patterns, `<placeholders>` and frontmatter changelogs are excluded — a checker that guesses gets muted, which is worse than none. A missing path that **git is told to ignore** is absent by design and accepted: that used to be a hand-written list, and being incomplete made this HARD check fail in every fresh clone while staying green on the machine where the installer had run. Known limit, stated in the file: it cannot tell an artifact the reader will create from a document that was never published. |
| `check-doc-frontmatter.py` | The YAML frontmatter of every tracked `.md` must parse. Not a YAML parser (these scripts stay stdlib-only): it catches the two failures that actually happen when English prose is written into a YAML scalar — an unescaped `"` inside a double-quoted string, and an unquoted `key:` value containing `: `. `--list` names every file checked. | hard | §4 makes the frontmatter load-bearing — every edit bumps `updated` and adds a changelog line — and nothing parsed it. On 2026-08-30 four of the most-edited documents in the repo (the roadmap, the correlation model, the common schema, DESIGN) carried frontmatter no YAML reader would accept, some of it for weeks: a convention kept by hand and read only by humans, who skip the block. |
| `doc_files.py` | Not a check: the shared answer to *which* `.md` the two documentation guards look at. `git ls-files` in a checkout, a tree walk when there is no `.git` (a `git archive` extraction, the Docker image, a tarball). | — | Both guards called git with `check=True`, so outside a checkout they did not report a problem — they raised and took the whole `check.sh` down. Same shape as the `test-guards.sh` defect of 2026-08-29, one directory over. |
| `release-check.sh` | Runs the whole gate against a **real fresh `git clone` of HEAD** in a throwaway directory. `--keep` leaves the clone; anything after `--` is passed through to `check.sh`. | — | The working tree is not the repository: it carries the installer's output, a populated `data/` and a local trust baseline. Twice now a hard check has been green here and red for everyone else. `git clone`, never `git archive` — an archive has no `.git`, so every guard that asks git a question behaves differently there than in the clone a user actually makes. |
| `test-guards.sh` | Smoke test of BEHAVIOR of `check-injection` + `check-config-integrity` in sandbox (ephemeral fixtures, temporary baseline). | hard | Makes soft guards deterministic. |
| `git-hooks/pre-commit` | `exec` of `check-leaks.sh` on staged files. Activate once per clone: `git config core.hooksPath tools/git-hooks`. | hard | |

## Deterministic oracles (uv projects + MCP)

| Dir | MCP Server | What it computes | Tests |
|---|---|---|---|
| `scoring/` | `scoring` | CVSS v3.1 base (FIRST.org formula), v4.0 validation, risk-matrix, EPSS (egress opt-in). | `validate.py` (golden) + `test_properties.py` (Hypothesis, `--group dev`). |
| `enrichment/` | `enrichment` | Enrichment of PUBLIC indicators (Shodan InternetDB keyless, VirusTotal keyed, ThreatFox/abuse.ch keyed). Egress gate + private indicator blocking. | `test_enrichment.py` (offline). |
| `compliance/` | `compliance` | Incident → notification obligations (GDPR/NIS2/DORA), from `obligations.yaml`. | `validate.py` (golden). |

Details and hand-verified values are in `RIFERIMENTO.md`/`README.md` of each dir.
