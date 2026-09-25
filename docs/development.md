---
title: Development and tests
updated: 2026-09-25
version: 0.2.0
linked_files:
  - README.md
  - tools/check.sh
  - tools/check-lint.sh
  - tools/release-check.sh
changelog:
  - "0.2.0 — 2026-09-25 — `tools/check.sh` grows a fourteenth section: static analysis. `tools/check-lint.sh` runs ruff (configuration in `ruff.toml`) over `analysis/` and `tools/`, hard when ruff is installed and SKIP otherwise, the same contract as pytest. `uv sync --extra dev` now installs ruff too."
  - "0.1.0 — 2026-09-11 — moved here from the README, which was getting long; the runner, the per-clone setup and the fresh-clone check are unchanged."
---

# Development and tests

One runner covers everything, and it is what "green" means here:

```bash
tools/check.sh                 # 14 sections: leak + input/trust guards, doc guards, static
                               # analysis, engine suite, GUI (HTTP + JS), scoring/enrichment/
                               # compliance golden
tools/check.sh --props         # + Hypothesis property tests for the scoring oracle
tools/check.sh --bench         # + the quick performance profile
```

One thing to do once per clone:

```bash
git config core.hooksPath tools/git-hooks     # pre-commit leak scan (§9)
```

The individual suites, when you want one of them on its own:

```bash
cd analysis     && uv run pytest tests/ -q          # engine; without pytest the gate runs the same
                                                    # files as plain scripts, minus the coverage number
cd analysis     && uv run ruff check ../analysis ../tools   # static analysis (tools/check-lint.sh)
cd analysis/gui && uv run python tests/test_gui.py  # the HTTP layer, FastAPI TestClient
cd analysis/gui && node --test tests/*.test.js      # the pure JS in static/lib.js
```

`uv sync --extra dev` installs pytest, coverage and ruff; `--extra yara` installs `yara-python`.
**Pass both together** (`uv sync --extra yara --extra dev`) — `uv sync` resolves the environment to
exactly what you name, so asking for one extra alone uninstalls the other.

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
