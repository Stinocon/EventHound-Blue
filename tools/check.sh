#!/usr/bin/env bash
# Workspace health check in a single pass: makes the hygiene pipeline executable (method/conventions.md §16)
# instead of aspirational. Run it before a commit or as a periodic check.
#
#   tools/check.sh          leak (tracked files) + INBOUND guard + the analysis test suite via
#                           pytest with coverage (auto-skips what needs a missing binary or
#                           dataset) + GUI (Python and JS) + golden scoring/enrichment/compliance
#                           (fast, offline)
#   tools/check.sh --props  adds property tests for scoring (Hypothesis, dev-group)
#   tools/check.sh --bench  adds the quick performance profile (engine.run_bench --analytics
#                           --quick): it reports timings, it does not assert them — a threshold
#                           would only encode this machine's speed and fail on someone else's
#
# Exits !=0 if a "hard" check fails (leak, guard smoke, analysis tests broken, golden scoring).
# INBOUND guards (injection) are SOFT: print advisory but DON'T block (decision remains with user
# judgment).
set -uo pipefail
cd "$(dirname "$0")/.."

WITH_PROPS=0
WITH_BENCH=0
for arg in "$@"; do
  [ "$arg" = "--props" ] && WITH_PROPS=1
  [ "$arg" = "--bench" ] && WITH_BENCH=1
done
fail=0

echo "== leak: tracked files (§9/§10/§11) =="
tools/check-leaks.sh --tracked || fail=1

echo "== INBOUND: injection in untrusted areas (soft) =="
tools/check-injection.sh || true

echo "== docs: repository paths named in tracked .md exist (hard) =="
# Hard, not soft: a document pointing at a file that does not exist is a wrong instruction, and the
# ones this found on its first run had all survived a commit whose message claimed to have removed
# them. Prose is not parsed — only markdown links and code spans that clearly name a repo path.
python3 tools/check-doc-paths.py || fail=1

echo "== docs: YAML frontmatter of tracked .md parses (hard) =="
# §4 makes the frontmatter load-bearing (every edit bumps `updated` and adds a changelog line), and
# nothing parsed it: four of the most-edited documents carried frontmatter no YAML reader would
# accept, some of it for weeks. A convention nothing checks is a convention that quietly stops.
python3 tools/check-doc-frontmatter.py || fail=1

echo "== guard: INBOUND guard smoke test (hard) =="
if tools/test-guards.sh >/dev/null 2>&1; then
  echo "  OK"
else
  echo "  FAIL — details: tools/test-guards.sh"; fail=1
fi

echo "== analysis: engine test suite (pytest + coverage) =="
# One invocation instead of the nine hand-listed groups this replaced: a new test file is picked up
# by collection, not by remembering to add it here. Coverage is printed because "the tests pass" and
# "the code is tested" are different claims (method/conventions.md §16.1) — the CLI entry points
# read 0% until tests/test_cli_smoke.py started exercising them.
# `python -m pytest` rather than the `pytest` console script: the guard just above proves the
# package is importable, and going through the interpreter runs it in every environment where that
# is true — including ones where executing a file under .venv/bin is not available. The two lines
# then also test the same thing they check for.
if (cd analysis && uv run python -c "import pytest, pytest_cov" >/dev/null 2>&1); then
  _pyt=$(cd analysis && uv run python -m pytest tests/ --cov --cov-report=term 2>&1); _rc=$?
  if [ "$_rc" -eq 0 ]; then
    echo "  OK — $(printf '%s\n' "$_pyt" | grep -Eo '[0-9]+ passed[^=]*' | tail -1 | sed 's/ *$//')"
    printf '%s\n' "$_pyt" | grep -E '^TOTAL' | awk '{print "  coverage: " $NF " (" $2 " statements)"}'
  else
    echo "  FAIL — details: cd analysis && uv run python -m pytest tests/ -x"
    printf '%s\n' "$_pyt" | grep -E '^(FAILED|ERROR)' | head -5 | sed 's/^/    /'
    fail=1
  fi
else
  # The suite must stay runnable without a test runner installed (CLI-first, no hard dev deps):
  # same files, executed as plain scripts, minus the coverage number.
  echo "  (pytest absent — script mode; \`cd analysis && uv sync --extra dev\` to measure coverage)"
  _u_ok=1
  for t in analysis/tests/test_*.py; do
    (cd analysis && uv run python "tests/$(basename "$t")" >/dev/null 2>&1) \
      || { echo "  FAIL — cd analysis && uv run python tests/$(basename "$t")"; _u_ok=0; fail=1; }
  done
  [ "$_u_ok" -eq 1 ] && echo "  OK (script mode)"
fi

echo "== analysis/gui: test web GUI (FastAPI TestClient) =="
if [ -f analysis/gui/tests/test_gui.py ]; then
  if (cd analysis/gui && uv run python tests/test_gui.py >/dev/null 2>&1); then
    echo "  OK"
  else
    echo "  FAIL — details: cd analysis/gui && uv run python tests/test_gui.py"; fail=1
  fi
else
  echo "  SKIP (gui not present)"
fi

echo "== analysis/gui: JS unit tests (node --test, pure logic in static/lib.js) =="
if [ -d analysis/gui/tests ] && ls analysis/gui/tests/*.test.js >/dev/null 2>&1; then
  if command -v node >/dev/null 2>&1; then
    # The glob, not `node --test tests/`: on Node 26 the directory form tries to require the
    # directory itself and fails before running anything ("Cannot find module .../tests").
    if (cd analysis/gui && node --test tests/*.test.js >/dev/null 2>&1); then
      echo "  OK"
    else
      echo "  FAIL — details: cd analysis/gui && node --test tests/*.test.js"; fail=1
    fi
  else
    echo "  SKIP (node not installed)"
  fi
else
  echo "  SKIP (no JS tests present)"
fi

echo "== scoring: golden CVSS/EPSS (deterministic oracle) =="
if [ -f tools/scoring/validate.py ]; then
  if (cd tools/scoring && uv run python validate.py >/dev/null 2>&1); then
    echo "  OK"
  else
    echo "  FAIL — details: cd tools/scoring && uv run python validate.py"; fail=1
  fi
else
  echo "  SKIP (tools/scoring not yet present)"
fi

echo "== enrichment: egress/privacy gate (offline) =="
if [ -f tools/enrichment/test_enrichment.py ]; then
  if (cd tools/enrichment && uv run python test_enrichment.py >/dev/null 2>&1); then
    echo "  OK"
  else
    echo "  FAIL — details: cd tools/enrichment && uv run python test_enrichment.py"; fail=1
  fi
else
  echo "  SKIP (tools/enrichment not present)"
fi

echo "== scoring: Hypothesis property test (CVSS/risk invariants) =="
if [ "$WITH_PROPS" -eq 1 ]; then
  if (cd tools/scoring && uv run --group dev python test_properties.py >/dev/null 2>&1); then
    echo "  OK"
  else
    echo "  FAIL — details: cd tools/scoring && uv run --group dev python test_properties.py"; fail=1
  fi
else
  echo "  SKIP (pass --props to include it)"
fi

echo "== analysis: performance profile (quick) =="
if [ "$WITH_BENCH" -eq 1 ]; then
  # Deliberately reports rather than asserts: a pass/fail threshold here would encode the speed of
  # whatever machine wrote it (docs/analysis/performance.md records the figures and the hardware).
  # It still fails the run if the profile cannot execute at all — that is a broken pipeline.
  _bench=$(cd analysis && uv run python -m engine.run_bench --analytics --quick 2>&1); _brc=$?
  if [ "$_brc" -eq 0 ]; then
    printf '%s\n' "$_bench" | grep -E '^(store\.from_records|TOTAL)' | sed 's/^/  /'
  else
    echo "  FAIL — details: cd analysis && uv run python -m engine.run_bench --analytics --quick"
    fail=1
  fi
else
  echo "  SKIP (pass --bench to include it)"
fi

echo "== compliance: golden resolver (GDPR/NIS2/DORA) =="
if [ -f tools/compliance/validate.py ]; then
  if (cd tools/compliance && uv run python validate.py >/dev/null 2>&1); then
    echo "  OK"
  else
    echo "  FAIL — details: cd tools/compliance && uv run python validate.py"; fail=1
  fi
else
  echo "  SKIP (tools/compliance not present)"
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "[check] result: FAILED"
  exit 1
fi
echo "[check] result: all green"
