#!/usr/bin/env bash
# Static analysis pass (ruff, configuration in ../ruff.toml).
#
# Hard when ruff is installed, SKIP when it is not — the same contract as pytest in check.sh: the
# gate has to stay runnable in a fresh clone with no dev extras and no network, and a check that
# cannot run must say so rather than report a pass it did not earn.
#
#   cd analysis && uv sync --extra dev     # installs ruff
#   tools/check-lint.sh
set -uo pipefail
cd "$(dirname "$0")/.."

if ! (cd analysis && uv run ruff --version) >/dev/null 2>&1; then
  echo "[lint] SKIP (ruff absent — install it with: cd analysis && uv sync --extra dev)"
  exit 0
fi

if (cd analysis && uv run ruff check ../analysis ../tools); then
  echo "[lint] OK"
  exit 0
fi

echo "[lint] FAIL — details: cd analysis && uv run ruff check ../analysis ../tools"
exit 1
