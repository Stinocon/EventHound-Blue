#!/usr/bin/env bash
# Start the analysis engine's local GUI on 127.0.0.1 (NEVER exposed on the network — §10).
# Dedicated port 8700 (8000 belongs to PersonalFinance's GUI).
# Starts in the BACKGROUND and returns immediately: suitable both for manual use
# (analysis/gui/serve.sh) and for the SessionStart hook (.claude/settings.json) that launches it
# when the project opens. Idempotent: if the GUI already answers, it exits without a second process.
set -uo pipefail
# Resolve both paths BEFORE cd'ing: `dirname "$0"` is relative to the ORIGINAL cwd, so computing
# the project root from it after the cd resolves against the wrong base (it did: RUNDIR collapsed
# to /.run, mkdir was denied and the log redirect aborted the launch).
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$HERE"

PORT="${ANALISI_GUI_PORT:-8700}"
if curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
  echo "GUI already up on http://127.0.0.1:${PORT}"
  exit 0
fi
# Log inside the project (gitignored .run/), not in the system temp — keep the host clean.
RUNDIR="$ROOT/.run"; mkdir -p "$RUNDIR"
LOG="$RUNDIR/gui-${PORT}.log"
# nohup + & : uvicorn survives the hook/shell exiting; the first start also runs uv sync.
# `python -m uvicorn` (not `uv run uvicorn`): the uvicorn console-script isn't always exposed in the env.
nohup uv run python -m uvicorn app:app --host 127.0.0.1 --port "${PORT}" >"$LOG" 2>&1 &
# Record the pid where setup-macos.sh `down` (and uninstall-macos.sh) look for it: a GUI started
# here must be stoppable by the same command that stops one started by `setup-macos.sh up`.
echo $! >"$RUNDIR/gui.pid"
disown 2>/dev/null || true
echo "GUI starting on http://127.0.0.1:${PORT} (background; log: $LOG)"
