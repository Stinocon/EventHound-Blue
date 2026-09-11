#!/usr/bin/env bash
# Run the full gate against a REAL fresh clone of HEAD, in a throwaway directory.
#
# Why this exists as a script rather than as a line in a checklist: twice now a hard check has been
# green here and red for everyone else, because the working tree is not the repository. It carries
# the installer's output (`analysis/.tools/`, the venvs), a populated `data/`, and a
# local trust-surface baseline — none of which a clone has. `tools/check.sh` run here answers
# "does it pass on this machine"; run there it answers "does it pass for someone who clones it",
# which is the only version of the question a release cares about.
#
# `git clone`, deliberately, and NOT `git archive | tar -x`: an archive has no `.git`, so every
# guard that asks git a question behaves differently there than in the clone a user actually makes.
#
#   tools/release-check.sh              # clone HEAD, run the gate, report, clean up
#   tools/release-check.sh --keep              # leave the clone in place for inspection
#   tools/release-check.sh --keep -- --props   # pass the rest through to check.sh
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEEP=0
PASSTHRU=()
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --) shift; PASSTHRU=("$@"); break ;;
    *) PASSTHRU=("$@"); break ;;
  esac
done

DIRTY="$(git -C "$ROOT" status --porcelain)"
if [ -n "$DIRTY" ]; then
  echo "! working tree is not clean — this checks HEAD, so uncommitted work is NOT included:"
  printf '%s\n' "$DIRTY" | sed 's/^/    /'
  echo
fi

WORK="$(mktemp -d)"
trap '[ "$KEEP" -eq 1 ] || rm -rf "$WORK"' EXIT
echo "== cloning HEAD ($(git -C "$ROOT" rev-parse --short HEAD)) into $WORK =="
git clone -q "$ROOT" "$WORK/EventHound" || { echo "! clone failed"; exit 2; }

echo "== running tools/check.sh in the clone =="
( cd "$WORK/EventHound" && tools/check.sh ${PASSTHRU+"${PASSTHRU[@]}"} )
rc=$?

echo
if [ "$rc" -eq 0 ]; then
  echo "[release-check] the gate passes on a fresh clone."
else
  echo "[release-check] the gate FAILS on a fresh clone (exit $rc) — it may still pass here."
fi
[ "$KEEP" -eq 1 ] && echo "[release-check] clone kept at $WORK/EventHound"
exit "$rc"
