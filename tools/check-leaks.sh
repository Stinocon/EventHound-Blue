#!/usr/bin/env bash
# Anti-leak guard: prevents real customer data or raw/licensed material from ending up
# in VERSIONED files (method/conventions.md §9/§10/§11 — non-negotiable privacy invariant). Those paths
# are already in .gitignore, but `git add -f` would force them: this is the mechanical safety net.
#
# Two modes:
#   (default)   checks files in STAGE        → use: pre-commit hook
#   --tracked   checks all TRACKED files     → use: tools/check.sh (periodic hygiene)
#
# Checks: (a) FORBIDDEN paths in versioning; (b) presence of REAL customer IDENTIFIERS,
# read from the "reale" column of data/pseudonym-map.md (private file, stays local). In security
# PII is not regex-able like an IBAN, and 10.x IPs are legitimate placeholders (§9): the reliable
# signal is the appearance of a known real identifier. If the map is absent/empty, content check is
# skipped with notice (doesn't fail).
#
# Exits !=0 if a violation is found. Emergency override: GUARD_SKIP=1 (not recommended, leaves trace).
#
# Use:  tools/check-leaks.sh [--tracked]
set -uo pipefail
# Deterministic UTF-8 locale: case-fold of `grep -i` on accented identifiers (e.g. 'Niccolò')
# depends on caller's locale. Under C/POSIX or unset locale (hook/CI) accented folding fails and
# a real identifier could slip through. Force UTF-8 for stable behavior.
export LC_ALL=en_US.UTF-8
cd "$(dirname "$0")/.."

# Unicode NFC normalization: grep match fails if pattern and content use different Unicode forms
# (e.g. 'à' precomposed U+00E0 vs 'a'+combining U+0300). Normalize BOTH to NFC.
# Requires python3; if absent degrades to raw comparison (documented) — never emptying
# content, because emptying would hide a leak instead of signaling it.
if command -v python3 >/dev/null 2>&1; then HAVE_NFC=1; else HAVE_NFC=0; fi
nfc() {
  if [ "$HAVE_NFC" = "1" ]; then
    python3 -c 'import sys,unicodedata; sys.stdout.write(unicodedata.normalize("NFC", sys.stdin.read()))'
  else
    cat
  fi
}

MODE="${1:-staged}"
case "$MODE" in
  staged|--tracked) ;;
  *) echo "[leak] unrecognized argument: '$MODE' (use: --tracked, or no argument for stage)" >&2; exit 2 ;;
esac

if [ "${GUARD_SKIP:-0}" = "1" ]; then
  echo "[leak] GUARD_SKIP=1 → check skipped (not recommended)."
  exit 0
fi

# Paths that must NEVER be versioned (mirror of sensitive .gitignore entries).
# Exceptions: impersonal templates and .gitkeep placeholders stay versionable (§17).
is_forbidden_path() {
  case "$1" in
    analysis/reports/.gitkeep|analysis/reports/templates/*) return 1 ;;
    data/*|\
    docs/*/pdf/*|method/acn/*.pdf|\
    analysis/reports/*|analysis/.tools/*|analysis/cases/*|\
    *.evtx|*.duckdb|\
    .venv/*|*/.venv/*) return 0 ;;
  esac
  return 1
}

list_files() {
  if [ "$MODE" = "--tracked" ]; then git ls-files
  else git diff --cached --name-only --diff-filter=ACMR; fi   # R: a git mv into a forbidden path must not slip through
}
get_content() {
  if [ "$MODE" = "--tracked" ]; then grep -Iq . "$1" 2>/dev/null && cat "$1" 2>/dev/null  # -Iq: salta i binari
  else git show ":$1" 2>/dev/null; fi
}

# Real customer identifiers from pseudonym map (column "reale" = 3rd field of md table).
# Discarded: headers, separators, placeholders ("(da compilare)", "(es. ...)") and values too
# short (<4 char) to avoid spurious matches on common substrings.
MAPPA="data/pseudonym-map.md"
grep_args=()
if [ -f "$MAPPA" ]; then
  while IFS= read -r val; do
    [ -z "$val" ] && continue
    nval="$(printf '%s' "$val" | nfc)"
    [ -z "$nval" ] && nval="$val"   # mai perdere un pattern se nfc fallisce
    grep_args+=(-e "$nval")
  done < <(awk -F'|' 'NF>=4 {print $3}' "$MAPPA" \
            | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
            | grep -viE 'da compilare|^reale$|^\(es\.|^_\(|^[-:[:space:]]+$' \
            | awk 'length >= 4')
fi

violations=0
checked_content=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if is_forbidden_path "$f"; then
    echo "[leak] FORBIDDEN path in versioning: $f"
    violations=$((violations + 1)); continue
  fi
  if [ "${#grep_args[@]}" -gt 0 ]; then
    checked_content=1
    hit="$(get_content "$f" | nfc | grep -ioF "${grep_args[@]}" | sort -u | head -3 | tr '\n' ' ')"
    if [ -n "$hit" ]; then
      echo "[leak] REAL IDENTIFIER (pseudonym map) in: $f -> $hit"
      violations=$((violations + 1))
    fi
  fi
done < <(list_files)

if [ "$violations" -gt 0 ]; then
  echo "[leak] BLOCKED: $violations violation/s (method/conventions.md §9/§10/§11)."
  echo "       If it's a false positive: GUARD_SKIP=1 git commit ..."
  exit 1
fi
# An empty map is not a clean bill of health: with nothing to match, the content half of this guard
# does not run, and saying "no real data" would be a claim it cannot make. On 2026-07-24 that is
# exactly what happened — a real customer ID, agent ID, hostname, user surname and public IP went
# into a versioned test fixture under a green OK, because the map was still the empty template.
# Still not a hard failure (a fresh clone legitimately has no map), but never again silent.
if [ "${#grep_args[@]}" -eq 0 ]; then
  echo "[leak] PARTIAL: no forbidden path in ${MODE#--} files, but data/pseudonym-map.md is absent"
  echo "       or holds no real identifiers — the content check DID NOT RUN. Populate the map"
  echo "       before any real data enters the workspace, or this guard is blind (§9)."
else
  # grep_args holds a "-e" flag per pattern, so its length is twice the identifier count.
  echo "[leak] OK: no real data or forbidden path in ${MODE#--} files ($(( ${#grep_args[@]} / 2 )) identifiers checked)."
fi
