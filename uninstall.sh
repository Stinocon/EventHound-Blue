#!/usr/bin/env bash
# EventHound — native uninstall (mirror of the setup scripts; macOS and Linux alike).
#
# Removes what `setup.sh install` created INSIDE the project: downloaded tool binaries, the
# Python environments, runtime state. Everything else is left alone on purpose:
#
#   • system packages (uv, wireshark/tshark, zeek, dotnet) installed through Homebrew or your
#     distro's package manager — shared with the whole machine, uninstalling them here would break
#     other projects. Remove by hand if you really want to.
#   • data/ — real client data and the pseudonym map (§9/§10). NEVER touched.
#
# DESTRUCTIVE (§12): prints exactly what it would delete, with sizes, and asks for a typed `yes`.
#
#   ./uninstall.sh              # show the plan, ask, then remove
#   ./uninstall.sh --dry-run    # show the plan and stop (also the default when not a TTY)
#   ./uninstall.sh --yes
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

info(){ printf "  \033[33m•\033[0m  %s\n" "$1"; }
ok(){ printf "  \033[32m✅\033[0m %s\n" "$1"; }
warn(){ printf "  \033[31m!\033[0m  %s\n" "$1"; }

DRY=0; ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --dry-run)       DRY=1 ;;
    --yes|-y)        ASSUME_YES=1 ;;
    -h|--help)       sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg"; echo "usage: $0 [--dry-run] [--yes]"; exit 1 ;;
  esac
done

# Piped/non-interactive and no explicit --yes: never delete on a guess.
if [ "$DRY" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ] && [ ! -t 0 ]; then
  DRY=1
  info "non-interactive shell: falling back to --dry-run (pass --yes to actually remove)"
fi

# Paths created by `setup.sh install` / by running the stack. Order = reporting order.
TARGETS=(
  "$ROOT/analysis/.tools"          # Hayabusa, EZ tools (EvtxECmd/RECmd/MFTECmd)
  "$ROOT/analysis/.venv"
  "$ROOT/analysis/gui/.venv"
  "$ROOT/.run"                     # service logs + pids
)
# uv envs of the deterministic tools (scoring/enrichment/compliance): created lazily by check.sh.
while IFS= read -r d; do [ -n "$d" ] && TARGETS+=("$d"); done < <(find "$ROOT/tools" -maxdepth 2 -type d -name .venv 2>/dev/null)

size_of(){ [ -e "$1" ] && du -sh "$1" 2>/dev/null | cut -f1 || echo "-"; }

echo "EventHound — native uninstall"
echo "── will be removed ───────────────────────────"
present=0
for t in "${TARGETS[@]}"; do
  if [ -e "$t" ]; then
    present=$((present + 1))
    printf "  %-8s %s\n" "$(size_of "$t")" "${t#"$ROOT"/}"
  fi
done
[ "$present" -eq 0 ] && info "nothing to remove (already clean)"

echo "── will be KEPT ──────────────────────────────"
info "data/ (real client data, §9) — never touched by this script"
info "$([ "$(uname -s)" = Darwin ] && echo 'Homebrew formulae' || echo 'distro packages') (uv, tshark, zeek, dotnet) — shared with the whole machine"
info "the git checkout itself — delete the folder by hand when you are done"

if [ "$DRY" -eq 1 ]; then
  echo
  info "dry run: nothing was removed"
  exit 0
fi
if [ "$present" -eq 0 ]; then
  exit 0
fi

if [ "$ASSUME_YES" -eq 0 ]; then
  echo
  printf "Type 'yes' to remove the above: "
  read -r reply
  [ "$reply" = "yes" ] || { warn "aborted — nothing removed"; exit 1; }
fi

echo "── stopping services ─────────────────────────"
bash "$ROOT/setup.sh" down

echo "── removing ──────────────────────────────────"
for t in "${TARGETS[@]}"; do
  [ -e "$t" ] || continue
  # Belt and braces: only ever delete inside the project (a bad $ROOT must not cost a home dir).
  case "$t" in
    "$ROOT"/*) rm -rf "$t" && ok "removed ${t#"$ROOT"/}" ;;
    *) warn "skipped (outside the project): $t" ;;
  esac
done

echo
ok "uninstall done"
info "to reinstall: ./setup.sh all"
