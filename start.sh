#!/usr/bin/env bash
# EventHound — Startup script
# Verifies the analysis tools and starts the GUI. No AI agent required.
# Usage: bash start.sh [--check]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

# Colors — degrade gracefully if no color support
if [ -t 1 ] && [ -n "$(command -v tput)" ] && tput colors >/dev/null 2>&1 && [ "$(tput colors)" -ge 8 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BOLD=''; NC=''
fi

ok()   { printf "${GREEN}[OK]${NC} %s\n" "$1"; }
fail() { printf "${RED}[XX]${NC} %s\n" "$1"; }

check_cmd()   { command -v "$1" >/dev/null 2>&1; }
has_glob()    { [ -n "$(printf '%s' "$1" | xargs -I {} sh -c 'ls {} 2>/dev/null')" ]; }
has_dlls()    { find "$1" -maxdepth 1 -name '*.dll' 2>/dev/null | grep -q .; }

# Parse args
CHECK_ONLY=false
if [ "${1:-}" = "--check" ]; then CHECK_ONLY=true; fi

echo "=== EventHound — Startup ==="
echo ""

# ── Tool verification ──────────────────────────────────────────────
echo "Checking tools..."
echo ""

pad() { printf "  %-22s" "$1"; }

tshark_ok=false;   check_cmd tshark     && tshark_ok=true
zeek_ok=false;     check_cmd zeek       && zeek_ok=true
hayabusa_ok=false; has_glob "$ROOT/analysis/.tools/hayabusa/hayabusa-*" && hayabusa_ok=true
evtxecmd_ok=false; has_dlls "$ROOT/analysis/.tools/evtxecmd/EvtxeCmd" && evtxecmd_ok=true
recmd_ok=false;    has_dlls "$ROOT/analysis/.tools/recmd"             && recmd_ok=true
mftcmd_ok=false;   has_dlls "$ROOT/analysis/.tools/mftcmd"            && mftcmd_ok=true

print_status() {
  local label="$1" status="$2" detail="${3:-}"
  pad "$label"
  if $status; then ok "${detail:-available}"; else fail "${detail:-not available}"; fi
}

print_status "Hayabusa"         "$hayabusa_ok"
print_status "tshark"           "$tshark_ok"
print_status "Zeek"             "$zeek_ok"
print_status "EvtxECmd"         "$evtxecmd_ok"
print_status "RECmd"            "$recmd_ok"
print_status "MFTECmd"          "$mftcmd_ok"

if $CHECK_ONLY; then
  echo ""
  echo "Check complete. Use 'bash start.sh' to start the GUI."
  exit 0
fi

# ── GUI ────────────────────────────────────────────────────────────
echo ""
echo "Starting GUI server..."
cd "$ROOT"
bash "$ROOT/analysis/gui/serve.sh"

echo ""
echo "=== EventHound ready ==="
echo "  GUI:     http://127.0.0.1:8700"
echo ""
