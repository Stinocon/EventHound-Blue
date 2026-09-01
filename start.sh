#!/usr/bin/env bash
# EventHound — Startup script
# Starts all services without requiring any AI agent.
# Usage: bash start.sh [--check]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

# Colors — degrade gracefully if no color support
if [ -t 1 ] && [ -n "$(command -v tput)" ] && tput colors >/dev/null 2>&1 && [ "$(tput colors)" -ge 8 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  RED=''
  GREEN=''
  YELLOW=''
  BOLD=''
  NC=''
fi

ok()   { printf "${GREEN}[OK]${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}[--]${NC} %s\n" "$1"; }
fail() { printf "${RED}[XX]${NC} %s\n" "$1"; }
bold() { printf "${BOLD}%s${NC}\n" "$1"; }

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
docker_ok=false;   check_cmd docker     && docker_ok=true

hayabusa_ok=false; has_glob "$ROOT/analysis/.tools/hayabusa/hayabusa-*" && hayabusa_ok=true
evtxecmd_ok=false; has_dlls "$ROOT/analysis/.tools/evtxecmd/EvtxeCmd" && evtxecmd_ok=true
recmd_ok=false;    has_dlls "$ROOT/analysis/.tools/recmd"             && recmd_ok=true
mftcmd_ok=false;   has_dlls "$ROOT/analysis/.tools/mftcmd"            && mftcmd_ok=true

# Qdrant status — a live check, regardless of how it was started (native binary or container).
qdrant_ok=false
if curl -sf http://127.0.0.1:6343/collections >/dev/null 2>&1; then
  qdrant_ok=true
fi
# Native Qdrant binary (downloaded by setup.sh install): on macOS this is the default stack.
qdrant_native=false
[ -x "$ROOT/analysis/.tools/qdrant/qdrant" ] && qdrant_native=true

print_status() {
  local label="$1" status="$2" detail="${3:-}"
  pad "$label"
  if $status; then
    ok "${detail:-available}"
  else
    fail "${detail:-not available}"
  fi
}

print_status "Hayabusa"         "$hayabusa_ok"
print_status "tshark"           "$tshark_ok"
print_status "Zeek"             "$zeek_ok"
print_status "EvtxECmd"         "$evtxecmd_ok"
print_status "RECmd"            "$recmd_ok"
print_status "MFTECmd"          "$mftcmd_ok"
print_status "Docker"           "$docker_ok"
print_status "Qdrant"           "$qdrant_ok"

if $CHECK_ONLY; then
  echo ""
  echo "Check complete. Use 'bash start.sh' to start services."
  exit 0
fi

# ── Qdrant ─────────────────────────────────────────────────────────
echo ""
echo "Starting Qdrant..."
if $qdrant_ok; then
  ok "Qdrant already running"
elif $qdrant_native; then
  # the platform setup script owns the native launch (ports, storage path, pid in .run/) — single source of
  # truth; don't duplicate the invocation here. It is idempotent and also brings up the GUI.
  bash "$ROOT/setup.sh" up
  curl -sf http://127.0.0.1:6343/collections >/dev/null 2>&1 && qdrant_ok=true
  $qdrant_ok && ok "Qdrant is healthy (native)" || fail "native Qdrant did not come up — see .run/qdrant.log"
else
  if ! $docker_ok; then
    fail "Docker not found and no native Qdrant binary — run: ./setup.sh install"
  else
    cd "$ROOT/rag"
    docker compose up -d qdrant 2>&1 | head -5
    echo "  Waiting for Qdrant to become healthy..."
    for i in $(seq 1 10); do
      sleep 2
      if curl -sf http://127.0.0.1:6343/collections >/dev/null 2>&1; then
        qdrant_ok=true
        ok "Qdrant is healthy"
        break
      fi
      printf "  Retry %d/10...\n" "$i"
    done
    if ! $qdrant_ok; then
      fail "Qdrant did not become healthy after 10 retries"
    fi
  fi
fi

# ── GUI ────────────────────────────────────────────────────────────
echo ""
echo "Starting GUI server..."
cd "$ROOT"
bash "$ROOT/analysis/gui/serve.sh"

# ── Summary ────────────────────────────────────────────────────────
echo ""
echo "=== EventHound ready ==="
echo "  GUI:     http://127.0.0.1:8700"
echo "  Qdrant:  http://127.0.0.1:6343"
echo ""

# Tool status summary
echo "Tool status:"
print_status "Hayabusa"         "$hayabusa_ok"
print_status "tshark"           "$tshark_ok"
print_status "Zeek"             "$zeek_ok"
print_status "EvtxECmd"         "$evtxecmd_ok"
print_status "RECmd"            "$recmd_ok"
print_status "MFTECmd"          "$mftcmd_ok"
print_status "Docker"           "$docker_ok"
print_status "Qdrant"           "$qdrant_ok"
echo ""
