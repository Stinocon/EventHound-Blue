#!/usr/bin/env bash
# EventHound — native macOS setup (no Docker).
#
# WHY native: on macOS, Docker containers are CPU-only and RAM-capped by the Docker VM — the on-box
# LLM (~10GB) OOMs there. Native Ollama uses Metal (GPU) and the full host RAM, and inference is far
# faster. Native is not unlimited: that RAM is shared with everything else, so which model this host
# runs is decided by `configured_model()` — the analyst's stored choice, else the default — and
# reported by `./setup-macos.sh model` (README, "Memory"). The analysis tools already run on the host. This script
# checks each component and installs/configures the missing ones, then runs the stack natively.
#
#   ./setup-macos.sh            # doctor: check everything, report what's missing (default)
#   ./setup-macos.sh install    # install/download the missing pieces (brew + binaries + uv sync + model)
#   ./setup-macos.sh up         # start the native stack (ollama + qdrant:6343 + rag-api:8600 + gui:8700)
#   ./setup-macos.sh up qdrant  # start ONE service only (ollama|qdrant|rag-api|gui)
#   ./setup-macos.sh down       # stop the native services this script started
#
# Only what is macOS-specific lives here — Homebrew, the Darwin release assets, the Playwright cache
# path. Everything else (services, EZ tools, uv envs, model, doctor layout) is in
# tools/setup-common.sh, shared with setup-linux.sh so the two cannot drift apart.
#
# Docker stays available (docker-compose.yml) for reproducible / non-macOS deployments.
set -uo pipefail

SELF="$0"
ROOT="$(cd "$(dirname "$0")" && pwd)"

PLATFORM_NAME="macOS"
ARCH="$(uname -m)"
[ "$ARCH" = "arm64" ] && DARWIN="aarch64-apple-darwin" || DARWIN="x86_64-apple-darwin"
HAYABUSA_GLOB="$ROOT/analysis/.tools/hayabusa/hayabusa-*-mac-*"
HAYABUSA_ASSET="mac-${ARCH/arm64/aarch64}|mac-universal"
QDRANT_ASSET="$DARWIN\.tar\.gz"
# Playwright's browser store is outside the project (shared across projects, like ~/.ollama).
PLAYWRIGHT_CACHE="$HOME/Library/Caches/ms-playwright"

hint(){
  case "$1" in
    ollama) echo "brew install ollama" ;;
    *)      echo "brew install $1" ;;
  esac
}

pkg_doctor(){
  echo "── prerequisites ─────────────────────────────"
  have brew && ok brew "$(brew --version 2>/dev/null | head -1)" || miss brew "install from https://brew.sh"
  have uv && ok uv "$(uv --version 2>/dev/null)" || miss uv "brew install uv"
  echo "── analysis tools ────────────────────────────"
  have tshark && ok tshark || miss tshark "brew install wireshark"
  have zeek && ok zeek || miss zeek "brew install zeek"
  have dotnet && ok dotnet "$(dotnet --version 2>/dev/null)" || miss dotnet "brew install dotnet (for EZ tools)"
}

pkg_install(){
  have brew || { echo "Homebrew required — https://brew.sh"; exit 1; }
  echo "── brew formulae ─────────────────────────────"
  for f in uv ollama zeek dotnet; do have "$f" || { echo "installing $f…"; brew install "$f"; }; done
  have tshark || { echo "installing wireshark (tshark)…"; brew install wireshark; }
}

. "$ROOT/tools/setup-common.sh"
main "$@"
