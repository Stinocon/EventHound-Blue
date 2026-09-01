#!/usr/bin/env bash
# EventHound — native macOS setup (no Docker).
#
# The analysis tools (Hayabusa, the Eric Zimmerman tools, tshark/Zeek) run on the host. This script
# checks each component and installs/configures the missing ones, then runs the GUI natively.
#
#   ./setup-macos.sh            # doctor: check everything, report what's missing (default)
#   ./setup-macos.sh install    # install/download the missing pieces (brew + binaries + uv sync)
#   ./setup-macos.sh up         # start the GUI on 127.0.0.1:8700
#   ./setup-macos.sh down       # stop the services this script started
#
# Only what is macOS-specific lives here — Homebrew and the Darwin release assets. Everything else
# (EZ tools, uv envs, doctor layout) is in tools/setup-common.sh, shared with setup-linux.sh so the
# two cannot drift apart.
#
# Docker stays available (docker-compose.yml) for reproducible / non-macOS deployments.
set -uo pipefail

SELF="$0"
ROOT="$(cd "$(dirname "$0")" && pwd)"

PLATFORM_NAME="macOS"
ARCH="$(uname -m)"
HAYABUSA_GLOB="$ROOT/analysis/.tools/hayabusa/hayabusa-*-mac-*"
HAYABUSA_ASSET="mac-${ARCH/arm64/aarch64}|mac-universal"

hint(){
  case "$1" in
    *) echo "brew install $1" ;;
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
  for f in zeek dotnet; do have "$f" || { echo "installing $f…"; brew install "$f"; }; done
  have tshark || { echo "installing wireshark (tshark)…"; brew install wireshark; }
}

. "$ROOT/tools/setup-common.sh"
main "$@"
