#!/usr/bin/env bash
# EventHound — native Linux setup (no Docker).
#
# WHY native here is a weaker claim than on macOS, and worth stating honestly: on Linux, Docker is a
# perfectly good runtime — containers get the host kernel and, with the NVIDIA toolkit, the GPU too.
# This script exists so that "no component requires Docker" is true off macOS as well: if you would
# rather not run containers, or you are on a box where Docker is not an option, everything here runs
# directly on the host.
#
#   ./setup-linux.sh            # doctor: check everything, report what's missing (default)
#   ./setup-linux.sh install    # install/download the missing pieces (packages + binaries + uv sync + model)
#   ./setup-linux.sh up         # start the native stack (ollama + qdrant:6343 + rag-api:8600 + gui:8700)
#   ./setup-linux.sh up qdrant  # start ONE service only (ollama|qdrant|rag-api|gui)
#   ./setup-linux.sh down       # stop the native services this script started
#
# Only what is Linux-specific lives here — the package manager, the Linux release assets, the
# Playwright cache path. Everything else (services, EZ tools, uv envs, model, doctor layout) is in
# tools/setup-common.sh, shared with setup-macos.sh so the two cannot drift apart.
set -uo pipefail

SELF="$0"
ROOT="$(cd "$(dirname "$0")" && pwd)"

PLATFORM_NAME="Linux"
ARCH="$(uname -m)"

# Release-asset selection. These are the names the projects actually publish (checked against their
# GitHub releases, not guessed) and they are not symmetrical:
#   Hayabusa  lin-x64-gnu / lin-aarch64-gnu, plus musl builds for Alpine
#   Qdrant    x86_64-unknown-linux-gnu, but on aarch64 only a MUSL build exists
LIBC="gnu"; [ -f /etc/alpine-release ] && LIBC="musl"
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
  HAYABUSA_ASSET="lin-aarch64-$LIBC"
  QDRANT_ASSET="aarch64-unknown-linux-musl\.tar\.gz"   # no gnu build published for aarch64
else
  HAYABUSA_ASSET="lin-x64-$LIBC"
  QDRANT_ASSET="x86_64-unknown-linux-$LIBC\.tar\.gz"
fi
HAYABUSA_GLOB="$ROOT/analysis/.tools/hayabusa/hayabusa-*-lin-*"
PLAYWRIGHT_CACHE="$HOME/.cache/ms-playwright"

# ── package manager ──────────────────────────────────────────────────────────────────────
# Detected once, so the doctor's suggestions are the commands that will actually work on THIS box
# rather than a Debian-shaped guess.
if   command -v apt-get >/dev/null 2>&1; then PM="apt";    PM_INSTALL="sudo apt-get install -y"
elif command -v dnf     >/dev/null 2>&1; then PM="dnf";    PM_INSTALL="sudo dnf install -y"
elif command -v pacman  >/dev/null 2>&1; then PM="pacman"; PM_INSTALL="sudo pacman -S --noconfirm"
elif command -v zypper  >/dev/null 2>&1; then PM="zypper"; PM_INSTALL="sudo zypper install -y"
elif command -v apk     >/dev/null 2>&1; then PM="apk";    PM_INSTALL="sudo apk add"
else PM="none"; PM_INSTALL=""
fi
[ "$(id -u)" = "0" ] && PM_INSTALL="${PM_INSTALL#sudo }"   # already root (container, CI): no sudo

# Distro package names differ; one place to translate.
pkg_name(){
  case "$1:$PM" in
    tshark:pacman)   echo "wireshark-cli" ;;
    tshark:*)        echo "tshark" ;;
    dotnet:apt)      echo "dotnet-sdk-9.0" ;;
    dotnet:dnf)      echo "dotnet-sdk-9.0" ;;
    dotnet:pacman)   echo "dotnet-sdk" ;;
    dotnet:*)        echo "dotnet-sdk-9.0" ;;
    unzip:*)         echo "unzip" ;;
    curl:*)          echo "curl" ;;
    zeek:*)          echo "zeek" ;;
    *)               echo "$1" ;;
  esac
}

hint(){
  case "$1" in
    # uv and ollama are not packaged by most distros; these are the vendors' own installers.
    uv)     echo "curl -LsSf https://astral.sh/uv/install.sh | sh" ;;
    ollama) echo "curl -fsSL https://ollama.com/install.sh | sh" ;;
    zeek)   echo "$PM_INSTALL $(pkg_name zeek)  (optional: PCAP works on tshark alone)" ;;
    *)      echo "$PM_INSTALL $(pkg_name "$1")" ;;
  esac
}

pkg_doctor(){
  echo "── prerequisites ─────────────────────────────"
  [ "$PM" = "none" ] && miss "package manager" "none of apt/dnf/pacman/zypper/apk found" || ok "package manager" "$PM"
  have curl && ok curl || miss curl "$(hint curl)"
  have unzip && ok unzip || miss unzip "$(hint unzip)"
  have uv && ok uv "$(uv --version 2>/dev/null)" || miss uv "$(hint uv)"
  echo "── analysis tools ────────────────────────────"
  have tshark && ok tshark || miss tshark "$(hint tshark)"
  # Zeek genuinely is optional: the PCAP adapter treats a missing binary as "no enrichment" and
  # carries on with tshark. It is also absent from most default repos (upstream ships it through the
  # openSUSE Build Service), so a missing zeek is reported, never worked around with a third-party
  # apt source added behind your back (§10 — the trust surface stays yours).
  have zeek && ok zeek || miss zeek "optional — $(hint zeek)"
  have dotnet && ok dotnet "$(dotnet --version 2>/dev/null)" || miss dotnet "$(hint dotnet) (for EZ tools)"
  systemctl is-active --quiet ollama 2>/dev/null && info "ollama runs under systemd — 'up' will use the running daemon"
}

pkg_install(){
  [ "$PM" = "none" ] && { echo "no supported package manager found (apt/dnf/pacman/zypper/apk)"; exit 1; }
  echo "── system packages ($PM) ─────────────────────"
  [ "$PM" = "apt" ] && export DEBIAN_FRONTEND=noninteractive   # tshark otherwise asks about dumpcap
  for t in curl unzip tshark dotnet; do
    have "$t" || { echo "installing $(pkg_name "$t")…"; $PM_INSTALL "$(pkg_name "$t")" || echo "  ! $(pkg_name "$t") not available from $PM — install it by hand"; }
  done
  # Optional, and often not packaged: try once, do not fail the install if it is missing.
  have zeek || { echo "installing zeek (optional)…"; $PM_INSTALL "$(pkg_name zeek)" >/dev/null 2>&1 \
    || info "zeek not in the $PM repos — PCAP analysis still works on tshark (see analysis/README.md)"; }
  # uv and ollama come from their vendors' install scripts. They are printed before running so the
  # command is never a surprise, and skipped entirely if the tool is already present (§10/§12).
  if ! have uv; then
    info "installing uv:  curl -LsSf https://astral.sh/uv/install.sh | sh"
    curl -LsSf https://astral.sh/uv/install.sh | sh || { echo "uv install failed — see https://docs.astral.sh/uv/"; exit 1; }
    export PATH="$HOME/.local/bin:$PATH"
  fi
  if ! have ollama; then
    info "installing ollama:  curl -fsSL https://ollama.com/install.sh | sh"
    curl -fsSL https://ollama.com/install.sh | sh || info "ollama install failed — the AI engine is optional, everything else works"
  fi
}

. "$ROOT/tools/setup-common.sh"
main "$@"
