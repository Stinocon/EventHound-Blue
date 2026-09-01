#!/usr/bin/env bash
# EventHound — native setup, whichever platform you are on.
#
# The real work lives in setup-macos.sh / setup-linux.sh (each holds only what genuinely differs;
# tools/setup-common.sh holds the rest). This is the OS-agnostic door onto them, so that scripts
# which need to drive the stack — start.sh bringing the GUI up, uninstall.sh stopping it — have ONE
# name to call instead of each repeating the platform test.
#
#   ./setup.sh            # doctor (default)
#   ./setup.sh install | up | down | all
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

case "$(uname -s)" in
  Darwin) exec bash "$ROOT/setup-macos.sh" "$@" ;;
  Linux)  exec bash "$ROOT/setup-linux.sh" "$@" ;;
  *) echo "unsupported platform: $(uname -s) — use Docker (docker-compose.yml)"; exit 1 ;;
esac
