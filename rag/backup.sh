#!/usr/bin/env bash
# Backup / restore of the RAG index (Qdrant storage) — for moving EventHound to another machine.
#
# WHY: the index (rag/qdrant_storage/) is gitignored and does NOT travel with the repo, and the web
# sources need a VPN to re-crawl (§15). This archives the built index so a new machine can restore it
# instead of re-ingesting/re-crawling. (Ollama models are NOT included — just re-`ollama pull`.)
#
#   ./backup.sh create [dest_dir]        # default dest: ~/eventhound-backups
#   ./backup.sh restore <archive.tar.gz> # into an empty rag/qdrant_storage on the new machine
#
# Qdrant is stopped during a `create` for a consistent copy, then restarted the SAME way it was
# running. Both runtimes are supported and detected, not assumed:
#   • native  (the default on macOS and on Linux via setup-linux.sh): pid in ../.run/qdrant.pid,
#     restarted with `setup.sh up qdrant` — that script owns ports/storage path/pid, this one must
#     not duplicate the invocation.
#   • docker  (compose stack): container $QDRANT_CONTAINER.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
STORAGE="$HERE/qdrant_storage"
PIDFILE="$ROOT/.run/qdrant.pid"
# Root compose names the container 'eventhound-qdrant'; the rag/ compose names it 'cyber-qdrant'.
CONTAINER="${QDRANT_CONTAINER:-eventhound-qdrant}"
QDRANT_HEALTH="${QDRANT_HEALTH:-http://127.0.0.1:6343/readyz}"

usage() { echo "usage: $0 create [dest_dir]   |   $0 restore <archive.tar.gz>"; exit 1; }

port_up()      { curl -sf "$QDRANT_HEALTH" >/dev/null 2>&1; }
in_docker()    { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; }
native_pid()   { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

# Which runtime is serving the index right now: docker | native | none.
mode() {
  if in_docker; then echo docker
  elif native_pid || port_up; then echo native
  else echo none; fi
}

# Wait (up to ~15s) for the port to go quiet, so the tar never races a live writer.
wait_down() {
  for _ in $(seq 1 15); do port_up || return 0; sleep 1; done
  echo "! Qdrant still answering on $QDRANT_HEALTH — snapshot may be inconsistent" >&2
}

cmd="${1:-}"; shift || true
case "$cmd" in
  create)
    dest="${1:-$HOME/eventhound-backups}"; mkdir -p "$dest"
    [ -d "$STORAGE" ] || { echo "error: no qdrant_storage at $STORAGE"; exit 1; }
    was="$(mode)"
    case "$was" in
      docker) echo "! Qdrant ($CONTAINER, docker) is running — stopping it for a consistent snapshot"
              docker stop "$CONTAINER" >/dev/null; wait_down ;;
      native) echo "! Qdrant (native, pid $(cat "$PIDFILE" 2>/dev/null || echo '?')) is running — stopping it for a consistent snapshot"
              [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
              rm -f "$PIDFILE"; wait_down ;;
      none)   echo "  Qdrant not running — snapshotting the storage as-is" ;;
    esac
    ts="$(date +%Y%m%d-%H%M%S)"; out="$dest/rag-qdrant-$ts.tar.gz"
    tar -czf "$out" -C "$HERE" qdrant_storage
    case "$was" in
      docker) docker start "$CONTAINER" >/dev/null; echo "  Qdrant restarted (docker)" ;;
      native) bash "$ROOT/setup.sh" up qdrant ;;
    esac
    echo "backup created: $out ($(du -h "$out" | cut -f1))"
    ;;
  restore)
    arc="${1:-}"; [ -f "$arc" ] || usage
    case "$(mode)" in
      docker) echo "error: stop Qdrant first — docker stop $CONTAINER"; exit 1 ;;
      native) echo "error: stop Qdrant first — (repo root) ./setup.sh down"; exit 1 ;;
    esac
    if [ -e "$STORAGE" ] && [ -n "$(ls -A "$STORAGE" 2>/dev/null)" ]; then
      echo "error: $STORAGE is not empty — move/remove it first (refusing to overwrite)"; exit 1
    fi
    tar -xzf "$arc" -C "$HERE"
    echo "restored into $STORAGE — now start the stack:"
    echo "  native: (repo root) ./setup.sh up      |     docker: (repo root) docker compose up -d"
    ;;
  *) usage;;
esac
