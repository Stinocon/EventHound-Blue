#!/usr/bin/env bash
# EventHound — the platform-neutral half of the native setup. NOT executable on its own:
# `setup-macos.sh` and `setup-linux.sh` define what actually differs between the two and source this.
#
# Why it exists: the two installers agree on roughly three quarters of their work — service
# start/stop, pid and log handling, the EZ tools (cross-platform .NET dlls), the uv environments,
# the doctor layout. Shipping that twice would guarantee the copies drift, and a stale installer is
# a support problem nobody notices until a fresh clone fails (method/conventions.md §16.3: one
# datum, one place).
#
# A platform file must define, BEFORE sourcing this:
#   PLATFORM_NAME     human name for the banner ("macOS" / "Linux")
#   HAYABUSA_GLOB     glob matching the installed binary          (e.g. "$TOOLS"/hayabusa/hayabusa-*-mac-*)
#   HAYABUSA_ASSET    regex picking its release asset             (e.g. "mac-aarch64")
#   hint <component>  the platform's install suggestion for a missing component
#   pkg_doctor        prints the "prerequisites" and "analysis tools" doctor rows
#   pkg_install       installs the system packages
# and then call `main "$@"`.
#
# Bash 3.2 compatible on purpose: that is what macOS ships, so no associative arrays, no globstar.

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[1]:-$0}")" && pwd)}"
TOOLS="$ROOT/analysis/.tools"
# Runtime state (logs + pids) lives INSIDE the project (gitignored) — don't pollute the system.
LOGDIR="$ROOT/.run"
ARCH="$(uname -m)"
mkdir -p "$LOGDIR"

ok(){ printf "  \033[32m✅\033[0m %-16s %s\n" "$1" "${2:-}"; }
miss(){ printf "  \033[31m❌\033[0m %-16s %s\n" "$1" "${2:-missing}"; }
info(){ printf "  \033[33m•\033[0m  %s\n" "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# ── component checks (return 0 if present) ───────────────────────────────────────────────
hayabusa_ok(){ ls $HAYABUSA_GLOB >/dev/null 2>&1; }
eztool_ok(){ ls "$TOOLS/$1"/**/"$2".dll >/dev/null 2>&1 || ls "$TOOLS/$1"/"$2".dll >/dev/null 2>&1; }
port_up(){ curl -sf "$1" >/dev/null 2>&1; }

# Launch a service FULLY DETACHED so it survives this script exiting (nohup + disown; exec so the
# pid is the service, not the wrapper shell). Args: name, bash-snippet (ending in `exec <cmd>`).
spawn(){
  nohup bash -c "$2" >"$LOGDIR/$1.log" 2>&1 &
  echo $! >"$LOGDIR/$1.pid"
  disown 2>/dev/null || true
}

doctor(){
  echo "EventHound — native $PLATFORM_NAME doctor ($ARCH)"
  pkg_doctor
  hayabusa_ok && ok hayabusa "$(ls $HAYABUSA_GLOB 2>/dev/null | head -1 | xargs basename)" || miss hayabusa "run: $SELF install"
  # Optional: without them Hayabusa still detects, with a narrower reach (no Linux/macOS/cloud/web).
  sigma_ok && ok "sigma rules" "$(cut -c1-12 "$SIGMA_DIR/.sigmahq-ref" 2>/dev/null || echo present)" \
    || info "SigmaHQ community rules absent — Hayabusa's built-in set only (run: $SELF install)"
  for p in evtxecmd:EvtxECmd recmd:RECmd mftcmd:MFTECmd; do
    eztool_ok "${p%%:*}" "${p##*:}" && ok "${p##*:}" || miss "${p##*:}" "EZ tool dll — run: $SELF install"
  done
  echo "── python envs ───────────────────────────────"
  [ -d "$ROOT/analysis/.venv" ] && ok "analysis env" || miss "analysis env" "cd analysis && uv sync --extra yara --extra dev"
  [ -d "$ROOT/analysis/gui/.venv" ] && ok "gui env" || miss "gui env" "cd analysis/gui && uv sync --extra yara"
  echo "── running services ──────────────────────────"
  port_up "http://127.0.0.1:8700/api/health" && ok "gui :8700" || info "gui not running (start: $SELF up)"
}

# ── install the missing pieces ───────────────────────────────────────────────────────────
SIGMA_DIR="$ROOT/analysis/sigma/community/sigmahq"

sigma_ok(){ [ -d "$SIGMA_DIR/rules" ]; }

sigma_install(){
  # Optional feature (doctor already treats its absence as `info`, not `miss`): every branch below
  # reports to INSTALL_OK/INSTALL_SKIP, never INSTALL_FAIL — those arrays are the caller's (install(),
  # the only caller), bash's dynamic scoping makes them visible here without passing them around.
  if ! have git; then
    echo "  ! git missing — SigmaHQ community rules skipped (Hayabusa's built-in set still works)"
    INSTALL_SKIP+=("sigma rules: git not installed")
    return 0
  fi
  if sigma_ok && [ -z "${SIGMA_REF:-}" ]; then
    info "SigmaHQ rules present ($(cat "$SIGMA_DIR/.sigmahq-ref" 2>/dev/null || echo 'ref unknown'))"
    INSTALL_OK+=("sigma rules (already present)")
    return 0
  fi
  mkdir -p "$SIGMA_DIR"
  if [ ! -d "$SIGMA_DIR/.git" ]; then
    git -C "$SIGMA_DIR" init -q 2>/dev/null || { echo "  ! git init failed — rules skipped"; INSTALL_SKIP+=("sigma rules: git init failed"); return 0; }
    git -C "$SIGMA_DIR" remote add origin https://github.com/SigmaHQ/sigma.git 2>/dev/null || true
    git -C "$SIGMA_DIR" config core.sparseCheckout true
    printf 'rules/\nrules-emerging-threats/\nrules-threat-hunting/\nLICENSE.Detection.Rules.md\n' \
      > "$SIGMA_DIR/.git/info/sparse-checkout"
  fi
  ref="${SIGMA_REF:-master}"
  if git -C "$SIGMA_DIR" fetch -q --depth 1 origin "$ref" 2>/dev/null \
     && git -C "$SIGMA_DIR" checkout -q FETCH_HEAD 2>/dev/null; then
    git -C "$SIGMA_DIR" rev-parse HEAD > "$SIGMA_DIR/.sigmahq-ref"
    ok "SigmaHQ rules ($(cut -c1-12 "$SIGMA_DIR/.sigmahq-ref"))"
    INSTALL_OK+=("sigma rules ($(cut -c1-12 "$SIGMA_DIR/.sigmahq-ref"))")
  else
    echo "  ! could not fetch SigmaHQ rules (offline, or ref '$ref' not found) — Hayabusa's"
    echo "    built-in set still works; re-run \`$SELF install\` when there is network."
    INSTALL_SKIP+=("sigma rules: fetch failed (offline, or ref '$ref' not found)")
  fi
}

# GitHub's unauthenticated API caps at 60 requests/hour/IP; on a rate limit or a network failure
# `curl -s` used to return an empty body indistinguishable from "no asset matched the pattern", so
# the caller's `! could not resolve …` line looked the same in all three cases and `install` quietly
# moved on with the tool missing — found out later, from an analysis that produced nothing.
# GH_ASSET_ERR says which one happened; GH_ASSET_VERSION (on success) says which release was taken,
# for the manifest below.
gh_asset_url(){ # repo, grep-pattern → download url of the first matching asset (latest release)
  GH_ASSET_ERR=""
  GH_ASSET_VERSION=""
  resp="$(curl -s -w '\n%{http_code}' "https://api.github.com/repos/$1/releases/latest" 2>/dev/null)"
  status="$(printf '%s\n' "$resp" | tail -n1)"
  body="$(printf '%s\n' "$resp" | sed '$d')"
  case "$status" in
    000|"") GH_ASSET_ERR="no network reachable to api.github.com"; return 1 ;;
    403|429) GH_ASSET_ERR="GitHub API rate-limited (60 unauthenticated requests/hour/IP) — retry later"; return 1 ;;
  esac
  if printf '%s' "$body" | grep -q "API rate limit exceeded"; then
    GH_ASSET_ERR="GitHub API rate-limited (60 unauthenticated requests/hour/IP) — retry later"
    return 1
  fi
  if [ "$status" != "200" ]; then
    GH_ASSET_ERR="GitHub API returned HTTP $status for $1/releases/latest"
    return 1
  fi
  GH_ASSET_VERSION="$(printf '%s' "$body" | grep -oE '"tag_name": "[^"]*"' | head -1 | cut -d'"' -f4)"
  url="$(printf '%s' "$body" | grep -oE '"browser_download_url": "[^"]*"' | cut -d'"' -f4 | grep -m1 -E "$2")"
  if [ -z "$url" ]; then
    GH_ASSET_ERR="no release asset matched pattern '$2' (release $GH_ASSET_VERSION found, nothing in it matches)"
    return 1
  fi
  printf '%s\n' "$url"
}

# sha256 of a downloaded file, macOS/Linux portable.
_sha256(){ if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1"; else sha256sum "$1"; fi; }

# `install` had no record of WHAT it fetched: two runs a week apart could pull two different
# Hayabusa builds and nothing would say so. Nothing here PINS a version (open question, not solved
# by this file) — it only records the one actually taken, sha256 included, so "which build is this"
# has an answer later. EZ tools have no versioned release API (fixed net9 URL) so their entries
# carry a null version; the sha256 still identifies the exact bytes.
manifest_record(){ # component, version-or-empty, url, downloaded-file-path
  local comp="$1" ver="$2" url="$3" path="$4" sum verf
  sum="$(_sha256 "$path" 2>/dev/null | awk '{print $1}')"
  [ -n "$sum" ] || return 0
  if [ -n "$ver" ]; then verf="\"$ver\""; else verf="null"; fi
  MANIFEST_ENTRIES+=("{\"component\": \"$comp\", \"version\": $verf, \"url\": \"$url\", \"sha256\": \"$sum\"}")
}

write_manifest(){
  [ "${#MANIFEST_ENTRIES[@]}" -eq 0 ] && return 0
  local i=0 n="${#MANIFEST_ENTRIES[@]}"
  {
    printf '{\n  "created_at": "%s",\n  "downloads": [\n' "$(date -u +%FT%TZ)"
    for e in "${MANIFEST_ENTRIES[@]}"; do
      i=$((i+1))
      [ "$i" -eq "$n" ] && printf '    %s\n' "$e" || printf '    %s,\n' "$e"
    done
    printf '  ]\n}\n'
  } > "$LOGDIR/install-manifest.json"
  info "download manifest: $LOGDIR/install-manifest.json"
}

# Tallies what install() actually did so a half-installed system and a complete one stop looking
# the same at the end.
install_summary(){
  echo "── install summary ───────────────────────────"
  if [ "${#INSTALL_OK[@]}" -gt 0 ]; then
    echo "  installed / already present:"
    for e in "${INSTALL_OK[@]}"; do echo "    - $e"; done
  fi
  if [ "${#INSTALL_SKIP[@]}" -gt 0 ]; then
    echo "  skipped (optional, not fatal):"
    for e in "${INSTALL_SKIP[@]}"; do echo "    - $e"; done
  fi
  if [ "${#INSTALL_FAIL[@]}" -gt 0 ]; then
    echo "  FAILED:"
    for e in "${INSTALL_FAIL[@]}"; do echo "    - $e"; done
  fi
  write_manifest
  if [ "${#INSTALL_FAIL[@]}" -gt 0 ]; then
    echo "install finished with ${#INSTALL_FAIL[@]} failure(s) — see above; re-run: $SELF install"
    return 1
  fi
  echo "install done — start with: $SELF up"
  return 0
}

install(){
  INSTALL_OK=(); INSTALL_SKIP=(); INSTALL_FAIL=(); MANIFEST_ENTRIES=()
  pkg_install
  echo "── Hayabusa ($PLATFORM_NAME binary) ──────────"
  if hayabusa_ok; then
    INSTALL_OK+=("hayabusa (already present)")
  elif url="$(gh_asset_url Yamato-Security/hayabusa "$HAYABUSA_ASSET")"; then
    hb_zip="$(mktemp "${TMPDIR:-/tmp}/eventhound-hayabusa.XXXXXX")"
    if curl -fsSL -o "$hb_zip" "$url"; then
      mkdir -p "$TOOLS/hayabusa"
      unzip -oq "$hb_zip" -d "$TOOLS/hayabusa"
      chmod +x $HAYABUSA_GLOB 2>/dev/null
      manifest_record hayabusa "$GH_ASSET_VERSION" "$url" "$hb_zip"
      rm -f "$hb_zip"
      ok hayabusa
      INSTALL_OK+=("hayabusa $GH_ASSET_VERSION")
    else
      rm -f "$hb_zip"
      echo "  ! Hayabusa download failed (network error fetching the release asset)"
      INSTALL_FAIL+=("hayabusa: download failed")
    fi
  else
    echo "  ! Hayabusa: $GH_ASSET_ERR"
    INSTALL_FAIL+=("hayabusa: $GH_ASSET_ERR")
  fi
  echo "── EZ tools (net9 dlls) ──────────────────────"
  # Cross-platform by construction: these are .NET dlls run through `dotnet`, same files everywhere.
  for p in evtxecmd:EvtxECmd recmd:RECmd mftcmd:MFTECmd; do
    d="${p%%:*}"; t="${p##*:}"
    if eztool_ok "$d" "$t"; then
      INSTALL_OK+=("$t (already present)")
      continue
    fi
    ez_zip="$(mktemp "${TMPDIR:-/tmp}/eventhound-$t.XXXXXX")"
    ez_url="https://download.ericzimmermanstools.com/net9/$t.zip"
    if curl -fsSL -o "$ez_zip" "$ez_url"; then
      mkdir -p "$TOOLS/$d"
      unzip -oq "$ez_zip" -d "$TOOLS/$d"
      manifest_record "$t" "" "$ez_url" "$ez_zip"
      rm -f "$ez_zip"
      ok "$t"
      INSTALL_OK+=("$t")
    else
      rm -f "$ez_zip"
      echo "  ! $t download failed"
      INSTALL_FAIL+=("$t: download failed")
    fi
  done
  echo "── SigmaHQ community rules ───────────────────"
  sigma_install
  echo "── python envs (uv sync) ─────────────────────"
  # Independent, not `&&`-chained: a failed `analysis` sync used to silently skip `gui` too.
  if (cd "$ROOT/analysis" && uv sync --extra yara --extra dev); then
    INSTALL_OK+=("analysis env (uv sync)")
  else
    echo "  ! analysis env: uv sync failed"
    INSTALL_FAIL+=("analysis env: uv sync failed")
  fi
  if (cd "$ROOT/analysis/gui" && uv sync --extra yara); then
    INSTALL_OK+=("gui env (uv sync)")
  else
    echo "  ! gui env: uv sync failed"
    INSTALL_FAIL+=("gui env: uv sync failed")
  fi
  install_summary
}

# ── run the native stack ─────────────────────────────────────────────────────────────────
up(){
  only="${1:-all}"
  want(){ [ "$only" = "all" ] || [ "$only" = "$1" ]; }
  # GUI: no RAG, no on-box LLM — the engine + GUI are the whole product. No EVENTHOUND_RUNTIME → "Local".
  if want gui && ! port_up "$(health_url gui)"; then
    info "starting gui :8700…"
    spawn gui "cd '$ROOT/analysis/gui' && exec uv run python -m uvicorn app:app --host 127.0.0.1 --port 8700"
    sleep 2
  fi
  [ "$only" = "all" ] && echo "up — GUI: http://127.0.0.1:8700  · logs in $LOGDIR" || info "up ($only)"
}

# The health URL `up` probes for the service, so `down` can wait for the SAME check to stop
# answering. Without that wait, `down gui && up gui` — the ordinary way to restart after an edit —
# probed the port while the old server was still closing it, concluded the service was already up,
# started nothing, and printed "up (gui)" over a dead port.
health_url(){
  case "$1" in
    gui) echo "http://127.0.0.1:8700/api/health" ;;
  esac
}

down(){
  only="${1:-all}"
  for s in gui; do
    [ "$only" = "all" ] || [ "$only" = "$s" ] || continue
    [ -f "$LOGDIR/$s.pid" ] && { kill "$(cat "$LOGDIR/$s.pid")" 2>/dev/null && info "stopped $s"; rm -f "$LOGDIR/$s.pid"; }
    url="$(health_url "$s")"
    [ -n "$url" ] && for _ in $(seq 1 15); do port_up "$url" || break; sleep 1; done
  done
  return 0
}

main(){
  case "${1:-doctor}" in
    doctor|"") doctor ;;
    install)   install ;;
    up)        up "${2:-all}" ;;
    down)      down "${2:-all}" ;;
    # First-run one-shot: install missing, start, verify. `up` and `doctor` run even when install
    # reported failures, and the exit code still carries them. Chaining these with && looked tidier
    # and said the opposite of what this product claims about itself: a partial install must not be
    # the reason nothing starts. Doctor is the right answer: it names what is missing.
    all)       install; _rc=$?; up; echo; doctor; exit "$_rc" ;;
    *) echo "usage: $SELF {doctor|install|up|down|all}" ; exit 1 ;;
  esac
}
