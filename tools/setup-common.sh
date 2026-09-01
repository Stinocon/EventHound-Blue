#!/usr/bin/env bash
# EventHound — the platform-neutral half of the native setup. NOT executable on its own:
# `setup-macos.sh` and `setup-linux.sh` define what actually differs between the two and source this.
#
# Why it exists: the two installers agree on roughly three quarters of their work — service start/stop,
# pid and log handling, the EZ tools (cross-platform .NET dlls), the uv environments, the model pull,
# the doctor layout. Shipping that twice would guarantee the copies drift, and a stale installer is a
# support problem nobody notices until a fresh clone fails (method/conventions.md §16.3: one datum,
# one place).
#
# A platform file must define, BEFORE sourcing this:
#   PLATFORM_NAME     human name for the banner ("macOS" / "Linux")
#   HAYABUSA_GLOB     glob matching the installed binary          (e.g. "$TOOLS"/hayabusa/hayabusa-*-mac-*)
#   HAYABUSA_ASSET    regex picking its release asset             (e.g. "mac-aarch64")
#   QDRANT_ASSET      regex picking the Qdrant release asset      (e.g. "aarch64-apple-darwin\.tar\.gz")
#   PLAYWRIGHT_CACHE  where Playwright keeps its browsers
#   hint <component>  the platform's install suggestion for a missing component
#   pkg_doctor        prints the "prerequisites" and "analysis tools" doctor rows
#   pkg_install       installs the system packages
# and then call `main "$@"`.
#
# Bash 3.2 compatible on purpose: that is what macOS ships, so no associative arrays, no globstar.

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[1]:-$0}")" && pwd)}"
TOOLS="$ROOT/analysis/.tools"
QDRANT_DIR="$TOOLS/qdrant"
QDRANT_STORAGE="$ROOT/rag/qdrant_storage"
# Runtime state (logs + pids) lives INSIDE the project (gitignored) — don't pollute the system.
LOGDIR="$ROOT/.run"
# Which model to pull and check for. NOT a literal: the rule that picks it lives in
# `analysis/ai/ollama_client.configured_model()` and is asked here, so the installer cannot download
# a 9 GB model the engine will then refuse to load. Before 2026-08-28 this hardcoded qwen2.5:14b and
# a 16 GB Mac got exactly that. `configured_model` and not `default_model`: an analyst who selected
# a different model in the Assistant's picker has stored that choice, and the installer must pull
# what the engine will actually talk to. Stdlib-only on purpose, so it answers before any `uv sync`
# has run; the literal survives only as the fallback for a host with no usable python3.
default_model(){
  python3 -c "import sys;sys.path.insert(0,'$ROOT/analysis');from ai.ollama_client import configured_model;print(configured_model())" 2>/dev/null \
    || echo "qwen2.5:7b-instruct"   # fallback when python3 cannot answer: the default model on
}                                    # purpose — an unmeasurable host must not be told to pull 9 GB
MODEL="${EVENTHOUND_LLM_MODEL:-$(default_model)}"
ARCH="$(uname -m)"
mkdir -p "$LOGDIR"

ok(){ printf "  \033[32m✅\033[0m %-16s %s\n" "$1" "${2:-}"; }
miss(){ printf "  \033[31m❌\033[0m %-16s %s\n" "$1" "${2:-missing}"; }
info(){ printf "  \033[33m•\033[0m  %s\n" "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# ── component checks (return 0 if present) ───────────────────────────────────────────────
hayabusa_ok(){ ls $HAYABUSA_GLOB >/dev/null 2>&1; }
eztool_ok(){ ls "$TOOLS/$1"/**/"$2".dll >/dev/null 2>&1 || ls "$TOOLS/$1"/"$2".dll >/dev/null 2>&1; }
# Runs it, rather than trusting the executable bit: the same checkout can be used from two platforms
# (shared volume, dual boot, a copied project folder), and a Darwin binary is still `-x` on Linux —
# doctor would report a green qdrant that cannot start, and `install` would decline to fetch the
# right one. Hayabusa needs no equivalent because its glob already carries the platform.
qdrant_bin(){ "$QDRANT_DIR/qdrant" --version >/dev/null 2>&1; }
port_up(){ curl -sf "$1" >/dev/null 2>&1; }
playwright_ok(){ ls -d "$PLAYWRIGHT_CACHE/chromium"* >/dev/null 2>&1; }
# Is the LLM already downloaded? `ollama list` only answers when the daemon is up, so fall back to
# the model store on disk — otherwise a stopped daemon reports a present model as missing and
# suggests a pointless ~10GB re-pull.
#
# THE TAG IS PART OF THE ANSWER. Both checks used to strip it (`${MODEL%%:*}`), so they answered
# "is any qwen2.5 present" — and once the model became analyst-selectable that became the normal
# path: with only `qwen2.5:7b-instruct` pulled, `MODEL=qwen2.5:14b` reported PRESENT, the installer
# pulled nothing, `doctor` printed a green line, and the engine failed at first use. The manifests
# directory is per NAME with one file per tag, so the on-disk check has to name the tag too.
model_ok(){
  local name="${MODEL%%:*}" tag="latest"
  case "$MODEL" in *:*) tag="${MODEL##*:}";; esac
  # Column 1 of `ollama list`, compared verbatim — not a regex over the whole table.
  ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qxF "$name:$tag" && return 0
  ls "$HOME/.ollama/models/manifests/"*/library/"$name/$tag" >/dev/null 2>&1
}

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
  echo "── RAG / LLM ─────────────────────────────────"
  # grep the version line: with the daemon down `ollama --version` prints a connection warning
  # first, which would show up as the detail next to a green check.
  have ollama && ok ollama "$(ollama --version 2>/dev/null | grep -m1 version || echo present)" || miss ollama "$(hint ollama)"
  if model_ok; then
    _models="$(ollama list 2>/dev/null | awk 'NR>1{print $1}' | tr '\n' ' ')"
    ok "model" "${_models:-$MODEL (on disk; daemon down)}"
  else
    miss "model" "ollama pull $MODEL"
  fi
  # The check nobody was doing before 2026-08-28: can THIS host load the configured model right now
  # — free RAM and swap pressure both — instead of finding out by losing the session to it.
  # `memory_status`, not `memory_preflight`: the latter answers None both for "it fits" and for
  # "nothing could be measured", and this line used to render the second as a green check. On a
  # fresh install, where the model is not pulled and so has no measurable size, doctor asserted the
  # opposite of the truth.
  # $MODEL goes through the ENVIRONMENT, not into the source literal: a model name carrying a quote
  # is operator-controlled rather than hostile, but interpolating it into `python3 -c` is a habit
  # worth not having in a tool that also reads evidence.
  EH_ROOT="$ROOT"; export EH_ROOT
  _mem="$(EH_M="$MODEL" python3 -c "import os,sys;sys.path.insert(0,os.environ['EH_ROOT']+'/analysis');from ai.ollama_client import OllamaClient;s,m=OllamaClient(model=os.environ['EH_M']).memory_status();print(s+'|'+m)" 2>/dev/null)"
  case "${_mem%%|*}" in
    ok)      ok   "memory" "${_mem#*|}" ;;
    refuse)  miss "memory" "${_mem#*|}" ;;
    *)       info "memory  not determined — ${_mem#*|}" ;;
  esac
  qdrant_bin && ok qdrant "$("$QDRANT_DIR/qdrant" --version 2>/dev/null | head -1)" || miss qdrant "native binary — run: $SELF install"
  # Only needed to ingest `type: web` RAG sources (crawl4ai in-process); everything else runs without it.
  playwright_ok && ok "crawler" "chromium (crawl4ai, native)" || miss "crawler" "web ingest only — run: $SELF install"
  echo "── python envs ───────────────────────────────"
  [ -d "$ROOT/analysis/.venv" ] && ok "analysis env" || miss "analysis env" "cd analysis && uv sync --extra yara --extra dev"
  [ -d "$ROOT/analysis/gui/.venv" ] && ok "gui env" || miss "gui env" "cd analysis/gui && uv sync --extra yara"
  [ -d "$ROOT/rag/.venv" ] && ok "rag env" || miss "rag env" "cd rag && uv sync --extra api"
  echo "── running services ──────────────────────────"
  port_up "http://127.0.0.1:11434/api/tags" && ok "ollama :11434" || info "ollama not running (start: $SELF up)"
  port_up "http://127.0.0.1:6343/readyz" && ok "qdrant :6343" || info "qdrant not running (start: $SELF up)"
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

# sha256 of a downloaded file, macOS/Linux portable — same shasum/sha256sum split as
# check-config-integrity.sh's `_sha`, kept separate because that one hashes config, this one binaries.
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
# the same at the end. Before this, the LLM-pull block was the last thing printed regardless of
# what had failed above it, and `install` always exited 0.
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
    # mktemp, not a fixed /tmp/hb.zip: two installs at once, or a stale file from a killed run,
    # used to collide on the same path.
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
  echo "── Qdrant ($PLATFORM_NAME binary) ────────────"
  if qdrant_bin; then
    INSTALL_OK+=("qdrant (already present)")
  elif url="$(gh_asset_url qdrant/qdrant "$QDRANT_ASSET")"; then
    qd_tgz="$(mktemp "${TMPDIR:-/tmp}/eventhound-qdrant.XXXXXX")"
    if curl -fsSL -o "$qd_tgz" "$url"; then
      mkdir -p "$QDRANT_DIR"
      tar -xzf "$qd_tgz" -C "$QDRANT_DIR"
      chmod +x "$QDRANT_DIR/qdrant"
      manifest_record qdrant "$GH_ASSET_VERSION" "$url" "$qd_tgz"
      rm -f "$qd_tgz"
      ok qdrant
      INSTALL_OK+=("qdrant $GH_ASSET_VERSION")
    else
      rm -f "$qd_tgz"
      echo "  ! Qdrant download failed (network error fetching the release asset)"
      INSTALL_FAIL+=("qdrant: download failed")
    fi
  else
    echo "  ! Qdrant: $GH_ASSET_ERR"
    INSTALL_FAIL+=("qdrant: $GH_ASSET_ERR")
  fi
  echo "── SigmaHQ community rules ───────────────────"
  # Hayabusa ships ~5000 rules concentrated on process_creation, registry_set and ps_script. The
  # SigmaHQ community set is what covers Linux, macOS, cloud, web servers, network and the Windows
  # channels Hayabusa handles thinly — coverage analysis/sigma/README.md has always described and
  # nothing has ever provided, because the script it pointed at did not exist.
  #
  # Downloaded, never redistributed: the community rules are under the Detection Rule License, not
  # this project's MIT (see NOTICE.md), and analysis/sigma/community/ is gitignored. The resolved
  # commit is recorded beside the checkout so an install can be reproduced and an update is visible;
  # SIGMA_REF pins it explicitly. A sparse checkout because the full repository is large and only
  # the `rules*` trees are used. Optional (Hayabusa's built-in set still works without it): its
  # outcomes go to INSTALL_SKIP/INSTALL_OK inside sigma_install, never INSTALL_FAIL.
  sigma_install
  echo "── python envs (uv sync) ─────────────────────"
  # Independent, not `&&`-chained: a failed `analysis` sync used to silently skip `gui` and `rag`
  # too, with the script carrying on into the Playwright step as if all three had worked.
  # `--extra api` for the RAG env: rag_api.py needs fastapi/uvicorn, and without them `up` skipped
  # the service every time while the README listed it among the four it starts. The GUI then fell
  # back to a subprocess per query, which reloads e5-large and the cross-encoder each time — it
  # works, and it is much slower, and nothing said so.
  # `--extra yara` for the GUI env too: without it the browser runs a smaller product than the CLI —
  # the demo's strongest bridge is one artifact named by four tools and the GUI only saw three.
  # Both extras for the engine env, never `--extra yara` alone: uv resolves extras as the whole
  # set, so asking for yara by itself UNINSTALLS pytest and the gate quietly loses its coverage run.
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
  if (cd "$ROOT/rag" && uv sync --extra api); then
    INSTALL_OK+=("rag env (uv sync)")
  else
    echo "  ! rag env: uv sync failed"
    INSTALL_FAIL+=("rag env: uv sync failed")
  fi
  echo "── crawler browser (Playwright/Chromium) ─────"
  # crawl4ai drives Playwright in-process (no container): the browser binary is the only piece uv
  # can't provide. Needed ONLY to ingest `type: web` sources; everything else works without it —
  # so a failure here is a skip, not a failure.
  if playwright_ok; then
    info "chromium already installed ($PLAYWRIGHT_CACHE)"
    INSTALL_OK+=("chromium (already present)")
  elif (cd "$ROOT/rag" && uv run python -m playwright install chromium); then
    ok chromium
    INSTALL_OK+=("chromium")
  else
    echo "  ! chromium install failed — web ingest will not work (local sources are unaffected)"
    INSTALL_SKIP+=("chromium: install failed (web ingest only)")
  fi
  echo "── LLM model ─────────────────────────────────"
  if have ollama; then
    if model_ok; then
      info "model $MODEL present"
      INSTALL_OK+=("model $MODEL (already present)")
    elif ollama pull "$MODEL"; then
      INSTALL_OK+=("model $MODEL")
    else
      echo "  ! ollama pull $MODEL failed"
      INSTALL_FAIL+=("model $MODEL: pull failed")
    fi
  else
    INSTALL_SKIP+=("model $MODEL: ollama not installed")
  fi
  install_summary
}

# ── run the native stack ─────────────────────────────────────────────────────────────────
# up [all|ollama|qdrant|rag-api|gui] — the filter lets other scripts (rag/backup.sh) restart ONE
# service through this file, which owns ports/storage/pid, instead of duplicating the invocation.
up(){
  only="${1:-all}"
  want(){ [ "$only" = "all" ] || [ "$only" = "$1" ]; }
  # Ollama: native daemon, shared across projects on :11434.
  if want ollama; then
    port_up "http://127.0.0.1:11434/api/tags" || { info "starting ollama…"; (ollama serve >"$LOGDIR/ollama.log" 2>&1 &) ; sleep 2; }
  fi
  # Qdrant: native on :6343 (separate from PersonalFinance's :6333), storage in rag/qdrant_storage.
  if want qdrant && ! port_up "http://127.0.0.1:6343/readyz"; then
    qdrant_bin || { echo "qdrant binary missing — run: $SELF install"; exit 1; }
    info "starting qdrant :6343…"
    # HTTP 6343 + gRPC 6344 (both distinct from PersonalFinance's 6333/6334); storage = the bind-mount
    # dir the Docker qdrant used, so the existing index is reused with no copy.
    spawn qdrant "cd '$ROOT/rag' && QDRANT__SERVICE__HTTP_PORT=6343 QDRANT__SERVICE__GRPC_PORT=6344 QDRANT__STORAGE__STORAGE_PATH='$QDRANT_STORAGE' exec '$QDRANT_DIR/qdrant'"
    sleep 3
  fi
  # rag-api: warm hybrid retrieval over HTTP. Its web deps are the `api` extra in rag/pyproject and
  # `install` syncs them; if the env predates that (or was synced by hand), this reports the skip
  # instead of failing, and the GUI falls back to a subprocess per query — correct, but cold.
  if want rag-api && ! port_up "http://127.0.0.1:8600/health"; then
    if (cd "$ROOT/rag" && uv run python -c "import fastapi" >/dev/null 2>&1); then
      info "starting rag-api :8600…"
      spawn rag-api "cd '$ROOT/rag' && QDRANT_URL=http://127.0.0.1:6343 exec uv run python -m uvicorn rag_api:app --host 127.0.0.1 --port 8600"
    else
      info "rag-api skipped (fastapi not in rag env; run: cd rag && uv sync --extra api) — the GUI"
      info "  falls back to a subprocess per query, which reloads the embedding models each time"
    fi
  fi
  # GUI: native ollama (:11434 default) + RAG via rag-api or subprocess fallback. No EVENTHOUND_RUNTIME → "Local".
  # `python -m uvicorn` (not `uv run uvicorn`): the console-script isn't always exposed in the env.
  if want gui && ! port_up "$(health_url gui)"; then
    info "starting gui :8700…"
    spawn gui "cd '$ROOT/analysis/gui' && RAG_API_URL=http://127.0.0.1:8600 QDRANT_URL=http://127.0.0.1:6343 exec uv run python -m uvicorn app:app --host 127.0.0.1 --port 8700"
    sleep 2
  fi
  [ "$only" = "all" ] && echo "up — GUI: http://127.0.0.1:8700  · logs in $LOGDIR" || info "up ($only)"
}

# Same service filter as `up`: `down gui` used to ignore its argument and stop everything, which is
# a nasty surprise when the intent was to restart one service.
# The health URL `up` probes for each service, so `down` can wait for the SAME check to stop
# answering. Without that wait, `down gui && up gui` — the ordinary way to restart after an edit —
# probed the port while the old server was still closing it, concluded the service was already up,
# started nothing, and printed "up (gui)" over a dead port.
health_url(){
  case "$1" in
    gui)     echo "http://127.0.0.1:8700/api/health" ;;
    rag-api) echo "http://127.0.0.1:8600/health" ;;
    qdrant)  echo "http://127.0.0.1:6343/collections" ;;
  esac
}

down(){
  only="${1:-all}"
  for s in gui rag-api qdrant; do
    [ "$only" = "all" ] || [ "$only" = "$s" ] || continue
    [ -f "$LOGDIR/$s.pid" ] && { kill "$(cat "$LOGDIR/$s.pid")" 2>/dev/null && info "stopped $s"; rm -f "$LOGDIR/$s.pid"; }
    url="$(health_url "$s")"
    [ -n "$url" ] && for _ in $(seq 1 15); do port_up "$url" || break; sleep 1; done
  done
  [ "$only" = "all" ] || [ "$only" = "ollama" ] && info "ollama daemon left running (shared across projects)"
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
    # and said the opposite of what this product claims about itself: the LLM and the RAG are
    # optional, and the GUI and CLI are whole without either — so a model that would not download on
    # a train must not be the reason nothing starts. Doctor is the right answer to a partial
    # install: it names what is missing and what that costs, which is more use than an empty screen.
    all)       install; _rc=$?; up; echo; doctor; exit "$_rc" ;;
    # Prints the model this host should run, so documentation and pull commands can name it without
    # hardcoding a size that is wrong on half the machines that read them.
    model)     echo "$MODEL" ;;
    *) echo "usage: $SELF {doctor|install|up [SERVICE]|down [SERVICE]|all|model}   SERVICE = all|ollama|qdrant|rag-api|gui"; exit 1 ;;
  esac
}
