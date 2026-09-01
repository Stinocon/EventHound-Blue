#!/usr/bin/env bash
# Guard of trust surface integrity for the agent (method/conventions.md §10 — supply-chain defense).
# A third-party plugin/hook added silently would alter the configuration the
# agent runs at each session. This guard takes a hash snapshot of that surface and
# signals ANY deviation from the versioned baseline.
#
# Monitored surface:
#   .claude/settings.json     (SessionStart/PreToolUse/... hooks)
#   .mcp.json                 (MCP servers the agent launches)
#   .claude/rules/*.md        (rules loaded into context)
#   .claude/agents/*.md       (subagent prompts: instructions shaping delegated work)
#   .claude/skills/**/*.md    (callable skills: work modes shaping behavior)
#   git config core.hooksPath (where git hooks live, e.g. pre-commit)
#   tools/*.sh, tools/*.py    (BODY of scripts run at session/commit/check, not only
#                              declarations: a tampered check-*.sh is running code — and so is a
#                              check-*.py, which the surface used to miss purely because the first
#                              guards happened to be shell)
#   tools/git-hooks/*         (body of git-hooks, e.g. pre-commit)
#   analysis/gui/serve.sh      (launched by SessionStart hook in .claude/settings.json)
#   *_mcp_server.py           (code that .mcp.json servers launch: rag/scoring/compliance/enrichment)
#
# Baseline: tools/config-baseline.sha256 (versioned — are hashes of impersonal files).
# INTENTIONAL sensitivity: signals even benign edits. For an anti-supply-chain guard it's correct
# ("your trust surface has changed → be aware"); after legitimate modification re-snapshot.
#
# Use:
#   tools/check-config-integrity.sh            verifies against baseline (soft: exit 0)
#   tools/check-config-integrity.sh --update   regenerates baseline from current state
#
# Env: CY_CONFIG_BASELINE baseline path override. Used by smoke test (test-guards.sh)
#      to exercise update/compare/drift in sandbox without touching real baseline.
set -uo pipefail
cd "$(dirname "$0")/.."

BASELINE="${CY_CONFIG_BASELINE:-tools/config-baseline.sha256}"

# shasum present everywhere on macOS; sha256sum on Linux. Minimal abstraction.
_sha() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$@"; else sha256sum "$@"; fi; }

# Computes current manifest of trust surface (path<TAB>hash), sorted.
compute_manifest() {
  {
    for f in .claude/settings.json .mcp.json; do
      [ -f "$f" ] && _sha "$f"
    done
    for d in .claude/rules .claude/agents .claude/skills; do
      if [ -d "$d" ]; then
        find "$d" -type f -name '*.md' 2>/dev/null | sort | while IFS= read -r r; do
          _sha "$r"
        done
      fi
    done
    # EXECUTED CODE body (not just declarations): hygiene scripts, git hooks, session hooks,
    # MCP servers. A guard hashing only hooksPath/.mcp.json as strings would notice a PATH change
    # but not tampering with the actual running BODY.
    for pat in 'tools/*.sh' 'tools/*.py' 'tools/git-hooks/*' 'analysis/gui/serve.sh' \
               'tools/effort-dispatch/hooks/*.sh' 'tools/effort-dispatch/bench/state/calibration.json' \
               'rag/rag_mcp_server.py' 'tools/scoring/scoring_mcp_server.py' \
               'tools/compliance/compliance_mcp_server.py' 'tools/enrichment/enrichment_mcp_server.py'; do
      for f in $pat; do
        [ -f "$f" ] && _sha "$f"
      done
    done
    # hooksPath is local git config, not a file: we hash it as a labeled string.
    hp=$(git config core.hooksPath 2>/dev/null || echo "(not set)")
    printf '%s  core.hooksPath=%s\n' "$(printf '%s' "$hp" | _sha | awk '{print $1}')" "$hp"
  } | sort
}

if [ "${1:-}" = "--update" ]; then
  compute_manifest > "$BASELINE"
  echo "[config] baseline updated: $BASELINE"
  echo "         (review the diff before committing: it's your trust surface)"
  exit 0
fi

if [ ! -f "$BASELINE" ]; then
  echo "[config] baseline absent ($BASELINE) — expected on a fresh clone: the trust surface is"
  echo "         local to each machine, so the baseline is not versioned."
  echo "         Generate it once with: tools/check-config-integrity.sh --update"
  exit 0
fi

_cur=$(mktemp); trap 'rm -f "$_cur"' EXIT
compute_manifest > "$_cur"

if diff -q "$BASELINE" "$_cur" >/dev/null 2>&1; then
  echo "[config] OK: trust surface (hook/MCP/rules/skills/hooksPath) unchanged from baseline."
else
  echo "[config] WARNING: trust surface HAS CHANGED from baseline."
  echo "         Verify that any deviation is yours and intentional (not a third-party plugin/hook):"
  diff "$BASELINE" "$_cur" | sed 's/^/           /'
  echo "         If it's legitimate: tools/check-config-integrity.sh --update"
fi
exit 0
