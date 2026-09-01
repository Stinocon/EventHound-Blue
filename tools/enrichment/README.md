# tools/enrichment — indicator enrichment (Shodan/VirusTotal/ThreatFox)

Annotates **public** indicators (IP, domain, hash) with **Shodan** exposure (InternetDB, keyless),
**VirusTotal** reputation (keyed), and known IOCs via **ThreatFox**/abuse.ch (keyed). Supports triage:
"is this external indicator known/malicious/exposed? is it linked to a malware family?". Implements
Phase 6 of the design (`analysis/DESIGN.md` §12).

## Core constraints (method/conventions.md §9/§15) — read

1. **Egress gate**: no network calls without `allow_egress=True` (default **False**).
2. **Public indicators only**: private/reserved IPs (RFC1918, loopback, link-local) and internal
   domains (`.local/.lan/.internal/.corp/.example/.home/.intranet`) **are never sent** outside —
   they are client data. Blocking occurs **even with egress enabled**. Hashes are public by nature.
3. **VirusTotal: lookup only, never upload** files.

VT requires `VT_API_KEY` in the environment; ThreatFox requires `THREATFOX_API_KEY` (free Auth-Key,
abuse.ch account). Shodan InternetDB is keyless.

**Optional `psl` extra** (defense in depth §9): with `uv sync --extra psl` (tldextract), an FQDN
whose TLD is not a real public suffix — an internal domain with fictitious TLD (`.corp`, `.acme`, …)
beyond the hardcoded list — is recognized as client data and not sent outside. Uses a bundled
snapshot: no network (§15). Without the extra, only the internal TLD list remains.

## Usage

```
cd tools/enrichment && uv run python test_enrichment.py     # offline gate (no network)

# real lookups (explicit egress; activate VPN like any egress, §15):
uv run python -c "import enrichment,json; print(json.dumps(enrichment.shodan_internetdb('1.1.1.1', allow_egress=True),indent=2))"
VT_API_KEY=... uv run python -c "import enrichment,json; print(json.dumps(enrichment.virustotal('1.1.1.1', allow_egress=True),indent=2))"
THREATFOX_API_KEY=... uv run python -c "import enrichment,json; print(json.dumps(enrichment.threatfox('1.1.1.1', allow_egress=True),indent=2))"
```

As MCP tool: `shodan_lookup(ip, allow_egress)`, `vt_lookup(indicator, allow_egress)`, and
`threatfox_lookup(indicator, allow_egress)` (registered in `.mcp.json`). `enrichment.enrich([...])`
annotates a list, skipping non-public ones (flag `use_shodan`/`use_vt`/`use_threatfox`).

Integration: cross-source indicators from the engine (`analytics.correlate.shared_indicators`,
also visible in GUI) feed `enrich()` for triage. `shared_indicators` returns rows
(`list[dict]`: `{indicator, kind, source_list, ...}`), while `enrich()` expects a `list[str]`:
project the field first, e.g. `enrich([r["indicator"] for r in shared_indicators(con)])`.
