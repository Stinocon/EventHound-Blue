"""MCP server (stdio): EventHound's analysis engine as native tools for an agentic harness.

Replaces the removed on-box Ollama engine. The reasoning now lives in the agent (Pi, Claude Code,
…); this server is the DETERMINISTIC half: it runs the pipeline locally and hands back the
correlated findings, pseudonymized (§9). Nothing leaves the machine unless the agent itself acts
on the answer.

Tools:
- `analyze` — run the pipeline on artifact paths → findings (timeline, bridges, clusters,
  kill-chain, host overview, technique catalogue, shared indicators). Client identifiers are
  pseudonymized via `data/pseudonym-map.md` before the response is returned.
- `analyze_case` — re-analyze a stored case (engine.run_case).
- `eid_lookup` — the Windows Event ID single source of truth (category/action, channel-aware).

The deterministic oracles (CVSS/risk/EPSS, compliance, enrichment) are their own MCP servers in
`tools/*/` — not here. This server is the ANALYSIS surface.

Usage: `cd analysis && uv run python analysis_mcp_server.py`
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analytics import runner  # noqa: E402
from adapters import windows_eventid  # noqa: E402
from redact import load_redactor  # noqa: E402

mcp = FastMCP("eventhound-analysis")


def _json_safe(obj):
    """The analysis carries datetimes out of DuckDB; convert to JSON-safe primitives."""
    return json.loads(json.dumps(obj, default=str))


@mcp.tool()
def analyze(
    evtx: list[str] | None = None,
    evtx_full: list[str] | None = None,
    pcap: list[str] | None = None,
    logs: list[dict] | None = None,
    registry: list[str] | None = None,
    registry_hives: list[str] | None = None,
    mft: list[str] | None = None,
    thor: list[dict] | None = None,
    okta: list[str] | None = None,
    osquery: list[str] | None = None,
    yara: list[dict] | None = None,
    crowdstrike: list[str] | None = None,
    infra_ips: list[str] | None = None,
) -> dict:
    """Run the EventHound pipeline on artifact paths and return the correlated findings.

    Sources are LOCAL paths. `evtx` (Hayabusa/Sigma detections), `evtx_full` (EvtxECmd full
    stream), `pcap` (tshark+Zeek), `mft` (a directory of MFTECmd JSON), `registry` (RECmd JSON
    directory or a .reg export), `registry_hives`, `okta`, `osquery`, `crowdstrike` (detection
    clipboard or LogScale JSON). `logs`/`thor`/`yara` are dicts: `logs` = [{"path": …, "fmt":
    "access|jsonl|regex|syslog"}], `thor` = [{"report": …} or {"md5s": …}], `yara` = [{"rules":
    …, "target": …}]. `infra_ips` declares infrastructure addresses to demote from clustering.

    Returns: the analysis (summary, shared_indicators, clusters, timeline, killchain, host_overview,
    technique_catalog, findings…), with client identifiers pseudonymized (§9). The raw evidence
    records are NOT returned — only the correlated views.
    """
    errors: list[str] = []
    records = runner.build_records(
        evtx=evtx, evtx_full=evtx_full, pcap=pcap, logs=logs, registry=registry,
        registry_hives=registry_hives, mft=mft, thor=thor, okta=okta, osquery=osquery,
        yara=yara, crowdstrike=crowdstrike, errors=errors,
    )
    if not records:
        return {"error": "no records produced from the given sources", "errors": errors}

    result = runner.analyze(records, infra_ips=infra_ips)
    result.pop("records", None)          # the raw evidence: identifiers verbatim, and not needed
    result["records_omitted"] = len(records)
    if errors:
        result["errors"] = errors

    # §9 gate: pseudonymize before the response reaches a (possibly cloud) agent.
    redactor = load_redactor()
    result = redactor.apply_obj(result)
    if not redactor.active:
        result["_privacy"] = (
            "WARNING: data/pseudonym-map.md is empty or absent — client identifiers were NOT "
            "pseudonymized. Populate the map (or do not point a cloud agent at this data)."
        )
    return _json_safe(result)


@mcp.tool()
def analyze_case(case_id: str, infra_ips: list[str] | None = None) -> dict:
    """Re-analyze a stored case (created with `engine.run_case`) and return its findings.

    Returns the same correlated views as `analyze`, pseudonymized (§9)."""
    result = runner.analyze_case(case_id, infra_ips=infra_ips)
    redactor = load_redactor()
    result = redactor.apply_obj(result)
    if not redactor.active:
        result["_privacy"] = (
            "WARNING: data/pseudonym-map.md is empty or absent — client identifiers were NOT "
            "pseudonymized."
        )
    return _json_safe(result)


@mcp.tool()
def eid_lookup(event_id: int, channel: str | None = None) -> dict:
    """Windows Event ID → category/action from the project's single source of truth.

    Args:
        event_id: the Event ID (e.g. 4624, 4688, 7045).
        channel: optional channel to disambiguate colliding IDs (e.g. "Microsoft-Windows-Sysmon/Operational").
    Returns: {event_id, channel, category, action, mapped}."""
    category, action = windows_eventid.classify(event_id, channel)
    return {
        "event_id": event_id,
        "channel": channel,
        "category": category,
        "action": action,
        "mapped": windows_eventid.is_mapped(event_id, channel),
    }


def main() -> None:
    print("[eventhound-analysis MCP] starting.", file=sys.stderr, flush=True)
    mcp.run()


if __name__ == "__main__":
    main()
