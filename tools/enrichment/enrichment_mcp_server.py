"""MCP server (stdio): enrichment of PUBLIC indicators from Shodan/VirusTotal/ThreatFox.

Egress gate (default off) and blocking of non-public indicators: see enrichment.py (§9/§15).
No file upload to VT — lookup only.
"""
import sys

from mcp.server.fastmcp import FastMCP

import enrichment

mcp = FastMCP("enrichment")


@mcp.tool()
def shodan_lookup(ip: str, allow_egress: bool = False) -> dict:
    """Exposure of a PUBLIC IP from Shodan InternetDB (keyless): ports, hostnames, known CVEs.

    GATE: default allow_egress=False (no network). Private/reserved IPs blocked (§9). Returns
    {ip, ports, hostnames, cpes, tags, vulns} or {error}."""
    try:
        return enrichment.shodan_internetdb(ip, allow_egress=allow_egress)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def vt_lookup(indicator: str, allow_egress: bool = False) -> dict:
    """Reputation of a PUBLIC IP/domain/hash from VirusTotal v3 (requires VT_API_KEY).

    No file upload: lookup only. GATE: default allow_egress=False; non-public indicators
    (client data) blocked (§9). Returns {indicator, kind, malicious, suspicious, harmless,
    undetected, reputation} or {error}."""
    try:
        return enrichment.virustotal(indicator, allow_egress=allow_egress)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def threatfox_lookup(indicator: str, allow_egress: bool = False) -> dict:
    """Known IOCs of a PUBLIC IP/domain/hash from ThreatFox/abuse.ch (requires THREATFOX_API_KEY).

    Tells whether the indicator is an IOC linked to a malware family. GATE: default
    allow_egress=False; non-public indicators (client data) blocked (§9). Returns
    {indicator, kind, found, count, iocs:[...]}, {indicator, kind, not_found} or {error}."""
    try:
        return enrichment.threatfox(indicator, allow_egress=allow_egress)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def main() -> None:
    print("[enrichment_mcp_server] starting.", file=sys.stderr, flush=True)
    mcp.run()


if __name__ == "__main__":
    main()
