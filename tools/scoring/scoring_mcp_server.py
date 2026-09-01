"""MCP server (stdio) that exposes the deterministic scoring oracle as native tools.

Everything is local, pure computation (no egress), EXCEPT epss_lookup which makes a network call
only if explicitly enabled (gate §15/§9). Reuses scoring.py entirely.
"""
import sys

from mcp.server.fastmcp import FastMCP

import scoring

mcp = FastMCP("scoring")


@mcp.tool()
def cvss_v31_base(vector: str) -> dict:
    """CVSS v3.1 base score from the vector (official FIRST.org formula, offline and deterministic).

    Args:
        vector: CVSS vector, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" (prefix optional).
    Returns:
        {score, severity, scope, vector, metrics} or {error} if the vector is malformed.
    """
    try:
        return scoring.cvss_v31_base(vector)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def cvss_v40_base(vector: str) -> dict:
    """Validates a CVSS v4.0 vector and extracts the base metrics.

    Note: the v4.0 NUMERIC score is not yet implemented (requires the official MacroVector
    table); use the FIRST.org calculator for the number.

    Args:
        vector: CVSS v4.0 vector, e.g. "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".
    Returns:
        {score(None), severity, valid, missing_base_metrics, vector, metrics, note} or {error}.
    """
    try:
        return scoring.cvss_v40_base(vector)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def risk_matrix(likelihood: int, impact: int, scale: int = 5) -> dict:
    """Qualitative risk = likelihood × impact on a 1..scale scale (default 5×5).

    The `level` bands are a default convention, not a standard.
    Returns: {product, normalized, level, ...} or {error}.
    """
    try:
        return scoring.risk_matrix(likelihood, impact, scale)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def epss_lookup(cve: str, allow_egress: bool = False) -> dict:
    """EPSS probability for a public CVE (FIRST.org keyless API).

    EGRESS GATE: by default it does NOT make network calls (allow_egress=False). Enable consciously —
    only public CVEs, never customer data (§15/§9). Returns: {cve, epss, percentile, date}, or
    {cve, epss(None), percentile(None), note} if FIRST.org has no data for the CVE, or {error}.
    """
    try:
        return scoring.epss_lookup(cve, allow_egress=allow_egress)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def main() -> None:
    print("[scoring_mcp_server] starting.", file=sys.stderr, flush=True)
    mcp.run()


if __name__ == "__main__":
    main()
