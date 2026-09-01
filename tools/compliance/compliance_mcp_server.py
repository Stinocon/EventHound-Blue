"""MCP server (stdio): maps an incident onto notification obligations (GDPR/NIS2/DORA).

Local, deterministic logic (compliance.py). NOT legal advice: indicates what to check.
Timelines must be confirmed against the official text (RAG: 'normative' collection).
"""
import sys

from mcp.server.fastmcp import FastMCP

import compliance

mcp = FastMCP("compliance")


@mcp.tool()
def incident_obligations(
    personal_data_breach: bool = False,
    high_risk_to_individuals: bool = False,
    entity_type: str = "none",
    significant_incident: bool = False,
    financial_entity: bool = False,
    major_ict_incident: bool = False,
) -> dict:
    """Notification obligations applicable to an incident, with deadlines and article references.

    Args:
        personal_data_breach: personal data breach (GDPR).
        high_risk_to_individuals: high risk to the rights of data subjects (GDPR art. 34).
        entity_type: NIS2 entity type — "essential", "important" or "none".
        significant_incident: "significant" incident for NIS2 purposes.
        financial_entity: financial entity (DORA).
        major_ict_incident: "major" ICT incident for DORA purposes.

    Returns:
        {obligations[], norms[], most_urgent, disclaimer}. Each obligation: norma, milestone,
        within_hours, when, authority, reference (article), da_validare.
    """
    incident = {
        "personal_data_breach": personal_data_breach,
        "high_risk_to_individuals": high_risk_to_individuals,
        "entity_type": entity_type,
        "significant_incident": significant_incident,
        "financial_entity": financial_entity,
        "major_ict_incident": major_ict_incident,
    }
    try:
        return compliance.summary(incident)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def main() -> None:
    print("[compliance_mcp_server] starting.", file=sys.stderr, flush=True)
    mcp.run()


if __name__ == "__main__":
    main()
