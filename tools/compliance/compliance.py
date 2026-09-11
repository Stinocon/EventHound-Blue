"""Compliance resolver: from incident attributes → applicable notification obligations.

Separates the LOGIC (deterministic, golden-tested) from the LEGAL DATA (obligations.yaml, with
citations and a `da_validare` flag). Timelines must be confirmed against the official text
under `method/normative/`. NOT legal advice: it's triage support that indicates WHAT to check.

Expected incident attributes (all optional, default false/None):
  personal_data_breach: bool        personal data breach (GDPR)
  high_risk_to_individuals: bool    high risk to the rights of data subjects (GDPR art. 34)
  entity_type: "essential"|"important"|"none"   NIS2 entity type
  significant_incident: bool        "significant" incident for NIS2 purposes
  financial_entity: bool            financial entity (DORA)
  major_ict_incident: bool          "major" ICT incident for DORA purposes
"""
from __future__ import annotations

from pathlib import Path

_OBLIGATIONS = None


def _load() -> list[dict]:
    global _OBLIGATIONS
    if _OBLIGATIONS is None:
        import yaml
        path = Path(__file__).resolve().parent / "obligations.yaml"
        _OBLIGATIONS = yaml.safe_load(path.read_text(encoding="utf-8"))["obbligazioni"]
    return _OBLIGATIONS


def _matches(trigger: dict, incident: dict) -> bool:
    for key, expected in trigger.items():
        actual = incident.get(key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def applicable(incident: dict) -> list[dict]:
    """Obligations applicable to the incident, sorted by urgency (shortest deadline first;
    unquantified deadlines stay at the tail). Each entry carries the norm, milestone, deadline,
    article reference and da_validare flag."""
    out = []
    for ob in _load():
        if _matches(ob.get("trigger", {}), incident):
            out.append({
                "id": ob["id"], "norma": ob["norma"], "milestone": ob["milestone"],
                "within_hours": ob.get("within_hours"), "when": ob.get("when"),
                "authority": ob.get("authority"), "reference": ob["reference"],
                "da_validare": ob.get("da_validare", True),
            })
    out.sort(key=lambda o: (o["within_hours"] is None, o["within_hours"] or 0))
    return out


def summary(incident: dict) -> dict:
    """Summary outcome: applicable obligations + norms involved + most urgent deadline."""
    obs = applicable(incident)
    norme = sorted({o["norma"] for o in obs})
    urgent = next((o for o in obs if o["within_hours"] is not None), None)
    return {
        "incident": incident,
        "obligations": obs,
        "norms": norme,
        "most_urgent": urgent,
        "disclaimer": "Triage support, not legal advice. Timelines must be validated against the "
                      "official text under `method/normative/`.",
    }


FUNZIONI = {"applicable": applicable, "summary": summary}
