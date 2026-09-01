# tools/compliance — incident → obligations mapping (GDPR/NIS2/DORA)

Given an incident, indicates **which notification obligations** are triggered, with **deadlines**, authorities,
and **article references**. Bridges analysis with the normative RAG (collection `normative`, containing
GDPR/NIS2/DORA): the engine flags the incident, here you see *what must be notified and by when*.

**Not legal advice.** It's a triage support: indicates what to verify. Legal content is
**data** (`obligations.yaml`) with citations and `to_validate` flags — timelines must be confirmed
against official text (some, e.g. DORA, are detailed by RTS/ITS). The **matching logic** is
deterministic and golden-tested.

## Usage

```
cd tools/compliance && uv run python validate.py     # logic gate (golden)
uv run python -c "import compliance,json; print(json.dumps(compliance.summary({'personal_data_breach':True,'entity_type':'essential','significant_incident':True}),ensure_ascii=False,indent=2))"
```

As MCP tool: `incident_obligations(personal_data_breach, high_risk_to_individuals, entity_type,
significant_incident, financial_entity, major_ict_incident)` (registered in `.mcp.json`).

## Incident Attributes

| attribute | norm | meaning |
|-----------|-------|-------------|
| `personal_data_breach` | GDPR | personal data breach |
| `high_risk_to_individuals` | GDPR | high risk to rights (→ art. 34, notification to data subjects) |
| `entity_type` | NIS2 | `essential` / `important` / `none` |
| `significant_incident` | NIS2 | "significant" incident |
| `financial_entity` | DORA | financial entity |
| `major_ict_incident` | DORA | "major" ICT incident |

For details and precise citations: `method/normative/obligations-map.md` and the `normative` collection
in the RAG.
