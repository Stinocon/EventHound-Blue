---
type: incident-analysis
date: "{{analysis_date}}"
product: "{{product}}"
scope: "{{host_tenant_user}}"   # pseudonyms (§9)
time_window: "{{window}}"
placeholders: [analysis_date, product, host_tenant_user, window, incident_title]
---

# Incident analysis — {{incident_title}}

## Context and scope
High-level summary of what happened, perimeter (host/tenant/users, pseudonyms), time window, data limitations.

## Timeline
Ordered sequence of events (timestamp → observed event, anonymized). Distinguish observed data from interpretation.

| when | observed event | source |
|------|----------------|--------|
| {{ts}} | {{event}}       | {{source}} |

## Entities involved
Hosts, users, accounts, IPs/domains (pseudonyms for client data; public malicious indicators — hashes, C2, CVEs — remain in plain text, §9).

## Techniques (MITRE ATT&CK)
Observed tactics/techniques (`Txxxx`), mapped to the kill chain phases (see `method/framework/`).

## Assessment
What likely happened, with what confidence; alternative hypotheses and residual uncertainties.

## Recommendations and next steps
Containment/eradication/recovery from least to most invasive, with **explicit impact** (§12). Hardening and monitoring guidance. Execution by the analyst in their authorized environment.
