---
type: detection-interpretation
date: "{{analysis_date}}"
product: "{{product}}"           # e.g. CrowdStrike Falcon
scope: "{{host_tenant_user}}"    # pseudonyms (§9)
time_window: "{{window}}"
placeholders: [analysis_date, product, host_tenant_user, window, detection_name, severity]
---

# Detection interpretation — {{detection_name}}

## Context
What we are looking at and data limitations. Severity/context: {{severity}}.

## Evidence
Observed facts, **anonymized** (§9): process, command line, file/hash, network, user/host (pseudonyms). Distinguish explicit data from interpretation.

## Interpretation
What the evidence suggests. Probable MITRE ATT&CK technique (`Txxxx`) when appropriate.

## Hypotheses and uncertainties
Alternative explanations (including false positive) and what would be needed to confirm them.

## Next steps (triage)
From least to most invasive, with **explicit impact** (read-only vs. endpoint modification, §12). Execution is the analyst's responsibility in their authorized environment.
