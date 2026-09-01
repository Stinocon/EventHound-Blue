"""Generate an investigation case from the analyze() output (Phase 6, case management).

Fills the §17 template (analysis/reports/templates/caso-investigazione.template.md) with the analysis
evidence. The produced markdown, if it contains real data, must be anonymized (§9) and saved in
data/ (gitignored), NEVER committed — the analyst decides, not this function (which returns text).
"""
from __future__ import annotations


def _section_techniques(analysis: dict) -> str:
    rows = analysis.get("technique_frequency") or []
    if not rows:
        return "_no technique detected_"
    return "\n".join(f"- `{r['technique']}` ({r['hits']})" for r in rows[:15])


def _section_evidence(analysis: dict) -> str:
    out = []
    bea = analysis.get("beaconing") or []
    if bea:
        out.append("**Beaconing (C2 candidates):**")
        out += [f"- {b['src_ip']} → {b['dst_ip']}:{b['dst_port']} "
                f"(every ~{b['mean_interval_s']}s, jitter {b['jitter']})" for b in bea[:5]]
    rp = analysis.get("rare_processes") or []
    if rp:
        out.append("**Process stacking (rare processes):**")
        out += [f"- `{r['process_name']}` ({r['occurrences']}x)" for r in rp[:5]]
    si = analysis.get("shared_indicators") or []
    if si:
        out.append("**Cross-source indicators:**")
        out += [f"- {r['indicator']} ({r['kind']}, sources: {r['source_list']})" for r in si[:5]]
    return "\n".join(out) if out else "_no notable long-tail evidence_"


def render(analysis: dict, meta: dict | None = None) -> str:
    """Markdown of the case from analyze() + metadata ({title, analyst, date, scope})."""
    meta = meta or {}
    s = analysis.get("summary") or {}
    m = analysis.get("_meta") or {}
    sources_line = (f"EVTX {m.get('evtx', 0)}, PCAP {m.get('pcap', 0)} — {m.get('records', s.get('events', 0))} records"
                    if m else f"{s.get('events', 0)} events")
    summary_text = (f"{s.get('events', 0)} events across {s.get('distinct_hosts', 0)} hosts and "
                    f"{s.get('distinct_users', 0)} users; "
                    f"{len(analysis.get('technique_frequency') or [])} ATT&CK techniques, "
                    f"{len(analysis.get('beaconing') or [])} beaconing candidates.")
    return f"""# Case — {meta.get('title', '(untitled)')}

- **Date**: {meta.get('date', '')}
- **Analyst**: {meta.get('analyst', '')}
- **Scope**: {meta.get('scope', '')}
- **Sources**: {sources_line}

## Summary

{summary_text}

## Detected ATT&CK techniques

{_section_techniques(analysis)}

## Key evidence (long-tail / correlation)

{_section_evidence(analysis)}

## Compliance obligations (if applicable)

{meta.get('compliance', '_assess with tools/compliance; timelines to validate against the official text_')}

## Hypotheses and next steps

{meta.get('next_step', '_to fill in: attack hypotheses, triage to propose, containment_')}

## Notes

- Real identifiers pseudonymized per `method/anonymization.md`.
- Security numbers from `tools/scoring`; obligations from `tools/compliance`.
"""
