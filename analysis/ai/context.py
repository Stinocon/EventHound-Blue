"""Context packer: analysis output → a bounded digest for the local model (DESIGN §14.4).

A saved analysis/report JSON (the output of `engine.run_analytics` / `run_report`) does not fit
raw in a small model's window. `pack_analysis` turns it into a
compact, bounded textual digest: the summary, the top-N rows of each non-empty recipe, and
the correlation highlights — enough to reason over, with **detail fetched on demand** via the
`query_analysis` tool (ai/tools.py) rather than pre-loaded here.

Pseudonymization note (§9): whatever the analysis records contain is already what the report
would show; the redaction gate that maps real identifiers to pseudonyms before the prompt is
step 3 (DESIGN §14.5). This module only *shapes* the context; it does not yet redact.
"""
from __future__ import annotations

import json
from pathlib import Path

# Keys in the analysis result that are not per-recipe row lists (handled explicitly / skipped).
# Everything NOT named here and shaped like a list is packed as "one more long-tail recipe", which
# is wrong for the correlation and kill-chain views: they were landing among the frequency tables
# under their own bare key name, so the model read the kill chain as a fifteenth statistic.
#
# Naming a key here removes it from the generic block and NOTHING else — it does not put it in the
# digest. `killchain`, `technique_catalog` and `host_killchain` sat here with no renderer of their
# own, so the on-box assistant — one of the three declared interfaces (§1) — could not see the kill
# chain at all, corroboration included, while the HTML report, the Markdown report, the GUI card and
# the demo's stdout all could. `_killchain_block` below is the fifth renderer nobody had counted.
_NON_RECIPE = {"summary", "host_overview", "shared_indicators", "episodes", "records", "timeline",
               "incident_clusters", "entity_graph", "killchain", "technique_catalog",
               "host_killchain", "thor_findings", "records_total", "records_capped",
               "infrastructure_ips", "errors",
               # A strict subset of the "Techniques observed" line above (same GROUP BY, same
               # hits, minus the names): it was worth packing while nothing rendered the
               # catalogue, and is pure repetition now that something does (§16.4).
               "technique_frequency"}

# Fields of a timeline row worth spending context on: who/where/what, not the full record.
_TIMELINE_FIELDS = ("source", "host", "user_name", "process_name", "action",
                    "src_ip", "dst_ip", "dns_query", "techniques", "rule_title")


def load_analysis(path: str | Path) -> dict:
    """Read a saved analysis/report JSON. Raises the usual IO/JSON errors to the caller."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"analysis JSON must be an object, got {type(data).__name__}")
    return data


def _row_line(row: dict, max_chars: int) -> str:
    """One recipe row as a compact 'k=v · k=v' line, non-empty fields only, bounded."""
    parts = []
    for k, v in row.items():
        if v in (None, "", [], {}):
            continue
        s = str(v)
        if len(s) > 80:
            s = s[:80] + "…"
        parts.append(f"{k}={s}")
    line = " · ".join(parts)
    return line[:max_chars] + ("…" if len(line) > max_chars else "")


def _clip(text: str, limit: int, sep: str = " · ") -> str:
    """`text` bounded to `limit`, cut on `sep` where possible and ALWAYS marked when shortened.

    A bare `text[:limit]` is not a shortening, it is a fabrication: cutting a corroboration
    sentence mid-value turned `updates.cdn-corp.example` into `updates.cdn-corp.exam` and
    `10.10.20.115` into `10.10.20.11` — a different, real host on the same /24 — and handed both to
    the model as observed evidence, with nothing to say they had been cut. Technique IDs are worse
    still: `T1021.002` clipped to `T1021` is a valid ID for a different technique, minted by a
    renderer, in the one product that refuses to mint them (§6).

    So: keep whole `sep`-separated groups while they fit. When not even the first group fits, drop
    to a finer separator inside it rather than cutting mid-token — the corroboration is built as
    `family · family`, each `clause, value, value`, so the finer cut still ends on a whole value.
    A hard cut is the last resort. Either way the result ends in `…`, which is the part that makes
    it honest, and says how many whole groups were dropped."""
    text = str(text or "")
    if len(text) <= limit:
        return text
    groups = text.split(sep)
    # The marker has to fit INSIDE the limit, or a bound the caller set is not a bound. Reserved
    # from the widest form it can take, so the result never exceeds `limit`.
    room = max(1, limit - (len(f"… (+{len(groups)} more)") if len(groups) > 1 else 1))
    kept: list[str] = []
    for g in groups:
        if kept and len(sep.join([*kept, g])) > room:
            break
        kept.append(g)
    dropped = len(groups) - len(kept)
    out = sep.join(kept)
    if len(out) > room:
        # The first group alone overflows: shorten it on the next separator down, then on spaces,
        # and only then cut blind. `_clip` is not recursive here on purpose — one pass per level
        # keeps the ellipsis count at one.
        finer = [f for f in (", ", " ") if f != sep]
        out = out[:room]
        for f in finer:
            cut = out.rsplit(f, 1)[0]
            if len(cut) >= room // 2:              # not so short that the line says nothing
                out = cut
                break
    return out.rstrip(" ,;·") + ("…" if dropped <= 0 else f"… (+{dropped} more)")


def _killchain_block(result: dict, max_rows: int, max_line: int, budget: int) -> str:
    """The kill chain as an ordered account, or "" when the analysis carries none.

    Ordered, like the timeline and unlike a recipe table: the value of a phase list to the model is
    how far the activity reaches, which a "top N rows" block destroys. The corroboration is carried
    through with the label it is given everywhere else — co-occurrence in time, never a technique
    (`correlate.phase_corroboration`) — because an assistant that repeated it as evidence of a
    technique would undo the one thing that feature exists to prevent.
    """
    phases = [p for p in (result.get("killchain") or []) if isinstance(p, dict)] \
        if isinstance(result.get("killchain"), list) else []
    hosts = [h for h in (result.get("host_killchain") or []) if isinstance(h, dict)] \
        if isinstance(result.get("host_killchain"), list) else []
    techs = [t for t in (result.get("technique_catalog") or []) if isinstance(t, dict)] \
        if isinstance(result.get("technique_catalog"), list) else []
    if not (phases or hosts or techs):
        return ""
    # `phases[-1]` assumed a sort the packer does not control. `correlate.killchain` does sort by
    # phase_order, but a hand-edited file, an imported bundle or a future consumer that filters the
    # list would make the digest state a "deepest phase" that is not the deepest — a false security
    # claim (§6) and worse than none. Ask for the maximum instead of trusting the order.
    deepest = max(phases, key=lambda p: p.get("phase_order") or 0)["phase"] if phases else None
    # The heading and the caveat are emitted whenever the block is, not only when a phase mapped:
    # they used to sit inside `if phases`, so the state where NOTHING could be placed on the chain
    # — the one that most needs the caveat — got an unheaded orphan list under `## Dataset`.
    out: list[str] = [
        f"## Kill chain ({len(phases)} phase(s) observed"
        + (f", deepest: {deepest or '?'}" if phases else ", none mappable from the evidence found")
        + "). An absent phase means NOT OBSERVED here, not that it did not happen."]
    for r in phases[:max_rows]:
        bits = [f"{r.get('events') or 0} event(s)", f"{r.get('hosts') or 0} host(s)"]
        for key, label in (("source_list", "sources"), ("tactics", "tactics"),
                           ("techniques", "techniques")):
            if r.get(key):
                bits.append(f"{label}: {r[key]}")
        if r.get("first_seen"):
            bits.append(f"{r['first_seen']} → {r.get('last_seen') or '?'}")
        out.append(f"- {r.get('phase') or '?'} — " + " · ".join(bits))
        if r.get("corroboration"):
            # The window WIDTH travels with the claim. "In the same window" over 59 minutes and
            # over 4 minutes are not the same statement — `correlate` computes the number for
            # exactly this reason and the attack map prints it; this was the only renderer that
            # dropped it, on the surface that turns it into prose for the analyst.
            secs = r.get("corroboration_window_s")
            span = f" ±{int(secs) // 60} min" if isinstance(secs, (int, float)) and secs else ""
            head = f"  also active in the same{span} window (CO-OCCURRENCE in time, not a technique): "
            out.append(head + _clip(r["corroboration"], max(40, max_line - len(head))))
    if hosts:
        shown = hosts[:max_rows]
        who = "; ".join(f"{h.get('host') or '?'} ({h.get('deepest_phase') or 'no mappable phase'}, "
                        f"{h.get('phases_covered') or 0} phase(s))" for h in shown)
        head = f"Hosts by depth (top {len(shown)} of {len(hosts)}, triage order): "
        out.append(head + _clip(who, max(40, max_line - len(head)), sep="; "))
    if techs:
        shown = techs[:max_rows]
        named = ", ".join(f"{t.get('technique') or '?'}"
                          + (f" ({t['name']})" if t.get("name") else "")
                          + f" ×{t.get('hits') or 0}" for t in shown)
        head = f"Techniques observed (top {len(shown)} of {len(techs)}): "
        out.append(head + _clip(named, max(40, max_line - len(head)), sep=", "))
    # A sub-budget, so the kill chain cannot crowd out the rest. It measured 1.8-1.9 KB on every
    # real analysis while the whole digest saturates around 10.7 KB — enough, inserted ahead of
    # them, to push the unified timeline past the tail cut on an ordinary case. The timeline is
    # load-bearing for this interface (DESIGN 0.20.0); a section that displaces it silently is not
    # an improvement.
    return _clip("\n".join(out), budget, sep="\n")


def pack_analysis(result: dict, *, max_rows: int = 8, max_line: int = 220,
                  budget_chars: int = 12000) -> str:
    """Produce a bounded textual digest of an analysis result.

    `max_rows` rows per recipe, each ≤ `max_line` chars; the whole digest is capped at
    `budget_chars` (a small-model context safeguard, §14.4) with an explicit truncation note."""
    lines: list[str] = []

    summary = result.get("summary") or {}
    if summary:
        by_source = summary.get("by_source") or {}
        lines.append(
            f"## Dataset\n{summary.get('events', 0)} events · "
            f"{summary.get('distinct_hosts', 0)} host(s) · {summary.get('distinct_users', 0)} user(s)"
            + (f" · sources: {', '.join(f'{k}={v}' for k, v in by_source.items())}" if by_source else "")
        )

    # Before the frequency tables: it is the account of what happened, and everything below is
    # detail underneath it.
    kc = _killchain_block(result, max_rows, max_line, max(600, budget_chars // 5))
    if kc:
        lines.append(kc)

    # Per-recipe findings: only non-empty lists, top N rows each.
    findings: list[str] = []
    for key, val in result.items():
        if key in _NON_RECIPE or not isinstance(val, list) or not val:
            continue
        block = [f"### {key} ({len(val)} row(s), top {min(max_rows, len(val))})"]
        for row in val[:max_rows]:
            block.append("- " + (_row_line(row, max_line) if isinstance(row, dict) else str(row)[:max_line]))
        findings.append("\n".join(block))
    if findings:
        lines.append("## Findings\n" + "\n\n".join(findings))

    # Correlation highlights: counts + a few items, defensively (shapes vary).
    corr: list[str] = []
    shared = result.get("shared_indicators")
    if isinstance(shared, list) and shared:
        corr.append(f"- shared indicators: {len(shared)} (e.g. "
                    + "; ".join(_row_line(r, 120) for r in shared[:3] if isinstance(r, dict)) + ")")
    episodes = result.get("episodes")
    if isinstance(episodes, list) and episodes:
        corr.append(f"- temporal episodes: {len(episodes)}")
    host_ov = result.get("host_overview")
    if isinstance(host_ov, list) and host_ov:
        corr.append(f"- hosts in overview: {len(host_ov)}")
    if corr:
        lines.append("## Correlation\n" + "\n".join(corr))

    # The timeline goes in as an ordered sequence rather than as one more row list: its value to the
    # model is the *order*, which a "top N rows of a recipe" block destroys. Bounded like everything
    # else here — the rest is reachable with query_analysis.
    tl = result.get("timeline")
    if isinstance(tl, list) and tl:
        block = [f"## Timeline ({len(tl)} notable event(s), first {min(max_rows, len(tl))} in order)"]
        for row in tl[:max_rows]:
            if not isinstance(row, dict):
                continue
            what = " · ".join(f"{k}={row[k]}" for k in _TIMELINE_FIELDS
                              if row.get(k) not in (None, "", [], {}))
            block.append(f"- {row.get('ts', '?')} [{row.get('why', '?')}] {what}"[:max_line])
        lines.append("\n".join(block))

    if not lines:
        return "(empty analysis: no events or findings)"

    digest = "\n\n".join(lines)
    if len(digest) > budget_chars:
        digest = digest[:budget_chars].rstrip() + \
            "\n\n[digest truncated to fit the context budget — use query_analysis for detail]"
    return digest
