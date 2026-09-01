"""Report generation — Markdown format.

Produce a pure Markdown report (portable, versionable, anonymizable before sharing).
Three levels:
  - summary: executive 1-pager (stat grid, top 5 ATT&CK, top 5 indicators, counts).
  - detailed: complete operational report (default).
  - full: everything, no row limits on tables.

PRIVACY (§9/§10): the Markdown displays real customer identifiers — save to `data/`
(gitignored), anonymize before sharing, never publish as Artifact.
"""
from __future__ import annotations

import datetime as _dt

from . import attack_map

SUMMARY_TEMPLATE = """# EventHound — Analysis Report (summary)

**Generated**: {gen}
**Sources**: {by_source}
**Records**: {records}
**Level**: summary

## Statistics

| Measure | Value |
|---|---|
| Events | {events} |
| Distinct hosts | {hosts} |
| Distinct users | {users} |
| ATT&CK techniques | {techniques} |
| Shared indicators | {indicators} |
| Correlated episodes | {episodes} |

## ATT&CK Techniques (top 5)

{technique_table}

## Sigma Community

{sigma_text}

## Correlated Episodes

{episodes_text}

## Cross-source Indicators (top 5)

{indicators_table}
"""


def _esc(v) -> str:
    return "" if v is None else str(v)


# Two decimals, so a 0.9 does not read as a different kind of number from the 0.55 under it.
def _fmt(key: str, val):
    return f"{val:.2f}" if key == "confidence" and isinstance(val, (int, float)) else val


def _md_table(rows: list[dict], cols: list[tuple[str, str]], limit: int | None = 50) -> str:
    """Render a list of dicts as a Markdown table."""
    rows = rows or []
    if not rows:
        return "*no data*"
    _slice = rows if limit is None else rows[:limit]
    header = "| " + " | ".join(label for _k, label in cols) + " |"
    sep = "| " + " | ".join("---" for _ in cols) + " |"
    body = []
    for r in _slice:
        cells = " | ".join(_esc(_fmt(k, r.get(k, ""))) for k, _lab in cols)
        body.append(f"| {cells} |")
    lines = [header, sep] + body
    if limit is not None and len(rows) > limit:
        lines.append(f"\n*… and {len(rows) - limit} more rows*")
    return "\n".join(lines)


def render_markdown(data: dict, name: str = "", scanned_at: str = "",
                    level: str = "detailed") -> str:
    """Render analysis as Markdown text.

    Args:
        data: Analysis result dict from analytics.runner.analyze().
        name: Report name; it is the report's title line. (The docstring used to say
            "unused in output, for API compatibility" — it has been in the title since
            the header was written, and the note sent readers looking for a caller to
            delete.)
        scanned_at: ISO timestamp string (auto-generated if empty).
        level: 'summary' | 'detailed' (default) | 'full'.

    Returns:
        Markdown report string.
    """
    s = data.get("summary", {}) or {}
    gen = scanned_at or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    by_source = ", ".join(f"{k}: {v}" for k, v in (s.get("by_source") or {}).items())
    records = _esc(s.get("events", 0))
    _name = name or "analysis"

    lines: list[str] = []

    if level == "summary":
        tf = data.get("technique_frequency", [])
        tf_top = sorted(tf, key=lambda x: -(x.get("hits", 0)))[:5]
        tf_table = _md_table(tf_top, [("technique", "Technique"), ("hits", "Hits")], limit=None)

        sc = data.get("sigma_community") or []
        sigma_n = len(sc)
        sigma_hits = sum(s.get("hits", 0) for s in sc)
        sigma_text = f"{sigma_n} rules, {sigma_hits} total hits" if sc else "*none*"

        ep = data.get("episodes") or []
        episodes_text = f"{len(ep)} correlated episodes" if ep else "*none*"

        # Already confidence-sorted: re-sorting by occurrence count put the noisiest bridge at the
        # top of the one-page summary and buried the strongest one.
        inds_top = (data.get("shared_indicators") or [])[:5]
        inds_table = _md_table(inds_top,
                               [("indicator", "Indicator"), ("kind", "Type"),
                                ("confidence_label", "Strength"), ("families", "#Families"),
                                ("source_list", "Sources"), ("occurrences", "Occ.")],
                               limit=None)

        tmpl_data = {
            "gen": gen, "by_source": by_source or "n/d", "records": records,
            "events": _esc(s.get("events", 0)),
            "hosts": _esc(s.get("distinct_hosts", 0)),
            "users": _esc(s.get("distinct_users", 0)),
            "techniques": _esc(len(tf)),
            "indicators": _esc(len(data.get("shared_indicators", []))),
            "episodes": _esc(len(data.get("episodes", []))),
            "technique_table": tf_table,
            "sigma_text": sigma_text,
            "episodes_text": episodes_text,
            "indicators_table": inds_table,
        }
        return SUMMARY_TEMPLATE.format(**tmpl_data)

    # ── detailed / full ────────────────────────────────────────────────────────
    limit = None if level == "full" else 50

    lines.append(f"# EventHound — Analysis Report — {_name}")
    lines.append("")
    lines.append(f"> **Generated**: {gen}")
    if by_source:
        lines.append(f"> **Sources**: {by_source}")
    lines.append(f"> **Records**: {records}")
    lines.append(f"> **Level**: {level}")
    lines.append("")

    # What the evidence shows, before any table. The HTML report has opened with the attack map and
    # its phase-by-phase account since the map was built; the Markdown one went straight to the
    # statistics, so the two formats told a different story from the same analysis — and Markdown is
    # the one that gets pasted into a ticket, where the reader has none of the context.
    story = attack_map.narrative(data)
    if story:
        lines.append("## What the evidence shows")
        lines.append("")
        lines.append("Assembled from the kill-chain coverage and the technique catalogue: every line "
                     "names the tools behind it. The phases are listed in kill-chain order, which is "
                     "**interpretation, not chronology** — read the timestamps, not the order.")
        lines.append("")
        lines.append(_md_table(story, [("phase", "Phase"), ("text", "What the evidence shows"),
                                       ("sources", "Tools")], limit=None))
        lines.append("")

    # Stat grid as table
    lines.append("## Statistics")
    lines.append("")
    lines.append("| Measure | Value |")
    lines.append("|---|---|")
    for lbl, key in [("Events", "events"), ("Distinct hosts", "distinct_hosts"),
                     ("Distinct users", "distinct_users")]:
        lines.append(f"| {lbl} | {_esc(s.get(key, 0))} |")
    lines.append(f"| ATT&CK techniques | {_esc(len(data.get('technique_frequency', [])))} |")
    lines.append(f"| Shared indicators | {_esc(len(data.get('shared_indicators', [])))} |")
    lines.append(f"| Correlated episodes | {_esc(len(data.get('episodes', [])))} |")
    lines.append("")

    # Timeline
    lines.append("## Timeline")
    lines.append("")
    lines.append("The notable events of every source on one chronological axis. *Why* says what "
                 "earned each row its place (ATT&CK technique, high/critical Sigma hit, "
                 "high-signal event type such as log clearing or persistence installation, THOR "
                 "finding, failed action) — a selection criterion, not a severity.")
    lines.append("")
    lines.append(_md_table(data.get("timeline"),
                           [("ts", "Time"), ("why", "Why"), ("source", "Source"),
                            ("host", "Host"), ("user_name", "User"),
                            ("process_name", "Process"), ("action", "Action"),
                            ("techniques", "ATT&CK")],
                           limit=limit))
    lines.append("")

    # ATT&CK Techniques
    lines.append("## Long-tail — ATT&CK techniques")
    lines.append("")
    lines.append("Frequency of detected techniques (Hayabusa/Sigma).")
    lines.append("")
    lines.append(_md_table(data.get("technique_frequency"),
                           [("technique", "Technique"), ("hits", "Hits")],
                           limit=limit))
    lines.append("")

    # Sigma Community
    _sc = data.get("sigma_community")
    if _sc:
        lines.append("## Sigma Community Detections")
        lines.append("")
        lines.append("Sigma community/custom rules triggered on this dataset.")
        lines.append("")
        lines.append(_md_table(_sc, [("rule", "Rule"), ("level", "Level"),
                                     ("hits", "Hits"), ("hosts", "Hosts")],
                               limit=limit))
        lines.append("")

    # Rare processes
    lines.append("## Long-tail — rare processes")
    lines.append("")
    lines.append("Process stacking: least frequent processes (tail).")
    lines.append("")
    lines.append(_md_table(data.get("rare_processes"),
                           [("process_name", "Process"), ("occurrences", "Occ."),
                            ("hosts", "Hosts")],
                           limit=limit))
    lines.append("")

    # Episodes
    lines.append("## Correlated Episodes")
    lines.append("")
    lines.append("Temporal clusters linking multiple source families in the same window.")
    lines.append("")
    lines.append(_md_table(data.get("episodes"),
                           [("start_ts", "Start"), ("end_ts", "End"),
                            ("duration_s", "Duration s"), ("events", "Events"),
                            ("families", "#Families"), ("sources", "Sources"),
                            ("kc_phases", "Kill-chain phases"),
                            ("hosts", "Hosts"), ("ips", "IPs")],
                           limit=limit))
    lines.append("")

    # Shared indicators
    lines.append("## Cross-source Indicators")
    lines.append("")
    lines.append("Entities (IP/domain/user/host/hash/file) present in multiple families: the "
                 "correlation bridge, strongest first. The kind of entity sets the band and the "
                 "number of corroborating tools orders within it; *Why* shows that arithmetic.")
    lines.append("")
    lines.append(_md_table(data.get("shared_indicators"),
                           [("indicator", "Indicator"), ("kind", "Type"), ("confidence", "Conf."),
                            ("confidence_label", "Strength"), ("confidence_why", "Why"),
                            ("families", "#Families"), ("match_type", "Match"),
                            ("source_list", "Sources"), ("occurrences", "Occ.")],
                           limit=limit))
    lines.append("")

    # ── the three views Markdown never rendered ───────────────────────────────────────────────
    kc = data.get("killchain") or []
    if kc:
        lines.append("## Kill-chain coverage")
        lines.append("")
        lines.append("Phases the activity is observed to reach. An absent phase means *not observed "
                     "here*, which a gap in telemetry looks exactly like — it is never shown as zero.")
        lines.append("")
        lines.append(_md_table(kc, [("phase", "Phase"), ("events", "Events"), ("hosts", "Hosts"),
                                    ("source_list", "Tools (with techniques)"),
                                    ("corroboration_families", "Also active in window"),
                                    ("first_seen", "First seen"),
                                    ("last_seen", "Last seen"), ("techniques", "Techniques")],
                               limit=limit))
        lines.append("")

    cat = data.get("technique_catalog") or []
    if cat:
        lines.append("## ATT&CK techniques observed")
        lines.append("")
        lines.append("Each technique resolved against the official ATT&CK map (offline STIX): what it "
                     "is, which tactic it serves, which kill-chain phase it lands in.")
        lines.append("")
        lines.append(_md_table(cat, [("technique", "ID"), ("name", "Name"), ("tactics", "Tactics"),
                                     ("phase", "Phase"), ("hits", "Hits"), ("hosts", "Hosts"),
                                     ("sources", "#Tools")], limit=limit))
        lines.append("")

    cl = data.get("incident_clusters") or []
    if cl:
        lines.append("## Incident clusters (cross-tool)")
        lines.append("")
        lines.append("Connected components of co-occurring entities: one cluster is one incident "
                     "reaching across tools. Membership is co-occurrence, never causation.")
        lines.append("")
        lines.append(_md_table(cl, [("deepest_phase", "Reaches"), ("kc_phases", "Phases"),
                                    ("sources", "#Tools"), ("source_list", "Tools"),
                                    ("entities", "#Entities"), ("users", "Users"),
                                    ("hosts", "Hosts"), ("ips", "IPs"), ("hashes", "#Hashes")],
                               limit=limit))
        lines.append("")

    thor = data.get("thor_findings") or []
    if thor:
        lines.append("## THOR findings")
        lines.append("")
        lines.append(_md_table(
            [{"score": r.get("thor.score"), "ts": r.get("@timestamp"),
              "host": r.get("host.name"), "rule": r.get("rule.title"),
              "file": r.get("file.name") or r.get("file.path"),
              "message": (str(r.get("message") or ""))[:160]} for r in thor],
            [("score", "Score"), ("ts", "When"), ("host", "Host"), ("rule", "Rule"),
             ("file", "Artifact"), ("message", "Detail")], limit=limit))
        lines.append("")

    # Top source IPs
    lines.append("## Source IPs by volume")
    lines.append("")
    lines.append("Who knocks the most (web logs: scanner/attacker).")
    lines.append("")
    lines.append(_md_table(data.get("top_source_ips"),
                           [("src_ip", "IP"), ("events", "Events"),
                            ("distinct_urls", "Distinct URLs"), ("sources", "Sources")],
                           limit=limit))
    lines.append("")

    # Web targets
    lines.append("## Most requested URLs/paths")
    lines.append("")
    lines.append("Endpoints under pressure (e.g., /wsproxy).")
    lines.append("")
    lines.append(_md_table(data.get("web_targets"),
                           [("url", "URL"), ("hits", "Hits"),
                            ("clients", "Clients"), ("sample_status", "Status")],
                           limit=limit))
    lines.append("")

    # Beaconing
    lines.append("## Beaconing (C2 candidates)")
    lines.append("")
    lines.append("Triples src→dst:port at regular intervals (low jitter = suspicious).")
    lines.append("")
    lines.append(_md_table(data.get("beaconing"),
                           [("host", "Host"), ("src_ip", "Src"), ("dst_ip", "Dst"),
                            ("dst_port", "Port"), ("connections", "Conn"),
                            ("mean_interval_s", "Interval s"), ("jitter", "Jitter")],
                           limit=limit))
    lines.append("")

    # Host overview
    lines.append("## Host Summary")
    lines.append("")
    lines.append("Volume, users, processes, destinations, and detections per host.")
    lines.append("")
    lines.append(_md_table(data.get("host_overview"),
                           [("host", "Host"), ("events", "Events"), ("users", "Users"),
                            ("processes", "Processes"), ("net_dsts", "Net dests"),
                            ("detections", "Detections")],
                           limit=limit))
    lines.append("")

    # Zeek HTTP
    _http = data.get("zeek_http", [])
    if _http:
        lines.append("## HTTP Requests (Zeek)")
        lines.append("")
        lines.append("HTTP requests seen by Zeek.")
        lines.append("")
        lines.append(_md_table(_http,
                               [("domain", "Domain"), ("path", "Path"),
                                ("method", "Method"), ("status", "Status"),
                                ("hits", "Hits")],
                               limit=limit))
        lines.append("")

    # Zeek SSL
    _ssl = data.get("zeek_ssl", [])
    if _ssl:
        lines.append("## SSL/TLS Connections (Zeek)")
        lines.append("")
        lines.append("SSL/TLS connections seen by Zeek (SNI, JA3).")
        lines.append("")
        lines.append(_md_table(_ssl,
                               [("ip", "IP"), ("port", "Port"), ("sni", "SNI"),
                                ("ja3", "JA3"), ("version", "Version"), ("hits", "Hits")],
                               limit=limit))
        lines.append("")

    # Zeek DNS
    _dns = data.get("zeek_dns_detail", [])
    if _dns:
        lines.append("## DNS Detail (Zeek)")
        lines.append("")
        lines.append("DNS query details from Zeek (response codes, response IPs).")
        lines.append("")
        lines.append(_md_table(_dns,
                               [("query", "Query"), ("rcode", "RCode"),
                                ("answer", "Answer"), ("hits", "Hits")],
                               limit=limit))
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("> **Privacy (§9)**: this report contains real customer identifiers — "
                 "anonymize before sharing, do not publish as Artifact.")
    lines.append("")

    return "\n".join(lines)
