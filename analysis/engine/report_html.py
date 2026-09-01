"""Generate a self-contained HTML report from the result of analytics.runner.analyze().

A single HTML file, **with no external dependencies** (inline CSS + SVG charts): no CDN, no
remote font/script — openable offline and consistent with confidentiality (CSP-safe, like the GUI).
Sections: summary, long-tail chart (ATT&CK + rare processes), correlations (episodes + cross-source
indicators), and the recipe tables.

PRIVACY (§9/§10): the HTML shows real client identifiers (hosts/users/IPs). It is a **local**
artifact — it must be saved in `data/` (gitignored), pseudonymized before sharing, and **never**
published as an Artifact. Values are HTML-escaped (they are also untrusted input).

Chart: single-series magnitude → one hue, no legend, rounded ends, recessive axes,
theme-aware light/dark (dataviz skill).
"""
from __future__ import annotations

import datetime as _dt
import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics.attack import KILLCHAIN_PHASES as _KC_PHASES  # noqa: E402
from engine import attack_map  # noqa: E402

# EventHound brand: inline SVG (no external resource, like the rest of the report).
_LOGO = (
    '<svg class="mark" viewBox="0 0 48 48" role="img" aria-label="EventHound">'
    '<rect width="48" height="48" rx="11" fill="#12151c"/>'
    '<path d="M17 15 C9 16 6 26 9 34 C10.5 37.5 14 38 15.5 34.5 C16.5 29 17 21 20 17 Z" fill="#3f74e0"/>'
    '<path d="M31 15 C39 16 42 26 39 34 C37.5 37.5 34 38 32.5 34.5 C31.5 29 31 21 28 17 Z" fill="#3f74e0"/>'
    '<path d="M24 11 C31 11 35 16 35 23 C35 31 30.5 37 24 39 C17.5 37 13 31 13 23 C13 16 17 11 24 11 Z" fill="#4f8cff"/>'
    '<ellipse cx="24" cy="31" rx="7" ry="5.5" fill="#6ea1ff"/>'
    '<circle cx="20" cy="23" r="1.9" fill="#0f1115"/><circle cx="28" cy="23" r="1.9" fill="#0f1115"/>'
    '<ellipse cx="24" cy="31.5" rx="3.1" ry="2.3" fill="#0f1115"/></svg>'
)


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _svg_barchart(rows: list[dict], label_key: str, value_key: str, max_bars: int = 12) -> str:
    rows = [r for r in (rows or []) if r.get(value_key)][:max_bars]
    if not rows:
        return '<p class="empty">no data</p>'
    maxv = max(r[value_key] for r in rows) or 1
    bar_h, gap, label_w, val_w, width = 18, 9, 240, 52, 760
    plot_w = width - label_w - val_w
    height = len(rows) * (bar_h + gap) + gap
    out = [f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" class="chart">']
    y = gap
    for r in rows:
        v = r[value_key]
        w = max(3.0, plot_w * v / maxv)
        lbl = _esc(str(r[label_key]))
        if len(lbl) > 42:
            lbl = lbl[:41] + "…"
        cy = y + bar_h * 0.72
        out.append(f'<text x="{label_w - 8}" y="{cy:.0f}" class="bl" text-anchor="end">{lbl}</text>')
        out.append(f'<rect x="{label_w}" y="{y}" width="{w:.1f}" height="{bar_h}" rx="4" class="bar"/>')
        out.append(f'<text x="{label_w + w + 6:.0f}" y="{cy:.0f}" class="bv">{_esc(v)}</text>')
        y += bar_h + gap
    out.append("</svg>")
    return "".join(out)


# A confidence of 0.9 printed beside one of 0.55 reads as a different KIND of number in a column
# meant to be scanned. Two decimals everywhere, since that is the precision the value is rounded to.
def _fmt(key: str, val):
    return f"{val:.2f}" if key == "confidence" and isinstance(val, (int, float)) else val


def _table(rows: list[dict], cols: list[tuple[str, str]], limit: int | None = 50) -> str:
    rows = rows or []
    if not rows:
        return '<p class="empty">no results</p>'
    head = "".join(f"<th>{_esc(label)}</th>" for _k, label in cols)
    body = []
    _slice = rows if limit is None else rows[:limit]
    for r in _slice:
        cells = "".join(f'<td class="mono">{_esc(_fmt(k, r.get(k)))}</td>' for k, _lab in cols)
        body.append(f"<tr>{cells}</tr>")
    more = "" if limit is None or len(rows) <= limit else (
        f'<div class="empty">…and {len(rows) - limit} more rows</div>'
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>{more}"


def _section(title: str, desc: str, body: str) -> str:
    d = f'<div class="desc">{_esc(desc)}</div>' if desc else ""
    return f'<section class="card"><h2>{_esc(title)}</h2>{d}{body}</section>'


def _sigma_section(entries: list[dict] | None) -> str:
    """Sigma Community Detections card, or empty string if no entries."""
    if not entries:
        return ""
    rows = []
    for s in entries:
        lvl = s.get("level") or "info"
        lc = {"Critical": "var(--danger)", "High": "var(--warning)",
              "Medium": "var(--accent)", "Low": "var(--muted)"}.get(lvl, "var(--muted)")
        rows.append(
            f"<tr><td style=\"font-weight:500\">{_esc(s.get('rule', ''))}</td>"
            f"<td><span style=\"color:{lc};font-weight:600\">{_esc(lvl)}</span></td>"
            f"<td style=\"text-align:right\">{s.get('hits', 0)}</td>"
            f"<td>{_esc(s.get('hosts', ''))}</td></tr>"
        )
    return _section(
        "Sigma Community Detections",
        "Sigma community/custom rules that fired on this dataset.",
        '<table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:12px">'
        '<thead><tr>'
        '<th style="text-align:left;padding:6px 8px;border-bottom:2px solid var(--border)">Rule</th>'
        '<th style="text-align:left;padding:6px 8px;border-bottom:2px solid var(--border)">Level</th>'
        '<th style="text-align:right;padding:6px 8px;border-bottom:2px solid var(--border)">Hits</th>'
        '<th style="text-align:left;padding:6px 8px;border-bottom:2px solid var(--border)">Host</th>'
        '</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>',
    )


def _thor_section(findings: list[dict] | None, limit: int | None = 50) -> str:
    """THOR (Nextron) findings card (score-sorted), or empty string if none."""
    if not findings:
        return ""
    return _section(
        "THOR findings (Nextron)",
        f"{len(findings)} scored findings from the THOR scan (highest score first); "
        "hashes/files/hosts feed cross-source correlation.",
        _table(findings,
               [("thor.score", "score"), ("ioc.severity", "severity"), ("file.name", "file"),
                ("rule.title", "matched IOC/rule"), ("ioc.description", "reason"),
                ("file.hash", "sha256")],
               limit=limit),
    )


def _registry_section(findings: list[dict] | None, limit: int | None = 50) -> str:
    """Registry persistence/configuration findings, or empty string if none.

    Registry evidence used to reach no page at all: the only `ioc.severity` section here was THOR's,
    so a Run key that WAS the persistence in an incident was ingested, correlated, and then invisible
    in the artifact an analyst hands over. `severity` is the adapter's own label, never a computed
    one (§6) — the ordering comes from the recipe, this only renders it."""
    if not findings:
        return ""
    return _section(
        "Registry findings (persistence and configuration)",
        f"{len(findings)} registry entries from hives and .reg exports, most suspicious first. "
        "An ASEP entry is a configuration fact, not by itself a detection: what makes one "
        "interesting is where its data points. The 'indicator' column says what the adapter "
        "objected to, and is empty when it objected to nothing.",
        _table(findings,
               [("severity", "severity"), ("category", "category"), ("key", "key"),
                ("value", "value"), ("data", "data"), ("indicator", "indicator"),
                ("hive", "hive"), ("host", "host"), ("source", "source")],
               limit=limit),
    )


def _killchain_section(analysis: dict) -> str:
    """Kill-chain progression: the phases the dataset shows evidence for, plus the per-host depth.

    Rendered as a phase strip (observed phases lit, the others dimmed) so "how far did this get"
    is readable at a glance, followed by the evidence behind each phase. The strip is inline SVG-free
    HTML — no external resources, like the rest of the report."""
    phases = analysis.get("killchain") or []
    hosts = analysis.get("host_killchain") or []
    # Not `if not phases`: a host can carry ATT&CK evidence the offline map cannot place on a
    # phase, and that used to be impossible — so this early return silently dropped the per-host
    # table for exactly the host the evidence is about. The phase strip degrades to all-dimmed,
    # which is the honest picture: evidence, no mappable depth.
    if not phases and not hosts:
        return ""
    seen = {p["phase"]: p for p in phases}
    cells = []
    for name in _KC_PHASES:
        p = seen.get(name)
        cls = "kc on" if p else "kc off"
        n = f'<span class="kcn">{_esc(str(p["events"]))} ev</span>' if p else '<span class="kcn">—</span>'
        cells.append(f'<div class="{cls}"><span class="kcl">{_esc(name)}</span>{n}</div>')
    strip = f'<div class="kcstrip">{"".join(cells)}</div>'
    # "sources" was the column that made a reader conclude the network saw nothing: it lists the
    # tools carrying a TECHNIQUE for the phase, which on a nine-source incident is one and a half of
    # them. Renamed to say so, and paired with the tools that were active in the same window — the
    # family names only, the full sentence stays in the map's narrative where it is readable.
    body = strip + _table(phases,
                          [("phase", "phase"), ("tactics", "ATT&CK tactics"), ("techniques", "techniques"),
                           ("events", "events"), ("hosts", "hosts"),
                           ("source_list", "sources (with techniques)"),
                           ("corroboration_families", "also active in window"),
                           ("first_seen", "first seen"), ("last_seen", "last seen")],
                          limit=None) if phases else strip
    if hosts:
        body += ('<div class="desc" style="margin-top:14px">Per host — how deep the observed activity reaches '
                 '(triage order):</div>')
        body += _table(hosts,
                       [("host", "host"), ("deepest_phase", "deepest phase"), ("phases", "phases covered"),
                        ("attack_events", "ATT&CK events"), ("first_seen", "first seen"), ("last_seen", "last seen")],
                       limit=20)
    return _section(
        "Kill-chain progression",
        "phases with evidence in this dataset, from the ATT&CK tactics of the detected techniques. "
        "The ATT&CK↔kill-chain correspondence is guidance, not a one-to-one mapping "
        "(method/framework/cyber-kill-chain.md): a missing phase means 'not observed here', which is "
        "not the same as 'did not happen'.",
        body,
    )


_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin:0; font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
       background:#f6f7f9; color:#1a1d24; }
header { padding:18px 24px; border-bottom:1px solid #e3e6ec; }
.brand { display:flex; align-items:center; gap:13px; }
.brand .mark { width:36px; height:36px; flex:0 0 auto; }
h1 { margin:0; font-size:19px; } h1 .hd { color:#4f8cff; } .sub { color:#6b7280; font-size:12px; margin-top:4px; }
main { padding:24px; max-width:980px; margin:0 auto; }
.banner { background:#fff4e5; border:1px solid #ffd8a8; color:#8a5a00; border-radius:8px;
          padding:10px 14px; font-size:12px; margin-bottom:18px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:0 0 18px; }
.stat { background:#fff; border:1px solid #e3e6ec; border-radius:10px; padding:14px; }
.stat .n { font-size:24px; font-weight:700; } .stat .l { color:#6b7280; font-size:12px; }
section.card { background:#fff; border:1px solid #e3e6ec; border-radius:10px; padding:16px; margin:16px 0; overflow-x:auto; }
section.card h2 { margin:0 0 4px; font-size:15px; } .desc { color:#6b7280; font-size:12px; margin-bottom:12px; }
table { width:100%; border-collapse:collapse; font-size:12.5px; } th,td { text-align:left; padding:6px 8px; border-bottom:1px solid #eceef2; vertical-align:top; }
th { color:#6b7280; font-weight:600; } td.mono { font-family:ui-monospace,Menlo,monospace; }
.empty { color:#9aa1ad; font-style:italic; font-size:12px; }
.chart .bar { fill:#3b6fd6; } .chart .bl { fill:#6b7280; font-size:11px; } .chart .bv { fill:#1a1d24; font-size:11px; font-weight:600; }
.kcstrip { display:flex; flex-wrap:wrap; gap:6px; margin:0 0 14px; }
.kc { flex:1 1 110px; border-radius:8px; padding:8px 10px; border:1px solid #e3e6ec; background:#fbfcfe; }
.kc.on { border-color:#3b6fd6; background:#eef3fd; }
.kc .kcl { display:block; font-size:11.5px; font-weight:600; }
.kc .kcn { font-size:11px; color:#6b7280; }
.kc.off { opacity:.55; } .kc.off .kcl { font-weight:500; }
@media (prefers-color-scheme: dark) {
  body { background:#0f1115; color:#dfe3ea; } header { border-color:#262b36; }
  .banner { background:#2a2113; border-color:#5a4415; color:#ffb454; }
  .stat,section.card { background:#171a21; border-color:#262b36; } .stat .l,.desc,.sub,th { color:#8b93a3; }
  td,th { border-color:#262b36; } .chart .bar { fill:#4f8cff; } .chart .bl { fill:#8b93a3; } .chart .bv { fill:#dfe3ea; }
  .kc { background:#141821; border-color:#262b36; } .kc.on { background:#16233c; border-color:#4f8cff; }
  .kc .kcn { color:#8b93a3; }
}
"""


def render_html(analysis: dict, meta: dict | None = None, *,
                level: str = "detailed") -> str:
    """Render analysis as a self-contained HTML report.

    level: 'summary' — stat grid + top 5 ATT&CK + top 5 indicators + counts
           'detailed' — current full report (default)
           'full' — detailed + no row limits
    """
    meta = meta or {}
    s = analysis.get("summary", {}) or {}
    gen = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    tiles = [
        (s.get("events", 0), "events"),
        (s.get("distinct_hosts", 0), "hosts"),
        (s.get("distinct_users", 0), "users"),
        (len(analysis.get("technique_frequency", [])), "ATT&CK techniques"),
        (len(analysis.get("shared_indicators", [])), "shared indicators"),
        (len(analysis.get("episodes", [])), "correlated episodes"),
    ]
    grid = "".join(f'<div class="stat"><div class="n">{_esc(n)}</div><div class="l">{_esc(l)}</div></div>'
                   for n, l in tiles)

    by_source = ", ".join(f"{_esc(k)}: {_esc(v)}" for k, v in (s.get("by_source") or {}).items())
    errors = meta.get("errors") or []
    err_html = (f'<div class="banner">Warnings: {_esc(" · ".join(errors))}</div>' if errors else "")

    parts = [
        # The map's own styles come from the renderer that owns them (attack_map.css), not from a
        # copy here: the GUI shows the same fragment, and two stylesheets for one component drift.
        f"<style>{_STYLE}\n{attack_map.css()}\n"
        f"@media (prefers-color-scheme: dark) {{{attack_map.css(dark=True)}}}</style>",
        f'<header><div class="brand">{_LOGO}<div>'
        '<h1>Event<span class="hd">Hound</span> — Analysis report</h1>'
        f'<div class="sub">Generated {gen} · sources — {by_source or "n/a"} · '
        f'{_esc(meta.get("records", s.get("events", 0)))} records</div>'
        '</div></div></header>',
        "<main>",
        '<div class="banner">Real client data: pseudonymize hosts/users/IPs before '
        "sharing (§9). Local file — do not publish as an Artifact.</div>",
        err_html,
        f'<div class="grid">{grid}</div>',
    ]

    # The map goes FIRST, at every level. It answers the question an analyst opens a report with —
    # what happened — and every table below it answers a narrower one. Put after the tables (where
    # it would have fitted more tidily) it would be the section nobody scrolls to.
    _graph = analysis.get("entity_graph") or {}
    if _graph.get("nodes"):
        parts.append(_section(
            "Attack map",
            "entities and how they are linked, in kill-chain order — an edge is co-occurrence in "
            "one event, not causation; hover a node for its evidence",
            attack_map.render_html(analysis, _graph),
        ))

    if level == "summary":
        # Summary: top 5 ATT&CK, top 5 indicators, sigma/episode count
        parts.append(_section(
            "Long-tail — ATT&CK techniques",
            "frequency of detected techniques (top 5)",
            _svg_barchart(analysis.get("technique_frequency"), "technique", "hits", max_bars=5),
        ))
        _sc = analysis.get("sigma_community") or []
        sigma_n = len(_sc)
        sigma_hits = sum(s.get("hits", 0) for s in _sc)
        parts.append(_section(
            "Sigma Community",
            f"Sigma community/custom rules: {sigma_n} rules, {sigma_hits} total hits",
            f'<p class="empty">{_esc(str(sigma_n))} rules, {_esc(str(sigma_hits))} hits</p>',
        ))
        _ep = analysis.get("episodes") or []
        parts.append(_section(
            "Correlated episodes",
            "temporal clusters",
            f'<p class="empty">{_esc(str(len(_ep)))} correlated episodes</p>',
        ))
        parts.append(_thor_section(analysis.get("thor_findings"), limit=5))
        parts.append(_registry_section(analysis.get("registry_findings"), limit=5))
        # The list arrives ordered by confidence — strongest bridge first, which is the order the
        # whole correlation chapter is built to produce. Re-sorting it by occurrence count here put
        # the noisiest bridge on top of the one-page summary and buried the strongest.
        top5inds = (analysis.get("shared_indicators") or [])[:5]
        if top5inds:
            parts.append(_section(
                "Cross-source indicators (top 5 by strength)",
                "entities present across multiple source families, strongest bridge first",
                _table(top5inds,
                       [("indicator", "indicator"), ("kind", "type"), ("confidence", "conf."),
                        ("confidence_label", "strength"), ("families", "#families"),
                        ("source_list", "sources"), ("occurrences", "occ.")]),
            ))
    else:
        # detailed or full — same sections, different row limits
        _limit = None if level == "full" else 50
        parts.extend([
            _killchain_section(analysis),
            _section("Timeline",
                     "the notable events of every source on one chronological axis — what happened, "
                     "in what order. 'why' says what earned each row its place (ATT&CK technique, "
                     "high/critical Sigma hit, high-signal event type such as log clearing or "
                     "persistence installation, THOR finding, failed action); it is a selection "
                     "criterion, not a severity",
                     _table(analysis.get("timeline"),
                            [("ts", "time"), ("why", "why"), ("source", "source"),
                             ("host", "host"), ("user_name", "user"), ("process_name", "process"),
                             ("action", "action"), ("techniques", "ATT&CK"),
                             ("rule_title", "rule")],
                            limit=_limit or 99999)),
            _thor_section(analysis.get("thor_findings"), limit=_limit),
            _registry_section(analysis.get("registry_findings"), limit=_limit),
            _section("ATT&CK techniques observed",
                     "each detected technique resolved against the official ATT&CK map: name, tactic "
                     "and the kill-chain phase it belongs to",
                     _table(analysis.get("technique_catalog"),
                            [("technique", "technique"), ("name", "name"), ("tactics", "tactic"),
                             ("phase", "kill-chain phase"), ("hits", "hits"), ("hosts", "hosts"),
                             ("first_seen", "first seen"), ("last_seen", "last seen")],
                            limit=_limit or 99999)),
            _section("Long-tail — ATT&CK techniques",
                     "frequency of detected techniques (Hayabusa/Sigma)",
                     _svg_barchart(analysis.get("technique_frequency"), "technique", "hits")),
            _sigma_section(analysis.get("sigma_community")),
            _section("Long-tail — rare processes",
                     "process stacking: the least frequent processes (tail)",
                     _svg_barchart(analysis.get("rare_processes"), "process_name", "occurrences")),
            _section("Correlated episodes",
                     "temporal clusters linking multiple source families in the same window",
                     _table(analysis.get("episodes"),
                            [("start_ts", "start"), ("end_ts", "end"), ("duration_s", "duration s"),
                             ("events", "events"), ("families", "#families"), ("sources", "sources"),
                             # The phases the window covers turn "these events are correlated" into
                             # "this window is Delivery → Installation". Computed since the episode
                             # view was written; printed nowhere until now.
                             ("kc_phases", "kill-chain phases"),
                             ("hosts", "hosts"), ("ips", "IP")],
                            limit=_limit or 99999)),
            _section("Cross-source indicators",
                     "entities (IP/domain/user/host/hash/file) present across multiple families: the correlation bridge, "
                     "strongest first. The kind of entity sets the band and the number of corroborating tools orders "
                     "within it — 'why' shows that arithmetic. 'match=normalized' means different spellings were "
                     "unified (see 'spellings'); 'ambiguous' means they may be different entities, and 'note' says so",
                     _table(analysis.get("shared_indicators"),
                            [("indicator", "indicator"), ("kind", "type"), ("confidence", "conf."),
                             ("confidence_label", "strength"), ("confidence_why", "why"),
                             ("families", "#families"), ("match_type", "match"), ("variants", "spellings"),
                             ("source_list", "sources"), ("origin_list", "origin (files)"),
                             ("ambiguity", "note"), ("occurrences", "occ.")],
                            limit=_limit or 99999)),
            _section("Incident clusters (cross-tool)",
                     "connected components of co-occurring entities: each cluster is one incident reaching "
                     "across multiple source families (users/hosts/IPs/hashes tied through shared events)",
                     _table(analysis.get("incident_clusters"),
                            [("deepest_phase", "reaches"), ("kc_phases", "phases"),
                             ("sources", "#sources"), ("source_list", "sources"), ("entities", "#entities"),
                             ("users", "users"), ("hosts", "hosts"), ("ips", "IPs"),
                             ("hashes", "#hashes"), ("files", "#files"), ("domains", "#domains"),
                             ("tactics", "tactics")],
                            limit=_limit or 99999)),
            _section("Source IPs by volume",
                     "who knocks the most (web logs: scanner/attacker)",
                     _table(analysis.get("top_source_ips"),
                            [("src_ip", "IP"), ("events", "events"), ("distinct_urls", "distinct URLs"),
                             ("sources", "sources")],
                            limit=_limit or 99999)),
            _section("Most-requested URLs/paths",
                     "endpoints under pressure (e.g. /wsproxy)",
                     _table(analysis.get("web_targets"),
                            [("url", "URL"), ("hits", "hits"), ("clients", "clients"),
                             ("sample_status", "status")],
                            limit=_limit or 99999)),
            _section("Beaconing (C2 candidates)",
                     "src→dst:port triples at regular intervals (low jitter = suspicious)",
                     _table(analysis.get("beaconing"),
                            [("host", "host"), ("src_ip", "src"), ("dst_ip", "dst"), ("dst_port", "port"),
                             ("connections", "conn"), ("mean_interval_s", "interval s"), ("jitter", "jitter")],
                            limit=_limit or 99999)),
            _section("Host summary",
                     "volume, users, processes, destinations and detections per host",
                     _table(analysis.get("host_overview"),
                            [("host", "host"), ("events", "events"), ("users", "users"),
                             ("processes", "processes"), ("net_dsts", "net dst"), ("detections", "detections")],
                            limit=_limit or 99999)),
        ])

        # ── Zeek sections (only if the data is present) ──────────────────────────
        _http = analysis.get("zeek_http", [])
        if _http:
            _rows = ""
            for h in (_http if level == "full" else _http[:50]):
                _sc = str(h.get("status", ""))
                if _sc.startswith("2"):
                    _st_color = "var(--accent)"
                elif _sc.startswith("3"):
                    _st_color = "var(--warning)"
                elif _sc.startswith("4"):
                    _st_color = "var(--danger)"
                else:
                    _st_color = "var(--fg)"
                _rows += (
                    "<tr>"
                    f'<td>{_esc(str(h.get("domain","")))}</td>'
                    f'<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{_esc(str(h.get("path","")))}</td>'
                    f'<td style="text-align:center">{_esc(str(h.get("method","")))}</td>'
                    f'<td style="text-align:center;color:{_st_color}">{_esc(str(h.get("status","")))}</td>'
                    f'<td style="text-align:right">{h.get("hits",0)}</td>'
                    "</tr>"
                )
            parts.append(
                '<section class="card"><h2>HTTP Requests (Zeek)</h2>'
                '<div class="desc">HTTP requests seen by Zeek.</div>'
                '<table><thead><tr>'
                "<th>Domain</th><th>Path</th><th>Method</th><th>Status</th><th>Hits</th>"
                f"</tr></thead><tbody>{_rows}</tbody></table></section>"
            )

        _ssl = analysis.get("zeek_ssl", [])
        if _ssl:
            parts.append(_section(
                "SSL/TLS Connections (Zeek)",
                "SSL/TLS connections seen by Zeek (SNI, JA3).",
                _table(_ssl, [("ip", "IP"), ("port", "Port"), ("sni", "SNI"),
                              ("ja3", "JA3"), ("version", "Version"), ("hits", "Hits")],
                       limit=_limit or 99999),
            ))

        _dnsd = analysis.get("zeek_dns_detail", [])
        if _dnsd:
            parts.append(_section(
                "DNS Detail (Zeek)",
                "DNS query detail from Zeek (response codes, answer IPs).",
                _table(_dnsd, [("query", "Query"), ("rcode", "RCode"),
                               ("answer", "Answer"), ("hits", "Hits")],
                       limit=_limit or 99999),
            ))

    parts.append("</main>")
    return "".join(parts)
