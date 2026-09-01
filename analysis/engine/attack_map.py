"""The attack map: one picture and one story, from the same evidence the tables show.

Every piece of this existed and none of it was ever drawn. `incident_clusters` says which entities
belong to one incident but collapses them into a membership list; `shared_indicators` ranks bridges
without saying what they connect to; the entity→tool edge list that used to be computed here had no renderer
consumed — it reached a markdown table at `--level full` and was dropped from the JSON report and
the AI context outright. So the answer to the first question an analyst asks, *what happened*, had
to be reassembled by reading four tables and holding them in your head.

Two renderings, from one model, sharing the report and the GUI so they cannot drift:

- the **graph** — entities and the links between them, laid out in kill-chain lanes. Inline SVG
  built here, with no library and no external resource, like the rest of the report.
- the **narrative** — a deterministic account, phase by phase: what was observed, on which hosts,
  when, and which tools said so.

What it does NOT claim. An edge is co-occurrence — two entities named by one event — not causation.
The kill-chain lane is interpretation, and `analytics/attack.py` documents the mapping as guidance
rather than fact. Every node carries the evidence count that put it there, and every narrative line
names its source, so the picture can be checked rather than believed (§6).
"""
from __future__ import annotations

import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import attack  # noqa: E402

# One colour per entity kind. Chosen to survive both report themes (the report ships light and dark)
# and to stay distinguishable in greyscale print, which is how these end up in a client annex.
_KIND_COLOR = {
    "user": "#c084fc",
    "host": "#4f8cff",
    "ip": "#f59e0b",
    "domain": "#22d3ee",
    "file": "#34d399",
    "file_hash": "#f87171",
}
_KIND_LABEL = {"user": "account", "host": "host", "ip": "address",
               "domain": "domain", "file": "artifact", "file_hash": "hash"}

_NO_PHASE = "not placed on the kill chain"


def _esc(v) -> str:
    return html.escape(str(v), quote=True)


def _short(v: str, n: int = 22) -> str:
    v = str(v)
    return v if len(v) <= n else v[: n - 1] + "…"


def lanes(graph: dict) -> list[tuple[str, list[dict]]]:
    """Nodes grouped into kill-chain lanes, in phase order, with the unplaced ones last.

    Unplaced last rather than first: they are context for the chain, not its beginning, and putting
    them at the top made the map look as though the intrusion started with whatever had no
    technique attached to it."""
    by_phase: dict[str, list[dict]] = {}
    for n in graph.get("nodes") or []:
        by_phase.setdefault(n.get("phase") or _NO_PHASE, []).append(n)
    ordered = sorted((p for p in by_phase if p != _NO_PHASE),
                     key=lambda p: attack.PHASE_ORDER.get(p, 99))
    if _NO_PHASE in by_phase:
        ordered.append(_NO_PHASE)
    out = []
    for phase in ordered:
        out.append((phase, sorted(by_phase[phase],
                                  key=lambda n: (-n.get("degree", 0), n["value"]))))
    return out


def render_svg(graph: dict, width: int = 900) -> str:
    """Inline SVG of the entity graph: lanes by kill-chain phase, edges weighted by co-occurrence.

    A deterministic layout, not a force-directed one: the same evidence must produce the same
    picture every time it is rendered, or two readers comparing two copies of the same report end
    up arguing about a difference that is only the layout settling differently.
    """
    grouped = lanes(graph)
    if not grouped:
        return '<p class="empty">no correlated entities to map</p>'

    lane_h, top_pad, label_w = 96, 34, 190
    # A node needs room for its LABEL, not just its circle. One lane laid out as a single row put
    # twelve entities in 670 px — 56 px each — under labels a hundred wide, so the bottom of the map
    # was a band of overlapping text: unreadable, and worse than unreadable because it looked like
    # information. A crowded lane therefore wraps onto as many rows as its labels need. Truncating
    # harder was the alternative and it is the wrong one: a hash cut to eight characters and an
    # address cut to eight look the same.
    slot_w, row_h = 108, 46
    positions: dict[str, tuple[float, float]] = {}
    body: list[str] = []
    y = top_pad
    for phase, nodes in grouped:
        usable = width - label_w - 40
        per_row = max(1, int(usable // slot_w))
        rows = (len(nodes) + per_row - 1) // per_row
        body.append(f'<text x="10" y="{y + 4:.0f}" class="am-lane">{_esc(_short(phase, 30))}</text>')
        body.append(f'<line x1="{label_w - 12}" y1="{y - 18:.0f}" x2="{width - 12}" '
                    f'y2="{y - 18:.0f}" class="am-rule"/>')
        for i, n in enumerate(nodes):
            row, col = divmod(i, per_row)
            in_row = min(per_row, len(nodes) - row * per_row)
            step = usable / max(in_row, 1)
            positions[n["id"]] = (label_w + step * (col + 0.5), y + row * row_h)
        y += max(lane_h, top_pad + rows * row_h)

    height = y + 40

    # Edges first so nodes sit on top of them.
    edges = [e for e in (graph.get("edges") or [])
             if e["source"] in positions and e["target"] in positions]
    maxw = max((e["weight"] for e in edges), default=1)
    for e in edges:
        x1, y1 = positions[e["source"]]
        x2, y2 = positions[e["target"]]
        w = 0.8 + 3.2 * (e["weight"] / maxw)
        body.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                    f'class="am-edge" stroke-width="{w:.2f}"><title>'
                    f'{_esc(e["source"])} ↔ {_esc(e["target"])}: {e["weight"]} shared events'
                    f'</title></line>')

    for phase, nodes in grouped:
        for n in nodes:
            x, ny = positions[n["id"]]
            # Radius from how many independent tools saw it, not from how loud it is: an entity
            # three tools agree on is the one worth looking at first.
            r = 6 + 2.4 * min(int(n.get("family_count") or 1), 5)
            color = _KIND_COLOR.get(n["kind"], "#8b93a3")
            title = (f'{_KIND_LABEL.get(n["kind"], n["kind"])} {n["value"]} — '
                     f'{n.get("events", 0)} events, {n.get("family_count", 0)} tools '
                     f'({", ".join(n.get("families") or [])})')
            body.append(f'<g class="am-node" data-id="{_esc(n["id"])}">'
                        f'<title>{_esc(title)}</title>'
                        f'<circle cx="{x:.1f}" cy="{ny:.1f}" r="{r:.1f}" fill="{color}" '
                        f'fill-opacity="0.85" stroke="{color}"/>'
                        f'<text x="{x:.1f}" y="{ny + r + 14:.0f}" class="am-lbl" '
                        f'text-anchor="middle">{_esc(_short(n["value"]))}</text></g>')

    legend = " ".join(
        f'<tspan fill="{c}">●</tspan> {_esc(_KIND_LABEL[k])}' for k, c in _KIND_COLOR.items())
    body.append(f'<text x="10" y="{height - 16}" class="am-lbl">{legend}</text>')
    return (f'<svg viewBox="0 0 {width} {height:.0f}" width="100%" role="img" class="am">'
            + "".join(body) + "</svg>")


def narrative(analysis: dict) -> list[dict]:
    """A phase-by-phase account of what the evidence shows, in kill-chain order.

    Deterministic and derived: every sentence is assembled from `killchain`, `technique_catalog` and
    `incident_clusters`, and each carries the tools that support it. Nothing is inferred beyond the
    ATT&CK→phase mapping, which is already declared as guidance.
    """
    out: list[dict] = []
    catalog = {t["technique"]: t for t in (analysis.get("technique_catalog") or [])}
    for row in analysis.get("killchain") or []:
        techs = [t.strip() for t in (row.get("techniques") or "").split(",") if t.strip()]
        named = [f'{t} ({catalog[t]["name"]})' if t in catalog and catalog[t].get("name") else t
                 for t in techs[:4]]
        hosts = row.get("hosts") or 0
        text = (f'{row.get("events", 0)} event(s) on {hosts} host(s) between '
                f'{row.get("first_seen") or "?"} and {row.get("last_seen") or "?"}')
        if named:
            text += ", via " + ", ".join(named)
        # The phase is established by the techniques above. What follows is weaker on purpose: the
        # other tools were active in the same window, and this is what they saw. Co-occurrence in
        # time, stated as such — the alternative was minting techniques out of network heuristics,
        # which would fill the lanes and mean less (§6).
        also = row.get("corroboration") or ""
        if also:
            win = row.get("corroboration_window_s")
            # None means the span could not be computed. Naming no width is honest; the previous
            # fallback printed the padding alone ("4 min") for what may have been hours, understating
            # exactly what the number exists to state.
            if win is None:
                text += f". In the same window — {also}"
            else:
                span = f"{int(win) // 60} min" if int(win) >= 120 else f"{int(win)} s"
                text += f". In the same {span} window — {also}"
        out.append({
            "phase": row.get("phase") or "",
            "phase_order": row.get("phase_order") or 0,
            "text": text,
            "sources": row.get("source_list") or "",
            "techniques": ", ".join(techs),
        })
    if not out:
        return out

    # The closing line is about REACH, and it is the one an analyst quotes. It says how far the
    # observed activity goes and immediately says what that does not mean: an absent phase means
    # "not observed here", which a gap in telemetry looks exactly like.
    deepest = max(out, key=lambda r: r["phase_order"])
    clusters = analysis.get("incident_clusters") or []
    scope = ""
    if clusters:
        c = clusters[0]
        parts = [p for p in (c.get("hosts"), c.get("users")) if p]
        if parts:
            scope = " Largest cluster: " + " / ".join(parts) + "."
    out.append({
        "phase": "Reach",
        "phase_order": 99,
        "text": (f'The observed activity reaches {deepest["phase"]}. Phases with no evidence are '
                 f'omitted, not shown as zero: absent means "not observed here", which is '
                 f'indistinguishable from a gap in telemetry.' + scope),
        "sources": "",
        "techniques": "",
    })
    return out


def render_html(analysis: dict, graph: dict) -> str:
    """The map as a self-contained HTML fragment: graph, then narrative. Used by the report and the
    GUI so both show the same thing rendered by the same code."""
    parts = [render_svg(graph)]
    if graph.get("truncated"):
        parts.append(f'<p class="empty">showing the {len(graph["nodes"])} most connected of '
                     f'{graph["total_nodes"]} entities — the rest are in the tables below.</p>')
    story = narrative(analysis)
    if story:
        rows = "".join(
            f'<tr><td><b>{_esc(s["phase"])}</b></td><td>{_esc(s["text"])}</td>'
            f'<td>{_esc(s["sources"])}</td></tr>' for s in story)
        # The lanes and this table are both in kill-chain order, and the timestamps in it are NOT
        # monotonic — the ATT&CK→phase mapping is coarse, so a lateral-movement hit can land in a
        # later phase than a C2 hit that happened after it. A reader who takes the order for a
        # chronology draws a false sequence out of true evidence, so the order says what it is.
        parts.append('<p class="empty">Phases are in kill-chain order, which is <b>interpretation, '
                     'not chronology</b>: read the timestamps for sequence, and the Timeline view '
                     'for the actual order of events.</p>')
        parts.append('<table class="am-story"><thead><tr><th>Phase</th><th>What the evidence '
                     f'shows</th><th>Tools</th></tr></thead><tbody>{rows}</tbody></table>')
    else:
        parts.append('<p class="empty">no kill-chain evidence to narrate</p>')
    return "".join(parts)


_CSS = """
.am { display:block; margin:6px 0 10px; }
.am-lane { font-size:11px; fill:#6b7280; font-weight:600; }
.am-rule { stroke:#e5e7eb; stroke-width:1; }
.am-edge { stroke:#9aa3b2; stroke-opacity:.45; }
.am-node circle { cursor:default; }
.am-lbl { font-size:10px; fill:#6b7280; }
.am-story td:nth-child(2) { white-space:normal; }
"""


_CSS_DARK = """
.am-rule { stroke:#262b36; } .am-edge { stroke:#6b7280; }
.am-lane, .am-lbl { fill:#8b93a3; }
"""


def css(dark: bool = False) -> str:
    """Styles for the fragment. Kept beside the renderer rather than in the report's stylesheet so
    the GUI gets the same look without copying it.

    `dark=True` returns ONLY the overrides, so the caller can drop them inside its own
    `prefers-color-scheme` block without repeating the light rules there."""
    return _CSS_DARK if dark else _CSS
