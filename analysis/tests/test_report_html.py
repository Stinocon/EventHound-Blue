"""Test of the HTML report generator (engine/report_html) — offline, deterministic.

Checks: the expected sections are present, the SVG chart is rendered, values are HTML-escaped, and —
confidentiality/CSP invariant — NO references to external resources appear (http(s)://, src=).
    uv run python tests/test_report_html.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import report_html  # noqa: E402

ANALYSIS = {
    "summary": {"events": 3, "by_source": {"evtx": 2, "log:acc": 1},
                "distinct_hosts": 1, "distinct_users": 1},
    "technique_frequency": [{"technique": "T1021.005", "hits": 5}, {"technique": "T1078", "hits": 2}],
    "rare_processes": [{"process_name": "C:\\evil<>.exe", "occurrences": 1, "hosts": 1}],
    "episodes": [{"start_ts": "2026-07-16 06:28:59", "end_ts": "2026-07-16 06:29:10",
                  "duration_s": 11.0, "events": 2, "families": 2, "sources": "evtx, log:acc",
                  "hosts": 1, "ips": 1}],
    "shared_indicators": [{"indicator": "203.0.113.5", "kind": "ip", "families": 2,
                           "source_list": "evtx, log:acc", "occurrences": 3}],
    "top_source_ips": [{"src_ip": "203.0.113.5", "events": 3, "distinct_urls": 1, "sources": 2}],
    "web_targets": [{"url": "/wsproxy", "hits": 1, "clients": 1, "sample_status": 101}],
    "beaconing": [],
    "host_overview": [{"host": "DC-01", "events": 3, "users": 1, "processes": 1,
                       "net_dsts": 0, "detections": 1}],
}


def run() -> int:
    h = report_html.render_html(ANALYSIS, {"records": 3, "errors": []})

    # NB "ATT&CK" in titles is escaped to "ATT&amp;CK": search for the escaped form
    for needle in ("ATT&amp;CK techniques", "Correlated episodes", "Cross-source indicators",
                   "T1021.005", "203.0.113.5", "/wsproxy"):
        assert needle in h, f"missing from report: {needle!r}"
    assert "<svg" in h and 'class="bar"' in h, "SVG chart not rendered"

    # HTML-escaping: the process name with <> must not appear raw (XSS/layout break)
    assert "C:\\evil<>.exe" not in h, "value not escaped"
    assert "evil&lt;&gt;.exe" in h, "expected escaping not found"

    # CSP/privacy invariant: no external resource (no http(s)://, no src=, no url())
    assert not re.search(r"https?://", h), "the report contains an external URL"
    assert "src=" not in h, "the report references an external resource (src=)"
    assert "url(" not in h, "the report uses url() (possible external fetch)"

    # privacy banner present
    assert "pseudonymize" in h and "Artifact" in h, "privacy banner absent"

    # ── the attack map: every mark on it must be able to show the evidence behind it ──
    # A picture is the one part of a report that invites belief without checking, so a node or an
    # edge that cannot say what put it there does not belong in one (§6).
    from analytics import runner
    from engine.run_demo import demo_records
    import tempfile as _tf
    _recs = demo_records(Path(_tf.mkdtemp(prefix="map-report-")) / "out", errors=[])
    _res = runner.analyze(_recs)
    _map = report_html.render_html(_res, {"name": "map"}, level="detailed")
    assert "Attack map" in _map, "the map section is missing from a report that has a graph"
    n_nodes = _map.count('class="am-node"')
    n_edges = _map.count('class="am-edge"')
    assert n_nodes > 0 and n_edges > 0, (n_nodes, n_edges)
    # One <title> per node and one per edge: hovering anything on the map states its evidence.
    # Matched on the edge markup, not on the phrase: the same words appear in the clusters
    # section's description, and a test that matched prose would drift on the first rewording.
    assert len(re.findall(r'class="am-edge"[^>]*><title>[^<]*shared events</title>', _map)) == n_edges, (
        "an edge on the map carries no evidence tooltip")
    assert _map.count(" events, ") >= n_nodes, (_map.count(" events, "), n_nodes)
    assert "co-occurrence" in _map, "the map does not state that an edge is not causation"
    assert not re.search(r"https?://", _map), "the map section introduced an external URL"

    print("PASS  report_html: sections, SVG, escaping, no external resource, privacy banner, "
          "attack map with per-node and per-edge evidence")
    return 0


def test_report_html():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
