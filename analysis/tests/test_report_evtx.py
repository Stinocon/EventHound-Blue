"""The EVTX-slice Markdown renderer (engine/report.py), which nothing exercised.

`run_evtx` calls `report.render`, and `run_evtx` needs Hayabusa and a real `.evtx` — so the only
renderer in the suite with no test was also the one on the path most likely to be run by hand. A
pure function of records needs no binary, which is why this file is mock records only.

    uv run python tests/test_report_evtx.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import report  # noqa: E402


def _rec(**kw) -> dict:
    base = {"@timestamp": "2026-07-16T06:28:59Z", "event.source": "evtx",
            "host.name": "WS-01", "rule.title": "Suspicious process", "rule.level": "low"}
    base.update(kw)
    return base


def test_norm_level_maps_abbreviations_and_unknowns() -> None:
    """Hayabusa abbreviates ("crit"), the label table does not, and anything unrecognised must fall
    to `info` rather than dropping the row from the counts."""
    for raw, want in (("crit", "crit"), ("critical", "crit"), ("Critical", "crit"),
                      ("high", "high"), ("medium", "med"), ("med", "med"),
                      ("low", "low"), ("info", "info"), ("informational", "info"),
                      (None, "info"), ("", "info"), ("weird", "info")):
        assert report._norm_level(raw) == want, (raw, report._norm_level(raw))


def test_render_context_counts_and_hosts() -> None:
    md = report.render([
        _rec(**{"rule.level": "critical", "host.name": "DC-01"}),
        _rec(**{"rule.level": "high", "host.name": "WS-01"}),
        _rec(**{"rule.level": "low"}),
    ], evtx_name="Security.evtx", scanned_at="2026-07-16T07:00:00Z")

    assert "# EVTX Slice → ATT&CK — Security.evtx" in md
    assert "- Observed hosts: DC-01, WS-01" in md
    assert "- Total detections: 3 — critical: 1 · high: 1 · low: 1" in md
    assert "- Scan: 2026-07-16T07:00:00Z" in md
    # A level with no rows must not appear in the summary at all.
    assert "medium: 0" not in md and "informational: 0" not in md


def test_render_techniques_grouped_and_unmapped_counted() -> None:
    md = report.render([
        _rec(**{"attack.techniques": ["T1059.001", "T1547.001"], "attack.tactics": ["execution"]}),
        _rec(**{"attack.techniques": ["T1105"]}),                      # techniques, no tactic
        _rec(),                                                        # no ATT&CK mapping at all
    ], evtx_name="Security.evtx", scanned_at="2026-07-16T07:00:00Z")

    assert "- **execution**: `T1059.001`, `T1547.001`" in md
    assert "- **(tactic not indicated)**: `T1105`" in md
    assert "Additionally 1 detections without explicit ATT&CK mapping" in md


def test_render_timeline_is_sorted_and_pipes_are_escaped() -> None:
    """A `|` inside a rule title or a command line would otherwise break the table it is written
    into — the row would silently gain a column."""
    md = report.render([
        _rec(**{"@timestamp": "2026-07-16T06:30:00Z", "rule.title": "late"}),
        _rec(**{"@timestamp": "2026-07-16T06:28:59Z", "rule.title": "a|b",
                "process.name": "cmd|exe"}),
    ], evtx_name="Security.evtx", scanned_at="2026-07-16T07:00:00Z")

    rows = [ln for ln in md.splitlines() if ln.startswith("| 2026-")]
    assert len(rows) == 2, rows
    # Sorted by @timestamp, not by input order.
    assert rows[0].startswith("| 2026-07-16T06:28:59Z") and "a/b" in rows[0], rows[0]
    assert rows[1].startswith("| 2026-07-16T06:30:00Z") and "late" in rows[1], rows[1]
    assert "cmd/exe" in rows[0], rows[0]
    assert "a|b" not in md and "cmd|exe" not in md


def test_render_empty_records_is_still_a_report() -> None:
    """No detections is a legitimate outcome and must read as one, not as a crash or a blank page."""
    md = report.render([], evtx_name="empty.evtx", scanned_at="2026-07-16T07:00:00Z")

    assert "- Observed hosts: n/d" in md
    assert "- Total detections: 0" in md
    assert "No ATT&CK techniques mapped in this slice's detections." in md
    assert "## Next Steps" in md


def run() -> int:
    test_norm_level_maps_abbreviations_and_unknowns()
    test_render_context_counts_and_hosts()
    test_render_techniques_grouped_and_unmapped_counted()
    test_render_timeline_is_sorted_and_pipes_are_escaped()
    test_render_empty_records_is_still_a_report()
    print("PASS  report (evtx slice): level normalization, context counts, technique grouping, "
          "timeline ordering + pipe escaping, and the empty case")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
