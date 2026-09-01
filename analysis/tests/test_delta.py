"""What-changed between two analyze() results (baseline.delta/delta_headline).

Pure logic on hand-built result dicts — no engine run, no DuckDB: the analyze() shape is fixed
(analytics/runner.py::analyze_con, analytics/correlate.py row shapes) and this only exercises the
comparison, so building it by hand is both faster and a check that the function reads the real
shape rather than one convenient to generate.

    uv run python tests/test_delta.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analytics import baseline  # noqa: E402


def _result(events=0, by_source=None, shared_indicators=None, incident_clusters=None,
           episodes=None, technique_catalog=None, killchain=None) -> dict:
    """Builds a minimal analyze()-shaped dict — only the keys delta() reads."""
    return {
        "summary": {"events": events, "by_source": by_source or {}},
        "shared_indicators": shared_indicators or [],
        "incident_clusters": incident_clusters or [],
        "episodes": episodes or [],
        "technique_catalog": technique_catalog or [],
        "killchain": killchain or [],
    }


def _bridge(indicator="203.0.113.5", kind="ip", families=2, source_list="evtx, log"):
    return {"indicator": indicator, "kind": kind, "families": families, "sources": families,
            "source_list": source_list, "confidence": 0.5, "confidence_label": "medium"}


def run() -> int:
    # --- first analysis: before=None means everything in `after` is new, not an empty diff -------
    after = _result(
        events=10, by_source={"evtx": 10},
        shared_indicators=[_bridge()],
        technique_catalog=[{"technique": "T1021.002", "name": "SMB/Windows Admin Shares"}],
        killchain=[{"phase": "Lateral Movement", "phase_order": 3}],
    )
    d = baseline.delta(None, after)
    assert d["first_analysis"] is True, d
    assert d["new_events"] == 10, d
    assert d["new_sources"] == ["evtx"], d
    assert len(d["new_bridges"]) == 1 and d["new_bridges"][0]["indicator"] == "203.0.113.5", d
    assert d["strengthened_bridges"] == [], d  # nothing to have strengthened against
    assert len(d["new_techniques"]) == 1, d
    assert d["kc_depth_before"] == 0 and d["kc_depth_after"] == 3, d
    assert d["deepest_phase_after"] == "Lateral Movement", d
    assert d["total_new"] > 0, d
    headline = baseline.delta_headline(d)
    assert headline.startswith("First analysis:"), headline
    assert headline.strip() != "", headline

    # --- a genuinely new bridge, and one carried over unchanged -------------------------------
    before = _result(
        events=10, by_source={"evtx": 10},
        shared_indicators=[_bridge(indicator="203.0.113.5", kind="ip", families=2)],
    )
    after = _result(
        events=15, by_source={"evtx": 15},
        shared_indicators=[
            _bridge(indicator="203.0.113.5", kind="ip", families=2),      # unchanged
            _bridge(indicator="CORP\\svc_backup", kind="user", families=2),  # new
        ],
    )
    d = baseline.delta(before, after)
    assert d["first_analysis"] is False, d
    assert d["new_events"] == 5, d
    assert len(d["new_bridges"]) == 1, d
    assert d["new_bridges"][0]["indicator"] == "CORP\\svc_backup", d
    assert d["strengthened_bridges"] == [], d  # the carried-over bridge did not grow
    assert d["total_new"] == 1, d

    # --- a bridge that gained a family: strengthened, not new, and annotated with families_before
    before = _result(shared_indicators=[_bridge(indicator="10.0.0.5", kind="ip", families=2)])
    after = _result(shared_indicators=[_bridge(indicator="10.0.0.5", kind="ip", families=3)])
    d = baseline.delta(before, after)
    assert d["new_bridges"] == [], d
    assert len(d["strengthened_bridges"]) == 1, d
    s = d["strengthened_bridges"][0]
    assert s["families_before"] == 2 and s["families"] == 3, s
    assert d["total_new"] == 1, d
    headline = baseline.delta_headline(d)
    assert "strengthened" in headline, headline

    # --- kill-chain depth advancing --------------------------------------------------------------
    before = _result(killchain=[{"phase": "Delivery", "phase_order": 1}])
    after = _result(killchain=[
        {"phase": "Delivery", "phase_order": 1},
        {"phase": "Actions on Objectives", "phase_order": 6},
    ])
    d = baseline.delta(before, after)
    assert d["kc_depth_before"] == 1 and d["kc_depth_after"] == 6, d
    assert d["deepest_phase_after"] == "Actions on Objectives", d
    headline = baseline.delta_headline(d)
    assert "Actions on Objectives" in headline, headline

    # --- clusters merging: fewer clusters, more entities than before ------------------------------
    before = _result(incident_clusters=[
        {"entities": 3, "sources": 2}, {"entities": 2, "sources": 2},
    ])
    after = _result(incident_clusters=[
        {"entities": 6, "sources": 3},  # the two above merged into one bigger cluster
    ])
    d = baseline.delta(before, after)
    assert d["cluster_count_before"] == 2 and d["cluster_count_after"] == 1, d
    assert d["clusters_merged"] is True, d
    headline = baseline.delta_headline(d)
    assert "merged" in headline, headline

    # a cluster count going down WITHOUT more entities (one just fell below min_entities) must not
    # be reported as a merge
    before = _result(incident_clusters=[{"entities": 3, "sources": 2}, {"entities": 2, "sources": 2}])
    after = _result(incident_clusters=[{"entities": 3, "sources": 2}])
    d = baseline.delta(before, after)
    assert d["clusters_merged"] is False, d

    # --- nothing changed at all: total_new == 0, and the headline says so plainly -----------------
    same = _result(
        events=10, by_source={"evtx": 10},
        shared_indicators=[_bridge()],
        incident_clusters=[{"entities": 4, "sources": 2}],
        technique_catalog=[{"technique": "T1021.002", "name": "x"}],
        killchain=[{"phase": "Delivery", "phase_order": 1}],
        episodes=[{"start_ts": "2026-07-16T06:00:00Z"}],
    )
    d = baseline.delta(same, same)
    assert d["total_new"] == 0, d
    assert d["new_events"] == 0, d
    assert d["clusters_merged"] is False, d
    assert d["new_episodes"] == 0, d
    headline = baseline.delta_headline(d)
    assert headline.strip() != "", headline
    assert "no changes" in headline.lower(), headline

    # --- `before` missing several keys entirely (older bundle / partial dict): no KeyError --------
    sparse_before = {"summary": {"events": 3, "by_source": {"evtx": 3}}}
    after = _result(
        events=8, by_source={"evtx": 8},
        shared_indicators=[_bridge()],
        technique_catalog=[{"technique": "T1059", "name": "Command and Scripting Interpreter"}],
        killchain=[{"phase": "Installation", "phase_order": 4}],
        episodes=[{"start_ts": "2026-07-16T06:00:00Z"}],
    )
    d = baseline.delta(sparse_before, after)
    assert d["new_events"] == 5, d
    assert len(d["new_bridges"]) == 1, d
    assert len(d["new_techniques"]) == 1, d
    assert d["kc_depth_before"] == 0, d
    assert d["new_episodes"] == 1, d
    assert baseline.delta_headline(d).strip() != "", d

    print("PASS  delta: first analysis, new/strengthened bridges, kill-chain depth, "
         "cluster merge, no-change, sparse before")
    return 0


def test_delta():
    assert run() == 0


if __name__ == "__main__":
    raise SystemExit(run())
