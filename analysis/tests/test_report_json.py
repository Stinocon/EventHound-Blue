"""The JSON report levels (engine/report_json.py) — the contract three levels used to share.

`detailed` and `full` were byte-identical until `records` was made the difference, and the CLI still
offers the three levels: a level that quietly returns the wrong amount of the analysis is the §9
question (do the raw identifiers leave with the report?) as much as a correctness one, so it is
pinned here rather than inferred from a rendered file.

    uv run python tests/test_report_json.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import report_json  # noqa: E402


def _analysis() -> dict:
    return {
        "_meta": {"bundle_version": 1},
        "summary": {"events": 3, "by_source": {"evtx": 2, "pcap": 1}},
        "records": [{"host.name": "WS-01"}, {"host.name": "DC-01"}, {"host.name": "WS-01"}],
        "technique_frequency": [{"technique": "T1059", "hits": 1}, {"technique": "T1105", "hits": 9},
                                {"technique": "T1547", "hits": 3}, {"technique": "T1003", "hits": 2},
                                {"technique": "T1071", "hits": 7}, {"technique": "T1021", "hits": 4}],
        "sigma_community": [{"hits": 2}, {"hits": 5}],
        "episodes": [{"id": 1}, {"id": 2}],
        "shared_indicators": [{"kind": "ip"}],
    }


def test_summary_keeps_the_digest_and_the_top_five() -> None:
    out = json.loads(report_json.render_json(_analysis(), level="summary"))

    assert out["summary"] == {"events": 3, "by_source": {"evtx": 2, "pcap": 1}}
    assert out["_meta"] == {"bundle_version": 1}
    # Top five by hits, descending: 9, 7, 4, 3, 2 — and T1059 (1 hit) is the one dropped.
    assert [t["technique"] for t in out["technique_frequency"]] == \
        ["T1105", "T1071", "T1021", "T1547", "T1003"]
    assert out["sigma_community_count"] == 2 and out["sigma_community_hits"] == 7
    assert out["episodes_count"] == 2
    assert "records" not in out and "shared_indicators" not in out


def test_detailed_drops_records_and_says_so() -> None:
    out = json.loads(report_json.render_json(_analysis(), level="detailed"))

    assert "records" not in out
    assert out["records_omitted"] == 3
    # Everything else survives: the views were computed from those records and are what the level is
    # for.
    assert out["shared_indicators"] == [{"kind": "ip"}]
    assert "technique_frequency" in out


def test_full_carries_the_evidence() -> None:
    out = json.loads(report_json.render_json(_analysis(), level="full"))

    assert len(out["records"]) == 3
    assert "records_omitted" not in out


def test_unknown_level_falls_back_to_full() -> None:
    """The CLI validates its own choices; a level that reached here unrecognised must hand back the
    complete analysis rather than a silently reduced one — too much is recoverable, too little is a
    report that looks complete and is not."""
    out = json.loads(report_json.render_json(_analysis(), level="detailed-ish"))

    assert "records" in out and "records_omitted" not in out


def test_meta_is_added_without_overwriting_what_is_already_there() -> None:
    out = json.loads(report_json.render_json(_analysis(), name="case-1",
                                             scanned_at="2026-07-16T07:00:00Z", level="summary"))
    assert out["_meta"]["_name"] == "case-1"
    assert out["_meta"]["_scanned_at"] == "2026-07-16T07:00:00Z"
    assert out["_meta"]["bundle_version"] == 1

    kept = json.loads(report_json.render_json(
        {"_meta": {"_name": "original"}, "summary": {}}, name="other"))
    assert kept["_meta"]["_name"] == "original"


def test_render_is_deterministic_json() -> None:
    """Same input, same bytes — a report that reshuffles between runs cannot be diffed."""
    a = report_json.render_json(_analysis(), level="summary")
    b = report_json.render_json(_analysis(), level="summary")
    assert a == b
    assert json.loads(a) == json.loads(b)


def run() -> int:
    test_summary_keeps_the_digest_and_the_top_five()
    test_detailed_drops_records_and_says_so()
    test_full_carries_the_evidence()
    test_unknown_level_falls_back_to_full()
    test_meta_is_added_without_overwriting_what_is_already_there()
    test_render_is_deterministic_json()
    print("PASS  report json: summary/detailed/full split, records omission, meta injection, "
          "deterministic bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
