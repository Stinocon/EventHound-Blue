"""Report generation — JSON format (filtered by level).

Produce a JSON dump of analysis, filtered by detail level:
  - summary: only _meta, summary, top 5 technique_frequency, sigma/episodes counts.
  - detailed: every analytic view, without the raw `records` array (default).
  - full: everything, including the records.

`detailed` used to be "everything except correlation_graph", and when that view was removed the two
levels became byte-identical — a choice the CLI still offered and that changed nothing. The line
between them is now the one that was always meant: `records` is the EVIDENCE the analysis was
computed from, it is by far the largest key, and it is the part a reader of a report does not need.
Dropping it is also the §9-relevant half, since the raw records carry every identifier verbatim.
"""
from __future__ import annotations

import copy
import json


def _filter_summary(data: dict) -> dict:
    """Keep only summary-level fields."""
    out: dict = {}
    if "_meta" in data:
        out["_meta"] = data["_meta"]
    if "summary" in data:
        out["summary"] = data["summary"]

    # Top 5 technique frequency
    tf = data.get("technique_frequency", [])
    out["technique_frequency"] = sorted(tf, key=lambda x: -(x.get("hits", 0)))[:5]

    # Count indicators
    sc = data.get("sigma_community", [])
    out["sigma_community_count"] = len(sc)
    out["sigma_community_hits"] = sum(s.get("hits", 0) for s in sc)
    ep = data.get("episodes", [])
    out["episodes_count"] = len(ep)

    return out


def _filter_detailed(data: dict) -> dict:
    """Every analytic view, without the raw records the views were computed from."""
    out = copy.deepcopy(data)
    out.pop("records", None)
    # Kept, because they are what says the omission happened rather than leaving it to be inferred.
    out["records_omitted"] = len(data.get("records") or [])
    return out


def render_json(data: dict, name: str = "", scanned_at: str = "",
                level: str = "detailed") -> str:
    """Render analysis as filtered JSON string.

    Args:
        data: Analysis result dict from analytics.runner.analyze().
        name: Optional name (included in _meta if not already present).
        scanned_at: ISO timestamp string (included in _meta if provided).
        level: 'summary' | 'detailed' (default, no raw records) | 'full' (with them).

    Returns:
        JSON string.
    """
    if level == "summary":
        payload = _filter_summary(data)
    elif level == "detailed":
        payload = _filter_detailed(data)
    else:  # full
        payload = data

    # Add optional metadata if not already present
    meta = payload.get("_meta") or {}
    changed = False
    if name and "_name" not in meta:
        meta["_name"] = name
        changed = True
    if scanned_at and "_scanned_at" not in meta:
        meta["_scanned_at"] = scanned_at
        changed = True
    if changed:
        payload = copy.deepcopy(payload) if payload is data else payload
        payload["_meta"] = meta

    return json.dumps(payload, indent=2, default=str, ensure_ascii=False)
