"""Baseline / diffing: what is NEW compared to a known-good state (Phase 6).

Compares current records against a baseline (a "clean" reference dataset) and
isolates what appears only in the current set: new processes, new network destinations, new domains,
new techniques, new parent→child pairs. It complements long-tail analysis: there you search for rare,
here you search for *different from normal*. Pure logic on common schema records, no networking.
"""
from __future__ import annotations


def _set(records, *keys):
    """Set of non-null values (or tuples of values) for the given keys."""
    out = set()
    for r in records:
        vals = tuple(r.get(k) for k in keys)
        if all(v is not None and v != "" for v in vals):
            # Per-record tolerance (like store._cell, §8): a non-hashable field (list/dict from an
            # adapter on dirty input) is coerced to string instead of aborting the entire diff
            # with TypeError: unhashable type.
            vals = tuple(v if isinstance(v, (str, int, float, bool, tuple)) else str(v) for v in vals)
            out.add(vals if len(vals) > 1 else vals[0])
    return out


def _techniques(records) -> set:
    out = set()
    for r in records:
        for t in (r.get("attack.techniques") or []):
            out.add(t)
    return out


def diff(current: list[dict], baseline: list[dict]) -> dict:
    """Elements present in CURRENT but absent in BASELINE, grouped by dimension of interest."""
    return {
        "new_processes": sorted(_set(current, "process.name") - _set(baseline, "process.name")),
        "new_dst_ips": sorted(_set(current, "destination.ip") - _set(baseline, "destination.ip")),
        "new_dns": sorted(_set(current, "dns.question.name") - _set(baseline, "dns.question.name")),
        "new_techniques": sorted(_techniques(current) - _techniques(baseline)),
        "new_parent_child": sorted(
            _set(current, "process.parent.name", "process.name")
            - _set(baseline, "process.parent.name", "process.name")
        ),
    }


def summary(current: list[dict], baseline: list[dict]) -> dict:
    d = diff(current, baseline)
    total_new = sum(len(v) for v in d.values())
    return {"diff": d, "total_new": total_new,
            "current_events": len(current), "baseline_events": len(baseline)}


# --- delta(): what's new between two analyze() RESULTS (Phase whole-case re-analysis) ------------
#
# Once every upload re-runs analytics over the whole accumulated case (not just the new file), the
# analyst faces the same wall of tables a second and third time, with no way to tell which rows are
# the reason they were paged. `diff()`/`summary()` above answer that question over raw records
# (new process, new destination IP, ...); this answers it one layer up, over the *analyze() output*
# itself — new cross-source bridges, a bridge that just got corroborated by another tool, the kill
# chain reaching one phase deeper, separate leads turning out to be the same incident. That is the
# information a re-analysis actually needs to surface, because it is the information that changes an
# analyst's next action.


def _rows(result: dict | None, key: str) -> list[dict]:
    """Tolerant read of a list-valued analyze() section: missing (older bundle, hand-built dict in
    a test, a `before=None` first analysis) reads as empty rather than raising KeyError."""
    return (result or {}).get(key) or []


def _families(row: dict) -> int:
    """`families` and its back-compat alias `sources` carry the same count (correlate.shared_indicators);
    tolerate either being absent so a bridge row from an older result still compares correctly."""
    v = row.get("families")
    if v is None:
        v = row.get("sources")
    return v or 0


def _kc_peak(result: dict | None) -> tuple[int, str]:
    """Deepest kill-chain phase reached: (phase_order, phase name), (0, "") when there is none.
    `killchain` has one row per phase actually observed (correlate.killchain), so the peak is simply
    the row with the highest phase_order — there is no separate "depth" field to read."""
    rows = _rows(result, "killchain")
    if not rows:
        return 0, ""
    peak = max(rows, key=lambda r: r.get("phase_order") or 0)
    return peak.get("phase_order") or 0, peak.get("phase") or ""


def delta(before: dict | None, after: dict) -> dict:
    """What changed between two analyze()/analyze_case() results.

    `before` is the previous run's result, or None the first time a case is analyzed. A first
    analysis is not "nothing changed" — everything in `after` is new — so rather than diffing
    against nothing (which would silently read as an empty, all-zero delta) `before` is treated as
    an empty result and the output additionally carries `first_analysis: True` so a caller can say
    so explicitly instead of guessing it from an all-new delta that happens to look the same as a
    real one.

    Every section is read tolerantly (`_rows`): a `before` missing a key entirely — an older bundle,
    or a result built by hand in a test — reads as if that section were empty, never KeyError. That
    is deliberate: a delta that crashes on an old case is worse than one that overstates what is new.
    """
    first_analysis = before is None
    before = before or {}

    summary_before = before.get("summary") or {}
    summary_after = after.get("summary") or {}
    new_events = (summary_after.get("events") or 0) - (summary_before.get("events") or 0)

    sources_before = set((summary_before.get("by_source") or {}).keys())
    sources_after = set((summary_after.get("by_source") or {}).keys())
    new_sources = sorted(sources_after - sources_before)

    shared_before = _rows(before, "shared_indicators")
    shared_after = _rows(after, "shared_indicators")
    before_bridges = {(r.get("indicator"), r.get("kind")): r for r in shared_before}

    new_bridges = [r for r in shared_after if (r.get("indicator"), r.get("kind")) not in before_bridges]
    strengthened_bridges = []
    for r in shared_after:
        key = (r.get("indicator"), r.get("kind"))
        prior = before_bridges.get(key)
        if prior is None:
            continue  # already counted in new_bridges, not a strengthening of an existing one
        before_count, after_count = _families(prior), _families(r)
        if after_count > before_count:
            strengthened_bridges.append({**r, "families_before": before_count})

    techniques_before = {r.get("technique") for r in _rows(before, "technique_catalog")}
    new_techniques = [r for r in _rows(after, "technique_catalog")
                     if r.get("technique") not in techniques_before]

    kc_depth_before, deepest_phase_before = _kc_peak(before)
    kc_depth_after, deepest_phase_after = _kc_peak(after)

    clusters_before = _rows(before, "incident_clusters")
    clusters_after = _rows(after, "incident_clusters")
    cluster_count_before, cluster_count_after = len(clusters_before), len(clusters_after)
    entities_before = sum(r.get("entities") or 0 for r in clusters_before)
    entities_after = sum(r.get("entities") or 0 for r in clusters_after)
    # Fewer clusters covering more entities is the concrete signature of a merge: the same
    # union-find over a bigger dataset joined components that used to be separate. Count alone (down)
    # is ambiguous — a cluster could just as well have dropped below `min_entities`/`min_families` and
    # disappeared — so both conditions are required.
    clusters_merged = cluster_count_after < cluster_count_before and entities_after > entities_before

    # Episodes have no persistent id across runs (session-gap bucketing recomputed on the whole
    # accumulated timeline each time), so "new" is judged by start_ts: a bucket boundary that did not
    # exist before. This is a heuristic, not an identity check — new data can shift where nearby
    # episodes start, in which case an unchanged episode may still count as "new" here. Acceptable
    # for a headline count; not a substitute for reading the episodes table itself.
    episode_starts_before = {r.get("start_ts") for r in _rows(before, "episodes")}
    new_episodes = sum(1 for r in _rows(after, "episodes")
                       if r.get("start_ts") not in episode_starts_before)

    return {
        "first_analysis": first_analysis,
        "new_events": new_events,
        "new_sources": new_sources,
        "new_bridges": new_bridges,
        "strengthened_bridges": strengthened_bridges,
        "new_techniques": new_techniques,
        "kc_depth_before": kc_depth_before,
        "kc_depth_after": kc_depth_after,
        "deepest_phase_before": deepest_phase_before,
        "deepest_phase_after": deepest_phase_after,
        "cluster_count_before": cluster_count_before,
        "cluster_count_after": cluster_count_after,
        "clusters_merged": clusters_merged,
        "new_episodes": new_episodes,
        # Deliberately only the list-valued fields above: new_events/new_episodes are already
        # visible on their own, and kc_depth/cluster_count are "before vs after" pairs, not "how many
        # new things" — folding either into this count would make it answer two different questions.
        "total_new": len(new_sources) + len(new_bridges) + len(strengthened_bridges) + len(new_techniques),
    }


def delta_headline(d: dict) -> str:
    """One plain-English sentence for a re-analysis banner. Never empty: "nothing changed" is said
    plainly rather than returned as silence, because a banner that goes blank when there is nothing
    to report is indistinguishable from a banner that failed to render."""
    parts: list[str] = []

    nb, sb = len(d.get("new_bridges") or []), len(d.get("strengthened_bridges") or [])
    if nb and sb:
        parts.append(f"{nb} new bridge{'s' if nb != 1 else ''} ({sb} strengthened)")
    elif nb:
        parts.append(f"{nb} new bridge{'s' if nb != 1 else ''}")
    elif sb:
        parts.append(f"{sb} strengthened bridge{'s' if sb != 1 else ''}")

    nt = len(d.get("new_techniques") or [])
    if nt:
        parts.append(f"{nt} new technique{'s' if nt != 1 else ''}")

    ns = d.get("new_sources") or []
    if ns:
        parts.append(f"{len(ns)} new source{'s' if len(ns) != 1 else ''} ({', '.join(ns)})")

    if d.get("kc_depth_after", 0) > d.get("kc_depth_before", 0) and d.get("deepest_phase_after"):
        parts.append(f"kill chain now reaches {d['deepest_phase_after']}")

    if d.get("clusters_merged"):
        parts.append("separate clusters merged into one")

    ne = d.get("new_episodes") or 0
    if ne:
        parts.append(f"{ne} new episode{'s' if ne != 1 else ''}")

    prefix = "First analysis: " if d.get("first_analysis") else ""
    if not parts:
        return prefix + ("nothing to correlate yet." if d.get("first_analysis")
                         else "no changes since the previous analysis.")
    return prefix + ", ".join(parts) + "."
