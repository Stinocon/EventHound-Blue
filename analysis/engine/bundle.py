"""Analysis bundle — a versioned, re-importable snapshot of an analyze() result.

WHY: an analysis could be exported (HTML/Markdown/JSON report) but never loaded back, so reopening
a case meant re-running Hayabusa/tshark/EvtxECmd over evidence that may no longer be at hand. A
bundle is the analyze() output plus the provenance needed to read it later — nothing more:

    {"bundle_version": 1, "created_at": "…Z", "tool_version": "0.19.0",
     "meta": {…},          # _meta of the run (source counts, errors, name)
     "analysis": {…}}      # the full analyze() dict, verbatim

It is a *snapshot*, not an archive: the evidence files are NOT included (they are client data, and
re-uploading them would defeat the point). Reports are re-rendered from it offline
(`run_report.py --from-bundle`), and the GUI re-imports it client-side.

PRIVACY (§9/§10): a bundle carries the same real identifiers as the report it renders. Save under
analysis/reports/ (gitignored) or data/, anonymize before sharing, never commit.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from engine.version import APP_VERSION

BUNDLE_VERSION = 1


def build(analysis: dict, name: str = "analysis", meta: dict | None = None) -> dict:
    """Wrap an analyze() result into a bundle. `meta` defaults to the result's own `_meta`."""
    meta = dict(meta if meta is not None else (analysis.get("_meta") or {}))
    meta.setdefault("name", name)
    return {
        "bundle_version": BUNDLE_VERSION,
        "created_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool_version": APP_VERSION,
        "meta": meta,
        "analysis": analysis,
    }


def dumps(bundle: dict) -> str:
    """Serialize a bundle. `default=str` mirrors report_json: datetimes must not break the export."""
    return json.dumps(bundle, indent=2, default=str, ensure_ascii=False)


def load(path: str | Path) -> dict:
    """Read and validate a bundle file. Raises ValueError on anything that isn't one.

    Also accepts a bare analyze() JSON (as produced by `report --format json --level full`): it is
    wrapped on the fly, so an already-exported report doesn't become a dead end.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"not a readable JSON file ({type(exc).__name__})") from exc
    return loads(data)


def loads(data: object) -> dict:
    """Same validation as load(), on already-parsed JSON."""
    if not isinstance(data, dict):
        raise ValueError("not a bundle: top level is not an object")
    if "bundle_version" not in data:
        # A bare analyze() dump: it always has `summary`. Wrap it rather than refusing.
        if "summary" in data:
            return build(data, name=(data.get("_meta") or {}).get("name", "analysis"))
        raise ValueError("not a bundle and not an analysis export (no bundle_version, no summary)")
    ver = data.get("bundle_version")
    if ver != BUNDLE_VERSION:
        raise ValueError(f"unsupported bundle_version {ver!r} (this build reads {BUNDLE_VERSION})")
    if not isinstance(data.get("analysis"), dict):
        raise ValueError("malformed bundle: 'analysis' missing or not an object")
    return data


def analysis_of(bundle: dict) -> dict:
    """The analyze() dict inside a bundle, with `_meta` restored from the bundle's own metadata."""
    analysis = bundle["analysis"]
    if not analysis.get("_meta") and bundle.get("meta"):
        analysis = {**analysis, "_meta": bundle["meta"]}
    return analysis
