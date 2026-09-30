"""Unified analysis API — one FastAPI surface over the v2 sensor plugins.

POST /analyze              — upload artifacts, get common-schema records.
POST /correlate            — upload artifacts, get the full findings bundle
                             (recipes + correlation over the same engine).
GET  /cases                — list persisted cases.
POST /cases                — create a case.
GET  /cases/{id}           — case metadata.
POST /cases/{id}/add       — upload artifacts into the case.
POST /cases/{id}/analyze   — run the full analytics over the case.
GET  /health               — liveness probe.

Privacy invariants, inherited from the GUI (§9/§10): the server binds to
127.0.0.1 only, uploaded files are written to a temporary directory and
deleted right after the analysis, and the JSON response carries real client
identifiers — localhost only, never expose it further.

Run with the GUI environment (it owns FastAPI and duckdb)::

    cd analysis/gui && uv run python ../../api/server.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

from fastapi import Form

# Bootstrap: make core/ importable when this module runs from the GUI env
# (the repo root is two levels up from this file).
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, File, HTTPException, UploadFile  # noqa: E402

from core.sensors import REGISTRY, sensor_for  # noqa: E402

app = FastAPI(title="EventHound v2 API", version="2.0.0")


def _ingest_upload(
    upload: UploadFile, dest_dir: Path, sensor_name: str | None = None
) -> list[dict]:
    """Persist one upload, ingest it through the matching sensor, return records.

    The sensor is picked from the artifact extension unless ``sensor_name``
    overrides it (a CrowdStrike clipboard ``.txt`` is not a THOR report).
    """
    dest = dest_dir / (upload.filename or "artifact")
    if not dest.resolve().parent == dest_dir.resolve():
        raise HTTPException(400, f"unsafe filename: {upload.filename}")
    with dest.open("wb") as out:
        shutil.copyfileobj(upload.file, out)
    try:
        return sensor_for(dest, override=sensor_name).ingest(dest)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(422, str(exc)) from exc
    except NotADirectoryError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface engine errors as 502
        raise HTTPException(502, f"analysis failed: {exc}") from exc


def _records_from_uploads(
    artifact: list[UploadFile], dest_dir: Path, sensor_name: str | None = None
) -> list[dict]:
    """Shared ingest road: persist uploads, run sensors, return records."""
    all_records: list[dict] = []
    for upload in artifact:
        all_records.extend(_ingest_upload(upload, dest_dir, sensor_name=sensor_name))
    return all_records


@app.post("/analyze")
async def analyze(
    artifact: list[UploadFile] = File(..., description="artifact(s) to analyze"),
    sensor: str = Form(
        default="",
        description="optional: route every artifact to this sensor (crowdstrike, yara, ...)",
    ),
) -> dict:
    """Analyze uploaded artifacts and return common-schema records.

    Each artifact is routed to its sensor by extension (``.evtx``/``.jsonl``
    → evtx, ``.pcap`` → pcap, ``.reg`` → registry, ``.log`` → logs, ``.txt``
    → thor) unless the ``sensor`` field overrides the guess. Uploaded files
    are deleted after the analysis (§9/§10).
    """
    all_records: list[dict] = []
    per_artifact: dict[str, int] = {}
    with tempfile.TemporaryDirectory(prefix="eh2-api-") as tmp:
        tmp_dir = Path(tmp)
        for upload in artifact:
            records = _ingest_upload(upload, tmp_dir, sensor_name=sensor or None)
            per_artifact[upload.filename or "artifact"] = len(records)
            all_records.extend(records)
    return {
        "count": len(all_records),
        "per_artifact": per_artifact,
        "records": all_records,
    }


@app.post("/correlate")
async def correlate(
    artifact: list[UploadFile] = File(..., description="artifact(s) to correlate"),
    infra_ips: str = Form(
        default="", description="comma-separated infrastructure IPs to exclude from bridging"
    ),
    sensor: str = Form(
        default="", description="optional: route every artifact to this sensor"
    ),
) -> dict:
    """Ingest artifacts and run the full analytics: recipes, timeline, episodes,
    kill chain, technique catalogue, clusters — the same bundle the v1
    engine produces, over the same in-memory DuckDB (nothing is persisted)."""
    from analytics import runner

    infra = [ip.strip() for ip in infra_ips.split(",") if ip.strip()]
    with tempfile.TemporaryDirectory(prefix="eh2-api-") as tmp:
        records = _records_from_uploads(artifact, Path(tmp), sensor_name=sensor or None)
    try:
        return runner.analyze(records, infra_ips=infra or None)
    except Exception as exc:  # noqa: BLE001 — surface engine errors as 502
        raise HTTPException(502, f"analysis failed: {exc}") from exc


# --- persisted cases ----------------------------------------------------------


def _case_or_404(case_id: str):
    from analytics import case_store

    if not case_store.exists(case_id):
        raise HTTPException(404, f"case not found: {case_id}")


@app.get("/cases")
async def cases() -> list[dict]:
    """List persisted cases (id + title + timestamps)."""
    from analytics import case_store

    return case_store.list_cases()


@app.post("/cases", status_code=201)
async def create_case(case_id: str = Form(...), title: str = Form(default="")) -> dict:
    """Create a persisted case. The id is the directory name under the
    (gitignored) case root, so it is validated, not trusted (§8)."""
    from analytics import case_store

    try:
        return case_store.create(case_id, title=title or None)
    except Exception as exc:  # noqa: BLE001 — CaseError (bad/duplicate id) is a 422
        raise HTTPException(422, str(exc)) from exc


@app.get("/cases/{case_id}")
async def case_meta(case_id: str) -> dict:
    """Case metadata: sources, record counts, version, notes presence."""
    from analytics import case_store

    _case_or_404(case_id)
    return case_store.load_meta(case_id)


@app.post("/cases/{case_id}/add")
async def case_add(
    case_id: str,
    artifact: list[UploadFile] = File(...),
    sensor: str = Form(
        default="", description="optional: route every artifact to this sensor"
    ),
) -> dict:
    """Upload artifacts into a case: each is ingested through its sensor and
    appended with its file name as the source label."""
    from analytics import case_store

    _case_or_404(case_id)
    added: dict[str, int] = {}
    with tempfile.TemporaryDirectory(prefix="eh2-case-") as tmp:
        tmp_dir = Path(tmp)
        for upload in artifact:
            records = _ingest_upload(upload, tmp_dir, sensor_name=sensor or None)
            case_store.append(case_id, records, label=upload.filename)
            added[upload.filename or "artifact"] = len(records)
    meta = case_store.load_meta(case_id)
    meta["added"] = added
    return meta


@app.post("/cases/{case_id}/analyze")
async def case_analyze(case_id: str) -> dict:
    """Run the full analytics over a persisted case (same bundle as
    /correlate, over the case's stored records — infrastructure IPs come
    from the case metadata)."""
    from analytics import runner

    _case_or_404(case_id)
    try:
        return runner.analyze_case(case_id)
    except Exception as exc:  # noqa: BLE001 — surface engine errors as 502
        raise HTTPException(502, f"analysis failed: {exc}") from exc


@app.get("/health")
async def health() -> dict:
    """Liveness probe: API up plus the sensor registry it serves."""
    return {"status": "ok", "version": "2.0.0", "sensors": sorted(REGISTRY)}


if __name__ == "__main__":  # pragma: no cover — manual run
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8700)
