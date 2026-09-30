"""Unified analysis API — one FastAPI surface over the v2 sensor plugins.

POST /analyze  — upload one or more artifacts, get common-schema records.
GET  /health   — liveness probe.

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

# Bootstrap: make core/ importable when this module runs from the GUI env
# (the repo root is two levels up from this file).
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, File, HTTPException, UploadFile  # noqa: E402

from core.sensors import REGISTRY, sensor_for  # noqa: E402

app = FastAPI(title="EventHound v2 API", version="2.0.0")


def _ingest_upload(upload: UploadFile, dest_dir: Path) -> list[dict]:
    """Persist one upload, ingest it through the matching sensor, return records.

    The sensor is picked from the artifact extension; an explicit ``sensor``
    form field (JSON body or multipart) overrides the guess.
    """
    dest = dest_dir / (upload.filename or "artifact")
    if not dest.resolve().parent == dest_dir.resolve():
        raise HTTPException(400, f"unsafe filename: {upload.filename}")
    with dest.open("wb") as out:
        shutil.copyfileobj(upload.file, out)
    try:
        return sensor_for(dest).ingest(dest)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(422, str(exc)) from exc
    except NotADirectoryError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface engine errors as 502
        raise HTTPException(502, f"analysis failed: {exc}") from exc


@app.post("/analyze")
async def analyze(
    artifact: list[UploadFile] = File(..., description="artifact(s) to analyze"),
) -> dict:
    """Analyze uploaded artifacts and return common-schema records.

    Each artifact is routed to its sensor by extension (``.evtx``/``.jsonl``
    → evtx, ``.pcap`` → pcap, ``.reg`` → registry, ``.log`` → logs, ``.txt``
    → thor). Uploaded files are deleted after the analysis (§9/§10).
    """
    all_records: list[dict] = []
    per_artifact: dict[str, int] = {}
    with tempfile.TemporaryDirectory(prefix="eh2-api-") as tmp:
        tmp_dir = Path(tmp)
        for upload in artifact:
            records = _ingest_upload(upload, tmp_dir)
            per_artifact[upload.filename or "artifact"] = len(records)
            all_records.extend(records)
    return {
        "count": len(all_records),
        "per_artifact": per_artifact,
        "records": all_records,
    }


@app.get("/health")
async def health() -> dict:
    """Liveness probe: API up plus the sensor registry it serves."""
    return {"status": "ok", "version": "2.0.0", "sensors": sorted(REGISTRY)}


if __name__ == "__main__":  # pragma: no cover — manual run
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8700)
