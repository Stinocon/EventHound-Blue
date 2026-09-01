"""EventHound — RAG HTTP service.

Thin HTTP wrapper around `pipeline.retrieve`: exposes hybrid retrieval as a
service, so lightweight clients (the `analysis/` GUI, other tools) don't need to import
the RAG's ML stack in-process (torch, sentence-transformers, qdrant-client) — which lives
only in this venv/container. The models stay WARM in memory between one query and the next.

Local startup (from the RAG venv):
    cd rag && uv run uvicorn rag_api:app --host 127.0.0.1 --port 8600

In Docker: see the `rag-api` service in `docker-compose.yml`.

No retrieval logic here: it's all in `pipeline.retrieve` (SOT). This file is
just the HTTP transport + the model warm-up.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from pipeline import retrieve
from pipeline.config import load_env


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm-up: loads .env and opens the Qdrant connection once. The embedders and the
    # reranker are lazy in retrieve (_get_dense/_get_sparse/_get_reranker) and then stay
    # warm for all subsequent requests of this process.
    load_env()
    try:
        retrieve._get_store()  # connects to Qdrant; if it's down, /search reports it per-request
    except Exception:
        pass
    yield


app = FastAPI(title="EventHound — RAG API", docs_url=None, redoc_url=None, lifespan=lifespan)


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "rag-api"}


@app.post("/search")
def search(payload: dict) -> JSONResponse:
    """Hybrid retrieval on a collection.

    JSON body: {query, collection, k, level}. Contract identical to what the GUI
    used to expect from the in-process import, so the caller only changes the transport."""
    query = (payload.get("query") or "").strip()
    if not query:
        return JSONResponse({"results": []})
    collection = payload.get("collection") or "knowledge_cyber"
    k = int(payload.get("k", 5))
    level = payload.get("level")
    try:
        res = retrieve.search(query, collection=collection, k=k, level=level)
        if not res and retrieve.collection_missing(collection):
            # Not the same answer as "nothing matched", and the difference is the operator's only
            # clue that an ingest died halfway. Still a 200 with an empty list: the caller's
            # contract does not change, it just stops being told silence.
            return JSONResponse({"results": [],
                                 "note": f"collection '{collection}' is not indexed on this "
                                         f"instance — this is not 'no matches'. Run rag/reindex.sh."})
        return JSONResponse({"results": [retrieve._result_dict(p, i)
                                         for i, p in enumerate(res, 1)]})
    except Exception as e:  # Qdrant down, collection missing, etc.: honest error, not an opaque 500
        return JSONResponse({"error": f"RAG search failed ({type(e).__name__}: {e})",
                             "results": []}, status_code=503)
