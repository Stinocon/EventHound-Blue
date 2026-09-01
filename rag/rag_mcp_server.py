"""MCP server (stdio) that exposes the local cybersecurity knowledge base (RAG) as a native tool.

Fully reuses the logic of `pipeline.retrieve.search` (hybrid dense⊕BM25 retrieval, RRF fusion,
cross-encoder reranking, per-source dedup). The heavy models (e5-large + reranker) are loaded
LAZILY by `retrieve`: the import of `pipeline.retrieve` is isolated inside the tool function, so
sessions that don't query the RAG don't pay the loading cost.

Startup: makes a best-effort attempt to ensure Qdrant is running (`docker compose up -d qdrant`,
port 6343) and to connect; if Docker/Qdrant aren't available it does NOT crash — it logs to
stderr and leaves it to the first `rag_search` call to return a readable error.

method/conventions.md §14: the RAG is the primary source. This tool is its idiomatic interface.
"""
import subprocess
import sys
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

RAG_DIR = Path(__file__).resolve().parent
QDRANT_URL = "http://localhost:6343"  # instance DEDICATED to the project (6333 is PersonalFinance's)

# Available collections (see sources.yaml). Default: the shared knowledge base.
COLLECTIONS = ("knowledge_cyber", "normative", "acn")

mcp = FastMCP("rag-cyber")


def _log(msg: str) -> None:
    print(f"[rag_mcp_server] {msg}", file=sys.stderr, flush=True)


def _ensure_qdrant_boot() -> None:
    """Best-effort at startup: starts Qdrant via docker compose and checks the connection.
    Never raises: every problem is logged to stderr and then handled by rag_search."""
    try:
        subprocess.run(
            ["docker", "compose", "up", "-d", "qdrant"],
            cwd=str(RAG_DIR), check=False, capture_output=True, timeout=60,
        )
    except Exception as e:  # docker missing, timeout, etc.
        # Don't abort: Qdrant might already be running externally (e.g. started manually
        # on 6343). Proceed anyway with the reachability probe.
        _log(f"starting Qdrant via docker failed ({type(e).__name__}: {e}); "
             "trying to connect anyway (it might already be running).")
    try:
        import os
        from qdrant_client import QdrantClient
        from pipeline.config import load_env
    except Exception as e:  # dependency missing/broken: don't abort the server
        _log(f"qdrant_client not importable ({type(e).__name__}: {e}); will retry on the first rag_search.")
        return
    # Same source of truth as QdrantStore (rag/.env → QDRANT_URL): the boot probe hits
    # exactly the endpoint that retrieve.search will actually connect to (§16, SOT).
    load_env()
    url = os.getenv("QDRANT_URL", QDRANT_URL)
    for i in range(1, 6):
        try:
            QdrantClient(url=url).get_collections()
            _log("Qdrant reachable.")
            return
        except Exception as e:
            if i < 5:
                _log(f"Qdrant not ready yet ({type(e).__name__}), attempt {i}/5; retrying in 2s.")
                time.sleep(2)
            else:
                _log(f"Qdrant unreachable after 5 attempts ({type(e).__name__}); "
                     "will retry on the first rag_search.")


@mcp.tool()
def rag_search(
    query: str,
    collection: str = "knowledge_cyber",
    k: int = 5,
    level: int | None = None,
) -> list[dict] | dict:
    """Queries the project's local cybersecurity knowledge base (RAG).

    It's a curated corpus with provenance and a reliability level (1 = authoritative/official
    vendor sources, 2 = reputable aggregators/papers, 3 = assistant notes to be validated).
    Hybrid retrieval: semantic (e5) + lexical (BM25, great for CVE IDs, techniques `T1003.001`,
    malware names, FQL/CQL syntax) with reranking. Use it as the PRIMARY LENS on technical/
    methodological/product/regulatory topics before relying on the model's own knowledge
    (method/conventions.md §14).

    Args:
        query: the question or terms to search for (IT or EN).
        collection: which corpus to query. Values: "knowledge_cyber" (frameworks: MITRE ATT&CK,
            NIST, SANS, ISC2 — default), "normative" (GDPR/NIS2), "acn" (Italian National
            Cybersecurity Agency).
        k: number of results (default 5).
        level: optional reliability-level filter (1, 2 or 3).

    Returns:
        List of results ordered by relevance, each with: source_id, source_name, level,
        title, url/locator, text (the retrieved chunk). On error (e.g. Qdrant not running)
        returns a single {"error": "..."} object with a readable message.

    Note: the "knowledge_cyber" collection currently has PARTIAL coverage (re-crawl pending):
    a poor result on frameworks may be a coverage gap, not the absence of the concept.
    """
    if collection not in COLLECTIONS:
        return {"error": f"Unknown collection: {collection!r}. Valid values: {list(COLLECTIONS)}."}
    try:
        # Isolated import: keeps the heavy models lazy (loaded by retrieve only on use).
        from pipeline.config import load_env
        from pipeline import retrieve
        load_env()
        points = retrieve.search(query, collection=collection, k=k, level=level)
        if not points and retrieve.collection_missing(collection):
            # "Never indexed" is not "nothing matched", and the caller is a model that will
            # otherwise report a coverage gap that does not exist (§6, §14).
            return {"error": f"Collection {collection!r} is not indexed on this instance — this "
                             f"is NOT an empty result set. Rebuild it with rag/reindex.sh."}
        # _result_dict is the canonical serializer for Qdrant points (lives in pipeline.retrieve).
        # It stays private in retrieve; if renamed, update it here too.
        return [retrieve._result_dict(p, i) for i, p in enumerate(points, 1)]
    except Exception as e:
        # The remedy has to match the failure. A memory refusal from `embedder.guard_memory` used
        # to be reported as "Is Qdrant running?", sending the analyst to restart a service that was
        # already up, over a message that had already said what to do.
        msg = str(e).rstrip(".")
        if "refusing to load" in msg:
            return {"error": f"RAG retrieval refused: {msg}."}
        return {"error": f"RAG retrieval failed ({type(e).__name__}): {msg}. "
                         "Is Qdrant running? start it with: cd rag && docker compose up -d qdrant"}


def main() -> None:
    _ensure_qdrant_boot()
    mcp.run()  # default stdio transport


if __name__ == "__main__":
    main()
