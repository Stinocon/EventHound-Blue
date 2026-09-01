"""RAG retrieval from Qdrant: hybrid (dense ⊕ sparse BM25, RRF fusion) + cross-encoder
reranking + per-source diversification. Core shared by the CLI and the MCP tool.

The dense side (e5-large) captures meaning; the sparse side (BM25) the exact terms — CVE IDs,
techniques `T1003.001`, malware/exploit names, FQL/CQL syntax. The cross-encoder reorders the
fused candidates by looking at query and text together. It's a LOCAL operation: no scraping.

CLI:
  uv run python -m pipeline.retrieve "kerberoasting" --collection knowledge_cyber
  uv run python -m pipeline.retrieve "T1003.001 LSASS" --no-hybrid     # dense only, for comparison
  uv run python -m pipeline.retrieve "lateral movement T1021" --collection knowledge_cyber --format json
"""
from __future__ import annotations

import argparse
from datetime import datetime

from qdrant_client.models import (FieldCondition, Filter, Fusion, FusionQuery,
                                  MatchValue, Prefetch, SparseVector)

from .config import (DENSE_VECTOR, RECENCY_YEAR_FLOOR, RERANK_MODEL,
                     RERANK_POOL_MIN, RERANK_POOL_RATIO, RERANK_RECENCY_WEIGHT,
                     RERANK_RELIABILITY_WEIGHT, SEARCH_POOL_MIN, SEARCH_POOL_RATIO,
                     SPARSE_VECTOR, TIME_SENSITIVE_CATEGORIES, load_env)
from .embedder import Embedder, SparseEmbedder, guard_memory
from .qdrant_store import QdrantStore

_dense: Embedder | None = None
_sparse: SparseEmbedder | None = None
_reranker = None
_store: QdrantStore | None = None


def _get_dense() -> Embedder:
    global _dense
    if _dense is None:
        # No guard call here: `Embedder` guards its own constructor (embedder.guard_memory), which
        # is what makes evaluate and ingest — the heaviest load of the three — covered too. Asking
        # twice on this path would only produce two readings of one machine.
        _dense = Embedder()
    return _dense


def _get_sparse() -> SparseEmbedder:
    global _sparse
    if _sparse is None:
        # NOT guarded: `SparseEmbedder.__init__` allocates nothing (embedder.py builds lazily in
        # `_build`, from `embed_query`). A guard here refused "the RAG sparse model" — a BM25 index
        # of a few megabytes — using arithmetic driven by the model the previous guard had just
        # admitted, which told the operator the wrong thing about the wrong component.
        _sparse = SparseEmbedder()
    return _sparse


def _get_reranker():
    global _reranker
    if _reranker is None:
        # The reranker is built here rather than in embedder.py, so it carries the guard itself.
        guard_memory("the RAG reranking model")
        # fastembed 0.8: the cross-encoder lives in a submodule.
        from fastembed.rerank.cross_encoder import TextCrossEncoder

        from .embedder import _cache_kwargs
        _reranker = TextCrossEncoder(model_name=RERANK_MODEL, **_cache_kwargs())
    return _reranker


def _get_store() -> QdrantStore:
    global _store
    if _store is None:
        _store = QdrantStore()
    return _store


def _rank_boost(pl: dict, current_year: int) -> float:
    """Additive boost (>=0) for the POST-rerank re-score: reliability + recency.

    Must be added to the relevance score NORMALIZED in [0,1] (small weights: tie-breaker, not
    override). Reliability from the `level` field: level 1 -> full weight, level 2 -> half,
    level 3 -> 0; unknown/malformed level -> treated as 2 (center: neither rewarded nor
    penalized). Recency: ONLY for time-sensitive categories, a linear fraction between
    RECENCY_YEAR_FLOOR (0) and the current year (full), clamped; missing/non-integer year ->
    no boost.

    NOTE: in the current cyber corpus the payloads don't carry `category`/`year`, so the
    recency half stays inert (no boost); the reliability half on `level` is active. Pure
    function, tested offline (test_rank_boost.py)."""
    lvl = pl.get("level")
    if not (isinstance(lvl, int) and not isinstance(lvl, bool) and lvl in (1, 2, 3)):
        lvl = 2
    boost = RERANK_RELIABILITY_WEIGHT * (3 - lvl) / 2.0
    if pl.get("category") in TIME_SENSITIVE_CATEGORIES:
        y = pl.get("year")
        if isinstance(y, int) and not isinstance(y, bool):
            frac = (y - RECENCY_YEAR_FLOOR) / max(1, current_year - RECENCY_YEAR_FLOOR)
            boost += RERANK_RECENCY_WEIGHT * min(1.0, max(0.0, frac))
    return boost


def collection_missing(collection: str, store: QdrantStore | None = None) -> bool:
    """Does this collection not exist? Public because "no hits" and "never indexed" are the same
    empty list out of `search`, and telling them apart is the caller's only way to say which.

    `search` returns [] for both by design — every caller already handles "nothing found" — but an
    operator whose reindex died between the delete and the ingest then gets silence from every
    query instead of an error, for as long as it takes someone to notice. Cheap to ask, and only
    asked when the answer was empty."""
    try:
        return not (store or _get_store()).client.collection_exists(collection)
    except Exception:
        return False   # Qdrant unreachable is a different failure, and the caller already reports it


def _filter(level=None, product=None, framework=None) -> Filter | None:
    conds = []
    if level is not None:
        if level not in (1, 2, 3):
            raise ValueError(f"Invalid reliability level: {level!r} (expected 1, 2 or 3).")
        conds.append(FieldCondition(key="level", match=MatchValue(value=level)))
    if product:
        conds.append(FieldCondition(key="product", match=MatchValue(value=product)))
    if framework:
        conds.append(FieldCondition(key="framework", match=MatchValue(value=framework)))
    return Filter(must=conds) if conds else None


def search(query: str, collection: str = "knowledge_cyber", k: int = 5,
           level: int | None = None, product: str | None = None, framework: str | None = None,
           rerank: bool = True, per_source: int = 2, pool: int | None = None,
           hybrid: bool = True, store: QdrantStore | None = None,
           authority_bias: bool = True):
    """Three-stage retrieval on a collection. Returns the Qdrant points (with payload).

    On legacy single-vector collections (pre-rebuild) it automatically degrades to
    plain dense retrieval, so the code also works before the hybrid reindex."""
    if k <= 0:
        return []
    per_source = max(1, per_source)  # 0 would empty the per-source dedup
    flt = _filter(level, product, framework)  # always validates the input (e.g. level) before hitting the network
    store = store or _get_store()
    client = store.client
    # non-existent collection: returns [] instead of propagating a 404 (the caller
    # already handles the "no results" case as an empty/non-existent collection).
    if not client.collection_exists(collection):
        return []
    pool = pool or max(k * SEARCH_POOL_RATIO, SEARCH_POOL_MIN)
    is_hybrid = store.is_hybrid(collection)

    qv = _get_dense().embed([query], input_type="query")[0]

    if is_hybrid and hybrid:
        idx, val = _get_sparse().embed_query(query)
        cands = client.query_points(
            collection_name=collection,
            prefetch=[
                Prefetch(query=qv, using=DENSE_VECTOR, limit=pool, filter=flt),
                Prefetch(query=SparseVector(indices=idx, values=val),
                         using=SPARSE_VECTOR, limit=pool, filter=flt),
            ],
            query=FusionQuery(fusion=Fusion.RRF), limit=pool, with_payload=True,
        ).points
    elif is_hybrid:
        cands = client.query_points(collection_name=collection, query=qv, using=DENSE_VECTOR,
                                    limit=pool, query_filter=flt, with_payload=True).points
    else:
        # legacy: single unnamed vector
        cands = client.query_points(collection_name=collection, query=qv,
                                    limit=pool, query_filter=flt, with_payload=True).points

    if rerank and cands:
        # the reranked pool must cover enough candidates that per-source dedup can fill the
        # top-k with just the reranked ones (includes k*per_source); the tail stays in RRF
        # order with its score zeroed out (honest output: "not reranked").
        rerank_pool = min(len(cands), max(RERANK_POOL_MIN, k * RERANK_POOL_RATIO, k * per_source))
        head, tail = cands[:rerank_pool], cands[rerank_pool:]
        scores = list(_get_reranker().rerank(query, [(p.payload or {}).get("text") or "" for p in head]))
        for i, p in enumerate(head):
            p.score = float(scores[i])  # RAW cross-encoder relevance: only the ORDER uses the boost
        if authority_bias and len(head) > 1:
            # re-score: normalized [0,1] relevance + (small) reliability/recency boost.
            # p.score stays the raw relevance (honest output); the boost only moves the ordering,
            # and only among candidates of near-equal relevance (tie-breaker, see config).
            lo, hi = float(min(scores)), float(max(scores))
            span = hi - lo
            cur_year = datetime.now().year

            def _key(i: int) -> float:
                norm = (float(scores[i]) - lo) / span if span > 0 else 0.0
                return norm + _rank_boost(head[i].payload or {}, cur_year)
            order = sorted(range(len(head)), key=_key, reverse=True)
        else:
            order = sorted(range(len(head)), key=lambda i: float(scores[i]), reverse=True)
        head_sorted = [head[i] for i in order]
        for p in tail:
            p.score = None
        cands = head_sorted + tail

    # diversification: at most `per_source` chunks per source, preserving order
    out, used = [], {}
    for p in cands:
        sid = (p.payload or {}).get("source_id")
        n = used.get(sid, 0)
        if n >= per_source:
            continue
        used[sid] = n + 1
        out.append(p)
        if len(out) >= k:
            break
    return out


def _result_dict(p, rank: int) -> dict:
    pl = p.payload or {}
    score = getattr(p, "score", None)
    return {
        "rank": rank,
        "score": round(score, 4) if score is not None else None,
        "source_id": pl.get("source_id"),
        "source_name": pl.get("source_name"),
        "level": pl.get("level"),
        "title": pl.get("document") or pl.get("source_name"),
        "url": pl.get("url"),
        "locator": pl.get("locator"),
        "text": (pl.get("text") or "").strip(),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Hybrid retrieval + rerank on a Qdrant collection.")
    ap.add_argument("query")
    ap.add_argument("--collection", default="knowledge_cyber")
    ap.add_argument("--k", "--top", type=int, default=5, dest="k")
    ap.add_argument("--level", type=int, help="reliability level filter (1/2/3)")
    ap.add_argument("--product", help="product filter (payload field `product`; no indexed source declares one today)")
    ap.add_argument("--framework", help="framework filter (e.g. mitre, nist)")
    ap.add_argument("--no-rerank", action="store_true", help="without cross-encoder reranking")
    ap.add_argument("--no-hybrid", action="store_true", help="dense only, without BM25 fusion")
    ap.add_argument("--no-authority-bias", action="store_true",
                    help="disable the reliability/recency post-rerank tie-breaker (relevance only)")
    ap.add_argument("--per-source", type=int, default=2, help="max chunks per source in the top-k")
    ap.add_argument("--format", choices=["text", "json"], default="text", dest="fmt")
    args = ap.parse_args()

    load_env()
    store = _get_store()
    res = search(args.query, collection=args.collection, k=args.k, level=args.level,
                 product=args.product, framework=args.framework,
                 rerank=not args.no_rerank, per_source=args.per_source, hybrid=not args.no_hybrid,
                 store=store, authority_bias=not args.no_authority_bias)

    if args.fmt == "json":
        import json
        print(json.dumps([_result_dict(p, i) for i, p in enumerate(res, 1)], ensure_ascii=False))
        return

    # honest label: reflects the REAL path taken (a legacy collection degrades to dense)
    really_hybrid = (not args.no_hybrid) and store.is_hybrid(args.collection)
    mode = ("hybrid" if really_hybrid else "dense") + ("" if args.no_rerank else "+rerank")
    print(f"Query: {args.query!r}  (collection {args.collection}, top {args.k}, {mode})\n")
    if not res:
        print("No results (empty or non-existent collection?).")
        return
    for i, p in enumerate(res, 1):
        pl = p.payload or {}
        score = getattr(p, "score", None)
        score_s = f"{score:.3f}" if score is not None else "  —  "
        print(f"[{i}] {score_s}  {pl.get('source_name', '?')} (lvl.{pl.get('level')}) — {pl.get('locator', '')}")
        snippet = (pl.get("text") or "").replace("\n", " ")
        print(f"    {snippet[:240]}...\n")


if __name__ == "__main__":
    main()
