"""Evaluation of RAG quality via golden queries.

Runs the validated queries in golden_queries.yaml against Qdrant and verifies that the
retrieved chunks contain the expected concepts (validated from a content and academic
cybersecurity standpoint). Useful for estimating the quality of what has been indexed and
for detecting coverage gaps.

Usable in two ways:
- from the CLI, on-demand:      uv run python -m pipeline.evaluate [--verbose] [--top N]
- automatically after ingest: `pipeline.ingest` calls these functions on the
  collections just updated (see ingest.py), reusing the already-loaded embedder.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

from .config import RAG_DIR, load_env
from .embedder import Embedder
from .qdrant_store import QdrantStore


def load_queries(path: str | None = None) -> tuple[list[dict], dict]:
    p = Path(path) if path else RAG_DIR / "golden_queries.yaml"
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return data.get("queries", []), data.get("defaults", {})


def _keyword_check(texts: list[str], keywords: list[str], mode: str) -> tuple[bool, list[str]]:
    blob = "\n".join(texts).lower()
    # Word-boundary match, not a raw substring: avoids incidental PASS results where a short
    # token matches inside an unrelated word (e.g. "contain" in "container", "risk" in "asterisk",
    # "api" in "rapidly"), which would weaken the gate in "any" mode.
    def _hit(k: str) -> bool:
        return re.search(r"(?<![0-9a-z])" + re.escape(k.lower()) + r"(?![0-9a-z])", blob) is not None
    found = [k for k in keywords if _hit(k)]
    ok = (len(found) == len(keywords)) if mode == "all" else bool(found)
    return ok, found


def _first_relevant_rank(texts: list[str], keywords: list[str], mode: str) -> int:
    """1-based rank of the FIRST single chunk that satisfies the expected terms (0 if none).

    Used for the ranking metrics (hit@1/hit@3/MRR): unlike the PASS/FAIL gate — which
    evaluates the terms on the CONCATENATION of the top-k — here relevance is per-chunk, so
    a retrieval that puts the right chunk first is worth more than one that puts it last."""
    for i, t in enumerate(texts, 1):
        ok, _ = _keyword_check([t], keywords, mode)
        if ok:
            return i
    return 0


def evaluate_queries(queries, defaults, embedder, store,
                     collections: set[str] | None = None,
                     top_k: int | None = None, verbose: bool = False) -> dict:
    """Runs the queries along the REAL retrieval path (hybrid dense⊕BM25 + rerank,
    see retrieve.search) and returns the outcome. If `collections` is given, only evaluates
    the queries whose collection is in that set. Reuses `embedder` (dense) and `store` passed
    by the caller by injecting them into retrieve, so the heavy model isn't reloaded.

    Gate: the presence of the expected TERMS in the retrieved chunks (content signal). The
    score is no longer gated as a cosine threshold: with RRF fusion and the cross-encoder it's
    on a different scale and should be read as informative (see the note on min_score in
    golden_queries.yaml)."""
    from . import retrieve  # local import: the reranker is lazy, only queries load it
    retrieve._dense = embedder  # reuse the dense model already loaded by the caller

    top_k = top_k or defaults.get("top_k", 5)
    existing = {c.name for c in store.client.get_collections().collections}

    passed = failed = skipped = 0
    hit1 = hit3 = 0          # how many queries have a relevant chunk at rank 1 / within rank 3
    rr_sum = 0.0             # sum of reciprocal ranks (for MRR)
    rows = []

    for q in queries:
        coll = q["collection"]
        if collections is not None and coll not in collections:
            continue  # out of scope for this run
        qid = q["id"]

        if coll not in existing:
            skipped += 1
            rows.append((qid, "SKIP", coll, 0.0, "collection missing"))
            continue

        hits = retrieve.search(q["query"], collection=coll, k=top_k, store=store)
        texts = [(h.payload or {}).get("text", "") for h in hits]
        top_score = next((h.score for h in hits if getattr(h, "score", None) is not None), 0.0)

        mode = "all" if q.get("expect_all") else "any"
        keywords = q.get("expect_all") or q.get("expect_any") or []
        kw_ok, found = _keyword_check(texts, keywords, mode)

        result = "PASS" if kw_ok else "FAIL"
        if result == "PASS":
            passed += 1
        else:
            failed += 1

        # ranking metrics (informative, not gating): rank of the first relevant chunk
        rank = _first_relevant_rank(texts, keywords, mode)
        if rank == 1:
            hit1 += 1
        if 1 <= rank <= 3:
            hit3 += 1
        if rank:
            rr_sum += 1.0 / rank

        detail = f"ok: {found}" if kw_ok else f"missing expected terms ({mode}): {keywords}"
        rows.append((qid, result, coll, top_score or 0.0, detail))

        if verbose and result != "PASS":
            for h in hits[:3]:
                pl = h.payload or {}
                snippet = (pl.get("text") or "").replace("\n", " ")[:140]
                sc = getattr(h, "score", None)
                print(f"    [{sc:.3f}] {pl.get('source_name', '?')} :: {snippet}" if sc is not None
                      else f"    [  —  ] {pl.get('source_name', '?')} :: {snippet}")

    return {"passed": passed, "failed": failed, "skipped": skipped, "rows": rows,
            "hit1": hit1, "hit3": hit3, "rr_sum": rr_sum}


def print_report(result: dict, title: str = "Golden-queries evaluation") -> None:
    rows = result["rows"]
    print(f"\n{title}")
    print(f"{'ID':34s} {'RESULT':6s} {'COLLECTION':16s} {'SCORE':6s} DETAIL")
    print("-" * 100)
    for qid, res, coll, score, detail in rows:
        print(f"{qid:34s} {res:6s} {coll:16s} {score:6.3f} {detail}")
    evaluated = result["passed"] + result["failed"]
    pct = (result["passed"] / evaluated * 100) if evaluated else 0.0
    print("-" * 100)
    print(f"PASS {result['passed']}/{evaluated} ({pct:.0f}%)  —  SKIP {result['skipped']} (collections not yet indexed)")
    if evaluated:
        # ranking metrics (informative): how high the first relevant chunk ranks.
        hit1 = result.get("hit1", 0) / evaluated * 100
        hit3 = result.get("hit3", 0) / evaluated * 100
        mrr = result.get("rr_sum", 0.0) / evaluated
        print(f"Ranking: hit@1 {hit1:.0f}%  ·  hit@3 {hit3:.0f}%  ·  MRR {mrr:.3f}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Golden-queries evaluation of the RAG.")
    ap.add_argument("--queries", help="Alternative path for golden_queries.yaml")
    ap.add_argument("--top", type=int, help="Number of results to retrieve (default from file)")
    ap.add_argument("--verbose", action="store_true", help="For FAILs, show the first retrieved results")
    args = ap.parse_args()

    load_env()
    queries, defaults = load_queries(args.queries)
    embedder = Embedder()
    store = QdrantStore()
    result = evaluate_queries(queries, defaults, embedder, store, top_k=args.top, verbose=args.verbose)
    print_report(result)
    if result["failed"] > 0:
        raise SystemExit(1)
    # No query evaluated (all SKIP because collections are missing) = a gate that validated
    # nothing: fail instead of giving a misleading green light (see golden_queries.yaml).
    if (result["passed"] + result["failed"]) == 0:
        print("ERROR: no golden query evaluated (collections missing). The gate validated nothing.")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
