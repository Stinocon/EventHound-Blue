from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path

import yaml
from dotenv import load_dotenv

# rag/ — the root of the stack (pipeline/ lives inside rag/)
RAG_DIR = Path(__file__).resolve().parent.parent

# PDF parser: 'legacy' (default: pypdf -> text cleanup, with optional OCR fallback for
# scanned documents) or 'docling' (layout-aware, tables structured as markdown grids; useful
# for EUR-Lex/regulation tables and CVEs). From env CY_PDF_PARSER. See sources/pdf_docling.py.
PDF_PARSER = os.getenv("CY_PDF_PARSER", "legacy").strip().lower()

# ── Hybrid retrieval (dense ⊕ sparse) + reranking ──────────────────────────────
# The stack stays fastembed-only (no API, no extra heavy dependency).
#   - dense: the Embedder model (default e5-large, 1024 dim) — "dense" vector
#   - sparse: lexical BM25 via fastembed — "bm25" vector; captures the EXACT terms
#     that semantics confuses (CVE IDs, techniques T1003.001, malware names, FQL/CQL syntax)
#   - rerank: fastembed cross-encoder (multilingual IT+EN) that reorders the fused candidates
SPARSE_MODEL = os.getenv("RAG_SPARSE_MODEL", "Qdrant/bm25")
RERANK_MODEL = os.getenv("RAG_RERANK_MODEL", "jinaai/jina-reranker-v2-base-multilingual")

# Names of the named vectors in the hybrid collections (Qdrant requires named vectors
# when a point has more than one). The legacy single-vector collections are NOT
# compatible: they need to be rebuilt (reindex.sh).
DENSE_VECTOR = "dense"
SPARSE_VECTOR = "bm25"

# Retrieval parameters (retrieve.search), kept here for traceability instead of being
# buried in literals. candidate pool for the RRF fusion = max(k*SEARCH_POOL_RATIO, SEARCH_POOL_MIN);
# the cross-encoder reranks min(retrieved_pool, max(RERANK_POOL_MIN, k*RERANK_POOL_RATIO,
# k*per_source)) candidates. For small k the retrieval pool dominates (at default k=5 the pool
# is 30, so RERANK_POOL_MIN=60 stays inert and the 30 retrieved are reranked); the floor of
# 60 kicks in from k>=10. Aligned with PersonalFinance (conoscenza/ingest/config.py).
SEARCH_POOL_RATIO = 6
SEARCH_POOL_MIN = 30
RERANK_POOL_MIN = 60
RERANK_POOL_RATIO = 3

# ── Authority/recency tie-breaker post-rerank (retrieve._rank_boost) ─────────
# Small ADDITIVE boost on the relevance score normalized in [0,1]: at equal cross-encoder
# relevance, it favors the most reliable sources (`level` field: 1 > 2 > 3) and — only for
# time-sensitive content — the most recent ones. Small weights: they are a TIE-BREAKER, never
# an override (a highly relevant level-3 source stays above a barely relevant level-1 one).
# Can be disabled at runtime with --no-authority-bias / authority_bias=False. Aligned with
# PersonalFinance.
RERANK_RELIABILITY_WEIGHT = 0.06
RERANK_RECENCY_WEIGHT = 0.04
# Base year for the linear recency fraction (below this year: recency = 0).
RECENCY_YEAR_FLOOR = 2015
# Categories whose content ages (CVEs, advisories, evolving regulations): only here does
# recency enter the boost, by comparing payload['category'].
# NOTE: the payloads of the current cyber corpus do NOT carry `category`/`year`, so the recency
# half stays INERT — it's wired for parity with PF and for the test, but produces no boost until
# ingest adds those fields. The reliability half (`level`) is active from the start.
TIME_SENSITIVE_CATEGORIES = {"normative", "cve", "advisory"}


def load_env() -> None:
    """Loads rag/.env if present (QDRANT_URL, EMBEDDING_*, ...)."""
    load_dotenv(RAG_DIR / ".env")


def _deep_merge(base: dict, override: dict) -> dict:
    out = deepcopy(base or {})
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = deepcopy(value)
    return out


def load_config(path: str | None = None) -> dict:
    """Reads sources.yaml and merges the defaults into each source."""
    cfg_path = Path(path) if path else RAG_DIR / "sources.yaml"
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    defaults = data.get("defaults", {})

    sources = []
    for src in data.get("sources", []):
        merged = dict(src)
        for section in ("chunk", "embedding", "crawler"):
            merged[section] = _deep_merge(defaults.get(section, {}), src.get(section, {}))
        sources.append(merged)

    return {
        "defaults": defaults,
        "sources": sources,
        "collections": data.get("collections", {}),
    }


def enabled_sources(cfg: dict, only: str | None = None):
    """Iterates the sources with enabled=true, optionally filtering by id."""
    for src in cfg["sources"]:
        if not src.get("enabled"):
            continue
        if only and src.get("id") != only:
            continue
        yield src
