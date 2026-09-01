#!/usr/bin/env bash
# HYBRID rebuild of the RAG (dense e5-large 1024 ⊕ sparse BM25, RRF + reranking).
# The collections move to NAMED VECTORS (dense+bm25): they must be rebuilt (delete + re-ingest).
#
# This script rebuilds ONLY the LOCAL-source collections — entirely OFFLINE, no scraping (§15):
# normative, acn. Idempotent.
#
# knowledge_cyber is NOT here: see the "knowledge_cyber" section at the bottom. It is a special
# case — it starts from STIX (local, offline) but the NIST/SANS/ISC2 sources need a re-crawl
# (VPN §15) and are gated on a user decision. See docs/roadmap.md and the memory
# rag-reindex-e5-pendente.
#
# Requires Qdrant up on :6343 — native (`./setup-macos.sh up`) or Docker (`docker compose up -d qdrant`).
set -euo pipefail
cd "$(dirname "$0")"

echo "== 1. Model probe (downloads e5-large ~2.2GB + BM25 if absent, one-off) =="
uv run python - <<'PY'
from pipeline.config import load_env
from pipeline.embedder import Embedder, SparseEmbedder
load_env()
e = Embedder()
print("dense:", e.model, "| backend:", e.backend, "| dim:", e.dim)
assert e.dim == 1024, f"unexpected dimension: {e.dim}"
s = SparseEmbedder()
idx, val = s.embed_query("probe T1003.001")
print("sparse:", s.model, "| terms in probe query:", len(idx))
PY

echo "== 2. Deleting the local collections (recreated hybrid by the ingest) =="
uv run python - <<'PY'
# Ask the memory guard AGAIN, immediately before destroying anything. Step 1 built the embedder in
# a process that has since exited, so its model is no longer resident and step 3 has to load it
# from scratch: between the two there was a window in which the collections were already gone and
# the ingest then refused, leaving the RAG empty — and a missing collection answers every query
# with "no results" rather than an error, so the failure would surface as silence days later.
from pipeline.embedder import guard_memory
guard_memory("the RAG embedding model")

from pipeline.qdrant_store import QdrantStore
s = QdrantStore()
for c in ["normative", "acn"]:
    if s.client.collection_exists(c):
        s.client.delete_collection(c)
        print("deleted", c)
PY

echo "== 3. Re-ingest of the local sources (re-chunk 400, dense+sparse) =="
for src in normative-pdf acn-pdf; do
  uv run python -m pipeline.ingest --source "$src" --no-eval
done

echo "== 4. Golden-query validation (only the collections that have them in golden_queries.yaml) =="
# Note: evaluate.py exits 1 when failed>0 (raise SystemExit(1)) and evaluates EVERY collection
# present in golden_queries.yaml. Today that is only knowledge_cyber:
# normative and acn — although rebuilt here — have NO golden queries, so they are
# NOT validated by this step (check by hand with a few targeted queries, §18). knowledge_cyber is
# evaluated but this script does NOT rebuild it (gated, re-embed pending): its FAIL/SKIP are
# expected and must NOT mask a successful local rebuild, so the outcome is recorded without aborting.
eval_rc=0
uv run python -m pipeline.evaluate || eval_rc=$?
if [ "$eval_rc" -ne 0 ]; then
  echo "== WARNING: evaluate reported failures/SKIP (rc=$eval_rc) =="
  echo "   Usually it is knowledge_cyber (not rebuilt here): check the FAIL lines above."
fi

echo "== DONE (local collections hybrid; evaluate rc=$eval_rc) =="

# ─────────────────────────────────────────────────────────────────────────────
# knowledge_cyber — NOT run by this script (gated). Procedure once decided:
#   1) MITRE, OFFLINE (no VPN), via the official STIX already in sources.yaml (mitre-attack-stix):
#        uv run python -c "from pipeline.qdrant_store import QdrantStore as Q; Q().client.delete_collection('knowledge_cyber')"
#        uv run python -m pipeline.ingest --source mitre-attack-stix --no-eval
#   2) NIST/SANS/ISC2 — RE-CRAWL of the site = scraping → VPN + confirmation (§15). First review the
#      patterns in sources.yaml (or replace NIST with the local SP800 PDFs). Then, ONE at a time
#      (--source is NOT repeatable: argparse would keep only the last value):
#        uv run python -m pipeline.ingest --source nist-csrc
#        uv run python -m pipeline.ingest --source sans
#        uv run python -m pipeline.ingest --source isc2
#   3) uv run python -m pipeline.evaluate  &&  re-commit rag/index_manifest.json
# Note: rebuilding knowledge_cyber from scratch DELETES the 3584 surviving chunks (partial) — expected.
# ─────────────────────────────────────────────────────────────────────────────
