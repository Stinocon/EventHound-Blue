"""Pipeline orchestrator: sources.yaml -> acquisition -> chunk -> embed -> upsert into Qdrant.

Examples:
  python -m pipeline.ingest --dry-run                 # counts documents and chunks, doesn't write
  python -m pipeline.ingest --source acn-pdf
  python -m pipeline.ingest                           # all enabled sources
"""
from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone

from qdrant_client.models import PointStruct

from .chunker import chunk_text
from .config import enabled_sources, load_config, load_env
from .document import Document
from .embedder import Embedder, SparseEmbedder
from .evaluate import evaluate_queries, load_queries, print_report
from .manifest import Manifest
from .qdrant_store import QdrantStore, hybrid_vector
from .sources.pdf_source import load_pdfs
from .sources.stix_source import load_stix
from .sources.text_source import load_text_files
from .sources.web_source import load_web

# Fixed namespace for deterministic IDs (re-ingest = update, not duplication).
_NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00cf4fc964ff")

# State sidecar: records FAILED sources (reason, attempt count, date) so they aren't
# retried blindly and stay visible for reviewing the sources before a re-crawl.
# Sidecar (not sources.yaml, which is hand-curated with comments and yaml.dump would ruin it).
from .config import RAG_DIR  # noqa: E402  (grouped with the module constants)
_STATUS_PATH = RAG_DIR / "ingest_status.json"


def _record_failure(source_id: str, reason: str) -> None:
    data = {}
    if _STATUS_PATH.exists():
        try:
            data = json.loads(_STATUS_PATH.read_text(encoding="utf-8"))
        except Exception:
            # Corrupt sidecar: don't overwrite it blindly, or we'd lose the history of all
            # the other sources. Set it aside and start fresh, but visibly and recoverably,
            # consistently with _clear_failure (which doesn't write to a corrupt file).
            backup = _STATUS_PATH.with_suffix(".corrupt.json")
            try:
                _STATUS_PATH.replace(backup)
                print(f"[ingest] {_STATUS_PATH.name} corrupt: saved as {backup.name}, starting fresh")
            except Exception:
                print(f"[ingest] {_STATUS_PATH.name} corrupt and unrecoverable: starting fresh")
            data = {}
    prev = data.get(source_id, {})
    attempts = int(prev.get("attempts", 0)) + 1 if prev.get("status") == "failed" else 1
    data[source_id] = {
        "status": "failed",
        "fail_reason": reason[:200],
        "attempts": attempts,
        "last_attempt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    _STATUS_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _clear_failure(source_id: str) -> None:
    if not _STATUS_PATH.exists():
        return
    try:
        data = json.loads(_STATUS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return
    if source_id in data:
        data.pop(source_id, None)
        _STATUS_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_documents(source: dict) -> list[Document]:
    stype = source.get("type")
    if stype == "pdf":
        return load_pdfs(source)
    if stype in ("file", "markdown", "text"):
        return load_text_files(source)
    if stype == "stix":
        return load_stix(source)
    if stype == "web":
        return load_web(source)
    raise ValueError(f"Unhandled source type: {stype}")


def _base_payload(source: dict, doc: Document) -> dict:
    meta = source.get("metadata") or {}
    return {
        "source_id": source["id"],
        "source_name": meta.get("source_name", source["id"]),
        "product": source.get("product"),
        "framework": source.get("framework"),
        "level": source.get("level"),
        "tags": meta.get("tags", []),
        "locator": doc.locator,
        **doc.metadata,
    }


def build_points(source: dict, doc: Document, chunks: list[str],
                 dense: list[list[float]], sparse: list[tuple[list[int], list[float]]]) -> list[PointStruct]:
    base = _base_payload(source, doc)
    points = []
    for i, (text, dvec, svec) in enumerate(zip(chunks, dense, sparse)):
        pid = str(uuid.uuid5(_NAMESPACE, f"{source['id']}:{doc.locator}:{i}"))
        points.append(PointStruct(id=pid, vector=hybrid_vector(dvec, svec),
                                  payload={**base, "chunk_index": i, "text": text}))
    return points


def ingest_source(source, embedder, sparse_embedder, store, manifest, dry_run=False) -> None:
    print(f"==> [{source['id']}] type={source['type']} collection={source['collection']}")
    docs = load_documents(source)
    print(f"    documents: {len(docs)}")

    chunk_cfg = source.get("chunk", {})
    points: list[PointStruct] = []
    total_chunks = 0

    if not dry_run:
        store.ensure_collection(source["collection"], embedder.dim)
    upserted = 0
    # Chunks from several documents are accumulated and embedded/upserted in wide
    # windows: fastembed/e5-large performs much better with large batches than with N
    # calls of a few chunks each (the same batching the ingest path uses throughout).
    EMBED_BATCH = 256
    pending: list[tuple[Document, list[str]]] = []
    pending_chunks = 0

    def _flush() -> int:
        nonlocal pending, pending_chunks
        if dry_run or not pending:
            n = 0
        else:
            texts = [c for _, cs in pending for c in cs]
            dense = embedder.embed(texts)
            sparse = sparse_embedder.embed(texts)
            off = 0
            pts: list[PointStruct] = []
            for d, cs in pending:
                k = len(cs)
                pts.extend(build_points(source, d, cs, dense[off:off + k], sparse[off:off + k]))
                off += k
            store.upsert(source["collection"], pts)
            n = len(pts)
        pending = []
        pending_chunks = 0
        return n

    for doc in docs:
        chunks = chunk_text(doc.text, chunk_cfg.get("max_tokens", 400), chunk_cfg.get("overlap", 80))
        if not chunks:
            continue
        total_chunks += len(chunks)
        if dry_run:
            continue
        pending.append((doc, chunks))
        pending_chunks += len(chunks)
        if pending_chunks >= EMBED_BATCH:
            upserted += _flush()
    upserted += _flush()

    print(f"    chunks: {total_chunks}")
    if dry_run:
        print("    (dry-run: nothing written to Qdrant)")
    else:
        print(f"    upsert: {upserted} points -> {source['collection']}")

    meta = source.get("metadata") or {}
    manifest.record(source["id"], source["collection"], meta.get("source_name", source["id"]),
                    documents=len(docs), chunks=total_chunks)


def main() -> None:
    ap = argparse.ArgumentParser(description="RAG ingest pipeline (crawl/parse -> chunk -> embed -> upsert into Qdrant).")
    ap.add_argument("--source", help="Run only the source with this id")
    ap.add_argument("--config", help="Alternative path for sources.yaml")
    ap.add_argument("--dry-run", action="store_true", help="Don't write to Qdrant; counts documents and chunks")
    ap.add_argument("--no-eval", action="store_true",
                    help="Skip the automatic validation (golden queries) at the end of ingest")
    args = ap.parse_args()

    load_env()
    cfg = load_config(args.config)
    sources = list(enabled_sources(cfg, args.source))
    if not sources:
        print("No enabled source (check 'enabled' in sources.yaml or the --source argument).")
        return

    embedder = None if args.dry_run else Embedder()
    sparse_embedder = None if args.dry_run else SparseEmbedder()
    store = None if args.dry_run else QdrantStore()
    manifest = Manifest()

    touched: set[str] = set()
    failed: list[str] = []
    for source in sources:
        try:
            ingest_source(source, embedder, sparse_embedder, store, manifest, dry_run=args.dry_run)
            if not args.dry_run:
                touched.add(source["collection"])
                _clear_failure(source["id"])  # success: clear any previous marker
        except Exception as exc:  # one source must not block the others
            print(f"    ! error on {source['id']}: {exc}")
            failed.append(source["id"])
            if not args.dry_run:
                _record_failure(source["id"], f"{type(exc).__name__}: {exc}")

    if not args.dry_run:
        path = manifest.write()
        print(f"\nManifest updated: {path}")
    else:
        print("\n(dry-run: manifest NOT written)")
    if failed:
        print(f"⚠ FAILED sources ({len(failed)}): {failed} — recorded in {_STATUS_PATH.name}, "
              "review the sources/retry (for web sources: VPN + confirmation §15).")

    # Automatic content validation: every time the RAG is updated, a validity test
    # (golden queries) is run on the collections that were touched.
    if not args.dry_run and not args.no_eval and touched:
        queries, defaults = load_queries()
        result = evaluate_queries(queries, defaults, embedder, store, collections=touched)
        print_report(result, title=f"Automatic content validation — collections updated: {sorted(touched)}")
        if result["failed"]:
            print(f"\n⚠ {result['failed']} check queries not passed: review content coverage.")


if __name__ == "__main__":
    main()
