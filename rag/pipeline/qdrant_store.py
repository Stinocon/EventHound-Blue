from __future__ import annotations

import os

from qdrant_client import QdrantClient
from qdrant_client.models import (Distance, Modifier, SparseVector,
                                  SparseVectorParams, VectorParams)

from .config import DENSE_VECTOR, SPARSE_VECTOR


def hybrid_vector(dense: list[float], sparse: tuple[list[int], list[float]]) -> dict:
    """Builds the named-vector dict for a hybrid PointStruct."""
    indices, values = sparse
    return {
        DENSE_VECTOR: dense,
        SPARSE_VECTOR: SparseVector(indices=indices, values=values),
    }


class QdrantStore:
    """Wrapper over Qdrant. Points to the DEDICATED instance of this project
    (default localhost:6343), separate from the PersonalFinance one.

    The collections are HYBRID: named dense vector ("dense") + BM25 sparse vector
    ("bm25"). Qdrant requires named vectors when a point has more than one.
    The old single unnamed-vector collections are NOT compatible: they need to be
    rebuilt (reindex.sh). `is_hybrid()` lets retrieval degrade gracefully on
    legacy collections not yet rebuilt.
    """

    def __init__(self, url: str | None = None, api_key: str | None = None):
        self.client = QdrantClient(
            url=url or os.getenv("QDRANT_URL", "http://localhost:6343"),
            api_key=api_key or os.getenv("QDRANT_API_KEY") or None,
        )

    def ensure_collection(self, name: str, size: int, distance: Distance = Distance.COSINE) -> None:
        if self.client.collection_exists(name):
            # Already exists: verify it's compatible with a hybrid upsert at this dim.
            # A legacy collection (single unnamed vector) or one with a different dimension
            # CANNOT receive our points (named dense+bm25): better to fail clearly
            # than to corrupt/reject halfway through an upsert. It needs to be rebuilt
            # (reindex.sh).
            info = self.client.get_collection(name)
            vectors = info.config.params.vectors
            dense = vectors.get(DENSE_VECTOR) if isinstance(vectors, dict) else None
            if dense is None:
                raise ValueError(
                    f"Collection '{name}' is not hybrid (vector '{DENSE_VECTOR}' missing): "
                    "legacy single-vector, it needs to be rebuilt (reindex.sh)."
                )
            if dense.size != size:
                raise ValueError(
                    f"Collection '{name}' has dim {dense.size}, the current model produces {size}: "
                    "it needs to be rebuilt (reindex.sh)."
                )
            # Our points always also carry the BM25 sparse vector: if the collection doesn't
            # declare it, the upsert would be rejected mid-batch. Better to fail clearly.
            sparse = info.config.params.sparse_vectors or {}
            if SPARSE_VECTOR not in sparse:
                raise ValueError(
                    f"Collection '{name}' doesn't declare the sparse vector '{SPARSE_VECTOR}': "
                    "it isn't hybrid, it needs to be rebuilt (reindex.sh)."
                )
            return
        self.client.create_collection(
            collection_name=name,
            vectors_config={DENSE_VECTOR: VectorParams(size=size, distance=distance)},
            # BM25 requires the IDF modifier: the TF values come from fastembed, the IDF is
            # computed by Qdrant over the whole collection.
            sparse_vectors_config={SPARSE_VECTOR: SparseVectorParams(modifier=Modifier.IDF)},
        )

    def is_hybrid(self, name: str) -> bool:
        """True if the collection uses the hybrid named vectors (post-rebuild);
        False if it's legacy with a single unnamed vector (pre-rebuild)."""
        try:
            info = self.client.get_collection(name)
            vectors = info.config.params.vectors
            return isinstance(vectors, dict) and DENSE_VECTOR in vectors
        except Exception:
            return False

    def upsert(self, name: str, points: list, batch: int = 128) -> None:
        for i in range(0, len(points), batch):
            self.client.upsert(collection_name=name, points=points[i:i + batch])
