from __future__ import annotations

import os
import sys
from pathlib import Path


def _threads_kwargs() -> dict:
    """kwargs {'threads': N} from EMBEDDING_THREADS, if it's an integer > 0; otherwise {}.
    A non-numeric value is ignored (it must not make the embedding fail)."""
    raw = os.getenv("EMBEDDING_THREADS")
    if not raw:
        return {}
    try:
        n = int(raw)
    except ValueError:
        return {}
    return {"threads": n} if n > 0 else {}


def _cache_kwargs() -> dict:
    """kwargs {'cache_dir': PATH} from FASTEMBED_CACHE_DIR, if set; otherwise {}.
    Used to persist fastembed models on a volume (Docker) or a stable path: without
    the env variable, fastembed's default behavior is used (unchanged)."""
    path = os.getenv("FASTEMBED_CACHE_DIR")
    return {"cache_dir": path} if path else {}


def guard_memory(what: str) -> None:
    """Refuse to load a multi-GiB model onto a host with no room for it.

    Lives HERE, at the allocation, and not at the callers. The RAG is the project's other
    gigabyte-scale allocator, and the first version of this guard sat in `retrieve`'s three lazy
    getters — which covered the query path and nothing else: `pipeline.evaluate` and
    `pipeline.ingest` construct `Embedder()` directly, ingest being the heaviest RAG load there is,
    and both walked straight past it. A guard on the callers has to be re-applied by every new
    caller; a guard on the constructor cannot be forgotten.

    It asks the weaker question (`hostmem.pressure_reason`), because fastembed reports no footprint
    and the size here cannot be honestly measured: is there any headroom at all. It fails open on
    anything unmeasurable, and `EVENTHOUND_ALLOW_LOW_MEMORY=1` overrides it — the same escape hatch
    as the on-box LLM, deliberately the same name, so an operator learns one switch and not two.
    """
    try:
        from tools import hostmem
    except ImportError:
        # The repository layout (rag/pipeline/embedder.py -> repo root two levels up) is not the
        # only one this runs in: inside the rag-api image the tree is /app/pipeline + /app/tools,
        # where the plain import above already works. Try that first, add the repo root only when
        # it does not, and never grow sys.path twice — a refused load leaves the singleton unset,
        # so this function is called again on the next query for as long as the pressure lasts.
        root = str(Path(__file__).resolve().parents[2])
        if root not in sys.path:
            sys.path.insert(0, root)
        try:
            from tools import hostmem
        except ImportError:
            return  # the shared module is unreachable: never a reason to stop answering queries
    reason = hostmem.pressure_reason(what)
    if reason:
        raise RuntimeError(f"refusing to load {what}: {reason}")


class Embedder:
    """Pluggable embedding.

    Backend (env EMBEDDING_BACKEND):
      - "fastembed" (default): local model, no API key. Suited to a
        personal stack. High-quality multilingual (IT+EN) default for retrieval
        (e5-large, 1024 dim): heavy and slow on CPU (see DEFAULT_MODELS for
        lighter alternatives). Requires the query:/passage: prefixes (_with_prefix).
      - "voyage": Voyage AI (env EMBEDDING_API_KEY).
      - "openai": OpenAI-compatible endpoint (env EMBEDDING_API_KEY, opt. EMBEDDING_BASE_URL).

    The vector dimension is detected at runtime (see `dim`): changing the model
    doesn't require touching the code, but an existing Qdrant collection needs
    to be recreated if the dimension changes.
    """

    DEFAULT_MODELS = {
        # Multilingual (IT+EN), 1024 dim: maximum retrieval quality in the
        # local stack. Requires the "query:"/"passage:" prefixes (handled in _with_prefix).
        # Lighter/faster alternative: "sentence-transformers/paraphrase-multilingual-mpnet-base-v2"
        # (768 dim, no prefixes) or "...MiniLM-L12-v2" (384 dim).
        "fastembed": "intfloat/multilingual-e5-large",
        "voyage": "voyage-3",
        "openai": "text-embedding-3-small",
    }

    def __init__(self, backend: str | None = None, model: str | None = None):
        self.backend = (backend or os.getenv("EMBEDDING_BACKEND", "fastembed")).lower()
        self.model = model or os.getenv("EMBEDDING_MODEL") or self.DEFAULT_MODELS.get(self.backend)
        if not self.model:
            raise ValueError(f"No default model for backend '{self.backend}'")
        self._dim: int | None = None
        self._impl = self._build()

    def _build(self):
        if self.backend == "fastembed":
            # Only the local backend allocates on this host; voyage/openai are HTTP clients.
            guard_memory("the RAG embedding model")
            from fastembed import TextEmbedding
            # EMBEDDING_THREADS: number of ONNX threads (default = fastembed's choice).
            # On a multi-core CPU it's worth pinning it to the performance cores to squeeze
            # the machine ("full power"); on this machine 8 (8 perf + 2 eff).
            # _threads_kwargs() ignores non-numeric values without crashing the embedding.
            return TextEmbedding(model_name=self.model, **_threads_kwargs(), **_cache_kwargs())
        if self.backend == "voyage":
            import voyageai
            return voyageai.Client(api_key=os.getenv("EMBEDDING_API_KEY"))
        if self.backend == "openai":
            from openai import OpenAI
            return OpenAI(
                api_key=os.getenv("EMBEDDING_API_KEY"),
                base_url=os.getenv("EMBEDDING_BASE_URL") or None,
            )
        raise ValueError(f"Unsupported embedding backend: {self.backend}")

    def _with_prefix(self, text: str, input_type: str) -> str:
        """The e5 models want an instruction prefix: 'query:' for queries,
        'passage:' for documents. Without it, quality drops noticeably. For
        other models (MiniLM, mpnet, bge-en, ...) nothing is applied."""
        if "e5" in (self.model or "").lower():
            prefix = "query: " if input_type == "query" else "passage: "
            return prefix + text
        return text

    def embed(self, texts, input_type: str = "document") -> list[list[float]]:
        texts = list(texts)
        if not texts:
            return []

        if self.backend == "fastembed":
            prepared = [self._with_prefix(t, input_type) for t in texts]
            vectors = [list(map(float, v)) for v in self._impl.embed(prepared)]
        elif self.backend == "voyage":
            resp = self._impl.embed(texts, model=self.model, input_type=input_type)
            vectors = [list(map(float, v)) for v in resp.embeddings]
        else:  # openai-compatible
            resp = self._impl.embeddings.create(model=self.model, input=texts)
            vectors = [list(map(float, d.embedding)) for d in resp.data]

        if self._dim is None and vectors:
            self._dim = len(vectors[0])
        return vectors

    @property
    def dim(self) -> int:
        if self._dim is None:
            self.embed(["probe"])
        if self._dim is None:
            raise RuntimeError(
                f"Could not detect the vector dimension for backend='{self.backend}' "
                f"model='{self.model}': the probe produced no embedding."
            )
        return self._dim


class SparseEmbedder:
    """Sparse (lexical) embedding for hybrid retrieval: BM25 via fastembed.

    Unlike the dense one, sparse weighs the EXACT TERMS present in the text
    (CVE IDs, techniques `T1003.001`, malware/exploit names, FQL/CQL syntax) — what
    semantics alone tends to confuse. Returns (indices, values) pairs to feed
    into a `qdrant_client.models.SparseVector`.

    The model (Qdrant/bm25) is downloaded once on first use and is small. For
    documents use `embed()`, for queries `embed_query()` (BM25 treats them differently:
    the IDF is computed by Qdrant, see `Modifier.IDF` in qdrant_store). Internally
    `embed_query()` calls fastembed's `query_embed()`.
    """

    def __init__(self, model: str | None = None):
        from .config import SPARSE_MODEL
        # SPARSE_MODEL already incorporates os.getenv("RAG_SPARSE_MODEL") (see config.py)
        self.model = model or SPARSE_MODEL
        self._impl = None

    def _build(self):
        if self._impl is None:
            from fastembed import SparseTextEmbedding
            self._impl = SparseTextEmbedding(model_name=self.model, **_threads_kwargs(), **_cache_kwargs())
        return self._impl

    @staticmethod
    def _to_pair(emb) -> tuple[list[int], list[float]]:
        return [int(i) for i in emb.indices], [float(v) for v in emb.values]

    def embed(self, texts) -> list[tuple[list[int], list[float]]]:
        texts = list(texts)
        if not texts:
            return []
        return [self._to_pair(e) for e in self._build().embed(texts)]

    def embed_query(self, text: str) -> tuple[list[int], list[float]]:
        # An empty query or one made only of stopwords may produce no sparse embedding:
        # next(..., None) avoids the StopIteration that would crash hybrid retrieval.
        # Empty pair = no lexical term; the dense branch still drives the retrieval anyway.
        emb = next(iter(self._build().query_embed(text)), None)
        if emb is None:
            return [], []
        return self._to_pair(emb)
