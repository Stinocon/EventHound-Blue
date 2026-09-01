# EventHound — the rag-api service image (retrieval as an HTTP service).
#
# Deliberately SLIM: it installs only the RETRIEVAL stack (qdrant-client + fastembed) and the HTTP
# transport (fastapi + uvicorn). It does NOT install crawl4ai/pypdf/mcp: ingest/crawling (chromium,
# heavy) does not run here — only pipeline.retrieve. See rag/pyproject.toml.
#
# BUILD CONTEXT IS THE REPOSITORY ROOT, not ./rag: the pipeline shares `tools/hostmem.py` with the
# on-box LLM, and Docker cannot COPY above its context. Copying `pipeline/` alone left the memory
# guard permanently inert inside this image — the import failed and the guard fails open, so the
# one process here that allocates gigabytes was the one process running without it. See the root
# `.dockerignore`, an allowlist shared with the eventhound image, which keeps the context to the
# handful of source paths the two of them actually copy.
FROM python:3.12-slim

WORKDIR /app

# Retrieval-only dependencies + the API. Versions aligned with pyproject.toml.
RUN pip install --no-cache-dir \
    "qdrant-client>=1.9.0" \
    "fastembed>=0.7.0" \
    "PyYAML>=6.0" \
    "python-dotenv>=1.0.0" \
    "fastapi>=0.110" \
    "uvicorn>=0.29"

# Code: the retrieval pipeline + the HTTP wrapper (no sources/datasets), plus the shared host-memory
# module the guard imports. `tools/` is a namespace package here exactly as it is in the repository.
COPY rag/pipeline/ ./pipeline/
COPY rag/rag_api.py ./
COPY tools/hostmem.py ./tools/hostmem.py

# Belt, not the mechanism: `CMD uvicorn rag_api:app` can only resolve `rag_api` with /app already
# on sys.path, so `from tools import hostmem` works here without this line. It is kept so a future
# CMD that runs from elsewhere does not silently disable the guard.
ENV PYTHONPATH=/app

# fastembed models under /models: mount a volume here to avoid re-downloading them at every start.
ENV FASTEMBED_CACHE_DIR=/models
# Qdrant reached by service name on the compose network (internal port 6333, not the host's 6343).
ENV QDRANT_URL=http://qdrant:6333

# NOTE on what the guard can and cannot see here: /proc/meminfo is not namespaced, so it measures
# the host (or Docker Desktop's VM) rather than this container or any mem_limit — it therefore errs
# PERMISSIVE. On a LINUX host that reading is still the machine that runs out when fastembed loads
# e5-large, which is what makes it worth having; on Docker Desktop for macOS it is the VM's memory,
# which is host-backed, so the VM can report gigabytes free while the Mac is the machine that dies
# — that platform is told to use the native stack instead (docker-compose.yml). Either way it is
# better placed than the LLM guard, which measures a different container from the one allocating.
EXPOSE 8600
CMD ["uvicorn", "rag_api:app", "--host", "0.0.0.0", "--port", "8600"]
