# rag/ — RAG infrastructure (crawler + vector DB)

Stack to index technical knowledge and make it queryable via semantic search: **crawl4ai** as crawler
(a library, in-process) and **Qdrant** as vector DB. Setup described in `../method/conventions.md` §13.

Qdrant runs either as a **native binary** (default on macOS: `../setup-macos.sh up qdrant`, storage in
`qdrant_storage/`, pid in `../.run/qdrant.pid`) or as a **container** (`docker compose up -d qdrant`).
Both use the same storage directory and the same port, so switching runtime does not rebuild the index.
crawl4ai needs no service at all: the pipeline drives it in-process as a library. Ingesting
`type: web` sources only requires the Playwright browser (`../setup-macos.sh install` provisions it).

## Dedicated Instance

This stack is **separate** from PersonalFinance's: Qdrant has a volume and a port of its own (host
`6343`). Do not point this project to the other's DB: knowledge is not shared between the two.

## Components

- `docker-compose.yml` — Qdrant + `rag-api` services (distinct ports), for the container route. Align
  images to your setup, not ports. No crawler service: crawl4ai is a library, used in-process.
- `sources.yaml` — **what** to index and **how** (web/pdf sources, auth, chunking, Qdrant collection).
- `.env.example` — template for credentials; copy to `.env` (gitignored).
- `sources_raw/` — raw inputs: provided PDFs, crawl dumps. **Gitignored** (licensed material).
- `secrets/` — `storage_state`/cookies for login-protected sources. **Gitignored**.
- `qdrant_storage/` — Qdrant persistent volume. **Gitignored**.

## Operational Flow

1. Start Qdrant — `../setup-macos.sh up qdrant` (native) or `docker compose up -d` (container).
2. Pipeline reads `sources.yaml` and, for each `enabled` source:
   - `type: pdf` → parses PDFs from indicated `path` (e.g., `sources_raw/normative/`, `../method/acn/`);
   - `type: markdown|file|text` → reads text files from indicated `path`;
   - `type: stix` → loads local STIX bundle (MITRE ATT&CK, primary via);
   - `type: web` → crawls with crawl4ai (JS rendering, depth/pattern/auth from config);
3. Text **chunks** → **embed** → **upsert** into indicated Qdrant `collection`.
4. Emission of an **index manifest** (collection → documents → source/URL) for traceability and quick access.

## Pipeline (`pipeline/`)

Modular Python code: `config` (reads `sources.yaml`+`.env`), `sources/` (PDF acquisition — with optional
Docling parser and OCR fallback — and web via crawl4ai with Wayback fallback), `chunker`, `embedder`
(pluggable dense + `SparseEmbedder` BM25), `qdrant_store` (hybrid collections with named vectors),
`manifest`, `ingest` (orchestrator), `retrieve` (**hybrid + reranking**
retrieval), `query` (historical alias for `retrieve`), `evaluate` (golden queries).

Retrieval also exposed as **MCP tool `rag_search`** (`rag/rag_mcp_server.py`, registered in `../.mcp.json`):
primary interface in session (§14), starts Qdrant itself and lazy-loads models.

**`rag-api`** (`rag/rag_api.py`, FastAPI) is a thin HTTP wrapper around `pipeline.retrieve`: it exposes
hybrid retrieval as a local service so lightweight clients (the `analysis/` GUI, other tools) don't need
to import the RAG's ML stack in-process (torch, fastembed, qdrant-client) — that stack lives only in this
venv/container, and models stay warm in memory across requests. Run locally with
`uv run uvicorn rag_api:app --host 127.0.0.1 --port 8600`, or as the `rag-api` service in
`docker-compose.yml` (built from `rag-api.Dockerfile`, `QDRANT_URL` pointing at the `qdrant` service).
Endpoints: `GET /health`, `POST /search`. No retrieval logic here — it's all in `pipeline.retrieve` (SOT).

Python management with **uv** (no manual `pip`/`venv`).

### Setup

```bash
cd rag
uv sync                     # creates .venv and installs dependencies from pyproject.toml
# optional cloud embedding backends: uv sync --extra voyage   |   uv sync --extra openai
cp .env.example .env        # populate if cloud backends needed; fastembed works out of the box

../setup-macos.sh up qdrant # native Qdrant (6343) — default on macOS
# or, container route:
docker compose up -d        # Qdrant (6343) + rag-api (8600)
```

### Backup / restore of the index

`./backup.sh create [dest_dir]` archives `qdrant_storage/` (default destination
`~/eventhound-backups`), stopping Qdrant first for a consistent snapshot and restarting it the way it
was running — native or container, detected, not assumed. `./backup.sh restore <archive.tar.gz>`
extracts into an **empty** `qdrant_storage/` and refuses while Qdrant is up. The index is gitignored
and web sources need a VPN to re-crawl (§15), so this is the way it moves between machines.

### Usage

```bash
# Count documents and chunks without writing to Qdrant
uv run python -m pipeline.ingest --dry-run

# Ingest a single source
uv run python -m pipeline.ingest --source acn-pdf

# All enabled sources in sources.yaml
uv run python -m pipeline.ingest

# Hybrid retrieval (dense+BM25+rerank); --no-hybrid / --no-rerank for comparison
uv run python -m pipeline.retrieve "lateral movement con SMB" --collection knowledge_cyber
uv run python -m pipeline.retrieve "T1003.001 LSASS" --collection knowledge_cyber --no-hybrid
```

In session, prefer the MCP tool `rag_search(query, collection, k, level)`.

Ingest emits `rag/index_manifest.json` (per source: documents, chunks, collection, timestamp).

### Embedding

Default **local** `fastembed` (no API key): dense `intfloat/multilingual-e5-large` (**1024 dim**,
multilingual IT+EN, with query/passage prefixes) + sparse BM25 `Qdrant/bm25` for **hybrid** retrieval,
and cross-encoder reranker `jinaai/jina-reranker-v2-base-multilingual`. All fastembed (no
sentence-transformers). Switchable to `voyage` or `openai`-compatible via `EMBEDDING_BACKEND` (dense
only). Vector dimension is detected at runtime; collections use **named vectors** (`dense` + `bm25`):
changing model or migrating from legacy to hybrid requires **rebuilding** the collection (`reindex.sh`).

> Operational note: with large model on CPU, ingest is very slow and running multiple ingests in parallel
> worsens it (ONNX thread oversubscription). Better to run a single sequential process (`uv run python -m
> pipeline.ingest` without `--source` runs sources in order) and for long runs, use `caffeinate` to avoid sleep.

### Evaluation (golden queries)

`golden_queries.yaml` contains control queries to **validate** (tied to MITRE ATT&CK techniques, NIST
publications, and foundational concepts) with expected terms in results. Script `pipeline/evaluate.py`
runs them along the **actual retrieval path** (hybrid + reranking, via `retrieve.search`) and marks PASS/FAIL
based on **presence of expected terms** in retrieved chunks (score, with RRF+rerank, is no longer a cosine
threshold: it's informational only), to estimate index quality and identify coverage gaps.

**Automatic validation in flow.** Each `pipeline.ingest` run that updates the RAG (new content or
re-ingest) launches validation on **just-touched collections** at end of run — reusing already-loaded
embedder, so no extra cost. Disable with `--no-eval`. If any query fails, it signals as a warning.

```bash
uv run python -m pipeline.ingest --source mitre-attack-stix   # ingest + automatic validation of knowledge_cyber
uv run python -m pipeline.ingest --no-eval               # ingest without validation

# On-demand validation (independent of ingest):
uv run python -m pipeline.evaluate            # PASS/FAIL report per query and percentage
uv run python -m pipeline.evaluate --verbose  # for FAIL, shows top retrieved results
```

Queries whose collection is not yet indexed show SKIP. To add new control queries, add entries to
`golden_queries.yaml` (with `collection`, `query`, `reference`, and `expect_any`/`expect_all`).

### Robustness Notes

- **Before any web crawl/scraping, warn the user** (they must enable VPN — see `method/conventions.md` §15). RAG queries
  and local PDF ingest are not scraping.
- **Precise, non-aggressive crawler**: `defaults.crawler` in `sources.yaml` configures `robots.txt` respect
  (`respect_robots`), request delay (`mean_delay`), max concurrency (`max_concurrency`), identifying user-agent,
  depth/page caps, boilerplate filtering (`excluded_tags`, `word_count_threshold`, `exclude_external_links`),
  and cache (`cache_mode`). Parameters are passed to crawl4ai only if the version accepts them (introspection
  filter in `web_source.py`), so adding more doesn't break.
- **crawl4ai** is most version-sensitive: its calls are isolated in `pipeline/sources/web_source.py`. If
  imports or parameters don't match installed version, adapt there (ref. official docs).
- **PDF**: parser per `CY_PDF_PARSER` — `legacy` (pypdf + text cleanup, default) or `docling` (layout-aware,
  tables as markdown grids; useful for EUR-Lex/normative and CVE; `uv add docling` as needed). Scanned PDFs
  pass through **OCR fallback** (pdf2image+pytesseract, if installed), then skip.
- **Failed web sources** cataloged in `ingest_status.json` (reason, retry count, date): don't blindly retry.
  **Wayback** (archive.org) fallback opt-in for blocked seeds (`crawler.wayback_fallback: true`) — still
  outbound network, see §15.
- **Deterministic point IDs** (`uuid5` from source+locator+chunk): re-ingest updates instead of duplicating.

## Login-Protected Sources

Recommended approach (`auth.method: storage_state`):

1. Manual login **once** in browser (incl. SSO/MFA).
2. Export session **storage state** (cookies + localStorage) to `secrets/<source>.storage_state.json`.
3. crawl4ai reuses that session to crawl the authenticated area.
4. When crawl is redirected to login, session has expired: recapture.

Caveat: licensed portal ToS constrain use (internal consultation only, no redistribution). Prefer
official PDFs when available (no login, more stable).

## Shared Knowledge (Public Cyber Sources)

In `sources.yaml`, collection `knowledge_cyber`: MITRE ATT&CK, NIST CSRC (glossary, SP 800, CSF),
SANS (white papers/resources), ISC2 (insights). Tight `include`/`exclude` patterns to stay technical
and exclude marketing/course pages/gated areas.
NIST CSRC glossary, once indexed, helps reconcile `method/glossary.md`.

## Adding a Source

Add a block to `sources.yaml` with `id`, `type`, `collection`, and — if needed — `crawler.auth`. Set
`enabled: true` when ready. Public sources (MITRE, NIST, SANS, ISC2) → `auth.required: false`.
