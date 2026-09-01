"""RAG pipeline: crawl/parse -> chunk -> embed -> upsert into Qdrant.

Modules:
- config      loading of sources.yaml and .env, merging of defaults
- document    Document dataclass shared across sources
- chunker     splitting text into chunks
- embedder    pluggable embedding (local fastembed / voyage / openai-compatible)
- qdrant_store wrapper over Qdrant (collections dedicated to this project)
- manifest    writing of index_manifest.json
- sources/    acquisition by type (pdf, web via crawl4ai)
- ingest      CLI orchestrator
- query       retrieval test
"""
