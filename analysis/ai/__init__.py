"""EventHound on-box conversational AI engine (DESIGN §14).

The interpretation layer that ships *inside* the product: a local LLM (Ollama) that
reasons over analysis output, grounds every technical claim in the RAG and proposes
insight / assessment / remediation — fully offline, proposing never executing (§12).

Step 1 (this module): RAG-only skeleton — the orchestration loop + the `rag_search`
tool + the grounding contract. Analysis context, scoring/enrichment tools and the
anonymization gate come in later steps (DESIGN §14.8).

CLI-first: everything here is usable head-less via `engine.run_ai`; the GUI chat and
per-function "AI button" are thin layers over `ai.engine.run` (not built yet).
"""
