"""Structured PDF parser via Docling (IBM, MIT license) — OPTIONAL.

Layout-aware alternative to the legacy path (pypdf -> text cleanup -> OCR): Docling recognizes the
document STRUCTURE (tables via TableFormer, headings, lists) and exports Markdown, where tables
stay as readable grids instead of flattened text. Useful for this workspace's tabular documents:
EUR-Lex regulation texts (GDPR/NIS2), CVE tables, control matrices.

Runs LOCALLY/offline: on first use it downloads the models (DocLayNet + TableFormer) into
Docling's cache, then no network calls. No LLM/VLM or external API.

Only activated with CY_PDF_PARSER=docling (cf. config.PDF_PARSER): by default ingest uses the
legacy path and this module isn't even imported. LAZY import of docling inside the
function: anyone not using the flag doesn't pay the heavy import cost. Docling is NOT in
pyproject by default (heavy dependency): install it with `uv add docling` in rag/ when you
want to use the flag.
"""
from __future__ import annotations


def docling_pdf_to_markdown(path: str) -> str:
    """Extracts the PDF (path) to Markdown with Docling. Returns '' on error or empty text, so
    the caller (load_pdfs) falls back to the legacy path without interruption."""
    try:
        from docling.document_converter import DocumentConverter

        result = DocumentConverter().convert(path)
        return (result.document.export_to_markdown() or "").strip()
    except Exception as e:
        import sys
        print(f"    [docling] extraction failed ({type(e).__name__}: {str(e)[:80]}) → falling back to legacy",
              file=sys.stderr, flush=True)
        return ""
