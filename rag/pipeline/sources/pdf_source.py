from __future__ import annotations

import re
from pathlib import Path

from ..config import RAG_DIR
from ..document import Document


def _resolve(path_str: str) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else (RAG_DIR / p).resolve()


def _clean_pdf_text(text: str) -> str:
    """Normalizes the typical artifacts of text extraction from PDFs, in
    particular those from EUR-Lex (stray spaces, words broken at line ends,
    multiple blank lines). Conservative: doesn't touch the content, only the form.

    Known limitation: it doesn't fix *intra-word* spaces (e.g. "respon sible"),
    which would require a dictionary; here multiple spaces, end-of-line
    de-hyphenation and vertical spacing are normalized.
    """
    text = text.replace("\x0c", "\n")                 # form feed -> newline
    text = re.sub(r"(\w)-\n(\w)", r"\1\2", text)        # "respon-\nsible" -> "responsible"
    text = re.sub(r"[ \t]{2,}", " ", text)              # multiple spaces/tabs -> single
    text = re.sub(r"[ \t]+\n", "\n", text)              # trailing spaces at end of line
    text = re.sub(r"\n[ \t]+", "\n", text)              # leading spaces at start of line
    text = re.sub(r"\n{3,}", "\n\n", text)              # 3+ blank lines -> paragraph
    return text.strip()


def _ocr_pdf_text(path: str) -> str:
    """OCR fallback for scanned PDFs (images without extractable text). Uses pdf2image
    (poppler) + pytesseract (tesseract, ita+eng languages) if installed; otherwise returns ''
    and the caller skips the file. OCR dependencies not in pyproject (heavy): installed on
    demand (`uv add pdf2image pytesseract` + system poppler/tesseract binaries)."""
    try:
        import pytesseract
        from pdf2image import convert_from_path
    except Exception:
        return ""
    try:
        pages = convert_from_path(path)
        return "\n\n".join(pytesseract.image_to_string(img, lang="ita+eng") for img in pages).strip()
    except Exception as exc:
        import sys
        print(f"    [ocr] failed on {path} ({type(exc).__name__}: {str(exc)[:80]})", file=sys.stderr)
        return ""


def load_pdfs(source: dict) -> list[Document]:
    """Extracts text from the source's PDFs (one Document per file).

    Parser per config.PDF_PARSER: 'docling' (layout-aware, structured tables) with fallback to
    the legacy path; 'legacy' (default: pypdf + text cleanup). Scanned PDFs without extractable
    text go through the OCR fallback (if the binaries are present), then get skipped.
    """
    from pypdf import PdfReader

    from ..config import PDF_PARSER

    src = source.get("source", {})
    base = _resolve(src.get("path", "./sources_raw"))
    pattern = src.get("glob", "*.pdf")

    if not base.exists():
        print(f"    ! source folder missing: {base}")
        return []

    files = [base] if base.is_file() else sorted(base.glob(pattern))
    docs: list[Document] = []
    for pdf in files:
        text = ""
        # 1) Docling (opt-in): tables as markdown grids
        if PDF_PARSER == "docling":
            from .pdf_docling import docling_pdf_to_markdown
            text = docling_pdf_to_markdown(str(pdf))
        # 2) Legacy pypdf (default, or fallback if docling doesn't produce output)
        if not text.strip():
            try:
                reader = PdfReader(str(pdf))
                raw = "\n\n".join((page.extract_text() or "") for page in reader.pages)
                text = _clean_pdf_text(raw)
            except Exception as exc:
                print(f"    ! unreadable PDF {pdf.name}: {exc}")
                continue
        # 3) OCR fallback for scanned documents (images)
        if not text.strip():
            print(f"    ! no text from {pdf.name} (scanned?) → attempting OCR")
            text = _ocr_pdf_text(str(pdf))
        if not text.strip():
            print(f"    ! no text from {pdf.name} even after OCR: skipped")
            continue
        docs.append(Document(locator=str(pdf), text=text, metadata={"document": pdf.name}))
    return docs
