from __future__ import annotations

from pathlib import Path

from ..config import RAG_DIR
from ..document import Document


def _resolve(path_str: str) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else (RAG_DIR / p).resolve()


def load_text_files(source: dict) -> list[Document]:
    """Loads text/markdown files (one Document per file)."""
    src = source.get("source", {})
    base = _resolve(src.get("path", "."))
    patterns = src.get("glob", "*.md")
    if isinstance(patterns, str):
        patterns = [patterns]

    if not base.exists():
        print(f"    ! source folder missing: {base}")
        return []

    files: set[Path] = set()
    if base.is_file():
        files.add(base)
    else:
        for pattern in patterns:
            files.update(base.glob(pattern))

    docs: list[Document] = []
    for path in sorted(files):
        if not path.is_file():
            continue
        # utf-8-sig: discards any BOM (U+FEFF) that str.strip() does NOT remove and that would
        # end up in the first indexed chunk, polluting the stored text and the lexical match.
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        if not text.strip():
            continue
        docs.append(Document(locator=str(path), text=text, metadata={"document": path.name}))
    return docs
