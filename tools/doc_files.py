"""Which .md files the documentation guards look at — one answer, two callers.

`git ls-files` is the right question in a checkout: it names what is tracked and skips the venvs,
the downloaded tools and the ignored output directories, none of which anyone documents. It is also
the wrong question everywhere else, and both guards used to call it with `check=True`: in a
`git archive` extraction, in the Docker image (which copies the source without `.git`) or in a
tarball download, they did not report a problem — they raised CalledProcessError and took the whole
`check.sh` down with them. A gate that cannot run outside the author's own clone is the defect
`test-guards.sh` was already caught with on 2026-08-29; this is the same shape one directory over.

So: ask git when git can answer, and walk the tree when it cannot, skipping what a checkout would
never have tracked anyway. The fallback is deliberately dumber than .gitignore — it is a degraded
mode, and it says so — but it checks the documentation rather than skipping it.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

# Directories a tracked .md never lives in. Not a .gitignore parser: the fallback only has to avoid
# scanning thousands of vendored markdown files, and being wrong here costs noise, never silence.
_SKIP = {".git", ".venv", "node_modules", "__pycache__", ".tools", ".run", "data",
         "qdrant_storage", "fastembed_cache", "sources_raw", "community", "cases", "reports"}


def markdown_files(root: Path) -> tuple[list[Path], bool]:
    """`(files, from_git)`. `from_git` is False when the tree is not a git checkout."""
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "*.md"],
                             capture_output=True, text=True, check=True).stdout
        return [root / line for line in out.splitlines() if line], True
    except (OSError, subprocess.CalledProcessError):
        pass
    found: list[Path] = []
    for path in sorted(root.rglob("*.md")):
        if any(part in _SKIP for part in path.relative_to(root).parts):
            continue
        found.append(path)
    return found, False
