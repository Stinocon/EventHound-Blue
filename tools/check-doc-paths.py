#!/usr/bin/env python3
"""Every repository path a tracked .md names must exist.

Documentation rots in a specific, cheap-to-catch way: a file is renamed and the six places that
point at it are not. That is how `uninstall-macos.sh` outlived the script becoming `uninstall.sh`,
how `analysis/scripts/dl-sigmahq.sh` was promised by a README for a directory that never existed,
and how `docs/crowdstrike/` survived its own deletion. None of it is subtle; all of it is invisible
to a human re-reading prose they wrote.

Scope, deliberately narrow: markdown links, and inline code spans that clearly name a path inside
this repository. Prose is not parsed and never will be — a checker that guesses produces noise, and
a noisy check gets muted, which is worse than not having one.

    python3 tools/check-doc-paths.py            # exit 1 on a broken reference
    python3 tools/check-doc-paths.py --list     # list every reference it checked
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import doc_files  # noqa: E402 — sibling module, same directory

# Top-level directories of this repository. A code span is only treated as a path when it starts
# with one of these — `analytics.runner` and `--fmt access` must not be mistaken for files.
_REPO_DIRS = ("analysis/", "docs/", "method/", "tools/", "data/", ".github/")

# Paths that legitimately do not exist in a fresh clone: gitignored working directories, and the
# private data area. Named rather than pattern-matched, so adding one is a decision.
# Paths that are absent from a checkout by design: the venvs, the downloaded tools, the RAG index,
# the analyst's own `data/`. This used to be a hand-written list, and a hand-written list of things
# git already knows drifts — it was missing `analysis/.venv`, `rag/.env`, `rag/fastembed_cache/`
# and four more, so `check.sh`, a HARD gate, was red in any fresh clone and green only on the
# machine where the installer had already run. Derived from `git check-ignore` instead: if git is
# told to ignore a path, its absence is the design and not a broken reference.
#
# Known limit, stated rather than papered over: this cannot tell an artifact the reader will create
# (`analysis/.venv`, `data/pseudonym-map.md`) from a document that was simply never published, and
# both are "ignored and absent". Trying to (an `.md` exception) flagged the analyst's own pseudonym
# map, which is correct to reference and correct to be missing. The check found two real dead
# pointers on its way to this rule — `docs/attribuzioni-terzi.md` from the YARA page and
# `.claude/rules/input-non-fidato.md` from DESIGN — and both were fixed in the documents rather
# than in the checker.
_ALLOWED_MISSING: set[str] = set()


def _ignored_by_git(refs: list[str]) -> set[str]:
    """Which of `refs` git is configured to ignore. Empty when git cannot answer.

    Each ref is asked twice, with and without a trailing slash, and that is not belt-and-braces:
    most of these patterns are directory-only (`.venv/`, `qdrant_storage/`), and git will not match
    `analysis/.venv` against `.venv/` unless it can see that the path IS a directory. On the
    machine where the installer has run it can; in a fresh clone it cannot — so without this the
    check passed here and failed for everyone else, which is the bug it was written to remove."""
    if not refs:
        return set()
    probe = []
    for r in refs:
        probe.append(r)
        probe.append(r.rstrip("/") + "/")
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "--stdin"],
                             input="\n".join(probe), capture_output=True, text=True)
    except OSError:
        return set()
    if out.returncode not in (0, 1):        # 1 = nothing matched, which is a valid answer
        return set()
    hit = {line.strip() for line in out.stdout.splitlines() if line.strip()}
    return {r for r in refs if r in hit or r.rstrip("/") + "/" in hit}

# Glob patterns and angle-bracket placeholders are prose about a SHAPE of path, not a reference to
# one: `run_*.py`, `docs/<product>/INDEX.md`. Checking them would report every one of them forever.
_NOT_A_REFERENCE = ("*", "<", ">", "?", "\\", "$", "{", "...", "…")

# Paths named only in the record of their own removal. A document that says "docs/crowdstrike/ was
# removed" is correct precisely because the directory is gone, and a checker that objected to it
# would be asking history to be rewritten to stay green. Deliberately NOT extended for
# `tools/check-config-integrity.sh`, which was removed on 2026-09-01 and stayed documented in three
# files until 2026-09-25: adding it here would make every future live mention of it green forever,
# which is the exact blindness this checker exists to remove. Its one remaining mention is prose.
_REMOVED = {"docs/crowdstrike/", "docs/sonicwall/"}

_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_CODE = re.compile(r"`([^`\n]+)`")
# Fenced blocks, for the reason the first-token rule exists: instructions live in them. `~~~` is a
# valid fence in CommonMark and a document converted from another toolchain will use it.
_FENCE = re.compile(r"(?:```|~~~)[^\n]*\n(.*?)(?:```|~~~)", re.DOTALL)

# Punctuation that ends a sentence, a list item or a `path: message` line rather than the path.
# Without this, a document quoting a tool's own output (`docs/roadmap.md: tools/x.sh`) yields the
# candidate `docs/roadmap.md:`, which can never exist — a false positive that reds a hard gate in
# every clone, and a gate everyone has learned to ignore is worse than no gate.
_TRIM = ".,;:)]}\u2019\u201d"


def _tracked_md() -> list[Path]:
    files, from_git = doc_files.markdown_files(ROOT)
    if not from_git:
        print("[docs] not a git checkout: enumerating .md by walking the tree "
              "(tools/doc_files.py)", file=sys.stderr)
    return files


def _strip_frontmatter(text: str) -> str:
    """Drop the YAML frontmatter before scanning.

    A `changelog:` entry legitimately names a path that no longer exists — recording that
    `docs/crowdstrike/` was removed is the entry's whole point, and a checker that objected to it
    would be asking history to be rewritten. The body describes the present and is checked; the
    header records the past and is not."""
    if not text.startswith("---"):
        return text
    end = text.find("\n---", 3)
    return text[end + 4:] if end != -1 else text


def _candidates(text: str) -> set[str]:
    found: set[str] = set()

    def _add_tokens(chunk: str) -> None:
        # EVERY token, not just the first. Fixing the first-token blindness by looking at the first
        # one only moved the hole one word over: `python3 tools/check.sh`, `uv run tools/x`, `cd
        # tools/`, `--rules tools/x.yar` all put the path second, and those are the shapes this
        # repository's own documentation uses. A token is only considered when it starts at a
        # directory this repository has, so prose and flags cost nothing.
        for raw in chunk.split():
            # `rstrip` and not `strip`: a LEADING dot is part of the path. Stripping both ends turned
            # the relative `.tools/evtxecmd/` into `tools/evtxecmd/` and reported a correct reference
            # as a broken one — the first thing this rule would have taught everyone to ignore.
            ref = raw.rstrip(_TRIM)
            if ref.startswith(_REPO_DIRS) and not any(c in ref for c in _NOT_A_REFERENCE):
                found.add(ref)

    for m in _LINK.finditer(text):
        target = m.group(1).split("#", 1)[0].strip()
        if (target and not target.startswith(("http://", "https://", "mailto:", "#"))
                and not any(c in target for c in _NOT_A_REFERENCE)):
            found.add(target)
    for m in _CODE.finditer(text):
        _add_tokens(m.group(1))
    for block in _FENCE.findall(text):
        _add_tokens(block)
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description="Check repository paths named in tracked .md files")
    ap.add_argument("--list", action="store_true", help="print every reference checked")
    args = ap.parse_args()

    missing: list[tuple[str, str]] = []
    checked = 0
    for md in _tracked_md():
        text = _strip_frontmatter(md.read_text(encoding="utf-8", errors="replace"))
        rel_md = md.relative_to(ROOT)
        for ref in sorted(_candidates(text)):
            if ref in _ALLOWED_MISSING or ref in _REMOVED:
                continue
            # Either reading may be the right one: a markdown link is relative to the file that
            # carries it, while a code span almost always names a path from the repository root —
            # and `docs/roadmap.md` links `analysis/correlation.md` meaning the first. Trying both
            # is not laxity; insisting on one reading reported correct links as broken.
            checked += 1
            if args.list:
                print(f"  {rel_md}: {ref}")
            if not (md.parent / ref).exists() and not (ROOT / ref).exists():
                missing.append((str(rel_md), ref))

    ignored = _ignored_by_git(sorted({ref for _where, ref in missing}))
    broken = [(where, ref) for where, ref in missing if ref not in ignored]

    if broken:
        print(f"[doc-paths] {len(broken)} broken reference(s) in tracked documentation:")
        for where, ref in broken:
            print(f"  {where}: {ref}")
        print("  Fix the reference or the path — a document that points at nothing is worse than "
              "one that says nothing.")
        return 1
    print(f"[doc-paths] OK: {checked} repository path(s) named in documentation all exist.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
