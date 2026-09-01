#!/usr/bin/env python3
"""The YAML frontmatter of every tracked .md must actually parse.

CLAUDE.md §4 makes the frontmatter load-bearing: every edit to a `method/` or `docs/` file bumps
`updated` and adds a `changelog` entry. That convention is worth exactly as much as the block is
parseable — and on 2026-08-30 four of the most-edited documents in the repo (`docs/roadmap.md`,
`docs/analysis/correlation.md`, `analysis/schema/common-schema.md`, `analysis/DESIGN.md`) had
frontmatter no YAML parser would read, some of it since August. Nothing noticed, because nothing
parses it: the convention is kept by hand and read by humans, who skip the block.

Scope, deliberately narrow — the same principle as check-doc-paths.py, and for the same reason: a
checker that guesses produces noise, and a noisy check gets muted. This is NOT a YAML parser (the
system python3 has none, and these scripts stay stdlib-only). It catches the two failures that
actually happened, both of them from writing long English prose into a YAML scalar:

  1. An unescaped `"` inside a double-quoted scalar. Every changelog entry here is one long
     `- "..."`, and prose quotes things.
  2. An unquoted `key:` value containing `: ` — YAML reads the second colon as a nested mapping.

    python3 tools/check-doc-frontmatter.py           # exit 1 on a broken block
    python3 tools/check-doc-frontmatter.py --list    # name every file it checked
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


def tracked_markdown() -> list[Path]:
    files, from_git = doc_files.markdown_files(ROOT)
    if not from_git:
        print("[docs] not a git checkout: enumerating .md by walking the tree "
              "(tools/doc_files.py)", file=sys.stderr)
    return files


def frontmatter(text: str) -> tuple[int, list[str]] | None:
    """(first line number, lines) of the frontmatter block, or None when there is none."""
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 4)
    if end == -1:
        return None
    return 2, text[4:end].split("\n")


def scan(lines: list[str], first_line: int) -> list[str]:
    problems: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = re.match(r'^(\s*)- "(.*)$', ln)
        if m:
            # A double-quoted scalar, possibly spanning lines: it ends at the first line whose last
            # character is a quote not itself escaped.
            start = i
            body = [m.group(2)]
            while not (body[-1].endswith('"') and not body[-1].endswith('\\"')):
                i += 1
                if i >= len(lines):
                    problems.append(f"line {first_line + start}: unterminated double-quoted scalar")
                    return problems
                body.append(lines[i])
            inner = "\n".join(body)[:-1]
            # An unescaped quote is one preceded by an even number of backslashes.
            for hit in re.finditer(r'(?<!\\)(?:\\\\)*"', inner):
                col = len(inner[:hit.end()].rsplit("\n", 1)[-1])
                problems.append(
                    f"line {first_line + start}: unescaped \" at column {col} of the scalar "
                    f"(…{inner[max(0, hit.end() - 40):hit.end() + 20]}…) — write it as \\\"")
            i += 1
            continue
        m = re.match(r'^([A-Za-z_][\w-]*): (?!\s*$)(.*)$', ln)
        if m and m.group(2)[:1] not in ('"', "'", "|", ">", "[", "{") and ": " in m.group(2):
            problems.append(
                f"line {first_line + i}: `{m.group(1)}:` holds an unquoted value containing "
                f"': ' — YAML reads that as a nested mapping; quote the whole value")
        i += 1
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--list", action="store_true", help="name every file checked")
    args = ap.parse_args()

    checked = broken = 0
    for path in tracked_markdown():
        try:
            block = frontmatter(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        if block is None:
            continue
        checked += 1
        problems = scan(block[1], block[0])
        rel = path.relative_to(ROOT)
        if problems:
            broken += 1
            for p in problems:
                print(f"[frontmatter] {rel}: {p}", file=sys.stderr)
        elif args.list:
            print(f"[frontmatter] OK {rel}")

    if broken:
        print(f"[frontmatter] {broken} of {checked} frontmatter block(s) will not parse.",
              file=sys.stderr)
        return 1
    print(f"[frontmatter] OK: {checked} frontmatter block(s) are well-formed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
