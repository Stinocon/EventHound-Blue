"""Shared bit of the `--json-out PATH` / deprecated `--json PATH` CLI convention.

Nine CLIs under engine/ take a PATH via --json to write full results as JSON, while four others
(run_ai/run_bench/run_decode/run_toolbench) use --json as a boolean "print to stdout" flag — same
flag name, two contracts. --json-out is now the canonical path flag for the first group; --json
PATH survives as a working alias (registered on the same `dest`, so either spelling lands in the
same place) to keep existing scripts and callers working, with one deprecation line on stderr when
it's actually the alias that was used.
"""
from __future__ import annotations

import sys


def warn_if_deprecated_json_flag(argv: list[str] | None) -> None:
    """Prints the deprecation notice iff the legacy `--json PATH` spelling (not `--json-out`) was
    on the command line. Sniffs argv directly rather than the parsed namespace: the alias shares
    its dest with --json-out, so `args.json_out` alone can't tell which spelling supplied it."""
    argv = argv if argv is not None else sys.argv[1:]
    if any(a == "--json" or a.startswith("--json=") for a in argv):
        print("--json PATH is deprecated; use --json-out PATH", file=sys.stderr)
