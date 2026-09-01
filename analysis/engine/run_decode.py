"""CLI for the decode engine — detects and decodes common encodings in log data.

Usage::

    uv run python -m engine.run_decode "<input_file_or_text>"
    uv run python -m engine.run_decode "<input>" --json
    uv run python -m engine.run_decode "<file>" --fields command_line,dns_query --min-confidence 0.5
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from decode.runner import scan_text, scan_fields  # noqa: E402


# ── helpers ────────────────────────────────────────────────────────────────


def _color(text: str, code: str) -> str:
    """Wrap *text* in ANSI escape *code* if stdout is a TTY."""
    if not sys.stdout.isatty():
        return text
    codes = {
        "bold": "\033[1m",
        "cyan": "\033[36m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "red": "\033[31m",
        "dim": "\033[2m",
        "reset": "\033[0m",
    }
    start = codes.get(code, "")
    end = codes["reset"] if start else ""
    return f"{start}{text}{end}"


def _confidence_color(c: float) -> str:
    if c >= 0.9:
        return "green"
    if c >= 0.7:
        return "cyan"
    if c >= 0.5:
        return "yellow"
    return "red"


def _print_plain(results, source_label: str) -> None:
    if not results:
        print(f"{source_label}: no encoding detected")
        return
    print(f"\n{source_label}:")
    for r in results:
        enc = _color(f"{r.encoder:>16}", "bold")
        conf = _color(f"{r.confidence:.2f}", _confidence_color(r.confidence))
        print(f"  {enc}  [{conf}]  {r.decoded}")
        if r.notes:
            print(f"  {'':>16}  {_color(r.notes, 'dim')}")


def _build_json_output(
    results: list | dict,
) -> dict:
    if isinstance(results, list):
        return {"results": [r.__dict__ for r in results]}
    if isinstance(results, dict):
        return {
            field: [r.__dict__ for r in rlist]
            for field, rlist in results.items()
        }
    return {}


# ── main ───────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Detects and decodes common encodings (base64, hex, URL, ROT, XOR, base58, unicode_escape)."
    )
    ap.add_argument("input", help="Text to analyze or path to a file")
    ap.add_argument("--fields", help="Fields to scan (comma-separated). Treats file as JSON with dict per line.")
    ap.add_argument("--min-confidence", type=float, default=0.5, help="Minimum confidence (default 0.5)")
    ap.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output in JSON format (instead of colored text)",
    )
    ap.add_argument(
        "--line-by-line",
        action="store_true",
        help="Read file line by line (default: entire file as single text)",
    )
    args = ap.parse_args(argv)

    # ── determine if input is a file ────────────────────────────────────
    input_path = Path(args.input)
    is_file = input_path.is_file()

    results_any: bool = False

    # ── JSON output: collect everything in a list ────────────────────────
    if args.json_output:
        all_output: list[dict] = []

        def _flush_item(label: str, res_list: list) -> None:
            nonlocal results_any
            for r in res_list:
                item = r.__dict__.copy()
                item["source"] = label
                all_output.append(item)
                results_any = True

        if is_file and args.line_by_line:
            with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    results = scan_text(line, min_confidence=args.min_confidence)
                    _flush_item(line[:60], results)
        elif is_file:
            text = input_path.read_text(encoding="utf-8", errors="replace")
            results = scan_text(text, min_confidence=args.min_confidence)
            _flush_item(str(input_path), results)
        else:
            results = scan_text(args.input, min_confidence=args.min_confidence)
            _flush_item(args.input[:60], results)

        print(json.dumps(all_output, ensure_ascii=False, indent=2))
        return 0 if results_any else 0

    # ── default output (colored text) ────────────────────────────────────
    if is_file and args.line_by_line:
        with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line:
                    continue
                results = scan_text(line, min_confidence=args.min_confidence)
                if results:
                    results_any = True
                _print_plain(results, line[:80])
    elif is_file:
        text = input_path.read_text(encoding="utf-8", errors="replace")
        results = scan_text(text, min_confidence=args.min_confidence)
        _print_plain(results, f"File: {input_path}")
        results_any = bool(results)
    else:
        results = scan_text(args.input, min_confidence=args.min_confidence)
        _print_plain(results, "Input")
        results_any = bool(results)

    return 0 if results_any else 0


if __name__ == "__main__":
    sys.exit(main())
