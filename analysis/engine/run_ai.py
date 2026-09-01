"""CLI: ask the on-box conversational engine a grounded question (DESIGN §14, step 1).

The head-less entry point to the local AI layer — usable without the GUI (CLI-first). It
runs the orchestration loop against a local Ollama model, letting the model ground its
answer in the RAG via the `rag_search` tool and cite sources (§6/§14.6). Nothing leaves the
machine; the engine proposes, never executes (§12).

Usage:
    uv run python -m engine.run_ai "What is T1003.001 and how do I hunt it?"
    uv run python -m engine.run_ai --ask "Explain NIS2 incident reporting timelines"
    uv run python -m engine.run_ai "..." --model llama3.1:8b --show-calls
    uv run python -m engine.run_ai "..." --json          # structured output (answer + calls)

Requires a running Ollama with the model pulled (env EVENTHOUND_LLM_MODEL, else the model
chosen in the GUI's Assistant picker, else
qwen2.5:7b-instruct). If Ollama or the model is absent, exits 3 with guidance (no crash).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ai import context as ai_context  # noqa: E402
from ai import engine as ai_engine  # noqa: E402
from ai import redact as ai_redact  # noqa: E402
from ai.ollama_client import OllamaClient, OllamaError  # noqa: E402
from ai.tools import default_registry  # noqa: E402
from analytics import case_store, runner  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Ask EventHound's on-box AI a grounded question.")
    ap.add_argument("question", nargs="?", help="the question (or use --ask, or pipe via stdin)")
    ap.add_argument("--ask", dest="ask", help="the question (alternative to the positional arg)")
    ap.add_argument("--model", help="Ollama model (default: env EVENTHOUND_LLM_MODEL, "
                                    "else the model chosen in the GUI, else the engine default)")
    ap.add_argument("--url", help="Ollama URL (default: env OLLAMA_URL or http://127.0.0.1:11434)")
    ap.add_argument("--rag-api-url",
                    default=os.environ.get("RAG_API_URL", "http://127.0.0.1:8600"),
                    help="rag-api service URL (falls back to the RAG venv subprocess if down)")
    ap.add_argument("--context", dest="context_path",
                    help="a saved analysis/report JSON (run_analytics/run_report) to reason over")
    ap.add_argument("--case", dest="case_id",
                    help="a stored case (engine.run_case) to reason over, analyzed on the fly")
    ap.add_argument("--enrich", action="store_true",
                    help="enable enrich_indicator (opt-in egress; public indicators only, §9)")
    ap.add_argument("--max-calls", type=int, default=6, help="cap on tool-call rounds")
    ap.add_argument("--show-calls", action="store_true", help="print the tool calls made")
    ap.add_argument("--stream", action="store_true",
                    help="stream the answer token-by-token to stdout as it is generated")
    ap.add_argument("--json", dest="json_out", action="store_true",
                    help="emit structured JSON (answer + calls) instead of prose")
    args = ap.parse_args(argv)

    question = args.ask or args.question
    if not question and not sys.stdin.isatty():
        question = sys.stdin.read().strip()
    if not question:
        print("error: no question given (positional, --ask, or stdin)", file=sys.stderr)
        return 2

    client = OllamaClient(url=args.url, model=args.model)
    reason = client.unusable_reason()
    if reason:
        print(f"Local AI unavailable: {reason}", file=sys.stderr)
        # The pull instructions belong to the "not pulled" case only. Printing them under a
        # refusal for lack of memory would send the operator to download a model they already have.
        if not client.available():
            print(f"Start it and pull the model, e.g.:\n"
                  f"  docker compose up -d ollama && "
                  f"docker exec eventhound-ollama ollama pull {client.model}\n"
                  f"  # or, host Ollama:  ollama serve & ollama pull {client.model}",
                  file=sys.stderr)
        return 3

    # Anonymization gate (§9/§14.5): pseudonymize before anything reaches the model.
    redactor = ai_redact.load_redactor()

    packed_context = None
    records = None
    if args.context_path and args.case_id:
        print("error: use --context or --case, not both", file=sys.stderr)
        return 2
    if args.context_path or args.case_id:
        try:
            # A case reaches the model through exactly the same path as a saved JSON — including
            # the redaction gate below (§9). Analyzing it here rather than reading a stored result
            # keeps the assistant on the current engine, not on whatever was exported months ago.
            analysis = (runner.analyze_case(args.case_id) if args.case_id
                        else ai_context.load_analysis(args.context_path))
        except (OSError, ValueError, json.JSONDecodeError, case_store.CaseError) as e:
            what = f"--case {args.case_id}" if args.case_id else f"--context {args.context_path}"
            print(f"error: cannot load {what}: {e}", file=sys.stderr)
            return 2
        if redactor.active:
            # Redact the whole analysis so the digest AND the query_analysis store are pseudonymized.
            analysis = redactor.apply_obj(analysis)
        else:
            print("warning: pseudonym map empty/absent — real identifiers in the analysis will "
                  "NOT be pseudonymized (§9). Data still stays on-box; populate "
                  "data/pseudonym-map.md to redact.", file=sys.stderr)
        packed_context = ai_context.pack_analysis(analysis)
        records = analysis.get("records") or []

    registry = default_registry(rag_api_url=args.rag_api_url, records=records, enrich=args.enrich)

    live = args.stream and not args.json_out  # stream tokens to stdout only in prose mode

    def on_event(kind: str, data: dict) -> None:
        if kind == "tool_call":
            print(f"  → {data['name']}({json.dumps(data['arguments'], ensure_ascii=False)})",
                  file=sys.stderr)
        elif kind == "token" and live:
            sys.stdout.write(data.get("text", ""))
            sys.stdout.flush()

    try:
        res = ai_engine.run(question, client=client, registry=registry, context=packed_context,
                            redactor=redactor, max_calls=args.max_calls, stream=args.stream,
                            on_event=on_event)
    except OllamaError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json_out:
        print(json.dumps({
            "answer": res.answer,
            "truncated": res.truncated,
            "calls": [{"name": c.name, "arguments": c.arguments, "result": c.result}
                      for c in res.calls],
        }, ensure_ascii=False, indent=2))
        return 0

    if args.show_calls and res.calls:
        print("Tool calls:")
        for c in res.calls:
            r = c.result if isinstance(c.result, dict) else {}
            if r.get("error"):
                summary = r["error"]
            elif "results" in r:
                summary = f"{len(r['results'])} result(s)"
            elif "matched" in r:
                summary = f"{r['matched']} row(s)"
            elif "mapped" in r:
                summary = f"{r.get('category')}/{r.get('action')}" if r["mapped"] else "unmapped"
            else:
                summary = "ok"
            print(f"  - {c.name}({json.dumps(c.arguments, ensure_ascii=False)}) → {summary}")
        print()
    if res.truncated:
        print("[note: tool-call cap reached; answer may be partial]\n", file=sys.stderr)
    if live:
        print()  # answer already streamed to stdout; just close the line
    else:
        print(res.answer or "(no answer)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
