"""Measure the on-box model's tool-calling instead of assuming it (eval/toolcall_prompts.json).

The default model moved to `qwen2.5:14b` in July because the 7B kept describing tool calls in prose
rather than emitting them (DESIGN §14.3/§14.9) — a decision taken on two ad-hoc queries. This runner
was written to measure that claim, and the figures it produced contradicted it; on 2026-08-29 the
default moved back to `qwen2.5:7b-instruct`, which is what the corpus supports. It matters beyond
ergonomics: an answer where `rag_search` never ran is ungrounded, and a CVSS number the oracle never
computed is invented (§6). Re-run this whenever the default is questioned again: the point of the
corpus is that the model choice stays an argument about figures.

    uv run python -m engine.run_toolbench                       # default model, one pass
    uv run python -m engine.run_toolbench --repeat 3            # sampling is nondeterministic
    uv run python -m engine.run_toolbench --model qwen2.5:7b-instruct
    uv run python -m engine.run_toolbench --case eid-unmapped-4656 -v
    uv run python -m engine.run_toolbench --repeat 3 --json > bench.json

Needs a local Ollama with the model pulled; without one it says so and exits 3, measuring nothing
rather than reporting a green it did not earn. The scoring logic is pure and is tested offline
against a scripted client (tests/test_toolbench.py) — a benchmark that cannot detect the defect it
was built for measures nothing either.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ai import context as ai_context  # noqa: E402
from ai import engine as ai_engine  # noqa: E402
from ai import redact as ai_redact  # noqa: E402
from ai.ollama_client import OllamaClient, OllamaError  # noqa: E402
from ai.tools import default_registry  # noqa: E402

CORPUS = Path(__file__).resolve().parents[1] / "eval" / "toolcall_prompts.json"

# Text that looks like a tool call the model wrote out instead of emitting: a JSON blob naming a
# function, an Ollama/Qwen call marker, or a fenced json block. Used only to tell "narrated" from
# "did not try at all" — two failures with different causes and different fixes.
_CALL_SHAPED = re.compile(
    r'"(?:name|function|tool|tool_name|arguments|parameters)"\s*:|<tool_call>|\[TOOL_CALL\]|```json',
    re.IGNORECASE)


def _mostly_non_latin(text: str) -> bool:
    """Did the model answer in a script the question was not asked in?

    Observed on qwen2.5:14b: an English prompt answered in Thai. Without this the run scores as a
    failed phrase check, which reads as 'the model did not degrade honestly' when what actually
    happened is that it answered in a language the analyst cannot use — a different defect with a
    different fix. Threshold on letters only, so digits, ATT&CK ids and punctuation do not sway it."""
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 40:
        return False
    return sum(1 for c in letters if ord(c) > 0x24F) / len(letters) > 0.3


def _loose_eq(a, b) -> bool:
    """Compare an emitted argument with an expected one tolerantly: models return 4624 and "4624"
    interchangeably, and collection names sometimes come back capitalised."""
    return str(a).strip().lower() == str(b).strip().lower()


def score_case(case: dict, res, *, error: str | None = None) -> dict:
    """Score one run of one case. Pure: `res` only needs `.answer`, `.calls` and `.truncated`.

    Returns the per-run record the aggregate is built from. `passed` is the whole contract holding;
    the individual flags exist because they fail for different reasons — `narrated` is a model
    limitation, `args_ok` is a schema mismatch, `answer_ok` is a grounding failure."""
    exp = case.get("expect") or {}
    want = exp.get("tool")
    if error is not None:
        return {"id": case["id"], "passed": False, "error": error, "called": False,
                "correct_tool": False, "narrated": False, "args_ok": True,
                "forbidden_called": False, "answer_ok": False, "truncated": False,
                "foreign_script": False, "calls": [], "answer": ""}

    answer = res.answer or ""
    names = [c.name for c in res.calls]
    matching = [c for c in res.calls if c.name == want] if want else []

    called = bool(names)
    correct_tool = bool(matching) if want else True
    # The §14.9 defect: the required call never happened, yet the answer talks as if it had.
    narrated = bool(want) and not matching and (
        want in answer or bool(_CALL_SHAPED.search(answer)))

    # Arguments: the dispatcher's own verdict (a schema mismatch comes back as an error result),
    # plus any argument values the case insists on.
    args_ok = True
    for c in res.calls:
        err = c.result.get("error", "") if isinstance(c.result, dict) else ""
        if err.startswith("bad arguments") or err.startswith("unknown tool"):
            args_ok = False
    for key, value in (exp.get("tool_args_contain") or {}).items():
        if not any(_loose_eq(c.arguments.get(key), value) for c in matching):
            args_ok = False

    forbidden = exp.get("forbid_tool")
    forbidden_called = bool(forbidden) and forbidden in names

    low = answer.lower()
    answer_ok = True
    any_of = exp.get("answer_any_of") or []
    if any_of and not any(s.lower() in low for s in any_of):
        answer_ok = False
    for pattern in (exp.get("answer_none_of_regex") or []):
        if re.search(pattern, answer):
            answer_ok = False

    foreign = _mostly_non_latin(answer)
    passed = correct_tool and args_ok and answer_ok and not forbidden_called and not foreign
    return {"id": case["id"], "passed": passed, "error": None, "called": called,
            "correct_tool": correct_tool, "narrated": narrated, "args_ok": args_ok,
            "forbidden_called": forbidden_called, "answer_ok": answer_ok,
            "foreign_script": foreign, "truncated": bool(res.truncated),
            # The call's error (if any) is kept so a saved run can be re-scored faithfully later:
            # transcripts are the measurement, scoring is derived from them (see --rescore).
            "calls": [{"name": c.name, "arguments": c.arguments,
                       "error": c.result.get("error") if isinstance(c.result, dict) else None}
                      for c in res.calls],
            "answer": answer}


class _SavedRun:
    """A saved run rebuilt into the shape `score_case` expects. The transcript (answer + calls) is
    the measurement; pass/fail is derived from it — so fixing a corpus expectation must not require
    another hour of querying a model, and re-scoring old transcripts with new labels is the honest
    way to compare. `result` carries only the recorded error, which is all `score_case` reads."""

    class _Call:
        def __init__(self, c: dict):
            self.name = c.get("name", "")
            self.arguments = c.get("arguments") or {}
            self.result = {"error": c["error"]} if c.get("error") else {}

    def __init__(self, run: dict):
        self.answer = run.get("answer") or ""
        self.truncated = bool(run.get("truncated"))
        self.calls = [self._Call(c) for c in (run.get("calls") or [])]


def rescore(saved: dict, cases_by_id: dict) -> list[dict]:
    """Re-score saved runs against the CURRENT corpus. Cases no longer in the corpus are dropped."""
    out = []
    for run in saved.get("runs") or []:
        case = cases_by_id.get(run["id"])
        if case is None:
            continue
        rec = score_case(case, _SavedRun(run))
        rec["seconds"] = run.get("seconds")
        out.append(rec)
    return out


def _percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile. statistics.quantiles needs n≥2 and interpolates; with a handful of
    runs the rank is both simpler and easier to defend than an interpolated figure."""
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, int(round(pct / 100 * len(ordered) + 0.5)) - 1))
    return ordered[k]


def aggregate(runs: list[dict], cases_by_id: dict) -> dict:
    """Turn per-run records into the rates the model decision is actually made on."""
    required = [r for r in runs if (cases_by_id[r["id"]].get("expect") or {}).get("tool")]
    latencies = [r["seconds"] for r in runs if r.get("seconds") is not None]
    return {
        "runs": len(runs),
        "passed": sum(1 for r in runs if r["passed"]),
        "errors": sum(1 for r in runs if r["error"]),
        "required_tool_runs": len(required),
        "emitted": sum(1 for r in required if r["called"]),
        "correct_tool": sum(1 for r in required if r["correct_tool"]),
        "narrated": sum(1 for r in required if r["narrated"]),
        "args_ok": sum(1 for r in required if r["args_ok"]),
        "answer_checks": sum(1 for r in runs if r["answer_ok"]),
        "foreign_script": sum(1 for r in runs if r.get("foreign_script")),
        "forbidden_called": sum(1 for r in runs if r["forbidden_called"]),
        "truncated": sum(1 for r in runs if r["truncated"]),
        "latency_p50": round(_percentile(latencies, 50), 2),
        "latency_p95": round(_percentile(latencies, 95), 2),
    }


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.0f}%" if d else "n/a"


def _build_context(corpus: dict, redactor=None) -> tuple[str, list[dict]]:
    """Pack the corpus' own records into a digest exactly as `run_ai --context` would.

    Running the real analytics rather than hand-writing a digest keeps the benchmark on the same
    context the product actually ships to the model; a hand-written one would measure a prompt
    nobody ever sends.

    REDACT, THEN PACK — the order the two production callers use (§9). Packing first and letting
    `engine.run`'s redactor sweep the finished string leaves an identifier the packer's own
    truncation split unmatched, because `Redactor` substitutes exact substrings: a corroboration
    line cut inside `SRV-FINANCE-PROD-01` reached the model as `SRV-FINANCE-PROD-0`. Only reachable
    with `--corpus` pointed at a file holding real `context_records`, which is exactly the case a
    benchmark harness invites."""
    from analytics import runner
    records = corpus.get("context_records") or []
    analysis = runner.analyze(records)
    if redactor is not None and getattr(redactor, "active", False):
        analysis = redactor.apply_obj(analysis)
    return ai_context.pack_analysis(analysis), analysis.get("records") or records


def run_corpus(cases: list[dict], corpus: dict, *, client, repeat: int = 1, max_calls: int = 6,
               rag_api_url: str = "http://127.0.0.1:8600",
               on_run=None) -> list[dict]:
    """Replay every case `repeat` times and return the scored runs."""
    redactor = ai_redact.load_redactor()   # inactive in a clean checkout; kept for path parity (§9)
    packed, ctx_records = (None, None)
    runs: list[dict] = []

    for case in cases:
        needs = case.get("needs") or {}
        if needs.get("context") and packed is None:
            packed, ctx_records = _build_context(corpus, redactor)
        registry = default_registry(rag_api_url=rag_api_url,
                                    records=ctx_records if needs.get("context") else None,
                                    enrich=bool(needs.get("enrich")))
        for _ in range(repeat):
            t0 = time.perf_counter()
            try:
                res = ai_engine.run(case["question"], client=client, registry=registry,
                                    context=packed if needs.get("context") else None,
                                    redactor=redactor, max_calls=max_calls)
                rec = score_case(case, res)
            except OllamaError as e:
                # One unreachable turn must not discard the fifty runs already measured.
                rec = score_case(case, None, error=f"{type(e).__name__}: {e}")
            rec["seconds"] = round(time.perf_counter() - t0, 2)
            runs.append(rec)
            if on_run:
                on_run(case, rec)
    return runs


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure tool-call reliability of the local model")
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--case", help="run a single case by id")
    ap.add_argument("--rescore", metavar="FILE",
                    help="re-score a saved --json run against the current corpus (no model needed)")
    ap.add_argument("--model", help="Ollama model (default: env EVENTHOUND_LLM_MODEL, "
                                    "else the model chosen in the GUI, else the engine default)")
    ap.add_argument("--url", help="Ollama URL (default: env OLLAMA_URL or http://127.0.0.1:11434)")
    ap.add_argument("--rag-api-url", default="http://127.0.0.1:8600")
    ap.add_argument("--repeat", type=int, default=1,
                    help="runs per case; sampling is nondeterministic, one pass is an anecdote")
    ap.add_argument("--max-calls", type=int, default=6, help="cap on tool-call rounds")
    ap.add_argument("--json", dest="json_out", action="store_true",
                    help="emit the runs and the aggregate as JSON instead of tables")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print each answer and the calls behind it")
    args = ap.parse_args()

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    cases = corpus.get("cases") or []
    if args.case:
        cases = [c for c in cases if c["id"] == args.case]
        if not cases:
            print(f"no case with id {args.case!r}", file=sys.stderr)
            return 2
    cases_by_id = {c["id"]: c for c in cases}

    if args.rescore:
        saved = json.loads(Path(args.rescore).read_text(encoding="utf-8"))
        runs = rescore(saved, cases_by_id)
        agg = aggregate(runs, cases_by_id)
        if args.json_out:
            print(json.dumps({"model": saved.get("model"), "rescored_from": args.rescore,
                              "aggregate": agg, "runs": runs}, ensure_ascii=False, indent=2))
            return 0
        was = (saved.get("aggregate") or {}).get("passed")
        print(f"Re-scored {len(runs)} saved run(s) of {saved.get('model')} against the current corpus")
        if was is not None:
            print(f"  passed: {was} -> {agg['passed']} (of {agg['runs']})")
        changed = {r["id"] for r, o in zip(runs, saved["runs"]) if r["passed"] != o["passed"]}
        print("  verdict changed on: " + (", ".join(sorted(changed)) if changed else "no case"))
        return 0

    client = OllamaClient(url=args.url, model=args.model)
    reason = client.unusable_reason()
    if reason:
        print(f"Local AI unavailable: {reason}", file=sys.stderr)
        if not client.available():
            print(f"Start it and pull the model:  ollama serve & ollama pull {client.model}",
                  file=sys.stderr)
        return 3

    live = not args.json_out

    def on_run(case, rec):
        if not live:
            return
        mark = "·" if rec["passed"] else ("!" if rec["error"] else "✗")
        detail = "narrated" if rec["narrated"] else (rec["error"] or "")
        print(f"  {mark} {case['id']:<34} {rec['seconds']:>6.1f}s "
              f"{','.join(c['name'] for c in rec['calls']) or '(no call)':<28} {detail}")
        if args.verbose:
            print(f"      {(rec['answer'] or '(empty)')[:600]}\n")

    if live:
        print(f"Model {client.model} · {len(cases)} case(s) × {args.repeat} "
              f"= {len(cases) * args.repeat} runs\n")
    runs = run_corpus(cases, corpus, client=client, repeat=args.repeat,
                      max_calls=args.max_calls, rag_api_url=args.rag_api_url, on_run=on_run)
    agg = aggregate(runs, cases_by_id)

    if args.json_out:
        print(json.dumps({"model": client.model, "corpus_version": corpus.get("corpus_version"),
                          "repeat": args.repeat, "aggregate": agg, "runs": runs},
                         ensure_ascii=False, indent=2))
        return 0

    print(f"\nPer case ({args.repeat} run(s) each):")
    for case in cases:
        rs = [r for r in runs if r["id"] == case["id"]]
        ok = sum(1 for r in rs if r["passed"])
        narr = sum(1 for r in rs if r["narrated"])
        note = f"  narrated {narr}/{len(rs)}" if narr else ""
        if not ok and not narr:
            reasons = []
            if any(not r["correct_tool"] for r in rs):
                reasons.append("required tool not called")
            if any(not r["args_ok"] for r in rs):
                reasons.append("arguments")
            if any(not r["answer_ok"] for r in rs):
                reasons.append("answer check")
            if any(r.get("foreign_script") for r in rs):
                reasons.append("answered in another script")
            note = "  " + ", ".join(reasons) if reasons else ""
        print(f"  {ok}/{len(rs)}  {case['id']:<34}{note}")

    r = agg
    print(f"\nRequired-tool cases ({r['required_tool_runs']} run(s)):")
    print(f"  emitted a tool call         {r['emitted']:>4}  ({_pct(r['emitted'], r['required_tool_runs'])})")
    print(f"  called the required tool    {r['correct_tool']:>4}  ({_pct(r['correct_tool'], r['required_tool_runs'])})")
    print(f"  NARRATED instead of calling {r['narrated']:>4}  ({_pct(r['narrated'], r['required_tool_runs'])})  <- §14.9")
    print(f"  arguments accepted          {r['args_ok']:>4}  ({_pct(r['args_ok'], r['required_tool_runs'])})")
    print(f"\nAnswer checks held    {r['answer_checks']}/{r['runs']}")
    print(f"Answered in another script {r['foreign_script']}/{r['runs']}")
    print(f"Forbidden tool called {r['forbidden_called']}")
    print(f"Cap reached           {r['truncated']}/{r['runs']}")
    print(f"Transport errors      {r['errors']}")
    print(f"Latency               p50 {r['latency_p50']}s   p95 {r['latency_p95']}s")
    print(f"\n{r['passed']}/{r['runs']} runs passed ({_pct(r['passed'], r['runs'])}) "
          f"on model {client.model}")
    # Deliberately exits 0 whatever the rates: this measures a model, it does not gate a build.
    # Wiring it into check.sh would make the suite fail on someone else's hardware and model.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
