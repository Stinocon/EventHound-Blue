"""Test of the on-box AI orchestration loop (ai/engine.py, ai/tools.py — DESIGN §14, step 1).

Two levels, like the other engine tests:
- `run_synthetic()`: ALWAYS run. Exercises the loop offline with a scripted fake client and a
  fake registry — no Ollama, no network. Validates tool dispatch, feeding results back, the
  final answer, argument parsing, unknown-tool handling and the call-cap. Plus a unit check of
  the RAG result compaction. This is where the loop's correctness is pinned.
- `run_e2e()`: end-to-end against a real local Ollama; skipped (pass) if Ollama or the model is
  absent. Only checks the loop returns a string answer without raising — model quality is not
  asserted here.

Run: uv run python tests/test_ai.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai import engine as ai_engine  # noqa: E402
from ai.tools import Tool, _compact_result  # noqa: E402
from tests._helpers import skip_test  # noqa: E402


class ScriptedClient:
    """Fake `client.chat`: returns scripted assistant messages in order. When `tools is None`
    (the engine's forced final turn after the cap), returns `final_when_toolless` instead."""

    def __init__(self, scripted: list[dict], final_when_toolless: dict | None = None):
        self._scripted = list(scripted)
        self._final = final_when_toolless
        self.calls: list[dict] = []

    def chat(self, messages, tools=None):
        self.calls.append({"n_messages": len(messages), "tools": tools})
        if tools is None and self._final is not None:
            return self._final
        return self._scripted.pop(0)


def _fake_rag_tool(recorder: list) -> Tool:
    def func(query, collection="knowledge_cyber", k=5):
        recorder.append({"query": query, "collection": collection, "k": k})
        return {"collection": collection,
                "results": [{"source": "MITRE ATT&CK", "level": 1, "url": None,
                             "locator": "T1003.001", "text": "OS Credential Dumping: LSASS Memory."}]}
    schema = {"type": "function", "function": {"name": "rag_search",
              "parameters": {"type": "object", "properties": {"query": {"type": "string"}}}}}
    return Tool(schema=schema, func=func)


def run_synthetic() -> int:
    # --- happy path: model calls rag_search, gets the result, then answers -----------------
    invoked: list = []
    registry = {"rag_search": _fake_rag_tool(invoked)}
    client = ScriptedClient([
        {"role": "assistant", "content": "",
         "tool_calls": [{"function": {"name": "rag_search",
                                      "arguments": {"query": "T1003.001", "k": 3}}}]},
        {"role": "assistant",
         "content": "T1003.001 is LSASS memory dumping (source: MITRE ATT&CK, T1003.001)."},
    ])
    res = ai_engine.run("What is T1003.001?", client=client, registry=registry)
    assert not res.truncated, "should end naturally, not by cap"
    assert len(res.calls) == 1 and res.calls[0].name == "rag_search", res.calls
    assert invoked == [{"query": "T1003.001", "collection": "knowledge_cyber", "k": 3}], invoked
    assert "LSASS" in res.answer and "MITRE" in res.answer, res.answer
    # the tool result was fed back to the model as a role:"tool" message
    assert any(m.get("role") == "tool" for m in res.messages), res.messages
    print("PASS  happy path: tool call dispatched, result fed back, grounded answer returned")

    # --- arguments as a JSON string (some models emit this) --------------------------------
    invoked2: list = []
    reg2 = {"rag_search": _fake_rag_tool(invoked2)}
    client2 = ScriptedClient([
        {"role": "assistant", "content": "",
         "tool_calls": [{"function": {"name": "rag_search",
                                      "arguments": '{"query": "kerberoasting"}'}}]},
        {"role": "assistant", "content": "done (source: MITRE)"},
    ])
    res2 = ai_engine.run("q", client=client2, registry=reg2)
    assert invoked2 and invoked2[0]["query"] == "kerberoasting", invoked2
    print("PASS  tool arguments parsed from a JSON string")

    # --- unknown tool → error result fed back, loop does not crash -------------------------
    reg3: dict = {}  # empty registry: any tool call is "unknown"
    client3 = ScriptedClient([
        {"role": "assistant", "content": "",
         "tool_calls": [{"function": {"name": "nope", "arguments": {}}}]},
        {"role": "assistant", "content": "recovered"},
    ])
    res3 = ai_engine.run("q", client=client3, registry=reg3)
    assert res3.calls[0].result.get("error", "").startswith("unknown tool"), res3.calls
    assert res3.answer == "recovered", res3.answer
    print("PASS  unknown tool → error result, loop recovers")

    # --- call cap: a model that never stops calling tools is forced to a final answer ------
    reg4 = {"rag_search": _fake_rag_tool([])}
    looping = {"role": "assistant", "content": "",
               "tool_calls": [{"function": {"name": "rag_search", "arguments": {"query": "x"}}}]}
    client4 = ScriptedClient([looping, looping, looping],
                             final_when_toolless={"role": "assistant", "content": "forced answer"})
    res4 = ai_engine.run("q", client=client4, registry=reg4, max_calls=2)
    assert res4.truncated is True, "cap should mark the result truncated"
    assert len(res4.calls) == 2, res4.calls               # exactly max_calls tool rounds
    assert res4.answer == "forced answer", res4.answer    # final tool-less turn produced it
    assert client4.calls[-1]["tools"] is None, client4.calls[-1]
    print("PASS  call cap enforced, final tool-less turn forces an answer")

    # --- RAG compaction: snippet trimmed, citation fields kept -----------------------------
    hit = {"source_name": "MITRE ATT&CK", "level": 1, "url": "https://x", "locator": "T1003",
           "text": "A" * 5000, "score": 0.9}
    c = _compact_result(hit, snippet_chars=100)
    assert c["source"] == "MITRE ATT&CK" and c["locator"] == "T1003" and c["level"] == 1
    assert len(c["text"]) <= 101 and c["text"].endswith("…"), len(c["text"])
    assert "score" not in c, c
    print("PASS  RAG result compaction: snippet bounded, citation fields preserved")
    return 0


def run_step2() -> int:
    """Context packer (ai/context) + the step-2 tools (eid_lookup, query_analysis)."""
    from ai import context as ai_context
    from ai.tools import _make_query_analysis, default_registry, eid_lookup

    # --- eid_lookup: mapped ID from the SOT vs an unmapped one (say 'verify', don't invent) --
    m = eid_lookup(4624, "Security")
    assert m["mapped"] and m["category"] == "authentication", m
    u = eid_lookup(4656, "Security")   # not in the SOT map → honest "unknown"
    assert u["mapped"] is False and u["note"], u
    print("PASS  eid_lookup: mapped EID from SOT, unmapped → verify (no confabulation)")

    # --- pack_analysis: bounded digest, top-N per recipe, truncation guard --------------------
    big = {
        "summary": {"events": 900, "distinct_hosts": 3, "distinct_users": 5,
                    "by_source": {"evtx": 800, "pcap": 100}},
        "rare_processes": [{"process_name": f"proc{i}.exe", "count": 1} for i in range(100)],
        "records": [{"host.name": "HOST-01"}] * 900,
        "timeline": [{"ts": f"2026-07-16T06:{i:02d}:00Z", "why": "ATT&CK technique",
                      "source": "evtx", "host": "HOST-01", "techniques": "T1021.002"}
                     for i in range(20)],
        "killchain": [
            {"phase": "Delivery", "phase_order": 2, "events": 4, "hosts": 1, "sources": 1,
             "source_list": "evtx", "tactics": "initial-access", "techniques": "T1566.001",
             "technique_count": 1, "first_seen": "2026-07-16T06:00:00", "last_seen": "…06:04:00",
             "corroboration": "zeek: 40 event(s), to 203.0.113.9, resolving cdn.evil.example, "
                              "updates.cdn-corp.example · registry: 4 event(s) · "
                              "crowdstrike: 3 event(s), as m.rossi · osquery: 3 event(s)",
             "corroboration_families": "zeek", "corroboration_window_s": 120},
            {"phase": "Command and Control", "phase_order": 6, "events": 1, "hosts": 1,
             "sources": 1, "source_list": "evtx", "tactics": "command-and-control",
             "techniques": "T1071.001", "technique_count": 1,
             "first_seen": "2026-07-16T06:20:00", "last_seen": "…06:20:00",
             "corroboration": "pcap: 812 event(s), to 203.0.113.9 "
                              "(flagged as periodic call-backs — to validate)",
             "corroboration_families": "pcap", "corroboration_window_s": 120},
        ],
        "host_killchain": [{"host": "HOST-01", "max_order": 6, "attack_events": 5,
                            "phases_covered": 2, "phases": "Delivery → Command and Control",
                            "deepest_phase": "Command and Control",
                            "first_seen": "2026-07-16T06:00:00", "last_seen": "…06:20:00"}],
        "technique_catalog": [{"technique": "T1566.001", "name": "Spearphishing Attachment",
                               "tactics": "initial-access", "phase": "Delivery", "hits": 4,
                               "hosts": 1, "sources": 1}],
    }
    digest = ai_context.pack_analysis(big, max_rows=8, budget_chars=12000)
    assert "## Dataset" in digest and "900 events" in digest, digest[:200]
    assert "rare_processes" in digest and digest.count("- process_name=") == 8, \
        f"expected top-8 rows, got {digest.count('- process_name=')}"
    assert "records" not in digest, "raw records must not be dumped into the digest"
    # the timeline goes in as an ordered sequence, not as one more recipe row list
    assert "## Timeline (20 notable event(s), first 8 in order)" in digest, digest[-400:]
    assert "### timeline" not in digest, "timeline packed as a recipe: the order is lost"
    assert "- 2026-07-16T06:00:00Z [ATT&CK technique]" in digest, digest[-400:]
    # The kill chain reaches the assistant. It was excluded from the digest outright — the fifth
    # renderer, against four that had it — so the one interface that answers in sentences was the
    # one that could not see how far the activity reached.
    assert "## Kill chain (2 phase(s) observed, deepest: Command and Control)" in digest, digest[:900]
    assert "- Delivery — 4 event(s)" in digest and "T1566.001" in digest, digest[:900]
    assert "Hosts by depth (top 1 of 1" in digest and "HOST-01 (Command and Control, 2 phase(s))" in digest, digest[:900]
    assert "Techniques observed (top 1 of 1)" in digest and "Spearphishing Attachment" in digest, digest[:900]
    # ...and it arrives labelled. Corroboration is co-occurrence in time; an assistant that
    # repeated it as evidence of a technique would undo the feature it comes from.
    assert "CO-OCCURRENCE in time, not a technique" in digest, digest[:900]
    assert "periodic call-backs" in digest, digest[:900]
    # The window WIDTH travels with the claim: "in the same window" over 59 minutes and over 4 are
    # not the same statement, and this was the only renderer that dropped the number.
    assert "same ±2 min window" in digest, digest[:900]
    # A SHORTENED line must say so, and must never end mid-value. R6 caught the digest presenting
    # `updates.cdn-corp.exam` and `10.10.20.11` — a truncated domain and a different real host on
    # the same /24 — to the model as observed evidence, with nothing marking the cut. A technique
    # ID is worse: `T1021.002` clipped to `T1021` is a valid ID for a different technique, minted
    # by a renderer, in the product that refuses to mint them (§6).
    kc_lines = [ln for ln in digest.splitlines() if "CO-OCCURRENCE" in ln]
    assert kc_lines, digest[:900]
    for ln in kc_lines:
        assert len(ln) <= 220, f"the line ignored its own bound ({len(ln)}): {ln}"
        if "…" not in ln:
            continue
        assert "more)" in ln or ln.rstrip("…").endswith((")", "e", "9")), ln
    long_line = next(ln for ln in kc_lines if "…" in ln)
    assert "updates.cdn-corp.exam…" not in long_line and "cdn-corp.exampl…" not in long_line, \
        f"a value was cut mid-token and offered as evidence: {long_line}"
    # ...and the sub-budget keeps it from displacing the timeline, which is what it costs
    assert digest.index("## Timeline") > digest.index("## Kill chain"), digest[:400]
    assert len([ln for ln in digest.splitlines() if ln.startswith("- 2026-07-16T06:")]) == 8, \
        "the kill chain pushed the timeline out of the digest"
    assert "### killchain" not in digest and "### technique_catalog" not in digest, \
        "kill chain packed as a frequency table: the order is what it is for"
    empty = ai_context.pack_analysis({"summary": {"events": 1}})
    assert "Kill chain" not in empty, "no phases observed must print no section at all"

    tiny = ai_context.pack_analysis(big, max_rows=8, budget_chars=300)
    assert "truncated" in tiny and len(tiny) < 400, len(tiny)
    print("PASS  pack_analysis: bounded digest, top-N rows, kill chain, budget truncation")

    # --- query_analysis: read-only detail over a store rebuilt from records -------------------
    records = [
        {"@timestamp": "2024-01-01T00:00:01Z", "event.source": "evtx",
         "event.category": "authentication", "event.code": 4624,
         "host.name": "HOST-01", "user.name": "USER-01", "message": "logon success type 3"},
        {"@timestamp": "2024-01-01T00:00:02Z", "event.source": "evtx",
         "event.category": "authentication", "event.code": 4625,
         "host.name": "HOST-02", "user.name": "USER-02", "message": "logon failed"},
        {"@timestamp": "2024-01-01T00:00:03Z", "event.source": "evtx",
         "event.code": 4688, "host.name": "HOST-01", "process.name": "mimikatz.exe",
         "message": "process create"},
    ]
    qa = _make_query_analysis(records)
    r_host = qa("events_for_host", "HOST-01")
    assert r_host["matched"] == 2 and all(x["host"] == "HOST-01" for x in r_host["rows"]), r_host
    r_eid = qa("by_event_code", 4625)
    assert r_eid["matched"] == 1 and r_eid["rows"][0]["user_name"] == "USER-02", r_eid
    r_search = qa("search", "mimikatz")
    assert r_search["matched"] == 1 and r_search["rows"][0]["event_code"] == 4688, r_search
    assert qa("bogus_op", "x").get("error"), "unknown op must error, not crash"
    assert qa("events_for_host", "HOST-01", limit=1)["matched"] == 1, "limit must cap rows"
    print("PASS  query_analysis: host/eid/search filters, unknown-op error, limit cap")

    # --- registry wiring: query_analysis present only with a context -------------------------
    assert "query_analysis" not in default_registry(), "no context → no query_analysis"
    assert "query_analysis" in default_registry(records=records), "context → query_analysis"
    assert "eid_lookup" in default_registry(), "eid_lookup always available"
    print("PASS  registry: eid_lookup always on, query_analysis gated on a loaded context")
    return 0


def run_step3() -> int:
    """Anonymization gate (ai/redact) + scoring/enrichment tools, and the §14.5 property:
    a real identifier never reaches the model in plaintext."""
    import json as _json

    from ai.redact import Redactor, load_redactor
    from ai.tools import Tool, cvss_score, enrich_indicator, risk_score

    # --- Redactor: case-insensitive, longest-first, recursive, empty=inactive ---------------
    red = Redactor([("acme.local", "corp.example"), ("acme", "CLIENT-A")])
    out = red.apply("connect to ACME.local via acme account")
    assert "acme" not in out.lower(), out           # both the domain and the bare name gone
    assert "corp.example" in out and "CLIENT-A" in out, out
    obj = red.apply_obj({"host": "ACME", "list": ["x acme y", 5]})
    assert obj["host"] == "CLIENT-A" and "CLIENT-A" in obj["list"][0] and obj["list"][1] == 5, obj
    assert Redactor([]).active is False and Redactor([]).apply("HOST-REAL") == "HOST-REAL"
    # load_redactor is driven with fixture maps rather than the machine's own: asserting that the
    # developer's map is empty tests the state of a private file, and broke the day it was filled in.
    with tempfile.TemporaryDirectory() as td:
        empty_map = Path(td) / "empty.md"
        empty_map.write_text("| pseudonimo | reale |\n|---|---|\n| _(es. HOST-01)_ | _(da compilare)_ |\n",
                             encoding="utf-8")
        assert load_redactor(empty_map).active is False, "placeholders only → inactive"
        filled_map = Path(td) / "filled.md"
        filled_map.write_text("| pseudonimo | reale |\n|---|---|\n| HOST-01 | REALNAME01 |\n",
                              encoding="utf-8")
        loaded = load_redactor(filled_map)
        assert loaded.active is True, "a populated map must arm the redactor"
        assert loaded.apply("REALNAME01 rebooted") == "HOST-01 rebooted"
        assert load_redactor(Path(td) / "missing.md").active is False, "absent map → no-op"
    print("PASS  redactor: case-insensitive longest-first substitution, recursive, empty=no-op")

    # --- §14.5 property: question + context + tool result all pseudonymized before the model -
    r2 = Redactor([("HOST-REAL", "HOST-01"), ("jsmith", "USER-01")])
    leaky_tool = Tool(schema={"type": "function", "function": {"name": "t", "parameters":
                      {"type": "object", "properties": {}}}},
                      func=lambda: {"host": "HOST-REAL", "user": "jsmith"})
    client = ScriptedClient([
        {"role": "assistant", "content": "",
         "tool_calls": [{"function": {"name": "t", "arguments": {}}}]},
        {"role": "assistant", "content": "HOST-01 shows suspicious activity"},
    ])
    res = ai_engine.run("investigate HOST-REAL used by jsmith", client=client,
                        registry={"t": leaky_tool}, context="HOST-REAL ran mimikatz", redactor=r2)
    blob = _json.dumps(res.messages)
    assert "HOST-REAL" not in blob and "jsmith" not in blob, "real identifier leaked into the prompt!"
    assert "HOST-01" in blob and "USER-01" in blob, blob
    print("PASS  redaction gate: question, context and tool output reach the model pseudonymized")

    # --- scoring tools: numbers from the oracle (§6) ----------------------------------------
    cv = cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert cv["score"] == 9.8 and cv["severity"] == "Critical", cv
    assert risk_score(4, 5)["level"] == "Critical", risk_score(4, 5)
    print("PASS  scoring tools: CVSS 9.8/Critical and risk level from the oracle")

    # --- enrichment guard: a private IP is refused offline, never sent (§9) -----------------
    ref = enrich_indicator("10.0.0.5")
    assert ref.get("error") and "not sent" in ref["error"], ref
    # Second consent: even a PUBLIC indicator must not leave until the user enabled egress —
    # otherwise the model decides on its own to put traffic on the wire (§7/§15).
    import os as _os
    import tempfile as _tf
    _prev = _os.environ.get("EVENTHOUND_CONFIG")
    _os.environ["EVENTHOUND_CONFIG"] = str(Path(_tf.mkdtemp(prefix="eh-ai-cfg-")) / "config.json")
    try:
        pub = enrich_indicator("8.8.8.8")
        assert pub.get("error") and "outbound lookups are disabled" in pub["error"], pub
    finally:
        if _prev is None:
            _os.environ.pop("EVENTHOUND_CONFIG", None)
        else:
            _os.environ["EVENTHOUND_CONFIG"] = _prev
    print("PASS  enrich_indicator: private IP refused, and public indicator gated on egress consent")
    return 0


class StreamClient:
    """Fake exposing chat_stream: each scripted turn is (tokens, final_message). Exercises the
    engine's streaming path offline — token events + message assembly — with no network."""

    def __init__(self, turns: list):
        self._turns = list(turns)

    def chat_stream(self, messages, tools=None):
        tokens, final = self._turns.pop(0)
        for t in tokens:
            yield ("token", t)
        yield ("final", final)

    def chat(self, messages, tools=None):  # fallback path (not used when stream=True)
        return self._turns.pop(0)[1]


def run_stream() -> int:
    """engine.run(stream=True): tool-call turn carries no tokens, the answer turn streams them."""
    from ai.tools import default_registry
    client = StreamClient([
        ([], {"role": "assistant", "content": "",
              "tool_calls": [{"function": {"name": "eid_lookup",
                                           "arguments": {"event_id": 4624, "channel": "Security"}}}]}),
        (["Event ", "4624 ", "is a logon."],
         {"role": "assistant", "content": "Event 4624 is a logon."}),
    ])
    tokens: list = []
    res = ai_engine.run("what is 4624?", client=client, registry=default_registry(),
                        stream=True, on_event=lambda k, d: k == "token" and tokens.append(d["text"]))
    assert "".join(tokens) == "Event 4624 is a logon.", tokens
    assert res.answer == "Event 4624 is a logon.", res.answer
    assert len(res.calls) == 1 and res.calls[0].name == "eid_lookup", res.calls
    print("PASS  streaming: tool turn (no tokens) then answer streamed token-by-token")
    return 0


def _smoke_model():
    """Prefer a FAST model for the e2e smoke check so the gate stays quick and independent of
    whichever model this installation is set to. Falls back to that one, else None (skip)."""
    from ai.ollama_client import OllamaClient
    for m in ("qwen2.5:7b-instruct", "qwen2.5:7b", "llama3.1:8b"):
        if OllamaClient(model=m).unusable_reason() is None:
            return m
    c = OllamaClient()
    # `unusable_reason`, not `available`: on a host too small to LOAD the model the e2e check must
    # skip honestly, the way it already skips when the model was never pulled. Asking the weaker
    # question here is what turned a constrained machine into a red suite.
    return c.model if c.unusable_reason() is None else None


def _smoke_reason() -> str | None:
    """Why no model is usable, in the words of the gate that decided it."""
    from ai.ollama_client import OllamaClient
    return OllamaClient().unusable_reason()


def run_e2e() -> int:
    from ai.ollama_client import OllamaClient
    from ai.tools import default_registry

    model = _smoke_model()
    if not model:
        # Carry the real reason: the reserve turns this into a permanent skip on a 16 GiB host,
        # and "no model available" is false when three are pulled.
        return skip_test(f"e2e: {_smoke_reason() or 'no local Ollama model available'}")
    client = OllamaClient(model=model)
    res = ai_engine.run("In one sentence, what is MITRE ATT&CK technique T1003.001?",
                        client=client, registry=default_registry(), max_calls=4)
    assert isinstance(res.answer, str) and res.answer, "expected a non-empty answer"
    print(f"PASS  e2e: model {client.model} answered ({len(res.answer)} chars, "
          f"{len(res.calls)} tool call(s))")
    return 0


def run_memory_guard() -> int:
    """The memory preflight (tools/hostmem.py + ollama_client.memory_preflight) — DESIGN §14.9.

    Regression cover for 2026-08-28, when the suite loaded a 9.1 GiB model onto a 16 GB Mac that
    had 2.3 GiB free and swap at 92%, and took the graphical session down with it. Everything is
    driven through injected host readings: a test that asserted against the real machine would
    pass or fail depending on what the developer happened to have open.
    """
    from ai import ollama_client as oc
    from tools import hostmem

    GIB = hostmem.GIB
    real = (hostmem.total_bytes, hostmem.available_bytes, hostmem.swap_used_fraction)

    def host(total=32.0, available=20.0, swap=0.1):
        """Pin the three host readings. None means "could not measure"."""
        hostmem.total_bytes = lambda: None if total is None else int(total * GIB)
        hostmem.available_bytes = lambda: None if available is None else int(available * GIB)
        hostmem.swap_used_fraction = lambda: swap

    def client(model, size_gib=8.37, resident=False, tags=None):
        """A client whose Ollama answers are scripted, so no daemon is touched."""
        c = oc.OllamaClient(model=model)
        listed = tags if tags is not None else [{"name": model, "size": int(size_gib * GIB)}]
        c._get = lambda path, timeout=None: (  # noqa: SLF001 — pinning the transport is the point
            {"models": listed} if path == "/api/tags"
            else {"models": ([{"name": model}] if resident else [])})
        return c

    try:
        # -- the default model is the same on every host -------------------------------------
        # It used to branch on RAM. That answered the hardware question and left the quality one
        # open; the toolbench corpus answered the quality one against the 14b, so a large host gets
        # the better model too and there is nothing left for the branch to decide. The 14b stays
        # SELECTABLE — the guard below is on the load, not on the choice.
        for total in (16.0, 32.0, 128.0, None):
            host(total=total)
            assert oc.default_model() == oc.DEFAULT_MODEL, f"host RAM changed the default ({total})"
        assert oc.DEFAULT_MODEL == "qwen2.5:7b-instruct", oc.DEFAULT_MODEL

        # -- the guard fires when the model does not fit -------------------------------------
        host(total=16.0, available=2.3, swap=0.5)          # the incident's own numbers
        reason = client(oc.LARGE_MODEL).memory_preflight()
        assert reason and "2.3 GiB available" in reason, f"expected a refusal, got {reason!r}"

        # -- and stays out of the way when it does -------------------------------------------
        host(total=32.0, available=20.0, swap=0.1)
        assert client(oc.LARGE_MODEL).memory_preflight() is None, "20 GiB free must pass"

        # -- swap pressure REPORTS, it does not decide -------------------------------------
        # It was a gate, and the reference machine falsified the premise: macOS grows the swapfile
        # on demand, so `used/total` sits near its ceiling on any host that has ever paged, and the
        # gate refused every RAG query until reboot. It was never load-bearing either — the incident
        # had 2.3 GiB available against a 2.4 GiB reserve, which the memory check alone refuses.
        host(total=24.0, available=18.0, swap=0.92)
        assert client(oc.LARGE_MODEL).memory_preflight() is None, \
            "swap alone must not refuse a load the memory comparison allows"
        host(total=16.0, available=1.0, swap=0.92)
        reason = client(oc.LARGE_MODEL).memory_preflight()
        assert reason and "swap is 92% full" in reason, \
            f"swap belongs in the refusal as context: {reason!r}"

        # -- the shared module may be absent, and that must not stop the module LOADING ------
        # The Docker image builds with context ./analysis and carries no tools/, so a bare
        # `from tools import hostmem` raised at import — gui/app.py imports this at module scope,
        # and the container crash-looped. No hostmem means no guard, the same fail-open as any
        # other unmeasurable input.
        saved = oc.hostmem
        try:
            oc.hostmem = None
            assert oc.default_model() == oc.DEFAULT_MODEL, "no hostmem: keep the documented default"
            assert client(oc.LARGE_MODEL).memory_status()[0] == "unknown"
            assert client(oc.LARGE_MODEL).memory_preflight() is None, "must fail open"
        finally:
            oc.hostmem = saved

        # -- the reserve needs a ceiling as well as a floor ---------------------------------
        # 15% uncapped reserved 19.2 GiB on a 128 GiB server and refused a 9.6 GiB model that had
        # 25 GiB of room. Neither the OS's needs nor the estimate's optimism scale with installed
        # RAM.
        host(total=128.0, available=25.0, swap=0.1)
        assert client(oc.LARGE_MODEL).memory_preflight() is None, \
            "a 128 GiB host with 25 GiB free must not refuse a 9.6 GiB model"
        host(total=4.0, available=3.0, swap=0.1)
        assert hostmem.reserve_bytes() == hostmem.RESERVE_FLOOR, "the floor still applies below it"

        # -- residency must be EXACT, or the untagged safety never runs ---------------------
        # `qwen2.5` reported "already loaded" because qwen2.5:7b-instruct was resident, while chat
        # sends the untagged string and Ollama resolves it to :latest — a different, unloaded blob.
        host(total=16.0, available=1.0, swap=0.1)
        c = oc.OllamaClient(model="qwen2.5")
        c._get = lambda path, timeout=None: (
            {"models": [{"name": "qwen2.5:14b", "size": int(8.37 * GIB)}]} if path == "/api/tags"
            else {"models": [{"name": "qwen2.5:7b-instruct"}]})
        state, msg = c.memory_status()
        assert state == "refuse", f"a loose residency match disabled the guard: {state} {msg}"

        # -- "cannot tell" must not be reported as "not loaded" -----------------------------
        def _ps_down(path, timeout=None):
            if path == "/api/ps":
                raise oc.OllamaError("probe timed out")
            return {"models": [{"name": oc.LARGE_MODEL, "size": int(8.37 * GIB)}]}
        c = oc.OllamaClient(model=oc.LARGE_MODEL)
        c._get = _ps_down
        assert c.memory_status()[0] == "unknown", \
            "a failed /api/ps refused a load that may never have happened"
        assert c.memory_preflight() is None, "must fail open when residency cannot be determined"

        # -- sys.path must not grow per client; the GUI builds one per request --------------
        import sys as _sys
        before = len(_sys.path)
        for _ in range(25):
            oc.OllamaClient()
        assert len(_sys.path) == before, f"sys.path grew by {len(_sys.path) - before} entries"

        # -- fails OPEN on every unmeasurable input ------------------------------------------
        # An engine grounded because vm_stat could not be parsed is a worse outage than the crash.
        host(total=None, available=None, swap=None)
        assert client(oc.LARGE_MODEL).memory_preflight() is None, "must proceed when blind"
        host(total=16.0, available=1.0, swap=0.99)
        c = client(oc.LARGE_MODEL, tags=[])   # size unknown → nothing to compare against
        assert c.memory_preflight() is None, "unknown model size must not block"
        assert c.memory_status()[0] == "unknown", "an unmeasurable size must not read as 'ok'"

        # -- a resident model is not about to be allocated -----------------------------------
        host(total=16.0, available=1.0, swap=0.99)
        assert client(oc.LARGE_MODEL, resident=True).memory_preflight() is None, \
            "a loaded model must not be blocked mid-conversation"

        # -- the operator can override -------------------------------------------------------
        import os
        os.environ["EVENTHOUND_ALLOW_LOW_MEMORY"] = "1"
        try:
            assert client(oc.LARGE_MODEL).memory_preflight() is None, "override ignored"
        finally:
            del os.environ["EVENTHOUND_ALLOW_LOW_MEMORY"]

        # -- the remedy must be actionable, and must never advise a BIGGER load ---------------
        # R6: the suggestion used to be gated on `model != DEFAULT_MODEL`, which was sound while
        # the default was the larger of two. Once the default became the smallest NAMED model it
        # stopped being the smallest possible one, and a refused 1.2 GiB model was answered with
        # "use qwen2.5:7b-instruct" — 3.5x the load that had just been declined.
        host(total=16.0, available=1.0, swap=0.1)
        both = [{"name": oc.DEFAULT_MODEL, "size": int(4.36 * GIB)},
                {"name": oc.LARGE_MODEL, "size": int(8.37 * GIB)}]
        reason = client(oc.DEFAULT_MODEL, tags=both).memory_preflight()
        assert reason and f"EVENTHOUND_LLM_MODEL={oc.DEFAULT_MODEL}" not in reason, \
            "must not suggest the model that just failed as its own remedy"
        reason14 = client(oc.LARGE_MODEL, tags=both).memory_preflight()
        assert "EVENTHOUND_LLM_MODEL" in reason14 and "EVENTHOUND_ALLOW_LOW_MEMORY" in reason14, \
            "environment variables must keep their case — they are case-sensitive"
        tiny = [{"name": "llama3.2:1b", "size": int(1.2 * GIB)},
                {"name": oc.DEFAULT_MODEL, "size": int(4.36 * GIB)}]
        reason_tiny = client("llama3.2:1b", tags=tiny).memory_preflight()
        assert reason_tiny and "EVENTHOUND_LLM_MODEL" not in reason_tiny, \
            f"recommended a LARGER model to a host that just ran out of memory: {reason_tiny}"
        # and when the default's size cannot be measured, silence rather than a guess
        solo = client(oc.LARGE_MODEL, tags=[{"name": oc.LARGE_MODEL, "size": int(8.37 * GIB)}])
        assert "EVENTHOUND_LLM_MODEL" not in (solo.memory_preflight() or ""), \
            "suggested a swap it could not show to be an improvement"

        # -- R6: "fits" and "could not measure" must not collapse into one green answer ------
        # `memory_preflight` answers None for both, which is correct as behaviour and was rendered
        # by `setup.sh doctor` as "host can load <model>" — so a fresh install, where the model is
        # not pulled and has no measurable size, asserted the opposite of the truth.
        host(total=32.0, available=20.0, swap=0.1)
        assert client(oc.LARGE_MODEL).memory_status()[0] == "ok"
        host(total=16.0, available=1.0, swap=0.1)
        assert client(oc.LARGE_MODEL).memory_status()[0] == "refuse"
        host(total=32.0, available=None, swap=0.1)
        assert client(oc.LARGE_MODEL).memory_status()[0] == "unknown", \
            "unmeasurable free memory must be 'unknown', never 'ok'"

        # -- R6: the reserve. Availability alone cleared loads this host could not survive, because
        # the macOS estimate is dominated by inactive pages a full compressor cannot release.
        host(total=16.0, available=10.0, swap=0.1)     # 10 > 9.63 need, but reserve is 2.4
        reason = client(oc.LARGE_MODEL).memory_preflight()
        assert reason and "reserved" in reason, f"reserve not applied: {reason!r}"

        # -- R6: a failed measurement must NOT be cached, or the guard dies for the client's life
        host(total=16.0, available=1.0, swap=0.1)
        c = oc.OllamaClient(model=oc.LARGE_MODEL)
        state = {"pulled": False}
        c._get = lambda path, timeout=None: (
            {"models": ([{"name": oc.LARGE_MODEL, "size": int(8.37 * GIB)}]
                        if state["pulled"] else [])} if path == "/api/tags" else {"models": []})
        assert c.memory_preflight() is None, "size unknown before the pull: must fail open"
        state["pulled"] = True
        assert c.memory_preflight(), "the guard stayed dead after the model was pulled"

        # -- R6: an untagged name must size against the LARGEST match, not the first listed
        host(total=64.0, available=60.0, swap=0.1)
        both = [{"name": "qwen2.5:7b-instruct", "size": int(4.36 * GIB)},
                {"name": "qwen2.5:14b", "size": int(8.37 * GIB)}]
        for order in (both, list(reversed(both))):
            assert client("qwen2.5", tags=order)._model_bytes() == int(8.37 * GIB), \
                "response order decided the budget; ambiguity must resolve upward"

        # -- the guard sits at the choke point, before any request goes out ------------------
        host(total=16.0, available=1.0, swap=0.1)
        c = client(oc.LARGE_MODEL)
        posted = []
        c._post = lambda path, payload: posted.append(path) or {}
        for call in (lambda: c.chat([{"role": "user", "content": "hi"}]),
                     lambda: list(c.chat_stream([{"role": "user", "content": "hi"}]))):
            try:
                call()
                raise AssertionError("expected OllamaError before the model was loaded")
            except oc.OllamaError as e:
                assert "refusing to load" in str(e), f"unexpected error: {e}"
        assert not posted, "the guard must refuse BEFORE issuing the request, not after"
    finally:
        hostmem.total_bytes, hostmem.available_bytes, hostmem.swap_used_fraction = real

    print("PASS  memory guard: one default on every host, load refused when it would not fit")
    return 0


def run_model_setting() -> int:
    """The model the engine talks to: environment, then the stored choice, then the default.

    This is the third attempt at the same line and the second defect in it. The setting existed and
    nothing read it; `70483b8` "connected" it by reading `load().get("llm_model")` while the store
    keeps settings under `data["settings"]`, so the lookup returned None and the field stayed as
    dead as before — with a docstring describing a precedence chain the code did not have. Asserted
    against a throwaway store, not the operator's own, and through the store's public accessors so
    the test cannot re-implement the bug it exists to catch."""
    import importlib
    import os
    import shutil
    import tempfile
    from pathlib import Path

    from ai import ollama_client as oc

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
    import eventhound_config as cfg

    tmpdir = Path(tempfile.mkdtemp())
    tmp = tmpdir / "config.json"
    saved_cfg = os.environ.get("EVENTHOUND_CONFIG")
    saved_env = os.environ.get("EVENTHOUND_LLM_MODEL")
    os.environ["EVENTHOUND_CONFIG"] = str(tmp)
    os.environ.pop("EVENTHOUND_LLM_MODEL", None)
    try:
        importlib.reload(cfg)   # config_path() reads the environment at call time, but be explicit
        assert oc.configured_model() == oc.DEFAULT_MODEL, "an empty store must give the default"

        cfg.set_setting("llm_model", oc.LARGE_MODEL)
        assert cfg.get_setting("llm_model") == oc.LARGE_MODEL, "the store did not keep the value"
        assert oc.configured_model() == oc.LARGE_MODEL, (
            "the stored model is ignored — the setting is inert again, which is the whole defect")
        assert oc.OllamaClient().model == oc.LARGE_MODEL, "the client did not take the stored model"

        # the environment is an intentional one-off override and still wins
        os.environ["EVENTHOUND_LLM_MODEL"] = "someone-elses:model"
        assert oc.configured_model() == "someone-elses:model", "the environment must win"
        del os.environ["EVENTHOUND_LLM_MODEL"]

        # clearing it returns to the default rather than to an empty model name
        cfg.set_setting("llm_model", "")
        assert oc.configured_model() == oc.DEFAULT_MODEL, "an empty choice must fall back"
    finally:
        for key, val in (("EVENTHOUND_CONFIG", saved_cfg), ("EVENTHOUND_LLM_MODEL", saved_env)):
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        importlib.reload(cfg)
        shutil.rmtree(tmpdir, ignore_errors=True)   # the GUI test cleans up after itself; so does this

    print("PASS  model setting: stored choice honoured, environment still wins, empty falls back")
    return 0


def run() -> int:
    run_synthetic()
    run_step2()
    run_step3()
    run_stream()
    run_memory_guard()
    run_model_setting()
    run_e2e()
    return 0


def test_ai():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
