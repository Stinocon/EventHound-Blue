"""Test of the local GUI (Phase 3) via FastAPI TestClient.

- /api/health always responds.
- /api/analyze: streams Server-Sent Events (progress + a final `complete` event); the test parses
  the stream and checks the `complete` payload (summary + sections). If tshark is present it also
  runs a synthetic PCAP; otherwise that part is skipped (like the other engine tests).
Run: uv run python tests/test_gui.py
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

GUI_DIR = Path(__file__).resolve().parents[1]
ANALISI_DIR = GUI_DIR.parent
sys.path.insert(0, str(GUI_DIR))
sys.path.insert(0, str(ANALISI_DIR))

from fastapi.testclient import TestClient  # noqa: E402

import app as gui_app  # noqa: E402


def _sse_complete(text: str) -> dict:
    """Parse an SSE stream body and return the data payload of the `complete` event.

    Raises AssertionError on an `error` event or if no `complete` event is present."""
    event, data_parts = None, []
    for line in text.splitlines():
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data_parts.append(line[5:].lstrip())
        elif line == "":
            if event == "error" and data_parts:
                raise AssertionError("stream error: " + "".join(data_parts))
            if event == "complete" and data_parts:
                return json.loads("".join(data_parts))
            event, data_parts = None, []
    if event == "complete" and data_parts:
        return json.loads("".join(data_parts))
    raise AssertionError(f"no 'complete' event in SSE stream: {text[:300]!r}")


def run() -> int:
    import os as _os

    # Every /api/analyze now lands in a case (an analysis that does not accumulate cannot correlate
    # with the next upload), which means this suite writes to the case root on almost every call.
    # It is therefore redirected for the WHOLE run — EVENTHOUND_CASES_DIR is read fresh on every
    # case_store call, never cached at import — so nothing under the real analysis/cases/ is
    # touched. Scoped here rather than around the case block alone, which is what let earlier runs
    # leave two real cases behind.
    _cases_root = Path(tempfile.mkdtemp(prefix="eh-cases-"))
    _os.environ["EVENTHOUND_CASES_DIR"] = str(_cases_root)
    try:
        return _run(TestClient(gui_app.app))
    finally:
        _os.environ.pop("EVENTHOUND_CASES_DIR", None)
        shutil.rmtree(_cases_root, ignore_errors=True)


def _run(client) -> int:

    h = client.get("/api/health").json()
    assert (h.get("status") == "ok" and "hayabusa" in h and "tshark" in h and "evtxecmd" in h), \
        f"unexpected health: {h}"

    # Route registration guard: FastAPI serves only the FIRST @app.<verb> registered for a given
    # (method, path) — a later duplicate is silently unreachable, and nothing else in this suite
    # would notice. This caught twelve routes registered twice at once (a 278-line dead block).
    from fastapi.routing import APIRoute
    seen: set[tuple[str, str]] = set()
    dupes: list[tuple[str, str]] = []
    for route in gui_app.app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods:
            key = (method, route.path)
            if key in seen:
                dupes.append(key)
            seen.add(key)
    assert not dupes, f"route(s) registered twice — the later copy is dead code: {dupes}"
    print(f"PASS  gui: no (method, path) registered twice across {len(seen)} routes")

    # invalid extension -> clean 400, with per-file reason in the errors array
    r = client.post("/api/analyze", files={"files": ("x.bin", b"\x00\x01", "application/octet-stream")})
    assert r.status_code == 400, f"expected 400 on invalid extension, got {r.status_code}"
    body = r.json()
    errs = body.get("errors", [])
    assert any("unsupported extension" in e for e in errs), (
        f"the 400 must report the rejected extension per-file, not just the empty list: {body}"
    )

    # log analysis (no external tool): synthetic access log -> 200 + web recipes + report
    access = ('203.0.113.5 - - [16/Jul/2026:06:28:59 +0200] "GET /wsproxy HTTP/1.1" 101 10 "-" -\n'
              '203.0.113.9 - - [16/Jul/2026:06:29:00 +0200] "POST /rollbackConfirm.action HTTP/1.1" 500 12 "-" -\n')
    r = client.post("/api/analyze", files={"files": ("extraweb_access.log", access.encode(), "text/plain")})
    assert r.status_code == 200, f"analyze log failed: {r.status_code} {r.text[:200]}"
    d = _sse_complete(r.text)
    assert d["summary"]["events"] == 2 and d["_meta"]["logs"] == 1, d.get("_meta")
    assert any(row["src_ip"] == "203.0.113.5" for row in d.get("top_source_ips", [])), d.get("top_source_ips")
    # this dataset has no ATT&CK/Sigma/THOR detections, only a bare HTTP 500 — the timeline's
    # salience filter still surfaces it as a "failed action" and drops the non-notable 101 line,
    # so `why` is never empty even without a formal detection
    timeline = d.get("timeline", [])
    assert timeline, "timeline must not be empty"
    assert all(row.get("why") for row in timeline), timeline
    assert any(row["why"] == "failed action" for row in timeline), timeline
    # the report is generated from the result without re-parsing the files (log-only: no ATT&CK
    # chart, but the web tables and the privacy banner are there)
    rep = client.post("/api/report", json={"data": d})
    assert rep.status_code == 200 and "/wsproxy" in rep.text and "Analysis report" in rep.text, rep.status_code

    # Config store: a key saved from the GUI must be readable by the CLI side, and must NEVER come
    # back out of the API in usable form (masked hint only).
    import os as _os
    import tempfile as _tf
    _cfg_path = Path(_tf.mkdtemp(prefix="eh-cfg-")) / "config.json"
    _prev_env = {k: _os.environ.get(k) for k in ("EVENTHOUND_CONFIG", "VT_API_KEY",
                                                 "EVENTHOUND_LLM_MODEL")}
    _os.environ["EVENTHOUND_CONFIG"] = str(_cfg_path)
    _os.environ.pop("VT_API_KEY", None)
    try:
        cfg = client.get("/api/config").json()
        assert any(s["service"] == "virustotal" for s in cfg["services"]), cfg
        assert all(not s["configured"] for s in cfg["services"]), "fresh config must be empty"
        r = client.post("/api/config", json={"service": "virustotal", "key": "SECRETKEY1234wxyz"})
        assert r.status_code == 200, r.text[:200]
        assert "SECRETKEY1234wxyz" not in r.text, "the API echoed the key back"
        vt = [s for s in r.json()["services"] if s["service"] == "virustotal"][0]
        assert vt["configured"] and vt["hint"] == "…wxyz" and vt["source"] == "config", vt
        # The CLI/tool side reads the same store — this is the whole point of the feature.
        _cfgmod = gui_app._config_mod()
        assert _cfgmod.get_api_key("virustotal") == "SECRETKEY1234wxyz", "CLI side cannot see the GUI key"
        assert _os.stat(_cfg_path).st_mode & 0o077 == 0, "config file must not be group/world readable"
        # An env var must win over the stored value, and be reported as such.
        _os.environ["VT_API_KEY"] = "ENVKEY0000abcd"
        assert _cfgmod.get_api_key("virustotal") == "ENVKEY0000abcd", "env override ignored"
        vt = [s for s in client.get("/api/config").json()["services"] if s["service"] == "virustotal"][0]
        assert vt["source"] == "environment" and vt["overridden_by_env"], vt
        _os.environ.pop("VT_API_KEY", None)
        # Unknown service is a 400, not a silent write.
        assert client.post("/api/config", json={"service": "nope", "key": "x"}).status_code == 400
        assert client.post("/api/config", json={"setting": "allow_egress", "value": True}).status_code == 200
        assert _cfgmod.get_setting("allow_egress") is True
        client.post("/api/config", json={"service": "virustotal", "key": ""})
        assert _cfgmod.get_api_key("virustotal") is None, "clearing the key did not work"
        print("PASS  gui: /api/config — GUI↔CLI shared store, masked output, env override, 0600")

        # The Assistant's model picker is the PERSISTENT setting, not a per-request override: the
        # choice has to reach the same store the CLI reads. `llm_model` was offered and read by
        # nothing, then "connected" through the wrong key and read by nothing again — so what this
        # asserts is the round trip, GUI in, engine out, not that a value was written somewhere.
        from ai import ollama_client as _oc
        _os.environ.pop("EVENTHOUND_LLM_MODEL", None)
        r = client.post("/api/ai/model", json={"model": _oc.LARGE_MODEL})
        assert r.status_code == 200, r.text[:200]
        body = r.json()
        assert body["model"] == _oc.LARGE_MODEL, body
        # The verdict travels with the choice — a large model on a small host is a refusal, and the
        # moment to say so is at the choice, not three seconds into a streamed answer. Which of the
        # four it is depends on the machine running the suite, so the contract is what is pinned.
        assert body.get("state") in ("ok", "unknown", "refuse", "missing"), body
        assert body.get("message"), "a verdict with no explanation is not a verdict"
        assert _cfgmod.get_setting("llm_model") == _oc.LARGE_MODEL, "the choice was not stored"
        assert _oc.configured_model() == _oc.LARGE_MODEL, "the engine does not see the GUI choice"
        listed = client.get("/api/ai/models").json()
        assert listed["selected"] == _oc.LARGE_MODEL, listed
        assert _oc.LARGE_MODEL in listed["models"], (
            "the selected model must be listed even when it is not pulled — a picker that drops "
            f"the analyst's own choice is how a setting looks broken: {listed}")
        # A model name is validated BEFORE it is stored. The value is handed to Ollama, echoed
        # into the picker and interpolated into $MODEL by setup.sh/uninstall.sh, so a field that
        # accepts a quote, a newline or 10 KB of text is one the rest of the product defends
        # against forever.
        for _bad in ('x" onfocus="alert(1)', "<img src=x onerror=alert(1)>", "a\nb",
                     "$(id); rm -rf /tmp/zz", "../../etc/passwd", "x" * 200):
            _r = client.post("/api/ai/model", json={"model": _bad})
            assert _r.status_code == 400, f"stored a name it should have refused: {_bad!r}"
        assert client.post("/api/ai/model", json={"model": 12345}).status_code == 400
        assert _cfgmod.get_setting("llm_model") == _oc.LARGE_MODEL, \
            "a refused name must not disturb the stored one"
        # ...and clearing it returns the engine to the default rather than to an empty model name.
        # A blank field is a CLEAR, not a malformed name: whitespace-only means the same thing.
        assert client.post("/api/ai/model", json={"model": "  "}).status_code == 200
        assert _cfgmod.get_setting("llm_model") == "", "whitespace did not clear the choice"
        assert client.post("/api/ai/model", json={"model": ""}).status_code == 200
        assert _oc.configured_model() == _oc.DEFAULT_MODEL, "clearing the choice did not fall back"
        print("PASS  gui: /api/ai/model — the picker persists to the store the CLI reads")
    finally:
        # RESTORE, not pop. This block clears EVENTHOUND_LLM_MODEL to test the fallback, and
        # popping it unconditionally stripped the operator's own pin from every later test in the
        # process — including the /api/ai/chat smoke turn below, which then ran on a different
        # model than the one the environment asked for.
        for _k, _v in _prev_env.items():
            _os.environ.pop(_k, None) if _v is None else _os.environ.__setitem__(_k, _v)
        shutil.rmtree(_cfg_path.parent, ignore_errors=True)

    # ATT&CK map: served from the engine's own file, so the UI and the analysis agree on names
    am = client.get("/api/attack-map")
    assert am.status_code == 200, am.status_code
    amj = am.json()
    assert amj["techniques"]["T1003.001"]["name"] == "LSASS Memory", amj["techniques"].get("T1003.001")
    assert "credential-access" in amj["techniques"]["T1003.001"]["tactics"], amj["techniques"]["T1003.001"]
    print(f"PASS  gui: /api/attack-map (ATT&CK v{amj.get('_attack_version')}, {len(amj['techniques'])} techniques)")

    # bundle format: the same endpoint returns the re-importable snapshot, not a rendering —
    # version stamped, analysis verbatim, and it must round-trip back through engine/bundle.py
    bun = client.post("/api/report", json={"data": d, "format": "bundle", "name": "gui-case"})
    assert bun.status_code == 200, f"bundle export failed: {bun.status_code}"
    assert "bundle-gui-case.json" in bun.headers.get("content-disposition", ""), bun.headers
    parsed = json.loads(bun.text)
    assert parsed["bundle_version"] == 1 and parsed["tool_version"] == gui_app.APP_VERSION, parsed.get("tool_version")
    assert parsed["analysis"]["summary"]["events"] == 2, parsed["analysis"].get("summary")
    from engine import bundle as _bundle  # noqa: PLC0415 — only needed here
    assert _bundle.loads(parsed)["analysis"]["summary"]["events"] == 2, "GUI bundle rejected by the engine loader"
    print("PASS  gui: bundle export (/api/report format=bundle) round-trips through engine/bundle")

    # Content-Disposition filename: `name` is a client-supplied JSON field (§8) interpolated into a
    # response header. A quote/CRLF/path segment there is a header/filename injection, latent today
    # only because the front-end happens to always send "analysis".
    hostile_name = 'evil"name\r\nX-Injected: 1\r\n../../etc/passwd'
    rep2 = client.post("/api/report", json={"data": d, "format": "json", "name": hostile_name})
    assert rep2.status_code == 200, rep2.status_code
    cd = rep2.headers.get("content-disposition", "")
    assert "\r" not in cd and "\n" not in cd, f"CRLF survived into the header: {cd!r}"
    fname = cd.split('filename="', 1)[1].rstrip('"')
    assert re.fullmatch(r"report-[A-Za-z0-9._-]+\.json", fname), f"filename not restricted to a safe basename: {fname!r}"
    # An input that sanitises to nothing (only characters the regex strips) falls back, not to "".
    assert gui_app._safe_filename_stem("") == "analysis"
    assert gui_app._safe_filename_stem('"""///\r\n') == "analysis"
    print("PASS  gui: /api/report Content-Disposition sanitises a hostile `name` (quote/CRLF/path)")

    # Cases (analytics/case_store.py): create/list/get/note/delete, plus /api/analyze `case=`
    # persistence. Isolated under a scratch root — EVENTHOUND_CASES_DIR is read fresh on every
    # case_store call (not cached at import), so setting it here (like EVENTHOUND_CONFIG above) is
    # enough; nothing under the real analysis/cases/ is ever touched.
    try:
        r = client.post("/api/cases", json={"id": "test-case-1", "title": "Test Case"})
        assert r.status_code == 200, r.text[:200]
        meta = r.json()
        assert meta["id"] == "test-case-1" and meta["record_count"] == 0, meta

        lst = client.get("/api/cases").json()
        c0 = [c for c in lst["cases"] if c["id"] == "test-case-1"]
        assert c0 and "size_mb" in c0[0], lst

        # invalid id -> 400, not 500 (§8: a case id from the browser is untrusted input)
        r = client.post("/api/cases", json={"id": "../escape"})
        assert r.status_code == 400, f"expected 400 on invalid case id, got {r.status_code}: {r.text[:200]}"

        # missing case -> 404
        r = client.get("/api/cases/does-not-exist")
        assert r.status_code == 404, f"expected 404 on missing case, got {r.status_code}"

        # analyze with case= persists the FULL record set server-side (reuses the tiny access-log
        # fixture from the /api/analyze test above)
        r = client.post("/api/analyze", data={"case": "test-case-2"},
                        files={"files": ("extraweb_access.log", access.encode(), "text/plain")})
        assert r.status_code == 200, f"analyze with case failed: {r.status_code} {r.text[:200]}"
        d2 = _sse_complete(r.text)
        assert not d2["_meta"].get("case_error"), d2["_meta"]
        lst = client.get("/api/cases").json()
        c2 = [c for c in lst["cases"] if c["id"] == "test-case-2"]
        assert c2 and c2[0]["record_count"] == d2["summary"]["events"] > 0, (c2, d2.get("summary"))

        # Re-sending the exact same batch to the same case is refused by case_store.append (a
        # sha256 signature collision), and the GUI does this routinely — it re-sends every
        # accumulated file on each Analyze click. The surfaced case_error must name what was
        # refused and why, not just the exception type: `_meta.case_error` used to read
        # "case persistence failed (CaseError)", telling the analyst nothing about the silent
        # degrade to in-memory analysis.
        r = client.post("/api/analyze", data={"case": "dup-guard"},
                        files={"files": ("dup.log", access.encode(), "text/plain")})
        assert r.status_code == 200, r.text[:200]
        assert not _sse_complete(r.text)["_meta"].get("case_error")
        r = client.post("/api/analyze", data={"case": "dup-guard"},
                        files={"files": ("dup.log", access.encode(), "text/plain")})
        assert r.status_code == 200, r.text[:200]
        case_error = _sse_complete(r.text)["_meta"].get("case_error")
        assert case_error, "expected a case_error on re-adding an identical batch"
        assert "already added" in case_error and "dup-guard" in case_error, case_error
        assert case_error != "case persistence failed (CaseError)", (
            "the message was reduced to the exception type again")
        print("PASS  gui: /api/analyze surfaces the CaseError message, not just its type, in _meta.case_error")

        # The arithmetic the browser's pendingFiles() depends on, and the hazard it exists for.
        # Incremental sends — one file per click, the sequence an analyst actually performs — must
        # add up exactly.
        one = access
        two = access.replace("203.0.113.5", "203.0.113.7").replace("203.0.113.9", "203.0.113.8")
        r = client.post("/api/analyze", data={"case": "inc-1"},
                        files={"files": ("first.log", one.encode(), "text/plain")})
        n1 = _sse_complete(r.text)["summary"]["events"]
        r = client.post("/api/analyze", data={"case": "inc-1"},
                        files={"files": ("second.log", two.encode(), "text/plain")})
        d5 = _sse_complete(r.text)
        assert not d5["_meta"].get("case_error"), d5["_meta"]
        assert d5["summary"]["events"] == n1 * 2, (n1, d5["summary"]["events"])

        # And the hazard: an OVERLAPPING batch is not refused, because the signature is taken over
        # the whole batch. "first.log", then "first.log + second.log" — which is what the GUI sent
        # on every click before static/lib.js pendingFiles() — persists first.log twice and inflates
        # every additive number with nothing on screen saying so. Pinned here because the guard is
        # client-side: if this ever starts passing, the store learned to catch it and the browser's
        # bookkeeping could be reconsidered.
        r = client.post("/api/analyze", data={"case": "inc-2"},
                        files={"files": ("first.log", one.encode(), "text/plain")})
        assert not _sse_complete(r.text)["_meta"].get("case_error")
        r = client.post("/api/analyze", data={"case": "inc-2"},
                        files=[("files", ("first.log", one.encode(), "text/plain")),
                               ("files", ("second.log", two.encode(), "text/plain"))])
        d6 = _sse_complete(r.text)
        assert not d6["_meta"].get("case_error"), (
            "the store now refuses an overlapping batch: revisit pendingFiles()")
        assert d6["summary"]["events"] == n1 * 3, (
            f"expected the documented over-count (3x{n1}), got {d6['summary']['events']}")
        print("PASS  gui: incremental sends add up; an overlapping batch double-counts "
              "(guarded in the browser by pendingFiles)")

        # /api/services — asked, never asserted. Settings used to print three fixed sentences
        # about the RAG whatever the machine was doing, and had no row at all for the two most
        # fragile pieces (Qdrant, Ollama). The contract that matters here is that every service
        # reports a state from the closed set and a detail an analyst can act on: a probe that
        # cannot tell must say `unknown`, never a green it did not establish.
        r = client.get("/api/services")
        assert r.status_code == 200, r.text[:200]
        svc = r.json()
        assert set(svc) == {"qdrant", "rag_api", "ollama"}, sorted(svc)
        for name, entry in svc.items():
            assert entry["state"] in ("up", "down", "unknown"), (name, entry)
            assert entry["detail"], f"{name} reported a state with no reason"
            assert entry["required"] is False, name
        print("PASS  gui: /api/services probes Qdrant, rag-api and Ollama with a reason each")

        r = client.get("/api/cases/test-case-2")
        assert r.status_code == 200, r.text[:200]
        opened = r.json()
        assert opened["summary"]["events"] == d2["summary"]["events"], (opened.get("summary"), d2.get("summary"))

        # note round-trips
        r = client.post("/api/cases/test-case-1/note", json={"text": "checked, nothing found"})
        assert r.status_code == 200, r.text[:200]
        assert r.json()["notes"][-1]["text"] == "checked, nothing found", r.json()

        # empty note -> 400
        r = client.post("/api/cases/test-case-1/note", json={"text": "   "})
        assert r.status_code == 400, f"expected 400 on empty note, got {r.status_code}"

        # delete removes it
        r = client.delete("/api/cases/test-case-1")
        assert r.status_code == 200 and r.json()["deleted"] == "test-case-1", r.text[:200]
        assert client.get("/api/cases/test-case-1").status_code == 404

        # Content-sniff routing: an Okta export and a YARA rule uploaded with the evidence must
        # reach their own adapters. Before this, an Okta `.json` fell through to the generic log
        # adapter — which reads top-level keys only, so the actor, the client address and the
        # outcome vanished — and a `.yar` was rejected outright as an unsupported extension.
        sys.path.insert(0, str(ANALISI_DIR))
        from demo import scenario as _scenario
        _demo_dir = Path(tempfile.mkdtemp(prefix="eh-demo-src-"))
        try:
            _plan = _scenario.generate(_demo_dir)["build_records"]
            okta_bytes = Path(_plan["okta"][0]).read_bytes()
            rules_bytes = (Path(_plan["yara"][0]["rules"]) / "eventhound_demo.yar").read_bytes()
            target_bytes = Path(_plan["yara"][0]["target"]).read_bytes()

            r = client.post("/api/analyze", data={"no_case": "true"}, files=[
                ("files", ("okta_system_log.json", okta_bytes, "application/json")),
            ])
            assert r.status_code == 200, r.text[:300]
            dm = _sse_complete(r.text)["_meta"]
            assert dm["okta"] == 1 and dm["logs"] == 0, dm

            # A rule plus the file it matches: the rule is held aside and applied to the evidence,
            # which is what an analyst uploading both plainly means.
            if shutil.which("yara") or True:
                r = client.post("/api/analyze", data={"no_case": "true"}, files=[
                    ("files", ("eventhound_demo.yar", rules_bytes, "text/plain")),
                    ("files", ("svcupdate.exe", target_bytes, "application/octet-stream")),
                ])
                # yara-python is not in the GUI venv; the pairing must still be attempted and the
                # absence reported rather than the rule being rejected as an unknown extension.
                assert r.status_code == 200, r.text[:300]
                ym = _sse_complete(r.text)["_meta"]
                assert ym["yara"] == 1, ym
                assert not any("unsupported extension" in e for e in ym["errors"]), ym["errors"]
        finally:
            shutil.rmtree(_demo_dir, ignore_errors=True)

        # The attack map, rendered server-side from a result the browser already holds. Asserting
        # an edge exists first is what stops the rest from passing on an empty picture — a map of
        # nothing renders perfectly well.
        r = client.post("/api/cases/demo")
        assert r.status_code == 200, r.text[:200]
        demo_result = client.get("/api/cases/demo").json()
        assert (demo_result.get("entity_graph") or {}).get("edges"), "no entity edges to map"
        r = client.post("/api/map", json={"data": demo_result})
        assert r.status_code == 200, r.text[:300]
        mp = r.json()
        assert not mp["empty"] and mp["nodes"] > 0, mp
        assert "<svg" in mp["html"] and "am-story" in mp["html"], mp["html"][:300]
        # Self-contained, like every other rendered surface: no CDN, no remote font, no script.
        assert "http://" not in mp["html"] and "https://" not in mp["html"], "external resource in the map"
        assert "<script" not in mp["html"].lower(), "the map fragment carries a script"

        # An analysis with nothing linked must say so rather than draw an empty frame.
        r = client.post("/api/map", json={"data": {"entity_graph": {"nodes": []}}})
        assert r.status_code == 200 and r.json()["empty"], r.text[:200]

        # Analysis with NO case named: the server must mint one and say which, because that id is
        # what the browser sends back on the next upload. If this ever returns nothing, every upload
        # starts a fresh store and nothing correlates with anything — the exact default the
        # always-on case was built to remove.
        r = client.post("/api/analyze",
                        files={"files": ("extraweb_access.log", access.encode(), "text/plain")})
        assert r.status_code == 200, r.text[:200]
        minted = _sse_complete(r.text)["_meta"].get("case")
        assert minted and minted.startswith("case-"), f"no case minted: {minted!r}"

        # ...and sending it back accumulates instead of starting over.
        r = client.post("/api/analyze", data={"case": minted},
                        files={"files": ("other.log", (access + "\n" + access).encode(), "text/plain")})
        d3 = _sse_complete(r.text)
        assert d3["_meta"]["case"] == minted, d3["_meta"]
        lst = {c["id"]: c for c in client.get("/api/cases").json()["cases"]}
        assert len(lst[minted]["sources"]) == 2, lst[minted]["sources"]

        # The opt-out is the only way back to a one-off look, and it must leave nothing behind.
        before = set(lst)
        r = client.post("/api/analyze", data={"no_case": "true"},
                        files={"files": ("solo.log", access.encode(), "text/plain")})
        d4 = _sse_complete(r.text)
        assert d4["_meta"].get("case") is None, d4["_meta"]
        after = {c["id"] for c in client.get("/api/cases").json()["cases"]}
        assert after == before, after - before

        # Infrastructure addresses: declared, never inferred. Rejecting a hostname matters — a
        # silently ignored entry would read as "declared" while changing nothing.
        r = client.post(f"/api/cases/{minted}/infrastructure", json={"ips": ["10.10.10.1", "10.10.10.1"]})
        assert r.status_code == 200 and r.json()["infrastructure_ips"] == ["10.10.10.1"], r.text[:200]
        r = client.post(f"/api/cases/{minted}/infrastructure", json={"ips": ["gateway.corp.example"]})
        assert r.status_code == 400, f"expected 400 on a non-address, got {r.status_code}"

        # The demo case: the only dataset in the GUI suite rich enough to produce a multi-source
        # episode, which is exactly the shape that used to break the response. `episodes` returned
        # DuckDB datetimes and every consumer here serialises with plain json.dumps, so the GUI
        # failed precisely when the temporal correlation succeeded. Asserting the payload is
        # JSON-clean is the guard that was missing; asserting an episode exists is what makes the
        # first assertion mean anything.
        r = client.post("/api/cases/demo")
        assert r.status_code == 200, r.text[:300]
        loaded = r.json()
        assert loaded["case"] == "demo", loaded
        assert sum(loaded["sources"].values()) > 40, loaded["sources"]

        r = client.get("/api/cases/demo")
        assert r.status_code == 200, r.text[:300]
        demo = r.json()
        assert demo["episodes"], "the demo produced no episode — the serialisation guard is vacuous"
        assert any(e["families"] > 1 for e in demo["episodes"]), demo["episodes"]
        json.dumps(demo)     # redundant here (the response parsed), explicit about what is guarded

        # A second click must rebuild rather than double every record: the case is regenerated.
        again = client.post("/api/cases/demo").json()
        assert again["sources"] == loaded["sources"], (again["sources"], loaded["sources"])

        # The scenario's infrastructure address is declared by the shared builder, not only by the
        # CLI. It used not to be, and the browser demo therefore returned one cluster holding the
        # whole estate — the uninvolved host and the benign destination dragged in through the
        # resolver — while the same demo on the command line returned the incident.
        assert loaded["infrastructure_ips"], loaded
        assert all(len(c["hosts"].split(", ")) <= 4 for c in demo["incident_clusters"]), \
            "a cluster naming more hosts than the scenario has: the demotion did not apply"

        # Stepwise load: one source at a time, in the story's order, so the analyst watches a bridge
        # appear as the second tool names the same thing. Step 0 starts a fresh case.
        first = client.post("/api/cases/demo", json={"step": 0}).json()
        assert first["label"] == first["steps"][0], first
        assert list(first["sources"]) == [first["label"]], first["sources"]
        assert first["done"] is False, first
        after_one = client.get("/api/cases/demo").json()["summary"]["events"]

        second = client.post("/api/cases/demo", json={"step": 1}).json()
        assert second["label"] == second["steps"][1], second
        after_two = client.get("/api/cases/demo").json()["summary"]["events"]
        assert after_two > after_one, (after_one, after_two)

        last = client.post("/api/cases/demo", json={"step": len(second["steps"]) - 1}).json()
        assert last["done"] is True, last
        assert client.post("/api/cases/demo", json={"step": 99}).status_code == 400
        assert client.post("/api/cases/demo", json={"step": "x"}).status_code == 400

        print("PASS  gui: /api/cases — create/list/get/note/delete, case= persistence, demo case "
              "(all at once and one source at a time)")
    finally:
        pass

    # Hayabusa toolbox endpoints (skip without the binary or a sample EVTX dataset)
    _hb_sample = (ANALISI_DIR / ".tools" / "EVTX-ATTACK-SAMPLES"
                  / "Lateral Movement" / "LM_WMI_4624_4688_TargetHost.evtx")
    try:
        gui_app.hayabusa_runner.find_binary()
        _hb_ok = _hb_sample.exists()
    except Exception:
        _hb_ok = False
    if _hb_ok:
        def _hb_post(path, **data):
            with open(_hb_sample, "rb") as fh:
                return client.post(path, files={"files": ("s.evtx", fh, "application/octet-stream")}, data=data)
        je = _hb_post("/api/hayabusa/eid-metrics").json()
        assert any(x.get("ID") == "4624" for x in je.get("result", [])), je
        assert len(_hb_post("/api/hayabusa/search", regex="4624").json().get("result", [])) > 0
        # regex + ignore_case must not 500 (Hayabusa rejects the combo; wrapper drops -i for regex)
        assert _hb_post("/api/hayabusa/search", regex="4624", ignore_case="true").status_code == 200
        assert _hb_post("/api/hayabusa/search").status_code == 400  # neither keyword nor regex
        print("PASS  gui: Hayabusa toolbox endpoints (eid-metrics + search)")
    else:
        print("SKIP  gui: Hayabusa endpoints (binary or sample EVTX absent)")

    # /api/decode: a base64 string round-trips through the decode/ detectors (no external tool).
    dec = client.post("/api/decode", json={"text": "the password is SGVsbG8gV29ybGQ="}).json()
    hits = dec.get("results", [])
    assert any(row.get("decoded") == "Hello World" and row.get("encoder") == "base64" for row in hits), hits
    assert client.post("/api/decode", json={"text": ""}).json() == {"results": []}
    print("PASS  gui: /api/decode round-trips a base64 string")

    # /api/registry (RECmd-backed hive analysis, distinct from the .reg-export path in /api/analyze):
    # skip without dotnet or RECmd.dll, exactly like tests/test_registry.py's own end-to-end guard.
    try:
        _reg_ok = gui_app.recmd_runner.dotnet_available()
        if _reg_ok:
            gui_app.recmd_runner.find_dll()
    except Exception:
        _reg_ok = False
    if _reg_ok:
        # No real hive fixture ships in this repo (tests/test_registry.py skips end-to-end for the
        # same reason) — RECmd runs and reports zero ASEP keys on a file it cannot parse as a hive,
        # rather than raising, so the request still completes and the case is still reached.
        r = client.post("/api/registry", data={"case": "reg-test"},
                        files={"files": ("NTUSER.DAT", b"not a real hive", "application/octet-stream")})
        assert r.status_code == 200, r.text[:200]
        body = r.json()
        assert body["case"] == "reg-test" and body["hives_processed"] == 1, body
        lst = client.get("/api/cases").json()
        assert any(c["id"] == "reg-test" for c in lst["cases"]), "the upload never reached a case"
        print("PASS  gui: /api/registry reaches a case")
    else:
        print("SKIP  gui: /api/registry (dotnet or RECmd.dll absent)")

    # on-box AI endpoints (DESIGN §14): input guards + model list + one real SSE turn.
    assert client.post("/api/ai/chat", json={"question": ""}).status_code == 400
    assert client.post("/api/ai/explain", json={}).status_code == 400
    models = client.get("/api/ai/models").json()
    assert "models" in models and "selected" in models, models  # picker source (may be empty if Ollama down)

    def _sse_events(text: str) -> dict:
        out, ev, parts = {}, None, []
        for line in text.splitlines():
            if line.startswith("event:"):
                ev = line[6:].strip()
            elif line.startswith("data:"):
                parts.append(line[5:].lstrip())
            elif line == "":
                if ev:
                    out[ev] = "".join(parts)
                ev, parts = None, []
        if ev:
            out[ev] = "".join(parts)
        return out

    # Smoke on a FAST model if pulled (keep the gate quick, independent of the 14b default).
    from ai.ollama_client import OllamaClient  # noqa: E402
    ai_model = next((m for m in ("qwen2.5:7b-instruct", "qwen2.5:7b", "llama3.1:8b")
                     if OllamaClient(model=m).available()), None)
    ai_payload = {"question": "In one short sentence, what is T1003.001?"}
    if ai_model:
        ai_payload["model"] = ai_model
    ai = client.post("/api/ai/chat", json=ai_payload)
    assert ai.status_code == 200, ai.status_code
    evs = _sse_events(ai.text)
    if "complete" in evs:
        # If Ollama/model is up: a grounded answer streamed, preceded by a start event.
        payload = json.loads(evs["complete"])
        assert isinstance(payload.get("answer"), str) and payload["answer"], payload
        assert "start" in evs and "model" in json.loads(evs["start"]), evs.get("start")
        print("PASS  gui: /api/ai/chat streamed a grounded answer")
    else:
        # No model pulled: the stream must carry an explicit unavailable error, not crash.
        err = json.loads(evs.get("error", "{}"))
        assert err.get("unavailable"), f"expected complete or unavailable error, got: {list(evs)}"
        print("SKIP  gui: /api/ai/chat (Ollama/model not available)")

    if not shutil.which("tshark"):
        print("PASS  gui: /api/health ok; /api/analyze (PCAP) skipped (tshark absent)")
        return 0

    sys.path.insert(0, str(ANALISI_DIR / "tests"))
    from make_sample_pcap import write_sample  # from analysis/tests/
    tmp = Path(tempfile.mkdtemp())
    try:
        pcap = write_sample(tmp / "sample.pcap")
        with open(pcap, "rb") as fh:
            r = client.post("/api/analyze", files={"files": ("sample.pcap", fh, "application/octet-stream")})
        assert r.status_code == 200, f"analyze failed: {r.status_code} {r.text[:200]}"
        d = _sse_complete(r.text)
        for key in ("summary", "beaconing", "nonstandard_ports", "top_talkers", "_meta"):
            assert key in d, f"missing key in response: {key}"
        assert d["summary"]["events"] > 0, "no event from the synthetic PCAP"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"PASS  gui: /api/health + /api/analyze on synthetic PCAP ({d['summary']['events']} events)")
    return 0


def test_gui():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
