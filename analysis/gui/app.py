"""Local web GUI for the analysis engine (Phase 3).

Upload an EVTX and/or a PCAP from the browser and get the Phase 2 views: ATT&CK detections,
long-tail (process stacking, rare parent-child, rare DNS, non-standard ports, beaconing),
timeline and cross-source correlation. Reuses analytics.runner.analyze() in full.

PRIVACY (method/conventions.md §9/§10): EVTX/PCAP are REAL client data.
- The server runs ONLY on 127.0.0.1 (never exposed on the network). Startup: gui/serve.sh.
- Uploaded files are processed in a temporary folder and DELETED right after the analysis:
  no client data persists on disk server-side. Results stay in memory/response.
- The output shows real identifiers (it is the analyst's console, like the product console):
  do not export/share it without pseudonymization (§9).
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from fastapi import Body, FastAPI, File, Form, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

ANALISI_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALISI_DIR))

from analytics import baseline, case_store, runner  # noqa: E402
import json as _json  # noqa: E402
from engine import (evtxecmd_runner, hayabusa_runner, mftcmd_runner,  # noqa: E402
                    recmd_runner, report_html)
from engine import bundle as bundle_mod  # noqa: E402
from engine.version import APP_VERSION as _APP_VERSION  # noqa: E402
from ai import context as ai_context  # noqa: E402  — on-box conversational engine (DESIGN §14)
from ai import engine as ai_engine  # noqa: E402
from ai import redact as ai_redact  # noqa: E402
from ai.ollama_client import OllamaClient, OllamaError  # noqa: E402
from ai.tools import default_registry as ai_registry  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"
_EVTX_EXT = {".evtx"}
_PCAP_EXT = {".pcap", ".pcapng", ".cap"}
_LOG_EXT = {".log", ".txt", ".json", ".jsonl", ".csv"}
_REG_EXT = {".reg"}
_YARA_EXT = {".yar", ".yara"}
_HIVE_EXT = {".dat", ".hve"}      # NTUSER.DAT / UsrClass.dat; SAM/SYSTEM/SOFTWARE arrive extensionless
_MAX_UPLOAD_BYTES = 1024 * 1024 * 1024  # per-file cap (1 GiB): avoid loading unbounded uploads into RAM
_CHUNK = 1024 * 1024

# Product version — defined once in engine/version.py (the exported bundles stamp the same value).
APP_VERSION = _APP_VERSION

# The simulated incident always lands in one fixed case, rebuilt on demand (see /api/cases/demo).
_DEMO_CASE = "demo"


def _mint_case_id() -> str:
    """An id for a case nobody named yet: `case-<today>-NN`, NN being the first free number.

    Every analysis lands in a case now, because the correlation that makes this product worth using
    happens BETWEEN uploads: a PCAP today and an EVTX tomorrow bridge only if both are in the same
    store. Behind an unchecked box that was opt-in, the default experience was the one where nothing
    correlates.

    Dated and numbered rather than one case per day: two unrelated investigations on the same
    afternoon must not silently merge, which would be the same error the correlation work has spent
    its time removing. The browser keeps the id it was given and sends it back, so a session
    accumulates into ONE case; a new browser session starts a new one."""
    day = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    existing = {c.get("id") for c in case_store.list_cases()}
    for n in range(1, 100):
        cid = f"case-{day}-{n:02d}"
        if cid not in existing:
            return cid
    # 99 cases in one day is not a workflow, it is a loop somewhere. Fall back to something unique
    # rather than overwriting the last one.
    return f"case-{day}-{_dt.datetime.now(_dt.timezone.utc).strftime('%H%M%S')}"

app = FastAPI(title="EventHound — local GUI", docs_url=None, redoc_url=None)


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
# An Ollama model reference: `[repository/]name[:tag]`. Bounded, so the settings store cannot be
# used to park arbitrary text that later reaches a shell variable or an HTML attribute.
_MODEL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")


def _safe_filename_stem(name: str) -> str:
    """Reduce a client-supplied name to a safe `Content-Disposition` filename component.

    `name` reaches /api/report as an untrusted JSON field (§8) and is interpolated straight into a
    response header — a quote, CR/LF or path separator there is a header/filename injection, not
    just a cosmetic issue. Keep only letters/digits/dot/dash/underscore; fall back to a fixed name
    when nothing survives (e.g. the whole input was `../` or control characters)."""
    cleaned = _SAFE_FILENAME_RE.sub("_", name or "").strip("._")
    return cleaned or "analysis"


def _config_mod():
    """The shared config store (tools/eventhound_config.py) — same file the CLI and MCP tools use.
    Imported by path, like the scoring/enrichment tools: each lives in its own uv environment."""
    sp = str(ANALISI_DIR.parent / "tools")
    if sp not in sys.path:
        sys.path.insert(0, sp)
    import eventhound_config
    return eventhound_config


@app.get("/api/health")
def health() -> dict:
    """Status and availability of local tools (Hayabusa for EVTX, tshark for PCAP)."""
    # Uses the SAME discovery logic as the runner (find_binary: only hayabusa-<ver>-<platform>,
    # excludes symlinks, .zip, rules and CSS): this way /api/health does not report hayabusa: true
    # when /api/analyze would actually fail with 'Hayabusa binary not found' (e.g. only the .zip present).
    try:
        hayabusa_runner.find_binary()
        hayabusa = True
    except FileNotFoundError:
        hayabusa = False
    # EvtxECmd requires both the dotnet runtime and the dll downloaded into .tools/evtxecmd/
    try:
        evtxecmd = evtxecmd_runner.dotnet_available()
        if evtxecmd:
            evtxecmd_runner.find_dll()
    except FileNotFoundError:
        evtxecmd = False
    # RECmd: like EvtxECmd — requires dotnet + dll in .tools/recmd/
    try:
        recmd = recmd_runner.dotnet_available()
        if recmd:
            recmd_runner.find_dll()
    except FileNotFoundError:
        recmd = False
    # MFTECmd: like EvtxECmd/RECmd — requires dotnet + dll in .tools/mftcmd/
    try:
        mftecmd = mftcmd_runner.dotnet_available()
        if mftecmd:
            mftcmd_runner.find_dll()
    except FileNotFoundError:
        mftecmd = False
    runtime = os.environ.get("EVENTHOUND_RUNTIME", "local")
    return {"status": "ok", "version": APP_VERSION, "runtime": runtime, "hayabusa": bool(hayabusa), "tshark": _tool_available("tshark"),
            "zeek": _tool_available("zeek"), "evtxecmd": bool(evtxecmd), "recmd": bool(recmd),
            "mftecmd": bool(mftecmd), "decode": True}


QDRANT_URL = os.environ.get("QDRANT_URL", "http://127.0.0.1:6343")


def _probe_json(url: str, timeout: float = 1.5) -> tuple[bool, object]:
    """GET a local service and parse its JSON. `(reachable, payload_or_reason)`.

    Reachability and emptiness are kept apart on purpose: a Qdrant that is down and a Qdrant with
    no collections are different problems with different fixes, and the Settings view used to print
    the same fixed sentence for both — in fact for every state, since it never asked at all.
    """
    import json
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 — loopback only
            return True, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return True, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 — unreachable, refused, timed out: one answer for the UI
        return False, type(e).__name__


@app.get("/api/services")
def services() -> dict:
    """Are the OPTIONAL services up: Qdrant, rag-api, Ollama.

    Separate from `/api/health` because that one answers from `shutil.which` and a file test and is
    fetched on every page load, while this one talks to three sockets. Settings asks for it when it
    renders; nothing else waits on it.

    Each entry is `{state: up|down|unknown, detail}` — `unknown` where the answer could not be
    established rather than being coerced into a green or a red. None of the three is required for
    an analysis, which is what `required: false` says to a reader deciding whether to care.
    """
    out: dict[str, dict] = {}

    ok, payload = _probe_json(QDRANT_URL.rstrip("/") + "/collections")
    if not ok:
        out["qdrant"] = {"state": "down", "detail": f"no answer on {QDRANT_URL} ({payload})"}
    elif isinstance(payload, dict):
        names = [c.get("name") for c in (payload.get("result") or {}).get("collections") or []]
        out["qdrant"] = {"state": "up",
                         "detail": ", ".join(n for n in names if n) or "no collections indexed yet"}
    else:
        out["qdrant"] = {"state": "unknown", "detail": str(payload)}

    ok, payload = _probe_json(RAG_API_URL.rstrip("/") + "/health")
    out["rag_api"] = ({"state": "up", "detail": "warm models, serving over HTTP"} if ok else
                      {"state": "down",
                       "detail": f"no answer on {RAG_API_URL} — RAG search falls back to a "
                                 f"subprocess in rag/.venv, which reloads the models per query"})

    # `unusable_reason` rather than a probe of our own: it is the project's single answer to "can
    # the assistant run", it already covers both halves (reachable, model pulled) plus the memory
    # preflight — a model that is pulled and still will not fit is a state Settings must not paint
    # green — and a second opinion here would drift from the one the CLI and the chat endpoint use.
    client = OllamaClient()
    reason = client.unusable_reason()
    out["ollama"] = ({"state": "up", "detail": f"{client.model} ready"} if reason is None else
                     {"state": "down", "detail": reason})
    for v in out.values():
        v["required"] = False
    return out


def _sniff_thor_report(path: str) -> bool:
    """A THOR .txt report has ' THOR: ' lines. Cheap peek at the first lines (content routing:
    .txt collides with the generic log adapter, so extension alone can't decide)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for _ in range(50):
                line = fh.readline()
                if not line:
                    break
                if " THOR: " in line:
                    return True
    except OSError:
        pass
    return False


def _sniff_thor_csv(path: str) -> bool:
    """The THOR md5s companion is `md5,path,score` — first field a 32-hex MD5."""
    import re as _re
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline().strip()
    except OSError:
        return False
    parts = first.split(",")
    return len(parts) >= 2 and bool(_re.fullmatch(r"[0-9a-fA-F]{32}", parts[0].strip()))


def _sniff_okta(path: str) -> bool:
    """An Okta System Log export: LogEvent objects carrying `eventType` and `published`.

    Sniffed rather than routed by extension because an Okta export is a `.json` like several other
    things: without this it fell through to the generic log adapter, which reads top-level keys only
    and so lost the actor, the client address and the outcome — the entire identity layer of an
    intrusion, silently."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
        if "eventType" not in head or "published" not in head:
            return False
        # Confirm it parses as an Okta shape rather than merely mentioning the words.
        stripped = head.lstrip()
        obj = None
        if stripped.startswith("["):
            obj = _json.loads(head[:head.rindex("}") + 1] + "]") if "}" in head else None
            obj = obj[0] if obj else None
        elif stripped.startswith("{"):
            obj = _json.loads(stripped[:stripped.index("}\n")] if "}\n" in stripped else stripped)
        return isinstance(obj, dict) and "eventType" in obj and "published" in obj
    except (OSError, ValueError, _json.JSONDecodeError):
        # A truncated head is not a verdict: fall back to the substring evidence, which is already
        # specific enough that a plain application log will not match it.
        return False


def _sniff_hive(path: str) -> bool:
    """A binary registry hive starts with the `regf` signature. SAM, SYSTEM and SOFTWARE are
    collected without an extension, so the magic is the only thing that identifies them."""
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"regf"
    except OSError:
        return False


def _sniff_mft(path: str) -> bool:
    """A raw NTFS `$MFT` begins with the FILE record magic. It has no extension to route on."""
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"FILE"
    except OSError:
        return False


def _sniff_osquery(path: str) -> bool:
    """An osquery result log has 'hostIdentifier' and 'unixTime' in each JSON object."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline().strip()
            if first:
                import json as _j
                obj = _j.loads(first)
                return isinstance(obj, dict) and "hostIdentifier" in obj and "unixTime" in obj
    except (OSError, _json.JSONDecodeError):
        pass
    return False


def _sniff_crowdstrike(path: str) -> bool:
    """CrowdStrike detection clipboard has 'Host name:' and 'Description:'."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(2048)
            return "Host name:" in head and ("Description:" in head or "Agent ID:" in head)
    except OSError:
        pass
    return False


async def _analyze_stream(evtx, evtxfull, pcap, logs, reg_paths, thor, errors,
                          osquery=None, crowdstrike=None, okta=None, hives=None, mft=None,
                          yara=None, case_id=None, case_label=None):
    """Generator yielding SSE events during analysis.

    Uses an asyncio.Queue with run_coroutine_threadsafe so that progress
    callbacks from within run_in_executor are yielded immediately.
    The queue is drained concurrently while the executor runs, so events
    stream live during both build_records and analyze phases.

    `case_id`: optional case (analytics/case_store.py) to persist the built records into before
    analyzing — creating the case first if it does not exist. When persistence succeeds, the
    analysis is produced from the case (runner.analyze_case) rather than from the records held only
    in this request, so it survives independently of the upload. A persistence failure degrades to
    the ordinary in-memory analysis instead of losing the result: it is reported via
    result['_meta']['case_error'], never by failing the whole request.
    """
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _sse(event_type, data):
        return f"event: {event_type}\ndata: {_json.dumps(data)}\n\n"

    def emit_sse(event_type, data):
        """Thread-safe: puts SSE string into the async queue."""
        asyncio.run_coroutine_threadsafe(
            queue.put(_sse(event_type, data)),
            loop,
        )

    # Phase 1: upload
    yield _sse("progress", {"phase": "upload", "percent": 5, "detail": "Files uploaded"})

    # Phase 2: build records — drain queue concurrently while executor runs
    def _build():
        def on_progress(phase, percent, detail=""):
            emit_sse("progress", {"phase": phase, "percent": percent, "detail": detail})
        return runner.build_records(
            evtx=evtx, evtx_full=evtxfull, pcap=pcap, logs=logs,
            registry=reg_paths, registry_hives=hives, mft=mft, thor=thor,
            osquery=osquery, okta=okta, yara=yara, crowdstrike=crowdstrike,
            errors=errors, _progress=on_progress,
        )

    build_task = loop.run_in_executor(None, _build)
    while not build_task.done():
        try:
            item = await asyncio.wait_for(queue.get(), timeout=0.1)
            yield item
        except asyncio.TimeoutError:
            pass
    while not queue.empty():
        yield await queue.get()
    try:
        records = build_task.result()
    except Exception as exc:
        yield _sse("error", {"error": f"Build failed: {exc}"})
        return

    # Phase 2b: persist into a case, if requested. Runs after a successful build so a build failure
    # never creates an empty/partial case.
    case_error = None
    if case_id:
        yield _sse("progress", {"phase": "persisting", "percent": 91,
                                "detail": f"Saving to case {case_id}..."})

        def _persist():
            if not case_store.exists(case_id):
                case_store.create(case_id)
            case_store.append(case_id, records, label=case_label)

        try:
            await loop.run_in_executor(None, _persist)
        except Exception as exc:  # noqa: BLE001 — degrade, don't lose the analysis (see docstring)
            # str(exc), not type(exc).__name__: case_store.CaseError already names what was refused
            # and why (e.g. "these records were already added ... under label ..."), which is the
            # common trigger (the GUI re-sends every accumulated file on each Analyze click). Its
            # message carries case metadata, never event content (§9) — same as /api/registry below.
            case_error = f"case persistence failed: {exc}"

    # Phase 3: analyze — drain queue concurrently while executor runs
    def _analyze():
        def on_progress(phase, percent, detail=""):
            emit_sse("progress", {"phase": phase, "percent": percent, "detail": detail})
        if case_id and case_error is None:
            return runner.analyze_case(case_id, _progress=on_progress)
        return runner.analyze(records, _progress=on_progress)

    analyze_task = loop.run_in_executor(None, _analyze)
    while not analyze_task.done():
        try:
            item = await asyncio.wait_for(queue.get(), timeout=0.1)
            yield item
        except asyncio.TimeoutError:
            pass
    while not queue.empty():
        yield await queue.get()
    try:
        result = analyze_task.result()
    except Exception as exc:
        yield _sse("error", {"error": f"Analysis failed: {exc}"})
        return

    # What changed since the last look at this case. With every upload re-analysing the WHOLE case,
    # the result is complete but no longer tells the analyst what is NEW — and re-reading a hundred
    # bridges to find the two that just appeared is how a real finding gets missed.
    if case_id and case_error is None:
        prior = case_store.load_analysis_digest(case_id)
        d = baseline.delta(prior, result)
        result["delta"] = d
        result["delta_headline"] = baseline.delta_headline(d)
        case_store.save_analysis_digest(case_id, result)

    result["_meta"] = {"case": case_id, "records": len(records), "evtx": len(evtx),
                       "evtx_full": len(evtxfull), "pcap": len(pcap),
                       "logs": len(logs), "registry": len(reg_paths),
                       "registry_hives": len(hives or []), "mft": len(mft or []),
                       "thor": len(thor), "osquery": len(osquery or []),
                       "okta": len(okta or []), "yara": len(yara or []),
                       "crowdstrike": len(crowdstrike or []),
                       "errors": errors}
    if case_error:
        result["_meta"]["case_error"] = case_error
    yield _sse("complete", result)


@app.post("/api/analyze")
async def analyze(files: list[UploadFile], evtx_full: bool = Form(False), case: str = Form(""),
                  no_case: bool = Form(False)) -> Response:
    """Receive one or more EVTX/PCAP/logs, analyze them locally and return the analyze() result.

    `evtx_full=True`: EVTX go through EvtxECmd (full stream) instead of Hayabusa
    (detection). Files are saved in a tempdir and deleted at the end of the request (no
    persistence; §9/§10); the records built from them are persisted into a case
    (analytics/case_store.py), which is what lets a later upload correlate with this one.

    The case is `case` when the caller names one, and a freshly minted `case-<today>-NN` when it
    does not — accumulating evidence is the default, not an option to find. `no_case=true` opts out
    for a one-off look at a file, and that is the only way to get the old behaviour: the analysis
    then lives and dies with the request, and says so."""
    case_id = case.strip() or None
    if case_id is None and not no_case:
        case_id = _mint_case_id()
    tmp = Path(tempfile.mkdtemp(prefix="analisi-gui-"))
    evtx: list[str] = []
    evtxfull: list[str] = []
    pcap: list[str] = []
    logs: list[dict] = []
    reg_paths: list[str] = []
    thor_reports: list[str] = []
    thor_csvs: list[str] = []
    osquery_paths: list[str] = []
    okta_paths: list[str] = []
    crowdstrike_paths: list[str] = []
    hives: list[str] = []
    mft_paths: list[str] = []
    yara_rules: list[str] = []
    unclaimed: list[tuple[str, str]] = []
    errors: list[str] = []
    for idx, f in enumerate(files):
        ext = Path(f.filename or "").suffix.lower()
        # Prefix with the index: two uploads with the SAME basename (e.g. Security.evtx from two
        # hosts) must not overwrite each other — otherwise the first file is lost and the second
        # gets analyzed twice, skewing every count.
        dest = tmp / f"{idx:03d}_{Path(f.filename or 'upload').name}"
        # Chunked copy with a size cap: do not load the whole upload into RAM (await f.read()).
        size = 0
        too_big = False
        try:
            with open(dest, "wb") as out:
                while True:
                    chunk = await f.read(_CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > _MAX_UPLOAD_BYTES:
                        too_big = True
                        break
                    out.write(chunk)
        except (OSError, ValueError) as e:
            # Filename too long / NUL byte / disk full / stream error: no unhandled traceback —
            # it would land in the server's persistent log with the real client filename
            # (§9/§10). Degrade the single file, not the whole request; only the exception
            # type, never the filename.
            errors.append(f"upload write failed ({type(e).__name__})")
            continue
        if too_big:
            errors.append(f"file too large (> {_MAX_UPLOAD_BYTES // (1024*1024)} MiB): {f.filename!r}")
            continue
        if ext in _EVTX_EXT:
            (evtxfull if evtx_full else evtx).append(str(dest))
        elif ext in _PCAP_EXT:
            pcap.append(str(dest))
        elif ext in _REG_EXT:
            reg_paths.append(str(dest))
        elif ext in _YARA_EXT:
            # Rules, not evidence: held aside and applied to everything else in the same upload.
            yara_rules.append(str(dest))
        elif ext in _HIVE_EXT or (not ext and _sniff_hive(str(dest))):
            hives.append(str(dest))
        elif not ext and _sniff_mft(str(dest)):
            mft_paths.append(str(dest))
        elif ext == ".txt" and _sniff_thor_report(str(dest)):
            thor_reports.append(str(dest))
        elif ext == ".csv" and _sniff_thor_csv(str(dest)):
            thor_csvs.append(str(dest))
        elif ext in {".json", ".log"} and _sniff_osquery(str(dest)):
            osquery_paths.append(str(dest))
        elif ext in {".json", ".jsonl", ".log"} and _sniff_okta(str(dest)):
            okta_paths.append(str(dest))
        elif ext in {".txt", ".log"} and _sniff_crowdstrike(str(dest)):
            crowdstrike_paths.append(str(dest))
        elif ext in _LOG_EXT:
            logs.append({"path": str(dest), "fmt": "auto"})
        else:
            # Held, not rejected yet: if YARA rules came up in the same upload — possibly AFTER this
            # file — then a binary no adapter claimed is precisely what they are meant to scan.
            # Deciding here would call a scan target "unsupported" purely because of upload order.
            unclaimed.append((f.filename or dest.name, str(dest)))

    # THOR: the .txt report is authoritative; the md5s .csv is a fallback used only if no report
    # was uploaded (otherwise the two would double-count the same findings).
    thor = ([{"report": p} for p in thor_reports] if thor_reports
            else [{"md5s": p} for p in thor_csvs])

    # YARA needs both halves. Rules apply to the files no other adapter claimed — a dropped binary,
    # a suspicious document — which is the only unambiguous reading of "here are rules and here are
    # files". Scanning the EVTX and the capture too would be slow and would say nothing.
    yara = [{"target": path, "rules": rules}
            for rules in yara_rules for _name, path in unclaimed]
    if yara_rules and not unclaimed:
        errors.append("YARA rules uploaded with nothing to scan — add the files to scan alongside them")
    if not yara_rules:
        for name, _path in unclaimed:
            errors.append(f"unsupported extension: {name!r} (expected .evtx/.pcap/.log/.reg/.yar, a registry hive or $MFT, osquery/Okta .json, crowdstrike .txt/.log, or a THOR report)")

    if not any((evtx, evtxfull, pcap, logs, reg_paths, thor, osquery_paths, okta_paths,
                crowdstrike_paths, hives, mft_paths, yara)):
        shutil.rmtree(tmp, ignore_errors=True)
        return JSONResponse({"error": "no valid file uploaded (expected .evtx/.pcap/.log/.reg, a registry hive or $MFT, osquery/Okta, crowdstrike, YARA rules with targets, or a THOR report)", "errors": errors}, status_code=400)

    # Uploaded file names, not tmp paths — used as the case source label so a case's `sources` list
    # reads like "Security.evtx" rather than an opaque tempdir path.
    case_label = ", ".join(f.filename for f in files if f.filename) or None

    async def event_stream():
        """Wrap _analyze_stream into an async generator, cleaning up tmp when done."""
        try:
            async for chunk in _analyze_stream(evtx, evtxfull, pcap, logs, reg_paths, thor, errors,
                                               osquery=osquery_paths, crowdstrike=crowdstrike_paths,
                                               okta=okta_paths, hives=hives, mft=mft_paths, yara=yara,
                                               case_id=case_id, case_label=case_label):
                yield chunk
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # no client data persists

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/config")
def get_config() -> dict:
    """Masked configuration status: which third-party keys are set, and where they come from.

    NEVER returns a usable key — only a `…abcd` hint (eventhound_config.status()). The same store
    backs the CLI, so a key set here is already in place for `engine.run_ai`, the MCP tools and the
    enrichment CLI, and vice versa."""
    cfg = _config_mod()
    return {"path": str(cfg.config_path()), "services": cfg.status(), "settings": cfg.settings()}


@app.post("/api/config")
def set_config(payload: dict) -> Response:
    """Store a key or a preference. `{"service": "virustotal", "key": "…"}` — an empty key clears it;
    `{"setting": "allow_egress", "value": true}` for preferences.

    The value is written to the private, gitignored `data/config.json` (0600). Errors never echo the
    submitted value back (it is a secret)."""
    cfg = _config_mod()
    try:
        if "service" in payload:
            cfg.set_api_key(str(payload["service"]), str(payload.get("key") or ""))
        elif "setting" in payload:
            cfg.set_setting(str(payload["setting"]), payload.get("value"))
        else:
            return JSONResponse({"error": "expected 'service' or 'setting'"}, status_code=400)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except OSError as e:  # unwritable path, full disk: no traceback (could contain the path)
        return JSONResponse({"error": f"could not write the config ({type(e).__name__})"}, status_code=500)
    return JSONResponse({"path": str(cfg.config_path()), "services": cfg.status(), "settings": cfg.settings()})


@app.get("/api/attack-map")
def attack_map() -> Response:
    """The ATT&CK map the engine uses (technique → name + tactics), served to the frontend.

    One physical file for both sides (`analytics/attack_map.json`, generated from the official
    STIX bundle): a second copy under static/ would drift the moment one of them is regenerated."""
    path = ANALISI_DIR / "analytics" / "attack_map.json"
    if not path.exists():
        return JSONResponse({"techniques": {}, "_attack_version": ""})
    return FileResponse(path, media_type="application/json")


@app.post("/api/report")
async def report(payload: dict) -> Response:
    """Render the report from the analyze() result in the requested format and level.

    The client sends {data, level, format, name} — no re-parsing of files.
    Formats: html (default), markdown, json, bundle (re-importable snapshot, ignores `level`:
    a bundle that dropped sections would not reopen faithfully).
    Levels: summary, detailed (default), full.

    The report contains real identifiers → the analyst saves it locally and pseudonymizes before
    sharing (§9); here it is only delivered to the browser, no server-side persistence."""
    level = payload.get("level", "detailed")
    fmt = payload.get("format", "html")
    data = payload.get("data", {})
    name = payload.get("name", "analysis")
    scanned_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    try:
        if fmt == "html":
            from engine.report_html import render_html
            content = render_html(data, data.get("_meta") or {}, level=level)
            media_type = "text/html"
            ext = "html"
        elif fmt == "markdown":
            from engine.report_markdown import render_markdown
            content = render_markdown(data, name=name, scanned_at=scanned_at, level=level)
            media_type = "text/markdown"
            ext = "md"
        elif fmt == "json":
            from engine.report_json import render_json
            content = render_json(data, name=name, scanned_at=scanned_at, level=level)
            media_type = "application/json"
            ext = "json"
        elif fmt == "bundle":
            content = bundle_mod.dumps(bundle_mod.build(data, name=name))
            media_type = "application/json"
            ext = "json"
        else:
            return JSONResponse({"error": f"Unknown format: {fmt}"}, status_code=400)
    except Exception as e:  # noqa: BLE001 — no traceback (could contain client data, §9/§10)
        return JSONResponse({"error": f"report generation failed ({type(e).__name__})"}, status_code=400)
    stem = "bundle" if fmt == "bundle" else "report"
    safe_name = _safe_filename_stem(name)
    return Response(content=content, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{stem}-{safe_name}.{ext}"'})


# ── Cases: persistent analyses (analytics/case_store.py) ──────────────────────────────────
# A case is a directory under analysis/cases/ (gitignored, listed in tools/check-leaks.sh) holding
# a file-backed DuckDB plus case.json metadata/notes. These endpoints are thin: all the state
# machinery lives in case_store; this layer only turns CaseError into the right HTTP status.

def _case_error_status(exc: case_store.CaseError) -> int:
    """Malformed/absent input from the browser is a 400 (§8: a case id is untrusted input); a case
    that legitimately does not exist is a 404. Never a bare 500 either way."""
    if getattr(exc, "bad_input", False):
        return 400
    msg = str(exc)
    if msg.startswith("invalid case id") or msg == "empty note":
        return 400
    return 404


@app.get("/api/cases")
def list_cases() -> dict:
    """Every persisted case, newest updated first. Each entry adds `size_mb` (on-disk size of the
    case's DuckDB + metadata), rounded to 1 decimal — the meta itself has no notion of disk size."""
    cases = []
    for meta in case_store.list_cases():
        entry = dict(meta)
        entry["size_mb"] = round(case_store.size_bytes(meta["id"]) / (1024 * 1024), 1)
        cases.append(entry)
    return {"cases": cases}


@app.post("/api/cases")
def create_case(payload: dict) -> Response:
    """Create an empty case. Body: {id, title?}. Records land in it later, either via /api/analyze's
    `case` field or the CLI's case_store.append. An id that fails validation or already exists is a
    400 with case_store's own message — never a 500."""
    try:
        meta = case_store.create(str(payload.get("id") or ""), title=payload.get("title") or None)
    except case_store.CaseError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse(meta)


@app.post("/api/cases/demo")
def load_demo_case(payload: dict | None = Body(None)) -> Response:
    """Generate the simulated incident and load it into a case, so the product can be shown with no
    customer evidence at all.

    It calls the same code the CLI does (`engine.run_demo.build_demo_case`), never a second
    implementation: a demo that drifts from the command it documents stops being a demonstration of
    anything. This endpoint used to have its own copy of the ingest loop, and that copy had already
    fallen behind — it never declared the scenario's infrastructure address, so the demo in the
    browser returned one cluster holding the whole estate while the same demo on the command line
    returned the incident.

    Two modes. Without a body the whole incident is loaded at once and the case is rebuilt from
    scratch (it holds nothing worth keeping, and a second click that doubled every record would make
    the correlation lie). With `{"step": n}` a single source is appended, in the story's order
    (`run_demo.DEMO_ORDER`) — which is the better demonstration, because the analyst watches a
    bridge appear at the moment a second tool names the same thing, instead of being handed the
    finished picture."""
    from engine import run_demo

    step = None
    if isinstance(payload, dict) and payload.get("step") is not None:
        try:
            step = int(payload["step"])
        except (TypeError, ValueError):
            return JSONResponse({"error": "step must be an integer"}, status_code=400)
        if not 0 <= step < len(run_demo.DEMO_ORDER):
            return JSONResponse({"error": f"step out of range (0..{len(run_demo.DEMO_ORDER) - 1})"},
                                status_code=400)

    only = run_demo.DEMO_ORDER[step] if step is not None else None
    # Step 0 starts a fresh case; every later step adds to the one already there.
    built = run_demo.build_demo_case(_DEMO_CASE, only=only, reset=(step in (None, 0)))
    return JSONResponse({
        **built,
        "step": step,
        "label": only,
        "steps": list(run_demo.DEMO_ORDER),
        "done": step is None or step == len(run_demo.DEMO_ORDER) - 1,
        # Not swallowed: a missing tshark or yara-python means a smaller picture, and the caller has
        # to be able to say so rather than present the result as complete.
    })


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> Response:
    """The same analyze() result shape /api/analyze returns, computed over the persisted case (not
    re-run from evidence), so the front end can drop it straight into the session (the "Open" action)."""
    try:
        meta = case_store.load_meta(case_id)
    except case_store.CaseError as e:
        return JSONResponse({"error": str(e)}, status_code=_case_error_status(e))
    result = runner.analyze_case(case_id)
    result["_meta"] = {"records": meta["record_count"], "case": case_id, "title": meta.get("title")}
    return JSONResponse(result)


@app.post("/api/cases/{case_id}/note")
def add_case_note(case_id: str, payload: dict) -> Response:
    """Append an analyst note. Body: {text}. Empty text is a 400 (case_store.note's own check, which
    runs before it even looks up the case)."""
    try:
        meta = case_store.note(case_id, str(payload.get("text") or ""))
    except case_store.CaseError as e:
        return JSONResponse({"error": str(e)}, status_code=_case_error_status(e))
    return JSONResponse(meta)


@app.post("/api/map")
def render_map(payload: dict) -> Response:
    """The attack map for an already-computed analysis: `{data: <analyze() result>}` → HTML fragment.

    Rendered server-side by `engine/attack_map.py`, the same code the HTML report uses, so the
    picture the analyst reads on screen and the one in the deliverable cannot differ. Nothing is
    re-parsed and no evidence is uploaded again — the result the browser already holds is enough."""
    from engine import attack_map

    data = payload.get("data") or {}
    graph = data.get("entity_graph") or {}
    if not graph.get("nodes"):
        return JSONResponse({"html": "", "empty": True,
                             "reason": "no entity is linked to another in this analysis"})
    return JSONResponse({
        "html": attack_map.render_html(data, graph),
        "css": attack_map.css(),
        "css_dark": attack_map.css(dark=True),
        "nodes": len(graph["nodes"]),
        "truncated": bool(graph.get("truncated")),
        "empty": False,
    })


@app.post("/api/cases/{case_id}/infrastructure")
def set_case_infrastructure(case_id: str, payload: dict) -> Response:
    """Declare this case's infrastructure addresses. Body: {ips: [...]}, which REPLACES the list.

    A gateway or a resolver is shared by every host on the network, so as a correlation bridge it
    links everything to everything — but nothing in the data says which address it is, so it has to
    be declared. Kept in the case because it describes the network, not the upload."""
    try:
        meta = case_store.set_infrastructure_ips(case_id, payload.get("ips") or [])
    except case_store.CaseError as e:
        return JSONResponse({"error": str(e)}, status_code=_case_error_status(e))
    return JSONResponse({"case": case_id, "infrastructure_ips": meta["infrastructure_ips"]})


@app.delete("/api/cases/{case_id}")
def delete_case(case_id: str) -> Response:
    """Remove a case directory. Destructive and irreversible — the confirmation is the caller's
    responsibility (§12); this endpoint just executes it."""
    try:
        case_store.delete(case_id)
    except case_store.CaseError as e:
        return JSONResponse({"error": str(e)}, status_code=_case_error_status(e))
    return JSONResponse({"deleted": case_id})


# ── Hayabusa toolbox: expose the analyst-facing subcommands over uploaded EVTX ────────────
# Each endpoint uploads one or more .evtx, runs a hayabusa_runner wrapper in a tempdir, returns
# the parsed rows, and deletes the files (no persistence; §9/§10). Fast, synchronous (no SSE).

async def _save_evtx_uploads(files: list[UploadFile], tmp: Path) -> tuple[list[Path], list[str]]:
    """Save uploaded .evtx files into `tmp`; skip non-evtx. Returns (paths, errors)."""
    paths: list[Path] = []
    errors: list[str] = []
    for idx, f in enumerate(files):
        if Path(f.filename or "").suffix.lower() != ".evtx":
            errors.append(f"skipped non-evtx: {f.filename!r}")
            continue
        dest = tmp / f"{idx:03d}_{Path(f.filename or 'upload').name}"
        size = 0
        try:
            with open(dest, "wb") as out:
                while True:
                    chunk = await f.read(_CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > _MAX_UPLOAD_BYTES:
                        errors.append(f"file too large: {f.filename!r}")
                        dest.unlink(missing_ok=True)
                        dest = None
                        break
                    out.write(chunk)
        except (OSError, ValueError) as e:
            errors.append(f"upload write failed ({type(e).__name__})")
            continue
        if dest is not None:
            paths.append(dest)
    return paths, errors


async def _hb_run(files: list[UploadFile], fn) -> JSONResponse:
    """Shared flow: check binary, save uploads, run `fn(evtx_dir)`, clean up, return JSON."""
    try:
        hayabusa_runner.find_binary()
    except FileNotFoundError:
        return JSONResponse({"error": "Hayabusa binary not found in .tools/hayabusa/"}, status_code=503)
    tmp = Path(tempfile.mkdtemp(prefix="hb-"))
    try:
        paths, errors = await _save_evtx_uploads(files, tmp)
        if not paths:
            return JSONResponse({"error": "no .evtx uploaded", "errors": errors}, status_code=400)
        try:
            result = fn(tmp)
        except Exception as e:  # tool error / bad input — no traceback (may carry client data, §9)
            return JSONResponse({"error": f"hayabusa failed ({type(e).__name__})", "errors": errors},
                                status_code=500)
        return JSONResponse({"result": result, "files": len(paths), "errors": errors})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@app.post("/api/hayabusa/eid-metrics")
async def hb_eid_metrics(files: list[UploadFile] = File(...)) -> JSONResponse:
    return await _hb_run(files, lambda d: hayabusa_runner.eid_metrics(d, d / "eid.csv"))


@app.post("/api/hayabusa/log-metrics")
async def hb_log_metrics(files: list[UploadFile] = File(...)) -> JSONResponse:
    return await _hb_run(files, lambda d: hayabusa_runner.log_metrics(d, d / "log.csv"))


@app.post("/api/hayabusa/computer-metrics")
async def hb_computer_metrics(files: list[UploadFile] = File(...)) -> JSONResponse:
    return await _hb_run(files, lambda d: hayabusa_runner.computer_metrics(d, d / "comp.csv"))


@app.post("/api/hayabusa/search")
async def hb_search(files: list[UploadFile] = File(...), keyword: str = Form(""),
                    regex: str = Form(""), ignore_case: bool = Form(True)) -> JSONResponse:
    kw = keyword.strip()
    rx = regex.strip()
    if not kw and not rx:
        return JSONResponse({"error": "provide a keyword or a regex"}, status_code=400)
    return await _hb_run(files, lambda d: hayabusa_runner.search(
        d, d / "search.json", keywords=([kw] if kw else None), regex=(rx or None),
        ignore_case=ignore_case))


@app.post("/api/hayabusa/pivot-keywords")
async def hb_pivot_keywords(files: list[UploadFile] = File(...),
                            min_level: str = Form("informational")) -> JSONResponse:
    return await _hb_run(files, lambda d: hayabusa_runner.pivot_keywords(d, d / "pivot", min_level=min_level))


@app.post("/api/hayabusa/extract-base64")
async def hb_extract_base64(files: list[UploadFile] = File(...)) -> JSONResponse:
    return await _hb_run(files, lambda d: hayabusa_runner.extract_base64(d, d / "b64.csv"))

from decode.runner import scan_text as _scan_text  # noqa: E402  — local import, always available


@app.post("/api/decode")
async def decode_text(payload: dict) -> JSONResponse:
    """Decode text submitted by the user."""
    text = payload.get("text", "")
    min_conf = float(payload.get("min_confidence", 0.5))
    if not text:
        return JSONResponse({"results": []})
    results = _scan_text(text, min_confidence=min_conf)
    return JSONResponse({"results": [r.__dict__ for r in results]})


@app.post("/api/registry")
async def analyze_registry(files: list[UploadFile] = File(...), case: str = Form("")) -> JSONResponse:
    """Analyze uploaded registry hives (SAM/SYSTEM/SOFTWARE/NTUSER.DAT) for ASEP/persistence.

    Goes through `runner.build_records(registry_hives=…)` like every other source. It used to call
    the adapter's private record builder directly and hand the rows straight back, which meant hive
    findings never entered the store, never correlated with anything and never reached a case — a
    persistence key on a host was visible in one panel and invisible everywhere the analysis
    actually happens. Requires RECmd.dll in analysis/.tools/recmd/ and dotnet in PATH.

    Uploaded files are deleted at the end of the request (§9/§10); the records are persisted only
    when `case` names one.
    """
    if not recmd_runner.dotnet_available():
        return JSONResponse({"error": "RECmd requires dotnet (.NET runtime) — not found in PATH"}, status_code=503)
    try:
        recmd_runner.find_dll()
    except FileNotFoundError:
        return JSONResponse({"error": "RECmd.dll not found in .tools/recmd/ — install RECmd from ericzimmerman.github.io"}, status_code=503)

    tmp = Path(tempfile.mkdtemp(prefix="analisi-reg-"))
    hives: list[str] = []
    errors: list[str] = []
    try:
        for idx, f in enumerate(files):
            dest = tmp / f"{idx:03d}_{Path(f.filename or 'upload').name}"
            size = 0
            too_big = False
            try:
                with open(dest, "wb") as out:
                    while True:
                        chunk = await f.read(_CHUNK)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > _MAX_UPLOAD_BYTES:
                            too_big = True
                            break
                        out.write(chunk)
            except (OSError, ValueError) as e:
                errors.append(f"upload write failed ({type(e).__name__})")
                continue
            if too_big:
                errors.append(f"file too large (> {_MAX_UPLOAD_BYTES // (1024*1024)} MiB): {f.filename!r}")
                continue
            hives.append(str(dest))

        if not hives:
            return JSONResponse({"error": "no valid hive uploaded", "errors": errors}, status_code=400)

        records = runner.build_records(registry_hives=hives, errors=errors)
        case_id = case.strip() or None
        if case_id:
            try:
                if not case_store.exists(case_id):
                    case_store.create(case_id)
                case_store.append(case_id, records, label=", ".join(
                    f.filename for f in files if f.filename) or "registry hives")
            except case_store.CaseError as e:
                errors.append(f"case persistence failed: {e}")
                case_id = None
        analysis = runner.analyze_case(case_id) if case_id else runner.analyze(records)
        categories = {r.get("rule.description") for r in records if r.get("rule.description")}
        return JSONResponse({
            "records": records,
            "asep_count": len(records),
            "records_ingested": len(records),
            "suspicious_categories": len(categories),
            "hives_processed": len(hives),
            "case": case_id,
            "analysis": analysis,
            "errors": errors,
        })
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


RAG_DIR = ANALISI_DIR.parent / "rag"
# rag-api service (warm models). In Docker points to the container; locally to the process on :8600.
RAG_API_URL = os.environ.get("RAG_API_URL", "http://127.0.0.1:8600")


def _rag_via_http(payload: dict) -> dict | None:
    """Query the rag-api service via HTTP. Returns None if unreachable (→ fallback)."""
    import json
    import urllib.error
    import urllib.request
    body = json.dumps(payload).encode()
    req = urllib.request.Request(RAG_API_URL.rstrip("/") + "/search", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 — local/trusted URL
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:  # the service replied with an error: propagate the body
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"error": f"rag-api HTTP {e.code}", "results": []}
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return None  # service down → subprocess fallback


def _rag_via_subprocess(query: str, collection: str, k: int, level) -> dict:
    """Fallback: run retrieve in the RAG venv (rag/.venv has the ML stack). Zero deps here.

    The rag-api service is the warm path; this makes the GUI work even without the service
    or Docker active, reloading the models on every query (slower, but always available)."""
    import json
    import subprocess
    cmd = ["uv", "run", "python", "-m", "pipeline.retrieve", query,
           "--collection", collection, "--k", str(k), "--format", "json"]
    if level is not None:
        cmd += ["--level", str(level)]
    try:
        p = subprocess.run(cmd, cwd=str(RAG_DIR), capture_output=True, text=True, timeout=240)
    except FileNotFoundError:
        return {"error": "RAG unavailable: 'uv' not in PATH and rag-api service not running",
                "results": []}
    except subprocess.TimeoutExpired:
        return {"error": "RAG timeout (>240s)", "results": []}
    if p.returncode != 0:
        tail = ((p.stderr or "").strip().splitlines() or [""])[-1]
        return {"error": f"RAG search failed ({tail})", "results": []}
    try:
        return {"results": json.loads(p.stdout or "[]")}
    except json.JSONDecodeError:
        return {"error": "RAG: non-JSON output from retrieval", "results": []}


@app.post("/api/rag/search")
async def rag_search(payload: dict) -> JSONResponse:
    """Search the RAG knowledge base (Qdrant on :6343).

    JSON body: {query, collection, k, level}. Primary path: rag-api service
    (RAG_API_URL, warm models). Fallback: subprocess in the RAG venv — so the GUI
    works even without the service/Docker active."""
    query = (payload.get("query") or "").strip()
    collection = payload.get("collection") or "knowledge_cyber"
    k = int(payload.get("k", 5))
    level = payload.get("level")
    if not query:
        return JSONResponse({"results": []})

    data = _rag_via_http({"query": query, "collection": collection, "k": k, "level": level})
    if data is None:  # service unreachable: fall back to the RAG venv
        data = _rag_via_subprocess(query, collection, k, level)
    return JSONResponse(data, status_code=503 if data.get("error") else 200)


# --- on-box conversational AI (DESIGN §14): thin SSE layer over ai.engine.run ---------------

# Keys that mean "this is analysis output the packer knows how to render", beyond the two that
# identify a full result. `aiExplainKillchain` posts {killchain, host_killchain, technique_catalog}
# and nothing else, so it fell through to the raw-JSON branch: the model received the corroboration
# as a bare field, WITHOUT the co-occurrence-not-a-technique label that `_killchain_block` exists
# to attach — on the path an analyst is most likely to use to ask about the kill chain.
_PACKABLE_KEYS = ("summary", "records", "killchain", "host_killchain", "technique_catalog",
                  "timeline", "shared_indicators", "episodes")


def _looks_like_analysis(obj) -> bool:
    """Analysis output the context packer can render, vs an arbitrary function output."""
    return isinstance(obj, dict) and any(k in obj for k in _PACKABLE_KEYS)


async def _ai_stream(question: str, context_obj, enrich: bool, model: str | None = None):
    """Stream an AI turn as SSE: a start event (model + redaction status), live tool events,
    then a `complete` event with the answer. Mirrors _analyze_stream (queue + executor) so the
    blocking engine.run does not stall the event loop. Anonymization gate applied here (§9).
    `model` optionally overrides the default (used e.g. by tests to smoke-check on a fast model)."""
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _sse(event_type, data):
        return f"event: {event_type}\ndata: {_json.dumps(data)}\n\n"

    client = OllamaClient(model=model) if model else OllamaClient()
    _reason = client.unusable_reason()
    if _reason:
        yield _sse("error", {"error": f"Local AI unavailable: {_reason}", "unavailable": True})
        return

    redactor = ai_redact.load_redactor()
    packed = None
    records = None
    if context_obj is not None:
        if redactor.active:
            context_obj = redactor.apply_obj(context_obj)
        if _looks_like_analysis(context_obj):
            packed = ai_context.pack_analysis(context_obj)
            records = context_obj.get("records") or []
        else:  # arbitrary function output → bounded JSON block as context
            packed = "```json\n" + _json.dumps(context_obj, ensure_ascii=False, indent=2)[:8000] + "\n```"

    yield _sse("start", {"model": client.model, "redaction_active": redactor.active,
                         "has_context": context_obj is not None})

    registry = ai_registry(records=records, enrich=enrich)

    def on_event(kind, data):
        if kind == "token":
            evt = _sse("token", {"text": data.get("text", "")})
        else:
            evt = _sse("tool", {"kind": kind, **data})
        asyncio.run_coroutine_threadsafe(queue.put(evt), loop)

    def _run():
        return ai_engine.run(question, client=client, registry=registry, context=packed,
                             redactor=redactor, stream=True, on_event=on_event)

    task = loop.run_in_executor(None, _run)
    while not task.done():
        try:
            yield await asyncio.wait_for(queue.get(), timeout=0.1)
        except asyncio.TimeoutError:
            pass
    while not queue.empty():
        yield await queue.get()
    try:
        res = task.result()
    except OllamaError as exc:
        yield _sse("error", {"error": str(exc)})
        return
    yield _sse("complete", {"answer": res.answer, "truncated": res.truncated,
                            "calls": [{"name": c.name, "arguments": c.arguments} for c in res.calls]})


@app.get("/api/ai/models")
def ai_models() -> dict:
    """Models pulled in the local Ollama, plus the one this installation is set to use.

    `selected` is the effective model — `EVENTHOUND_LLM_MODEL`, else the stored `llm_model`, else
    the engine default — and it is listed even when it is not pulled, because a picker that
    silently drops the analyst's own choice is how a setting looks broken. Empty list if Ollama is
    unreachable (the picker then just shows the selection)."""
    client = OllamaClient()
    models = client.tags()
    if client.model and client.model not in models:
        models = sorted([*models, client.model])
    # No `default` alias beside `selected`: two keys carrying one value is how they drift (§16.3).
    return {"models": models, "selected": client.model,
            "pinned_by_env": bool(os.environ.get("EVENTHOUND_LLM_MODEL"))}


@app.post("/api/ai/model")
def ai_set_model(payload: dict) -> Response:
    """Persist the analyst's model choice and answer, honestly, whether this host can load it.

    The picker used to be a per-request override that vanished on reload, while `llm_model` — the
    setting the CLI and the MCP tools read — was written by nothing. One control now does both, so
    a model chosen here is the model the whole product talks to.

    The verdict comes back with the choice rather than at the first question, because the answer
    for a large model on a small host is a refusal (`memory_status`), and finding that out three
    seconds into a streamed answer is the wrong moment. Selecting a model this host cannot hold is
    ALLOWED — the guard is the load, not the setting — it just says so."""
    name = payload.get("model")
    if name is not None and not isinstance(name, str):
        return JSONResponse({"error": "'model' must be a string"}, status_code=400)
    name = (name or "").strip()
    # Validated before it is stored, not after. The value is handed to Ollama, echoed into the
    # picker, and interpolated into `$MODEL` by setup.sh and uninstall.sh — a settings field that
    # accepts newlines, 10 KB of text or a quote is a field the rest of the product has to defend
    # against forever. An Ollama model name is `[repo/]name[:tag]`; anything else is a mistake, and
    # a 400 says so instead of storing it silently. `_safe_filename` above sets the same standard.
    if name and not _MODEL_NAME_RE.fullmatch(name):
        return JSONResponse({"error": "not a model name: expected [repository/]name[:tag], "
                                      "letters, digits and . _ - / : only, up to 128 characters"},
                            status_code=400)
    try:
        _config_mod().set_setting("llm_model", name)
    except ImportError:
        # tools/ is absent in the eventhound image (docs/roadmap.md, Open). Say so, rather than
        # returning the bare 500 that made the picker's note render a JSON parse error.
        return JSONResponse({"error": "the settings store is not available in this deployment "
                                      "(tools/ is not in this image) — set EVENTHOUND_LLM_MODEL "
                                      "instead"}, status_code=501)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except OSError as e:
        return JSONResponse({"error": f"could not write the config ({type(e).__name__})"},
                            status_code=500)
    client = OllamaClient(model=name or None)
    # ONE /api/tags round trip, reused for both questions. Asking each of them separately issued
    # the identical request twice — the duplication `unusable_reason` was written to remove — and
    # `tags()` was inheriting the 180 s chat timeout, so the verdict this endpoint exists to
    # deliver early could take longer than the answer it was meant to precede.
    models = client._models()
    if models is None or not client.available(models):
        return JSONResponse({"model": client.model, "state": "missing",
                             "message": f"'{client.model}' is not pulled on this host "
                                        f"(and Ollama may be down). Pull it with: "
                                        f"ollama pull {client.model}"})
    state, message = client.memory_status(models)
    return JSONResponse({"model": client.model, "state": state, "message": message})


def _enrich_requested(payload: dict) -> bool:
    """Whether the assistant may be handed the threat-intel tool for this turn.

    The Settings switch ("Allow outbound threat-intel lookups") wrote `allow_egress` to the shared
    store and NOTHING in the browser ever sent `enrich`, so from the GUI the tool was never
    registered and the switch was decoration: the only way to an enrichment lookup was the CLI or
    an MCP client. The stored setting is now the default, which is what a user who ticked it meant.

    An explicit `enrich` in the body still wins — the field exists for tests and one-off callers —
    and this only decides whether the model is OFFERED the tool. `ai/tools.enrich_indicator`
    re-reads `allow_egress` before any request leaves the machine (§7), so a stale page cannot turn
    egress on by asking.
    """
    if payload.get("enrich") is not None:
        return bool(payload.get("enrich"))
    try:
        return bool(_config_mod().get_setting("allow_egress"))
    except Exception:  # noqa: BLE001 — an unreadable store is not an invitation to reach the network
        return False


@app.post("/api/ai/chat")
async def ai_chat(payload: dict) -> Response:
    """Conversational turn. Body: {question, context?, enrich?}. `context` is an optional analysis
    result (from /api/analyze) the assistant should reason over. Streams SSE."""
    question = (payload.get("question") or "").strip()
    if not question:
        return JSONResponse({"error": "empty question"}, status_code=400)
    return StreamingResponse(
        _ai_stream(question, payload.get("context"), _enrich_requested(payload), payload.get("model")),
        media_type="text/event-stream")


@app.post("/api/ai/explain")
async def ai_explain(payload: dict) -> Response:
    """Per-function 'AI button'. Body: {function, output, question?, enrich?}. Hands one function's
    already-computed output to the engine as context. Streams SSE."""
    output = payload.get("output")
    if output is None:
        return JSONResponse({"error": "no output to explain"}, status_code=400)
    fn = (payload.get("function") or "this analysis").strip()
    question = (payload.get("question") or "").strip() or (
        f"Interpret the '{fn}' output provided as context: what stands out, how serious is it, "
        f"and what should I check next? Ground your reasoning in the RAG and cite sources.")
    return StreamingResponse(
        _ai_stream(question, output, _enrich_requested(payload), payload.get("model")),
        media_type="text/event-stream")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


app.mount("/", StaticFiles(directory=str(STATIC)), name="static")
