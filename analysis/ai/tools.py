"""Read-only tool registry exposed to the local LLM (DESIGN §14.3).

Every tool here is READ-ONLY: it retrieves or computes, it never acts on a real system
(§12). Step 1 ships a single tool — `rag_search`, the grounding tool (§6/§14.6) — reusing
the exact HTTP→subprocess fallback the GUI uses for the RAG, so it works with the `rag-api`
service (warm) or, if it is down, the RAG venv subprocess (always available). scoring /
enrichment / query_analysis join the registry in later steps (§14.8).

A `Tool` bundles the Ollama function schema (what the model sees) with the callable that
executes it. `default_registry()` returns the name→Tool map the engine dispatches over.
"""
from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
RAG_DIR = REPO_ROOT / "rag"

# The RAG collections the model may target; named in the schema so it picks the right one.
RAG_COLLECTIONS = ["knowledge_cyber", "normative", "acn"]


@dataclass
class Tool:
    schema: dict                      # Ollama function schema (type/function/name/parameters)
    func: Callable[..., dict]         # executes the call, returns a JSON-serializable dict


# --- rag_search -----------------------------------------------------------

def _rag_via_http(payload: dict, base_url: str) -> dict | None:
    """Query the rag-api service. None if unreachable → subprocess fallback."""
    body = json.dumps(payload).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/search", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 — local/trusted URL
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"error": f"rag-api HTTP {e.code}", "results": []}
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return None


def _rag_via_subprocess(query: str, collection: str, k: int) -> dict:
    """Fallback: run retrieval in the RAG venv (has the ML stack). Slower (cold models),
    but works without the service or Docker — same contract as the GUI's fallback."""
    cmd = ["uv", "run", "python", "-m", "pipeline.retrieve", query,
           "--collection", collection, "--k", str(k), "--format", "json"]
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


def _compact_result(r: dict, snippet_chars: int) -> dict:
    """Trim a retrieval hit to what the model needs to reason and cite (§14.4 budget):
    the citation fields + a bounded text snippet, dropping raw score internals."""
    text = (r.get("text") or "").strip()
    if len(text) > snippet_chars:
        text = text[:snippet_chars].rstrip() + "…"
    return {
        "source": r.get("source_name") or r.get("title"),
        "level": r.get("level"),
        "url": r.get("url"),
        "locator": r.get("locator"),
        "text": text,
    }


def rag_search(query: str, collection: str = "knowledge_cyber", k: int = 5,
               *, rag_api_url: str = "http://127.0.0.1:8600",
               snippet_chars: int = 600) -> dict:
    """Hybrid retrieval over an EventHound RAG collection. Returns compacted, citable hits.

    This is the grounding tool: the model calls it before making a technical claim, and
    cites `source`/`url`/`locator` from the results (§6/§14.6)."""
    query = (query or "").strip()
    if not query:
        return {"results": [], "note": "empty query"}
    if collection not in RAG_COLLECTIONS:
        collection = "knowledge_cyber"
    k = max(1, min(int(k or 5), 10))

    data = _rag_via_http({"query": query, "collection": collection, "k": k, "level": None},
                         rag_api_url)
    if data is None:  # service down → RAG venv
        data = _rag_via_subprocess(query, collection, k)
    if data.get("error"):
        return {"error": data["error"], "results": []}
    hits = [_compact_result(r, snippet_chars) for r in (data.get("results") or [])]
    return {"collection": collection, "results": hits}


RAG_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "rag_search",
        "description": (
            "Search EventHound's local knowledge base (MITRE ATT&CK, GDPR/NIS2/DORA "
            "regulations, ACN guidance) with hybrid retrieval. "
            "Call this to ground any technical claim before stating it, and cite the returned "
            "source. Returns the most relevant passages with their source and locator."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "the search query"},
                "collection": {
                    "type": "string",
                    "enum": RAG_COLLECTIONS,
                    "description": ("knowledge_cyber = ATT&CK/frameworks; "
                                    "normative = GDPR/NIS2/DORA; acn = ACN"),
                },
                "k": {"type": "integer", "description": "number of passages (1-10, default 5)"},
            },
            "required": ["query"],
        },
    },
}


# --- eid_lookup -----------------------------------------------------------

def eid_lookup(event_id, channel: str | None = None) -> dict:
    """Windows Event ID → its meaning from EventHound's channel-aware SOT (windows_eventid).

    Grounds the model on EIDs from the DATA, not from memory — a 7-8B model confabulates EID
    semantics (§14.9). Unmapped IDs return mapped=False (say 'verify', do not invent, §6)."""
    from adapters import windows_eventid as w
    category, action = w.classify(event_id, channel)
    mapped = (category, action) != (None, None)
    return {
        "event_id": event_id,
        "channel": channel,
        "category": category,
        "action": action,
        "mapped": mapped,
        "note": None if mapped else
        "not in the known Event ID map — treat any meaning as a hypothesis to verify against "
        "Microsoft docs; do not state a definition as fact.",
    }


EID_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "eid_lookup",
        "description": (
            "Look up the meaning (category + action) of a Windows Event ID from EventHound's "
            "channel-aware map. Call this before describing what an Event ID means — do not rely "
            "on memory. Returns mapped=false when the ID is unknown (then say it must be verified)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "event_id": {"type": "integer", "description": "the Windows Event ID (e.g. 4624)"},
                "channel": {"type": "string",
                            "description": "event channel to disambiguate (e.g. 'Security', "
                                           "'System', 'Microsoft-Windows-Sysmon/Operational')"},
            },
            "required": ["event_id"],
        },
    },
}


# --- query_analysis (read-only detail over the current analysis store) -----

_QA_COLS = ("ts", "source", "category", "action", "event_code", "outcome", "host",
            "user_name", "process_name", "cmdline", "src_ip", "dst_ip", "message")


def _make_query_analysis(records: list[dict]):
    """Build a read-only `query_analysis` over a DuckDB store rebuilt from the saved records.

    Only a fixed set of PARAMETERIZED queries is exposed (no free-form SQL from the model): a
    small-model footgun and an injection surface, avoided by construction (§12 read-only)."""
    from analytics import store  # local import: duckdb only needed when a context is loaded

    con = store.from_records(records) if records else None
    cols = ", ".join(f'"{c}"' for c in _QA_COLS)

    def _rows(where: str, params: list, limit: int) -> list[dict]:
        limit = max(1, min(int(limit or 20), 100))
        cur = con.execute(f"SELECT {cols} FROM events WHERE {where} "
                          f"ORDER BY ts_parsed NULLS LAST LIMIT {limit}", params)
        names = [d[0] for d in cur.description]
        out = []
        for r in cur.fetchall():
            row = {n: v for n, v in zip(names, r) if v not in (None, "")}
            if isinstance(row.get("message"), str) and len(row["message"]) > 200:
                row["message"] = row["message"][:200] + "…"
            out.append(row)
        return out

    def query_analysis(op: str, value: str | int | None = None, limit: int = 20) -> dict:
        if con is None:
            return {"error": "no analysis context loaded (run with --context)"}
        try:
            if op == "events_for_host":
                rows = _rows("host = ?", [str(value)], limit)
            elif op == "events_for_user":
                rows = _rows("user_name = ?", [str(value)], limit)
            elif op == "by_event_code":
                rows = _rows("event_code = ?", [int(value)], limit)
            elif op == "search":
                pat = f"%{value}%"
                rows = _rows("message ILIKE ? OR process_name ILIKE ? OR cmdline ILIKE ? "
                             "OR url ILIKE ? OR file_name ILIKE ?", [pat] * 5, limit)
            else:
                return {"error": f"unknown op '{op}' (use events_for_host|events_for_user|"
                                 "by_event_code|search)"}
        except (ValueError, TypeError) as e:
            return {"error": f"bad value for op '{op}': {e}"}
        return {"op": op, "value": value, "matched": len(rows), "rows": rows}

    return query_analysis


QUERY_ANALYSIS_SCHEMA = {
    "type": "function",
    "function": {
        "name": "query_analysis",
        "description": (
            "Fetch detail rows from the CURRENT analysis on demand (read-only). Use it to pull "
            "the events behind a finding instead of guessing. ops: events_for_host / "
            "events_for_user / by_event_code / search (substring over message/process/cmdline/"
            "url/file)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "op": {"type": "string",
                       "enum": ["events_for_host", "events_for_user", "by_event_code", "search"]},
                "value": {"type": "string",
                          "description": "the host/user/event-id/search term for the op"},
                "limit": {"type": "integer", "description": "max rows (1-100, default 20)"},
            },
            "required": ["op", "value"],
        },
    },
}


# --- scoring (deterministic oracle, §6 — numbers never by hand) -----------

def _scoring_mod():
    import sys
    sp = str(REPO_ROOT / "tools" / "scoring")
    if sp not in sys.path:
        sys.path.insert(0, sp)
    import scoring
    return scoring


def cvss_score(vector: str) -> dict:
    """CVSS base score from a vector, via the golden-tested oracle (§6). Dispatches v3.1/v4.0."""
    s = _scoring_mod()
    v = (vector or "").strip()
    return s.cvss_v40_base(v) if v.upper().startswith("CVSS:4.0") else s.cvss_v31_base(v)


def risk_score(likelihood: int, impact: int, scale: int = 5) -> dict:
    """Likelihood × impact risk from the oracle's matrix (§6), never computed by hand."""
    return _scoring_mod().risk_matrix(int(likelihood), int(impact), int(scale))


CVSS_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "cvss_score",
        "description": ("Compute a CVSS base score (v3.1 or v4.0) from its vector string via the "
                        "deterministic oracle. Always use this for a CVSS number — never state one "
                        "from memory (§6). Returns score, severity and the parsed metrics."),
        "parameters": {
            "type": "object",
            "properties": {"vector": {"type": "string",
                           "description": "CVSS vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
            "required": ["vector"],
        },
    },
}

RISK_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "risk_score",
        "description": ("Compute a likelihood×impact risk level from the oracle's matrix. Use this "
                        "instead of asserting a risk rating; returns product, normalized value and "
                        "level."),
        "parameters": {
            "type": "object",
            "properties": {
                "likelihood": {"type": "integer", "description": "1..scale"},
                "impact": {"type": "integer", "description": "1..scale"},
                "scale": {"type": "integer", "description": "matrix scale (default 5)"},
            },
            "required": ["likelihood", "impact"],
        },
    },
}


# --- enrichment (egress-gated, public indicators only, §9/§14.5) ----------

def _enrichment_mod():
    import sys
    sp = str(REPO_ROOT / "tools" / "enrichment")
    if sp not in sys.path:
        sys.path.insert(0, sp)
    import enrichment
    return enrichment


def _config_mod():
    """Shared config store (tools/eventhound_config.py): stored API keys + the egress preference."""
    import sys
    sp = str(REPO_ROOT / "tools")
    if sp not in sys.path:
        sys.path.insert(0, sp)
    import eventhound_config
    return eventhound_config


def enrich_indicator(indicator: str) -> dict:
    """Look up a PUBLIC indicator's reputation/exposure. The oracle's own guard blocks any
    private/reserved IP or internal domain even here (client data never leaves, §9).

    Two consents are required, not one: the indicator must be public, AND the user must have
    enabled outbound lookups (Settings → 'Allow outbound threat-intel lookups', or
    `python tools/eventhound_config.py set-setting allow_egress true`). Otherwise the model could
    put traffic on the wire on its own initiative — §7/§15 say that stays the user's decision.
    Keyed services (VirusTotal, ThreatFox) are used only when their key is configured."""
    e = _enrichment_mod()
    cfg = _config_mod()
    indicator = (indicator or "").strip()
    kind = e.indicator_kind(indicator)
    if not e.is_public(indicator):
        return {"error": f"'{indicator}' is not a public indicator (client data?) — not sent (§9)",
                "kind": kind}
    if not cfg.get_setting("allow_egress"):
        return {"error": "outbound lookups are disabled: enable them in Settings (or "
                         "`python tools/eventhound_config.py set-setting allow_egress true`) "
                         "before external enrichment (§7/§15).",
                "kind": kind, "indicator": indicator}
    out: dict = {"kind": kind, "indicator": indicator}
    if kind == "ip":
        out["shodan_internetdb"] = e.shodan_internetdb(indicator, allow_egress=True)
    if cfg.get_api_key("virustotal"):
        out["virustotal"] = e.virustotal(indicator, allow_egress=True)
    if cfg.get_api_key("threatfox"):
        out["threatfox"] = e.threatfox(indicator, allow_egress=True)
    if len(out) == 2:      # nothing but kind/indicator: no keyless path and no key configured
        out["note"] = ("keyless enrichment covers public IPs (Shodan InternetDB); hash/domain "
                       "lookups need a VirusTotal or ThreatFox key — add one in Settings.")
    return out


ENRICH_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "enrich_indicator",
        "description": ("Look up external reputation/exposure of a PUBLIC indicator (a public IP, "
                        "hash or domain). NEVER pass a private/internal IP, hostname, username or "
                        "corporate domain — those are client data and are refused. Sends the "
                        "indicator to a third party (opt-in egress)."),
        "parameters": {
            "type": "object",
            "properties": {"indicator": {"type": "string",
                           "description": "a public IP / file hash / domain"}},
            "required": ["indicator"],
        },
    },
}


def default_registry(*, rag_api_url: str = "http://127.0.0.1:8600",
                     records: list[dict] | None = None,
                     enrich: bool = False) -> dict[str, Tool]:
    """Read-only tool registry (§14.3). Always: rag_search (grounding), eid_lookup (EID SOT),
    cvss_score + risk_score (deterministic oracle, §6). With an analysis context (`records`):
    query_analysis for on-demand detail. With `enrich=True` (opt-in egress, §9): enrich_indicator."""
    reg = {
        "rag_search": Tool(
            schema=RAG_TOOL_SCHEMA,
            func=lambda query, collection="knowledge_cyber", k=5: rag_search(
                query, collection=collection, k=k, rag_api_url=rag_api_url),
        ),
        "eid_lookup": Tool(
            schema=EID_TOOL_SCHEMA,
            func=lambda event_id, channel=None: eid_lookup(event_id, channel),
        ),
        "cvss_score": Tool(schema=CVSS_TOOL_SCHEMA, func=lambda vector: cvss_score(vector)),
        "risk_score": Tool(schema=RISK_TOOL_SCHEMA,
                           func=lambda likelihood, impact, scale=5: risk_score(likelihood, impact, scale)),
    }
    if records is not None:
        reg["query_analysis"] = Tool(schema=QUERY_ANALYSIS_SCHEMA,
                                     func=_make_query_analysis(records))
    if enrich:
        reg["enrich_indicator"] = Tool(schema=ENRICH_TOOL_SCHEMA,
                                       func=lambda indicator: enrich_indicator(indicator))
    return reg
