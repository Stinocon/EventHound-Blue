"""Adapter: JSON from EvtxECmd -> common schema (ECS subset).

Complement to `evtx_hayabusa` (which brings DETECTIONS): here enters the FULL STREAM of
events normalized by EvtxECmd. `event.source="evtx_full"` keeps them distinct from detections
(`evtx`) so they coexist in DuckDB without double counting, and long-tail recipes see every
event, not only those flagged by Sigma.

EvtxECmd emits JSON line-delimited (one line per event, with BOM). The useful fields:
`EventId`, `Channel`, `Computer`, `TimeCreated`, `Keywords`, `Payload` (canonical EventData as
a JSON string: `{"EventData":{"Data":[{"@Name":..,"#text":..}]}}`), and `PayloadData1..6` (labels
already extracted from maps, used as fallback). Category/action come from the SOT EID
(`windows_eventid`, channel-aware). No ATT&CK: EvtxECmd is not a detection engine.

Anonymization downstream (§9), as for the other adapter: here we remain faithful to the raw data.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from adapters.windows_eventid import classify as _classify_eid  # SOT EID map (§16.3)

_EMPTY = (None, "", "-", "n/a", "N/A")

# CANONICAL names of EventData fields (not abbreviated as in Hayabusa).
# `User` is how SYSMON spells it, and it was missing: every process creation, network connection
# and file write from a Sysmon-heavy collection — the normal case for --evtx-full — entered the
# store with no user at all. No identity bridge in correlation, an empty "who" column in the
# timeline, and `summary.distinct_users` undercounting the box.
_USER_KEYS = ("TargetUserName", "SubjectUserName", "AccountName", "User")
# The domain beside the account, so `normalize.realms_conflict` can do its job: it flags
# alice@corp against alice@partner as a POSSIBLE FALSE MERGE, and it had nothing to work with here
# because the adapter took the bare name and dropped the realm the event carried next to it.
_USER_DOMAIN_KEYS = ("TargetDomainName", "SubjectDomainName")
_PROC_NAME_KEYS = ("NewProcessName", "Image", "ProcessName", "Application")
_CMDLINE_KEYS = ("CommandLine", "ProcessCommandLine")
_PARENT_NAME_KEYS = ("ParentProcessName", "ParentImage")
_PARENT_CMDLINE_KEYS = ("ParentCommandLine",)
_SRC_IP_KEYS = ("IpAddress", "SourceIp", "SourceAddress", "ClientAddress")
_DST_IP_KEYS = ("DestinationIp", "DestAddress")
_DST_PORT_KEYS = ("DestinationPort", "DestPort")
_DNS_KEYS = ("QueryName",)
_LOGON_TYPE_KEYS = ("LogonType",)
_FILE_NAME_KEYS = ("TargetFilename", "TargetName")
_FILE_HASH_KEYS = ("Hashes", "Hash")


def _hashes(raw) -> tuple[str | None, str | None]:
    """`(sha256, md5)` out of Sysmon's multi-hash string, or `(value, None)` for a bare hash.

    Sysmon writes `SHA1=…,MD5=…,SHA256=…,IMPHASH=…` into one field. The adapter copied the whole
    string into `file.hash`, and `normalize.canon_hash` takes the part after the LAST `=` — so the
    stored artifact hash was the **IMPHASH**. Two consequences, the second worse than the first:
    the SHA-256 that THOR, CrowdStrike and osquery put in `file.hash` was never corroborated, and
    an imphash is *designed* to be shared by unrelated binaries with the same import table, so the
    store asserted "same artifact" across programs that merely link alike — the `aip` failure mode,
    from a field the report labels "file hash". An analyst pivoting that value into VirusTotal
    looked up the wrong object. The MD5 sitting in the same string was discarded too.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, None
    text = raw.strip()
    if "=" not in text:
        return text, None                      # a bare hash (EVTX `Hash` fields carry one)
    parts: dict[str, str] = {}
    for chunk in text.replace(";", ",").split(","):
        if "=" not in chunk:
            continue
        algo, _, val = chunk.partition("=")
        parts[algo.strip().upper()] = val.strip()
    # IMPHASH is deliberately never a file hash: it identifies an import table, not a file.
    sha = parts.get("SHA256") or parts.get("SHA1") or None
    return sha, parts.get("MD5") or None

_PAYLOAD_DATA_KEYS = tuple(f"PayloadData{i}" for i in range(1, 7))
_TS_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?(?P<off>Z|[+-]\d{2}:?\d{2})?\s*$"
)


def _norm_ts(ts):
    """Normalize the EvtxECmd TimeCreated (explicit offset, 100ns fraction) to ISO-UTC format
    with 'Z' and 6-digit fraction, so the store's TRY_CAST (which strips the 'Z') can parse it."""
    if not isinstance(ts, str):
        return ts
    m = _TS_RE.match(ts.strip())
    if not m:
        return ts
    base = m.group("base").replace(" ", "T")
    frac = (m.group("frac") or "")[:7]      # '.' + up to 6 digits
    off = m.group("off") or ""
    if off in ("", "Z", "+00:00", "+0000"):
        return f"{base}{frac}Z"
    try:                                     # non-UTC offset: convert to UTC
        offc = off if ":" in off else f"{off[:3]}:{off[3:]}"
        dt = datetime.fromisoformat(f"{base}{frac}{offc}")
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    except ValueError:
        return f"{base}{frac}Z"


def _eventdata(payload) -> dict:
    """Extract {name: value} from the Payload's EventData block (JSON string or dict)."""
    if not payload:
        return {}
    try:
        obj = json.loads(payload) if isinstance(payload, str) else payload
    except (json.JSONDecodeError, TypeError):
        return {}
    data = ((obj or {}).get("EventData") or {}).get("Data")
    out: dict = {}
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("@Name"):
                out[item["@Name"]] = item.get("#text")
    elif isinstance(data, dict) and data.get("@Name"):
        out[data["@Name"]] = data.get("#text")
    return out


def _first(d: dict, keys: tuple[str, ...]):
    for k in keys:
        v = d.get(k)
        if v not in _EMPTY:
            return v
    return None


def _port_int(v):
    try:
        return int(str(v).strip()) if v not in (None, "") else None
    except (ValueError, TypeError):
        return None


def _logon_type(ed: dict, d: dict):
    """LogonType from EventData; fallback on PayloadData labels ('LogonType 3')."""
    v = _first(ed, _LOGON_TYPE_KEYS)
    if v not in _EMPTY:
        return v
    for k in _PAYLOAD_DATA_KEYS:
        s = d.get(k)
        if isinstance(s, str) and "logontype" in s.lower().replace(" ", ""):
            m = re.search(r"(\d+)", s)
            if m:
                return m.group(1)
    return None


def _outcome(eid, keywords, category):
    kw = keywords.lower() if isinstance(keywords, str) else ""
    if "failure" in kw:
        return "failure"
    if "success" in kw:
        return "success"
    if eid in (4625, 4771):
        return "failure"
    if eid in (4624, 4634, 4647, 4672, 4768, 4769):
        return "success"
    return None


def _record_from_evtxecmd(d: dict, source: str = "evtx_full") -> dict:
    eid = d.get("EventId")
    channel = d.get("Channel")
    category, action = _classify_eid(eid, channel)
    ed = _eventdata(d.get("Payload"))

    rec = {
        "@timestamp": _norm_ts(d.get("TimeCreated")),
        "event.source": source,
        "event.category": category,
        "event.action": action,
        "event.code": eid if isinstance(eid, int) and not isinstance(eid, bool) else _port_int(eid),
        "event.channel": channel,
        "event.outcome": _outcome(eid, d.get("Keywords"), category),
        "host.name": d.get("Computer"),
        # EvtxECmd also resolves a top-level `UserName` (often `DOMAIN\\account`); it is the
        # fallback, not the primary, because EventData names the subject of the event precisely.
        "user.name": _first(ed, _USER_KEYS) or (d.get("UserName") or None),
        "process.name": _first(ed, _PROC_NAME_KEYS),
        "process.command_line": _first(ed, _CMDLINE_KEYS),
        "process.parent.name": _first(ed, _PARENT_NAME_KEYS),
        "process.parent.command_line": _first(ed, _PARENT_CMDLINE_KEYS),
        "source.ip": _first(ed, _SRC_IP_KEYS),
        "destination.ip": _first(ed, _DST_IP_KEYS),
        "destination.port": _port_int(_first(ed, _DST_PORT_KEYS)),
        "dns.question.name": _first(ed, _DNS_KEYS),
        "logon.type": _logon_type(ed, d),
        "file.name": _first(ed, _FILE_NAME_KEYS),
    }
    sha, md5 = _hashes(_first(ed, _FILE_HASH_KEYS))
    if sha:
        rec["file.hash"] = sha
    if md5:
        rec["file.hash.md5"] = md5
    # The realm goes INTO the name (`CORP\\alice`), not into a field of its own: the store derives
    # `user_domain` from `user.name` via normalize.user_domain, so a separate `user.domain` key
    # would have been written and never read. `canon_user` still reduces this to `alice`, so the
    # identity bridge is unchanged — what it gains is the realm, which is what `realms_conflict`
    # needs to flag alice@corp against alice@partner as a possible FALSE merge.
    dom = _first(ed, _USER_DOMAIN_KEYS)
    if dom and rec.get("user.name") and "\\" not in str(rec["user.name"]) and "@" not in str(rec["user.name"]):
        rec["user.name"] = f"{dom}\\{rec['user.name']}"
    return {k: v for k, v in rec.items() if v not in (None, [], "")}


def load_records(json_path: str | Path, source: str = "evtx_full") -> list[dict]:
    """Read the EvtxECmd JSON line-delimited output and return records in the common schema.

    Args:
        json_path: Path to the EvtxECmd JSON output.
        source: Source string to tag each record with (default ``"evtx_full"``).
                Pass ``f"evtx_full:{filename}"`` for file-level granularity (see correlate.py).
    """
    records: list[dict] = []
    # utf-8-sig: discards the BOM; errors=replace: a non-UTF-8 byte degrades the line, does not abort the load.
    with open(json_path, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(d, dict):
                continue
            records.append(_record_from_evtxecmd(d, source=source))
    return records
