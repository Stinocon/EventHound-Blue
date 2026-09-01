"""Adapter: CrowdStrike detection/investigation -> common schema (ECS subset).

Two input formats, auto-detected:
1. **Detection clipboard** — text copied from the CrowdStrike console via
   Action > Copy Detection to Clipboard (or Copy Support Information).
   Format: ``Key: Value`` lines, one detection per block.
2. **LogScale/Investigation JSON** — output of a LogScale/CQL query, either
   standalone JSON, NDJSON, or the full ``@rawstring`` wrapper.

Field mapping (grounded on real data, not guessed):
    Host name / ComputerName     -> host.name
    File name                    -> file.name
    File path                    -> file.path
    Command line                 -> process.command_line
    SHA 256 / SHA256HashData     -> file.hash.sha256
    MD5 Hash                     -> file.hash.md5
    IP address / LocalAddressIP4  -> source.ip  (aip is NOT: see the note in _LOGSCALE_MAP)
    User name / UserName         -> user.name
    Detected / timestamp         -> @timestamp
    Description                  -> message
    Platform / event_platform    -> host.os
    event_simpleName             -> event.action (LogScale only)

Namespaced crowdstrike.* extras carry agent ID, customer ID, detection URL,
user SID, and raw event fields for detail.

NOTE: grounded on real client data (two formats confirmed 2026-07-24).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_SOURCE = "crowdstrike"

_CLIPBOARD_MAP = {
    "Host name": "host.name",
    "File name": "file.name",
    "File path": "file.path",
    "Command line": "process.command_line",
    "SHA 256": "file.hash.sha256",
    "MD5 Hash": "file.hash.md5",
    "IP address": "source.ip",
    "User name": "user.name",
    "Platform": "host.os",
    "Description": "message",
    "Agent ID": "crowdstrike.agent_id",
    "Customer ID": "crowdstrike.customer_id",
    "Full detection details": "crowdstrike.detection_url",
    "Pattern": "crowdstrike.pattern",
}

_LOGSCALE_MAP = {
    "ComputerName": "host.name",
    "SHA256HashData": "file.hash.sha256",
    "UserName": "user.name",
    "LocalAddressIP4": "source.ip",
    "event_simpleName": "event.action",
    "event_platform": "host.os",
    "RawProcessId": "process.pid",
    "ParentProcessId": "process.parent.pid",
    # Process/network/DNS fields the common schema documents for LogScale events (schema 0.5.0
    # names ImageFileName/CommandLine for ProcessRollup2; DomainName and RemoteAddressIP4 are the
    # canonical Falcon LogScale field names for the DNS and network-connect event families).
    "ImageFileName": "process.name",
    "CommandLine": "process.command_line",
    "DomainName": "dns.question.name",
    "RemoteAddressIP4": "destination.ip",
    "aid": "crowdstrike.agent_id",
    # `aip` is the agent's EXTERNAL address — the tenant's NAT egress, identical for every host
    # behind it. It is deliberately NOT mapped to source.ip: as a correlation indicator it would
    # bridge every CrowdStrike event to every other one, the same noise that gets loopback and
    # SYSTEM excluded in correlate.py. Kept namespaced, so it stays visible and queryable.
    "aip": "crowdstrike.agent_ip",
    "cid": "crowdstrike.customer_id",
    "UserSid": "crowdstrike.user_sid",
    "name": "crowdstrike.event_name",
    "id": "crowdstrike.event_id",
    "ExitCode": "crowdstrike.exit_code",
    "ProcessStartTime": "crowdstrike.process_start_time",
}

# Regex to extract the UTC timestamp from the Detected field.
_UTC_TS_RE = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC\)")


def _clean(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if v not in (None, "", [], {})}


def _parse_clipboard(text: str) -> list[dict]:
    """Parse the Key: Value clipboard format, one detection per block."""
    from datetime import datetime, timezone

    blocks = re.split(r"\n\s*\n", text.strip())
    out: list[dict] = []
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        rec: dict[str, str | None] = {}
        for line in block.splitlines():
            line = line.strip()
            if not line:
                continue
            # Split on ': ' (first occurrence only, since values contain colons)
            idx = line.find(": ")
            if idx == -1:
                continue
            key = line[:idx].strip()
            value = line[idx + 2:].strip()
            if key in _CLIPBOARD_MAP:
                rec[_CLIPBOARD_MAP[key]] = value
            elif key == "Detected":
                # Extract UTC timestamp from "(YYYY-MM-DD HH:MM:SS UTC)"
                m = _UTC_TS_RE.search(value)
                if m:
                    try:
                        dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
                        rec["@timestamp"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                    except ValueError:
                        pass
        if not rec:
            continue
        rec["event.source"] = _SOURCE
        rec["event.category"] = "threat"
        out.append(_clean(rec))
    return out


def _parse_logscale_event(ev: dict) -> dict | None:
    """Map one LogScale JSON event to the common schema."""
    from datetime import datetime, timezone

    if not isinstance(ev, dict):
        return None
    rec: dict[str, str | None] = {}
    for src_key, dst_key in _LOGSCALE_MAP.items():
        if src_key not in ev:
            continue
        val = ev[src_key]
        if val is None:
            continue
        rec[dst_key] = str(val)

    # Convert timestamp (epoch milliseconds string) to ISO-8601
    ts_raw = ev.get("timestamp")
    if ts_raw is not None:
        try:
            ts_ms = int(ts_raw)
            dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
            rec["@timestamp"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError, OSError):
            pass

    rec["event.source"] = _SOURCE
    # Only claim a category the record actually supports: a LogScale query returns process, network
    # and DNS events alike, and labelling all of them "process" would put a wrong value in a field
    # the analytics group by. No process field mapped -> no category asserted (§6).
    if any(k.startswith("process.") for k in rec):
        rec["event.category"] = "process"
    return _clean(rec)


def _parse_logscale(text: str) -> list[dict]:
    """Handle three sub-formats: @rawstring wrapper, single JSON, NDJSON."""
    text = text.strip()
    if not text:
        return []

    # Check for @rawstring wrapper
    if "@rawstring:" in text:
        events_json: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("@rawstring:"):
                raw = line[len("@rawstring:"):].strip()
                if raw:
                    events_json.append(raw)
        if events_json:
            out: list[dict] = []
            for raw in events_json:
                try:
                    ev = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                rec = _parse_logscale_event(ev)
                if rec:
                    out.append(rec)
            return out

    # Try single JSON object
    try:
        data = json.loads(text)
        if isinstance(data, list):
            events = data
        else:
            events = [data]
        out = []
        for ev in events:
            rec = _parse_logscale_event(ev)
            if rec:
                out.append(rec)
        return out
    except json.JSONDecodeError:
        pass

    # NDJSON fallback: one JSON per non-empty line
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        rec = _parse_logscale_event(ev)
        if rec:
            out.append(rec)
    return out


def _detect_format(text: str) -> str:
    """Return 'clipboard' or 'logscale' based on content heuristics."""
    text_stripped = text.strip()
    if not text_stripped:
        return "clipboard"  # default
    if "@rawstring" in text_stripped:
        return "logscale"
    # A JSON export saved as a single object (`{...}`) OR as an array (`[...]`). The array shape was
    # NOT detected here: `_detect_format` only looked for `{`, so a LogScale query exported as a
    # JSON array fell through to the clipboard parser, which reads `Key: Value` lines and found none
    # — the whole source yielded nothing, with no error anywhere.
    if text_stripped.startswith("{") or text_stripped.startswith("["):
        return "logscale"
    if "Host name:" in text_stripped or "Description:" in text_stripped:
        return "clipboard"
    # Default: try clipboard first (more common use case)
    return "clipboard"


def _parse(text: str) -> list[dict]:
    """Main dispatcher: detect format and parse accordingly."""
    fmt = _detect_format(text)
    if fmt == "clipboard":
        return _parse_clipboard(text)
    return _parse_logscale(text)


def load_records(path: str | Path) -> list[dict]:
    """CrowdStrike detection/investigation data as common-schema records.

    Accepts detection clipboard text (.txt) or LogScale/CQL JSON (.json/.log).
    Format is auto-detected.
    """
    return _parse(Path(path).read_text(encoding="utf-8", errors="replace"))