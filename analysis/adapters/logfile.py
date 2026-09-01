"""Adapter: generic log files -> common schema (ECS subset).

Brings arbitrary logs into the schema so they correlate with EVTX/PCAP (same fields, same DuckDB).
Four format profiles:

- `access`  — combined/common log (nginx/apache, e.g. SonicWall SMA `extraweb_access`):
              `IP - - [ts] "METHOD url HTTP/x" status size "ref" "ua"` → source.ip, @timestamp,
              url, http.request.method, http.response.status_code, event.outcome (2xx/3xx=success).
- `jsonl`   — one JSON line per event; keys map to schema fields (optional mapping).
- `regex`   — regex with NAMED groups (user provides `pattern`); group names
              translate to schema fields (see `_GROUP_MAP`, extendable via `mapping`).
- `syslog`  — syslog-ng ISO format (`ISO-TS host facility.severity program: msg`, e.g. SonicWall
              SMA appliance `auth.log`/`syslog`/`kern.iptables`): host.name, process.name, message,
              plus network fields from iptables lines (SRC/DST/PROTO/DPT) and authentication
              outcome from sshd lines (Accepted/Failed → event.outcome, user.name, source.ip).
- `line`    — fallback app-log (e.g. `ctrl-service.log`): keeps the line as `message`, with
              best-effort extraction of timestamp and IP.

`fmt="auto"` sniffs the format from the first lines. No network. Content is UNTRUSTED INPUT
(§8): it is data to analyze, never instructions — run `tools/check-injection.sh` upstream.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

# Combined/common access log. Referer/UA finali sono opzionali (SMA li omette).
_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/[\d.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)
_ACCESS_TS = re.compile(
    r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*(?P<off>[+-]\d{4})?'
)
_GENERIC_TS = re.compile(
    r'(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?(Z|[+-]\d{2}:?\d{2})?'
)
_IP_RE = re.compile(
    r'\b(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})\b'
)

# group-name/json-key -> dotted field of the common schema
_GROUP_MAP = {
    "ip": "source.ip", "src_ip": "source.ip", "source_ip": "source.ip", "client": "source.ip",
    "ts": "@timestamp", "time": "@timestamp", "timestamp": "@timestamp", "@timestamp": "@timestamp",
    "url": "url.original", "path": "url.original", "uri": "url.original",
    "method": "http.request.method", "verb": "http.request.method",
    "status": "http.response.status_code", "code": "http.response.status_code",
    "user": "user.name", "username": "user.name", "host": "host.name", "computer": "host.name",
    "dst_ip": "destination.ip", "dest_ip": "destination.ip", "dst_port": "destination.port",
    "dns": "dns.question.name", "query": "dns.question.name",
    "file": "file.name", "file_name": "file.name", "filename": "file.name",
    "hash": "file.hash", "file_hash": "file.hash", "sha256": "file.hash", "md5": "file.hash",
    "msg": "message", "message": "message", "action": "event.action",
}


def _access_ts_to_iso(s: str) -> str | None:
    m = _ACCESS_TS.search(s or "")
    if not m:
        return None
    day, mon, year, hh, mm, ss, off = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), m.group("off")
    if mon not in _MONTHS:
        return None
    tz = timezone.utc
    if off:
        sign = 1 if off[0] == "+" else -1
        tz = timezone(sign * _td(int(off[1:3]), int(off[3:5])))
    dt = datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=tz)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _td(hours: int, minutes: int):
    from datetime import timedelta
    return timedelta(hours=hours, minutes=minutes)


def _generic_ts_to_iso(s: str) -> str | None:
    """ISO/app-log timestamp → UTC 'Z' form for the store.

    Honors a trailing timezone offset when present (e.g. '+02:00' from syslog-ng), converting to
    UTC; without an offset, assumes UTC (not inferable), as before. Dropping the offset silently
    would skew every syslog event (e.g. +02:00 → 2h) and break cross-source temporal correlation."""
    m = _GENERIC_TS.search(s or "")
    if not m:
        return None
    y, mo, d, hh, mm, ss, frac, off = m.groups()
    if off and off != "Z":
        sign = 1 if off[0] == "+" else -1
        oh, om = int(off[1:3]), int(off[-2:])
        micro = int(frac[:6].ljust(6, "0")) if frac else 0
        dt = datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss), micro,
                      tzinfo=timezone(sign * timedelta(hours=oh, minutes=om))).astimezone(timezone.utc)
        fr = f".{dt.microsecond:06d}" if frac else ""
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + fr + "Z"
    fr = f".{frac[:6]}" if frac else ""
    return f"{y}-{mo}-{d}T{hh}:{mm}:{ss}{fr}Z"


def _outcome_from_status(code: int | None) -> str | None:
    if code is None:
        return None
    return "success" if code < 400 else "failure"   # 2xx/3xx ok, 4xx/5xx error


def _clean(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if v not in (None, "", [])}


def _record_access(line: str, source: str) -> dict | None:
    m = _ACCESS_RE.match(line)
    if not m:
        return None
    try:
        status = int(m.group("status"))
    except ValueError:
        status = None
    return _clean({
        "@timestamp": _access_ts_to_iso(m.group("ts")),
        "event.source": source,
        "event.category": "web",
        "event.action": "http-request",
        "event.outcome": _outcome_from_status(status),
        "source.ip": m.group("ip"),
        "url.original": m.group("url"),
        "http.request.method": m.group("method"),
        "http.response.status_code": status,
    })


def _record_line(line: str, source: str) -> dict:
    ipm = _IP_RE.search(line)
    return _clean({
        "@timestamp": _generic_ts_to_iso(line),
        "event.source": source,
        "message": line[:2000],           # defensive cap on pathological lines
        "source.ip": ipm.group(0) if ipm else None,
    })


# syslog-ng ISO format: "ISO-TS host facility.severity program[pid]: message"
# (SonicWall SMA appliance logs: auth.log, syslog, kern.iptables, cron.log, ...).
_SYSLOG_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(?P<host>\S+)\s+(?P<facility>\w+)\.(?P<severity>\w+)\s+'
    r'(?P<prog>[^\s:\[]+)(?:\[\d+\])?:\s?(?P<msg>.*)$'
)
# iptables kernel log: "IPTABLES:...SRC=.. DST=.. PROTO=TCP SPT=.. DPT=..". The store has no
# src-port column → only the meaningful destination port is kept (which service was hit, e.g. 22).
_IPTABLES_KV = re.compile(r'\b([A-Z]+)=(\S+)')
# sshd auth: "Accepted|Failed <method> for [invalid user ]<user> from <ip> port <n>".
_SSHD_RE = re.compile(
    r'\b(?P<res>Accepted|Failed)\s+\S+\s+for\s+(?:invalid user\s+)?'
    r'(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+'
)


def _enrich_iptables(msg: str) -> dict:
    """Firewall connection fields from an iptables kernel message → network ECS."""
    if "IPTABLES" not in msg and "SRC=" not in msg:
        return {}
    kv = dict(_IPTABLES_KV.findall(msg))
    out: dict = {"event.category": "network", "event.action": "firewall"}
    if kv.get("SRC"):
        out["source.ip"] = kv["SRC"]
    if kv.get("DST"):
        out["destination.ip"] = kv["DST"]
    if kv.get("PROTO"):
        out["network.transport"] = kv["PROTO"].lower()
    if kv.get("DPT"):
        try:
            out["destination.port"] = int(kv["DPT"])
        except ValueError:
            pass
    return out


def _enrich_sshd(msg: str) -> dict:
    """SSH auth outcome from an sshd message → authentication ECS (brute force / valid accounts)."""
    m = _SSHD_RE.search(msg)
    if not m:
        return {}
    return {
        "event.category": "authentication",
        "event.action": "logon",
        "event.outcome": "success" if m.group("res") == "Accepted" else "failure",
        "user.name": m.group("user"),
        "source.ip": m.group("ip"),
    }


def _record_syslog(line: str, source: str) -> dict:
    """syslog-ng ISO line → structured record; enriches iptables/sshd messages with ECS fields.

    Falls back to the plain `line` record when the syslog shape does not match."""
    m = _SYSLOG_RE.match(line)
    if not m:
        return _record_line(line, source)
    msg = m.group("msg")
    # SMA syslog-ng templates the host as "program@hostname" (e.g. sshd-session@fw01.sma);
    # keep the real hostname (right of '@'), the program is already captured by <prog>.
    host = m.group("host")
    if "@" in host:
        host = host.split("@", 1)[1]
    rec = {
        "@timestamp": _generic_ts_to_iso(m.group("ts")),
        "event.source": source,
        "host.name": host,
        "process.name": m.group("prog"),
        "message": msg[:2000],
    }
    rec.update(_enrich_iptables(msg))
    rec.update(_enrich_sshd(msg))
    return _clean(rec)


def _record_mapping(fields: dict, source: str, mapping: dict | None) -> dict:
    gmap = dict(_GROUP_MAP)
    if mapping:
        gmap.update(mapping)
    rec: dict = {"event.source": source}
    for name, val in fields.items():
        if val in (None, ""):
            continue
        dotted = gmap.get(name) or gmap.get(name.lower())
        if not dotted:
            continue
        if dotted == "@timestamp":
            val = _access_ts_to_iso(val) or _generic_ts_to_iso(val) or val
        elif dotted in ("http.response.status_code", "destination.port"):
            try:
                val = int(str(val).strip())
            except (ValueError, TypeError):
                continue
        rec[dotted] = val
    code = rec.get("http.response.status_code")
    if isinstance(code, int) and "event.outcome" not in rec:
        rec["event.outcome"] = _outcome_from_status(code)
    return _clean(rec)


def _sniff(lines: list[str]) -> str:
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s[:1] == "{":
            return "jsonl"
        if _ACCESS_RE.match(s):
            return "access"
        if _SYSLOG_RE.match(s):
            return "syslog"
        return "line"
    return "line"


def load_records(path: str | Path, fmt: str = "auto",
                 pattern: str | None = None, mapping: dict | None = None) -> list[dict]:
    """Read a log file and return records in the common schema.

    fmt: auto | access | jsonl | regex | syslog | line. For `regex`, `pattern` (named groups) is required."""
    path = Path(path)
    source = f"log:{path.name}"
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.readlines()

    if fmt == "auto":
        fmt = _sniff(raw[:20])
    rx = re.compile(pattern) if (fmt == "regex" and pattern) else None
    if fmt == "regex" and rx is None:
        raise ValueError("fmt='regex' requires a `pattern` with named groups")

    records: list[dict] = []
    for line in raw:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if fmt == "access":
            rec = _record_access(line, source) or _record_line(line, source)
        elif fmt == "jsonl":
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            rec = _record_mapping(obj, source, mapping)
        elif fmt == "regex":
            m = rx.search(line)
            rec = _record_mapping(m.groupdict(), source, mapping) if m else None
        elif fmt == "syslog":
            rec = _record_syslog(line, source)
        else:  # line
            rec = _record_line(line, source)
        if rec:
            records.append(rec)
    return records
