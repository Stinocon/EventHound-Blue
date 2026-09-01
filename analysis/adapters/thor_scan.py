"""Adapter: THOR / THOR Lite (Nextron) scan reports -> common schema (ECS subset).

THOR is a forensic scanner; its findings (suspicious files, filename/hash IOC hits, YARA/Sigma
matches, anomalies) correlate naturally with EVTX/MFT/PCAP via file hash, file name, host and user.

Input (SOT = the `.txt` report — richer than the HTML render and the md5s CSV):
    <Mon DD HH:MM:SS> <HOST>/<IP> THOR: <Severity>: MODULE: <m> MESSAGE: <msg> SCORE: N
        FILE: <path> MD5: .. SHA1: .. SHA256: .. OWNER: <acct> REASON_1: <why>
        SIGCLASS_1: <class> MATCHED_1: <ioc> REF_1: <ref> ... SCANID: S-...
Values may contain spaces, backslashes and colons (timestamps, ACLs, hex); KEYS are always
uppercase tokens followed by ": " (colon + SPACE), so we split on that boundary only.
Severity ladder: Alert > Warning > Notice > Info. Findings = scored lines (Warning/Notice with SCORE).
The syslog prefix carries no year (inferred from the report filename); THOR logs the .txt in UTC.

A `.csv` companion (`md5,path,score`) is a lower-fidelity fallback used only when no .txt is given.

Anonymization (§9): host.name / user.name (OWNER) are client identifiers, pseudonymized downstream
(after parsing, like every adapter). Hashes / IOC rule names are technical indicators, not pseudonymized.
"""
from __future__ import annotations

import csv as _csv
import re
from pathlib import Path

_SOURCE = "thor"

# A THOR line: syslog prefix (no year) + "HOST/IP THOR: <sev>: <rest>".
_LINE_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^/\s]+)(?:/(?P<ip>[0-9.]+))?\s+THOR:\s+(?P<sev>\w+):\s+(?P<rest>.*)$"
)
# Key boundary: a leading space, an UPPERCASE token (optionally _<n> indexed), then ": ".
_KEY_RE = re.compile(r" ([A-Z][A-Z0-9_]*): ")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
# THOR severity word -> ioc severity label (THOR's own level, not a computed score, §6).
_SEVERITY = {"Alert": "high", "Warning": "medium", "Notice": "low", "Info": "info", "Error": "info"}
_YEAR_RE = re.compile(r"_(\d{4})-\d{2}-\d{2}_")


def _clean(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if v not in (None, "", [])}


def _basename(path: str | None) -> str | None:
    """Basename of a Windows or POSIX path (the cross-source file join key)."""
    if not path:
        return None
    return re.split(r"[\\/]", path.strip())[-1] or None


def _parse_kv(rest: str) -> dict:
    """Split the post-severity remainder into {KEY: value} on ' KEY: ' boundaries."""
    s = " " + rest  # so the first key (MODULE) is matched too
    keys = list(_KEY_RE.finditer(s))
    out: dict[str, str] = {}
    for i, m in enumerate(keys):
        end = keys[i + 1].start() if i + 1 < len(keys) else len(s)
        out[m.group(1)] = s[m.end():end].strip()
    return out


def _int(v: str | None) -> int | None:
    if v is None:
        return None
    v = v.strip()
    return int(v) if v.lstrip("-").isdigit() else None


def _year_from_name(path: Path) -> int:
    m = _YEAR_RE.search(path.name)
    if m:
        return int(m.group(1))
    # The filename carries the year when present. When it does not, the report's mtime year is a
    # real observation time — the moment the report was written to disk, which is >= the scan.
    # The old fallback was `datetime.now().year`: a THOR report from any past year was silently
    # stamped with the CURRENT year, so every finding landed in the wrong year and the timeline
    # placed a years-old scan "today".
    from datetime import datetime, timezone
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).year
    except OSError:
        # No name, no stat: there is no honest year. 1970 is wrong too, so the caller must not
        # receive a fabricated one — raise is disproportionate for one unreadable file, so return
        # a sentinel the timestamp builder treats as "no year available".
        return 0


def _record_from_line(line: str, year: int) -> list[dict]:
    """Zero, one or two records: the primary finding, plus a 'linked' record when the line
    carries a secondary file object (FILE_1/MD5_1/SHA256_1 — a referenced/related sample).
    The linked record is correlatable (its hash/name/host become indicators) but is not a
    scored finding, so it stays out of the findings table (excluded in analyze())."""
    m = _LINE_RE.match(line)
    if not m:
        return []
    sev = m.group("sev")
    kv = _parse_kv(m.group("rest"))
    # A finding is a scored line; unscored Info/Notice telemetry (version, license) is skipped.
    if "SCORE" not in kv:
        return []
    mon = _MONTHS.get(m.group("mon"))
    if not mon:
        return []
    # `year == 0` means "no honest year is available" (no filename year, no mtime): a finding
    # with no usable time is better than one stamped `0000-…`, which is a fabrication. `_clean`
    # drops a None @timestamp, so the record simply carries no time.
    ts = f"{year:04d}-{mon:02d}-{int(m.group('day')):02d}T{m.group('time')}Z" if year else None
    file_full = kv.get("FILE")
    module = kv.get("MODULE")
    host = m.group("host")
    primary = _clean({
        "@timestamp": ts,
        "event.source": _SOURCE,
        "event.category": "malware",
        "event.action": "thor-" + (module.lower() if module else "match"),
        "event.outcome": "unknown",
        "host.name": host,
        "user.name": kv.get("OWNER"),
        "file.name": _basename(file_full),
        "file.hash": kv.get("SHA256"),        # primary correlation key
        "file.hash.md5": kv.get("MD5"),       # secondary correlation key (union in correlate.py)
        "message": kv.get("MESSAGE"),
        "rule.title": kv.get("MATCHED_1") or kv.get("REASON_1"),
        "ioc.description": kv.get("REASON_1"),
        "ioc.severity": _SEVERITY.get(sev),
        # Namespaced THOR extras — travel in the record (not DuckDB columns) for the findings table.
        "thor.score": _int(kv.get("SCORE")),
        "thor.severity": sev,
        "thor.module": module,
        "thor.path": file_full,
        "thor.ext": kv.get("EXT"),
        "thor.size": _int(kv.get("SIZE")),
        "thor.md5": kv.get("MD5"),
        "thor.sha1": kv.get("SHA1"),
        "thor.sha256": kv.get("SHA256"),
        "thor.sigclass": kv.get("SIGCLASS_1"),
        "thor.ref": kv.get("REF_1"),
        "thor.host_ip": m.group("ip"),
        "thor.created": kv.get("CREATED"),
        "thor.modified": kv.get("MODIFIED"),
    })
    out = [primary]
    # Secondary object (_1): a referenced/related file (its own hashes/name). Emitted as a
    # 'linked' record so its hash/name/host also correlate cross-source; kept out of the
    # findings table (no score). We map only the known file fields — no invented semantics.
    if kv.get("FILE_1") or kv.get("SHA256_1") or kv.get("MD5_1"):
        out.append(_clean({
            "@timestamp": ts,
            "event.source": _SOURCE,
            "event.category": "malware",
            "event.action": "thor-linked",
            "host.name": host,
            "user.name": kv.get("OWNER_1") or kv.get("OWNER"),
            "file.name": _basename(kv.get("FILE_1")),
            "file.hash": kv.get("SHA256_1"),
            "file.hash.md5": kv.get("MD5_1"),
            "message": kv.get("MESSAGE"),
            "ioc.severity": _SEVERITY.get(sev),
            "thor.linked": True,
            "thor.linked_to": _basename(file_full),
            "thor.path": kv.get("FILE_1"),
            "thor.sha1": kv.get("SHA1_1"),
            "thor.sha256": kv.get("SHA256_1"),
            "thor.md5": kv.get("MD5_1"),
            "thor.exists": kv.get("EXISTS_1"),
            "thor.module": module,
        }))
    return out


def _from_report(path: Path) -> list[dict]:
    year = _year_from_name(path)
    out: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            out.extend(_record_from_line(line.rstrip("\n"), year))
    return out


def _from_csv(path: Path) -> list[dict]:
    """Fallback: the `md5,path,score` companion (no timestamps/rules, lower fidelity)."""
    out: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        for row in _csv.reader(fh):
            if len(row) < 2:
                continue
            md5, fpath = row[0].strip(), row[1].strip()
            score = _int(row[2]) if len(row) > 2 else None
            if not md5:
                continue
            out.append(_clean({
                "event.source": _SOURCE,
                "event.category": "malware",
                "event.action": "thor-match",
                "file.name": _basename(fpath),
                "file.hash.md5": md5,
                "ioc.severity": "medium",
                "thor.score": score,
                "thor.path": fpath,
                "thor.md5": md5,
                "thor.sigclass": "Filename",
            }))
    return out


def load_records(report: str | Path | None = None, md5s: str | Path | None = None) -> list[dict]:
    """THOR findings as common-schema records.

    `report`: the THOR `.txt` (authoritative). `md5s`: the `md5,path,score` CSV, used as a
    fallback only when no report is given. At least one must be provided.
    """
    if report:
        return _from_report(Path(report))
    if md5s:
        return _from_csv(Path(md5s))
    raise ValueError("thor_scan.load_records: provide a report .txt or an md5s .csv")
