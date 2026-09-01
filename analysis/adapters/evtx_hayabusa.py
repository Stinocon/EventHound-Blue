"""Adapter: Hayabusa timeline (JSONL) -> common schema (ECS subset).

Normalizes each detection produced by Hayabusa into a record of the common schema
defined in analysis/schema/common-schema.md. Process/network/user fields are
extracted best-effort from the `Details` block, whose keys vary by event
type (Sysmon vs Security vs PowerShell). When a field cannot be determined,
it is left absent: nothing is fabricated (consistent with §6 — method/conventions.md).

Anonymization: internal host/user/IP must be pseudonymized *downstream* (see
common-schema.md and method/anonymization.md), not here: the adapter remains
faithful to the raw data, pseudonymization is a separate step before
shareable output.
"""
from __future__ import annotations

import json
from pathlib import Path

from adapters.windows_eventid import classify as _classify_eid  # SOT of the EID map (§16.3)

# Candidate keys in Details (order of preference). Hayabusa uses abbreviated names.
_PROC_NAME_KEYS = ("Image", "Proc", "SrcProc", "Process", "NewProc", "NewProcess", "Application")
_CMDLINE_KEYS = ("CmdLine", "Cmdline", "CommandLine", "Command")
# ParentCmdLine is a COMMAND LINE, not a name: it goes in the parent's command_line field, not in
# process.parent.name (which is a keyword/process name). Keep the two distinct.
_PARENT_NAME_KEYS = ("ParentImage", "ParentProc", "ParentProcessName")
_PARENT_CMDLINE_KEYS = ("ParentCmdLine", "ParentCommandLine")
_USER_KEYS = ("User", "SubjectUserName", "TargetUserName", "SrcUser", "TgtUser")
_SRC_IP_KEYS = ("SrcIP", "SourceIp", "src_ip")
_DST_IP_KEYS = ("DstIP", "DestinationIp", "TgtIP", "dst_ip")
_DST_PORT_KEYS = ("DstPort", "DestinationPort", "TgtPort")
_DNS_KEYS = ("Query", "QueryName", "DnsQuery")

# Hayabusa's MitreTactics uses an abbreviated vocabulary — its own config/mitre_tactics.txt is the
# source (`tag_output_str`). Passed through as-is, "DefImpair"/"CredAccess" reached the reports as
# if they were ATT&CK tactic names, and `attack.phase_of_tactic("defimpair")` resolved to nothing:
# a tactic-only Sigma rule (345 of the 3142 vendored rules declare a tactic and no technique ID)
# carried its phase into the store as an opaque string no kill-chain view could place. Normalized
# here to the full ATT&CK kebab-case name.
_HAYABUSA_TACTIC_MAP = {
    "Recon": "reconnaissance",
    "ResDev": "resource-development",
    "InitAccess": "initial-access",
    "Exec": "execution",
    "Persis": "persistence",
    "PrivEsc": "privilege-escalation",
    "Stealth": "stealth",             # defense-evasion maps to Stealth too (config/mitre_tactics.txt)
    "DefImpair": "defense-impairment",
    "CredAccess": "credential-access",
    "Disc": "discovery",
    "LatMov": "lateral-movement",
    "Collect": "collection",
    "C2": "command-and-control",
    "Exfil": "exfiltration",
    "Impact": "impact",
}


def _norm_tactics(tactics) -> list[str]:
    """Hayabusa's tactic abbreviations → full ATT&CK kebab-case names.

    A value that is already a full tactic name (the demo generates them that way) passes through
    lower-cased and hyphenated; anything unrecognised degrades the same way rather than being
    dropped — the store and attack.py read kebab-case."""
    out: list[str] = []
    for t in tactics or []:
        if not isinstance(t, str) or not t.strip():
            continue
        full = _HAYABUSA_TACTIC_MAP.get(t.strip())
        out.append(full if full is not None else t.strip().lower().replace(" ", "-"))
    return out


_EMPTY = (None, "", "n/a", "-")


def _first(details: dict, keys: tuple[str, ...]):
    for k in keys:
        v = details.get(k)
        if v in _EMPTY:
            continue
        # Hayabusa may emit an array when EventData has multiple values for the same key
        # (e.g., multiple DstIP). These fields have a SCALAR contract in the common schema: a list
        # value would end up stringified by the DuckDB store as '[a, b]', a bogus indicator that
        # breaks correlation (shared_indicators) and pseudonymization (§9). Reduce to scalar
        # by taking the first non-empty element. (attack.techniques remains a list: handled downstream.)
        if isinstance(v, (list, tuple)):
            v = next((x for x in v if x not in _EMPTY), None)
            if v is None:
                continue
        return v
    return None


def _port_int(v):
    """Coerce a port to int (the common schema declares destination.port as `long`), as done by
    the PCAP adapter. Non-numeric/None value → None (discarded downstream by the final comprehension)."""
    try:
        return int(str(v).strip()) if v not in (None, "") else None
    except (ValueError, TypeError):
        return None


def _record_from_hayabusa(d: dict, source: str = "evtx") -> dict:
    details = d.get("Details") or {}
    if not isinstance(details, dict):
        details = {}
    eid = d.get("EventID")
    # Channel-aware: disambiguates EID collisions between channels (e.g., 22 Sysmon vs RDP).
    category, action = _classify_eid(eid, d.get("Channel"))
    tags = d.get("MitreTags") or []
    # MitreTags may contain non-string elements (numbers, None) from atypical rule packs:
    # check isinstance str before indexing, otherwise t[0] raises TypeError and loses the entire record.
    techniques = [t for t in tags if isinstance(t, str) and t[:1] in ("T", "t") and t[1:2].isdigit()]

    # Sigma community/custom detection: the RuleFile produced by Hayabusa contains the path of the
    # rule relative to rules/. Rules loaded from sigma-community/ and sigma-custom/ symlinks
    # have that prefix in the path. Builtin (hayabusa/ + sigma/) do not.
    _rule_file = d.get("RuleFile") or ""
    _is_community = bool(_rule_file) and ("sigma-community" in _rule_file or "sigma-custom" in _rule_file)

    rec = {
        "@timestamp": d.get("Timestamp"),
        "event.source": source,
        "event.category": category,
        "event.action": action or d.get("RuleTitle"),
        "event.code": eid,
        "event.channel": d.get("Channel"),
        # mapping ATT&CK
        "attack.technique": techniques[0] if techniques else None,
        "attack.techniques": techniques,
        "attack.tactics": _norm_tactics(d.get("MitreTactics")),
        # host / user
        "host.name": d.get("Computer"),
        "user.name": _first(details, _USER_KEYS),
        # process
        "process.name": _first(details, _PROC_NAME_KEYS),
        "process.command_line": _first(details, _CMDLINE_KEYS),
        "process.parent.name": _first(details, _PARENT_NAME_KEYS),
        "process.parent.command_line": _first(details, _PARENT_CMDLINE_KEYS),
        # network
        "source.ip": _first(details, _SRC_IP_KEYS),
        "destination.ip": _first(details, _DST_IP_KEYS),
        # destination.port is `long` in the common schema: coerce to int as done by the PCAP adapter,
        # otherwise a consumer trusting the declared numeric type (e.g., membership test
        # against a set of integers) would receive a string.
        "destination.port": _port_int(_first(details, _DST_PORT_KEYS)),
        "dns.question.name": _first(details, _DNS_KEYS),
        # metadati detection (namespace dedicato)
        "rule.title": d.get("RuleTitle"),
        "rule.level": d.get("Level"),
        "rule.id": d.get("RuleID"),
        "rule.file": _rule_file or None,
        "sigma.community": _is_community,
    }
    return {k: v for k, v in rec.items() if v not in (None, [], "")}


def load_records(jsonl_path: str | Path, source: str = "evtx") -> list[dict]:
    """Read the Hayabusa JSONL and return records in the common schema.

    Args:
        jsonl_path: Path to the Hayabusa JSONL output.
        source: Source string to tag each record with (default ``"evtx"``).
                Pass ``f"evtx:{filename}"`` for file-level granularity (see correlate.py).
    """
    records: list[dict] = []
    # utf-8-sig: strips any BOM on the first line (otherwise the first json.loads fails).
    # errors="replace": a single non-UTF-8 byte (Windows path/cmdline with surrogates) must not
    # abort the entire load mid-stream — the dirty line degrades, the rest are read.
    with open(jsonl_path, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Valid JSON but non-object (array/string/number/null): not a Hayabusa record;
            # degrade the line instead of aborting the load with AttributeError on d.get().
            if not isinstance(d, dict):
                continue
            records.append(_record_from_hayabusa(d, source=source))
    return records
