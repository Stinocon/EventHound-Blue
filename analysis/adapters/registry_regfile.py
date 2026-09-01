"""Adapter: Windows Registry export (.reg) → common schema.

Parses native Windows Registry Editor export format (.reg files) and produces records
in the EventHound common schema (same output shape as ``registry_recmd.py``).

The parser is dependency-free (stdlib only: ``re``, ``datetime``, ``pathlib``, ``codecs``)
and handles:
- UTF-16LE BOM, UTF-8, ANSI encoding detection
- Key/value parsing with ASEP classification
- IOC extraction (suspicious auto-start paths, IFEO debuggers, service ImagePath, etc.)
- Continuation lines in hex values (trailing ``\\``)
- Deleted keys (``[-HKEY_...]``) and deleted values (``"name"=-``)

``event.source="registry"`` keeps records compatible with ``registry_recmd.py`` output
for DuckDB ingestion.

Anonymization downstream (§9): the adapter remains faithful to the raw data.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from . import registry_asep

# ---------------------------------------------------------------------------
# ASEP patterns — copied from registry_recmd.py
# ---------------------------------------------------------------------------



def _classify_key(key_path: str) -> str | None:
    """Delegates to the shared table (adapters/registry_asep.py).

    Both registry adapters kept their own copy of the map AND of this function. They were
    still identical, which is luck: one datum, one place. The merge is also where the cases
    that returned None got fixed — an offline hive's ControlSet001, RECmd's hive-relative
    paths, a `knownlls` typo, three patterns naming a value instead of a key, and a
    first-match order that reported RunOnce as Run."""
    return registry_asep.classify_key(key_path)


def _guess_hive(key_path: str) -> str:
    """Guess the registry hive from a key path.

    Handles both full paths (``HKEY_LOCAL_MACHINE\\SOFTWARE\\...``) and
    relative hive paths (``Software\\...``, ``System\\...``).
    """
    lower = key_path.lower()
    # Strip HKEY_* prefix if present
    for prefix in (
        "hkey_local_machine\\",
        "hkey_current_user\\",
        "hkey_users\\",
        "hkey_classes_root\\",
    ):
        if lower.startswith(prefix):
            lower = lower[len(prefix) :]
            break

    if lower.startswith("system\\") or lower.startswith("controlset"):
        return "SYSTEM"
    if lower.startswith("software\\") or lower.startswith("microsoft\\"):
        return "SOFTWARE"
    if lower.startswith("sam\\"):
        return "SAM"
    if lower.startswith("security\\"):
        return "SECURITY"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Registry type mapping  (.reg short-name → REG_* constant)
# ---------------------------------------------------------------------------

_REG_SHORT_MAP: dict[str, str] = {
    "dword": "REG_DWORD",
    "hex": "REG_BINARY",
    "expand_sz": "REG_EXPAND_SZ",
    "multi_sz": "REG_MULTI_SZ",
    "binary": "REG_BINARY",
}

# Registry type number → REG_* constant (for ``hex(n):`` syntax).
_HEX_TYPE_MAP: dict[int, str] = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}


def _norm_reg_type(reg_type: str | None) -> str:
    """Map a .reg type indicator to a standard ``REG_*`` name.

    Args:
        reg_type: raw type string from the .reg file (e.g. ``"hex(2)"``, ``"dword"``,
                  ``None`` for default REG_SZ).

    Returns:
        Standard registry type name (e.g. ``"REG_EXPAND_SZ"``, ``"REG_DWORD"``).
    """
    if reg_type is None or reg_type == "":
        return "REG_SZ"
    # Already a standard name: return it. Without this, `_norm_reg_type("REG_SZ")` fell through to
    # the REG_BINARY fallback — and `_check_ioc` only inspects string types, so passing the correct
    # standard name was enough to switch the entire indicator layer off.
    if reg_type.upper().startswith("REG_"):
        return reg_type.upper()
    # Named type
    mapped = _REG_SHORT_MAP.get(reg_type)
    if mapped is not None:
        return mapped
    # ``hex(n):`` → numeric type
    if reg_type.startswith("hex(") and reg_type.endswith(")"):
        try:
            num = int(reg_type[4:-1])
            if num in _HEX_TYPE_MAP:
                return _HEX_TYPE_MAP[num]
        except ValueError:
            pass
    # Fallback
    return "REG_BINARY"


# ---------------------------------------------------------------------------
# Encoding detection
# ---------------------------------------------------------------------------

def _detect_encoding(raw: bytes) -> str:
    """Detect encoding of .reg file raw bytes and return decoded string.

    Checks for UTF-16LE BOM (``ff fe``) first, then tries UTF-8 (with or
    without BOM), then falls back to latin-1 (which never fails).

    Args:
        raw: raw bytes from a .reg file.

    Returns:
        Decoded string content.
    """
    if raw[:2] == b"\xff\xfe":
        return raw.decode("utf-16-le")
    # Try UTF-8 (utf-8-sig strips the UTF-8 BOM if present)
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    # Fallback: latin-1 never fails
    return raw.decode("latin-1")


# ---------------------------------------------------------------------------
# Line normalization
# ---------------------------------------------------------------------------

# Continuation line regex: backslash + newline + optional leading whitespace
_CONTINUATION_RE = re.compile(r"\\\r?\n\s*")


def _normalize_lines(content: str) -> list[str]:
    """Split .reg content into logical lines, joining hex continuations.

    In .reg files, hex data can span multiple lines.  A trailing backslash
    at end of line acts as a continuation marker and is removed together
    with leading whitespace on the next line.

    Example::

        "Val"=hex:01,02,\\
          03,04

    becomes the logical line::

        "Val"=hex:01,02,03,04
    """
    # Strip UTF-8 BOM character if still present in decoded string
    if content.startswith("\ufeff"):
        content = content[1:]
    # Fast path: if no backslash-newline continuations, skip regex
    if "\\\r\n" not in content and "\\\n" not in content:
        return content.splitlines()
    # Slow path: merge continuation lines
    return _CONTINUATION_RE.sub("", content).splitlines()


# ---------------------------------------------------------------------------
# String unescaping
# ---------------------------------------------------------------------------

def _unescape(s: str) -> str:
    """Unescape ``\\\\`` → ``\\`` and ``\\"`` → ``"`` in .reg string values.

    Uses a sentinel two-pass approach so that ``\\\\"`` (escaped backslash
    followed by escaped quote) is handled correctly.
    """
    s = s.replace("\\\\", "\x00")  # \\ → sentinel
    s = s.replace('\\"', '"')      # \" → "
    s = s.replace("\x00", "\\")    # sentinel → \
    return s


# ---------------------------------------------------------------------------
# Value line parser
# ---------------------------------------------------------------------------

_VALUE_LINE_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"\s*=\s*(.*)$')
_DEFAULT_VALUE_RE = re.compile(r"^@\s*=\s*(.*)$")
_QUOTED_STRING_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"\s*$')
_TYPE_PREFIX_RE = re.compile(
    r"^(?P<type>hex(?:\(\d+\))?|dword|expand_sz|multi_sz|binary):(?P<data>.*)$",
    re.IGNORECASE,
)


def _decode_hex_string(data: str) -> str:
    """Decode a `hex(1):`/`hex(2):` value back to the string regedit wrote.

    regedit exports REG_SZ and REG_EXPAND_SZ as UTF-16LE hex bytes (`hex(1):`/`hex(2):`), each
    character two bytes and a trailing NUL. The indicator layer ran its regexes on the RAW hex
    string — "43,00,3a,00,…" — so a service ImagePath dropped to `C:\\Windows\\Temp\\x.exe` and
    written back as an expandable string NEVER matched a Temp/AppData/cmd.exe pattern: the .reg
    layer could not fire on the one value type regedit actually uses for paths that contain
    environment variables. Decoded here, once, so both the stored `registry.data` and the IOC check
    see the string the analyst sees in regedit.

    Not decodable → return the raw bytes unchanged: the indicator layer then stays silent, which
    is honest — a value it cannot read is not "clean", it is unread, and fabricating a string
    would be worse than missing a match.
    """
    try:
        raw = bytes(int(b, 16) for b in data.replace(",", " ").split() if b)
    except ValueError:
        return data
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return data
    return text.rstrip("\x00")


def _parse_value_line(line: str) -> tuple[str | None, str | None, str | None, bool] | None:
    """Parse a single logical .reg value line (after continuation merging).

    Args:
        line: A single normalized .reg value line.

    Returns:
        ``(value_name, reg_type, value_data, is_deleted)`` or ``None`` if the
        line is not a recognisable value definition.

        * ``value_name`` — the value name (``None`` for ``@`` default value).
        * ``reg_type``   — the .reg type indicator (e.g. ``"hex(2)"``, ``"dword"``,
                           ``None`` for quoted-string REG_SZ).
        * ``value_data`` — the raw value data as a string.
        * ``is_deleted`` — ``True`` for ``"name"=-`` (deleted value).
    """
    # Match ``"name" = rest`` or ``@ = rest``
    m = _VALUE_LINE_RE.match(line)
    if m:
        value_name = _unescape(m.group(1))
        rest = m.group(2).strip()
    else:
        m = _DEFAULT_VALUE_RE.match(line)
        if m:
            value_name = None  # unnamed default value
            rest = m.group(1).strip()
        else:
            return None

    # Deleted value ``"name"=-``
    if rest == "-":
        return (value_name, None, None, True)

    # Typed value: ``type:data``
    m = _TYPE_PREFIX_RE.match(rest)
    if m:
        reg_type = m.group("type").lower()
        value_data = m.group("data")
        # regedit writes the string types as hex; decode them so registry.data and the IOC layer
        # see the real path, not "43,00,3a,00,…". Binary and numeric types stay raw.
        if reg_type in ("hex(1)", "hex(2)"):
            value_data = _decode_hex_string(value_data)
        return (value_name, reg_type, value_data, False)

    # Quoted string (REG_SZ): ``"string data"``
    m = _QUOTED_STRING_RE.match(rest)
    if m:
        value_data = _unescape(m.group(1))
        return (value_name, None, value_data, False)

    return None


# ---------------------------------------------------------------------------
# Pre-compiled patterns for IOC detection
# ---------------------------------------------------------------------------

# Run key: suspicious AppData path
# Both of these used to end in `\\.exe`, which is a literal backslash followed by ANY character
# followed by "exe" — not an escaped dot. They therefore required a second directory level after
# AppData/Temp and a path ending in `<sep><char>exe`, which no real value has: neither pattern had
# ever matched anything. The demo makes the cost concrete — a Run key AND a service ImagePath both
# pointing at C:\Windows\Temp\svcupdate.exe, the persistence of the whole simulated intrusion,
# annotated by nothing. A dead detection rule is worse than a missing one: it reports "no indicator"
# with the same voice it would use for a clean key.
_IOC_RUN_APPDATA_RE = re.compile(r"[A-Za-z]:\\Users\\[^\\]+\\AppData\\", re.IGNORECASE)
# A Temp directory anywhere in the value: `C:\Temp`, `C:\Windows\Temp`, `%TEMP%`, and the user
# temp under AppData\Local. Deliberately NOT restricted to `.exe` any more — a Run value pointing
# into Temp is worth an analyst's attention whatever the extension, and the extension test was the
# half of the old pattern that made it wrong. AppData is checked first by the caller, so a path
# under AppData\Local\Temp keeps its own (lower) severity.
_IOC_TEMP_PATH_RE = re.compile(r"%TEMP%|[A-Za-z]:\\(?:Windows\\)?Temp\\|\\AppData\\Local\\Temp\\",
                               re.IGNORECASE)
_IOC_RUN_TEMP_RE = _IOC_TEMP_PATH_RE
# Run key: obfuscated command via cmd.exe
_IOC_RUN_CMD_RE = re.compile(r"cmd\.exe\s*/[cd]", re.IGNORECASE)
# Run key: obfuscated command via powershell.exe
_IOC_RUN_PS_RE = re.compile(r"powershell\.exe\s+", re.IGNORECASE)

# IFEO debugger patterns (pre-escaped from re.escape())
_IOC_IFEO_DBG_PATTERNS = {
    "cmd.exe": re.compile(r"cmd\.exe", re.IGNORECASE),
    "powershell.exe": re.compile(r"powershell\.exe", re.IGNORECASE),
    "wscript.exe": re.compile(r"wscript\.exe", re.IGNORECASE),
    "cscript.exe": re.compile(r"cscript\.exe", re.IGNORECASE),
}

# Service ImagePath patterns (pre-escaped from re.escape())
_IOC_SVC_PATTERNS = {
    "cmd.exe /c": re.compile(r"cmd\.exe\ /c", re.IGNORECASE),
    "powershell": re.compile(r"powershell", re.IGNORECASE),
    "net.exe": re.compile(r"net\.exe", re.IGNORECASE),
    "net1.exe": re.compile(r"net1\.exe", re.IGNORECASE),
}
# One spelling of "this is in a Temp directory", shared with the Run check above: this used to be
# `%TEMP%|C:\\Temp`, which missed `C:\\Windows\\Temp` — the single most common place a
# dropped service binary actually sits, and where the demo puts it.
_IOC_SVC_TEMP_RE = _IOC_TEMP_PATH_RE

# Scheduled task action patterns (pre-escaped from re.escape())
_IOC_TASK_PATTERNS = {
    "powershell -enc": re.compile(r"powershell\ \-enc", re.IGNORECASE),
    "cmd /c": re.compile(r"cmd\ /c", re.IGNORECASE),
    "mshta": re.compile(r"mshta", re.IGNORECASE),
    "regsvr32": re.compile(r"regsvr32", re.IGNORECASE),
    "rundll32": re.compile(r"rundll32", re.IGNORECASE),
}


# ---------------------------------------------------------------------------
# IOC checking
# ---------------------------------------------------------------------------


def _check_ioc(
    key_path: str,
    value_name: str | None,
    value_data: str | None,
    reg_type: str | None,
) -> tuple[str | None, str | None]:
    """Check a registry entry for suspicious indicators.

    Args:
        key_path: full registry key path.
        value_name: value name (or ``None`` for default value).
        value_data: value data as raw string.
        reg_type: the .reg type indicator string.

    Returns:
        ``(ioc_description, ioc_severity)`` or ``(None, None)`` if no indicator found.
    """
    if not value_data or not isinstance(value_data, str):
        return None, None

    category = _classify_key(key_path)
    if not category:
        return None, None

    # Only check IOCs on string types we can inspect
    std_type = _norm_reg_type(reg_type)
    if std_type not in ("REG_SZ", "REG_EXPAND_SZ", "REG_DWORD"):
        return None, None

    # --- 1. Suspicious paths in auto-start (Run / RunOnce) ---
    if "Run" in category:
        if _IOC_RUN_APPDATA_RE.search(value_data):
            return ("Run key with user-writable AppData path", "medium")
        if _IOC_RUN_TEMP_RE.search(value_data):
            return ("Run key with Temp directory path", "high")
        if _IOC_RUN_CMD_RE.search(value_data) or _IOC_RUN_PS_RE.search(value_data):
            return ("Run key with encoded/obfuscated command", "high")

    # --- 2. Suspicious IFEO Debugger ---
    if "IFEO" in category and value_name and value_name.lower() == "debugger":
        for dbg, dbg_re in _IOC_IFEO_DBG_PATTERNS.items():
            if dbg_re.search(value_data):
                return (f"IFEO debugger pointing to {dbg}", "medium")
        # Debugger outside standard install paths
        lower = value_data.lower()
        if not (lower.startswith("c:\\program files") or lower.startswith("c:\\windows")):
            return ("IFEO debugger outside standard paths", "medium")

    # --- 3. Suspicious service ImagePath ---
    if "Services" in category and value_name and value_name.lower() == "imagepath":
        for sc, sc_re in _IOC_SVC_PATTERNS.items():
            if sc_re.search(value_data):
                return (f"Service ImagePath contains {sc}", "high")
        if _IOC_SVC_TEMP_RE.search(value_data):
            return ("Service ImagePath points to Temp directory", "high")

    # --- 4. Suspicious scheduled task actions ---
    if "Scheduled Task" in category:
        for sa, sa_re in _IOC_TASK_PATTERNS.items():
            if sa_re.search(value_data):
                return (f"Scheduled task action contains {sa}", "high")

    # --- 5. CLSID COM objects — omitted for scope ---

    return None, None


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------

def _make_record(
    timestamp: str,
    key_path: str,
    value_name: str | None,
    value_data: str | None,
    reg_type: str | None,
    is_persistence: bool,
    is_delete: bool,
    category: str | None,
    ioc_desc: str | None,
    ioc_severity: str | None,
    message: str,
    hive: str | None = None,
) -> dict | None:
    """Build a common-schema record dict from parsed .reg data.

    ``None``, empty string, and empty list values are stripped from the
    output (consistent with ``evtx_evtxecmd.py`` and ``registry_recmd.py``).

    Args:
        hive: pre-computed hive name (avoids re-calling ``_guess_hive`` per value).
              If ``None``, the hive is guessed from ``key_path``.
    """
    if is_delete:
        action = "registry-delete"
    elif is_persistence:
        action = "persistence"
    else:
        action = "registry-read"

    rec: dict[str, object] = {
        "@timestamp": timestamp,
        "event.source": "registry",
        "event.category": "configuration",
        "event.action": action,
        "event.kind": "state",
        "registry.key": key_path,
        "registry.hive": hive if hive is not None else _guess_hive(key_path),
        "registry.type": _norm_reg_type(reg_type),
        "message": message[:2000],
    }
    if value_name is not None:
        rec["registry.value"] = value_name
    if value_data is not None:
        rec["registry.data"] = value_data
    if category is not None:
        rec["rule.description"] = category
    if ioc_desc is not None:
        rec["ioc.description"] = ioc_desc
        rec["ioc.severity"] = ioc_severity

    return {k: v for k, v in rec.items() if v not in (None, [], "")}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_regfile(content: str, progress=None, observed_at: str | None = None) -> list[dict]:
    """Parse a .reg file content string and return records in the common schema.

    Args:
        content: decoded string content of a .reg file.
        progress: optional callback ``progress(pct: float, msg: str)`` called
                  periodically during line processing (every 50,000 lines) to
                  report progress.
        observed_at: when this registry state was captured, ISO-8601 UTC. A .reg export
                  carries no timestamp of its own, so the records are stamped with the
                  moment the state was *observed* — `load_records` passes the export
                  file's mtime. Defaults to now() for the content-only path, where there
                  is no file to read a time from.

    Returns:
        List of records in the common schema (ECS subset).

    The records keep ``event.kind: "state"``: a registry export says what the machine
    looks like, not what happened at a point in time, and the timestamp is an upper
    bound on when the state existed — never the moment the key was written.
    """
    now_ts = observed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = _normalize_lines(content)
    total = len(lines)
    records: list[dict] = []
    current_key: str | None = None
    current_hive: str | None = None
    current_is_deleted: bool = False
    current_category: str | None = None

    for i, raw_line in enumerate(lines):
        if progress and i % 50000 == 0 and i > 0:
            progress(min(i / total * 100, 99.9), f"Registry: processing line {i:,}/{total:,}")

        stripped = raw_line.strip()

        # Skip blank lines, comments, and the header line
        if not stripped:
            continue
        if stripped.startswith(";") or stripped.startswith("//"):
            continue
        if (
            stripped.startswith("Windows Registry Editor")
            or stripped.startswith("REGEDIT")
        ):
            continue

        # --- Key line: [key_path] or [-key_path] ---
        if stripped.startswith("[") and stripped.endswith("]"):
            key_content = stripped[1:-1].strip()
            key_is_deleted = key_content.startswith("-")
            if key_is_deleted:
                current_key = key_content[1:].strip()
                current_is_deleted = True
            else:
                current_key = key_content
                current_is_deleted = False
                current_category = _classify_key(current_key)

            # Compute hive once per key (shared by all values under it)
            current_hive = _guess_hive(current_key)

            # Emit a record for deleted keys (no sub-values to process)
            if key_is_deleted:
                rec = _make_record(
                    timestamp=now_ts,
                    key_path=current_key,
                    value_name=None,
                    value_data=None,
                    reg_type=None,
                    is_persistence=False,
                    is_delete=True,
                    category=None,
                    ioc_desc=None,
                    ioc_severity=None,
                    message=stripped,
                    hive=current_hive,
                )
                if rec:
                    records.append(rec)
                current_key = None
                current_hive = None
                current_category = None  # Don't process values under a deleted key
            continue

        # --- Value line (requires an active, non-deleted key) ---
        if current_key is None or current_is_deleted:
            continue

        parsed = _parse_value_line(stripped)
        if parsed is None:
            continue

        value_name, reg_type, value_data, is_deleted = parsed
        category = current_category

        if is_deleted:
            action_is_delete = True
            is_persistence = False
            # Suppress category for deletions (the value is gone)
            record_category: str | None = None
        elif category:
            action_is_delete = False
            is_persistence = True
            record_category = category
        else:
            action_is_delete = False
            is_persistence = False
            record_category = None

        # IOC extraction (only meaningful for non-deleted values)
        ioc_desc: str | None = None
        ioc_severity: str | None = None
        if not is_deleted:
            ioc_desc, ioc_severity = _check_ioc(
                current_key, value_name, value_data, reg_type,
            )

        rec = _make_record(
            timestamp=now_ts,
            key_path=current_key,
            value_name=value_name,
            value_data=value_data,
            reg_type=reg_type,
            is_persistence=is_persistence,
            is_delete=action_is_delete,
            category=record_category,
            ioc_desc=ioc_desc,
            ioc_severity=ioc_severity,
            message=stripped,
            hive=current_hive,
        )
        if rec:
            records.append(rec)

    return records


def load_records(path: str | Path, progress=None) -> list[dict]:
    """Load a .reg file from disk, parse, and return records in the common schema.

    Handles encoding detection automatically (UTF-16LE BOM → UTF-8 → latin-1).

    Args:
        path: filesystem path to a .reg file.
        progress: optional callback ``progress(pct: float, msg: str)`` forwarded
                  to ``parse_regfile`` for progress reporting during line processing.

    Returns:
        List of records in the common schema.
    """
    src = Path(path)
    raw = src.read_bytes()
    content = _detect_encoding(raw)
    # The export's mtime, not now(): stamping the state with the moment of analysis made every
    # persistence entry land "today", which is both untrue and non-deterministic — re-analysing a
    # six-month-old case moved its persistence to the current date, and two runs of the same file
    # disagreed. The mtime is a real observation time and the same on every run.
    observed_at = datetime.fromtimestamp(src.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return parse_regfile(content, progress=progress, observed_at=observed_at)
