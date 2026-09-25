"""Adapter: Windows Registry (via RECmd) → common schema.

RECmd extracts ALL keys and values from a registry hive in JSON format. This adapter
filters PERSISTENCE entries (ASEP = Auto-Start Extension Points): Run, RunOnce, services,
Winlogon, IFEO, AppInit_DLLs, scheduled tasks, printers, SSP, etc.

`event.source="registry"` distinguishes these records from EVTX and other sources.

The adapter complements `evtx_evtxecmd` (EVTX full-stream) and `mft_mftecmd` (MFT file metadata):
cross-source correlation on host+timestamp can link a suspicious registry key to an
EVTX event or a file on disk.

Anonymization downstream (§9): the adapter does not pseudonymize, remains faithful to the raw data.
"""
from __future__ import annotations

from pathlib import Path

from . import registry_asep

from . import ez_json


# RECmd fields containing the registry value
_VALUE_DATA_KEYS = ("ValueData", "valueData", "data", "Value")
_VALUE_NAME_KEYS = ("ValueName", "valueName", "name", "KeyName")
_KEY_PATH_KEYS = ("KeyPath", "keyPath", "Path")
_TIMESTAMP_KEYS = ("LastWriteTimestamp", "lastWriteTimestamp", "Timestamp", "timestamp")


def _first(d: dict, keys: tuple[str, ...]):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", "-", "n/a", "N/A"):
            return v
    return None


def _classify_key(key_path: str) -> str | None:
    """Delegates to the shared table (adapters/registry_asep.py).

    Both registry adapters kept their own copy of the map AND of this function. They were
    still identical, which is luck: one datum, one place. The merge is also where the cases
    that returned None got fixed — an offline hive's ControlSet001, RECmd's hive-relative
    paths, a `knownlls` typo, three patterns naming a value instead of a key, and a
    first-match order that reported RunOnce as Run."""
    return registry_asep.classify_key(key_path)


def _norm_ts(ts):
    """Normalize RECmd timestamp to ISO-UTC format with Z (shared: ez_json.norm_ez_ts).

    RECmd uses ``yyyy-MM-dd HH:mm:ss.fffffff`` (space separator, 7-digit fraction). The old
    normalizer appended ``Z`` verbatim AND, for an explicit ``+HH:MM`` offset, DROPPED the offset
    and appended ``Z`` — which shifted a non-UTC timestamp by its whole offset (the store is told
    the value is UTC). The shared normalizer keeps the offset so the store can convert it correctly,
    and truncates the fraction to six digits."""
    return ez_json.norm_ez_ts(ts)


def _record_from_recmd(d: dict, hive_name: str = "") -> dict | None:
    """Convert a RECmd record (dict) to the common schema.

    Filters only ASEP/persistence entries. Skips entries without timestamp."""
    key_path = _first(d, _KEY_PATH_KEYS)
    if not key_path:
        return None

    category = _classify_key(key_path)
    if not category:
        return None  # Not a known persistence key

    value_name = _first(d, _VALUE_NAME_KEYS)
    value_data = _first(d, _VALUE_DATA_KEYS)
    timestamp = _norm_ts(_first(d, _TIMESTAMP_KEYS))

    if not timestamp:
        return None

    rec = {
        "@timestamp": timestamp,
        "event.source": "registry",
        "event.category": "configuration",
        "event.action": "persistence",
        "registry.key": key_path,
        "registry.value": value_name,
        "registry.data": str(value_data) if value_data is not None else None,
        "registry.hive": hive_name or _guess_hive(key_path),
        "event.kind": "state",
        "rule.description": category,
    }
    # The artifact the finding contributes (see registry_asep.program_from_value): a Run value is a
    # command line and the program it launches is the binary the other sources name. Without it a
    # hive's persistence reached the store and no bridge. The RAW value goes in, not `str(...)`: a
    # DWORD or a binary blob is not a string, and coercing it here would defeat the type guard the
    # shared helper applies — the .reg adapter gates on the value type for the same reason.
    program = registry_asep.program_from_value(category, value_name, value_data)
    if program:
        rec["file.path"] = program
    return {k: v for k, v in rec.items() if v not in (None, [], "")}


def _guess_hive(key_path: str) -> str:
    """Attempt to guess the hive from the key path.

    SYSTEM hives start with ``System\\``, SOFTWARE/SAM/SECURITY hives
    with ``Software\\`` or ``Microsoft\\``, NTUSER with user keys."""
    lower = key_path.lower()
    if lower.startswith("system\\") or lower.startswith("controlset"):
        return "SYSTEM"
    if lower.startswith("software\\") or lower.startswith("microsoft\\"):
        return "SOFTWARE"
    if lower.startswith("sam\\"):
        return "SAM"
    if lower.startswith("security\\"):
        return "SECURITY"
    return "UNKNOWN"


def load_records(json_dir: str | Path, hive_name: str = "") -> list[dict]:
    """Read all RECmd JSON files in a directory and return records in the common schema.

    RECmd produces a JSON file containing an array of objects, one per key/value.
    The adapter filters only ASEP (persistence) entries.

    Args:
        json_dir: directory with RECmd JSON output files.
        hive_name: name of the hive (e.g. ``SYSTEM``, ``SOFTWARE``, ``NTUSER.DAT``).

    Returns:
        List of records in the common schema (persistence entries only).
    """
    records: list[dict] = []
    # RECmd's --json mode writes ONE nested SimpleKey document; --bn writes NDJSON. The previous
    # reader accepted neither and produced zero entries from a real hive, silently. Values live
    # inside the key, so the tree is flattened to one row per value before mapping — reading the
    # document flat saw a single key and none of its values, which is where persistence lives.
    for doc in ez_json.load_dir(json_dir):
        entries = (ez_json.flatten_simple_keys(doc)
                   if ("Values" in doc or "SubKeys" in doc) else [doc])
        for entry in entries:
            rec = _record_from_recmd(entry, hive_name)
            if rec:
                records.append(rec)

    return records
