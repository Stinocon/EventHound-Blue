"""Adapter: NTFS $MFT (via MFTECmd) → common schema.

MFTECmd extracts metadata from EVERY FILE record in $MFT: name, path, timestamps (created0x10,
modified0x10, accessed0x10, record_change0x10, created0x30, modified0x30, accessed0x30,
record_change0x30), size, attributes, parent directory.

This adapter maps each FILE record into the common ECS schema for correlation with
EVTX (suspicious file creation), registry (file-based persistence) and PCAP (executable
downloads).

`event.source="mft"` distinguishes these records from EVTX, registry and other sources.

Anonymization downstream (§9): real file names are NOT pseudonymized (they are indicators).
"""
from __future__ import annotations

from pathlib import Path

from . import ez_json

# MFT attribute names for timestamps (0x10 = $STANDARD_INFORMATION, 0x30 = $FILE_NAME)
# MFTECmd emits fields with these prefixes.
_SI_PREFIX = "0x10"     # $STANDARD_INFORMATION
_FN_PREFIX = "0x30"     # $FILE_NAME

# Common fields in MFTECmd JSON output
_ENTRY_ID_KEYS = ("EntryNumber", "entryNumber", "Entry")
_SEQ_KEYS = ("SequenceNumber", "sequenceNumber", "Sequence")
_PARENT_KEYS = ("ParentEntryNumber", "parentEntryNumber", "ParentEntry")
_FILENAME_KEYS = ("FileName", "fileName", "Name", "name")
_EXT_KEYS = ("Extension", "extension", "Ext")
_PATH_KEYS = ("FullPath", "fullPath", "Path", "ParentPath")
_SIZE_KEYS = ("FileSize", "fileSize", "Size", "RealSize")
_ALLOC_SIZE_KEYS = ("AllocatedSize", "allocatedSize", "AllocatedSize")
_ATTR_KEYS = ("Attributes", "attributes")
_IS_DIR = ("IsDirectory", "isDirectory", "Directory")
_IS_DELETED = ("IsDeleted", "isDeleted", "Deleted")


def _first(d: dict, keys: tuple[str, ...]):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", "-", "n/a", "N/A"):
            return v
    return None


def _port_int(v):
    try:
        return int(str(v).strip()) if v not in (None, "") else None
    except (ValueError, TypeError):
        return None


def _norm_ts(ts):
    """Normalize the MFTECmd timestamp to ISO-UTC format with Z.

    MFTECmd defaults to ``yyyy-MM-dd HH:mm:ss.fffffff`` — space separator, 7-digit fraction. The
    shared normalizer (ez_json.norm_ez_ts, one copy for both Eric Zimmerman tools) converts it to
    ``yyyy-MM-ddTHH:mm:ss.ffffffZ``."""
    return ez_json.norm_ez_ts(ts)


def _ts_field(d: dict, attr: str, kind: str) -> str | None:
    """Extract an MFTECmd timestamp from the dictionary.

    MFTECmd produces fields like ``Created0x10``, ``LastModified0x10``, ``LastAccess0x10``,
    ``LastRecordChange0x10`` and their 0x30 counterparts.
    Also tries lowercase and underscore variants."""
    candidates = [
        f"{kind}{attr}",           # Created0x10
        f"{kind}_{attr}",          # Created_0x10
        f"{kind.lower()}{attr}",   # created0x10
        f"{kind.lower()}_{attr}",  # created_0x10
        f"{attr}_{kind}",          # 0x10_Created
        f"{attr}{kind}",           # 0x10Created
    ]
    for c in candidates:
        v = d.get(c)
        if v not in (None, "", "-", "n/a", "N/A"):
            return _norm_ts(v)
    return None


def _record_from_mftecmd(d: dict) -> dict | None:
    """Convert an MFTECmd record (dict) to the common schema.

    Extracts file metadata: name, path, timestamps, size, attributes."""
    entry = _port_int(_first(d, _ENTRY_ID_KEYS))
    filename = _first(d, _FILENAME_KEYS)
    if not entry and not filename:
        return None  # Invalid record

    full_path = _first(d, _PATH_KEYS) or ""
    ext = _first(d, _EXT_KEYS) or ""
    is_dir = _first(d, _IS_DIR)
    is_deleted = _first(d, _IS_DELETED)

    # Timestamp: both SI (0x10) and FN (0x30) if available
    created = _ts_field(d, "0x10", "Created") or _ts_field(d, "0x30", "Created")
    modified = _ts_field(d, "0x10", "LastModified") or _ts_field(d, "0x30", "LastModified")
    accessed = _ts_field(d, "0x10", "LastAccess") or _ts_field(d, "0x30", "LastAccess")
    changed = _ts_field(d, "0x10", "LastRecordChange") or _ts_field(d, "0x30", "LastRecordChange")

    # Prefer created as primary timestamp, fallback to modified
    timestamp = created or modified or changed or accessed

    file_size = _port_int(_first(d, _SIZE_KEYS))
    alloc_size = _port_int(_first(d, _ALLOC_SIZE_KEYS))

    # Build the file name (with extension if separate)
    file_name = filename
    # MFTECmd sets `Extension = Path.GetExtension(FileName)`, and .NET returns the extension WITH
    # its leading period — while `FileName` already ends in it. The old test therefore asked whether
    # the name ended in "..exe" and, finding that it did not, appended: every extended record came
    # out as `malware.exe..exe`, so `canon_file` was a name nothing else could ever match and the
    # MFT bridged to nothing — which is the entire reason the source exists.
    if ext and filename:
        suffix = ext if ext.startswith(".") else f".{ext}"
        if not filename.lower().endswith(suffix.lower()):
            file_name = f"{filename}{suffix}"

    rec = {
        "@timestamp": timestamp,
        "event.source": "mft",
        "event.category": "file",
        "event.action": "file-metadata",
        "file.name": file_name,
        "file.path": full_path or None,
        "file.extension": ext or None,
        "file.size": file_size,
        "file.allocated_size": alloc_size,
        "file.attributes": _port_int(_first(d, _ATTR_KEYS)),
        "mft.entry": entry,
        "mft.sequence": _port_int(_first(d, _SEQ_KEYS)),
        "mft.parent_entry": _port_int(_first(d, _PARENT_KEYS)),
        "mft.is_directory": is_dir if is_dir is not None else None,
        "mft.is_deleted": is_deleted if is_deleted is not None else None,
        "mft.timestamp_modified": modified,
        "mft.timestamp_accessed": accessed,
        "mft.timestamp_changed": changed,
    }
    return {k: v for k, v in rec.items() if v not in (None, [], "")}


def load_records(json_dir: str | Path) -> list[dict]:
    """Read all MFTECmd JSON files in a directory and return records in the common schema.

    MFTECmd produces a JSON file containing an array of objects, one per FILE record in the MFT.

    Args:
        json_dir: directory with MFTECmd JSON output files.

    Returns:
        List of records in the common schema (file metadata).
    """
    # MFTECmd writes NDJSON, one record per line — not an array. The previous reader called
    # json.load, caught the resulting "Extra data" and skipped the file in silence, so a real $MFT
    # ingested as ZERO records with no error anywhere. See adapters/ez_json.py.
    records: list[dict] = []
    for entry in ez_json.load_dir(json_dir):
        rec = _record_from_mftecmd(entry)
        if rec:
            records.append(rec)
    return records
