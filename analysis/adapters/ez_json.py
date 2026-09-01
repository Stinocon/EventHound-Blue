"""Reading the JSON the Eric Zimmerman tools actually emit.

Both `mft_mftecmd` and `registry_recmd` used the same reader, and it was wrong in the same way:
it accepted a top-level **array**, and fell back to `data.get("Data") or []` for a dict — where
`[]` is already a list, so the `[data]` single-document fallback could never fire. Neither tool
produces an array:

* **MFTECmd** writes one record per line (`sWrite.WriteLine(mftOutRecord.ToJson())`) — NDJSON.
  `json.load` raises `JSONDecodeError: Extra data`, which the caller caught and turned into
  `continue`. The file was skipped **without an error**, so a `$MFT` ingested as zero records and
  the report said "no suspicious files" because nothing had been read.
* **RECmd** with `--kn \\ --json <dir> --jsonf <name>` writes ONE nested `SimpleKey` document
  (`File.WriteAllText(outFile, jso.ToJson())`). It parsed fine, had no `"Data"` key, and produced
  zero entries. Its `--bn` batch mode is NDJSON, like MFTECmd.

Neither failure was visible: `errors` stayed empty, the GUI reported the source as ingested, and the
count was zero. The repository's own tests fed a hand-written array — the one shape the tools never
produce — and both end-to-end tests self-skip for want of a real hive, so nothing ever exercised it.

Found by the fourth adversarial review (R6-A, 2026-08-30), which read the vendors' sources rather
than the adapters' assumptions.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Eric Zimmerman timestamps: .NET's `yyyy-MM-dd HH:mm:ss.fffffff` — a SPACE separator and a
# 7-digit fraction (100-nanosecond ticks, where ISO-8601 allows six = microseconds).
_EZ_TS_SPACE = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})")
_EZ_TS_FRACTION = re.compile(r"^(.*?\.\d{6})\d+(.*)$")
_TS_HAS_ZONE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def norm_ez_ts(ts) -> str | None:
    """Eric Zimmerman `yyyy-MM-dd HH:mm:ss.fffffff` → ISO-8601 `yyyy-MM-ddTHH:mm:ss.ffffffZ`.

    Both MFTECmd and RECmd write timestamps with a space separator and a 7-digit fraction. The
    previous per-adapter normalizer just appended ``Z`` to whatever it got, producing
    ``2024-03-15 10:30:00.1234567Z`` — not ISO-8601, and fragile against the store's cast (which
    tolerates it today only by luck of the naive TIMESTAMP path truncating the 7th digit). A
    trailing offset is preserved; a value with none is read as UTC.
    """
    if not isinstance(ts, str):
        return ts
    ts = ts.strip()
    if not ts:
        return ts
    m = _EZ_TS_SPACE.match(ts)
    if m:
        ts = f"{m.group(1)}T{m.group(2)}{ts[m.end():]}"
    m = _EZ_TS_FRACTION.match(ts)
    if m:
        ts = m.group(1) + m.group(2)
    if _TS_HAS_ZONE.search(ts):
        return ts
    return f"{ts}Z"


def load_documents(path: str | Path) -> list[dict]:
    """Every JSON object in one file, whatever shape the tool wrote it in.

    Handles, in order: NDJSON (one object per line), a top-level array, a `{"Data": [...]}`
    wrapper, and a single object. A line or file that is not JSON is skipped — these are tool
    outputs, and one malformed record must not lose the rest of the run.
    """
    try:
        text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return []
    text = text.strip()
    if not text:
        return []

    docs: list[dict] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # NDJSON: the ordinary output of both tools, and the shape that used to abort the file.
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                docs.append(obj)
        return docs

    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        inner = data.get("Data") if isinstance(data.get("Data"), list) else None
        if inner is None and isinstance(data.get("data"), list):
            inner = data.get("data")
        if inner is not None:
            return [d for d in inner if isinstance(d, dict)]
        return [data]
    return docs


def load_dir(json_dir: str | Path) -> list[dict]:
    """`load_documents` over every *.json under a directory, recursively."""
    out: list[dict] = []
    for f in sorted(Path(json_dir).rglob("*.json")):
        out.extend(load_documents(f))
    return out


def flatten_simple_keys(doc: dict, _path: str | None = None) -> list[dict]:
    """A RECmd `SimpleKey` tree → one flat row per VALUE, plus one for a key with no values.

    RECmd's `--json` mode hands back the key it was asked for with its `Values` and `SubKeys`
    nested inside it. The adapter reads flat `KeyPath`/`ValueName`/`ValueData` rows, so without
    this it saw a single key and none of its values — which is where the persistence lives.

    A key with no values still yields a row: `\\Run` existing at all is a fact, and dropping it
    would make "no Run key" and "an empty Run key" look identical.
    """
    if not isinstance(doc, dict):
        return []
    key_path = doc.get("KeyPath") or doc.get("Key Path") or _path or ""
    ts = (doc.get("LastWriteTimestamp") or doc.get("LastWriteTime")
          or doc.get("Last Write Timestamp"))
    rows: list[dict] = []
    values = doc.get("Values")
    if isinstance(values, list) and values:
        for v in values:
            if not isinstance(v, dict):
                continue
            row = dict(v)
            row.setdefault("KeyPath", key_path)
            # A value carries no time of its own: the key's last-write is the honest anchor, and it
            # is what the flat CSV/batch shapes put on the row too.
            if ts and not row.get("LastWriteTimestamp"):
                row["LastWriteTimestamp"] = ts
            rows.append(row)
    elif key_path:
        rows.append({"KeyPath": key_path, "LastWriteTimestamp": ts})
    for sub in doc.get("SubKeys") or []:
        rows.extend(flatten_simple_keys(sub, key_path))
    return rows
