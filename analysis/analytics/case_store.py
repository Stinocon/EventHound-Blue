"""Case persistence: an analysis that survives the process (roadmap 'Next up' #3).

Until now an analysis lived in RAM for the length of a request and a bundle was a snapshot of the
*conclusions*. A case keeps the **data**: one directory per case holding a file-backed DuckDB and a
small JSON of metadata and notes. That is what makes reopening, annotating and comparing two
analyses of the same host possible, and it is the precondition for baseline/diffing to be serious.

    <root>/<case-id>/case.duckdb    events + raw_records
    <root>/<case-id>/case.json      metadata, sources, notes

Two tables on purpose. `events` is the analytic table (flat columns, derived ATT&CK/normalization
fields) that every recipe queries. `raw_records` keeps the original common-schema dicts, so a case
outlives a schema change: when the column layout moves, `connect()` notices the fingerprint mismatch
and rebuilds `events` from the raw records instead of querying columns that no longer exist. Without
that, every store.py change would silently rot every stored case.

Connections are opened and closed around each operation rather than held. DuckDB allows a single
writer per file, so a long-lived handle in the GUI would lock the same case out of the CLI — the two
surfaces are meant to be usable in the same session, on the same case.

PRIVACY (§9/§10): a case holds real client data — hostnames, users, internal IPs. It lives under
`analysis/cases/`, which is gitignored *and* listed as a forbidden path in tools/check-leaks.sh.
Nothing here uploads, exports or shares anything; deletion is the caller's explicit decision.

Not to be confused with `analytics/case.py`, which renders an investigation *report* from an
analysis. This module stores the analysis itself.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analytics import store  # noqa: E402
from engine.version import APP_VERSION  # noqa: E402

CASE_VERSION = 1

# A case id reaches this module from a CLI argument and, later, from a browser field: it becomes a
# directory name, so it is validated rather than trusted (§8). No separators, no dot-dot, no
# surprises on a case-insensitive filesystem.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

_DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "cases"


class CaseError(RuntimeError):
    """Invalid case id, missing case, a case that already exists, or a rejected declaration.

    `bad_input` distinguishes "you asked for something impossible" from "that case is not here",
    which the HTTP layer needs to answer 400 rather than 404. It is an attribute rather than a
    second exception class because callers catch one thing today, and it is set at the raise site
    rather than inferred from the message — matching error text by prefix works until someone
    rewords a message, and then it fails silently in the direction of the wrong status code."""

    def __init__(self, *args, bad_input: bool = False):
        super().__init__(*args)
        self.bad_input = bad_input


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def root_dir(root: str | Path | None = None) -> Path:
    """Where cases live. `EVENTHOUND_CASES_DIR` overrides the default for tests and for putting
    cases on a bigger disk than the checkout."""
    if root:
        return Path(root)
    env = os.environ.get("EVENTHOUND_CASES_DIR")
    return Path(env) if env else _DEFAULT_ROOT


def case_dir(case_id: str, root: str | Path | None = None) -> Path:
    if not _ID_RE.match(case_id or ""):
        raise CaseError(f"invalid case id {case_id!r}: use lowercase letters, digits, . _ - (max 64)")
    return root_dir(root) / case_id


def _meta_path(case_id: str, root=None) -> Path:
    return case_dir(case_id, root) / "case.json"


def _db_path(case_id: str, root=None) -> Path:
    return case_dir(case_id, root) / "case.duckdb"


def exists(case_id: str, root=None) -> bool:
    try:
        return _meta_path(case_id, root).exists()
    except CaseError:
        return False


def load_meta(case_id: str, root=None) -> dict:
    p = _meta_path(case_id, root)
    if not p.exists():
        raise CaseError(f"no case {case_id!r} in {root_dir(root)}")
    return json.loads(p.read_text(encoding="utf-8"))


def save_meta(case_id: str, meta: dict, root=None) -> None:
    meta["updated_at"] = _now()
    _meta_path(case_id, root).write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def list_cases(root=None) -> list[dict]:
    """Every case in the root, newest update first. Unreadable directories are skipped, not fatal:
    a corrupted case must not make the list command useless."""
    base = root_dir(root)
    out = []
    if not base.exists():
        return out
    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue
        try:
            out.append(json.loads((d / "case.json").read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return sorted(out, key=lambda m: m.get("updated_at", ""), reverse=True)


def _open_db(case_id: str, root=None):
    import duckdb
    return duckdb.connect(str(_db_path(case_id, root)))


def create(case_id: str, title: str | None = None, root=None) -> dict:
    """Create an empty case. Records are added with `append`, one source at a time."""
    d = case_dir(case_id, root)
    if (d / "case.json").exists():
        raise CaseError(f"case {case_id!r} already exists: {d}")
    d.mkdir(parents=True, exist_ok=True)
    con = _open_db(case_id, root)
    try:
        store.create_events_table(con)
        con.execute("CREATE TABLE IF NOT EXISTS raw_records (id BIGINT, rec VARCHAR)")
    finally:
        con.close()
    meta = {
        "case_version": CASE_VERSION,
        "id": case_id,
        "title": title or case_id,
        "created_at": _now(),
        "updated_at": _now(),
        "tool_version": APP_VERSION,
        "schema_fingerprint": store.schema_fingerprint(),
        "record_count": 0,
        "sources": [],
        "notes": [],
        # Addresses the analyst declares as network infrastructure — the gateway, the resolver, the
        # proxy, the VPN concentrator. They cannot be inferred: a gateway is an ordinary unicast
        # address and nothing in the data distinguishes it. They belong to the network under
        # investigation rather than to any one upload, which is why they live in the case.
        "infrastructure_ips": [],
    }
    save_meta(case_id, meta, root)
    return meta


def _content_signature(records: list[dict]) -> str | None:
    """Sha256 over the batch's canonical JSON, one line per record in the order given. The order
    is deliberately not normalized (e.g. sorted): two batches that differ only in record order are
    not the same append, and treating them as identical would hide a real difference upstream. An
    empty batch has no signature — it is not content, and hashing it would make every empty source
    collide with every other, which is not the collision this check exists to catch."""
    if not records:
        return None
    h = hashlib.sha256()
    for r in records:
        h.update(json.dumps(r, ensure_ascii=False, default=str).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def append(case_id: str, records: list[dict], label: str | None = None, root=None,
           *, force: bool = False) -> dict:
    """Add records to a case: raw first, then the analytic rows derived from them.

    Sources are added incrementally so the peak memory is one source, not the whole case. The
    parsing step upstream still materializes its own file — this removes the ceiling on the
    analytics side, not on the adapters'.

    A repeated append of the exact same batch is refused, not silently doubled and not silently
    dropped: every metric downstream (record counts, beaconing connection counts, episode sizes) is
    additive, so re-adding the same PCAP or export a second time would inflate all of them without
    anything telling the analyst it happened. The check compares a sha256 signature of this batch's
    content against every source already recorded for the case; a genuine deliberate re-add is still
    possible with `force=True`. An empty batch has no signature and is never refused, matching the
    existing no-op behaviour for a source that parsed to nothing."""
    meta = load_meta(case_id, root)
    signature = _content_signature(records)
    if signature is not None and not force:
        for src in meta["sources"]:
            # Cases written before this change carry no "signature" key: .get() returns None,
            # which never equals a real signature, so old sources are compared safely rather than
            # raising a KeyError or, worse, matching everything by accident.
            if src.get("signature") == signature:
                raise CaseError(
                    f"these records were already added to case {case_id!r} under label "
                    f"{src['label']!r} at {src['added_at']} ({src['records']} records); "
                    "pass force=True to add them again anyway"
                )
    con = _open_db(case_id, root)
    try:
        start = con.execute("SELECT coalesce(max(id) + 1, 0) FROM events").fetchone()[0]
        if records:      # executemany refuses an empty parameter set; a source that yielded
            con.executemany("INSERT INTO raw_records VALUES (?, ?)",   # nothing is not an error
                            [[start + i, json.dumps(r, ensure_ascii=False, default=str)]
                             for i, r in enumerate(records)])
        store.insert_records(con, records, start_id=start)
        total = con.execute("SELECT count(*) FROM events").fetchone()[0]
    finally:
        con.close()
    meta["record_count"] = total
    meta["sources"].append({"added_at": _now(), "label": label or "records", "records": len(records),
                             "signature": signature})
    save_meta(case_id, meta, root)
    return meta


def rebuild_events(case_id: str, root=None) -> int:
    """Re-derive `events` from `raw_records` under the current schema. Returns the row count."""
    con = _open_db(case_id, root)
    try:
        rows = con.execute("SELECT rec FROM raw_records ORDER BY id").fetchall()
        records = [json.loads(r[0]) for r in rows]
        con.execute("DROP TABLE IF EXISTS events")
        store.create_events_table(con)
        store.insert_records(con, records)
    finally:
        con.close()
    meta = load_meta(case_id, root)
    meta["schema_fingerprint"] = store.schema_fingerprint()
    meta["record_count"] = len(records)
    save_meta(case_id, meta, root)
    return len(records)


def connect(case_id: str, root=None):
    """Open the case's DuckDB, rebuilding `events` first if the schema moved since it was written.

    The caller closes it. Read-only is not offered on purpose: the rebuild needs to write, and a
    half-migrated case would be worse than a locked one."""
    meta = load_meta(case_id, root)
    if meta.get("schema_fingerprint") != store.schema_fingerprint():
        rebuild_events(case_id, root)
    return _open_db(case_id, root)


def read_records(con, limit: int | None = None) -> list[dict]:
    """Raw records from an already-open case connection. DuckDB refuses a second connection to the
    same file with a different configuration inside one process, so a caller that already holds one
    passes it here instead of reopening."""
    sql = "SELECT rec FROM raw_records ORDER BY id" + (" LIMIT ?" if limit else "")
    return [json.loads(r[0]) for r in con.execute(sql, [limit] if limit else []).fetchall()]


def records_of(case_id: str, limit: int | None = None, root=None) -> list[dict]:
    """The original common-schema records, in insertion order. Used to rehydrate the parts of an
    analysis that work on records rather than on SQL (IoC search, THOR findings, baseline diff)."""
    con = _open_db(case_id, root)
    try:
        return read_records(con, limit)
    finally:
        con.close()


def set_infrastructure_ips(case_id: str, ips, root=None) -> dict:
    """Declare which addresses are network infrastructure for this case.

    Correlation treats them differently in two ways, deliberately not the same way. As an indicator
    bridge the address is DEMOTED but still shown — sometimes the proxy is where the interesting
    thing happened, and deleting the row would take that lead away without saying so. As a cluster
    member it is EXCLUDED, because clustering is transitive: one universal connector merges every
    component into a single blob, and a host with no part in the incident joins it in two hops
    (it queried the same resolver, and the resolver appears in a firewall line beside the
    compromised host). Demoting cannot undo a merge — only not making it can.

    Replaces the list rather than adding to it: the analyst is stating what the infrastructure IS,
    and a setter that only ever grew would make a mistaken entry impossible to take back."""
    import ipaddress

    clean: list[str] = []
    for v in (ips or []):
        s = str(v or "").strip()
        if not s:
            continue
        try:
            ipaddress.ip_address(s)
        except ValueError:
            raise CaseError(f"not an IP address: {s!r} — declare addresses, not names or ranges",
                            bad_input=True) from None
        if s not in clean:
            clean.append(s)
    meta = load_meta(case_id, root)
    meta["infrastructure_ips"] = clean
    save_meta(case_id, meta, root)
    return meta


# What the delta between two analyses actually reads (analytics/baseline.delta). Keeping only these
# fields is what makes "what changed since last time" affordable: the alternative is analyzing the
# case twice per upload — once before the append and once after — which doubles the cost of every
# ingest on exactly the cases that are big enough for the question to matter.
_DIGEST_FIELDS = {
    "shared_indicators": ("indicator", "kind", "families", "sources", "confidence", "source_list"),
    "technique_catalog": ("technique", "name"),
    "killchain": ("phase", "phase_order"),
    "incident_clusters": ("entities", "sources"),
    "episodes": ("start_ts",),
}
_DIGEST_CAP = 500


def analysis_digest(result: dict) -> dict:
    """The smallest slice of an analyze() result that a later delta can be computed against."""
    out: dict = {"summary": {"events": (result.get("summary") or {}).get("events") or 0,
                             "by_source": dict((result.get("summary") or {}).get("by_source") or {})}}
    for key, fields in _DIGEST_FIELDS.items():
        rows = result.get(key) or []
        out[key] = [{f: r.get(f) for f in fields if f in r} for r in rows[:_DIGEST_CAP]]
    return out


def save_analysis_digest(case_id: str, result: dict, root=None) -> None:
    """Remember this analysis so the next one can say what changed. Never fatal: a case that cannot
    record its digest still analyzes, it just reports the next delta as a first analysis."""
    try:
        meta = load_meta(case_id, root)
        meta["last_analysis"] = analysis_digest(result)
        save_meta(case_id, meta, root)
    except (CaseError, OSError, ValueError):
        pass


def load_analysis_digest(case_id: str, root=None) -> dict | None:
    """The previous analysis digest, or None when there is none (or the case cannot be read)."""
    try:
        return load_meta(case_id, root).get("last_analysis")
    except (CaseError, OSError, ValueError):
        return None


def note(case_id: str, text: str, root=None) -> dict:
    """Append an analyst note. Notes are the case's memory: what was checked and what was ruled out
    is exactly what gets lost between sessions."""
    text = (text or "").strip()
    if not text:
        raise CaseError("empty note")
    meta = load_meta(case_id, root)
    meta["notes"].append({"ts": _now(), "text": text})
    save_meta(case_id, meta, root)
    return meta


def delete(case_id: str, root=None) -> Path:
    """Remove a case directory. Destructive and irreversible: the caller confirms (§12)."""
    d = case_dir(case_id, root)
    if not d.exists():
        raise CaseError(f"no case {case_id!r} in {root_dir(root)}")
    base = root_dir(root).resolve()
    target = d.resolve()
    if base not in target.parents:
        raise CaseError(f"refusing to delete {target}: outside the case root {base}")
    shutil.rmtree(target)
    return target


def size_bytes(case_id: str, root=None) -> int:
    return sum(f.stat().st_size for f in case_dir(case_id, root).glob("*") if f.is_file())
