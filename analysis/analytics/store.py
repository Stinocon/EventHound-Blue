"""DuckDB store on common schema records (Phase 2).

Loads records produced by adapters (evtx_hayabusa, pcap_tshark, ...) into an `events` table
with flat columns (dotted common schema fields become underscore-prefixed columns). It is the
foundation for long-tail analytics and cross-source correlation.

Everything stays LOCAL. `from_records` keeps the data in memory and writes nothing (DESIGN §2);
the same table can also be built inside a file-backed connection (`analytics/case_store.py`) when
an analysis has to survive the process. Records remain faithful to raw data; anonymization is a
downstream step (§9 — method/conventions.md).
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import sys
from typing import Iterable

from . import attack, normalize

# (SQL column, dotted key in common schema, DuckDB type)
_COLUMNS: list[tuple[str, str, str]] = [
    ("ts", "@timestamp", "VARCHAR"),
    # `source` is the ORIGIN (qualified with the file where the adapter provides it, e.g.
    # "pcap:capture.pcap"); `family` is the TOOL behind it ("pcap"). Correlation counts families —
    # how many independent tools corroborate an indicator — while the origin answers "which file".
    # See normalize.source_family for why the two had to be separated.
    # EVTX stays family-level on purpose: Hayabusa's timeline does not attribute a record to the
    # file it came from in directory mode, so a per-file origin would exist on the single-file path
    # and vanish on the batched one. `host.name` already separates collections from several hosts.
    ("source", "event.source", "VARCHAR"),
    ("family", "__family__", "VARCHAR"),
    ("category", "event.category", "VARCHAR"),
    ("action", "event.action", "VARCHAR"),
    ("event_code", "event.code", "INTEGER"),  # Windows Event ID (was produced by adapters but discarded)
    ("outcome", "event.outcome", "VARCHAR"),  # success | failure | unknown
    ("host", "host.name", "VARCHAR"),
    ("user_name", "user.name", "VARCHAR"),
    ("process_name", "process.name", "VARCHAR"),
    ("cmdline", "process.command_line", "VARCHAR"),
    ("parent_name", "process.parent.name", "VARCHAR"),
    ("pid", "process.pid", "VARCHAR"),
    ("src_ip", "source.ip", "VARCHAR"),
    # The ephemeral source port identifies a CONNECTION, which `destination.port` alone cannot: two
    # rows sharing src/dst/dport may be two call-backs or two packets of one exchange, and the
    # difference is the whole of beaconing. Carried by the two PCAP adapters; NULL everywhere else,
    # where a row already means one connection.
    ("src_port", "source.port", "INTEGER"),
    ("dst_ip", "destination.ip", "VARCHAR"),
    ("dst_port", "destination.port", "INTEGER"),
    ("dns_query", "dns.question.name", "VARCHAR"),
    ("transport", "network.transport", "VARCHAR"),
    ("protocol", "network.protocol", "VARCHAR"),
    ("bytes", "network.bytes", "BIGINT"),
    ("logon_type", "logon.type", "VARCHAR"),
    # log/web (logfile adapter) and file/artifacts (YARA, dropped scripts): correlation pivot
    ("url", "url.original", "VARCHAR"),
    ("http_method", "http.request.method", "VARCHAR"),
    ("http_status", "http.response.status_code", "INTEGER"),
    ("file_name", "file.name", "VARCHAR"),
    # Some adapters name the artifact only by its full path (YARA emits `file.path` and no
    # `file.name`; osquery does the same for file events). Without the column those records carried
    # no artifact at all into the store, so a YARA match could not bridge to the EVTX that executed
    # the same binary — `file_canon` below now falls back to it.
    ("file_path", "file.path", "VARCHAR"),
    ("file_hash", "file.hash", "VARCHAR"),
    ("file_hash_md5", "file.hash.md5", "VARCHAR"),  # secondary hash (e.g. THOR MD5); a second correlation key
    # Derived entity-normalization columns (computed in Python at load; see normalize.py). They let
    # correlation join on the *entity* when tools spell it differently (CORP\alice vs alice@corp.example;
    # DC1 vs dc1.corp.example). Sentinel dotted keys are computed specially in _cell (not read from the record).
    ("user_canon", "__canon_user__", "VARCHAR"),
    ("host_canon", "__canon_host__", "VARCHAR"),
    ("user_generic", "__user_generic__", "BOOLEAN"),  # ubiquitous machine account (SYSTEM…): not an identity bridge
    # Realms kept beside the canonical name: two spellings of one account that disagree on the realm
    # (alice@corp.example vs alice@partner.example) are a possible FALSE merge, and correlation
    # flags that instead of asserting a link (normalize.realms_conflict).
    ("user_domain", "__user_domain__", "VARCHAR"),
    ("host_domain", "__host_domain__", "VARCHAR"),
    ("host_generic", "__host_generic__", "BOOLEAN"),
    ("file_canon", "__canon_file__", "VARCHAR"),      # lowercase basename: bridges path vs bare name
    ("file_generic", "__file_generic__", "BOOLEAN"),  # svchost.exe & co: on every host, no signal
    ("src_ip_generic", "__src_ip_generic__", "BOOLEAN"),   # loopback/link-local/multicast/invalid
    ("dst_ip_generic", "__dst_ip_generic__", "BOOLEAN"),
    ("dns_generic", "__dns_generic__", "BOOLEAN"),         # wpad/localhost/reverse lookups: infrastructure noise
    ("message", "message", "VARCHAR"),  # raw row/log (app-log without structured fields)
    ("techniques", "attack.techniques", "VARCHAR"),  # list -> string "T1,T2"
    # ATT&CK/kill-chain derivation (attack.py, from the official STIX map). Computed here so every
    # query joins on tactic/phase without re-deriving it per recipe. Only the Hayabusa adapter emits
    # attack.tactics; for every other source the tactics are resolved from the technique IDs.
    ("tactics", "__tactics__", "VARCHAR"),          # "credential-access,lateral-movement"
    ("kc_phase", "__kc_phase__", "VARCHAR"),        # deepest kill-chain phase of the event
    ("kc_order", "__kc_order__", "INTEGER"),        # 1..7 (0 = no ATT&CK evidence): sortable depth
    # ONE definition of "this record carries ATT&CK evidence", because it had three and all three
    # were wrong. `kc_phase IS NOT NULL` misses a detection whose technique ID the offline map
    # cannot resolve; `techniques <> ''` misses a rule that declares a TACTIC and no ID (345 of the
    # 3142 vendored SigmaHQ rules do exactly that) and, being a raw-string test, counts a YARA
    # `attack = "Credential Access"` meta value as a technique. Each spelling was written where it
    # was needed and the question drifted apart across five call sites. It is answered once, here.
    ("attack_evidence", "__attack_evidence__", "BOOLEAN"),
    # Sigma rule metadata (from Hayabusa output)
    ("rule_title", "rule.title", "VARCHAR"),
    ("rule_level", "rule.level", "VARCHAR"),
    ("rule_file", "rule.file", "VARCHAR"),
    # The matched rule's NAME (YARA `m.rule`, Zeek notice `note`) — distinct from `rule.title`,
    # which is the human-readable title of a Sigma rule. It was emitted by two adapters and had no
    # column, so it was dropped at ingest: a YARA hit recorded as a match with no way to say which
    # rule matched, and a Zeek notice with no way to say which notice fired.
    ("rule_name", "rule.name", "VARCHAR"),
    ("sigma_community", "sigma.community", "BOOLEAN"),
    # Zeek enrichment (PCAP via Zeek adapter): application fields outside core ECS subset
    ("url.domain", "url.domain", "VARCHAR"),
    ("url.path", "url.path", "VARCHAR"),
    ("dns.answer", "dns.answer", "VARCHAR"),
    ("dns.response_code", "dns.response_code", "VARCHAR"),
    ("tls.server_name", "tls.server_name", "VARCHAR"),
    ("tls.ja3", "tls.ja3", "VARCHAR"),
    ("tls.version", "tls.version", "VARCHAR"),
    # Registry (RECmd and .reg exports). `common-schema.md` has documented these since 0.3.0 and
    # both adapters emit them; there was no column to put them in, so every one was dropped at
    # ingest and a hive or a .reg landed in the store as a timestamp, an action and a raw message.
    # The Run key that IS the persistence in the demo therefore contributed no host, no user, no
    # artifact and no bridge — the same shape as the `file.hash.sha256` defect of 2026-08-27, where
    # a documented field had no column and two whole sources could never corroborate a hash.
    ("registry.key", "registry.key", "VARCHAR"),
    ("registry.value", "registry.value", "VARCHAR"),
    ("registry.data", "registry.data", "VARCHAR"),
    ("registry.hive", "registry.hive", "VARCHAR"),
    ("registry.type", "registry.type", "VARCHAR"),
    # Documented alongside them and dropped with them: the ASEP category a registry finding carries,
    # and the IOC annotation the adapters attach when a value looks suspicious.
    ("rule.description", "rule.description", "VARCHAR"),
    ("ioc.description", "ioc.description", "VARCHAR"),
    ("ioc.severity", "ioc.severity", "VARCHAR"),
]


_NUMERIC_TYPES = {"INTEGER", "BIGINT"}


def _attack_of(record: dict) -> dict:
    """ATT&CK annotation of one record. Prefers the tactics the adapter already provides (Hayabusa
    reads them from the Sigma rule) and completes/derives the rest from the technique IDs."""
    ann = attack.annotate(record.get("attack.techniques"))
    declared = record.get("attack.tactics") or []
    if declared:
        tactics = sorted({str(t).strip().lower().replace(" ", "-") for t in declared if str(t).strip()})
        phases = sorted({p for p in (attack.phase_of_tactic(t) for t in tactics) if p},
                        key=lambda p: attack.PHASE_ORDER[p])
        if tactics:
            ann = {**ann, "tactics": sorted(set(ann["tactics"]) | set(tactics))}
        if phases:
            merged = sorted(set(ann["phases"]) | set(phases), key=lambda p: attack.PHASE_ORDER[p])
            ann = {**ann, "phases": merged, "max_phase": merged[-1],
                   "max_phase_order": attack.PHASE_ORDER[merged[-1]]}
    return ann


def _cell(record: dict, dotted: str, sql_type: str = "VARCHAR", ann: dict | None = None):
    # Derived normalization columns: computed from the raw user/host, not stored on the record.
    if dotted == "__canon_user__":
        return normalize.canon_user(record.get("user.name"))
    if dotted == "__canon_host__":
        return normalize.canon_host(record.get("host.name"))
    if dotted == "__user_generic__":
        raw_user = record.get("user.name")
        # A computer account (DC1$) is the machine, not a person: excluded from the identity bridge.
        return (normalize.is_generic_user(normalize.canon_user(raw_user))
                or normalize.is_machine_user(raw_user))
    if dotted == "__user_domain__":
        return normalize.user_domain(record.get("user.name"))
    if dotted == "__host_domain__":
        return normalize.host_domain(record.get("host.name"))
    if dotted == "__host_generic__":
        return normalize.is_generic_host(normalize.canon_host(record.get("host.name")))
    if dotted == "__family__":
        return normalize.source_family(record.get("event.source"))
    # `file.path` is the fallback because an adapter that only knows the full path (YARA, osquery
    # file events) would otherwise contribute no artifact at all; canon_file takes the basename, so
    # a path and a bare name still collapse to the same key.
    if dotted == "__canon_file__":
        return normalize.canon_file(record.get("file.name") or record.get("file.path"))
    if dotted == "__file_generic__":
        return normalize.is_generic_file(
            normalize.canon_file(record.get("file.name") or record.get("file.path")))
    if dotted == "__src_ip_generic__":
        return normalize.is_generic_ip(record.get("source.ip"))
    if dotted == "__dst_ip_generic__":
        return normalize.is_generic_ip(record.get("destination.ip"))
    if dotted == "__dns_generic__":
        return normalize.is_generic_domain(normalize.canon_domain(record.get("dns.question.name")))
    if dotted in ("__tactics__", "__kc_phase__", "__kc_order__", "__attack_evidence__"):
        ann = ann if ann is not None else _attack_of(record)   # computed once per record by the loader
        if dotted == "__tactics__":
            return ",".join(ann["tactics"]) or None
        if dotted == "__kc_phase__":
            return ann["max_phase"] or None
        if dotted == "__attack_evidence__":
            # A resolved phase (which is how a declared tactic with no ID counts) OR a WELL-FORMED
            # technique ID. `split_techniques` validates the shape, so an ID the map does not know
            # is still evidence — that is the case this column was born for — while free text in
            # the same field is not.
            return bool(ann["max_phase"]) or bool(
                attack.split_techniques(record.get("attack.techniques")))
        return ann["max_phase_order"]
    val = record.get(dotted)
    # Case/format canonicalization applied in place: a hash is case-insensitive by definition and a
    # DNS name is not case-sensitive either, so storing the canonical form costs nothing in fidelity
    # and fixes joins that would otherwise silently miss (Sysmon upper vs THOR lower).
    if dotted in ("file.hash", "file.hash.md5"):
        # `file.hash` is the SHA-256 slot (common-schema.md: "SHA256 preferred"), but two adapters
        # spell it `file.hash.sha256` — CrowdStrike (`SHA 256`/`SHA256HashData`) and osquery
        # (`columns.sha256`). That name had no column, so the strongest bridge there is — a shared
        # artifact hash — was dropped on the floor for both of them while the schema documented it
        # as mapped. Read either spelling here rather than editing two adapters: the next one to
        # arrive gets it for free.
        if dotted == "file.hash" and val is None:
            val = record.get("file.hash.sha256")
        return normalize.canon_hash(val)
    if dotted == "dns.question.name":
        return normalize.canon_domain(val)
    if dotted == "attack.techniques":
        if not val:
            return None
        return ",".join(str(t) for t in val) if isinstance(val, (list, tuple)) else str(val)
    if sql_type in _NUMERIC_TYPES and val is not None and not isinstance(val, int):
        # Per-record tolerance (like TRY_CAST on timestamp): a non-numeric value becomes NULL
        # instead of failing the entire executemany with a DuckDB Conversion Error — a single dirty record
        # (e.g., a port 'https' from an adapter) should not abort analysis of the entire dataset.
        # Also avoids leaking raw customer values into logged error messages (§9).
        # Routes through float() to accept legitimate numerics (443.0, '443.0' from JSON adapter) without
        # losing them to NULL; only true non-numeric junk (e.g., 'https') stays discarded. bool is a
        # subtype of int but not a valid port/byte: discard it explicitly.
        if isinstance(val, bool):
            return None
        try:
            return int(float(str(val).strip()))
        except (ValueError, TypeError):
            return None
    return val


def schema_fingerprint() -> str:
    """Short hash of the column layout. A persisted case records the fingerprint it was written
    with, so a later schema change is detected and the table rebuilt from the raw records instead
    of silently answering queries with columns that no longer exist (case_store.connect)."""
    blob = ";".join(f"{c}:{t}" for c, _, t in _COLUMNS)
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def create_events_table(con) -> None:
    """DDL only, on any connection (in-memory or file-backed). `ts_parsed` is part of the table
    rather than an ALTER afterwards: a persisted store is written incrementally, one source at a
    time, and a column added post-hoc would not exist on reopen."""
    cols_ddl = ",\n  ".join(f'"{c}" {t}' for c, _, t in _COLUMNS)
    con.execute(f"CREATE TABLE IF NOT EXISTS events (\n  id BIGINT,\n  {cols_ddl},\n  ts_parsed TIMESTAMP\n)")


@contextlib.contextmanager
def _without_probing_for_pandas():
    """Stop DuckDB paying for an absent pandas once per bound value.

    Its Python client probes `import pandas` while converting parameters, and Python does not cache
    a FAILED import — so with pandas not installed (it is not a dependency here) every probe
    re-walks `sys.path`. Measured with cProfile on 1000 synthetic records: 35 652 failed imports,
    ~2.7 ms per record, which made loading the store cost more than every recipe and correlation
    query put together. Negative-caching the module name collapses that to a single failed import:
    2000 records went from 5.21 s to 1.37 s, a 3.8x on the dominant stage (measured figures and
    hardware in docs/analysis/performance.md).

    Deliberately scoped: the entry is removed on exit, so nothing outside this block sees a
    poisoned `sys.modules`; and when pandas IS available the probe hits the normal module cache
    anyway, so this does nothing at all. The right long-term fix belongs upstream in duckdb.
    """
    if "pandas" in sys.modules or importlib.util.find_spec("pandas") is not None:
        yield
        return
    sys.modules["pandas"] = None
    try:
        yield
    finally:
        if sys.modules.get("pandas", False) is None:
            del sys.modules["pandas"]


def insert_records(con, records: Iterable[dict], start_id: int = 0) -> int:
    """Append records to an existing `events` table, numbering ids from `start_id`.
    Returns the next free id, so a case can grow one source at a time."""
    col_list = ", ".join(['"id"'] + [f'"{c}"' for c, _, _ in _COLUMNS])
    placeholders = ",".join(["?"] * (1 + len(_COLUMNS)))
    rows = []
    i = start_id
    for rec in records:
        ann = _attack_of(rec)          # once per record: three derived columns read from it
        rows.append([i] + [_cell(rec, dotted, t, ann) for _, dotted, t in _COLUMNS])
        i += 1
    if rows:
        with _without_probing_for_pandas():
            con.executemany(f"INSERT INTO events ({col_list}) VALUES ({placeholders})", rows)
        # Normalized timestamp. Most adapters emit ISO UTC with 'Z', but not all of them can: two
        # paths pass the source's own spelling straight through (the Okta `published` field, and the
        # generic JSONL log adapter when neither of its parsers recognises the value). Stripping the
        # 'Z' and casting to a naive TIMESTAMP handled the common case and silently mishandled the
        # rest: `2026-03-12T10:30:00+02:00` became 10:30 instead of 08:30, so a source in another
        # timezone was shifted by its whole offset — which moves it into or out of an episode, out of
        # order in the timeline, and gives the kill-chain narrative the wrong hour. Epoch seconds
        # became NULL, which drops the record out of every temporal view altogether.
        # So: offset-aware spellings are converted to UTC, naive ones are taken as written (they are
        # already UTC by convention, and casting them as TIMESTAMPTZ would apply the machine's own
        # timezone — the same bug in the other direction), and a bare epoch is read as one.
        # TRY_CAST still yields NULL rather than failing the whole load on something unparseable.
        con.execute("""
            UPDATE events SET ts_parsed = CASE
                WHEN regexp_matches(ts, '(Z|[+-][0-9]{2}:?[0-9]{2})$')
                    THEN TRY_CAST(ts AS TIMESTAMPTZ) AT TIME ZONE 'UTC'
                WHEN regexp_matches(ts, '^[0-9]{9,11}(\\.[0-9]+)?$')
                    THEN to_timestamp(TRY_CAST(ts AS DOUBLE))
                ELSE TRY_CAST(ts AS TIMESTAMP)
            END
            WHERE id >= ? AND ts_parsed IS NULL
        """, [start_id])
    return i


def from_records(records: Iterable[dict]):
    """Creates an in-memory DuckDB connection with the `events` table populated.

    Adds an `id` column (row index) and `ts_parsed` (best-effort TIMESTAMP,
    NULL if timestamp is not parseable) for temporal analytics."""
    import duckdb

    con = duckdb.connect()
    create_events_table(con)
    insert_records(con, records)
    return con


def summary(con) -> dict:
    """Basic counts to orient on the loaded dataset."""
    n = con.execute("SELECT count(*) FROM events").fetchone()[0]
    # Grouped by FAMILY, not origin: a 278-file EVTX collection is one telemetry source to the
    # analyst reading the dashboard, not 278 of them.
    by_source = dict(con.execute(
        "SELECT coalesce(family, source), count(*) FROM events GROUP BY 1 ORDER BY 2 DESC"
    ).fetchall())
    by_category = dict(con.execute(
        "SELECT category, count(*) FROM events WHERE category IS NOT NULL GROUP BY category ORDER BY 2 DESC"
    ).fetchall())
    # CANONICAL, not raw. `WS-11`, `ws-11` and `ws-11.corp.example` are one machine, and the
    # correlation layer's entire job is to say so — while this line counted them as three and put
    # "7 hosts" at the top of a report whose own cross-source table, three sections below, showed
    # the four. Two answers to one question on one page, and the wrong one was the headline.
    hosts = con.execute("SELECT count(DISTINCT host_canon) FROM events "
                        "WHERE host_canon IS NOT NULL").fetchone()[0]
    users = con.execute("SELECT count(DISTINCT user_canon) FROM events "
                        "WHERE user_canon IS NOT NULL").fetchone()[0]
    return {"events": n, "by_source": by_source, "by_category": by_category,
            "distinct_hosts": hosts, "distinct_users": users}
