"""Adapter: PCAP (via Zeek) → common schema (ECS subset, network fields).

Runs ``zeek -r <pcap>`` in a temporary directory, then parses Zeek TSV logs
(conn.log, dns.log, http.log, ssl.log, notice.log) into the common schema.
Complementary to pcap_tshark: Zeek provides application-layer visibility (HTTP, SSL, DNS)
that tshark -T fields does not easily offer.

Conn.log records are the base; dns/http/ssl/notice **enrich** the same
record by uid (one record per application-layer transaction, each carrying the connection's
4-tuple and outcome).

Anonymization: client internal IPs must be pseudonymized *downstream* (malicious
public IPs are not) — see common-schema.md and §9 — method/conventions.md.
"""
from __future__ import annotations

import datetime as _dt
import tempfile
from pathlib import Path

from .pcap_zeek_runner import run_zeek

# ── helpers ─────────────────────────────────────────────────────────────────


def _epoch_to_iso(ts_str: str | None) -> str | None:
    """Convert Zeek epoch string (e.g. ``1700000000.000000``) to ISO UTC."""
    if not ts_str:
        return None
    try:
        ts = float(ts_str)
        return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    except (ValueError, OSError, OverflowError):
        return None


def _map_conn_state(state: str | None, proto: str | None = None) -> str | None:
    """Map Zeek ``conn_state`` to ``event.outcome``.

    Reference: https://docs.zeek.org/en/current/quickstart.html#conn.log

    `failure` here is read downstream as a *finding*: `correlate._TIMELINE_WHY` promotes a failed
    action onto the salience-filtered timeline, on the reasoning that a rejected or unanswered
    attempt is worth seeing. That makes the difference between "this failed" and "the capture does
    not show how it ended" a real one, and three of these states were on the wrong side of it:

    * `S1` — established and not terminated — is an ONGOING connection, the normal state of every
      long-lived session in a capture that stops before it does;
    * `SH`/`SHR` — a FIN with no SYN seen — is an ordinary close whose beginning is outside the
      capture window.

    None of the three says anything failed; they say the observation is partial, which is
    `unknown`. And `S0` — no reply — is a genuine failure for TCP (a SYN nobody answered) but the
    ordinary shape of **UDP** in a one-directional capture: a DNS question whose answer was not
    recorded is not a failed action, and calling it one put every DNS lookup in the demo on the
    incident timeline.
    """
    if not state:
        return None
    if state == "S0" and str(proto or "").lower() == "udp":
        return "unknown"
    mapping = {
        "SF": "success",    # normal establishment and termination
        "S0": "failure",    # SYN sent, never answered
        "REJ": "failure",   # connection rejected
        "RSTO": "failure",  # reset by the originator
        "RSTR": "failure",  # reset by the responder
        "S1": "unknown",    # established, not yet terminated — ongoing, not failed
        "SH": "unknown",    # FIN from the originator, no SYN seen — partial view of a normal close
        "SHR": "unknown",   # FIN from the responder, same
        "OTH": "unknown",   # no SYN seen, partial traffic
    }
    return mapping.get(state, "unknown")


# ── TSV parser ──────────────────────────────────────────────────────────────


def _parse_zeek_tsv(content: str) -> list[dict]:
    """Parse a Zeek TSV log into a list of dicts (raw).

    Zeek format (https://docs.zeek.org/en/current/logs/ascii.html):
    - Header lines starting with ``#``.
    - ``#separator`` specifies the separator (default ``\\x09`` = tab).
    - ``#fields`` lists the field names separated by the separator.
    - Subsequent lines are data, with values separated by the separator.
    - ``(empty)`` and ``-`` indicate empty and unset fields, respectively.
    """
    lines = content.splitlines()
    if not lines:
        return []

    separator = "\t"
    fields: list[str] = []

    for line in lines:
        if not line:
            continue
        if line.startswith("#separator "):
            suffix = line[len("#separator "):]
            if suffix.startswith("\\x") and len(suffix) >= 4:
                try:
                    separator = chr(int(suffix[2:4], 16))
                except (ValueError, TypeError):
                    pass
            elif suffix:
                separator = suffix[0]
        elif line.startswith("#fields"):
            parts = line.split(separator)
            if len(parts) > 1:
                fields = parts[1:]

    if not fields:
        return []

    records: list[dict] = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        cols = line.split(separator)
        # Pad or truncate to the expected number of fields
        if len(cols) < len(fields):
            cols += [""] * (len(fields) - len(cols))

        record: dict = {}
        for j, field_name in enumerate(fields):
            val = cols[j] if j < len(cols) else ""
            if val in ("(empty)", "-"):
                record[field_name] = None
            else:
                record[field_name] = val
        records.append(record)

    return records


# ── field mapping (raw → common schema) ──────────────────────────────────────


def _conn_record(raw: dict, source: str = "pcap") -> dict:
    """Map a conn.log record to a common schema record."""
    rec: dict = {}

    ts = _epoch_to_iso(raw.get("ts"))
    if ts:
        rec["@timestamp"] = ts

    rec["event.source"] = source
    rec["event.category"] = "network"

    proto = raw.get("proto")
    if proto:
        rec["network.transport"] = proto.lower()

    service = raw.get("service")
    if service:
        rec["network.protocol"] = service

    orig_bytes = raw.get("orig_bytes")
    if orig_bytes and orig_bytes.isdigit():
        rec["network.bytes"] = int(orig_bytes)

    src_ip = raw.get("id.orig_h")
    if src_ip:
        rec["source.ip"] = src_ip

    dst_ip = raw.get("id.resp_h")
    if dst_ip:
        rec["destination.ip"] = dst_ip

    dst_port = raw.get("id.resp_p")
    if dst_port and str(dst_port).isdigit():
        rec["destination.port"] = int(dst_port)

    # The originator port completes the 4-tuple that names a connection. tshark reports the same
    # tuple packet by packet, so carrying it here is what lets the two views of ONE capture collapse
    # into one connection instead of being counted twice (see recipes.beaconing).
    src_port = raw.get("id.orig_p")
    if src_port and str(src_port).isdigit():
        rec["source.port"] = int(src_port)

    outcome = _map_conn_state(raw.get("conn_state"), raw.get("proto"))
    if outcome:
        rec["event.outcome"] = outcome

    history = raw.get("history")
    if history:
        rec["zeek.connection.history"] = history

    return rec


def _dns_enrichment(raw: dict) -> dict:
    """Map a dns.log record to enrichment fields in the common schema."""
    rec: dict = {}
    query = raw.get("query")
    if query:
        rec["dns.question.name"] = query
    qtype = raw.get("qtype_name")
    if qtype:
        rec["dns.question.type"] = qtype
    answers = raw.get("answers")
    if answers:
        rec["dns.answer"] = answers
    rcode = raw.get("rcode_name")
    if rcode:
        rec["dns.response_code"] = rcode
    return rec


def _http_enrichment(raw: dict) -> dict:
    """Map an http.log record to enrichment fields in the common schema."""
    rec: dict = {}
    host = raw.get("host")
    if host:
        rec["url.domain"] = host
    uri = raw.get("uri")
    if uri:
        rec["url.path"] = uri
    ua = raw.get("user_agent")
    if ua:
        rec["user_agent.original"] = ua
    method = raw.get("method")
    if method:
        rec["http.request.method"] = method
    sc = raw.get("status_code")
    if sc and str(sc).isdigit():
        rec["http.response.status_code"] = int(sc)
    mime = raw.get("resp_mime_types")
    if mime:
        rec["file.mime_type"] = mime
    return rec


def _ssl_enrichment(raw: dict) -> dict:
    """Map an ssl.log record to enrichment fields in the common schema."""
    rec: dict = {}
    sni = raw.get("server_name")
    if sni:
        rec["tls.server_name"] = sni
    ja3 = raw.get("ja3")
    if ja3:
        rec["tls.ja3"] = ja3
    ja3s = raw.get("ja3s")
    if ja3s:
        rec["tls.ja3s"] = ja3s
    version = raw.get("version")
    if version:
        rec["tls.version"] = version
    issuer = raw.get("issuer")
    if issuer:
        rec["tls.issuer"] = issuer
    return rec


def _notice_enrichment(raw: dict) -> dict:
    """Map a notice.log record to enrichment fields in the common schema.

    notice.log's `uid` is the uid of the connection the notice is ABOUT (there is no separate
    `conn` column — the old join key that made notices unreachable)."""
    rec: dict = {}
    msg = raw.get("msg")
    if msg:
        rec["rule.description"] = msg
    note = raw.get("note")
    if note:
        rec["rule.name"] = note
    sub = raw.get("sub")
    if sub:
        rec["rule.category"] = sub
    return rec


# ── merging ─────────────────────────────────────────────────────────────────


def _merge_logs(
    conn_raw: list[dict],
    dns_raw: list[dict],
    http_raw: list[dict],
    ssl_raw: list[dict],
    notice_raw: list[dict],
    source: str = "pcap",
) -> list[dict]:
    """Merge conn.log (base) with enrichment from other logs by uid.

    dns/http/ssl entries share the conn uid. notice.log's `uid` IS the connection uid — the old
    code joined on a `conn` column that notice.log does not have, so a notice NEVER reached a
    record and its rule/description/category were dropped at ingest. And a connection can carry
    MANY application-layer transactions (HTTP keep-alive: several requests on one conn; several
    DNS answers), so the enrichment indexes are LISTS, not one-slot dicts: the old
    ``by_uid_http[uid] = r`` kept only the LAST request of a connection and silently discarded
    the rest.

    Product: one record per connection when it carries no app-layer transaction, else one record
    per transaction (each = the conn base + that transaction's fields + its own time), plus one
    record per notice. Nothing is dropped.
    """
    def _index(rows: list[dict]) -> dict[str, list[dict]]:
        by_uid: dict[str, list[dict]] = {}
        for r in rows:
            uid = r.get("uid")
            if uid:
                by_uid.setdefault(uid, []).append(r)
        return by_uid

    dns_by_uid = _index(dns_raw)
    http_by_uid = _index(http_raw)
    ssl_by_uid = _index(ssl_raw)
    notice_by_uid = _index(notice_raw)

    records: list[dict] = []
    for raw in conn_raw:
        uid = raw.get("uid")
        base = _conn_record(raw, source=source)
        dns_list = dns_by_uid.get(uid, [])
        http_list = http_by_uid.get(uid, [])
        ssl_list = ssl_by_uid.get(uid, [])
        notice_list = notice_by_uid.get(uid, [])

        # One record per application-layer transaction, in log order.
        transactions = ([(d, _dns_enrichment) for d in dns_list]
                        + [(h, _http_enrichment) for h in http_list]
                        + [(s, _ssl_enrichment) for s in ssl_list])

        if transactions:
            for entry, enrich in transactions:
                rec = dict(base)
                rec.update(enrich(entry))
                # The transaction's own time is more precise than the connection's start.
                entry_ts = _epoch_to_iso(entry.get("ts"))
                if entry_ts:
                    rec["@timestamp"] = entry_ts
                # A notice applies to the connection, not to one transaction: attach the first
                # to the first record; further notices get their own records below.
                if notice_list:
                    rec.update(_notice_enrichment(notice_list[0]))
                records.append(rec)
        else:
            rec = dict(base)
            if notice_list:
                rec.update(_notice_enrichment(notice_list[0]))
            records.append(rec)

        # Each further notice is its own event about the connection.
        for extra in notice_list[1:]:
            rec = dict(base)
            rec.update(_notice_enrichment(extra))
            extra_ts = _epoch_to_iso(extra.get("ts"))
            if extra_ts:
                rec["@timestamp"] = extra_ts
            records.append(rec)

    return records


# ── public API ──────────────────────────────────────────────────────────────


def load_records(pcap_path: str | Path) -> list[dict]:
    """Run Zeek on a PCAP and return records in the common schema.

    Args:
        pcap_path: Path to the .pcap/.pcapng file.

    Returns:
        List of records in the common schema (ECS subset).

    Raises:
        FileNotFoundError: PCAP not found or zeek not installed.
        RuntimeError: Zeek fails on the input.
    """
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    source = f"pcap:{pcap_path.name}"

    with tempfile.TemporaryDirectory(prefix="zeek-") as td:
        work_dir = Path(td)
        logs = run_zeek(pcap_path, work_dir)

        # Parse each recognized log
        conn_raw: list[dict] = []
        dns_raw: list[dict] = []
        http_raw: list[dict] = []
        ssl_raw: list[dict] = []
        notice_raw: list[dict] = []

        for log_type, path in logs.items():
            content = path.read_text(encoding="utf-8", errors="replace")
            parsed = _parse_zeek_tsv(content)
            if log_type == "conn":
                conn_raw = parsed
            elif log_type == "dns":
                dns_raw = parsed
            elif log_type == "http":
                http_raw = parsed
            elif log_type == "ssl":
                ssl_raw = parsed
            elif log_type == "notice":
                notice_raw = parsed
            # files.log, weird.log, packet_filter.log: ignored

        return _merge_logs(conn_raw, dns_raw, http_raw, ssl_raw, notice_raw, source=source)
