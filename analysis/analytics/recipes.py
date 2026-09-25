"""Long-tail and network analytical recipes on records in DuckDB (Phase 2).

Long-tail philosophy: in the noise of a real dataset, the MALICIOUS is often RARE — the process
seen once, the anomalous parent-child pair, the first appearance of a user on a host,
the domain queried once, periodic beaconing. These functions isolate the tail.

Each function takes a connection (see store.from_records) and returns a list of dicts
(rows). No data leaves the process: it is all local SQL on in-memory DuckDB.
"""
from __future__ import annotations

from . import attack

# "Expected" ports where reporting traffic is not worth the effort (long-tail by exclusion).
# SINGLE SOT of the standard port set (§16): engine/run_pcap imports this set instead of
# maintaining a divergent copy. Curated union of two historical sets (web/mail/dir/Win admin).
COMMON_PORTS = {20, 21, 22, 23, 25, 53, 80, 88, 110, 123, 135, 139, 143, 389,
                443, 445, 464, 465, 587, 636, 993, 995, 3389, 5985, 5986, 8080, 8443}


def _rows(con, sql: str, params: list | None = None) -> list[dict]:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


def technique_frequency(con) -> list[dict]:
    """Frequency of ATT&CK techniques (explodes the techniques list).

    Split in Python rather than by `string_split` in SQL, for the same reason `technique_catalog`
    does: the column holds whatever the adapter put there, and `yara_scan` copies a rule's `attack`
    meta value verbatim — so a rule tagged `attack = "Credential Access"` was reported here as an
    ATT&CK technique named "Credential Access". `attack.split_techniques` is the one parser that
    knows a technique is `T#### [.###]`, and it is now the only thing that answers this."""
    rows = _rows(con, """
        SELECT techniques, count(*) AS hits FROM events
        WHERE techniques IS NOT NULL AND techniques <> ''
        GROUP BY techniques
    """)
    agg: dict[str, int] = {}
    for r in rows:
        for tid in attack.split_techniques(r["techniques"]):
            agg[tid] = agg.get(tid, 0) + r["hits"]
    return [{"technique": t, "hits": h}
            for t, h in sorted(agg.items(), key=lambda kv: (-kv[1], kv[0]))]


def rare_processes(con, max_count: int = 2) -> list[dict]:
    """Process stacking: process names seen <= max_count times (rare tail)."""
    return _rows(con, """
        SELECT process_name, count(*) AS occurrences,
               count(DISTINCT host) AS hosts
        FROM events WHERE process_name IS NOT NULL
        GROUP BY process_name HAVING count(*) <= ?
        ORDER BY occurrences, process_name
    """, [max_count])


def first_seen(con) -> list[dict]:
    """First appearance of each (host, user) pair: useful for new/lateral access detection."""
    return _rows(con, """
        SELECT host, user_name, min(ts) AS first_ts, count(*) AS events
        FROM events WHERE host IS NOT NULL AND user_name IS NOT NULL
        GROUP BY host, user_name ORDER BY first_ts
    """)


def anomalous_parent_child(con, max_count: int = 2) -> list[dict]:
    """Rare parent→child pairs (unusual process chains)."""
    return _rows(con, """
        SELECT parent_name, process_name, count(*) AS occurrences
        FROM events
        WHERE parent_name IS NOT NULL AND process_name IS NOT NULL
        GROUP BY parent_name, process_name HAVING count(*) <= ?
        ORDER BY occurrences, parent_name, process_name
    """, [max_count])


def top_talkers(con, limit: int = 20) -> list[dict]:
    """Network destinations by volume: connections and bytes to each IP."""
    return _rows(con, """
        SELECT dst_ip, count(*) AS connections,
               coalesce(sum(bytes), 0) AS total_bytes,
               count(DISTINCT dst_port) AS ports
        FROM events WHERE dst_ip IS NOT NULL
        GROUP BY dst_ip ORDER BY connections DESC, total_bytes DESC
        LIMIT ?
    """, [limit])


def rare_dns(con, max_count: int = 1, long_len: int = 50) -> list[dict]:
    """Rare DNS queries (seen <= max_count times) or anomalously long (possible tunneling)."""
    return _rows(con, """
        SELECT dns_query, count(*) AS lookups, max(length(dns_query)) AS name_len
        FROM events WHERE dns_query IS NOT NULL
        GROUP BY dns_query
        HAVING count(*) <= ? OR max(length(dns_query)) >= ?
        ORDER BY lookups, name_len DESC
    """, [max_count, long_len])


def nonstandard_ports(con) -> list[dict]:
    """Traffic to ports outside the expected set (COMMON_PORTS)."""
    placeholders = ",".join(["?"] * len(COMMON_PORTS))
    return _rows(con, f"""
        SELECT dst_ip, dst_port, transport, count(*) AS connections,
               coalesce(sum(bytes), 0) AS total_bytes
        FROM events
        WHERE dst_port IS NOT NULL AND dst_port NOT IN ({placeholders})
        GROUP BY dst_ip, dst_port, transport
        ORDER BY connections DESC, dst_port
    """, sorted(COMMON_PORTS))


def beaconing(con, min_events: int = 4, max_jitter: float = 0.25) -> list[dict]:
    """Candidate C2 beaconing: triples (src,dst,port) with REGULAR connections over time.

    A beacon is a *connection* repeated on a metronome, so the interval series has to be built from
    connections — and a row is not one. tshark reports a capture packet by packet and Zeek reports
    the same capture connection by connection, so the SYN, the ACK, every data segment and Zeek's
    own summary of one exchange all arrived as separate "connections" a few hundred milliseconds
    apart. That drove the mean toward zero and the jitter through the roof: on any real capture the
    check silently failed to fire, and it passed its own test only because the one fixture that
    existed had exactly one packet per flow.

    Rows are therefore folded into connections first, on the 4-tuple that names one — including the
    ephemeral `source.port`, which is why that field exists in the schema — and the interval is
    measured between the *starts* of consecutive connections. Where a source carries no source port
    (EVTX Sysmon 3, firewall logs, anything hand-written) each row already means one connection and
    is kept as its own, so nothing about those sources changes.

    A beacon has a stable average interval and low jitter (stddev/mean). Requires parseable
    timestamps (ts_parsed)."""
    # PARTITION/GROUP include host: on EVTX events (Sysmon EID 3) src_ip is often NULL, and without
    # host, connections from DIFFERENT machines to the same dst:port would be merged into a single
    # fake regular beacon (false positive). host.name discriminates the true source.
    return _rows(con, """
        WITH conns AS (
            SELECT host, src_ip, dst_ip, dst_port, min(ts_parsed) AS started
            FROM events
            WHERE dst_ip IS NOT NULL AND dst_port IS NOT NULL AND ts_parsed IS NOT NULL
            GROUP BY host, src_ip, dst_ip, dst_port, coalesce(src_port, id)
        ),
        gaps AS (
            SELECT host, src_ip, dst_ip, dst_port, started,
                   epoch(started) - epoch(lag(started) OVER (
                       PARTITION BY host, src_ip, dst_ip, dst_port ORDER BY started)) AS gap
            FROM conns
        )
        SELECT host, src_ip, dst_ip, dst_port,
               count(*) + 1 AS connections,
               round(avg(gap), 2) AS mean_interval_s,
               round(coalesce(stddev_samp(gap), 0) / nullif(avg(gap), 0), 3) AS jitter
        FROM gaps WHERE gap IS NOT NULL
        GROUP BY host, src_ip, dst_ip, dst_port
        HAVING count(*) + 1 >= ? AND avg(gap) > 0
           AND coalesce(stddev_samp(gap), 0) / nullif(avg(gap), 0) <= ?
        ORDER BY jitter, connections DESC
    """, [min_events, max_jitter])


def top_source_ips(con, limit: int = 25) -> list[dict]:
    """Source IPs by volume (useful on web/access logs: who knocks most, e.g., scanner/attacker)."""
    return _rows(con, """
        SELECT src_ip, count(*) AS events,
               count(DISTINCT url) AS distinct_urls,
               count(DISTINCT source) AS sources
        FROM events WHERE src_ip IS NOT NULL
        GROUP BY src_ip ORDER BY events DESC, src_ip LIMIT ?
    """, [limit])


def http_status_summary(con) -> list[dict]:
    """Distribution of HTTP status codes (spikes in 4xx/5xx = probes/exploits/errors)."""
    return _rows(con, """
        SELECT http_status, count(*) AS hits, count(DISTINCT src_ip) AS clients
        FROM events WHERE http_status IS NOT NULL
        GROUP BY http_status ORDER BY hits DESC, http_status
    """)


def web_targets(con, limit: int = 25) -> list[dict]:
    """Most requested URLs/paths (highlights endpoints under attack, e.g. /wsproxy on SMA)."""
    return _rows(con, """
        SELECT url, count(*) AS hits, count(DISTINCT src_ip) AS clients,
               max(http_status) AS sample_status
        FROM events WHERE url IS NOT NULL
        GROUP BY url ORDER BY hits DESC, url LIMIT ?
    """, [limit])


def zeek_http(con) -> list[dict]:
    """HTTP requests seen by Zeek."""
    rows = con.execute("""
        SELECT "url.domain" AS domain, "url.path" AS path,
               http_method AS method,
               http_status AS status,
               COUNT(*) AS hits
        FROM events
        WHERE "url.domain" IS NOT NULL
        GROUP BY "url.domain", "url.path", http_method, http_status
        ORDER BY COUNT(*) DESC
        LIMIT 30
    """).fetchall()
    return [{"domain": r[0], "path": r[1], "method": r[2], "status": r[3], "hits": r[4]} for r in rows]


def zeek_ssl(con) -> list[dict]:
    """SSL/TLS connections seen by Zeek (SNI, JA3)."""
    rows = con.execute("""
        SELECT dst_ip AS ip, dst_port AS port,
               "tls.server_name" AS sni, "tls.ja3" AS ja3,
               "tls.version" AS version,
               COUNT(*) AS hits
        FROM events
        WHERE "tls.server_name" IS NOT NULL
        GROUP BY dst_ip, dst_port, "tls.server_name", "tls.ja3", "tls.version"
        ORDER BY COUNT(*) DESC
        LIMIT 30
    """).fetchall()
    return [{"ip": r[0], "port": r[1], "sni": r[2], "ja3": r[3], "version": r[4], "hits": r[5]} for r in rows]


def zeek_dns_detail(con) -> list[dict]:
    """DNS details from Zeek: response codes and answer IPs, which only Zeek supplies.

    Gated on Zeek's own columns, like its siblings `zeek_http` (url.domain) and `zeek_ssl`
    (tls.server_name). It filtered on `dns_query IS NOT NULL` — source-agnostic — so a DNS name
    seen by tshark or named in an EVTX record was counted under a heading that says Zeek, with both
    promised columns blank. A reader concluded Zeek had seen the resolution; it had not."""
    rows = con.execute("""
        SELECT dns_query AS query, "dns.response_code" AS rcode,
               "dns.answer" AS answer, COUNT(*) AS hits
        FROM events
        WHERE dns_query IS NOT NULL
          AND ("dns.response_code" IS NOT NULL OR "dns.answer" IS NOT NULL)
        GROUP BY dns_query, "dns.response_code", "dns.answer"
        ORDER BY COUNT(*) DESC
        LIMIT 30
    """).fetchall()
    return [{"query": r[0], "rcode": r[1], "answer": r[2], "hits": r[3]} for r in rows]


def sigma_community(con) -> list[dict]:
    """Group detections from Sigma community/custom rules."""
    return _rows(con, """
        SELECT rule_title AS rule, rule_level AS level,
               COUNT(*) AS hits,
               LIST(DISTINCT host) AS hosts
        FROM events
        WHERE sigma_community = true
        GROUP BY rule_title, rule_level
        ORDER BY hits DESC, rule_title
    """)



def registry_findings(con, limit: int = 500) -> list[dict]:
    """Registry persistence and configuration findings, most suspicious first.

    The columns for these have existed since the store learned about `registry.*` — before that a
    hive or a `.reg` landed as a timestamp, an action and a raw message. They still reached no
    report and no view: an ASEP entry could be the persistence in an intrusion and be visible
    nowhere, which is the same silence one layer up.

    Read from the store rather than from the record list, so a persisted case answers this fully:
    `analyze()`'s `records` is capped (RECORDS_CAP) and would report a prefix of the findings as if
    it were all of them — the mistake `records_capped` exists to stop being invisible.

    Ordering is by the severity the ADAPTER assigned (never a computed one, §6) and then by key and
    value, so it is total: two runs over identical evidence must list identical rows in identical
    order, which is the property a `string_agg` without ORDER BY once broke here.

    `ts`, not `ts_parsed`: the whole analysis is serialized to JSON (the report, the bundle, the
    GUI's SSE), and DuckDB hands back a real `datetime` for the parsed column, which
    `json.dumps` refuses. No recipe emits one today — this one did for about ten minutes, and both
    the demo end-to-end test and the CLI smoke test turned red on it, which is the system working."""
    return _rows(con, """
        SELECT "registry.hive"   AS hive,
               "registry.key"    AS key,
               "registry.value"  AS value,
               "registry.data"   AS data,
               "registry.type"   AS type,
               "rule.description" AS category,
               "ioc.severity"    AS severity,
               "ioc.description" AS indicator,
               host, source, ts AS observed
        FROM events
        WHERE "registry.key" IS NOT NULL AND "registry.key" <> ''
        ORDER BY CASE lower(coalesce("ioc.severity", ''))
                     WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                     WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                 "registry.key", "registry.value", "registry.data"
        LIMIT ?
    """, [limit])

# Registry: name -> (function, description). Used by CLI and GUI.
RECIPES = {
    "technique_frequency": (technique_frequency, "ATT&CK technique frequency"),
    "rare_processes": (rare_processes, "Process stacking (rare processes)"),
    "first_seen": (first_seen, "First appearance host/user"),
    "anomalous_parent_child": (anomalous_parent_child, "Rare parent→child pairs"),
    "top_talkers": (top_talkers, "Network destinations by volume"),
    "rare_dns": (rare_dns, "Rare/long DNS queries"),
    "nonstandard_ports": (nonstandard_ports, "Non-standard ports"),
    "beaconing": (beaconing, "C2 beaconing candidates"),
    "top_source_ips": (top_source_ips, "Source IPs by volume (web logs)"),
    "http_status_summary": (http_status_summary, "HTTP status distribution"),
    "web_targets": (web_targets, "Most requested URLs/paths"),
    "sigma_community": (sigma_community, "Detections from Sigma community/custom rules"),
    "registry_findings": (registry_findings, "Registry persistence/config findings (ASEP)"),
    "zeek_http": (zeek_http, "HTTP requests from Zeek"),
    "zeek_ssl": (zeek_ssl, "SSL/TLS connections from Zeek (SNI, JA3)"),
    "zeek_dns_detail": (zeek_dns_detail, "DNS details from Zeek"),
}
