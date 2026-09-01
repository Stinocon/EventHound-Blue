"""Test: Zeek adapter field mapping + integration with sample PCAP.

Two levels:
1. **Synthetic** (always run): tests TSV parsing and field
   mapping with fake strings — no external binaries.
2. **Integration** (if zeek + tshark present): generates a sample PCAP,
   runs both adapters and verifies cross-source coherence.

    uv run python tests/test_pcap_zeek.py
"""
from __future__ import annotations

import os

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tests._helpers import skip_test  # noqa: E402


def run_synthetic() -> None:
    """Tests parsing and field-mapping WITHOUT Zeek (always run)."""
    from adapters.pcap_zeek import (
        _parse_zeek_tsv,
        _conn_record,
        _dns_enrichment,
        _http_enrichment,
        _ssl_enrichment,
        _notice_enrichment,
        _map_conn_state,
        _epoch_to_iso,
        _merge_logs,
    )

    # ── 1. Conn.log TSV parsing ──────────────────────────────────────────
    tsv_conn = (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#open\t2026-07-20-14-45-04\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\t"
        "id.resp_h\tid.resp_p\tproto\tservice\t"
        "orig_bytes\tconn_state\thistory\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\t"
        "count\tstring\tstring\n"
        "#close\t2026-07-20-14-45-05\n"
        "1700000000.000000\tUID-001\t10.0.0.5\t50000\t"
        "203.0.113.10\t443\ttcp\thttp\t1024\tSF\tShADadfF\n"
    )
    raw = _parse_zeek_tsv(tsv_conn)
    assert len(raw) == 1, f"expected 1 conn record, found {len(raw)}"
    r = raw[0]
    assert r["ts"] == "1700000000.000000"
    assert r["uid"] == "UID-001"
    assert r["id.orig_h"] == "10.0.0.5"
    assert r["id.resp_p"] == "443"
    assert r["id.resp_h"] == "203.0.113.10"
    assert r["proto"] == "tcp"
    assert r["service"] == "http"
    assert r["conn_state"] == "SF"

    # ── 2. Conn record mapping ───────────────────────────────────────────
    rec = _conn_record(raw[0])
    assert rec["source.ip"] == "10.0.0.5", rec
    assert rec["destination.ip"] == "203.0.113.10", rec
    assert rec["destination.port"] == 443 and isinstance(rec["destination.port"], int), rec
    assert rec["network.transport"] == "tcp", rec
    assert rec["network.protocol"] == "http", rec
    assert rec["event.outcome"] == "success", rec
    assert rec["zeek.connection.history"] == "ShADadfF", rec
    assert rec["event.source"] == "pcap", rec
    assert rec["event.category"] == "network", rec

    # Timestamp parsing
    assert rec.get("@timestamp") == "2023-11-14T22:13:20.000000Z", rec.get("@timestamp")

    # ── 3. dns.log parsing ───────────────────────────────────────────────
    tsv_dns = (
        "#separator \\x09\n"
        "#fields\tuid\tquery\tqtype_name\tanswers\trcode_name\n"
        "#types\tstring\tstring\tstring\tstring\tstring\n"
        "UID-001\tmalware-c2.example\tA\t10.0.0.1,10.0.0.2\tNOERROR\n"
    )
    dns_raw = _parse_zeek_tsv(tsv_dns)
    assert len(dns_raw) == 1
    d = dns_raw[0]
    assert d["query"] == "malware-c2.example"
    assert d["qtype_name"] == "A"
    assert d["answers"] == "10.0.0.1,10.0.0.2"

    # ── 4. DNS enrichment ────────────────────────────────────────────────
    enrichment = _dns_enrichment(dns_raw[0])
    assert enrichment["dns.question.name"] == "malware-c2.example"
    assert enrichment["dns.question.type"] == "A"
    assert enrichment["dns.answer"] == "10.0.0.1,10.0.0.2"
    assert enrichment["dns.response_code"] == "NOERROR"

    # ── 5. http.log + enrichment ─────────────────────────────────────────
    tsv_http = (
        "#separator \\x09\n"
        "#fields\tuid\thost\turi\tmethod\tstatus_code\tuser_agent\tresp_mime_types\n"
        "#types\tstring\tstring\tstring\tstring\tcount\tstring\tstring\n"
        "UID-002\twww.example.com\t/path\tGET\t200\tcurl/7.0\ttext/html\n"
    )
    http_raw = _parse_zeek_tsv(tsv_http)
    e_http = _http_enrichment(http_raw[0])
    assert e_http["url.domain"] == "www.example.com"
    assert e_http["url.path"] == "/path"
    assert e_http["http.request.method"] == "GET"
    assert e_http["http.response.status_code"] == 200
    assert isinstance(e_http["http.response.status_code"], int)
    assert e_http["user_agent.original"] == "curl/7.0"
    assert e_http["file.mime_type"] == "text/html"

    # ── 6. ssl.log + enrichment ──────────────────────────────────────────
    tsv_ssl = (
        "#separator \\x09\n"
        "#fields\tuid\tserver_name\tja3\tversion\tissuer\n"
        "#types\tstring\tstring\tstring\tstring\tstring\n"
        "UID-003\twww.example.com\tabc123def\tTLSv12\tCN=example\n"
    )
    ssl_raw = _parse_zeek_tsv(tsv_ssl)
    e_ssl = _ssl_enrichment(ssl_raw[0])
    assert e_ssl["tls.server_name"] == "www.example.com"
    assert e_ssl["tls.ja3"] == "abc123def"
    assert e_ssl["tls.version"] == "TLSv12"
    assert e_ssl["tls.issuer"] == "CN=example"

    # ── 7. notice.log + enrichment ───────────────────────────────────────
    # Real notice.log has NO `conn` column: `uid` is the uid of the connection the notice is
    # about. The old fixture invented a `conn` field, and the old merge joined on it — so a notice
    # could never reach a record.
    tsv_notice = (
        "#separator \\x09\n"
        "#fields\tuid\tmsg\tnote\tsub\n"
        "#types\tstring\tstring\tstring\tstring\n"
        "UID-001\tConnection to known C2\tSSL::Invalid_OCSP_Certificate\tc2\n"
    )
    notice_raw = _parse_zeek_tsv(tsv_notice)
    e_notice = _notice_enrichment(notice_raw[0])
    assert e_notice["rule.description"] == "Connection to known C2"
    assert e_notice["rule.name"] == "SSL::Invalid_OCSP_Certificate"
    assert e_notice["rule.category"] == "c2"
    assert notice_raw[0]["uid"] == "UID-001"

    # ── 8. Merge per uid ─────────────────────────────────────────────────
    merged = _merge_logs(conn_raw=raw, dns_raw=dns_raw,
                         http_raw=[], ssl_raw=[], notice_raw=notice_raw)
    assert len(merged) == 1
    m = merged[0]
    assert m["dns.question.name"] == "malware-c2.example"
    assert m["source.ip"] == "10.0.0.5"
    # The notice (joined on uid, not on a non-existent `conn` column) reaches the record.
    assert m["rule.name"] == "SSL::Invalid_OCSP_Certificate", m
    assert m["rule.description"] == "Connection to known C2", m

    # ── 8b. One uid, many HTTP requests: none may be dropped ─────────────
    tsv_http_many = (
        "#separator \\x09\n"
        "#fields\tuid\thost\turi\tmethod\tstatus_code\n"
        "#types\tstring\tstring\tstring\tstring\tcount\n"
        "UID-001\twww.example.com\t/a\tGET\t200\n"
        "UID-001\twww.example.com\t/b\tGET\t200\n"
        "UID-001\twww.example.com\t/c\tPOST\t302\n"
    )
    many = _merge_logs(conn_raw=raw, dns_raw=[],
                       http_raw=_parse_zeek_tsv(tsv_http_many), ssl_raw=[], notice_raw=[])
    assert len(many) == 3, f"3 HTTP requests must yield 3 records, got {len(many)}"
    paths = sorted(r["url.path"] for r in many)
    assert paths == ["/a", "/b", "/c"], paths
    # Every one of them still carries the connection's own 4-tuple.
    assert all(r["source.ip"] == "10.0.0.5" and r["destination.ip"] == "203.0.113.10"
               for r in many)

    # ── 9. conn_state mapping ────────────────────────────────────────────
    assert _map_conn_state("SF") == "success"
    assert _map_conn_state("REJ") == "failure"
    assert _map_conn_state("S0") == "failure"
    assert _map_conn_state("OTH") == "unknown"
    assert _map_conn_state("BOGUS") == "unknown"
    assert _map_conn_state(None) is None
    # `failure` is promoted onto the salience-filtered timeline, so it has to mean something
    # failed — not that the capture shows only part of the exchange.
    assert _map_conn_state("S1") == "unknown", "an ongoing connection has not failed"
    assert _map_conn_state("SH") == "unknown", "a FIN with no SYN in the capture is a partial view"
    assert _map_conn_state("SHR") == "unknown"
    # A UDP request with no reply recorded is the ordinary shape of DNS in a one-way capture; the
    # same state over TCP is a SYN nobody answered, which is a real failure.
    assert _map_conn_state("S0", "udp") == "unknown", "a DNS question is not a failed action"
    assert _map_conn_state("S0", "tcp") == "failure"

    # ── 10. Timestamp malformato ─────────────────────────────────────────
    assert _epoch_to_iso(None) is None
    assert _epoch_to_iso("") is None
    assert _epoch_to_iso("not-a-number") is None
    valid_ts = _epoch_to_iso("1700000000.000000")
    assert valid_ts is not None and valid_ts.endswith("Z")

    # ── 11. TSV edge: log with no data (only header) ──────────────────────
    empty_log = "#separator \\x09\n#fields\tuid\tquery\n#types\tstring\tstring\n"
    assert _parse_zeek_tsv(empty_log) == []

    # ── 12. Zeek uses '-' for unset and '(empty)' for empty ───────────────
    tsv_unset = (
        "#separator \\x09\n"
        "#fields\tuid\tservice\tanswers\n"
        "#types\tstring\tstring\tstring\n"
        "UID-001\t-\t-\n"
    )
    parsed_unset = _parse_zeek_tsv(tsv_unset)
    assert len(parsed_unset) == 1
    assert parsed_unset[0]["service"] is None
    assert parsed_unset[0]["answers"] is None

    # ── 13. IPv6 ─────────────────────────────────────────────────────────
    tsv_ipv6 = (
        "#separator \\x09\n"
        "#fields\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n"
        "#types\tstring\taddr\taddr\tport\tenum\n"
        "UID-v6\t2001:db8::1\t2600::1\t443\ttcp\n"
    )
    raw_v6 = _parse_zeek_tsv(tsv_ipv6)
    rec_v6 = _conn_record(raw_v6[0])
    assert rec_v6["source.ip"] == "2001:db8::1"
    assert rec_v6["destination.ip"] == "2600::1"
    assert rec_v6["destination.port"] == 443

    print("PASS  Zeek field-mapping (synthetic, always run)")


def run() -> int:
    run_synthetic()

    if not shutil.which("zeek"):
        return skip_test("zeek not installed (field-mapping still validated by run_synthetic)")

    from adapters import pcap_tshark, pcap_zeek
    from make_sample_pcap import write_sample

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        pcap = Path(tmp.name)
    write_sample(pcap)

    try:
        # ── Zeek adapter ────────────────────────────────────────────────
        zeek_records = pcap_zeek.load_records(pcap)
        assert len(zeek_records) > 0, "Zeek produced no records"

        # DNS
        zeek_dns = {
            r.get("dns.question.name") for r in zeek_records
            if r.get("dns.question.name")
        }
        assert "malware-c2.example" in zeek_dns, \
            f"expected DNS not found in Zeek; found: {zeek_dns}"

        # Ports
        zeek_ports = {
            (r.get("destination.ip"), r.get("destination.port"))
            for r in zeek_records
        }
        assert ("198.51.100.7", 4444) in zeek_ports, \
            f"port 4444 not found in Zeek: {zeek_ports}"
        assert ("203.0.113.10", 443) in zeek_ports, \
            f"port 443 not found in Zeek: {zeek_ports}"

        print(f"PASS  Zeek PCAP: {len(zeek_records)} records, expected DNS and ports")

        # ── Cross-check with tshark ──────────────────────────────────────
        if shutil.which("tshark"):
            tshark_records = pcap_tshark.load_records(pcap)

            # (src.ip, dst.ip, dst.port) triples from both adapters
            tshark_triples = {
                (r.get("source.ip"), r.get("destination.ip"), r.get("destination.port"))
                for r in tshark_records if r.get("source.ip")
            }
            zeek_triples = {
                (r.get("source.ip"), r.get("destination.ip"), r.get("destination.port"))
                for r in zeek_records if r.get("source.ip")
            }

            common = tshark_triples & zeek_triples
            assert len(common) > 0, \
                f"no common triples between tshark {tshark_triples} and zeek {zeek_triples}"

            # Both see DNS and key ports
            assert ("10.0.0.5", "8.8.8.8", 53) in common, \
                f"DNS 8.8.8.8:53 not in common: {common}"
            assert ("10.0.0.5", "203.0.113.10", 443) in common, \
                f"443 not in common: {common}"

            print(f"PASS  Cross-check tshark × Zeek: {len(common)} common triples")
        else:
            # Tail of the function: the zeek-only checks above already ran and asserted; this
            # only reports that the tshark cross-source coherence check was not exercised.
            skip_test("Cross-check: tshark not installed")

        # A RELATIVE path must work. zeek runs with cwd set to its own temp work dir, so an
        # unresolved relative path was looked up there instead of the analyst's directory: zeek
        # exited "unable to open", the PCAP analysis silently continued on tshark alone, and the
        # whole application layer went missing behind one non-fatal error line. That is exactly the
        # shape every CLI produces when the analyst types `--pcap capture.pcap`.
        cwd = os.getcwd()
        try:
            os.chdir(pcap.parent)
            rel = pcap_zeek.load_records(pcap.name)
            assert rel, "zeek returned nothing for a relative path (it resolves against its own cwd)"
        finally:
            os.chdir(cwd)

    finally:
        pcap.unlink(missing_ok=True)

    return 0


def test_pcap_zeek():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
