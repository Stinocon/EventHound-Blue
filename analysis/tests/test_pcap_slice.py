"""Validation of PCAP adapter: from the synthetic sample must emerge what we
put there (DNS query, conversations, non-standard port).

Offline and deterministic: the pcap is generated at runtime by make_sample_pcap.
Requires `tshark` in PATH; if absent, the test is skipped.

    uv run python tests/test_pcap_slice.py
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tests._helpers import skip_test  # noqa: E402


def run_synthetic() -> None:
    """Always validates PCAP→schema mapping on pure _record layer (list of columns in _FIELDS
    order), without depending on tshark (often absent in CI, skipping every field-mapping verification).
    Covers: tcp/udp transport, destination.port int, dns.question.name, non-IP packet discard (e.g. ARP)."""
    from adapters import pcap_tshark

    # _FIELDS: frame.time_epoch, frame.len, ip.src, ip.dst, ip.proto, ipv6.src, ipv6.dst,
    #          ipv6.nxt, tcp.srcport, udp.srcport, tcp.dstport, udp.dstport, dns.qry.name,
    #          _ws.col.Protocol
    tcp_cols = ["1700000000.0", "60", "10.0.0.5", "203.0.113.10", "6",
                "", "", "", "50001", "", "443", "", "", "TLSv1.2"]
    rec = pcap_tshark._record(tcp_cols)
    assert rec is not None and rec["network.transport"] == "tcp", rec
    assert rec["destination.ip"] == "203.0.113.10", rec
    assert rec["destination.port"] == 443 and isinstance(rec["destination.port"], int), rec
    # The ephemeral source port is what tells two packets of one connection from two connections;
    # `recipes.beaconing` folds rows into connections on it (see its docstring).
    assert rec["source.port"] == 50001 and isinstance(rec["source.port"], int), rec
    assert rec["event.category"] == "network", rec

    dns_cols = ["1700000001.0", "80", "10.0.0.5", "10.0.0.1", "17",
                "", "", "", "50004", "", "", "53", "malware-c2.example", "DNS"]
    drec = pcap_tshark._record(dns_cols)
    assert drec is not None and drec["dns.question.name"] == "malware-c2.example", drec
    assert drec["network.transport"] == "udp", drec

    # non-IP packet (no ip.src/dst/dns): must be discarded
    arp_cols = ["1700000002.0", "42"] + [""] * 12
    assert pcap_tshark._record(arp_cols) is None, "non-IP packet not discarded"
    print("PASS  pcap field-mapping (synthetic, always run)")


def run() -> int:
    run_synthetic()

    if not shutil.which("tshark"):
        return skip_test("tshark not installed (field-mapping still validated by run_synthetic)")

    from adapters import pcap_tshark
    from make_sample_pcap import write_sample

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        pcap = Path(tmp.name)
    write_sample(pcap)
    records = pcap_tshark.load_records(pcap)
    pcap.unlink(missing_ok=True)

    dns = {r.get("dns.question.name") for r in records}
    dports = {(r.get("destination.ip"), r.get("destination.port")) for r in records}

    assert "malware-c2.example" in dns, f"expected DNS not found; found: {dns}"
    assert ("198.51.100.7", 4444) in dports, f"non-standard port connection missing: {dports}"
    assert ("203.0.113.10", 443) in dports, f"443 connection missing: {dports}"
    assert sum(1 for r in records if r.get("destination.port") == 443) == 2, \
        "expected 2 connections to 443"

    print(f"PASS  PCAP: {len(records)} packets, expected DNS and flows present")
    return 0


def test_pcap_slice():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
