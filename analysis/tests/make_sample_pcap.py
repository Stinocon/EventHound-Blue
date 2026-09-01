"""Generate a deterministic sample PCAP for PCAP adapter tests.

No live capture or network: builds a small pcap by hand (linktype Ethernet) with a few
representative packets — a DNS query, some TCP connections (443 and an unusual port) — so the test
is reproducible and offline.

The packet primitives now live in `demo/pcap_writer.py`, where the demo scenario needs the same
ones; this module keeps only *which* packets the fixture contains. `test_demo.py` pins the sha256
of the file produced here, so the move is verified byte-for-byte rather than assumed.

The IPs used are documentation (RFC 5737: 203.0.113.0/24, 198.51.100.0/24) and private
(RFC 1918): no real data.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo import pcap_writer  # noqa: E402

_BASE_TS = 1700000000  # fixed epoch for deterministic output


def _packets() -> list[bytes]:
    return [
        # 1) DNS query to a "suspicious" domain
        pcap_writer.dns_packet("10.0.0.5", "8.8.8.8", 50000, "malware-c2.example"),
        # 2-3) two legitimate HTTPS connections to the same host
        pcap_writer.tcp_packet("10.0.0.5", "203.0.113.10", 50001, 443),
        pcap_writer.tcp_packet("10.0.0.5", "203.0.113.10", 50002, 443),
        # 4) connection to an unusual port (possible C2 on non-standard port)
        #    NB: the port must be OUTSIDE recipes.COMMON_PORTS (8443 is included, so NOT
        #    would be "non-standard"); 4444 is non-standard and consistent with test_analytics.
        pcap_writer.tcp_packet("10.0.0.5", "198.51.100.7", 50003, 4444),
        # 5) second DNS query, benign domain
        pcap_writer.dns_packet("10.0.0.5", "8.8.8.8", 50004, "update.example"),
    ]


def write_sample(path: str | Path) -> Path:
    return pcap_writer.write_pcap(
        path, [(_BASE_TS + i, pkt) for i, pkt in enumerate(_packets())])


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sample.pcap"
    print("written:", write_sample(out))
