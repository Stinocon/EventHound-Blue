"""Hand-built PCAP writer: the byte-level primitives, with no capture and no network.

There is no Python library in this project's dependency set that *writes* a capture, and adding one
to produce a handful of packets would fail the minimal-code ladder. So the packets are assembled by
hand — Ethernet + IPv4 + TCP/UDP — which is enough for what the PCAP adapter actually reads back
through tshark: epoch, frame length, addresses, transport, destination port and the DNS question.

Promoted here from `tests/make_sample_pcap.py`, which had these primitives to itself while the demo
needed exactly the same ones. The test now imports them, and pins the sha256 of its sample so this
move stays provably byte-for-byte.

Every address used by callers must be documentation (RFC 5737) or private (RFC 1918) space: these
files are committed to a public-bound repo and must never carry a real one (§9).
"""
from __future__ import annotations

import struct
from pathlib import Path

_SRC_MAC = b"\x02\x00\x00\x00\x00\x01"
_DST_MAC = b"\x02\x00\x00\x00\x00\x02"


def _ipv4_checksum(header: bytes) -> int:
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) + header[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ip_to_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def ipv4(proto: int, src: str, dst: str, payload: bytes) -> bytes:
    total_len = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s",
                      0x45, 0x00, total_len, 0x0001, 0x4000, 64, proto, 0,
                      _ip_to_bytes(src), _ip_to_bytes(dst))
    chk = _ipv4_checksum(hdr)
    hdr = hdr[:10] + struct.pack(">H", chk) + hdr[12:]
    return hdr + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack(">HHHH", sport, dport, length, 0) + payload


def tcp(sport: int, dport: int, flags: int = 0x002, payload: bytes = b"",
        seq: int = 0, ack: int = 0) -> bytes:
    """TCP segment. `flags` defaults to SYN; pass 0x018 (PSH|ACK) for a segment carrying data."""
    off_flags = (5 << 12) | flags
    return struct.pack(">HHIIHHHH", sport, dport, seq, ack, off_flags, 64240, 0, 0) + payload


def dns_query(name: str) -> bytes:
    qname = b"".join(struct.pack("B", len(p)) + p.encode() for p in name.split(".")) + b"\x00"
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def eth(payload: bytes) -> bytes:
    return _DST_MAC + _SRC_MAC + struct.pack(">H", 0x0800) + payload


def tcp_packet(src: str, dst: str, sport: int, dport: int,
               flags: int = 0x002, payload: bytes = b"") -> bytes:
    """A full Ethernet frame carrying one TCP segment."""
    return eth(ipv4(6, src, dst, tcp(sport, dport, flags=flags, payload=payload)))


def dns_packet(src: str, dst: str, sport: int, name: str) -> bytes:
    """A full Ethernet frame carrying one DNS A query."""
    return eth(ipv4(17, src, dst, udp(sport, 53, dns_query(name))))


def write_pcap(path: str | Path, packets) -> Path:
    """Write `packets` — an iterable of (epoch_seconds, frame_bytes) — as a libpcap file.

    Timestamps are taken from the caller rather than generated, because the demo's whole point is a
    chain whose *timing* is declared: a generated 'now' would move the capture out of the incident's
    window and out of its episode every time the file is rebuilt.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        # global header: magic, v2.4, thiszone, sigfigs, snaplen, network=1 (Ethernet)
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, pkt in packets:
            sec = int(ts)
            usec = int(round((float(ts) - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(pkt), len(pkt)))
            fh.write(pkt)
    return path
