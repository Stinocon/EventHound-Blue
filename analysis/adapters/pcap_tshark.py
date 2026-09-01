"""Adapter: PCAP (via tshark) → common schema (ECS subset, network fields).

Wraps `tshark -T fields` to extract network fields from each packet into the
common schema (analysis/schema/common-schema.md): source.ip, destination.ip,
destination.port, dns.question.name. No network: reads a local .pcap file.

Anonymization: client internal IPs must be pseudonymized *downstream* (malicious
public IPs are not) — see common-schema.md and §9 — method/conventions.md.
"""
from __future__ import annotations

import datetime as _dt
import shutil
import subprocess
from pathlib import Path

# tshark fields extracted, in order; -T fields output is tab-separated.
_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ip.proto",        # 6=TCP, 17=UDP
    "ipv6.src",
    "ipv6.dst",
    "ipv6.nxt",        # next-header IPv6: 6=TCP, 17=UDP (same mapping as ip.proto)
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "dns.qry.name",
    "_ws.col.Protocol",
]
_TRANSPORT = {"6": "tcp", "17": "udp"}


def _tshark() -> str:
    exe = shutil.which("tshark")
    if not exe:
        raise FileNotFoundError("tshark not found in PATH (install Wireshark/tshark).")
    return exe


def _record(cols: list[str], source: str = "pcap") -> dict | None:
    f = dict(zip(_FIELDS, cols))
    ts = f.get("frame.time_epoch") or ""
    when = None
    if ts:
        try:
            when = _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc) \
                .strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except (ValueError, OSError, OverflowError):
    # malformed/out-of-range epoch (inf, too large/negative): degrade the single
    # @timestamp to None, do not abort the entire load (cf. evtx_hayabusa, "don't make up,
    # skip it"). float('inf')→OverflowError, huge negative epoch→OSError.
            when = None
    dport = f.get("tcp.dstport") or f.get("udp.dstport") or None
    # The ephemeral source port is what identifies a CONNECTION. Without it every packet of one
    # exchange reads as a separate connection, which is why `recipes.beaconing` was measuring
    # inter-packet gaps on any real capture instead of the interval between call-backs.
    sport = f.get("tcp.srcport") or f.get("udp.srcport") or None
    # Transport: tcp/udp.dstport fields are populated by tshark even with IPv6 extension headers,
    # where ipv6.nxt is the FIRST next-header (e.g., 44=Fragment, 0=Hop-by-Hop) and not 6/17.
    # Therefore prefer the presence of dstport; fall back to ip.proto/ipv6.nxt only if absent.
    if f.get("tcp.dstport"):
        transport = "tcp"
    elif f.get("udp.dstport"):
        transport = "udp"
    else:
        transport = _TRANSPORT.get(f.get("ip.proto") or f.get("ipv6.nxt") or "", None)
    rec = {
        "@timestamp": when,
        "event.source": source,
        "event.category": "network",
        "network.transport": transport,
        "network.protocol": (f.get("_ws.col.Protocol") or None),
        "network.bytes": int(f["frame.len"]) if f.get("frame.len", "").isdigit() else None,
        "source.ip": f.get("ip.src") or f.get("ipv6.src") or None,
        "destination.ip": f.get("ip.dst") or f.get("ipv6.dst") or None,
        "source.port": int(sport) if (sport and sport.isdigit()) else None,
        "destination.port": int(dport) if (dport and dport.isdigit()) else None,
        "dns.question.name": f.get("dns.qry.name") or None,
    }
    if not rec["source.ip"] and not rec["destination.ip"] and not rec["dns.question.name"]:
        return None  # non-IP packet not relevant (e.g. ARP)
    return {k: v for k, v in rec.items() if v not in (None, "")}


def load_records(pcap_path: str | Path) -> list[dict]:
    """Run tshark on a PCAP and return records in the common schema."""
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")
    source = f"pcap:{pcap_path.name}"
    cmd = [_tshark(), "-r", str(pcap_path), "-T", "fields"]
    for fld in _FIELDS:
        cmd += ["-e", fld]
    # occurrence=f: for multi-value fields keep only the first (separator of -T fields = tab by default)
    cmd += ["-E", "occurrence=f"]
    # explicit encoding/errors: text=True would use the locale (ASCII under LC_ALL=C in cron/launchd/CI),
    # and a non-UTF-8 byte in a field (e.g., dns.qry.name of a malicious packet) would abort the entire
    # PCAP analysis. Degrade the dirty byte, not the stream.
    try:
        proc = subprocess.run(
            cmd, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
    except subprocess.CalledProcessError as exc:
        # Corrupted/truncated/non-capture PCAP: tshark exits non-zero. Report a clean domain error
        # (with tshark's stderr), consistent with "don't make up, skip it" — no raw traceback.
        msg = (exc.stderr or "").strip() or f"tshark exited with code {exc.returncode}"
        raise RuntimeError(f"tshark failed to read {pcap_path}: {msg}")
    out = proc.stdout

    records: list[dict] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        # pad to expected length
        cols += [""] * (len(_FIELDS) - len(cols))
        rec = _record(cols, source=source)
        if rec:
            records.append(rec)
    return records
