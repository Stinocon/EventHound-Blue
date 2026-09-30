"""PCAP sensor — Zeek primary, tshark fallback.

Delegates to ``adapters.pcap_zeek`` (per-connection records, the analytic
road) and falls back to ``adapters.pcap_tshark`` (per-packet) when Zeek is
not installed on the machine.
"""

from __future__ import annotations

from pathlib import Path

from core.sensors.base import Sensor


def _zeek_available() -> bool:
    from shutil import which

    return which("zeek") is not None or which("zexec") is not None


class PcapSensor(Sensor):
    name = "pcap"

    def ingest(self, source, backend: str = "auto") -> list[dict]:
        source = Path(source)
        if not source.exists():
            raise FileNotFoundError(f"artifact not found: {source}")

        if backend == "zeek" or (backend == "auto" and _zeek_available()):
            from adapters import pcap_zeek

            return pcap_zeek.load_records(source)
        if backend in {"tshark", "auto"}:
            from adapters import pcap_tshark

            return pcap_tshark.load_records(source)
        raise ValueError(f"unknown PCAP backend {backend!r} (zeek|tshark|auto)")
