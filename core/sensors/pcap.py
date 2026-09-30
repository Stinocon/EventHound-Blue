"""PCAP sensor — the v1 runner road: tshark + Zeek, concatenated.

``analytics/runner.build_records`` (the pipeline the demo, the analytics
and the MCP use) reads a PCAP with ``adapters.pcap_tshark`` (per-packet
records), then enriches with ``adapters.pcap_zeek`` (application layer:
HTTP, SSL, DNS detail) when Zeek is installed — the two record sets are
concatenated, not merged. ``backend="auto"`` reproduces exactly that:
tshark first (a tshark failure is fatal), Zeek after (skipped when the
binary is absent). A machine with Zeek only falls back to Zeek alone.

``backend="both"`` is instead the run_pcap view: the two record sets
merged and deduplicated per flow (``engine.run_pcap._merge_records``).
"""

from __future__ import annotations

from pathlib import Path

from core.sensors.base import Sensor


def _available(binary: str) -> bool:
    from shutil import which

    return which(binary) is not None


class PcapSensor(Sensor):
    name = "pcap"

    def ingest(self, source, backend: str = "auto") -> list[dict]:
        source = Path(source)
        if not source.exists():
            raise FileNotFoundError(f"artifact not found: {source}")

        has_tshark = _available("tshark")
        has_zeek = _available("zeek") or _available("zexec")

        if backend == "auto":
            if not has_tshark and not has_zeek:
                raise ValueError(
                    "no PCAP backend available: install tshark and/or zeek"
                )
            if not has_tshark:
                return self._zeek(source)  # zeek-only fallback (no tshark)
            records = self._tshark(source)  # fatal if it fails, as in the runner
            if has_zeek:
                records += self._zeek(source)  # application-layer enrichment
            return records
        if backend == "tshark":
            return self._tshark(source)
        if backend == "zeek":
            return self._zeek(source)
        if backend == "both":
            return self._both(source)
        raise ValueError(f"unknown PCAP backend {backend!r} (auto|tshark|zeek|both)")

    @staticmethod
    def _tshark(source: Path) -> list[dict]:
        from adapters import pcap_tshark

        return pcap_tshark.load_records(source)

    @staticmethod
    def _zeek(source: Path) -> list[dict]:
        from adapters import pcap_zeek

        return pcap_zeek.load_records(source)

    def _both(self, source: Path) -> list[dict]:
        from engine.run_pcap import _merge_records  # noqa: SLF001 — v1 merge road

        return _merge_records(self._tshark(source), self._zeek(source))
