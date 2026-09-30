"""THOR (Nextron) sensor — scored findings from a THOR report.

Delegates to ``adapters.thor_scan.load_records``: the syslog-style THOR
report plus, optionally, the ``md5s`` file listing all scanned hashes.
"""

from __future__ import annotations

from pathlib import Path

from core.sensors.base import Sensor


class ThorSensor(Sensor):
    name = "thor"

    def ingest(self, source, md5s: str | Path | None = None) -> list[dict]:
        from adapters import thor_scan

        source = Path(source)
        if not source.exists():
            raise FileNotFoundError(f"artifact not found: {source}")
        return thor_scan.load_records(source, md5s=md5s)
