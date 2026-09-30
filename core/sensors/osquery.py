"""osquery sensor — result logs (NDJSON snapshots/diffs).

Delegates to ``adapters.osquery_result.load_records``.
"""

from __future__ import annotations

from core.sensors.base import Sensor


class OsquerySensor(Sensor):
    name = "osquery"

    def ingest(self, source) -> list[dict]:
        from adapters import osquery_result

        return osquery_result.load_records(source)
