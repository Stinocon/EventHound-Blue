"""CrowdStrike sensor — detection clipboard or LogScale/Investigation JSON.

Delegates to ``adapters.crowdstrike`` (auto-detects the two formats, both
grounded on real data). A ``.txt`` artifact is ambiguous between THOR and
CrowdStrike clipboard — callers pick this sensor explicitly (API ``sensor``
form field), the extension map stays with THOR.
"""

from __future__ import annotations

from pathlib import Path

from core.sensors.base import Sensor


class CrowdstrikeSensor(Sensor):
    name = "crowdstrike"

    def ingest(self, source) -> list[dict]:
        from adapters import crowdstrike

        source = Path(source)
        if not source.exists():
            raise FileNotFoundError(f"artifact not found: {source}")
        return crowdstrike.load_records(source)
