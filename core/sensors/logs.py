"""Generic log sensor — syslog/access/JSON/regex via the v1 log adapter.

Delegates to ``adapters.logfile.load_records``; format detection is the
adapter's (``fmt="auto"`` sniffs the first lines). Optional ``fmt`` and
``mapping`` pass through unchanged.
"""

from __future__ import annotations

from core.sensors.base import Sensor


class LogsSensor(Sensor):
    name = "logs"

    def ingest(self, source, fmt: str = "auto", **kwargs) -> list[dict]:
        from adapters import logfile

        return logfile.load_records(source, fmt=fmt, **kwargs)
