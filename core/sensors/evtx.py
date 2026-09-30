"""EVTX sensor — Hayabusa json-timeline (detection) as the primary road.

Accepts either a pre-built Hayabusa JSONL timeline (``.jsonl``/``.json``) or
a raw ``.evtx``; in the latter case it runs Hayabusa first
(``engine.hayabusa_runner.run``) into a temporary timeline, then normalizes
through ``adapters.evtx_hayabusa.load_records``.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from core.sensors.base import Sensor


class EvtxSensor(Sensor):
    name = "evtx"

    def ingest(self, source, **kwargs) -> list[dict]:
        from adapters import evtx_hayabusa

        source = Path(source)
        if not source.exists():
            raise FileNotFoundError(f"artifact not found: {source}")

        if source.suffix.lower() in {".jsonl", ".json"}:
            return evtx_hayabusa.load_records(source, source="evtx")

        if source.suffix.lower() == ".evtx":
            from engine import hayabusa_runner

            with tempfile.TemporaryDirectory(prefix="eh2-hayabusa-") as tmp:
                timeline = Path(tmp) / "timeline.jsonl"
                hayabusa_runner.run(source, timeline, **kwargs)
                return evtx_hayabusa.load_records(timeline, source="evtx")

        raise ValueError(
            f"unsupported EVTX artifact {source.suffix!r}: "
            "expected .evtx or a Hayabusa .jsonl timeline"
        )
