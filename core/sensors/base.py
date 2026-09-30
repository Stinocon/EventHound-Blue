"""Sensor plugin contract and analysis-engine bootstrap.

A sensor turns one artifact (EVTX, PCAP, log file, registry export, MFT, THOR
report, osquery snapshot) into common-schema records — plain dicts with dotted
ECS-subset keys, exactly what ``analysis/adapters/`` already produce and what
``analytics/store.py`` consumes. The v2 plugin does not reimplement any
parsing: it delegates to the tested v1 adapter and adds a uniform interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from core.bootstrap import ensure_engine_path

ensure_engine_path()  # the adapters/engine below live in analysis/


class Sensor(ABC):
    """A source plugin: artifact path -> common-schema records.

    Records are dicts with dotted ECS-subset keys (``@timestamp``,
    ``event.source``, ``host.name``, ...) as defined in
    ``analysis/schema/common-schema.md``. No sensor may return records that
    do not carry ``@timestamp`` and ``event.source``.
    """

    #: Stable plugin name, used by the registry and the API.
    name: str = "sensor"

    @abstractmethod
    def ingest(self, source: str | Path, **kwargs: Any) -> list[dict]:
        """Ingest one artifact and return common-schema records."""
        raise NotImplementedError
