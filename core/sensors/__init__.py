"""Sensor registry — every source plugin, discovered statically.

Usage::

    from core.sensors import registry

    records = registry["logs"]().ingest("auth.log")
"""

from __future__ import annotations

from typing import Callable

from core.sensors.base import Sensor
from core.sensors.evtx import EvtxSensor
from core.sensors.logs import LogsSensor
from core.sensors.mft import MftSensor
from core.sensors.osquery import OsquerySensor
from core.sensors.pcap import PcapSensor
from core.sensors.registry import RegistrySensor
from core.sensors.thor import ThorSensor

#: name -> sensor class. Adding a source = adding one import and one entry.
REGISTRY: dict[str, type[Sensor]] = {
    EvtxSensor.name: EvtxSensor,
    LogsSensor.name: LogsSensor,
    MftSensor.name: MftSensor,
    OsquerySensor.name: OsquerySensor,
    PcapSensor.name: PcapSensor,
    RegistrySensor.name: RegistrySensor,
    ThorSensor.name: ThorSensor,
}

#: File extension -> default sensor name, for auto-detection by artifact.
EXTENSION_MAP: dict[str, str] = {
    ".evtx": "evtx",
    ".jsonl": "evtx",  # Hayabusa timeline (see EvtxSensor)
    ".pcap": "pcap",
    ".pcapng": "pcap",
    ".reg": "registry",
    ".log": "logs",
    ".txt": "thor",  # THOR reports; use the explicit name for other text
}


def sensor_for(path: str) -> Sensor:
    """Pick a sensor from an artifact's extension (best effort)."""
    from pathlib import Path

    name = EXTENSION_MAP.get(Path(path).suffix.lower())
    if name is None:
        raise ValueError(f"no sensor for {path!r}; pick one of {sorted(REGISTRY)}")
    return REGISTRY[name]()


__all__ = [
    "EXTENSION_MAP",
    "REGISTRY",
    "Sensor",
    "sensor_for",
    "Callable",
]
