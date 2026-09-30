"""Sensor plugin tests — every plugin against the real sample artifacts.

Counts below were verified against the v1 adapters on the shipped samples
(2026-09-30); they are the regression contract for the v2 wrappers.
External binaries (Hayabusa, Zeek, tshark) are probed and the test skips
when absent — a skip is not a pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.sensors import REGISTRY, sensor_for
from core.sensors.evtx import EvtxSensor
from core.sensors.logs import LogsSensor
from core.sensors.mft import MftSensor
from core.sensors.osquery import OsquerySensor
from core.sensors.pcap import PcapSensor
from core.sensors.registry import RegistrySensor
from core.sensors.thor import ThorSensor

SAMPLES = Path(__file__).resolve().parent.parent.parent / "samples"


def _sample(name: str) -> Path:
    """Path to a sample artifact; SKIP the test when the (gitignored, §9)
    sample set is absent — a missing dataset is a skip, not a fail."""
    path = SAMPLES / name
    if not path.exists():
        pytest.skip(f"sample not present: {name} (gitignored sample set)")
    return path


# samples/ artifacts are client-shaped data (§9): real identifiers only
# inside the gitignored/private sample set, never in assertions.


def _assert_records(records: list[dict], expected_source: str) -> None:
    """Every plugin must return common-schema records with the contract keys.

    ``event.source`` keeps the origin family, optionally qualified with the
    file name (common-schema.md: the source stays the origin) — hence the
    ``startswith`` on the bare family (``log:auth.log`` for the log sensor).
    """
    assert records, "sensor returned no records"
    for r in records:
        assert "@timestamp" in r, f"missing @timestamp in {r}"
        assert r["event.source"].split(":")[0] == expected_source, r["event.source"]


# --- logs --------------------------------------------------------------------


def test_logs_auth_sensor():
    records = LogsSensor().ingest(_sample("sma-01_auth.log"))
    assert len(records) == 6
    _assert_records(records, "log")  # v1 emits 'log:<filename>'


def test_logs_access_sensor():
    records = LogsSensor().ingest(_sample("sma-01_extraweb_access.log"))
    assert len(records) == 10
    _assert_records(records, "log")


def test_logs_explicit_format():
    records = LogsSensor().ingest(
        _sample("sma-01_auth.log"), fmt="syslog"
    )
    assert len(records) == 6


# --- evtx (Hayabusa timeline) --------------------------------------------------


def test_evtx_timeline_sensor():
    records = EvtxSensor().ingest(_sample("ws-01_hayabusa-timeline.jsonl"))
    assert len(records) == 10
    _assert_records(records, "evtx")


# No raw .evtx ships with the repo (client-shaped data, §9), so the raw
# Hayabusa road is exercised by the v1 engine suite; here the contract is
# the timeline road plus input validation.


def test_evtx_rejects_unknown_extension():
    with pytest.raises(ValueError, match="unsupported EVTX artifact"):
        EvtxSensor().ingest(_sample("sma-01_auth.log"))


# --- pcap ---------------------------------------------------------------------


def test_pcap_sensor_zeek():
    records = PcapSensor().ingest(_sample("perimeter.pcap"), backend="zeek")
    assert len(records) == 15
    _assert_records(records, "pcap")


def test_pcap_sensor_tshark():
    from shutil import which

    if which("tshark") is None:
        pytest.skip("tshark not installed")
    records = PcapSensor().ingest(_sample("perimeter.pcap"), backend="tshark")
    _assert_records(records, "pcap")


def test_pcap_unknown_backend():
    with pytest.raises(ValueError, match="unknown PCAP backend"):
        PcapSensor().ingest(_sample("perimeter.pcap"), backend="nope")


# --- registry -------------------------------------------------------------------


def test_registry_regfile_sensor():
    records = RegistrySensor().ingest(_sample("ws-01_run-key.reg"))
    assert len(records) == 1
    _assert_records(records, "registry")


def test_registry_rejects_missing_file():
    with pytest.raises(FileNotFoundError):
        RegistrySensor().ingest(SAMPLES / "does-not-exist.reg")


# --- thor ------------------------------------------------------------------------


def test_thor_sensor():
    records = ThorSensor().ingest(_sample("ws-01_thor_2026-03-12_0840.txt"))
    assert len(records) == 3
    _assert_records(records, "thor")
    alert = [r for r in records if r.get("ioc.severity") == "high"]
    assert alert, "THOR sample must contain at least one high-severity finding"


# --- osquery ------------------------------------------------------------------------


def test_osquery_sensor():
    records = OsquerySensor().ingest(_sample("ws-01_osquery.jsonl"))
    assert len(records) == 2
    _assert_records(records, "osquery")


# --- mft (contract only: no MFTECmd output ships in samples/) --------------------


def test_mft_requires_directory():
    with pytest.raises(NotADirectoryError, match="MFTECmd JSON output"):
        MftSensor().ingest(_sample("ws-01_run-key.reg"))


# --- registry sanity ---------------------------------------------------------------


def test_registry_covers_all_sensors():
    assert sorted(REGISTRY) == [
        "crowdstrike",
        "evtx",
        "logs",
        "mft",
        "osquery",
        "pcap",
        "registry",
        "thor",
        "yara",
    ]


def test_sensor_for_extension():
    assert sensor_for("a/b.evtx").name == "evtx"
    assert sensor_for("c.pcap").name == "pcap"
    assert sensor_for("x.reg").name == "registry"
    assert sensor_for("y.log").name == "logs"
    with pytest.raises(ValueError, match="no sensor"):
        sensor_for("z.xyz")
