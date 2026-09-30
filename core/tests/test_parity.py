"""Parity test — the v2 sensors must produce EXACTLY the v1 records.

The demo scenario (analysis/demo/scenario.py, pure stdlib, deterministic)
generates the artifacts; run_demo.demo_records reads them back through the
v1 adapters and reports per-source records. Each artifact then goes through
its v2 sensor, and the two record lists must be identical — the v2 layer
wraps the v1 adapters, so any difference is a wrapper bug, not analysis
drift.

Sources whose external tool is missing are skipped (repo convention: a skip
is not a pass): tshark/zeek for pcap, yara-python for yara.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.sensors import REGISTRY
from core.sensors.base import Sensor  # noqa: F401 — registry type

# artifact -> (sensor name, source in run_demo per_source). Explicit mapping,
# not extension guessing: the demo's osquery export is a .log and its
# CrowdStrike clipboard is a .txt — both ambiguous by extension.
_ARTIFACTS: dict[str, tuple[str, str]] = {
    "crowdstrike_detections.txt": ("crowdstrike", "crowdstrike"),
    "fs-02_osquery_result.log": ("osquery", "osquery"),
    "perimeter.pcap": ("pcap", "pcap"),
    "ws-11_hayabusa-timeline.jsonl": ("evtx", "evtx"),
    "ws-11_run-keys.reg": ("registry", "registry"),
    "sma-01_auth.log": ("logs", "logs"),
    "sma-01_extraweb_access.log": ("logs", "logs"),
    "ws-11_thor_2026-03-12_0810.txt": ("thor", "thor"),
}

_YARA_TARGET = "quarantine/svcupdate.exe"
_YARA_RULES = "yara_rules/eventhound_demo.yar"


def _demo_available() -> dict[str, bool]:
    from engine import run_demo

    return run_demo.available_tools()


def test_v2_sensors_reproduce_v1_records():
    """Per source: v2 sensor output == v1 adapter output, record for record."""
    from engine import run_demo

    import tempfile

    with tempfile.TemporaryDirectory(prefix="eh2-parity-") as tmp:
        per_source: dict[str, list[dict]] = {}
        run_demo.demo_records(Path(tmp) / "out", per_source=per_source)
        out = Path(tmp) / "out"

        tools = _demo_available()
        compared = 0
        v2_by_source: dict[str, list[dict]] = {}
        for filename, (sensor_name, source) in _ARTIFACTS.items():
            path = out / filename
            assert path.exists(), f"demo did not generate {filename}"
            if source == "pcap" and not (tools.get("tshark") or tools.get("zeek")):
                pytest.skip("no pcap tool installed (tshark/zeek)")
            records = REGISTRY[sensor_name]().ingest(path)
            v2_by_source.setdefault(source, []).extend(records)

        # yara: separate signature (target + rules)
        if tools.get("yara"):
            yara_records = REGISTRY["yara"]().ingest(
                out / _YARA_TARGET, rules=out / _YARA_RULES
            )
            v2_by_source["yara"] = yara_records
        else:
            pytest.skip("yara-python not installed")

        for source, v2_records in v2_by_source.items():
            v1_records = per_source[source]
            assert len(v2_records) == len(v1_records), (
                f"{source}: v2 produced {len(v2_records)} records, "
                f"v1 produced {len(v1_records)}"
            )
            # Order-insensitive comparison: Zeek emits near-simultaneous flows
            # in a run-dependent order (same records, different sequence), so
            # the contract is the RECORD SET — the analytics sort by timestamp
            # downstream anyway.
            key = lambda recs: sorted(  # noqa: E731 — local, used twice
                json.dumps(r, sort_keys=True, default=str) for r in recs
            )
            assert key(v2_records) == key(v1_records), (
                f"{source}: v2 records differ from v1 adapter output"
            )
            compared += len(v2_records)

        assert compared > 40, f"parity checked only {compared} records"
