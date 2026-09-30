"""YARA sensor — scan a target (file or folder) against a rules file/folder.

Delegates to ``adapters.yara_scan``: one record per match (file × rule),
ATT&CK technique propagated from the rule meta when present. The rules path
is a required second argument — there is no meaningful default.

``yara-python`` is an optional dependency of the v1 engine
(``uv sync --extra yara``); when absent the import fails with a clear
error and the caller skips this sensor (repo convention: skip, not fail).
"""

from __future__ import annotations

from pathlib import Path

from core.sensors.base import Sensor


class YaraSensor(Sensor):
    name = "yara"

    def ingest(self, source, rules) -> list[dict]:
        from adapters import yara_scan

        source = Path(source)
        rules = Path(rules)
        if not source.exists():
            raise FileNotFoundError(f"scan target not found: {source}")
        if not rules.exists():
            raise FileNotFoundError(f"YARA rules not found: {rules}")
        return yara_scan.load_records(source, rules)
