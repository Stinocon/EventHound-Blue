"""Registry sensor — .reg export (pure Python) or RECmd CSV.

Primary road is ``adapters.registry_regfile`` (a native ``.reg`` parser, no
external binary). When the artifact is a RECmd CSV directory instead, the
sensor delegates to ``adapters.registry_recmd``.
"""

from __future__ import annotations

from pathlib import Path

from core.sensors.base import Sensor


class RegistrySensor(Sensor):
    name = "registry"

    def ingest(self, source) -> list[dict]:
        from adapters import registry_recmd, registry_regfile

        source = Path(source)
        if not source.exists():
            raise FileNotFoundError(f"artifact not found: {source}")

        if source.is_file() and source.suffix.lower() == ".reg":
            return registry_regfile.load_records(source)

        if source.is_dir():
            return registry_recmd.load_records(source)

        raise ValueError(
            "expected a .reg file or a RECmd CSV directory, got: " f"{source}"
        )
