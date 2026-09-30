"""MFT sensor — MFTECmd CSV/JSON output directory.

``adapters.mft_mftecmd.load_records`` takes the directory MFTECmd wrote its
``*.json`` output to (one JSON per MFT), not the raw ``$MFT``: the runner
that drives the binary is ``engine.mftcmd_runner``.
"""

from __future__ import annotations

from pathlib import Path

from core.sensors.base import Sensor


class MftSensor(Sensor):
    name = "mft"

    def ingest(self, source) -> list[dict]:
        from adapters import mft_mftecmd

        source = Path(source)
        if not source.is_dir():
            raise NotADirectoryError(
                f"expected an MFTECmd JSON output directory, got: {source}"
            )
        return mft_mftecmd.load_records(source)
