"""Engine path bootstrap — make the v1 engine importable from the v2 packages.

The v1 engine lives in ``analysis/``; the GUI and the MCP server import it by
inserting that directory on ``sys.path`` (see ``analysis/analysis_mcp_server.py``,
``analysis/gui/app.py``). The v2 packages do the same through this single
function, so no module needs import-time side effects.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ENGINE_DIR = Path(__file__).resolve().parent.parent / "analysis"


def ensure_engine_path() -> Path:
    """Insert analysis/ on sys.path (idempotent) and return it."""
    if str(_ENGINE_DIR) not in sys.path:
        sys.path.insert(0, str(_ENGINE_DIR))
    return _ENGINE_DIR
