"""Shared test helpers. The important one is `skip_test`.

Every test here runs two ways: as a plain script (`uv run python tests/test_x.py`, which is how the
suite has always been driven and how it stays usable without a test runner) and under pytest. Those
two want opposite things from a missing dependency:

- as a script, "tshark is not installed" means print a line and exit 0 — not a failure;
- under pytest, returning 0 makes the test **pass**, which is a lie: an untested path reported as a
  tested one. That false green is the reason the suite moved to pytest at all.

`skip_test` gives each what it needs from a single call site, so the test files keep their
`run() -> int` shape and gain honest reporting for free.
"""
from __future__ import annotations

import os


def skip_test(reason: str) -> int:
    """Report a skipped test. Under pytest raises a real skip; as a script prints and returns 0."""
    print(f"SKIP  {reason}")
    if os.environ.get("PYTEST_CURRENT_TEST"):
        import pytest
        pytest.skip(reason, allow_module_level=True)
    return 0


def have(binary: str) -> bool:
    """Is an external tool on PATH? (shutil.which, named for how the tests read.)"""
    import shutil
    return shutil.which(binary) is not None


def subprocess_env(root, extra: dict | None = None) -> dict:
    """Environment for a test that launches an entry point as a real subprocess.

    Carries `COVERAGE_PROCESS_START` through, so the child is measured too: pytest-cov installs a
    .pth hook that starts coverage in any Python process when that variable is set. Without it the
    CLI entry points read as 0% covered while the smoke test is exercising them — a coverage number
    that lies about what is tested is worse than no number at all. Harmless when coverage is off.
    """
    import sys
    env = {**os.environ, "PYTHONPATH": str(root), **(extra or {})}
    if "coverage" in sys.modules:      # i.e. the parent is running under pytest --cov
        env["COVERAGE_PROCESS_START"] = str(root / "pyproject.toml")
    return env
