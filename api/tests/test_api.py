"""Test of the unified v2 API (FastAPI TestClient), repo convention: plain script.

- /health answers ok and lists the sensor registry.
- /analyze routes two artifacts to two sensors in one request, returns
  common-schema records with verified counts (3 THOR + 1 registry, 6 log lines).
- Input validation: unknown extension -> 422, path-traversal filename -> 400.

Run: cd analysis/gui && uv run python ../../api/tests/test_api.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.server import app  # noqa: E402

SAMPLES = _ROOT / "samples"


def _require_samples():
    if not SAMPLES.is_dir():
        print("  SKIP — gitignored sample set not present (§9)")
        sys.exit(0)

client = TestClient(app)

_FAILED = []


def _check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"  {status} — {name}" + (f" ({detail})" if detail and not condition else ""))
    if not condition:
        _FAILED.append(name)


def test_health():
    response = client.get("/health")
    body = response.json()
    _check("health 200", response.status_code == 200)
    _check("health ok", body.get("status") == "ok")
    _check("health lists sensors", "evtx" in body.get("sensors", []))


def test_analyze_thor_and_registry():
    thor = (SAMPLES / "ws-01_thor_2026-03-12_0840.txt")
    reg = (SAMPLES / "ws-01_run-key.reg")
    response = client.post(
        "/analyze",
        files=[
            ("artifact", (thor.name, thor.read_bytes())),
            ("artifact", (reg.name, reg.read_bytes())),
        ],
    )
    body = response.json()
    _check("analyze 200", response.status_code == 200, response.text)
    _check("record count 3+1", body.get("count") == 4, str(body.get("count")))
    _check(
        "per-artifact counts",
        body.get("per_artifact") == {thor.name: 3, reg.name: 1},
    )
    families = sorted(
        {r["event.source"].split(":")[0] for r in body.get("records", [])}
    )
    _check("two sensor families", families == ["registry", "thor"])
    # every record carries the schema contract keys
    _check(
        "records carry @timestamp",
        all("@timestamp" in r for r in body.get("records", [])),
    )


def test_analyze_logs():
    log = (SAMPLES / "sma-01_auth.log")
    response = client.post(
        "/analyze", files=[("artifact", (log.name, log.read_bytes()))]
    )
    body = response.json()
    _check("logs 200", response.status_code == 200, response.text)
    _check("6 log records", body.get("count") == 6, str(body.get("count")))


def test_analyze_unsupported_extension():
    response = client.post(
        "/analyze",
        files=[("artifact", ("data.xyz", b"not an artifact"))],
    )
    _check("unknown extension 422", response.status_code == 422)
    _check(
        "error names the problem",
        "no sensor" in response.json().get("detail", ""),
    )


def test_analyze_rejects_unsafe_filename():
    response = client.post(
        "/analyze",
        files=[("artifact", ("../evil.sh", b"# boom"))],
    )
    _check("traversal filename 400", response.status_code == 400)
    _check(
        "error says unsafe filename",
        "unsafe filename" in response.json().get("detail", ""),
    )


_require_samples()

if __name__ == "__main__":
    print("api/tests/test_api.py")
    for fn in [
        test_health,
        test_analyze_thor_and_registry,
        test_analyze_logs,
        test_analyze_unsupported_extension,
        test_analyze_rejects_unsafe_filename,
    ]:
        print(f" {fn.__name__}:")
        fn()
    if _FAILED:
        print(f"FAILED: {len(_FAILED)} check(s): {_FAILED}")
        sys.exit(1)
    print("all checks passed")
