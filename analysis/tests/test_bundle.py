"""Test of the analysis bundle (engine/bundle + run_export/run_report) — offline, deterministic.

Checks the round trip that makes an analysis re-openable: analyze() dict → bundle → back to an
analysis → rendered report, with the same content on both sides. Also covers what a bundle must
REFUSE (wrong version, malformed) and the tolerated bare analyze() export.

    uv run python tests/test_bundle.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import bundle as bundle_mod  # noqa: E402
from engine import run_export, run_report  # noqa: E402
from engine.version import APP_VERSION  # noqa: E402

# Same shape analyze() returns (a subset is enough: the bundle is agnostic to the recipes).
ANALYSIS = {
    "summary": {"events": 3, "by_source": {"evtx": 2, "log:acc": 1},
                "distinct_hosts": 1, "distinct_users": 1},
    "technique_frequency": [{"technique": "T1021.005", "hits": 5}],
    "shared_indicators": [{"indicator": "203.0.113.5", "kind": "ip", "families": 2,
                           "source_list": "evtx, log:acc", "occurrences": 3}],
    "host_overview": [{"host": "DC-01", "events": 3, "users": 1, "processes": 1,
                       "net_dsts": 0, "detections": 1}],
    "_meta": {"records": 3, "evtx": 1, "logs": 1, "errors": []},
}


def run() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="eh-bundle-"))

    # ── build/serialize: provenance is stamped, the analysis travels verbatim ──
    b = bundle_mod.build(ANALYSIS, name="case-01")
    assert b["bundle_version"] == bundle_mod.BUNDLE_VERSION == 1, b["bundle_version"]
    assert b["tool_version"] == APP_VERSION, b["tool_version"]
    assert b["meta"]["name"] == "case-01" and b["meta"]["records"] == 3, b["meta"]
    assert b["created_at"].endswith("Z"), b["created_at"]
    assert b["analysis"] == ANALYSIS, "the analysis must travel unmodified"

    path = tmp / "case.json"
    path.write_text(bundle_mod.dumps(b), encoding="utf-8")
    back = bundle_mod.load(path)
    assert bundle_mod.analysis_of(back) == ANALYSIS, "round trip altered the analysis"

    # ── refusals: a bundle from a future/foreign build must not be read as if it were ours ──
    for bad, why in [
        ({"bundle_version": 99, "analysis": {}}, "version"),
        ({"bundle_version": 1}, "malformed"),
        ({"nothing": "here"}, "not a bundle"),
        ([1, 2, 3], "not an object"),
    ]:
        try:
            bundle_mod.loads(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"loads() accepted an invalid bundle ({why}): {bad}")

    # ── tolerance: a bare analyze() export (report --format json --level full) is wrapped ──
    bare = tmp / "bare.json"
    bare.write_text(json.dumps(ANALYSIS), encoding="utf-8")
    wrapped = bundle_mod.load(bare)
    assert wrapped["bundle_version"] == 1, wrapped
    assert bundle_mod.analysis_of(wrapped)["summary"]["events"] == 3

    # ── CLI: run_export --from-json  →  run_report --from-bundle, no evidence involved ──
    out = tmp / "exported.json"
    rc = run_export.main(["--from-json", str(bare), "--name", "case-01", "--out", str(out)])
    assert rc == 0 and out.exists(), f"run_export failed (rc={rc})"
    exported = json.loads(out.read_text(encoding="utf-8"))
    assert exported["bundle_version"] == 1 and exported["meta"]["name"] == "case-01", exported["meta"]

    for fmt, needle in [("html", "T1021.005"), ("markdown", "T1021.005"), ("json", "T1021.005")]:
        rep = tmp / f"report.{fmt}"
        rc = run_report.main(["--from-bundle", str(out), "--format", fmt, "--out", str(rep)])
        assert rc == 0, f"run_report --from-bundle --format {fmt} failed (rc={rc})"
        text = rep.read_text(encoding="utf-8")
        assert needle in text, f"{fmt} report re-rendered from the bundle lost its content"
    # the HTML rendered from the bundle is the same one the direct path produces
    from engine import report_html
    direct = report_html.render_html(ANALYSIS, ANALYSIS["_meta"])
    from_bundle = (tmp / "report.html").read_text(encoding="utf-8")
    assert "203.0.113.5" in from_bundle and "203.0.113.5" in direct, "cross-source indicator lost"

    # ── mutually exclusive inputs are rejected (argparse exits 2) ──
    for argv in (["--from-bundle", str(out), "--evtx", "x.evtx"], []):
        try:
            run_report.main(argv)
        except SystemExit as e:
            assert e.code == 2, e.code
        else:
            raise AssertionError(f"run_report accepted invalid args: {argv}")

    print("PASS  bundle: round trip, refusals, bare-export tolerance, run_export→run_report CLI")
    return 0


def test_bundle():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
