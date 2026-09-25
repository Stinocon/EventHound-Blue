"""Test of the logon 4624/4625 view (engine/run_logons).

Two levels, like test_evtx_slice:
- `run_synthetic()`: ALWAYS run. Validates the parsing of the logon-summary CSVs and the render of
  the report on synthetic data, without depending on the Hayabusa binary or the gitignored datasets.
- `run()`: end-to-end on an EVTX-ATTACK-SAMPLES sample (LM_WMI, Type 3 logon from 10.0.2.17);
  skipped if the dataset or the Hayabusa binary are missing.

Runnable with pytest or directly:
    uv run python tests/test_logons.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests._helpers import skip_test  # noqa: E402

SAMPLE_REL = "Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx"

# Synthetic CSV in the exact format of `hayabusa logon-summary` (header + example rows):
# one rare remote logon (Type 10 RDP, count 1), one frequent network one (Type 3, count 5),
# one local one (Type 2, count 3) that must NOT end up among the remote ones.
_SYNTH_SUCCESS = (
    "Successful,Event,Target Account,Target Domain,Target Computer,Logon Type,"
    "Source Account,Source Domain,Source Computer,Source IP Address\n"
    "1,Sec 4624,Administrator,CORP,SRV-01,10 - RemoteInteractive,-,-,WKS-09,10.0.0.9\n"
    "5,Sec 4624,svc_backup,CORP,SRV-01,3 - Network,-,-,,10.0.0.20\n"
    "3,Sec 4624,alice,CORP,WKS-09,2 - Interactive,-,-,,-\n"
)
_SYNTH_FAILED = (
    "Failed,Event,Target Account,Target Domain,Target Computer,Logon Type,"
    "Source Account,Source Domain,Source Computer,Source IP Address\n"
    "40,Sec 4625,Administrator,CORP,SRV-01,3 - Network,-,-,,45.83.12.7\n"
)


def _sample_path() -> Path | None:
    p = ROOT / ".tools" / "EVTX-ATTACK-SAMPLES" / SAMPLE_REL
    return p if p.exists() else None


def run_synthetic() -> None:
    from engine import run_logons

    assert run_logons._parse_type("10 - RemoteInteractive") == (10, "10 - RemoteInteractive")
    assert run_logons._parse_type("n/d") == (None, "n/d")

    with tempfile.TemporaryDirectory() as td:
        succ = Path(td) / "s-successful.csv"
        fail = Path(td) / "s-failed.csv"
        succ.write_text(_SYNTH_SUCCESS, encoding="utf-8")
        fail.write_text(_SYNTH_FAILED, encoding="utf-8")
        srows = run_logons._read_csv(succ)
        frows = run_logons._read_csv(fail)

    assert len(srows) == 3, srows
    remote = [r for r in srows if r["type_num"] in run_logons.REMOTE_LOGON_TYPES]
    # Type 3 and 10 are remote; Type 2 (Interactive) stays out.
    assert {r["type_num"] for r in remote} == {3, 10}, remote
    assert not any(r["type_num"] == 2 for r in remote)

    md = run_logons.render(srows, frows, ["synthetic.evtx"], "2026-07-20 00:00:00Z")
    assert "Remote logons" in md
    # the rare RDP logon (count 1) must appear before the frequent network one (count 5):
    # ascending rarity ordering.
    assert md.index("10 - RemoteInteractive") < md.index("3 - Network"), md
    assert "Failed logons (4625)" in md and "45.83.12.7" in md
    # the local logon (Type 2) must NOT end up in the remote section
    assert "2 - Interactive" not in md.split("## Failed logons")[0].split("## Remote logons")[1]
    print("PASS  logon parsing + render (synthetic, always run)")


def run() -> int:
    from engine import hayabusa_runner, run_logons

    run_synthetic()

    sample = _sample_path()
    if sample is None:
        print("Note: end-to-end skipped — parsing/render is still validated by run_synthetic().")
        return skip_test(f"{SAMPLE_REL} (dataset absent in .tools/)")
    try:
        hayabusa_runner.find_binary()
    except FileNotFoundError:
        return skip_test("end-to-end (Hayabusa binary absent in .tools/)")

    with tempfile.TemporaryDirectory() as td:
        succ_csv, fail_csv = hayabusa_runner.run_logon_summary(sample, Path(td) / "logon")
        srows = run_logons._read_csv(succ_csv)
        frows = run_logons._read_csv(fail_csv)

    # The failure CSV parses too (usually empty for this sample): the summary's two halves are
    # both readable, so a logon view that silently lost the failures would show up here.
    assert isinstance(frows, list), frows
    remote = [r for r in srows if r["type_num"] in run_logons.REMOTE_LOGON_TYPES]
    assert remote, f"FAIL  {SAMPLE_REL}: no remote logon detected"
    # the WMI sample shows network logons (Type 3) from source 10.0.2.17
    assert any(r["type_num"] == 3 for r in remote), remote
    assert any(r["source_ip"] == "10.0.2.17" for r in srows), srows
    print(f"PASS  {SAMPLE_REL}: {len(remote)} remote logons (Type 3 from 10.0.2.17)")
    return 0


# pytest entry point
def test_logons():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
