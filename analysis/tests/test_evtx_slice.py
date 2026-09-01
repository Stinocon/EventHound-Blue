"""Test of EVTX → ATT&CK slice validation (mirror of RAG golden queries).

Declares, for a known EVTX dataset, the expected outcome and verifies the engine produces it.
Here: the mimikatz sample from EVTX-ATTACK-SAMPLES must surface
`T1003.001` (OS Credential Dumping: LSASS Memory).

The dataset lives in analysis/.tools/ (gitignored): if absent, the test is skipped
(not a failure) — see README to obtain it.

Runnable with either pytest or directly:
    uv run python tests/test_evtx_slice.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# (sub-path of sample in .tools/EVTX-ATTACK-SAMPLES, expected technique)
CASES = [
    ("Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx", "T1003.001"),
]


def _sample_path(rel: str) -> Path | None:
    p = ROOT / ".tools" / "EVTX-ATTACK-SAMPLES" / rel
    return p if p.exists() else None


def run_synthetic() -> None:
    """Always validates EVTX→schema mapping on a synthetic Hayabusa record, without depending on
    gitignored datasets (which often are missing and would skip every field-mapping verification).
    Covers: EID→category/action, process/parent/user/host, ATT&CK techniques with non-string tag
    tolerated (#25), and robustness of load_records on BOM (#35) + malformed JSON line."""
    import json
    from adapters import evtx_hayabusa

    det = {
        "Timestamp": "2024-01-01T00:00:00.000000Z",
        "EventID": 1,                       # Sysmon ProcessCreate
        "Computer": "HOST-01",
        "RuleTitle": "Synthetic ProcessCreate",
        "MitreTags": ["T1059.001", 123, None],   # 123/None non-string: must not crash
        "Details": {
            "Image": "C:/Windows/System32/cmd.exe",
            "CmdLine": "cmd.exe /c whoami",
            "ParentImage": "C:/Windows/explorer.exe",
            "ParentCmdLine": "explorer.exe /factory",
            "User": "USER-01",
        },
    }
    rec = evtx_hayabusa._record_from_hayabusa(det)
    assert rec["event.category"] == "process", rec
    assert rec["event.action"] == "process-create", rec
    assert rec["host.name"] == "HOST-01"
    assert rec["user.name"] == "USER-01"
    assert rec["process.command_line"] == "cmd.exe /c whoami"
    assert rec["process.parent.name"].endswith("explorer.exe"), rec
    # ParentCmdLine must end up in parent's command_line field, not in process.parent.name (#27)
    assert rec["process.parent.command_line"] == "explorer.exe /factory", rec
    assert "T1059.001" in (rec.get("attack.techniques") or []), rec

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        p = Path(tmp.name)
    # BOM on first line + broken JSON line + valid JSON lines but non-object (array/null):
    # only first is read, others skipped without aborting load (#non-dict).
    p.write_bytes(
        b"\xef\xbb\xbf" + (json.dumps(det) + "\n").encode("utf-8")
        + b"{ broken json\n" + b"[1,2,3]\n" + b"null\n"
    )
    recs = evtx_hayabusa.load_records(p)
    p.unlink(missing_ok=True)
    assert len(recs) == 1, f"BOM/malformed line/non-object JSON not handled: {len(recs)} records"
    print("PASS  evtx field-mapping (synthetic, always run)")


def run_tactics() -> None:
    """Hayabusa's abbreviated tactic vocabulary is normalized to full ATT&CK names.

    `DefImpair`/`CredAccess` used to reach the reports verbatim — strings that are NOT ATT&CK
    tactic names, and that `attack.phase_of_tactic` could not resolve, so a tactic-only rule (a
    tactic, no technique ID) lost its kill-chain phase. The mapping is grounded in Hayabusa's own
    config/mitre_tactics.txt."""
    from adapters import evtx_hayabusa as h
    from analytics import attack
    assert h._norm_tactics(["DefImpair", "CredAccess", "LatMov", "C2"]) == [
        "defense-impairment", "credential-access", "lateral-movement", "command-and-control"
    ]
    # Already-full names pass through lower-cased; the demo generates them that way.
    assert h._norm_tactics(["persistence", "defense-evasion"]) == ["persistence", "defense-evasion"]
    # Unrecognised / non-string degrade, never crash the record.
    assert h._norm_tactics(["Recon", 123, None, ""]) == ["reconnaissance"]
    # A tactic-only detection now resolves its phase instead of disappearing.
    det = {"Timestamp": "2024-01-01T00:00:00.000000Z", "EventID": 1, "Channel": "Sysmon",
           "MitreTags": [], "MitreTactics": ["DefImpair"], "Details": {}}
    rec = h._record_from_hayabusa(det)
    assert rec["attack.tactics"] == ["defense-impairment"], rec
    assert attack.phase_of_tactic(rec["attack.tactics"][0]) == "Installation"
    print("PASS  evtx Hayabusa tactics: abbreviated vocabulary normalized to ATT&CK names")


def run() -> int:
    from adapters import evtx_hayabusa
    from engine import hayabusa_runner

    run_synthetic()
    run_tactics()

    ran = 0
    for rel, expected in CASES:
        sample = _sample_path(rel)
        if sample is None:
            # Not skip_test(): this guards only one entry of CASES, not the whole test — a
            # pytest.skip here would abort the loop and the ran==0 note below. Left as a plain
            # print; run_synthetic() above already covers field-mapping under pytest.
            print(f"SKIP  {rel} (dataset missing in .tools/)")
            continue
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            jsonl = Path(tmp.name)
        hayabusa_runner.run(sample, jsonl)
        records = evtx_hayabusa.load_records(jsonl)
        jsonl.unlink(missing_ok=True)
        techs = {t for r in records for t in (r.get("attack.techniques") or [])}
        assert expected in techs, (
            f"FAIL  {rel}: expected {expected}, found {sorted(techs) or 'none'}"
        )
        print(f"PASS  {rel}: {expected} detected ({len(records)} detections)")
        ran += 1

    if ran == 0:
        print("Note: gitignored EVTX datasets absent — end-to-end slice skipped "
              "(field-mapping is still validated by run_synthetic).")
    return 0


# Entry point pytest
def test_evtx_slice():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
