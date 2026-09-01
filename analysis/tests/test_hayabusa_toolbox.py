"""Test of the Hayabusa toolbox wrappers (engine/hayabusa_runner: eid/log/computer metrics,
search, pivot-keywords, extract-base64).

Two levels, like test_logons:
- `run_synthetic()`: ALWAYS run. Validates the output parsers (_read_csv, _read_jsonl, _parse_pivot)
  on synthetic fixtures, without the Hayabusa binary or gitignored datasets.
- `run()`: end-to-end on an EVTX-ATTACK-SAMPLES sample (LM_WMI); skipped if the dataset or the
  Hayabusa binary are missing.

Run: uv run python tests/test_hayabusa_toolbox.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests._helpers import skip_test  # noqa: E402

SAMPLE_REL = "Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx"


def _sample_path() -> Path | None:
    p = ROOT / ".tools" / "EVTX-ATTACK-SAMPLES" / SAMPLE_REL
    return p if p.exists() else None


def run_synthetic() -> None:
    from engine import hayabusa_runner as hr

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # _read_csv: header + rows, empty file → []
        csv_p = tmp / "eid.csv"
        csv_p.write_text("Total,%,Channel,ID,Event\n6,75.0%,Sec,4624,Logon success\n", encoding="utf-8")
        rows = hr._read_csv(csv_p)
        assert rows and rows[0]["ID"] == "4624" and rows[0]["Event"] == "Logon success", rows
        empty = tmp / "empty.csv"
        empty.write_text("", encoding="utf-8")
        assert hr._read_csv(empty) == []
        assert hr._read_csv(tmp / "nope.csv") == []

        # _read_json_stream: concatenated JSON objects (multi-line, like Hayabusa's -J), noise skipped
        jl = tmp / "search.json"
        jl.write_text('{\n"Event ID": 4624, "Channel": "Sec"}\nnot-json\n{"Event ID": 4688}\n',
                      encoding="utf-8")
        recs = hr._read_json_stream(jl)
        assert [r["Event ID"] for r in recs] == [4624, 4688], recs

        # _parse_pivot: one file per category, header line + values
        (tmp / "pv-IP Addresses.txt").write_text("IP Addresses: ( %IpAddress% ):\n10.0.2.17\n",
                                                  encoding="utf-8")
        (tmp / "pv-Processes.txt").write_text("Processes: ( %Image% ):\ncmd.exe\npowershell.exe\n",
                                              encoding="utf-8")
        pv = hr._parse_pivot(tmp / "pv")
        assert pv["IP Addresses"] == ["10.0.2.17"], pv
        assert pv["Processes"] == ["cmd.exe", "powershell.exe"], pv

        # Batch staging: same basename from three hosts must survive as three files. The real
        # function is called, not a copy of it — a test that re-implements the rule stays green
        # while the code it claims to cover changes underneath.
        from analytics.runner import stage_batch_dir
        srcs = []
        for i in range(3):
            d = tmp / f"host{i}"
            d.mkdir()
            (d / "Security.evtx").write_bytes(b"fake")
            srcs.append(str(d / "Security.evtx"))
        batch_dir = tmp / "batch"
        batch_dir.mkdir()
        staged = stage_batch_dir(srcs, batch_dir)
        assert staged == ["Security.evtx", "001_Security.evtx", "002_Security.evtx"], staged
        resolved = {p.resolve() for p in batch_dir.iterdir()}
        assert len(resolved) == 3, resolved
        assert resolved == {Path(s).resolve() for s in srcs}, resolved

        # failed_files: Hayabusa exits 0 on a file it cannot read and only says so in a per-run
        # error log. Driven from a fabricated stdout + log, so it runs without the binary.
        logs = tmp / "logs"
        logs.mkdir()
        (logs / "errorlog-20260724_120000.log").write_text(
            "user input: hayabusa json-timeline -d /some/dir\n"
            "Failed to open evtx file: /some/dir/001_Security.evtx\n"
            "Failed to open evtx file: /some/dir/Application.evtx\n",
            encoding="utf-8")
        stdout = ("Scanning in progress. Please wait.\n"
                  f"Errors were generated. Please check {logs / 'errorlog-20260724_120000.log'}"
                  " for details.\n")
        assert hr.failed_files(stdout) == ["001_Security.evtx", "Application.evtx"]
        # A clean run says nothing about an error log, and a dangling reference is not fatal:
        # losing the ingest over its own error reporting would be worse than the silence.
        assert hr.failed_files("Scanning in progress. Please wait.\n") == []
        assert hr.failed_files("Please check /nonexistent/errorlog-1.log for details") == []

    print("PASS  toolbox parsers (_read_csv/_read_json_stream/_parse_pivot, always run)")


def run() -> int:
    from engine import hayabusa_runner as hr

    run_synthetic()

    sample = _sample_path()
    if sample is None:
        print("Note: end-to-end skipped — parsers validated by run_synthetic().")
        return skip_test(f"{SAMPLE_REL} (dataset absent in .tools/)")
    try:
        hr.find_binary()
    except FileNotFoundError:
        return skip_test("end-to-end (Hayabusa binary absent in .tools/)")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        eid = hr.eid_metrics(sample, tmp / "eid.csv")
        assert any(r.get("ID") == "4624" for r in eid), eid
        print(f"PASS  eid-metrics: {len(eid)} event-id rows (4624 present)")

        logm = hr.log_metrics(sample, tmp / "log.csv")
        assert logm and logm[0].get("Filename", "").endswith(".evtx") and int(logm[0]["Events"]) > 0, logm
        print(f"PASS  log-metrics: {logm[0]['Events']} events, channels={logm[0].get('Channels')}")

        comp = hr.computer_metrics(sample, tmp / "comp.csv")
        assert comp and comp[0].get("Computer") and int(comp[0]["Events"]) > 0, comp
        print(f"PASS  computer-metrics: {len(comp)} computer(s)")

        found = hr.search(sample, tmp / "search.jsonl", regex="4624")
        assert found and all("Event ID" in e for e in found), found[:1]
        assert any(e.get("Event ID") == 4624 for e in found), found[:1]
        print(f"PASS  search regex '4624': {len(found)} events")

        pv = hr.pivot_keywords(sample, tmp / "pivot")
        assert isinstance(pv, dict) and pv, list(pv)
        # the WMI sample has a source IP 10.0.2.17 → appears among the IP-address pivots
        ip_cats = [v for k, v in pv.items() if "IP" in k]
        assert any("10.0.2.17" in vals for vals in ip_cats), pv
        print(f"PASS  pivot-keywords: {len(pv)} categories (10.0.2.17 pivoted)")

        b64 = hr.extract_base64(sample, tmp / "b64.csv")
        assert isinstance(b64, list)   # this sample has no base64 → empty, must not crash
        print(f"PASS  extract-base64: {len(b64)} decoded strings")

        # An unreadable EVTX among readable ones must be REPORTED, not merely absent. Hayabusa
        # exits 0 on it, so before this was wired the file vanished from the analysis and the
        # analyst had a shorter timeline with nothing to explain it. Both ingest paths are
        # exercised: batch (2+ files) and single-file, since both were equally silent.
        from analytics import runner as _runner
        import shutil as _shutil
        good = tmp / "good.evtx"
        _shutil.copy(sample, good)
        bad = tmp / "CORRUPT.evtx"
        bad.write_bytes(b"not an evtx" * 20)

        # The comparison is against the same file ingested alone, not against a record count: this
        # sample yields no Sigma detections, which is precisely the case that makes "no records"
        # useless as a failure signal and this reporting necessary.
        clean_errs: list[str] = []
        alone = _runner.build_records(evtx=[str(good)], errors=clean_errs)
        assert not clean_errs, clean_errs

        errs: list[str] = []
        recs = _runner.build_records(evtx=[str(good), str(bad)], errors=errs)
        assert any("CORRUPT.evtx" in e and "skipped" in e for e in errs), errs
        assert len(recs) == len(alone), "the unreadable file must cost the readable one nothing"
        assert not any("good.evtx" in e for e in errs), errs

        errs_single: list[str] = []
        _runner.build_records(evtx=[str(bad)], errors=errs_single)
        assert any("CORRUPT.evtx" in e and "skipped" in e for e in errs_single), errs_single
        print("PASS  unreadable EVTX reported (batch + single), readable one still ingested")

    return 0


def test_hayabusa_toolbox():
    run()


if __name__ == "__main__":
    raise SystemExit(run())
