"""The CLI surface: every entry point starts, and the offline ones actually work.

Coverage said this out loud: `engine/run_*.py` sat at 0%. The project's first principle is that the
tools are usable from the terminal without any AI or GUI, and not one of those entry points was
exercised — an import error or a broken argparse would have shipped and only been found by hand.

Two levels here. `--help` on **every** entry point discovered by globbing (so a new CLI is covered
the day it is written, with no list to keep in sync) catches import errors, syntax errors and
argparse mistakes for the price of a subprocess. Then the entry points that need no external binary
and no evidence file are run for real, end to end.

    uv run python tests/test_cli_smoke.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests._helpers import subprocess_env  # noqa: E402


def _run(args: list[str], env_extra: dict | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a module entry point the way a user would, from the engine's directory."""
    return subprocess.run([sys.executable, "-m", *args], cwd=ROOT,
                          env=subprocess_env(ROOT, env_extra),
                          capture_output=True, text=True, timeout=timeout)


def _entry_points() -> list[str]:
    return sorted(p.stem for p in (ROOT / "engine").glob("run_*.py"))


def test_every_cli_has_a_working_help() -> None:
    """Discovered by glob on purpose: a CLI added tomorrow is covered without editing this test."""
    entries = _entry_points()
    assert len(entries) >= 10, f"suspiciously few entry points discovered: {entries}"
    broken = []
    for name in entries:
        p = _run([f"engine.{name}", "--help"], timeout=90)
        if p.returncode != 0 or "usage" not in (p.stdout + p.stderr).lower():
            broken.append(f"{name}: rc={p.returncode} {(p.stderr or p.stdout)[:160]}")
    assert not broken, "entry points that do not start:\n  " + "\n  ".join(broken)


def test_decode_cli_decodes() -> None:
    """A pure-stdlib CLI: no excuse for it not to be exercised for real.

    The payload is a realistic one (an encoded PowerShell command line): short strings decode into
    plausible garbage under several encoders at once, and the detector ranks by confidence — so a
    test on a two-word input would be pinning the ranking, not the decoding."""
    p = _run(["engine.run_decode", "--json", "cG93ZXJzaGVsbCAtZW5jIEpBQnc9"])
    assert p.returncode == 0, p.stderr[:300]
    hits = json.loads(p.stdout)
    b64 = next((h for h in hits if h["encoder"] == "base64"), None)
    assert b64 and b64["decoded"].startswith("powershell -enc"), hits


def test_case_cli_lifecycle() -> None:
    """create -> note -> show -> list -> rm, over a scratch case root: no binaries, no evidence.

    This is the CLI half of case persistence; the store itself is covered by test_case_store."""
    with tempfile.TemporaryDirectory(prefix="eh-cli-cases-") as tmp:
        env = {"EVENTHOUND_CASES_DIR": tmp}

        p = _run(["engine.run_case", "new", "cli-smoke", "--title", "CLI smoke"], env)
        assert p.returncode == 0 and "cli-smoke" in p.stdout, (p.stdout, p.stderr)

        p = _run(["engine.run_case", "note", "cli-smoke", "checked, nothing found"], env)
        assert p.returncode == 0, p.stderr[:300]

        p = _run(["engine.run_case", "show", "cli-smoke"], env)
        assert "CLI smoke" in p.stdout and "checked, nothing found" in p.stdout, p.stdout

        p = _run(["engine.run_case", "list"], env)
        assert "cli-smoke" in p.stdout, p.stdout

        # a bad id must fail cleanly, not traceback (§8: ids are untrusted input)
        p = _run(["engine.run_case", "show", "../escape"], env)
        assert p.returncode == 2 and "invalid case id" in p.stderr, (p.returncode, p.stderr[:200])
        assert "Traceback" not in p.stderr, p.stderr[:300]

        p = _run(["engine.run_case", "rm", "cli-smoke", "--yes"], env)
        assert p.returncode == 0, p.stderr[:300]
        p = _run(["engine.run_case", "list"], env)
        assert "cli-smoke" not in p.stdout, p.stdout


def test_bundle_round_trip_through_the_cli() -> None:
    """run_export --from-json -> run_report --from-bundle, the documented way to reopen a case
    without the evidence. Offline: it starts from an analysis JSON, so no tool has to run."""
    from analytics import runner  # noqa: E402  (after sys.path insertion above)

    records = [
        {"@timestamp": "2026-07-16T06:28:59Z", "event.source": "log:a.log",
         "event.category": "web", "event.action": "http-request", "source.ip": "203.0.113.5"},
        {"@timestamp": "2026-07-16T06:29:10Z", "event.source": "evtx",
         "event.category": "authentication", "event.action": "logon", "event.code": 4624,
         "host.name": "DC-01", "source.ip": "203.0.113.5", "attack.techniques": ["T1021.002"]},
    ]
    with tempfile.TemporaryDirectory(prefix="eh-cli-bundle-") as tmp:
        analysis_json = Path(tmp) / "analysis.json"
        analysis_json.write_text(json.dumps(runner.analyze(records), default=str), encoding="utf-8")

        bundle = Path(tmp) / "case.json"
        p = _run(["engine.run_export", "--from-json", str(analysis_json), "--out", str(bundle)])
        assert p.returncode == 0, (p.stdout, p.stderr)
        assert json.loads(bundle.read_text())["bundle_version"] == 1

        out_md = Path(tmp) / "case.md"
        p = _run(["engine.run_report", "--from-bundle", str(bundle),
                  "--format", "markdown", "--out", str(out_md)])
        assert p.returncode == 0, (p.stdout, p.stderr)
        text = out_md.read_text(encoding="utf-8")
        assert "203.0.113.5" in text and "T1021.002" in text, text[:400]


def test_eval_cli_runs_the_corpus() -> None:
    """The corpus runner is itself an entry point: if it stops exiting non-zero on failure, the
    gate would go green on a broken correlation engine."""
    p = _run(["engine.run_eval"])
    assert p.returncode == 0, (p.stdout[-800:], p.stderr[-400:])
    assert "0 failed" in p.stdout, p.stdout[-400:]


def test_bench_cli_profiles_the_pipeline() -> None:
    """The performance profile runs offline on synthetic data, so there is no reason for it to be
    an unexecuted entry point — the thing it measures would then be unmeasured and untested.

    Asserts the shape, never a duration: a timing threshold here would encode the speed of whichever
    machine wrote it (the figures live in docs/analysis/performance.md, with their hardware)."""
    p = _run(["engine.run_bench", "--analytics", "--quick", "--json"], timeout=180)
    assert p.returncode == 0, (p.stdout[-400:], p.stderr[-400:])
    out = json.loads(p.stdout)
    assert out["analytics"] and out["machine"]["cpu_count"], out.keys()
    run = out["analytics"][0]
    stages = {s["stage"] for s in run["stages"]}
    # The load stage and at least one recipe and one correlation must have been timed: a profile
    # that silently stopped measuring part of the pipeline would still print a table.
    assert "store.from_records" in stages, stages
    assert any(s.startswith("recipe.") for s in stages), stages
    assert any(s.startswith("correlate.") for s in stages), stages
    assert run["n"] == 1000 and run["total_seconds"] > 0 and run["peak_rss_mb"] > 0, run


def test_combined_clis_take_every_source() -> None:
    """The three CLIs that CORRELATE must accept every source `build_records` does.

    They used to take four of eleven, which made the command line the surface where correlation was
    impossible: an analyst with a THOR report and a registry export could get two separate readings
    and never one analysis. The check is two DIFFERENT source types in one invocation, because that
    — not the flag existing — is what proves the records met each other in one store.

    The demo scenario supplies real artifacts (`demo/scenario.py`), so nothing here needs an
    external binary: a `.reg` export and a THOR report are both pure text.
    """
    sys.path.insert(0, str(ROOT))
    from demo import scenario

    with tempfile.TemporaryDirectory(prefix="cli-sources-") as td:
        plan = scenario.generate(Path(td) / "src")["build_records"]
        reg = plan["registry"][0]
        thor = plan["thor"][0]["report"]
        okta = plan["okta"][0]
        out = Path(td) / "analysis.json"

        p = _run(["engine.run_analytics", "--registry", reg, "--thor", thor, "--okta", okta,
                  "--json", str(out)], timeout=180)
        assert p.returncode == 0, (p.returncode, p.stdout[-500:], p.stderr[-500:])
        result = json.loads(out.read_text(encoding="utf-8"))
        families = set((result.get("summary") or {}).get("by_source") or {})
        assert {"registry", "thor", "okta"} <= families, families

        # run_report and run_export must accept the same surface; rendering one is enough to prove
        # the flags reach build_records rather than merely being declared.
        rep = Path(td) / "report.html"
        p = _run(["engine.run_report", "--thor", thor, "--okta", okta,
                  "--out", str(rep), "--format", "html"], timeout=180)
        assert p.returncode == 0, (p.returncode, p.stdout[-500:], p.stderr[-500:])
        assert rep.exists() and rep.stat().st_size > 0

        bundle = Path(td) / "bundle.json"
        p = _run(["engine.run_export", "--registry", reg, "--okta", okta, "--out", str(bundle)],
                 timeout=180)
        assert p.returncode == 0, (p.returncode, p.stdout[-500:], p.stderr[-500:])
        assert bundle.exists() and json.loads(bundle.read_text(encoding="utf-8"))

    # syslog was supported by the adapter and missing from the CLI's choices, so an appliance
    # auth.log could not be read by the command that exists to read logs.
    p = _run(["engine.run_logs", "--help"], timeout=60)
    assert "syslog" in p.stdout + p.stderr, "run_logs still refuses --fmt syslog"


def test_json_flag_is_boolean_or_has_json_out_alias() -> None:
    """Pins the --json contract split: nine CLIs used to take --json as a PATH to write while
    two others (run_bench/run_decode) used --json as a boolean "print to stdout" flag — same name,
    two contracts, and a value-less `--json` on the first group used to be an argparse error.
    --json-out is now the canonical path flag; --json survives everywhere it took a path only as a
    deprecated alias (same dest), and stays exactly boolean on the two it always was.

    Source-level AST check rather than a live subprocess per entry point: none of these CLIs expose
    their argparse parser separately from main(), so there is no parser object to introspect
    without invoking --help on all of them and diffing text — more brittle than reading the
    `add_argument("--json"/"--json-out", ...)` call itself. `ast.walk` over `Call` nodes (not a
    text grep) so a reformatted call — multi-line, reordered kwargs — still matches."""
    import ast

    boolean_json_files = {"run_bench.py", "run_decode.py"}

    for path in sorted((ROOT / "engine").glob("run_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        json_calls = []  # [(flag, {kwarg: literal value})] for every add_argument("--json"/"--json-out", ...)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_argument" and node.args):
                continue
            first = node.args[0]
            if not (isinstance(first, ast.Constant) and first.value in ("--json", "--json-out")):
                continue
            kwargs = {kw.arg: kw.value.value for kw in node.keywords
                     if kw.arg and isinstance(kw.value, ast.Constant)}
            json_calls.append((first.value, kwargs))

        if not json_calls:
            continue  # entry point takes no --json at all (e.g. run_evtx, run_pcap, run_report)

        if path.name in boolean_json_files:
            assert [f for f, _ in json_calls] == ["--json"], (path.name, json_calls)
            assert json_calls[0][1].get("action") == "store_true", \
                f"{path.name}: --json must stay a boolean flag, got {json_calls}"
        else:
            flags = {f for f, _ in json_calls}
            assert "--json-out" in flags, f"{path.name}: missing canonical --json-out, has {json_calls}"
            for flag, kwargs in json_calls:
                assert kwargs.get("action") != "store_true", \
                    f"{path.name}: {flag} takes a PATH, must not be action=store_true ({json_calls})"


def run() -> int:
    test_every_cli_has_a_working_help()
    test_json_flag_is_boolean_or_has_json_out_alias()
    test_combined_clis_take_every_source()
    test_bench_cli_profiles_the_pipeline()
    test_decode_cli_decodes()
    test_case_cli_lifecycle()
    test_bundle_round_trip_through_the_cli()
    test_eval_cli_runs_the_corpus()
    print(f"PASS  cli smoke: {len(_entry_points())} entry points start; every source reaches the "
          f"three combined CLIs; decode, case, bundle round-trip and corpus run end to end")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
