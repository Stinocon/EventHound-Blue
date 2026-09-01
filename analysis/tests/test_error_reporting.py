"""What an analyst is told when a source cannot be read — offline, deterministic.

The risk this file exists for is the **silent incomplete analysis**: a tool that is not installed,
reported as nothing more than an exception class name, reads exactly like a file with no findings.
`PCAP capture.pcap: FileNotFoundError` above a grid of zeros is not a message anyone can act on,
and the adapter had already written the actionable sentence that the caller was discarding.

The second half of the file pins the §9 side of keeping that sentence: these strings reach the HTML
report and the exported bundle, so an absolute path inside an exception message must collapse to
its basename — while prose that merely contains a slash must survive untouched, which is where the
first implementation of the scrub went wrong.

    uv run python tests/test_error_reporting.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from _helpers import have, skip_test  # noqa: E402
from analytics import runner  # noqa: E402


def _case(label: str, got, expected) -> None:
    assert got == expected, f"{label}: expected {expected!r}, got {got!r}"


def test_message_is_kept() -> None:
    """The adapter's own sentence survives — it is the only place the fix is written down."""
    exc = FileNotFoundError("tshark not found in PATH (install Wireshark/tshark).")
    _case("tool message", runner.describe_error(exc),
          "FileNotFoundError: tshark not found in PATH (install Wireshark/tshark).")
    # A slash in prose or in a relative path is not a path root: both used to be mangled.
    _case("relative path", runner.describe_error(RuntimeError("EvtxECmd.dll not in .tools/evtxecmd/")),
          "RuntimeError: EvtxECmd.dll not in .tools/evtxecmd/")
    print("PASS  the adapter's message reaches the analyst, slashes in prose intact")


def test_absolute_paths_collapse() -> None:
    """§9: an absolute path can name the customer in a case directory; a basename cannot."""
    exc = OSError("[Errno 2] No such file or directory: '/var/cases/ACME/DC01_Security.evtx'")
    got = runner.describe_error(exc)
    assert "ACME" not in got and "/var" not in got, got
    assert got.endswith("'DC01_Security.evtx'"), got
    _case("windows path", runner.describe_error(ValueError("bad key C:\\Users\\rossi\\NTUSER.DAT")),
          "ValueError: bad key NTUSER.DAT")
    _case("home path", runner.describe_error(ValueError("~/cases/ACME/hive.dat is truncated")),
          "ValueError: hive.dat is truncated")
    # A URL is not a path: it is matched first and kept whole, or a doc link becomes "b".
    _case("url kept", runner.describe_error(RuntimeError("see https://example.com/docs/a/b")),
          "RuntimeError: see https://example.com/docs/a/b")
    print("PASS  absolute paths collapse to a basename, URLs survive")


def test_degrades_to_the_type() -> None:
    """No message means the old behaviour, not an empty string with a stray separator."""
    _case("empty", runner.describe_error(ValueError()), "ValueError")
    long = runner.describe_error(ValueError("x" * 500))
    assert len(long) < 250 and long.endswith("\u2026"), len(long)
    print("PASS  no message degrades to the type; a long one is truncated")


def test_missing_zeek_is_reported_once() -> None:
    """Zeek absent used to be `pass`. An analysis missing the whole application layer must say so,
    once per run — the tool is missing from the host, not from each capture.

    Driven by making `zeek_path()` answer None rather than by uninstalling Zeek, which is also the
    point of asking that question instead of inferring the answer from an exception: a missing PCAP
    raises the same FileNotFoundError that a missing zeek does, and the first version of this note
    reported a mistyped filename as an uninstalled tool.
    """
    if not have("tshark"):
        return skip_test("tshark not installed: no PCAP reaches the Zeek decision")
    from adapters import pcap_zeek_runner
    from make_sample_pcap import write_sample

    original = pcap_zeek_runner.zeek_path
    with tempfile.TemporaryDirectory() as td:
        caps = [str(write_sample(Path(td) / f"c{i}.pcap")) for i in (1, 2)]
        pcap_zeek_runner.zeek_path = lambda: None
        try:
            errors: list[str] = []
            records = runner.build_records(pcap=caps, errors=errors)
        finally:
            pcap_zeek_runner.zeek_path = original
    assert records, "tshark produced no records: the fixture, not the Zeek path, is broken"
    zeek = [e for e in errors if e.startswith("PCAP-Zeek")]
    _case("one note for two captures", len(zeek), 1)
    for expected in ("not installed", "application layer", "HTTP", "tshark"):
        assert expected in zeek[0], (expected, zeek[0])
    print("PASS  Zeek missing reported once, naming what was not extracted and what still is")


def test_a_broken_capture_is_one_problem_not_two() -> None:
    """tshark and Zeek fail on an unreadable capture for the same reason; saying it twice makes one
    problem look like two."""
    errors: list[str] = []
    runner.build_records(pcap=[str(ROOT / "tests" / "no-such.pcap")], errors=errors)
    _case("single line", len([e for e in errors if "no-such.pcap" in e]), 1)
    print("PASS  an unreadable capture is reported once")


def run() -> int:
    test_message_is_kept()
    test_absolute_paths_collapse()
    test_degrades_to_the_type()
    test_missing_zeek_is_reported_once()
    test_a_broken_capture_is_one_problem_not_two()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
