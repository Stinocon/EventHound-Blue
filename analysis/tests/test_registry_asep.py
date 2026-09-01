"""The ASEP table both registry adapters classify against — offline, deterministic.

A key that classifies as None is not merely unlabelled: both adapters DISCARD it. So every case
below used to be evidence loss, not a cosmetic gap, and the fourth adversarial review (R6-A,
2026-08-30) found all of them by running the classifier instead of reading it.

    uv run python tests/test_registry_asep.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters import registry_asep  # noqa: E402


def _is(key: str, expected: str | None) -> None:
    got = registry_asep.classify_key(key)
    assert got == expected, f"{key!r}: expected {expected!r}, got {got!r}"


def test_offline_hive() -> None:
    """`CurrentControlSet` is a symlink created at boot; a collected SYSTEM hive has ControlSet001.

    A SYSTEM hive is the artifact you collect FOR service persistence (T1543.003), LSA packages,
    print monitors and BootExecute. Every one of them matched nothing and was dropped."""
    _is(r"ControlSet001\Services\MaliciousSvc", "Services")
    _is(r"ControlSet002\Services\MaliciousSvc", "Services")
    _is(r"ControlSet001\Control\Print\Monitors\Evil", "Print Monitor")
    _is(r"System\CurrentControlSet\Services\Foo", "Services")   # the online spelling still works
    print("PASS  an offline hive's ControlSet00N classifies")


def test_hive_relative_paths() -> None:
    """RECmd's KeyPath is relative to the hive root, with no leading `Software\\`."""
    _is(r"Microsoft\Windows\CurrentVersion\Run", "User ASEP - Run")
    _is(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "User ASEP - Run")
    print("PASS  hive-relative and absolute spellings both classify")


def test_longest_match_wins() -> None:
    """A prefix table matched in insertion order reports the SHORTEST match. RunOnce, RunServices
    and RunServicesOnce all came back as plain "Run", and Winsock2 as "Services" — so filtering the
    Registry view for RunOnce returned nothing on a machine that had RunOnce persistence."""
    _is(r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "User ASEP - RunOnce")
    _is(r"Software\Microsoft\Windows\CurrentVersion\RunServices", "User ASEP - RunServices")
    _is(r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", "User ASEP - RunServicesOnce")
    _is(r"Software\Microsoft\Windows\CurrentVersion\Run", "User ASEP - Run")
    _is(r"ControlSet001\Services\Winsock2\Parameters", "Winsock LSP")
    _is(r"ControlSet001\Control\Session Manager\KnownDLLs", "Known DLLs")
    _is(r"ControlSet001\Control\Session Manager", "Session Manager")
    print("PASS  the longest pattern wins, so RunOnce is not reported as Run")


def test_patterns_that_named_a_value() -> None:
    """Three entries named a VALUE and were tested against a KEY path, so they never fired.

    `Security Packages` and `Authentication Packages` are values of `…\\Control\\Lsa` — an SSP DLL
    added there is credential-theft persistence (T1547.005) and classified as nothing at all."""
    _is(r"ControlSet001\Control\Lsa", "LSA Packages")
    _is(r"System\CurrentControlSet\Control\Lsa", "LSA Packages")
    print("PASS  the LSA and Session Manager keys classify, not their value names")


def test_still_says_no() -> None:
    """The other half of a classifier: an ordinary key must not become a persistence record."""
    for key in (r"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\App",
                r"Software\Classes\.txt",
                r"ControlSet001\Enum\PCI",
                ""):
        _is(key, None)
    assert registry_asep.classify_key(None) is None      # type: ignore[arg-type]
    print("PASS  a non-ASEP key is still not persistence")


def run() -> int:
    test_offline_hive()
    test_hive_relative_paths()
    test_longest_match_wins()
    test_patterns_that_named_a_value()
    test_still_says_no()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
