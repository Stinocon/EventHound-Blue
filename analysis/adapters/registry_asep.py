"""Which registry keys are auto-start / persistence locations — one map, two adapters.

`registry_recmd` and `registry_regfile` each carried their own copy of this table and their own
`_classify_key`. The two copies were still identical, which is luck rather than design: the project's
own rule is that a datum lives in one place because two copies diverge.

Merging them was the occasion to fix what the fourth adversarial review (R6-A, 2026-08-30) found by
running the classifier instead of reading it. Every item below is a case that returned None — and a
key that classifies as None is not merely unlabelled, it is DISCARDED by both adapters:

* **An offline hive has no `CurrentControlSet`.** It is a symlink created at boot; a raw SYSTEM hive
  contains `ControlSet001` / `ControlSet002`. Every service, LSA package, print monitor and
  BootExecute entry — the reason one collects a SYSTEM hive at all — matched nothing.
* **RECmd's `KeyPath` is hive-root-relative**: `Microsoft\\Windows\\CurrentVersion\\Run`, with no
  leading `Software\\`. Patterns anchored on the hive name could not match it either.
* **`knownlls`** was a typo for `knowndlls`.
* **Three patterns named a VALUE, not a key**: `…\\Control\\Lsa\\Security Packages`,
  `…\\Authentication Packages` and `…\\Session Manager\\BootExecute` are values inside
  `…\\Control\\Lsa` and `…\\Session Manager`. An SSP DLL added for credential theft (T1547.005)
  classified as nothing.
* **First-match order let short patterns shadow long ones**: `…\\CurrentVersion\\Run` was tested
  before `…\\RunOnce`, so RunOnce/RunServices/RunServicesOnce all reported as "Run", and
  `…\\Services\\Winsock2\\Parameters` reported as "Services". Matching is longest-first now, which
  is the only order in which a prefix table means what it looks like it means.
"""
from __future__ import annotations

import re

# key-path fragment (lower-case, single backslashes) -> category
_ASEP_PATTERNS: dict[str, str] = {
    # User- and machine-level Run keys
    r"software\microsoft\windows\currentversion\run": "User ASEP - Run",
    r"software\microsoft\windows\currentversion\runonce": "User ASEP - RunOnce",
    r"software\microsoft\windows\currentversion\runservices": "User ASEP - RunServices",
    r"software\microsoft\windows\currentversion\runservicesonce": "User ASEP - RunServicesOnce",
    r"software\microsoft\windows\currentversion\policies\explorer\run": "Policy ASEP - Run",
    # Logon / startup
    r"software\microsoft\windows nt\currentversion\winlogon": "Winlogon",
    r"software\microsoft\windows nt\currentversion\windows": "AppInit/Windows",
    r"software\microsoft\active setup": "Active Setup",
    # Debugger hijack (T1546.012)
    r"software\microsoft\windows nt\currentversion\image file execution options": "IFEO Debugger",
    # Scheduled tasks in the registry
    r"software\microsoft\windows nt\currentversion\schedule\taskcache": "Scheduled Task",
    # Services and the Winsock chain
    r"system\currentcontrolset\services\winsock2\parameters": "Winsock LSP",
    r"system\currentcontrolset\services": "Services",
    # Print monitors
    r"system\currentcontrolset\control\print\monitors": "Print Monitor",
    # LSA: the packages are VALUES of this key, so the key is what gets classified. Which package
    # list it is (Security vs Authentication) is the value name, and the indicator layer reads it.
    r"system\currentcontrolset\control\lsa": "LSA Packages",
    # Session Manager: KnownDLLs is its own subkey; BootExecute is a value of the parent.
    r"system\currentcontrolset\control\session manager\knowndlls": "Known DLLs",
    r"system\currentcontrolset\control\session manager": "Session Manager",
}

# Longest first: a prefix table matched in insertion order reports the shortest match, so RunOnce
# came back as "Run" and Winsock2 as "Services".
_ORDERED: list[tuple[str, str]] = sorted(
    _ASEP_PATTERNS.items(), key=lambda kv: len(kv[0]), reverse=True)

# The same patterns without their hive prefix, for the hive-root-relative paths RECmd emits.
_ORDERED_RELATIVE: list[tuple[str, str]] = sorted(
    ((re.sub(r"^(?:software|system)\\", "", p), c) for p, c in _ASEP_PATTERNS.items()),
    key=lambda kv: len(kv[0]), reverse=True)

_CONTROLSET_RE = re.compile(r"controlset\d{3}", re.IGNORECASE)


def normalize_key_path(key_path: str) -> str:
    """Lower-case, single backslashes, and `ControlSet001` folded to `currentcontrolset`."""
    lower = key_path.lower().replace("\\\\", "\\").replace("/", "\\")
    return _CONTROLSET_RE.sub("currentcontrolset", lower)


def classify_key(key_path: str) -> str | None:
    """The ASEP category of a key path, or None when it is not a persistence location.

    None means the record is DISCARDED by both adapters, so a miss here is evidence loss, not a
    missing label — which is why the table above is matched two ways: as written, and with the hive
    prefix stripped for the relative paths RECmd produces.
    """
    if not isinstance(key_path, str) or not key_path:
        return None
    lower = normalize_key_path(key_path)
    for pattern, category in _ORDERED:
        if pattern in lower:
            return category
    for pattern, category in _ORDERED_RELATIVE:
        if pattern in lower:
            return category
    return None


# ---------------------------------------------------------------------------
# ASEP value → the program it launches
# ---------------------------------------------------------------------------

# Extensions that name something the OS will execute. Deliberately wider than `.exe`: a persistence
# value launches a script or an installer just as usefully, and a detector that only knew `.exe` was
# how the old registry path patterns came to match nothing. `.dll` is deliberately absent: a DLL is
# not launched by naming it in a Run value or as a service ImagePath, and admitting one would mint a
# file entity from a shared system component.
_PROGRAM_EXTS = (".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
                 ".js", ".jse", ".wsf", ".wsh", ".msi", ".cpl")

# The SHORTEST leading run of the value that ends in a program extension and is followed by
# whitespace, a comma or the end. Non-greedy on purpose: on a command line it stops at the program,
# so the arguments can never be part of the answer — and a value whose LAST argument happens to end
# in `.exe`, or is a bare URL to one, cannot be mistaken for the program itself. It is also what
# reads a path that legitimately contains spaces (`C:\Program Files\Vendor\agent.exe /silent`),
# which a split on whitespace stops at `C:\Program`.
_PROGRAM_RE = re.compile(
    r"^(?P<prog>.*?(?:%s))(?=[\s,]|$)" % "|".join(re.escape(e) for e in _PROGRAM_EXTS),
    re.IGNORECASE)

# Winlogon holds several command values; `Userinit` is a comma-separated list of them.
_WINLOGON_PROGRAM_VALUES = frozenset({"userinit", "shell", "appsetup", "vmapplet", "taskman"})


def _first_program(command: str) -> str | None:
    r"""The executable a command line starts, or None when the string names no program.

    A Run value is a COMMAND LINE, not a path: quoting, arguments and the NT native `\??\` prefix
    are all normal, and reading the raw string as a filename is how a path became an artifact that
    never matched anything. A quoted program followed by arguments is read as the quoted token; any
    other value is read as the shortest leading run that ends in a program extension, which handles
    a path containing spaces and stops before the arguments. The rule is deliberately conservative —
    an unreadable value returns None rather than a guess, because a fabricated `file.path` bridges
    records that share nothing.
    """
    s = (command or "").strip()
    if not s:
        return None
    if s.startswith('"'):
        end = s.find('"', 1)
        if end < 0:
            return None                      # unbalanced quote: unreadable, not a guess
        token = s[1:end]
    else:
        m = _PROGRAM_RE.match(s)
        if not m:
            return None
        token = m.group("prog")
    token = token.strip().strip(",").strip()
    # NT native paths (`\??\C:\...`) and the long-path form (`\\?\C:\...`) name the same file.
    for prefix in ("\\??\\", "\\\\?\\"):
        if token.startswith(prefix):
            token = token[len(prefix):]
            break
    token = token.strip().strip(",").strip()
    if not token or '"' in token:
        return None
    # A URL is not a file on this host: `mshta.exe http://…/x.exe` names `mshta.exe`, and a value
    # that is nothing but a URL names no local program at all.
    if "://" in token:
        return None
    if not token.lower().endswith(_PROGRAM_EXTS):
        return None
    return token


def program_from_value(category: str | None, value_name: str | None,
                       value_data: str | None) -> str | None:
    r"""The program an ASEP value launches, or None — the artifact a registry finding contributes.

    Registry findings were stored, rendered and correlated by key, value and data, and reached no
    artifact at all: a Run key whose data is `C:\Windows\Temp\svcupdate.exe` could not bridge to the
    EVTX, YARA, CrowdStrike and osquery records naming the same binary. The store must not mint a
    file entity out of arbitrary registry data, so the decision lives here, where the key is known
    to be an ASEP and the value is known to be a program — and it is a decision, not a rule about
    strings: which value of which key holds an executable is registry knowledge, and the categories
    below are the ones where that is true.

    Deliberately NOT extracted: `LSA Packages`, `Known DLLs` and `AppInit/Windows` name DLL
    COMPONENTS, not launched programs. Turning a component list into file entities would bridge
    unrelated hosts through a shared system DLL — a correlation that links everything measures
    nothing. Nor does a scheduled task: its action lives in the REG_BINARY `Actions` blob under
    `…\Schedule\TaskCache`, which is not a string any of this can read, and a branch that cannot
    fire is worse than an absent one — it claims a capability in the schema and the report.
    """
    if not category or not value_data or not isinstance(value_data, str):
        return None
    name = (value_name or "").strip().lower()

    # Checked first: `RunServices` would otherwise also match the Services test below.
    if "Run" in category:
        return _first_program(value_data)
    if category == "Services":
        return _first_program(value_data) if name == "imagepath" else None
    if category == "IFEO Debugger":
        return _first_program(value_data) if name == "debugger" else None
    if category == "Winlogon":
        if name in _WINLOGON_PROGRAM_VALUES:
            # The value is a LIST, and the platform's own program comes FIRST (`userinit.exe` is
            # Windows's, `explorer.exe` the normal shell); an injected program is APPENDED. Taking
            # the first entry returned the benign binary and dropped the payload — the one thing the
            # finding is about. The LAST program is the one that differs from the default.
            programmes = [p for p in (_first_program(part) for part in value_data.split(",")) if p]
            return programmes[-1] if programmes else None
        return None
    if category == "Active Setup":
        return _first_program(value_data) if name == "stubpath" else None
    return None
