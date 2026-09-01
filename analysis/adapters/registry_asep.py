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
