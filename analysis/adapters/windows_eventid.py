"""Map Windows Event ID → (event.category, event.action) — SOT of the project.

Stable classification of Event IDs, independent of any single analysis scope. It is the
single source (§16.3): EVTX adapters (`evtx_hayabusa`, `evtx_evtxecmd`) import it instead of
keeping divergent copies. Categories follow the ECS vocabulary used in the common schema
(`schema/common-schema.md`): authentication, process, network, file, registry, iam, session,
service, task, powershell, wmi, driver, configuration.

**Channel-aware.** Different channels reuse the SAME number with different meanings (e.g., EID 22 =
Sysmon DnsQuery *or* TerminalServices ShellStart; EID 1 = Sysmon ProcessCreate). `classify`
accepts the channel to disambiguate; without a channel it uses a sensible default (Sysmon for low EIDs
1–29, Security/System for high ones) that reproduces the historical behavior of the Hayabusa adapter.

Sources of meanings (§6): Microsoft documentation (Security Auditing / system events),
Sysmon schema by Sysinternals, and DFIR cheat sheets (evtxparser.com). Less standard entries are
still mapped to conservative category/action values; when in doubt (None, None) is returned, no
precise semantics are fabricated.
"""
from __future__ import annotations

# ── Security (channel "Security") ──────────────────────────────────────────────
_SECURITY: dict[int, tuple[str, str]] = {
    1102: ("configuration", "audit-log-cleared"),      # anti-forensics: Security log cleared
    4616: ("configuration", "system-time-changed"),
    4624: ("authentication", "logon"),
    4625: ("authentication", "logon-failed"),
    4634: ("authentication", "logoff"),
    4647: ("authentication", "logoff-user-initiated"),
    4648: ("authentication", "logon-explicit-credentials"),  # runas /netonly → credential theft
    4672: ("authentication", "special-privileges-assigned"),
    4768: ("authentication", "kerberos-tgt-requested"),
    4769: ("authentication", "kerberos-service-ticket-requested"),  # kerberoasting
    4771: ("authentication", "kerberos-preauth-failed"),
    4776: ("authentication", "ntlm-credential-validation"),
    4778: ("session", "session-reconnected"),          # RDP reconnect
    4779: ("session", "session-disconnected"),         # RDP disconnect
    4688: ("process", "process-create"),
    4689: ("process", "process-exit"),
    4697: ("service", "service-installed"),
    4698: ("task", "scheduled-task-created"),
    4699: ("task", "scheduled-task-deleted"),
    4700: ("task", "scheduled-task-enabled"),
    4701: ("task", "scheduled-task-disabled"),
    4702: ("task", "scheduled-task-updated"),
    4719: ("configuration", "audit-policy-changed"),
    4720: ("iam", "user-account-created"),
    4722: ("iam", "user-account-enabled"),
    4723: ("iam", "password-change-attempted"),
    4724: ("iam", "password-reset"),
    4725: ("iam", "user-account-disabled"),
    4726: ("iam", "user-account-deleted"),
    4728: ("iam", "member-added-to-global-group"),
    4729: ("iam", "member-removed-from-global-group"),
    4732: ("iam", "member-added-to-local-group"),       # e.g. local Administrators
    4733: ("iam", "member-removed-from-local-group"),
    4735: ("iam", "local-group-changed"),
    4738: ("iam", "user-account-changed"),
    4740: ("iam", "user-account-locked-out"),
    4756: ("iam", "member-added-to-universal-group"),
    4767: ("iam", "user-account-unlocked"),
    4657: ("registry", "registry-value-modified"),
    4663: ("file", "object-access-attempt"),
    4670: ("file", "permissions-changed"),
    5140: ("file", "network-share-accessed"),
    5142: ("file", "network-share-added"),
    5143: ("file", "network-share-modified"),
    5144: ("file", "network-share-deleted"),
    5145: ("file", "network-share-detailed-access"),    # PsExec/ADMIN$ → lateral movement
    5156: ("network", "connection-allowed"),            # WFP
    5157: ("network", "connection-blocked"),            # WFP
}

# ── System (channel "System") ──────────────────────────────────────────────────
_SYSTEM: dict[int, tuple[str, str]] = {
    104: ("configuration", "event-log-cleared"),        # another system log cleared
    1074: ("configuration", "system-shutdown-initiated"),
    6005: ("configuration", "event-log-service-started"),
    6006: ("configuration", "event-log-service-stopped"),
    6008: ("configuration", "unexpected-shutdown"),
    7034: ("service", "service-crashed"),
    7036: ("service", "service-state-changed"),
    7040: ("service", "service-start-type-changed"),
    7045: ("service", "service-installed"),             # New Service (persistence)
}

# ── PowerShell (channels "Windows PowerShell" / "PowerShell/Operational") ───────
_POWERSHELL: dict[int, tuple[str, str]] = {
    400: ("powershell", "engine-state-started"),
    403: ("powershell", "engine-state-stopped"),
    600: ("powershell", "provider-lifecycle"),
    4103: ("powershell", "module-logging"),
    4104: ("powershell", "scriptblock-logging"),        # deobfuscated: high value
    4105: ("powershell", "scriptblock-start"),
    4106: ("powershell", "scriptblock-stop"),
}

# ── Sysmon (channel "Microsoft-Windows-Sysmon/Operational") ────────────────────
_SYSMON: dict[int, tuple[str, str]] = {
    1: ("process", "process-create"),
    2: ("file", "file-creation-time-changed"),
    3: ("network", "network-connect"),
    4: ("configuration", "sysmon-service-state-changed"),
    5: ("process", "process-terminated"),
    6: ("driver", "driver-loaded"),
    7: ("process", "image-loaded"),
    8: ("process", "create-remote-thread"),             # injection
    9: ("file", "raw-access-read"),
    10: ("process", "process-access"),                  # e.g. access to lsass
    11: ("file", "file-create"),
    12: ("registry", "registry-key-created-deleted"),
    13: ("registry", "registry-value-set"),
    14: ("registry", "registry-key-value-renamed"),
    15: ("file", "file-create-stream-hash"),            # ADS
    16: ("configuration", "sysmon-config-changed"),
    17: ("process", "named-pipe-created"),
    18: ("process", "named-pipe-connected"),
    19: ("wmi", "wmi-event-filter"),
    20: ("wmi", "wmi-event-consumer"),
    21: ("wmi", "wmi-consumer-filter-binding"),
    22: ("network", "dns-query"),
    23: ("file", "file-delete-archived"),
    24: ("configuration", "clipboard-changed"),
    25: ("process", "process-tampering"),
    26: ("file", "file-delete-logged"),
    27: ("file", "file-block-executable"),
    28: ("file", "file-block-shredding"),
    29: ("file", "file-executable-detected"),
    255: ("configuration", "sysmon-error"),
}

# ── TerminalServices / RDP (channels LocalSessionManager / RemoteConnectionManager) ─
_TERMINALSERVICES: dict[int, tuple[str, str]] = {
    21: ("session", "rdp-session-logon"),
    22: ("session", "rdp-shell-start"),
    23: ("session", "rdp-session-logoff"),
    24: ("session", "rdp-session-disconnected"),
    25: ("session", "rdp-session-reconnected"),
    1024: ("session", "rdp-client-connection-attempt"),
    1149: ("session", "rdp-user-authentication-succeeded"),
}

# ── Task Scheduler (channel "TaskScheduler/Operational") ───────────────────────
_TASKSCHED: dict[int, tuple[str, str]] = {
    106: ("task", "scheduled-task-registered"),
    129: ("task", "scheduled-task-launched-process"),
    140: ("task", "scheduled-task-updated"),
    141: ("task", "scheduled-task-deleted"),
    200: ("task", "scheduled-task-action-started"),
    201: ("task", "scheduled-task-action-completed"),
}

# ── WMI-Activity (channel "WMI-Activity/Operational") ──────────────────────────
_WMI: dict[int, tuple[str, str]] = {
    5857: ("wmi", "wmi-provider-started"),
    5858: ("wmi", "wmi-operation-failed"),
    5859: ("wmi", "wmi-permanent-consumer-registered"),
    5860: ("wmi", "wmi-temporary-consumer-registered"),
    5861: ("wmi", "wmi-permanent-consumer-binding"),    # WMI persistence
}


def _channel_family(channel: str | None) -> str | None:
    """Map an EVTX channel name to a map family. None = unknown."""
    c = (channel or "").lower()
    if not c:
        return None
    if "sysmon" in c:
        return "sysmon"
    if "powershell" in c:
        return "powershell"
    if any(k in c for k in ("terminalservices", "localsessionmanager",
                            "remoteconnectionmanager", "rdpclient")):
        return "rdp"
    if "taskscheduler" in c:
        return "task"
    if "wmi-activity" in c:
        return "wmi"
    if "security" in c:
        return "security"
    if "system" in c:
        return "system"
    return None


_FAMILY = {
    "security": _SECURITY, "system": _SYSTEM, "powershell": _POWERSHELL,
    "sysmon": _SYSMON, "rdp": _TERMINALSERVICES, "task": _TASKSCHED, "wmi": _WMI,
}


def classify(eid, channel: str | None = None) -> tuple[str | None, str | None]:
    """Return (category, action) for an Event ID, optionally disambiguated by channel.

    With a known channel: uses that family's map. Without a channel: low EIDs (1–29) are
    interpreted as Sysmon (historical behavior), others searched in Security → System →
    PowerShell → RDP → Task → WMI. Unmapped / non-integer EID → (None, None)."""
    if isinstance(eid, bool):          # bool is a subtype of int but is not an Event ID
        return (None, None)
    if not isinstance(eid, int):
        try:
            eid = int(eid)
        except (TypeError, ValueError):
            return (None, None)

    fam = _channel_family(channel)
    if fam is not None:
        hit = _FAMILY[fam].get(eid)
        if hit is not None:
            return hit
        # canale noto ma EID non in quella mappa: prosegui col fallback sotto (rule pack atipici).

    if 1 <= eid <= 29 and eid in _SYSMON:
        return _SYSMON[eid]
    for table in (_SECURITY, _SYSTEM, _POWERSHELL, _TERMINALSERVICES, _TASKSCHED, _WMI):
        hit = table.get(eid)
        if hit is not None:
            return hit
    return (None, None)


def is_mapped(eid, channel: str | None = None) -> bool:
    return classify(eid, channel) != (None, None)
