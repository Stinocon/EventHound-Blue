"""Test of Event ID SOT map (adapters/windows_eventid) — offline, always run.

Verifies key EIDs, channel-aware disambiguation (Sysmon↔RDP collisions), fallback
without channel (historical compat), and that Hayabusa adapter uses SOT instead of local copy.
    uv run python tests/test_windows_eventid.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapters import windows_eventid as w  # noqa: E402


def test_security_e_sysmon_chiave():
    assert w.classify(4624, "Security") == ("authentication", "logon")
    assert w.classify(4625, "Security") == ("authentication", "logon-failed")
    assert w.classify(4648, "Security")[1] == "logon-explicit-credentials"   # pass-the-hash
    assert w.classify(4769, "Security")[0] == "authentication"               # kerberoasting
    assert w.classify(5145, "Security")[1] == "network-share-detailed-access"  # PsExec/ADMIN$
    assert w.classify(1102, "Security") == ("configuration", "audit-log-cleared")  # log clear
    assert w.classify(4688, "Security") == ("process", "process-create")
    assert w.classify(7045, "System") == ("service", "service-installed")
    assert w.classify(4104, "Microsoft-Windows-PowerShell/Operational")[0] == "powershell"
    assert w.classify(1, "Microsoft-Windows-Sysmon/Operational") == ("process", "process-create")


def test_channel_aware_disambigua_collisioni():
    # EID 22: Sysmon = DnsQuery, TerminalServices = ShellStart. Channel decides.
    assert w.classify(22, "Microsoft-Windows-Sysmon/Operational") == ("network", "dns-query")
    assert w.classify(22, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")[0] == "session"
    # EID 21: Sysmon WmiFilterBinding vs RDP session-logon
    assert w.classify(21, "Microsoft-Windows-Sysmon/Operational")[0] == "wmi"
    assert w.classify(21, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")[1] == "rdp-session-logon"


def test_fallback_senza_canale():
    # Low EIDs (1–29) without channel → Sysmon (historical compat of Hayabusa adapter)
    assert w.classify(1) == ("process", "process-create")
    assert w.classify(22) == ("network", "dns-query")
    # High EIDs without channel → Security/System/PowerShell
    assert w.classify(4624) == ("authentication", "logon")
    assert w.classify(4104)[0] == "powershell"
    assert w.classify(7045)[0] == "service"


def test_input_robusti():
    assert w.classify(None) == (None, None)
    assert w.classify("4624") == ("authentication", "logon")   # string coercion
    assert w.classify(True) == (None, None)                    # bool is not an EID
    assert w.classify(999999) == (None, None)                  # not mapped
    assert w.is_mapped(4624) and not w.is_mapped(999999)


def test_hayabusa_usa_la_sot():
    # adapter must not have local _EID_MAP: must call SOT (dedup §16.3)
    from adapters import evtx_hayabusa
    assert not hasattr(evtx_hayabusa, "_EID_MAP"), "evtx_hayabusa still has local EID map"
    rec = evtx_hayabusa._record_from_hayabusa(
        {"EventID": 4624, "Channel": "Security", "Timestamp": "2026-01-01T00:00:00Z", "Computer": "H"}
    )
    assert rec["event.category"] == "authentication" and rec["event.action"] == "logon", rec


if __name__ == "__main__":
    test_security_e_sysmon_chiave()
    test_channel_aware_disambigua_collisioni()
    test_fallback_senza_canale()
    test_input_robusti()
    test_hayabusa_usa_la_sot()
    print("OK — windows_eventid: 5 tests passed")
