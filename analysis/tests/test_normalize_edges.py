"""Edge cases of entity normalization and of the ATT&CK/kill-chain layer — offline, deterministic.

The risk this file exists for is the **false merge**: two different principals collapsed into one
entity make the engine assert a link that never existed, and an analyst acts on it. Each case below
is a way that can happen (or a real link that would be missed), pinned so a future change to
normalize.py cannot reintroduce it silently.

    uv run python tests/test_normalize_edges.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analytics import attack, normalize, runner  # noqa: E402


def _case(label: str, got, expected) -> None:
    assert got == expected, f"{label}: expected {expected!r}, got {got!r}"


def test_user_spellings() -> None:
    """The same person written by four tools must land on one key — and stop there."""
    for raw in ("CORP\\Alice", "alice@corp.example", "Alice", "corp/alice", "  alice  "):
        _case(f"canon_user({raw!r})", normalize.canon_user(raw), "alice")
    # Realm kept aside, so a conflict stays detectable after the merge.
    _case("realm netbios", normalize.user_domain("CORP\\Alice"), "corp")
    _case("realm upn", normalize.user_domain("alice@corp.example"), "corp.example")
    _case("realm bare", normalize.user_domain("alice"), None)
    # NetBIOS vs DNS spelling of one realm is NOT a conflict; two realms are.
    assert not normalize.realms_conflict(["corp", "corp.example"]), "NetBIOS/DNS wrongly flagged"
    assert not normalize.realms_conflict(["corp.example", None, ""]), "unknown realm must not conflict"
    assert normalize.realms_conflict(["corp.example", "partner.example"]), "cross-realm merge not flagged"
    print("PASS  user: 4 spellings → one key; realm kept; cross-realm conflict detected")


def test_non_identities() -> None:
    """Values that are on every host are not identities: bridging them links everything."""
    for u in ("SYSTEM", "NT AUTHORITY\\SYSTEM", "LOCAL SERVICE", "ANONYMOUS LOGON", "DWM-1", "UMFD-0", "-"):
        assert normalize.is_generic_user(normalize.canon_user(u)), f"{u} must not bridge identities"
    # Computer account: the machine acting, not a person.
    assert normalize.is_machine_user("DC1$"), "DC1$ not recognized as a computer account"
    assert normalize.is_generic_user(normalize.canon_user("DC1$")), "DC1$ must not bridge identities"
    assert not normalize.is_generic_user(normalize.canon_user("CORP\\alice")), "a real account was excluded"
    # Administrator stays an identity: ubiquitous but meaningful (and privileged).
    assert not normalize.is_generic_user("administrator"), "administrator must remain an identity"

    for ip in ("127.0.0.1", "::1", "0.0.0.0", "169.254.10.1", "224.0.0.251", "255.255.255.255", "not-an-ip", ""):
        assert normalize.is_generic_ip(ip), f"{ip!r} must not be a correlation bridge"
    for ip in ("10.0.0.5", "203.0.113.9", "2001:db8::1"):
        assert not normalize.is_generic_ip(ip), f"{ip} is a real endpoint and must bridge"

    for d in ("localhost", "1.0.0.127.in-addr.arpa", "WPAD"):
        assert normalize.is_generic_domain(normalize.canon_domain(d)), f"{d} must not bridge"
    assert not normalize.is_generic_domain(normalize.canon_domain("evil.example.")), "real domain excluded"
    assert normalize.is_generic_file(normalize.canon_file("C:\\Windows\\System32\\svchost.exe"))
    assert not normalize.is_generic_file(normalize.canon_file("C:\\Temp\\evil.exe"))
    print("PASS  non-identities: service/computer accounts, loopback & co, reverse DNS, system binaries")


def test_case_and_path_variants() -> None:
    """Real links that an exact string join misses."""
    # Sysmon writes hashes uppercase, THOR lowercase — same artifact.
    up = "A" * 64
    _case("hash case", normalize.canon_hash(up), "a" * 64)
    _case("hash prefixed", normalize.canon_hash("SHA256=" + up), "a" * 64)
    # Junk must not become a shared 'indicator' that bridges unrelated sources.
    for bad in ("n/a", "-", "", "zz" * 16, "abc"):
        _case(f"hash junk {bad!r}", normalize.canon_hash(bad), None)
    # Path vs bare name, and case.
    for raw in ("C:\\Temp\\Evil.EXE", "/tmp/evil.exe", "evil.exe"):
        _case(f"canon_file({raw!r})", normalize.canon_file(raw), "evil.exe")
    # FQDN vs short host, trailing dot, IPs untouched.
    for raw in ("DC1", "dc1.corp.example", "dc1.corp.example."):
        _case(f"canon_host({raw!r})", normalize.canon_host(raw), "dc1")
    _case("host domain", normalize.host_domain("dc1.corp.example"), "corp.example")
    _case("host domain short", normalize.host_domain("dc1"), None)
    _case("ipv4 untouched", normalize.canon_host("10.1.1.220"), "10.1.1.220")
    _case("dns canon", normalize.canon_domain("WWW.Corp.Example."), "www.corp.example")
    print("PASS  variants: hash case/prefix/junk, path→basename, FQDN→short, DNS canonical")


def test_attack_and_killchain() -> None:
    """Technique → tactic comes from the official map; tactic → phase is the documented guidance."""
    _case("technique name", attack.technique_name("T1003.001"), "LSASS Memory")
    _case("technique name, sloppy id", attack.technique_name(" t1003.001 "), "LSASS Memory")
    assert "credential-access" in attack.tactics_of("T1003.001"), attack.tactics_of("T1003.001")
    _case("phase", attack.phases_of("T1566"), ["Delivery"])
    _case("c2 phase", attack.phases_of("T1071.004"), ["Command and Control"])
    # Free text in the technique column must not become a fake technique.
    _case("parse", attack.split_techniques("T1021.002, T1078 | not-a-technique;T1021.002"),
          ["T1021.002", "T1078"])
    ann = attack.annotate(["T1566.001", "T1071.004"])
    _case("annotate depth", ann["max_phase"], "Command and Control")
    _case("annotate empty", attack.annotate(None)["max_phase_order"], 0)
    assert attack.attack_version(), "the generated map must record the ATT&CK version it came from"
    print(f"PASS  attack: names/tactics/phases from the official map (ATT&CK v{attack.attack_version()})")


def test_end_to_end_correlation() -> None:
    """The whole point, on one small dataset: one actor across three sources, and no false bridges."""
    records = [
        # Same person, three spellings, three sources — must merge into ONE user bridge.
        {"@timestamp": "2026-07-20T10:00:00Z", "event.source": "crowdstrike", "user.name": "alice@corp.example",
         "source.ip": "203.0.113.9"},
        {"@timestamp": "2026-07-20T10:01:00Z", "event.source": "evtx", "user.name": "CORP\\Alice",
         "host.name": "DC1.corp.example", "attack.techniques": ["T1003.001"]},
        {"@timestamp": "2026-07-20T10:02:00Z", "event.source": "log:vpn", "user.name": "alice",
         "host.name": "dc1", "attack.techniques": ["T1071.004"]},
        # Noise that must NOT bridge anything: SYSTEM, a computer account, loopback, svchost.
        {"@timestamp": "2026-07-20T10:03:00Z", "event.source": "evtx", "user.name": "NT AUTHORITY\\SYSTEM",
         "host.name": "dc1", "source.ip": "127.0.0.1", "file.name": "C:\\Windows\\System32\\svchost.exe"},
        {"@timestamp": "2026-07-20T10:04:00Z", "event.source": "log:vpn", "user.name": "DC1$",
         "source.ip": "127.0.0.1", "file.name": "/usr/bin/svchost.exe"},
        # Same artifact, two spellings of the hash and of the path → one bridge.
        {"@timestamp": "2026-07-20T10:05:00Z", "event.source": "evtx", "host.name": "dc1",
         "file.name": "C:\\Temp\\Evil.EXE", "file.hash": "B" * 64},
        {"@timestamp": "2026-07-20T10:06:00Z", "event.source": "thor", "host.name": "dc1",
         "file.name": "evil.exe", "file.hash": "b" * 64},
        # A different realm, same account name → must be surfaced as AMBIGUOUS, not as a fact.
        {"@timestamp": "2026-07-20T10:07:00Z", "event.source": "crowdstrike", "user.name": "bob@corp.example"},
        {"@timestamp": "2026-07-20T10:08:00Z", "event.source": "evtx", "user.name": "PARTNER\\bob",
         "host.name": "ws9"},
    ]
    out = runner.analyze(records)
    by_kind = {}
    for r in out["shared_indicators"]:
        by_kind.setdefault(r["kind"], {})[r["indicator"]] = r

    alice = by_kind.get("user", {}).get("alice")
    assert alice, f"the three spellings of alice did not merge: {list(by_kind.get('user', {}))}"
    _case("alice families", alice["families"], 3)
    _case("alice match_type", alice["match_type"], "normalized")
    assert alice["confidence_label"] in ("high", "medium"), alice

    bob = by_kind.get("user", {}).get("bob")
    assert bob and bob["match_type"] == "ambiguous", f"cross-realm bob not flagged: {bob}"
    # Realms are reported as spelled: NetBIOS `PARTNER\bob` → "partner", UPN → "corp.example".
    assert "partner" in bob["realms"] and "corp.example" in bob["realms"], bob
    assert bob["confidence"] < alice["confidence"], "an ambiguous bridge must rank below a certain one"

    assert "system" not in by_kind.get("user", {}), "SYSTEM must not be an identity bridge"
    assert "dc1$" not in by_kind.get("user", {}), "a computer account must not be an identity bridge"
    assert "127.0.0.1" not in by_kind.get("ip", {}), "loopback must not bridge sources"
    assert "svchost.exe" not in by_kind.get("file", {}), "a system binary must not bridge sources"

    assert ("b" * 64) in by_kind.get("file_hash", {}), "upper/lower hash spellings did not merge"
    assert "evil.exe" in by_kind.get("file", {}), "path vs bare filename did not merge"

    # Kill-chain layer on the same run.
    phases = {p["phase"] for p in out["killchain"]}
    assert {"Exploitation", "Command and Control"} <= phases, out["killchain"]
    hk = {h["host"]: h for h in out["host_killchain"]}
    assert hk["dc1"]["deepest_phase"] == "Command and Control", hk["dc1"]
    cat = {t["technique"]: t for t in out["technique_catalog"]}
    _case("catalog name", cat["T1003.001"]["name"], "LSASS Memory")
    top = out["incident_clusters"][0]
    assert top["kc_depth"] >= attack.PHASE_ORDER["Command and Control"], top
    print("PASS  e2e: identity merged across 3 sources, ambiguity flagged, noise excluded, kill-chain built")


def run() -> int:
    test_user_spellings()
    test_non_identities()
    test_case_and_path_variants()
    test_attack_and_killchain()
    test_end_to_end_correlation()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
