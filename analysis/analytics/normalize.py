"""Entity normalization for cross-tool correlation (Phase 2+).

Different tools spell the same entity differently, so an exact string join misses real links:
    user  — Okta `alice@corp.example`, EVTX `CORP\\alice`, a log `alice`  → all the same actor
    host  — `DC1`, `dc1.corp.example`                                     → the same machine
    hash  — Sysmon `A1B2…` (upper), THOR `a1b2…` (lower)                  → the same artifact
This module canonicalizes those ambiguous indicators so correlation joins on the *entity*, not the
spelling. Deliberately conservative: it strips wrappers and case, it does NOT fuzzy-match distinct
names (a wrong merge is a real cost in security, §6). The raw variants are kept and shown alongside
the canonical value, so every merge is auditable.

The dangerous direction is the *false merge*, and it has two shapes, both handled here:

  • **Same account name, different realm.** `alice@corp.example` and `alice@partner.example` are
    two people; collapsing both to `alice` invents a link. The domain is therefore extracted and
    kept (`user_domain`/`host_domain`), and correlation flags a bridge whose spellings disagree on
    the realm as `ambiguous` instead of presenting it as fact. NetBIOS vs DNS spellings of the same
    realm (`CORP` vs `corp.example`) are reconciled on the first label, so the common case does not
    get flagged.
  • **Ubiquitous values that are not identities.** `SYSTEM`, `DC1$`, `127.0.0.1`, `svchost.exe`
    appear everywhere; bridging on them links every source to every other. They are recognized and
    excluded from the entity bridges — while staying fully queryable in the timeline.
"""
from __future__ import annotations

import ipaddress
import re

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTHS = {32, 40, 64, 128}          # MD5, SHA1, SHA256, SHA512

# Ubiquitous machine/service accounts: present on every host, so they are NOT identity bridges —
# correlating them across sources is noise. Kept queryable, excluded from the user correlation.
_GENERIC_USERS = {
    "system", "local service", "network service", "local system",
    "anonymous logon", "iusr", "-", "n/a", "na", "unknown", "null",
    # Session/desktop pseudo-accounts Windows spawns per session: never a person.
    "dwm", "umfd", "font driver host", "window manager",
}
# Same idea, but matched by prefix because Windows numbers them per session (DWM-1, UMFD-0).
_GENERIC_USER_PREFIXES = ("dwm-", "umfd-")

# Binaries present on every Windows host: as a *file* bridge they link everything to everything.
# (They stay in the timeline and in process analytics — this only affects entity correlation.)
_GENERIC_FILES = {
    "svchost.exe", "cmd.exe", "powershell.exe", "explorer.exe", "lsass.exe", "services.exe",
    "rundll32.exe", "regsvr32.exe", "wmiprvse.exe", "conhost.exe", "taskhostw.exe", "dllhost.exe",
    "csrss.exe", "winlogon.exe", "spoolsv.exe", "msiexec.exe", "searchindexer.exe", "smss.exe",
}

# Names that answer "which host" with "any of them".
_GENERIC_HOSTS = {"localhost", "-", "n/a", "na", "unknown", "null", "::1"}

# DNS names that are infrastructure noise rather than an indicator.
_GENERIC_DOMAINS = {"localhost", "wpad", "-", "n/a"}
_GENERIC_DOMAIN_SUFFIXES = (".in-addr.arpa", ".ip6.arpa", ".arpa")   # reverse lookups


def canon_user(v) -> str | None:
    """Canonical account name: strip UPN (`user@domain`) and NetBIOS/local (`domain\\user`) wrappers,
    lowercase. `CORP\\Alice`, `alice@corp.example`, `Alice` → `alice`.

    The realm is intentionally dropped here (that is what makes the cross-tool join work) and kept
    separately by `user_domain()`; correlation uses both — see the module docstring."""
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    if "@" in s:                      # UPN / email → local part
        s = s.split("@", 1)[0]
    if "\\" in s:                     # DOMAIN\user or HOST\user → account part
        s = s.rsplit("\\", 1)[1]
    if "/" in s:                      # DOMAIN/user, seen in some exports
        s = s.rsplit("/", 1)[1]
    s = s.strip().lower()
    return s or None


def user_domain(v) -> str | None:
    """Realm the account was spelled with: `CORP\\alice` → `corp`, `alice@corp.example` →
    `corp.example`, bare `alice` → None (unknown, not a conflict)."""
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    if "@" in s:
        dom = s.split("@", 1)[1]
    elif "\\" in s:
        dom = s.rsplit("\\", 1)[0]
    elif "/" in s:
        dom = s.rsplit("/", 1)[0]
    else:
        return None
    dom = dom.strip().strip(".").lower()
    # `.\alice` and `HOSTNAME\alice` both mean "local account"; the first is not a realm at all.
    return dom or None


def is_machine_user(v) -> bool:
    """Windows computer account (`DC1$`): the machine acting, not a person. Never an identity
    bridge — otherwise every event a host generates ties its users together."""
    return str(v or "").strip().endswith("$")


def is_generic_user(canon: str | None) -> bool:
    """True for ubiquitous machine/service accounts (noise as an identity bridge)."""
    c = (canon or "").strip().lower()
    if not c:
        return True
    if c in _GENERIC_USERS or c.startswith(_GENERIC_USER_PREFIXES):
        return True
    return c.endswith("$")            # computer account, incl. already-canonicalized `dc1$`


def canon_host(v) -> str | None:
    """Canonical short hostname: lowercase, strip the DNS domain of an FQDN. IPs are left as-is.
    `DC1`, `dc1.corp.example` → `dc1`; `10.1.1.220` stays `10.1.1.220`."""
    if v is None:
        return None
    s = str(v).strip().rstrip(".").lower()
    if not s:
        return None
    if ":" in s or _IPV4.match(s):   # IPv6 or IPv4 → do not touch
        return s
    return s.split(".")[0] or None   # FQDN → short hostname


def host_domain(v) -> str | None:
    """DNS domain of an FQDN host (`dc1.corp.example` → `corp.example`); None for a short name."""
    if v is None:
        return None
    s = str(v).strip().rstrip(".").lower()
    if not s or ":" in s or _IPV4.match(s) or "." not in s:
        return None
    return s.split(".", 1)[1] or None


def is_generic_host(canon: str | None) -> bool:
    """Host values that identify no particular machine."""
    c = (canon or "").strip().lower()
    return (not c) or c in _GENERIC_HOSTS


def realms_conflict(domains) -> bool:
    """True when the realms observed for one canonical entity cannot be the same realm.

    Reconciles NetBIOS with DNS on the first label — `CORP` and `corp.example` are the same domain
    spelled two ways, and flagging that as a conflict would make the flag useless. `corp` vs
    `partner` cannot be reconciled: two different realms, so the same account name is probably two
    different accounts. Unknown realms (bare `alice`) are ignored, not counted as conflicting."""
    labels = {str(d).strip().lower().split(".")[0] for d in domains if d}
    labels.discard("")
    return len(labels) > 1


def canon_hash(v) -> str | None:
    """Lowercase a file hash and reject anything that is not one.

    Case matters in practice: Sysmon writes `A1B2…`, THOR writes `a1b2…`, and an exact join misses
    the match entirely. Non-hex or wrong-length values (`n/a`, a truncated field) are dropped rather
    than becoming a shared 'indicator' that bridges unrelated sources."""
    if v is None:
        return None
    s = str(v).strip().lower()
    # Sysmon-style prefixed forms: "SHA256=ABCD…"
    if "=" in s:
        s = s.rsplit("=", 1)[1].strip()
    if len(s) not in _HASH_LENGTHS or not _HEX.match(s):
        return None
    return s


def canon_domain(v) -> str | None:
    """Canonical DNS name: lowercase, strip the trailing root dot. `WWW.Corp.Example.` → the same
    name every other tool writes."""
    if v is None:
        return None
    s = str(v).strip().rstrip(".").lower()
    return s or None


def is_generic_domain(canon: str | None) -> bool:
    """Reverse-lookup and infrastructure names: noise as a correlation bridge."""
    c = (canon or "").strip().lower()
    if not c:
        return True
    return c in _GENERIC_DOMAINS or c.endswith(_GENERIC_DOMAIN_SUFFIXES)


def canon_file(v) -> str | None:
    """Canonical artifact name: lowercase basename. `C:\\Temp\\Evil.EXE` and `/tmp/evil.exe` both
    become `evil.exe`, so a name seen as a full path by one tool and bare by another still joins."""
    if v is None:
        return None
    s = str(v).strip().replace("\\", "/").rstrip("/")
    if not s:
        return None
    return s.rsplit("/", 1)[-1].strip().lower() or None


def is_generic_file(canon: str | None) -> bool:
    """Ubiquitous system binaries: present on every host, worthless as a bridge."""
    return (canon or "").strip().lower() in _GENERIC_FILES


def source_family(v) -> str | None:
    """Tool family behind an `event.source`, i.e. the label without its per-file suffix.

    Adapters disagree on how much they put in `event.source`: PCAP and the generic log adapter
    qualify it with the file (`pcap:capture.pcap`, `log:access.log`), every other adapter emits a
    bare family constant (`evtx`, `thor`, `okta`). Correlation counts *how many independent tools*
    corroborate an indicator, and confidence grows with that count — so reading the qualified label
    as the unit made two captures from one sensor look like two tools, while two EVTX files from
    two hosts looked like one. The family is the unit for that count; the qualified label stays as
    the origin, for provenance.
    """
    s = str(v or "").strip()
    if not s:
        return None
    return s.split(":", 1)[0].strip().lower() or None


def is_generic_ip(v) -> bool:
    """Addresses that identify no particular endpoint: loopback, unspecified, link-local,
    multicast, broadcast. Without this, one `127.0.0.1` in two files reads as a cross-source link.
    Invalid values (a hostname in an IP field) are also excluded from the IP bridge."""
    s = str(v or "").strip()
    if not s:
        return True
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return True
    return bool(ip.is_loopback or ip.is_unspecified or ip.is_link_local
                or ip.is_multicast or ip.is_reserved
                or (ip.version == 4 and str(ip) == "255.255.255.255"))
