"""Enrichment of indicators from external threat intel (analysis DESIGN §12 / Phase 6).

Annotates PUBLIC indicators (IP, domain, hash) with Shodan exposure (InternetDB, keyless),
VirusTotal reputation (keyed), and known ThreatFox/abuse.ch IOCs (keyed). Built for triage:
"is this external IP/domain/hash known? is it linked to a malware family?".

CORE CONSTRAINTS (method/conventions.md §9/§15) — security comes before functionality:
1. EGRESS GATE: no network call unless `allow_egress=True` (default False).
2. PUBLIC INDICATORS ONLY: private/reserved IPs (RFC1918, loopback, link-local) and internal
   domains (.local/.lan/.internal/.corp/.example/.home/.intranet) are NEVER sent externally — they
   are client data. The guard triggers EVEN with egress enabled. Hashes (MD5/SHA1/SHA256) are
   public by nature (they identify the threat, not the client).
VirusTotal NEVER receives file uploads: only lookups of already-public hash/IP/domain.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import eventhound_config  # noqa: E402 — shared key store (env var wins over the stored value)

_INTERNAL_TLDS = (".local", ".lan", ".internal", ".corp", ".example", ".home", ".intranet")
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
# Syntactically valid hostname: label [A-Za-z0-9-] (no leading/trailing '-') separated by dots,
# at least two labels, max 253 chars. No '/', ':', '#', '?', '%', spaces or other non-host chars:
# without this, an internal IP/host with a suffix (e.g. '10.0.0.5/foo', 'dc01.internal/x') would be
# classified as 'domain' and would bypass the §9 guard (sent to VirusTotal/Shodan).
# The final label (TLD) must contain at least one letter: a real TLD is never all-numeric.
# Without this, malformed IPv4s (e.g. '999.999.999.999', '1.2') fail ip_address() but match
# _DOMAIN_RE (all-digit labels allowed) and would be classified 'domain' + sent to VT/Shodan.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.(?!-)[A-Za-z0-9-]*[A-Za-z][A-Za-z0-9-]*(?<!-)\.?$"
)
_TIMEOUT = 12.0

# #24 (defense in depth §9): if the 'psl' extra is installed (tldextract), an FQDN whose TLD is NOT
# a real public suffix (e.g. internal domain with a made-up TLD .corp/.acme beyond the
# hardcoded list) is treated as client data and not sent externally. tldextract uses a
# bundled snapshot: no network (§15). Without the extra, only the _INTERNAL_TLDS list remains.
_tld_extract = None
_tld_tried = False


def _registrable_or_none(domain: str):
    """True if `domain` has a REAL (registrable) public suffix, False if the TLD is not public
    (internal/fictitious domain), None if the public-suffix list is not available (extra 'psl' missing)."""
    global _tld_extract, _tld_tried
    if not _tld_tried:
        _tld_tried = True
        try:
            import tldextract
            _tld_extract = tldextract.TLDExtract(suffix_list_urls=())  # offline: snapshot bundled (§15)
        except Exception:
            _tld_extract = None
    if _tld_extract is None:
        return None
    return bool(_tld_extract(domain).suffix)


def indicator_kind(indicator: str) -> str:
    """'ip' | 'domain' | 'hash' | 'unknown'."""
    s = (indicator or "").strip()
    try:
        # rstrip of ONE trailing dot: the DNS-root form '10.0.0.5.' / FQDN '192.168.1.1.' (common in
        # DNS/tshark logs) is not accepted by ip_address() and would end up classified as 'domain'
        # (all-numeric label), bypassing the §9 guard (internal IP sent to VirusTotal/Shodan).
        ipaddress.ip_address(s[:-1] if s.endswith(".") else s)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.match(s):
        return "hash"
    if _DOMAIN_RE.match(s):
        return "domain"
    return "unknown"


def is_public(indicator: str) -> bool:
    """True if the indicator can be sent externally without exposing client data (§9)."""
    kind = indicator_kind(indicator)
    if kind == "ip":
        # Consistent with indicator_kind: strip any trailing dot ('10.0.0.5.') that
        # ip_address() would reject, otherwise this branch would raise ValueError after
        # indicator_kind has already classified the indicator as 'ip'.
        s = indicator.strip()
        ip = ipaddress.ip_address(s[:-1] if s.endswith(".") else s)
        # fec0::/10 is DEPRECATED IPv6 site-local (RFC 3879): an internal range, but ipaddress
        # reports it as is_global=True and not is_private/is_reserved. Without this explicit
        # exclusion an internal client IPv6 indicator would bypass the §9 guard (sent to Shodan/VT).
        if isinstance(ip, ipaddress.IPv6Address) and ip in ipaddress.ip_network("fec0::/10"):
            return False
        # Public only if globally routable: besides private (RFC1918), explicitly exclude
        # multicast/reserved/loopback/link-local/unspecified — they are not useful external
        # indicators and should not be queried anyway (some count as internal data, §9).
        return ip.is_global and not (
            ip.is_private or ip.is_multicast or ip.is_reserved
            or ip.is_loopback or ip.is_link_local or ip.is_unspecified
        )
    if kind == "domain":
        # indicator_kind has already guaranteed a well-formed hostname (_DOMAIN_RE): here it's
        # enough to exclude internal TLDs as defense in depth. Comparison on the LAST label, not
        # endswith on free text (so 'host.local' is internal but 'x.localdomain' is not masked).
        d = indicator.strip().lower().rstrip(".")
        internal = {t.lstrip(".") for t in _INTERNAL_TLDS}
        labels = d.split(".")
        if labels[-1] in internal or d in internal:
            return False
        # #24: defense in depth — if the public-suffix list is available (extra 'psl'), an FQDN
        # with a non-public TLD (e.g. internal domain with a made-up TLD) is treated as non-public.
        if _registrable_or_none(d) is False:
            return False
        return True
    if kind == "hash":
        return True  # hashes identify the threat, not the client
    return False


def _guard(indicator: str, allow_egress: bool) -> dict | None:
    """Returns an error dict if the call is NOT allowed, otherwise None."""
    if not allow_egress:
        return {"error": "egress disabled: enrichment requires a network call. "
                         "Retry with allow_egress=True (public indicators only, never client data — §9/§15)."}
    if indicator_kind(indicator) == "unknown":
        return {"error": f"unrecognized indicator (expected IP/domain/hash): {indicator!r}. "
                         "Check the input: it is not a valid IP, well-formed domain, or valid hash."}
    if not is_public(indicator):
        return {"error": f"indicator is NOT public (client data?): {indicator!r}. "
                         "Private/reserved IPs and internal domains are not sent externally (§9)."}
    return None


def _get_json(url: str, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_json(url: str, payload: dict, headers: dict | None = None) -> dict:
    body = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def shodan_internetdb(ip: str, allow_egress: bool = False) -> dict:
    """Exposure of a public IP from Shodan InternetDB (keyless, free).
    Returns {ip, ports, hostnames, cpes, tags, vulns} or {error}."""
    blocked = _guard(ip, allow_egress)
    if blocked:
        return blocked
    if indicator_kind(ip) != "ip":
        return {"error": f"not an IP: {ip!r}"}
    try:
        data = _get_json(f"https://internetdb.shodan.io/{urllib.parse.quote(ip.strip(), safe='')}")
    except urllib.error.HTTPError as e:
        # 404 = IP not present in InternetDB: this is NOT an error, it's the normal "clean" response
        # (no known exposure). Must be distinguished from a real failure (5xx/timeout) to avoid
        # confusing triage. Returns empty exposure with an explicit flag.
        if e.code == 404:
            return {"ip": ip, "ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": [],
                    "no_data": True, "note": "no known exposure in Shodan InternetDB (404)"}
        return {"error": f"Shodan InternetDB failed (HTTPError {e.code}): {e}"}
    except Exception as e:
        return {"error": f"Shodan InternetDB failed ({type(e).__name__}): {e}"}
    return {"ip": ip, "ports": data.get("ports", []), "hostnames": data.get("hostnames", []),
            "cpes": data.get("cpes", []), "tags": data.get("tags", []), "vulns": data.get("vulns", [])}


def virustotal(indicator: str, allow_egress: bool = False, api_key: str | None = None) -> dict:
    """Reputation of a public IP/domain/hash from VirusTotal v3 (requires VT_API_KEY).
    No file upload: lookup only. Returns {indicator, kind, malicious, suspicious,
    harmless, undetected, reputation} or {error}."""
    blocked = _guard(indicator, allow_egress)
    if blocked:
        return blocked
    # Explicit argument > VT_API_KEY in the environment > the key stored once (GUI or CLI).
    key = api_key or eventhound_config.get_api_key("virustotal")
    if not key:
        return {"error": "VirusTotal key missing: set VT_API_KEY, or store it once "
                         "(GUI Settings, or `python tools/eventhound_config.py set virustotal`)."}
    kind = indicator_kind(indicator)
    path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}.get(kind)
    if not path:
        return {"error": f"indicator type not supported by VT: {indicator!r}"}
    try:
        data = _get_json(f"https://www.virustotal.com/api/v3/{path}/{urllib.parse.quote(indicator.strip(), safe='')}",
                         headers={"x-apikey": key})
    except urllib.error.HTTPError as e:
        # 404 = indicator not present in the VT dataset: "unknown", not a lookup failure.
        # Must be distinguished from 401 (wrong key) and 429 (rate limit), which have a different
        # triage meaning.
        if e.code == 404:
            return {"indicator": indicator, "kind": kind, "not_found": True}
        return {"error": f"VirusTotal failed (HTTP {e.code}): {e.reason}", "http_status": e.code}
    except Exception as e:
        return {"error": f"VirusTotal failed ({type(e).__name__}): {e}"}
    attr = (data.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    return {"indicator": indicator, "kind": kind,
            "malicious": stats.get("malicious"), "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"), "undetected": stats.get("undetected"),
            "reputation": attr.get("reputation")}


def threatfox(indicator: str, allow_egress: bool = False, api_key: str | None = None) -> dict:
    """Searches for a PUBLIC IP/domain/hash among known ThreatFox IOCs (abuse.ch, requires
    THREATFOX_API_KEY). Tells whether the indicator is an IOC linked to a malware family.
    Returns {indicator, kind, found, count, iocs:[{malware_printable, threat_type,
    confidence_level, first_seen, tags, reference}]}, {indicator, kind, not_found} or {error}."""
    blocked = _guard(indicator, allow_egress)
    if blocked:
        return blocked
    key = api_key or eventhound_config.get_api_key("threatfox")
    if not key:
        return {"error": "ThreatFox key missing: set THREATFOX_API_KEY, or store it once "
                         "(GUI Settings, or `python tools/eventhound_config.py set threatfox`)."}
    kind = indicator_kind(indicator)
    try:
        data = _post_json(
            "https://threatfox-api.abuse.ch/api/v1/",
            {"query": "search_ioc", "search_term": indicator.strip(), "exact_match": True},
            headers={"Auth-Key": key},
        )
    except urllib.error.HTTPError as e:
        # 401 = wrong key; 429 = rate limit — triage meanings distinct from a real failure.
        return {"error": f"ThreatFox failed (HTTP {e.code}): {e.reason}", "http_status": e.code}
    except Exception as e:
        return {"error": f"ThreatFox failed ({type(e).__name__}): {e}"}
    status = data.get("query_status")
    if status == "no_result":
        return {"indicator": indicator, "kind": kind, "not_found": True}
    if status != "ok":
        # e.g. 'illegal_search_term'/'illegal_query': input rejected by ThreatFox, not a match.
        return {"indicator": indicator, "kind": kind, "error": f"ThreatFox query_status={status!r}"}
    entries = data.get("data") or []
    iocs = [{"malware_printable": x.get("malware_printable") or x.get("malware"),
             "threat_type": x.get("threat_type"),
             "confidence_level": x.get("confidence_level"),
             "first_seen": x.get("first_seen"),
             "tags": x.get("tags") or [],
             "reference": x.get("reference")}
            for x in entries]
    return {"indicator": indicator, "kind": kind, "found": True, "count": len(iocs), "iocs": iocs}


def enrich(indicators: list[str], allow_egress: bool = False,
           use_shodan: bool = True, use_vt: bool = False, use_threatfox: bool = False) -> list[dict]:
    """Annotates a list of indicators. Non-public ones are skipped with a reason (never sent).
    Shodan for IP only; VT and ThreatFox for ip/domain/hash (if enabled and key present)."""
    out = []
    for ind in (indicators or []):
        if not isinstance(ind, str):
            out.append({"indicator": ind, "kind": "unknown", "public": False,
                        "skipped": "invalid indicator (expected str) — skipped"})
            continue
        kind = indicator_kind(ind)
        row: dict = {"indicator": ind, "kind": kind, "public": is_public(ind)}
        if not row["public"]:
            row["skipped"] = "not public (client data) — not sent externally (§9)"
            out.append(row); continue
        if use_shodan and kind == "ip":
            row["shodan"] = shodan_internetdb(ind, allow_egress=allow_egress)
        if use_vt:
            row["virustotal"] = virustotal(ind, allow_egress=allow_egress)
        if use_threatfox:
            row["threatfox"] = threatfox(ind, allow_egress=allow_egress)
        out.append(row)
    return out


FUNZIONI = {"shodan_internetdb": shodan_internetdb, "virustotal": virustotal,
            "threatfox": threatfox, "enrich": enrich}
