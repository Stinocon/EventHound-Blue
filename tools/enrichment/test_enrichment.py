"""Enrichment tests — FULLY OFFLINE (no network calls).

Verifies the two core constraints (§9/§15) without touching the network: egress gate and blocking
of non-public indicators (client data). Assertions only use paths that return BEFORE any
urlopen (egress off, private indicator, VT key missing).
Usage: uv run python test_enrichment.py
"""
import sys

import enrichment as e


def main() -> None:
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # classification
    check(e.indicator_kind("8.8.8.8") == "ip", "8.8.8.8 should be ip")
    check(e.indicator_kind("evil.example.com") == "domain", "domain not recognized")
    check(e.indicator_kind("a" * 64) == "hash", "sha256 not recognized")
    check(e.indicator_kind("non valido") == "unknown", "expected unknown")

    # public vs client data (§9)
    check(e.is_public("8.8.8.8") is True, "public IP should be public")
    check(e.is_public("10.0.0.5") is False, "RFC1918 IP must NOT be public")
    check(e.is_public("192.168.1.1") is False, "192.168/16 NOT public")
    check(e.is_public("127.0.0.1") is False, "loopback NOT public")
    check(e.is_public("corp.local") is False, "internal .local domain NOT public")
    check(e.is_public("acme.example") is False, ".example domain (anonymized) NOT public")
    check(e.is_public("malware.example.com") is True, "public domain should be public")
    check(e.is_public("d41d8cd98f00b204e9800998ecf8427e") is True, "hash should be public")

    # §9 GUARD BYPASS (super-debug regression): a private IP / internal host with a non-host
    # suffix (path, port, '#', '%', space) must NOT be classified 'domain' nor come out as
    # public — otherwise it would end up at VirusTotal/Shodan. These cases failed with the loose check.
    for bad in ("10.0.0.5/foo", "192.168.1.1/path", "10.0.0.5#x", "dc01.internal/x",
                "fileserver.corp?a=b", "host.lan:8080", "internal.corp.local/etc/passwd",
                "http://internal.corp.local/path", "a.local%0d",
                "192.168.1.1.", "10.0.0.5.", "127.0.0.1."):
        check(e.indicator_kind(bad) != "domain", f"{bad!r} must NOT be classified as domain")
        check(e.is_public(bad) is False, f"{bad!r} must NOT come out as public (§9 bypass)")

    # reserved/multicast/link-local IPs are not external indicators: NOT public (over-egress)
    check(e.is_public("224.0.0.1") is False, "multicast NOT public")
    check(e.is_public("169.254.1.1") is False, "link-local NOT public")
    check(e.is_public("0.0.0.0") is False, "unspecified NOT public")

    # internal IPv6: ULA (fc00::/7) and link-local (fe80::/10) not public; fec0::/10 is DEPRECATED
    # site-local (RFC 3879) which ipaddress erroneously reports as is_global=True (§9 bypass).
    check(e.is_public("fec0::1") is False, "IPv6 site-local fec0::/10 NOT public (§9 bypass)")
    check(e.is_public("fd00::1") is False, "IPv6 ULA fd00::/8 NOT public")
    check(e.is_public("fc00::1") is False, "IPv6 ULA fc00::/7 NOT public")
    check(e.is_public("fe80::1") is False, "IPv6 link-local NOT public")

    # malformed IPv4: all-numeric labels must NOT pass as 'domain' (would be sent to VT)
    check(e.indicator_kind("999.999.999.999") != "domain", "malformed IPv4 must NOT be domain")
    check(e.indicator_kind("1.2") != "domain", "'1.2' must NOT be domain")

    # #24 defense in depth: with the 'psl' extra (tldextract) an FQDN whose TLD is not a real
    # public suffix (internal domain with a made-up TLD) must NOT come out as public. If the extra
    # is not installed, the check is skipped (optional behavior, like YARA).
    try:
        import tldextract  # noqa: F401
        has_psl = True
    except Exception:
        has_psl = False
    if has_psl:
        check(e.is_public("dc01.acmecorp") is False, "FQDN with made-up TLD NOT public (#24, psl)")
        check(e.is_public("fileserver.acme") is False, "made-up internal TLD NOT public (#24, psl)")
        check(e.is_public("evil.example.com") is True, "real public domain stays public (#24, psl)")
        check(e.is_public("host.co.uk") is True, "compound public suffix stays public (#24, psl)")

    # egress gate: default OFF -> error, no network
    check("error" in e.shodan_internetdb("8.8.8.8"), "egress off: shodan should give error")
    check("error" in e.virustotal("8.8.8.8"), "egress off: VT should give error")

    # egress ON but PRIVATE indicator -> blocked by the guard BEFORE the network (§9)
    r = e.shodan_internetdb("10.0.0.5", allow_egress=True)
    check("error" in r and "public" in r["error"].lower(), "private IP must be blocked even with egress")

    # egress ON, public indicator, but without VT_API_KEY -> key error (no network)
    import os
    os.environ.pop("VT_API_KEY", None)
    r = e.virustotal("8.8.8.8", allow_egress=True)
    check("error" in r and "VT_API_KEY" in r["error"], "without VT key, expected key error")

    # ThreatFox: same core constraints (§9/§15), all offline
    check("error" in e.threatfox("8.8.8.8"), "egress off: threatfox should give error")
    r = e.threatfox("10.0.0.5", allow_egress=True)
    check("error" in r and "public" in r["error"].lower(), "private IP blocked even with egress (threatfox)")
    os.environ.pop("THREATFOX_API_KEY", None)
    r = e.threatfox("8.8.8.8", allow_egress=True)
    check("error" in r and "THREATFOX_API_KEY" in r["error"], "without ThreatFox key, expected key error")

    # enrich: private skipped (never sent), public marked as public
    rows = e.enrich(["10.0.0.5", "8.8.8.8"], allow_egress=False)
    priv = next(x for x in rows if x["indicator"] == "10.0.0.5")
    pub = next(x for x in rows if x["indicator"] == "8.8.8.8")
    check(priv.get("skipped") and not priv["public"], "private IP must be skipped in enrich")
    # the shodan attempt must be present BUT, with egress off, must be the gate error (no
    # network): it's not enough that the 'shodan' key exists — the sub-result must prove the gate held
    check(pub["public"] and "shodan" in pub, "public IP must have the shodan attempt")
    check("error" in pub["shodan"] and "egress" in pub["shodan"]["error"].lower(),
          "enrich with egress off: shodan must be the gate error, not network data (§15)")

    # enrich with use_threatfox: the attempt is there but with egress off it must be the gate error
    pub_tf = e.enrich(["8.8.8.8"], allow_egress=False, use_threatfox=True)[0]
    check("threatfox" in pub_tf and "error" in pub_tf["threatfox"]
          and "egress" in pub_tf["threatfox"]["error"].lower(),
          "enrich use_threatfox with egress off: gate error, no network (§15)")

    # non-str indicator in the batch: skipped, does not crash the whole enrich
    rows2 = e.enrich(["8.8.8.8", None, 123], allow_egress=False)
    check(any(r.get("skipped", "").startswith("invalid indicator") for r in rows2),
          "enrich must skip non-str indicators without aborting the batch")

    if fails:
        print("FAIL enrichment:")
        for f in fails:
            print("   -", f)
        sys.exit(1)
    print("PASS  enrichment: classification, public/private guard (§9), egress gate (§15), "
          "enrich (shodan/vt/threatfox)")


if __name__ == "__main__":
    main()
