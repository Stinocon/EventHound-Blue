"""Test of extended correlation (analytics/correlate): temporal episodes + cross-source
indicators + families + timeline. Offline, on synthetic records in common schema (no real data).

Scenario: a web log and an EVTX share an IP a few seconds apart (SSRF→logon chain
SonicWall SMA style); a third isolated event later must NOT enter the episode.
    uv run python tests/test_correlation.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analytics import correlate, recipes, store  # noqa: E402

RECORDS = [
    # web log: SSRF wsproxy from attacker IP
    {"@timestamp": "2026-07-16T06:28:59Z", "event.source": "log:extraweb_access.log",
     "event.category": "web", "event.action": "http-request", "source.ip": "203.0.113.5",
     "url.original": "/wsproxy?serviceType=SSH", "http.response.status_code": 101},
    # EVTX: 11 seconds later, network logon from SAME IP (same window → correlated)
    {"@timestamp": "2026-07-16T06:29:10Z", "event.source": "evtx",
     "event.category": "authentication", "event.action": "logon", "event.code": 4624,
     "host.name": "DC-01", "source.ip": "203.0.113.5", "logon.type": "3",
     "attack.techniques": ["T1021.002"]},
    # isolated event much later: different episode, single source → excluded
    {"@timestamp": "2026-07-16T10:00:00Z", "event.source": "evtx",
     "event.category": "process", "event.code": 4688, "host.name": "DC-01",
     "process.name": "cmd.exe"},
    # no rule fired and no technique attached, but clearing the log IS the finding: the timeline
    # must keep it on the action alone
    {"@timestamp": "2026-07-16T10:05:00Z", "event.source": "evtx",
     "event.category": "configuration", "event.action": "audit-log-cleared",
     "event.code": 1102, "host.name": "DC-01"},
]


def run() -> int:
    con = store.from_records(RECORDS)
    try:
        shared = correlate.shared_indicators(con)
        eps = correlate.episodes(con, gap_seconds=120)
        tl_notable = correlate.timeline(con)
        tl_all = correlate.timeline(con, ip="203.0.113.5", notable=False)
    finally:
        con.close()

    # a dataset where nothing carries a signal: the timeline must fall back to context,
    # never come back empty
    con2 = store.from_records(RECORDS[2:3])
    try:
        tl_fallback = correlate.timeline(con2)
    finally:
        con2.close()

    # 1) the shared IP between log and evtx appears, with 2 distinct sources
    ip = next((r for r in shared if r["indicator"] == "203.0.113.5"), None)
    assert ip is not None, f"shared IP not detected: {shared}"
    assert ip["sources"] == 2, ip
    assert ip["kind"] == "ip"

    # 2) an episode linking 2 sources in the close window; 10:00 event is out
    linked = [e for e in eps if e["sources"] >= 2]
    assert linked, f"no cross-source episode: {eps}"
    e = linked[0]
    assert e["events"] == 2, e            # only two close events
    assert e["sources"] == 2, e
    assert e["duration_s"] <= 120, e

    # 3) the bridge names the tool FAMILIES that saw the address, not the qualified origins:
    #    `log:web.log` is one tool, and it is the family that decides corroboration.
    fams = {f.strip() for f in (ip["source_list"] or "").split(",") if f.strip()}
    assert fams == {"log", "evtx"}, f"unexpected families: {fams}"
    assert ip["source_list"] == "evtx, log", ip
    assert ip["origin_list"] == "evtx, log:extraweb_access.log", ip

    # 4) timeline: the technique event and the log clearing are notable, the plain cmd.exe is not,
    #    and each surviving row says which criterion kept it
    assert [r["why"] for r in tl_notable] == ["ATT&CK technique", "high-signal event type"], tl_notable
    assert tl_notable[0]["host"] == "DC-01", tl_notable[0]
    assert tl_notable[0]["kc_phase"], tl_notable[0]      # phase resolved from the technique

    # 5) unfiltered mode + IP filter: both events on that IP, chronologically
    assert [r["source"] for r in tl_all] == ["log:extraweb_access.log", "evtx"], tl_all
    assert all(r["why"] == "context" for r in tl_all[:1]), tl_all

    # 6) nothing notable -> context fallback instead of an empty view
    assert len(tl_fallback) == 1 and tl_fallback[0]["why"] == "context", tl_fallback

    print("PASS  correlation: cross-source indicators + temporal episode + families + timeline")
    return 0


# ── phase corroboration ───────────────────────────────────────────────────────────────────────
# The kill chain is derived from ATT&CK techniques and only the endpoint sources carry them, so the
# account of a multi-source incident was being told by the handful of records that had one. This
# adds the weaker, true claim — the other tools were active in the same window, and this is what
# they saw — and the thing that can go wrong with it is that it re-admits the noise the rest of the
# correlation excludes, which is what the first implementation did.
_PHASE_RECORDS = [
    # the endpoint evidence that establishes the phase
    {"@timestamp": "2026-07-20T10:00:00Z", "event.source": "evtx", "event.category": "process",
     "event.action": "process-create", "host.name": "WS-09", "process.name": "evil.exe",
     "attack.techniques": ["T1071.004"]},
    # the network, which carries no technique and must still be named
    {"@timestamp": "2026-07-20T10:00:30Z", "event.source": "pcap:capture.pcap",
     "event.category": "network", "host.name": "WS-09", "source.ip": "198.51.100.9",
     "source.port": 50100, "destination.ip": "203.0.113.99", "destination.port": 443,
     "dns.question.name": "cdn.evil.example"},
    # everything below is noise the correlation already excludes, and this view must too
    {"@timestamp": "2026-07-20T10:00:40Z", "event.source": "log:fw.log", "event.category": "network",
     "user.name": "WS-09$", "source.ip": "127.0.0.1", "destination.ip": "127.0.0.1"},
    {"@timestamp": "2026-07-20T10:00:50Z", "event.source": "log:fw.log", "event.category": "network",
     "user.name": "SYSTEM", "destination.ip": "10.0.0.1"},
    # far outside the window: must not be swept in
    {"@timestamp": "2026-07-20T18:00:00Z", "event.source": "crowdstrike",
     "event.category": "authentication", "event.action": "user-authentication",
     "user.name": "unrelated.person"},
    # a SECOND technique-carrying family, seconds away. It belongs to its own phase's evidence and
    # must never be quoted as another phase's corroboration: doing so relaunders the same handful
    # of endpoint records as breadth, which is the whole thing this view removes.
    {"@timestamp": "2026-07-20T10:00:20Z", "event.source": "yara", "event.category": "file",
     "event.action": "rule-match", "host.name": "WS-09", "file.name": "evil.exe",
     "attack.techniques": ["T1486"]},
]


def test_phase_corroboration() -> int:
    con = store.from_records(_PHASE_RECORDS)
    try:
        phases = correlate.killchain(con)
        assert phases, "no kill-chain phase to corroborate — the fixture lost its technique"
        correlate.phase_corroboration(con, phases, beaconing=[{"dst_ip": "203.0.113.99"}],
                                      infra_ips=["10.0.0.1"])
    finally:
        con.close()

    ph = phases[0]
    note = ph["corroboration"]
    # 1) the tool that carries no technique is named, with the signal it produced
    assert "pcap" in note, note
    assert "203.0.113.99" in note and "to validate" in note, note
    # 2) and it is a SIGNAL, not a technique: the phase's techniques are untouched
    assert ph["techniques"] == "T1071.004", ph["techniques"]
    # 3) the exclusions the correlation applies apply here too
    assert "yara" not in note, (
        f"a phase quoted another phase's technique-carrying evidence as corroboration: {note}")
    assert "127.0.0.1" not in note, f"loopback re-admitted as corroboration: {note}"
    assert "WS-09$" not in note and "SYSTEM" not in note, f"machine/service account named: {note}"
    assert "10.0.0.1" not in note, f"declared infrastructure named as corroboration: {note}"
    # 4) events eight hours away are not "in the same window"
    assert "crowdstrike" not in note, f"an event outside the window was swept in: {note}"
    # 5) the width of the claim is reported: "in the same window" over an hour is not the same
    #    statement as over half a minute, and the reader cannot weigh it without the number
    assert 0 < ph["corroboration_window_s"] <= 600, ph["corroboration_window_s"]

    # The assertions above are only worth their space if they can fail. Run the same view with the
    # infrastructure declaration withheld: the address must come back, which is what proves the
    # filter above is load-bearing rather than incidentally satisfied by this fixture.
    con2 = store.from_records(_PHASE_RECORDS)
    try:
        undeclared = correlate.killchain(con2)
        correlate.phase_corroboration(con2, undeclared, beaconing=[{"dst_ip": "203.0.113.99"}])
    finally:
        con2.close()
    assert "10.0.0.1" in undeclared[0]["corroboration"], (
        "withholding the infrastructure declaration changed nothing — the exclusion above is "
        "vacuous and this test measures nothing")

    # 6) the compact form the table renderers use is populated alongside the sentence
    assert "pcap" in ph["corroboration_families"], ph["corroboration_families"]
    assert "event(s)" not in ph["corroboration_families"], (
        "the families field must be names only — the sentence is unreadable in a table column")

    # 7) DETERMINISM. Event counts inside a short window tie constantly, and an ORDER BY without a
    # tie-break let two runs over identical evidence name different tools in the narrative.
    import random
    seen = set()
    for seed in range(6):
        shuffled = list(_PHASE_RECORDS)
        random.Random(seed).shuffle(shuffled)
        c = store.from_records(shuffled)
        try:
            ps = correlate.killchain(c)
            correlate.phase_corroboration(c, ps, beaconing=[{"dst_ip": "203.0.113.99"}],
                                          infra_ips=["10.0.0.1"])
            seen.add(tuple(p["corroboration_families"] for p in ps))
        finally:
            c.close()
    assert len(seen) == 1, f"corroboration depends on ingest order: {seen}"

    # 8) the infrastructure exclusion must survive whitespace. The store marks the value non-generic
    # on the stripped form, so an unstripped spelling passed the SQL filter and then evaded the
    # Python one — reachable through the generic log adapter's operator-supplied capture groups.
    padded = [dict(r) for r in _PHASE_RECORDS]
    for r in padded:
        if r.get("destination.ip") == "10.0.0.1":
            r["destination.ip"] = " 10.0.0.1 "
    c = store.from_records(padded)
    try:
        ps = correlate.killchain(c)
        correlate.phase_corroboration(c, ps, infra_ips=["10.0.0.1"])
        assert "10.0.0.1" not in ps[0]["corroboration"], (
            f"a padded spelling of the declared infrastructure evaded the exclusion: "
            f"{ps[0]['corroboration']}")
    finally:
        c.close()

    # 9) the NOT IN / NULL trap. A technique-carrying record with no event.source puts a NULL into
    # the "phase's own families" subquery, and `NOT IN` against a set holding one NULL is NULL for
    # every row — so the corroboration emptied itself for the WHOLE analysis, silently, while the
    # evidence sat in the store. The failure has no symptom other than an absence, which is exactly
    # the shape this view exists to remove.
    c = store.from_records([
        {"@timestamp": "2026-07-20T10:00:00Z", "event.category": "process",
         "event.action": "process-create", "host.name": "WS-09",
         "attack.techniques": ["T1071.004"]},            # a technique, and no source
        {"@timestamp": "2026-07-20T10:00:30Z", "event.source": "pcap:c.pcap",
         "event.category": "network", "host.name": "WS-09", "destination.ip": "203.0.113.99"},
    ])
    try:
        ps = correlate.killchain(c)
        correlate.phase_corroboration(c, ps, beaconing=[], infra_ips=[])
        assert "pcap" in ps[0]["corroboration"], (
            "one unnamed source emptied the corroboration for every phase: "
            f"{ps[0]['corroboration']!r}")
    finally:
        c.close()

    # and the outer half of the same trap: a record with no event.source must be REPORTED, not
    # silently dropped. The first fix excluded NULLs from the subquery and left the outer
    # comparison evaluating to NULL, which quietly discarded evidence in the one view built to
    # stop silent absences.
    c = store.from_records([
        {"@timestamp": "2026-07-20T10:00:00Z", "event.source": "evtx", "event.category": "process",
         "event.action": "process-create", "host.name": "WS-09",
         "attack.techniques": ["T1071.004"]},
        {"@timestamp": "2026-07-20T10:00:30Z", "event.category": "network", "host.name": "WS-09",
         "destination.ip": "203.0.113.99"},
    ])
    try:
        ps = correlate.killchain(c)
        correlate.phase_corroboration(c, ps, beaconing=[], infra_ips=[])
        assert "unnamed source" in ps[0]["corroboration"], (
            f"a record with no event.source was silently dropped: {ps[0]['corroboration']!r}")
    finally:
        c.close()

    # 10) `kc_phase IS NULL` was a PROXY for "carries no technique", and the two differ. The phase
    # is derived through the vendored offline ATT&CK map, so an ID the map cannot resolve — newer
    # than the snapshot, or vendor-specific — stores a NULL phase on a record that plainly carries
    # a technique. Under the proxy that detection landed in "these other tools were also active in
    # the window", which is the one sentence this view promises never to say about real evidence.
    unresolvable = [
        {"@timestamp": "2026-07-20T10:00:00Z", "event.source": "evtx", "event.category": "process",
         "event.action": "process-create", "host.name": "WS-09",
         "attack.techniques": ["T1071.004"]},
        {"@timestamp": "2026-07-20T10:00:30Z", "event.source": "crowdstrike",
         "event.category": "process", "event.action": "detection", "host.name": "WS-09",
         "destination.ip": "203.0.113.99", "attack.techniques": ["T9999.999"]},
    ]
    c = store.from_records(unresolvable)
    try:
        ps = correlate.killchain(c)
        assert c.execute("SELECT count(*) FROM events WHERE techniques = 'T9999.999' "
                         "AND kc_phase IS NULL").fetchone()[0] == 1, (
            "the fixture stopped exercising the case: T9999.999 now resolves to a phase")
        correlate.phase_corroboration(c, ps, beaconing=[], infra_ips=[])
        assert "crowdstrike" not in ps[0]["corroboration"], (
            "a record carrying an unresolvable technique was rendered as a tool that merely "
            f"co-occurred: {ps[0]['corroboration']!r}")
    finally:
        c.close()
    # and the mutation that proves the assertion is not vacuous: strip the technique and the same
    # record must come back, because then it really is a tool that was only also active.
    silent = [dict(r) for r in unresolvable]
    silent[1].pop("attack.techniques")
    c = store.from_records(silent)
    try:
        ps = correlate.killchain(c)
        correlate.phase_corroboration(c, ps, beaconing=[], infra_ips=[])
        assert "crowdstrike" in ps[0]["corroboration"], (
            "removing the technique changed nothing — the check above measures nothing: "
            f"{ps[0]['corroboration']!r}")
    finally:
        c.close()

    # 11) the same proxy in the sibling view. `host_killchain` counted "attack events" with
    # `kc_phase IS NOT NULL` and filtered on it too, so a host whose only detection carried an
    # unresolvable ID vanished from the list that decides who gets looked at first.
    c = store.from_records([
        {"@timestamp": "2026-07-20T10:00:00Z", "event.source": "evtx", "event.category": "process",
         "event.action": "process-create", "host.name": "WS-01",
         "attack.techniques": ["T1071.004"]},
        {"@timestamp": "2026-07-20T10:05:00Z", "event.source": "crowdstrike",
         "event.category": "process", "event.action": "detection", "host.name": "WS-02",
         "attack.techniques": ["T9999.999"]},
        {"@timestamp": "2026-07-20T10:06:00Z", "event.source": "pcap:c.pcap",
         "event.category": "network", "host.name": "WS-03", "destination.ip": "203.0.113.99"},
    ])
    try:
        # keyed by host_canon, which is the lower-cased form
        hosts = {h["host"]: h for h in correlate.host_killchain(c)}
        assert "ws-01" in hosts, hosts
        assert "ws-02" in hosts, (
            "a host whose only detection carries an unresolvable technique disappeared from the "
            f"triage list: {sorted(hosts)}")
        assert hosts["ws-02"]["attack_events"] == 1, hosts["ws-02"]
        assert hosts["ws-02"]["max_order"] == 0 and hosts["ws-02"]["phases_covered"] == 0, hosts["ws-02"]
        assert hosts["ws-02"]["deepest_phase"] == correlate.UNMAPPED_PHASE, hosts["ws-02"]
        # it ranks BELOW the host with real depth: the list is still the triage order
        assert [h["host"] for h in correlate.host_killchain(c)][:2] == ["ws-01", "ws-02"], \
            correlate.host_killchain(c)
        # and a host carrying no technique at all is still out: this widens the view, not empties it
        assert "ws-03" not in hosts, f"a host with no detection at all entered the list: {sorted(hosts)}"
    finally:
        c.close()

    # 12) THE PROXY, THIRD TIME. R6 caught the fix in 11 breaking what it did not break before:
    # `kc_phase IS NOT NULL` and `techniques <> ''` are each a PROXY for "carries ATT&CK evidence"
    # and each misses what the other catches. 345 of the 3142 vendored SigmaHQ rules declare a
    # TACTIC and no technique ID, so `store._attack_of` resolves their phase while `techniques`
    # stays NULL — and the second proxy deleted those hosts from triage and quoted a phase's own
    # establishing detection as another phase's corroboration. The question now lives in ONE place
    # (`store.attack_evidence`) and this pins all three inputs to it.
    tactic_only = {"@timestamp": "2026-07-20T09:00:00Z", "event.source": "evtx",
                   "event.category": "process", "event.action": "process-create",
                   "host.name": "WS-07", "rule.name": "Suspicious LSASS access",
                   "attack.tactics": ["Credential Access"]}          # a phase, and NO technique id
    unresolvable = {"@timestamp": "2026-07-20T09:00:30Z", "event.source": "crowdstrike",
                    "event.category": "process", "event.action": "detection", "host.name": "WS-07",
                    "attack.techniques": ["T9999.999"]}              # an id, and NO phase
    prose = {"@timestamp": "2026-07-20T09:01:00Z", "event.source": "yara", "event.category": "file",
             "event.action": "rule-match", "host.name": "WS-07", "file.name": "x.dll",
             "attack.techniques": ["Credential Access"]}             # free text in the id field
    silent = {"@timestamp": "2026-07-20T09:01:30Z", "event.source": "pcap:c.pcap",
              "event.category": "network", "host.name": "WS-07", "destination.ip": "203.0.113.9"}
    c = store.from_records([tactic_only, unresolvable, prose, silent])
    try:
        got = dict(c.execute("SELECT coalesce(source, '?'), attack_evidence FROM events").fetchall())
        assert got == {"evtx": True, "crowdstrike": True, "yara": False, "pcap:c.pcap": False}, got
        # a declared tactic IS the phase, and the record carrying it is not "also active"
        ps = correlate.killchain(c)
        correlate.phase_corroboration(c, ps, beaconing=[], infra_ips=[])
        for ph in ps:
            assert "evtx" not in ph["corroboration"], (
                f"the detection that establishes a phase was quoted as another phase's "
                f"corroboration: {ph['phase']} -> {ph['corroboration']!r}")
            assert "crowdstrike" not in ph["corroboration"], ph["corroboration"]
        # ...while free text in the technique field is NOT evidence, and stays a silent tool
        assert any("yara" in ph["corroboration"] for ph in ps), (
            f"a YARA rule tagged with prose was mistaken for ATT&CK evidence: "
            f"{[p['corroboration'] for p in ps]}")
        assert any("pcap" in ph["corroboration"] for ph in ps), [p["corroboration"] for p in ps]
        # ...and it is not laundered into the technique catalogue or the frequency recipe either
        assert [t["technique"] for t in correlate.technique_catalog(c)] == ["T9999.999"], \
            correlate.technique_catalog(c)
        assert [t["technique"] for t in recipes.technique_frequency(c)] == ["T9999.999"], \
            recipes.technique_frequency(c)
        # the host is present, counted on both kinds of evidence, and timed from the FIRST of them
        hosts = correlate.host_killchain(c)
        assert len(hosts) == 1 and hosts[0]["host"] == "ws-07", hosts
        assert hosts[0]["attack_events"] == 2, (
            f"a tactic-only detection stopped counting as an ATT&CK event: {hosts[0]}")
        assert hosts[0]["first_seen"].startswith("2026-07-20T09:00"), (
            f"first_seen skipped the earliest evidence: {hosts[0]}")
        assert hosts[0]["deepest_phase"] == "Exploitation" and hosts[0]["max_order"] == 4, hosts[0]
    finally:
        c.close()
    # and the mutation: with ONLY the tactic-only record, the host must still be in the list. This
    # is the assertion the committed fix failed — it returned [].
    c = store.from_records([tactic_only])
    try:
        hosts = correlate.host_killchain(c)
        assert [h["host"] for h in hosts] == ["ws-07"], (
            f"a host whose only detection declares a tactic and no technique id vanished from "
            f"the triage list: {hosts}")
    finally:
        c.close()

    print("PASS  correlation: phase corroboration names the silent tools and keeps the noise out")
    return 0


def test_correlation():
    run()


if __name__ == "__main__":
    raise SystemExit(run() or test_phase_corroboration())
