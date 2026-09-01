"""Cross-source correlation and timeline on records in DuckDB (Phase 2).

The common schema exists precisely for this: mapping EVTX, PCAP, CrowdStrike, ... to uniform fields
enables correlation "across tools" by host, user, IP, time (DESIGN §1, §5).
"""
from __future__ import annotations

import datetime as _dt

from . import attack, normalize
from .recipes import _rows


def _iso(v):
    """A timestamp as the ISO string every consumer expects, whatever the query handed back.

    DuckDB returns a `datetime` for a TIMESTAMP column, and three consumers serialise these dicts
    with plain `json.dumps` (the GUI's SSE completion, the case endpoint, the exported bundle), so a
    datetime is a TypeError rather than a result. It was already being coerced inline in `episodes`;
    it is here now because the kill-chain views need exactly the same coercion, and two spellings of
    one rule is how they come to disagree (§16.3)."""
    return v.strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(v, "strftime") else v


def _earlier(a, b):
    """The earlier of two timestamps, either of which may be None (a record whose ts did not parse)."""
    return b if a is None else (a if b is None else min(a, b))


def _later(a, b):
    return b if a is None else (a if b is None else max(a, b))


# Event actions that belong on a triage timeline even when no rule fired on them. They come from the
# project's Event ID SOT vocabulary (adapters/windows_eventid.py) and are the DFIR triage canon:
# audit tampering, persistence installation, privileged identity changes, thread injection, failed
# authentication. Without this, a full EVTX stream where Hayabusa found nothing would drop the log
# clearing that *is* the finding.
# Deliberately NOT in the list, because they fire constantly and would crowd the cap: process-create,
# named-pipe-created, image-loaded, driver-loaded, scriptblock-logging, and logon-explicit-credentials
# (4648 — high value, but routine on many hosts; the Sigma rules cover its malicious shapes).
_NOTABLE_ACTIONS = (
    "audit-log-cleared", "event-log-cleared", "audit-policy-changed",
    "event-log-service-stopped", "sysmon-config-changed", "process-tampering", "raw-access-read",
    "service-installed", "scheduled-task-created", "scheduled-task-registered",
    "wmi-event-consumer", "wmi-event-filter", "wmi-consumer-filter-binding",
    "wmi-permanent-consumer-registered", "wmi-permanent-consumer-binding",
    "user-account-created", "member-added-to-local-group", "member-added-to-global-group",
    "member-added-to-universal-group", "password-reset",
    "create-remote-thread", "logon-failed", "kerberos-preauth-failed",
)
_NOTABLE_ACTIONS_SQL = "[" + ", ".join(f"'{a}'" for a in _NOTABLE_ACTIONS) + "]"

# Which events earn a place in the unified timeline, and the reason shown beside each row.
# A chronological cap over *everything* returns the first N rows of the file — boot noise, not the
# incident — so the timeline is salience-filtered and always states WHY a row is in it. The order of
# the CASE branches decides only which label wins when several apply; it is NOT a severity score
# (that is the oracle's job, §6) and it never reorders the timeline, which stays strictly temporal.
_TIMELINE_WHY = """
    CASE
        WHEN coalesce(attack_evidence, false) THEN 'ATT&CK technique'
        WHEN lower(coalesce(rule_level, '')) IN ('critical', 'high')
            THEN 'Sigma ' || lower(rule_level)
        WHEN list_contains(""" + _NOTABLE_ACTIONS_SQL + """, action) THEN 'high-signal event type'
        WHEN source LIKE 'thor%' AND coalesce(action, '') <> 'thor-linked' THEN 'THOR finding'
        WHEN lower(coalesce(outcome, '')) = 'failure' THEN 'failed action'
    END
"""

_TIMELINE_COLS = """
    id, ts, source, category, action, event_code, outcome, host, user_name,
    process_name, parent_name, cmdline, src_ip, dst_ip, dst_port, dns_query,
    file_name, url, techniques, kc_phase, rule_title, rule_level
"""


def timeline(con, host: str | None = None, user: str | None = None, ip: str | None = None,
             limit: int = 200, notable: bool = True) -> list[dict]:
    """Events in chronological order, filterable by host/user/IP. Unified multi-source view.

    `notable=True` (default) keeps only the events that carry a signal — an ATT&CK technique, a
    high/critical Sigma hit, a THOR finding, a failed action — each tagged with `why`. On a dataset
    where nothing is notable (e.g. a PCAP with no detections) it falls back to the plain
    chronological head, labelled `context`, so the view is never mysteriously empty.
    """
    conds, params = [], []
    if host:
        conds.append("host = ?"); params.append(host)
    if user:
        conds.append("user_name = ?"); params.append(user)
    if ip:
        conds.append("(src_ip = ? OR dst_ip = ?)"); params += [ip, ip]
    if notable:
        conds.append(f"({_TIMELINE_WHY}) IS NOT NULL")
    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    rows = _rows(con, f"""
        SELECT {_TIMELINE_COLS}, ({_TIMELINE_WHY}) AS why
        FROM events {where}
        ORDER BY ts_parsed NULLS LAST, id
        LIMIT ?
    """, params + [limit])
    if notable and not rows:
        return timeline(con, host=host, user=user, ip=ip, limit=limit, notable=False)
    for r in rows:
        r["why"] = r.get("why") or "context"
    return rows


def host_overview(con) -> list[dict]:
    """Summary per host: volume, distinct users, techniques observed, network destinations.

    Grouped on `host_canon`, like every other view that counts hosts. Grouping on the raw spelling
    split one machine into `WS-11`, `ws-11` and `ws-11.corp.example` — three rows of one host, on
    the same page as the table whose purpose is to state that they are one, and immediately above
    `host_killchain`, which had always grouped canonically and therefore disagreed. The raw
    spellings are not lost: `shared_indicators` reports them as the evidence for the match."""
    return _rows(con, """
        SELECT host_canon AS host,
               count(*) AS events,
               count(DISTINCT user_canon) AS users,
               count(DISTINCT process_name) AS processes,
               count(DISTINCT dst_ip) AS net_dsts,
               count(DISTINCT CASE WHEN coalesce(attack_evidence, false) THEN id END) AS detections
        FROM events WHERE host_canon IS NOT NULL
        GROUP BY host_canon ORDER BY detections DESC, events DESC, host_canon
    """)


# Union of correlatable indicators extracted from EVERY record, with the tool family it came from
# and the origin (the qualified label, file-level where the adapter provides one).
#
# The bridge is counted per FAMILY — "how many independent tools saw this" — not per origin. Doing
# it per origin was wrong in both directions at once: two PCAPs from the same capture point counted
# as two corroborating tools and inflated confidence, while ten EVTX files collected from ten hosts
# all carried the bare label `evtx` and so could never corroborate each other at all. The origin is
# carried alongside and reported, so "which file" is never lost. Pivots: IP (src/dst), DNS domain,
# user, host, hash, and file/artifact name.
# `indicator` is the CANONICAL key; `raw` keeps the original spelling; `realm` carries the domain an
# identity was spelled with (NULL where the concept doesn't apply). user/host/file are normalized in
# store.py so an entity spelled differently by different tools (CORP\alice vs alice@corp.example;
# DC1 vs dc1.corp.example; C:\Temp\evil.exe vs evil.exe) still joins, and hashes/DNS names are
# case-canonical there too.
#
# Everything ubiquitous is excluded, because a bridge on it is not a link but noise that connects
# every source to every other: machine/service accounts (SYSTEM, DC1$), loopback/link-local/
# multicast/invalid IPs, reverse-lookup and infrastructure DNS names, and system binaries
# (svchost.exe & co). All of it stays queryable in the timeline — this only governs correlation.
_INDICATORS_CTE = """
    WITH ind AS (
        SELECT src_ip AS indicator, src_ip AS raw, 'ip' AS kind, NULL AS realm,
               coalesce(family, source) AS family, source AS origin FROM events
            WHERE src_ip IS NOT NULL AND NOT coalesce(src_ip_generic, false)
        UNION ALL SELECT dst_ip, dst_ip, 'ip', NULL, coalesce(family, source), source FROM events
            WHERE dst_ip IS NOT NULL AND NOT coalesce(dst_ip_generic, false)
        UNION ALL SELECT dns_query, dns_query, 'domain', NULL, coalesce(family, source), source FROM events
            WHERE dns_query IS NOT NULL AND NOT coalesce(dns_generic, false)
        UNION ALL SELECT user_canon, user_name, 'user', user_domain, coalesce(family, source), source FROM events
            WHERE user_canon IS NOT NULL AND NOT coalesce(user_generic, false)
        UNION ALL SELECT host_canon, host, 'host', host_domain, coalesce(family, source), source FROM events
            WHERE host_canon IS NOT NULL AND NOT coalesce(host_generic, false)
        UNION ALL SELECT file_hash, file_hash, 'file_hash', NULL, coalesce(family, source), source FROM events
            WHERE file_hash IS NOT NULL
        UNION ALL SELECT file_hash_md5, file_hash_md5, 'file_hash', NULL, coalesce(family, source), source FROM events
            WHERE file_hash_md5 IS NOT NULL
        UNION ALL SELECT file_canon, coalesce(file_name, file_path), 'file', NULL,
               coalesce(family, source), source FROM events
            WHERE file_canon IS NOT NULL AND NOT coalesce(file_generic, false)
    )
"""


# Correlation-strength heuristic (NOT a security score — that's the oracle's job, §6).
#
# The rule, in one line: **the kind of entity sets the band, corroboration orders within the band,
# and only a penalty can drop you out of it.** A shared hash is a strong bridge (a unique artifact);
# a shared address is weak (proxies, NAT and infrastructure are shared by everything); a normalized
# identity match is solid but slightly softer than an exact one.
#
# The previous scale summed a kind weight topping out at 1.0 with a corroboration bonus of up to
# 0.3 and then clamped the result to 1.0 — so every strong bridge saturated. On the simulated
# incident the hash bridge (1.0 + 0.1) and the account bridge (0.85 + 0.3 - 0.1) both came out at
# exactly 1.00 / high, and the tie was then broken by the number of families: the ACCOUNT was
# ranked above the HASH, which is the reverse of the hierarchy this module documents and the demo
# was built to show. The bands below cannot saturate and cannot be crossed by corroboration alone,
# so the documented order is now a property of the arithmetic rather than a hope about it.
#
# Note the order of `host` and `domain`: it is the reverse of what it used to be in this table, and
# matches what the docstring below, the in-app Help and docs/analysis/correlation.md all already
# said. Two tools naming the same MACHINE is a more specific claim than two tools naming the same
# DNS name, which every host on the estate may legitimately resolve.
_KIND_WEIGHT = {"file_hash": 0.85, "user": 0.70, "host": 0.55, "domain": 0.40, "file": 0.25, "ip": 0.10}

# 1.00 is deliberately unreachable: this is a heuristic that ranks leads, and a bridge printed at
# "1.00" reads as certainty to whoever quotes the report (§6).
_MAX_CORROBORATION = 0.10       # at most two thirds of a band: never enough to overtake the one above
_PENALTY_AMBIGUOUS = 0.30       # two bands down: an ambiguous bridge must never outrank a certain one
_PENALTY_NORMALIZED = 0.05      # within the band: below an exact match of the same kind
_PENALTY_INFRASTRUCTURE = 0.30


def _confidence(row: dict) -> tuple[float, str]:
    """The confidence of a bridge, and the arithmetic that produced it, in words.

    Returns `(confidence, why)`. The second half is not decoration: a number an analyst cannot
    take apart is a number they either over-trust or ignore, and this one decides reading order."""
    kind = row.get("kind")
    base = _KIND_WEIGHT.get(kind, 0.25)
    families = int(row.get("families", 2))
    # A third tool is worth half the bonus, a fourth the rest. Corroboration orders bridges of the
    # same kind; it deliberately cannot promote one kind above another.
    boost = min(max(families - 2, 0) * 0.05, _MAX_CORROBORATION)
    parts = [f"{kind} bridge {base:.2f}"]
    if boost:
        parts.append(f"+{boost:.2f} for {families} corroborating tools")

    penalty = 0.0
    mt = row.get("match_type")
    if mt == "ambiguous":
        # Same account name, irreconcilable realms: it may well be two different principals. Still
        # shown — hiding it would lose a real lead — but never above a bridge that is certain.
        penalty += _PENALTY_AMBIGUOUS
        parts.append(f"-{_PENALTY_AMBIGUOUS:.2f} ambiguous (same name, different realms)")
    elif mt == "normalized":
        penalty += _PENALTY_NORMALIZED
        parts.append(f"-{_PENALTY_NORMALIZED:.2f} spellings had to be normalized")
    # An address the analyst declared as infrastructure — the gateway, the resolver, the proxy, the
    # VPN concentrator — is shared by everything on the network, so it is a bridge in form only.
    # Demoted rather than dropped: sometimes the proxy IS where the interesting thing happened, and
    # deleting the row would take that lead away silently.
    if row.get("infrastructure"):
        penalty += _PENALTY_INFRASTRUCTURE
        parts.append(f"-{_PENALTY_INFRASTRUCTURE:.2f} declared infrastructure")
    return round(max(0.0, min(1.0, base + boost - penalty)), 2), " · ".join(parts)


def _infra_set(infra_ips) -> set:
    """Declared infrastructure addresses, canonicalized for comparison.

    Deliberately a declaration and not a guess: `normalize.is_generic_ip` can rule out loopback,
    link-local, multicast and reserved space because those are wrong by construction, but a gateway
    is a perfectly ordinary unicast address and nothing in the data says which one it is. Only the
    analyst knows, so only the analyst can say — and the case remembers it."""
    return {str(v).strip().lower() for v in (infra_ips or []) if str(v or "").strip()}


# Cut on the band boundaries so the label means something concrete: high = a shared artifact or a
# shared identity, medium = a shared machine or name, low = a shared filename or address.
def _conf_label(c: float) -> str:
    return "high" if c >= 0.70 else ("medium" if c >= 0.40 else "low")


def shared_indicators(con, infra_ips=None) -> list[dict]:
    """Indicators (IP, domain, user, host, hash, file) present in MULTIPLE source families:
    the cross-source correlation bridge (e.g. an IP in both EVTX and web logs, or the same user
    seen by Okta and EVTX under different spellings). `variants` lists the raw forms merged;
    `match_type` is 'normalized' when >1 spelling collapsed (auditable). `confidence`/`confidence_label`
    rank bridges by strength (hash > identity > host > domain > file > IP), so the analyst reads the
    solid links first instead of noisy shared infrastructure."""
    rows = _rows(con, _INDICATORS_CTE + """
        SELECT indicator, kind,
               count(DISTINCT family) AS families,
               count(DISTINCT family) AS sources,   -- back-compat alias (same value as families)
               string_agg(DISTINCT family, ', ' ORDER BY family) AS source_list,
               string_agg(DISTINCT origin, ', ' ORDER BY origin) AS origin_list,
               string_agg(DISTINCT raw, ' | ' ORDER BY raw) AS variants,
               string_agg(DISTINCT realm, ', ' ORDER BY realm) AS realms,
               CASE WHEN count(DISTINCT raw) > 1 THEN 'normalized' ELSE 'exact' END AS match_type,
               count(*) AS occurrences
        FROM ind
        GROUP BY indicator, kind
        HAVING count(DISTINCT family) > 1
    """)
    infra = _infra_set(infra_ips)
    for r in rows:
        if r["kind"] == "ip" and str(r["indicator"]).strip().lower() in infra:
            r["infrastructure"] = True
            r["ambiguity"] = ("declared infrastructure (gateway/proxy/resolver): shared by every "
                              "host on the network, so this is a bridge in form only")
        realms = [x.strip() for x in (r.get("realms") or "").split(",") if x.strip()]
        r["realms"] = ", ".join(sorted(set(realms)))
        if normalize.realms_conflict(realms):
            # Same name, different realm: report it as a *candidate*, not as an established link.
            r["match_type"] = "ambiguous"
            r["ambiguity"] = f"same {r['kind']} name in different realms ({r['realms']}) — verify before treating as one entity"
        r["confidence"], r["confidence_why"] = _confidence(r)
        r["confidence_label"] = _conf_label(r["confidence"])
    # A total order. `confidence` is a rounded two-decimal heuristic, so ties are the normal case
    # rather than the exception, and everything below the tie was previously decided by whatever
    # order DuckDB grouped the rows in — while run_eval asserts POSITIONS in this very list. The
    # kind and the indicator make the order reproducible; both are ascending, so the sort cannot
    # use reverse= and negates the descending keys instead.
    # Ties are the normal case, not the exception: `confidence` is rounded to two decimals. What
    # breaks them has to mean something — the stronger KIND first (by its own band weight, not by
    # the alphabet, which only happened to agree), then the indicator, so the order is reproducible.
    # Everything below the tie used to be decided by whatever order DuckDB grouped the rows in,
    # while run_eval asserts POSITIONS in this very list.
    rows.sort(key=lambda r: (-r["confidence"], -r["families"], -r["occurrences"],
                             -_KIND_WEIGHT.get(r["kind"], 0.25), str(r["indicator"])))
    return rows


def episodes(con, gap_seconds: int = 120, min_sources: int = 2, limit: int = 100) -> list[dict]:
    """Temporal clusters (episodes) linking MULTIPLE source files in the same window.

    Bucketing by *session-gap*: consecutive events (time-ordered) within `gap_seconds` belong
    to the same episode; a larger gap opens a new episode. Only episodes covering ≥ `min_sources`
    distinct source files are kept — the "these events from different sources are correlated" signal."""
    rows = _rows(con, """
        WITH ordered AS (
            SELECT id, ts_parsed, coalesce(family, source) AS family, host, src_ip, dst_ip, kc_phase, kc_order,
                   CASE WHEN lag(ts_parsed) OVER (ORDER BY ts_parsed, id) IS NULL
                          OR epoch(ts_parsed) - epoch(lag(ts_parsed) OVER (ORDER BY ts_parsed, id)) > ?
                        THEN 1 ELSE 0 END AS newgrp
            FROM events WHERE ts_parsed IS NOT NULL
        ),
        grp AS (
            SELECT *, sum(newgrp) OVER (ORDER BY ts_parsed, id ROWS UNBOUNDED PRECEDING) AS episode
            FROM ordered
        )
        SELECT min(ts_parsed) AS start_ts, max(ts_parsed) AS end_ts,
               round(epoch(max(ts_parsed)) - epoch(min(ts_parsed)), 1) AS duration_s,
               count(*) AS events,
               count(DISTINCT family) AS families,
               count(DISTINCT family) AS sources,   -- back-compat alias (same value as families)
               string_agg(DISTINCT family, ', ' ORDER BY family) AS source_list,
               count(DISTINCT host) AS hosts,
               count(DISTINCT coalesce(src_ip, dst_ip)) AS ips,
               max(kc_order) AS kc_depth,
               string_agg(DISTINCT kc_phase, ' | ' ORDER BY kc_phase) AS phase_blob
        FROM grp
        GROUP BY episode
        HAVING count(DISTINCT family) >= ?
        ORDER BY start_ts
        LIMIT ?
    """, [gap_seconds, min_sources, limit])
    # An episode is a *time* bridge; naming the phases it covers turns "these events are correlated"
    # into "this window is Delivery → Installation", which is what goes into the incident narrative.
    for r in rows:
        phases = [p for p in (r.pop("phase_blob", "") or "").split(" | ") if p]
        r["kc_phases"] = " → ".join(sorted(phases, key=lambda p: attack.PHASE_ORDER.get(p, 0)))
        r["kc_depth"] = r.get("kc_depth") or 0
        # `min(ts_parsed)` comes back as a datetime and three consumers serialise this dict with
        # plain json.dumps, so it has to be coerced — see `_iso`, which is now shared with the
        # kill-chain views that had the same need and were reading the raw VARCHAR to avoid it.
        for key in ("start_ts", "end_ts"):
            r[key] = _iso(r.get(key))
    return rows


def killchain(con, limit_examples: int = 6) -> list[dict]:
    """Kill-chain coverage: which phases the dataset shows evidence for, and how deep it goes.

    One row per phase actually observed, in kill-chain order, with the ATT&CK tactics and techniques
    that put it there, when it was first and last seen, and on how many hosts. The phase mapping is
    GUIDANCE (method/framework/cyber-kill-chain.md: the ATT&CK↔kill-chain correspondence is not
    one-to-one) — it narrates *how far* the observed activity reaches, it does not prove intent.
    Phases with no evidence are omitted rather than shown as zero: an absent phase means "not
    observed here", which is not the same as "did not happen" (a gap in telemetry looks identical).
    """
    rows = _rows(con, """
        SELECT kc_phase AS phase, min(kc_order) AS phase_order,
               count(*) AS events,
               count(DISTINCT host_canon) AS hosts,
               count(DISTINCT coalesce(family, source)) AS sources,
               string_agg(DISTINCT coalesce(family, source), ', ' ORDER BY coalesce(family, source)) AS source_list,
               -- ts is the VARCHAR the record carried and the adapters do not agree on its spelling
               -- (ISO with microseconds, ISO to the second, epoch), so min/max over it is a
               -- LEXICOGRAPHIC comparison across formats — which decides the order of the phases in
               -- the narrative. ts_parsed is the TIMESTAMP the store derives for exactly this.
               min(ts_parsed) AS first_seen, max(ts_parsed) AS last_seen,
               string_agg(DISTINCT tactics, ',' ORDER BY tactics) AS tactic_blob,
               string_agg(DISTINCT techniques, ',' ORDER BY techniques) AS technique_blob
        FROM events
        WHERE kc_phase IS NOT NULL
        GROUP BY kc_phase
    """)
    out = []
    for r in rows:
        tactics = sorted({t.strip() for t in (r.pop("tactic_blob", "") or "").split(",") if t.strip()})
        techs = attack.split_techniques(r.pop("technique_blob", "") or "")
        out.append({**r,
                    "first_seen": _iso(r.get("first_seen")), "last_seen": _iso(r.get("last_seen")),
                    "tactics": ", ".join(tactics),
                    "techniques": ", ".join(techs[:limit_examples]),
                    "technique_count": len(techs)})
    out.sort(key=lambda r: (r["phase_order"], r["phase"]))
    return out


def phase_corroboration(con, phases: list[dict], beaconing: list[dict] | None = None,
                        infra_ips=None, pad_seconds: int = 120, limit_families: int = 4) -> None:
    """What the OTHER tools were doing in each kill-chain phase's window. Mutates `phases`.

    The kill chain is built from `kc_phase`, which is derived from ATT&CK techniques, and only the
    endpoint sources carry those: on the simulated incident six records out of a hundred and two —
    five EVTX and one YARA — decide every phase, while the capture, the identity provider, the
    scanners and the file server contribute nothing to the account. A reader then sees "Command and
    Control: 1 event, evtx" beside a capture that contains a regular beacon to the C2 and concludes
    the network saw nothing, which is false.

    What this adds is deliberately NOT a technique. Minting `T1571` from a non-standard port would
    populate the lanes and make the map worse: a correlation that links everything measures nothing,
    and that applies to phases exactly as it applies to bridges (§6). It adds the weaker, true claim
    instead — **in the same window, these other tools were also active, and this is what they saw** —
    which is co-occurrence in time, the same thing `episodes` reports, and is labelled as such
    wherever it is rendered.

    Four corrections from the R6 review, three of which defeated the premise above:

    - The absence of ATT&CK evidence is now a WHERE clause, not just a sentence in this docstring.
      Without it the query matched on family alone, so two phases quoted each other's evidence —
      on the very incident this cites, the same six records reappeared as apparent breadth of
      corroboration, which is the failure being removed.

      It took three attempts to write that clause, and the first two were proxies that each
      missed the half the other caught. `kc_phase IS NULL` is not "carries no technique": the
      phase is derived through the vendored offline map, so an ID the map cannot resolve stores a
      NULL phase on a record that plainly carries a technique, and that record was rendered as
      "another tool that happened to be active in the window" — the one sentence this view
      promises never to say about real evidence. `coalesce(techniques,'') = ''` is not it either,
      and was worse: 345 of the 3142 vendored SigmaHQ rules declare a TACTIC and no technique ID,
      so `store._attack_of` resolves their phase from the tactic while `techniques` stays NULL —
      substituting one proxy for the other quoted a phase's OWN establishing detection as another
      phase's corroboration, which is the same failure with a different input. The question is now
      asked once, in `store.attack_evidence`, and answered for both halves at the record.
    - The phase's own families are excluded by a subquery on `kc_phase`, not by re-splitting the
      aggregated `source_list` string. A source whose name contained the separator used to be torn
      in half and could quote its own events back.
    - The ordering carries an explicit tie-break. Event counts inside a short window tie constantly,
      and `ORDER BY count(*) DESC` alone let two runs over identical evidence name different tools
      in an analyst-facing narrative.
    - The beacon is described as a property of the DESTINATION, not of the tool that saw it.
      `recipes.beaconing` groups by host/src/dst/port and carries no family, so matching on the
      address alone credited "periodic call-backs" to whichever tool happened to log one packet to
      it — a behavioural claim attributed to evidence that never showed periodicity, in the one
      feature whose premise is that it never mints one.

    The window is the phase's own span padded by `pad_seconds` (the measured session gap, so the
    padding is the one already defended by the corpus rather than a new number).
    """
    beacon_dsts = {str(b.get("dst_ip")).strip() for b in (beaconing or []) if b.get("dst_ip")}
    infra = {str(i).strip().lower() for i in _infra_set(infra_ips)}
    for ph in phases:
        first, last = ph.get("first_seen"), ph.get("last_seen")
        ph["corroboration"] = ""
        ph["corroboration_families"] = ""
        # Set on every row, including this early exit: killchain rows with heterogeneous keys
        # reach exported bundles, where a missing key and a null one are not the same thing.
        ph["corroboration_window_s"] = None
        if not first or not last:
            continue
        # Bound, not interpolated: the window comes from our own store, but a SQL string built by
        # concatenation in a tool that reads attacker-controlled evidence is a habit worth not
        # having. epoch() arithmetic rather than INTERVAL so the padding is a bindable number too.
        rows = _rows(con, """
            SELECT coalesce(family, source, '(unnamed source)') AS family, count(*) AS events,
                   count(*) FILTER (WHERE lower(coalesce(outcome, '')) = 'failure') AS failures,
                   -- The same exclusions the correlation applies. Without them this sentence
                   -- reintroduces exactly what the rest of the engine removes: the first run named
                   -- loopback, a machine account and the declared infrastructure address as
                   -- corroborating evidence — values that co-occur with everything and therefore
                   -- corroborate nothing.
                   string_agg(DISTINCT dst_ip, ', ' ORDER BY dst_ip)
                       FILTER (WHERE NOT coalesce(dst_ip_generic, false)) AS dsts,
                   string_agg(DISTINCT dns_query, ', ' ORDER BY dns_query)
                       FILTER (WHERE NOT coalesce(dns_generic, false)) AS domains,
                   string_agg(DISTINCT user_canon, ', ' ORDER BY user_canon)
                       FILTER (WHERE NOT coalesce(user_generic, false)) AS users
            FROM events
            WHERE ts_parsed IS NOT NULL
              -- the silent tools only: an event carrying ATT&CK evidence belongs to some phase's
              -- own account, and quoting it here would launder it into a second phase's breadth.
              -- `attack_evidence` (store.py) is the ONE definition of that question — see the
              -- docstring for the two proxies that stood here before and what each of them missed.
              AND NOT coalesce(attack_evidence, false)
              -- The third coalesce argument is load-bearing, not tidiness. `NOT IN` against a
              -- subquery holding a single NULL is NULL for every row, so ONE technique-carrying
              -- record without an event.source silently emptied the corroboration for the whole
              -- analysis. The first fix excluded NULLs from the subquery, which cured that and
              -- left the outer side still evaluating to NULL — quietly dropping every unnamed
              -- record from the very view built to stop silent absences. Giving the key a name
              -- keeps both sides comparable and reports the evidence for what it is.
              AND coalesce(family, source, '(unnamed source)') NOT IN (
                    SELECT DISTINCT coalesce(family, source, '(unnamed source)') FROM events
                    WHERE kc_phase = ?)
              AND epoch(ts_parsed)
                  BETWEEN epoch(TRY_CAST(replace(?, 'Z', '') AS TIMESTAMP)) - ?
                      AND epoch(TRY_CAST(replace(?, 'Z', '') AS TIMESTAMP)) + ?
            GROUP BY 1
            ORDER BY count(*) DESC, 1 ASC
        """, [ph.get("phase"), first, pad_seconds, last, pad_seconds])
        notes, families = [], []
        for r in rows[:limit_families]:
            bits = [f"{r['events']} event(s)"]
            if r["failures"]:
                bits.append(f"{r['failures']} failed")
            dsts = sorted({d.strip() for d in (r["dsts"] or "").split(", ")
                           if d.strip() and d.strip().lower() not in infra})
            hit = [d for d in dsts if d in beacon_dsts]
            shown = (hit + [d for d in dsts if d not in hit])[:2]
            if shown:
                # The flag is attached to the ADDRESS it belongs to, and said of the address rather
                # than of this tool: `recipes.beaconing` reports a destination contacted on a
                # metronome, which is what C2 looks like and also what a backup agent looks like.
                # Which tool logged a packet to it says nothing about the periodicity. Trailing the
                # whole list instead left the reader unable to tell which of two addresses it meant.
                bits.append("to " + ", ".join(
                    f"{d} (flagged as periodic call-backs — to validate)" if d in beacon_dsts else d
                    for d in shown))
            doms = sorted({d for d in (r["domains"] or "").split(", ") if d})
            if doms:
                bits.append("resolving " + ", ".join(doms[:2]))
            users = sorted({u for u in (r["users"] or "").split(", ") if u})
            if users:
                bits.append("as " + ", ".join(users[:2]))
            notes.append(f"{r['family']}: " + ", ".join(bits))
            families.append(r["family"])
        ph["corroboration"] = " · ".join(notes)
        # A compact form for the table renderers: the sentence above is unreadable in a column, but
        # a column that lists only the technique-carrying tools is what made the reader conclude the
        # network saw nothing.
        ph["corroboration_families"] = ", ".join(families)
        # How wide the claim is. A phase whose own span is a minute and one whose span is an hour
        # both read as "in the same window", and they are not remotely the same statement — the
        # second one co-occurs with most of the incident by construction. None when it cannot be
        # computed: the previous version fell back to 0, which printed the padding alone as if it
        # were the whole window and understated exactly what the number exists to state.
        try:
            span = (_dt.datetime.fromisoformat(str(last).replace("Z", ""))
                    - _dt.datetime.fromisoformat(str(first).replace("Z", ""))).total_seconds()
            ph["corroboration_window_s"] = int(span) + 2 * pad_seconds
        except (ValueError, TypeError):
            pass


def technique_catalog(con, limit: int = 100) -> list[dict]:
    """Observed techniques resolved against the official ATT&CK map: id → name, tactics, phase.

    This is the "mapping" half of the kill-chain view: the engine flags `T1021.002`, this says it is
    *SMB/Windows Admin Shares*, lateral-movement, Actions on Objectives — without a network call
    (`analytics/attack_map.json`, generated from the official STIX bundle)."""
    rows = _rows(con, """
        SELECT techniques, count(*) AS hits, count(DISTINCT host_canon) AS hosts,
               count(DISTINCT coalesce(family, source)) AS sources,
               min(ts_parsed) AS first_seen, max(ts_parsed) AS last_seen   -- parsed, not the raw VARCHAR
        FROM events WHERE techniques IS NOT NULL AND techniques <> ''
        GROUP BY techniques
    """)
    agg: dict[str, dict] = {}
    for r in rows:
        for tid in attack.split_techniques(r["techniques"]):
            cur = agg.setdefault(tid, {"technique": tid, "name": attack.technique_name(tid),
                                       "tactics": ", ".join(attack.tactics_of(tid)),
                                       "phase": (attack.phases_of(tid) or [""])[-1],
                                       "hits": 0, "hosts": 0, "sources": 0,
                                       "first_seen": r["first_seen"], "last_seen": r["last_seen"]})
            cur["hits"] += r["hits"]
            cur["hosts"] = max(cur["hosts"], r["hosts"])       # per-group max: no double counting
            cur["sources"] = max(cur["sources"], r["sources"])
            # datetimes now, so a plain min/max is a real comparison — but either side can be
            # NULL (a record whose timestamp did not parse), and None is not orderable.
            cur["first_seen"] = _earlier(cur["first_seen"], r["first_seen"])
            cur["last_seen"] = _later(cur["last_seen"], r["last_seen"])
    out = sorted(agg.values(), key=lambda t: (-t["hits"], t["technique"]))
    for t in out:
        t["first_seen"] = _iso(t["first_seen"])
        t["last_seen"] = _iso(t["last_seen"])
        # Not silent: an unresolved ID means the map is older than the rule set (or the rule emits a
        # non-ATT&CK id). Flagged so it gets fixed by regenerating the map, not by guessing.
        if not t["name"]:
            t["name"] = "(not in ATT&CK map)"
    return out[:limit]


def host_killchain(con, limit: int = 50) -> list[dict]:
    """Per host: how deep the chain goes and which phases are covered — the triage ordering.

    A host at "Actions on Objectives" with four phases covered is a different problem from one with
    a single Delivery hit, and that difference is what decides who gets looked at first.

    `attack_events` counts records carrying ATT&CK evidence (`store.attack_evidence`), which is
    neither "has a resolved phase" nor "has a technique string" — the two proxies this line has
    already been written with, each of which DELETED a host from the list that decides who is
    looked at first. `kc_phase IS NOT NULL` dropped a host whose only detection carried an ID the
    offline map cannot resolve; `techniques <> ''` dropped one whose only detection came from a
    Sigma rule declaring a tactic and no ID, and moved `first_seen` to whichever later event did
    carry one. `phases_covered` and `max_order` deliberately still read `kc_phase`/`kc_order`:
    they measure MAPPABLE DEPTH, which is a different question and is correctly zero for evidence
    the map cannot place. Such a host appears last, saying what it is: evidence, no depth."""
    rows = _rows(con, """
        SELECT host_canon AS host,
               -- `kc_order` is 0, never NULL, for a record the map cannot place (store._cell
               -- returns `max_phase_order`), so max() over a non-empty group is always a number
               -- and the negating sort below is safe without a coalesce.
               max(kc_order) AS max_order,
               count(*) FILTER (WHERE coalesce(attack_evidence, false)) AS attack_events,
               count(DISTINCT kc_phase) AS phases_covered,
               string_agg(DISTINCT kc_phase, ' | ' ORDER BY kc_phase) AS phase_blob,
               min(ts_parsed) FILTER (WHERE coalesce(attack_evidence, false)) AS first_seen,
               max(ts_parsed) FILTER (WHERE coalesce(attack_evidence, false)) AS last_seen
        FROM events WHERE host_canon IS NOT NULL
        GROUP BY host_canon
        HAVING count(*) FILTER (WHERE coalesce(attack_evidence, false)) > 0
    """)
    for r in rows:
        phases = [p for p in (r.pop("phase_blob", "") or "").split(" | ") if p]
        r["phases"] = " → ".join(sorted(phases, key=lambda p: attack.PHASE_ORDER.get(p, 0)))
        # The label says which of the two cases an empty depth is, because the renderers print this
        # column and "" reads as "nothing found here" — the opposite of what it means.
        r["deepest_phase"] = next((p for p in attack.KILLCHAIN_PHASES[::-1] if p in phases),
                                  UNMAPPED_PHASE if r["attack_events"] else "")
        r["first_seen"] = _iso(r.get("first_seen"))
        r["last_seen"] = _iso(r.get("last_seen"))
    # The host name breaks the tie. Without it two hosts with the same depth came out in whatever
    # order DuckDB grouped them, so the same case ranked its hosts differently on two runs — and
    # this list IS the triage order.
    rows.sort(key=lambda r: (-r["max_order"], -r["phases_covered"], -r["attack_events"],
                             r["host"] or ""))
    return rows[:limit]


# What an empty kill-chain depth means when the record DID carry ATT&CK evidence: the offline map
# could not place the technique. One constant, because two views print it and two copies of a
# user-facing string diverge (§16.3).
UNMAPPED_PHASE = "(technique not in ATT&CK map)"

_CLUSTER_SQL = """
        SELECT coalesce(family, source) AS family, user_canon, user_generic, host_canon, host_generic,
               src_ip, dst_ip, src_ip_generic, dst_ip_generic,
               dns_query, dns_generic, file_hash, file_hash_md5, file_canon, file_generic,
               kc_phase, kc_order, tactics, attack_evidence
        FROM events
"""


def _record_entities(r: dict, infra: set) -> list[tuple[str, str]]:
    """The correlatable entities one event names, with the same exclusions the bridges apply.

    Shared by the clustering and the attack map so the two cannot disagree about what an entity is —
    a map drawing a link the clustering does not make (or the reverse) would leave the analyst to
    decide which of the two views is lying."""
    ents: list[tuple[str, str]] = []
    u = r.get("user_canon")
    if u and not r.get("user_generic"):
        ents.append(("user", u))
    if r.get("host_canon") and not r.get("host_generic"):
        ents.append(("host", r["host_canon"]))
    for f, gen in (("src_ip", "src_ip_generic"), ("dst_ip", "dst_ip_generic")):
        if r.get(f) and not r.get(gen) and str(r[f]).strip().lower() not in infra:
            ents.append(("ip", r[f]))
    if r.get("dns_query") and not r.get("dns_generic"):
        ents.append(("domain", r["dns_query"]))
    for f in ("file_hash", "file_hash_md5"):
        if r.get(f):
            ents.append(("file_hash", r[f]))
    if r.get("file_canon") and not r.get("file_generic"):
        ents.append(("file", r["file_canon"]))
    return ents


def entity_graph(con, infra_ips=None, limit_nodes: int = 40, min_weight: int = 1) -> dict:
    """Entities and the links between them: the map of who touched what.

    The correlation views answer three different questions and none of them is this one.
    `shared_indicators` says which entities several tools agree on, and `incident_clusters` says
    which entities belong to one incident — but it
    collapses them into a membership list, throwing away the pairs it computed on the way. That
    leaves the analyst with "these fourteen things are related" and no way to see HOW.

    Two entities are linked when one event names both. That is co-occurrence, not causation, and the
    weight is how many events say it — the map ranks leads, it does not prove them (§6).

    Returns `{nodes, edges, truncated, total_nodes}`. Nodes are capped by degree-weight because a
    picture of four hundred nodes communicates less than a table; the cap is reported rather than
    applied silently, since a missing node is exactly the kind of absence an analyst must not have
    to infer.
    """
    rows = _rows(con, _CLUSTER_SQL)
    infra = _infra_set(infra_ips)

    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str], int] = {}
    for r in rows:
        ents = _record_entities(r, infra)
        keys = []
        for kind, val in ents:
            key = f"{kind}:{val}"
            keys.append(key)
            n = nodes.setdefault(key, {"id": key, "kind": kind, "value": val, "events": 0,
                                       "families": set(), "phases": set(), "kc_order": 0})
            n["events"] += 1
            if r.get("family"):
                n["families"].add(r["family"])
            if r.get("kc_phase"):
                n["phases"].add(r["kc_phase"])
                n["kc_order"] = max(n["kc_order"], int(r.get("kc_order") or 0))
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                a, b = sorted((keys[i], keys[j]))
                if a != b:
                    edges[(a, b)] = edges.get((a, b), 0) + 1

    total_nodes = len(nodes)
    for n in nodes.values():
        n["families"] = sorted(n["families"])
        n["family_count"] = len(n["families"])
        n["phases"] = sorted(n["phases"], key=lambda p: attack.PHASE_ORDER.get(p, 0))
        n["phase"] = n["phases"][-1] if n["phases"] else ""

    # Degree-weight: an entity is kept for how much of the picture it holds together, not for how
    # often it appears — a noisy but unconnected value is exactly what should fall off the map.
    degree: dict[str, int] = {}
    for (a, b), w in edges.items():
        degree[a] = degree.get(a, 0) + w
        degree[b] = degree.get(b, 0) + w
    kept = sorted(nodes.values(),
                  key=lambda n: (-degree.get(n["id"], 0), -n["family_count"], -n["events"], n["id"])
                  )[:limit_nodes]
    keep_ids = {n["id"] for n in kept}
    # The node id breaks both ties. The map is a picture: which nodes it keeps and which edges it
    # draws must not change between two runs over the same case, or the same evidence produces two
    # different pictures and neither can be cited.
    out_edges = [{"source": a, "target": b, "weight": w}
                 for (a, b), w in sorted(edges.items(), key=lambda kv: (-kv[1], kv[0]))
                 if w >= min_weight and a in keep_ids and b in keep_ids]
    for n in kept:
        n["degree"] = degree.get(n["id"], 0)
    return {"nodes": kept, "edges": out_edges,
            "total_nodes": total_nodes, "truncated": total_nodes > len(kept)}


def incident_clusters(con, min_families: int = 2, min_entities: int = 2, limit: int = 50,
                      infra_ips=None) -> list[dict]:
    """Connected components of co-occurring entities → cross-tool incident clusters.

    Two entities that appear in the SAME event are linked; transitively (Union-Find), a cluster is a
    set of entities — users, hosts, IPs, domains, hashes, files — tied together through shared events.
    A cluster spanning MULTIPLE source families is an incident that reaches across tools (e.g. an Okta
    login → the same user on an EVTX host → a hash THOR flagged on it). Entities use canonical, normalized
    user/host keys; ubiquitous machine accounts (SYSTEM…) are excluded (they'd bridge everything).
    Kept only when it links >= `min_families` sources and >= `min_entities` entities.
    """
    rows = _rows(con, _CLUSTER_SQL)

    # Infrastructure is EXCLUDED here rather than demoted, which is the opposite of what the
    # indicator bridges do with the same list — and deliberately so. A bridge is one row the
    # analyst reads and can discount; a cluster is transitive, so one universal connector merges
    # every component into a single blob. A host with no part in an incident joins it in two hops:
    # it queried the same resolver, and the resolver appears in a firewall line beside the
    # compromised host. Demoting cannot undo a merge — only not making it can.
    infra = _infra_set(infra_ips)

    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:      # path compression
            parent[x], x = root, parent[x]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    ent_kind: dict[str, tuple[str, str]] = {}       # key -> (kind, value)
    ent_sources: dict[str, set] = {}                # key -> set of sources
    ent_phases: dict[str, set] = {}                 # key -> kill-chain phases seen on its events
    ent_tactics: dict[str, set] = {}                # key -> ATT&CK tactics seen on its events
    ent_evidence: set = set()                       # keys whose events carry ATT&CK evidence

    for r in rows:
        # Same exclusions as the indicator bridges: an entity that is on every host (SYSTEM, DC1$,
        # 127.0.0.1, svchost.exe) would merge unrelated clusters into one useless blob.
        ents = _record_entities(r, infra)
        keys = [f"{k}:{v}" for k, v in ents]
        phase = r.get("kc_phase")
        tacs = {t for t in (r.get("tactics") or "").split(",") if t}
        evidence = bool(r.get("attack_evidence"))
        for key, (kind, val) in zip(keys, ents):
            ent_kind[key] = (kind, val)
            ent_sources.setdefault(key, set()).add(r.get("family"))
            if evidence:
                ent_evidence.add(key)
            if phase:
                ent_phases.setdefault(key, set()).add(phase)
            if tacs:
                ent_tactics.setdefault(key, set()).update(tacs)
        for i in range(1, len(keys)):     # co-occurrence in the same event → link
            union(keys[0], keys[i])

    comps: dict[str, list[str]] = {}
    for key in ent_kind:
        comps.setdefault(find(key), []).append(key)

    out: list[dict] = []
    for members in comps.values():
        if len(members) < min_entities:
            continue
        srcs: set = set()
        for m in members:
            srcs |= ent_sources.get(m, set())
        srcs.discard(None)
        if len(srcs) < min_families:
            continue
        by_kind: dict[str, set] = {}
        for m in members:
            kind, val = ent_kind[m]
            by_kind.setdefault(kind, set()).add(val)
        # Kill-chain reach of the cluster: the union of the phases its entities were seen in.
        phases: set = set()
        tactics: set = set()
        for m in members:
            phases |= ent_phases.get(m, set())
            tactics |= ent_tactics.get(m, set())
        ordered = sorted(phases, key=lambda p: attack.PHASE_ORDER.get(p, 0))
        # An empty depth has two meanings and the column showed one string for both. A cluster
        # holding a detection the offline map cannot place reads exactly like a cluster holding no
        # detection at all — the ambiguity `host_killchain` was given a label for, left alive one
        # screen away in the sibling view until R6 found it.
        has_evidence = any(m in ent_evidence for m in members)
        out.append({
            "entities": len(members),
            "sources": len(srcs),
            "source_list": ", ".join(sorted(srcs)),
            "users": ", ".join(sorted(by_kind.get("user", []))[:8]),
            "hosts": ", ".join(sorted(by_kind.get("host", []))[:8]),
            "ips": ", ".join(sorted(by_kind.get("ip", []))[:8]),
            "hashes": len(by_kind.get("file_hash", [])),
            "files": len(by_kind.get("file", [])),
            "domains": len(by_kind.get("domain", [])),
            "kc_phases": " → ".join(ordered),
            "kc_depth": attack.PHASE_ORDER.get(ordered[-1], 0) if ordered else 0,
            "deepest_phase": (ordered[-1] if ordered
                              else (UNMAPPED_PHASE if has_evidence else "")),
            "tactics": ", ".join(sorted(tactics)),
        })
    # Depth first: a cluster reaching Actions on Objectives outranks a wider but shallower one.
    out.sort(key=lambda c: (-c["kc_depth"], -c["sources"], -c["entities"],
                            c["hosts"], c["users"], c["ips"]))
    return out[:limit]
