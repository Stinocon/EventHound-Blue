---
title: Correlation EVTX ↔ PCAP ↔ log — reading guide
updated: 2026-09-11
version: 0.12.1
linked_files:
  - analysis/README.md
  - analysis/analytics/correlate.py
  - analysis/schema/common-schema.md
changelog:
  - "0.12.1 (2026-09-11) — the demo is described as nine source types, not 'ten real source files'."
  - "0.12.0 (2026-08-29) — \"carries no ATT&CK technique\" is one question with one answer. It had three spellings across five call sites and each missed what the others caught: `kc_phase IS NULL` (a technique the offline map cannot resolve is real detection evidence rendered as co-occurrence), `techniques <> ''` (345 of the 3142 vendored SigmaHQ rules declare a tactic and no ID, so their phase resolves while the column is empty — that spelling quoted a phase's own establishing detection as another phase's corroboration and dropped the host from the triage list), and both being raw-string tests that counted a YARA `attack = \"Credential Access\"` meta value as a technique. The store's derived `attack_evidence` column is now the single definition, read by the corroboration, `host_killchain`, `incident_clusters`, `recipes.technique_frequency` and the timeline. Found by the third adversarial round, in the fix the second one had produced two commits earlier."
  - "0.11.0 — 2026-08-28 — per-phase corroboration corrected after an adversarial review, three of the four findings defeating its own premise. It claimed to report the tools carrying NO ATT&CK technique but filtered on family alone, so two phases quoted each other's technique-carrying evidence and the same handful of endpoint records reappeared as breadth — `kc_phase IS NULL` is now a WHERE clause, not a sentence in a docstring. The phase's own families are excluded by a subquery on `kc_phase` instead of by re-splitting the aggregated `source_list`, which tore a source name containing the separator in half. The ordering gained an explicit tie-break: counts inside a short window tie constantly, and two runs over identical evidence named different tools in the narrative. The beacon is now described as a property of the DESTINATION and attached to the address it belongs to — `recipes.beaconing` carries no family, so matching on the address alone credited \"periodic call-backs\" to whichever tool logged one packet to it. Also: the window is None rather than a fabricated 240 s when the span cannot be computed, and a new `corroboration_families` carries the compact form into the four table/card renderers that still showed only the technique-carrying tools."
  - "0.10.0 — 2026-08-28 — per-phase corroboration. The kill chain is derived from ATT&CK techniques and only the endpoint sources carry them, so on the simulated incident six records out of a hundred and two told the whole account: the narrative said \"Command and Control: 1 event, evtx\" while the capture held a regular beacon to the C2. Each phase now also states what the OTHER tools were doing in its window, as co-occurrence in time and never as a technique, with the width of that window stated so the claim can be weighed — and with the same exclusions the rest of the correlation applies, because the first implementation cheerfully named loopback, a machine account and the declared gateway as corroborating evidence."
  - "0.9.0 — 2026-08-28 — the confidence scale stopped saturating. Kind weights topping out at 1.0 plus a corroboration bonus of up to 0.3, clamped at 1.0, meant every strong bridge printed 1.00 / high and the tie fell through to the family count — so on the simulated incident the ACCOUNT bridge (five tools) outranked the HASH bridge (three), the reverse of the hierarchy this page documents. Confidence is now a band per entity kind that corroboration orders within and cannot cross, 1.00 is deliberately unreachable, and every row carries the arithmetic that produced it. `host` and `domain` swapped to match what this page, the module docstring and the in-app Help all already said. `correlation_graph` removed: the attack map superseded it and it reached one Markdown branch. Also recorded: a timestamp carrying a UTC offset was being stored with the offset dropped."
  - "0.8.0 — 2026-08-27 — Added the attack map: entity↔entity links in kill-chain lanes plus a deterministic phase-by-phase narrative, rendered once (engine/attack_map.py) for both the report and the GUI. Records what an edge does and does not claim."
  - "0.7.0 — 2026-08-27 — Added the infrastructure-address section: a gateway or resolver co-occurs with everything, so it is demoted as a bridge and excluded from clustering — declared per case, never inferred. Records that the case is now always active and that each ingest reports what changed."
  - "0.6.0 — 2026-08-27 — Added the beaconing section: a beacon is a repeated *connection*, and rows are folded into connections on `source.port` before intervals are measured. Added the simulated incident (`engine.run_demo`) as the way to see all of this without customer evidence — it is what exposed the beaconing defect."
  - "0.1.0 — 2026-07-20 — first draft: the two correlation primitives (shared indicators and temporal episodes) and an anonymized end-to-end example linking EVTX, PCAP and web logs."
  - "0.2.0 — 2026-07-20 — English translation."
  - "0.3.0 — 2026-07-23 — third primitive documented (the timeline: the bridge by *order*, with its selection criterion); framing corrected — the module also produces incident clusters and the kill-chain layer, pointed at rather than restated."
  - "0.4.0 — 2026-07-23 — added the measurement section: labelled corpus (eval/correlation_corpus.json + engine/run_eval), what the cases assert including the must-NOT-link ones, the measured session-gap band (120–300 s) and the discrimination test that keeps the corpus honest."
  - "0.5.0 — 2026-08-27 — the bridge is counted per tool FAMILY, not per source file: counting the qualified label credited two captures from one sensor as two corroborating tools while leaving ten EVTX files unable to corroborate each other at all. `source_list` now names families and `origin_list` keeps the file provenance. Two artifact bridges that were silently missing are documented as fixed (a SHA-256 spelled `file.hash.sha256`, and a file known only by its path)."
---

# Correlation EVTX ↔ PCAP ↔ log

The EventHound engine brings heterogeneous sources — EVTX (endpoint), PCAP (network), arbitrary logs —
into **one common schema** on DuckDB. On that single table it computes *whether and how* events from
different sources belong to the **same fact**. It is the answer to the question "are these events
correlated?".

Correlation (`analytics/correlate.py`) has **three complementary primitives** — the bridge by
*entity*, by *time*, and by *order*. On top of them the module also assembles **incident clusters**
(connected components of co-occurring entities: one cluster, one incident across tools) and the
**ATT&CK / kill-chain layer** (which phases the activity reaches, per dataset, per host, per
cluster). The phase mapping is guidance, not doctrine — the reasoning lives in
[`method/framework/cyber-kill-chain.md`](../../method/framework/cyber-kill-chain.md) and is not
repeated here.

## 1. Cross-source indicators (the bridge by *entity*)

An entity that appears in **more than one source family** is a bridge: if `198.51.100.7` is both the
destination of beaconing in the PCAP and the client hammering `/wsproxy` in the web log, the two
sources are looking at the same actor. The entities considered: **IP, domain, user, host, hash,
file**.

**A family is a tool, not a file.** The question a bridge answers is *how many independent tools
corroborate this*, and confidence grows with the count — so the unit has to be the tool. Adapters
disagree on how much they put in `event.source`: PCAP and the generic log adapter qualify it with
the file (`pcap:capture.pcap`), the others emit a bare constant (`evtx`, `thor`, `okta`). Reading
the qualified label as the unit was wrong in both directions at once: two captures from one sensor
counted as two corroborating tools, while ten EVTX files collected from ten hosts all carried the
same label and could never corroborate each other. The family (`pcap`, `evtx`, …) is the unit for
the count; the qualified label is kept as the **origin**, so "which file" is never lost.

Fields of the `shared_indicators` view:

| field | meaning |
|-------|---------|
| `indicator` | the entity value (e.g. `198.51.100.7`, `USER-03`) |
| `kind` | type: `ip` / `domain` / `user` / `host` / `file_hash` / `file` |
| `families` | **number of tool families** it appears in (>1 = bridge) |
| `confidence` / `confidence_label` | the bridge's strength, and its band (`high` ≥ 0.70, `medium` ≥ 0.40, `low` below) |
| `confidence_why` | the arithmetic that produced it, in words |
| `source_list` | which families (e.g. `evtx, pcap`) |
| `origin_list` | which files (e.g. `evtx, pcap:capture.pcap`) — provenance, not corroboration |
| `occurrences` | total occurrences |

Reading rule: sort by `confidence` desc — the view already does.

**The kind sets the band, corroboration orders within it, and only a penalty leaves it.** That is
the whole model, and it is arithmetic rather than intention:

| kind | band | why it sits there |
|---|---|---|
| `file_hash` | 0.85 – 0.95 | one artifact, named by its content: the strongest claim available |
| `user` | 0.70 – 0.80 | one principal, after normalization reconciled the spellings |
| `host` | 0.55 – 0.65 | one machine |
| `domain` | 0.40 – 0.50 | a name every host on the estate may legitimately resolve |
| `file` | 0.25 – 0.35 | a filename, which collides |
| `ip` | 0.10 – 0.20 | shared infrastructure is the normal explanation, not the interesting one |

Corroboration — a third tool, then a fourth — adds at most 0.10, which is deliberately never enough
to overtake the band above: five tools naming one account do not make it a stronger bridge than one
shared artifact. A normalized match costs 0.05 (below an exact match of the same kind), an ambiguous
one 0.30 and a declared infrastructure address 0.30, and those *can* drop a row out of its band,
which is the point of a penalty. **1.00 is unreachable by construction**: this ranks leads, and a
bridge printed at 1.00 reads as certainty to whoever quotes the report (§6). Each row carries
`confidence_why` — the arithmetic in words — because a number the analyst cannot take apart is one
they either over-trust or ignore.

This replaced a scale that saturated. Kind weights reached 1.0, the bonus added up to 0.3, and the
result was clamped: on the simulated incident the hash bridge (1.0 + 0.1) and the account bridge
(0.85 + 0.3 − 0.1) both printed **1.00 / high**, the tie fell through to the family count, and the
account — seen by five tools — was ranked above the hash, seen by three. The documented order was
being contradicted by the code that was supposed to implement it, silently, at the top of the list
an analyst reads first. `eval/correlation_corpus.json` now carries
`corroboration-cannot-outrank-the-stronger-kind`, and mutation 12 of
`tests/test_corpus_discriminates.py` restores the old scale and checks the case turns red.

Two artifact bridges used to go missing and no longer do, both worth knowing because the symptom
was silence rather than an error. A SHA-256 spelled `file.hash.sha256` — which is what CrowdStrike
and osquery emit — had no column and never reached the store, so those two tools could not
corroborate a hash with anything. And a record that names its artifact only by full path (YARA
matches, osquery file events) carried no artifact at all; the basename is now read from
`file.path` when `file.name` is absent, so a scanner hit bridges to the endpoint that ran the
same binary.

## 2. Temporal episodes (the bridge by *time*)

Even without a shared entity, events close in time can be the same incident. An **episode** is a
cluster of events separated by less than a *session-gap*; it becomes interesting when it collects
**more than one family** in the same window (endpoint + network + logs close together).

Fields of the `episodes` view:

| field | meaning |
|-------|---------|
| `start_ts` / `end_ts` | start and end of the window |
| `duration_s` | duration in seconds |
| `events` | events in the cluster |
| `families` | **number of families** involved (>1 = cross-source) |
| `sources` | the sources involved |
| `hosts` / `ips` | hosts and IPs touched in the episode |

Reading rule: an episode with `families` > 1 and a short duration is an incident candidate — it should
be read together with the shared indicators that fall in the same window.

## 3. The timeline (the bridge by *order*)

Indicators say *what is linked*, episodes say *what happened close together*. The question that
follows both is **in what order** — the sequence is what turns a set of findings into a narrative.

The `timeline` view puts the events of every loaded source on one chronological axis. It is
**salience-filtered**: a chronological cap over everything would return the first N rows of the file
(boot noise), so a row is kept when it carries an ATT&CK technique, a high/critical Sigma hit, a
high-signal event type, a THOR finding, or a failed action — and every row states which of those
earned it its place.

The **high-signal event types** are the reason a full EVTX stream with no rule hits is still useful:
they are the DFIR triage canon read straight from the project's Event ID map — audit and event log
clearing, audit-policy changes, service and scheduled-task installation, WMI persistence, privileged
group changes, account creation, remote thread creation, failed authentication. Log clearing that no
rule fired on *is* the finding; the list is in `correlate._NOTABLE_ACTIONS`, together with what is
deliberately excluded from it (process creation, image loads, script-block logging — they fire
constantly and would crowd everything else out of the cap).

| field | meaning |
|-------|---------|
| `ts` | timestamp (the axis; rows without a parsable one sort last) |
| `why` | the selection criterion: `ATT&CK technique`, `Sigma critical` / `Sigma high`, `high-signal event type`, `THOR finding`, `failed action`, or `context` |
| `source` | which source file the event came from |
| `kc_phase` | kill-chain phase, when the event carries ATT&CK evidence |
| `host` / `user_name` / `process_name` / `cmdline` / `src_ip` / `dst_ip` / `dns_query` / `file_name` / `url` | the substance of the event, source-dependent |
| `techniques` / `rule_title` | what fired, when a detection is involved |

Two things `why` is **not**: a severity and a ranking. It says why the row survived the filter, not
how serious it is — severity comes from the rule and from the analyst, and scoring from the oracle
(§6). The timeline never reorders itself by it: the axis stays strictly temporal, because reordering
by importance would destroy the one thing the view exists to show.

When a dataset contains nothing notable (a PCAP with no detections, say), the view falls back to the
plain chronological head, labelled `context`, rather than coming back empty — an empty timeline would
read as "nothing happened" when it means "nothing matched the filter".

The view is capped (500 events in `analyze()`) and filterable by host, user and IP from the API
(`correlate.timeline(con, host=…, user=…, ip=…)`); the GUI filters the same rows client-side.

Known limit of the cap: a flood of one repeated event type — a brute force producing thousands of
failed logons, say — fills it and pushes everything after it out of view. The filters (by `why`, by
source, by host) are the way past that; the counts in the other correlation views are what tell you
the flood happened.

## End-to-end example (anonymized)

> Synthetic data. Real client identifiers are pseudonyms (§9); the IPs are documentation addresses
> (RFC 5737, not client data).

Three sources from the same case:

- **EVTX from `HOST-01`** — remote logon (Type 3) by `USER-03` at 06:28, followed by a rare process.
- **PCAP** — from `HOST-01`, beaconing toward `198.51.100.7:8443`, ~30 s interval, low jitter.
- **Web log (SMA)** — `198.51.100.7` repeatedly requests `/wsproxy` (status 101) between 06:29 and 06:34.

Producing the single report:

```
cd analysis
uv run python -m engine.run_report \
  --evtx-full "HOST-01_Security.evtx" \
  --pcap      "perimetro.pcap" \
  --log       "sma_access.log" --fmt access \
  --out reports/caso-HOST-01.html
```

What the correlation surfaces:

- **Shared indicators**: `198.51.100.7` with `families = 2` (`pcap, logfile`) — links the network to
  the web log. `USER-03` with `families = 2` (`evtx_full, logfile`) — links the endpoint to the web log.
- **Episode**: a 06:28–06:34 window with `families = 3` (`evtx_full, pcap, logfile`) — endpoint,
  network and perimeter within the same six-minute span.
- **Timeline**: the same window in order — the `/wsproxy` requests first, then the Type 3 logon on
  `HOST-01`, then the rare process, then the first beacon. The direction is what the entity and time
  bridges cannot tell you: perimeter → endpoint → outbound, not the reverse.

Read together: a remote logon on `HOST-01` (`USER-03`), a periodic C2 channel toward `198.51.100.7`,
and the same IP exploiting `/wsproxy` on the SMA — not three disconnected signals, but **a single
episode**. The beaconing (low jitter) and the `101` status (websocket upgrade) remain *signals to be
validated* (§6), not conclusions: correlation says *where to look*, the analyst decides.

## Measuring the correlation instead of trusting it

Every number above — the confidence weight of each entity kind, the beaconing jitter threshold, the
episode session-gap — was chosen by hand. That is unavoidable at the start and indefensible
afterwards, so there is a **labelled corpus**: `analysis/eval/correlation_corpus.json` declares cases
(records in the common schema) together with what the engine must conclude from them, and
`engine/run_eval.py` reports what holds.

```
cd analysis
uv run python -m engine.run_eval                 # every case, exit 1 on a failed expectation
uv run python -m engine.run_eval --sweep-gap     # episode expectations across session-gap values
```

What the cases assert is deliberately a mix of *must link* and **must not link**: an attacker IP
shared by a perimeter log and an endpoint must bridge; `SYSTEM`, a machine account, loopback and
`svchost.exe` must not, because an entity present on every host connects everything to everything.
Two spellings of one account must unify; the same account name in two different realms must be
flagged as ambiguous rather than merged. A shared hash must outrank a shared IP.

The sweep is what turns the session-gap from a preference into a measurement. With the current
corpus it holds fully between **120 s and 300 s**: below that a real chain — a request, a logon 90
seconds later, a process 80 seconds after that, all corroborated by a shared IP — gets split into
separate episodes; above it, two sources eight minutes apart with nothing in common merge into one
"episode" that is pure noise. The 120 s default sits at the lower edge of that band.

A corpus that always passes proves nothing, so `tests/test_corpus_discriminates.py` breaks one knob
at a time and asserts the case guarding it turns red. When a case fails, read its `rationale` before
touching the label: the expectation is a security claim, and relaxing it to get a green run is the
exact failure this is built to prevent.

## 4. The attack map (the bridge by *relationship*)

The three primitives above each answer a narrower question than the one an analyst actually opens
with. `shared_indicators` says which entities several tools agree on; `episodes` says which events
fall in one window; `timeline` says in what order. `incident_clusters` comes closest — it says which
entities belong to one incident — but it collapses them into a membership list, throwing away the
pairs it computed on the way. That leaves "these fourteen things are related" with no way to see
*how*.

`correlate.entity_graph()` keeps those pairs. Two entities are linked when one event names both, and
the weight is how many events say so. `engine/attack_map.py` lays them out in kill-chain lanes and
renders inline SVG — no library, no external resource — beside a narrative assembled from
`killchain` and `technique_catalog`: for each phase, what was observed, on how many hosts, between
which times, and which tools said so. One renderer serves both the HTML report and the GUI's Attack
Map view, so the picture in the deliverable and the picture on screen cannot differ.

What it claims, and what it does not:

- an **edge is co-occurrence**, not causation. Two entities named by the same event may be attacker
  and victim, or two fields of one routine log line;
- the **lane is interpretation**. The ATT&CK→kill-chain mapping is guidance, documented as such;
- a **node's size is how many tools saw it**, not how dangerous it is. Severity is the oracle's job;
- every node and every edge carries the evidence behind it (`<title>`: event count, tools, weight),
  and a test asserts that none is drawn without it. A picture is the one part of a report that
  invites belief without checking, so anything on it that cannot say what put it there does not
  belong on it (§6);
- the map is capped at the most connected entities and **says when it truncates** — a picture of
  four hundred nodes communicates less than a table, and a silently missing node is exactly the kind
  of absence an analyst must not have to infer.

Clicking a node in the GUI filters the timeline to it: the map says what is linked, the timeline
says in what order, and carrying the value across is the reason the two sit next to each other.

## The phase says what the endpoint saw; the window says who else was there

`kc_phase` is derived from ATT&CK evidence — a technique ID the vendored offline map resolves, or a
tactic a Sigma rule declares outright — and the adapters that emit either are the endpoint ones:
Hayabusa's Sigma hits and a YARA rule that names a technique in its metadata. Everything else in the
suite carries none: the capture, the identity provider, the appliance logs, the scanners, osquery,
the registry. On the simulated incident that is **six records out of a hundred and two**, across two
of nine tool families, deciding every phase of the account — and the attack map putting eleven of
seventeen entities in a lane labelled *not placed on the kill chain*. A reader saw "Command and
Control: 1 event, evtx" beside a capture containing a metronomic beacon to the C2 and concluded the
network had seen nothing.

The tempting fix is to mint techniques from the network heuristics — a non-standard port becomes
`T1571`, a DNS query becomes `T1071.004`. It was rejected. A non-standard port is not evidence of
`T1571`; it is a reason to look. Minting them would fill the lanes and make the picture *less*
informative, which is the same failure the bridge exclusions exist to prevent, applied to phases
instead of entities (§6).

What each phase states instead is the weaker claim that is actually true: **in the same window,
these other tools were also active, and this is what they saw.** That is co-occurrence in time — the
same relation `episodes` reports — and it is labelled as such. Three things keep it honest:

- the **width of the window is stated**. "In the same 4 min window" and "in the same 59 min window"
  are not the same statement, and the second one co-occurs with most of the incident by
  construction. A phase whose own span is long says so, and the reader discounts it accordingly;
- **"carries no ATT&CK evidence" is one question, asked in one place.** It was written three times
  as three different proxies and each was wrong in its own direction. `kc_phase IS NULL` treats a
  detection whose technique ID is newer than the vendored map as a tool that merely happened to be
  active. `techniques <> ''` misses the 345 of 3142 vendored SigmaHQ rules that declare a *tactic*
  and no ID — for those the phase resolves while the column stays empty, so that spelling quoted a
  phase's own establishing detection as another phase's breadth, and deleted the host from the
  triage list entirely. Being a raw string test it also counted a YARA rule tagged
  `attack = "Credential Access"` as a technique. The store now answers it once, in the derived
  `attack_evidence` column (a resolved phase, or a well-formed `T#### [.###]` id), and the
  corroboration, the per-host depth, the clusters, the technique frequency and the timeline all
  read that;
- the **same exclusions** apply as everywhere else. The first implementation named `127.0.0.1`, a
  machine account and the analyst's own declared gateway as corroborating evidence — values that
  co-occur with everything and therefore corroborate nothing. `tests/test_correlation.py` asserts
  each of those stays out, and proves the assertion can fail by re-running the same view with the
  infrastructure declaration withheld;
- a **beacon is named as a signal**, "(to validate)", because `recipes.beaconing` reports a
  destination contacted on a metronome, which is what C2 looks like and also what a backup agent
  looks like.

## The address that bridges everything bridges nothing

A gateway, a proxy, a DNS resolver or a VPN concentrator is shared by every host on the network. As
an indicator it satisfies the definition of a bridge perfectly — the same value in several tool
families — and says nothing at all. `normalize.is_generic_ip` cannot help: it rules out loopback,
link-local, multicast and reserved space because those are wrong by construction, while a gateway is
an ordinary unicast address that nothing in the data distinguishes from a workstation.

So it is **declared**, per case (`run_case infra <case> <ip>…`, or the Cases view in the GUI), and
remembered there because it describes the network rather than any one upload. What the declaration
does differs by view, deliberately:

- as an **indicator bridge** the address is *demoted*, not removed — its confidence drops and the
  row says why. Sometimes the proxy is exactly where the interesting thing happened, and deleting
  the row would take that lead away without telling anyone;
- as a **cluster member** it is *excluded*. Clustering is transitive, so one universal connector
  merges every component into a single blob: a host with no part in an incident joins it in two
  hops — it queried the same resolver, and the resolver appears in a firewall line beside the
  compromised host. Demoting cannot undo a merge; only not making it can.

The simulated incident shows both. Declaring the resolver drops the unrelated host and the benign
destination out of the incident cluster (18 entities down to 14) while its own bridge stays visible
at a confidence of 0.1 instead of 0.4.

## A beacon is a connection, not a packet

`recipes.beaconing` looks for a destination contacted on a metronome: stable mean interval, jitter
(stddev/mean) under 0.25, at least four connections. The trap is what counts as *one* connection.
tshark reports a capture packet by packet and Zeek reports the same capture connection by
connection, so the SYN, the ACK, every data segment and Zeek's own summary of a single exchange all
arrived a few hundred milliseconds apart. The mean interval collapsed toward zero and the jitter
went through the roof: a real beacon in a real capture was never reported. It passed its own test
because the only PCAP fixture that existed had exactly one packet per flow.

Rows are therefore folded into connections first, on the 4-tuple that names one — which is why
`source.port` is in the schema. The interval is measured between the *starts* of consecutive
connections. Where a source carries no source port (Sysmon EID 3, firewall logs) each row already
means one connection and is kept as its own, so nothing about those sources changed.

The mirror error costs just as much: a single bulk upload whose segments happen to be evenly spaced
must never be read as command-and-control. The corpus case
`beacon-is-a-connection-not-a-packet` puts both flows side by side at the same cadence — six
call-backs and six segments of one connection — because only the number of connections tells them
apart.

## Seeing all of it without customer evidence

`engine/run_demo` generates one coherent intrusion as nine source types, ingests them through
the ordinary adapters and produces the full analysis:

```
cd analysis
uv run python -m engine.run_demo                  # generate, ingest, correlate, report
uv run python -m engine.run_demo --artifacts-only # write the files, load them by hand in the GUI
```

Every bridge it produces is designed to exercise a different mechanism, and so is the noise it must
refuse to bridge. `analysis/demo/expectations.json` states those claims in the corpus's own shape,
and `tests/test_demo.py` verifies them end to end — from files on disk, not from records.

## From the CLI, without the HTML report

The same views as JSON (for inspection or for the GUI):

```
uv run python -m engine.run_analytics \
  --evtx-full "HOST-01_Security.evtx" --pcap "perimetro.pcap" \
  --json-out reports/caso-HOST-01.json
```

Generic logs instead go through `engine.run_logs` (positional + `--fmt`), then flow into the same
`analyze()`. The GUI (`analysis/gui/`) does the same job from the browser, locally.
