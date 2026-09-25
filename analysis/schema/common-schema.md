---
title: Common analysis schema (ECS subset)
updated: 2026-09-25
version: 0.10.0
related_files:
  - analysis/DESIGN.md
  - analysis/README.md
changelog:
  - "0.10.0 — 2026-09-25 — a registry finding contributes an artifact. An ASEP value is a command line, and both registry adapters parse the program it launches into `file.path` (`registry_asep.program_from_value`): quoting, arguments and the NT native prefix are read, the program is not guessed, and the DLL-component lists (`LSA Packages`, `Known DLLs`, `AppInit`) deliberately contribute nothing. Before this, a Run key whose data named the payload bridged to no other source at all."
  - "0.9.0 — 2026-09-01 — R6-A follow-through: the defects that round left OPEN are closed. Zeek notices join on `uid` (not a non-existent `conn` column) and reach a record; one record per application-layer transaction, so a keep-alive connection's several HTTP requests/DNS answers are no longer collapsed to the last. `rule.name` (YARA rule, Zeek notice) is a store column. YARA no longer stamps the matched file as `process.name`. osquery `remote_address` → `destination.ip` (it is the OTHER end). LogScale adds `ImageFileName`/`CommandLine`/`DomainName`/`RemoteAddressIP4` and detects a JSON-ARRAY export. Hayabusa's abbreviated tactic vocabulary (DefImpair/CredAccess/…) is normalized to ATT&CK names. `.reg` `hex(1)`/`hex(2)` are decoded to their string, so the indicator layer fires on `REG_EXPAND_SZ`. MFT/RECmd timestamps are normalized to ISO-8601 (space→T, 7-digit→6-digit fraction) and THOR's year fallback is the report's mtime, not `datetime.now().year`."
  - "0.8.0 — 2026-08-30 — the `registry.*` group and its `ioc.*`/`rule.description` companions now reach an output: `recipes.registry_findings` reads them from the store (not from the capped record list), the HTML report has a Registry section at every level, and the GUI renders the same rows for both roads in. They had had columns since 0.7.0 and no page since ever — a Run key that IS the persistence was ingested, correlated and invisible."
  - "0.7.0 — 2026-08-29 — new derived store column `attack_evidence` (BOOLEAN): does this record carry ATT&CK evidence — a technique ID of the documented shape, or a kill-chain phase resolved from a declared tactic. It exists because that question had been asked in five places in three different spellings and every spelling was wrong for some real input; the correlation, the per-host kill-chain depth, the clusters, the technique frequency and the timeline now all read it. No source-facing field change: it is computed from `attack.techniques` and `attack.tactics`, which are unchanged."
  - "0.7.0 — 2026-08-27 — Added `source.port`: the ephemeral port is what identifies a CONNECTION, and without it every packet of one exchange read as a separate connection. `recipes.beaconing` was therefore measuring inter-packet intervals on any real capture — and on any capture read by both tshark (per packet) and Zeek (per connection) — so a genuine C2 beacon went undetected. Carried by both PCAP adapters; NULL elsewhere, where one row already means one connection."
  - "0.6.0 — 2026-08-27 — Correlation counts tool FAMILIES, not source files: `event.source` stays the origin (qualified with the file where the adapter provides one) and the derived `family` column is the unit a bridge is counted in. Added `file.path` as a store column and as the fallback feeding the artifact join key, so a tool that names an artifact only by its path (YARA, osquery file events) still bridges. `file.hash.sha256` is now accepted as a spelling of `file.hash`: it was documented as mapped since 0.5.0 but had no column, so CrowdStrike and osquery hashes never reached correlation."
  - "0.1.0 — 2026-06-15 — first operational definition of the common schema, ECS subset (Phase 0 decision)."
  - "0.1.1 — 2026-06-21 — added `process.parent.command_line` (ParentCmdLine does not go in process.parent.name)."
  - "0.2.0 — 2026-07-20 — added `event.code` (EID, now a store column), web fields (`url.original`, `http.request.method`, `http.response.status_code`) for the log adapter, file fields (`file.name`, `file.hash`) for EXE/artifacts, `message` (raw log). Enables EVTX↔log↔file correlation and the full EID map (windows_eventid).
  - \"0.3.0 — 2026-07-21 — Added registry fields (key, value, data, hive, type) + IOC fields (description, severity) for .reg and RECmd adapters."
  - "0.5.0 — 2026-07-24 — Documented two new sources: CrowdStrike (detection clipboard + LogScale/CQL JSON, namespaced crowdstrike.* extras) and osquery result logs (NDJSON, table→event.category, namespaced osquery.* extras). Records the two fields deliberately NOT promoted into the common schema — CrowdStrike `aip` (the tenant NAT egress: as an indicator it bridges every event to every other) and osquery `columns.category`/`tty`/`name` outside process tables. No new store columns."
  - "0.4.2 — 2026-07-22 — Entity normalization for correlation join keys (host.name/user.name): normalize.py canonicalizes UPN/NetBIOS users and FQDN hosts so different tool spellings correlate; derived store columns user_canon/host_canon/user_generic; raw variants + match_type surfaced. No source-facing field change."
  - "0.4.1 — 2026-07-22 — Documented the Okta System Log mapping (identity source, DESIGN Phase 5): LogEvent → event.action/category/outcome, user.name, source.ip, message + namespaced okta.* extras. No new store columns (reuses existing fields)."
  - "0.4.0 — 2026-07-22 — Added `file.hash.md5` (secondary hash → a second correlation key, unioned in correlate.py) and the THOR (Nextron) scan source: findings map to file.name/file.hash(+md5)/host/user + ioc.description/severity + rule.title, with namespaced `thor.*` extras (score, path, sigclass, ref)."
---

# Common analysis schema

Phase 0 decision: the common schema is an **ECS subset** (Elastic Common
Schema), chosen over OCSF for simplicity and tooling adoption (see
`DESIGN.md` §5 and §10). Each adapter (`analysis/adapters/`) normalizes
the native source format into these fields; correlation and analytics
run on this schema in DuckDB.

## Fields

### Common
| field | type | notes |
|-------|------|-------|
| `@timestamp` | datetime (UTC) | event timestamp, normalized to UTC |
| `event.source` | keyword | `evtx` \| `crowdstrike` \| `okta` \| ... |
| `event.action` | keyword | specific action (e.g. `process-create`, `logon`) |
| `event.category` | keyword | ECS category (e.g. `process`, `authentication`, `network`) |
| `event.outcome` | keyword | `success` \| `failure` \| `unknown` |
| `event.code` | long | Windows Event ID (e.g. 4624); classified by `adapters/windows_eventid.py` |
| `message` | text | raw line/message (app-log without structured fields) |
| `attack.technique` | keyword | mapped ATT&CK ID (e.g. `T1059.001`), if determinable |

### Host
| field | type | notes |
|-------|------|-------|
| `host.name` | keyword | **pseudonym** (e.g. `HOST-01`), see anonymization |
| `host.os` | keyword | operating system / platform |

### User
| field | type | notes |
|-------|------|-------|
| `user.name` | keyword | **pseudonym** (e.g. `USER-01`) |
| `user.domain` | keyword | domain (pseudonymized if it identifies the client) |

### Process
| field | type | notes |
|-------|------|-------|
| `process.name` | keyword | image name |
| `process.command_line` | text | command line |
| `process.pid` | long | PID |
| `process.parent.name` | keyword | parent process |
| `process.parent.command_line` | text | parent process command line (e.g. ParentCmdLine) |

### Network
| field | type | notes |
|-------|------|-------|
| `source.ip` | ip | source IP (private/client IPs pseudonymized; public malicious IPs not) |
| `destination.ip` | ip | destination IP |
| `source.port` | long | source (ephemeral) port — identifies a *connection*, not just an endpoint: `recipes.beaconing` folds rows into connections on it. Populated by the PCAP adapters; absent where a row already means one connection |
| `destination.port` | long | destination port |
| `dns.question.name` | keyword | queried domain |

### Auth
| field | type | notes |
|-------|------|-------|
| `logon.type` | keyword/long | logon type (e.g. 2 interactive, 3 network, 10 RDP) |

### Web / HTTP (log adapter)
| field | type | notes |
|-------|------|-------|
| `url.original` | keyword | requested URL/path (e.g. `/wsproxy?...`) |
| `http.request.method` | keyword | HTTP method (GET/POST/...) |
| `http.response.status_code` | long | status code; maps `event.outcome` (2xx/3xx→success, 4xx/5xx→failure) |

### File / artifacts (YARA, EXE, dropped scripts)
| field | type | notes |
|-------|------|-------|
| `file.name` | keyword | file/artifact name (e.g. `sma1000_847feb….sh`) |
| `file.path` | keyword | full path when the tool reports one; its basename feeds the artifact join key when `file.name` is absent |
| `file.hash` | keyword | artifact hash, primary (SHA256 preferred); indicator, not pseudonymized. `file.hash.sha256` is accepted as a spelling of this field |
| `file.hash.md5` | keyword | secondary hash (e.g. THOR MD5); a second cross-source correlation key (unioned in `correlate.py`) |

### Registry

| Field | Type | Description |
|-------|------|-------------|
| `registry.key` | string | Full registry key path (e.g. `HKEY_LOCAL_MACHINE\SOFTWARE\...\Run`) |
| `registry.value` | string | Value name under the key |
| `registry.data` | string | Value data (raw, as string) |
| `registry.hive` | string | Hive guess: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER, UNKNOWN |
| `registry.type` | string | REG_SZ, REG_DWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ, REG_NONE |
| `file.path` | keyword | the program an ASEP value launches, when it is one: a Run/RunOnce/RunServices value, a service `ImagePath`, an IFEO `Debugger`, a Winlogon `Userinit`/`Shell`, an Active Setup `StubPath`. Read as the shortest leading run of the value that ends in a program extension (so quoting, arguments and the NT native prefix are handled and the arguments are never part of it), never guessed, never minted from a DLL component list, and never from a value that is a URL |
| `rule.description` | string | ASEP category (e.g. "User ASEP - Run", "IFEO Debugger") or null |
| `ioc.description` | string | IOC description if suspicious, or null |
| `ioc.severity` | string | IOC severity: low, medium, high, or null |

## Rules

- **Anonymization (first class).** `host.name`, `user.name`, `user.domain`,
  internal client IPs/hosts must be pseudonymized according to
  `method/anonymization.md`, preferably **after parsing** (the adapter
  produces the record, a pseudonymization step normalizes it before
  shareable output). Technical indicators (hashes, public malicious IPs,
  CVEs, ATT&CK techniques) are not pseudonymized.
- **UTC.** All timestamps normalized to UTC to enable cross-source
  correlation by time window.
- **Join keys.** Cross-source correlation uses `host.name`, `user.name`,
  IP/hash/file and the `@timestamp` window. `host.name` and `user.name` are
  **entity-normalized** at correlation time (`analytics/normalize.py`:
  `CORP\alice`/`alice@corp.example`→`alice`, `dc1.corp.example`→`dc1`) so
  different tool spellings join; the raw variants are kept and shown.
- **Extensibility.** Source-specific additional fields are allowed with a
  namespaced prefix (e.g. `crowdstrike.aid`), without breaking the common
  subset.

## Known mappings (reference)

- EVTX Security 4624/4625 → `event.category=authentication`, `event.outcome`,
  `logon.type`, `user.name`, `host.name`.
- EVTX Security 4688 / Sysmon 1 → `event.category=process`,
  `event.action=process-create`, `process.*`.
- EVTX PowerShell 4104 → `event.category=process`, `process.command_line`
  (script block), mappable to `T1059.001`.
- CrowdStrike `ProcessRollup2` → `process.name` (`ImageFileName`),
  `process.command_line` (`CommandLine`), `process.parent.name`,
  `host.name` (from `ComputerName`/`aid`).
- CrowdStrike detection clipboard / LogScale JSON → `event.source=crowdstrike`,
  `host.name` (`Host name`/`ComputerName`), `user.name`, `file.name`, `file.path`,
  `file.hash.sha256` (`SHA 256`/`SHA256HashData`), `file.hash.md5`,
  `process.command_line` (`CommandLine`), `process.name` (`ImageFileName`),
  `dns.question.name` (`DomainName`), `destination.ip` (`RemoteAddressIP4`),
  `source.ip` (`IP address`/`LocalAddressIP4`),
  `@timestamp` (UTC in the `Detected` line, or epoch-ms `timestamp`).
  Namespaced extras: `crowdstrike.agent_id`, `crowdstrike.customer_id`,
  `crowdstrike.detection_url`, `crowdstrike.user_sid`, `crowdstrike.agent_ip`.
  **`aip` stays in `crowdstrike.agent_ip` and is deliberately not `source.ip`**: it is the
  agent's external address, i.e. the tenant's NAT egress, identical for every host behind it,
  so as an indicator it would bridge every event to every other one.
- osquery result log (NDJSON) → `event.source=osquery`, `@timestamp` (epoch `unixTime`),
  `host.name` (`hostIdentifier`), `event.action` (`added`/`removed`), `event.category`
  (from the table name: `processes`→process, `listening_ports`→network, `file_events`→file …),
  `process.*`, `user.name`/`user.id`, `destination.port`, `source.ip` (local `address`),
  `destination.ip` (`remote_address`: the OTHER end of a session), `file.path`,
  `file.hash.md5`/`sha1`/`sha256`. Namespaced extras: `osquery.query` (the table),
  `osquery.columns` (the raw row), `osquery.decorations`, `osquery.host_uuid`.
  `columns.category` (the FIM group), `columns.tty` and, outside process tables,
  `columns.name` are read but **not** promoted: they collide with schema fields they do not mean.
- Okta System Log `LogEvent` → `event.source=okta`, `event.action` (`eventType`),
  `event.category` (derived from the eventType namespace: `user.session`/`user.authentication`
  → authentication), `event.outcome` (`outcome.result`), `user.name` (`actor.alternateId`),
  `source.ip` (`client.ipAddress`), `message` (`displayMessage`). Namespaced extras:
  `okta.severity`, `okta.outcome_reason`, `okta.target`, `okta.country`, `okta.is_proxy`,
  `okta.user_agent`.
- THOR (Nextron) scored finding → `event.source=thor`, `event.category=malware`,
  `file.name` (basename of `FILE`), `file.hash` (`SHA256`), `file.hash.md5` (`MD5`),
  `host.name`, `user.name` (`OWNER`), `rule.title` (`MATCHED_1`),
  `ioc.description` (`REASON_1`), `ioc.severity` (from the THOR level:
  Alert→high, Warning→medium, Notice→low). Namespaced extras: `thor.score`,
  `thor.path`, `thor.sigclass`, `thor.ref`, `thor.sha1`, `thor.module`.
