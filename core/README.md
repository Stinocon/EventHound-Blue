# core/ — EventHound v2 plugin layer

The lean, uniform surface over the v1 engine. The v1 adapters and analytics
stay the engine; this package adds:

- **`sensors/`** — one plugin per source, all with the same contract:
  `ingest(source) -> list[dict]`, producing common-schema records (ECS subset,
  dotted keys — see `analysis/schema/common-schema.md`). No plugin
  reimplements parsing: each delegates to its tested v1 adapter.

| sensor     | accepts                                        | delegates to (v1)              |
|------------|------------------------------------------------|--------------------------------|
| `evtx`     | Hayabusa `.jsonl` timeline, or raw `.evtx` (runs Hayabusa) | `adapters.evtx_hayabusa`, `engine.hayabusa_runner` |
| `pcap`     | `.pcap`/`.pcapng` — tshark + Zeek concatenated, the `build_records` road (`backend=auto`); `zeek`/`tshark` alone, or `both` (merged per flow, the `run_pcap` view) | `adapters.pcap_tshark`, `adapters.pcap_zeek`, `engine.run_pcap` |
| `logs`     | syslog / access / JSONL / regex                | `adapters.logfile`             |
| `mft`      | MFTECmd JSON output directory                  | `adapters.mft_mftecmd`         |
| `registry` | `.reg` export, or RECmd CSV directory          | `adapters.registry_regfile`, `adapters.registry_recmd` |
| `thor`     | THOR (Nextron) report (+ optional md5s file)    | `adapters.thor_scan`           |
| `osquery`  | osquery result log (NDJSON)                    | `adapters.osquery_result`      |
| `crowdstrike` | detection clipboard or LogScale JSON (explicit routing: a `.txt` that is not a THOR report) | `adapters.crowdstrike` |
| `yara`     | scan target + rules file (`ingest(target, rules)`) | `adapters.yara_scan` (needs `yara-python`) |

- **`knowledge.py`** — one door to the knowledge base: ATT&CK lookups
  (`technique(id)`, `attack_version()`) over the vendored `attack_map.json`,
  and GDPR/NIS2/DORA obligations (`obligations_for(incident)`) over the
  golden-tested compliance resolver. Deliberately **not** a migration: the
  data and the queries already exist in v1; copying them into a second store
  would be a duplicate that drifts.

## Tests

```bash
cd analysis && uv run pytest ../core/tests/ -v
```

Counts are regression contracts verified against the shipped samples; tests
skip (never pass silently) when an external binary or the PyYAML dependency
of `tools/compliance` is missing. `test_parity.py` goes further: it
generates the demo scenario and proves that every v2 sensor reproduces the
v1 adapter output record for record (order-insensitive — Zeek emits
near-simultaneous flows in a run-dependent order).
