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
| `pcap`     | `.pcap`/`.pcapng` (Zeek primary, tshark fallback) | `adapters.pcap_zeek`, `adapters.pcap_tshark` |
| `logs`     | syslog / access / JSONL / regex                | `adapters.logfile`             |
| `mft`      | MFTECmd JSON output directory                  | `adapters.mft_mftecmd`         |
| `registry` | `.reg` export, or RECmd CSV directory          | `adapters.registry_regfile`, `adapters.registry_recmd` |
| `thor`     | THOR (Nextron) report (+ optional md5s file)    | `adapters.thor_scan`           |
| `osquery`  | osquery result log (NDJSON)                    | `adapters.osquery_result`      |

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
of `tools/compliance` is missing.
