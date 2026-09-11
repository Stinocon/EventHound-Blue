---
title: Performance figures
updated: 2026-09-11
version: 2.0.0
linked_files:
  - analysis/engine/run_bench.py
  - docs/roadmap.md
changelog:
  - "2.0.0 (2026-09-11) — the model-reliability half is removed with the on-box LLM it measured (removed 2026-09-01): `engine/run_toolbench.py` and `eval/toolcall_prompts.json` are gone, so the 'Tool-call reliability' and 'Re-scoring' sections are dropped. What remains is the pipeline profile and the ingest measurements, which still hold."
  - "1.2.0 (2026-08-29) — the open decision this table had been carrying is closed: `qwen2.5:7b-instruct` is the default on EVERY host, the RAM branch is gone, and the 14b is a selectable option rather than a preference. Nothing about the measurements changed — they said this in July; what changed is that they were acted on."
  - "1.1.0 (2026-08-28) — the tool-call section gained the axis it never had: memory. The 14b is now *preferred* rather than *default* (reachable only at 24 GiB of RAM or more, DESIGN §14.9, after loading it on a 16 GB host killed that host's graphical session), and the quality argument these figures already made against it — 54/60 vs 44/60, zero non-Latin answers vs 7, 2.2x faster — is stated as the open decision it is."
  - "1.0.0 (2026-07-24) — created: the first profile of the analytics pipeline and the first measured tool-call reliability figures, with the three defects the measuring exposed (per-value pandas probing in the store, per-file Hayabusa invocation, the silent record cap)."
---

# Performance figures

How the pipeline behaves on a large dataset, produced by a command rather than an impression.

    cd analysis
    uv run python -m engine.run_bench --analytics          # pipeline profile, offline, synthetic
    uv run python -m engine.run_bench --ingest             # real Hayabusa throughput

**The hardware matters and is part of the result.** Everything below was measured on an Apple M1
Pro, 16 GB, macOS 26.5.2, Python 3.12.13, DuckDB 1.5.4, native install (not Docker). A figure
without its machine is a number without units.

## Analytics pipeline

Synthetic records in the common schema, three sources sharing entity pools so correlation has real
joins to do rather than empty ones (`_synthetic_records` in `engine/run_bench.py`). Each stage is
timed separately, because a total says the run got slower without saying what to fix.

| records | store load | all 15 recipes | all 9 correlations | total | peak RSS |
|--------:|-----------:|---------------:|-------------------:|------:|---------:|
|   1 000 |     0.72 s |      **~20 ms** |            **~20 ms** | 0.87 s |  126 MB |
|  10 000 |     7.05 s |      **~25 ms** |            **~62 ms** | 7.47 s |  185 MB |
| 100 000 |    76.8  s |      **~0.2 s** |            **~0.5 s** |  106 s |  340 MB |

The shape is unambiguous: **loading the store is the pipeline**. Every recipe and every correlation
query together account for well under 1 % of the time at every size tested; the heaviest single
analytic (`correlate.incident_clusters`, 0.34 s at 100 k) is two orders of magnitude below the load.
DuckDB is doing exactly what it was chosen for — the analytics are effectively free, and the cost is
all in getting rows into it.

Memory scales gently: 340 MB resident at 100 000 events. Nothing here suggests a memory ceiling
before a time ceiling.

### The defect this exposed: a missing pandas cost 2.7 ms per record

Profiling the load stage found **35 652 failed imports for 1 000 records** — DuckDB's Python client
probes `import pandas` while converting each bound value, and Python does not cache a *failed*
import, so with pandas absent (it is not a dependency of this project) every probe re-walked
`sys.path`. Thirty-six columns per row meant thirty-six full path walks per record.

`analytics/store.py` now negative-caches the module name for the duration of the bulk insert and
restores `sys.modules` afterwards (`_without_probing_for_pandas`). Measured on the same 2 000
records, same process:

| insert path | seconds | per record |
|---|---:|---:|
| before | 5.21 s | 2.61 ms |
| after  | 1.37 s | 0.68 ms |

A **3.8x** speed-up on the dominant stage, from twenty-five lines and no new dependency. The
figures in the table above are *after* the fix; before it, 100 000 records took roughly four and a
half minutes to load instead of seventy-seven seconds.

The residual 0.68 ms/record is the same probe still raising `ImportError` ~36 times per row, now
cheaply. Removing it entirely belongs upstream in DuckDB, not here.

## Ingest (EVTX via Hayabusa)

Real parsing over the local `EVTX-ATTACK-SAMPLES` corpus: 278 files, 46 MB.

| files | MB | seconds | s/file |
|------:|---:|--------:|-------:|
|     1 | 0.07 |   3.19 | 3.19 |
|     8 | 2.53 |   7.41 | 0.93 |
|    32 | 17.1 |  25.3  | 0.79 |
|   278 | 46.5 | 204.7  | 0.74 |

Read that column, not the MB/s: cost tracks **file count**, not bytes. `build_records` invokes
Hayabusa once per EVTX file (`runner.py`, `_process_evtx`), and each invocation loads the full
~5 000-rule Sigma set before parsing anything. The per-file floor is the rule load; the parallel
`ThreadPoolExecutor` hides some of it across cores, which is why s/file drops from 3.19 to ~0.75 and
then stops improving.

The same design shows up in memory: a single Hayabusa invocation peaks around **540 MB** (the rule
set, not the evidence — the 0.07 MB file and the 2.5 MB batch produce the same figure). `ru_maxrss`
for children reports the largest single child, so the concurrent peak is roughly *workers × 540 MB*
— on an 8-core box, several gigabytes for a job whose input is tens of megabytes. Batching removes
that multiplier along with the time.

**Measured alternative**: the same 278 files handed to Hayabusa once as a directory
(`json-timeline -d`, rules loaded a single time) took **7.5 seconds** and produced 2 087 records
against the current path's 2 082 — a **27x** difference on the project's primary ingest path.

That change is *not* applied here. Directory mode gives no per-file error report, and the current
path deliberately isolates failures so one corrupt EVTX in a client's collection does not abort the
batch (`errors` in `build_records`). Trading that away needs its own decision, not a side effect of
a benchmarking task. It is now on the roadmap with this number attached.

### About the 500 MB question

The roadmap asked what happens on a 500 MB EVTX. Two honest answers:

- A single 500 MB `.evtx` file **has not been tested** — none exists here, and one will not be
  fabricated to produce a comfortable number (§6).
- A 500 MB *collection*, which is what triage evidence actually looks like, extrapolates from the
  measured 0.74 s/file: ~3 000 files ≈ **37 minutes** on the current path, or roughly **80 seconds**
  if the batching above is adopted. The extrapolation assumes the corpus' file-size distribution;
  since cost tracks file count rather than bytes, a collection of fewer, larger files would land
  well below it.

## The 5 000-record cap

`analyze()` returns at most 5 000 raw records (`RECORDS_CAP` in `analytics/runner.py`). It bounds
only two outputs derived from the records rather than from SQL — the browser-side IoC search corpus
and the THOR findings list. **All SQL analytics run over the complete dataset**, so no long-tail,
correlation or timeline result was ever truncated by it.

It was, however, applied **silently**, which made it a correctness problem rather than a performance
one: an analyst searching an indicator in the GUI over a 40 000-event case was searching the first
5 000, ordered by whichever adapter happened to run first, and a miss was indistinguishable from a
real absence. The analysis now carries `records_total` and `records_capped`, and the GUI states the
scope above the search box.

The cap itself stays at 5 000. The measurements support that: it is a browser constraint (`matchIocs`
stringifies every record for every indicator), not an engine one, and the honest fix for the full
dataset is the CLI or the analysis MCP server — both of which query DuckDB directly. Raising it would trade a
clear boundary for a slower page.

## Reproducing

`engine/run_bench.py` is an entry point like every other tool here, and it is excluded from the
default gate: `tools/check.sh --bench` runs the quick profile only, and reports rather than asserts.
A pass/fail threshold on a timing would encode the speed of the machine that wrote it and fail on
everybody else's.
