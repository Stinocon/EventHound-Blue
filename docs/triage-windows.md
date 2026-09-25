---
title: Triage of a Windows endpoint — a complete walkthrough
updated: 2026-09-25
version: 0.1.0
linked_files:
  - analysis/demo/triage_windows.py
  - analysis/demo/triage_expectations.json
  - analysis/tests/test_triage.py
  - analysis/engine/run_demo.py
  - analysis/adapters/osquery_result.py
changelog:
  - "0.1.0 — 2026-09-25 — first draft. The scenario, the collection step by step, what the engine concludes and why, how to read the output, and the scope the scenario deliberately does not cover."
---

# Triage of a Windows endpoint

You have a Windows host that is probably compromised. You have a short window and you do not yet
know what you are looking at. This page is the whole job, in order, with what to expect at each
step — and it is also the scenario `run_demo --scenario triage-windows` reproduces, so you can run
the entire thing end to end before you point it at anything real.

If you have not installed the suite yet, do that first: `./setup.sh all`, then `./setup.sh doctor`
to see which sensors are present and what a missing one costs.

## 1. What makes this triage different

Most of what an analyst has on Windows is **history**: an event log records that something happened.
That is what Hayabusa and Sigma read, and it is the backbone of the suite.

It also has a limit that shows up in exactly this situation. The intrusion happened an hour ago, and
somebody cleared the Security log before you arrived (T1070.001). The logon that started it is gone.
You cannot reconstruct it, and no amount of reading the remaining events will bring it back.

What you can still ask is the other question: **what is true right now**. Is the payload still
running? Is the connection to the attacker still open? That is a *state* question, and it is what
osquery answers. Everything below is arranged around the difference between the two.

## 2. What to collect

Three things, all of them obtainable while the machine is still up. Collect before you contain: a
reboot ends the state evidence, and the state evidence is the part you cannot re-create.

**a. What the machine recorded.** Copy the EVTX channels, or run Hayabusa on the host:

```bash
# on the host (or against a copy of the channels)
hayabusa csv-timeline -d C:\Windows\System32\winevt\Logs -o timeline.jsonl -J
```

`-J` produces the JSONL the engine consumes. The Sysmon channel is the one that matters most here:
it is a separate log, it survives a Security-log wipe, and it is where the execution and the network
connection were recorded.

**b. What the machine is.** Point osquery at the questions a triage starts with and log the results
to a file. `osqueryi` is enough — no agent, no service, no deployment:

```bash
osqueryi --json "SELECT pid, name, path, cmdline, parent, parent_path, uid FROM processes;"     > processes.json
osqueryi --json "SELECT pid, local_address, local_port, remote_address, remote_port, state
                 FROM process_open_sockets;"                                                   > sockets.json
osqueryi --json "SELECT pid, address, port, protocol FROM listening_ports;"                    > listening.json
```

To get the **result-log** format the adapter reads (NDJSON, one object per line, with `name`,
`unixTime`, `columns`), run `osqueryd` with a scheduled-query config instead of `osqueryi`. Both
shapes are accepted — the adapter takes an array, a single object or NDJSON.

**c. What a scanner finds on disk.** A THOR report, or YARA rules and a target. This is what
answers "is the file on disk the file that is running" — the scanner names the artifact, and the
state snapshot says whether that artifact is live.

## 3. Run it

```bash
cd analysis

# the CLI, on your own evidence
uv run python -m engine.run_report \
  --evtx timeline.jsonl --osquery sockets.json --osquery listening.json --osquery processes.json \
  --thor thor_report.txt --out report.html

# or the same thing, generated, with nothing to collect first
uv run python -m engine.run_demo --scenario triage-windows
```

The demo writes its artifacts, ingests them through the **same adapters** you just used, correlates
them and renders the report. Read that report before you run your own — the shape of what follows is
the shape you will see.

In the GUI (`http://127.0.0.1:8700`) the same files go up in one upload: osquery result logs and a
THOR report are recognised **by content**, not by extension, so they land in the right adapters
without telling it which is which.

## 4. What it concludes, and why

On the generated scenario the engine reports five bridges and one cluster, and the interesting part
is which of them depend on the live state:

| bridge | families | what it means |
|---|---|---|
| `198.51.100.13` | evtx, osquery | the address appears in a connection the *log* recorded and in a socket that is **still open**. The log alone says "a connection happened"; the pair says "it is happening" |
| `9c1e77b0…` (hash) | osquery, thor | the scanner hashed a file on disk; the state snapshot hashed the file that is **running**. Same hash, so same file |
| `fontdrvhost.exe` | osquery, thor | the artifact, named from both sides |
| `ws-07` | evtx, osquery, thor | all three tools agree on the host |
| `m.bianchi` | evtx, thor | the account, from the recorded execution and the scanner's file owner |

Then rebuild the same evidence **without** osquery and the picture collapses from five bridges to
two: the address and every artifact link go with it. That is not a claim in a document, it is
`tests/test_triage.py`, which asserts exactly that — a source that adds nothing should be removed,
and the way to find out is to remove it and look.

Two details worth noticing, because they are the difference between a tool and a report:

- **The negative controls.** `svchost.exe` and `services.exe` appear in more than one source here and
  must **not** become bridges: they are on every Windows host, so a correlation that linked them
  would link everything. The expectations assert their absence as explicitly as the presence of the
  real ones.
- **The parent.** The live process row carries `parent_path = C:\Windows\System32\services.exe`,
  which is what makes the running process the same object as the service the event log recorded
  being installed. Two sources, one object, and no single tool could have said it.

## 5. How to read the output

- **Attack Map** first: entities in kill-chain lanes, each mark carrying the evidence behind it.
  Clicking a node filters the timeline to it.
- **Timeline**: every source on one axis, salience-filtered — each row says what earned it its place.
- **The log-cleared event is in there, and it is critical.** Read it before trusting anything above
  it: it tells you which part of the history is missing, which is itself a finding.
- **Report & Bundle** to export. A bundle reopens the analysis without re-running the sensors; a
  report carries the real identifiers, so anonymize before sharing.

## 6. What this scenario does not cover

Declared rather than glossed, because a demonstration whose limits are implicit is a demonstration
that overclaims:

- **The Windows-specific osquery tables are absent.** A full triage would also read `services`,
  `scheduled_tasks` and `autoruns`. Their columns have never been verified against a real Windows
  result log here, and an adapter written against a guessed column shape is how a product gets
  silently wrong answers — so the scenario uses only the cross-platform tables (`processes`,
  `process_open_sockets`, `listening_ports`, `file_events`) that a genuine macOS capture did verify.
  Persistence in this scenario is evidenced by the event log, not by a table nobody has checked.
- **EVTX arrives as the JSONL Hayabusa emits**, not through the Hayabusa binary: a `.evtx` is BinXML
  and no Python writer for it exists. Everything downstream of the binary runs for real, and
  `run_demo --evtx-dir` runs the binary itself over a corpus you supply.
- **Nothing here is a conclusion about your evidence.** The engine flags, it does not decide.
