# EventHound — Local Web GUI

EventHound web interface for uploading EVTX/PCAP/logs/registry hives from the browser and viewing
the engine's analytics without using the CLI: ATT&CK detection, long-tail (process stacking, rare
parent-child, rare DNS, non-standard ports, **beaconing**), per-host summary, **cross-source
indicators**, timeline, plus the **Hayabusa toolbox** (metrics/search/pivot/base64, see below).
Icons are official Material Symbols inlined as SVG (single
`ICON_PATHS` source in `static/index.html`) — fully offline/CSP-safe, no icon font or CDN.

It is a thin layer over `analytics.runner.analyze()` (plus dedicated wrappers for the Hayabusa
toolbox, RECmd registry scan, and decode): the GUI contains no analysis logic of its own, only
upload + rendering. Stack: **FastAPI** + a vanilla single-page HTML/JS (no npm/Vite build).
`/api/analyze` streams progress via **Server-Sent Events** (SSE), ending in a `complete` event with
the full `analyze()` payload (or an `error` event).

## Privacy (method/conventions.md §9/§10) — read

- The server runs **only on 127.0.0.1**, never exposed to the network.
- Uploaded files (real client data) are processed in a **temporary** directory and **deleted**
  immediately after analysis: no server-side persistence.
- The output shows real identifiers (it is the analyst's console): do not export/share without
  pseudonymization.

## Startup

```
./setup-macos.sh up gui    # from the repo root: the usual way

cd analysis/gui && uv sync --extra yara && ./serve.sh   # or directly — http://127.0.0.1:8700
                                           # (port override: ANALISI_GUI_PORT; pid in .run/gui.pid)
```

Requires the engine's local tools: **Hayabusa** (EVTX detections), **tshark**/**Zeek** (PCAP), and
the `dotnet` runtime + Eric Zimmerman DLLs (**EvtxECmd** full stream, **RECmd** registry, **MFTECmd**
MFT) in `analysis/.tools/`. `/api/health` reports availability of each; the GUI degrades gracefully
with whichever subset is present. Also runnable **containerized**: the root `docker-compose.yml`
builds an `eventhound` image (`analysis/eventhound.Dockerfile`) with every tool baked in, run as the
`eventhound` service on the same `127.0.0.1:8700`.

## Endpoints

- `GET /` — the page.
- `GET /api/health` — `{status, runtime, hayabusa, tshark, zeek, evtxecmd, recmd, mftecmd, decode}`.
  Read at boot by every view, not only by Settings: a source view whose tool is missing now says
  what that costs (`toolNotices`, `static/lib.js`) instead of letting the upload fail later.
- `POST /api/analyze` — multipart with one or more `.evtx`/`.pcap`(`.pcapng`/`.cap`)/log
  (`.log`/`.txt`/`.json`/`.jsonl`/`.csv`)/`.reg` files; `evtx_full=true` routes EVTX through
  EvtxECmd instead of Hayabusa. Returns an SSE stream (progress events + final `complete`/`error`).
  The browser sends only what the current case has NOT already ingested (`pendingFiles`,
  `static/lib.js`): the page accumulates uploads per view, and re-sending all of them on every click
  appended the earlier ones to the case a second time — the store's duplicate check hashes the whole
  batch, so it refuses an exact repeat and not an overlapping one.
  Files are routed by extension where that is unambiguous and by CONTENT where it is not: an osquery
  export and an osquery log are both `.json` (sniffed on their own shapes), a CrowdStrike clipboard
  and a THOR report are both `.txt`, and a registry hive or an `$MFT` arrives with no extension at
  all (`regf` / `FILE` magic). A `.yar`/`.yara` upload is treated as RULES and applied to whatever
  files in the same upload no other adapter claimed — which is also why an unrecognised file is only
  reported as unsupported once it is clear no rules came with it. That path needs `yara-python` in
  THIS environment (`uv sync --extra yara`); without it the scan is reported as an error rather than
  quietly skipped, and the GUI runs a smaller version of the product than the CLI — the demo'''s
  strongest bridge is one artifact named by four tools, and three of them are not YARA.
  The records are persisted into a case: `case` when the caller names one, a freshly minted
  `case-<today>-NN` when it does not — accumulating evidence is the default, because a capture today
  and an EVTX tomorrow bridge only if both are in one store. `no_case=true` opts out for a one-off
  look. The case used comes back in `_meta.case`, and the result carries `delta`/`delta_headline`:
  what this upload changed, so a full re-analysis does not bury the two bridges that just appeared.
- `POST /api/report` — renders a report (HTML/Markdown/JSON) from an already-computed `analyze()`
  result, no re-parsing of the source files. `format=bundle` returns instead the re-importable
  snapshot built by `engine/bundle.py` (the detail level does not apply to it). Importing a bundle
  is client-side — no endpoint, the file never reaches the server.
- `POST /api/registry` — analyzes uploaded registry hives (SAM/SYSTEM/SOFTWARE/NTUSER.DAT) for
  ASEP/persistence via **RECmd**. It now goes through `runner.build_records(registry_hives=…)` like
  every other source and accepts `case=`: it used to call the adapter's private record builder and
  hand the rows straight back, so hive findings never entered the store, never correlated and never
  reached a case — a persistence key was visible in one panel and invisible everywhere the analysis
  happens. Hives uploaded to `/api/analyze` take the same road.
- `POST /api/hayabusa/{eid-metrics,log-metrics,computer-metrics,search,pivot-keywords,extract-base64}`
  — the **Hayabusa toolbox**, wrapping `hayabusa_runner.run_command()` (frequency/orientation,
  keyword/regex hunting, IOC pivoting, Base64 extraction) inside the EVTX view — same upload, no
  separate view. See `docs/analysis/threat-hunting-evtx.md` for the per-EID hunting playbook that
  maps to these commands.
- `GET|POST /api/cases`, `GET|DELETE /api/cases/{id}`, `POST /api/cases/{id}/note` — persistent
  cases (`analytics/case_store.py`): list with on-disk size, create, reopen as an `analyze()`
  result, annotate, delete. `/api/analyze` writes into one when given `case=`.
- `POST /api/cases/{id}/infrastructure` — declare the case's infrastructure addresses (gateway,
  proxy, resolver, VPN concentrator); the body `{ips: [...]}` REPLACES the list. They cannot be
  inferred — a gateway is an ordinary unicast address — and they change correlation two ways on
  purpose: demoted as an indicator bridge (still shown), excluded from clustering (where one
  universal connector merges every lead into a single blob).
- `POST /api/map` — the attack map for an already-computed analysis (`{data: <analyze() result>}`)
  → `{html, css, css_dark, nodes, truncated}`. Rendered server-side by `engine/attack_map.py`, the
  same code the HTML report uses, so the picture on screen and the one in the deliverable cannot
  differ. Nothing is re-parsed and no evidence is uploaded again.
- `POST /api/cases/demo` — generates the simulated incident (`demo/scenario.py`) and loads it into
  the case `demo`. With no body the whole incident is loaded at once and the case is rebuilt from
  scratch; with `{"step": n}` a single source is appended, in the story's order
  (`run_demo.DEMO_ORDER`), which is the better demonstration — the analyst watches a bridge appear
  at the moment a second tool names the same thing. Both call
  `engine.run_demo.build_demo_case`, never a second implementation: this endpoint used to hold its
  own copy of the ingest loop, and that copy had fallen behind — it never declared the scenario's
  infrastructure address, so the demo in the browser returned one cluster holding the whole estate
  while the same demo on the command line returned the incident. The response reports which sources
  produced records and which tools were missing, so a smaller picture is never presented as a
  complete one.

  *(`POST /api/yara-scan` is gone. Nothing in the interface ever reached it, and `/api/analyze`
  already applies uploaded `.yar` rules to the files no other adapter claimed — and, unlike the
  dedicated endpoint, puts the matches through the correlation. One road in.)*
- `GET /api/attack-map` — the ATT&CK technique→tactic/phase map used by the front end.
- `GET|POST /api/config` — the GUI↔CLI shared settings store (API keys masked on read).
- `POST /api/decode` — Base64/hex/URL/ROT/XOR/Base58/unicode auto-decoding of pasted text.
## Test

```
uv run python tests/test_gui.py
```
Verifies `/api/health`, the SSE `/api/analyze` + `/api/report` round trip on a synthetic log, the
Hayabusa toolbox endpoints (skipped without the binary/sample EVTX), and `/api/analyze` on a
synthetic PCAP if `tshark` is available.
