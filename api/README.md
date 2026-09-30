# api/ — EventHound v2 unified API

One FastAPI surface over the v2 sensor plugins (`core/sensors/`); the CLI is
a thin wrapper over the same endpoints, so there is exactly one analysis
code path. The v1 GUI (`analysis/gui/`) remains a separate, complete surface
until v2 replaces it at the merge.

## Privacy invariants (§9/§10 — same as the GUI)

- Binds to **127.0.0.1 only**.
- Uploaded artifacts land in a temporary directory and are **deleted right
  after the analysis**.
- Responses carry real client identifiers — localhost only, never expose
  further.

## Run (FastAPI lives in the GUI environment)

```bash
cd analysis/gui && uv run python ../../api/server.py   # 127.0.0.1:8700
```

## CLI (same endpoints, no server needed)

```bash
cd analysis/gui && uv run python ../../api/cli.py health
cd analysis/gui && uv run python ../../api/cli.py analyze a.evtx b.log --out out.json
cd analysis/gui && uv run python ../../api/cli.py correlate a.evtx b.log --infra-ips 10.0.0.1 --out findings.json
cd analysis/gui && uv run python ../../api/cli.py case-list
cd analysis/gui && uv run python ../../api/cli.py case-new c1 --title "incident"
cd analysis/gui && uv run python ../../api/cli.py case-add c1 a.evtx b.log
cd analysis/gui && uv run python ../../api/cli.py case-analyze c1 --out case-findings.json
```

## Endpoints

| method  | path       | what |
|---------|------------|------|
| `POST`  | `/analyze` | multipart artifacts → sensor by extension (or the `sensor` field override) → common-schema records (JSON) |
| `POST`  | `/correlate` | artifacts → the full findings bundle: recipes, timeline, episodes, clusters, kill chain, technique catalogue (same engine, nothing persisted) |
| `GET`   | `/cases` | list persisted cases |
| `POST`  | `/cases` | create a case (`case_id`, `title`) — the id is validated, not trusted (§8) |
| `GET`   | `/cases/{id}` | case metadata |
| `POST`  | `/cases/{id}/add` | upload artifacts into the case (sensor per artifact) |
| `POST`  | `/cases/{id}/analyze` | full analytics over the case (same bundle as `/correlate`) |
| `GET`   | `/health`  | liveness + the sensor registry |

The `sensor` field (on `/analyze`, `/correlate`, `/cases/{id}/add`) routes every
artifact of the request to one named sensor — the road a CrowdStrike clipboard
`.txt` takes, which the extension would otherwise guess as a THOR report.

Validation: unknown extension → `422`; path-traversal filename → `400`;
engine failure → `502`.

## Test

```bash
cd analysis/gui && uv run python ../../api/tests/test_api.py
```

(Plain script, the GUI-environment convention — `analysis/gui/tests/` runs
the same way.)
