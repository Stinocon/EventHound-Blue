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
```

## Endpoints

| method  | path       | what |
|---------|------------|------|
| `POST`  | `/analyze` | multipart artifacts → sensor by extension → common-schema records (JSON) |
| `GET`   | `/health`  | liveness + the sensor registry |

Validation: unknown extension → `422`; path-traversal filename → `400`;
engine failure → `502`.

## Test

```bash
cd analysis/gui && uv run python ../../api/tests/test_api.py
```

(Plain script, the GUI-environment convention — `analysis/gui/tests/` runs
the same way.)
