"""EventHound v2 CLI — a thin wrapper over the unified API.

Uses FastAPI's TestClient so the CLI exercises the SAME endpoints a remote
client would (zero duplicated logic), without requiring a running server::

    cd analysis/gui && uv run python ../../api/cli.py analyze a.evtx b.log --out out.json
    cd analysis/gui && uv run python ../../api/cli.py health
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.server import app  # noqa: E402 — after the sys.path bootstrap

_client = TestClient(app)


@click.group()
def cli() -> None:
    """EventHound v2 — unified analysis API client."""


@cli.command()
@click.argument("artifacts", nargs=-1, type=click.Path(exists=True))
@click.option("--out", "-o", default=None, help="write the JSON response to a file")
def analyze(artifacts: tuple[str, ...], out: str | None) -> None:
    """Analyze one or more artifacts (sensor picked by extension)."""
    if not artifacts:
        raise click.UsageError("no artifact given")
    files = [("artifact", (Path(a).name, Path(a).read_bytes())) for a in artifacts]
    response = _client.post("/analyze", files=files)
    if response.status_code != 200:
        raise click.ClickException(f"API {response.status_code}: {response.text}")
    payload = response.json()
    click.echo(
        f"analyzed {len(artifacts)} artifact(s): {payload['count']} records "
        + json.dumps(payload["per_artifact"])
    )
    if out:
        Path(out).write_text(json.dumps(payload, indent=2) + "\n")
        click.echo(f"written: {out}")


@cli.command()
def health() -> None:
    """Show API health and the available sensors."""
    response = _client.get("/health")
    click.echo(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    cli()
