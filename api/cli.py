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


@cli.command()
@click.argument("artifacts", nargs=-1, type=click.Path(exists=True))
@click.option("--infra-ips", default="", help="comma-separated infrastructure IPs")
@click.option("--out", "-o", default=None, help="write the JSON response to a file")
def correlate(artifacts: tuple[str, ...], infra_ips: str, out: str | None) -> None:
    """Correlate artifacts: full findings bundle over the same engine."""
    if not artifacts:
        raise click.UsageError("no artifact given")
    files = [("artifact", (Path(a).name, Path(a).read_bytes())) for a in artifacts]
    response = _client.post(
        "/correlate", files=files, data={"infra_ips": infra_ips}
    )
    if response.status_code != 200:
        raise click.ClickException(f"API {response.status_code}: {response.text}")
    payload = response.json()
    summary = payload.get("summary", {})
    click.echo(
        f"correlated {len(artifacts)} artifact(s): "
        f"{summary.get('events', '?')} events, "
        f"{len(payload.get('episodes', []))} episodes, "
        f"{len(payload.get('shared_indicators', []))} shared indicators, "
        f"{len(payload.get('incident_clusters', []))} clusters"
    )
    if out:
        Path(out).write_text(json.dumps(payload, indent=2) + "\n")
        click.echo(f"written: {out}")


@cli.command("case-list")
def case_list() -> None:
    """List persisted cases."""
    response = _client.get("/cases")
    click.echo(json.dumps(response.json(), indent=2))


@cli.command("case-new")
@click.argument("case_id")
@click.option("--title", default="", help="human-readable case title")
def case_new(case_id: str, title: str) -> None:
    """Create a persisted case."""
    response = _client.post("/cases", data={"case_id": case_id, "title": title})
    if response.status_code != 201:
        raise click.ClickException(f"API {response.status_code}: {response.text}")
    click.echo(f"created case {case_id}")


@cli.command("case-add")
@click.argument("case_id")
@click.argument("artifacts", nargs=-1, type=click.Path(exists=True))
def case_add(case_id: str, artifacts: tuple[str, ...]) -> None:
    """Upload artifacts into a case."""
    if not artifacts:
        raise click.UsageError("no artifact given")
    files = [("artifact", (Path(a).name, Path(a).read_bytes())) for a in artifacts]
    response = _client.post(f"/cases/{case_id}/add", files=files)
    if response.status_code != 200:
        raise click.ClickException(f"API {response.status_code}: {response.text}")
    added = response.json().get("added", {})
    click.echo(f"added to {case_id}: {json.dumps(added)}")


@cli.command("case-analyze")
@click.argument("case_id")
@click.option("--out", "-o", default=None, help="write the JSON response to a file")
def case_analyze(case_id: str, out: str | None) -> None:
    """Run the full analytics over a persisted case."""
    response = _client.post(f"/cases/{case_id}/analyze")
    if response.status_code != 200:
        raise click.ClickException(f"API {response.status_code}: {response.text}")
    payload = response.json()
    summary = payload.get("summary", {})
    click.echo(
        f"case {case_id}: {summary.get('events', '?')} events, "
        f"{summary.get('distinct_hosts', '?')} hosts, "
        f"{len(payload.get('timeline', []))} timeline rows"
    )
    if out:
        Path(out).write_text(json.dumps(payload, indent=2) + "\n")
        click.echo(f"written: {out}")


if __name__ == "__main__":
    cli()
