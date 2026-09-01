"""Phase 1 CLI: a single EVTX slice → ATT&CK report.

Orchestration: Hayabusa (Sigma + ATT&CK detection) → adapter to common schema
→ Markdown report. Everything local and offline (DESIGN §2).

Usage:
    uv run python -m engine.run_evtx <file.evtx> [--out report.md]
                                     [--profile super-verbose] [--min-level low]

Example (public EVTX-ATTACK-SAMPLES):
    uv run python -m engine.run_evtx \\
        ".tools/EVTX-ATTACK-SAMPLES/Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx"
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adapters import evtx_hayabusa  # noqa: E402
from engine import hayabusa_runner, report  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="EVTX Slice → ATT&CK (Phase 1).")
    ap.add_argument("evtx", help="path to .evtx file to analyze")
    ap.add_argument("--out", help="path to Markdown report (default: reports/<name>-<date>.md)")
    ap.add_argument("--profile", default="super-verbose",
                    help="Hayabusa output profile with ATT&CK tags")
    ap.add_argument("--min-level", default="low",
                    help="minimum rule level (informational|low|medium|high|critical)")
    args = ap.parse_args(argv)

    evtx = Path(args.evtx)
    if not evtx.exists():
        print(f"error: EVTX not found: {evtx}", file=sys.stderr)
        return 2

    # A missing Hayabusa is an INSTALLATION problem with a printed remedy, not a stack trace.
    # `run_mft` and `run_pcap` already exit with one line here; these two raised through main and
    # buried the sentence that says what to download under a traceback.
    try:
        hayabusa_runner.find_binary()
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    scanned_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        jsonl = Path(tmp.name)
    try:
        print(f"[1/3] Hayabusa on {evtx.name} (profile {args.profile}, min-level {args.min_level})…")
        hayabusa_runner.run(evtx, jsonl, profile=args.profile, min_level=args.min_level)

        print("[2/3] Normalization → common schema…")
        records = evtx_hayabusa.load_records(jsonl, source=f"evtx:{evtx.name}")
    finally:
        # Guaranteed cleanup of temporary JSONL even if Hayabusa fails (corrupted EVTX →
        # CalledProcessError) or load raises: otherwise customer data Hayabusa output
        # would remain on disk (§9/§10).
        jsonl.unlink(missing_ok=True)

    print(f"[3/3] Report ({len(records)} detections)…")
    md = report.render(records, evtx_name=evtx.name, scanned_at=scanned_at)

    out = Path(args.out) if args.out else (
        Path(__file__).resolve().parents[1] / "reports"
        / f"{evtx.stem}-{_dt.date.today().isoformat()}.md"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(f"\nReport: {out}")

    # terminal summary
    techs = sorted({t for r in records for t in (r.get("attack.techniques") or [])})
    print(f"ATT&CK Techniques: {', '.join(techs) if techs else 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
