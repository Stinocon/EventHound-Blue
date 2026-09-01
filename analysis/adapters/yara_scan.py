"""Adapter YARA: file matching → common schema records (DESIGN Phase 5).

Compiles YARA rules from a folder/file and scans a local file (or folder); each
match becomes an ECS-subset record (event.source=yara). If a rule carries an ATT&CK technique
in its meta (key `attack`/`mitre`, e.g., "T1059"), it propagates to attack.techniques.

OPTIONAL dependency: `yara-python` is not in defaults (C extension). Install on demand
(`uv sync --extra yara`); if absent, import fails with a clear message and the caller
skips it (like OCR/Docling). No networking; everything local (§2 of DESIGN).
"""
from __future__ import annotations

from datetime import datetime, timezone

import sys
from pathlib import Path

# rule meta keys that may contain an ATT&CK technique
_ATTACK_META_KEYS = ("attack", "mitre", "mitre_attack", "technique")


def _import_yara():
    try:
        import yara  # type: ignore
    except Exception as e:  # pragma: no cover - environment-dependent
        raise RuntimeError(
            "yara-python not available: install it with `uv sync --extra yara` "
            f"({type(e).__name__}: {e})"
        )
    # `import yara` can resolve to the local `analysis/yara/` rules directory (a namespace package,
    # no `.compile`) instead of the yara-python library when the lib isn't installed. Guard on the
    # real API so this degrades to a clean skip rather than an AttributeError at compile time.
    if not hasattr(yara, "compile"):
        raise RuntimeError(
            "yara-python not available: 'import yara' resolved to a non-library module "
            f"({getattr(yara, '__file__', None)!r}); install with `uv sync --extra yara`"
        )
    return yara


def _rule_files(rules: str | Path) -> list[Path]:
    p = Path(rules)
    if p.is_file():
        return [p]
    if p.is_dir():
        # rglob: rules in subdirectories should not be silently ignored.
        return sorted([*p.rglob("*.yar"), *p.rglob("*.yara")])
    return []


def _targets(target: str | Path) -> list[Path]:
    p = Path(target)
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted(f for f in p.rglob("*") if f.is_file())
    return []


def _technique(meta: dict) -> list[str]:
    for k in _ATTACK_META_KEYS:
        v = meta.get(k)
        if v:
            return [str(v)]
    return []


def load_records(target: str | Path, rules: str | Path) -> list[dict]:
    """Scans `target` with rules in `rules`; one record per match (file × rule)."""
    yara = _import_yara()
    rule_files = _rule_files(rules)
    if not rule_files:
        # Diagnostics on stderr: the scanned target may be a customer artifact (§9), and
        # stdout could end up in a report/log. No full paths or raw exception text.
        print("    ! no YARA rules found in the specified path", file=sys.stderr)
        return []
    try:
        compiled = yara.compile(filepaths={f"r{i}": str(p) for i, p in enumerate(rule_files)})
    except yara.Error as exc:
        # A malformed rule (invalid YARA syntax) should not crash the entire scan:
        # report it and return empty, consistent with "don't make up, skip it" in DESIGN.
        print(f"    ! YARA rule compilation failed ({type(exc).__name__})", file=sys.stderr)
        return []

    records: list[dict] = []
    for f in _targets(target):
        try:
            matches = compiled.match(str(f))
        except Exception as exc:
            # Only basename + exception type: full path may contain hostname/client name (§9)
            # and raw exc may leak scanned file content.
            print(f"    ! YARA scan failed on {f.name} ({type(exc).__name__})", file=sys.stderr)
            continue
        # A match had no timestamp at all, so `ts_parsed` was NULL and every YARA finding fell out
        # of the timeline, the episodes and every temporal recipe — present in the data, absent
        # from every view that orders by time. The file's mtime is the honest anchor available: it
        # is when the artifact was last written, which is usually when it was dropped, and it puts
        # the match next to the events that put it there.
        try:
            mtime = datetime.fromtimestamp(f.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except OSError:
            mtime = None      # file vanished between walk and stat: no time is better than a wrong one
        for m in matches:
            meta = getattr(m, "meta", {}) or {}
            rec = {
                "@timestamp": mtime,
                "event.source": "yara",
                "event.category": "file",
                "event.action": "yara-match",
                "event.kind": "state",         # a scan reports what is on disk now, not an event
                "file.name": f.name,           # the artifact join key (canon_file also reads file.path)
                "file.path": str(f),
                "rule.name": m.rule,
            }
            if mtime is None:
                rec.pop("@timestamp")
            techs = _technique(meta)
            if techs:
                rec["attack.techniques"] = techs
            records.append(rec)
    return records
