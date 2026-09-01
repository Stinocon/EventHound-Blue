"""Wrapper around Hayabusa binary (decision: wrap mature tools, DESIGN §2/§4).

Runs `hayabusa json-timeline` on an EVTX file and returns the path to the produced JSONL.
Hayabusa comes with ~5000 Sigma rules with MITRE ATT&CK mapping: we use
an output profile that includes the `MitreTactics`/`MitreTags` fields.

The binary and rules live in analysis/.tools/ (gitignored): see README.
No network calls: analysis is local and offline (DESIGN §2).

Supplementary Sigma Rules
--------------------------
SigmaHQ community rules (``sigma/community/sigmahq/``) and custom project rules
(``sigma/custom/detection/``) are linked via persistent symlinks inside Hayabusa's
``rules/`` directory. This avoids using ``-r`` (which in Hayabusa v3.9.x would
replace bundle rules instead of adding to them) and preserves all ~5000 built-in rules.

Symlinks are idempotent: created once at first ``run()``, skipped after.
The ``.tools/`` directory is gitignored, so there's no risk of versioning them.
"""
from __future__ import annotations

import csv
import json
import multiprocessing as mp
import re
import subprocess
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1] / ".tools"
HAYABUSA_DIR = TOOLS_DIR / "hayabusa"

# Base directory of the supplemental rules (community + custom)
SIGMA_BASE = TOOLS_DIR.parent / "sigma"

# Mappa: nome symlink dentro rules/ di Hayabusa → directory sorgente
_EXTRA_RULE_LINKS: list[tuple[str, Path]] = [
    ("sigma-community", SIGMA_BASE / "community" / "sigmahq"),
    ("sigma-custom", SIGMA_BASE / "custom" / "detection"),
]


_ERRORLOG_RE = re.compile(r"Please check (\S+errorlog-[\w-]+\.log) for details")
_FAILED_FILE_RE = re.compile(r"Failed to open evtx file:\s*(.+?)\s*$")


def failed_files(stdout: str) -> list[str]:
    """Names of the EVTX files Hayabusa could not read during a run.

    Hayabusa **exits 0 when it cannot parse a file**: it skips it, notes it in a per-run
    `logs/errorlog-<timestamp>.log`, and prints a line pointing at that log. Nothing in the exit
    status or the output distinguishes "this file was unreadable" from "this file had no
    detections", so without reading that log a corrupt or truncated EVTX simply disappears from a
    client's collection — the analyst sees a smaller timeline and no reason to doubt it.

    Returns basenames only (§9: an error string reaches the GUI, the report and the bundle, and a
    full path can carry a case or host name). Best effort: an unreadable or unexpected log yields
    an empty list, because failing the ingest over the *error reporting* would be worse than the
    silence it replaces.
    """
    m = _ERRORLOG_RE.search(stdout)
    if not m:
        return []
    log_path = Path(m.group(1))
    if not log_path.is_absolute():
        log_path = HAYABUSA_DIR / log_path
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: list[str] = []
    for line in lines:
        hit = _FAILED_FILE_RE.search(line)
        if hit:
            out.append(Path(hit.group(1)).name)
    return out


def find_binary() -> Path:
    """Locate the Hayabusa binary without pinning a version.

    Matches `hayabusa-<version>-<platform>` (e.g., hayabusa-3.9.0-mac-aarch64):
    excludes the `hayabusa` symlink and `.zip` archive.
    """
    candidates = [p for p in HAYABUSA_DIR.glob("hayabusa-*-*")
                  if p.is_file() and p.suffix != ".zip"]
    if not candidates:
        raise FileNotFoundError(
            f"Hayabusa binary not found in {HAYABUSA_DIR}. "
            f"Install it (see analysis/README.md)."
        )
    return candidates[0]


def _ensure_rule_links(extra_rules: list[str | Path] | None = None) -> None:
    """Create idempotent symlinks inside Hayabusa's ``rules/`` directory.

    Links SigmaHQ community rules, project custom rules, and, if provided,
    additional directories from ``extra_rules``. Symlinks are created only if
    the source directory exists and the link is not already present.
    """
    hayabusa_rules = HAYABUSA_DIR / "rules"
    if not hayabusa_rules.is_dir():
        return  # Hayabusa not yet installed

    links = list(_EXTRA_RULE_LINKS)
    if extra_rules:
        for i, d in enumerate(extra_rules):
            links.append((f"sigma-extra-{i}", Path(d)))

    for link_name, target_dir in links:
        link_path = hayabusa_rules / link_name
        if not target_dir.is_dir():
            continue
        want = target_dir.resolve()
        if link_path.is_symlink():
            # An existing link: keep it only if it already points at the right
            # place; otherwise drop a stale/dangling link (e.g. left behind after
            # the project directory was renamed/moved) and recreate it.
            try:
                if link_path.readlink() == want:
                    continue
            except OSError:
                pass
            link_path.unlink()
        elif link_path.exists():
            continue  # a real file/dir sits there (not one of ours) — leave it
        link_path.symlink_to(want, target_is_directory=True)


def run(evtx_path: str | Path, out_jsonl: str | Path,
         profile: str = "super-verbose", min_level: str = "low",
        extra_rules: list[str | Path] | None = None,
        skipped: list[str] | None = None) -> Path:
    """Run Hayabusa on an EVTX and save detection timeline to JSONL.

    Automatically links supplementary rules (SigmaHQ community in
    ``sigma/community/sigmahq/`` and custom in ``sigma/custom/detection/``)
    into Hayabusa's ``rules/`` directory via idempotent symlinks.
    This preserves Hayabusa's ~5000 bundle rules (does not use the ``-r`` flag,
    which in v3.9.x would replace them).

    If ``sigma/`` is absent (community not yet downloaded) creates no links and
    Hayabusa runs with bundle rules only — unchanged behavior.

    profile: Hayabusa output profile including ATT&CK tags
             (super-verbose | verbose | timesketch-verbose).
    min_level: minimum rule level to load
                (informational | low | medium | high | critical).
        Changed default from medium to low (2026-07-21): -m medium filters out too
        many rules and produces no records for many EVTX files.
    extra_rules: additional Sigma rule directories to link.
    skipped: if given, receives the basenames of files Hayabusa could not read (see
             ``failed_files``) — it exits 0 on those, so nothing else would say so.
    """
    _ensure_rule_links(extra_rules)

    binary = find_binary()
    evtx_path = Path(evtx_path).resolve()
    out_jsonl = Path(out_jsonl).resolve()
    if not evtx_path.exists():
        raise FileNotFoundError(f"EVTX not found: {evtx_path}")
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(binary), "json-timeline",
        "-f", str(evtx_path),
        "-L",                 # output JSONL
        "-o", str(out_jsonl),
        "-w",                 # no-wizard: no interactive prompts
        "-O",                 # ISO-8601 UTC timestamp
        "-K", "-N",           # no colors, no terminal summary
        "-C",                 # overwrite existing output
        "-p", profile,
        "-m", min_level,
        "-t", str(mp.cpu_count()),
    ]
    # cwd = Hayabusa dir: so ./rules, ./rules/config, and ./config resolve.
    proc = subprocess.run(cmd, cwd=str(HAYABUSA_DIR), check=True,
                          capture_output=True, text=True)
    if skipped is not None:
        skipped.extend(failed_files(proc.stdout))
    return out_jsonl


def run_batch(evtx_dir: str | Path, out_jsonl: str | Path,
              profile: str = "super-verbose", min_level: str = "low",
              extra_rules: list[str | Path] | None = None,
              skipped: list[str] | None = None) -> Path:
    """Run Hayabusa on a DIRECTORY of EVTX files (batch mode, ~27x faster for 278 files).

    Accepts the same parameters as ``run()`` but uses ``-d`` (directory mode) instead of
    ``-f`` (single file). If the batch invocation fails, callers should fall back to per-file
    processing (see ``analysis/analytics/runner.py`` ``_batch_evtx``).

    ``skipped`` matters more here than in ``run()``: a whole collection goes in as one argument,
    so without it an unreadable file among two hundred readable ones leaves no trace at all.
    """
    _ensure_rule_links(extra_rules)

    binary = find_binary()
    evtx_dir = Path(evtx_dir).resolve()
    out_jsonl = Path(out_jsonl).resolve()
    if not evtx_dir.is_dir():
        raise NotADirectoryError(f"EVTX directory not found: {evtx_dir}")
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(binary), "json-timeline",
        "-d", str(evtx_dir),
        "-L",                 # output JSONL
        "-o", str(out_jsonl),
        "-w",                 # no-wizard: no interactive prompts
        "-O",                 # ISO-8601 UTC timestamp
        "-K", "-N",           # no colors, no terminal summary
        "-C",                 # overwrite existing output
        "-p", profile,
        "-m", min_level,
        "-t", str(mp.cpu_count()),
    ]
    # cwd = Hayabusa dir: so ./rules, ./rules/config, and ./config resolve.
    proc = subprocess.run(cmd, cwd=str(HAYABUSA_DIR), check=True,
                          capture_output=True, text=True)
    if skipped is not None:
        skipped.extend(failed_files(proc.stdout))
    return out_jsonl


def run_logon_summary(evtx_path: str | Path, out_prefix: str | Path) -> tuple[Path, Path]:
    """Run `hayabusa logon-summary` on an EVTX and return (successful_csv, failed_csv).

    Unlike `run()` (which uses Sigma rules), `logon-summary` is the DEDICATED command
    for logon events 4624/4625: enumerates ALL successful/failed logons, not just those
    flagged by a rule. It is the authoritative source for lateral movement hunting.

    Hayabusa (`-o <prefix>`) writes TWO CSVs: `<prefix>-successful.csv` and `<prefix>-failed.csv`
    (columns: count, Event, Target Account/Domain/Computer, Logon Type, Source
    Account/Domain/Computer, Source IP Address). No network calls.
    """
    binary = find_binary()
    evtx_path = Path(evtx_path).resolve()
    out_prefix = Path(out_prefix).resolve()
    if not evtx_path.exists():
        raise FileNotFoundError(f"EVTX not found: {evtx_path}")
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(binary), "logon-summary",
        "-f", str(evtx_path),
        "-o", str(out_prefix),
        "-O",                 # ISO-8601 UTC timestamp
        "-K", "-q",           # no colors, no banner
        "-C",                 # overwrite existing output
    ]
    subprocess.run(cmd, cwd=str(HAYABUSA_DIR), check=True,
                   capture_output=True, text=True)
    return (out_prefix.parent / f"{out_prefix.name}-successful.csv",
            out_prefix.parent / f"{out_prefix.name}-failed.csv")


# ── Toolbox: generic wrapper over Hayabusa's other subcommands ────────────────────────────
# Beyond json-timeline (run) and logon-summary, Hayabusa ships analyst-facing commands:
# eid-metrics, log-metrics, computer-metrics (triage/orientation), search (keyword/regex hunt),
# pivot-keywords-list (IOCs to pivot on), extract-base64. Each runs through run_command() and a
# small output parser. Wraps mature tooling (DESIGN §2/§4); no network, all local.


def run_command(subcommand: str, inputs: str | Path, out: str | Path | None = None,
                extra_args: list[str] | None = None, timeout: int = 900) -> subprocess.CompletedProcess:
    """Run an arbitrary Hayabusa subcommand on an EVTX file or directory.

    `inputs`: a single .evtx file (→ `-f`) or a directory of .evtx files (→ `-d`).
    Adds the common flags `-C -K -q` (clobber, no color, no banner). `extra_args` carries the
    per-command options (e.g. `-O`, `-r <regex>`, `-w`). Runs with cwd=HAYABUSA_DIR so ./rules
    resolves. Raises CalledProcessError on non-zero exit.
    """
    binary = find_binary()
    inp = Path(inputs).resolve()
    if not inp.exists():
        raise FileNotFoundError(f"input not found: {inp}")
    args = [str(binary), subcommand, "-d" if inp.is_dir() else "-f", str(inp), "-C", "-K", "-q"]
    if out is not None:
        args += ["-o", str(Path(out).resolve())]
    if extra_args:
        args += list(extra_args)
    return subprocess.run(args, cwd=str(HAYABUSA_DIR), check=True,
                          capture_output=True, text=True, timeout=timeout)


def _read_csv(path: str | Path) -> list[dict]:
    """Parse a Hayabusa CSV output file into a list of row dicts (empty if absent/empty)."""
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return []
    with p.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
        return [dict(r) for r in csv.DictReader(fh)]


def _read_json_stream(path: str | Path) -> list[dict]:
    """Parse Hayabusa search output (`-J`/`-L`) into a list of event dicts.

    Note: Hayabusa emits **concatenated** JSON objects (each may span multiple lines) — not a
    JSON array and not strict one-object-per-line JSONL — so neither `json.load` nor a per-line
    parse works. Decode successive objects with raw_decode, skipping any non-JSON noise."""
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return []
    text = p.read_text(encoding="utf-8", errors="replace")
    dec = json.JSONDecoder()
    out: list[dict] = []
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n,":
            i += 1
        if i >= n:
            break
        try:
            obj, end = dec.raw_decode(text, i)
        except json.JSONDecodeError:
            nxt = text.find("{", i + 1)
            if nxt == -1:
                break
            i = nxt
            continue
        if isinstance(obj, dict):
            out.append(obj)
        elif isinstance(obj, list):
            out.extend(x for x in obj if isinstance(x, dict))
        i = end
    return out


def _parse_pivot(out_prefix: str | Path) -> dict[str, list[str]]:
    """Parse pivot-keywords-list output: one `<prefix>-<Category>.txt` per category
    (header line `Category: ( %Placeholder% ):` + one keyword per line) → {category: [keywords]}."""
    prefix = Path(out_prefix)
    result: dict[str, list[str]] = {}
    for f in sorted(prefix.parent.glob(f"{prefix.name}-*.txt")):
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            continue
        category = lines[0].split(":", 1)[0].strip() or f.stem[len(prefix.name) + 1:]
        keywords = [ln.strip() for ln in lines[1:] if ln.strip()]
        result[category] = keywords
    return result


def eid_metrics(inputs: str | Path, out: str | Path) -> list[dict]:
    """Event ID distribution — rows: Total, %, Channel, ID, Event."""
    run_command("eid-metrics", inputs, out, ["-O"])
    return _read_csv(out)


def log_metrics(inputs: str | Path, out: str | Path) -> list[dict]:
    """Per-file metadata — Filename, Computers, Events, First/Last Timestamp, Channels, Providers, Size."""
    run_command("log-metrics", inputs, out, ["-O"])
    return _read_csv(out)


def computer_metrics(inputs: str | Path, out: str | Path) -> list[dict]:
    """Events per computer — Computer, OS information, UpTime, Timezone, Events."""
    run_command("computer-metrics", inputs, out)
    return _read_csv(out)


def search(inputs: str | Path, out: str | Path, keywords: list[str] | None = None,
           regex: str | None = None, ignore_case: bool = False, and_logic: bool = False) -> list[dict]:
    """Keyword/regex search over all events → parsed JSONL event dicts.

    Provide `keywords` (OR by default; `and_logic=True` for AND) or a `regex`."""
    if not keywords and not regex:
        raise ValueError("search requires keywords or regex")
    extra = ["-J", "-O"]   # -J: JSON objects (concatenated; see _read_json_stream)
    if regex:
        extra += ["-r", regex]
    for kw in (keywords or []):
        extra += ["-k", kw]
    # `--ignore-case` applies to keyword search only; Hayabusa rejects it together with `--regex`
    # (with a regex, case is controlled inside the pattern, e.g. (?i)).
    if ignore_case and not regex:
        extra.append("-i")
    if and_logic:
        extra.append("-a")
    run_command("search", inputs, out, extra)
    return _read_json_stream(out)


def extract_base64(inputs: str | Path, out: str | Path) -> list[dict]:
    """Extract and decode base64 strings found in events (CSV output; empty list if none)."""
    run_command("extract-base64", inputs, out)
    return _read_csv(out)


def pivot_keywords(inputs: str | Path, out_prefix: str | Path,
                   min_level: str = "informational") -> dict[str, list[str]]:
    """Pivot keywords by category (IP Addresses, Processes, Users, ...) → {category: [keywords]}.

    Uses `-w` (no wizard) to run non-interactively; `min_level` sets the rule floor."""
    run_command("pivot-keywords-list", inputs, out_prefix, ["-w", "-m", min_level])
    return _parse_pivot(out_prefix)
