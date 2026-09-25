"""Orchestration Phase 2: from input (EVTX/PCAP) to records, and from records to analytics.

Reusable from both CLI (engine/run_analytics) and GUI (Phase 3): `build_records` produces
records in the common schema by wrapping adapters; `analyze` loads them into DuckDB and runs
all recipes + correlation, returning a dict ready to serialize.
"""
from __future__ import annotations

import multiprocessing as mp
import re
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# `crowdstrike` is aliased because `build_records` takes a parameter of that name: imported bare, the
# parameter shadows the module inside the function and every call raises AttributeError on a list.
from adapters import crowdstrike as crowdstrike_adapter  # noqa: E402
from adapters import pcap_zeek_runner  # noqa: E402
from adapters import (evtx_evtxecmd, evtx_hayabusa, okta_systemlog,  # noqa: E402
                      osquery_result, pcap_tshark, registry_regfile, thor_scan, yara_scan)
from analytics import case_store, correlate, recipes, store  # noqa: E402

# Cap on the raw records carried in the analyze() output. The SQL analytics run over the whole
# dataset; this bounds only the two outputs derived from the records themselves — the corpus the
# browser stringify-searches for IoCs, and the THOR findings list. It is reported alongside
# (`records_total`/`records_capped`) rather than applied silently: a truncated corpus turns a
# "not found" in the IoC search into a false negative the analyst has no way to see.
RECORDS_CAP = 5000

# How many notable events the unified timeline carries. Named because the demo's end-to-end
# test bounds this number and was reading correlate.timeline's own default instead, so the
# test and the report it verifies were looking at two differently-capped views.
TIMELINE_LIMIT = 500


# Only an ABSOLUTE path is collapsed, and only where one can start: at the beginning of the
# message or after whitespace, a quote or an open paren. A bare separator is not enough — the first
# version of this scrub read the slash in "install Wireshark/tshark" and in ".tools/evtxecmd/" as a
# path root and mangled both. A relative path carries no customer identifier anyway (§9); an
# absolute one can carry a case directory named after the client, which is the whole reason to
# scrub. URLs are matched first and kept verbatim, so `https://host/a/b` is not read as a path.
_SCRUB_RE = re.compile(
    r"(?P<url>[a-zA-Z][a-zA-Z0-9+.-]*://\S+)"
    r"|(?<![^\s'\"(])(?P<path>(?:[A-Za-z]:[\\/]|~?[\\/])[^\s'\"()]*)"
)


def _scrub(m: "re.Match") -> str:
    if m.group("url"):
        return m.group("url")
    tail = re.split(r"[\\/]", m.group("path").rstrip("\\/"))[-1]
    return tail or m.group("path")


def describe_error(exc: BaseException, limit: int = 200) -> str:
    """`Type: message` for the `errors` list — never the bare exception type.

    The type alone was all these paths used to report, and it is not enough: `PCAP capture.pcap:
    FileNotFoundError` above a grid of zeros gives the analyst no way to learn that tshark is not
    installed, which is precisely what the adapter's own message says
    (`adapters/pcap_tshark.py`). A missing tool read as an empty capture is a false negative.

    The message is kept but scrubbed, because these strings reach the HTML report and the exported
    bundle: absolute paths collapse to their basename — the same §9 rule the surrounding code
    already applies when it reports `Path(path).name` rather than `path` — whitespace collapses,
    and the result is truncated. An exception with no message degrades to the type, which is the
    old behaviour and the honest floor.
    """
    msg = " ".join(str(exc).split())
    msg = _SCRUB_RE.sub(_scrub, msg)
    if len(msg) > limit:
        msg = msg[:limit - 1].rstrip() + "\u2026"
    return f"{type(exc).__name__}: {msg}" if msg else type(exc).__name__


def stage_batch_dir(paths: list[str], dest: Path) -> list[str]:
    """Symlink `paths` into `dest` for Hayabusa's directory mode; return the staged names.

    A collection to triage routinely holds several `Security.evtx` from different hosts, and a flat
    staging directory would keep only one of them, dropping the rest without a word. Duplicates get
    a numeric prefix. Named (rather than inlined) so the collision rule can be tested by running it.
    """
    seen: dict[str, int] = {}
    staged: list[str] = []
    for p in paths:
        name = Path(p).name
        if name in seen:
            seen[name] += 1
            name = f"{seen[name]:03d}_{name}"
        else:
            seen[name] = 0
        (dest / name).symlink_to(Path(p).resolve())
        staged.append(name)
    return staged


def build_records(evtx: list[str] | None = None, pcap: list[str] | None = None,
                  evtx_full: list[str] | None = None, logs: list[dict] | None = None,
                  registry: list[str] | None = None,
                  registry_hives: list[str] | None = None,
                  mft: list[str] | None = None,
                  thor: list[dict] | None = None,
                  okta: list[str] | None = None,
                  osquery: list[str] | None = None,
                  yara: list[dict] | None = None,
                  crowdstrike: list[str] | None = None,
                  hayabusa_kwargs: dict | None = None,
                  errors: list[str] | None = None,
                  _progress: callable | None = None) -> list[dict]:
    """Builds common schema records from inputs. Execution LOCAL (Hayabusa/tshark/dotnet).

    Sources: `evtx` (Hayabusa → detection, source `evtx`), `evtx_full` (EvtxECmd → full stream,
    source `evtx_full`), `pcap` (tshark), `logs` (generic log adapter; each element is a dict
    `{"path": str, "fmt": str, "pattern": str|None, "mapping": dict|None}`). The two EVTX paths
    coexist without double-counting (distinct source) and correlate.

    Per-file isolation: if `errors` is provided, failure of a single file does NOT abort the batch —
    the error is appended as `basename: ExceptionType` (name+type only, never verbatim messages/paths,
    §9/§10) and processing continues. If `errors` is None, behavior remains "fail-fast" (propagates).
    """
    from engine import hayabusa_runner

    records: list[dict] = []

    if _progress:
        _progress("parsing", 10, "Processing EVTX files...")

    # --- evtx (Hayabusa): batch first, per-file fallback ---
    # Hayabusa exits 0 on a file it cannot read, so an unreadable EVTX raises nothing and simply
    # contributes no events. `skipped` carries those names back out of both paths and they are
    # reported like any other ingest error — a dropped log is the kind of absence an analyst must
    # never have to infer from a shorter timeline.
    # Collected here rather than reported inline: raising from inside _batch_evtx would be caught
    # by its own fallback and re-run every file per-file, and raising inside a worker thread would
    # surface as a bare exception type, losing the message. Reported once, after the block.
    evtx_skipped: list[str] = []

    def _process_evtx(path: str) -> list[dict]:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            jsonl = Path(tmp.name)
        skipped: list[str] = []
        try:
            hayabusa_runner.run(Path(path), jsonl, skipped=skipped, **(hayabusa_kwargs or {}))
            recs = evtx_hayabusa.load_records(jsonl)
        finally:
            jsonl.unlink(missing_ok=True)
        evtx_skipped.extend(skipped)
        return recs

    def _batch_evtx(paths: list[str]) -> list[dict]:
        """Try all EVTX files in one Hayabusa invocation (directory mode)."""
        with tempfile.TemporaryDirectory(prefix="hayabusa-batch-") as tmpdir:
            staged = stage_batch_dir(paths, Path(tmpdir))
            # Staging renames duplicate basenames, so a skipped file comes back under its staged
            # name; map it to the caller's own before anyone reads it.
            original = {s: Path(p).name for s, p in zip(staged, paths, strict=True)}
            with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
                jsonl = Path(tmp.name)
            skipped: list[str] = []
            try:
                hayabusa_runner.run_batch(Path(tmpdir), jsonl, skipped=skipped,
                                          **(hayabusa_kwargs or {}))
                recs = evtx_hayabusa.load_records(jsonl)
            finally:
                jsonl.unlink(missing_ok=True)
            evtx_skipped.extend(original.get(n, n) for n in skipped)
            return recs

    if evtx:
        if len(evtx) == 1:
            # Single file: no batch benefit
            try:
                records.extend(_process_evtx(evtx[0]))
            except Exception as exc:
                if errors is None:
                    raise
                errors.append(f"evtx {Path(evtx[0]).name}: {describe_error(exc)}")
        else:
            # Multiple files: try batch first, fall back to per-file
            try:
                records.extend(_batch_evtx(evtx))
            except Exception as batch_exc:
                # Batch failed (corrupt EVTX or Hayabusa error): fall back to per-file isolation.
                # The reason is reported, not discarded: the fallback is ~27x slower on a real
                # corpus (docs/analysis/performance.md), so silently taking it turns a Hayabusa
                # misconfiguration into "the tool is just slow".
                if errors is not None:
                    errors.append(f"evtx batch: {describe_error(batch_exc)} — fell back to "
                                  f"per-file ingest, which is slower")
                max_workers = min(len(evtx), mp.cpu_count())
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    futures = {pool.submit(_process_evtx, p): p for p in evtx}
                    for fut in as_completed(futures):
                        path = futures[fut]
                        try:
                            records.extend(fut.result())
                        except Exception as exc:
                            if errors is None:
                                raise
                            errors.append(f"evtx {Path(path).name}: {describe_error(exc)}")
        # Deduplicated because a batch that fell back reports each unreadable file twice.
        for name in dict.fromkeys(evtx_skipped):
            msg = f"evtx {name}: skipped by Hayabusa (unreadable or corrupt)"
            if errors is None:
                raise RuntimeError(msg)
            errors.append(msg)
    for path in (evtx_full or []):
        from engine import evtxecmd_runner
        with tempfile.TemporaryDirectory(prefix="evtxecmd-") as td:
            try:
                out = evtxecmd_runner.run_evtxecmd(Path(path), td)
                records.extend(evtx_evtxecmd.load_records(out))
            except Exception as e:  # noqa: BLE001
                if errors is None:
                    raise
                errors.append(f"EVTX-full {Path(path).name}: {describe_error(e)}")
    if _progress and evtx:
        _progress("parsing", 30, "EVTX done")
    # Zeek is optional and its absence used to be silent, which made an incomplete analysis
    # indistinguishable from a complete one: no HTTP, no TLS/JA3, no DNS answers, and nothing on
    # screen saying so. Reported once per run rather than once per capture — the tool is missing
    # from the host, not from the file, and N identical lines would bury the real per-file errors.
    zeek_missing = False
    for path in (pcap or []):
        try:
            records.extend(pcap_tshark.load_records(path))
        except Exception as e:  # noqa: BLE001
            if errors is None:
                raise
            errors.append(f"PCAP {Path(path).name}: {describe_error(e)}")
            # Whatever stopped tshark — an unreadable, missing or corrupt capture — stops Zeek for
            # the same reason, and reporting it twice makes one problem look like two.
            continue
        # Zeek: application enrichment (HTTP, SSL, DNS detail). Non-fatal error.
        # Asked before attempting, not inferred from the failure: a missing PCAP raises the same
        # FileNotFoundError as a missing zeek, and reading one as the other reports a tool as
        # uninstalled because the analyst mistyped a filename.
        if pcap_zeek_runner.zeek_path() is None:
            zeek_missing = True
        else:
            try:
                from adapters import pcap_zeek
                records.extend(pcap_zeek.load_records(path))
            except Exception as e:  # noqa: BLE001
                if errors is not None:
                    errors.append(f"PCAP-Zeek {Path(path).name}: {describe_error(e)}")
    if zeek_missing and errors is not None:
        errors.append("PCAP-Zeek: Zeek is not installed, so the application layer was not "
                      "extracted (HTTP, TLS/JA3, DNS answers, Zeek notices). Flows and DNS "
                      "questions come from tshark and are unaffected.")
    if _progress and pcap:
        _progress("parsing", 50, "PCAP done")
    for spec in (logs or []):
        from adapters import logfile
        path = spec.get("path")
        try:
            records.extend(logfile.load_records(
                path, fmt=spec.get("fmt", "auto"),
                pattern=spec.get("pattern"), mapping=spec.get("mapping"),
            ))
        except Exception as e:  # noqa: BLE001
            if errors is None:
                raise
            errors.append(f"LOG {Path(path).name if path else '?'}: {describe_error(e)}")
    if _progress and logs:
        _progress("parsing", 70, "Logs done")
    # --- registry (.reg native export files) ---
    for pi, path in enumerate(registry or []):
        try:
            def _reg_progress(pct: float, msg: str, _pi: int = pi) -> None:
                if _progress:
                    # Scale to 70-85% range
                    base = 70 + (_pi / max(len(registry), 1)) * 15
                    _progress("registry", base + pct * 0.15, msg)
            recs = registry_regfile.load_records(path, progress=_reg_progress)
            records.extend(recs)
        except Exception as exc:
            if errors is None:
                raise
            errors.append(f"registry {Path(path).name}: {describe_error(exc)}")
    # --- registry (binary hives, via RECmd) ---
    # The hive path existed only behind a GUI endpoint that called the adapter's private record
    # builder directly, so hives never reached the store, never correlated, and never entered a
    # case. Routed through build_records like every other source: one road in.
    for path in (registry_hives or []):
        from adapters import registry_recmd
        from engine import recmd_runner
        with tempfile.TemporaryDirectory(prefix="recmd-") as td:
            try:
                name = Path(path).name
                recmd_runner.run(path, td, out_name=f"{name}.json")
                records.extend(registry_recmd.load_records(td, hive_name=name))
            except Exception as exc:  # noqa: BLE001
                if errors is None:
                    raise
                errors.append(f"registry-hive {Path(path).name}: {describe_error(exc)}")
    # --- $MFT (via MFTECmd) ---
    # Same story: the adapter and its runner both existed and only the tests ever called them, while
    # the GUI showed an availability badge for a feature with no road to it.
    for path in (mft or []):
        from adapters import mft_mftecmd
        from engine import mftcmd_runner
        with tempfile.TemporaryDirectory(prefix="mftecmd-") as td:
            try:
                mftcmd_runner.run(path, td)
                records.extend(mft_mftecmd.load_records(td))
            except Exception as exc:  # noqa: BLE001
                if errors is None:
                    raise
                errors.append(f"mft {Path(path).name}: {describe_error(exc)}")
    if _progress and (registry or registry_hives or mft):
        _progress("parsing", 85, "Registry done")
    # --- thor (Nextron scan reports: .txt authoritative, md5s .csv fallback) ---
    for spec in (thor or []):
        try:
            records.extend(thor_scan.load_records(
                report=spec.get("report"), md5s=spec.get("md5s"),
            ))
        except Exception as exc:  # noqa: BLE001
            if errors is None:
                raise
            name = spec.get("report") or spec.get("md5s") or "?"
            errors.append(f"thor {Path(name).name}: {describe_error(exc)}")
    if _progress and thor:
        _progress("parsing", 88, "THOR done")
    # --- okta (System Log JSON/NDJSON export) ---
    for path in (okta or []):
        try:
            records.extend(okta_systemlog.load_records(path))
        except Exception as exc:  # noqa: BLE001
            if errors is None:
                raise
            errors.append(f"okta {Path(path).name}: {describe_error(exc)}")
    if _progress and okta:
        _progress("parsing", 89, "Okta done")
    # --- yara (YARA rule scanning) ---
    for spec in (yara or []):
        try:
            records.extend(yara_scan.load_records(
                target=spec.get("target"), rules=spec.get("rules"),
            ))
        except Exception as exc:  # noqa: BLE001
            if errors is None:
                raise
            name = spec.get("target") or spec.get("rules") or "?"
            errors.append(f"yara {Path(name).name}: {describe_error(exc)}")
    if _progress and yara:
        _progress("parsing", 89, "YARA done")
    # --- osquery (result log NDJSON) ---
    for path in (osquery or []):
        try:
            records.extend(osquery_result.load_records(path))
        except Exception as exc:  # noqa: BLE001
            if errors is None:
                raise
            errors.append(f"osquery {Path(path).name}: {describe_error(exc)}")
    if _progress and osquery:
        _progress("parsing", 89, "osquery done")
    # --- crowdstrike (detection clipboard / LogScale JSON) ---
    for path in (crowdstrike or []):
        try:
            records.extend(crowdstrike_adapter.load_records(path))
        except Exception as exc:  # noqa: BLE001
            if errors is None:
                raise
            errors.append(f"crowdstrike {Path(path).name}: {describe_error(exc)}")
    if _progress and crowdstrike:
        _progress("parsing", 89, "CrowdStrike done")
    if _progress:
        _progress("parsing", 90, "Records ready")
    return records


def analyze(records: list[dict], _progress: callable | None = None,
            infra_ips=None) -> dict:
    """Loads records into DuckDB and runs all analytics + correlation.
    Returns a dict {summary, <recipe>..., host_overview, shared_indicators}."""
    con = store.from_records(records)
    try:
        return analyze_con(con, records, _progress, infra_ips=infra_ips)
    finally:
        # Ensures the DuckDB connection is closed even if a recipe/correlation raises (e.g. SQL/type
        # error on an anomalous dataset): otherwise the connection stays open after each failed GUI
        # request, accumulating leaks in the long-running process.
        con.close()


def analyze_case(case_id: str, root=None, records_limit: int = RECORDS_CAP,
                 _progress: callable | None = None) -> dict:
    """Same analytics over a persisted case, without rebuilding the store from evidence.

    The SQL analytics run over the whole stored dataset. The two outputs derived from raw records
    rather than from SQL — the client-side IoC search corpus and the THOR findings list — cover the
    first `records_limit` records, the same cap `analyze()` applies to `records`.

    The case is also where the declared infrastructure addresses live, so they are read from it and
    applied here: they are a property of the network under investigation, not of one upload, which
    is exactly why they had to be remembered somewhere rather than re-entered each time."""
    con = case_store.connect(case_id, root)
    try:
        meta_error = None
        try:
            infra_ips = case_store.load_meta(case_id, root).get("infrastructure_ips") or []
        except Exception as exc:
            # A case whose meta cannot be read still analyzes — but it analyzes WITHOUT the declared
            # infrastructure addresses, which silently re-merges the estate into one cluster. That is
            # a different result, so it is reported rather than absorbed.
            infra_ips, meta_error = [], f"case meta unreadable ({describe_error(exc)}): " \
                                        "infrastructure addresses not applied"
        out = analyze_con(con, case_store.read_records(con, limit=records_limit), _progress,
                          infra_ips=infra_ips)
        if meta_error:
            out.setdefault("errors", []).append(meta_error)
        return out
    finally:
        con.close()


def analyze_con(con, records: list[dict] | None = None,
                _progress: callable | None = None, infra_ips=None) -> dict:
    """Run every recipe and correlation over an already-populated `events` table.

    The caller owns the connection and closes it — that is what lets a file-backed case be analyzed
    without materializing it in memory first. `records` supplies the two outputs that are not SQL
    (IoC search corpus, THOR findings); without it those are simply absent."""
    records = records or []
    out: dict = {"summary": store.summary(con)}
    # Echoed back so every surface can SAY that a demotion happened. A confidence quietly lowered by
    # a setting the reader cannot see is worse than no demotion at all.
    if infra_ips:
        out["infrastructure_ips"] = sorted({str(v).strip() for v in infra_ips if str(v or "").strip()})
    if _progress:
        _progress("analyzing", 92, "Running analytics...")
    for i, (name, (fn, _desc)) in enumerate(recipes.RECIPES.items()):
        if _progress:
            _progress("analyzing", min(92 + i, 98), f"Recipe: {name}")
        out[name] = fn(con)
    if _progress:
        _progress("correlating", 98, "Cross-source correlation...")
    out["host_overview"] = correlate.host_overview(con)
    out["shared_indicators"] = correlate.shared_indicators(con, infra_ips=infra_ips)
    out["episodes"] = correlate.episodes(con)
    out["incident_clusters"] = correlate.incident_clusters(con, infra_ips=infra_ips)
    # The entity-to-entity links the clustering computes and then throws away. Carried in the result
    # because it is what the attack map draws, and a second pass over the store to rebuild something
    # already derived would be both slower and free to disagree with the cluster it came from.
    out["entity_graph"] = correlate.entity_graph(con, infra_ips=infra_ips)
    # Unified timeline: after "which entities are linked" the next question is "in what order",
    # so the notable events of every source land on one chronological axis (see correlate.timeline
    # for what counts as notable). Capped like `records` below: a view, not the dataset.
    out["timeline"] = correlate.timeline(con, limit=TIMELINE_LIMIT)
    # ATT&CK/kill-chain layer: what the detections mean and how far the activity reaches.
    out["killchain"] = correlate.killchain(con)
    # What the tools that carry no ATT&CK technique were doing in each phase's window. Not a
    # technique and never rendered as one: the kill chain is derived from the endpoint sources
    # alone, and without this the account of a nine-source incident is told by six records.
    correlate.phase_corroboration(con, out["killchain"], out.get("beaconing"), infra_ips=infra_ips)
    out["technique_catalog"] = correlate.technique_catalog(con)
    out["host_killchain"] = correlate.host_killchain(con)
    if _progress:
        _progress("done", 100, "Complete")
    # Records for the client-side IoC search, capped (RECORDS_CAP) and — unlike before — saying so.
    # The total comes from the store, not from `records`: on a persisted case the caller already
    # handed us a truncated list, so len(records) would report the cap back as if it were the size
    # of the dataset.
    out["records"] = records[:RECORDS_CAP]
    out["records_total"] = out["summary"].get("events", len(records))
    out["records_capped"] = out["records_total"] > len(out["records"])
    # THOR findings surfaced as a ready, score-sorted list (report/GUI render it directly)
    thor = [r for r in records if r.get("event.source") == "thor"
            and r.get("event.action") != "thor-linked"]  # linked records correlate but aren't findings
    if thor:
        # Score first, then the finding itself: THOR scores repeat heavily, and a list truncated at
        # 1000 that reorders between runs drops different findings each time.
        out["thor_findings"] = sorted(
            thor, key=lambda r: (-(r.get("thor.score") or 0),
                                 str(r.get("@timestamp") or ""),
                                 str(r.get("message") or "")))[:1000]
    return out
