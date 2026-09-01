"""Host memory facts, and whether this host can absorb a large allocation (DESIGN §14.9).

Lives in `tools/` rather than beside its first caller because it has two: the on-box LLM in
`analysis/ai/` and the RAG's embedding and reranking models in `rag/pipeline/`. Both allocate
gigabytes on the same host, and duplicating the policy would give the two allocators different
opinions about the same machine. `tools/eventhound_config.py` is the precedent for a plain,
stdlib-only module here imported from another tree.

Why this exists. On 2026-08-28 the suite killed the graphical session of a 16 GB Mac: Ollama
loaded `qwen2.5:14b` — 9.1 GiB predicted — while the RAG stack, Qdrant, the GUI and DuckDB were
resident, and swap sat at 92% of its ceiling. Ollama had logged the problem itself
(`system_limited=true`) and loaded anyway; nothing on our side was looking. The default model had
been chosen on tool-call reliability alone (DESIGN §14.3), against no memory budget at all.

Stdlib only, consistent with the rest of `analysis/` — no psutil for three numbers.

Every function here returns `None` when it cannot measure, and every caller must treat `None` as
"proceed". A memory probe that fails closed would ground the engine on any platform we did not
anticipate, which trades a rare crash for a certain outage.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

GIB = 1024 ** 3

# LC_ALL=C: `sysctl vm.swapusage` renders decimals with the locale separator ("14336,00M" under
# an Italian locale), which a naive float() drops on the floor. Forcing the C locale makes the
# output deterministic; the parser below stays tolerant of both separators regardless.
_ENV = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


def _run(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5, env=_ENV, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def _num(text: str) -> float | None:
    """First number in `text`, accepting both decimal separators."""
    m = re.search(r"(\d+(?:[.,]\d+)?)", text)
    return float(m.group(1).replace(",", ".")) if m else None


def _meminfo() -> dict[str, int]:
    """/proc/meminfo as bytes. Empty when absent (i.e. not Linux)."""
    try:
        raw = Path("/proc/meminfo").read_text()
    except OSError:
        return {}
    out = {}
    for line in raw.splitlines():
        key, _, rest = line.partition(":")
        val = _num(rest)
        if val is not None:
            out[key.strip()] = int(val) * 1024  # meminfo reports kB
    return out


def total_bytes() -> int | None:
    """Physical RAM. On Apple silicon this is also the GPU's memory — the model competes with
    everything else for the same pool, which is precisely why the 14b did not fit."""
    if sys.platform == "darwin":
        out = _run(["sysctl", "-n", "hw.memsize"])
        val = _num(out) if out else None
        return int(val) if val else None
    return _meminfo().get("MemTotal")


def available_bytes() -> int | None:
    """Memory a new allocation could plausibly get.

    On Linux this is `MemAvailable`, which the kernel computes for exactly this question. Note the
    `is not None` tests: `MemAvailable: 0` is the one reading that says unambiguously "there is no
    memory", and a falsy test turned it into `None`, which every caller reads as "could not measure,
    proceed" — the single most inverted answer this module could give.

    macOS publishes no equivalent, so this approximates it as free + inactive + speculative pages.
    Two corrections over the conventional formula, both from the R6 review of this file:

    - `Pages purgeable` is **not** added. The disjoint buckets (free, active, inactive, speculative,
      throttled, wired, occupied-by-compressor) already account for physical memory; purgeable is a
      cross-cutting label over pages counted in active/inactive, so adding it counts them twice.
    - The estimate stays **optimistic** even so, and knowingly: `inactive` dominates it, and on a
      host with a full compressor those pages cannot be reclaimed without paging. Rather than guess
      a discount factor, the caller subtracts an explicit reserve (`reserve_bytes`) — the optimism
      is answered with a stated margin instead of a fudged measurement.
    """
    if sys.platform != "darwin":
        info = _meminfo()
        for key in ("MemAvailable", "MemFree"):
            if info.get(key) is not None:
                return info[key]
        return None
    out = _run(["vm_stat"])
    if not out:
        return None
    page = _num(out.split("page size of", 1)[1]) if "page size of" in out else None
    if not page:
        return None
    wanted = ("Pages free", "Pages inactive", "Pages speculative")
    pages = 0.0
    seen = False
    for line in out.splitlines():
        key, _, rest = line.partition(":")
        if key.strip() in wanted:
            val = _num(rest)
            if val is not None:
                pages += val
                seen = True
    return int(pages * page) if seen else None


# How much of the host must be left for everything that is not the model. `available_bytes` is
# optimistic by construction (see above) and the incident's cost was paid by the OS, not by the
# process that over-allocated: the graphical session died, not Ollama. A stated reserve is the
# honest way to answer an optimistic estimate — 15% of RAM, never less than 1 GiB.
RESERVE_FRACTION = 0.15
RESERVE_FLOOR = 1 * GIB
# And a ceiling. The reserve answers the macOS estimate's optimism and the OS's own needs, and
# neither scales with installed RAM: an uncapped 15% reserved 19.2 GiB on a 128 GiB server and
# refused a 9.6 GiB model that had 25 GiB of room. The percentage is right for small hosts, where
# the risk lives; above ~27 GiB it stops describing anything real.
RESERVE_CEILING = 4 * GIB


def reserve_bytes() -> int:
    """Memory to keep out of any single allocation's reach."""
    total = total_bytes()
    if not total:
        return RESERVE_FLOOR
    return max(RESERVE_FLOOR, min(RESERVE_CEILING, int(total * RESERVE_FRACTION)))


def swap_used_fraction() -> float | None:
    """How much of the swap ceiling is already spent, 0.0-1.0.

    The incident's clearest single number: 13.2 GB of a 14.3 GB ceiling, 92%, and still there
    after the session died. A box that deep in swap has no room to absorb a multi-GB allocation
    however encouraging `available_bytes` looks, because the pages it would evict have nowhere
    left to go. Returns None when there is no swap configured or it cannot be read.
    """
    if sys.platform == "darwin":
        out = _run(["sysctl", "-n", "vm.swapusage"])
        if not out:
            return None
        # "total = 14336,00M  used = 13204,50M  free = 1131,50M  (encrypted)"
        tot = re.search(r"total\s*=\s*([\d.,]+)", out)
        used = re.search(r"used\s*=\s*([\d.,]+)", out)
        if not tot or not used:
            return None
        t, u = _num(tot.group(1)), _num(used.group(1))
        return (u / t) if t and u is not None and t > 0 else None
    info = _meminfo()
    total, free = info.get("SwapTotal"), info.get("SwapFree")
    if not total or free is None:
        return None
    return (total - free) / total


# Swap pressure is reported, never used as a verdict. The first version of this module gated on
# `used/total > 0.85` and asserted that the pages had "nowhere to go". The reference machine
# falsified it: swap read `total = 14336M` during the incident and `16384M` a day later, because
# macOS grows the swapfile on demand — with hundreds of GiB free on the volume, the denominator
# expands to meet the numerator, so a machine that swaps at all settles near the ceiling and stays
# there. Gating on it refused every RAG query on that machine until reboot.
#
# It was never load-bearing anyway: at the incident the host had 2.3 GiB available against a 2.4 GiB
# reserve, so the memory comparison alone refuses that load. The signal is kept because it tells an
# operator something true — this host has been paging — and that belongs in a message, not a gate.
OVERRIDE_ENV = "EVENTHOUND_ALLOW_LOW_MEMORY"


def override_active() -> bool:
    """True when the operator has taken responsibility for the host themselves."""
    import os
    return os.environ.get(OVERRIDE_ENV, "").strip().lower() in ("1", "true", "yes")


def swap_note() -> str:
    """" (swap is N% full)" when this host has been paging, else "". Context, not a verdict."""
    frac = swap_used_fraction()
    return f" (swap is {frac * 100:.0f}% full)" if frac is not None and frac > 0.5 else ""


def pressure_reason(what: str = "a large model") -> str | None:
    """Why this host cannot absorb a multi-GiB allocation right now, or None when it can.

    The weaker sibling of the LLM's `memory_preflight`, for allocations whose SIZE cannot be known:
    the RAG loads its embedding and reranking models through fastembed, which reports no footprint
    and caches wherever it likes. Rather than hardcode a guess, this answers the question that can
    be answered honestly — is there any headroom at all — and says nothing when there is. It fails
    open on every unmeasurable input, for the same reason everything here does.
    """
    if override_active():
        return None
    avail, reserve = available_bytes(), reserve_bytes()
    if avail is not None and avail < reserve:
        return (f"loading {what} would leave this host nothing: {avail / GIB:.1f} GiB available "
                f"against a {reserve / GIB:.1f} GiB reserve{swap_note()}. Free memory, or set "
                f"{OVERRIDE_ENV}=1 to proceed anyway.")
    return None
