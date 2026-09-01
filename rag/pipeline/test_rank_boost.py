"""Unit test (offline) of the reliability/recency ranking boost — retrieve._rank_boost.

Pure function, no dependency on Qdrant or the models: checks monotonicity for reliability
(the `level` field), recency only on time-sensitive categories, window clamping and
handling of missing inputs. Runs in check.sh with no network and no models.

Usage:  cd rag && uv run python -m pipeline.test_rank_boost   (exits !=0 on the first failed assert)
"""
from __future__ import annotations

from .config import (RECENCY_YEAR_FLOOR as FLOOR, RERANK_RECENCY_WEIGHT as W_REC,
                     RERANK_RELIABILITY_WEIGHT as W_REL)
from .retrieve import _rank_boost

CUR = 2026
EPS = 1e-9

# a time-sensitive category (from config) and a non-time-sensitive one; used to isolate the recency half
TS = "cve"          # in TIME_SENSITIVE_CATEGORIES
NON_TS = "framework"  # outside


def approx(a: float, b: float) -> None:
    assert abs(a - b) < EPS, f"expected {b}, got {a}"


def test_reliability_monotonic_and_values():
    # non-time-sensitive category: only the reliability boost applies
    approx(_rank_boost({"level": 1, "category": NON_TS}, CUR), W_REL * 1.0)   # level 1 full
    approx(_rank_boost({"level": 2, "category": NON_TS}, CUR), W_REL * 0.5)   # level 2 half
    approx(_rank_boost({"level": 3, "category": NON_TS}, CUR), 0.0)           # level 3 zero
    b1 = _rank_boost({"level": 1, "category": NON_TS}, CUR)
    b2 = _rank_boost({"level": 2, "category": NON_TS}, CUR)
    b3 = _rank_boost({"level": 3, "category": NON_TS}, CUR)
    assert b1 > b2 > b3


def test_unknown_level_treated_as_center():
    center = W_REL * 0.5  # like level 2
    approx(_rank_boost({"category": NON_TS}, CUR), center)                    # missing
    approx(_rank_boost({"level": None, "category": NON_TS}, CUR), center)
    approx(_rank_boost({"level": True, "category": NON_TS}, CUR), center)     # bool != 1
    approx(_rank_boost({"level": 7, "category": NON_TS}, CUR), center)        # out of range


def test_recency_only_time_sensitive():
    # time-sensitive category: 2026 gets the full boost, 2015 (=floor) no recency
    approx(_rank_boost({"level": 2, "category": TS, "year": CUR}, CUR), W_REL * 0.5 + W_REC)
    approx(_rank_boost({"level": 2, "category": TS, "year": FLOOR}, CUR), W_REL * 0.5)
    # same reliability and a recent year BUT a non-time-sensitive category: no recency boost
    approx(_rank_boost({"level": 2, "category": NON_TS, "year": CUR}, CUR), W_REL * 0.5)
    # real cyber payload (without `category`): inert, reliability only
    approx(_rank_boost({"level": 2, "year": CUR}, CUR), W_REL * 0.5)


def test_recency_clamp_and_missing_year():
    approx(_rank_boost({"level": 2, "category": TS, "year": 2000}, CUR), W_REL * 0.5)          # < floor -> 0
    approx(_rank_boost({"level": 2, "category": TS, "year": 3000}, CUR), W_REL * 0.5 + W_REC)  # future -> full
    approx(_rank_boost({"level": 2, "category": TS}, CUR), W_REL * 0.5)                        # missing year
    approx(_rank_boost({"level": 2, "category": TS, "year": "?"}, CUR), W_REL * 0.5)           # non-integer


def test_boost_always_non_negative_and_small():
    # invariant: >= 0 and <= sum of weights (the tie-breaker can't dominate relevance)
    for lvl in (1, 2, 3, None):
        for cat in (TS, NON_TS, None):
            for yr in (1990, 2015, 2026, 3000, "?", None):
                b = _rank_boost({"level": lvl, "category": cat, "year": yr}, CUR)
                assert 0.0 <= b <= W_REL + W_REC + EPS, f"boost out of range: {b} ({lvl},{cat},{yr})"


def test_memory_guard_refuses_and_fails_open():
    """The RAG must not load gigabytes onto a host with no room, and must not stop answering
    because it could not measure one. Host readings are injected — a test that consulted the real
    machine would pass or fail on what the developer happened to have open."""
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
    from tools import hostmem

    from . import retrieve  # noqa: F401 — smoke: it must still import once the guard moved out
    from .embedder import Embedder, guard_memory
    real = (hostmem.available_bytes, hostmem.swap_used_fraction, hostmem.total_bytes)
    try:
        hostmem.total_bytes = lambda: 16 * hostmem.GIB
        # no headroom at all -> refuse, before any model object is constructed
        hostmem.available_bytes = lambda: int(0.2 * hostmem.GIB)
        hostmem.swap_used_fraction = lambda: 0.1
        try:
            guard_memory("the RAG embedding model")
            raise AssertionError("expected a refusal on a host with no headroom")
        except RuntimeError as e:
            assert "refusing to load" in str(e), e
        # swap high but memory fine -> must PROCEED. Swap was a gate and the premise was wrong:
        # macOS grows the swapfile on demand, so the ratio sits near its ceiling on any host that
        # has ever paged, and this refused every RAG query on the reference machine until reboot.
        hostmem.available_bytes = lambda: 12 * hostmem.GIB
        hostmem.swap_used_fraction = lambda: 0.95
        guard_memory("the RAG reranking model")
        # it still belongs in the message when memory IS the reason
        hostmem.available_bytes = lambda: int(0.2 * hostmem.GIB)
        try:
            guard_memory("the RAG embedding model")
            raise AssertionError("expected a refusal on a host with no headroom")
        except RuntimeError as e:
            assert "swap is 95% full" in str(e), f"swap dropped from the message entirely: {e}"
        # room, and unmeasurable: both must proceed
        hostmem.available_bytes = lambda: 12 * hostmem.GIB
        hostmem.swap_used_fraction = lambda: 0.1
        guard_memory("the RAG embedding model")
        hostmem.available_bytes = lambda: None
        hostmem.swap_used_fraction = lambda: None
        guard_memory("the RAG embedding model")
        # The guard belongs to the CONSTRUCTOR, not to retrieve's lazy getters: `evaluate` and
        # `ingest` build an Embedder directly, so a guard the callers had to remember to call left
        # the heaviest load in the project — a full ingest — unguarded. Asserted on the class, not
        # on those two modules, so the coverage does not depend on who imports what today.
        hostmem.available_bytes = lambda: int(0.2 * hostmem.GIB)
        hostmem.swap_used_fraction = lambda: 0.1
        # `_build` is stubbed after the guard call it is being tested for: if the guard ever fails
        # to raise, this must report that — not fall through into `from fastembed import
        # TextEmbedding` and pull 2.1 GB, in a file whose contract is no network and no models.
        built = []
        real_build = Embedder._build

        def _guarded_stub(self):
            guard_memory("the RAG embedding model")
            built.append(self.model)
            return object()

        Embedder._build = _guarded_stub
        try:
            Embedder(backend="fastembed")
            raise AssertionError(f"Embedder() allocated on a host with no headroom: {built}")
        except RuntimeError as e:
            assert "refusing to load" in str(e), e
        finally:
            Embedder._build = real_build
        assert not built, "the guard ran after the allocation, not before it"
    finally:
        hostmem.available_bytes, hostmem.swap_used_fraction, hostmem.total_bytes = real


if __name__ == "__main__":
    test_reliability_monotonic_and_values()
    test_unknown_level_treated_as_center()
    test_recency_only_time_sensitive()
    test_recency_clamp_and_missing_year()
    test_boost_always_non_negative_and_small()
    test_memory_guard_refuses_and_fails_open()
    print("OK — _rank_boost: 5 tests passed, plus the RAG memory guard")
