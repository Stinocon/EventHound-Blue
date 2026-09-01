"""Property-based tests (Hypothesis) of the scoring oracle — complementary to golden.yaml.

The golden cases verify PUNCTUAL cases (input→expected, calculated by hand, in RIFERIMENTO.md).
These tests verify INVARIANTS over the whole space of valid inputs: properties that must hold for
ANY vector/matrix, not just the chosen examples. They find the edge cases that a golden case
doesn't think to cover.

Dev-only dependency (hypothesis), outside the MCP server runtime. Runnable via:
    cd tools/scoring && uv run --group dev python test_properties.py

Note of merit: we do NOT assert strict monotonicity of C/I/A at Scope:Changed — the official
FIRST.org formula for the impact at Changed scope (7.52·(isc−0.029) − 3.25·(isc−0.02)^15) is NOT
monotonically increasing near isc≈1 (the derivative changes sign). Asserting it would give a false
failure on a CORRECT behavior of the specification. We instead assert monotonicity on the
exploitability side (AC), where the score is monotonic by construction.
"""
from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

import scoring

# Allowed values per metric (from the official tables in scoring.py)
_V31 = {
    "AV": ["N", "A", "L", "P"], "AC": ["L", "H"], "PR": ["N", "L", "H"],
    "UI": ["N", "R"], "S": ["U", "C"], "C": ["N", "L", "H"],
    "I": ["N", "L", "H"], "A": ["N", "L", "H"],
}


def _v31_metrics(draw) -> dict:
    return {k: draw(st.sampled_from(v)) for k, v in _V31.items()}


def _v31_vector(m: dict) -> str:
    return "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"))


@st.composite
def v31_vectors(draw) -> str:
    return _v31_vector(_v31_metrics(draw))


@settings(max_examples=300)
@given(v31_vectors())
def test_v31_score_bounds_and_rounding(vector: str):
    r = scoring.cvss_v31_base(vector)
    s = r["score"]
    assert 0.0 <= s <= 10.0, f"score out of [0,10]: {s} ({vector})"
    # rounded to 1 decimal place (roundup spec): 10*score is (almost) an integer
    assert abs(s * 10 - round(s * 10)) < 1e-9, f"score not at 1 decimal place: {s} ({vector})"
    # severity consistent with the official bands
    assert r["severity"] == scoring._severity(s), r
    assert r["scope"] in ("Changed", "Unchanged")


@settings(max_examples=200)
@given(v31_vectors())
def test_v31_ac_monotonicity(vector: str):
    # AC:L (0.77) makes exploitability >= AC:H (0.44); the score is monotonically increasing
    # in exploitability by construction (impact fixed, min and roundup monotonic) → L >= H.
    m = scoring._parse_vector(vector)
    low = dict(m, AC="L")
    high = dict(m, AC="H")
    s_low = scoring.cvss_v31_base(_v31_vector(low))["score"]
    s_high = scoring.cvss_v31_base(_v31_vector(high))["score"]
    assert s_low >= s_high, f"AC:L ({s_low}) < AC:H ({s_high}) for {vector}"


@st.composite
def v40_vectors(draw) -> str:
    parts = [f"{k}:{draw(st.sampled_from(list(v)))}" for k, v in scoring._V40_BASE.items()]
    return "CVSS:4.0/" + "/".join(parts)


@settings(max_examples=200)
@given(v40_vectors())
def test_v40_complete_vector_validates(vector: str):
    r = scoring.cvss_v40_base(vector)
    # a complete v4.0 vector with valid values: recognized as valid, no missing metric,
    # score None for honesty (MacroVector table not implemented) — never an exception.
    assert r["valid"] is True, r
    assert r["missing_base_metrics"] == [], r
    assert r["score"] is None


@settings(max_examples=300)
@given(st.integers(min_value=1, max_value=10),
       st.integers(min_value=1, max_value=10),
       st.integers(min_value=1, max_value=10))
def test_risk_matrix_bounds_symmetry_monotonicity(likelihood: int, impact: int, scale: int):
    # keep likelihood/impact within the scale (out-of-range input is tested separately)
    l = min(likelihood, scale)
    i = min(impact, scale)
    r = scoring.risk_matrix(l, i, scale)
    assert r["product"] == l * i
    assert 0.0 < r["normalized"] <= 1.0, r
    assert r["level"] in ("Low", "Medium", "High", "Critical")
    # symmetry: likelihood × impact = impact × likelihood
    assert scoring.risk_matrix(i, l, scale)["normalized"] == r["normalized"]
    # monotonicity: raising the impact (scale unchanged) never lowers the normalized risk
    if i < scale:
        assert scoring.risk_matrix(l, i + 1, scale)["normalized"] >= r["normalized"]


@settings(max_examples=100)
@given(st.integers(), st.integers(), st.integers(min_value=1, max_value=10))
def test_risk_matrix_rejects_out_of_range(likelihood: int, impact: int, scale: int):
    # out of [1, scale] must raise, not return a plausible-but-wrong number
    if not (1 <= likelihood <= scale and 1 <= impact <= scale):
        try:
            scoring.risk_matrix(likelihood, impact, scale)
            assert False, f"expected ValueError for ({likelihood},{impact},{scale})"
        except ValueError:
            pass


if __name__ == "__main__":
    test_v31_score_bounds_and_rounding()
    test_v31_ac_monotonicity()
    test_v40_complete_vector_validates()
    test_risk_matrix_bounds_symmetry_monotonicity()
    test_risk_matrix_rejects_out_of_range()
    print("OK — property tests: 5 properties verified (CVSS v3.1/v4.0 + risk_matrix)")
