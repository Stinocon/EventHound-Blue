"""DETERMINISTIC scoring oracle for security (CVSS, risk, EPSS).

Principle (borrowed from PersonalFinance, "every number from a tool, never by hand"): an LLM
predicts tokens, it doesn't compute. A plausible-but-wrong CVSS base score has a real cost in
triage. Here the functions are pure and verifiable (golden.yaml + validate.py), so the numbers
come from a controlled source, not from the model's estimate.

Functions exposed (FUNZIONI dict, used by validate.py and the MCP server):
  - cvss_v31_base   CVSS v3.1 base score from the vector (official FIRST.org formula, offline)
  - cvss_v40_base   CVSS v4.0 vector validation (numeric score: follow-up, see note)
  - risk_matrix     risk = likelihood × impact on a configurable scale
  - epss_lookup     exploit probability (EPSS) — OPT-IN external lookup (egress, §15/§9)
"""
from __future__ import annotations

import math

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 — base score (official FIRST.org specification)
# ─────────────────────────────────────────────────────────────────────────────

_V31_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    # PR depends on Scope: separate table for S:U and S:C
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
           "C": {"N": 0.85, "L": 0.68, "H": 0.5}},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}
_V31_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _parse_vector(vector: str) -> dict:
    """Split a CVSS vector 'CVSS:3.1/AV:N/AC:L/...' into a dict {metric: value}.
    Tolerates the absence of the 'CVSS:x.y/' prefix."""
    parts = [p for p in (vector or "").strip().split("/") if p]
    metrics = {}
    for p in parts:
        if ":" not in p:
            raise ValueError(f"invalid component in vector: {p!r}")
        k, v = p.split(":", 1)
        # The 'CVSS:x.y' prefix is kept under the 'CVSS' key (version),
        # so the version guard in cvss_v40_base becomes effective. It is not a
        # base metric: cvss_v31_base/cvss_v40_base ignore it in their respective calculations.
        metrics[k.strip().upper()] = v.strip().upper()
    return metrics


def _roundup(x: float) -> float:
    """Round up to 1 decimal place as per the v3.1 specification (avoids the
    floating-point artifacts of a plain ceil)."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000.0) + 1) / 10.0


def _severity(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def cvss_v31_base(vector: str) -> dict:
    """CVSS v3.1 base score from the vector. Returns {score, severity, scope, vector, metrics}.

    Only BASE metrics (AV/AC/PR/UI/S/C/I/A); any temporal/environmental metrics in the
    vector are ignored for the base score. Raises ValueError if base metrics are missing
    or a value is not allowed (better to fail than to invent)."""
    m = _parse_vector(vector)
    missing = [k for k in _V31_BASE_METRICS if k not in m]
    if missing:
        raise ValueError(f"missing base metrics: {missing}")

    scope = m["S"]
    if scope not in ("U", "C"):
        raise ValueError(f"invalid Scope: {scope!r} (expected U or C)")

    def w(metric, value):
        table = _V31_WEIGHTS[metric]
        if value not in table:
            raise ValueError(f"invalid value for {metric}: {value!r}")
        return table[value]

    av, ac, ui = w("AV", m["AV"]), w("AC", m["AC"]), w("UI", m["UI"])
    pr_table = _V31_WEIGHTS["PR"][scope]
    if m["PR"] not in pr_table:
        raise ValueError(f"invalid value for PR: {m['PR']!r}")
    pr = pr_table[m["PR"]]
    c, i, a = w("C", m["C"]), w("I", m["I"]), w("A", m["A"])

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _roundup(min(impact + exploitability, 10))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10))

    return {
        "score": score,
        "severity": _severity(score),
        "scope": "Changed" if scope == "C" else "Unchanged",
        "vector": vector,
        "metrics": m,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CVSS v4.0 — vector validation (numeric score: follow-up)
# ─────────────────────────────────────────────────────────────────────────────

_V40_BASE = {
    "AV": ("N", "A", "L", "P"), "AC": ("L", "H"), "AT": ("N", "P"),
    "PR": ("N", "L", "H"), "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"), "VI": ("H", "L", "N"), "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"), "SI": ("H", "L", "N"), "SA": ("H", "L", "N"),
}


def cvss_v40_base(vector: str) -> dict:
    """Validates a CVSS v4.0 vector and extracts its base metrics.

    HONESTY NOTE (§6): the v4.0 numeric score is NOT computed from a closed-form formula but from
    an official MacroVector table (~270 entries) + interpolation. Transcribing it by hand here would
    risk wrong numbers: until the verified official table is incorporated, this function
    returns score=None with a message. Vector validation is still useful (rejects
    malformed vectors). Use the official FIRST.org calculator for the score. Follow-up tracked."""
    m = _parse_vector(vector)
    version = m.get("CVSS")
    if version is not None and version != "4.0":
        raise ValueError(f"vector is not CVSS v4.0 (declared version: {version})")
    # The VC/VI/VA/SC/SI/SA metrics exist only in v4.0 (in v3.1 they are C/I/A + Scope):
    # their total absence signals a non-v4.0 vector even without an explicit prefix.
    if not any(k in m for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        raise ValueError("vector not recognized as CVSS v4.0 (missing the VC/VI/VA/SC/SI/SA metrics)")
    missing = [k for k in _V40_BASE if k not in m]
    invalid = [f"{k}:{m[k]}" for k in _V40_BASE if k in m and m[k] not in _V40_BASE[k]]
    if invalid:
        raise ValueError(f"invalid values: {invalid}")
    valid = not missing
    if valid:
        note = ("v4.0 score not implemented (requires the official MacroVector table); "
                "vector validated. Use the FIRST.org calculator for the number.")
    else:
        note = ("v4.0 score not implemented (requires the official MacroVector table); "
                f"vector INCOMPLETE, missing base metrics: {missing}. "
                "Use the FIRST.org calculator for the number.")
    return {
        "score": None,
        "severity": None,
        "valid": valid,
        "missing_base_metrics": missing,
        "vector": vector,
        "metrics": m,
        "note": note,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Qualitative risk = likelihood × impact
# ─────────────────────────────────────────────────────────────────────────────

def risk_matrix(likelihood: int, impact: int, scale: int = 5) -> dict:
    """Risk = likelihood × impact on a 1..scale scale (default 5×5).

    Returns {product, normalized (0..1), level}. The `level` bands are a default CONVENTION
    (thresholds 0.16/0.36/0.64 on the normalized value), not a standard or quartiles:
    the organization can redefine them.
    Deterministic and verifiable; no customer data involved."""
    if not (isinstance(likelihood, int) and not isinstance(likelihood, bool)
            and isinstance(impact, int) and not isinstance(impact, bool)
            and isinstance(scale, int) and not isinstance(scale, bool)):
        raise ValueError("likelihood, impact and scale must be integers")
    if scale < 1:
        raise ValueError(f"scale must be >= 1 (received {scale})")
    if not (1 <= likelihood <= scale and 1 <= impact <= scale):
        raise ValueError(f"likelihood and impact must be within [1, {scale}]")
    product = likelihood * impact
    normalized = product / (scale * scale)
    if normalized <= 0.16:
        level = "Low"
    elif normalized <= 0.36:
        level = "Medium"
    elif normalized <= 0.64:
        level = "High"
    else:
        level = "Critical"
    return {"product": product, "normalized": round(normalized, 4), "level": level,
            "likelihood": likelihood, "impact": impact, "scale": scale}


# ─────────────────────────────────────────────────────────────────────────────
# EPSS — exploit probability over the next 30 days (external lookup, OPT-IN)
# ─────────────────────────────────────────────────────────────────────────────

def epss_lookup(cve: str, allow_egress: bool = False, timeout: float = 10.0) -> dict:
    """EPSS (Exploit Prediction Scoring System) probability for a CVE, from FIRST.org's keyless API.

    EGRESS GATE (§15/§9): by default it does NOT make network calls (allow_egress=False) and
    returns a guiding error. It's a lookup of a PUBLIC CVE: never customer data, only
    public identifiers. Enable consciously with allow_egress=True.

    Returns {cve, epss, percentile, date} or {error}."""
    import re
    cve = (cve or "").strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        return {"error": f"invalid CVE identifier: {cve!r} (expected CVE-YYYY-NNNN)"}
    if not allow_egress:
        return {"error": "egress disabled: EPSS requires a network call (FIRST.org API). "
                         "Retry with allow_egress=True (public CVEs only, never customer data — §15/§9)."}
    import json
    import urllib.request
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        rows = data.get("data") or [] if isinstance(data, dict) else []
        if not rows:
            return {"cve": cve, "epss": None, "percentile": None, "note": "no EPSS data for this CVE"}
        r = rows[0]
        return {
            "cve": cve,
            "epss": float(r["epss"]) if r.get("epss") is not None else None,
            "percentile": float(r["percentile"]) if r.get("percentile") is not None else None,
            "date": r.get("date"),
        }
    except Exception as e:
        return {"error": f"EPSS lookup failed ({type(e).__name__}): {e}"}


FUNZIONI = {
    "cvss_v31_base": cvss_v31_base,
    "cvss_v40_base": cvss_v40_base,
    "risk_matrix": risk_matrix,
    "epss_lookup": epss_lookup,
}
