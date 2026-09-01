# tools/scoring — deterministic scoring oracle

**Verifiable** calculation of security scores, so numbers come from a controlled source and
not from model estimation (a wrong CVSS base score costs in triage). Same principle as PersonalFinance's
calculator: pure functions + golden tests as gates for correctness.

## Functions (`scoring.FUNCTIONS`)

| function | what it does | source / status |
|----------|---------|---------------|
| `cvss_v31_base(vector)` | CVSS v3.1 base score from vector | official FIRST.org formula — **offline, golden-tested** |
| `cvss_v40_base(vector)` | validates CVSS v4.0 vector, extracts metrics | **numeric score: follow-up** (needs official MacroVector table); validation active |
| `risk_matrix(likelihood, impact, scale=5)` | risk = likelihood × impact | `level` bands = default convention (thresholds 0.16/0.36/0.64 on normalized), not standard nor quartiles |
| `epss_lookup(cve, allow_egress=False)` | EPSS probability of CVE | keyless FIRST.org API — **egress OPT-IN** (§15/§9) |

## Usage

Golden (correctness gate):

    cd tools/scoring && uv run python validate.py

Quick CLI:

    uv run python -c "import scoring, json; print(json.dumps(scoring.cvss_v31_base('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')))"

As MCP tool: registered in `.mcp.json` (server `scoring`) — exposes `cvss_v31_base`, `cvss_v40_base`,
`risk_matrix`, `epss_lookup` natively in session.

## Notes

- **EPSS is the only egress point** and is disabled by default: requires `allow_egress=True` and
  concerns only public CVEs, never client data (§15/§9). Consistent with Phase 6 of
  `analysis/DESIGN.md` (enrichment from external threat intel).
- Expected values in `golden.yaml` are hand-verified in `RIFERIMENTO.md`, not copied from output:
  if a weight or rounding changes, golden breaks (that's its purpose).
- `cvss_v31_base` considers only **base** metrics; temporal/environmental metrics in the vector
  are ignored for base score purposes.
