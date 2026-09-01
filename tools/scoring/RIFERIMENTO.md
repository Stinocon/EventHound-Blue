# REFERENCE — hand-verification of golden cases

Expected values in `golden.yaml` are derived from the specification, not copied from output. Here is
the verification trace.

## CVSS v3.1 — formula (FIRST.org, Specification Document)

Weights: AV{N .85, A .62, L .55, P .2}, AC{L .77, H .44}, UI{N .85, R .62},
PR (S:U){N .85, L .62, H .27} / (S:C){N .85, L .68, H .5}, C/I/A{N 0, L .22, H .56}.

    ISCBase = 1 − (1−C)(1−I)(1−A)
    Impact  = 6.42·ISCBase                                   (S:U)
            = 7.52·(ISCBase−0.029) − 3.25·(ISCBase−0.02)^15  (S:C)
    Exploitability = 8.22·AV·AC·PR·UI
    BaseScore = 0                                  if Impact ≤ 0
              = roundup(min(Impact+Exploit, 10))   (S:U)
              = roundup(min(1.08·(Impact+Exploit), 10))  (S:C)

`roundup` = round up to 1 decimal place (integer algorithm from spec).
Severity: 0 None · 0.1–3.9 Low · 4.0–6.9 Medium · 7.0–8.9 High · 9.0–10.0 Critical.

### Cases

- `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`: ISCBase=1−0.44³=0.9148; Impact=6.42·0.9148=5.873;
  Exploit=8.22·.85·.77·.85·.85=3.887; sum 9.760 → **9.8 Critical**.
- same with `S:C`: Impact=7.52·(0.9148−0.029)−3.25·(0.8948)^15≈5.751; Exploit (PR:N,S:C=.85) same
  3.887; 1.08·(9.638)=10.41 → cap 10 → **10.0 Critical**.
- Heartbleed `…/S:U/C:H/I:N/A:N`: ISCBase=0.56; Impact=3.595; Exploit=3.887; 7.482 → **7.5 High**.
- local privesc `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`: Exploit=8.22·.55·.77·.62·.85=1.834;
  Impact=5.873; 7.707 → **7.8 High**.
- XSS `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`: ISCBase=1−.78·.78=0.3916; Impact (S:C)≈2.727;
  Exploit=8.22·.85·.77·.85·.62=2.835; 1.08·5.562=6.007 → **6.1 Medium**.
- `…/C:N/I:N/A:N`: ISCBase=0 → Impact 0 → **0.0 None**.

## risk_matrix

product = likelihood·impact; normalized = product/scale². Default bands (convention, not quartiles) on normalized:
≤0.16 Low · ≤0.36 Medium · ≤0.64 High · >0.64 Critical.

- 5×5 → 25, norm 1.0 → Critical · 1×2 → 2, norm 0.08 → Low · 3×3 → 9, norm 0.36 → Medium ·
  4×4 → 16, norm 0.64 → High.

## CVSS v4.0

The v4.0 numeric score does NOT derive from a closed formula but from an official MacroVector table
(~270 entries) with interpolation: not transcribed here (risk of errors). `cvss_v40_base` validates
the vector and returns `score: null` with a note. For the number: official FIRST.org calculator.

## EPSS

`epss_lookup` queries `api.first.org/data/v1/epss?cve=…` (keyless). No golden: depends on network
and values change over time. Egress OPT-IN (§15/§9).
