# EventHound Custom Sigma Rules

EventHound-specific Sigma rules, designed to cover detection gaps not addressed by the community.

## Included rules

| Rule | Description | ATT&CK |
|------|-------------|--------|
| `suspicious_powershell_encoded.yaml` | Detects PowerShell commands with encoded parameters (`-enc`, `-EncodedCommand`) | T1059.001 |
| `unusual_dns_over_https.yaml` | Detects connections to known DoH endpoints (Cloudflare, Google, OpenDNS) | T1071.004 |
| `ldap_recon_directory_service_1644.yaml` | Detects SharpHound/BloodHound/PowerView AD enumeration **on the domain controller** via NTDS event 1644 (Directory Service log) — complements the community client-side rule `win_ldap_recon` (EventID 30). Requires `Field Engineering=5` on the DC. `status: experimental` (field names grounded on Microsoft KB 3060643, pending validation on a real 1644 sample) | T1087.002, T1069.002, T1482 |

## Conventions

- All rules use Sigma 1.x format.
- `id` UUID generated once and never reused.
- `status: experimental` until validated on real datasets.
- `level: medium` as default for non-critical rules.
- MITRE ATT&CK tags normalized (`attack.<tactic>`, `attack.<id>`).

## Adding a new rule

1. Create the `.yaml` file here.
2. Specify `logsource` and `detection` with clear selection criteria.
3. Include `falsepositives:` with legitimate usage scenarios.
4. Update the table in this README.
