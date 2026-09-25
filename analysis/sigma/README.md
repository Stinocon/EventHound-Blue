# EventHound Sigma Rules

This directory contains two categories of Sigma rules for EventHound:

- **`community/sigmahq/`** — Official [SigmaHQ](https://github.com/SigmaHQ/sigma) community rules,
  fetched by `./setup.sh install` as a shallow sparse checkout of the `rules*` trees. **Not
  versioned** (gitignored) and never redistributed: they carry the **Detection Rule License**,
  not this project's MIT (see [`NOTICE.md`](../../NOTICE.md)). The resolved commit is written to
  `community/sigmahq/.sigmahq-ref`, so an install can be reproduced and an update is visible;
  `SIGMA_REF=<tag-or-commit> ./setup.sh install` pins it. Without them Hayabusa still detects,
  with the narrower reach the table below describes — `./setup.sh doctor` says which you have.
- **`custom/`** — EventHound-specific rules, versioned and maintained internally.

## Coverage

Hayabusa includes ~5000 Sigma rules but with coverage concentrated on `process_creation` (1402), `windows_generic` (407), `registry_set` (233) and `ps_script` (190).

SigmaHQ community rules fill significant gaps, covering log sources that Hayabusa does not handle well:

| Log source                    | SigmaHQ community coverage                             |
|-------------------------------|--------------------------------------------------------|
| IIS web server logs           | `windows/builtin/iis-configuration/`                   |
| DNS server (Windows DNS)      | `windows/builtin/dns_server/`                          |
| DHCP                          | `windows/builtin/system/microsoft_windows_dhcp_server/` |
| AD replication / Kerberos     | `windows/builtin/security/`, `windows/builtin/system/microsoft_windows_kerberos_key_distribution_center/` |
| Certificate services          | `windows/builtin/certificate_services_client_lifecycle_system/`, `windows/builtin/system/microsoft_windows_certification_authority/` |
| File share access (5140/5145) | `windows/builtin/security/account_management/`, `windows/builtin/security/object_access/` |
| Sysmon (extended)             | `windows/sysmon/` (broader coverage than Hayabusa subset) |
| Linux                         | `linux/` (auditd, process_creation, file_event, network_connection, builtin) |
| macOS                         | `macos/` (process_creation, file_event)                |
| Network (DNS, firewall)       | `network/dns/`, `network/firewall/`, `network/zeek/`, `network/cisco/` |
| Web server (Apache, Nginx)    | `web/product/apache/`, `web/product/nginx/`            |
| Cloud (AWS, Azure, GCP, M365) | `cloud/`                                               |

## Usage with Hayabusa

To use community and custom rules together with Hayabusa:

```bash
hayabusa csv-timeline \
  -r analysis/sigma/community/sigmahq \
  -r analysis/sigma/custom/detection \
  -d <evtx_directory>
```

## Adding a custom rule

1. Create the `.yaml` file in `analysis/sigma/custom/detection/`.
2. Follow the [Sigma specification](https://github.com/SigmaHQ/sigma-specification).
3. Use a unique UUID for the `id` field.
4. Include at least `title`, `description`, `logsource`, `detection`, `condition`, and `level`.
5. Set `status: experimental` for rules under validation.
6. Reference MITRE ATT&CK techniques in `tags`.

### Guidelines

- **False positives**: Always document known possible false positives.
- **Severity level**: Use `low`, `medium`, `high`, or `critical` per Sigma taxonomy.
- **References**: Include links to documentation, CVEs, or ATT&CK techniques.
- **Testing**: Validate the rule with representative datasets before promoting to `stable`.

## Version tracking

- **Community rules**: Cloned from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) on 2026-07-20.
  - Commit: latest available at clone time.
  - To update: `./setup.sh install` (or `SIGMA_REF=<tag> ./setup.sh install` to pin a release).
- **Custom rules**: Versioned in the EventHound repository, with `modified` date updated on each revision.

## Directory structure

```
analysis/sigma/
├── README.md                  # This file
├── community/
│   └── sigmahq/               # SigmaHQ rules (gitignored)
│       ├── application/
│       ├── category/
│       ├── cloud/
│       ├── identity/
│       ├── linux/
│       ├── macos/
│       ├── network/
│       ├── web/
│       └── windows/
└── custom/                    # EventHound rules (versioned)
    ├── README.md
    └── detection/
        ├── ldap_recon_directory_service_1644.yaml
        ├── suspicious_powershell_encoded.yaml
        └── unusual_dns_over_https.yaml
```
