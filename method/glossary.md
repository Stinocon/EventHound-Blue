---
title: Cybersecurity glossary
updated: 2026-09-11
version: 0.2.2
linked_files:
  - method/security-instructions.md
  - method/framework/INDEX.md
changelog:
  - "0.2.2 — 2026-09-11 — `rag/sources.yaml` left `linked_files` after the RAG removal (2026-09-01)."
  - "0.1.0 — 2026-06-14 — initial draft, base entries."
  - "0.2.0 — 2026-06-14 — expansion across domains: IT/systems, networking, identity, cryptography, malware, attacks, OT/ICS, cloud, IR/forensics."
  - "0.2.1 — 2026-07-20 — English translation."
---

# Glossary

Broad terminological reference on cybersecurity, IT, OT, systems, networking and malware. Grows over time; should be reconciled with the **NIST CSRC glossary**. Vendor-specific terminology is deliberately out of scope.

## Fundamentals

- **CIA triad** — Confidentiality, Integrity, Availability: the three objectives of information security.
- **AAA** — Authentication, Authorization, Accounting: identity, permissions, tracking.
- **Threat / Vulnerability / Risk** — threat (potential agent/event), vulnerability (exploitable weakness), risk (probability × impact).
- **Exploit** — code or technique that exploits a vulnerability.
- **Asset** — valuable resource to protect (data, system, service).
- **Attack surface** — set of exposed attack points.
- **Defense in depth** — multiple independent control layers.
- **Least privilege** — grant only minimum necessary permissions.
- **Zero Trust** — don't implicitly trust network or identity; always verify.
- **IoC / IoA** — Indicator of Compromise (observable artifact) / Indicator of Attack (behavioral sequence).
- **TTP** — Tactics, Techniques, Procedures: the "how" of an adversary (MITRE ATT&CK).

## IT and operating systems

- **Process / Thread** — instance of a running program / internal execution unit.
- **Privilege / Token (Windows)** — rights associated with an account; the access token carries SID and privileges.
- **SID** — Security Identifier: unique identifier of a principal in Windows.
- **System Registry (Registry)** — Windows configuration database; common persistence key.
- **Service / Daemon** — background process (Windows service / *nix daemon).
- **LOLBins / LOLBAS** — Living-Off-the-Land Binaries: legitimate system binaries abused (e.g. `rundll32`, `certutil`).
- **Scheduled task / cron** — scheduled execution mechanisms, often used for persistence.
- **UAC** — User Account Control: privilege elevation in Windows.
- **Sandbox** — isolated environment for running untrusted code.
- **Hypervisor / VM / Container** — hardware virtualization / virtual machine / OS-level isolation.

## Networking

- **TCP/IP, UDP** — transport protocol suite; TCP is reliable/connection-oriented, UDP is connectionless.
- **Port** — logical endpoint of a service (e.g. 443 HTTPS, 53 DNS, 3389 RDP, 445 SMB).
- **DNS** — name→IP resolution; abused for tunneling/C2 and fast flux.
- **DHCP** — dynamic IP address assignment.
- **NAT / PAT** — address/port translation between networks.
- **VLAN / Segmentation** — logical traffic separation to reduce lateral movement.
- **Firewall / IDS / IPS** — traffic control / intrusion detection / intrusion prevention.
- **Proxy / Reverse proxy** — intermediary for outbound traffic / toward internal services.
- **VPN** — encrypted tunnel between networks/hosts.
- **TLS/SSL** — channel encryption; basis of HTTPS.
- **Netflow / PCAP** — flow metadata / full packet capture.
- **C2 (Command & Control)** — channel through which the attacker commands compromised hosts; beaconing = periodic check-in.

## Identity & Access Management

- **IAM** — identity and access management.
- **Active Directory (AD)** — Windows directory service; domains, OUs, GPOs.
- **LDAP** — directory access protocol.
- **Kerberos** — ticket-based AD authentication (TGT/TGS); target of Kerberoasting, Golden/Silver Ticket attacks.
- **SSO** — Single Sign-On: one authentication for multiple services.
- **MFA / 2FA** — multi-factor authentication.
- **SAML / OAuth 2.0 / OIDC** — federation and authorization/identity for web and APIs.
- **PAM** — Privileged Access Management: control of privileged accounts.
- **Pass-the-Hash / Pass-the-Ticket** — hash/ticket reuse to authenticate without password.

## Cryptography

- **Symmetric / Asymmetric** — same key (AES) / public-private pair (RSA, ECC).
- **Hash** — one-way function (SHA-256); for file integrity and identification.
- **HMAC** — keyed hash for authenticity/integrity.
- **PKI / Certificate / CA** — public key infrastructure; certificates signed by a Certification Authority.
- **Salt / KDF** — random value and derivation function to strengthen password hashes (bcrypt, Argon2).
- **Encryption at rest / in transit** — data encrypted on disk / in transit.

## Malware

- **Virus / Worm** — code that spreads via a host file / independently over the network.
- **Trojan** — apparently legitimate software with malicious payload.
- **Ransomware** — encrypts data and demands ransom; often with double extortion (exfiltration + encryption).
- **RAT** — Remote Access Trojan: remote control of the host.
- **Rootkit / Bootkit** — deep hiding at OS / boot level.
- **Loader / Dropper / Stager** — component that downloads/installs/launches the next payload.
- **Backdoor** — hidden persistent access.
- **Keylogger / Infostealer** — keystroke capture / credential and data theft.
- **Botnet** — network of compromised hosts commanded via C2.
- **Fileless malware** — in-memory execution without disk artifacts (e.g. via PowerShell/WMI).
- **Packer / Obfuscation** — compression/obfuscation to evade detection.

## Attacks and techniques (aligned with ATT&CK tactics)

- **Phishing / Spear phishing** — email deception for credentials or execution (Initial Access).
- **Initial Access / Execution** — initial access / code execution.
- **Persistence** — maintain access over time.
- **Privilege Escalation** — obtain higher privileges.
- **Defense Evasion** — evade security controls.
- **Credential Access** — credential theft (LSASS dumping, Kerberoasting).
- **Discovery** — internal reconnaissance of hosts, users, network.
- **Lateral Movement** — movement between hosts (RDP, SMB, PsExec, WMI).
- **Collection / Exfiltration** — data collection and exfiltration.
- **Impact** — destruction, encryption, manipulation (ransomware, wiper).
- **Supply chain attack** — compromise via trusted supplier/component.
- **DoS / DDoS** — service denial, also distributed.
- **MITM** — Man-in-the-Middle: traffic interception/modification.

## OT / ICS

- **OT** — Operational Technology: systems that control physical/industrial processes.
- **ICS / SCADA** — Industrial Control Systems / supervision and data acquisition.
- **PLC / RTU** — Programmable Logic Controller / Remote Terminal Unit: field controllers.
- **HMI** — Human-Machine Interface: operator interface.
- **DCS** — Distributed Control System.
- **Purdue Model** — hierarchical IT/OT segmentation in levels (0-5).
- **OT protocols** — Modbus, DNP3, OPC, PROFINET: often lacking native authentication.
- **Safety vs Security** — in OT physical safety (safety) takes priority; unavailability has kinetic impact.

## Cloud

- **IaaS / PaaS / SaaS** — service models (infrastructure / platform / software).
- **Shared Responsibility Model** — division of security responsibilities between provider and customer.
- **CSPM / CWPP / CNAPP** — cloud posture / workload protection / native application platform.
- **IMDS** — Instance Metadata Service: metadata endpoint, SSRF target for credential theft.
- **Identity federation / Conditional access** — identity federation and conditional access.

## Detection, monitoring and response

- **EDR / XDR** — Endpoint (eXtended) Detection and Response.
- **SIEM / SOAR** — log correlation / response orchestration and automation.
- **SOC** — Security Operations Center.
- **Detection / Alert** — event generated by rule or model on a suspicious criterion.
- **False positive / negative** — benign alarm / malicious activity not detected.
- **Sigma / YARA / Snort** — portable rules for log / file and memory / network traffic.
- **Threat hunting** — proactive search for threats not already alerted.
- **Triage / Containment / Eradication / Recovery** — operational response phases.
- **Severity** — criticality level (informational → critical).

## Incident Response and forensics

- **IR cycle (NIST SP 800-61)** — Preparation, Detection & Analysis, Containment/Eradication/Recovery, Post-incident.
- **IR cycle (SANS, 6 phases)** — Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned.
- **Timeline / Pivoting** — chronological reconstruction / movement between correlated entities in the investigation.
- **Forensic artifacts** — Prefetch, ShimCache, Amcache, MFT, Event Log, journal, memory.
- **Chain of custody** — chain of custody of evidence, integrity and traceability.
- **Dwell time** — time between compromise and detection.
- **IOC pivoting** — expand an indicator to find correlated activities.

## Vulnerability management

- **CVE** — unique identifier of a known vulnerability.
- **CVSS** — severity scoring (0-10).
- **CWE** — taxonomy of weakness classes.
- **KEV (CISA)** — catalog of known exploited vulnerabilities.
- **Zero-day** — vulnerability without a patch known at the time of exploitation.
- **Patch / Mitigation / Compensating control** — correction / reduction / alternative control.
