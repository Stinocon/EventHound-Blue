<!--
document: NOTICE — third-party material and licences
version: 1.0
updated: 2026-07-24
-->

# Third-party notices

EventHound itself is MIT-licensed (see [`LICENSE`](LICENSE)). This file records everything in or
around the project that is **somebody else's work**, and under what terms — kept honest for the same
reason the rest of the repository is: an attribution nobody can check is not an attribution.

Two categories, and the distinction matters legally as much as practically.

## 1. Third-party material redistributed in this repository

This is what you receive when you clone. It is covered by its own licence, not by EventHound's.

| What | Where | Author | Licence |
|---|---|---|---|
| **Material Symbols** icon paths (Outlined, 24 px, `viewBox 0 -960 960 960`), embedded inline as SVG path data | `analysis/gui/static/lib.js` (`ICON_PATHS`), `analysis/gui/static/index.html` | Google | [Apache-2.0](https://github.com/google/material-design-icons/blob/master/LICENSE) |
| **MITRE ATT&CK®** technique identifiers, names and tactic assignments (Enterprise v19.1) — a derivative of the official STIX bundle, generated offline by `analytics/build_attack_map.py` | `analysis/analytics/attack_map.json` | The MITRE Corporation | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |

**© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation.** ATT&CK's terms grant the licence and require that any copy carry both that
designation and the terms; the same notice is embedded in the file itself (`_copyright`), so it
travels even when the JSON is copied out of the repository on its own. The map holds identifiers,
names and tactics — the vocabulary the engine needs to say what `T1021.002` *is* offline — and not
ATT&CK's descriptive text.

This row was missing until 2026-08-29, while section 3 below affirmatively stated that the ATT&CK
bundle was not redistributed here. It is: not the bundle, but a derivative of it, tracked and
shipped with every clone. Recorded plainly rather than quietly corrected, because an attribution
nobody can check is the thing this file exists to prevent.

One icon in that map is **not** Google's: `hub`, used by the Attack Map view, is drawn in this
repository in the same grid because the vendored Material set carries no graph glyph. It is
marked as such at its definition, so the Apache-2.0 attribution above is not read as covering
something it does not.

The icons are inlined rather than fetched from a CDN because the GUI must work fully offline and
under a strict CSP. Inlining does not change their licence: the Apache-2.0 attribution above travels
with any copy of this repository.

## 2. Tools EventHound drives but does **not** include

None of the following is redistributed here. They are downloaded to the gitignored
`analysis/.tools/` by `setup.sh install`, or expected on `PATH`, and each remains under its own
licence and its authors' terms — **which you accept by installing them**, not by using EventHound.
This is the deliberate design decision recorded in `docs/roadmap.md`: *wrapped, never reimplemented*,
and *documented, never vendored*.

| Tool | Role here | Author |
|---|---|---|
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | EVTX timeline and Sigma detection | Yamato Security |
| [Sigma rules](https://github.com/SigmaHQ/sigma) (bundled with Hayabusa, plus optional community sets) | detection content | SigmaHQ and contributors — note the community rules carry the **Detection Rule License**, not MIT |
| [Eric Zimmerman's tools](https://ericzimmermanstools.com/) (EvtxECmd, MFTECmd, RECmd) | EVTX full stream, MFT, registry | Eric Zimmerman |
| [Zeek](https://zeek.org/) | PCAP application-layer enrichment (optional) | The Zeek Project |
| [tshark / Wireshark](https://www.wireshark.org/) | PCAP parsing | Wireshark Foundation |
| [THOR](https://www.nextron-systems.com/thor/) | scan reports are *read*; the scanner is commercial and is not part of this | Nextron Systems |
| Python dependencies | see each `pyproject.toml` | respective authors |

**YARA rules** follow the same rule and are worth calling out because it is a common mistake: none
are vendored. `docs/analysis/yara-rules.md` points at licence-verified sources and
`analysis/yara_rules/` is gitignored, so rules you clone locally never end up committed under this
repository's licence.

## 3. Data in the local knowledge base

The knowledge base lives as **markdown** under `method/` (frameworks, `normative/`, `acn/`,
`fonti/`) and is built from sources that are **not** redistributed here: the MITRE ATT&CK STIX
**bundle** (MITRE, [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/))
and the official texts of GDPR / NIS2 / DORA and ACN guidance, each under its own terms. The raw
PDFs under `method/acn/` are gitignored. The small offline **derivative** the engine needs —
technique id → name and tactics — is tracked, and is listed in section 1 above with MITRE's required
copyright designation. The regulatory material is a starting point for verification, **never legal
advice**.
