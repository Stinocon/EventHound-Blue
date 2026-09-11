---
title: Troubleshooting
updated: 2026-09-11
version: 0.1.0
linked_files:
  - README.md
  - tools/check.sh
changelog:
  - "0.1.0 — 2026-09-11 — moved here from the README, which was getting long."
---

# Troubleshooting

- **Port 8700 already in use.** `./setup.sh down gui` stops the one this project started (its pid is
  in `.run/gui.pid`). If something else owns the port, `analysis/gui/serve.sh` honours
  `ANALISI_GUI_PORT` — but `./setup.sh up gui` hardcodes 8700, so start it through `serve.sh`
  directly when you need another port.
- **Edited Python and the GUI did not change.** The server does not reload:
  `./setup.sh down gui && ./setup.sh up gui`. Editing `static/index.html` only needs a browser reload.
- **`install` could not fetch Hayabusa.** It names the cause: no network, GitHub's unauthenticated
  releases API rate-limiting you (60 requests an hour per address — wait it out, or download the
  release yourself into `analysis/.tools/`), or a release whose assets no longer match the expected name.
- **`install` ended with a FAILED list.** It prints a summary of what was installed, skipped and
  failed, and exits non-zero if anything failed — a half-installed system and a complete one used to
  end identically. `./setup.sh all` still starts what it has and still runs `doctor` afterwards:
  a missing optional tool is not a reason for nothing to start. `doctor` then names what is missing
  and what it costs.
- **Which build of Hayabusa / the EZ tools is this?** `.run/install-manifest.json` records
  the version and sha256 of everything `install` downloaded. Nothing pins those downloads — that is
  an open question, not a solved one — but what was taken is written down.
- **The trust-surface guard complains on a fresh clone.** Expected: the baseline is local by design.
  Generate it once (`tools/check-config-integrity.sh --update`, see `docs/development.md`). It is a
  soft check and never blocks.
- **The leak guard reports PARTIAL.** Also expected until `data/pseudonym-map.md` exists — with no
  map there are no identifiers to search for, and the guard says so rather than reporting a pass it
  did not earn.
- **A source produced no records and no error.** Check the warnings line above the results: a missing
  tool now names itself and says what it costs. If Zeek is absent, PCAP analysis runs on tshark alone
  and the application layer is missing — that is reported, not silent.
