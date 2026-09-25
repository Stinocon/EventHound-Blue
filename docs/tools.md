---
title: Installing the external tools by hand
updated: 2026-09-25
version: 0.1.0
linked_files:
  - setup.sh
  - tools/setup-common.sh
  - setup-macos.sh
  - setup-linux.sh
  - NOTICE.md
  - docs/troubleshooting.md
changelog:
  - "0.1.0 — 2026-09-25 — first draft. What each external component does, what breaks without it, and how to install it without the installer: a machine with no network, a package manager that does not have it, or a version that has to be pinned."
---

# Installing the external tools by hand

`./setup.sh install` is the fast path and it is what the getting-started section recommends. This
page is for when it cannot do the job: a machine with no outbound network, a distribution whose
packages are too old, a version that has to be pinned, or a failure you want to repair one component
at a time.

**Start by asking what is actually missing.** The doctor reports every component, its version when it
has one, and the command that fixes it:

```bash
./setup.sh doctor
```

Nothing below is guessed: each entry says where the installer gets the component from, which is the
same source you can use by hand.

## What each component is for

Nothing here is redistributed with EventHound. Every one of these is somebody else's work, kept at
its own licence and its authors' terms — see [`NOTICE.md`](../NOTICE.md). `setup.sh install`
downloads them into `analysis/.tools/` (gitignored); the environment variables and the pythons are
yours to manage.

| Component | Required? | What it does | What breaks without it |
|---|---|---|---|
| `uv` | **yes** | runs the engine, the CLI and the tests | nothing runs |
| `tshark` (Wireshark) | for PCAP | flows, DNS questions, non-standard ports | a `.pcap` produces an error naming the missing tool, not a silent zero |
| `dotnet` runtime | for the EZ tools | runs the EvtxECmd/RECmd/MFTECmd dlls | the full-EVTX, registry-hive and `$MFT` paths are unavailable |
| `EvtxECmd` | optional | the full EVTX event stream (not just detections) | only Hayabusa's detections are available from EVTX |
| `RECmd` | optional | registry **hives** | `.reg` exports still work; hives do not |
| `MFTECmd` | optional | `$MFT` | no file-system timeline |
| `Hayabusa` | for EVTX | Sigma and ATT&CK matching, plus the toolbox | EVTX arrives as nothing; the rest of the suite still runs |
| SigmaHQ rules | optional | community coverage beyond Hayabusa's built-in set | Hayabusa detects on its built-in rules alone (narrower: no Linux/macOS/cloud/web) |
| `Zeek` | optional | PCAP application layer (HTTP, TLS/JA3, DNS answers, notices) | PCAP works on tshark alone, with no application layer — and the run says so |
| `yara-python` | optional | YARA file matching | the YARA CLI and the uploaded-rule path report a clean skip |
| `osquery` | not needed to run | **collecting** evidence from a host | nothing: EventHound reads a result log it is given |
| `git` | optional | the SigmaHQ sparse checkout | community rules are skipped by the installer |

## uv (required)

The Python runner. On macOS it is a Homebrew formula; elsewhere the vendor ships an installer.

```bash
# macOS
brew install uv

# Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

uv --version
```

Then build the two project environments. Both extras are named on purpose: `uv sync` resolves the
environment to exactly what you name, so asking for one alone uninstalls the other.

```bash
cd analysis     && uv sync --extra yara --extra dev
cd analysis/gui && uv sync --extra yara
```

## tshark (PCAP)

```bash
# macOS
brew install wireshark

# Debian/Ubuntu (sets the noninteractive flag: tshark otherwise asks about dumpcap)
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
# Fedora / Arch / openSUSE
sudo dnf install wireshark-cli      # or: sudo pacman -S wireshark-cli / sudo zypper install wireshark
```

On Linux a normal user may need to be in the `wireshark` group to capture live; **reading a capture
file does not require it**, which is the only thing EventHound does.

## dotnet runtime (the Eric Zimmerman tools)

These three tools are .NET assemblies, identical on every platform, run through `dotnet`.

```bash
# macOS
brew install dotnet

# Linux: from the distribution, or Microsoft's feed if the packaged version is too old
sudo apt-get install -y dotnet-sdk-9.0     # dnf: dotnet-sdk-9.0 · pacman: dotnet-sdk
```

## EvtxECmd, RECmd, MFTECmd

Three zip archives, unpacked into one directory each. The URLs are stable and version-less — the
archive is the current `net9` build — which is also why nothing here is pinned: `setup.sh install`
records what it actually downloaded in `.run/install-manifest.json` rather than asserting a version.

```bash
cd analysis/.tools
for t in EvtxECmd:evtxecmd RECmd:recmd MFTECmd:mftcmd; do
  name="${t%%:*}"; dir="${t##*:}"
  mkdir -p "$dir"
  curl -fsSL -o "/tmp/$name.zip" "https://download.ericzimmermanstools.com/net9/$name.zip"
  unzip -oq "/tmp/$name.zip" -d "$dir"
done
```

The doctor looks for `<tool>.dll` in `analysis/.tools/<dir>/` or one level below it, so a subdirectory
kept from the zip is fine. Verify with `./setup.sh doctor` — each one should read `✅`.

## Hayabusa

A release asset from GitHub, not a package. Pick the asset for your platform and unpack it under
`analysis/.tools/hayabusa/`; the doctor matches `hayabusa-*-mac-*` on macOS and `hayabusa-*-lin-*` on
Linux, so the archive's own directory name is what it expects.

```bash
# macOS (Apple silicon). The version IS in the asset name, so it cannot be a `latest` URL: read the
# current one from https://github.com/Yamato-Security/hayabusa/releases (4.1.0 at the time of
# writing, and the installer resolves it through the API for the same reason).
curl -fsSL -o /tmp/hb.zip \
  "https://github.com/Yamato-Security/hayabusa/releases/download/v4.1.0/hayabusa-4.1.0-mac-aarch64.zip"
mkdir -p analysis/.tools/hayabusa && unzip -oq /tmp/hb.zip -d analysis/.tools/hayabusa
chmod +x analysis/.tools/hayabusa/hayabusa-*
```

To pin a version, download that release's asset by URL instead of the current one — which is what the
version-in-the-name forces — and note that `setup.sh install` will leave an existing binary alone.
On Linux the asset names carry the libc too (`lin-x64-gnu`, `lin-x64-musl`, `lin-aarch64-gnu`,
`lin-aarch64-musl`); `ldd --version` tells you which, and picking the wrong one is a binary that does
not start.

## SigmaHQ community rules

Optional, and the installer provisions them with a **shallow sparse checkout** into
`analysis/sigma/community/sigmahq/` — only the rule directories are fetched, never the whole
repository, and the resolved commit is written to `.sigmahq-ref` so an analysis can say which rules
it ran against.

```bash
cd analysis/sigma && mkdir -p community/sigmahq && cd community/sigmahq
git init -q
git remote add origin https://github.com/SigmaHQ/sigma.git
git config core.sparseCheckout true
printf 'rules/\nrules-emerging-threats/\nrules-threat-hunting/\nLICENSE.Detection.Rules.md\n' \
  > .git/info/sparse-checkout
git fetch -q --depth 1 origin master && git checkout -q FETCH_HEAD
git rev-parse HEAD > .sigmahq-ref
```

Set `SIGMA_REF=<tag-or-commit>` on `./setup.sh install` to pin a different ref. The rules are **not**
redistributed with EventHound — they carry the Detection Rule Licence — which is why this is a
checkout and not a vendored copy.

## Zeek (optional)

```bash
brew install zeek                      # macOS
sudo apt-get install -y zeek           # Debian/Ubuntu; on many distributions it is not packaged
```

Zeek is genuinely optional and the installer will not add a third-party repository behind your back
to get it. A missing Zeek is **reported as a missing sensor** on every PCAP run — the flows and DNS
questions still come from tshark, and the run says that the application layer was not extracted.

## yara-python (optional)

A Python extra, not a binary:

```bash
cd analysis && uv sync --extra yara
```

Its absence is a clean skip, never a failure — but note that a missing `yara-python` means uploaded
`.yar` rules are **not** applied, and the run says so rather than reporting a scan with no hits.

## osquery (only to collect evidence)

EventHound reads an osquery **result log**; it does not run or manage osquery, and no agent is
deployed by this suite. Installing it is only about collecting evidence from a host you are
authorised to examine.

```bash
# macOS: Homebrew's cask installs a system package and a launch daemon, so it asks for sudo
brew install --cask osquery

# Linux: from the vendor's repository, or the distribution's package
#   https://osquery.io/downloads/official
```

To produce the NDJSON result log the adapter reads, run `osqueryd` with a scheduled-query config; a
plain `osqueryi --json "SELECT …"` gives a different shape (a JSON array of rows) and is fine for
reading by eye. The walkthrough in [`triage-windows.md`](triage-windows.md) shows both.

## Docker

An alternative runtime, not a dependency: the root `docker-compose.yml` builds one `eventhound` image
with the engine, the GUI and every wrapped tool baked in. It exists for reproducible deployments and
for platforms the native scripts do not cover.

## Provenance and what is not pinned

- `setup.sh install` writes `.run/install-manifest.json` with the URL and the SHA-256 of every file it
  downloaded. It is a record, not a lock: nothing verifies a pin against it, and a second install
  weeks later gets whatever the upstream release is then.
- The SigmaHQ rules are the one component with a recorded ref (`.sigmahq-ref`), because a checkout has
  a commit and a zip download does not.
