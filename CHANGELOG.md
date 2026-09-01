# Changelog

What changed between released versions, in one screen. The **reasoning** — why a thing was built,
why another was refused, what a fix cost — lives in [`docs/roadmap.md`](docs/roadmap.md), which is
the single source of truth for the state of the project. This file is the index into it, not a
second copy of it: two documents saying the same thing in different words is how they start
disagreeing.

The product version is `analysis/engine/version.py` (`APP_VERSION`). It is stamped into every
exported analysis bundle, so an archived case records which build produced it.

## Unreleased

Everything since the last tag. The first tag has not been cut yet — see
[README, "How mature is it, concretely"](README.md#how-mature-is-it-concretely) for what the project
does and does not claim about itself today.

- **The GUI stopped double-counting evidence.** Every Analyze click re-sent the whole accumulated
  session, and the case store's duplicate check hashes the whole batch: an overlapping batch was
  accepted and the earlier files were persisted twice, inflating every additive number.
- **A missing tool stopped reading as an empty result.** Adapter failures now carry the tool's own
  message (scrubbed of absolute paths — these strings reach reports and bundles), and a missing Zeek
  is stated instead of passed over.
- **The interface stopped asserting things it had not checked.** Per-view notices for missing tools,
  a real probe of Qdrant / rag-api / Ollama in Settings, the Assistant reporting unavailability on
  arrival, and the outbound-lookup switch actually reaching the assistant.
- **`--json-out PATH`** is the canonical way to write JSON from the CLIs that take a path
  (`--json PATH` still works and says it is deprecated), and **`run_case new|add` takes all eleven
  sources**, so MFT, osquery, CrowdStrike and YARA evidence can enter a persistent case.
- **The gate is green in a fresh clone**, verified by cloning into a temporary directory and running
  it there. Two documentation guards were failing or crashing outside the author's own tree.
