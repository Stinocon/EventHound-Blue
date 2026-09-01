---
title: Minimal code — the decision ladder
updated: 2026-07-23
version: 1.0.0
linked_files:
  - method/conventions.md
changelog:
  - "1.0.0 (2026-07-23) — extracted so the rule survives independently of the (undistributed) agent configuration that used to hold it."
---

# Minimal code — the decision ladder

Before writing new code, climb the ladder and stop at the **first rung that solves the problem**:

1. **Must it exist?** If the need is not concrete and current, do not write it (§7).
2. **Does it already exist here?** Reuse or extend; do not duplicate. One fact, one place (§16).
3. **Does the standard library do it?** Use it.
4. **Does a platform feature do it** — the shell, git, DuckDB, or one of the already-wrapped binaries
   (Hayabusa, tshark, Zeek, the EZ tools)? Use it.
5. **Does an already-installed dependency do it?** Use it. No new dependency for a single function.
6. **Would one line or one function do?** Then no module, class, or abstraction "for later".
7. Only then: the **minimal code** that solves it, with its tests (golden / property / end-to-end
   with auto-skip, like the rest of `analysis/tests/` and `tools/*/`).

The ladder does not suspend the method: traceability (§4/§16) and hygiene still apply. **Minimal
means minimal surface, not minimal quality** — what does get written is correct and robust from day
zero. In security a wrong query or command has a real cost (§6); robustness is not the optional part.

> The rung ordering is our restatement of the anti-over-engineering ladder from
> [Ponytail](https://github.com/DietrichGebert/ponytail) (MIT): the idea was taken and rewritten,
> nothing was installed.
