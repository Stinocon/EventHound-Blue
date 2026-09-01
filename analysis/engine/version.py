"""Product version — single source of truth.

Consumed by the GUI (`/api/health`, displayed in Settings) and stamped into exported bundles
(`engine/bundle.py`) so an archived analysis records which build produced it. Kept aligned with the
current analysis/DESIGN.md engine milestone; bump here when the shipped product moves.

It had drifted eight milestones behind (0.27.0 against DESIGN 0.35.0) while the rule above sat in
this docstring — and this number is stamped into every exported bundle, so an archived analysis was
recording a build that had not produced it. Re-aligned 2026-08-29.
"""
APP_VERSION = "0.35.0"
