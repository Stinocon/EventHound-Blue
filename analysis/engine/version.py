"""Product version — single source of truth.

Reported by the GUI (`/api/health`, displayed in Settings) and stamped into exported bundles
(`engine/bundle.py`) and persistent cases, so an archived analysis records which build produced it.
This is the version the product presents as its own, and it must match the git release tag.

The `pyproject.toml` versions are inert on purpose (workspace environments, not distributions) and
the frontmatter `version:` counters in the README/docs are per-document changelog counters — neither
is the product version. Bump this one value when cutting a release, and tag the same number.
"""
APP_VERSION = "1.0.0"
