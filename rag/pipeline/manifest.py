from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_PATH = Path(__file__).resolve().parent.parent / "index_manifest.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Manifest:
    """Tracks what has been indexed: per source (documents, chunks,
    collection, timestamp) and aggregated per collection. Loads the existing
    manifest so partial ingests update instead of overwriting."""

    def __init__(self, path: Path | str = MANIFEST_PATH):
        self.path = Path(path)
        self.sources: dict = {}
        if self.path.exists():
            try:
                self.sources = json.loads(self.path.read_text(encoding="utf-8")).get("sources", {})
            except Exception as exc:
                # Corrupt manifest: do NOT silently reset it, otherwise the next write()
                # would overwrite the inventory of ALL other sources (see docstring). We set
                # aside the damaged file and stop the run, so the operator notices.
                backup = self.path.with_suffix(self.path.suffix + ".corrupt")
                try:
                    self.path.replace(backup)
                except OSError:
                    backup = self.path
                raise RuntimeError(
                    f"index_manifest.json corrupt ({type(exc).__name__}: {exc}); "
                    f"saved as {backup}. Restore from git or regenerate before re-indexing."
                ) from exc

    def record(self, source_id, collection, source_name, documents, chunks) -> None:
        self.sources[source_id] = {
            "collection": collection,
            "source_name": source_name,
            "documents": documents,
            "chunks": chunks,
            "ingested_at": _now(),
        }

    def write(self) -> Path:
        collections: dict = {}
        for sid, info in self.sources.items():
            # .get: a legacy/malformed entry without 'collection' must not raise a KeyError and
            # lose the entire manifest write; it ends up in a visible "_unknown" bucket, not discarded.
            coll = info.get("collection") or "_unknown"
            agg = collections.setdefault(coll, {"sources": [], "chunks": 0})
            agg["sources"].append(sid)
            agg["chunks"] += info.get("chunks", 0)

        payload = {
            "generated_at": _now(),
            "collections": collections,
            "sources": self.sources,
        }
        self.path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return self.path
