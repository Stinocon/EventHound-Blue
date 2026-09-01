from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Document:
    """Content unit acquired from a source, before chunking.

    locator: stable identifier (PDF path or page URL). It becomes part of the
             deterministic ID of the Qdrant points, so re-ingesting updates
             instead of duplicating.
    """

    locator: str
    text: str
    metadata: dict = field(default_factory=dict)
