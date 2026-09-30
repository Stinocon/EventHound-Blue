"""EventHound v2 core — the lean plugin surface over the v1 engine.

The v1 adapters (``analysis/adapters/``) and analytics (``analysis/analytics/``)
stay the engine; this package gives them one uniform entry point:

- ``core.sensors`` — one plugin per source, each with ``ingest(source) -> list[dict]``
  producing the common-schema records (ECS subset, dotted keys).
- ``core.knowledge`` — the knowledge queries (ATT&CK map, compliance obligations)
  exposed through one interface.

Every module here must import the v1 packages the same way the GUI and the MCP
server do: ``sys.path.insert`` of the ``analysis/`` directory (see
``core/sensors/base.py``).
"""
