"""Nipo Science local application.

A single-user, on-device research workbench. The researcher supplies a
`ResearchIntent`, approves an ActionPlan, and deterministic Python runs in
process; every output is recorded as an immutable Artifact Version with its
provenance. Provider subscriptions and API keys belong to the researcher and
never leave this machine.

This package deliberately reuses two existing assets verbatim rather than
reimplementing them:

- `science_workbench_science` — the deterministic probe/spectrum analysis.
- `services.api.artifacts` — the Artifact model contracts and `ArtifactService`,
  which depend only on the `ArtifactStore` protocol and therefore accept a local
  SQLite-plus-filesystem adapter without modification.

The multi-tenant fields those contracts require are satisfied by the fixed
single-user constants in `nipo_local.config`.
"""
