# ADR-0001: Isolated monorepo and service boundaries

- Status: Accepted
- Owners: Platform Architecture, API Platform

## Context

The workbench must remain independent of sibling repositories while keeping
frontend, API, workers, contracts, science code, and infrastructure coherent.

## Decision

Only `science-workbench/` is a build and write boundary. Deployable services are
`apps/web`, `services/api`, and `services/worker`; shared code is limited to
versioned packages under `packages/`. Services communicate through frozen API,
event, Runner, Artifact, and runtime contracts. No service imports another
service's implementation or reaches into sibling repositories.

Tenant authority is derived by the API. Workers receive tenant-scoped IDs and
fenced leases, never browser authority. Runner, provider runtime, Reviewer, and
artifact preview remain distinct trust zones.

## Verification and consequences

`make test-boundaries` rejects escaping imports, paths, workspaces, symlinks,
build inputs, and writes. Contract tests own cross-service compatibility.
Shared-database access does not permit bypassing the owning service's policy.

