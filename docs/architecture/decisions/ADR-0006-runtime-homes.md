# ADR-0006: Opaque per-user provider runtime homes

- Status: Accepted
- Owner: Runtime Platform

## Context

Official subscription runtimes manage OAuth state in vendor-specific homes.
Sharing or mounting those homes would cross user, tenant, and sandbox borders.

## Decision

Runtime Broker allocates an encrypted opaque home for exactly one requesting
user, provider, and connection. Only the broker can address or mount it. Homes
never enter application responses, model context, Runner namespaces, exports,
logs, backups outside the encrypted policy, or another user's runtime process.

Runtime launch is serialized per connection, pinned to an approved version,
restricted to provider-only egress, and starts only after capability probes.
Disconnect, revocation, failed reauthentication, or account mismatch closes
sessions and schedules cryptographic destruction. There is no silent fallback.

## Verification and consequences

Conformance tests probe cross-user paths, filesystem/environment disclosure,
concurrent leases, token canaries, revocation, and cleanup receipts. The core
domain sees only opaque connection IDs and normalized runtime events.

