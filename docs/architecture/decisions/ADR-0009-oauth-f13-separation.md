# ADR-0009: Provider OAuth state is separate from F13 credentials

- Status: Accepted
- Owners: Runtime Security, Connector Security

## Context

Requester-owned subscription authentication and Organization-owned connector
secrets have different subjects, consumers, approvals, and revocation semantics.

## Decision

`provider_connections` hold requester-owned provider/account metadata and an
opaque reference to the per-user runtime home. The application never models or
exports vendor refresh/access-token fields. F13 `credentials` hold Organization-
owned Connector/Tool secrets used only through Vault and one-use Broker handles.

The domains use distinct KMS purposes, data keys, tables, service identities,
ACLs, audit events, APIs, rotation flows, and deletion receipts. A Run snapshots
the requester's selected provider connection; it cannot substitute an Owner's
connection. OAuth state cannot satisfy a Connector secret scope, and F13 secret
material cannot authenticate a provider runtime.

## Verification and consequences

Security tests attempt cross-user connection use, cross-domain decrypt, OAuth
token export/logging, F13 handle replay, rotation, revocation, and deletion.
Break-glass can expose neither raw token nor raw secret.

