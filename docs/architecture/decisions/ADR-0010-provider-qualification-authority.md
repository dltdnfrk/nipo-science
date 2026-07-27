# ADR-0010: Provider qualification uses an external signing authority

- Status: Superseded by ADR-0011 (local-first single-user)
- Owners: Runtime Security, Data Security

## Context

A process-local seal can be recreated by the same evaluator that decides whether
a capture passed. It cannot prove the decision survived a restart, cannot support
independent verification, and lets an ordinary database writer fabricate current
qualification state. Run provenance also becomes ambiguous after a qualification
refresh unless each Run pins the receipt it actually used.

## Decision

The capture evaluator submits an exact subject-bound claim to a separately
operated Unix-socket authority. The authority alone owns its RSA private key and
returns a signed receipt; it receives no database credential. Runtime and
evaluator processes load only an exact deployment public-key set. Production
runtime identity comes from a protected deployment-supplied policy file for the
exact platform, pinned to its exact SHA-256.
The checked-in Darwin arm64 policy entry is development and test evidence only.
Unknown keys, duplicate or extra fields, malformed claims, socket ownership
violations, authority outage, and signature failure all fail closed.

Authority, qualification adopter, Run dispatcher, and cleanup worker are
separate processes with non-reused deployment credentials. The capability roles
`science_workbench_qualification`, `science_workbench_dispatcher`, and
`science_workbench_provider_cleanup` are `NOLOGIN` and `NOINHERIT`. A
separate deployment-managed dedicated `NOINHERIT` LOGIN is a member of each
respective role. All three capability roles are `NOBYPASSRLS`. The cleanup role
has no direct table visibility or mutation privilege and may execute only four
fixed `SECURITY DEFINER` functions: a database-time-clamped bounded due-candidate
list, exact locked due-work validation, and two exact completion mutations. The
adopter verifies `session_user`, role membership, role safety attributes, signature, subject,
revision, and runtime identity before executing its own fixed
append-and-connection-CAS transaction. It accepts no caller-provided SQL
callback. The dispatcher verifies the same login confinement before exact Run
insertion. The cleanup worker receives its own deployment credential, never one
resident in the ordinary application or provider runtime. The ordinary
application may read receipts but cannot append them, change the current receipt
pointer, or insert a Run.

Every model-backed Run is inserted atomically by the dedicated dispatcher with
the exact current receipt ID and digest, connection revision, selected model,
profile digest, runtime version, and executable digest. Those Run fields and
receipt rows are immutable. Qualification refresh appends history rather than
replacing it.
Capture publishes the profile first, the signed receipt sidecar second, and
requests database adoption third. Each file publication and the adopter
transaction are individually atomic, but the ordered sequence is not an atomic
triple. Adoption failure may leave non-authoritative sidecars but leaves no
database receipt or current pointer. The adopter compare-and-swap rechecks the
exact connection snapshot, including connection creation time, and the
receipt/runtime subject before commit.

On a fresh upgrade, current revision 0003 archives every observable prior
unsigned signal as `legacy_unverified`, including a bare `healthy` connection
with no qualification metadata or timestamp, before normalizing it to `pending`.
Revision `0004_provider_security` converges roles, privileges, and guards for a
deployment already stamped 0003. It does not fabricate evidence if an older 0003
already demoted and lost the bare state: the connection remains `pending`, history
remains empty, and recovery requires a pre-0003 backup under approved remediation
or a new qualification. Downgrade refuses to delete signed or legacy history.

## Verification and consequences

Production separately provisions the authority and its private key, an authority
socket, a public-key file, the adopter LOGIN, the dispatcher LOGIN, the cleanup
credential, and the exact-platform runtime policy. Historical verification keys
are retained permanently in the active key set or a permanently available
archive verifier because immutable receipt history must remain verifiable.
Authority, adopter, dispatcher, or cleanup outage fails the affected new work
closed without mutating history. Tests cover external issuance, public-only
restart verification, refresh history, exact Run binding, migration,
ordinary-role forgery, dedicated-login mismatch, cleanup separation, and the
absence of an arbitrary writer callback. Those code-path checks do not claim a
successful external live qualification: the current external attempt is blocked
by the provider subscription usage limit, and release remains blocked until a
fresh deployment attempt succeeds.
