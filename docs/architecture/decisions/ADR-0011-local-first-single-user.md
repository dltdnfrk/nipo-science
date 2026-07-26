# ADR-0011: Local-first single-user deployment replaces tenant controls

- Status: Accepted
- Owners: Platform Architecture, Data Security

## Context

Nipo Science has pivoted from a hosted multi-tenant service to a single-user
research workbench that runs on the researcher's own computer against the
researcher's own provider subscriptions and API keys. Most of the control
surface SPEC-v0.4 required exists to separate one customer's data from
another's, to separate an operator from a customer, or to make a server
trustworthy to a party who does not administer it. On one researcher's machine
none of those parties exist. Removing those controls silently would leave no
record of what was given up, so this decision enumerates every one of them.

## Decision

SPEC-v0.5 supersedes SPEC-v0.4. Every control below is dropped, together with
the threat it addressed and the reason that threat does not arise, or is
otherwise handled, when the application runs on one researcher's machine under
their own operating-system account with their own keys. The common
justification, stated once: the operating system already grants the researcher
read and write access to every byte the application stores, so no control that
protects those bytes *from the researcher* can add security, and there is no
second tenant, no operator, and no server administrator to protect them from.

Tenancy and data isolation:

- **PostgreSQL row-level security (SEC01).** Protected against one tenant
  reading another tenant's rows through a shared connection. There is one
  installation, one database file, and one reader. Dropped.
- **`org_id` tenancy and tenant-preserving foreign keys.** Protected against a
  query or a foreign key crossing an organization boundary. Retained as inert
  data: SPEC-v0.5 persists fixed local constants so records stay portable and
  the shared Artifact models are reused verbatim, and forbids deriving any
  authorization decision from them.
- **Cross-tenant non-disclosing 404 (AC-TENANT, GS10).** Protected against
  existence disclosure across organizations. There is no second organization
  whose resource existence could be disclosed. Dropped.
- **Private tenant-scoped object keys (SEC02).** Protected against guessing
  another tenant's object path in shared storage. Replaced by content
  addressing in a directory the researcher owns.
- **Single-object expiring download URLs (SEC03) and authorization-aware
  download revocation (SEC15).** Protected against a leaked URL granting
  standing access to a tenant's object. The mechanism survives inside the
  reused Artifact service and still bounds token lifetime, but it is no longer
  load-bearing: the holder of the token is the owner of the file.
- **Measured GKE and gVisor isolation outcomes (SEC06, ADR-0005).** Protected
  against untrusted tenant code escaping into the platform or into another
  tenant's namespace, filesystem, or service identity. There is no platform to
  escape into and no other tenant. It is replaced by a disclosure, not by a
  substitute control: SPEC-v0.5 section 5 states that execution is in-process,
  enumerates the six controls it does *not* provide, forbids describing it as a
  sandbox, and records `execution_isolation: "in_process"` on every durable
  record. The residual risk that analysis code runs with the researcher's full
  account authority is carried explicitly rather than mitigated.

Identity, session, and the public API surface:

- **Magic-link authentication and expiring same-origin sessions (F01).**
  Protected against an unauthenticated party reaching a tenant's data over the
  internet. Nothing is reachable over the internet; SPEC-v0.5 LS01 forbids
  binding a listener beyond loopback and forbids any switch that would enable
  remote access.
- **Organizations, memberships, invitations, Owner and Member roles, and
  ownership transfer.** Protected against privilege escalation between
  colleagues sharing a tenant. There is one human and no membership graph.
  Dropped.
- **CSRF, Origin, Fetch Metadata, session rotation, and token hashing (SEC11,
  ADR-0002).** Protected against a hostile site driving an authenticated
  browser session. A loopback interface reached from a browser retains this
  exposure, so it is not dropped: LS01 keeps cross-origin state-change
  rejection and a local session credential, and drops only the parts that
  presuppose a hosted origin and a tenant cookie.
- **`/api/v1` conventions: `Idempotency-Key`, `If-Match`, secure host-only
  cookies, and the audit, deletion, and legal-hold read endpoints (section 8).**
  Protected against replay, lost updates, and unauthorized reads across a
  network boundary. The compare-and-swap and one-use approval rules that
  actually protect correctness are retained in SPEC-v0.5 sections 4 and 6; the
  HTTP framing around them is not.

Credential custody:

- **KMS envelope encryption (SEC04).** Protected against an operator or a
  database backup exposing a customer's ciphertext key material. There is no
  operator, no managed KMS, and no shared backup. Replaced by an exact local
  mechanism: the macOS Keychain holds one 32-byte master key and provider keys
  are AES-256-GCM sealed under it with the provider identifier as additional
  authenticated data.
- **F13 application Connector and Broker credentials, the Vault, and one-use
  broker handles (F13, AC-F13, AC-F13-B, AC-F13-C, AC-F13-D, ADR-0009).**
  Protected against organization-owned secrets reaching tenant code, and
  against provider OAuth material being manipulated through a credential API.
  There is no organization-owned secret: every credential is the researcher's
  own, and the two-domain separation has nothing left to separate. The
  invariant that survives is the one that still bites — SPEC-v0.5 LS03 keeps
  secrets out of every log, exception, `__repr__`, argument list, artifact, run
  record, export, and model context.
- **Official-subscription-OAuth-only, and the prohibition on API keys and
  BYOK (section 4).** Protected against a platform holding or brokering
  credentials it had no license to hold. Inverted deliberately: the local
  product is BYOK by definition, because the researcher's key never leaves
  their machine and no third party ever holds it.

Provider qualification:

- **The external Unix-socket signing authority and its receipt chain
  (ADR-0010, AC-PROVIDER-AUTHORITY).** Protected against a compromised
  application runtime forging the claim that a provider runtime had been
  qualified. Qualification exists so that a platform can prove to itself, and
  to a customer, that a binary it dispatched to was the approved one. The
  researcher chooses and installs their own provider client; there is no party
  to prove it to and no signing authority to be substituted. Dropped.
- **The qualification adopter, the dedicated Run dispatcher, the provider
  cleanup worker, their `NOLOGIN`/`NOINHERIT`/`NOBYPASSRLS` capability roles,
  and the four fixed `SECURITY DEFINER` functions (AC-PROVIDER-RUN-BINDING).**
  Protected against a compromised application role forging a receipt, choosing
  a current pointer, or inserting an unqualified Run. Those roles exist to
  fragment authority inside a database several processes share. One process
  owns one SQLite file. Dropped.
- **Qualification migrations 0003 and 0004 and `legacy_unverified` evidence
  (AC-PROVIDER-MIGRATION).** Protected the historical fact that a pre-signing
  deployment had accepted unsigned health signals. No deployment exists whose
  history needs preserving. Dropped.
- **`operator_account_ref`, adapter tiering, the required `openai_codex`
  launch default, and the `zai_glm` `unsupported_auth` registry state.**
  Protected against an operator's account correlation being mistaken for
  authorization, and against shipping an adapter whose auth mode was not
  licensed. Replaced by a flat registry of thirteen providers with no required
  default, each usable only once the researcher supplies their own credential.
- **Opaque per-user runtime homes and the Runtime Broker (ADR-0006).**
  Protected one user's provider session from another user's runtime process on
  shared infrastructure. There is one user and one home directory. Dropped.

Compliance, retention, and operations:

- **Compliance Operator legal holds (SEC16, AC-DATA).** Protected a customer's
  data from deletion while a legal obligation attached to it, under an
  authority deliberately separated from the customer. The separation is
  unenforceable on a machine the researcher administers: any hold the software
  placed could be removed with a file manager. Asserting it would be a false
  claim, so it is dropped rather than simulated. A researcher subject to a
  preservation obligation must meet it with their institution's own controls.
- **Security Incident Operator break-glass (SEC14).** Protected against
  standing operator access to customer data during an incident. There is no
  operator and no standing access to constrain. Dropped.
- **Deletion requests, receipts, tombstones, restore replay, and the 30-day
  deletion window across database, objects, exports, queue, cache, and
  qualified provider copies (AC-DATA).** Protected a customer's right to have
  a controller erase data the controller held. The researcher is the
  controller; deleting the data root deletes the data. Dropped, with one
  consequence recorded: content addressing means an unreferenced blob survives
  until the explicit sweep runs, so deletion is not instantaneous by default.
- **Append-only audit logging (SEC09) and the retention schedule — 90-day
  operational logs, one-year audit, 24-hour run events, idempotency records,
  and export blobs (SEC10).** Protected the ability to reconstruct who did
  what to whose data across an operator boundary. There is one actor, and an
  append-only log on their own disk cannot bind them. The provenance record,
  which is what actually makes results checkable, is retained in full and
  strengthened by SPEC-v0.5 section 6.
- **Hosted reliability and capacity targets NFR01-NFR04, the browser matrix
  NFR09, and PostgreSQL PITR RPO/RTO with quarterly restore evidence
  (NFR10).** Protected a service-level commitment to a customer and a recovery
  commitment for data the platform held. There is no service level and no
  platform-held copy; backup is the researcher's own. Replaced by LN01-LN08,
  which measure the things a local application can actually be held to.

Server-side orchestration, ingestion, and tool governance:

- **The transactional Run event log, SSE streaming, `Last-Event-ID` replay,
  410 on expired history, worker leases, and fencing tokens (F04, ADR-0003,
  NFR06).** Protected against a stale worker completing a Run it no longer
  owned, and against a reconnecting browser losing or duplicating events across
  a network. There is no worker fleet and no network between producer and
  reader. The property that mattered is retained in a form the local app can
  actually enforce: SPEC-v0.5 section 6 fences the produced-execution identity
  by exclusive creation so one execution publishes at most one chain, keeps
  truncation detectable, and forbids automatic replay.
- **Malware-clean upload gating (SEC07).** Protected other tenants and the
  platform from a file one tenant uploaded. The researcher supplies their own
  files to their own machine, which already runs their own endpoint controls.
  The part that still applies is retained as LS05: parsing is bounded and never
  executes input.
- **Fixed-host connectors, SSRF redirect rechecking, and the PubMed and
  OpenAlex integrations (F08, SEC13).** Protected a server's network position
  from being borrowed to reach internal addresses. A local process has no
  privileged network position to borrow. The connectors are out of scope for
  the local release vertical; if they return, retrieved text remains untrusted
  data under LS06.
- **Project Tool Grants with `allow`/`ask`/`deny` (half of F11), the
  application-as-sole-Tool-executor rule, and provider built-in tool
  disablement (ADR-0007).** Protected against a model selecting a tenant,
  credential, host, or artifact key. No tool executes in the local release
  vertical, so a grant matrix would govern nothing. The half of F11 that
  survives is the one that governs science: the immutable one-use ActionPlan
  approval bound to the canonical `ResearchIntent` digest, kept in SPEC-v0.5
  section 4.
- **The Skills subsystem and the three canonical Skill IDs (F07).** Protected
  against an unvalidated Skill declaring undeclared connector, network, or
  secret access. No Skill participates in a local deterministic run, which is
  why `skill_content_hashes` is empty by construction and disclosed as such
  rather than left as an unexplained empty tuple.

Nothing above weakens what SPEC-v0.5 keeps. Immutable Artifact Versions with
compare-and-swap commits, independently verifiable provenance, the human-owned
`ResearchIntent` and its one-use approval, the trace-only Reviewer with
`inconclusive` as a normal verdict and RV01-RV05 unchanged, research-only
non-clinical scope with refusal as a correct outcome, secrets never in
plaintext at rest, no automatic provider fallback, byte-level determinism, and
a version-pinned Export that rejects traversal, links, normalized collisions,
and credential material are all carried forward unchanged or strengthened.
Three controls are newly required because the local shape creates them: LS01
loopback-only binding, LS08 owner-only file creation, and LS10 no telemetry or
implicit cloud sync of the data root.

## Verification and consequences

`pytest apps/local/tests` exercises the controls that replaced the dropped
ones — content-addressed compare-and-swap commits, blob digest verification,
crash-ordering and sweep behaviour, provenance digest recomputation,
determinism across separate interpreters and hash seeds, credential sealing and
non-leakage, and refusal before any write — and the acceptance identifiers in
`docs/requirements/requirements-v0.5.yaml` bind each remaining control to a
test that must fail when its named behaviour breaks. Three limits are stated
rather than claimed away: this decision does not assert that the local product
provides confinement, since `execution_isolation` is `in_process` and analysis
code holds the researcher's full account authority; it does not assert that the
Keychain master-key item is restricted to this application, since it is created
without a trusted-application list; and it does not assert that the dropped
controls were unnecessary in the hosted product, only that their threats do not
arise in this one. `make verify-spec` remains pinned to SPEC-v0.4 and its
manifest, so the v0.5 contract is not yet machine-verified; extending the
verifier, and registering this decision in `docs/architecture/architecture.json`
and the threat model, are follow-on work outside this ADR.
