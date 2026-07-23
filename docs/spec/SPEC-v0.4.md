---
document_id: FS-SPEC-001
version: "0.4"
status: normative
requirements_manifest: docs/requirements/requirements.yaml
---

# Science Workbench MVP specification v0.4

## 0. Normative status

This document is the self-contained product and engineering contract for the MVP. `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, and `MAY` are normative. The ID-keyed machine contract in `docs/requirements/requirements.yaml` is the implementation and verification authority. If this prose and that manifest diverge, delivery stops until both are amended together.

The product is a research-support workbench. It MUST NOT make clinical diagnoses, patient-care decisions, or automate detailed regulated-pathogen procedures. Inputs that lack calibration, units, or safe research context MUST stop as `insufficient_data`, an inconclusive result, or a safe refusal; the system MUST NOT fabricate a diagnosis or missing evidence.

## 1. Product contract and deterministic dry-lab path

The primary P0 outcome is this ordered, observable chain:

1. A researcher supplies a validated spectrum, image, table, or report.
2. The researcher supplies a complete `ResearchIntent` stating the question, why the research matters, intended benefit, success criteria, domain and safety constraints, stop conditions, declared research mode, and data origin.
3. The system creates a versioned ActionPlan. Approval fixes the canonical `ResearchIntent` digest and plan digest before execution.
4. The approved plan runs deterministic Python in an isolated Session Kernel.
5. The execution creates normalized CSV, PNG, Markdown, and evidence Ledger Artifact Versions.
6. Provenance pins the `ResearchIntent`, input checksums, code, environment, runtime, Skill, source identifiers, execution, and output checksums.
7. A persisted Review verifies the pinned record without re-execution.
8. Export pins selected versions and creates a checksummed reproducibility pack.

No stage may be skipped in the release vertical. Artifact Versions, approved ActionPlans, Executions, Run events, Review inputs, Findings, and Export selections are immutable. A retry creates a new Run. Kernel or lease loss MUST NOT automatically replay Python, tools, connectors, or other side effects.

## 2. Roles, tenancy, and authority

`Owner` and `Member` are organization roles. Both may perform research work; Owner alone manages membership, Project tool grants, application credentials, and organization settings. All tenant access is derived from the authenticated user and active membership. Client-supplied `org_id` is never authority, and cross-organization resource access is a non-disclosing 404 in synchronous APIs.

`Compliance Operator` is an internal role separated from Owner and Member. Only an authorized Compliance Operator may place or release a legal hold. Each hold action MUST append actor, authority, reason, affected scope, and timestamp to an immutable audit record. Owner may view hold status but has no hold mutation authority. No jurisdiction, statutory basis, or customer legal copy is invented by this system.

## 3. P0 feature requirements

| ID | Normative requirement |
|---|---|
| F01 | Magic-link authentication, expiring same-origin sessions, invitation joining, and at most one active organization membership. |
| F02 | Tenant-scoped Project create, read, update, and archive. |
| F03 | Persistent Session listing, ordered history, resume, and archive. |
| F04 | Transactional Run event storage, SSE streaming, `Last-Event-ID` replay, and terminal recovery. |
| F05 | Isolated deterministic Python with a bounded Session Kernel and durable Artifact outputs. |
| F06 | Immutable checksummed Artifact Versions, compare-and-swap updates, and dependency provenance. |
| F07 | Validated Project-scoped loading of exactly the three canonical MVP Skills. |
| F08 | PubMed and OpenAlex connectors preserving source identifiers, retrieval time, raw references, and partial failure. |
| F09 | Persisted Reviewer v1 over pinned evidence, with no execution or write capability. |
| F10 | Version-pinned Export Pack with selected artifacts, manifest, provenance, and checksums. |
| F11 | Project Tool Grant and Plan Approval bound to a complete, canonical `ResearchIntent` only. There is no monetary governance behavior. |
| F13 | Encrypted application Connector and Broker credentials. Provider OAuth connections are a separate requester-owned domain. |

F12 and other P1/P2 concepts are outside the MVP release gate. P0 is exactly F01-F11 and F13.

## 4. Agent runtime and authentication contract

Model execution uses the provider-neutral `AgentRuntimeAdapter`, not a metered platform Provider Adapter. Every connection is a requester-owned `provider_connections` record keyed to `requester_user_id`; it is never an organization default binding. A Run MUST persist an explicit `provider_connection_id` selected by its requester. The server verifies ownership, enabled state, health, model eligibility, and qualification before dispatch.

Only official subscription OAuth is allowed. There is no API-key/BYOK mode, unofficial OAuth or token scraping, subscription-token import, or browser-cookie reuse. OAuth secrets remain in the runtime connection vault and MUST NOT enter messages, model context, execution input, artifacts, logs, exports, or F13 credential APIs.

Live qualification is scoped to an adapter and its pinned runtime, not to a provider account. The runtime identity is the exact adapter ID, runtime version, and executable SHA-256 selected by a deployment-supplied, protected policy file pinned to its exact SHA-256; the validated executable bytes are staged privately and those exact bytes are executed. The checked-in Darwin arm64 entry in `config/provider-runtime-policies.json` is development and test evidence only, not a production admission policy. Production supplies the policy for its exact platform through the deployment configuration boundary. Package replacement, policy-file replacement, version drift, or executable digest drift invalidates current qualification and blocks dispatch. `operator_account_ref` is operator-supplied correlation metadata and MUST NOT be treated as proof of which OAuth account the CLI used or compared with official completion account metadata as an authorization decision. Requester and account ownership remain independently bound by the official OAuth completion and the requester-owned connection record.

The live-capture evaluator sends the exact claim to an external Unix-socket qualification authority. Only that authority holds signing material, and it receives no database credential. The evaluator, application runtime, standalone capture CLI, database adopter, and dispatcher receive public keys only and MUST fail closed when the authority, key, receipt, subject, or runtime binding is unavailable or invalid. Authority, qualification adopter, Run dispatcher, and cleanup worker are separate processes with non-reused deployment credentials. `science_workbench_qualification`, `science_workbench_dispatcher`, and `science_workbench_provider_cleanup` are `NOLOGIN`, `NOINHERIT`, `NOBYPASSRLS` capability roles; separate deployment-managed dedicated `NOINHERIT` LOGINs may assume only their respective role. The cleanup capability has no direct table visibility or mutation privilege. It may execute only four fixed `SECURITY DEFINER` functions for a database-time-clamped, 100-row due-candidate list, exact locked due-work validation, and the two exact completion mutations. Its credential is never resident in the ordinary application or provider runtime. The ordinary application role cannot append a receipt, choose a current receipt, or insert a Run. The adopter owns the exact receipt append and connection compare-and-swap SQL without a caller-supplied database callback; the dispatcher owns exact qualified Run insertion.

Capture publishes the profile first, publishes the signed receipt sidecar second, and requests database adoption third. Each file publication and the adopter transaction are individually atomic, but the ordered sequence is not one atomic triple. Adoption compare-and-swap rechecks the exact requester/connection/revision, connection creation time, runtime-home reference, account, eligible models, selected model, health, adapter, and receipt/runtime binding. Adoption failure may leave profile and receipt sidecars, but they remain non-authoritative and the adopter transaction leaves no database receipt or current pointer. `provider_qualification_receipts` is immutable append-only signed history. A refresh appends a new receipt and advances the connection pointer without rewriting the prior receipt. Every model-backed Run is inserted through the dedicated dispatcher with the exact current receipt ID and digest, connection revision, selected model, profile digest, runtime version, and executable digest; these fields are immutable for the Run. Restart reloads and publicly verifies the stored receipt before it can authorize dispatch. Because immutable history remains verifiable, every historical public key is retained permanently in the active key set or in a permanently available archive verifier; rotation never deletes a key required by a stored receipt.

On a fresh upgrade, current revision 0003 copies every observable prior unsigned signal to `provider_qualification_legacy_evidence` with classification `legacy_unverified`, including a bare `healthy` connection with no qualification metadata or timestamp, then clears its authorization effect and normalizes unsigned `healthy` to `pending`. Remediation revision `0004_provider_security` converges roles, privileges, and guards for a deployment already stamped 0003. If an older 0003 already demoted a bare `healthy` row without preserving evidence, 0004 leaves that row `pending` and history empty rather than fabricating a record; operators must recover the historical fact from a pre-0003 backup under approved remediation or requalify it as new state. Legacy evidence never grants authorization. Downgrade refuses to destroy either signed or legacy qualification history.

Repository tests and local PostgreSQL exercises verify the authority client, public verifier, adoption, dispatch, cleanup, migration, and role code paths; they are not external live qualification. The current external attempt is blocked by the provider subscription usage limit, so no deployment-signed or adopted live qualification is claimed and release remains blocked until a fresh external attempt succeeds.

| Adapter ID | Launch status | Required behavior |
|---|---|---|
| `openai_codex` | required default | MUST be live-qualified, enabled, and the sole launch default; absence or failed qualification blocks release. |
| `anthropic_claude_code` | optional, disabled by default | MAY enable only after its own official OAuth, version, terms, retention, deletion, confinement, live, and cleanup qualification; otherwise stays disabled. |
| `xai_grok_build` | optional, disabled by default | Same independent fail-closed gate; failure disables only this adapter. |
| `moonshot_kimi_code` | optional, disabled by default | Same independent fail-closed gate; third-party key mode is forbidden. |
| `zai_glm` | visible, disabled | Registry reason is exactly `unsupported_auth`; there is no connect action until official OAuth support is qualified. |

Automatic provider fallback is forbidden. Quota, reauthentication, cancellation, unavailable runtime, and terminal failure are surfaced as stable provider-neutral states. A failure never selects another provider connection or model. Optional adapter failure cannot corrupt existing Artifact Versions.

### 4.1 Provider connection lifecycle

The same-origin API supports connect initiation/device or callback completion, list/detail, account and model selection, health, reauthentication, cancellation, and revocation. OAuth state is opaque, single-use, expiring, requester-bound, redirect-bound, and tenant-bound. Runtime homes are isolated by connection and inaccessible to Sandbox code. Revocation terminates future dispatch and produces cleanup and audit receipts.

## 5. Runs, tools, and approvals

Research Run states are `queued | running | awaiting_user | awaiting_approval | completed | failed | cancelled`. Legal state changes are compare-and-swap transitions; invalid transitions return `409 INVALID_RUN_TRANSITION`. Worker ownership uses a lease and fencing token. Completion from a stale token is rejected. Cancellation is idempotent, and retry creates a new Run with `retry_of_run_id`.

F11 contains only:

- Project Tool Grants with `allow | ask | deny`, defaulting to `deny`.
- An immutable, one-use Plan Approval bound to organization, Run, requester, tool, canonical arguments hash, network scope, secret scope, and expiry.

Every executable ActionPlan additionally binds one complete `ResearchIntent`. It records the human-owned question, why the research matters, intended benefit, success criteria, constraints, stop conditions, declared mode (`ai_for_science | copilot | bounded_agentic`), and data origin (`observed | synthetic | mixed`). Text is already boundary-trimmed at the contract boundary; whitespace-only or normalization-colliding list entries are rejected rather than silently rewritten. These fields have no server-authored or preselected scientific defaults. Changing any field changes both the intent digest and plan digest and therefore requires a new approval.

Synthetic or mixed data requires an explicit distinct generator and validator, each identified by its own declared reference. Unlabelled synthetic data, a shared declared reference, or a universal assumed real-to-synthetic ratio fails closed. This declaration does not itself prove organizational or model independence; qualified evaluator identity and validation-result evidence remain a separate release increment. The contract does not infer that synthetic data is acceptable for a domain.

`deny` creates zero Execution side effects. `ask` persists the ActionPlan and waits. Only the requester may approve; an Owner may reject another user's pending request but cannot approve it. Mutation, expiry, replay, or cross-tenant consumption invalidates the approval. There are no budget, cost-cap, spend, cost-approval, monetary event, monetary error, or monetary metric schemas or behaviors.

Run SSE events are limited to lifecycle and scientific work, including `run.status`, `message.delta`, `tool.started`, `tool.output`, `tool.completed`, `approval.required`, `artifact.saved`, `review.finding`, `run.completed`, and `run.failed`. Approval events contain the action reason and scoped resource, never monetary fields. Events have a monotonically increasing sequence and are replayable for at least 24 hours; expired history returns 410 and the client recovers with `GET /runs/{id}`.

## 6. Persisted Review lifecycle

Review is an independently persisted resource, not an inline mutation of the source Run.

- `POST /reviews` accepts a source Run and pinned Artifact Version or Execution references and returns `202` with `review_id`, a system-created Review `run_id`, and `status`.
- `GET /reviews/{id}` returns the persisted Review, pinned inputs, status, Findings, and timestamps. Repeated polling is idempotent.
- Review states are `queued | running | completed | failed`. Submission deduplicates by the canonical pinned-input digest.
- The Review worker calls `submit_findings` exactly once. Findings use verdict `pass | warn | fail | inconclusive` and status `open | resolved | rebutted | accepted_risk`.

The Reviewer validates the original immutable evidence. It has no Runner, Python, Bash, Connector, Artifact-save, or other write capability and MUST NOT request or cause re-execution. It cannot overwrite an Artifact Version. A correction is performed only by the Main Agent as a new Execution and new Artifact Version; rebuttal and accepted risk preserve original evidence and actor/reason audit.

Review rules are exact IDs: RV01 numeric claim support; RV02 DOI/PMID/OpenAlex validity and relevance; RV03 table/figure correspondence to pinned input, code, and output; RV04 evidence-level non-escalation; RV05 research-only and safety compliance.

## 7. Skills, connectors, credentials, and artifacts

The only MVP Skill IDs are exactly:

- `literature-review`
- `source-attribution`
- `probe-diagnostic`

The loader pins Skill ID, semantic version, content hash, and optional kernel hash per Run. It validates declared Connector, Tool, network, and secret requirements and rejects traversal, links, executable binaries, and undeclared access. `probe-diagnostic` separates molecular, optical, and experimental-artifact hypotheses; its name does not authorize clinical diagnosis.

PubMed and OpenAlex are fixed-host application connectors. Results preserve original identifiers, retrieval time, raw-object reference, typed mapping, and partial failure. Redirects are rechecked for SSRF. Retrieved text is untrusted data.

F13 credentials serve only application-side Connectors and approved Broker operations. They are KMS envelope-encrypted, ciphertext-only at rest, masked in APIs, short-lived in consumer memory, rotatable, revocable, and audited. Sandbox access uses a signed one-use broker handle for one registry operation; plaintext never enters user code, stdout, stderr, Artifact, or model context. Provider OAuth material lives only in requester-owned `provider_connections`; F13 credentials cannot authenticate `AgentRuntimeAdapter`, and provider OAuth material cannot be stored or manipulated through F13 APIs. The acceptance IDs `AC-F13`, `AC-F13-B`, `AC-F13-C`, and `AC-F13-D` are immutable identifiers.

Artifact Version content cannot change after creation. Every version records checksum, size, media type, producing Execution, environment hash, input dependencies, code hash, runtime connection/adapter identity without secrets, and Skill/source hashes. Export selects explicit Version IDs and includes CSV, PNG, Markdown, Ledger, `manifest.json`, checksums, provenance, ActionPlan, the pinned `ResearchIntent` digest, and Review status. It rejects traversal, links, normalized collisions, unselected latest-version races, and credentials.

## 8. Data model and public API

Every tenant table includes `org_id`, and parent references use tenant-preserving foreign keys. Primary IDs are UUIDv7; times are UTC. Core entities are organizations, users, memberships, auth sessions, projects, sessions, runs, messages, run events, action plans, approval requests, executions, uploaded files, artifacts, artifact versions, artifact dependencies, reviews, review findings, skills, run skill snapshots, connectors, connector calls, F13 credentials, provider connections, tool grants, export jobs, audit logs, deletion requests, deletion receipts, and legal holds.

`provider_connections` contains requester, adapter ID, encrypted OAuth/runtime-home reference, account metadata, selected model, qualification state, health, and revocation timestamps. `runs.provider_connection_id` is required for model-backed Runs. No schema represents organization provider binding or monetary governance.

Public APIs use `/api/v1`, JSON except multipart upload, secure host-only auth cookies, CSRF and Origin checks on mutation, `Idempotency-Key` on authenticated creation/execution, and `If-Match` on mutable resources. Errors use `{error: {code, message, request_id}}`. Required P0 surfaces include auth; organization; Projects; Sessions; files; messages; Run status/events/respond/approve/cancel/retry; Artifacts and Versions; Skills; Connectors; Tool Grants; F13 credentials; provider connections; `POST /reviews`; `GET /reviews/{id}`; Findings; Exports; deletion; audit; and legal-hold read status. Legal-hold mutation is internal Compliance Operator-only.

The external API contains no API-key/BYOK field, provider binding endpoint, monetary policy endpoint, monetary approval field, or monetary usage endpoint. Operational token counts MAY be recorded for reliability and provider quota diagnostics, but they MUST NOT be converted into price, cost, spend, reservation, cap, or approval semantics.

## 9. Sandbox and measured gVisor controls

Local and GKE Runners implement the same `Runner` contract. GKE uses the gVisor RuntimeClass and MUST prove controls by observed outcomes, not configuration-name assertions. Release evidence MUST demonstrate:

1. a non-root identity inside the workload;
2. denied writes to the read-only root filesystem;
3. denied default egress and cloud metadata access;
4. enforced CPU, memory, wall-time, output, and process limits;
5. denied cross-Run namespace, filesystem, object-prefix, and service-identity access;
6. absence of OAuth and F13 credential mounts in the Sandbox;
7. actual gVisor RuntimeClass selection and local/GKE scientific checksum parity.

The specification does not claim that literal workload seccomp or `NoNewPrivileges` flags are provided by gVisor. Such configuration may be recorded when independently available, but it is not accepted as proof of SEC06 and is not a literal workload requirement. Package installation, privileged execution, host mounts, unrestricted egress, and arbitrary connector hosts are forbidden.

## 10. Security, retention, and operations

SEC01-SEC16 are release-blocking. Controls include PostgreSQL RLS; private tenant-scoped object keys; single-object expiring download URLs; KMS envelope encryption; secret absence from durable contexts; measured gVisor outcomes; clean-upload gating; prompt-injection non-promotion; append-only auditing; CSRF/Origin/Fetch Metadata; path normalization; fixed-host SSRF controls; allowlist logging/redaction; authorization-aware downloads; immediate deletion tombstones; and Compliance Operator legal holds.

SEC14 incident break-glass has no standing access. Only an authorized internal Security Incident Operator may request the least-privilege resource-and-action scope for a recorded reason and explicit approval. Access MUST have a bounded expiry, support immediate revocation, and write every attempt, approval, access, denial, and revocation to an immutable access audit. This incident authority does not place or release legal holds; that authority remains exclusively with Compliance Operator.

Operational logs retain 90 days and append-only audit records retain one year by default. Run events and idempotency records retain 24 hours; completed Export blobs retain 24 hours; project content deletion completes within 30 days unless held. Deletion spans database, object versions, exports, queue/cache, and qualified provider copies, emits per-system receipts, and reapplies tombstones after restore. Legal holds suspend covered deletion until an authorized release; they do not grant content access.

Metrics are operational only: request rate/error/latency, Run state residence and failures, provider token latency/quota/reauth state, Sandbox allocation/execution/OOM/timeouts, Connector success/latency, Artifact checksum failures, Review catch/false-positive/resolution rates, Export duration/failure, and deletion receipt completion. No monetary metric exists.

## 11. Toolchain and deployment variance

The current reproducible development stack is exact: Node `24.17.0`, pnpm `11.12.0`, Python `3.12.13`, uv `0.11.28`, and PostgreSQL `18.4`. Product architecture is Next.js/TypeScript web, FastAPI/Python APIs and workers, PostgreSQL RLS, Redis, private object storage, KMS envelope encryption, and GKE/gVisor in Seoul. A future version change requires the manifest, bootstrap, compatibility evidence, and this section to change together.

## 12. Acceptance and evaluation

The exact acceptance IDs are:

`AC-F01`, `AC-F01-B`, `AC-F01-C`, `AC-F01-D`, `AC-F01-E`, `AC-F02`, `AC-F03`, `AC-F04`, `AC-F04-B`, `AC-F05`, `AC-F05-B`, `AC-F06`, `AC-F06-B`, `AC-F07`, `AC-F08`, `AC-F09`, `AC-F10`, `AC-F11`, `AC-F11-B`, `AC-F13`, `AC-F13-B`, `AC-F13-C`, `AC-F13-D`, `AC-PROVIDER-AUTHORITY`, `AC-PROVIDER-RUN-BINDING`, `AC-PROVIDER-MIGRATION`, `AC-SAFE`, `AC-TENANT`, `AC-COMPLIANCE`, `AC-DATA`, and `AC-NFR`.

Their Given/When/Then statements are normative in the ID-keyed manifest. In particular, AC-F11 covers every public Run/ActionPlan ResearchIntent boundary and its provenance binding; AC-F11-B covers Tool Grant and approval authority. AC-F13-D tests the hard separation between requester OAuth connections and F13 application credentials. AC-PROVIDER-AUTHORITY covers the external signer and narrow adopter credential boundary; AC-PROVIDER-RUN-BINDING covers durable immutable receipt and Run provenance; AC-PROVIDER-MIGRATION covers non-authoritative legacy preservation. AC-SAFE enforces research-only non-clinical use; AC-DATA exercises deletion, restore tombstones, and Compliance Operator hold authority.

Golden Sessions are exactly GS01-GS10. Enabled runtimes run GS01-GS10 three times; scientific primitives and artifacts are checksum-deterministic while free-form prose is evaluated structurally. GS08 prompt-injection, GS09 secret-redaction, and GS10 tenant-isolation safety checks require 100%. The required `openai_codex` profile must pass; each optional adapter is evaluated independently and remains disabled without a complete profile. Reviewer catch rate is at least 90% and false-positive rate at most 10% on a versioned corpus.

NFR01-NFR10 cover 72-hour reliability, CRUD P95 at most 500 ms, visible provider-token P95 at most three seconds where reported, Sandbox allocation P95 at most ten seconds, zero checksum mismatch, recovery reconciliation within five minutes without replay, 500 MiB Export within five minutes, WCAG 2.2 AA and keyboard completion, current-browser coverage, and RPO 15 minutes/RTO four hours with restore evidence.

## 13. Definition of done and release gate

A requirement is Done only when its ID maps to implementation, automated tests, raw evidence, evidence checksum, owner, and rollback note; unit/integration/contract/E2E/security/recovery tests pass; API and user documentation agree; redaction is proven; migrations are forward/backward/forward verified; Korean UI and accessibility are observed; and Critical/High security plus P0 product defects are zero.

Release requires 100% of F01-F11/F13 acceptance, AC-PROVIDER-AUTHORITY, AC-PROVIDER-RUN-BINDING, AC-PROVIDER-MIGRATION, AC-SAFE, AC-TENANT, AC-COMPLIANCE, AC-DATA, AC-NFR, SEC01-SEC16, RV01-RV05, and the required runtime gate. The complete dry-lab chain must be observed through HTTP and a production browser and independently verified from the Export Pack. Missing `openai_codex` qualification, any automatic fallback, any provider API-key/BYOK surface, an enabled unqualified optional adapter, a connectable GLM adapter, a Reviewer execution capability, a monetary semantic, an unsupported legal-hold actor, or a false gVisor control claim blocks release.

Product name, brand, pricing, launch jurisdiction and legal copy, pilot cohort, on-call owner, and deployment authorization remain external owner decisions. This specification authorizes implementation and verification only; it does not authorize deployment or a commit.
