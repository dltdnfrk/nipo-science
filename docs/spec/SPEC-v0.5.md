---
document_id: FS-SPEC-001
version: "0.5"
status: normative
supersedes: docs/spec/SPEC-v0.4.md
requirements_manifest: docs/requirements/requirements.yaml
---

# Nipo Science local workbench specification v0.5

## 0. Normative status and scope

This document is the self-contained product and engineering contract for the local product. `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, and `MAY` are normative. The ID-keyed machine contract in `docs/requirements/requirements.yaml` is the implementation and verification authority. If this prose and that manifest diverge, delivery stops until both are amended together.

This document supersedes `docs/spec/SPEC-v0.4.md`, which described a hosted multi-tenant service and is retained as history, not authority. Every control v0.4 required and this document drops is enumerated with its justification in `docs/architecture/decisions/ADR-0011-local-first-single-user.md`. A control absent from both is an error here, not a permitted omission.

Nipo Science local is a single-user research workbench running on the researcher's own computer against their own provider subscriptions and API keys. There is no hosted service, tenant, operator, or party other than the researcher who can read the data. `org_id`, `project_id`, and `requester_id` persist as fixed local constants so records stay portable and the shared Artifact models are reused verbatim; they are data, and no authorization decision MAY be derived from them.

The product is research support. It MUST NOT make clinical diagnoses or patient-care decisions, automate detailed regulated-pathogen procedures, or initiate an irreversible wet-lab action. Input lacking calibration, units, or safe research context MUST terminate as `insufficient_data`, `inconclusive`, or a safe refusal; refusal is a correct outcome. The system MUST NOT fabricate a diagnosis, measurement, citation, or other missing evidence.

## 1. Product contract and the local dry-lab chain

The primary P0 outcome is this ordered, observable chain, executed entirely on one machine:

1. The researcher supplies a real measurement file — spectrum, image, table, or report — with declared units, calibration, and data origin.
2. The researcher supplies a complete `ResearchIntent` stating the question, why the research matters, intended benefit, success criteria, constraints, stop conditions, research mode, and data origin.
3. The system creates an immutable ActionPlan. Approval fixes the canonical `ResearchIntent` digest and the plan digest before any execution.
4. The approved plan runs deterministic Python whose actual isolation is disclosed, not asserted (section 5).
5. The execution creates normalized CSV, PNG, Markdown, and evidence-ledger Artifact Versions.
6. Provenance pins the input, intent, code, and environment digests and the producing execution, and is independently verifiable (section 6).
7. A persisted Review verifies the pinned record without re-execution.
8. Export pins selected Versions and produces a checksummed reproducibility pack.

No stage MAY be skipped in the release vertical. Artifact Versions, approved ActionPlans, executions, Run records, Review inputs, Findings, and Export selections are immutable; a correction is a new Version, never an overwrite. A retry creates a new Run and a new execution identity, and a crash or abandoned Run MUST NOT automatically replay Python, a provider call, or any other side effect.

## 2. Authority model and installation boundary

There is exactly one human authority: the operating-system account owning the data root. There are no roles, accounts, invitations, or administrative separation, because every such boundary would separate the researcher from data the operating system already grants them.

The data root is `~/.nipo-science` by default. It MUST be created owner-only and MUST NOT default to a directory covered by an implicit cloud-sync policy; `~/Documents` is excluded for exactly this reason. Every file inside it holding a secret or private research content MUST be mode `0600` from the instant it first exists, never created readable and tightened afterwards. The application MUST NOT bind a listening socket to any interface other than loopback and MUST NOT expose a configuration value, environment variable, or flag enabling remote access. Any local HTTP surface MUST reject cross-origin state-changing requests and MUST require a local session credential not derivable from readable data-root metadata.

## 3. P0 feature requirements

| ID | Normative requirement |
|---|---|
| L01 | Single-user installation with a fixed local identity, an owner-only data root outside implicitly synced directories, and no listener beyond loopback. |
| L02 | Persistent local Projects and Sessions with list, resume, and archive, durable across restart. |
| L03 | Real measurement files load into typed scientific inputs with declared units, calibration, and data origin; malformed input is refused before any Artifact exists. |
| L04 | A complete `ResearchIntent` and an immutable, one-use ActionPlan approval bound to its canonical digest. |
| L05 | Deterministic Python execution whose actual isolation level is disclosed in every durable record it produces. |
| L06 | Immutable, content-addressed Artifact Versions committed by compare-and-swap against an exact base Version. |
| L07 | Provenance pinning input, intent, code, environment, and producing execution, independently verifiable from the artifacts alone. |
| L08 | Durable Run records whose truncation is detectable, with one-use produced-execution identity. |
| L09 | Local provider registry and credential custody with explicit provider and model selection. |
| L10 | A model turn bound to the selected provider and model, with no automatic fallback. |
| L11 | A persisted, trace-only Reviewer over pinned evidence implementing RV01-RV05. |
| L12 | A version-pinned Export Pack with manifest, checksums, provenance, ActionPlan, pinned intent digest, and Review status. |

P0 is exactly L01-L12; this document defines no P1 or P2 scope. There are no budget, cost-cap, spend, cost-approval, monetary event, monetary error, or monetary metric schemas or behaviours, because the researcher's spending is governed by their own provider account outside this system. Token counts MAY be recorded for diagnostics but MUST NOT be converted into price, cost, cap, or approval semantics.

## 4. ResearchIntent and ActionPlan approval

A `ResearchIntent` records the human-owned `question`, `rationale`, `intended_benefit`, `success_criteria`, `constraints`, `stop_conditions`, `research_mode` (`ai_for_science | copilot | bounded_agentic`), and `data_origin` (`observed | synthetic | mixed`). These fields MUST have no system-authored, preselected, or inferred scientific default. Text is validated at the contract boundary: a value that is not already NFC-normalized, is boundary-padded with whitespace, contains a surrogate, is empty, or collides with a sibling list entry MUST be rejected rather than silently rewritten. `synthetic` and `mixed` MUST declare a distinct generator reference and validator reference; an absent reference, or a generator and validator that are the same, MUST fail closed, and `observed` MUST carry neither. This declaration does not establish independence between them, and the contract does not infer that synthetic data is acceptable for any domain.

The canonical digest is SHA-256 over the JSON projection serialized with sorted keys, compact separators, and `ensure_ascii=false`, encoded UTF-8. Every executable ActionPlan MUST bind exactly one complete `ResearchIntent` by that digest.

An ActionPlan approval MUST be immutable, one-use, and bound to the plan digest, the `ResearchIntent` digest, the target Project, and an expiry. Changing any intent field changes both digests and MUST require a new approval. A mutated, expired, replayed, or already-consumed approval MUST be rejected with zero execution side effects. Approval consumption and execution start MUST commit together, so an approval cannot be consumed without an execution nor an execution begin without consuming its approval.

## 5. Execution and disclosed isolation

Determinism is normative: identical scientific input and identical `ResearchIntent` MUST produce byte-identical CSV, PNG, and Markdown across separate interpreter processes and differing hash seeds, and evidence ledgers identical except for the fields binding them to their own execution identity. Output rendering MUST NOT read a clock, locale, random source, hostname, username, or absolute path.

The current implementation executes analysis in the application's own interpreter process. It provides no subprocess boundary, no filesystem, network, or syscall confinement, no CPU, memory, wall-time, or process-count fence, and no privilege reduction relative to the researcher's own account. This MUST be disclosed rather than inferred from absence: every durable record an execution produces MUST carry the isolation level as an explicit field, whose current value is exactly `in_process`. The product MUST NOT describe in-process execution as a sandbox, claim confinement, or present an isolation control it does not measure. A stronger isolation level MAY be introduced only with an outcome test demonstrating the specific denial it claims; a configuration name is never evidence of a control.

The consequence MUST appear in user-facing documentation: analysis code, and any input parser it invokes, runs with the researcher's full account authority and can read the data root, including the sealed credential file and any provider key in the process environment. Executing untrusted third-party analysis code is therefore outside supported use until an isolation boundary exists and is outcome-tested. Input parsing MUST be bounded and MUST NOT execute input: evaluating input as code, deserializing a format carrying executable behaviour, and expanding an archive without declared entry-count and output-size bounds are forbidden.

## 6. Artifact Versions and independently verifiable provenance

Artifact Version content MUST NOT change after creation, and is addressed by SHA-256 and stored once per installation. A commit MUST be rejected, leaving no write behind, when its payload does not hash to its recorded digest, its recorded size disagrees with its payload, its object key is not the server-derived key, its Version identifier already exists, its base Version number is stale, or its pinned lineage is unsorted, non-unique, or unresolvable in the same Project. Every read MUST re-verify stored bytes against the recorded digest and MUST fail loudly on mismatch rather than return bytes. A failed commit MUST NOT delete content, because deleting on the failure path would destroy bytes another writer had already published; reclamation MUST instead be an explicit sweep that serializes against committers and refuses to remove recently written content.

Every Version MUST record the provenance fields the manifest enumerates under `artifacts.recorded_fields` and MUST project lineage back in commit order. The producer MUST NOT choose the object key, content digest, or output reference: bytes are registered with an out-of-band watcher that derives the digest and mints an opaque reference, and only that reference is exchanged for a Version.

Provenance MUST be independently verifiable: a third party holding only the exported artifacts and the pinned toolchain can recompute each digest and compare it, trusting no statement the producing run made about itself. The input digest MUST be recomputable from the canonical serialization of the declared scientific input; the `ResearchIntent` digest from the intent's canonical bytes; the code digest from the exact source files that can shape an output byte; the environment digest from the recorded environment facts, which MUST cover every dependency whose version can change a pinned digest or an artifact byte; and each artifact digest from its own bytes. A digest that cannot be recomputed independently is self-reported and MUST NOT be presented as provenance.

Truncation is detectable rather than impossible, because four immutable Versions cannot be committed in one transaction. A Run record MUST be created before anything is published, updated after every committed output, closed `completed` only once the final ledger commits, and closed `failed` with a non-secret reason and exactly the outputs committed so far on any escaping error. It MUST fence its produced-execution identity by exclusive creation, so one identity publishes at most one chain and a retry MUST use a new one. A reader MUST always distinguish a complete chain from a dead one without re-executing anything.

## 7. Providers, credentials, and model selection

Every provider connection is the researcher's own account. The registry offers thirteen selectable providers; one requiring a key is unusable until the researcher supplies their own. There is no qualification authority, signed receipt chain, organization default binding, or provider privileged as a required launch default.

Automatic provider fallback is forbidden. The researcher selects provider and model explicitly and the selection MUST be persisted with the Run. Quota exhaustion, authentication failure, cancellation, unavailability, and terminal error MUST surface as stable provider-neutral states; a failure MUST NOT select another provider, model, or credential, and MUST NOT corrupt or invalidate an existing Artifact Version.

Provider credentials MUST NOT exist in plaintext at rest, and the implemented custody is exact and MUST be preserved. The macOS Keychain holds exactly one value: a 32-byte random master key, base64-encoded to 44 printable ASCII characters, a shape chosen because it survives the measured defects of the `security` generic-password transport, which silently truncates, blanks, or hex-encodes other values. Provider keys are sealed with AES-256-GCM under that master key and stored as ciphertext only, with the provider identifier as additional authenticated data, so a ciphertext MUST NOT be movable between providers' slots. Every write MUST be read back and compared before being reported successful; a key MUST be stored byte-exact, and input that would not be stored verbatim MUST be rejected with the reason rather than silently normalized; a read failure MUST be distinguishable from absence and MUST NOT fall through to another source, which would resolve the wrong key; a corrupt store MUST be reported and MUST NOT be quarantined, discarded, or overwritten; and status MUST be resolvable without decrypting or unlocking anything.

A read-only environment fallback `NIPO_<PROVIDER_ID>_API_KEY` MAY be consulted when no credential is stored. It MUST NOT be written to, and its use MUST be disclosed, because a value in the process environment is inherited by every child process and readable by any process running as the same account. Secrets MUST NOT appear in a log, exception message, `__repr__`, process argument list, Artifact, Run record, Export, model context, or any other durable or observable context.

## 8. Trace-only Review

Review is an independently persisted resource over pinned evidence, not an inline mutation of the source Run. It MUST record its pinned Artifact Version and execution references, status (`queued | running | completed | failed`), Findings, and timestamps; reads MUST be idempotent; submission MUST deduplicate by the canonical pinned-input digest; and Findings MUST be submitted exactly once per Review.

The Reviewer MUST be structurally incapable — the capability absent from its interface, not merely unused — of executing Python, executing a shell, invoking a Runner, calling a connector, executing a tool, opening a network connection, writing or updating an Artifact Version, and causing or requesting re-execution. Any attempt MUST be rejected without creating an execution or changing an Artifact.

Findings carry verdict `pass | warn | fail | inconclusive` and status `open | resolved | rebutted | accepted_risk`. `inconclusive` is a normal verdict, not a Reviewer failure: missing, unreachable, or uncheckable evidence MUST produce `inconclusive`, never `pass`. A correction is performed only by the producing path as a new execution and a new Version followed by a new Review; rebuttal and accepted risk preserve the original evidence with actor and reason.

Review rules are exact IDs: RV01 every numeric claim exists in pinned execution output or pinned source evidence; RV02 every cited identifier resolves and supports its claim, and one that cannot be checked — including when the machine is offline — is `inconclusive`, never `pass`; RV03 tables and figures correspond to pinned input, code, and output digests; RV04 the stated evidence level never exceeds the level actually retrieved; RV05 output respects the research-only, non-clinical, and safety limits of section 0.

## 9. Export Pack

Export MUST select explicit Version identifiers and MUST NOT resolve "latest" at pack time. The pack MUST contain the selected artifacts, `manifest.json`, `checksums.sha256`, the provenance manifest, the approved ActionPlan, the pinned `ResearchIntent` digest, and the Review status. Manifest and checksum bytes MUST be canonical — sorted keys, compact separators, `ensure_ascii=true`, UTF-8, no self-referential digest — and the pack MUST verify independently: a third party recomputes every entry digest and the manifest digest from the pack alone and reaches the same result.

Export MUST reject, by refusing to produce a pack rather than sanitizing: an absolute or drive-qualified path, a backslash, a `.` or `..` segment, a segment ending in `.`, or a reserved device name; any link, since entries are regular files only; a path colliding with another after NFKC normalization and case folding; a path that is a directory prefix of another; a path equal to or beneath a reserved pack root; a selected-version set that is unsorted, non-unique, or unequal to the exported entries; and any credential material, sealed or plaintext, including any provider key, master key, session credential, or download signing key.

## 10. Storage and local interface

Durable state is a single SQLite database plus a sharded content-addressed blob directory beneath the data root. SQLite MUST run in WAL mode with `synchronous = FULL`, MUST use `STRICT` tables, and MUST be at least 3.44.0, the first release providing the ordered aggregate the lineage projection needs. There is no PostgreSQL, row-level security, object store, Redis, or network database.

Core entities are enumerated in the manifest under `storage.entities`. Every parent reference MUST resolve to a row that exists; a record MUST NOT reference an entity that exists nowhere. Primary identifiers are UUIDv7 and times are UTC. Content MUST be addressed by digest alone, so identical bytes are stored once per installation, and the data root MUST be portable: no absolute path, hostname, username, or machine identifier MAY be embedded in an Artifact Version or its provenance.

The local interface MAY be a loopback HTTP API with a browser or native front end. When present it MUST obey section 2, MUST apply the same immutability and approval rules as any other caller, and MUST NOT expose a credential value, a decrypted key, or a raw provider response containing credential material.

## 11. Security requirements

LS01-LS10 are release-blocking and their statements are normative in the manifest: LS01 loopback-only binding; LS02 ciphertext-only provider credentials; LS03 secret absence from durable and observable contexts; LS04 disclosed, never overstated isolation; LS05 bounded parsing that never executes input; LS06 prompt-injection non-promotion; LS07 path rejection covering traversal, links, reserved roots, and normalized collisions; LS08 owner-only file creation; LS09 digest-verified blob reads; LS10 egress limited to the selected provider with no telemetry or implicit cloud sync.

Two residual risks are disclosed rather than claimed away and MUST be carried in user-facing documentation until closed: in-process execution, under which no control assuming confinement MAY be asserted (section 5); and the Keychain master-key item, created without a trusted-application list, so this document MUST NOT claim only this application can read it. Both threats are another process running as the same researcher. Neither is remote, and both are bounded by the account that already owns the data root.

## 12. Toolchain

The reproducible stack is exact: Python `3.12.13`, uv `0.11.28`, SQLite `3.44.0` or newer, and macOS as the supported platform for the Keychain-backed credential path. Node `24.17.0` and pnpm `11.12.0` apply only to the local front end when one ships. Repository gates are `ruff check` and `ruff format --check` with `select = ALL`, `basedpyright` at `typeCheckingMode = "all"` with zero errors, and `pytest` with `filterwarnings = ["error"]`. A version change requires the manifest, the bootstrap, compatibility evidence, and this section to change together.

## 13. Acceptance, golden runs, and non-functional requirements

The exact acceptance IDs are `AC-L01`, `AC-L02`, `AC-L03`, `AC-L04`, `AC-L05`, `AC-L05-B`, `AC-L06`, `AC-L06-B`, `AC-L07`, `AC-L07-B`, `AC-L08`, `AC-L09`, `AC-L09-B`, `AC-L10`, `AC-L11`, `AC-L11-B`, `AC-L12`, `AC-L12-B`, `AC-SAFE`, `AC-DETERMINISM`, and `AC-LOCAL`. Their Given/When/Then statements are normative in the manifest. In particular, AC-L05-B covers the isolation disclosure and the prohibition on claiming confinement; AC-L07-B covers independent recomputation of every pinned digest; AC-L11-B covers the Reviewer's structural incapability and the `inconclusive` outcome; and AC-LOCAL proves no research content leaves the machine except in the model turn the researcher explicitly initiated.

Golden local runs are exactly GL01-GL08 and NFRs are exactly LN01-LN08; both are stated in the manifest. Each golden run executes three times; scientific primitives and artifacts are digest-deterministic while free-form prose is evaluated structurally; GL08 prompt-injection non-promotion requires 100%. Reviewer catch rate is at least 90% and false-positive rate at most 10% on a versioned corpus, and an `inconclusive` verdict on unreachable evidence MUST NOT be scored as a false positive.

## 14. Conformance status

This section is normative in one direction: a requirement listed as not implemented MUST NOT be described as satisfied, here or in any product surface, until its acceptance ID passes.

Implemented and verified in `apps/local` are L04, L05, L06, L07, L08, L09, L11, and L12. A loopback local interface now exists and serves the front end from its own origin, so LS01 has a listener to enforce against and does. The first-run flow is product-reachable: starting the local API creates the owner-only data root through `LocalPaths.ensure` before any token write — the token writer refuses to create the root itself, so a permissive umask can never widen the layout — and an empty workspace shows a guided first-run panel disclosing the data-root location outside synced directories, the loopback-only interface, and the in-process execution and Keychain residual risks of section 11. L01 remains partial only in that a packaged installer is out of scope for this repository. Not implemented are L02, since Projects are an archival marker; L03; and L10. L04 is a reachable product surface for its ActionPlan half: the local interface creates an immutable plan from a complete `ResearchIntent`, displays the server-derived plan and intent digests, and grants the one-use approval, while editing any intent field invalidates the binding and demands a new plan. Run start is reachable through the local API with a typed scientific-input document, consuming the approval and the execution claim in one transaction; starting a run from a measurement file in the product remains L03 work, and the interface says so instead of pretending otherwise. The Export Pack is a reachable product surface: the local interface plans pinned candidates, produces a pack into the owner-only export directory, lists and reclaims stored packs, and serves the bytes through a single-use download capability. AC-L12 is verified by named tests over the HTTP product path, and every AC-L12-B refusal is verified clause-for-clause at the exporting contract, whose path, link, collision, selection, and credential refusals the route inherits; the route itself additionally refuses non-pinned, duplicate, and empty selections and canonicalizes only the presentation order of the pinned set, which the manifest records.

Known divergences are enumerated in the manifest under `conformance.disclosed_divergences` and MUST remain disclosed until closed. They include in-process isolation, `skill_content_hashes` empty by construction, an absent session-link execution reference, and a plaintext download signing key that section 7's prohibition covers only for provider credentials.

Two divergences are closed. The environment digest now covers every byte-shaping dependency section 6 requires: `workbench.environment_facts` pins `pillow`, `pydantic`, and `pydantic-core` alongside the interpreter, because `input_sha256` is taken over `ProbeInput.model_dump_json()` and the Markdown and ledger bytes derive from it. And the producing path now has a correction producer: `workbench.correct_analysis` re-runs an analysis against an existing Artifact and commits the next Version by compare-and-swap, leaving the Version it corrects byte-identical.

## 15. Definition of done and release gate

A requirement is Done only when its ID maps to an implementation, to an automated test that fails when the named behaviour is broken — verified by mutation, not by the test passing — and to raw evidence, an evidence checksum, an owner, and a rollback note; when unit, integration, contract, end-to-end, and recovery tests pass; when user-facing documentation agrees with this document; and when secret redaction is proven rather than assumed. A behaviour crossing a real external boundary — the Keychain, the filesystem, another process, a provider endpoint — is not Done on mocked tests alone and MUST include a real-system test. Placeholders are blockers, not evidence: a `TODO` standing in for required behaviour, a skipped or exclusive test, a stub returning a fixed value, and an unimplemented branch each block their requirement.

Release requires 100% of L01-L12 acceptance, `AC-SAFE`, `AC-DETERMINISM`, `AC-LOCAL`, LS01-LS10, RV01-RV05, GL01-GL08, and LN01-LN08, with the complete chain observed end to end on a clean machine from a real measurement file through to an independently verified Export Pack. Release is blocked by any automatic provider fallback; any sandbox or confinement claim no outcome test demonstrates; any Reviewer execution or Artifact-write capability; any secret reaching a durable or observable context; any Version overwrite; any non-deterministic scientific output; any monetary semantic; any listener beyond loopback; any telemetry or implicit cloud sync of the data root; and any requirement section 14 still lists as not implemented.

Product name, brand, pricing, distribution, notarization, and support commitments remain external owner decisions. This specification authorizes implementation and verification only, not distribution.
