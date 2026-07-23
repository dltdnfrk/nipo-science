# Nipo Science

The current foundation establishes an isolated monorepo, reproducible toolchain,
shared Python/TypeScript contracts, local services, the PostgreSQL persistence
schema, and a test-principal Korean Artifact inspection slice. Production public
provider connection and OAuth surfaces remain gated to later implementation
waves; production database sessions and qualified provider Run dispatch are
already wired through their restricted service boundaries.

## Skeleton

- `apps/web`: Korean product shell and isolated test fixtures
- `services/api`: API service boundary, local stub, and persistence migrations
- `services/worker`: worker service boundary and local stub
- `packages/contracts`: shared interface contracts
- `packages/science`: shared scientific domain package
- `infra`: deployment and data-service configuration
- `tests`: cross-project and boundary tests
- `docs`: project documentation
- `tools`: target-local developer tooling

The pnpm workspace is confined to `apps/*` and `packages/*`. Nothing in this
repository references or writes to sibling repositories.

## Toolchain decision

The reproducible pins are Node 24.17.0, pnpm 11.12.0, Python 3.12.13, and uv
0.11.28. PostgreSQL 18.4 is the current local data-service baseline. Next.js 16.2.10
and React 19.2.7 are reserved for the later web bootstrap and are deliberately
not dependencies in Wave 0.

The 2026-07-13 official-stack review superseded the plan's earlier pnpm 10 and
PostgreSQL 16 examples. The plan, normative v0.4 specification, and this target
now agree on pnpm 11.12.0 and PostgreSQL 18.4.

The `0.0.0` values in the private Node and non-package Python manifests are an
intentional non-release sentinel, not the product or deployment version. Release,
SBOM, and provenance identity come from the source commit and the external
release authority; publishing either workspace manifest as a package is outside
this repository's current contract.

## Bootstrap

Run `make bootstrap`. mise installs the exact tools and stores its config/trust
state under `.tools`, while mise, uv, and pnpm caches remain under `.cache`; no
global installation or global mutable package state is used. Bootstrap rejects
symlinked local environment, store, cache, and workspace dependency roots. It
then runs `uv sync --locked` into the exact-Python `.venv` and
`pnpm install --frozen-lockfile` with the existing release-age policy and a
project-local pnpm store under `.tools/pnpm`. Both lockfiles are required and
are never rewritten by bootstrap.

Bootstrap is idempotent. After it completes, `make test-openapi` runs the shared
OpenAPI, Python/Pydantic, and TypeScript/Zod contract gates without any separate
dependency-install step.

Run `make test-boundaries` to execute the standard-library boundary tests and
then scan the real project root, using the local virtual environment when it is
available.

## Local Docker stack

Run `make stack-up`, `make smoke-local`, and `make stack-down` in that order to
build, verify, and remove the local stack. Published service ports bind only to
`127.0.0.1` and remain overrideable through the `SWB_*_PORT` variables.

The browser-facing app origin is `http://localhost:53000`; the isolated Artifact
origin is `http://127.0.0.1:59000`. These resolvable loopback hosts require no
`/etc/hosts` entries and keep the host-only app cookie outside the Artifact
origin. `COOKIE_DOMAIN` remains empty. The Artifact UI test-principal fixture
documented below intentionally reverses the two loopback hostnames while
preserving the same cross-origin cookie boundary.

## Persistence verification

Run `make test-migrations` for empty and seeded forward/backward/forward coverage,
and `make test-rls` for live PostgreSQL tenant and integrity attacks. Each target
uses a process-specific Compose project and dynamically assigned loopback port,
then removes its containers, network, and volume in a guaranteed cleanup path.

The signed principal adapter is enabled only in tests. Both its verified claim and
database RLS require an active `(org_id, user_id)` membership. Public API routes
remain disabled until production F01 authentication is implemented; the test
principal is not a production authentication fallback.

## Scientific upload ingestion

Run `make test-upload` to verify the quarantine-to-clean ingestion boundary. The
pipeline allows PDF, PNG, JPEG, TIFF, CSV, TSV, JSON, macro-free tabular XLSX,
TXT, and Markdown only. XLSX accepts standard styles, shared strings, themes,
calculation chains, and document properties while rejecting active/external parts;
requires extension, declared MIME, and decoded structure to agree; and rejects
archives, embedded archive polyglots, undeclared or corrupt OOXML parts, external
relationships, malware, and scanner failures. Limits are 50 MiB per file, 100 MiB
per request, 10 files, 8,192 lazy transport chunks per file, 200 PDF pages, and 50
megapixels; individual XLSX data XML parts are limited to 16 MiB. Every object
key and store operation is bound to the authenticated
organization, project, and requester scope. Agent reads are denied until the
request is scanned, fully decoded, and atomically promoted; clean bytes are
immutable, and every rejection invokes request-atomic removal.

## Immutable Artifact Versions

Run `make test-artifacts` to verify the upload-to-Artifact persistence boundary.
Artifact IDs and Version IDs are server-generated UUIDv7 values. Version saves
use `base_version_no` compare-and-swap, derive tenant-private object keys only
from organization, Project, and SHA-256, retain immutable producer/environment/
code/runtime/Skill/source/input lineage, and deduplicate identical bytes without
collapsing Version history. An organization/Project/requester/execution-bound
Output Watcher claim is fenced, exception-safe, exclusive, and becomes
non-replayable only after a successful Version commit. Runtime adapter and
connection provenance come from that trusted execution binding, not the draft.
An ambiguous database response is reconciled by the server-owned Version ID;
canonical input-Version ordering keeps that comparison stable, and the same
watcher output cannot be replayed as a later Version.

Session links pin explicit Version IDs and reject duplicate or cross-tenant
associations; archived Projects and Sessions accept no new provenance or links.
Downloads are HMAC-bound to organization, Project, Version, and an integral-
millisecond expiry. Minimum-duration deadlines round upward while an independent
hard cap rounds `now + 10 minutes` downward, so a 1 ms request is not shortened
and no token exceeds ten minutes. Redemption holds the Project row lock across
archive authorization and blob read. Expiry, token tampering, checksum mismatch,
foreign scope, and archived Projects fail closed. The durable adapter commits CAS metadata
and immutable lineage in PostgreSQL, enforces same-Project composite keys and the
current requester's execution scope, and stores bytes below an owner-private
content-addressed root. Project/Artifact locks serialize archive and CAS changes.
Blobs are fsynced before atomic publication, while filesystem or metadata failure
compensates unreferenced content under a per-address database lock. The
deterministic in-memory adapter remains for isolated tests.

The production Artifact HTTP composition is available through
`python -m services.api.artifact_production_app`. It consumes persisted opaque
sessions, derives organization and requester identity server-side, resolves
Artifact Project scope under forced RLS, and composes PostgreSQL metadata with
owner-private blob and recovery roots. The environment contract, role grant,
trusted execution binding, TLS/origin requirements, and exact invocation are in
[docs/operations/artifact-service.md](docs/operations/artifact-service.md).

## Provider qualification boundary

Run `make test-provider-runtime` to verify the external-authority client,
public receipt verifier, durable adoption, qualified Run dispatch, cleanup,
migration, and PostgreSQL privilege code paths. Qualification authority,
adopter, dispatcher, and cleanup worker are separate credentialed processes.
`science_workbench_qualification` and `science_workbench_dispatcher` are
`NOLOGIN`, `NOINHERIT`, `NOBYPASSRLS` capability roles assumed by separate deployment-managed
`NOINHERIT` LOGINs; the ordinary application role cannot insert Runs. The
`science_workbench_provider_cleanup` capability role is also `NOLOGIN` and
`NOINHERIT` with `NOBYPASSRLS`; its dedicated LOGIN has no direct provider-table
access and may execute only four fixed due-candidate, validation, and completion
functions. It is never resident in the ordinary application or provider runtime.

Production supplies a protected exact runtime-policy file for its deployed
platform and pins the file's SHA-256. The
Darwin arm64 policy checked into `config/provider-runtime-policies.json` is a
development/test example only. A fresh upgrade archives observable bare legacy
`healthy` state before normalization. `0004_provider_security` converges a
stale-0003 deployment but never fabricates evidence already lost by an older
0003; that case requires pre-0003 backup remediation or new qualification. The code-path
gates are not external live qualification: the current external attempt is
blocked by the provider subscription usage limit, no deployment-signed or
adopted live qualification is claimed, and release remains blocked until a fresh
external attempt succeeds. Deployment, rotation, recovery, and rollback are
documented in
[docs/operations/provider-qualification.md](docs/operations/provider-qualification.md).

## Deterministic Dry-Lab Science

Run `make test-science` to verify the pure research-support analysis package.
It normalizes numeric tables, spectra, RGB images, and reports while retaining
explicit UCUM units, calibration checksums, missingness, and immutable Artifact
Version lineage. Spectrum endpoint-baseline correction, local peaks, color
regions, descriptive statistics, PNG plots, hypothesis CSV, and evidence hashes
are deterministic and require no network or model call.

Probe analysis always emits molecular, optical, and experimental-artifact
branches in fixed order with `non_diagnostic` scope. Missing units, calibration,
lineage, or a dimensionally incompatible wavelength unit produce
`insufficient_data`; malformed numeric shapes, unrepresentable derived arithmetic,
and invalid Unicode scalar data produce `invalid_data`. Neither path imputes
hidden values, collapses nonfinite evidence values, or emits a diagnostic verdict.

## Test-principal Artifact UI

Run `make test-e2e-artifacts` to verify the Korean Artifact list/detail slice.
The fixture creates immutable CSV, PNG, and PDF V1/V2 histories, shows checksum,
producer Execution, environment hash, predecessor diff, and lineage, and changes
only an explicitly selected Version-to-Session association. Unknown tenant IDs
remain indistinguishable from absent IDs, stale Version creation is rejected,
and download bytes are checked against the selected SHA-256.

The app route is unavailable without the opaque test-principal cookie. Preview
bytes are served from `localhost` while the app is served from `127.0.0.1`, so
the host-only app cookie does not match the preview origin. Preview responses
allow only passive CSV/PNG/PDF media and enforce `default-src 'none'`, `nosniff`,
and `no-referrer`; active HTML never enters the preview store. The iframe is
sandboxed and accepts only the server-declared Artifact origin.

## Deterministic Dry-Lab Fixture Vertical

Run `make test-dry-lab` to verify the live loopback fixture. The ordered flow
validates a calibrated CSV upload and complete human-authored ResearchIntent,
freezes both into the ActionPlan digest, consumes one approval, runs a fixed
normalizer in an isolated Python child, emits immutable CSV, PNG, Markdown,
evidence-ledger, and provenance artifacts, persists a read-only hash Review,
creates a safe relative-path Export receipt, and records runtime cleanup. The
ResearchIntent and its digest remain bound through approval, provenance, Review,
and Export; a missing or incomplete intent is rejected before planning.

The fixture rejects malformed or uncalibrated data, unsafe paths, network and
package-install requests, stale leases, approval replay, cancellation, and
Kernel loss without retrying side effects. It is a bounded research-only
acceptance surface, not the production identity or product UI delivered in
later waves. Start `services.api.dry_lab_fixture.run_server()` to serve the
accessible Korean browser fixture from `apps/web/g002-fixture.html`.

The authenticated ProductServer journey is also an explicit process-local
browser fixture. `ProductDryLabService` can be composed only with
`authenticated_fixture=True`; a normal server starts without demo identities,
Runs, or Artifacts. Its reload and multi-Run checks are UI/API acceptance
evidence, not PostgreSQL restart or production persistence evidence. Durable
Artifact creation, Version reads, and downloads now use the production
composition documented above. Production Run, approval, execution, Review, and
Export durability remains bound to the normalized PostgreSQL graph and still
requires its own principal-scoped service composition before release.
