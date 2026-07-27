# Nipo Science

The repository is migrating to the SPEC-v0.5 local-first single-user science
workbench. The current tree keeps the isolated monorepo, reproducible
toolchain, shared Python/TypeScript contracts, the deterministic science
package, the artifact reuse closure, and the nipo_local workbench
(`apps/local`), while the hosted multi-tenant application and persistence
planes are being retired in staged deletions (ADR-0011).

## Skeleton

- `apps/web`: Korean product shell and isolated test fixtures
- `services/api`: staged-retirement SaaS zone plus the artifact reuse closure
- `services/worker`: worker service boundary and local stub
- `packages/contracts`: shared interface contracts
- `packages/science`: shared scientific domain package
- `tests`: cross-project and boundary tests
- `docs`: project documentation
- `tools`: target-local developer tooling

The pnpm workspace is confined to `apps/*` and `packages/*`. Nothing in this
repository references or writes to sibling repositories.

## Toolchain decision

The reproducible pins are Node 24.17.0, pnpm 11.12.0, Python 3.12.13, and uv
0.11.28. Next.js 16.2.10 and React 19.2.7 are reserved for the later web
bootstrap and are deliberately not dependencies in Wave 0.

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

Run `make test-artifacts` to verify the artifact reuse closure.
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
foreign scope, and archived Projects fail closed. The filesystem blob store
fsyncs bytes below a private content-addressed root before atomic publication,
and the deterministic in-memory adapter backs isolated tests; the retired
hosted PostgreSQL adapter is gone with the persistence plane.

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

