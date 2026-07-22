# Nipo Science Design Contract

Status: frozen before G003 product-screen implementation  
Decision date: 2026-07-13  
Selected generated reference: `docs/design/reference-mineral-notebook.svg`

## Research brief

### Product and users

Nipo Science is a Korean-first, non-diagnostic research-support product for researchers who must inspect how an input became a result. The primary user is a computational researcher moving between Project context, calibrated input, immutable approval, live execution, Artifact evidence, persisted Review, and reproducible Export. Organization owners additionally manage membership and provider connections, but ownership never grants another researcher's provider credentials or approval authority.

The product must optimize for traceability rather than chat novelty. Every important state needs a visible object, stable identifier, timestamp, status, and next action. Evidence and interpretation remain distinct. Failures stay visible and recoverable; no optimistic UI may imply that a mutation committed before the server confirms it.

### Greenfield landscape study

The design contract combines patterns from three product families without copying their visual identity:

1. **Scientific notebooks and instrument consoles** — strong sample/run identity, calibrated units, compact plots, persistent provenance, and explicit incomplete-data states. Risk: instrument UIs become cramped and inaccessible.
2. **Version-control review tools** — immutable revisions, side-by-side differences, findings anchored to exact evidence, and conspicuous pending/approved states. Risk: developer jargon obscures scientific intent.
3. **Operations timelines** — ordered events, recoverable terminal states, stable status language, and detail-on-demand. Risk: dashboard card grids fragment the research narrative.

Rejected visual territories:

- generic blue/purple SaaS cards and decorative gradients;
- glassmorphism, floating shadows, or rounded-card nesting that weakens hierarchy;
- chat-first composition that hides the ActionPlan, evidence chain, or Reviewer boundary;
- red/green-only status communication;
- 11–12px Korean body text or condensed CJK typography;
- decorative laboratory imagery that could imply clinical use.

### Selected concept

**Mineral Notebook** is selected. The generated reference uses warm paper surfaces, deep mineral green structure, amber attention states, 1px rules, editorial whitespace, and a persistent evidence rail. It places the ordered run timeline beside the immutable approval and below a stable Project breadcrumb, then pairs the scientific visualization with Artifact/Review evidence. The reference is a composition target, not production markup.

Selection reasons:

- the color system is recognizably scientific without default SaaS blue or diagnostic styling;
- a three-zone hierarchy survives desktop density and collapses naturally on mobile;
- provenance and approval remain visible rather than hidden in modals;
- functional borders and spacing replace excessive depth;
- CJK labels have room for full words instead of clipped abbreviations.

## Information architecture

Global destinations, in order:

1. 워크스페이스 — active Organization, Projects, recent Sessions and Runs;
2. 업로드 — validated research inputs and bounded previews;
3. 실행 기록 — ActionPlan, approval, ordered events, cancellation and recovery;
4. 아티팩트 — immutable versions, checksums, lineage and safe downloads;
5. 검토 결과 — persisted Review, pinned evidence and Findings;
6. 내보내기 — selected versions, manifest and reproducibility status;
7. 제공자 설정 — requester-owned connections, explicit selection and disabled GLM explanation.

The desktop shell uses a 232px navigation rail, a fluid primary canvas, and an optional 360–400px evidence rail. At 768px the navigation becomes a compact top/side control and evidence follows the main object. At 375px all content is one column; the current object, status, and primary action precede supporting evidence. No horizontal page scroll is allowed.

## Tokens

### Color

- `--ink-strong: #23352d`; `--ink: #34483d`; `--ink-muted: #68736c`;
- `--paper: #fbfaf5`; `--paper-warm: #f3f0e7`; `--paper-accent: #eef2e8`;
- `--rule: #c9c5b7`; `--rule-strong: #8da795`;
- `--positive: #345e48`; `--attention: #8a641e`; `--danger: #9a3434`;
- every text/background pairing must meet WCAG 2.2 AA; status never relies on color alone.

### Typography

- Korean body: system CJK stack, 16px/1.65 default, never below 14px;
- headings: 20–32px, 700 weight, restrained tracking;
- metadata: 13–14px with full labels;
- hashes/code: system monospace, 12–13px with wrapping and a copy label;
- tabular numerals for measurements, timestamps and version numbers.

### Shape, spacing and motion

- 4px base spacing; common gaps 8/12/16/24/32;
- 6–12px radii only where they communicate containment; no pill-shaped content cards;
- 1px borders establish hierarchy; shadows are reserved for a true overlay;
- focus ring: 3px high-contrast outer ring with 2px separation;
- motion duration 120–220ms, transform/opacity only, and disabled by `prefers-reduced-motion`;
- live run changes use text plus `aria-live`, never perpetual animation.

## Primitive contract

Implement these primitives before composing product routes:

- `AppShell`, `GlobalNav`, `PageHeader`, `Breadcrumbs`;
- `StatusBadge` with icon/text and neutral/positive/attention/danger states;
- `ObjectSummary`, `KeyValueList`, `HashValue`, `Timestamp`;
- `RunTimeline`, `ApprovalPanel`, `ArtifactTable`, `FindingList`, `EmptyState`;
- `Button`, `IconButton`, `Field`, `Select`, `Dialog`, `Toast`, `InlineError`;
- `SkipLink`, semantic landmarks, visible labels, programmatic descriptions, and keyboard order.

All interactive controls must support keyboard activation and visible focus. Dialogs trap and restore focus. Tables expose headers and a mobile list alternative. Loading, empty, incomplete, error, forbidden/non-disclosing, and terminal states are first-class; skeletons never conceal errors.

## Product-route contract

- `/workspace`: Organization and Project context, recent activity, empty/loading/error states.
- `/upload`: format/size guidance, validated preview, scan state, atomic rejection.
- `/runs/:id/approval`: immutable digest, exact scope, approve/reject and expiry.
- `/runs/:id`: ordered progress, reconnect/recovery, cancel, Artifact links.
- `/artifacts/:id`: versions, checksum, lineage, preview/download separation.
- `/reviews/:id`: pinned evidence, Findings and no re-execution affordance.
- `/exports/:id`: selected versions, manifest/checksum and completion state.
- `/settings/providers`: requester-owned connection state, explicit account/model selection, no fallback, disabled GLM explanation.

Every route must render meaningful Korean text at 375, 768 and 1280 CSS pixels, preserve content at 200% zoom, and expose no credential, raw token, tenant ID control, or clinical/diagnostic claim.

## Authentication and tenancy presentation

Magic-link request responses are enumeration-safe and visually identical. Intent and session cookies are host-only server concerns and never displayed. The active Organization is server-derived; no client input chooses `org_id`. Cross-tenant and unknown resources share the same non-disclosing not-found treatment. Membership and owner actions state their permanence and last-owner constraint before mutation.

## Accessibility and quality gates

Required before visual approval:

- semantic landmarks, one `h1`, skip link, keyboard-only completion, focus restoration;
- WCAG 2.2 AA automated scan with zero serious/critical issues plus manual focus/label review;
- Korean/CJK wrapping, line-height and truncation review with long names and hashes;
- reduced motion, high zoom, narrow viewport, empty/error/offline/slow states;
- zero browser console errors and no unhandled promise rejection;
- no hidden content or flattened design solely to improve performance scores;
- median production-build performance evidence at 375 and 1280, with recorded commands and artifacts;
- fresh all-route captures at 375/768/1280 reviewed independently by two visual reviewers.

## Implementation order

1. Freeze this research record and selected generated reference.
2. Implement tokens and primitive showcase; verify accessibility and CJK behavior.
3. Implement identity/tenant API and same-origin security.
4. Compose product routes from the accepted primitives.
5. Run production-browser journeys and dual visual review.

Product screens must not predate steps 1–2 in repository history. Any deviation from this contract requires an explicit design-decision amendment with evidence.

## Deployment evidence qualification

Deployment qualification is fail-closed and is separate from rendered desired-state validation. Rendered manifests are synthetic fixtures and can demonstrate only contract structure; they never become live GKE evidence by a string, checksum, self-hash, or `captured_live_gke` label.

A qualifying release requires exactly one detached-signature capture for each explicitly named environment, `staging` and `production`, with distinct cluster UIDs and nonces. The collector is invoked only as `/opt/science-workbench/bin/gke-evidence-collector-v1 --format=canonical-v2`; every ancestor and its leaf must be root-owned, non-symlink, and not group/world-writable before its held descriptor is executed. It emits canonical raw resource and probe streams plus proof-bound deployed manifest, image, environment, control, corpus, input, watcher registration/receipt, scientific-output checksum-set, and signed workload-graph digests. Observations derive every value from the proof; callers cannot rebind a capture to other deployment artifacts, watcher identities, or outputs. Capture age is limited to 15 minutes.

Every RuntimeClass, Pod, node-pool, NetworkPolicy, Workload Identity, admission, and mount-control record carries the exact workload-graph digest derived from signed project, cluster, location, environment, run, manifest, and image identity. Unknown, duplicate, empty, concatenated, or extra resource attributes fail. This includes exact gVisor handler/binding, project-bound Workload Identity pool and GSA, exact egress allowlist, non-empty quota, sandbox-enabled node-pool scheduling, workload-selecting egress policy bindings, and control-plane isolation.

Each required denial vector binds fixed target and test-vector SHA-256 digests, an exact allowed transport/result pair, its specific policy reason, UTC capture-session time, and a strictly positive duration at most 10 seconds. Timeout, ambiguous transport or result, mismatched target/test vector, misleading reason, or out-of-bound duration is inconclusive and fails qualification. All resource and probe fields are included in both record and envelope evidence digests.

gVisor remains truthfully non-evidence for workload seccomp or no-new-privileges (`false` for both contract claims). Construction and process-local issuer identity never establish trust. Qualification exclusively uses detached-signature verification through fixed `/usr/bin/ssh-keygen -Y verify`, fixed principal/namespace, and a root-owned, non-symlink, non-group/world-writable `/etc/science-workbench/gke-allowed-signers` policy. The verifier and every path ancestor receive the same no-follow safety checks; allowed-signers contents are opened through that boundary, snapshotted to a private file, then passed to the verifier to prevent policy replacement between inspection and use. Missing or unsafe policy blocks release, while a serialized/reloaded proof can qualify only through a genuine correctly provisioned signature. Synthetic fixtures and unverified signed-attestation captures can validate structure but cannot qualify a release.
