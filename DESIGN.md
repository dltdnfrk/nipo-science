# Nipo Science Design Contract

Status: active Nipo Labs redesign contract
Decision date: 2026-07-22
Direction: **Spectral Control Room**

## 0. Research log

- Embedded reference: `linear.app.md` for dark-native luminance hierarchy, compact controls, quiet borders, keyboard-first navigation, and persistent context. We intentionally do not copy Linear's violet, logo, typography weights, or product composition.
- Layout reference: `layout-skill.md` for a fixed navigation shell, one owned main scroll region, intrinsic grids, `min-block-size: 0`, and overflow-safe mobile reflow.
- Redesign audit: the previous warm paper, deep green, mineral vocabulary, and repeated bordered-card composition made an AI research platform read like an institutional geology notebook. The traceability model remains valuable; the metaphor does not.
- UI/UX DB query: `AI science research evidence workspace premium precise operational dashboard`. Its liquid-glass recommendation was rejected because animated blur and translucent text reduce evidence density, contrast, and performance. Its dark operations palette, responsive, touch, and accessibility constraints were retained.
- Live primary-source research, accessed 2026-07-22:
  - Linear initiatives/projects/views: https://linear.app/docs/initiatives, https://linear.app/docs/projects, https://linear.app/docs/custom-views
  - Elicit search/extraction tables: https://elicit.com/solutions/search and https://docs.elicit.com/
  - Consensus filters and research agent: https://help.consensus.app/en/articles/9922799-advanced-search-filters and https://help.consensus.app/en/articles/12641232-research-agent
  - Scite citation context and stance: https://scite.ai/ and https://api.scite.ai/docs
  - NotebookLM source selection and citation jumps: https://support.google.com/notebooklm/answer/16215270 and https://support.google.com/notebooklm/answer/16179559
- Product inference: separate human workflow status from machine freshness/quality signals; keep citations and exact evidence locations adjacent to claims; preserve configurable evidence views and query-to-table extraction; make agent steps inspectable rather than chat-hidden.

## 1. Direction

Nipo Science is the research operating system inside **Nipo Labs**. The atmosphere is a dark spectral control room: quiet near-black depth, calibrated mint light, fine coordinate grids, and dense evidence surfaces that feel measured rather than decorated. The signature material is **luminous graphite**: stacked charcoal surfaces defined by luminance, hairline cool borders, and a local mint rim only where an action or live state earns it.

The memorable moment is the workspace's **evidence signal**. Project, run, and artifact counts form a restrained spectral trace that resolves into the primary action. It is not a looping decoration: it communicates that inputs travel through approval, execution, evidence, review, and export. Hover/focus exposes the same path without hiding content; reduced-motion users receive the final state immediately.

Avoid:

- minerals, paper notebooks, earth greens, laboratory stock imagery, clinical symbols, and diagnostic language;
- purple/blue AI gradients, floating glass cards, glow on every surface, chat-first composition, and decorative orbit graphics;
- equal-height card walls, pill overload, tiny Korean metadata, and status conveyed by color alone.

## 2. Product principles and users

Primary user: a Korean-first computational researcher who must inspect how an input became a result. Secondary user: an organization owner managing membership and requester-owned provider connections without gaining another researcher's approval authority or credentials.

Principles:

1. **Evidence before synthesis.** Every conclusion exposes its source object, immutable identifier, timestamp, and next inspectable action.
2. **Human status, machine signal.** Approval and workflow state are explicit human-owned states; freshness, confidence, and evidence quality are distinct machine signals.
3. **One decisive action per view.** Each route names one primary action; secondary actions remain visibly subordinate.
4. **Dense, never cramped.** Operational detail may be compact, but Korean body copy stays 16px or larger and metadata never drops below 13px.
5. **Failure remains legible.** Empty, error, forbidden, expired, unavailable, and incomplete states keep context and a recovery path.
6. **No tenant theatre.** The server owns organization identity. The UI displays **Nipo Labs** and never exposes tenant IDs or credential material.

## 3. Information architecture and scroll ownership

Primary navigation:

1. **워크스페이스** — projects, live research signal, recent runs, and the next action;
2. **새 연구** — upload, ResearchIntent, execution target, validation, and ActionPlan creation;
3. **아티팩트** — immutable versions, checksum, lineage, preview, and safe download;
4. **연결** — requester-owned provider connection, qualification, explicit model selection, and cleanup receipts.

Run, Approval, Review, and Export remain server-ID-addressed objects beneath the workspace parent. No fake demo IDs enter the global navigation.

Desktop shell:

- `AppShell`: 248px fixed navigation rail + `minmax(0, 1fr)` work region, bounded by `100dvh`;
- `GlobalNav` and `WorkspaceBar` stay fixed; `MainScroll` is the single vertical scroll owner and has `min-block-size: 0`;
- content max-width is 1184px, aligned to a 12-column reading grid;
- evidence detail is inline or a 340–384px support column only when the content warrants it.

Tablet (768–1023px): 208px rail, one main scroll owner, support columns collapse beneath the primary object. Mobile (<768px): compact top brand row + horizontally scrollable labeled navigation + single content column. No page-level horizontal overflow is allowed; data tables switch to structured cards.

## 4. Design tokens

### Color: one spectral mint story

Canvas and graphite:

- `--canvas: #07090d`; `--canvas-ambient: #09111a`; `--nav: #0a0d12`;
- `--surface-1: #0f141c`; `--surface-2: #151c27`; `--surface-3: #1b2431`; `--surface-hover: #202b39`;
- `--text-strong: #f4f7fb`; `--text: #d2dae5`; `--text-muted: #91a0b2`; `--text-faint: #8291a5`;
- `--line-subtle: rgba(213, 231, 255, 0.08)`; `--line: rgba(213, 231, 255, 0.14)`; `--line-strong: rgba(213, 231, 255, 0.24)`.

Spectral mint ramp:

- `--signal-100: #d7fff3`; `--signal-300: #82f2cc`; `--signal-500: #39d9ac`; `--signal-700: #16866b`; `--signal-900: #0d3d33`;
- `--signal-wash: rgba(57, 217, 172, 0.10)`; `--signal-glow: rgba(57, 217, 172, 0.22)`.

Functional exceptions:

- `--attention: #f2c66d`; `--attention-wash: rgba(242, 198, 109, 0.10)`;
- `--danger: #ff8a84`; `--danger-wash: rgba(255, 138, 132, 0.10)`;
- `--info: #89c7ff`; `--info-wash: rgba(137, 199, 255, 0.10)`.

Every pairing must meet WCAG 2.2 AA. Signal/status never relies on color alone.

### Typography

- UI/CJK: `Pretendard Variable`, `Pretendard`, `SUIT Variable`, `SUIT`, `Apple SD Gothic Neo`, system-ui, sans-serif;
- technical: `SFMono-Regular`, `Cascadia Code`, `Roboto Mono`, ui-monospace, monospace;
- display: 40/44 desktop, 32/38 tablet, 28/34 mobile, 650 weight, negative tracking;
- h1: 32/38 desktop to 26/32 mobile, 650; h2: 19/26, 620; h3: 16/24, 620;
- body: 16/26, 400–500; metadata: 13–14/20; technical values: 12–13/20 with tabular numerals and anywhere wrap;
- labels use sentence case or short Korean nouns; avoid all-caps except the `NIPO LABS` brand signature and technical overlines.

### Spacing, shape, focus, z-index

- base 4px; scale 4/8/12/16/20/24/32/40/48/64;
- radius 4px micro, 8px control, 12px panel, 16px hero; no pill content cards;
- z-index 0 canvas, 10 sticky, 30 overlay, 50 dialog, 100 skip link;
- focus: 2px `--signal-300` ring with 3px canvas separation;
- touch targets: 44px minimum; buttons use 44–48px height.

## 5. Reusable primitives and required states

Primitive showcase: `apps/web/product/showcase.html` is the equivalent state harness. It must render before route composition and be captured at 375, 768, and 1280.

- `NipoMark`: custom four-node spectral glyph, wordmark, `NIPO LABS` signature;
- `AppShell`, `GlobalNav`, `NavItem`, `OrganizationCard`, `WorkspaceBar`, `MainScroll`;
- `PageHeader`: eyebrow/breadcrumb, one h1, descriptive lede, optional primary action;
- `WorkspaceHero`, `SignalTrace`, `MetricStrip`;
- `Panel`, `EvidencePanel`, `ObjectSummary`, `KeyValueList`, `HashValue`, `Timestamp`;
- `StatusBadge`: icon + text for neutral/positive/attention/danger;
- `Button`, `TextLink`, `IconButton`: default/hover/focus/active/disabled/busy;
- `Field`, `Select`, `FilePicker`: default/focus/filled/invalid/disabled/help;
- `RunTimeline`, `ArtifactTable`, `ArtifactCard`, `FindingList`, `ProviderCard`;
- `InlineError`, `EmptyState`, `LoadingState`, `Toast`, `Dialog`, `SkipLink`.

Material recipe:

- base panel: `--surface-1` + 1px `--line-subtle` + inset top highlight;
- raised panel: `--surface-2` + `--line` + one cool ambient shadow;
- active evidence: local `--signal-wash` background, signal edge, and small glow only around the active affordance;
- overlays: opaque enough for text contrast; blur is optional support, never the only separation.

## 6. Motion and interaction

- duration tokens 120ms press, 180ms state, 260ms route/content reveal; transform and opacity only;
- hover raises interactive surfaces by at most 2px; active returns to 0 and scales to 0.985;
- navigation active indicator and evidence trace communicate location/progression; no perpetual decorative animation;
- form submissions expose busy text/ARIA and keep controls stable; errors focus the relevant control;
- `prefers-reduced-motion: reduce` removes travel and delivers the final state immediately.

## 7. Route contracts

- `/workspace`: Nipo Labs identity, research signal, project/run metrics, primary `새 연구 시작`, project list, recent run actions.
- `/upload`: visible step framing, upload validation, complete ResearchIntent, execution target, bounded preview, atomic Run + ActionPlan creation.
- `/runs/:id/approval`: immutable digest, scope, expiry, approve/reject/cancel with no optimistic success.
- `/runs/:id`: current status, ordered progress, recovery language, provider boundary, artifact links.
- `/artifacts`: evidence library with type/version/checksum and empty/error states.
- `/artifacts/:id`: immutable versions, selected evidence, lineage, preview/download separation, session attachment.
- `/reviews/:id`: pinned evidence and findings, no re-execution affordance.
- `/exports/:id`: selected paths, manifest/checksum, cleanup impact/confirmation/receipt.
- `/settings/providers`: requester-owned connection, explicit model, qualification, no fallback, safe authorization, cleanup receipt.
- unknown/foreign resources: one non-disclosing 404 surface with a workspace recovery action.

## 8. Accessibility and QA contract

- semantic landmarks, one h1, skip link, route-change focus, keyboard-only completion, focus restoration;
- visible labels, descriptive names for icon controls, polite live updates, alert errors, no color-only status;
- 200% zoom, 375/768/1280, long Korean, long hashes/URLs, empty/error/offline/expired, reduced motion;
- no horizontal page scroll, hidden provenance, clipped controls, or nested unnamed scroll regions;
- zero serious/critical accessibility findings and zero browser console errors caused by the app;
- fresh all-route captures reviewed by two independent visual oracles after objective visual QA.

## 9. Implementation order

1. Capture the RED organization identity and current Mineral Notebook baseline.
2. Freeze this active contract and build/capture the primitive showcase.
3. Implement shell and global tokens while preserving the existing SPA/API/security contracts.
4. Compose workspace and route surfaces from the accepted primitives.
5. Run focused contracts, real-browser journeys, all-route captures, independent review, and cleanup.

No deployment is requested. The deployment qualification notes below remain a non-UI historical operational record and do not override this active visual contract.

---

## Superseded historical UI contract

Status: archived; retained only to preserve prior decision history. Its Mineral Notebook direction and tokens are non-normative.
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

Global collection destinations, in order:

1. 워크스페이스 — active Organization, Projects, recent Sessions and Runs;
2. 업로드 — validated research inputs and bounded previews;
3. 아티팩트 — immutable versions, checksums, lineage and safe downloads;
4. 제공자 설정 — requester-owned connections, explicit selection and disabled GLM explanation.

Run, Review, and Export are ID-addressed research objects rather than global
collections. Their real server-issued links appear in Workspace activity and related
object views; `/runs/:id`, `/reviews/:id`, and `/exports/:id` therefore keep
워크스페이스 as their active navigation parent. Placeholder or demo IDs are never
added merely to fill the global navigation.

The desktop shell uses a 232px navigation rail, a fluid primary canvas, and an optional 360–400px evidence rail. At 768px the navigation becomes a compact top/side control and evidence follows the main object. At 375px all content is one column; the current object, status, and primary action precede supporting evidence. No horizontal page scroll is allowed.

## Tokens

### Color

- `--ink-strong: #23352d`; `--ink: #34483d`; `--ink-muted: #59665e`;
- `--paper: #fbfaf5`; `--paper-warm: #f3f0e7`; `--paper-accent: #eef2e8`; `--paper-danger: #fff7f5`;
- `--rule: #c9c5b7`; `--rule-strong: #8da795`;
- `--positive: #345e48`; `--attention: #8a641e`; `--danger: #9a3434`;
- `--on-ink: #fff`; `--on-ink-muted: #d9e1d5`;
- `--focus-on-ink: #f6d365`; `--rule-on-ink: #789080`;
- every text/background pairing must meet WCAG 2.2 AA; status never relies on color alone.

The earlier muted token `#68736c` is rejected because it does not preserve the
required contrast on the warm paper surfaces at metadata sizes.

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
- `/upload`: user-authored ResearchIntent, CSV format/size guidance, validated preview, scan state, and atomic Run plus ActionPlan creation or rejection.
- `/runs/:id/approval`: immutable digest, exact scope, approve/reject and expiry.
- `/runs/:id`: ordered progress, reconnect/recovery, cancel, Artifact links.
- `/artifacts/:id`: versions, checksum, lineage, preview/download separation.
- `/reviews/:id`: pinned evidence, Findings and no re-execution affordance.
- `/exports/:id`: selected versions, manifest/checksum and completion state.
- `/settings/providers`: requester-owned connection state, explicit account/model selection, no fallback, disabled GLM explanation.

Every route must render meaningful Korean text at 375, 768 and 1280 CSS pixels, preserve content at 200% zoom, and expose no credential, raw token, tenant ID control, or clinical/diagnostic claim.

### Design-decision amendment: ResearchIntent authority

The requirements and specification adopted after the initial visual freeze make a complete human-authored ResearchIntent mandatory at every public Run and ActionPlan boundary. The upload surface therefore collects the research question, rationale, intended benefit, success criteria, constraints, stop conditions, research mode, data origin, and distinct generator/validator references when applicable. `POST /api/v1/runs` validates that object and atomically creates the Run and its immutable ActionPlan; no session-scoped shortcut may create a queued Run outside the upload → plan → approval → execution → review → export chain. The server-owned ResearchIntent digest remains visible through Run, provenance, Review, and Export evidence. This amendment is verified by the OpenAPI, product HTTP, browser journey, persistence, and migration gates.

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
