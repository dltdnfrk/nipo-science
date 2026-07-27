# Architecture contract

This directory freezes the security and architecture decisions of the
SPEC-v0.5 local-first single-user product. The JSON files are normative,
machine-readable inputs to `make verify-architecture`; the ADRs explain
implementation consequences. Later contracts may add detail but may not
weaken these invariants without superseding the affected ADR and updating
its executable security test.

## Manifests

- `architecture.json`: accepted decisions, local trust boundaries, and
  capability invariants.
- `threat-model.json`: abuse cases, accountable owners, controls, tests, and
  evidence destinations. Every High threat pins an executable SECURITY case;
  hosted threats retired by ADR-0011 remain as Dropped history.
- `data-classification.json`: field-level classification, retention, egress,
  and redaction rules for the researcher-owned data root.
- `observability.json`: the local-only log policy — a metadata allowlist,
  no telemetry, no external log shipping, no implicit cloud sync.

The execution contract deliberately claims no confinement: analysis runs as
deterministic in-process Python, the recorded isolation is disclosed
verbatim, and any sandbox or confinement claim requires an outcome test of
the specific denial. Likewise the Keychain master-key item is created
without a trusted-application list, so no manifest claims that only this
application can read it. Both residual risks are another process running as
the same researcher, and both are carried in user-facing documentation per
SPEC-v0.5 section 11.

ADR-0001 through ADR-0010 describe the hosted multi-tenant service this
repository no longer builds; they remain as history. ADR-0011 supersedes
them for every hosted control, enumerates each dropped control with its
justification, and fixes the local-first topology this directory now
freezes: a loopback-only interface, a researcher-owned data root with
owner-only permissions, Keychain-sealed provider credentials, egress limited
to the explicitly selected provider, immutable digest-addressed Artifact
Versions, and a Reviewer that is structurally incapable of execution.
