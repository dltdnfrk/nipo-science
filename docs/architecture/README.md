# Architecture contract

This directory freezes Wave 0 security and architecture decisions. The JSON
files are normative, machine-readable inputs to `make verify-architecture`;
the ADRs explain implementation consequences. Later contracts may add detail
but may not weaken these invariants without superseding the affected ADR and
updating its executable security test.

## Manifests

- `architecture.json`: accepted decisions, service/trust boundaries, and
  capability invariants.
- `threat-model.json`: abuse cases, accountable owners, controls, tests, and
  evidence destinations.
- `data-classification.json`: field-level classification, retention, egress,
  and redaction rules.

The GKE Runner contract deliberately makes no claim that gVisor applies a
literal workload seccomp or `NoNewPrivileges` policy. Isolation is accepted
only through local/GKE outcome parity tests plus compensating controls: gVisor
runtime class, separate node pool and control plane, non-root/read-only image,
dropped capabilities, default-deny egress, per-Execution identity, quotas,
image admission, and Output Watcher registration.

Provider qualification authority, immutable receipt history, dedicated
database adoption, dedicated Run dispatch, isolated cleanup, exact Run binding,
permanent historical verification, and `0004_provider_security` convergence are
fixed by ADR-0010 and operated through
`docs/operations/provider-qualification.md`. The authority, adopter,
dispatcher, and cleanup worker are separate credential boundaries. Cleanup uses
the exact `science_workbench_provider_cleanup` `NOBYPASSRLS` capability, with no
direct table access, only through four fixed due-selection, validation, and
completion functions; the ordinary application cannot insert Runs. Production runtime policy is deployment-supplied,
and the checked-in Darwin policy is development/test evidence only. Passing the
repository code-path gates does not substitute for a successful external live
qualification. A stale deployment already stamped with an older 0003 is never
given fabricated legacy evidence; missing history requires backup remediation.
