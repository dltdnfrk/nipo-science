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
permanent historical verification, and `0004_provider_security` convergence
were fixed by ADR-0010. ADR-0011 supersedes ADR-0010, and the hosted provider
plane — the authority, adopter, dispatcher, cleanup worker, and their
operations runbook — is retired.
