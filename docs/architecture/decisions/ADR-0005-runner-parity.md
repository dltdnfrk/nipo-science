# ADR-0005: Local-to-GKE Runner parity

- Status: Accepted
- Owners: Runner Platform, Runner Security

## Context

Local development and GKE/gVisor differ in mechanisms, so configuration-name
parity can conceal materially different isolation or scientific results.

## Decision

Both implementations satisfy one `RunnerProvider` protocol and the same
outcome suite: deterministic scientific checksums; timeout, OOM, cancellation,
filesystem, secret, metadata, private-network, control-plane, and egress denial;
and Output Watcher registration. GKE adds gVisor RuntimeClass, a separate
sandbox node pool, non-root/read-only images, all capabilities dropped,
default-deny NetworkPolicy, quotas, per-Execution identity, and signed-image
admission.

We do not assert that gVisor applies literal workload seccomp or
`NoNewPrivileges`. Release evidence is outcome-based and records the actual
runtime and compensating controls.

## Verification and consequences

The same conformance corpus runs locally and in a disposable GKE namespace.
Any denial or scientific checksum mismatch blocks parity and release.

