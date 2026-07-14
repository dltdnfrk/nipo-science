# ADR-0004: Artifact-first immutable provenance

- Status: Accepted
- Owner: Artifact Platform

## Context

Chat prose and live Kernel variables are not reproducible scientific evidence.

## Decision

Artifact Versions are the durable product and are immutable after creation.
Every derived output pins content, code, environment, input Version, producer
Execution, Skill, and runtime hashes. Updates use compare-and-swap to create a
new monotonic Version; correction never overwrites evidence.

The sandbox cannot select an object key. An out-of-sandbox Output Watcher
registers files under the current Execution prefix, computes the checksum, and
exchanges only that registered reference with Artifact Service. Exports and
Reviews pin Version IDs rather than resolving latest at execution time.

## Verification and consequences

Artifact contract tests alter each hash, race base versions, forge output
references, and change latest during Review/Export. Kernel memory and temporary
files are explicitly non-provenance until saved as an Artifact Version.

