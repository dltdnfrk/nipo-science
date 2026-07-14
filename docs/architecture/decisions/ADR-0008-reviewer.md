# ADR-0008: Reviewer verifies without reexecution

- Status: Accepted
- Owner: Review Platform

## Context

Recomputing during review changes the evidence under inspection and creates an
unapproved execution path.

## Decision

Reviewer reads a version-pinned projection of the user request, response,
Executions, log references, Artifact Versions, provenance hashes, source IDs,
and DOI results. Its only mutation is one idempotent `submit_findings` call per
Review. It has no Runner, Python, Bash, Connector, Tool execution, network,
Artifact write/save, or Version-update capability.

If evidence is missing, Reviewer returns an inconclusive or failing Finding.
Only Main Agent may remediate through a newly approved Execution and a new
Artifact Version, followed by a new Review.

## Verification and consequences

Reviewer protocol tests attempt each forbidden capability, request reexecution,
submit twice, and mutate pinned evidence. Every attempt is rejected without an
Execution or Artifact change.

