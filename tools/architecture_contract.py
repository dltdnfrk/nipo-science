"""Normative architecture identifiers required by the verification gate."""

from __future__ import annotations

from typing import Final

# History principle: a decision removed from REQUIRED_DECISIONS keeps its ADR
# document under docs/architecture/decisions/ as history; removal from this
# frozenset never deletes the ADR file. ADR-0011 (local-first-single-user) is
# registered in docs/architecture/architecture.json but deliberately absent
# from the three sets below: rewriting them for the local-first topology is
# Stage 4 work, and adding the decision now would force threat-model.json and
# data-classification.json changes that must land in the same commit to keep
# verify-architecture (CI-006) green.
REQUIRED_DECISIONS: Final = frozenset(
    {
        "isolated-monorepo-service-boundaries",
        "same-origin-auth",
        "transactional-event-log",
        "artifact-first-immutable-provenance",
        "local-gke-runner-parity",
        "opaque-per-user-runtime-homes",
        "application-sole-tool-executor",
        "reviewer-non-reexecution",
        "oauth-f13-state-separation",
    }
)
REQUIRED_THREATS: Final = frozenset(
    {
        "tenant-escape",
        "oauth-token-theft",
        "provider-built-in-tool-bypass",
        "provider-vendor-compromise",
        "prompt-injection",
        "ssrf",
        "malicious-files-and-archives",
        "sandbox-escape",
        "stale-workers-and-lease-fencing",
        "approval-replay",
        "export-traversal",
        "deletion-and-backup-resurrection",
        "dependency-and-supply-chain-compromise",
    }
)
REQUIRED_FIELDS: Final = frozenset(
    {
        "oauth_refresh_token",
        "oauth_access_token",
        "scientific_inputs",
        "artifact_outputs",
        "reviews",
        "audit_events",
        "operational_logs",
        "exports",
    }
)
