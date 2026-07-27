"""Normative architecture identifiers required by the verification gate."""

from __future__ import annotations

from typing import Final

# History principle: a decision removed from REQUIRED_DECISIONS keeps its ADR
# document under docs/architecture/decisions/ as history; removal from this
# frozenset never deletes the ADR file. Stage 4 of the ADR-0011 local-first
# migration rewrote all three sets for the single-user product: the required
# decisions are the ones that still govern the local topology, the required
# threats are the High items of the rewritten threat model (each carries an
# executable SECURITY case), and the required fields are the local data
# classes — researcher-owned provider credentials, the local session token and
# download signing key, and the research content the data root holds.
REQUIRED_DECISIONS: Final = frozenset(
    {
        "isolated-monorepo-service-boundaries",
        "artifact-first-immutable-provenance",
        "application-sole-tool-executor",
        "reviewer-non-reexecution",
        "local-first-single-user",
    }
)
REQUIRED_THREATS: Final = frozenset(
    {
        "provider-endpoint-compromise",
        "prompt-injection",
        "approval-replay",
        "export-traversal",
        "dependency-and-supply-chain-compromise",
        "loopback-exposure",
        "provider-credential-theft",
        "overstated-isolation-claim",
        "data-root-permission-broadening",
        "unsanctioned-egress",
    }
)
REQUIRED_FIELDS: Final = frozenset(
    {
        "provider_api_key",
        "local_session_token",
        "download_signing_key",
        "scientific_inputs",
        "artifact_outputs",
        "reviews",
        "exports",
        "operational_logs",
    }
)
