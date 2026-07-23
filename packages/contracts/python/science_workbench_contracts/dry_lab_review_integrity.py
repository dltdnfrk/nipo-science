import hashlib
from collections.abc import Mapping
from typing import Protocol
from uuid import UUID

from .dry_lab_integrity_types import DryLabIntegrityContract
from .export_manifest import (
    canonical_export_json,
    canonical_export_manifest_payload,
    parse_export_envelope,
    verify_export_envelope,
)
from .skill_manifests import CANONICAL_SKILL_IDS


class ExportContractAuthority(Protocol):
    """Resolve an independently sealed immutable dry-lab contract root."""

    def resolve_contract_sha256(self, source_run_id: UUID) -> str | None:
        """Return the externally anchored canonical contract digest."""
        ...


def canonical_dry_lab_contract_sha256(contract: DryLabIntegrityContract) -> str:
    """Digest the complete authoritative contract, including its detached proof."""

    return hashlib.sha256(
        canonical_export_json(contract.model_dump(mode="json"))
    ).hexdigest()


def _output_ids(contract: DryLabIntegrityContract) -> set[UUID]:
    return {
        contract.outputs.normalized_csv_version_id,
        contract.outputs.figure_png_version_id,
        contract.outputs.analysis_markdown_version_id,
        contract.outputs.ledger_json_version_id,
        contract.outputs.ledger_csv_version_id,
    }


def _provenance_pins_mismatch(contract: DryLabIntegrityContract) -> bool:
    return (
        contract.provenance.source_run_id != contract.source_run_id
        or contract.provenance.action_plan_sha256 != contract.action_plan.digest_sha256
        or contract.provenance.research_intent_sha256
        != contract.action_plan.research_intent_sha256
        or contract.export.research_intent_sha256
        != contract.action_plan.research_intent_sha256
        or contract.review.pinned_input_sha256 != contract.provenance.manifest_sha256
    )


def _canonical_export_payloads_match(
    contract: DryLabIntegrityContract, payloads: Mapping[str, bytes]
) -> bool:
    expected_payloads = {
        contract.export.provenance_path: canonical_export_json(
            contract.provenance.model_dump(mode="json")
        ),
        contract.export.action_plan_path: canonical_export_json(
            contract.action_plan.model_dump(mode="json")
        ),
        contract.export.review_path: canonical_export_json(
            contract.review.model_dump(mode="json")
        ),
    }
    return all(
        payloads.get(path) == payload for path, payload in expected_payloads.items()
    )


def _review_and_export_pins_mismatch(contract: DryLabIntegrityContract) -> bool:
    reviewed = set(contract.review.pinned_artifact_version_ids)
    original_outputs = _output_ids(contract)
    current_versions = set(original_outputs)
    seen_successors: set[UUID] = set()
    for event in contract.review.resolution_events:
        if event.kind != "correction":
            continue
        old_version_id = event.old_artifact_version_id
        new_version_id = event.new_artifact_version_id
        if (
            old_version_id is None
            or new_version_id is None
            or old_version_id not in current_versions
            or new_version_id in current_versions
            or new_version_id in seen_successors
        ):
            return True
        current_versions.remove(old_version_id)
        current_versions.add(new_version_id)
        seen_successors.add(new_version_id)
    approved_executions = {item.execution_id for item in contract.executions}
    reviewed_executions = set(contract.review.pinned_execution_ids)
    return (
        contract.review.status != "completed"
        or contract.review.submission is None
        or contract.review.source_run_id != contract.source_run_id
        or reviewed != original_outputs
        or len(reviewed) != len(contract.review.pinned_artifact_version_ids)
        or reviewed_executions != approved_executions
        or len(reviewed_executions) != len(contract.review.pinned_execution_ids)
        or set(contract.export.selected_artifact_version_ids) != current_versions
    )


def _findings_reference_unpinned_evidence(contract: DryLabIntegrityContract) -> bool:
    submission = contract.review.submission
    if submission is None:
        return False
    reviewed = set(contract.review.pinned_artifact_version_ids)
    reviewed_executions = set(contract.review.pinned_execution_ids)
    return any(
        set(finding.artifact_version_ids) - reviewed
        or set(finding.execution_ids) - reviewed_executions
        for finding in submission.findings
    )


def _resolution_events_bind_reviewed_versions(
    contract: DryLabIntegrityContract,
) -> bool:
    submission = contract.review.submission
    if submission is None:
        return not contract.review.resolution_events
    current_versions = set(contract.review.pinned_artifact_version_ids)
    for event in contract.review.resolution_events:
        if event.kind != "correction":
            continue
        old_version_id = event.old_artifact_version_id
        new_version_id = event.new_artifact_version_id
        if (
            old_version_id is None
            or new_version_id is None
            or old_version_id not in current_versions
            or new_version_id in current_versions
        ):
            return False
        current_versions.remove(old_version_id)
        current_versions.add(new_version_id)
    return current_versions == set(contract.export.selected_artifact_version_ids)


def _skill_pins_mismatch(contract: DryLabIntegrityContract) -> bool:
    skill_ids = {skill.id for skill in contract.skills}
    skill_pins = {pin.ref_id: pin.sha256 for pin in contract.provenance.skill_hashes}
    expected_refs = {f"{skill.id}@{skill.version}" for skill in contract.skills}
    return (
        set(skill_pins) != expected_refs
        or skill_ids != set(CANONICAL_SKILL_IDS)
        or any(
            skill.project_id != contract.project_id
            or skill.run_id != contract.source_run_id
            or skill_pins.get(f"{skill.id}@{skill.version}") != skill.content_sha256
            for skill in contract.skills
        )
    )


def _chain_references_mismatch(contract: DryLabIntegrityContract) -> bool:
    return (
        contract.ledger.json_artifact_version_id
        != contract.outputs.ledger_json_version_id
        or contract.ledger.csv_artifact_version_id
        != contract.outputs.ledger_csv_version_id
        or contract.export.source_run_id != contract.source_run_id
        or contract.export.review_id != contract.review.id
        or contract.review.run_id == contract.review.source_run_id
        or any(
            version.org_id != contract.org_id
            or version.project_id != contract.project_id
            for version in contract.artifact_versions
        )
    )


def _correction_checksums_mismatch(contract: DryLabIntegrityContract) -> bool:
    versions = {version.id: version for version in contract.artifact_versions}
    for event in contract.review.resolution_events:
        if event.kind != "correction":
            continue
        old_version_id = event.old_artifact_version_id
        new_version_id = event.new_artifact_version_id
        if old_version_id is None or new_version_id is None:
            return True
        old_version = versions.get(old_version_id)
        new_version = versions.get(new_version_id)
        predecessor_correction = next(
            (
                prior
                for prior in reversed(contract.review.resolution_events)
                if (
                    prior.kind == "correction"
                    and prior.new_artifact_version_id == old_version_id
                )
            ),
            None,
        )
        if (
            old_version is None
            or new_version is None
            or old_version.artifact_id != new_version.artifact_id
            or old_version.org_id != new_version.org_id
            or old_version.project_id != new_version.project_id
            or (
                predecessor_correction is not None
                and old_version.content_sha256
                != predecessor_correction.successor_checksum
            )
            or new_version.version != old_version.version + 1
            or old_version.id not in new_version.input_version_ids
            or new_version.created_at < old_version.created_at
            or new_version.content_sha256 != event.successor_checksum
        ):
            return True
    return False


def _export_entry_errors(contract: DryLabIntegrityContract) -> tuple[str, ...]:
    entries = contract.export.artifact_entries
    selected = set(contract.export.selected_artifact_version_ids)
    entry_versions = tuple(entry.artifact_version_id for entry in entries)
    if (
        len(set(entry_versions)) != len(entry_versions)
        or set(entry_versions) != selected
        or len({entry.path for entry in entries}) != len(entries)
    ):
        return ("Export entries are not an exact selected-version bijection",)
    versions = {version.id: version for version in contract.artifact_versions}
    errors: list[str] = []
    for entry in entries:
        version = versions.get(entry.artifact_version_id)
        if (
            version is None
            or version.content_sha256 != entry.sha256
            or version.media_type != entry.media_type
        ):
            errors.append("Export entry does not match selected Artifact Version")
    return tuple(errors)


def final_export_integrity_errors(
    contract: DryLabIntegrityContract,
    envelope_bytes: bytes,
    authority: ExportContractAuthority | None = None,
) -> tuple[str, ...]:
    if authority is None or authority.resolve_contract_sha256(
        contract.source_run_id
    ) != canonical_dry_lab_contract_sha256(contract):
        return ("Export envelope does not bind selected immutable versions",)
    review_errors = review_integrity_errors(contract)
    if review_errors:
        return review_errors
    try:
        envelope = parse_export_envelope(envelope_bytes)
        payloads = {member.path: member.payload_bytes() for member in envelope.members}
    except (TypeError, ValueError):
        return ("Export envelope does not bind selected immutable versions",)
    if (
        _export_entry_errors(contract)
        or not verify_export_envelope(envelope_bytes)
        or contract.export.detached_proof is None
        or contract.export.detached_proof != envelope.proof
        or payloads.get(contract.export.manifest_path)
        != canonical_export_manifest_payload(contract.export)
        or not _canonical_export_payloads_match(contract, payloads)
    ):
        return ("Export envelope does not bind selected immutable versions",)
    return ()


def review_integrity_errors(
    contract: DryLabIntegrityContract,
) -> tuple[str, ...]:
    errors: list[str] = []
    if _provenance_pins_mismatch(contract):
        errors.append("Run, ActionPlan, and Review digest pins do not match provenance")
    if _review_and_export_pins_mismatch(contract):
        errors.append("Review and Export must pin exactly the output versions")
    if _findings_reference_unpinned_evidence(contract):
        errors.append("Finding references unpinned evidence")
    if not _resolution_events_bind_reviewed_versions(contract):
        errors.append("Resolution events do not bind reviewed immutable versions")
    if _skill_pins_mismatch(contract):
        errors.append("canonical Skill snapshots lack Project, Run, or provenance pins")
    if _chain_references_mismatch(contract):
        errors.append("Ledger, Review, and Export chain references do not match")
    if _correction_checksums_mismatch(contract):
        errors.append(
            "Correction successor checksum does not bind an immutable version"
        )
    errors.extend(_export_entry_errors(contract))
    return tuple(errors)
