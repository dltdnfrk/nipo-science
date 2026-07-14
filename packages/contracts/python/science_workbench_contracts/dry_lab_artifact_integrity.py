from .dry_lab_integrity_types import DryLabIntegrityContract


def _base_errors(contract: DryLabIntegrityContract) -> list[str]:
    errors: list[str] = []
    versions = {version.id: version for version in contract.artifact_versions}
    coordinates = {
        (version.artifact_id, version.version) for version in contract.artifact_versions
    }
    if len(versions) != len(contract.artifact_versions) or len(coordinates) != len(
        versions
    ):
        errors.append("Artifact Version IDs and revision coordinates must be unique")
    input_ids = [item.artifact_version_id for item in contract.scientific_inputs]
    execution_ids = [item.execution_id for item in contract.executions]
    if len(set(input_ids)) != len(input_ids) or len(set(execution_ids)) != len(
        execution_ids
    ):
        errors.append("scientific input and Execution IDs must be unique")
    output_ids = (
        contract.outputs.normalized_csv_version_id,
        contract.outputs.figure_png_version_id,
        contract.outputs.analysis_markdown_version_id,
        contract.outputs.ledger_json_version_id,
        contract.outputs.ledger_csv_version_id,
    )
    if len(set(output_ids)) != len(output_ids):
        errors.append("required output versions must be distinct")
    if set(input_ids) & set(output_ids):
        errors.append("scientific source inputs must be disjoint from derived outputs")
    pin_groups = (
        contract.provenance.input_hashes,
        contract.provenance.execution_hashes,
        contract.provenance.output_hashes,
        contract.provenance.skill_hashes,
        contract.provenance.source_hashes,
    )
    if any(len({pin.ref_id for pin in pins}) != len(pins) for pins in pin_groups):
        errors.append("provenance ref_id values must be unique within each pin class")
    return errors


def _input_execution_errors(contract: DryLabIntegrityContract) -> list[str]:
    errors: list[str] = []
    versions = {version.id: version for version in contract.artifact_versions}
    input_pins = {pin.ref_id: pin.sha256 for pin in contract.provenance.input_hashes}
    expected_input_refs = {
        reference
        for item in contract.scientific_inputs
        for reference in (
            str(item.artifact_version_id),
            f"calibration:{item.artifact_version_id}",
        )
    }
    if set(input_pins) != expected_input_refs:
        errors.append(
            "provenance input pins must exactly cover content and calibration"
        )
    for item in contract.scientific_inputs:
        version = versions.get(item.artifact_version_id)
        if (
            version is None
            or input_pins.get(str(item.artifact_version_id)) != version.content_sha256
        ):
            errors.append("scientific input content checksum is not provenance-pinned")
        if (
            input_pins.get(f"calibration:{item.artifact_version_id}")
            != item.calibration.calibration_sha256
        ):
            errors.append(
                "scientific input calibration checksum is not provenance-pinned"
            )
    execution_pins = {
        pin.ref_id: pin.sha256 for pin in contract.provenance.execution_hashes
    }
    if set(execution_pins) != {
        str(execution.execution_id) for execution in contract.executions
    }:
        errors.append("provenance execution pins must exactly cover Executions")
    errors.extend(
        "Execution is not bound to approved plan and provenance hash"
        for execution in contract.executions
        if execution.action_plan_id != contract.action_plan.action_plan_id
        or execution.approval_id != contract.action_plan.approval_id
        or execution_pins.get(str(execution.execution_id)) != execution.execution_sha256
    )
    return errors


def _output_ledger_errors(contract: DryLabIntegrityContract) -> list[str]:
    errors: list[str] = []
    versions = {version.id: version for version in contract.artifact_versions}
    input_ids = {item.artifact_version_id for item in contract.scientific_inputs}
    execution_ids = {execution.execution_id for execution in contract.executions}
    output_specs = (
        (contract.outputs.normalized_csv_version_id, "text/csv"),
        (contract.outputs.figure_png_version_id, "image/png"),
        (contract.outputs.analysis_markdown_version_id, "text/markdown"),
        (contract.outputs.ledger_json_version_id, "application/json"),
        (contract.outputs.ledger_csv_version_id, "text/csv"),
    )
    output_ids = {version_id for version_id, _ in output_specs}
    output_pins = {pin.ref_id: pin.sha256 for pin in contract.provenance.output_hashes}
    skill_hashes = {skill.content_sha256 for skill in contract.skills}
    source_hashes = {pin.sha256 for pin in contract.provenance.source_hashes}
    if set(output_pins) != {str(output_id) for output_id in output_ids}:
        errors.append("provenance output pins must exactly cover outputs")
    for version_id, media_type in output_specs:
        version = versions.get(version_id)
        matches = (
            version is not None
            and version.media_type == media_type
            and version.producing_execution_id in execution_ids
            and output_pins.get(str(version_id)) == version.content_sha256
            and version.code_sha256 == contract.provenance.code_sha256
            and version.environment_sha256 == contract.provenance.environment_sha256
            and version.runtime_adapter_id == contract.provenance.runtime_adapter_id
            and version.runtime_connection_id
            == contract.provenance.runtime_connection_id
            and set(version.input_version_ids) == input_ids
            and len(version.input_version_ids) == len(input_ids)
            and set(version.skill_content_hashes) == skill_hashes
            and len(version.skill_content_hashes) == len(skill_hashes)
            and set(version.source_hashes) == source_hashes
            and len(version.source_hashes) == len(source_hashes)
        )
        if not matches:
            errors.append("output Artifact Version does not match complete provenance")
    for row in contract.ledger.rows:
        version = versions.get(row.artifact_version_id)
        if (
            version is None
            or version.content_sha256 != row.supporting_sha256
            or row.execution_id not in execution_ids
            or row.artifact_version_id not in output_ids
        ):
            errors.append("Ledger row lacks checksum-pinned execution evidence")
    return errors


def artifact_integrity_errors(contract: DryLabIntegrityContract) -> tuple[str, ...]:
    return (
        *_base_errors(contract),
        *_input_execution_errors(contract),
        *_output_ledger_errors(contract),
    )
