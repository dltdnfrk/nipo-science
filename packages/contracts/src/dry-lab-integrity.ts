import type { Uuid7 } from "./common"
import type { DryLabRunContractCore } from "./dry-lab-contract"
import { CANONICAL_SKILL_IDS } from "./skill-manifests"

function sameSet(left: Iterable<string>, right: Iterable<string>): boolean {
  const leftSet = new Set(left)
  const rightSet = new Set(right)
  return leftSet.size === rightSet.size && [...leftSet].every((value) => rightSet.has(value))
}

export function validateDryLabIntegrity(contract: DryLabRunContractCore): readonly string[] {
  const errors: string[] = []
  const versions = new Map(contract.artifact_versions.map((version) => [version.id, version]))
  const coordinates = new Set(
    contract.artifact_versions.map((version) => `${version.artifact_id}:${version.version}`),
  )
  if (versions.size !== contract.artifact_versions.length || coordinates.size !== versions.size) {
    errors.push("Artifact Version IDs and revision coordinates must be unique")
  }
  const inputIds = contract.scientific_inputs.map((input) => input.artifact_version_id)
  const executionIds = new Set(contract.executions.map((execution) => execution.execution_id))
  if (
    new Set(inputIds).size !== inputIds.length ||
    executionIds.size !== contract.executions.length
  ) {
    errors.push("scientific input and Execution IDs must be unique")
  }
  const outputSpecs: readonly (readonly [Uuid7, string])[] = [
    [contract.outputs.normalized_csv_version_id, "text/csv"],
    [contract.outputs.figure_png_version_id, "image/png"],
    [contract.outputs.analysis_markdown_version_id, "text/markdown"],
    [contract.outputs.ledger_json_version_id, "application/json"],
    [contract.outputs.ledger_csv_version_id, "text/csv"],
  ]
  const outputIds = outputSpecs.map(([versionId]) => versionId)
  if (inputIds.some((id) => outputIds.includes(id))) {
    errors.push("scientific source inputs must be disjoint from derived outputs")
  }
  if (new Set(outputIds).size !== outputIds.length)
    errors.push("required output versions must be distinct")
  const pinGroups = [
    contract.provenance.input_hashes,
    contract.provenance.execution_hashes,
    contract.provenance.output_hashes,
    contract.provenance.skill_hashes,
    contract.provenance.source_hashes,
  ]
  if (pinGroups.some((pins) => new Set(pins.map((pin) => pin.ref_id)).size !== pins.length)) {
    errors.push("provenance ref_id values must be unique within each pin class")
  }
  const inputPins = new Map(contract.provenance.input_hashes.map((pin) => [pin.ref_id, pin.sha256]))
  const expectedInputRefs = inputIds.flatMap((id) => [id, `calibration:${id}`])
  if (!sameSet(inputPins.keys(), expectedInputRefs)) {
    errors.push("provenance input pins must exactly cover content and calibration")
  }
  for (const input of contract.scientific_inputs) {
    const version = versions.get(input.artifact_version_id)
    if (
      version === undefined ||
      inputPins.get(input.artifact_version_id) !== version.content_sha256
    ) {
      errors.push("scientific input content checksum is not provenance-pinned")
    }
    if (
      inputPins.get(`calibration:${input.artifact_version_id}`) !==
      input.calibration.calibration_sha256
    ) {
      errors.push("scientific input calibration checksum is not provenance-pinned")
    }
  }
  const executionPins = new Map(
    contract.provenance.execution_hashes.map((pin) => [pin.ref_id, pin.sha256]),
  )
  if (!sameSet(executionPins.keys(), executionIds)) {
    errors.push("provenance execution pins must exactly cover approved Executions")
  }
  for (const execution of contract.executions) {
    if (
      execution.action_plan_id !== contract.action_plan.action_plan_id ||
      execution.approval_id !== contract.action_plan.approval_id ||
      executionPins.get(execution.execution_id) !== execution.execution_sha256
    ) {
      errors.push("Execution is not bound to its approved plan and provenance hash")
    }
  }
  const outputPins = new Map(
    contract.provenance.output_hashes.map((pin) => [pin.ref_id, pin.sha256]),
  )
  const skillHashes = new Set(contract.skills.map((skill) => skill.content_sha256))
  const sourceHashes = new Set(contract.provenance.source_hashes.map((pin) => pin.sha256))
  if (!sameSet(outputPins.keys(), outputIds))
    errors.push("provenance output pins must exactly cover outputs")
  for (const [versionId, mediaType] of outputSpecs) {
    const version = versions.get(versionId)
    if (
      version === undefined ||
      version.media_type !== mediaType ||
      !executionIds.has(version.producing_execution_id) ||
      outputPins.get(versionId) !== version.content_sha256 ||
      version.code_sha256 !== contract.provenance.code_sha256 ||
      version.environment_sha256 !== contract.provenance.environment_sha256 ||
      version.runtime_adapter_id !== contract.provenance.runtime_adapter_id ||
      version.runtime_connection_id !== contract.provenance.runtime_connection_id ||
      new Set(version.input_version_ids).size !== inputIds.length ||
      !inputIds.every((inputId) => version.input_version_ids.includes(inputId)) ||
      new Set(version.skill_content_hashes).size !== skillHashes.size ||
      ![...skillHashes].every((hash) => version.skill_content_hashes.includes(hash)) ||
      new Set(version.source_hashes).size !== sourceHashes.size ||
      ![...sourceHashes].every((hash) => version.source_hashes.includes(hash))
    ) {
      errors.push("output Artifact Version does not match its complete provenance")
    }
  }
  for (const row of contract.ledger.rows) {
    const version = versions.get(row.artifact_version_id)
    if (
      version?.content_sha256 !== row.supporting_sha256 ||
      !executionIds.has(row.execution_id) ||
      !outputIds.includes(row.artifact_version_id)
    ) {
      errors.push("Ledger row does not reference checksum-pinned execution evidence")
    }
  }
  if (
    contract.provenance.source_run_id !== contract.source_run_id ||
    contract.provenance.action_plan_sha256 !== contract.action_plan.digest_sha256 ||
    contract.provenance.research_intent_sha256 !== contract.action_plan.research_intent_sha256 ||
    contract.export.research_intent_sha256 !== contract.action_plan.research_intent_sha256 ||
    contract.review.pinned_input_sha256 !== contract.provenance.manifest_sha256
  ) {
    errors.push("Run, ActionPlan, and Review digest pins do not match provenance")
  }
  const review = contract.review
  const reviewed = new Set(review.pinned_artifact_version_ids)
  const reviewedExecutions = new Set(review.pinned_execution_ids)
  const selected = new Set(contract.export.selected_artifact_version_ids)
  if (
    review.status !== "completed" ||
    review.submission === null ||
    review.source_run_id !== contract.source_run_id ||
    outputIds.some((id) => !reviewed.has(id)) ||
    reviewed.size !== outputIds.length ||
    reviewed.size !== review.pinned_artifact_version_ids.length ||
    reviewedExecutions.size !== executionIds.size ||
    reviewedExecutions.size !== review.pinned_execution_ids.length ||
    [...reviewedExecutions].some((id) => !executionIds.has(id)) ||
    selected.size !== reviewed.size ||
    [...selected].some((id) => !reviewed.has(id))
  ) {
    errors.push("Review and Export must pin exactly the distinct output versions")
  }
  if (review.submission !== null) {
    for (const finding of review.submission.findings) {
      if (
        !finding.artifact_version_ids.every((id) => reviewed.has(id)) ||
        !finding.execution_ids.every((id) => review.pinned_execution_ids.includes(id))
      ) {
        errors.push("Finding references unpinned evidence")
      }
    }
  }
  const skillIds = new Set(contract.skills.map((skill) => skill.id))
  const skillPins = new Map(contract.provenance.skill_hashes.map((pin) => [pin.ref_id, pin.sha256]))
  const expectedSkillRefs = contract.skills.map((skill) => `${skill.id}@${skill.version}`)
  if (
    !sameSet(skillPins.keys(), expectedSkillRefs) ||
    !CANONICAL_SKILL_IDS.every((id) => skillIds.has(id)) ||
    !contract.skills.every(
      (skill) =>
        skill.project_id === contract.project_id &&
        skill.run_id === contract.source_run_id &&
        skillPins.get(`${skill.id}@${skill.version}`) === skill.content_sha256,
    )
  ) {
    errors.push("canonical Skill snapshots are not bound to Project, Run, and provenance")
  }
  if (
    contract.ledger.json_artifact_version_id !== contract.outputs.ledger_json_version_id ||
    contract.ledger.csv_artifact_version_id !== contract.outputs.ledger_csv_version_id ||
    contract.export.source_run_id !== contract.source_run_id ||
    contract.export.review_id !== review.id ||
    review.run_id === review.source_run_id ||
    contract.artifact_versions.some(
      (version) => version.org_id !== contract.org_id || version.project_id !== contract.project_id,
    )
  ) {
    errors.push("Ledger, Review, and Export chain references do not match")
  }
  for (const entry of contract.export.artifact_entries) {
    const version = versions.get(entry.artifact_version_id)
    if (version?.content_sha256 !== entry.sha256 || version.media_type !== entry.media_type) {
      errors.push("Export entry does not match selected Artifact Version")
    }
  }
  return errors
}
