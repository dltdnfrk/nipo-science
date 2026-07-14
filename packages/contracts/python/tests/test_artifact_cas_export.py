from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from science_workbench_contracts.artifact_versions import (
    ArtifactAttachmentState,
    AttachArtifactVersion,
    AttachmentApplied,
    AttachmentRejected,
    DetachArtifactVersion,
    apply_artifact_attachment_cas,
)

ARTIFACT_ID = "018f47a0-7b9c-7a20-8def-0123456789ab"
ORG_ID = "018f47a0-7b9c-7a01-8def-0123456789ab"
PROJECT_ID = "018f47a0-7b9c-7a03-8def-0123456789ab"
VERSION_ONE = "018f47a0-7b9c-7a10-8def-0123456789ab"
VERSION_TWO = "018f47a0-7b9c-7a11-8def-0123456789ab"


def test_applies_attach_and_detach_with_compare_and_swap() -> None:
    # Given: an immutable attachment state at revision one.
    state = ArtifactAttachmentState.model_validate_json(
        json.dumps(
            {
                "artifact_id": ARTIFACT_ID,
                "org_id": ORG_ID,
                "project_id": PROJECT_ID,
                "revision": 1,
                "version_ids": [VERSION_ONE],
            }
        )
    )
    attach = AttachArtifactVersion.model_validate_json(
        json.dumps(
            {
                "operation": "attach",
                "base_revision": 1,
                "version_id": VERSION_TWO,
                "version_org_id": ORG_ID,
                "version_project_id": PROJECT_ID,
                "version_artifact_id": ARTIFACT_ID,
            }
        )
    )

    # When: the current revision attaches and then detaches a version.
    attached = apply_artifact_attachment_cas(state, attach)
    assert isinstance(attached, AttachmentApplied)
    detach = DetachArtifactVersion.model_validate_json(
        json.dumps(
            {"operation": "detach", "base_revision": 2, "version_id": VERSION_ONE}
        )
    )
    detached = apply_artifact_attachment_cas(attached.state, detach)

    # Then: each operation creates a new revision without mutating the prior state.
    assert isinstance(detached, AttachmentApplied)
    assert state.revision == 1
    assert state.model_dump(mode="json")["version_ids"] == [VERSION_ONE]
    assert detached.state.revision == 3
    assert detached.state.model_dump(mode="json")["version_ids"] == [VERSION_TWO]


def test_rejects_stale_compare_and_swap_without_state_change() -> None:
    # Given: a revision-two state and a stale revision-one attach command.
    state = ArtifactAttachmentState.model_validate_json(
        json.dumps(
            {
                "artifact_id": ARTIFACT_ID,
                "org_id": ORG_ID,
                "project_id": PROJECT_ID,
                "revision": 2,
                "version_ids": [VERSION_ONE],
            }
        )
    )
    command = AttachArtifactVersion.model_validate_json(
        json.dumps(
            {
                "operation": "attach",
                "base_revision": 1,
                "version_id": VERSION_TWO,
                "version_org_id": ORG_ID,
                "version_project_id": PROJECT_ID,
                "version_artifact_id": ARTIFACT_ID,
            }
        )
    )

    # When: compare-and-swap evaluates the stale command.
    result = apply_artifact_attachment_cas(state, command)

    # Then: it returns a typed conflict and preserves the original attachment state.
    assert isinstance(result, AttachmentRejected)
    assert result.reason == "stale_revision"
    assert state.model_dump(mode="json") == {
        "artifact_id": ARTIFACT_ID,
        "org_id": ORG_ID,
        "project_id": PROJECT_ID,
        "revision": 2,
        "version_ids": [VERSION_ONE],
    }


def test_rejects_duplicate_attachment_and_missing_attach_detach_targets() -> None:
    # Given: duplicate state and commands for present and absent IDs.
    duplicate = json.dumps(
        {
            "artifact_id": ARTIFACT_ID,
            "org_id": ORG_ID,
            "project_id": PROJECT_ID,
            "revision": 1,
            "version_ids": [VERSION_ONE, VERSION_ONE],
        }
    )
    state = ArtifactAttachmentState.model_validate_json(
        json.dumps(
            {
                "artifact_id": ARTIFACT_ID,
                "org_id": ORG_ID,
                "project_id": PROJECT_ID,
                "revision": 1,
                "version_ids": [VERSION_ONE],
            }
        )
    )
    attach = AttachArtifactVersion.model_validate_json(
        json.dumps(
            {
                "operation": "attach",
                "base_revision": 1,
                "version_id": VERSION_ONE,
                "version_org_id": ORG_ID,
                "version_project_id": PROJECT_ID,
                "version_artifact_id": ARTIFACT_ID,
            }
        )
    )
    detach = DetachArtifactVersion.model_validate_json(
        json.dumps(
            {"operation": "detach", "base_revision": 1, "version_id": VERSION_TWO}
        )
    )

    # When/Then: duplicate state and invalid operations fail without mutation.
    with pytest.raises(ValidationError, match="unique"):
        _ = ArtifactAttachmentState.model_validate_json(duplicate)
    attached = apply_artifact_attachment_cas(state, attach)
    detached = apply_artifact_attachment_cas(state, detach)
    cross_tenant = apply_artifact_attachment_cas(
        state,
        AttachArtifactVersion.model_validate_json(
            json.dumps(
                {
                    "operation": "attach",
                    "base_revision": 1,
                    "version_id": VERSION_TWO,
                    "version_org_id": VERSION_TWO,
                    "version_project_id": PROJECT_ID,
                    "version_artifact_id": ARTIFACT_ID,
                }
            )
        ),
    )
    assert isinstance(attached, AttachmentRejected)
    assert isinstance(detached, AttachmentRejected)
    assert attached.reason == "already_attached"
    assert detached.reason == "not_attached"
    assert isinstance(cross_tenant, AttachmentRejected)
    assert cross_tenant.reason == "context_mismatch"
