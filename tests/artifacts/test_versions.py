import hashlib
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

import pytest
from services.api.artifacts import (
    ArtifactError,
    ArtifactErrorCode,
    ArtifactVersion,
    VersionDraft,
)

from .support import (
    EXECUTION_A,
    EXECUTION_B,
    RUNTIME_CONNECTION,
    SCOPE_A,
    SCOPE_B,
    SESSION_A,
    SHA_A,
    SHA_B,
    build_service,
)


def _draft(
    artifact_id: UUID,
    base_version_no: int,
    watcher_reference: str,
    execution_id: UUID = EXECUTION_A,
    input_version_ids: tuple[UUID, ...] = (),
) -> VersionDraft:
    return VersionDraft.model_validate(
        {
            "artifact_id": artifact_id,
            "base_version_no": base_version_no,
            "watcher_reference": watcher_reference,
            "producing_execution_id": execution_id,
            "environment_sha256": SHA_A,
            "code_sha256": SHA_B,
            "runtime_adapter_id": "openai_codex",
            "runtime_connection_id": RUNTIME_CONNECTION,
            "skill_content_hashes": (SHA_A,),
            "source_hashes": (SHA_B,),
            "input_version_ids": input_version_ids,
        }
    )


def test_versions_are_monotonic_immutable_and_content_addressed() -> None:
    service, store, watcher, _ = build_service()
    artifact = service.create_artifact(SCOPE_A, "Probe measurements")
    first_payload = b"wavelength,value\n450,0.12\n"
    second_payload = b"wavelength,value\n450,0.15\n"
    first_ref = watcher.register(SCOPE_A, EXECUTION_A, first_payload, "text/csv")
    version_one = service.create_version(SCOPE_A, _draft(artifact.id, 0, first_ref))
    second_ref = watcher.register(SCOPE_A, EXECUTION_A, second_payload, "text/csv")
    version_two = service.create_version(
        SCOPE_A, _draft(artifact.id, 1, second_ref, input_version_ids=(version_one.id,))
    )

    assert version_one.version_no == 1
    assert version_two.version_no == 2
    assert version_one.content_sha256 == hashlib.sha256(first_payload).hexdigest()
    assert service.read_version(SCOPE_A, version_one.id) == version_one
    assert service.read_content(SCOPE_A, version_one.id) == first_payload
    assert service.read_content(SCOPE_A, version_two.id) == second_payload
    assert service.lineage(SCOPE_A, version_two.id) == (version_one.id,)
    assert store.object_count(SCOPE_A) == 2


def test_stale_base_is_409_equivalent_and_dedupe_preserves_versions() -> None:
    service, store, watcher, _ = build_service()
    artifact = service.create_artifact(SCOPE_A, "Normalized output")
    payload = b"sample,value\ncontrol,1\n"
    first_reference = watcher.register(SCOPE_A, EXECUTION_A, payload, "text/csv")
    second_reference = watcher.register(SCOPE_A, EXECUTION_A, payload, "text/csv")
    stale_reference = watcher.register(SCOPE_A, EXECUTION_A, payload, "text/csv")
    version_one = service.create_version(
        SCOPE_A, _draft(artifact.id, 0, first_reference)
    )
    version_two = service.create_version(
        SCOPE_A, _draft(artifact.id, 1, second_reference)
    )

    with pytest.raises(ArtifactError) as captured:
        _ = service.create_version(SCOPE_A, _draft(artifact.id, 1, stale_reference))

    assert captured.value.code is ArtifactErrorCode.STALE_BASE
    version_three = service.create_version(
        SCOPE_A, _draft(artifact.id, 2, stale_reference)
    )
    assert service.read_version(SCOPE_A, version_one.id) == version_one
    assert service.read_version(SCOPE_A, version_two.id) == version_two
    assert service.read_version(SCOPE_A, version_three.id) == version_three
    assert store.version_count(SCOPE_A, artifact.id) == 3
    assert store.object_count(SCOPE_A) == 1


def test_lineage_and_session_associations_are_tenant_scoped_and_unique() -> None:
    service, _, watcher, _ = build_service()
    artifact_a = service.create_artifact(SCOPE_A, "Derived A")
    artifact_b = service.create_artifact(SCOPE_B, "Input B")
    reference_b = watcher.register(SCOPE_B, EXECUTION_B, b"foreign", "text/plain")
    version_b = service.create_version(
        SCOPE_B,
        _draft(artifact_b.id, 0, reference_b, execution_id=EXECUTION_B),
    )
    reference_a = watcher.register(SCOPE_A, EXECUTION_A, b"derived", "text/plain")

    with pytest.raises(ArtifactError) as captured:
        _ = service.create_version(
            SCOPE_A,
            _draft(
                artifact_a.id,
                0,
                reference_a,
                input_version_ids=(version_b.id,),
            ),
        )
    assert captured.value.code is ArtifactErrorCode.INVALID_LINEAGE

    version_a = service.create_version(SCOPE_A, _draft(artifact_a.id, 0, reference_a))
    link = service.attach_session(SCOPE_A, SESSION_A, version_a.id)
    assert link.artifact_version_id == version_a.id

    with pytest.raises(ArtifactError) as duplicate:
        _ = service.attach_session(SCOPE_A, SESSION_A, version_a.id)
    with pytest.raises(ArtifactError) as foreign:
        _ = service.read_version(SCOPE_B, version_a.id)
    assert duplicate.value.code is ArtifactErrorCode.ASSOCIATION_EXISTS
    assert foreign.value.code is ArtifactErrorCode.NOT_FOUND


def test_concurrent_base_zero_creates_exactly_one_first_version() -> None:
    service, store, watcher, _ = build_service()
    artifact = service.create_artifact(SCOPE_A, "Concurrent")
    references = tuple(
        watcher.register(SCOPE_A, EXECUTION_A, payload, "text/plain")
        for payload in (b"first", b"second")
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = tuple(
            pool.submit(
                service.create_version,
                SCOPE_A,
                _draft(artifact.id, 0, reference),
            )
            for reference in references
        )

    created: list[ArtifactVersion] = []
    rejected: list[ArtifactErrorCode] = []
    for future in futures:
        try:
            created.append(future.result())
        except ArtifactError as error:
            rejected.append(error.code)
    assert len(created) == 1
    assert rejected == [ArtifactErrorCode.STALE_BASE]
    assert store.version_count(SCOPE_A, artifact.id) == 1
