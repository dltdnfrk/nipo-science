from datetime import timedelta
from uuid import UUID

import pytest
from services.api.artifacts import (
    MAX_ARTIFACT_OUTPUT_BYTES,
    ArtifactError,
    ArtifactErrorCode,
    VersionDraft,
)

from .support import (
    EXECUTION_A,
    EXECUTION_B,
    ORG_A,
    PROJECT_A,
    PROJECT_B,
    RUNTIME_CONNECTION,
    SCOPE_A,
    SCOPE_B,
    SCOPE_C,
    SHA_A,
    SHA_B,
    build_service,
)


def _draft(
    artifact_id: UUID,
    reference: str,
    execution_id: UUID = EXECUTION_A,
) -> VersionDraft:
    return VersionDraft.model_validate(
        {
            "artifact_id": artifact_id,
            "base_version_no": 0,
            "watcher_reference": reference,
            "producing_execution_id": execution_id,
            "environment_sha256": SHA_A,
            "code_sha256": SHA_B,
            "runtime_adapter_id": "openai_codex",
            "runtime_connection_id": RUNTIME_CONNECTION,
            "skill_content_hashes": (),
            "source_hashes": (),
            "input_version_ids": (),
        }
    )


def test_output_watcher_references_cannot_be_forged_or_rebound() -> None:
    service, store, watcher, _ = build_service()
    artifact = service.create_artifact(SCOPE_A, "Watcher output")
    foreign_artifact = service.create_artifact(SCOPE_B, "Foreign output")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"verified", "text/plain")

    for forged_reference, execution_id in (
        (f"{reference}-forged", EXECUTION_A),
        (reference, EXECUTION_B),
    ):
        with pytest.raises(ArtifactError) as captured:
            _ = service.create_version(
                SCOPE_A,
                _draft(artifact.id, forged_reference, execution_id),
            )
        assert captured.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID
    with pytest.raises(ArtifactError) as cross_tenant:
        _ = service.create_version(
            SCOPE_B,
            _draft(foreign_artifact.id, reference, EXECUTION_B),
        )
    assert cross_tenant.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID
    assert store.version_count(SCOPE_A, artifact.id) == 0

    version = service.create_version(SCOPE_A, _draft(artifact.id, reference))
    assert version.object_key.startswith(
        f"org/{SCOPE_A.org_id}/project/{SCOPE_A.project_id}/sha256/"
    )
    assert reference not in version.object_key
    retried = service.create_version(SCOPE_A, _draft(artifact.id, reference))
    assert retried == version
    conflicting = _draft(artifact.id, reference).model_copy(
        update={"environment_sha256": "c" * 64}
    )
    with pytest.raises(ArtifactError) as rebound:
        _ = service.create_version(SCOPE_A, conflicting)
    with pytest.raises(ArtifactError) as replayed_claim:
        _ = watcher.claim(SCOPE_A, EXECUTION_A, reference)
    assert rebound.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID
    assert replayed_claim.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID


def test_output_watcher_rejects_another_requester_in_the_same_project() -> None:
    service, store, watcher, _ = build_service()
    artifact = service.create_artifact(SCOPE_A, "Requester-bound output")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"owned", "text/plain")

    with pytest.raises(ArtifactError) as registration:
        _ = watcher.register(SCOPE_C, EXECUTION_A, b"foreign", "text/plain")
    with pytest.raises(ArtifactError) as consumption:
        _ = service.create_version(SCOPE_C, _draft(artifact.id, reference))

    assert registration.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID
    assert consumption.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID
    assert store.version_count(SCOPE_A, artifact.id) == 0


def test_output_watcher_rejects_payload_above_shared_durable_limit() -> None:
    _, _, watcher, _ = build_service()

    with pytest.raises(ArtifactError) as rejected:
        _ = watcher.register(
            SCOPE_A,
            EXECUTION_A,
            b"x" * (MAX_ARTIFACT_OUTPUT_BYTES + 1),
            "application/octet-stream",
        )

    assert rejected.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID


@pytest.mark.parametrize(
    "media_type",
    [
        "text/html",
        "image/svg+xml",
        "text/plain; charset=utf-8",
        "text/plain\r\nX-Injected: yes",
    ],
)
def test_output_watcher_rejects_active_or_noncanonical_media_types(
    media_type: str,
) -> None:
    _, _, watcher, _ = build_service()

    with pytest.raises(ArtifactError) as rejected:
        _ = watcher.register(SCOPE_A, EXECUTION_A, b"untrusted", media_type)

    assert rejected.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID


def test_output_watcher_claim_release_requires_the_exact_fencing_token() -> None:
    _, _, watcher, _ = build_service()
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"claim", "text/plain")
    claim = watcher.claim(SCOPE_A, EXECUTION_A, reference)
    forged = claim.model_copy(
        update={"token": UUID("018f47a0-7b9c-7d01-8def-0123456789ab")}
    )

    with pytest.raises(ArtifactError) as rejected:
        watcher.release(forged)

    watcher.finalize(claim)
    watcher.finalize(claim)
    assert rejected.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID


@pytest.mark.parametrize(
    "runtime_update",
    [
        {"runtime_adapter_id": "fabricated_adapter"},
        {"runtime_connection_id": UUID("018f47a0-7b9c-7a42-8def-0123456789ab")},
    ],
)
def test_version_rejects_runtime_provenance_not_bound_to_execution(
    runtime_update: dict[str, str | UUID],
) -> None:
    service, store, watcher, _ = build_service()
    artifact = service.create_artifact(SCOPE_A, "Runtime-bound output")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"bound", "text/plain")
    fabricated = _draft(artifact.id, reference).model_copy(update=runtime_update)

    with pytest.raises(ArtifactError) as rejected:
        _ = service.create_version(SCOPE_A, fabricated)

    assert rejected.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID
    assert store.version_count(SCOPE_A, artifact.id) == 0


def test_content_addresses_are_tenant_specific_for_identical_bytes() -> None:
    service, _, watcher, _ = build_service()
    artifact_a = service.create_artifact(SCOPE_A, "A")
    artifact_b = service.create_artifact(SCOPE_B, "B")
    reference_a = watcher.register(SCOPE_A, EXECUTION_A, b"same", "text/plain")
    reference_b = watcher.register(SCOPE_B, EXECUTION_B, b"same", "text/plain")
    version_a = service.create_version(SCOPE_A, _draft(artifact_a.id, reference_a))
    version_b = service.create_version(
        SCOPE_B,
        _draft(artifact_b.id, reference_b, execution_id=EXECUTION_B),
    )

    assert version_a.content_sha256 == version_b.content_sha256
    assert version_a.object_key != version_b.object_key
    assert f"org/{ORG_A}/project/{PROJECT_A}" in version_a.object_key
    assert f"project/{PROJECT_B}" in version_b.object_key


def test_content_checksum_mismatch_fails_closed() -> None:
    service, store, watcher, _ = build_service()
    artifact = service.create_artifact(SCOPE_A, "Checksum")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"original", "text/plain")
    version = service.create_version(SCOPE_A, _draft(artifact.id, reference))
    store.corrupt_blob_for_test(version.id, b"tampered")

    with pytest.raises(ArtifactError) as captured:
        _ = service.read_content(SCOPE_A, version.id)

    assert captured.value.code is ArtifactErrorCode.CHECKSUM_MISMATCH


def test_download_ttl_is_integral_millisecond_and_never_shortened() -> None:
    service, _, watcher, clock = build_service()
    artifact = service.create_artifact(SCOPE_A, "Download TTL")
    payload = b"immutable evidence"
    reference = watcher.register(SCOPE_A, EXECUTION_A, payload, "text/plain")
    version = service.create_version(SCOPE_A, _draft(artifact.id, reference))

    with pytest.raises(ArtifactError) as long_ttl:
        _ = service.issue_download(SCOPE_A, version.id, timedelta(minutes=11))
    assert long_ttl.value.code is ArtifactErrorCode.DOWNLOAD_TTL_INVALID
    with pytest.raises(ArtifactError) as sub_millisecond:
        _ = service.issue_download(SCOPE_A, version.id, timedelta(microseconds=999))
    assert sub_millisecond.value.code is ArtifactErrorCode.DOWNLOAD_TTL_INVALID

    clock.advance(timedelta(microseconds=999_999))
    issued_at = clock.now()
    millisecond = service.issue_download(SCOPE_A, version.id, timedelta(milliseconds=1))
    assert millisecond.expires_at - issued_at >= timedelta(milliseconds=1)
    clock.advance(timedelta(milliseconds=1))
    assert service.redeem_download(SCOPE_A, millisecond.token) == payload
    clock.advance(timedelta(microseconds=1))
    with pytest.raises(ArtifactError) as millisecond_expired:
        _ = service.redeem_download(SCOPE_A, millisecond.token)
    assert millisecond_expired.value.code is ArtifactErrorCode.DOWNLOAD_EXPIRED
    clock.advance(timedelta(microseconds=-1_001_000))

    clock.advance(timedelta(microseconds=500))
    aligned = service.issue_download(SCOPE_A, version.id, timedelta(milliseconds=1))
    clock.advance(timedelta(microseconds=1_499))
    assert clock.now() < aligned.expires_at
    assert service.redeem_download(SCOPE_A, aligned.token) == payload
    clock.advance(timedelta(microseconds=1))
    assert clock.now() == aligned.expires_at
    with pytest.raises(ArtifactError) as aligned_expired:
        _ = service.redeem_download(SCOPE_A, aligned.token)
    assert aligned_expired.value.code is ArtifactErrorCode.DOWNLOAD_EXPIRED
    clock.advance(timedelta(microseconds=-2_000))

    clock.advance(timedelta(microseconds=123_456))
    maximum = service.issue_download(SCOPE_A, version.id, timedelta(minutes=10))
    assert maximum.expires_at - clock.now() <= timedelta(minutes=10)
    assert maximum.expires_at.microsecond == 123_000


def test_downloads_are_short_lived_scoped_and_archive_aware() -> None:
    service, store, watcher, clock = build_service()
    artifact = service.create_artifact(SCOPE_A, "Download")
    payload = b"immutable evidence"
    reference = watcher.register(SCOPE_A, EXECUTION_A, payload, "text/plain")
    version = service.create_version(SCOPE_A, _draft(artifact.id, reference))
    download = service.issue_download(SCOPE_A, version.id, timedelta(minutes=10))
    assert service.redeem_download(SCOPE_A, download.token) == payload
    with pytest.raises(ArtifactError) as cross_scope:
        _ = service.redeem_download(SCOPE_B, download.token)
    with pytest.raises(ArtifactError) as forged:
        _ = service.redeem_download(SCOPE_A, f"{download.token}x")
    payload_segment, signature_segment = download.token.split(".", maxsplit=1)
    with pytest.raises(ArtifactError) as noncanonical:
        _ = service.redeem_download(
            SCOPE_A,
            f"{payload_segment}.{signature_segment}=",
        )
    assert cross_scope.value.code is ArtifactErrorCode.NOT_FOUND
    assert forged.value.code is ArtifactErrorCode.DOWNLOAD_INVALID
    assert noncanonical.value.code is ArtifactErrorCode.DOWNLOAD_INVALID

    clock.advance(timedelta(minutes=10))
    with pytest.raises(ArtifactError) as expired:
        _ = service.redeem_download(SCOPE_A, download.token)
    assert expired.value.code is ArtifactErrorCode.DOWNLOAD_EXPIRED

    clock.advance(timedelta(seconds=-1))
    store.archive_project(SCOPE_A)
    with pytest.raises(ArtifactError) as archived:
        _ = service.redeem_download(SCOPE_A, download.token)
    assert archived.value.code is ArtifactErrorCode.PROJECT_ARCHIVED
