import base64
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from pydantic import ValidationError

from science_workbench_contracts.dry_lab_contract import DryLabRunContract
from science_workbench_contracts.dry_lab_review_integrity import (
    canonical_dry_lab_contract_sha256,
    final_export_integrity_errors,
)
from science_workbench_contracts.export_manifest import (
    FIXED_EXPORT_MEMBER_MEDIA_TYPES,
    ExportManifest,
    build_detached_export_proof,
    build_export_envelope,
    canonical_export_json,
    canonical_export_manifest_payload,
    export_checksum_set_sha256,
    serialize_export_envelope,
    verify_detached_export_proof,
    verify_export_envelope,
)

FIXTURE = Path(__file__).parents[2] / "fixtures" / "gs04-dry-lab-contract.json"
VERSION_ONE = "018f47a0-7b9c-7a10-8def-0123456789ab"
VERSION_TWO = "018f47a0-7b9c-7a11-8def-0123456789ab"
type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class MemoryExportContractAuthority:
    _anchors: dict[UUID, str]

    def __init__(self, contract: DryLabRunContract) -> None:
        self._anchors = {
            contract.source_run_id: canonical_dry_lab_contract_sha256(contract)
        }

    def resolve_contract_sha256(self, source_run_id: UUID) -> str | None:
        return self._anchors.get(source_run_id)


def export_authority(contract: DryLabRunContract) -> MemoryExportContractAuthority:
    return MemoryExportContractAuthority(contract)


type JsonArray = list[JsonValue]
type JsonObject = dict[str, JsonValue]
type EnvelopeMutation = Callable[[JsonObject], None]


def _json_object(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


def _json_array(value: JsonValue) -> JsonArray:
    assert isinstance(value, list)
    return value


def _json_integer(value: JsonValue) -> int:
    assert isinstance(value, int)
    assert not isinstance(value, bool)
    return value


def _envelope_json(envelope_bytes: bytes) -> JsonObject:
    decoded = cast("object", json.loads(envelope_bytes))
    return cast("JsonObject", decoded)


def _members(envelope: JsonObject) -> JsonArray:
    return _json_array(envelope["members"])


def _proof(envelope: JsonObject) -> JsonObject:
    return _json_object(envelope["proof"])


def _member_with_path(envelope: JsonObject, path: str) -> JsonObject:
    for member in _members(envelope):
        member_object = _json_object(member)
        if member_object["path"] == path:
            return member_object
    message = f"missing envelope member: {path}"
    raise AssertionError(message)


def _remove_member(envelope: JsonObject) -> None:
    _ = _members(envelope).pop()


def _increment_member_count(envelope: JsonObject) -> None:
    envelope["member_count"] = _json_integer(envelope["member_count"]) + 1


def _append_extra_member(envelope: JsonObject) -> None:
    _members(envelope).append(
        {
            "path": "artifacts/extra.txt",
            "media_type": "text/plain",
            "payload_base64": "",
        }
    )


def _reverse_members(envelope: JsonObject) -> None:
    _members(envelope).reverse()


def _alter_first_member(envelope: JsonObject) -> None:
    _json_object(_members(envelope)[0])["payload_base64"] = base64.b64encode(
        b"altered"
    ).decode("ascii")


def _remove_proof(envelope: JsonObject) -> None:
    del envelope["proof"]


def _alter_proof_source_run_id(envelope: JsonObject, source_run_id: str) -> None:
    _proof(envelope)["source_run_id"] = source_run_id


def _source_run_id_mutation(source_run_id: str) -> EnvelopeMutation:
    def mutate(envelope: JsonObject) -> None:
        _alter_proof_source_run_id(envelope, source_run_id)

    return mutate


def _alter_proof_profile(envelope: JsonObject) -> None:
    _proof(envelope)["profile"] = "unbound-profile"


def _alter_proof_review_id(envelope: JsonObject, review_id: str) -> None:
    _proof(envelope)["review_id"] = review_id


def _review_id_mutation(review_id: str) -> EnvelopeMutation:
    def mutate(envelope: JsonObject) -> None:
        _alter_proof_review_id(envelope, review_id)

    return mutate


def _reverse_selected_artifact_version_ids(envelope: JsonObject) -> None:
    proof = _proof(envelope)
    proof["selected_artifact_version_ids"] = list(
        reversed(_json_array(proof["selected_artifact_version_ids"]))
    )


def _alter_proof_manifest_sha256(envelope: JsonObject) -> None:
    _proof(envelope)["manifest_sha256"] = "0" * 64


def _alter_proof_checksum_set_sha256(envelope: JsonObject) -> None:
    _proof(envelope)["checksum_set_sha256"] = "0" * 64


def _alter_proof_archive_sha256(envelope: JsonObject) -> None:
    _proof(envelope)["archive_sha256"] = "0" * 64


def _alter_checksums_member(envelope: JsonObject) -> None:
    _member_with_path(envelope, "checksums.sha256")["payload_base64"] = (
        base64.b64encode(b"tampered").decode("ascii")
    )


def _alter_manifest_member(envelope: JsonObject) -> None:
    _member_with_path(envelope, "manifest.json")["payload_base64"] = base64.b64encode(
        b"{}"
    ).decode("ascii")


def _coherently_rehash_fixed_member_media_type(envelope: JsonObject) -> None:
    path = "review/review.json"
    media_type = "application/x-tampered"
    _member_with_path(envelope, path)["media_type"] = media_type
    proof = _proof(envelope)
    entries = _json_array(proof["entries"])
    for entry in entries:
        entry_object = _json_object(entry)
        if entry_object["path"] == path:
            entry_object["media_type"] = media_type
            break
    else:
        message = f"missing proof entry: {path}"
        raise AssertionError(message)
    proof["checksum_set_sha256"] = hashlib.sha256(
        canonical_export_json(
            tuple(
                _json_object(entry)
                for entry in entries
                if _json_object(entry)["path"] != "checksums.sha256"
            )
        )
    ).hexdigest()


def _mutated_export_envelope(envelope_bytes: bytes, mutate: EnvelopeMutation) -> bytes:
    value = _envelope_json(envelope_bytes)
    mutate(value)
    return canonical_export_json(value)


def _contract() -> DryLabRunContract:
    return DryLabRunContract.model_validate_json(FIXTURE.read_text(encoding="utf-8"))


def _proof_inputs() -> tuple[
    DryLabRunContract,
    ExportManifest,
    dict[str, tuple[str, bytes]],
]:
    contract = _contract()
    artifact_payloads = {
        entry.path: f"immutable artifact bytes: {entry.path}".encode("ascii")
        for entry in contract.export.artifact_entries
    }
    artifact_hashes = {
        path: hashlib.sha256(payload).hexdigest()
        for path, payload in artifact_payloads.items()
    }
    manifest = contract.export.model_copy(
        update={
            "artifact_entries": tuple(
                entry.model_copy(update={"sha256": artifact_hashes[entry.path]})
                for entry in contract.export.artifact_entries
            )
        }
    )
    versions = tuple(
        version.model_copy(
            update={
                "content_sha256": artifact_hashes[entry.path],
            }
        )
        if (
            entry := next(
                (
                    item
                    for item in manifest.artifact_entries
                    if item.artifact_version_id == version.id
                ),
                None,
            )
        )
        is not None
        else version
        for version in contract.artifact_versions
    )
    updated_contract = contract.model_copy(
        update={"export": manifest, "artifact_versions": versions}
    )
    manifest = updated_contract.export
    paths = (
        manifest.manifest_path,
        manifest.checksums_path,
        manifest.provenance_path,
        manifest.action_plan_path,
        manifest.review_path,
        *(entry.path for entry in manifest.artifact_entries),
    )
    artifact_media = {
        entry.path: entry.media_type for entry in manifest.artifact_entries
    }
    payloads = {
        path: (
            (
                artifact_media[path]
                if path in artifact_media
                else FIXED_EXPORT_MEMBER_MEDIA_TYPES[path]
            ),
            (
                canonical_export_manifest_payload(manifest)
                if path == manifest.manifest_path
                else artifact_payloads.get(path, path.encode("ascii"))
            ),
        )
        for path in paths
        if path != manifest.checksums_path
    }
    payloads.update(
        {
            manifest.provenance_path: (
                FIXED_EXPORT_MEMBER_MEDIA_TYPES[manifest.provenance_path],
                canonical_export_json(
                    updated_contract.provenance.model_dump(mode="json")
                ),
            ),
            manifest.action_plan_path: (
                FIXED_EXPORT_MEMBER_MEDIA_TYPES[manifest.action_plan_path],
                canonical_export_json(
                    updated_contract.action_plan.model_dump(mode="json")
                ),
            ),
            manifest.review_path: (
                FIXED_EXPORT_MEMBER_MEDIA_TYPES[manifest.review_path],
                canonical_export_json(updated_contract.review.model_dump(mode="json")),
            ),
        }
    )
    payloads[manifest.checksums_path] = (
        FIXED_EXPORT_MEMBER_MEDIA_TYPES[manifest.checksums_path],
        b"".join(
            f"{hashlib.sha256(payload).hexdigest()}  {path}\n".encode("ascii")
            for path, (_, payload) in sorted(payloads.items())
        ),
    )
    return updated_contract, manifest, payloads


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        ('"path":"artifacts/normalized.csv"', '"path":"../escape"'),
        ('"path":"artifacts/normalized.csv"', '"path":"/absolute.csv"'),
        ('"entry_kind":"file"', '"entry_kind":"symlink"'),
        ('"path":"artifacts/normalized.csv"', '"path":"manifest.json"'),
        ('"path":"artifacts/normalized.csv"', '"path":"manifest.json/evil"'),
        ('"path":"artifacts/normalized.csv"', '"path":"provenance"'),
        ('"path":"artifacts/normalized.csv"', '"path":"review"'),
        ('"path":"artifacts/normalized.csv"', '"path":"CON.txt"'),
        ('"path":"artifacts/normalized.csv"', '"path":"manifest.json."'),
        (
            '"path":"artifacts/figure.png"',
            '"path":"artifacts/normalized.csv/child"',
        ),
    ],
)
def test_rejects_unsafe_export_entries(needle: str, replacement: str) -> None:
    # Given: a valid export with one unsafe path or link mutation.
    contract = _contract()
    assert tuple(entry.path for entry in contract.export.artifact_entries) == tuple(
        sorted(entry.path for entry in contract.export.artifact_entries)
    )
    mutated = contract.export.model_dump_json().replace(needle, replacement, 1)

    # When/Then: the export boundary rejects the unsafe entry.
    with pytest.raises(ValidationError):
        _ = ExportManifest.model_validate_json(mutated)


def test_rejects_normalized_collision_and_unselected_latest_race() -> None:
    # Given: a selected manifest changed to collide or resolve an unselected Version.
    contract = _contract()
    raw_export = contract.export.model_dump_json()
    collision = raw_export.replace("artifacts/figure.png", "ARTIFACTS/normalized.csv")
    rogue_version_id = UUID("018f47a0-7b9c-7aff-8def-0123456789ab")
    unselected_export = contract.export.model_copy(
        update={
            "selected_artifact_version_ids": tuple(
                rogue_version_id if str(version_id) == VERSION_TWO else version_id
                for version_id in contract.export.selected_artifact_version_ids
            ),
            "artifact_entries": tuple(
                entry.model_copy(update={"artifact_version_id": rogue_version_id})
                if str(entry.artifact_version_id) == VERSION_TWO
                else entry
                for entry in contract.export.artifact_entries
            ),
        }
    )
    unselected = contract.model_copy(update={"export": unselected_export})
    unicode_collision = raw_export.replace(
        "artifacts/normalized.csv", "artifacts/Straße.csv"
    ).replace("artifacts/figure.png", "ARTIFACTS/STRASSE.CSV")

    # When/Then: all race-prone manifests fail before pack construction.
    with pytest.raises(ValidationError, match="normalization"):
        _ = ExportManifest.model_validate_json(collision)
    with pytest.raises(ValidationError, match="exported exactly once"):
        _ = DryLabRunContract.model_validate(unselected.model_dump(mode="python"))
    with pytest.raises(ValidationError):
        _ = ExportManifest.model_validate_json(unicode_collision)


def test_rejects_unreviewed_extra_export_and_aliased_required_output() -> None:
    # Given: Export includes an extra input, or two outputs alias one Version.
    contract = _contract()
    raw = contract.model_dump_json()
    selected_extra = f'"selected_artifact_version_ids":["{VERSION_ONE}",'
    extra_entry = (
        f'"artifact_entries":[{{"path":"artifacts/input.csv",'
        f'"artifact_version_id":"{VERSION_ONE}",'
        f'"sha256":"{"a" * 64}","media_type":"text/csv","entry_kind":"file"}},'
    )
    unreviewed = raw.replace(
        '"selected_artifact_version_ids":[', selected_extra, 1
    ).replace('"artifact_entries":[', extra_entry, 1)
    aliased = raw.replace(
        f'"ledger_csv_version_id":"{contract.outputs.ledger_csv_version_id}"',
        f'"ledger_csv_version_id":"{contract.outputs.normalized_csv_version_id}"',
        1,
    )

    # When/Then: only distinct reviewed output Versions may enter the Export.
    with pytest.raises(ValidationError, match="exactly the output versions"):
        _ = DryLabRunContract.model_validate_json(unreviewed)
    with pytest.raises(ValidationError, match="distinct"):
        _ = DryLabRunContract.model_validate_json(aliased)


def test_detached_export_proof_rejects_payload_and_metadata_tampering() -> None:
    contract, manifest, payloads = _proof_inputs()
    proof = build_detached_export_proof(manifest, payloads)
    envelope_bytes = serialize_export_envelope(
        build_export_envelope(manifest, payloads)
    )
    bytes_by_path: dict[str, bytes] = {
        path: payload for path, (_, payload) in payloads.items()
    }
    assert verify_detached_export_proof(manifest, proof, bytes_by_path)
    bound_contract = contract.model_copy(
        update={"export": manifest.model_copy(update={"detached_proof": proof})}
    )
    assert (
        final_export_integrity_errors(
            bound_contract,
            envelope_bytes,
            export_authority(bound_contract),
        )
        == ()
    )
    assert final_export_integrity_errors(bound_contract, envelope_bytes) == (
        "Export envelope does not bind selected immutable versions",
    )
    assert final_export_integrity_errors(
        bound_contract,
        envelope_bytes,
        export_authority(contract),
    ) == ("Export envelope does not bind selected immutable versions",)
    artifact_entry = next(
        entry for entry in proof.entries if entry.artifact_version_id is not None
    )
    substituted = proof.model_copy(
        update={
            "entries": tuple(
                entry.model_copy(update={"artifact_sha256": "0" * 64})
                if entry.path == artifact_entry.path
                else entry
                for entry in proof.entries
            )
        }
    )
    assert not verify_detached_export_proof(manifest, substituted, bytes_by_path)
    metadata_substituted = proof.model_copy(
        update={
            "entries": tuple(
                entry.model_copy(update={"media_type": "application/x-tampered"})
                if entry.path == artifact_entry.path
                else entry
                for entry in proof.entries
            )
        }
    )
    checksum_substituted = proof.model_copy(update={"checksum_set_sha256": "0" * 64})
    assert not verify_detached_export_proof(
        manifest, metadata_substituted, bytes_by_path
    )
    assert not verify_detached_export_proof(
        manifest, checksum_substituted, bytes_by_path
    )
    profile_substituted = proof.model_copy(update={"profile": "unbound-profile"})
    assert not verify_detached_export_proof(
        manifest, profile_substituted, bytes_by_path
    )
    assert not verify_detached_export_proof(
        manifest,
        proof,
        {
            **bytes_by_path,
            manifest.checksums_path: b"tampered checksum member\n",
        },
    )
    missing_payloads = {
        path: payload
        for path, payload in bytes_by_path.items()
        if path != manifest.review_path
    }
    assert not verify_detached_export_proof(manifest, proof, missing_payloads)
    assert (
        final_export_integrity_errors(
            bound_contract,
            envelope_bytes,
            export_authority(bound_contract),
        )
        == ()
    )
    repeated = build_detached_export_proof(manifest, payloads)
    assert repeated.entries == proof.entries
    assert repeated.checksum_set_sha256 == proof.checksum_set_sha256
    assert repeated.archive_sha256 == proof.archive_sha256
    substituted_payloads = {
        **bytes_by_path,
        manifest.review_path: b"tampered",
    }
    assert not verify_detached_export_proof(manifest, proof, substituted_payloads)
    with pytest.raises(ValueError, match="selected Artifact Version digest"):
        _ = build_detached_export_proof(
            manifest,
            {
                **payloads,
                artifact_entry.path: (
                    artifact_entry.media_type,
                    b"substituted artifact bytes",
                ),
            },
        )
    arbitrary_manifest_payloads = {
        **payloads,
        manifest.manifest_path: (
            "application/json",
            b"arbitrary manifest bytes",
        ),
    }
    with pytest.raises(ValueError, match="canonical manifest payload"):
        _ = build_detached_export_proof(manifest, arbitrary_manifest_payloads)
    noncanonical_manifest = canonical_export_manifest_payload(manifest).replace(
        b",", b", "
    )
    assert not verify_detached_export_proof(
        manifest,
        proof,
        {**bytes_by_path, manifest.manifest_path: noncanonical_manifest},
    )
    regenerated_entries = tuple(
        entry.model_copy(
            update={"sha256": hashlib.sha256(b"substituted artifact bytes").hexdigest()}
        )
        if entry.path == artifact_entry.path
        else entry
        for entry in proof.entries
    )
    regenerated_over_substitution = proof.model_copy(
        update={
            "entries": regenerated_entries,
            "checksum_set_sha256": export_checksum_set_sha256(regenerated_entries),
        }
    )
    assert not verify_detached_export_proof(
        manifest,
        regenerated_over_substitution,
        {
            **bytes_by_path,
            artifact_entry.path: b"substituted artifact bytes",
        },
    )
    assert (
        final_export_integrity_errors(
            bound_contract,
            envelope_bytes,
            export_authority(bound_contract),
        )
        == ()
    )
    reordered = proof.model_copy(update={"entries": tuple(reversed(proof.entries))})
    with pytest.raises(ValidationError, match="path ordered"):
        _ = reordered.__class__.model_validate(reordered.model_dump(mode="python"))
    with pytest.raises(ValidationError, match="canonically ordered"):
        _ = ExportManifest.model_validate(
            {
                **manifest.model_dump(mode="python"),
                "selected_artifact_version_ids": tuple(
                    reversed(manifest.selected_artifact_version_ids)
                ),
            }
        )


def test_final_export_requires_exact_contract_detached_proof() -> None:
    contract, manifest, payloads = _proof_inputs()
    proof = build_detached_export_proof(manifest, payloads)
    envelope_bytes = serialize_export_envelope(
        build_export_envelope(manifest, payloads)
    )
    unbound_manifest = ExportManifest.model_validate(
        {
            **manifest.model_dump(mode="python"),
            "detached_proof": proof.model_copy(
                update={"review_id": contract.review.run_id}
            ),
        }
    )
    unbound_contract = contract.model_copy(update={"export": unbound_manifest})
    assert final_export_integrity_errors(
        unbound_contract,
        envelope_bytes,
        export_authority(unbound_contract),
    ) == ("Export envelope does not bind selected immutable versions",)
    absent_contract = contract.model_copy(
        update={"export": manifest.model_copy(update={"detached_proof": None})}
    )
    assert final_export_integrity_errors(
        absent_contract,
        envelope_bytes,
        export_authority(absent_contract),
    ) == ("Export envelope does not bind selected immutable versions",)
    stale_contract = contract.model_copy(
        update={
            "export": manifest.model_copy(
                update={
                    "detached_proof": proof.model_copy(
                        update={"archive_sha256": "0" * 64}
                    )
                }
            )
        }
    )
    assert final_export_integrity_errors(
        stale_contract,
        envelope_bytes,
        export_authority(stale_contract),
    ) == ("Export envelope does not bind selected immutable versions",)
    recomputed_payloads = {
        **payloads,
        manifest.review_path: (
            FIXED_EXPORT_MEMBER_MEDIA_TYPES[manifest.review_path],
            b"recomputed review payload",
        ),
    }
    recomputed_payloads[manifest.checksums_path] = (
        FIXED_EXPORT_MEMBER_MEDIA_TYPES[manifest.checksums_path],
        b"".join(
            f"{hashlib.sha256(payload).hexdigest()}  {path}\n".encode("ascii")
            for path, (_, payload) in sorted(recomputed_payloads.items())
            if path != manifest.checksums_path
        ),
    )
    recomputed_substitute = build_detached_export_proof(manifest, recomputed_payloads)
    recomputed_contract = contract.model_copy(
        update={
            "export": manifest.model_copy(
                update={"detached_proof": recomputed_substitute}
            )
        }
    )
    assert final_export_integrity_errors(
        recomputed_contract,
        envelope_bytes,
        export_authority(recomputed_contract),
    ) == ("Export envelope does not bind selected immutable versions",)


def test_final_export_composes_review_and_correction_chain_validation() -> None:
    contract, manifest, payloads = _proof_inputs()
    proof = build_detached_export_proof(manifest, payloads)
    envelope_bytes = serialize_export_envelope(
        build_export_envelope(manifest, payloads)
    )
    bound_contract = contract.model_copy(
        update={"export": manifest.model_copy(update={"detached_proof": proof})}
    )
    incoherent = bound_contract.model_copy(
        update={
            "review": bound_contract.review.model_copy(
                update={"source_run_id": bound_contract.review.run_id}
            )
        }
    )

    assert final_export_integrity_errors(
        incoherent,
        envelope_bytes,
        export_authority(incoherent),
    ) == (
        "Review and Export must pin exactly the output versions",
        "Ledger, Review, and Export chain references do not match",
    )


def test_export_envelope_is_self_contained_and_rejects_archive_attacks() -> None:
    contract, manifest, payloads = _proof_inputs()
    envelope = build_export_envelope(manifest, payloads)
    envelope_bytes = serialize_export_envelope(envelope)
    del manifest, payloads

    # Structural verification needs no builder state; authorization uses a
    # separately sealed contract.
    assert verify_export_envelope(envelope_bytes)
    bound_contract = contract.model_copy(
        update={
            "export": contract.export.model_copy(
                update={"detached_proof": envelope.proof}
            )
        }
    )
    assert (
        final_export_integrity_errors(
            bound_contract,
            envelope_bytes,
            export_authority(bound_contract),
        )
        == ()
    )

    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _remove_member)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _increment_member_count)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _append_extra_member)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _reverse_members)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _alter_first_member)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _remove_proof)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(
            envelope_bytes, _source_run_id_mutation(str(contract.review.run_id))
        )
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _alter_proof_profile)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(
            envelope_bytes, _review_id_mutation(str(contract.review.run_id))
        )
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _reverse_selected_artifact_version_ids)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _alter_proof_manifest_sha256)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _alter_proof_checksum_set_sha256)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _alter_proof_archive_sha256)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _alter_checksums_member)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(envelope_bytes, _alter_manifest_member)
    )
    assert not verify_export_envelope(
        _mutated_export_envelope(
            envelope_bytes, _coherently_rehash_fixed_member_media_type
        )
    )
