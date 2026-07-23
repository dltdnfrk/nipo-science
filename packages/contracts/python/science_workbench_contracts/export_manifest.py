from __future__ import annotations

import base64
import hashlib
import json
import re
import unicodedata
from typing import (
    TYPE_CHECKING,
    Annotated,
    Literal,
    LiteralString,
    Never,
    Self,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

from pydantic import AfterValidator, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from .common import NonEmptyText, Sha256, UtcTimestamp, Uuid7
from .task6_common import Task6ContractModel

RESERVED_EXPORT_ROOTS = frozenset(
    {
        "manifest.json",
        "checksums.sha256",
        "provenance",
        "review",
    }
)
WINDOWS_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
FIXED_EXPORT_MEMBER_MEDIA_TYPES = {
    "manifest.json": "application/json",
    "checksums.sha256": "text/plain",
    "provenance/manifest.json": "application/json",
    "provenance/action-plan.json": "application/json",
    "review/review.json": "application/json",
}


def _raise_export_error(code: LiteralString, message: LiteralString) -> Never:
    raise PydanticCustomError(code, message)


def _safe_export_path(path: str) -> str:
    segments = path.split("/")
    is_drive_path = re.match(r"^[A-Za-z]:", path) is not None
    is_safe = (
        path.isascii()
        and re.fullmatch(r"[A-Za-z0-9._/-]+", path) is not None
        and not path.startswith(("/", "\\"))
        and not is_drive_path
        and "\\" not in path
        and all(segment not in {"", ".", ".."} for segment in segments)
        and all(not segment.endswith(".") for segment in segments)
        and all(
            segment.split(".", 1)[0].casefold() not in WINDOWS_DEVICE_NAMES
            for segment in segments
        )
    )
    if not is_safe:
        _raise_export_error(
            "unsafe_export_path",
            "export path must be a safe relative POSIX path",
        )
    return path


SafeExportPath = Annotated[NonEmptyText, AfterValidator(_safe_export_path)]


class ExportArtifactEntry(Task6ContractModel):
    path: SafeExportPath
    artifact_version_id: Uuid7
    sha256: Sha256
    media_type: NonEmptyText
    entry_kind: Literal["file"]


class ExportPayloadEntry(Task6ContractModel):
    path: SafeExportPath
    media_type: NonEmptyText
    size_bytes: Annotated[int, Field(ge=0)]
    sha256: Sha256
    artifact_version_id: Uuid7 | None = None
    artifact_sha256: Sha256 | None = None


class DetachedExportProof(Task6ContractModel):
    profile: Literal["science-workbench-export-v1"]
    source_run_id: Uuid7
    review_id: Uuid7
    selected_artifact_version_ids: tuple[Uuid7, ...]
    entries: Annotated[tuple[ExportPayloadEntry, ...], Field(min_length=1)]
    checksum_set_sha256: Sha256
    manifest_sha256: Sha256
    archive_sha256: Sha256

    @model_validator(mode="after")
    def validate_canonical_proof(self) -> Self:
        paths = tuple(entry.path for entry in self.entries)
        if paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
            _raise_export_error(
                "export_proof_ordering",
                "export proof entries must be unique and canonically path ordered",
            )
        if self.selected_artifact_version_ids != tuple(
            sorted(self.selected_artifact_version_ids)
        ) or len(set(self.selected_artifact_version_ids)) != len(
            self.selected_artifact_version_ids
        ):
            _raise_export_error(
                "export_proof_selection",
                (
                    "export proof selected version IDs must be unique and "
                    "canonically ordered"
                ),
            )
        artifact_ids = tuple(
            entry.artifact_version_id
            for entry in self.entries
            if entry.artifact_version_id is not None
        )
        if (
            len(artifact_ids) != len(set(artifact_ids))
            or set(artifact_ids) != set(self.selected_artifact_version_ids)
            or any(
                (entry.artifact_version_id is None) != (entry.artifact_sha256 is None)
                for entry in self.entries
            )
        ):
            _raise_export_error(
                "export_proof_bijection",
                "export proof entries must bind every selected version exactly once",
            )
        if self.checksum_set_sha256 != export_checksum_set_sha256(self.entries):
            _raise_export_error(
                "export_checksum_set_digest",
                "detached export checksum-set digest mismatch",
            )
        return self


class ExportEnvelopeMember(Task6ContractModel):
    path: SafeExportPath
    media_type: NonEmptyText
    payload_base64: str

    @field_validator("payload_base64")
    @classmethod
    def validate_canonical_payload_base64(cls, value: str) -> str:
        try:
            payload = base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError):
            _raise_export_error(
                "export_envelope_payload_encoding",
                "envelope payload must be canonical base64",
            )
        if base64.b64encode(payload).decode("ascii") != value:
            _raise_export_error(
                "export_envelope_payload_encoding",
                "envelope payload must be canonical base64",
            )
        return value

    def payload_bytes(self) -> bytes:
        return base64.b64decode(self.payload_base64.encode("ascii"), validate=True)


class ExportEnvelope(Task6ContractModel):
    media_type: Literal[
        "application/vnd.science-workbench.export-envelope+json;version=1"
    ]
    version: Literal["science-workbench-export-envelope-v1"]
    member_count: Annotated[int, Field(ge=1)]
    proof: DetachedExportProof
    members: Annotated[tuple[ExportEnvelopeMember, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_canonical_members(self) -> Self:
        paths = tuple(member.path for member in self.members)
        proof_paths = tuple(entry.path for entry in self.proof.entries)
        if (
            paths != tuple(sorted(paths))
            or len(set(paths)) != len(paths)
            or self.member_count != len(self.members)
            or paths != proof_paths
            or len(self.members) != len(self.proof.entries)
        ):
            _raise_export_error(
                "export_envelope_members",
                "envelope members must exactly match the canonical proof member set",
            )
        proof_entries = {entry.path: entry for entry in self.proof.entries}
        if any(
            member.media_type != proof_entries[member.path].media_type
            for member in self.members
        ):
            _raise_export_error(
                "export_envelope_metadata",
                "envelope member media type must match the proof",
            )
        if any(
            proof_entries.get(path) is None
            or proof_entries[path].media_type != expected_media_type
            for path, expected_media_type in FIXED_EXPORT_MEMBER_MEDIA_TYPES.items()
        ):
            _raise_export_error(
                "export_envelope_fixed_member_metadata",
                "envelope fixed member media types must be authoritative",
            )
        return self


def canonical_export_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def export_checksum_set_sha256(entries: tuple[ExportPayloadEntry, ...]) -> str:
    """Hash the non-recursive member root described by checksums.sha256."""
    return hashlib.sha256(
        canonical_export_json(
            tuple(
                entry.model_dump(mode="json")
                for entry in entries
                if entry.path != "checksums.sha256"
            )
        )
    ).hexdigest()


def _checksums_payload(entries: tuple[ExportPayloadEntry, ...]) -> bytes:
    return b"".join(
        f"{entry.sha256}  {entry.path}\n".encode("ascii")
        for entry in entries
        if entry.path != "checksums.sha256"
    )


def _archive_digest(
    entries: tuple[ExportPayloadEntry, ...],
    payloads: Mapping[str, bytes],
) -> str:
    """Hash every archive member, including the non-recursive checksum member."""
    digest = hashlib.sha256()
    for entry in entries:
        path = entry.path.encode("utf-8")
        payload = payloads[entry.path]
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def canonical_export_manifest_payload(manifest: ExportManifest) -> bytes:
    """Return the canonical, non-self-referential manifest.json representation."""
    return canonical_export_json(
        manifest.model_dump(mode="json", exclude={"detached_proof"})
    )


def build_detached_export_proof(
    manifest: ExportManifest,
    payloads: Mapping[str, tuple[str, bytes]],
) -> DetachedExportProof:
    try:
        manifest = ExportManifest.model_validate(manifest.model_dump(mode="python"))
    except ValueError:
        _raise_export_error(
            "invalid_export_manifest",
            "export manifest must satisfy its canonical invariants",
        )
    required_paths = {
        manifest.manifest_path,
        manifest.checksums_path,
        manifest.provenance_path,
        manifest.action_plan_path,
        manifest.review_path,
        *(entry.path for entry in manifest.artifact_entries),
    }
    if set(payloads) != required_paths:
        _raise_export_error(
            "export_payload_set",
            "export payloads must contain exactly every manifest path",
        )
    artifact_entries = {entry.path: entry for entry in manifest.artifact_entries}
    if any(
        media_type != artifact_entries[path].media_type
        for path, (media_type, _) in payloads.items()
        if path in artifact_entries
    ):
        _raise_export_error(
            "export_payload_metadata",
            "artifact payload media type must match its manifest entry",
        )
    if any(
        media_type != FIXED_EXPORT_MEMBER_MEDIA_TYPES[path]
        for path, (media_type, _) in payloads.items()
        if path in FIXED_EXPORT_MEMBER_MEDIA_TYPES
    ):
        _raise_export_error(
            "export_payload_metadata",
            "fixed export payload media type must be authoritative",
        )
    if any(
        hashlib.sha256(payload).hexdigest() != artifact_entries[path].sha256
        for path, (_, payload) in payloads.items()
        if path in artifact_entries
    ):
        _raise_export_error(
            "export_artifact_payload_digest",
            "artifact payload bytes must match the selected Artifact Version digest",
        )
    entries = tuple(
        ExportPayloadEntry(
            path=path,
            media_type=media_type,
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            artifact_version_id=(
                None
                if path not in artifact_entries
                else artifact_entries[path].artifact_version_id
            ),
            artifact_sha256=(
                None if path not in artifact_entries else artifact_entries[path].sha256
            ),
        )
        for path, (media_type, payload) in sorted(payloads.items())
    )
    byte_payloads = {path: payload for path, (_, payload) in payloads.items()}
    if byte_payloads[manifest.manifest_path] != canonical_export_manifest_payload(
        manifest
    ):
        _raise_export_error(
            "export_manifest_payload",
            "manifest.json bytes must equal the canonical manifest payload",
        )
    if byte_payloads[manifest.checksums_path] != _checksums_payload(entries):
        _raise_export_error(
            "export_checksums_payload",
            "checksums.sha256 bytes must canonically describe every payload",
        )
    return DetachedExportProof(
        profile="science-workbench-export-v1",
        source_run_id=manifest.source_run_id,
        review_id=manifest.review_id,
        selected_artifact_version_ids=manifest.selected_artifact_version_ids,
        entries=entries,
        checksum_set_sha256=export_checksum_set_sha256(entries),
        manifest_sha256=hashlib.sha256(
            byte_payloads[manifest.manifest_path]
        ).hexdigest(),
        archive_sha256=_archive_digest(entries, byte_payloads),
    )


def verify_detached_export_proof(
    manifest: ExportManifest,
    proof: DetachedExportProof,
    payloads: Mapping[str, bytes],
) -> bool:
    proof_payload = proof.model_dump(mode="python", warnings=False)
    if proof_payload.get("profile") != "science-workbench-export-v1":
        return False
    try:
        manifest = ExportManifest.model_validate(manifest.model_dump(mode="python"))
        proof = DetachedExportProof.model_validate(proof_payload)
    except ValueError:
        return False
    required_paths = {
        manifest.manifest_path,
        manifest.checksums_path,
        manifest.provenance_path,
        manifest.action_plan_path,
        manifest.review_path,
        *(entry.path for entry in manifest.artifact_entries),
    }
    proof_paths = tuple(entry.path for entry in proof.entries)
    entries = {entry.path: entry for entry in proof.entries}
    payload_paths_match = set(payloads) == required_paths
    proof_paths_match = (
        proof_paths == tuple(sorted(required_paths)) and set(entries) == required_paths
    )
    payload_metadata_matches = (
        payload_paths_match
        and proof_paths_match
        and all(
            entry.size_bytes == len(payloads[path])
            and entry.sha256 == hashlib.sha256(payloads[path]).hexdigest()
            for path, entry in entries.items()
        )
    )
    artifact_entries = {entry.path: entry for entry in manifest.artifact_entries}
    proof_artifact_entries = tuple(
        entry for entry in proof.entries if entry.artifact_version_id is not None
    )
    artifact_bindings_match = (
        len(proof_artifact_entries) == len(manifest.artifact_entries)
        and {entry.artifact_version_id for entry in proof_artifact_entries}
        == set(manifest.selected_artifact_version_ids)
        and all(
            entry.artifact_version_id == artifact_entries[path].artifact_version_id
            and entry.artifact_sha256 == artifact_entries[path].sha256
            and entry.sha256 == artifact_entries[path].sha256
            and entry.media_type == artifact_entries[path].media_type
            for path, entry in entries.items()
            if path in artifact_entries
        )
        and all(
            entry.artifact_version_id is None and entry.artifact_sha256 is None
            for path, entry in entries.items()
            if path not in artifact_entries
        )
    )
    fixed_member_metadata_matches = proof_paths_match and all(
        entries[path].media_type == expected_media_type
        for path, expected_media_type in FIXED_EXPORT_MEMBER_MEDIA_TYPES.items()
    )
    manifest_payload_matches = payload_paths_match and payloads[
        manifest.manifest_path
    ] == canonical_export_manifest_payload(manifest)
    canonical_metadata_matches = (
        payload_paths_match
        and payloads[manifest.checksums_path] == _checksums_payload(proof.entries)
        and proof.checksum_set_sha256 == export_checksum_set_sha256(proof.entries)
        and proof.manifest_sha256
        == hashlib.sha256(payloads[manifest.manifest_path]).hexdigest()
        and proof.archive_sha256 == _archive_digest(proof.entries, payloads)
    )
    return (
        proof.source_run_id == manifest.source_run_id
        and proof.review_id == manifest.review_id
        and proof.selected_artifact_version_ids
        == manifest.selected_artifact_version_ids
        and payload_metadata_matches
        and artifact_bindings_match
        and manifest_payload_matches
        and fixed_member_metadata_matches
        and canonical_metadata_matches
    )


def build_export_envelope(
    manifest: ExportManifest,
    payloads: Mapping[str, tuple[str, bytes]],
) -> ExportEnvelope:
    """Build the self-contained outer envelope around an exact inner archive."""
    proof = build_detached_export_proof(manifest, payloads)
    return ExportEnvelope(
        media_type="application/vnd.science-workbench.export-envelope+json;version=1",
        version="science-workbench-export-envelope-v1",
        member_count=len(payloads),
        proof=proof,
        members=tuple(
            ExportEnvelopeMember(
                path=path,
                media_type=media_type,
                payload_base64=base64.b64encode(payload).decode("ascii"),
            )
            for path, (media_type, payload) in sorted(payloads.items())
        ),
    )


def serialize_export_envelope(envelope: ExportEnvelope) -> bytes:
    """Serialize an envelope into its sole canonical wire representation."""
    validated = ExportEnvelope.model_validate(envelope.model_dump(mode="python"))
    return canonical_export_json(validated.model_dump(mode="json"))


def parse_export_envelope(envelope_bytes: object) -> ExportEnvelope:
    """Strictly parse only a canonical export envelope byte sequence."""
    if not isinstance(envelope_bytes, bytes):
        message = "export envelope must be bytes"
        raise TypeError(message)
    try:
        envelope = ExportEnvelope.model_validate_json(envelope_bytes)
    except ValueError:
        _raise_export_error("invalid_export_envelope", "invalid export envelope")
    if serialize_export_envelope(envelope) != envelope_bytes:
        _raise_export_error(
            "noncanonical_export_envelope",
            "export envelope must use canonical serialization",
        )
    return envelope


def verify_export_envelope(envelope_bytes: bytes) -> bool:
    """Verify structural self-integrity; authorization requires a sealed contract."""
    try:
        envelope = parse_export_envelope(envelope_bytes)
        payloads = {member.path: member.payload_bytes() for member in envelope.members}
        manifest_payload = payloads.get("manifest.json")
        if manifest_payload is None:
            return False
        manifest = ExportManifest.model_validate_json(manifest_payload)
        if manifest_payload != canonical_export_manifest_payload(manifest):
            return False
        return verify_detached_export_proof(manifest, envelope.proof, payloads)
    except (TypeError, ValueError):
        return False


class ExportManifest(Task6ContractModel):
    id: Uuid7
    source_run_id: Uuid7
    review_id: Uuid7
    research_intent_sha256: Sha256
    selected_artifact_version_ids: Annotated[tuple[Uuid7, ...], Field(min_length=1)]
    artifact_entries: Annotated[tuple[ExportArtifactEntry, ...], Field(min_length=1)]
    manifest_path: Literal["manifest.json"]
    checksums_path: Literal["checksums.sha256"]
    provenance_path: Literal["provenance/manifest.json"]
    action_plan_path: Literal["provenance/action-plan.json"]
    review_path: Literal["review/review.json"]
    detached_proof: DetachedExportProof | None = None
    created_at: UtcTimestamp

    @model_validator(mode="after")
    def validate_pinned_paths(self) -> Self:
        selected = set(self.selected_artifact_version_ids)
        entry_versions = {entry.artifact_version_id for entry in self.artifact_entries}
        if (
            self.selected_artifact_version_ids
            != tuple(sorted(self.selected_artifact_version_ids))
            or len(selected) != len(self.selected_artifact_version_ids)
            or len(entry_versions) != len(self.artifact_entries)
            or entry_versions != selected
        ):
            _raise_export_error(
                "export_version_selection",
                (
                    "selected version IDs must be unique, canonically ordered, "
                    "and exported exactly once"
                ),
            )
        canonical_entries = tuple(
            sorted(self.artifact_entries, key=lambda entry: entry.path)
        )
        canonical_manifest = (
            self
            if self.artifact_entries == canonical_entries
            else self.model_copy(update={"artifact_entries": canonical_entries})
        )
        normalized_paths = tuple(
            unicodedata.normalize("NFKC", entry.path).casefold()
            for entry in canonical_manifest.artifact_entries
        )
        reserved_roots = {
            unicodedata.normalize("NFKC", path).casefold()
            for path in RESERVED_EXPORT_ROOTS
        }
        if any(
            path == root or path.startswith(f"{root}/")
            for path in normalized_paths
            for root in reserved_roots
        ):
            _raise_export_error(
                "reserved_export_path",
                "artifact entry collides with a reserved pack path",
            )
        if len(set(normalized_paths)) != len(normalized_paths):
            _raise_export_error(
                "export_path_collision",
                "export paths collide after normalization",
            )
        if any(
            other.startswith(f"{path}/")
            for path in normalized_paths
            for other in normalized_paths
            if path != other
        ):
            _raise_export_error(
                "export_prefix_collision",
                "export file and directory paths collide",
            )
        return canonical_manifest
