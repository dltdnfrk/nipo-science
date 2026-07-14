"""Capture raw GKE collector output into detached-signature deployment evidence."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import os
import signal
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

COLLECTOR_COMMAND: Final = "/opt/science-workbench/bin/gke-evidence-collector-v1"
COLLECTOR_ARGV: Final = (COLLECTOR_COMMAND, "--format=canonical-v2")
COLLECTOR_TIMEOUT_COMMAND: Final = (
    "/opt/science-workbench/bin/gke-evidence-collector-v1 --format=canonical-v2"
)
COLLECTOR_TIMEOUT_SECONDS: Final = 30
_COLLECTOR_ENV: Final = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
EXPECTED_RECEIPT_KEYS: Final = (
    "project_id",
    "cluster_name",
    "location",
    "cluster_uid",
    "environment",
    "run_id",
    "nonce",
    "captured_at_utc",
    "collector_id",
    "collector_version",
    "workload_graph_sha256",
    "deployed_manifest_sha256",
    "deployed_image_sha256",
    "deployed_environment_sha256",
    "deployed_control_sha256",
    "corpus_sha256",
    "input_sha256",
    "watcher_registration_id",
    "watcher_receipt_sha256",
    "scientific_output_checksum_set_sha256",
    "release-attestation-key-id",
    "release-attestation-signature",
)
EXPECTED_COLLECTOR_ID: Final = "collector"
EXPECTED_COLLECTOR_VERSION: Final = "v1"
ATTESTATION_KEY_ID: Final = "release-attestation-key-id"
ATTESTATION_SIGNATURE: Final = "release-attestation-signature"
RESOURCE_FIELD_COUNT: Final = 8
PROBE_FIELD_COUNT: Final = 10
SHA256_LENGTH: Final = 64
SUCCESS_EXIT_CODE: Final = 0
VERIFY_COMMAND: Final = "/usr/bin/ssh-keygen"
ALLOWED_SIGNERS_PATH: Final = "/etc/science-workbench/gke-allowed-signers"
VERIFY_NAMESPACE: Final = "science-workbench-gke-capture"
VERIFY_PRINCIPAL: Final = "gke-evidence-collector"
VERIFY_TIMEOUT_SECONDS: Final = 5
EXPECTED_VERIFIER_KEY_ID: Final = "release-key"
MAX_ALLOWED_SIGNERS_BYTES: Final = 1_048_576
ALLOWED_SIGNER_POLICY_FIELD_COUNT: Final = 4
CANONICAL_ATTESTATION_PAYLOAD_TYPE_ERROR: Final = (
    "attestation payload requires a CaptureProof"
)
_CANONICAL_OUTPUT_SECTION_COUNT: Final = 2
_RESOURCE_SECTION: Final = b"\n---RESOURCES---\n"
_PROBE_SECTION: Final = b"\n---PROBES---\n"
type _CAPTURE_ERROR_TYPE = ValueError
_UNSAFE_PATH_ERROR: Final = "fixed collector path is unsafe or unsupported"
_COLLECTOR_START_ERROR: Final = "collector command could not be started"
_COLLECTOR_EXIT_ERROR: Final = "collector command did not exit successfully"
_COLLECTOR_TIMEOUT_ERROR: Final = (
    f"collector command timed out: {COLLECTOR_TIMEOUT_COMMAND}"
)
_OWNER_WRITE_OR_GROUP_WRITE: Final = 0o022
_EXECUTE_BITS: Final = 0o111
_ROOT_DIRECTORY: Final = "/"
_CANONICAL_UTC_SUFFIX: Final = "Z"


@dataclass(frozen=True, slots=True)
class CapturedResource:
    """A collector-recorded Kubernetes resource."""

    stable_id: str
    kind: str
    name: str
    uid: str
    generation: int
    spec: str
    status: str
    workload_graph_sha256: str
    source_sha256: str


@dataclass(frozen=True, slots=True)
class CapturedProbe:
    """A collector-recorded control-denial probe."""

    vector: str
    attempted_at_utc: datetime
    executor: str
    target_sha256: str
    test_vector_sha256: str
    transport: str
    result_code: str
    duration_ms: int
    policy_reason: str
    outcome: str
    raw_sha256: str


@dataclass(frozen=True, slots=True)
class CaptureProof:
    """A detached-signature capture receipt."""

    project_id: str
    cluster_name: str
    location: str
    cluster_uid: str
    environment: str
    run_id: str
    nonce: str
    captured_at_utc: datetime
    collector_id: str
    collector_version: str
    workload_graph_sha256: str
    raw_inventory_sha256: str
    raw_probe_sha256: str
    deployed_manifest_sha256: str
    deployed_image_sha256: str
    deployed_environment_sha256: str
    deployed_control_sha256: str
    corpus_sha256: str
    input_sha256: str
    watcher_registration_id: str
    watcher_receipt_sha256: str
    scientific_output_checksum_set_sha256: str
    normalized_evidence_sha256: str
    resource_records_sha256: str
    probe_records_sha256: str
    verifier_key_id: str
    attestation: str


@dataclass(frozen=True, slots=True)
class LiveCapture:
    """The parsed output of one fixed collector invocation."""

    proof: CaptureProof
    resources: tuple[CapturedResource, ...]
    probes: tuple[CapturedProbe, ...]


@dataclass(frozen=True, slots=True)
class WorkloadIdentity:
    """Identity and immutable workload inputs bound by the workload graph."""

    project_id: str
    cluster_name: str
    location: str
    cluster_uid: str
    environment: str
    run_id: str
    manifest_sha256: str
    image_sha256: str


def workload_graph_sha256(identity: WorkloadIdentity) -> str:
    """Return the identity graph to which every live control must bind."""
    return _field_digest(
        (
            identity.project_id,
            identity.cluster_name,
            identity.location,
            identity.cluster_uid,
            identity.environment,
            identity.run_id,
            identity.manifest_sha256,
            identity.image_sha256,
        )
    )


def capture_live_gke() -> LiveCapture:
    """Capture and parse evidence from the fixed GKE collector."""
    raw = asyncio.run(_collect_canonical_output())
    metadata_bytes, resource_bytes, probe_bytes = _split_canonical_output(raw)
    metadata = _parse_metadata(metadata_bytes)
    graph = workload_graph_sha256(
        WorkloadIdentity(
            metadata["project_id"],
            metadata["cluster_name"],
            metadata["location"],
            metadata["cluster_uid"],
            metadata["environment"],
            metadata["run_id"],
            metadata["deployed_manifest_sha256"],
            metadata["deployed_image_sha256"],
        )
    )
    if metadata["workload_graph_sha256"] != graph:
        msg = "collector workload graph does not bind capture identity"
        raise _capture_error(msg)
    resources = _parse_resources(resource_bytes)
    probes = _parse_probes(probe_bytes)
    proof = CaptureProof(
        project_id=metadata["project_id"],
        cluster_name=metadata["cluster_name"],
        location=metadata["location"],
        cluster_uid=metadata["cluster_uid"],
        environment=metadata["environment"],
        run_id=metadata["run_id"],
        nonce=metadata["nonce"],
        captured_at_utc=_parse_utc(metadata["captured_at_utc"]),
        collector_id=metadata["collector_id"],
        collector_version=metadata["collector_version"],
        workload_graph_sha256=graph,
        raw_inventory_sha256=_digest(resource_bytes),
        raw_probe_sha256=_digest(probe_bytes),
        deployed_manifest_sha256=metadata["deployed_manifest_sha256"],
        deployed_image_sha256=metadata["deployed_image_sha256"],
        deployed_environment_sha256=metadata["deployed_environment_sha256"],
        deployed_control_sha256=metadata["deployed_control_sha256"],
        corpus_sha256=metadata["corpus_sha256"],
        input_sha256=metadata["input_sha256"],
        watcher_registration_id=metadata["watcher_registration_id"],
        watcher_receipt_sha256=metadata["watcher_receipt_sha256"],
        scientific_output_checksum_set_sha256=metadata[
            "scientific_output_checksum_set_sha256"
        ],
        normalized_evidence_sha256=_normalized_evidence_digest(
            metadata_bytes, resource_bytes, probe_bytes
        ),
        resource_records_sha256=_resource_record_digest(resources),
        probe_records_sha256=_probe_record_digest(probes),
        verifier_key_id=_verified_key_id(metadata[ATTESTATION_KEY_ID]),
        attestation=metadata[ATTESTATION_SIGNATURE],
    )
    return LiveCapture(proof, resources, probes)


def is_durably_verified(proof: CaptureProof) -> bool:
    """Return whether a proof has a trusted durable detached signature."""
    if not _proof_structure_valid(proof):
        return False
    try:
        _ = asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        return False
    try:
        signature = base64.b64decode(proof.attestation, validate=True)
    except (ValueError, UnicodeEncodeError):
        return False
    if not signature:
        return False
    try:
        return asyncio.run(
            verify_detached_signature(
                canonical_attestation_payload(proof),
                signature,
                proof.verifier_key_id,
            )
        )
    except (OSError, TypeError, ValueError):
        return False


def _proof_structure_valid(proof: object) -> bool:
    """Reject malformed reconstructed objects before invoking the verifier."""
    if (
        type(proof) is not CaptureProof
        or type(proof.captured_at_utc) is not datetime
        or proof.captured_at_utc.tzinfo is not UTC
    ):
        return False
    if (
        proof.collector_id != EXPECTED_COLLECTOR_ID
        or proof.collector_version != EXPECTED_COLLECTOR_VERSION
        or proof.verifier_key_id != EXPECTED_VERIFIER_KEY_ID
    ):
        return False
    return all(
        type(value) is str
        for value in (
            proof.project_id,
            proof.cluster_name,
            proof.location,
            proof.cluster_uid,
            proof.environment,
            proof.run_id,
            proof.nonce,
            proof.collector_id,
            proof.collector_version,
            proof.workload_graph_sha256,
            proof.raw_inventory_sha256,
            proof.raw_probe_sha256,
            proof.deployed_manifest_sha256,
            proof.deployed_image_sha256,
            proof.deployed_environment_sha256,
            proof.deployed_control_sha256,
            proof.corpus_sha256,
            proof.input_sha256,
            proof.watcher_registration_id,
            proof.watcher_receipt_sha256,
            proof.scientific_output_checksum_set_sha256,
            proof.normalized_evidence_sha256,
            proof.resource_records_sha256,
            proof.probe_records_sha256,
            proof.verifier_key_id,
            proof.attestation,
        )
    )


def _safe_path(path: str, *, executable: bool) -> int | None:
    """Open a root-owned regular file after checking every ancestor without links."""
    resolved_path = Path(path)
    if not resolved_path.is_absolute():
        return None
    directory = os.open(_ROOT_DIRECTORY, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        parts = resolved_path.parts[1:]
        if not (_safe_directory(os.fstat(directory)) and parts):
            return None
        for part in parts[:-1]:
            next_directory = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
            if not _safe_directory(os.fstat(directory)):
                return None
        before = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if not _safe_regular_file(before, executable=executable):
            return None
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        same_file = _same_file(before, os.fstat(descriptor))
    except OSError:
        return None
    else:
        if not same_file:
            os.close(descriptor)
        return descriptor if same_file else None
    finally:
        os.close(directory)


def _safe_directory(metadata: os.stat_result) -> bool:
    """Return whether an ancestor directory is root-owned and non-writable."""
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == 0
        and not metadata.st_mode & _OWNER_WRITE_OR_GROUP_WRITE
    )


def _safe_regular_file(metadata: os.stat_result, *, executable: bool) -> bool:
    """Return whether a leaf is a trusted regular file with required mode bits."""
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and not metadata.st_mode & _OWNER_WRITE_OR_GROUP_WRITE
        and (not executable or bool(metadata.st_mode & _EXECUTE_BITS))
    )


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    """Return whether a path stat and descriptor describe one unchanged file."""
    return (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        stat.S_IMODE(before.st_mode),
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        stat.S_IMODE(after.st_mode),
    )


def open_trusted_path(path: str, *, executable: bool) -> int | None:
    """Open a fixed policy path only after root-owned no-follow validation."""
    return _safe_path(path, executable=executable)


def _descriptor_backed_path(descriptor: int) -> str | None:
    """Return a child-visible descriptor path on supported GKE/Linux hosts."""
    if not sys.platform.startswith("linux") or not Path("/proc/self/fd").is_dir():
        return None
    return f"/proc/self/fd/{descriptor}"


def _trusted_executable(descriptor: int) -> str | None:
    """Return a descriptor-backed executable path, or fail closed."""
    return _descriptor_backed_path(descriptor)


@dataclass(frozen=True, slots=True)
class _VerifierDescriptors:
    verifier: int
    signers: int
    signature: int
    executable: str
    signers_path: str
    signature_path: str


def _close_descriptor(descriptor: int | None) -> None:
    if descriptor is not None:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def allowed_signers_policy_matches_key_id(
    descriptor: int,
    expected_key_id: str,
) -> bool:
    """Bind the expected key label to exactly one retained Ed25519 public key."""
    size = os.fstat(descriptor).st_size
    if not 0 < size <= MAX_ALLOWED_SIGNERS_BYTES:
        return False
    try:
        policy = os.pread(descriptor, size + 1, 0).decode("ascii")
    except (OSError, UnicodeDecodeError):
        return False
    lines = tuple(line.strip() for line in policy.splitlines() if line.strip())
    if len(lines) != 1:
        return False
    fields = lines[0].split()
    if (
        len(fields) != ALLOWED_SIGNER_POLICY_FIELD_COUNT
        or fields[0] != VERIFY_PRINCIPAL
        or fields[1] != "ssh-ed25519"
        or fields[3] != expected_key_id
    ):
        return False
    try:
        public_key = base64.b64decode(fields[2], validate=True)
    except ValueError:
        return False
    return bool(public_key)


def _prepare_verifier_descriptors(
    signature: bytes,
    expected_key_id: str,
) -> _VerifierDescriptors | None:
    """Open and retain every descriptor required by the signature verifier."""
    verifier = open_trusted_path(VERIFY_COMMAND, executable=True)
    signers: int | None = None
    signature_descriptor: int | None = None
    prepared: _VerifierDescriptors | None = None
    try:
        if verifier is not None:
            executable = _descriptor_backed_path(verifier)
            signers = open_trusted_path(ALLOWED_SIGNERS_PATH, executable=False)
            if (
                executable is not None
                and signers is not None
                and allowed_signers_policy_matches_key_id(
                    signers,
                    expected_key_id,
                )
            ):
                signers_path = _descriptor_backed_path(signers)
                if signers_path is not None:
                    signature_descriptor, snapshot_path = tempfile.mkstemp(
                        prefix="gke-capture-", suffix=".sig"
                    )
                    _ = os.write(signature_descriptor, signature)
                    _ = os.lseek(signature_descriptor, 0, os.SEEK_SET)
                    Path(snapshot_path).unlink()
                    signature_path = _descriptor_backed_path(signature_descriptor)
                    if signature_path is not None:
                        prepared = _VerifierDescriptors(
                            verifier,
                            signers,
                            signature_descriptor,
                            executable,
                            signers_path,
                            signature_path,
                        )
    except OSError:
        pass
    finally:
        if prepared is None:
            _close_descriptor(signature_descriptor)
            _close_descriptor(signers)
            _close_descriptor(verifier)
    return prepared


def _close_verifier_descriptors(descriptors: _VerifierDescriptors) -> None:
    """Close descriptors retained for one verifier process."""
    _close_descriptor(descriptors.signature)
    _close_descriptor(descriptors.signers)
    _close_descriptor(descriptors.verifier)


async def verify_detached_signature(
    message: bytes,
    signature: bytes,
    expected_key_id: str = EXPECTED_VERIFIER_KEY_ID,
) -> bool:
    """Verify one detached signature through retained trusted descriptors."""
    descriptors = _prepare_verifier_descriptors(signature, expected_key_id)
    if descriptors is None:
        return False
    try:
        process = await asyncio.create_subprocess_exec(
            VERIFY_COMMAND,
            "-Y",
            "verify",
            "-f",
            descriptors.signers_path,
            "-I",
            VERIFY_PRINCIPAL,
            "-n",
            VERIFY_NAMESPACE,
            "-s",
            descriptors.signature_path,
            executable=descriptors.executable,
            pass_fds=(
                descriptors.verifier,
                descriptors.signers,
                descriptors.signature,
            ),
            env=_COLLECTOR_ENV,
            stdin=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        try:
            _ = await asyncio.wait_for(
                process.communicate(message), timeout=VERIFY_TIMEOUT_SECONDS
            )
        except TimeoutError:
            process.kill()
            _ = await process.communicate()
            return False
        else:
            return process.returncode == SUCCESS_EXIT_CODE
    except OSError:
        return False
    finally:
        _close_verifier_descriptors(descriptors)


def canonical_attestation_payload(proof: CaptureProof) -> bytes:
    """Serialize the signed fields of a capture proof deterministically."""
    if type(proof) is not CaptureProof:
        raise TypeError(CANONICAL_ATTESTATION_PAYLOAD_TYPE_ERROR)
    return _length_framed(
        (
            proof.project_id,
            proof.cluster_name,
            proof.location,
            proof.cluster_uid,
            proof.environment,
            proof.run_id,
            proof.nonce,
            canonical_utc_timestamp(proof.captured_at_utc),
            proof.collector_id,
            proof.collector_version,
            proof.workload_graph_sha256,
            proof.raw_inventory_sha256,
            proof.raw_probe_sha256,
            proof.deployed_manifest_sha256,
            proof.deployed_image_sha256,
            proof.deployed_environment_sha256,
            proof.deployed_control_sha256,
            proof.corpus_sha256,
            proof.input_sha256,
            proof.watcher_registration_id,
            proof.watcher_receipt_sha256,
            proof.scientific_output_checksum_set_sha256,
            proof.normalized_evidence_sha256,
            proof.resource_records_sha256,
            proof.probe_records_sha256,
            proof.verifier_key_id,
        )
    )


def _length_framed(fields: tuple[str, ...]) -> bytes:
    """Encode strings with unambiguous fixed-width length prefixes."""
    return b"".join(
        len(value.encode()).to_bytes(8, "big") + value.encode() for value in fields
    )


async def _collect_canonical_output() -> bytes:
    """Run the collector and return only a successful canonical output."""
    try:
        process = await start_fixed_collector()
    except OSError as error:
        raise _capture_error(_COLLECTOR_START_ERROR) from error
    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=COLLECTOR_TIMEOUT_SECONDS
        )
    except TimeoutError as error:
        await _terminate_collector(process)
        raise _capture_error(_COLLECTOR_TIMEOUT_ERROR) from error
    if process.returncode != SUCCESS_EXIT_CODE:
        raise _capture_error(_COLLECTOR_EXIT_ERROR)
    return stdout


async def _start_collector() -> asyncio.subprocess.Process:
    """Start the fixed collector through its already-open trusted descriptor."""
    descriptor = open_trusted_path(COLLECTOR_COMMAND, executable=True)
    if descriptor is None or os.name != "posix":
        if descriptor is not None:
            os.close(descriptor)
        raise OSError(_UNSAFE_PATH_ERROR)
    try:
        executable = _trusted_executable(descriptor)
        if executable is None:
            raise OSError(_UNSAFE_PATH_ERROR)
        return await asyncio.create_subprocess_exec(
            *COLLECTOR_ARGV,
            executable=executable,
            pass_fds=(descriptor,),
            env=_COLLECTOR_ENV,
            stderr=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    finally:
        os.close(descriptor)


async def start_fixed_collector() -> asyncio.subprocess.Process:
    """Start the fixed collector through the public trusted execution boundary."""
    return await _start_collector()


async def _terminate_collector(process: asyncio.subprocess.Process) -> None:
    """Terminate a timed-out collector and reap it."""
    if os.name == "posix":
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    else:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
    with contextlib.suppress(ProcessLookupError):
        _ = await process.communicate()


def _split_canonical_output(raw: bytes) -> tuple[bytes, bytes, bytes]:
    """Separate the three non-empty LF-only canonical collector sections."""
    if b"\r" in raw:
        msg = "collector output must use LF-only line endings"
        raise _capture_error(msg)
    metadata_and_resources = raw.split(_RESOURCE_SECTION)
    if len(metadata_and_resources) != _CANONICAL_OUTPUT_SECTION_COUNT:
        msg = "collector output has malformed resource section"
        raise _capture_error(msg)
    metadata, resources_and_probes = metadata_and_resources
    parts = resources_and_probes.split(_PROBE_SECTION)
    if len(parts) != _CANONICAL_OUTPUT_SECTION_COUNT:
        msg = "collector output has malformed probe section"
        raise _capture_error(msg)
    resources, probes = parts
    if not metadata or not resources or not probes:
        msg = "collector output has an empty evidence section"
        raise _capture_error(msg)
    return metadata, resources, probes


def _parse_metadata(raw: bytes) -> dict[str, str]:
    """Parse and validate the ordered collector metadata receipt."""
    values: dict[str, str] = {}
    for line in _lines(raw, "collector receipt"):
        key, separator, value = line.partition("=")
        if not separator or not key or not value or key in values:
            msg = "collector receipt metadata is malformed"
            raise _capture_error(msg)
        values[key] = value
    if tuple(values) != EXPECTED_RECEIPT_KEYS:
        msg = "collector receipt metadata keys are incomplete or reordered"
        raise _capture_error(msg)
    if (
        values["collector_id"] != EXPECTED_COLLECTOR_ID
        or values["collector_version"] != EXPECTED_COLLECTOR_VERSION
    ):
        msg = "collector identity or version is not permitted"
        raise _capture_error(msg)
    for name in (
        "workload_graph_sha256",
        "deployed_manifest_sha256",
        "deployed_image_sha256",
        "deployed_environment_sha256",
        "deployed_control_sha256",
        "corpus_sha256",
        "input_sha256",
        "watcher_receipt_sha256",
        "scientific_output_checksum_set_sha256",
    ):
        _sha(values[name])
    _ = _verified_key_id(values[ATTESTATION_KEY_ID])
    if (
        not values["watcher_registration_id"]
        or not values[ATTESTATION_KEY_ID]
        or not values[ATTESTATION_SIGNATURE]
    ):
        msg = "collector attestation or watcher registration is malformed"
        raise _capture_error(msg)
    return values


def _parse_resources(raw: bytes) -> tuple[CapturedResource, ...]:
    """Parse collector resource records."""
    parsed: list[CapturedResource] = []
    for line in _lines(raw, "resource evidence"):
        fields = line.split("|")
        if len(fields) != RESOURCE_FIELD_COUNT:
            msg = "resource evidence record is malformed"
            raise _capture_error(msg)
        stable_id, kind, name, uid, generation_text, spec, status, graph = fields
        try:
            generation = int(generation_text)
        except ValueError as error:
            msg = "resource generation is malformed"
            raise _capture_error(msg) from error
        _sha(graph)
        parsed.append(
            CapturedResource(
                stable_id,
                kind,
                name,
                uid,
                generation,
                spec,
                status,
                graph,
                _digest(line.encode()),
            )
        )
    return tuple(parsed)


def _parse_probes(raw: bytes) -> tuple[CapturedProbe, ...]:
    """Parse collector probe records."""
    parsed: list[CapturedProbe] = []
    for line in _lines(raw, "probe evidence"):
        fields = line.split("|")
        if len(fields) != PROBE_FIELD_COUNT:
            msg = "probe evidence record is malformed"
            raise _capture_error(msg)
        (
            vector,
            attempted,
            executor,
            target,
            test_vector,
            transport,
            result,
            duration_text,
            reason,
            outcome,
        ) = fields
        try:
            duration = int(duration_text)
        except ValueError as error:
            msg = "probe duration is malformed"
            raise _capture_error(msg) from error
        _sha(target)
        _sha(test_vector)
        parsed.append(
            CapturedProbe(
                vector,
                _parse_utc(attempted),
                executor,
                target,
                test_vector,
                transport,
                result,
                duration,
                reason,
                outcome,
                _digest(line.encode()),
            )
        )
    return tuple(parsed)


def _lines(raw: bytes, scope: str) -> tuple[str, ...]:
    """Decode a non-empty UTF-8 LF-delimited canonical evidence section."""
    if b"\r" in raw or raw.endswith(b"\n"):
        msg = f"{scope} is empty or malformed"
        raise _capture_error(msg)
    try:
        lines = tuple(raw.decode("utf-8").split("\n"))
    except UnicodeDecodeError as error:
        msg = f"{scope} is not UTF-8"
        raise _capture_error(msg) from error
    if not lines or any(not line or "\x00" in line for line in lines):
        msg = f"{scope} is empty or malformed"
        raise _capture_error(msg)
    return lines


def _parse_utc(value: str) -> datetime:
    """Parse the single canonical UTC timestamp spelling from collector evidence."""
    if not value.endswith(_CANONICAL_UTC_SUFFIX):
        msg = "collector timestamp is not canonical UTC"
        raise _capture_error(msg)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        msg = "collector timestamp is malformed"
        raise _capture_error(msg) from error
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != UTC.utcoffset(parsed)
        or value != canonical_utc_timestamp(parsed)
    ):
        msg = "collector timestamp is not canonical UTC"
        raise _capture_error(msg)
    return parsed


def canonical_utc_timestamp(value: datetime) -> str:
    """Return the unique collector wire spelling for a UTC timestamp."""
    return value.astimezone(UTC).isoformat().replace("+00:00", _CANONICAL_UTC_SUFFIX)


def _verified_key_id(value: str) -> str:
    """Return the only configured signer identity accepted for this policy."""
    if value != EXPECTED_VERIFIER_KEY_ID:
        msg = "collector attestation key ID is not permitted"
        raise _capture_error(msg)
    return value


def _digest(raw: bytes) -> str:
    """Return the SHA-256 hex digest of bytes."""
    return hashlib.sha256(raw).hexdigest()


def _normalized_evidence_digest(
    metadata: bytes, resources: bytes, probes: bytes
) -> str:
    """Digest the unsigned canonical evidence sections."""
    unsigned = b"\n".join(
        line
        for line in metadata.splitlines()
        if not line.startswith(f"{ATTESTATION_SIGNATURE}=".encode())
    )
    digest = hashlib.sha256()
    for part in (unsigned, resources, probes):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def _resource_record_digest(records: tuple[CapturedResource, ...]) -> str:
    """Digest parsed resource records in wire order."""
    return _field_digest(
        tuple(
            value
            for r in records
            for value in (
                r.stable_id,
                r.kind,
                r.name,
                r.uid,
                str(r.generation),
                r.spec,
                r.status,
                r.workload_graph_sha256,
                r.source_sha256,
            )
        )
    )


def _probe_record_digest(records: tuple[CapturedProbe, ...]) -> str:
    """Digest parsed probe records in wire order."""
    return _field_digest(
        tuple(
            value
            for p in records
            for value in (
                p.vector,
                canonical_utc_timestamp(p.attempted_at_utc),
                p.executor,
                p.target_sha256,
                p.test_vector_sha256,
                p.transport,
                p.result_code,
                str(p.duration_ms),
                p.policy_reason,
                p.outcome,
                p.raw_sha256,
            )
        )
    )


def _field_digest(fields: tuple[str, ...]) -> str:
    """Return a length-framed SHA-256 digest of strings."""
    digest = hashlib.sha256()
    for value in fields:
        encoded = value.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _sha(value: str) -> None:
    """Raise when a collector SHA-256 value is not canonical lowercase hex."""
    if len(value) != SHA256_LENGTH or any(c not in "0123456789abcdef" for c in value):
        msg = "collector receipt SHA-256 is malformed"
        raise _capture_error(msg)


def _capture_error(reason: str) -> _CAPTURE_ERROR_TYPE:
    """Create a capture parsing failure."""
    return ValueError(reason)
