"""Adversarial tests for detached-signature GKE deployment evidence."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import os
import shutil
import struct
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from tools.platform_policy import deployment_capture
from tools.platform_policy.deployment_capture import (
    COLLECTOR_ARGV,
    CaptureProof,
    WorkloadIdentity,
    canonical_attestation_payload,
    capture_live_gke,
    is_durably_verified,
    workload_graph_sha256,
)
from tools.platform_policy.deployment_contract import (
    CONTROL_INVENTORY,
    PROBE_POLICY,
    CaptureKind,
    ContractViolationError,
    DeploymentContract,
    EnvironmentObservation,
    NamedChecksum,
    OutputWatcherReceipt,
    ParityEnvelope,
    RenderedDesiredStateObservation,
    canonical_contract_sha256,
    canonical_evidence_sha256,
    is_release_qualified,
    observation_from_live_capture,
    validate_parity_envelope,
)

_REAL_START_FIXED_COLLECTOR = deployment_capture.start_fixed_collector
_REAL_VERIFY_DETACHED_SIGNATURE = deployment_capture.verify_detached_signature
def _resolve_openssl_command() -> str:
    """Portable OpenSSL 3 resolution: ed25519 `pkeyutl -rawin` requires real
    OpenSSL, so prefer Homebrew installs on macOS (the system LibreSSL lacks
    -rawin) and fall back to PATH openssl on Linux CI runners."""
    override = os.environ.get("NIPO_OPENSSL_COMMAND")
    if override:
        return override
    for candidate in ("/opt/homebrew/bin/openssl", "/usr/local/opt/openssl/bin/openssl"):
        if Path(candidate).exists():
            return candidate
    return shutil.which("openssl") or "openssl"


_OPENSSL_COMMAND = _resolve_openssl_command()


def _digest(value: str) -> str:
    return value.encode().hex().ljust(64, "0")[:64]


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _output_set_digest() -> str:
    return _field_digest(("result.csv", _digest("output")))


def _field_digest(values: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for value in values:
        raw = value.encode()
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _utc_wire(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _metadata(
    environment: str, captured_at: datetime, signature: str = "unverified"
) -> bytes:
    graph = workload_graph_sha256(
        WorkloadIdentity(
            "project",
            f"{environment}-cluster",
            "us-central1",
            f"{environment}-uid",
            environment,
            f"{environment}-run",
            _digest("manifest"),
            _digest("image"),
        )
    )
    values = (
        "project_id=project",
        f"cluster_name={environment}-cluster",
        "location=us-central1",
        f"cluster_uid={environment}-uid",
        f"environment={environment}",
        f"run_id={environment}-run",
        f"nonce={environment}-nonce",
        f"captured_at_utc={_utc_wire(captured_at)}",
        "collector_id=collector",
        "collector_version=v1",
        f"workload_graph_sha256={graph}",
        f"deployed_manifest_sha256={_digest('manifest')}",
        f"deployed_image_sha256={_digest('image')}",
        f"deployed_environment_sha256={_digest('environment-' + environment)}",
        f"deployed_control_sha256={_digest('controls')}",
        f"corpus_sha256={_digest('corpus')}",
        f"input_sha256={_digest('input')}",
        "watcher_registration_id=watcher",
        f"watcher_receipt_sha256={_digest('receipt')}",
        f"scientific_output_checksum_set_sha256={_output_set_digest()}",
        "release-attestation-key-id=release-key",
        f"release-attestation-signature={signature}",
    )
    return "\n".join(values).encode()


def _resources(environment: str) -> bytes:
    graph = workload_graph_sha256(
        WorkloadIdentity(
            "project",
            f"{environment}-cluster",
            "us-central1",
            f"{environment}-uid",
            environment,
            f"{environment}-run",
            _digest("manifest"),
            _digest("image"),
        )
    )
    attrs = {
        "runtime-class-gvisor": "handler=gvisor",
        "sandbox-pod-runtime-class-binding": "runtimeClassName=gvisor-runtimeclass",
        "sandbox-node-scheduling": "nodeSelector=sandbox",
        "sandbox-node-pool": "sandboxEnabled=true",
        "control-plane-isolation": "controlPlaneIsolated=true",
        "workload-egress-selector": "workloadSelector=sandbox",
        "workload-identity-pool": "workloadPool=project.svc.id.goog",
        "workload-identity-ksa-gsa": "gcpServiceAccount=runner@project.iam.gserviceaccount.com",
        "workload-identity-iam-binding": "role=roles/iam.workloadIdentityUser",
        "workload-identity-token-behavior": "automountServiceAccountToken=false",
        "network-default-deny": "policyTypes=Egress",
        "network-allowed-egress": "allowedHosts=artifact-registry.googleapis.com,logging.googleapis.com",
        "resource-quota": "hard=pods",
        "admission-signed-pinned-image": "signed=true;digestPinned=true",
        "host-path-mount-forbidden": "hostPath=false",
        "runtime-socket-mount-forbidden": "runtimeSocketMount=false",
    }
    statuses = {
        "runtime-class-gvisor": "ready",
        "sandbox-pod-runtime-class-binding": "ready",
        "sandbox-node-scheduling": "scheduled-sandbox",
        "sandbox-node-pool": "ready",
        "control-plane-isolation": "enforced",
        "workload-egress-selector": "enforced",
        "workload-identity-pool": "enabled",
        "workload-identity-ksa-gsa": "bound",
        "workload-identity-iam-binding": "bound",
        "workload-identity-token-behavior": "metadata-token-verified",
        "network-default-deny": "default-deny",
        "network-allowed-egress": "enforced",
        "resource-quota": "enforced",
        "admission-signed-pinned-image": "enforced",
        "host-path-mount-forbidden": "validated",
        "runtime-socket-mount-forbidden": "validated",
    }
    return "\n".join(
        "|".join(
            (
                c.stable_id,
                c.kind,
                c.stable_id,
                c.stable_id + "-uid",
                "1",
                attrs[c.stable_id],
                statuses[c.stable_id],
                graph,
            )
        )
        for c in CONTROL_INVENTORY
    ).encode()


def _probes(captured_at: datetime) -> bytes:
    return "\n".join(
        "|".join(
            (
                vector,
                _utc_wire(captured_at),
                "probe-executor",
                _sha(target),
                _sha(test),
                transport,
                result,
                "1",
                reason,
                "denied",
            )
        )
        for vector, (target, test, transport, result, reason) in PROBE_POLICY.items()
    ).encode()


_OUTPUTS: list[bytes] = []
_TEST_SIGNATURES: dict[bytes, bytes] = {}


_ED25519_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
_ED25519_PUBLIC = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
_OPENSSH_KEY_TYPE = b"ssh-ed25519"
_OPENSSH_COMMENT = b"deterministic-test-fixture"
_PKCS8_ED25519_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
_SSHSIG_MAGIC = b"SSHSIG"
_SSHSIG_VERSION = 1
_SSHSIG_HASH = b"sha512"


def _ssh_string(value: bytes) -> bytes:
    """Encode one SSH length-prefixed string."""
    return struct.pack(">I", len(value)) + value


def _write_ed25519_fixture(key: Path) -> None:
    """Write deterministic RFC 8410 private and OpenSSH public test keys."""
    private_der = _PKCS8_ED25519_PREFIX + _ED25519_SEED
    private_body = base64.b64encode(private_der).decode()
    private_lines = "\n".join(
        private_body[index : index + 64] for index in range(0, len(private_body), 64)
    )
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"
    _ = key.with_suffix(".pem").write_text(f"{begin}\n{private_lines}\n{end}\n")
    _ = key.with_suffix(".pem").chmod(0o600)
    public_blob = _ssh_string(_OPENSSH_KEY_TYPE) + _ssh_string(_ED25519_PUBLIC)
    _ = key.with_suffix(".pub").write_text(
        f"{_OPENSSH_KEY_TYPE.decode()} {base64.b64encode(public_blob).decode()} "
        f"{_OPENSSH_COMMENT.decode()}\n"
    )


class _Process:
    returncode: int = 0
    pid: int = 1

    async def communicate(self) -> tuple[bytes, bytes]:
        return _OUTPUTS.pop(0), b""


async def _fake_collector() -> _Process:
    return _Process()


@pytest.fixture(autouse=True)
def collector(monkeypatch: pytest.MonkeyPatch) -> None:
    _OUTPUTS.clear()
    monkeypatch.setattr(deployment_capture, "start_fixed_collector", _fake_collector)


def _live(
    environment: str, captured_at: datetime, signature: str = "unverified"
) -> EnvironmentObservation:
    _OUTPUTS.append(
        _metadata(environment, captured_at, signature)
        + b"\n---RESOURCES---\n"
        + _resources(environment)
        + b"\n---PROBES---\n"
        + _probes(captured_at)
    )
    return observation_from_live_capture(capture_live_gke())


def _seal(envelope: ParityEnvelope) -> ParityEnvelope:
    unsigned = replace(envelope, evidence_sha256="")
    return replace(unsigned, evidence_sha256=canonical_evidence_sha256(unsigned))


def _envelope() -> ParityEnvelope:
    at = datetime.now(UTC)
    checksums = (NamedChecksum("result.csv", _digest("output")),)

    return _seal(
        ParityEnvelope(
            canonical_contract_sha256(DeploymentContract.canonical()),
            _digest("corpus"),
            _digest("input"),
            RenderedDesiredStateObservation(
                _digest("manifest"), CaptureKind.SYNTHETIC_CONTRACT_FIXTURE
            ),
            (_live("staging", at), _live("production", at)),
            checksums,
            checksums,
            OutputWatcherReceipt("watcher", _digest("receipt")),
            "release-challenge",
            "",
        )
    )


class MemoryReleaseQualificationAuthority:
    _expected: dict[str, tuple[tuple[str, str, str], ...]]
    _consumed: set[str]

    def __init__(self, envelope: ParityEnvelope) -> None:
        self._expected = {
            envelope.release_challenge_id: tuple(
                (
                    observation.environment,
                    observation.capture_proof.run_id,
                    observation.capture_proof.nonce,
                )
                for observation in envelope.observations
                if observation.capture_proof is not None
            )
        }
        self._consumed = set()

    def consume(
        self,
        challenge_id: str,
        evidence_sha256: str,
        captures: tuple[tuple[str, str, str], ...],
    ) -> bool:
        if (
            not evidence_sha256
            or challenge_id in self._consumed
            or self._expected.get(challenge_id) != captures
        ):
            return False
        self._consumed.add(challenge_id)
        return True


def test_live_capture_has_no_caller_evidence_arguments_and_uses_canonical_v2_wire() -> (
    None
):
    assert not inspect.signature(capture_live_gke).parameters
    observation = _live("staging", datetime.now(UTC))
    assert observation.capture_proof is not None
    assert (
        observation.resources[0].workload_graph_sha256
        == observation.capture_proof.workload_graph_sha256
    )
    assert observation.probes[0].duration_ms == 1
    assert COLLECTOR_ARGV == (
        "/opt/science-workbench/bin/gke-evidence-collector-v1",
        "--format=canonical-v2",
    )


def test_unsafe_fixed_collector_path_fails_before_any_process_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoked = False

    async def forbidden(*_args: object, **_kwargs: object) -> object:
        nonlocal invoked
        invoked = True
        msg = "must not execute"
        raise AssertionError(msg)

    def untrusted_path(_path: str, *, executable: bool) -> None:
        _ = executable

    monkeypatch.setattr(deployment_capture, "open_trusted_path", untrusted_path)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    with pytest.raises(OSError, match="unsafe"):
        _ = asyncio.run(_REAL_START_FIXED_COLLECTOR())
    assert not invoked


def test_collector_process_boundary_executes_held_descriptor_with_fixed_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    descriptor = os.open("/usr/bin/true", os.O_RDONLY)

    async def boundary(*args: object, **kwargs: object) -> _Process:
        pass_fds = kwargs.get("pass_fds")
        assert isinstance(pass_fds, tuple)
        assert isinstance(pass_fds[0], int)
        assert os.fstat(pass_fds[0]).st_size > 0
        calls.append((args, kwargs))
        return _Process()

    def trusted_collector_path(_path: str, *, executable: bool) -> int:
        _ = executable
        return descriptor

    def descriptor_backed_path(held_descriptor: int) -> str:
        return f"/proc/self/fd/{held_descriptor}"

    monkeypatch.setattr(deployment_capture, "open_trusted_path", trusted_collector_path)
    monkeypatch.setattr(
        deployment_capture,
        "_descriptor_backed_path",
        descriptor_backed_path,
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", boundary)
    process = asyncio.run(_REAL_START_FIXED_COLLECTOR())
    assert process.returncode == 0

    args, kwargs = calls.pop()
    assert args == COLLECTOR_ARGV
    assert kwargs["executable"] == f"/proc/self/fd/{descriptor}"
    assert kwargs["env"] == {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}


def test_collector_fails_closed_without_descriptor_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = os.open("/usr/bin/true", os.O_RDONLY)
    invoked = False

    def trusted_collector_path(_path: str, *, executable: bool) -> int:
        _ = executable
        return descriptor

    def unavailable_descriptor_path(_descriptor: int) -> None:
        return None

    async def forbidden(*_args: object, **_kwargs: object) -> object:
        nonlocal invoked
        invoked = True
        msg = "must not execute"
        raise AssertionError(msg)

    monkeypatch.setattr(deployment_capture, "open_trusted_path", trusted_collector_path)
    monkeypatch.setattr(
        deployment_capture, "_descriptor_backed_path", unavailable_descriptor_path
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    with pytest.raises(OSError, match="unsafe"):
        _ = asyncio.run(_REAL_START_FIXED_COLLECTOR())
    assert not invoked


@pytest.mark.parametrize(
    "replacement",
    [
        (b"\n", b"\r\n"),
        (b"Z", b"+00:00"),
        (b"T", b" "),
    ],
)
def test_noncanonical_capture_wire_bytes_are_rejected(
    replacement: tuple[bytes, bytes],
) -> None:
    captured_at = datetime.now(UTC)
    raw = (
        _metadata("staging", captured_at)
        + b"\n---RESOURCES---\n"
        + _resources("staging")
        + b"\n---PROBES---\n"
        + _probes(captured_at)
    )
    _OUTPUTS.append(raw.replace(*replacement, 1))
    with pytest.raises(ValueError, match="collector"):
        _ = capture_live_gke()


def test_misleading_attestation_key_id_is_rejected_before_proof_construction() -> None:
    captured_at = datetime.now(UTC)
    raw = (
        _metadata("staging", captured_at).replace(
            b"release-attestation-key-id=release-key",
            b"release-attestation-key-id=retired-key",
        )
        + b"\n---RESOURCES---\n"
        + _resources("staging")
        + b"\n---PROBES---\n"
        + _probes(captured_at)
    )
    _OUTPUTS.append(raw)
    with pytest.raises(ValueError, match="key ID"):
        _ = capture_live_gke()


def test_reloaded_proof_with_misleading_key_id_is_not_durably_verified() -> None:
    proof = _live("staging", datetime.now(UTC)).capture_proof
    assert proof is not None
    assert not is_durably_verified(replace(proof, verifier_key_id="retired-key"))


def test_unsafe_ancestor_or_symlink_never_produces_trusted_file(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    _ = unsafe.chmod(0o777)
    leaf = unsafe / "collector"
    _ = leaf.write_text("x")
    _ = leaf.chmod(0o755)
    assert deployment_capture.open_trusted_path(str(leaf), executable=True) is None
    link = tmp_path / "link"
    link.symlink_to(leaf)
    assert deployment_capture.open_trusted_path(str(link), executable=True) is None


def test_descriptor_backed_policy_fails_closed_when_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier_descriptor = os.open("/usr/bin/true", os.O_RDONLY)
    allowed_descriptor = os.open("/dev/null", os.O_RDONLY)
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
    descriptor_requests: list[int] = []

    def trusted_path(path: str, *, executable: bool) -> int | None:
        _ = executable
        if path == deployment_capture.VERIFY_COMMAND:
            return verifier_descriptor
        if path == deployment_capture.ALLOWED_SIGNERS_PATH:
            return allowed_descriptor
        return None

    def unavailable_descriptor_path(descriptor: int) -> str | None:
        descriptor_requests.append(descriptor)

    async def boundary(*args: str, **kwargs: object) -> None:
        calls.append((args, kwargs))

    monkeypatch.setattr(deployment_capture, "open_trusted_path", trusted_path)
    monkeypatch.setattr(
        deployment_capture,
        "_descriptor_backed_path",
        unavailable_descriptor_path,
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", boundary)
    assert not asyncio.run(_REAL_VERIFY_DETACHED_SIGNATURE(b"message", b"signature"))
    assert descriptor_requests == [verifier_descriptor]
    assert calls == []


def test_fixed_verifier_boundary_uses_retained_descriptor_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    _ = allowed.write_text("gke-evidence-collector ssh-ed25519 a2V5 release-key\n")
    verifier_descriptor = os.open("/usr/bin/true", os.O_RDONLY)
    allowed_descriptor = os.open(allowed, os.O_RDONLY)
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def trusted_path(path: str, *, executable: bool) -> int | None:
        _ = executable
        if path == deployment_capture.VERIFY_COMMAND:
            return verifier_descriptor
        if path == deployment_capture.ALLOWED_SIGNERS_PATH:
            return allowed_descriptor
        return None

    def descriptor_path(descriptor: int) -> str:
        return f"/proc/self/fd/{descriptor}"

    class VerifierProcess:
        returncode: int = 0

        async def communicate(self, _message: bytes) -> tuple[bytes, bytes]:
            return b"", b""

        def kill(self) -> None:
            return None

    async def boundary(*args: str, **kwargs: object) -> VerifierProcess:
        calls.append((args, kwargs))
        return VerifierProcess()

    monkeypatch.setattr(deployment_capture, "open_trusted_path", trusted_path)
    monkeypatch.setattr(deployment_capture, "_descriptor_backed_path", descriptor_path)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", boundary)

    assert asyncio.run(_REAL_VERIFY_DETACHED_SIGNATURE(b"message", b"signature"))
    argv, options = calls.pop()
    pass_fds = cast("tuple[int, ...]", options["pass_fds"])
    executable = cast("str", options["executable"])
    assert argv[:3] == (deployment_capture.VERIFY_COMMAND, "-Y", "verify")
    assert argv[4] == f"/proc/self/fd/{allowed_descriptor}"
    assert argv[10].startswith("/proc/self/fd/")
    assert pass_fds[:2] == (verifier_descriptor, allowed_descriptor)
    assert executable == f"/proc/self/fd/{verifier_descriptor}"


@pytest.mark.parametrize(
    "policy",
    [
        (
            "gke-evidence-collector ssh-ed25519 a2V5 release-key\n"
            "gke-evidence-collector ssh-ed25519 b3RoZXI= retired-key\n"
        ),
        "gke-evidence-collector ssh-ed25519 a2V5 retired-key\n",
    ],
)
def test_allowed_signer_policy_binds_one_exact_key_label(
    tmp_path: Path,
    policy: str,
) -> None:
    allowed = tmp_path / "allowed"
    _ = allowed.write_text(policy)
    descriptor = os.open(allowed, os.O_RDONLY)
    try:
        assert not deployment_capture.allowed_signers_policy_matches_key_id(
            descriptor,
            deployment_capture.EXPECTED_VERIFIER_KEY_ID,
        )
    finally:
        os.close(descriptor)


def test_same_uid_policy_replacement_cannot_change_retained_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    _ = allowed.write_text("gke-evidence-collector ssh-ed25519 a2V5 release-key\n")
    replacement = tmp_path / "replacement"
    _ = replacement.write_text("substituted policy\n")
    verifier_descriptor = os.open("/usr/bin/true", os.O_RDONLY)
    policy_descriptor: int | None = None

    def trusted_path(path: str, *, executable: bool) -> int | None:
        nonlocal policy_descriptor
        _ = executable
        if path == deployment_capture.VERIFY_COMMAND:
            return verifier_descriptor
        if path == deployment_capture.ALLOWED_SIGNERS_PATH:
            policy_descriptor = os.open(allowed, os.O_RDONLY)
            _ = replacement.replace(allowed)
            return policy_descriptor
        return None

    def descriptor_path(descriptor: int) -> str:
        return f"/proc/self/fd/{descriptor}"

    class VerifierProcess:
        returncode: int = 0

        async def communicate(self, _message: bytes) -> tuple[bytes, bytes]:
            return b"", b""

        def kill(self) -> None:
            return None

    async def boundary(*args: str, **kwargs: object) -> VerifierProcess:
        argv = args
        pass_fds = cast("tuple[int, ...]", kwargs["pass_fds"])
        assert policy_descriptor is not None
        assert argv[4] == f"/proc/self/fd/{policy_descriptor}"
        assert pass_fds[1] == policy_descriptor
        _ = os.lseek(policy_descriptor, 0, os.SEEK_SET)
        assert (
            os.read(policy_descriptor, 96)
            == b"gke-evidence-collector ssh-ed25519 a2V5 release-key\n"
        )
        assert allowed.read_bytes() == b"substituted policy\n"
        return VerifierProcess()

    monkeypatch.setattr(deployment_capture, "open_trusted_path", trusted_path)
    monkeypatch.setattr(deployment_capture, "_descriptor_backed_path", descriptor_path)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", boundary)
    assert asyncio.run(_REAL_VERIFY_DETACHED_SIGNATURE(b"message", b"signature"))


def test_synthetic_fixture_is_structurally_valid_but_not_qualified() -> None:
    envelope = _envelope()
    assert (
        validate_parity_envelope(DeploymentContract.canonical(), envelope) == envelope
    )
    assert not is_release_qualified(
        DeploymentContract.canonical(),
        envelope,
        MemoryReleaseQualificationAuthority(envelope),
    )


@pytest.fixture
def signer_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    verifier = Path(deployment_capture.VERIFY_COMMAND)
    assert verifier.is_file(), "fixed verifier unavailable"
    key = tmp_path / "key"
    _write_ed25519_fixture(key)
    allowed = tmp_path / "allowed"
    public_key_fields = key.with_suffix(".pub").read_text().split()
    _ = allowed.write_text(
        f"{deployment_capture.VERIFY_PRINCIPAL} "
        f"{public_key_fields[0]} {public_key_fields[1]} "
        f"{deployment_capture.EXPECTED_VERIFIER_KEY_ID}\n"
    )

    def safe(path: str, *, executable: bool) -> int | None:
        _ = executable
        actual = (
            verifier
            if path == deployment_capture.VERIFY_COMMAND
            else allowed
            if path == deployment_capture.ALLOWED_SIGNERS_PATH
            else None
        )
        return None if actual is None else os.open(actual, os.O_RDONLY)

    monkeypatch.setattr(deployment_capture, "open_trusted_path", safe)

    async def verify_signature(
        message: bytes,
        signature: bytes,
        _expected_key_id: str,
    ) -> bool:
        key_digest = hashlib.sha256(message).digest()
        return _TEST_SIGNATURES.get(key_digest) == signature

    monkeypatch.setattr(
        deployment_capture,
        "verify_detached_signature",
        verify_signature,
    )
    return key


def _sign(key: Path, proof: CaptureProof, output: Path) -> str:
    message = canonical_attestation_payload(proof)
    signed_data = b"".join(
        (
            _SSHSIG_MAGIC,
            _ssh_string(deployment_capture.VERIFY_NAMESPACE.encode()),
            _ssh_string(b""),
            _ssh_string(_SSHSIG_HASH),
            _ssh_string(hashlib.sha512(message).digest()),
        )
    )
    signed_path = output.with_suffix(".signed")
    raw_signature_path = output.with_suffix(".raw-signature")
    _ = signed_path.write_bytes(signed_data)
    completed = subprocess.run(
        (
            _OPENSSL_COMMAND,
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(key.with_suffix(".pem")),
            "-in",
            str(signed_path),
            "-out",
            str(raw_signature_path),
        ),
        check=True,
        capture_output=True,
    )
    assert completed.returncode == 0
    signature_blob = b"".join(
        (
            _ssh_string(_OPENSSH_KEY_TYPE),
            _ssh_string(raw_signature_path.read_bytes()),
        )
    )
    public_blob = _ssh_string(_OPENSSH_KEY_TYPE) + _ssh_string(_ED25519_PUBLIC)
    envelope = b"".join(
        (
            _SSHSIG_MAGIC,
            struct.pack(">I", _SSHSIG_VERSION),
            _ssh_string(public_blob),
            _ssh_string(deployment_capture.VERIFY_NAMESPACE.encode()),
            _ssh_string(b""),
            _ssh_string(_SSHSIG_HASH),
            _ssh_string(signature_blob),
        )
    )
    encoded = base64.b64encode(envelope).decode()
    armored = (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(encoded[index : index + 70] for index in range(0, len(encoded), 70))
        + "\n-----END SSH SIGNATURE-----\n"
    ).encode()
    _TEST_SIGNATURES[hashlib.sha256(message).digest()] = armored
    return base64.b64encode(armored).decode()


def test_serialized_reloaded_signed_proof_qualifies_without_process_issuer(
    signer_boundary: Path, tmp_path: Path
) -> None:
    unsigned = _live("staging", datetime.now(UTC)).capture_proof
    assert unsigned is not None
    signed = replace(
        unsigned, attestation=_sign(signer_boundary, unsigned, tmp_path / "proof")
    )
    reloaded = CaptureProof(
        project_id=signed.project_id,
        cluster_name=signed.cluster_name,
        location=signed.location,
        cluster_uid=signed.cluster_uid,
        environment=signed.environment,
        run_id=signed.run_id,
        nonce=signed.nonce,
        captured_at_utc=signed.captured_at_utc,
        collector_id=signed.collector_id,
        collector_version=signed.collector_version,
        workload_graph_sha256=signed.workload_graph_sha256,
        raw_inventory_sha256=signed.raw_inventory_sha256,
        raw_probe_sha256=signed.raw_probe_sha256,
        deployed_manifest_sha256=signed.deployed_manifest_sha256,
        deployed_image_sha256=signed.deployed_image_sha256,
        deployed_environment_sha256=signed.deployed_environment_sha256,
        deployed_control_sha256=signed.deployed_control_sha256,
        corpus_sha256=signed.corpus_sha256,
        input_sha256=signed.input_sha256,
        watcher_registration_id=signed.watcher_registration_id,
        watcher_receipt_sha256=signed.watcher_receipt_sha256,
        scientific_output_checksum_set_sha256=(
            signed.scientific_output_checksum_set_sha256
        ),
        normalized_evidence_sha256=signed.normalized_evidence_sha256,
        resource_records_sha256=signed.resource_records_sha256,
        probe_records_sha256=signed.probe_records_sha256,
        verifier_key_id=signed.verifier_key_id,
        attestation=signed.attestation,
    )
    assert is_durably_verified(reloaded)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("collector_id", "other-collector"),
        ("collector_version", "v2"),
    ],
)
def test_resigned_disallowed_collector_identity_is_not_durably_verified(
    signer_boundary: Path, tmp_path: Path, field: str, value: str
) -> None:
    unsigned = _live("staging", datetime.now(UTC)).capture_proof
    assert unsigned is not None
    altered = replace(unsigned, **{field: value})
    resigned = replace(
        altered,
        attestation=_sign(signer_boundary, altered, tmp_path / field),
    )
    assert not is_durably_verified(resigned)


def test_only_detached_signatures_qualify_and_tampering_fails(
    signer_boundary: Path, tmp_path: Path
) -> None:
    at = datetime.now(UTC)
    staged = _live("staging", at)
    production = _live("production", at)
    proofs: list[EnvironmentObservation] = []
    for index, observation in enumerate((staged, production)):
        proof = observation.capture_proof
        assert proof is not None
        proofs.append(
            replace(
                observation,
                capture_proof=replace(
                    proof,
                    attestation=_sign(signer_boundary, proof, tmp_path / str(index)),
                ),
            )
        )
    envelope = _seal(replace(_envelope(), observations=tuple(proofs)))
    authority = MemoryReleaseQualificationAuthority(envelope)
    assert is_release_qualified(DeploymentContract.canonical(), envelope, authority)
    assert not is_release_qualified(DeploymentContract.canonical(), envelope, authority)
    unissued = _seal(
        replace(
            envelope,
            release_challenge_id="unissued-challenge",
            evidence_sha256="",
        )
    )
    assert not is_release_qualified(
        DeploymentContract.canonical(),
        unissued,
        MemoryReleaseQualificationAuthority(envelope),
    )
    proof = envelope.observations[0].capture_proof
    assert proof is not None
    forged = replace(proof, run_id="forged")
    assert not is_durably_verified(forged)


def test_all_probe_ambiguity_and_duration_vectors_fail() -> None:
    envelope = _envelope()
    probe = envelope.observations[0].probes[0]
    for changed_probe in (
        replace(probe, target_sha256=_digest("wrong")),
        replace(probe, test_vector_sha256=_digest("wrong")),
        replace(probe, transport="timeout"),
        replace(probe, result_code="TIMEOUT"),
        replace(probe, policy_reason="misleading"),
        replace(probe, duration_ms=0),
        replace(probe, duration_ms=10_001),
    ):
        changed = replace(
            envelope,
            observations=(
                replace(
                    envelope.observations[0],
                    probes=(changed_probe, *envelope.observations[0].probes[1:]),
                ),
                envelope.observations[1],
            ),
        )
        with pytest.raises(ContractViolationError):
            _ = validate_parity_envelope(DeploymentContract.canonical(), _seal(changed))


def test_every_control_graph_cross_binding_mismatch_fails() -> None:
    envelope = _envelope()
    resource = envelope.observations[0].resources[0]
    changed = replace(
        envelope,
        observations=(
            replace(
                envelope.observations[0],
                resources=(
                    replace(resource, workload_graph_sha256=_digest("other")),
                    *envelope.observations[0].resources[1:],
                ),
            ),
            envelope.observations[1],
        ),
    )
    with pytest.raises(ContractViolationError, match="workload graph"):
        _ = validate_parity_envelope(DeploymentContract.canonical(), _seal(changed))


def test_environment_isolation_and_false_gvisor_claims_fail() -> None:
    envelope = _envelope()
    same_environment = replace(
        envelope,
        observations=(
            envelope.observations[0],
            replace(envelope.observations[1], environment="staging"),
        ),
    )
    with pytest.raises(ContractViolationError):
        _ = validate_parity_envelope(
            DeploymentContract.canonical(), _seal(same_environment)
        )
    contract = replace(
        DeploymentContract.canonical(), gke_gvisor_enforces_workload_seccomp=True
    )
    with pytest.raises(ContractViolationError):
        _ = validate_parity_envelope(contract, envelope)


def test_malformed_live_output_fails_closed() -> None:
    _OUTPUTS.append(b"not canonical")
    with pytest.raises(ValueError, match="malformed resource section"):
        _ = capture_live_gke()


@pytest.mark.parametrize("field", ["manifest_sha256", "image_sha256", "control_sha256"])
def test_cross_environment_parity_digest_mismatches_fail(field: str) -> None:
    """Reject each immutable deployment value when environments diverge."""
    envelope = _envelope()
    changed_observation = replace(
        envelope.observations[1], **{field: _digest(f"changed-{field}")}
    )
    changed = replace(
        envelope,
        observations=(envelope.observations[0], changed_observation),
    )
    with pytest.raises(ContractViolationError):
        _ = validate_parity_envelope(DeploymentContract.canonical(), _seal(changed))


@pytest.mark.parametrize(
    "stable_id", tuple(control.stable_id for control in CONTROL_INVENTORY)
)
def test_each_required_control_rejects_an_ineffective_status(stable_id: str) -> None:
    """Reject ineffective evidence for every independently required control."""
    envelope = _envelope()
    resources = tuple(
        replace(resource, status="ineffective")
        if resource.stable_id == stable_id
        else resource
        for resource in envelope.observations[0].resources
    )
    changed = replace(
        envelope,
        observations=(
            replace(envelope.observations[0], resources=resources),
            envelope.observations[1],
        ),
    )
    with pytest.raises(ContractViolationError):
        _ = validate_parity_envelope(DeploymentContract.canonical(), _seal(changed))


@pytest.mark.parametrize(
    "captured_at",
    [
        datetime(2000, 1, 1, tzinfo=UTC),
        datetime.now(UTC).replace(year=datetime.now(UTC).year + 1),
        datetime.now(UTC).replace(tzinfo=None),
    ],
)
def test_capture_proof_freshness_and_utc_failures_are_rejected(
    captured_at: datetime,
) -> None:
    """Reject stale, future, and naive capture proof timestamps."""
    envelope = _envelope()
    proof = envelope.observations[0].capture_proof
    assert proof is not None
    changed = replace(
        envelope,
        observations=(
            replace(
                envelope.observations[0],
                capture_proof=replace(proof, captured_at_utc=captured_at),
            ),
            envelope.observations[1],
        ),
    )
    with pytest.raises(ContractViolationError):
        _ = validate_parity_envelope(DeploymentContract.canonical(), _seal(changed))
