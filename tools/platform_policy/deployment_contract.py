"""Fail-closed, two-environment GKE deployment qualification contract."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Protocol, override

from tools.platform_policy.deployment_capture import (
    EXPECTED_COLLECTOR_ID,
    EXPECTED_COLLECTOR_VERSION,
    CaptureProof,
    LiveCapture,
    WorkloadIdentity,
    canonical_utc_timestamp,
    is_durably_verified,
    workload_graph_sha256,
)

SHA256_LENGTH: Final = 64
MAX_CAPTURE_AGE: Final = timedelta(minutes=15)
MAX_PROBE_DURATION_MS: Final = 10_000
STAGING: Final = "staging"
PRODUCTION: Final = "production"
ENVIRONMENT_COUNT: Final = 2
ENVIRONMENTS: Final = (STAGING, PRODUCTION)


type CaptureIdentity = tuple[str, str, str]


class ReleaseQualificationAuthority(Protocol):
    """Atomically bind and consume coordinator-issued release challenges."""

    def consume(
        self,
        challenge_id: str,
        evidence_sha256: str,
        captures: tuple[CaptureIdentity, ...],
    ) -> bool:
        """Return whether exact expected captures consumed the challenge once."""
        ...


class CaptureKind(StrEnum):
    """Identify whether an observation is synthetic or captured live."""

    SYNTHETIC_CONTRACT_FIXTURE = "synthetic_contract_fixture"
    CAPTURED_LIVE_GKE = "captured_live_gke"


class ProbeOutcome(StrEnum):
    """Represent the only conclusive probe outcome accepted by the contract."""

    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class ContractViolationError(ValueError):
    """Describe a fail-closed deployment contract validation failure."""

    reason: str

    @override
    def __str__(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class ControlRequirement:
    """Identify one required deployed control and Kubernetes kind."""

    stable_id: str
    kind: str


CONTROL_INVENTORY: Final[tuple[ControlRequirement, ...]] = (
    ControlRequirement("runtime-class-gvisor", "RuntimeClass"),
    ControlRequirement("sandbox-pod-runtime-class-binding", "Pod"),
    ControlRequirement("sandbox-node-scheduling", "Pod"),
    ControlRequirement("sandbox-node-pool", "NodePool"),
    ControlRequirement("control-plane-isolation", "NetworkPolicy"),
    ControlRequirement("workload-egress-selector", "NetworkPolicy"),
    ControlRequirement("workload-identity-pool", "Cluster"),
    ControlRequirement("workload-identity-ksa-gsa", "ServiceAccount"),
    ControlRequirement("workload-identity-iam-binding", "IAMPolicyBinding"),
    ControlRequirement("workload-identity-token-behavior", "Pod"),
    ControlRequirement("network-default-deny", "NetworkPolicy"),
    ControlRequirement("network-allowed-egress", "NetworkPolicy"),
    ControlRequirement("resource-quota", "ResourceQuota"),
    ControlRequirement("admission-signed-pinned-image", "ValidatingAdmissionPolicy"),
    ControlRequirement("host-path-mount-forbidden", "Pod"),
    ControlRequirement("runtime-socket-mount-forbidden", "Pod"),
)
EFFECTIVE_REQUIREMENTS: Final[dict[str, tuple[str, str]]] = {
    "runtime-class-gvisor": ("handler=gvisor", "ready"),
    "sandbox-pod-runtime-class-binding": (
        "runtimeClassName=gvisor-runtimeclass",
        "ready",
    ),
    "sandbox-node-scheduling": ("nodeSelector=sandbox", "scheduled-sandbox"),
    "sandbox-node-pool": ("sandboxEnabled=true", "ready"),
    "control-plane-isolation": ("controlPlaneIsolated=true", "enforced"),
    "workload-egress-selector": ("workloadSelector=sandbox", "enforced"),
    "workload-identity-pool": ("workloadPool=", "enabled"),
    "workload-identity-ksa-gsa": ("iam.gke.io/gcp-service-account=", "bound"),
    "workload-identity-iam-binding": ("roles/iam.workloadIdentityUser", "bound"),
    "workload-identity-token-behavior": (
        "automountServiceAccountToken=false",
        "metadata-token-verified",
    ),
    "network-default-deny": ("policyTypes=Egress", "default-deny"),
    "network-allowed-egress": (
        "allowedHosts=artifact-registry.googleapis.com,logging.googleapis.com",
        "enforced",
    ),
    "resource-quota": ("hard=", "enforced"),
    "admission-signed-pinned-image": ("signed=true;digestPinned=true", "enforced"),
    "host-path-mount-forbidden": ("hostPath=false", "validated"),
    "runtime-socket-mount-forbidden": ("runtimeSocketMount=false", "validated"),
}
# Vector fields: target, test vector, transport, result, rejection reason.
PROBE_POLICY: Final[dict[str, tuple[str, str, str, str, str]]] = {
    "filesystem-denial": (
        "file:///proc/1/root",
        "open-read-proc-root-v1",
        "exec",
        "EACCES",
        "filesystem-permission-denied",
    ),
    "secret-denial": (
        "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
        "read-service-account-token-v1",
        "exec",
        "EACCES",
        "secret-mount-denied",
    ),
    "metadata-denial": (
        "http://metadata.google.internal/computeMetadata/v1/",
        "get-gce-metadata-v1",
        "http",
        "HTTP_403",
        "metadata-access-denied",
    ),
    "private-network-denial": (
        "tcp://10.0.0.1:443",
        "connect-private-network-v1",
        "tcp",
        "ECONNREFUSED",
        "private-network-denied",
    ),
    "control-plane-denial": (
        "https://kubernetes.default.svc/api",
        "get-kubernetes-api-v1",
        "http",
        "HTTP_403",
        "control-plane-denied",
    ),
    "egress-denial": (
        "https://example.invalid/",
        "connect-unallowlisted-egress-v1",
        "http",
        "HTTP_403",
        "egress-policy-denied",
    ),
}
DENIAL_OUTCOME_IDS: Final[tuple[str, ...]] = tuple(PROBE_POLICY)


@dataclass(frozen=True, slots=True)
class DeploymentContract:
    """Describe the immutable deployment qualification policy."""

    version: str
    controls: tuple[ControlRequirement, ...]
    gke_gvisor_enforces_workload_seccomp: bool
    gke_gvisor_enforces_workload_no_new_privileges: bool

    @classmethod
    def canonical(cls) -> DeploymentContract:
        """Return the only accepted deployment contract."""
        return cls(
            version="deployment-contract-v3",
            controls=CONTROL_INVENTORY,
            gke_gvisor_enforces_workload_seccomp=False,
            gke_gvisor_enforces_workload_no_new_privileges=False,
        )


@dataclass(frozen=True, slots=True)
class RenderedDesiredStateObservation:
    """Bind a synthetic rendered manifest to its digest."""

    manifest_sha256: str
    capture_kind: CaptureKind


@dataclass(frozen=True, slots=True)
class ResourceObservation:
    """Represent one observed workload control resource."""

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
class ProbeAttempt:
    """Represent one exact observed policy-denial probe."""

    vector: str
    environment: str
    run_id: str
    cluster_uid: str
    attempted_at_utc: datetime
    executor: str
    target_sha256: str
    test_vector_sha256: str
    transport: str
    result_code: str
    duration_ms: int
    outcome: ProbeOutcome
    policy_reason: str
    raw_sha256: str


@dataclass(frozen=True, slots=True)
class EnvironmentObservation:
    """Represent the deployment evidence collected from one environment."""

    environment: str
    manifest_sha256: str
    image_sha256: str
    environment_sha256: str
    control_sha256: str
    resources: tuple[ResourceObservation, ...]
    probes: tuple[ProbeAttempt, ...]
    capture_proof: CaptureProof | None
    capture_kind: CaptureKind


@dataclass(frozen=True, slots=True)
class NamedChecksum:
    """Associate a scientific output name with its SHA-256 digest."""

    name: str
    sha256: str


@dataclass(frozen=True, slots=True)
class OutputWatcherReceipt:
    """Identify the independent output watcher receipt."""

    registration_id: str
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class ParityEnvelope:
    """Bind desired state, live observations, and scientific output parity."""

    contract_sha256: str
    corpus_sha256: str
    input_sha256: str
    desired_state: RenderedDesiredStateObservation
    observations: tuple[EnvironmentObservation, ...]
    local_scientific_output_checksums: tuple[NamedChecksum, ...]
    gke_scientific_output_checksums: tuple[NamedChecksum, ...]
    output_watcher_receipt: OutputWatcherReceipt
    release_challenge_id: str
    evidence_sha256: str


def observation_from_live_capture(capture: LiveCapture) -> EnvironmentObservation:
    """Convert parsed fixed-collector evidence into an environment observation."""
    proof = capture.proof
    return EnvironmentObservation(
        proof.environment,
        proof.deployed_manifest_sha256,
        proof.deployed_image_sha256,
        proof.deployed_environment_sha256,
        proof.deployed_control_sha256,
        tuple(
            ResourceObservation(
                r.stable_id,
                r.kind,
                r.name,
                r.uid,
                r.generation,
                r.spec,
                r.status,
                r.workload_graph_sha256,
                r.source_sha256,
            )
            for r in capture.resources
        ),
        tuple(
            ProbeAttempt(
                p.vector,
                proof.environment,
                proof.run_id,
                proof.cluster_uid,
                p.attempted_at_utc,
                p.executor,
                p.target_sha256,
                p.test_vector_sha256,
                p.transport,
                p.result_code,
                p.duration_ms,
                ProbeOutcome(p.outcome),
                p.policy_reason,
                p.raw_sha256,
            )
            for p in capture.probes
        ),
        proof,
        CaptureKind.CAPTURED_LIVE_GKE,
    )


def validate_contract(contract: DeploymentContract) -> DeploymentContract:
    """Return the canonical contract or raise for any policy drift."""
    if contract != DeploymentContract.canonical():
        msg = "deployment contract differs from canonical contract"
        raise _violation(msg)
    return contract


def canonical_contract_sha256(contract: DeploymentContract) -> str:
    """Return the canonical digest of the accepted deployment contract."""
    _ = validate_contract(contract)
    return _digest_fields(
        (
            contract.version,
            *(field for c in contract.controls for field in (c.stable_id, c.kind)),
            str(contract.gke_gvisor_enforces_workload_seccomp),
            str(contract.gke_gvisor_enforces_workload_no_new_privileges),
        )
    )


def validate_parity_envelope(
    contract: DeploymentContract, envelope: ParityEnvelope
) -> ParityEnvelope:
    """Return a fully validated two-environment deployment evidence envelope."""
    _ = validate_contract(contract)
    if (
        envelope.desired_state.capture_kind
        is not CaptureKind.SYNTHETIC_CONTRACT_FIXTURE
    ):
        msg = "rendered desired state must be synthetic"
        raise _violation(msg)
    _sha("manifest_sha256", envelope.desired_state.manifest_sha256)
    if envelope.contract_sha256 != canonical_contract_sha256(contract):
        msg = "contract digest must bind canonical contract"
        raise _violation(msg)
    _sha("corpus_sha256", envelope.corpus_sha256)
    if not envelope.release_challenge_id:
        msg = "release qualification requires a coordinator challenge"
        raise _violation(msg)
    _sha("input_sha256", envelope.input_sha256)
    _validate_observation_pair(envelope)
    _checksums("local scientific output", envelope.local_scientific_output_checksums)
    _checksums("GKE scientific output", envelope.gke_scientific_output_checksums)
    if (
        envelope.local_scientific_output_checksums
        != envelope.gke_scientific_output_checksums
    ):
        msg = "local and GKE scientific output checksums must match"
        raise _violation(msg)
    if not envelope.output_watcher_receipt.registration_id:
        msg = "Output Watcher receipt requires a registration identifier"
        raise _violation(msg)
    _sha("Output Watcher receipt", envelope.output_watcher_receipt.receipt_sha256)
    if envelope.evidence_sha256 != canonical_evidence_sha256(envelope):
        msg = "parity envelope evidence SHA-256 does not match"
        raise _violation(msg)
    return envelope


def is_release_qualified(
    contract: DeploymentContract,
    envelope: ParityEnvelope,
    authority: ReleaseQualificationAuthority,
) -> bool:
    """Verify captures and atomically consume their coordinator challenge."""
    _ = validate_parity_envelope(contract, envelope)
    proofs = tuple(observation.capture_proof for observation in envelope.observations)
    if any(proof is None for proof in proofs) or not all(
        observation.capture_kind is CaptureKind.CAPTURED_LIVE_GKE
        and proof is not None
        and is_durably_verified(proof)
        for observation, proof in zip(envelope.observations, proofs, strict=True)
    ):
        return False
    captures = tuple(
        (proof.environment, proof.run_id, proof.nonce)
        for proof in proofs
        if proof is not None
    )
    return authority.consume(
        envelope.release_challenge_id,
        envelope.evidence_sha256,
        captures,
    )


def canonical_evidence_sha256(envelope: ParityEnvelope) -> str:
    """Return the deterministic digest of all parity envelope evidence."""
    fields = (
        envelope.contract_sha256,
        envelope.corpus_sha256,
        envelope.input_sha256,
        envelope.release_challenge_id,
        envelope.desired_state.manifest_sha256,
        envelope.desired_state.capture_kind.value,
    )
    for o in envelope.observations:
        fields += _observation_fields(o)
    for c in (
        envelope.local_scientific_output_checksums
        + envelope.gke_scientific_output_checksums
    ):
        fields += (c.name, c.sha256)
    return _digest_fields(
        (
            *fields,
            envelope.output_watcher_receipt.registration_id,
            envelope.output_watcher_receipt.receipt_sha256,
        )
    )


def _validate_observation_pair(envelope: ParityEnvelope) -> None:
    if len(envelope.observations) != ENVIRONMENT_COUNT:
        msg = "staging and production observations are both required"
        raise _violation(msg)
    by_environment = {o.environment: o for o in envelope.observations}
    if (
        tuple(by_environment) != ENVIRONMENTS
        or len(by_environment) != ENVIRONMENT_COUNT
    ):
        msg = "observations must identify one staging and one production environment"
        raise _violation(msg)
    staging, production = by_environment[STAGING], by_environment[PRODUCTION]
    _validate_observation(envelope, staging)
    _validate_observation(envelope, production)
    if (staging.manifest_sha256, staging.image_sha256, staging.control_sha256) != (
        production.manifest_sha256,
        production.image_sha256,
        production.control_sha256,
    ):
        msg = "staging and production manifest, image, and controls must match"
        raise _violation(msg)
    if staging.environment_sha256 == production.environment_sha256:
        msg = "environment digests must remain explicitly distinct"
        raise _violation(msg)
    if (
        staging.capture_proof
        and production.capture_proof
        and (
            staging.capture_proof.cluster_uid == production.capture_proof.cluster_uid
            or staging.capture_proof.nonce == production.capture_proof.nonce
        )
    ):
        msg = "staging and production capture identities must be distinct"
        raise _violation(msg)


def _validate_observation(
    envelope: ParityEnvelope, observation: EnvironmentObservation
) -> None:
    for name, digest in (
        ("manifest_sha256", observation.manifest_sha256),
        ("image_sha256", observation.image_sha256),
        ("environment_sha256", observation.environment_sha256),
        ("control_sha256", observation.control_sha256),
    ):
        _sha(name, digest)
    if observation.manifest_sha256 != envelope.desired_state.manifest_sha256:
        msg = "captured manifest must bind rendered desired state"
        raise _violation(msg)
    proof = observation.capture_proof
    if observation.capture_kind is CaptureKind.CAPTURED_LIVE_GKE:
        if proof is None:
            msg = "live observation requires a detached-signature capture proof"
            raise _violation(msg)
        _validate_proof(proof, observation, envelope)
    elif proof is not None:
        msg = "synthetic observation cannot carry a live capture proof"
        raise _violation(msg)
    _resources(observation.resources, proof)
    _probes(observation, proof)
    if proof is not None:
        _validate_record_binding(proof, observation)


def _validate_proof(
    proof: CaptureProof, o: EnvironmentObservation, envelope: ParityEnvelope
) -> None:
    if (
        proof.collector_id != EXPECTED_COLLECTOR_ID
        or proof.collector_version != EXPECTED_COLLECTOR_VERSION
    ):
        msg = "capture proof collector identity or version is not permitted"
        raise _violation(msg)
    if proof.environment != o.environment or not all(
        (
            proof.project_id,
            proof.cluster_name,
            proof.location,
            proof.cluster_uid,
            proof.run_id,
            proof.nonce,
        )
    ):
        msg = "capture proof identity is incomplete or relabelled"
        raise _violation(msg)
    now = datetime.now(UTC)
    if (
        proof.captured_at_utc.tzinfo is None
        or proof.captured_at_utc.utcoffset() != timedelta(0)
        or proof.captured_at_utc > now
        or now - proof.captured_at_utc > MAX_CAPTURE_AGE
    ):
        msg = "capture proof is stale or not UTC"
        raise _violation(msg)
    for name, digest in (
        ("workload graph", proof.workload_graph_sha256),
        ("raw inventory", proof.raw_inventory_sha256),
        ("raw probe", proof.raw_probe_sha256),
        ("manifest", proof.deployed_manifest_sha256),
        ("image", proof.deployed_image_sha256),
        ("environment", proof.deployed_environment_sha256),
        ("controls", proof.deployed_control_sha256),
        ("corpus", proof.corpus_sha256),
        ("input", proof.input_sha256),
        ("watcher receipt", proof.watcher_receipt_sha256),
        ("scientific output checksum set", proof.scientific_output_checksum_set_sha256),
        ("resource records", proof.resource_records_sha256),
        ("probe records", proof.probe_records_sha256),
        ("normalized evidence", proof.normalized_evidence_sha256),
    ):
        _sha(name, digest)
    expected_graph = workload_graph_sha256(
        WorkloadIdentity(
            proof.project_id,
            proof.cluster_name,
            proof.location,
            proof.cluster_uid,
            proof.environment,
            proof.run_id,
            proof.deployed_manifest_sha256,
            proof.deployed_image_sha256,
        )
    )
    if proof.workload_graph_sha256 != expected_graph:
        msg = "capture proof workload graph is not identity-bound"
        raise _violation(msg)
    if (
        proof.deployed_manifest_sha256,
        proof.deployed_image_sha256,
        proof.deployed_environment_sha256,
        proof.deployed_control_sha256,
        proof.corpus_sha256,
        proof.input_sha256,
        proof.watcher_receipt_sha256,
        proof.watcher_registration_id,
        proof.scientific_output_checksum_set_sha256,
    ) != (
        o.manifest_sha256,
        o.image_sha256,
        o.environment_sha256,
        o.control_sha256,
        envelope.corpus_sha256,
        envelope.input_sha256,
        envelope.output_watcher_receipt.receipt_sha256,
        envelope.output_watcher_receipt.registration_id,
        _checksum_set_sha256(envelope.gke_scientific_output_checksums),
    ):
        msg = "capture proof does not bind parity envelope values"
        raise _violation(msg)


def _validate_record_binding(proof: CaptureProof, o: EnvironmentObservation) -> None:
    resource = _digest_fields(
        tuple(
            v
            for r in o.resources
            for v in (
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
    probes = _digest_fields(
        tuple(
            v
            for p in o.probes
            for v in (
                p.vector,
                canonical_utc_timestamp(p.attempted_at_utc),
                p.executor,
                p.target_sha256,
                p.test_vector_sha256,
                p.transport,
                p.result_code,
                str(p.duration_ms),
                p.policy_reason,
                p.outcome.value,
                p.raw_sha256,
            )
        )
    )
    if (
        resource != proof.resource_records_sha256
        or probes != proof.probe_records_sha256
    ):
        msg = "observations do not match sealed captured records"
        raise _violation(msg)


def _resources(
    resources: tuple[ResourceObservation, ...], proof: CaptureProof | None
) -> None:
    if tuple(r.stable_id for r in resources) != tuple(
        c.stable_id for c in CONTROL_INVENTORY
    ):
        msg = "required resource evidence is missing, duplicate, unknown, or reordered"
        raise _violation(msg)
    kinds = {c.stable_id: c.kind for c in CONTROL_INVENTORY}
    for r in resources:
        if (
            r.kind != kinds[r.stable_id]
            or not all((r.name, r.uid, r.spec, r.status))
            or r.generation < 1
        ):
            msg = "resource evidence is unknown or ineffective"
            raise _violation(msg)
        _sha("resource source", r.source_sha256)
        _sha("resource workload graph", r.workload_graph_sha256)
        if r.status != EFFECTIVE_REQUIREMENTS[r.stable_id][1]:
            msg = "resource evidence is ineffective"
            raise _violation(msg)
        _validate_resource_attributes(r.stable_id, _resource_attributes(r.spec), proof)
        if proof is not None and r.workload_graph_sha256 != proof.workload_graph_sha256:
            msg = "resource is not bound to the signed workload graph"
            raise _violation(msg)


def _resource_attributes(spec: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for part in spec.split(";"):
        key, separator, value = part.partition("=")
        if (
            not separator
            or not key
            or not value
            or key in attrs
            or not key.replace("_", "").isalnum()
        ):
            msg = "resource schema is malformed or ambiguous"
            raise _violation(msg)
        attrs[key] = value
    return attrs


def _validate_resource_attributes(
    stable_id: str, attrs: dict[str, str], proof: CaptureProof | None
) -> None:
    required = {
        "runtime-class-gvisor": {"handler": "gvisor"},
        "sandbox-pod-runtime-class-binding": {
            "runtimeClassName": "gvisor-runtimeclass"
        },
        "sandbox-node-scheduling": {"nodeSelector": "sandbox"},
        "sandbox-node-pool": {"sandboxEnabled": "true"},
        "control-plane-isolation": {"controlPlaneIsolated": "true"},
        "workload-egress-selector": {"workloadSelector": "sandbox"},
        "workload-identity-pool": {"workloadPool": ""},
        "workload-identity-ksa-gsa": {"gcpServiceAccount": ""},
        "workload-identity-iam-binding": {"role": "roles/iam.workloadIdentityUser"},
        "workload-identity-token-behavior": {"automountServiceAccountToken": "false"},
        "network-default-deny": {"policyTypes": "Egress"},
        "network-allowed-egress": {
            "allowedHosts": "artifact-registry.googleapis.com,logging.googleapis.com"
        },
        "resource-quota": {"hard": "pods"},
        "admission-signed-pinned-image": {"signed": "true", "digestPinned": "true"},
        "host-path-mount-forbidden": {"hostPath": "false"},
        "runtime-socket-mount-forbidden": {"runtimeSocketMount": "false"},
    }[stable_id]
    if set(attrs) != set(required):
        msg = "resource schema has unknown, duplicate, or missing attributes"
        raise _violation(msg)
    if any(
        (bool(value) and attrs[key] != value) or not attrs[key]
        for key, value in required.items()
    ):
        msg = "resource evidence is ineffective"
        raise _violation(msg)
    if (
        proof
        and stable_id == "workload-identity-pool"
        and attrs["workloadPool"] != f"{proof.project_id}.svc.id.goog"
    ):
        msg = "workload identity pool is not bound to the proof project"
        raise _violation(msg)
    if (
        proof
        and stable_id == "workload-identity-ksa-gsa"
        and not attrs["gcpServiceAccount"].endswith(
            f"@{proof.project_id}.iam.gserviceaccount.com"
        )
    ):
        msg = "workload identity GSA is not bound to the proof project"
        raise _violation(msg)


def _probes(o: EnvironmentObservation, proof: CaptureProof | None) -> None:
    if tuple(p.vector for p in o.probes) != DENIAL_OUTCOME_IDS:
        msg = "required probe evidence is missing, duplicate, unknown, or reordered"
        raise _violation(msg)
    for p in o.probes:
        if (
            p.environment != o.environment
            or not all((p.executor, p.policy_reason, p.run_id, p.cluster_uid))
            or p.outcome is not ProbeOutcome.DENIED
        ):
            msg = "probe outcome is not a captured policy denial"
            raise _violation(msg)
        if (
            p.attempted_at_utc.tzinfo is None
            or p.attempted_at_utc.utcoffset() != timedelta(0)
        ):
            msg = "probe time is invalid or inconclusive"
            raise _violation(msg)
        _sha("probe target", p.target_sha256)
        _sha("probe test vector", p.test_vector_sha256)
        _sha("probe raw", p.raw_sha256)
        target, test, transport, result, reason = PROBE_POLICY[p.vector]
        if (
            p.target_sha256,
            p.test_vector_sha256,
            p.transport,
            p.result_code,
            p.policy_reason,
        ) != (_sha256(target), _sha256(test), transport, result, reason):
            msg = "probe semantics are ambiguous, mismatched, or inconclusive"
            raise _violation(msg)
        if not 0 < p.duration_ms <= MAX_PROBE_DURATION_MS:
            msg = "probe duration is invalid or inconclusive"
            raise _violation(msg)
        if proof:
            if p.run_id != proof.run_id or p.cluster_uid != proof.cluster_uid:
                msg = "probe is not bound to the captured run and cluster"
                raise _violation(msg)
            if (
                p.attempted_at_utc > proof.captured_at_utc
                or proof.captured_at_utc - p.attempted_at_utc > MAX_CAPTURE_AGE
            ):
                msg = "probe time is outside the capture session"
                raise _violation(msg)


def _checksums(scope: str, values: tuple[NamedChecksum, ...]) -> None:
    if not values or len({v.name for v in values}) != len(values):
        msg = f"{scope} checksums must be non-empty and unique"
        raise _violation(msg)
    for v in values:
        if not v.name:
            msg = f"{scope} checksum name must not be empty"
            raise _violation(msg)
        _sha(f"{scope} checksum", v.sha256)


def _observation_fields(o: EnvironmentObservation) -> tuple[str, ...]:
    fields = (
        o.environment,
        o.manifest_sha256,
        o.image_sha256,
        o.environment_sha256,
        o.control_sha256,
        o.capture_kind.value,
    )
    for r in o.resources:
        fields += (
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
    for p in o.probes:
        fields += (
            p.vector,
            p.environment,
            p.run_id,
            p.cluster_uid,
            canonical_utc_timestamp(p.attempted_at_utc),
            p.executor,
            p.target_sha256,
            p.test_vector_sha256,
            p.transport,
            p.result_code,
            str(p.duration_ms),
            p.outcome.value,
            p.policy_reason,
            p.raw_sha256,
        )
    if o.capture_proof:
        proof = o.capture_proof
        fields += (
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
            proof.attestation,
        )
    return fields


def _checksum_set_sha256(values: tuple[NamedChecksum, ...]) -> str:
    return _digest_fields(tuple(f for v in values for f in (v.name, v.sha256)))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _sha(name: str, digest: str) -> None:
    if len(digest) != SHA256_LENGTH or any(c not in "0123456789abcdef" for c in digest):
        msg = f"{name} must be a lowercase SHA-256 hex digest"
        raise _violation(msg)


def _digest_fields(fields: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for field in fields:
        encoded = field.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _violation(reason: str) -> ContractViolationError:
    return ContractViolationError(reason)
