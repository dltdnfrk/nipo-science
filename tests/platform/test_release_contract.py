"""Adversarial contract tests for the trusted G006 finalization boundary."""

from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError
from tools.platform_policy.ci_contract import load_checked_in_ci_catalog
from tools.platform_policy.release_contract import (
    CI_JOB_CATEGORIES,
    NFR_REQUIREMENT_IDS,
    REQUIRED_EXTERNAL_BINDINGS,
    REQUIRED_EXTERNAL_CONTROL_IDS,
    AttachmentEvidence,
    ClaimKind,
    CleanupEvidence,
    ControlEvidence,
    DetachedEvidenceSeal,
    EvidenceIssuerTrust,
    ExternalEvidence,
    FinalizationTrust,
    FinalizedReleaseEnvelope,
    FrozenAuthority,
    JsonValue,
    ManualQaEvidence,
    MeasurementValue,
    NfrObservation,
    NfrRequirementId,
    ReleaseContractError,
    ReleaseFinalizationContext,
    ReleaseFinalizer,
    ReleaseReceipt,
    ReleaseSnapshotLease,
    ReviewEvidence,
    SiblingRoots,
    StrictModel,
    canonical_bytes,
    sha256_bytes,
    sibling_tree_sha256,
    source_tree_sha256,
    tree_sha256,
    verify_and_finalize_success,
    verify_finalized_release_document,
    verify_finalized_release_envelope,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Literal

    from tools.platform_policy.ci_contract import CiControlCatalog

FINALIZED_AT = "2026-07-14T12:00:00Z"
KEY = b"test-only-finalization-key-not-serialized"


@dataclass(frozen=True)
class _HmacAuthority:
    """Pinned test-only runtime authority; no key material enters a document."""

    authority_id: str = "test-finalizer"
    key_id: str = "test-key-1"
    algorithm: str = "HMAC-SHA256"
    authority_version: str = "1"
    environment: Literal["test"] = "test"
    key: bytes = KEY

    def sign(self, payload: bytes) -> bytes:
        return hmac.digest(self.key, payload, "sha256")

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)

    def issue_finalization(self) -> tuple[str, str]:
        return FINALIZED_AT, "signer-issued-finalization-nonce-0001"


@dataclass(frozen=True)
class _HmacIssuer:
    issuer_id: str
    key: bytes = KEY

    def sign(self, payload: bytes) -> bytes:
        return hmac.digest(self.key, payload, "sha256")

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


@dataclass
class _AuthorizationAuthority:
    authority_id: str = "test-release-authorization"
    trust_domain: str = "test-release-authorization-v1"
    bindings: dict[tuple[str, str], str] = field(default_factory=dict)
    consumed: set[tuple[str, str, str, str]] = field(default_factory=set)

    def bind(self, session_id: str, lease_generation: str, payload_sha256: str) -> None:
        self.bindings[(session_id, lease_generation)] = payload_sha256

    def consume(
        self, session_id: str, lease_generation: str, payload_sha256: str, nonce: str
    ) -> bool:
        key = (session_id, lease_generation, payload_sha256, nonce)
        if (
            self.bindings.get((session_id, lease_generation)) != payload_sha256
            or key in self.consumed
        ):
            return False
        self.consumed.add(key)
        return True


def _without_seals(value: JsonValue) -> JsonValue:
    """Remove detached seal fields from recursively typed fixture claim data."""
    if isinstance(value, dict):
        return {
            key: _without_seals(item)
            for key, item in value.items()
            if key not in {"seal", "revision_anchor_seal", "external_anchor_seal"}
        }
    if isinstance(value, list):
        return [_without_seals(item) for item in value]
    return value


def _seal(
    claim: StrictModel, kind: ClaimKind, receipt: ReleaseReceipt, issuer: _HmacIssuer
) -> DetachedEvidenceSeal:
    claim_hash = sha256_bytes(
        canonical_bytes(_without_seals(claim.canonical_projection()))
    )
    unsigned = DetachedEvidenceSeal(
        claim_kind=kind,
        issuer_id=issuer.issuer_id,
        release_id=receipt.release_id,
        run_id=receipt.run_id,
        attempt_id=receipt.attempt_id,
        source_tree_sha256=receipt.authority.source_tree_sha256,
        verified_revision=receipt.authority.verified_revision,
        requirements_sha256=receipt.authority.requirements_sha256,
        goals_sha256=receipt.authority.goals_sha256,
        goals_state_revision=receipt.authority.goals_state_revision,
        session_id=receipt.authority.session_id,
        lease_generation=receipt.authority.lease_generation,
        command_catalog_sha256=receipt.authority.command_catalog_sha256,
        toolchain_sha256=receipt.authority.toolchain_sha256,
        issued_at_utc="2026-07-14T11:59:00Z",
        claim_sha256=claim_hash,
        signature_b64="unsigned-test-seal",
    )
    signature = base64.b64encode(
        issuer.sign(
            canonical_bytes(unsigned.canonical_projection(exclude={"signature_b64"}))
        )
    ).decode("ascii")
    return unsigned.model_copy(update={"signature_b64": signature})


def _issuer(trust: FinalizationTrust, kind: ClaimKind) -> _HmacIssuer:
    binding = next(item for item in trust.evidence_issuers if item.claim_kind == kind)
    issuer = binding.issuer
    if not isinstance(issuer, _HmacIssuer):
        msg = "test fixture issuer is not HMAC-backed"
        raise TypeError(msg)
    return issuer


def _reseal_receipt_anchors(
    receipt: ReleaseReceipt, trust: FinalizationTrust
) -> ReleaseReceipt:
    unsigned = receipt.model_copy(
        update={"revision_anchor_seal": None, "external_anchor_seal": None}
    )
    return unsigned.model_copy(
        update={
            "revision_anchor_seal": _seal(
                unsigned,
                ClaimKind.REVISION_ANCHOR,
                unsigned,
                _issuer(trust, ClaimKind.REVISION_ANCHOR),
            ),
            "external_anchor_seal": _seal(
                unsigned,
                ClaimKind.EXTERNAL_ANCHOR,
                unsigned,
                _issuer(trust, ClaimKind.EXTERNAL_ANCHOR),
            ),
        }
    )


@dataclass
class _TestSnapshotAuthority:
    root: Path
    session_id: str = "canonical"

    def acquire(self) -> ReleaseSnapshotLease:
        root = self.root
        if (
            not root.is_absolute()
            or root.is_symlink()
            or root.name != "science-workbench"
        ):
            msg = "test snapshot root is not canonical"
            raise ReleaseContractError(msg)
        parent = root.parent
        context = ReleaseFinalizationContext(
            science_root=root,
            drylab_root=parent / "drylab",
            ontologylab_root=parent / "ontologylab",
            requirements_path=root / "docs/requirements/requirements.yaml",
            goals_path=parent / f".gjc/_session-{self.session_id}/ultragoal/goals.json",
            evidence_root=root / "artifacts/ulw-g006",
            command_catalog_path=root / ".ci/ci-contract.json",
            dependency_path=root / "uv.lock",
            fixture_path=root / "artifacts/ulw-g006/fixture.json",
            toolchain_path=root / "pyproject.toml",
            revision_anchor_path=root / "artifacts/ulw-g006/revision-anchor.json",
            external_anchor_path=root / "artifacts/ulw-g006/external-anchor.json",
        )
        return ReleaseSnapshotLease(context, self.session_id)

    def verify(self, lease: ReleaseSnapshotLease) -> None:
        if lease.context.science_root != self.root or lease.revision != self.session_id:
            msg = "test snapshot lease was substituted"
            raise ReleaseContractError(msg)

    def release(self, lease: ReleaseSnapshotLease) -> None:
        _ = lease


@dataclass
class _Fixture:
    root: Path
    finalizer: ReleaseFinalizer
    receipt: ReleaseReceipt
    trust: FinalizationTrust
    evidence: Path
    issuer: _HmacAuthority
    authorization_writer: _AuthorizationAuthority

    def finalize(
        self, *, mutation_hook: Callable[[], None] | None = None
    ) -> FinalizedReleaseEnvelope:
        return self.finalizer.finalize(self.receipt, mutation_hook=mutation_hook)


def _write(path: Path, value: bytes | str) -> str:
    _ = path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_bytes(value.encode() if isinstance(value, str) else value)
    return sha256_bytes(path.read_bytes())


def _attachment(
    evidence: Path, name: str, content: bytes | str | None = None
) -> tuple[AttachmentEvidence, str]:
    value = content if content is not None else f"synthetic canonical evidence:{name}\n"
    digest = _write(evidence / name, value)
    return AttachmentEvidence(path=name, sha256=digest), digest


def _nfr_measurements(requirement_id: NfrRequirementId) -> dict[str, MeasurementValue]:
    values: dict[NfrRequirementId, dict[str, MeasurementValue]] = {
        "NFR01": {"success_percent": 99.9, "max_continuous_failure_seconds": 1},
        "NFR02": {"crud_p95_ms": 1, "error_percent": 0},
        "NFR03": {"visible_token_samples": 1, "visible_token_p95_seconds": 1},
        "NFR04": {"sandbox_allocation_p95_seconds": 1},
        "NFR05": {"checksum_mismatches": 0},
        "NFR06": {"recovery_seconds": 1, "side_effect_replays": 0},
        "NFR07": {"export_bytes": 500 * 1024 * 1024, "export_seconds": 1},
        "NFR08": {"keyboard_complete": True, "serious_wcag_violations": 0},
        "NFR09": {
            "chrome_major_versions": (124, 125),
            "chrome_latest_major": 125,
            "chrome_p0_cases": 2,
            "chrome_p0_failures": 0,
            "edge_major_versions": (124, 125),
            "edge_latest_major": 125,
            "edge_p0_cases": 2,
            "edge_p0_failures": 0,
            "safari_major_versions": (17, 18),
            "safari_latest_major": 18,
            "safari_p0_cases": 2,
            "safari_p0_failures": 0,
        },
        "NFR10": {
            "quarterly_restore_current": True,
            "rpo_minutes": 1,
            "rto_minutes": 1,
            "tombstones_replayed": True,
            "side_effect_replays": 0,
            "restore_evidence_date": "2026-07-13",
        },
    }
    return values[requirement_id]


def _security_log() -> bytes:
    case_lines = tuple(
        b"SECURITY_CASE="
        + canonical_bytes(
            {
                "case_id": f"synthetic-security-case-{index:02d}",
                "outcome": "passed",
                "threat_id": f"T{index:02d}",
            }
        )
        for index in range(1, 14)
    )
    mappings = [
        {
            "evidence_root_sha256": sha256_bytes(line),
            "job": "SECURITY",
            "positive_case_count": 1,
            "threat_id": f"T{index:02d}",
        }
        for index, line in enumerate(case_lines, start=1)
    ]
    return (
        b"13 passed\n"
        + b"".join(case_lines)
        + b"SECURITY_EVIDENCE="
        + canonical_bytes(mappings)
    )


def _build_controls(
    evidence: Path,
    attachments: list[AttachmentEvidence],
    catalog: CiControlCatalog,
    source_root: str,
    toolchain_sha256: str,
) -> list[ControlEvidence]:
    controls: list[ControlEvidence] = []
    for index, job in enumerate(catalog.jobs):
        observed_count = (
            13
            if job.job.value == "security"
            else (
                job.analyzer_inventory_count
                if job.count_kind == "analyzer-inventory"
                else 1
            )
        )
        if observed_count is None:
            msg = "analyzer inventory control must declare an observation count"
            raise ValueError(msg)
        if job.job.value == "security":
            log_content: bytes | str = _security_log()
        else:
            count_line = (
                f"CHECKS_EXECUTED={observed_count}\n"
                if job.count_kind == "checks"
                else f"{observed_count} passed\n"
            )
            log_content = f"job={job.job.value}\n{count_line}"
        log_attachment, log_hash = _attachment(
            evidence, f"controls/{index:02d}-log.txt", log_content
        )
        coverage_attachment, coverage_hash = _attachment(
            evidence, f"controls/{index:02d}-coverage.json"
        )
        attachments.extend((log_attachment, coverage_attachment))
        controls.append(
            ControlEvidence(
                control_id=job.job.value,
                category=CI_JOB_CATEGORIES[job.job],
                argv=job.argv,
                outcome="success",
                exit_code=0,
                observed_positive_count=observed_count,
                raw_log_sha256=log_hash,
                attachment_sha256=(coverage_hash,),
                requirement_ids=job.requirement_ids,
                goal_ids=(f"G{index + 1:03d}",) if index < 10 else (),
                evidence_kind="machine",
                count_kind=job.count_kind,
                parser_version=job.parser_version,
                analyzer_inventory_root_sha256=job.analyzer_inventory_root_sha256,
                catalog_root_sha256=catalog.catalog_root_sha256,
                catalog_source_root_sha256=catalog.source_root_sha256,
                catalog_run_id="canonical-run",
                release_id="G006",
                run_id="canonical-run",
                attempt_id="canonical-attempt",
                source_root_sha256=source_root,
                toolchain_sha256=toolchain_sha256,
                authority_context_id="test-runner-context",
                authority_generation_id="test-runner-generation",
                manifest_sha256=catalog.catalog_root_sha256,
                observed_epoch=29,
                coverage_sha256=coverage_hash,
            )
        )
    return controls


def _build_external_evidence(
    evidence: Path, attachments: list[AttachmentEvidence]
) -> list[ExternalEvidence]:
    external_evidence: list[ExternalEvidence] = []
    for index, control_id in enumerate(sorted(REQUIRED_EXTERNAL_CONTROL_IDS)):
        primary, primary_hash = _attachment(
            evidence, f"external/{index:02d}-attestation.json"
        )
        bound, bound_hash = _attachment(evidence, f"external/{index:02d}-binding.json")
        attachments.extend((primary, bound))
        external_evidence.append(
            ExternalEvidence(
                control_id=control_id,
                available=True,
                sha256=primary_hash,
                detail="synthetic authoritative attestation",
                requirement_ids=REQUIRED_EXTERNAL_BINDINGS[control_id][0],
                goal_ids=REQUIRED_EXTERNAL_BINDINGS[control_id][1],
                attachment_sha256=(bound_hash,),
                observed_at_utc=f"2026-07-14T10:{index:02d}:00Z",
                authority_id=f"external-{index}",
            )
        )
    return external_evidence


def _build_reviews(
    evidence: Path, attachments: list[AttachmentEvidence], source_root: str
) -> list[ReviewEvidence]:
    independent_reviews: list[ReviewEvidence] = []
    roles: tuple[Literal["code", "visual"], ...] = ("code", "visual", "visual")
    for index, role in enumerate(roles):
        review, review_hash = _attachment(evidence, f"reviews/{role}-{index}.json")
        attachments.append(review)
        captures: tuple[str, ...] = ()
        if role == "visual":
            capture, capture_hash = _attachment(evidence, f"captures/{index}.png")
            attachments.append(capture)
            captures = (capture_hash,)
        independent_reviews.append(
            ReviewEvidence(
                reviewer_id=f"reviewer-{index}",
                role=role,
                independent=True,
                decision="pass",
                blocker_count=0,
                sha256=review_hash,
                reviewed_source_sha256=source_root,
                reviewed_capture_sha256=captures,
                reviewed_at_utc=f"2026-07-14T11:0{index}:00Z",
                authority_id=f"review-{index}",
            )
        )
    return independent_reviews


def _build_nfr_observations(
    evidence: Path, attachments: list[AttachmentEvidence]
) -> list[NfrObservation]:
    observations: list[NfrObservation] = []
    for requirement_id in NFR_REQUIREMENT_IDS:
        report, report_hash = _attachment(evidence, f"nfr/{requirement_id}-report.json")
        raw, raw_hash = _attachment(evidence, f"nfr/{requirement_id}-raw.json")
        attachments.extend((report, raw))
        start = (
            "2026-07-11T12:00:00Z"
            if requirement_id == "NFR01"
            else "2026-07-14T09:00:00Z"
        )
        end = (
            "2026-07-14T12:00:00Z"
            if requirement_id == "NFR01"
            else "2026-07-14T10:00:00Z"
        )
        observations.append(
            NfrObservation(
                requirement_id=requirement_id,
                duration_seconds=259200 if requirement_id == "NFR01" else 3600,
                sample_count=6 if requirement_id == "NFR09" else 1,
                environment="synthetic",
                measurements=_nfr_measurements(requirement_id),
                report_sha256=report_hash,
                raw_data_sha256=raw_hash,
                observed_start_utc=start,
                observed_end_utc=end,
                environment_id="synthetic-env",
                workload_id="synthetic-workload",
            )
        )
    return observations


@pytest.fixture
def canonical_fixture(tmp_path: Path) -> _Fixture:
    """A complete canonical sibling topology and exact checked-in authorities."""
    parent = tmp_path / "release-parent"
    root = parent / "science-workbench"
    drylab = parent / "drylab"
    ontologylab = parent / "ontologylab"
    for directory in (root, drylab, ontologylab):
        _ = directory.mkdir(parents=True)
        _ = _write(directory / "tracked.txt", directory.name)
    repository = Path(__file__).parents[2]
    requirements = (repository / "docs/requirements/requirements.yaml").read_bytes()
    catalog = (repository / ".ci/ci-contract.json").read_bytes()
    _ = _write(root / "docs/requirements/requirements.yaml", requirements)
    _ = _write(root / ".ci/ci-contract.json", catalog)
    _ = _write(root / "uv.lock", "synthetic dependency authority\n")
    _ = _write(root / "pyproject.toml", "[project]\nname = 'synthetic'\n")
    _ = _write(root / "artifacts/ulw-g006/fixture.json", "{}\n")
    goals_path = parent / ".gjc/_session-canonical/ultragoal/goals.json"
    goals = {
        "state_revision": 29,
        "goals": [
            {
                "id": f"G{number:03d}",
                "status": "complete",
                "title": "goal",
                "objective": "synthetic durable goal",
                "createdAt": "2026-07-01T00:00:00Z",
            }
            for number in range(1, 11)
        ],
    }
    _ = _write(goals_path, canonical_bytes(goals))
    evidence = root / "artifacts/ulw-g006"
    attachments: list[AttachmentEvidence] = []

    # Build source identity before artifacts; artifacts are deliberately excluded from it.
    source_root = source_tree_sha256(root)
    revision = {
        "revision": "synthetic-clean-revision",
        "source_tree_sha256": source_root,
        "dirty": False,
    }
    _ = _write(
        root / "artifacts/ulw-g006/revision-anchor.json", canonical_bytes(revision)
    )
    _ = _write(
        root / "artifacts/ulw-g006/external-anchor.json",
        b"synthetic external anchor\n",
    )
    attachments.extend(
        AttachmentEvidence(
            path=name,
            sha256=sha256_bytes((evidence / name).read_bytes()),
        )
        for name in ("fixture.json", "revision-anchor.json", "external-anchor.json")
    )
    ci_catalog = load_checked_in_ci_catalog(root / ".ci/ci-contract.json")

    controls = _build_controls(
        evidence,
        attachments,
        ci_catalog,
        source_root,
        sha256_bytes((root / "pyproject.toml").read_bytes()),
    )
    external_evidence = _build_external_evidence(evidence, attachments)
    independent_reviews = _build_reviews(evidence, attachments, source_root)
    qa, qa_hash = _attachment(evidence, "manual-qa.json")
    cleanup, cleanup_hash = _attachment(evidence, "cleanup.json")
    attachments.extend((qa, cleanup))
    nfr_observations = _build_nfr_observations(evidence, attachments)

    receipt = ReleaseReceipt(
        release_id="G006",
        run_id="canonical-run",
        attempt_id="canonical-attempt",
        outcome="incomplete",
        authority=FrozenAuthority(
            verified_revision="synthetic-clean-revision",
            source_tree_sha256=source_root,
            dirty=False,
            requirements_sha256=sha256_bytes(requirements),
            goals_sha256=sha256_bytes(goals_path.read_bytes()),
            goals_state_revision=29,
            session_id="canonical",
            lease_generation="canonical",
            command_catalog_sha256=sha256_bytes(catalog),
            dependency_sha256=sha256_bytes((root / "uv.lock").read_bytes()),
            fixture_sha256=sha256_bytes(
                (root / "artifacts/ulw-g006/fixture.json").read_bytes()
            ),
            toolchain_sha256=sha256_bytes((root / "pyproject.toml").read_bytes()),
            revision_anchor_sha256=sha256_bytes(
                (root / "artifacts/ulw-g006/revision-anchor.json").read_bytes()
            ),
        ),
        siblings=SiblingRoots(
            science_pre_sha256=source_root,
            science_post_sha256=source_root,
            drylab_pre_sha256=sibling_tree_sha256(drylab),
            drylab_post_sha256=sibling_tree_sha256(drylab),
            ontologylab_pre_sha256=sibling_tree_sha256(ontologylab),
            ontologylab_post_sha256=sibling_tree_sha256(ontologylab),
        ),
        controls=tuple(controls),
        cleanup=CleanupEvidence(complete=True, receipt_sha256=cleanup_hash),
        external_evidence=tuple(external_evidence),
        independent_reviews=tuple(independent_reviews),
        manual_qa=ManualQaEvidence(
            performed=True,
            sha256=qa_hash,
            blocker_count=0,
            tested_source_sha256=source_root,
            performed_at_utc="2026-07-14T11:30:00Z",
            operator_id="qa",
        ),
        nfr_observations=tuple(nfr_observations),
        attachments=tuple(attachments),
        external_anchor_sha256=sha256_bytes(
            (root / "artifacts/ulw-g006/external-anchor.json").read_bytes()
        ),
    )
    issuers = {kind: _HmacIssuer(f"test-{kind.value}-issuer") for kind in ClaimKind}
    receipt = receipt.model_copy(
        update={
            "controls": tuple(
                item.model_copy(
                    update={
                        "seal": _seal(
                            item, ClaimKind.CI, receipt, issuers[ClaimKind.CI]
                        )
                    }
                )
                for item in receipt.controls
            ),
            "external_evidence": tuple(
                item.model_copy(
                    update={
                        "seal": _seal(
                            item,
                            ClaimKind.EXTERNAL,
                            receipt,
                            issuers[ClaimKind.EXTERNAL],
                        )
                    }
                )
                for item in receipt.external_evidence
            ),
            "independent_reviews": tuple(
                item.model_copy(
                    update={
                        "seal": _seal(
                            item, ClaimKind.REVIEW, receipt, issuers[ClaimKind.REVIEW]
                        )
                    }
                )
                for item in receipt.independent_reviews
            ),
            "manual_qa": receipt.manual_qa.model_copy(
                update={
                    "seal": _seal(
                        receipt.manual_qa,
                        ClaimKind.MANUAL_QA,
                        receipt,
                        issuers[ClaimKind.MANUAL_QA],
                    )
                }
            ),
            "cleanup": receipt.cleanup.model_copy(
                update={
                    "seal": _seal(
                        receipt.cleanup,
                        ClaimKind.CLEANUP,
                        receipt,
                        issuers[ClaimKind.CLEANUP],
                    )
                }
            ),
            "nfr_observations": tuple(
                item.model_copy(
                    update={
                        "seal": _seal(
                            item, ClaimKind.NFR, receipt, issuers[ClaimKind.NFR]
                        )
                    }
                )
                for item in receipt.nfr_observations
            ),
            "revision_anchor_seal": _seal(
                receipt,
                ClaimKind.REVISION_ANCHOR,
                receipt,
                issuers[ClaimKind.REVISION_ANCHOR],
            ),
            "external_anchor_seal": _seal(
                receipt,
                ClaimKind.EXTERNAL_ANCHOR,
                receipt,
                issuers[ClaimKind.EXTERNAL_ANCHOR],
            ),
        }
    )
    authority = _HmacAuthority()
    authorization = _AuthorizationAuthority()
    trust = FinalizationTrust(
        authority=authority,
        authority_id=authority.authority_id,
        key_id=authority.key_id,
        algorithm=authority.algorithm,
        authority_version=authority.authority_version,
        environment="test",
        expected_session_id="canonical",
        expected_lease_generation="canonical",
        evidence_issuers=tuple(
            EvidenceIssuerTrust(kind, issuers[kind], issuers[kind].issuer_id)
            for kind in ClaimKind
        ),
        authorization_authority=authorization,
        authorization_authority_id="test-release-authorization",
        authorization_trust_domain="test-release-authorization-v1",
    )
    return _Fixture(
        root,
        ReleaseFinalizer(_TestSnapshotAuthority(root), trust, authority, authorization),
        receipt,
        trust,
        evidence,
        authority,
        authorization,
    )


def test_canonical_fixture_finalizes_and_verifies_document(
    canonical_fixture: _Fixture,
) -> None:
    envelope = canonical_fixture.finalize()
    document = canonical_bytes(envelope)
    payload = verify_finalized_release_document(document, trust=canonical_fixture.trust)
    assert payload.receipt.outcome == "incomplete"
    assert len(payload.receipt.controls) == 27
    assert (
        len(
            {
                item
                for control in payload.receipt.controls
                for item in control.requirement_ids
            }
        )
        == 81
    )
    assert (
        len({item for control in payload.receipt.controls for item in control.goal_ids})
        == 10
    )
    assert {item.category for item in payload.receipt.controls} == set(
        CI_JOB_CATEGORIES.values()
    )
    assert len({item.category for item in payload.receipt.controls}) == 11
    assert {
        item.control_id for item in payload.receipt.external_evidence
    } == REQUIRED_EXTERNAL_CONTROL_IDS
    assert len(payload.evidence_references) == len(
        {item.sha256 for item in payload.evidence_references}
    )
    assert KEY not in document


def test_caller_finalization_epoch_is_rejected(canonical_fixture: _Fixture) -> None:
    with pytest.raises(ReleaseContractError, match="caller-owned"):
        _ = canonical_fixture.finalizer.finalize(
            canonical_fixture.receipt,
            finalized_at_utc=FINALIZED_AT,
            finalization_nonce="caller-owned-finalization-nonce",
        )


def test_ordinary_success_and_retired_api_are_rejected(
    canonical_fixture: _Fixture,
) -> None:
    with pytest.raises(ValidationError, match="failure"):
        _ = ReleaseReceipt.model_validate(
            canonical_fixture.receipt.model_copy(
                update={"outcome": "success"}
            ).model_dump()
        )
    with pytest.raises(ReleaseContractError, match="caller-owned"):
        _ = verify_and_finalize_success(
            canonical_fixture.receipt,
            context=canonical_fixture.finalizer.context(),
            authority_resolver=object(),
        )


@pytest.mark.parametrize(
    "relative",
    [
        "tracked.txt",
        "../drylab/tracked.txt",
        "../ontologylab/tracked.txt",
        "docs/requirements/requirements.yaml",
        "artifacts/ulw-g006/manual-qa.json",
    ],
)
def test_mutation_race_is_rejected(canonical_fixture: _Fixture, relative: str) -> None:
    target = canonical_fixture.root / relative
    if relative.startswith("../"):
        target = canonical_fixture.root.parent / relative[3:]

    def mutate() -> None:
        _ = target.write_text("mutated")

    with pytest.raises(ReleaseContractError, match="changed during finalization"):
        _ = canonical_fixture.finalize(mutation_hook=mutate)


def test_timestamps_must_be_real_fresh_and_not_future(
    canonical_fixture: _Fixture,
) -> None:
    external = canonical_fixture.receipt.external_evidence[0]
    for observed_at, message in (
        ("2026-02-30T10:00:00Z", "real UTC"),
        ("2026-07-21T12:00:01Z", "future or stale"),
        ("2026-07-01T12:00:00Z", "future or stale"),
    ):
        forged = external.model_copy(
            update={"observed_at_utc": observed_at, "seal": None}
        )
        forged = forged.model_copy(
            update={
                "seal": _seal(
                    forged,
                    ClaimKind.EXTERNAL,
                    canonical_fixture.receipt,
                    _issuer(canonical_fixture.trust, ClaimKind.EXTERNAL),
                )
            }
        )
        receipt = canonical_fixture.receipt.model_copy(
            update={
                "external_evidence": (
                    forged,
                    *canonical_fixture.receipt.external_evidence[1:],
                )
            }
        )
        receipt = _reseal_receipt_anchors(receipt, canonical_fixture.trust)
        with pytest.raises(ReleaseContractError, match=message):
            _ = canonical_fixture.finalizer.finalize(
                receipt,
            )


def test_typed_aliasing_and_epoch_forgery_are_rejected(
    canonical_fixture: _Fixture,
) -> None:
    manual_qa = canonical_fixture.receipt.manual_qa.model_copy(
        update={
            "sha256": canonical_fixture.receipt.controls[0].raw_log_sha256,
            "seal": None,
        }
    )
    manual_qa = manual_qa.model_copy(
        update={
            "seal": _seal(
                manual_qa,
                ClaimKind.MANUAL_QA,
                canonical_fixture.receipt,
                _issuer(canonical_fixture.trust, ClaimKind.MANUAL_QA),
            )
        }
    )
    aliased = canonical_fixture.receipt.model_copy(update={"manual_qa": manual_qa})
    aliased = _reseal_receipt_anchors(aliased, canonical_fixture.trust)
    with pytest.raises(ReleaseContractError, match="alias"):
        _ = canonical_fixture.finalizer.finalize(
            aliased,
        )
    fake_duration = canonical_fixture.receipt.nfr_observations[0].model_copy(
        update={
            "duration_seconds": 259200,
            "observed_start_utc": "2026-07-12T12:00:00Z",
        }
    )
    with pytest.raises(ValidationError, match="duration"):
        _ = type(fake_duration).model_validate(fake_duration.model_dump())
    stale_restore = canonical_fixture.receipt.nfr_observations[-1].model_copy(
        update={
            "measurements": {
                **canonical_fixture.receipt.nfr_observations[-1].measurements,
                "restore_evidence_date": "2026-04-01",
            },
            "seal": None,
        }
    )
    stale_restore = stale_restore.model_copy(
        update={
            "seal": _seal(
                stale_restore,
                ClaimKind.NFR,
                canonical_fixture.receipt,
                _issuer(canonical_fixture.trust, ClaimKind.NFR),
            )
        }
    )
    stale_receipt = canonical_fixture.receipt.model_copy(
        update={
            "nfr_observations": (
                *canonical_fixture.receipt.nfr_observations[:-1],
                stale_restore,
            )
        }
    )
    stale_receipt = _reseal_receipt_anchors(stale_receipt, canonical_fixture.trust)
    with pytest.raises(ReleaseContractError, match="current quarter"):
        _ = canonical_fixture.finalizer.finalize(stale_receipt)


def test_control_logs_external_bindings_and_sanitization_are_rederived(
    canonical_fixture: _Fixture,
) -> None:
    control = canonical_fixture.receipt.controls[2]
    forged_count = control.model_copy(
        update={
            "observed_positive_count": control.observed_positive_count + 1,
            "seal": None,
        }
    )
    forged_count = forged_count.model_copy(
        update={
            "seal": _seal(
                forged_count,
                ClaimKind.CI,
                canonical_fixture.receipt,
                _issuer(canonical_fixture.trust, ClaimKind.CI),
            )
        }
    )
    forged_controls = (
        *canonical_fixture.receipt.controls[:2],
        forged_count,
        *canonical_fixture.receipt.controls[3:],
    )
    forged_receipt = canonical_fixture.receipt.model_copy(
        update={"controls": forged_controls}
    )
    forged_receipt = _reseal_receipt_anchors(forged_receipt, canonical_fixture.trust)
    with pytest.raises(ReleaseContractError, match="derived from its log"):
        _ = canonical_fixture.finalizer.finalize(forged_receipt)

    external = canonical_fixture.receipt.external_evidence[0].model_copy(
        update={"requirement_ids": ("F01",), "seal": None}
    )
    external = external.model_copy(
        update={
            "seal": _seal(
                external,
                ClaimKind.EXTERNAL,
                canonical_fixture.receipt,
                _issuer(canonical_fixture.trust, ClaimKind.EXTERNAL),
            )
        }
    )
    external_receipt = canonical_fixture.receipt.model_copy(
        update={
            "external_evidence": (
                external,
                *canonical_fixture.receipt.external_evidence[1:],
            )
        }
    )
    external_receipt = _reseal_receipt_anchors(
        external_receipt, canonical_fixture.trust
    )
    with pytest.raises(ReleaseContractError, match="exact source-bound"):
        _ = canonical_fixture.finalizer.finalize(external_receipt)

    original = canonical_fixture.receipt.controls[0]
    attachment = next(
        item
        for item in canonical_fixture.receipt.attachments
        if item.sha256 == original.raw_log_sha256
    )
    sensitive = (
        b"Author" + b"ization: Bear" + b"er credential-material-123456\n211 passed\n"
    )
    sensitive_hash = _write(canonical_fixture.evidence / attachment.path, sensitive)
    sensitive_control = original.model_copy(
        update={"raw_log_sha256": sensitive_hash, "seal": None}
    )
    sensitive_control = sensitive_control.model_copy(
        update={
            "seal": _seal(
                sensitive_control,
                ClaimKind.CI,
                canonical_fixture.receipt,
                _issuer(canonical_fixture.trust, ClaimKind.CI),
            )
        }
    )
    sensitive_attachments = tuple(
        item.model_copy(update={"sha256": sensitive_hash})
        if item.path == attachment.path
        else item
        for item in canonical_fixture.receipt.attachments
    )
    sensitive_receipt = canonical_fixture.receipt.model_copy(
        update={
            "controls": (
                sensitive_control,
                *canonical_fixture.receipt.controls[1:],
            ),
            "attachments": sensitive_attachments,
        }
    )
    sensitive_receipt = _reseal_receipt_anchors(
        sensitive_receipt, canonical_fixture.trust
    )
    with pytest.raises(ReleaseContractError, match="sensitive bytes"):
        _ = canonical_fixture.finalizer.finalize(sensitive_receipt)


def test_topology_session_manifest_and_catalog_forgeries_are_rejected(
    canonical_fixture: _Fixture,
) -> None:
    off_topology = ReleaseFinalizer(
        _TestSnapshotAuthority(canonical_fixture.root.parent / "drylab"),
        canonical_fixture.trust,
        canonical_fixture.issuer,
        canonical_fixture.authorization_writer,
    )
    with pytest.raises(ReleaseContractError, match="snapshot root"):
        _ = off_topology.finalize(canonical_fixture.receipt)
    wrong_session = ReleaseFinalizer(
        _TestSnapshotAuthority(canonical_fixture.root, "wrong"),
        canonical_fixture.trust,
        canonical_fixture.issuer,
        canonical_fixture.authorization_writer,
    )
    with pytest.raises(ReleaseContractError, match="receipt session"):
        _ = wrong_session.finalize(
            canonical_fixture.receipt,
        )
    missing = canonical_fixture.receipt.model_copy(
        update={"attachments": canonical_fixture.receipt.attachments[:-1]}
    )
    missing = _reseal_receipt_anchors(missing, canonical_fixture.trust)
    with pytest.raises(ReleaseContractError, match="manifest"):
        _ = canonical_fixture.finalizer.finalize(
            missing,
        )
    extra_path = canonical_fixture.evidence / "extra.bin"
    _ = extra_path.write_bytes(b"extra")
    with pytest.raises(ReleaseContractError, match="manifest"):
        _ = canonical_fixture.finalize()
    extra_path.unlink()
    changed = canonical_fixture.receipt.controls[0].model_copy(
        update={"argv": ("forged",), "seal": None}
    )
    changed = changed.model_copy(
        update={
            "seal": _seal(
                changed,
                ClaimKind.CI,
                canonical_fixture.receipt,
                _issuer(canonical_fixture.trust, ClaimKind.CI),
            )
        }
    )
    changed_receipt = canonical_fixture.receipt.model_copy(
        update={
            "controls": (
                changed,
                *canonical_fixture.receipt.controls[1:],
            )
        }
    )
    changed_receipt = _reseal_receipt_anchors(changed_receipt, canonical_fixture.trust)
    with pytest.raises(ReleaseContractError, match="canonical catalog"):
        _ = canonical_fixture.finalizer.finalize(changed_receipt)
    short_receipt = canonical_fixture.receipt.model_copy(
        update={"controls": canonical_fixture.receipt.controls[:-1]}
    )
    short_receipt = _reseal_receipt_anchors(short_receipt, canonical_fixture.trust)
    with pytest.raises(ReleaseContractError, match="27-control catalog"):
        _ = canonical_fixture.finalizer.finalize(short_receipt)

    duplicate_receipt = canonical_fixture.receipt.model_copy(
        update={
            "controls": (
                *canonical_fixture.receipt.controls,
                canonical_fixture.receipt.controls[0],
            )
        }
    )
    with pytest.raises(ValidationError, match="duplicate control"):
        _ = canonical_fixture.finalizer.finalize(duplicate_receipt)


def test_envelope_payload_signature_identity_and_replay_tampering_are_rejected(
    canonical_fixture: _Fixture,
) -> None:
    envelope = canonical_fixture.finalize()
    _ = verify_finalized_release_envelope(envelope, trust=canonical_fixture.trust)
    with pytest.raises(ReleaseContractError, match="replay"):
        _ = verify_finalized_release_envelope(envelope, trust=canonical_fixture.trust)
    for update, message in (
        ({"payload_sha256": "0" * 64}, "hash"),
        ({"authority_id": "forged"}, "pinned"),
        ({"signature_b64": "AA=="}, "signature"),
    ):
        with pytest.raises(ReleaseContractError, match=message):
            _ = verify_finalized_release_envelope(
                envelope.model_copy(update=update), trust=canonical_fixture.trust
            )
    forged_payload = envelope.payload.model_copy(
        update={"finalization_nonce": "forged-payload-nonce-0001"}
    )
    with pytest.raises(ReleaseContractError, match="hash"):
        _ = verify_finalized_release_envelope(
            envelope.model_copy(update={"payload": forged_payload}),
            trust=canonical_fixture.trust,
        )
    forged_reference = envelope.payload.evidence_references[0].model_copy(
        update={"release_id": "forged-release"}
    )
    reference_payload = envelope.payload.model_copy(
        update={
            "evidence_references": (
                forged_reference,
                *envelope.payload.evidence_references[1:],
            )
        }
    )
    with pytest.raises(ReleaseContractError, match="signature"):
        _ = verify_finalized_release_envelope(
            envelope.model_copy(
                update={
                    "payload": reference_payload,
                    "payload_sha256": sha256_bytes(canonical_bytes(reference_payload)),
                }
            ),
            trust=canonical_fixture.trust,
        )
    wrong_session_trust = replace(
        canonical_fixture.trust,
        expected_session_id="other-session",
    )
    with pytest.raises(ReleaseContractError, match="complete release"):
        _ = verify_finalized_release_envelope(
            envelope,
            trust=wrong_session_trust,
        )
    wrong = _HmacAuthority(key=b"wrong")
    wrong_trust = FinalizationTrust(
        authority=wrong,
        authority_id=wrong.authority_id,
        key_id=wrong.key_id,
        algorithm=wrong.algorithm,
        authority_version=wrong.authority_version,
        environment="test",
        expected_session_id="canonical",
        expected_lease_generation="canonical",
        evidence_issuers=canonical_fixture.trust.evidence_issuers,
        authorization_authority=_AuthorizationAuthority(),
        authorization_authority_id="test-release-authorization",
        authorization_trust_domain="test-release-authorization-v1",
    )
    with pytest.raises(ReleaseContractError, match="signature"):
        _ = verify_finalized_release_envelope(envelope, trust=wrong_trust)
    with pytest.raises(ReleaseContractError, match="not canonical"):
        _ = verify_finalized_release_document(
            canonical_bytes(envelope).replace(b"{", b"{\n", 1),
            trust=canonical_fixture.trust,
        )


def _included_tree_hash(root: Path, root_name: str) -> str:
    """Hash the selected release tree through its public contract."""
    if root_name == "science-workbench":
        return source_tree_sha256(root)
    return tree_sha256(root)


@pytest.mark.parametrize("root_name", ["science-workbench", "drylab", "ontologylab"])
def test_included_tree_symlink_is_rejected(tmp_path: Path, root_name: str) -> None:
    root = tmp_path / root_name
    _ = root.mkdir()
    target = tmp_path / "target"
    _ = target.write_text("one")
    (root / "link").symlink_to(target)
    with pytest.raises(ReleaseContractError, match="included symlink"):
        _ = _included_tree_hash(root, root_name)


def test_sibling_tree_hash_records_link_without_following_target(
    tmp_path: Path,
) -> None:
    sibling = tmp_path / "drylab"
    sibling.mkdir()
    first_target = tmp_path / "first-target"
    second_target = tmp_path / "second-target"
    _ = first_target.write_text("first")
    _ = second_target.write_text("second")
    link = sibling / "python"
    link.symlink_to(Path("..") / first_target.name)
    original = sibling_tree_sha256(sibling)
    _ = first_target.write_text("mutated")
    assert sibling_tree_sha256(sibling) == original
    link.unlink()
    link.symlink_to(Path("..") / second_target.name)
    assert sibling_tree_sha256(sibling) != original


@pytest.mark.parametrize("root_name", ["science-workbench", "drylab", "ontologylab"])
def test_included_tree_hardlink_is_rejected(tmp_path: Path, root_name: str) -> None:
    root = tmp_path / root_name
    _ = root.mkdir()
    original = root / "original"
    _ = original.write_text("one")
    _ = (root / "alias").hardlink_to(original)
    with pytest.raises(ReleaseContractError, match="aliased release evidence"):
        _ = _included_tree_hash(root, root_name)


def test_canonical_bytes_are_stable() -> None:
    assert canonical_bytes({"b": 1, "a": True}) == b'{"a":true,"b":1}\n'
