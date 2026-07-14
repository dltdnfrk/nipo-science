import hashlib
import hmac
import json
import os
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

import pytest
from pydantic import ValidationError
from tools.platform_policy import ci_contract, ci_runner
from tools.platform_policy.ci_contract import (
    CiCatalogJob,
    CiControlCatalog,
    CiCurrentRun,
    CiExecutionAttestation,
    CiExecutionLease,
    CiJob,
    CiRunState,
    EvidenceIntegrityError,
    GateResult,
    GeneratedContract,
    RequiredSecurityCatalog,
    SecurityEvidenceMapping,
    StaleGeneratedContractError,
    TaskAttemptBundle,
    ci_catalog_root,
    ci_catalog_source_root,
    load_checked_in_ci_catalog,
    load_published_ci_generation,
    load_task_attempt_bundle,
    security_catalog_source_bytes,
    verify_evidence,
    verify_evidence_files,
    verify_generated_contract,
)
from tools.platform_policy.ci_runner import (
    CiPublicationBinding,
    TaskAttemptRequest,
    publish_ci_generation,
    seal_task_attempt_evidence,
    verify_ci_control_catalog_commands,
)
from tools.platform_policy.release_contract import requirement_ids

if TYPE_CHECKING:
    from collections.abc import Callable

FIXTURES = Path(__file__).parent.parent / "fixtures" / "ci"
INJECTED_WRITE_FAILURE = "injected write failure"


AUTHORITY_CONTEXT = "revision-2026-07-13"
SOURCE_TREE_SHA256 = "a" * 64


def _fixed_source_identity(_root: Path) -> str:
    return SOURCE_TREE_SHA256


def _security_catalog(
    high_threat_ids: tuple[str, ...] = ("HIGH-1",),
) -> RequiredSecurityCatalog:
    provisional = RequiredSecurityCatalog(
        high_threat_ids=high_threat_ids,
        source_root_sha256="0" * 64,
    )
    source_root = hashlib.sha256(security_catalog_source_bytes(provisional)).hexdigest()
    return provisional.model_copy(update={"source_root_sha256": source_root})


TEST_SECURITY_CATALOG = _security_catalog()


def _seal_control_catalog(
    source_identity: str,
    jobs: tuple[CiCatalogJob, ...],
) -> CiControlCatalog:
    provisional = CiControlCatalog.model_construct(
        version=1,
        source_identity=source_identity,
        source_root_sha256="0" * 64,
        catalog_root_sha256="0" * 64,
        security_catalog_id="test-high-threat",
        jobs=jobs,
    )
    with_source = provisional.model_copy(
        update={"source_root_sha256": ci_catalog_source_root(provisional)}
    )
    complete = with_source.model_copy(
        update={"catalog_root_sha256": ci_catalog_root(with_source)}
    )
    return CiControlCatalog.model_validate(complete.model_dump())


def _control_catalog(source_identity: str) -> CiControlCatalog:
    requirement_ids = tuple(sorted(ci_contract.TRUSTED_REQUIREMENT_IDS))
    jobs = tuple(
        CiCatalogJob(
            job=job,
            argv=("test", str(job)),
            count_kind="pytest",
            category="test",
            environment_profile="test-ci",
            control_ids=(f"CONTROL-{job}",),
            requirement_ids=requirement_ids[index * 3 : (index + 1) * 3],
        )
        for index, job in enumerate(CiJob)
    )
    return _seal_control_catalog(source_identity, jobs)


TEST_CONTROL_CATALOG = _control_catalog(SOURCE_TREE_SHA256)


class MemoryCiAuthority:
    catalog_mode: Literal["fresh", "stale-source", "altered-control"]
    security_stale: bool

    def __init__(
        self,
        *,
        catalog_mode: Literal[
            "fresh",
            "stale-source",
            "altered-control",
        ] = "fresh",
        security_stale: bool = False,
    ) -> None:
        self.catalog_mode = catalog_mode
        self.security_stale = security_stale
        self.anchors: dict[tuple[str, str], str] = {}
        self.current: dict[str, CiCurrentRun] = {}
        self.leases: dict[str, CiExecutionLease] = {}
        self.authorized_leases: set[str] = set()
        self.lease_sequence: int = 0
        self.signing_material: bytes = b"test-memory-authority-material"

    def bind(
        self, authority_context: str, generation_id: str, manifest_sha256: str
    ) -> None:
        self.anchors[authority_context, generation_id] = manifest_sha256

    def resolve(self, authority_context: str, generation_id: str) -> str:
        return self.anchors[authority_context, generation_id]

    def begin(self, current_run: CiCurrentRun) -> None:
        self.current[current_run.authority_context] = current_run

    def complete(self, current_run: CiCurrentRun) -> None:
        if current_run.state is CiRunState.SUCCESS:
            message = "blind success completion is forbidden"
            raise ValueError(message)
        self.current[current_run.authority_context] = current_run

    def issue_execution_lease(
        self, current_run: CiCurrentRun, job: CiJob
    ) -> CiExecutionLease:
        self.lease_sequence += 1
        lease = CiExecutionLease(
            lease_id=(
                f"{current_run.run_id}:{current_run.attempt_id}:"
                f"{job}:{self.lease_sequence}"
            ),
            authority_context=current_run.authority_context,
            run_id=current_run.run_id,
            attempt_id=current_run.attempt_id,
            source_tree_sha256=current_run.source_tree_sha256,
            job=job,
        )
        self.leases[lease.lease_id] = lease
        return lease

    def authorize_execution_lease(
        self,
        lease: CiExecutionLease,
        current_run: CiCurrentRun,
        catalog: CiControlCatalog,
        job: CiCatalogJob,
    ) -> None:
        expected_catalog = self.resolve_control_catalog(
            current_run.authority_context,
            current_run.source_tree_sha256,
            current_run.run_id,
        )
        if (
            self.leases.get(lease.lease_id) != lease
            or lease.lease_id in self.authorized_leases
            or self.current.get(current_run.authority_context) != current_run
            or job not in catalog.jobs
            or job.job is not lease.job
            or catalog != expected_catalog
        ):
            message = "execution lease is not authorized"
            raise ValueError(message)
        self.authorized_leases.add(lease.lease_id)

    def attest_execution(
        self, lease: CiExecutionLease, record: GateResult, toolchain: str
    ) -> CiExecutionAttestation:
        if (
            self.leases.get(lease.lease_id) != lease
            or lease.lease_id not in self.authorized_leases
        ):
            raise LookupError(lease.lease_id)
        current_run = self.current.get(lease.authority_context)
        if (
            current_run is None
            or current_run.run_id != lease.run_id
            or current_run.attempt_id != lease.attempt_id
            or current_run.source_tree_sha256 != lease.source_tree_sha256
            or lease.job is not record.job
            or record.catalog_run_id != lease.run_id
        ):
            message = "execution lease is not bound to this record"
            raise ValueError(message)
        if (
            record.catalog_root_sha256 is None
            or record.catalog_source_root_sha256 is None
            or record.outcome != "success"
        ):
            message = "execution record is not an attestable success"
            raise ValueError(message)
        attestation = CiExecutionAttestation(
            lease_id=lease.lease_id,
            authority_context=lease.authority_context,
            run_id=lease.run_id,
            attempt_id=lease.attempt_id,
            source_tree_sha256=lease.source_tree_sha256,
            catalog_root_sha256=record.catalog_root_sha256,
            catalog_source_root_sha256=record.catalog_source_root_sha256,
            job=record.job,
            argv=record.argv,
            requirement_ids=record.requirement_ids,
            control_ids=record.control_ids,
            toolchain=toolchain,
            executed_count=record.executed_count,
            output_sha256=record.output_sha256,
            outcome=record.outcome,
            started_at=record.started_at,
            finished_at=record.finished_at,
            signature="unsigned",
        )
        signature = hmac.new(
            self.signing_material,
            attestation.model_dump_json(exclude={"signature"}).encode(),
            hashlib.sha256,
        ).hexdigest()
        return attestation.model_copy(update={"signature": signature})

    def verify_execution_attestation(
        self,
        attestation: CiExecutionAttestation,
        record: GateResult,
        current_run: CiCurrentRun,
    ) -> None:
        lease = self.leases.get(attestation.lease_id)
        if lease is None or lease.run_id != current_run.run_id:
            raise LookupError(attestation.lease_id)
        expected = self.attest_execution(lease, record, attestation.toolchain)
        if (
            not hmac.compare_digest(expected.signature, attestation.signature)
            or expected != attestation
        ):
            message = "forged execution attestation"
            raise ValueError(message)

    def finalize_attested_generation(
        self,
        current_run: CiCurrentRun,
        published_run: CiCurrentRun,
        manifest_sha256: str,
        attestations: tuple[CiExecutionAttestation, ...],
    ) -> None:
        if self.current.get(current_run.authority_context) != current_run:
            message = "stale run"
            raise ValueError(message)
        if published_run.state is not CiRunState.SUCCESS or len(attestations) != len(
            CiJob
        ):
            message = "incomplete attestations"
            raise ValueError(message)
        self.anchors[
            current_run.authority_context, cast("str", published_run.generation_id)
        ] = manifest_sha256
        self.current[current_run.authority_context] = published_run

    def resolve_current(self, authority_context: str) -> CiCurrentRun:
        return self.current[authority_context]

    def resolve_control_catalog(
        self,
        authority_context: str,
        source_identity: str,
        run_id: str,
    ) -> CiControlCatalog:
        _ = authority_context, run_id
        if self.catalog_mode == "stale-source":
            return _control_catalog("c" * 64)
        catalog = _control_catalog(source_identity)
        if self.catalog_mode == "altered-control":
            first = catalog.jobs[0].model_copy(
                update={"control_ids": ("ALTERED-CONTROL",)}
            )
            return _seal_control_catalog(
                source_identity,
                (first, *catalog.jobs[1:]),
            )
        return catalog

    def resolve_security_catalog(self, catalog_id: str) -> RequiredSecurityCatalog:
        if catalog_id != "test-high-threat":
            raise ValueError(catalog_id)
        return (
            _security_catalog(("HIGH-2",))
            if self.security_stale
            else TEST_SECURITY_CATALOG
        )


def test_control_catalog_job_rejects_duplicate_control_ids() -> None:
    with pytest.raises(ValueError, match="invalid CI catalog job"):
        _ = CiCatalogJob(
            job=CiJob.PLATFORM_TESTS,
            argv=("<python>", "-m", "pytest"),
            count_kind="pytest",
            category="test",
            environment_profile="local-ci",
            control_ids=("CI-001", "CI-001"),
            requirement_ids=("REQ-CI-001",),
        )


def test_control_catalog_rejects_missing_duplicate_and_ambiguous_jobs() -> None:
    jobs = TEST_CONTROL_CATALOG.jobs
    duplicate_control = jobs[1].model_copy(update={"control_ids": jobs[0].control_ids})
    invalid_catalogs = (
        jobs[:-1],
        (jobs[0], jobs[0], *jobs[2:]),
        (jobs[0], duplicate_control, *jobs[2:]),
    )
    for invalid_jobs in invalid_catalogs:
        with pytest.raises(ValueError, match="invalid CI control catalog"):
            _ = _seal_control_catalog(SOURCE_TREE_SHA256, invalid_jobs)


def test_control_catalog_rejects_missing_duplicate_and_substituted_requirements() -> (
    None
):
    jobs = TEST_CONTROL_CATALOG.jobs
    invalid_catalogs = (
        (*jobs[:-1], jobs[-1].model_copy(update={"requirement_ids": ("AC-F01",)})),
        (
            jobs[0].model_copy(
                update={
                    "requirement_ids": (
                        *jobs[1].requirement_ids[:2],
                        jobs[0].requirement_ids[2],
                    )
                }
            ),
            *jobs[1:],
        ),
        (
            jobs[0].model_copy(
                update={
                    "requirement_ids": (
                        "UNTRUSTED-REQ",
                        *jobs[0].requirement_ids[1:],
                    )
                }
            ),
            *jobs[1:],
        ),
    )
    for invalid_jobs in invalid_catalogs:
        with pytest.raises(ValueError, match="invalid CI control catalog"):
            _ = _seal_control_catalog(SOURCE_TREE_SHA256, tuple(invalid_jobs))


def test_security_evidence_rejects_forged_marker_without_case_evidence() -> None:
    forged = (
        b"1 passed\n"
        b'SECURITY_EVIDENCE=[{"threat_id":"HIGH-1","job":"SECURITY",'
        b'"positive_case_count":1,"evidence_root_sha256":"'
        + hashlib.sha256(b"1 passed\n").hexdigest().encode()
        + b'"}]\n'
    )

    with pytest.raises(EvidenceIntegrityError, match="map every High threat"):
        _ = ci_contract.parse_security_evidence_output(TEST_SECURITY_CATALOG, forged)


def test_security_catalog_resolver_rejects_retained_forged_source_root() -> None:
    forged = TEST_SECURITY_CATALOG.model_copy(update={"high_threat_ids": ("HIGH-2",)})

    with pytest.raises(ci_contract.SecurityCatalogAuthorityError):
        _ = ci_contract.resolve_security_catalog(lambda _: forged, "test-high-threat")


def test_catalog_rejects_forged_analyzer_inventory_count() -> None:
    root = Path(__file__).parents[2]
    catalog = load_checked_in_ci_catalog(root / ".ci/ci-contract.json")
    analyzer = next(job for job in catalog.jobs if job.job is CiJob.LINT)
    forged = GateResult(
        job=analyzer.job,
        executed_count=cast("int", analyzer.analyzer_inventory_count) + 1,
        output_sha256="a" * 64,
        argv=analyzer.argv,
        count_kind=analyzer.count_kind,
        parser_version=analyzer.parser_version,
        analyzer_inventory_root_sha256=analyzer.analyzer_inventory_root_sha256,
        category=analyzer.category,
        environment_profile=analyzer.environment_profile,
        control_ids=analyzer.control_ids,
        requirement_ids=analyzer.requirement_ids,
        prerequisites=analyzer.prerequisites,
        blockers=analyzer.blockers,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:00:01Z",
        catalog_root_sha256=catalog.catalog_root_sha256,
        catalog_source_root_sha256=catalog.source_root_sha256,
        catalog_run_id="test-run",
    )

    with pytest.raises(EvidenceIntegrityError, match="authority"):
        ci_contract.verify_records_against_catalog((forged,), catalog, "test-run")


@pytest.mark.parametrize("catalog_mode", ["stale-source", "altered-control"])
def test_generation_loader_rejects_stale_or_altered_control_catalog(
    tmp_path: Path,
    catalog_mode: Literal["stale-source", "altered-control"],
) -> None:
    records, outputs = complete_generation(b"catalog-authority")
    publish_generation(tmp_path, records, outputs)
    stale = MemoryCiAuthority(catalog_mode=catalog_mode)
    stale.anchors = dict(CI_AUTHORITY.anchors)
    stale.current = dict(CI_AUTHORITY.current)

    with pytest.raises(EvidenceIntegrityError, match="authority"):
        _ = load_published_ci_generation(
            tmp_path,
            AUTHORITY_CONTEXT,
            SOURCE_TREE_SHA256,
            stale,
        )


def test_generation_loader_rejects_changed_security_catalog(tmp_path: Path) -> None:
    records, outputs = complete_generation(b"security-authority")
    publish_generation(tmp_path, records, outputs)
    stale = MemoryCiAuthority(security_stale=True)
    stale.anchors = dict(CI_AUTHORITY.anchors)
    stale.current = dict(CI_AUTHORITY.current)

    with pytest.raises(EvidenceIntegrityError, match="authority"):
        _ = load_published_ci_generation(
            tmp_path,
            AUTHORITY_CONTEXT,
            SOURCE_TREE_SHA256,
            stale,
        )


CI_AUTHORITY = MemoryCiAuthority()


def _attest_records(
    current_run: CiCurrentRun,
    records: tuple[GateResult, ...],
) -> tuple[GateResult, ...]:
    attested: list[GateResult] = []
    catalog = CI_AUTHORITY.resolve_control_catalog(
        current_run.authority_context,
        current_run.source_tree_sha256,
        current_run.run_id,
    )
    for record in records:
        lease = CI_AUTHORITY.issue_execution_lease(current_run, record.job)
        catalog_job = next(item for item in catalog.jobs if item.job is record.job)
        CI_AUTHORITY.authorize_execution_lease(lease, current_run, catalog, catalog_job)
        attested.append(
            record.model_copy(
                update={
                    "execution_attestation": CI_AUTHORITY.attest_execution(
                        lease, record, "test-toolchain"
                    )
                }
            )
        )
    return tuple(attested)


def publish_generation(
    root: Path,
    records: tuple[GateResult, ...],
    outputs: tuple[bytes, ...],
    authority_context: str = AUTHORITY_CONTEXT,
    *,
    patch_source_identity: bool = True,
) -> None:
    current_run = CiCurrentRun(
        run_id="test-run",
        attempt_id="test-attempt",
        authority_context=authority_context,
        source_tree_sha256=SOURCE_TREE_SHA256,
        started_at="2026-07-13T00:00:00Z",
        state=CiRunState.ACTIVE,
    )
    CI_AUTHORITY.begin(current_run)
    records = _attest_records(current_run, records)
    binding = CiPublicationBinding(
        authority_context,
        SOURCE_TREE_SHA256,
        CI_AUTHORITY,
        current_run,
    )
    if patch_source_identity:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                ci_runner,
                "source_tree_identity",
                _fixed_source_identity,
            )
            generation_id, published_run = publish_ci_generation(
                root,
                records,
                outputs,
                binding,
            )
    else:
        generation_id, published_run = publish_ci_generation(
            root,
            records,
            outputs,
            binding,
        )
    assert generation_id == published_run.generation_id
    assert CI_AUTHORITY.resolve_current(authority_context) == published_run


def _security_output() -> bytes:
    cases = tuple(
        (
            identifier,
            (
                b"SECURITY_CASE="
                + json.dumps(
                    {
                        "case_id": f"case-{index}",
                        "outcome": "passed",
                        "threat_id": identifier,
                    },
                    separators=(",", ":"),
                ).encode()
                + b"\n"
            ),
        )
        for index, identifier in enumerate(TEST_SECURITY_CATALOG.high_threat_ids)
    )
    evidence = b"".join(line for _, line in cases)
    mappings = [
        {
            "threat_id": identifier,
            "job": "SECURITY",
            "positive_case_count": 1,
            "evidence_root_sha256": hashlib.sha256(line).hexdigest(),
        }
        for identifier, line in cases
    ]
    marker = json.dumps(mappings, separators=(",", ":")).encode()
    return evidence + b"SECURITY_EVIDENCE=" + marker + b"\n"


def _security_roots(output: bytes) -> tuple[str, ...]:
    return tuple(
        mapping.evidence_root_sha256
        for mapping in ci_contract.parse_security_evidence_output(
            TEST_SECURITY_CATALOG, output
        )
    )


def result(job: CiJob, count: int, output: bytes | None = None) -> GateResult:
    catalog_job = next(item for item in TEST_CONTROL_CATALOG.jobs if item.job is job)
    if output is None:
        output = _security_output() if job is CiJob.SECURITY else b"1 passed"
    security_roots = _security_roots(output) if job is CiJob.SECURITY else ()
    return GateResult(
        job=job,
        executed_count=count,
        output_sha256=hashlib.sha256(output).hexdigest(),
        argv=catalog_job.argv,
        count_kind=catalog_job.count_kind,
        parser_version=catalog_job.parser_version,
        category=catalog_job.category,
        environment_profile=catalog_job.environment_profile,
        control_ids=catalog_job.control_ids,
        requirement_ids=catalog_job.requirement_ids,
        prerequisites=catalog_job.prerequisites,
        blockers=catalog_job.blockers,
        attachment_sha256=security_roots,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:00:01Z",
        catalog_root_sha256=TEST_CONTROL_CATALOG.catalog_root_sha256,
        catalog_source_root_sha256=TEST_CONTROL_CATALOG.source_root_sha256,
        catalog_run_id="test-run",
        security_catalog_root_sha256=(
            TEST_SECURITY_CATALOG.source_root_sha256 if job is CiJob.SECURITY else None
        ),
        security_threat_ids=(
            TEST_SECURITY_CATALOG.high_threat_ids if job is CiJob.SECURITY else ()
        ),
        security_evidence_roots=security_roots,
    )


def complete_generation(
    platform_output: bytes,
) -> tuple[tuple[GateResult, ...], tuple[bytes, ...]]:
    platform_proof = platform_output + b"\n1 passed"
    outputs = tuple(
        platform_proof
        if job == CiJob.PLATFORM_TESTS
        else _security_output()
        if job == CiJob.SECURITY
        else b"1 passed"
        for job in CiJob
    )
    return (
        tuple(
            result(job, 1, output) for job, output in zip(CiJob, outputs, strict=True)
        ),
        outputs,
    )


def test_execution_attestation_rejects_forged_and_wrong_bound_values() -> None:
    current_run = CiCurrentRun(
        run_id="test-run",
        attempt_id="test-attempt",
        authority_context=AUTHORITY_CONTEXT,
        source_tree_sha256=SOURCE_TREE_SHA256,
        started_at="2026-07-13T00:00:00Z",
        state=CiRunState.ACTIVE,
    )
    CI_AUTHORITY.begin(current_run)
    base = result(CiJob.PLATFORM_TESTS, 1)
    lease = CI_AUTHORITY.issue_execution_lease(current_run, base.job)
    catalog = CI_AUTHORITY.resolve_control_catalog(
        AUTHORITY_CONTEXT, SOURCE_TREE_SHA256, current_run.run_id
    )
    catalog_job = next(item for item in catalog.jobs if item.job is base.job)
    CI_AUTHORITY.authorize_execution_lease(lease, current_run, catalog, catalog_job)
    signed = base.model_copy(
        update={
            "execution_attestation": CI_AUTHORITY.attest_execution(
                lease, base, "test-toolchain"
            )
        }
    )
    attestation = signed.execution_attestation
    assert attestation is not None
    assert (
        ci_contract.verify_execution_attestation(CI_AUTHORITY, signed, current_run)
        == attestation
    )
    for changed in (
        base,
        signed.model_copy(
            update={
                "execution_attestation": attestation.model_copy(
                    update={"signature": "forged"}
                )
            }
        ),
        signed.model_copy(
            update={
                "execution_attestation": attestation.model_copy(
                    update={"source_tree_sha256": "b" * 64}
                )
            }
        ),
        signed.model_copy(
            update={
                "execution_attestation": attestation.model_copy(
                    update={"run_id": "replayed-run"}
                )
            }
        ),
        signed.model_copy(
            update={
                "execution_attestation": attestation.model_copy(
                    update={"job": CiJob.TYPECHECK}
                )
            }
        ),
        signed.model_copy(
            update={
                "execution_attestation": attestation.model_copy(
                    update={"catalog_root_sha256": "b" * 64}
                )
            }
        ),
        signed.model_copy(update={"catalog_root_sha256": "b" * 64}),
        signed.model_copy(update={"catalog_run_id": "wrong-run"}),
    ):
        with pytest.raises(EvidenceIntegrityError):
            _ = ci_contract.verify_execution_attestation(
                CI_AUTHORITY, changed, current_run
            )


def test_execution_lease_cannot_cross_jobs_and_success_requires_atomic_finalize() -> (
    None
):
    current_run = CiCurrentRun(
        run_id="lease-run",
        attempt_id="lease-attempt",
        authority_context=AUTHORITY_CONTEXT,
        source_tree_sha256=SOURCE_TREE_SHA256,
        started_at="2026-07-13T00:00:00Z",
        state=CiRunState.ACTIVE,
    )
    CI_AUTHORITY.begin(current_run)
    platform_lease = CI_AUTHORITY.issue_execution_lease(
        current_run, CiJob.PLATFORM_TESTS
    )
    catalog = CI_AUTHORITY.resolve_control_catalog(
        current_run.authority_context,
        current_run.source_tree_sha256,
        current_run.run_id,
    )
    platform_job = next(
        item for item in catalog.jobs if item.job is CiJob.PLATFORM_TESTS
    )
    CI_AUTHORITY.authorize_execution_lease(
        platform_lease,
        current_run,
        catalog,
        platform_job,
    )
    typecheck_record = result(CiJob.TYPECHECK, 1).model_copy(
        update={"catalog_run_id": current_run.run_id}
    )
    with pytest.raises(ValueError, match="lease"):
        _ = CI_AUTHORITY.attest_execution(
            platform_lease,
            typecheck_record,
            "test-toolchain",
        )

    blind_success = current_run.model_copy(
        update={
            "finished_at": "2026-07-13T00:01:00Z",
            "generation_id": "blind-generation",
            "state": CiRunState.SUCCESS,
        }
    )
    with pytest.raises(ValueError, match="blind success"):
        CI_AUTHORITY.complete(blind_success)
    assert CI_AUTHORITY.resolve_current(AUTHORITY_CONTEXT) == current_run


def test_published_generation_rejects_an_active_current_run(tmp_path: Path) -> None:
    records, outputs = complete_generation(b"current-run")
    publish_generation(tmp_path, records, outputs)
    CI_AUTHORITY.begin(
        CiCurrentRun(
            run_id="new-run",
            attempt_id="new-attempt",
            authority_context=AUTHORITY_CONTEXT,
            source_tree_sha256=SOURCE_TREE_SHA256,
            started_at="2026-07-13T00:02:00Z",
            state=CiRunState.ACTIVE,
        )
    )
    with pytest.raises(EvidenceIntegrityError, match="current run"):
        _ = load_published_ci_generation(
            tmp_path, AUTHORITY_CONTEXT, SOURCE_TREE_SHA256, CI_AUTHORITY
        )


def test_published_ci_generation_rejects_source_tree_identity_drift(
    tmp_path: Path,
) -> None:
    records, outputs = complete_generation(b"source-bound")
    publish_generation(tmp_path, records, outputs)

    with pytest.raises(EvidenceIntegrityError, match="authority"):
        _ = load_published_ci_generation(
            tmp_path, AUTHORITY_CONTEXT, "b" * 64, CI_AUTHORITY
        )


def test_ci_publication_rejects_unredacted_log_bytes(tmp_path: Path) -> None:
    output = b"Author" + b"ization: Bear" + b"er publication-material"
    records, _ = complete_generation(output)
    outputs = tuple(output for _record in records)

    with pytest.raises(EvidenceIntegrityError, match="unredacted secret"):
        publish_generation(tmp_path, records, outputs)


def test_ci_publication_rejects_stale_superseded_run(tmp_path: Path) -> None:
    records, outputs = complete_generation(b"stale-run")
    stale_run = CiCurrentRun(
        run_id="test-run",
        attempt_id="test-attempt",
        authority_context=AUTHORITY_CONTEXT,
        source_tree_sha256=SOURCE_TREE_SHA256,
        started_at="2026-07-13T00:00:00Z",
        state=CiRunState.ACTIVE,
    )
    CI_AUTHORITY.begin(
        stale_run.model_copy(
            update={
                "run_id": "superseding-run",
                "attempt_id": "superseding-attempt",
            }
        )
    )
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(ci_runner, "source_tree_identity", _fixed_source_identity)
        with pytest.raises(EvidenceIntegrityError, match="stale or superseded"):
            _ = publish_ci_generation(
                tmp_path,
                records,
                outputs,
                CiPublicationBinding(
                    AUTHORITY_CONTEXT,
                    SOURCE_TREE_SHA256,
                    CI_AUTHORITY,
                    stale_run,
                ),
            )


@pytest.mark.parametrize(
    ("record_update", "output_update", "match"),
    [
        ({"control_ids": ("descriptor-drift",)}, None, "authority"),
        ({"executed_count": 2}, None, "rederived"),
        ({}, b"checksum-drift", "checksum drift"),
    ],
)
def test_ci_publication_rederives_catalog_counts_and_checksums(
    tmp_path: Path,
    record_update: dict[str, object],
    output_update: bytes | None,
    match: str,
) -> None:
    records, outputs = complete_generation(b"publication-rederivation")
    changed_record = records[0].model_copy(update=record_update)
    changed_output = outputs[0] if output_update is None else output_update
    changed_records = (changed_record, *records[1:])
    changed_outputs = (changed_output, *outputs[1:])
    current_run = CiCurrentRun(
        run_id="test-run",
        attempt_id="test-attempt",
        authority_context=AUTHORITY_CONTEXT,
        source_tree_sha256=SOURCE_TREE_SHA256,
        started_at="2026-07-13T00:00:00Z",
        state=CiRunState.ACTIVE,
    )
    CI_AUTHORITY.begin(current_run)
    changed_records = _attest_records(current_run, changed_records)

    def source_tree_identity(_root: Path) -> str:
        return SOURCE_TREE_SHA256

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(ci_runner, "source_tree_identity", source_tree_identity)
        with pytest.raises(EvidenceIntegrityError, match=match):
            _ = publish_ci_generation(
                tmp_path,
                changed_records,
                changed_outputs,
                CiPublicationBinding(
                    AUTHORITY_CONTEXT,
                    SOURCE_TREE_SHA256,
                    CI_AUTHORITY,
                    current_run,
                ),
            )


def test_ci_publication_recomputes_checkout_source_identity(
    tmp_path: Path,
) -> None:
    records, outputs = complete_generation(b"source-drift")
    current_run = CiCurrentRun(
        run_id="test-run",
        attempt_id="test-attempt",
        authority_context=AUTHORITY_CONTEXT,
        source_tree_sha256=SOURCE_TREE_SHA256,
        started_at="2026-07-13T00:00:00Z",
        state=CiRunState.ACTIVE,
    )
    CI_AUTHORITY.begin(current_run)

    def source_tree_identity(_root: Path) -> str:
        return "b" * 64

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(ci_runner, "source_tree_identity", source_tree_identity)
        with pytest.raises(EvidenceIntegrityError, match="source tree identity"):
            _ = publish_ci_generation(
                tmp_path,
                records,
                outputs,
                CiPublicationBinding(
                    AUTHORITY_CONTEXT,
                    SOURCE_TREE_SHA256,
                    CI_AUTHORITY,
                    current_run,
                ),
            )


def test_ci_publication_cleanup_fifo_preserves_originating_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    records, outputs = complete_generation(b"cleanup-fifo")
    original_write = ci_runner.write_generation_file

    def inject_fifo_then_fail(directory_fd: int, name: str, content: bytes) -> None:
        del name, content
        os.mkfifo("injected-fifo", dir_fd=directory_fd)
        raise OSError(INJECTED_WRITE_FAILURE)

    monkeypatch.setattr(ci_runner, "write_generation_file", inject_fifo_then_fail)
    with pytest.raises(OSError, match=INJECTED_WRITE_FAILURE):
        publish_generation(tmp_path, records, outputs)
    monkeypatch.setattr(ci_runner, "write_generation_file", original_write)


def test_ordinary_task_attempt_success_is_unrepresentable() -> None:
    with pytest.raises(ValidationError):
        _ = TaskAttemptBundle.model_validate(
            {
                "task_id": "task",
                "run_id": "run",
                "execution_id": "execution",
                "attempt_id": "attempt",
                "revision": 1,
                "outcome": "success",
                "exit_code": 0,
                "started_at": "2026-07-13T00:00:00Z",
                "finished_at": "2026-07-13T00:01:00Z",
                "command": ("pytest",),
                "control_id": "CONTROL",
                "raw_log_sha256": "a" * 64,
                "root_sha256": "b" * 64,
            }
        )


@pytest.mark.parametrize(
    ("outcome", "exit_code", "finished_at"),
    [
        ("failure", 1, "2026-07-13T00:01:00Z"),
        ("incomplete", None, None),
    ],
)
def test_seal_task_attempt_evidence_is_append_only_for_all_outcomes(
    tmp_path: Path,
    outcome: Literal["failure", "incomplete"],
    exit_code: int | None,
    finished_at: str | None,
) -> None:
    request = TaskAttemptRequest(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id=f"attempt-{outcome}",
        revision=1,
        outcome=outcome,
        exit_code=exit_code,
        started_at="2026-07-13T00:00:00Z",
        finished_at=finished_at,
        command=("pytest",),
        control_id="CONTROL",
        attachments=(),
    )
    sealed = seal_task_attempt_evidence(tmp_path, request, b"raw evidence")
    assert (sealed / "bundle.json").is_file()
    with pytest.raises(EvidenceIntegrityError, match="already exists"):
        _ = seal_task_attempt_evidence(tmp_path, request, b"raw evidence")


@pytest.mark.parametrize(
    ("raw_log", "attachments"),
    [
        (b'{"access_' + b'token":"raw-material"}', ()),
        (b"clean", (b"client_" + b"secret=attachment-material",)),
        (
            b'{"device_code":"device-material","authorization_code":"auth-material"}',
            (),
        ),
        (b"clean", (b"?api_" + b"key=query-material&x=1",)),
        (b"clean", (b"Set-" + b"Cookie: session=cookie-material",)),
    ],
)
def test_task_attempt_sink_rejects_unredacted_secrets(
    tmp_path: Path,
    raw_log: bytes,
    attachments: tuple[bytes, ...],
) -> None:
    request = TaskAttemptRequest(
        task_id="secret-task",
        run_id="run",
        execution_id="execution",
        attempt_id="attempt",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="CONTROL",
        attachments=attachments,
    )

    with pytest.raises(EvidenceIntegrityError, match="unredacted secret"):
        _ = seal_task_attempt_evidence(tmp_path, request, raw_log)


def test_task_attempt_write_failure_cleans_temporary_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = TaskAttemptRequest(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id="attempt",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="CONTROL",
        attachments=(),
    )
    original_fsync = os.fsync
    calls = 0

    def interrupted_fsync(file_descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(INJECTED_WRITE_FAILURE)
        original_fsync(file_descriptor)

    monkeypatch.setattr("tools.platform_policy.ci_contract.os.fsync", interrupted_fsync)
    with pytest.raises(OSError, match=INJECTED_WRITE_FAILURE):
        _ = seal_task_attempt_evidence(tmp_path, request, b"raw evidence")
    task_dir = tmp_path / "task"
    assert not (task_dir / "attempt").exists()
    assert tuple(task_dir.iterdir()) == ()


def test_task_attempt_rename_infrastructure_error_is_not_misclassified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = TaskAttemptRequest(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id="attempt",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="CONTROL",
        attachments=(),
    )

    def fail_rename(
        source: str,
        destination: str,
        *,
        source_dir_fd: int,
        destination_dir_fd: int,
    ) -> None:
        del source, destination, source_dir_fd, destination_dir_fd
        raise OSError(INJECTED_WRITE_FAILURE)

    monkeypatch.setattr(ci_contract, "atomic_rename_no_replace", fail_rename)
    with pytest.raises(OSError, match=INJECTED_WRITE_FAILURE):
        _ = seal_task_attempt_evidence(tmp_path, request, b"raw evidence")


def test_runner_derives_attachment_digest_from_evidence_bytes(tmp_path: Path) -> None:
    """Caller metadata cannot substitute for runner-observed attachment bytes."""
    attachment = b"attachment bytes"
    request = TaskAttemptRequest(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id="attached-attempt",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="CONTROL",
        attachments=(attachment,),
    )
    sealed = seal_task_attempt_evidence(tmp_path, request, b"raw evidence")
    bundle = (sealed / "bundle.json").read_text()
    assert hashlib.sha256(attachment).hexdigest() in bundle
    assert (sealed / "attachment-0").read_bytes() == attachment


def test_task_attempt_preexisting_partial_final_fails_closed(
    tmp_path: Path,
) -> None:
    request = TaskAttemptRequest(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id="attempt",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="CONTROL",
        attachments=(),
    )
    partial = tmp_path / "task" / "attempt"
    partial.mkdir(parents=True)
    _ = (partial / "raw.log").write_bytes(b"interrupted")

    with pytest.raises(EvidenceIntegrityError, match="already exists"):
        _ = seal_task_attempt_evidence(tmp_path, request, b"raw evidence")
    assert (partial / "raw.log").read_bytes() == b"interrupted"


def test_task_attempt_rejects_symlinked_evidence_ancestor(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    evidence_root = tmp_path / "evidence"
    evidence_root.symlink_to(target, target_is_directory=True)
    request = TaskAttemptRequest(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id="attempt",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="CONTROL",
    )

    with pytest.raises(EvidenceIntegrityError, match="path-safe"):
        _ = seal_task_attempt_evidence(evidence_root, request, b"raw evidence")


def test_task_attempt_ancestor_swap_cannot_redirect_descriptor_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    evidence_root = root / "evidence"
    evidence_root.mkdir(parents=True)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    original_open = cast("Callable[..., int]", os.open)
    swapped = False
    original_root = tmp_path / "root-original"

    def swap_ancestor(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal original_root, swapped
        if path == "evidence" and not swapped:
            swapped = True
            _ = root.rename(original_root)
            root.symlink_to(attacker, target_is_directory=True)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("tools.platform_policy.ci_contract.os.open", swap_ancestor)
    request = TaskAttemptRequest(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id="attempt",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="CONTROL",
    )

    _ = seal_task_attempt_evidence(evidence_root, request, b"raw evidence")

    assert not (attacker / "task").exists()
    assert (
        original_root / "evidence" / "task" / "attempt" / "raw.log"
    ).read_bytes() == b"raw evidence"


@pytest.mark.parametrize("sidecar_kind", ["hardlink", "symlink", "fifo"])
def test_task_attempt_sidecars_reject_unsafe_files_without_blocking(
    tmp_path: Path, sidecar_kind: str
) -> None:
    request = TaskAttemptRequest(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id=f"unsafe-{sidecar_kind}",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="CONTROL",
    )
    sealed = seal_task_attempt_evidence(tmp_path, request, b"raw evidence")
    bundle = TaskAttemptBundle.model_validate_json(
        (sealed / "bundle.json").read_bytes()
    )
    raw_log = sealed / "raw.log"
    outside = tmp_path / f"outside-{sidecar_kind}"
    _ = outside.write_bytes(b"raw evidence")
    raw_log.unlink()
    if sidecar_kind == "hardlink":
        os.link(outside, raw_log)
    elif sidecar_kind == "symlink":
        raw_log.symlink_to(outside)
    else:
        os.mkfifo(raw_log)
    with pytest.raises(EvidenceIntegrityError, match="path-safe"):
        _ = load_task_attempt_bundle(sealed, bundle.root_sha256)


def test_task_attempt_loader_rejects_coherently_anchored_unsanitized_log(
    tmp_path: Path,
) -> None:
    request = TaskAttemptRequest(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id="unsanitized",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="CONTROL",
    )
    sealed = seal_task_attempt_evidence(tmp_path, request, b"clean")
    raw_log = b"Author" + b"ization: Bear" + b"er coherently-anchored-material"
    bundle = TaskAttemptBundle.model_validate_json(
        (sealed / "bundle.json").read_bytes()
    )
    forged = bundle.model_copy(
        update={"raw_log_sha256": hashlib.sha256(raw_log).hexdigest()}
    )
    forged = forged.model_copy(
        update={"root_sha256": ci_contract.task_attempt_root(forged)}
    )
    _ = (sealed / "raw.log").write_bytes(raw_log)
    _ = (sealed / "bundle.json").write_text(forged.model_dump_json())

    with pytest.raises(EvidenceIntegrityError, match="unredacted secret"):
        _ = load_task_attempt_bundle(sealed, forged.root_sha256)


@pytest.mark.parametrize("entry_kind", ["hardlink", "symlink", "fifo"])
def test_staged_generation_reader_rejects_unsafe_entries_without_blocking(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    outside = tmp_path / f"outside-{entry_kind}"
    _ = outside.write_bytes(b"staged")
    entry = tmp_path / "entry"
    if entry_kind == "hardlink":
        os.link(outside, entry)
    elif entry_kind == "symlink":
        entry.symlink_to(outside)
    else:
        os.mkfifo(entry)
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(RuntimeError, match="unsafe"):
            _ = ci_runner.read_staged_generation_file(directory_fd, entry.name)
    finally:
        os.close(directory_fd)


@pytest.mark.parametrize("entry_kind", ["hardlink", "symlink", "fifo"])
def test_published_generation_reader_rejects_unsafe_entries_without_blocking(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    outside = tmp_path / f"published-outside-{entry_kind}"
    _ = outside.write_bytes(b"published")
    entry = tmp_path / "entry"
    if entry_kind == "hardlink":
        os.link(outside, entry)
    elif entry_kind == "symlink":
        entry.symlink_to(outside)
    else:
        os.mkfifo(entry)
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(EvidenceIntegrityError, match="exact job log set"):
            _ = ci_contract.read_generation_file(directory_fd, entry.name)
    finally:
        os.close(directory_fd)


def test_ci_runner_main_injects_configured_external_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[tuple[Path, object]] = []

    def run_with_authority(root: Path, authority: object) -> tuple[GateResult, ...]:
        captured.append((root, authority))
        return (result(CiJob.PLATFORM_TESTS, 1),)

    monkeypatch.setattr(
        ci_runner,
        "configured_ci_generation_manifest_authority",
        lambda: CI_AUTHORITY,
    )
    monkeypatch.setattr(ci_runner, "run_ci", run_with_authority)
    monkeypatch.setattr(sys, "argv", ["ci_runner", str(tmp_path)])

    assert ci_runner.main() == 0
    assert captured == [(tmp_path.resolve(), CI_AUTHORITY)]


@pytest.mark.parametrize("generations_exists", [False, True])
def test_ci_generation_fsyncs_parent_for_created_or_existing_generations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, generations_exists: bool
) -> None:
    evidence_dir = tmp_path / ".ci" / "evidence"
    evidence_dir.mkdir(parents=True)
    if generations_exists:
        (evidence_dir / "generations").mkdir()
    parent_inode = evidence_dir.stat().st_ino
    fsynced_inodes: list[int] = []
    original_fsync = ci_runner.fsync_generation

    def record_fsync(file_descriptor: int) -> None:
        fsynced_inodes.append(os.fstat(file_descriptor).st_ino)
        original_fsync(file_descriptor)

    monkeypatch.setattr(ci_runner, "fsync_generation", record_fsync)
    records, outputs = complete_generation(b"existing")
    publish_generation(tmp_path, records, outputs)

    assert parent_inode in fsynced_inodes


def test_concurrent_attempt_publishers_have_one_no_replace_winner(
    tmp_path: Path,
) -> None:
    request = TaskAttemptRequest(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id="attempt",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="CONTROL",
    )
    successes: list[Path] = []
    failures: list[EvidenceIntegrityError] = []

    def publish() -> None:
        try:
            successes.append(seal_task_attempt_evidence(tmp_path, request, b"raw"))
        except EvidenceIntegrityError as error:
            failures.append(error)

    publishers = tuple(threading.Thread(target=publish) for _ in range(2))
    for publisher in publishers:
        publisher.start()
    for publisher in publishers:
        publisher.join()

    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], EvidenceIntegrityError)
    assert (tmp_path / "task" / "attempt" / "raw.log").read_bytes() == b"raw"


def test_concurrent_ci_publishers_leave_a_complete_latest_generation(
    tmp_path: Path,
) -> None:
    failures: list[EvidenceIntegrityError] = []

    def publish(output: bytes) -> None:
        try:
            records, outputs = complete_generation(output)
            publish_generation(
                tmp_path,
                records,
                outputs,
                patch_source_identity=False,
            )
        except EvidenceIntegrityError as error:
            failures.append(error)

    publishers = (
        threading.Thread(target=publish, args=(b"first",)),
        threading.Thread(target=publish, args=(b"second",)),
    )
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            ci_runner,
            "source_tree_identity",
            _fixed_source_identity,
        )
        for publisher in publishers:
            publisher.start()
        for publisher in publishers:
            publisher.join()

    assert len(failures) <= 1
    assert all("stale or superseded" in str(error) for error in failures)
    published = load_published_ci_generation(
        tmp_path, AUTHORITY_CONTEXT, SOURCE_TREE_SHA256, CI_AUTHORITY
    )
    raw_output = published.logs[CiJob.PLATFORM_TESTS]
    assert raw_output in {b"first\n1 passed", b"second\n1 passed"}
    platform_result = next(
        item for item in published.records if item.job == CiJob.PLATFORM_TESTS
    )
    assert platform_result.output_sha256 == hashlib.sha256(raw_output).hexdigest()
    current = CI_AUTHORITY.resolve_current(AUTHORITY_CONTEXT)
    assert current.generation_id == (tmp_path / ".ci/evidence/latest").readlink().name


type GenerationCandidate = tuple[tuple[GateResult, ...], tuple[bytes, ...]]


def assert_latest_is_complete_generation(
    root: Path, candidates: tuple[GenerationCandidate, ...]
) -> None:
    latest = root / ".ci/evidence/latest"
    generation_id = latest.readlink().name
    manifest = cast(
        "dict[str, object]", json.loads((latest / "manifest.json").read_bytes())
    )
    recovery_authority = MemoryCiAuthority()
    recovery_authority.anchors = dict(CI_AUTHORITY.anchors)
    recovery_authority.leases = dict(CI_AUTHORITY.leases)
    recovery_authority.authorized_leases = set(CI_AUTHORITY.authorized_leases)
    recovery_authority.current[AUTHORITY_CONTEXT] = CiCurrentRun(
        run_id=cast("str", manifest["run_id"]),
        attempt_id=cast("str", manifest["attempt_id"]),
        authority_context=cast("str", manifest["authority_context"]),
        source_tree_sha256=cast("str", manifest["source_tree_sha256"]),
        started_at=cast("str", manifest["started_at"]),
        finished_at=cast("str", manifest["finished_at"]),
        generation_id=generation_id,
        state=CiRunState.SUCCESS,
    )
    published = load_published_ci_generation(
        root, AUTHORITY_CONTEXT, SOURCE_TREE_SHA256, recovery_authority
    )

    def without_attestations(
        records: tuple[GateResult, ...],
    ) -> tuple[GateResult, ...]:
        return tuple(
            record.model_copy(update={"execution_attestation": None})
            for record in records
        )

    matching = [
        candidate
        for candidate in candidates
        if verify_evidence(without_attestations(candidate[0]))
        == verify_evidence(without_attestations(published.records))
    ]
    assert len(matching) == 1
    expected_records, expected_outputs = matching[0]
    assert {record.job for record in published.records} == {
        record.job for record in expected_records
    }
    for record, output in zip(expected_records, expected_outputs, strict=True):
        assert published.logs[record.job] == output


@pytest.mark.parametrize(
    "tamper",
    [
        "log",
        "manifest",
        "aggregate",
        "noncanonical-manifest",
        "wrong-job-set",
        "extra-file",
        "missing-log",
        "unsafe-pointer",
    ],
)
def test_published_ci_generation_rejects_tampering(tmp_path: Path, tamper: str) -> None:
    records, outputs = complete_generation(b"intact")
    publish_generation(tmp_path, records, outputs)
    latest = tmp_path / ".ci/evidence/latest"
    if tamper == "log":
        _ = (latest / "platform-tests.log").write_bytes(b"tampered")
    elif tamper == "manifest":
        _ = (latest / "manifest.json").write_bytes(b"{}")
    elif tamper == "aggregate":
        manifest = latest / "manifest.json"
        _ = manifest.write_bytes(
            manifest.read_bytes().replace(
                b'"aggregate_sha256":"', b'"aggregate_sha256":"0', 1
            )
        )
    elif tamper == "noncanonical-manifest":
        manifest = latest / "manifest.json"
        _ = manifest.write_bytes(
            manifest.read_bytes().replace(b'{"aggregate', b'{\n"aggregate')
        )
    elif tamper == "wrong-job-set":
        manifest = cast(
            "dict[str, object]",
            json.loads((latest / "manifest.json").read_bytes()),
        )
        results = cast("list[object]", manifest["results"])
        _ = results.pop()
        _ = (latest / "manifest.json").write_bytes(
            (
                json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n"
            ).encode()
        )
        (latest / f"{records[-1].job}.log").unlink()
    elif tamper == "extra-file":
        _ = (latest / "extra").write_bytes(b"tampered")
    elif tamper == "missing-log":
        (latest / "platform-tests.log").unlink()
    else:
        latest.unlink()
        latest.symlink_to("../outside")
    with pytest.raises(EvidenceIntegrityError):
        _ = load_published_ci_generation(
            tmp_path, AUTHORITY_CONTEXT, SOURCE_TREE_SHA256, CI_AUTHORITY
        )


@pytest.mark.parametrize("tamper", ["result-not-object", "wrong-result-primitive"])
def test_published_ci_generation_wraps_malformed_result_types(
    tmp_path: Path, tamper: str
) -> None:
    records, outputs = complete_generation(b"typed")
    publish_generation(tmp_path, records, outputs)
    manifest_path = tmp_path / ".ci/evidence/latest/manifest.json"
    manifest = cast(
        "dict[str, object]",
        json.loads(manifest_path.read_bytes()),
    )
    results = cast("list[object]", manifest["results"])
    if tamper == "result-not-object":
        results[0] = "invalid"
    else:
        first = cast("dict[str, object]", results[0])
        first["executed_count"] = "1"
    _ = manifest_path.write_bytes(
        (json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n").encode()
    )
    with pytest.raises(EvidenceIntegrityError, match="malformed"):
        _ = load_published_ci_generation(
            tmp_path, AUTHORITY_CONTEXT, SOURCE_TREE_SHA256, CI_AUTHORITY
        )


def test_published_ci_generation_rejects_pointer_substitution_and_wrong_authority(
    tmp_path: Path,
) -> None:
    first_records, first_outputs = complete_generation(b"first")
    publish_generation(tmp_path, first_records, first_outputs)
    second_records, second_outputs = complete_generation(b"second")
    publish_generation(tmp_path, second_records, second_outputs, "other-revision")
    latest = tmp_path / ".ci/evidence/latest"
    latest.unlink()
    generations = tmp_path / ".ci/evidence/generations"
    second = next(
        path.name
        for path in generations.iterdir()
        if (path / "platform-tests.log").read_bytes() == b"second\n1 passed"
    )
    latest.symlink_to(f"generations/{second}")
    with pytest.raises(EvidenceIntegrityError, match="authority"):
        _ = load_published_ci_generation(
            tmp_path, AUTHORITY_CONTEXT, SOURCE_TREE_SHA256, CI_AUTHORITY
        )


def test_published_ci_generation_returns_detached_verified_log_bytes(
    tmp_path: Path,
) -> None:
    records, outputs = complete_generation(b"intact")
    publish_generation(tmp_path, records, outputs)
    published = load_published_ci_generation(
        tmp_path, AUTHORITY_CONTEXT, SOURCE_TREE_SHA256, CI_AUTHORITY
    )
    latest = tmp_path / ".ci/evidence/latest"
    _ = (latest / "platform-tests.log").write_bytes(b"tampered")
    assert published.logs[CiJob.PLATFORM_TESTS] == b"intact\n1 passed"


@pytest.mark.parametrize("anchor", [None, "0" * 64])
def test_published_generation_rejects_missing_or_stale_external_anchor(
    tmp_path: Path, anchor: str | None
) -> None:
    records, outputs = complete_generation(b"anchored")
    publish_generation(tmp_path, records, outputs)
    generation_name = (
        (tmp_path / ".ci/evidence/latest")
        .readlink()
        .as_posix()
        .removeprefix("generations/")
    )
    if anchor is None:
        _ = CI_AUTHORITY.anchors.pop((AUTHORITY_CONTEXT, generation_name))
    else:
        CI_AUTHORITY.anchors[AUTHORITY_CONTEXT, generation_name] = anchor

    with pytest.raises(EvidenceIntegrityError, match="anchor"):
        _ = load_published_ci_generation(
            tmp_path, AUTHORITY_CONTEXT, SOURCE_TREE_SHA256, CI_AUTHORITY
        )


def test_published_generation_rejects_coherent_replacement_without_anchor(
    tmp_path: Path,
) -> None:
    first_records, first_outputs = complete_generation(b"first")
    publish_generation(tmp_path, first_records, first_outputs)
    first_name = (
        (tmp_path / ".ci/evidence/latest")
        .readlink()
        .as_posix()
        .removeprefix("generations/")
    )
    second_records, second_outputs = complete_generation(b"second")
    publish_generation(tmp_path, second_records, second_outputs)
    second_name = (
        (tmp_path / ".ci/evidence/latest")
        .readlink()
        .as_posix()
        .removeprefix("generations/")
    )
    generations = tmp_path / ".ci/evidence/generations"
    for source in (generations / second_name).iterdir():
        _ = (generations / first_name / source.name).write_bytes(source.read_bytes())
    latest = tmp_path / ".ci/evidence/latest"
    latest.unlink()
    latest.symlink_to(f"generations/{first_name}")

    with pytest.raises(EvidenceIntegrityError, match="current run authority"):
        _ = load_published_ci_generation(
            tmp_path, AUTHORITY_CONTEXT, SOURCE_TREE_SHA256, CI_AUTHORITY
        )


def test_initial_ci_publication_fsync_boundary_does_not_acknowledge_latest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_parent_fsync(_file_descriptor: int) -> None:
        raise OSError(INJECTED_WRITE_FAILURE)

    monkeypatch.setattr(ci_runner, "fsync_generation", fail_parent_fsync)
    records, outputs = complete_generation(b"initial")

    with pytest.raises(OSError, match=INJECTED_WRITE_FAILURE):
        publish_generation(tmp_path, records, outputs)

    assert not (tmp_path / ".ci/evidence/latest").exists()


@pytest.mark.parametrize("crash_at", range(1, len(CiJob) + 6))
def test_ci_generation_crash_before_each_fsync_keeps_old_or_new_complete_latest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, crash_at: int
) -> None:
    old_records, old_outputs = complete_generation(b"old")
    publish_generation(tmp_path, old_records, old_outputs)

    original_fsync = ci_contract.fsync_confined_file
    calls = 0

    def crash_before_fsync(file_descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == crash_at:
            raise OSError(INJECTED_WRITE_FAILURE)
        original_fsync(file_descriptor)

    monkeypatch.setattr(ci_contract, "fsync_confined_file", crash_before_fsync)
    monkeypatch.setattr(ci_runner, "fsync_generation", crash_before_fsync)
    new_records, new_outputs = complete_generation(b"new")
    with pytest.raises(OSError, match=INJECTED_WRITE_FAILURE):
        publish_generation(tmp_path, new_records, new_outputs)
    assert_latest_is_complete_generation(
        tmp_path, ((old_records, old_outputs), (new_records, new_outputs))
    )


@pytest.mark.parametrize("crash_at", range(1, len(CiJob) + 2))
def test_ci_generation_crash_before_each_file_write_keeps_old_or_new_complete_latest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, crash_at: int
) -> None:
    old_records, old_outputs = complete_generation(b"old")
    publish_generation(tmp_path, old_records, old_outputs)

    original_write = ci_contract.write_confined_file
    calls = 0

    def crash_before_write(directory_fd: int, name: str, content: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == crash_at:
            raise OSError(INJECTED_WRITE_FAILURE)
        original_write(directory_fd, name, content)

    monkeypatch.setattr(ci_contract, "write_confined_file", crash_before_write)
    new_records, new_outputs = complete_generation(b"new")
    with pytest.raises(OSError, match=INJECTED_WRITE_FAILURE):
        publish_generation(tmp_path, new_records, new_outputs)
    assert_latest_is_complete_generation(
        tmp_path, ((old_records, old_outputs), (new_records, new_outputs))
    )


@pytest.mark.parametrize(
    "boundary",
    ["generation-rename", "pointer-symlink", "latest-switch"],
)
def test_ci_generation_crash_at_publication_boundaries_keeps_complete_latest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    old_records, old_outputs = complete_generation(b"old")
    publish_generation(tmp_path, old_records, old_outputs)

    if boundary == "generation-rename":

        def crash_generation_rename(
            source: str,
            destination: str,
            *,
            source_dir_fd: int,
            destination_dir_fd: int,
        ) -> None:
            del source, destination, source_dir_fd, destination_dir_fd
            raise OSError(INJECTED_WRITE_FAILURE)

        monkeypatch.setattr(
            ci_runner, "atomic_rename_no_replace", crash_generation_rename
        )
    elif boundary == "pointer-symlink":

        def crash_pointer_symlink(
            target: str,
            link_name: str,
            target_is_directory: bool = False,
            *,
            dir_fd: int | None = None,
        ) -> None:
            del target, link_name, target_is_directory, dir_fd
            raise OSError(INJECTED_WRITE_FAILURE)

        monkeypatch.setattr(ci_runner, "create_latest_pointer", crash_pointer_symlink)
    else:

        def crash_latest_switch(
            evidence_fd: int,
            pointer_name: str,
        ) -> None:
            del evidence_fd, pointer_name
            raise OSError(INJECTED_WRITE_FAILURE)

        monkeypatch.setattr(ci_runner, "switch_latest_pointer", crash_latest_switch)

    new_records, new_outputs = complete_generation(b"new")
    with pytest.raises(OSError, match=INJECTED_WRITE_FAILURE):
        publish_generation(tmp_path, new_records, new_outputs)
    assert_latest_is_complete_generation(
        tmp_path, ((old_records, old_outputs), (new_records, new_outputs))
    )


def test_contract_gate_accepts_executed_counts_and_checksums() -> None:
    # Given
    records = tuple(result(job, 1) for job in CiJob)

    # When
    digest = verify_evidence(records)

    # Then
    assert len(digest) == 64


def test_contract_zero_executed_count_is_rejected() -> None:
    # Given
    records = (result(CiJob.PLATFORM_TESTS, 0),)

    # When / Then
    with pytest.raises(EvidenceIntegrityError, match="executed_count"):
        _ = verify_evidence(records)


def test_contract_checksum_free_success_text_is_rejected() -> None:
    # Given
    records = (
        GateResult(
            job=CiJob.PLATFORM_TESTS,
            executed_count=1,
            output_sha256="PASS",
        ),
    )

    # When / Then
    with pytest.raises(EvidenceIntegrityError, match="checksum"):
        _ = verify_evidence(records)


def test_contract_stale_codegen_fixture_is_rejected(tmp_path: Path) -> None:
    # Given
    source = tmp_path / "openapi.json"
    generated = tmp_path / "types.json"
    _ = source.write_text('{"paths": {}, "components": {"schemas": {}}}')
    _ = generated.write_text((FIXTURES / "stale-generated.json").read_text())
    contract = GeneratedContract.from_paths(source, generated)

    # When / Then
    with pytest.raises(StaleGeneratedContractError):
        verify_generated_contract(contract)


def test_contract_tampered_evidence_log_is_rejected(tmp_path: Path) -> None:
    # Given
    record = result(CiJob.PLATFORM_TESTS, 1, b"1 passed")
    _ = (tmp_path / "platform-tests.log").write_bytes(b"tampered")

    # When / Then
    with pytest.raises(EvidenceIntegrityError, match="raw output checksum"):
        verify_evidence_files(tmp_path, (record,))


def test_contract_unexpected_evidence_log_is_rejected(tmp_path: Path) -> None:
    # Given
    record = result(CiJob.PLATFORM_TESTS, 1, b"1 passed")
    _ = (tmp_path / "platform-tests.log").write_bytes(b"1 passed")
    _ = (tmp_path / "e2e.log").write_bytes(b"legacy")

    # When / Then
    with pytest.raises(EvidenceIntegrityError, match="exact job log set"):
        verify_evidence_files(tmp_path, (record,))


@pytest.mark.parametrize("log_kind", ["hardlink", "symlink", "fifo"])
def test_contract_evidence_logs_reject_unsafe_entries_without_blocking(
    tmp_path: Path, log_kind: str
) -> None:
    record = result(CiJob.PLATFORM_TESTS, 1, b"1 passed")
    log = tmp_path / "platform-tests.log"
    outside = tmp_path / f"outside-{log_kind}"
    _ = outside.write_bytes(b"1 passed")
    if log_kind == "hardlink":
        os.link(outside, log)
    elif log_kind == "symlink":
        log.symlink_to(outside)
    else:
        os.mkfifo(log)

    with pytest.raises(EvidenceIntegrityError, match="exact job log set"):
        verify_evidence_files(tmp_path, (record,))


def test_contract_generated_catalog_matches_openapi_source() -> None:
    # Given
    root = Path(__file__).parents[2]
    source = root / "packages/contracts/openapi/openapi.json"
    generated = root / ".ci/generated/openapi-catalog.json"

    # When
    contract = GeneratedContract.from_paths(source, generated)

    # Then
    verify_generated_contract(contract)


def test_checked_in_ci_catalog_matches_runtime_and_normative_authorities() -> None:
    root = Path(__file__).parents[2]
    catalog = load_checked_in_ci_catalog(root / ".ci/ci-contract.json")
    runtime = ci_runner.ci_commands(root)
    verified = verify_ci_control_catalog_commands(catalog, runtime, root)
    mapped_requirements = tuple(
        identifier for job in catalog.jobs for identifier in job.requirement_ids
    )
    expected_requirements = requirement_ids(
        root / "docs/requirements/requirements.yaml"
    )
    security = verified[CiJob.SECURITY]

    assert set(verified) == set(CiJob)
    assert len(mapped_requirements) == len(set(mapped_requirements)) == 81
    assert set(mapped_requirements) == set(expected_requirements)
    assert set(security.control_ids) == {f"T{number:02d}" for number in range(1, 14)}


def security_catalog_authority(catalog_id: str) -> RequiredSecurityCatalog:
    assert catalog_id == "catalog-1"
    catalog = RequiredSecurityCatalog(
        high_threat_ids=("threat-1",),
        source_root_sha256="0" * 64,
    )
    return catalog.model_copy(
        update={
            "source_root_sha256": hashlib.sha256(
                security_catalog_source_bytes(catalog)
            ).hexdigest()
        }
    )


def security_request() -> TaskAttemptRequest:
    attachment = b"security attachment"
    return TaskAttemptRequest(
        task_id="security-task",
        run_id="run",
        execution_id="execution",
        attempt_id="security-attempt",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="SECURITY",
        attachments=(attachment,),
        security_catalog_id="catalog-1",
        high_threat_evidence=(
            SecurityEvidenceMapping(
                threat_id="threat-1",
                positive_case_count=1,
                evidence_root_sha256=hashlib.sha256(attachment).hexdigest(),
            ),
        ),
    )


def test_security_attempt_requires_catalog(tmp_path: Path) -> None:
    request = TaskAttemptRequest(
        task_id="security-task",
        run_id="run",
        execution_id="execution",
        attempt_id="missing-catalog",
        revision=1,
        outcome="failure",
        exit_code=1,
        started_at="2026-07-13T00:00:00Z",
        finished_at="2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="SECURITY",
    )

    with pytest.raises(EvidenceIntegrityError, match="map every High threat"):
        _ = seal_task_attempt_evidence(tmp_path, request, b"raw evidence")


@pytest.mark.parametrize("target", ["security-catalog.json", "attachment-0"])
def test_security_attempt_load_rejects_tampering(tmp_path: Path, target: str) -> None:
    sealed = seal_task_attempt_evidence(
        tmp_path,
        security_request(),
        b"raw evidence",
        security_catalog_authority,
    )
    anchor = cast(
        "str", json.loads((sealed / "bundle.json").read_text())["root_sha256"]
    )
    _ = (sealed / target).write_bytes(b"tampered")

    with pytest.raises(EvidenceIntegrityError):
        _ = load_task_attempt_bundle(sealed, anchor, security_catalog_authority)


def test_security_attempt_load_re_resolves_catalog_authority(tmp_path: Path) -> None:
    sealed = seal_task_attempt_evidence(
        tmp_path,
        security_request(),
        b"raw evidence",
        security_catalog_authority,
    )
    anchor = cast(
        "str", json.loads((sealed / "bundle.json").read_text())["root_sha256"]
    )
    assert (
        load_task_attempt_bundle(
            sealed, anchor, security_catalog_authority
        ).security_catalog_id
        == "catalog-1"
    )

    def changed_catalog_authority(catalog_id: str) -> RequiredSecurityCatalog:
        catalog = security_catalog_authority(catalog_id)
        return catalog.model_copy(update={"high_threat_ids": ("other-threat",)})

    with pytest.raises(EvidenceIntegrityError, match="map every High threat"):
        _ = load_task_attempt_bundle(sealed, anchor, changed_catalog_authority)
