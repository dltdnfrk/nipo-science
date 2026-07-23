import hashlib
import hmac
import json
import sys
import time
import tomllib
from pathlib import Path
from typing import cast

import pytest
from tools.platform_policy import ci_runner
from tools.platform_policy.ci_contract import (
    TRUSTED_REQUIREMENT_IDS,
    CiCatalogJob,
    CiControlCatalog,
    CiCurrentRun,
    CiExecutionAttestation,
    CiExecutionLease,
    CiJob,
    CiRequirementCaseBinding,
    CiRunState,
    CountKindValue,
    EvidenceIntegrityError,
    GateResult,
    RequiredSecurityCaseBinding,
    RequiredSecurityCatalog,
    SecurityCaseEvidence,
    ci_catalog_root,
    ci_catalog_source_root,
    ci_requirement_case_evidence_bytes,
    security_catalog_source_bytes,
    verify_ci_requirement_case_output,
)
from tools.platform_policy.ci_paths import (
    G002_ARTIFACT_PYTHON_PATHS,
    G002_PYTHON_PATHS,
    G002_UPLOAD_PYTHON_PATHS,
    G003_SCIENCE_PYTHON_PATHS,
    G004_ARTIFACT_UI_PYTHON_PATHS,
)
from tools.platform_policy.ci_runner import (
    CiCommand,
    CiExecutionBinding,
    CountKind,
    MissingExecutedCountError,
    archive_legacy_ci_latest,
    ci_commands,
    execute_job,
    portable_ci_argv,
    run_ci,
    source_tree_identity,
)


def _security_catalog() -> RequiredSecurityCatalog:
    binding = RequiredSecurityCaseBinding(
        threat_id="HIGH-1",
        case_id="case-1",
        source_sha256="a" * 64,
        test_sha256="b" * 64,
        denial_observation_sha256="c" * 64,
        postcondition_observation_sha256="d" * 64,
    )
    provisional = RequiredSecurityCatalog(
        high_threat_ids=("HIGH-1",),
        case_bindings=(binding,),
        source_root_sha256="0" * 64,
    )
    source_root = hashlib.sha256(security_catalog_source_bytes(provisional)).hexdigest()
    return provisional.model_copy(update={"source_root_sha256": source_root})


TEST_SECURITY_CATALOG = _security_catalog()


def _case_evidence(
    binding: RequiredSecurityCaseBinding,
) -> SecurityCaseEvidence:
    return SecurityCaseEvidence(
        threat_id=binding.threat_id,
        case_id=binding.case_id,
        source_sha256=binding.source_sha256,
        test_sha256=binding.test_sha256,
        denial_observation_sha256=binding.denial_observation_sha256,
        postcondition_observation_sha256=binding.postcondition_observation_sha256,
        outcome="passed",
    )


def _control_catalog(
    source_identity: str,
    root: Path,
    commands: tuple[CiCommand, ...],
    requirement_case_bindings: tuple[CiRequirementCaseBinding, ...] = (),
) -> CiControlCatalog:
    requirements = tuple(sorted(TRUSTED_REQUIREMENT_IDS))
    mapped_requirements = frozenset(
        binding.requirement_id for binding in requirement_case_bindings
    )
    jobs = tuple(
        CiCatalogJob(
            job=command.job,
            argv=portable_ci_argv(command, root),
            count_kind=cast("CountKindValue", str(command.count_kind)),
            analyzer_inventory_root_sha256=(
                ci_runner.inventory_root_sha256(command.inventory, root)
                if command.count_kind is CountKind.ANALYZER_INVENTORY
                else None
            ),
            analyzer_inventory_count=(
                len(command.inventory)
                if command.count_kind is CountKind.ANALYZER_INVENTORY
                else None
            ),
            category="test",
            environment_profile="test-ci",
            control_ids=(f"CONTROL-{command.job}",),
            requirement_ids=tuple(
                binding.requirement_id
                for binding in requirement_case_bindings
                if binding.job is command.job
            ),
        )
        for command in commands
    )
    provisional = CiControlCatalog.model_construct(
        version=1,
        source_identity=source_identity,
        requirements_sha256="e" * 64,
        source_root_sha256="0" * 64,
        catalog_root_sha256="0" * 64,
        security_catalog_id="test-high-threat",
        jobs=jobs,
        requirement_case_bindings=requirement_case_bindings,
        unverified_requirement_ids=tuple(
            requirement
            for requirement in requirements
            if requirement not in mapped_requirements
        ),
    )
    with_source = provisional.model_copy(
        update={"source_root_sha256": ci_catalog_source_root(provisional)}
    )
    complete = with_source.model_copy(
        update={"catalog_root_sha256": ci_catalog_root(with_source)}
    )
    return CiControlCatalog.model_validate(complete.model_dump())


class MemoryCiAuthority:
    reject_bind: bool
    commit_then_raise: bool
    anchors: dict[tuple[str, str], str]
    root: Path
    commands: tuple[CiCommand, ...]
    requirement_case_bindings: tuple[CiRequirementCaseBinding, ...]

    def __init__(
        self,
        root: Path,
        commands: tuple[CiCommand, ...],
        *,
        reject_bind: bool = False,
        commit_then_raise: bool = False,
        requirement_case_bindings: tuple[CiRequirementCaseBinding, ...] = (),
    ) -> None:
        self.root = root
        self.commands = commands
        self.requirement_case_bindings = requirement_case_bindings
        self.reject_bind = reject_bind
        self.commit_then_raise = commit_then_raise
        self.anchors = {}
        self.current: dict[str, CiCurrentRun] = {}
        self.leases: dict[str, CiExecutionLease] = {}
        self.authorized_leases: set[str] = set()
        self.lease_sequence: int = 0
        self.signing_material: bytes = b"test-memory-authority-material"

    def bind(
        self,
        authority_context: str,
        generation_id: str,
        manifest_sha256: str,
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
            attachment_sha256=record.attachment_sha256,
            security_catalog_root_sha256=record.security_catalog_root_sha256,
            security_threat_ids=record.security_threat_ids,
            security_evidence_roots=record.security_evidence_roots,
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
        if expected != attestation or not hmac.compare_digest(
            expected.signature, attestation.signature
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
        if self.reject_bind:
            message = "authority rejected manifest"
            raise RuntimeError(message)
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
        if self.commit_then_raise:
            message = "authority committed before acknowledgment failed"
            raise RuntimeError(message)

    def resolve_current(self, authority_context: str) -> CiCurrentRun:
        return self.current[authority_context]

    def resolve_control_catalog(
        self,
        authority_context: str,
        source_identity: str,
        run_id: str,
    ) -> CiControlCatalog:
        _ = authority_context, run_id
        return _control_catalog(
            source_identity,
            self.root,
            self.commands,
            self.requirement_case_bindings,
        )

    def resolve_security_catalog(self, catalog_id: str) -> RequiredSecurityCatalog:
        if catalog_id != "test-high-threat":
            raise ValueError(catalog_id)
        return TEST_SECURITY_CATALOG


def _execution_binding(
    root: Path,
    command: CiCommand,
    requirement_case_bindings: tuple[CiRequirementCaseBinding, ...] = (),
) -> CiExecutionBinding:
    commands = tuple(
        command
        if job is command.job
        else CiCommand(
            job,
            (sys.executable, "-c", 'print("1 passed")'),
            CountKind.PYTEST,
        )
        for job in CiJob
    )
    authority = MemoryCiAuthority(
        root,
        commands,
        requirement_case_bindings=requirement_case_bindings,
    )
    source_identity = source_tree_identity(root)
    current_run = CiCurrentRun(
        run_id="direct-execution-run",
        attempt_id="direct-execution-attempt",
        authority_context="direct-execution-context",
        source_tree_sha256=source_identity,
        started_at="2026-07-13T00:00:00Z",
        state=CiRunState.ACTIVE,
    )
    authority.begin(current_run)
    catalog = authority.resolve_control_catalog(
        current_run.authority_context,
        source_identity,
        current_run.run_id,
    )
    catalog_job = next(item for item in catalog.jobs if item.job is command.job)
    return CiExecutionBinding(
        catalog_job=catalog_job,
        catalog=catalog,
        current_run=current_run,
        security_catalog=(
            TEST_SECURITY_CATALOG if command.job is CiJob.SECURITY else None
        ),
        lease=authority.issue_execution_lease(current_run, command.job),
        authority=authority,
    )


def test_default_pytest_pythonpath_includes_science_package() -> None:
    project = Path(__file__).parents[2] / "pyproject.toml"

    with project.open("rb") as stream:
        configuration = tomllib.load(stream)

    assert (
        "packages/science"
        in configuration["tool"]["pytest"]["ini_options"]["pythonpath"]
    )


def test_child_environment_excludes_authority_signer_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CI_GENERATION_MANIFEST_AUTHORITY", "secret:signer")
    monkeypatch.setenv("TEST_AUTHORITY_MATERIAL", "durable-material")
    environment = ci_runner.scrubbed_subprocess_environment()
    assert "CI_GENERATION_MANIFEST_AUTHORITY" not in environment
    assert "TEST_AUTHORITY_MATERIAL" not in environment


def test_execution_requires_a_lease_before_starting_a_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executed = False

    def forbidden_process(
        _argv: tuple[str, ...],
        _root: Path,
    ) -> tuple[int, bytes]:
        nonlocal executed
        executed = True
        return 0, b"1 passed\n"

    monkeypatch.setattr(ci_runner, "RUN_PROCESS", forbidden_process)
    command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (sys.executable, "-c", 'print("1 passed")'),
        CountKind.PYTEST,
    )
    with pytest.raises(EvidenceIntegrityError, match="lease"):
        _ = execute_job(command, tmp_path)
    assert not executed


def test_substituted_command_is_rejected_before_process_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog_command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (sys.executable, "-c", 'print("1 passed")'),
        CountKind.PYTEST,
    )
    binding = _execution_binding(tmp_path, catalog_command)
    substituted = CiCommand(
        CiJob.PLATFORM_TESTS,
        (sys.executable, "-c", 'print("999 passed")'),
        CountKind.PYTEST,
    )
    executed = False

    def forbidden_process(_argv: tuple[str, ...], _root: Path) -> tuple[int, bytes]:
        nonlocal executed
        executed = True
        return 0, b"999 passed\n"

    monkeypatch.setattr(ci_runner, "RUN_PROCESS", forbidden_process)
    with pytest.raises(EvidenceIntegrityError, match="lease"):
        _ = execute_job(substituted, tmp_path, binding)
    assert not executed


@pytest.mark.parametrize(
    "reserved",
    ["<python>", "<ruff>", "<basedpyright>", "<root>"],
)
def test_reserved_portable_argument_is_rejected_before_process_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reserved: str,
) -> None:
    concrete = {
        "<python>": sys.executable,
        "<ruff>": str(Path(sys.executable).with_name("ruff")),
        "<basedpyright>": str(Path(sys.executable).with_name("basedpyright")),
        "<root>": str(tmp_path),
    }[reserved]
    catalog_command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (concrete,),
        CountKind.PYTEST,
    )
    binding = _execution_binding(tmp_path, catalog_command)
    substituted = CiCommand(
        CiJob.PLATFORM_TESTS,
        (reserved,),
        CountKind.PYTEST,
    )
    executed = False

    def forbidden_process(_argv: tuple[str, ...], _root: Path) -> tuple[int, bytes]:
        nonlocal executed
        executed = True
        return 0, b"1 passed\n"

    monkeypatch.setattr(ci_runner, "RUN_PROCESS", forbidden_process)
    with pytest.raises(EvidenceIntegrityError, match="lease"):
        _ = execute_job(substituted, tmp_path, binding)
    assert not executed


def test_forged_lease_is_rejected_before_process_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (sys.executable, "-c", 'print("1 passed")'),
        CountKind.PYTEST,
    )
    binding = _execution_binding(tmp_path, command)
    forged = CiExecutionBinding(
        catalog_job=binding.catalog_job,
        catalog=binding.catalog,
        current_run=binding.current_run,
        security_catalog=binding.security_catalog,
        lease=binding.lease.model_copy(update={"lease_id": "forged-lease"}),
        authority=binding.authority,
    )
    executed = False

    def forbidden_process(_argv: tuple[str, ...], _root: Path) -> tuple[int, bytes]:
        nonlocal executed
        executed = True
        return 0, b"1 passed\n"

    monkeypatch.setattr(ci_runner, "RUN_PROCESS", forbidden_process)
    with pytest.raises(EvidenceIntegrityError, match="lease"):
        _ = execute_job(command, tmp_path, forged)
    assert not executed


def test_stale_self_consistent_catalog_is_rejected_before_process_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fresh_command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (sys.executable, "-c", 'print("1 passed")'),
        CountKind.PYTEST,
    )
    binding = _execution_binding(tmp_path, fresh_command)
    stale_command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (sys.executable, "-c", 'print("2 passed")'),
        CountKind.PYTEST,
    )
    stale_commands = tuple(
        stale_command
        if job is stale_command.job
        else CiCommand(
            job,
            (sys.executable, "-c", 'print("1 passed")'),
            CountKind.PYTEST,
        )
        for job in CiJob
    )
    stale_catalog = _control_catalog(
        binding.current_run.source_tree_sha256,
        tmp_path,
        stale_commands,
    )
    stale_job = next(
        item for item in stale_catalog.jobs if item.job is stale_command.job
    )
    stale_binding = CiExecutionBinding(
        catalog_job=stale_job,
        catalog=stale_catalog,
        current_run=binding.current_run,
        security_catalog=None,
        lease=binding.authority.issue_execution_lease(
            binding.current_run,
            stale_command.job,
        ),
        authority=binding.authority,
    )
    executed = False

    def forbidden_process(_argv: tuple[str, ...], _root: Path) -> tuple[int, bytes]:
        nonlocal executed
        executed = True
        return 0, b"2 passed\n"

    monkeypatch.setattr(ci_runner, "RUN_PROCESS", forbidden_process)
    with pytest.raises(EvidenceIntegrityError, match="lease"):
        _ = execute_job(stale_command, tmp_path, stale_binding)
    assert not executed


def test_bounded_runner_kills_closed_pipe_descendants(tmp_path: Path) -> None:
    sentinel = tmp_path / "descendant-survived"
    child = (
        "import time; from pathlib import Path; "
        f"time.sleep(0.5); Path({str(sentinel)!r}).write_text('survived')"
    )
    parent = (
        "import subprocess, sys; "
        "subprocess.Popen("
        f"[sys.executable, '-c', {child!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True)"
    )
    return_code, _output = ci_runner.run_bounded_process(
        (sys.executable, "-c", parent),
        tmp_path,
    )
    assert return_code == 0
    time.sleep(0.8)
    assert not sentinel.exists()


@pytest.mark.parametrize("failure_mode", ["construction", "registration"])
def test_bounded_runner_cleans_up_after_selector_setup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    sentinel = tmp_path / "selector-failure-survivor"
    child = (
        "import time; from pathlib import Path; "
        f"time.sleep(0.5); Path({str(sentinel)!r}).write_text('survived')"
    )

    class FailingRegistrationSelector:
        def register(self, _fileobj: object, _events: int) -> None:
            message = "selector registration failed"
            raise RuntimeError(message)

        def close(self) -> None:
            return

    def failing_constructor() -> object:
        message = "selector construction failed"
        raise RuntimeError(message)

    def registration_failure() -> object:
        return FailingRegistrationSelector()

    factory = (
        failing_constructor if failure_mode == "construction" else registration_failure
    )
    monkeypatch.setattr(ci_runner, "SELECTOR_FACTORY", factory)
    with pytest.raises(RuntimeError, match="selector"):
        _ = ci_runner.run_bounded_process(
            (sys.executable, "-c", child),
            tmp_path,
        )
    time.sleep(0.8)
    assert not sentinel.exists()


def test_run_ci_requires_an_external_generation_authority(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="external generation authority"):
        _ = run_ci(tmp_path)


def test_unit_pytest_count_is_parsed_from_executed_output(tmp_path: Path) -> None:
    # Given
    command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (sys.executable, "-c", 'print("3 passed in 0.01s")'),
        CountKind.PYTEST,
    )

    # When
    result, _ = execute_job(command, tmp_path, _execution_binding(tmp_path, command))

    # Then
    assert result.executed_count == 3


def test_unit_pytest_count_allows_deselection_suffix(tmp_path: Path) -> None:
    # Given
    command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (sys.executable, "-c", 'print("5 passed, 4 deselected in 0.06s")'),
        CountKind.PYTEST,
    )

    # When
    result, _ = execute_job(command, tmp_path, _execution_binding(tmp_path, command))

    # Then
    assert result.executed_count == 5


def test_successful_job_without_work_markers_is_rejected(tmp_path: Path) -> None:
    command = CiCommand(
        CiJob.BOUNDARIES,
        (sys.executable, "-c", "pass"),
        CountKind.PYTEST,
    )

    with pytest.raises(MissingExecutedCountError):
        _ = execute_job(command, tmp_path, _execution_binding(tmp_path, command))


def test_child_cannot_emit_parent_owned_requirement_case_marker(
    tmp_path: Path,
) -> None:
    command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (
            sys.executable,
            "-c",
            'print("1 passed\\nCI_REQUIREMENT_CASE={}")',
        ),
        CountKind.PYTEST,
    )

    with pytest.raises(EvidenceIntegrityError, match="parent-owned"):
        _ = execute_job(command, tmp_path, _execution_binding(tmp_path, command))


def test_parent_executes_exact_bound_requirement_case(tmp_path: Path) -> None:
    source_path = tmp_path / "requirement_subject.py"
    test_path = tmp_path / "test_requirement_subject.py"
    _ = source_path.write_text(
        "def requirement_is_bound() -> bool:\n    return True\n",
        encoding="utf-8",
    )
    _ = test_path.write_text(
        "from requirement_subject import requirement_is_bound\n\n"
        "def test_bound_requirement() -> None:\n"
        "    assert requirement_is_bound()\n",
        encoding="utf-8",
    )
    provisional = CiRequirementCaseBinding.model_construct(
        requirement_id="F01",
        job=CiJob.PLATFORM_TESTS,
        case_id="case-F01",
        source_path=source_path.name,
        source_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
        test_path=test_path.name,
        test_sha256=hashlib.sha256(test_path.read_bytes()).hexdigest(),
        test_node_id=f"{test_path.name}::test_bound_requirement",
        observation_sha256="0" * 64,
    )
    binding = CiRequirementCaseBinding.model_validate(
        provisional.model_copy(
            update={
                "observation_sha256": hashlib.sha256(
                    ci_requirement_case_evidence_bytes(provisional)
                ).hexdigest()
            }
        ).model_dump()
    )
    command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (sys.executable, "-c", 'print("1 passed")'),
        CountKind.PYTEST,
    )

    result, raw_output = execute_job(
        command,
        tmp_path,
        _execution_binding(tmp_path, command, (binding,)),
    )

    verify_ci_requirement_case_output(raw_output, (binding,))
    assert result.requirement_ids == ("F01",)
    assert result.attachment_sha256 == (binding.observation_sha256,)
    assert result.execution_attestation is not None
    assert result.execution_attestation.attachment_sha256 == (
        binding.observation_sha256,
    )
    assert raw_output.count(b"CI_REQUIREMENT_CASE=") == 1


@pytest.mark.parametrize("changed_path", ["source", "test"])
def test_parent_rejects_changed_requirement_case_files(
    tmp_path: Path,
    changed_path: str,
) -> None:
    # Given: a catalog binding issued for exact source and test bytes.
    source_path = tmp_path / "requirement_subject.py"
    test_path = tmp_path / "test_requirement_subject.py"
    _ = source_path.write_text(
        "def requirement_is_bound() -> bool:\n    return True\n",
        encoding="utf-8",
    )
    _ = test_path.write_text(
        "from requirement_subject import requirement_is_bound\n\n"
        "def test_bound_requirement() -> None:\n"
        "    assert requirement_is_bound()\n",
        encoding="utf-8",
    )
    provisional = CiRequirementCaseBinding.model_construct(
        requirement_id="F01",
        job=CiJob.PLATFORM_TESTS,
        case_id="case-F01",
        source_path=source_path.name,
        source_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
        test_path=test_path.name,
        test_sha256=hashlib.sha256(test_path.read_bytes()).hexdigest(),
        test_node_id=f"{test_path.name}::test_bound_requirement",
        observation_sha256="0" * 64,
    )
    binding = CiRequirementCaseBinding.model_validate(
        provisional.model_copy(
            update={
                "observation_sha256": hashlib.sha256(
                    ci_requirement_case_evidence_bytes(provisional)
                ).hexdigest()
            }
        ).model_dump()
    )
    changed_file = source_path if changed_path == "source" else test_path
    _ = changed_file.write_text("# changed after authority binding\n", encoding="utf-8")
    command = CiCommand(
        CiJob.PLATFORM_TESTS,
        (sys.executable, "-c", 'print("1 passed")'),
        CountKind.PYTEST,
    )

    # When / Then: the parent rejects the stale authority binding before evidence.
    with pytest.raises(EvidenceIntegrityError, match="source does not match"):
        _ = execute_job(
            command,
            tmp_path,
            _execution_binding(tmp_path, command, (binding,)),
        )


def test_security_job_rejects_generic_pytest_success_without_sealed_evidence(
    tmp_path: Path,
) -> None:
    command = CiCommand(
        CiJob.SECURITY,
        (sys.executable, "-c", 'print("1 passed in 0.01s")'),
        CountKind.PYTEST,
    )

    with pytest.raises(MissingExecutedCountError):
        _ = execute_job(command, tmp_path, _execution_binding(tmp_path, command))


def test_security_job_accepts_exact_authority_mapped_evidence(tmp_path: Path) -> None:
    case_payload = _case_evidence(
        TEST_SECURITY_CATALOG.case_bindings[0]
    ).model_dump_json()
    case_line = f"SECURITY_CASE={case_payload}\n".encode()
    evidence_root = hashlib.sha256(case_line).hexdigest()
    payload = json.dumps(
        [
            {
                "threat_id": "HIGH-1",
                "job": "SECURITY",
                "positive_case_count": 1,
                "evidence_root_sha256": evidence_root,
            }
        ],
        separators=(",", ":"),
    )
    script = (
        f'print("SECURITY_CASE=" + {case_payload!r});'
        f'print("SECURITY_EVIDENCE=" + {payload!r})'
    )
    command = CiCommand(
        CiJob.SECURITY,
        (
            sys.executable,
            "-c",
            script,
        ),
        CountKind.PYTEST,
    )
    result, _output = execute_job(
        command,
        tmp_path,
        _execution_binding(tmp_path, command),
    )

    assert result.security_threat_ids == ("HIGH-1",)
    assert result.security_evidence_roots == (evidence_root,)
    assert result.attachment_sha256 == (evidence_root,)
    assert result.security_catalog_root_sha256 == (
        TEST_SECURITY_CATALOG.source_root_sha256
    )
    attestation = result.execution_attestation
    assert attestation is not None
    assert attestation.attachment_sha256 == result.attachment_sha256
    assert (
        attestation.security_catalog_root_sha256 == result.security_catalog_root_sha256
    )
    assert attestation.security_threat_ids == result.security_threat_ids
    assert attestation.security_evidence_roots == result.security_evidence_roots


def test_unittest_and_check_markers_are_summed(tmp_path: Path) -> None:
    command = CiCommand(
        CiJob.BOUNDARIES,
        (sys.executable, "-c", 'print("Ran 2 tests\\nCHECKS_EXECUTED=3")'),
        CountKind.PYTEST,
    )

    result, _ = execute_job(command, tmp_path, _execution_binding(tmp_path, command))

    assert result.executed_count == 5


def test_execute_job_redacts_structured_oauth_and_cookie_secrets(
    tmp_path: Path,
) -> None:
    command = CiCommand(
        CiJob.SECRET_SCAN,
        (
            sys.executable,
            "-c",
            "print('Author"
            "ization: Bear"
            "er bearer-material');"
            "print('{\"access_"
            'token":"json-material"}\');'
            "print('client_"
            "secret=form-material');"
            "print('Cook"
            "ie: session=session-material');"
            "print('CHECKS_EXECUTED=1')",
        ),
        CountKind.CHECKS,
    )

    result, raw_output = execute_job(
        command, tmp_path, _execution_binding(tmp_path, command)
    )

    assert result.executed_count == 1
    assert raw_output.count(b"[REDACTED]") == 4
    for material in (
        b"bearer-material",
        b"json-material",
        b"form-material",
        b"session-material",
    ):
        assert material not in raw_output


def test_execute_job_redacts_query_codes_and_preserves_binary_safe_content(
    tmp_path: Path,
) -> None:
    command = CiCommand(
        CiJob.SECRET_SCAN,
        (
            sys.executable,
            "-c",
            'import sys; sys.stdout.buffer.write(b"?device_'
            'code=code-material&x=1\\n\\x00ok\\nCHECKS_EXECUTED=1\\n")',
        ),
        CountKind.CHECKS,
    )

    result, raw_output = execute_job(
        command, tmp_path, _execution_binding(tmp_path, command)
    )

    assert result.executed_count == 1
    assert b"code-material" not in raw_output
    assert b"?device_" + b"code=[REDACTED]&x=1\n\x00ok\n" in raw_output


def test_execute_job_removes_nonsemantic_end_of_line_spacing(tmp_path: Path) -> None:
    command = CiCommand(
        CiJob.SECRET_SCAN,
        (
            sys.executable,
            "-c",
            'import sys; sys.stdout.buffer.write(b"diagnostic  \\nnext\\t\\r\\nCHECKS_EXECUTED=1  \\n")',
        ),
        CountKind.CHECKS,
    )

    result, raw_output = execute_job(
        command, tmp_path, _execution_binding(tmp_path, command)
    )

    assert result.executed_count == 1
    assert raw_output == b"diagnostic\nnext\r\nCHECKS_EXECUTED=1\n"


def test_integration_raw_output_is_returned_for_atomic_publication(
    tmp_path: Path,
) -> None:
    # Given
    command = CiCommand(
        CiJob.SECRET_SCAN,
        (sys.executable, "-c", 'print("CHECKS_EXECUTED=2")'),
        CountKind.CHECKS,
    )

    # When
    result, raw_output = execute_job(
        command, tmp_path, _execution_binding(tmp_path, command)
    )

    # Then
    assert raw_output == b"CHECKS_EXECUTED=2\n"
    assert len(result.output_sha256) == 64


def test_execute_job_uses_the_explicit_checkout_root(tmp_path: Path) -> None:
    command = CiCommand(
        CiJob.SECRET_SCAN,
        (
            sys.executable,
            "-c",
            'from pathlib import Path; print("CHECKS_EXECUTED=1"); print(Path.cwd())',
        ),
        CountKind.CHECKS,
    )

    _, raw_output = execute_job(
        command, tmp_path, _execution_binding(tmp_path, command)
    )

    assert tmp_path.as_posix().encode() in raw_output


def test_source_tree_identity_binds_ci_contract_but_ignores_ci_runtime_output(
    tmp_path: Path,
) -> None:
    contract = tmp_path / ".ci" / "ci-contract.json"
    contract.parent.mkdir()
    _ = contract.write_text('{"jobs":["lint"]}\n')
    baseline = source_tree_identity(tmp_path)

    _ = contract.write_text('{"jobs":["typecheck"]}\n')
    assert source_tree_identity(tmp_path) != baseline
    _ = contract.write_text('{"jobs":["lint"]}\n')

    for relative_path in (
        ".ci/evidence/generation/manifest.json",
        ".ci/failed-attempts/attempt/raw.log",
    ):
        runtime_output = tmp_path / relative_path
        runtime_output.parent.mkdir(parents=True, exist_ok=True)
        _ = runtime_output.write_text("runtime output")
        assert source_tree_identity(tmp_path) == baseline
        runtime_output.unlink()

    generated = tmp_path / ".ci/generated/openapi-catalog.json"
    generated.parent.mkdir(parents=True, exist_ok=True)
    _ = generated.write_text("generated contract")
    assert source_tree_identity(tmp_path) != baseline


def test_legacy_checked_in_latest_directory_is_preserved_outside_publish_pointer(
    tmp_path: Path,
) -> None:
    latest = tmp_path / ".ci/evidence/latest"
    latest.mkdir(parents=True)
    _ = (latest / "legacy.log").write_bytes(b"legacy evidence")
    baseline = source_tree_identity(tmp_path)

    archive_legacy_ci_latest(tmp_path)

    assert not latest.exists()
    archived = tuple((tmp_path / ".ci/evidence").glob(".legacy-latest-*"))
    assert len(archived) == 1
    assert (archived[0] / "legacy.log").read_bytes() == b"legacy evidence"
    assert source_tree_identity(tmp_path) == baseline


def test_missing_authority_context_does_not_archive_legacy_latest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    latest = tmp_path / ".ci/evidence/latest"
    latest.mkdir(parents=True)
    _ = (latest / "legacy.log").write_bytes(b"legacy evidence")
    monkeypatch.delenv("GITHUB_SHA", raising=False)

    with pytest.raises(ValueError, match="GITHUB_SHA"):
        _ = run_ci(tmp_path, MemoryCiAuthority(tmp_path, ()))

    assert latest.is_dir()
    assert (latest / "legacy.log").read_bytes() == b"legacy evidence"
    assert tuple((tmp_path / ".ci/evidence").glob(".legacy-latest-*")) == ()


def test_contract_ci_commands_execute_repository_gates_without_recursion(
    tmp_path: Path,
) -> None:
    # Given
    expected_make_targets = {
        CiJob.BOUNDARIES: "test-boundaries",
        CiJob.SPEC: "verify-spec",
        CiJob.ARCHITECTURE: "verify-architecture",
        CiJob.OPENAPI: "test-openapi",
        CiJob.PROTOCOL_CONTRACTS: "test-protocol-contracts",
        CiJob.ARTIFACT_CONTRACTS: "test-artifact-contracts",
        CiJob.LOCAL_CONFIG: "test-local-config",
        CiJob.MIGRATIONS: "test-migrations",
        CiJob.RLS: "test-rls",
        CiJob.UPLOAD: "test-upload",
        CiJob.ARTIFACTS: "test-artifacts",
        CiJob.SCIENCE: "test-science",
        CiJob.ARTIFACT_UI: "test-e2e-artifacts",
        CiJob.RETENTION: "test-retention",
        CiJob.GENERATED_DRIFT: "check-generated-contracts",
        CiJob.DRY_LAB: "test-dry-lab",
        CiJob.PRODUCT_UI: "test-product-ui",
        CiJob.PROVIDER_RUNTIME: "test-provider-runtime",
    }

    # When
    commands = ci_commands(tmp_path)
    make_targets = {
        command.job: command.argv[-1]
        for command in commands
        if command.argv[0] == "make"
    }

    # Then
    assert make_targets == expected_make_targets
    assert all("ci-local" not in command.argv for command in commands)
    assert all("-k" not in command.argv for command in commands)
    assert all(
        command.count_kind is not getattr(CountKind, "EXIT", None)
        for command in commands
    )


def test_contract_static_jobs_cover_g001_and_integrated_g002(
    tmp_path: Path,
) -> None:
    # Given
    expected_paths = {
        "packages/contracts/python",
        "tests/test_openapi_contract.py",
        "services/local",
        "tests/local_stack",
        "tools/platform_policy",
        "tests/platform",
        "tools/boundary_ast_rules.py",
        "tools/boundary_node_cases.py",
        "tools/boundary_node_rules.py",
        "tools/boundary_os_cases.py",
        "tools/boundary_python_sinks.py",
        "tools/boundary_shell_cases.py",
        "tools/boundary_shell_rules.py",
        "tools/boundary_text_rules.py",
        "tools/boundary_write_rules.py",
        "tools/boundary_path_values.py",
        "tools/boundary_adversarial_cases.py",
        "tools/check_boundaries.py",
        "tests/test_boundaries.py",
        "tools/verify_spec.py",
        "tools/spec_contract.py",
        "tools/spec_runtime.py",
        "tools/tests/test_verify_spec.py",
        "tools/verify_architecture.py",
        "tools/architecture_contract.py",
        "tools/architecture_manifest.py",
        "tests/test_architecture.py",
        "services/api/migrations",
        "services/api/persistence",
        "services/api/tests/persistence",
        "services/api/upload",
        "tests/upload",
        "services/api/artifacts",
        "tests/artifacts",
        "packages/science",
        "tests/science",
        "services/api/artifact_ui_app.py",
        "services/api/artifact_ui_http.py",
        "services/api/product_artifact_fixtures.py",
        "services/api/product_artifact_http.py",
        "services/api/product_artifact_types.py",
        "services/api/product_artifact_validation.py",
        "services/api/product_artifact_views.py",
        "services/api/product_artifacts.py",
        "services/api/product_pdf_validation.py",
        "services/api/product_preview.py",
        "tools/run_artifact_ui_fixture.py",
        "tests/artifact_ui",
    }
    integrated_g002 = {
        "services/api/migrations",
        "services/api/persistence",
        "services/api/tests/persistence",
    }
    assert integrated_g002 == set(G002_PYTHON_PATHS)
    integrated_upload = {"services/api/upload", "tests/upload"}
    assert integrated_upload == set(G002_UPLOAD_PYTHON_PATHS)
    integrated_artifacts = {"services/api/artifacts", "tests/artifacts"}
    assert integrated_artifacts == set(G002_ARTIFACT_PYTHON_PATHS)
    integrated_science = {"packages/science", "tests/science"}
    assert integrated_science == set(G003_SCIENCE_PYTHON_PATHS)
    integrated_artifact_ui = {
        "services/api/artifact_ui_app.py",
        "services/api/artifact_ui_http.py",
        "services/api/product_artifact_fixtures.py",
        "services/api/product_artifact_http.py",
        "services/api/product_artifact_types.py",
        "services/api/product_artifact_validation.py",
        "services/api/product_artifact_views.py",
        "services/api/product_artifacts.py",
        "services/api/product_pdf_validation.py",
        "services/api/product_preview.py",
        "tools/run_artifact_ui_fixture.py",
        "tests/artifact_ui",
    }
    assert integrated_artifact_ui == set(G004_ARTIFACT_UI_PYTHON_PATHS)

    # When
    by_job = {command.job: command for command in ci_commands(tmp_path)}
    lint_paths = set(by_job[CiJob.LINT].argv[2:])
    typecheck_paths = set(by_job[CiJob.TYPECHECK].argv[1:])

    # Then
    assert lint_paths == expected_paths
    assert typecheck_paths == expected_paths
    for paths in (lint_paths, typecheck_paths):
        assert integrated_g002 <= paths
        assert integrated_upload <= paths
        assert integrated_artifacts <= paths
        assert integrated_science <= paths
        assert integrated_artifact_ui <= paths


def test_extended_release_categories_are_exactly_once_and_non_vacuous(
    tmp_path: Path,
) -> None:
    expected_paths: dict[CiJob, str] = {
        CiJob.DRY_LAB: "test-dry-lab",
        CiJob.PRODUCT_UI: "test-product-ui",
        CiJob.PROVIDER_RUNTIME: "test-provider-runtime",
        CiJob.SECURITY: "tools.platform_policy.security_gate",
        CiJob.RECOVERY: "tests/platform/test_g005_recovery_contract.py",
        CiJob.PERFORMANCE: "tests/platform/test_deployment_contract.py",
        CiJob.RELEASE: "tests/platform/test_release_contract.py",
    }
    commands = ci_commands(tmp_path)
    selected = tuple(command for command in commands if command.job in expected_paths)

    assert len(selected) == len(expected_paths)
    assert {command.job: command.argv[-1] for command in selected} == expected_paths
    assert all(isinstance(command.argv, tuple) and command.argv for command in selected)
    assert all(
        command.count_kind in {CountKind.PYTEST, CountKind.CHECKS}
        for command in selected
    )
    assert all(
        command.count_kind is not getattr(CountKind, "EXIT", None)
        for command in commands
    )
    assert all(
        command.argv[0] != "make" or str(tmp_path) in command.argv
        for command in selected
    )


def test_zero_exit_without_an_observed_count_cannot_succeed(tmp_path: Path) -> None:
    command = CiCommand(
        CiJob.SECURITY,
        (sys.executable, "-c", "pass"),
        CountKind.PYTEST,
    )

    with pytest.raises(MissingExecutedCountError):
        _ = execute_job(command, tmp_path, _execution_binding(tmp_path, command))


def test_vacuous_current_run_preserves_prior_latest_and_seals_incomplete_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / ".ci/evidence"
    evidence.mkdir(parents=True)
    latest = evidence / "latest"
    latest.symlink_to("generations/old")
    commands = (
        CiCommand(
            CiJob.LINT,
            (sys.executable, "-c", "pass"),
            CountKind.PYTEST,
        ),
        *tuple(
            CiCommand(
                job,
                (sys.executable, "-c", 'print("1 passed")'),
                CountKind.PYTEST,
            )
            for job in tuple(CiJob)[1:]
        ),
    )

    def every_command(_root: Path) -> tuple[CiCommand, ...]:
        return commands

    monkeypatch.setattr(ci_runner, "ci_commands", every_command)
    monkeypatch.setenv(
        ci_runner.CI_SOURCE_TREE_ENV,
        source_tree_identity(tmp_path),
    )
    monkeypatch.setenv("GITHUB_SHA", "revision")

    with pytest.raises(MissingExecutedCountError):
        _ = run_ci(tmp_path, MemoryCiAuthority(tmp_path, commands))

    assert latest.readlink() == Path("generations/old")
    bundles = tuple((tmp_path / ".ci/failed-attempts").rglob("bundle.json"))
    assert len(bundles) == 1
    assert '"outcome":"incomplete"' in bundles[0].read_text()


@pytest.mark.parametrize("commit_then_raise", [False, True])
def test_publication_finalization_reconciles_authority_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    commit_then_raise: bool,
) -> None:
    evidence = tmp_path / ".ci/evidence"
    evidence.mkdir(parents=True)
    latest = evidence / "latest"
    latest.symlink_to("generations/old")
    commands = tuple(
        CiCommand(job, ("trusted", str(job)), CountKind.PYTEST) for job in CiJob
    )
    raw_output = b"1 passed\n"

    def every_command(_root: Path) -> tuple[CiCommand, ...]:
        return commands

    def successful_job(
        command: CiCommand,
        _root: Path,
        binding: CiExecutionBinding,
    ) -> tuple[GateResult, bytes]:
        catalog_job = binding.catalog_job
        catalog = binding.catalog
        catalog_run_id = binding.current_run.run_id
        security_catalog = binding.security_catalog
        security = command.job is CiJob.SECURITY
        if security:
            if security_catalog is None:
                message = "missing SECURITY catalog"
                raise RuntimeError(message)
            case_lines = tuple(
                b"SECURITY_CASE="
                + _case_evidence(binding).model_dump_json().encode()
                + b"\n"
                for binding in security_catalog.case_bindings
            )
            evidence_roots = tuple(
                hashlib.sha256(case_line).hexdigest() for case_line in case_lines
            )
            mappings = [
                {
                    "threat_id": identifier,
                    "job": "SECURITY",
                    "positive_case_count": 1,
                    "evidence_root_sha256": evidence_root,
                }
                for identifier, evidence_root in zip(
                    (binding.threat_id for binding in security_catalog.case_bindings),
                    evidence_roots,
                    strict=True,
                )
            ]
            marker = json.dumps(mappings, separators=(",", ":")).encode()
            output = b"".join(case_lines) + b"SECURITY_EVIDENCE=" + marker + b"\n"
        else:
            output = raw_output
            evidence_roots = ()
        record = GateResult(
            job=command.job,
            executed_count=1,
            output_sha256=hashlib.sha256(output).hexdigest(),
            argv=catalog_job.argv,
            count_kind=catalog_job.count_kind,
            category=catalog_job.category,
            environment_profile=catalog_job.environment_profile,
            control_ids=catalog_job.control_ids,
            requirement_ids=catalog_job.requirement_ids,
            prerequisites=catalog_job.prerequisites,
            blockers=catalog_job.blockers,
            attachment_sha256=evidence_roots,
            started_at="2026-07-13T00:00:00Z",
            finished_at="2026-07-13T00:00:01Z",
            catalog_root_sha256=catalog.catalog_root_sha256,
            catalog_source_root_sha256=catalog.source_root_sha256,
            catalog_run_id=catalog_run_id,
            security_catalog_root_sha256=(
                security_catalog.source_root_sha256
                if security and security_catalog is not None
                else None
            ),
            security_threat_ids=(
                security_catalog.high_threat_ids
                if security and security_catalog is not None
                else ()
            ),
            security_evidence_roots=evidence_roots,
        )
        binding.authority.authorize_execution_lease(
            binding.lease,
            binding.current_run,
            binding.catalog,
            catalog_job,
        )
        attestation = binding.authority.attest_execution(
            binding.lease,
            record,
            "test-toolchain",
        )
        return (
            record.model_copy(update={"execution_attestation": attestation}),
            output,
        )

    monkeypatch.setattr(ci_runner, "ci_commands", every_command)
    monkeypatch.setattr(ci_runner, "execute_job", successful_job)
    monkeypatch.setenv(
        ci_runner.CI_SOURCE_TREE_ENV,
        source_tree_identity(tmp_path),
    )
    monkeypatch.setenv("GITHUB_SHA", "revision")

    authority = MemoryCiAuthority(
        tmp_path,
        commands,
        reject_bind=not commit_then_raise,
        commit_then_raise=commit_then_raise,
    )
    if commit_then_raise:
        records = run_ci(tmp_path, authority)
        assert len(records) == len(CiJob)
        assert latest.is_symlink()
        current = authority.resolve_current("revision")
        assert current.state is CiRunState.SUCCESS
        assert current.generation_id == latest.readlink().name
    else:
        with pytest.raises(RuntimeError, match="authority rejected"):
            _ = run_ci(tmp_path, authority)
        assert not latest.is_symlink()
