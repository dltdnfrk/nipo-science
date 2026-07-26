import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Final, NoReturn, cast

import pytest
from tools.platform_policy import ci_contract, ci_rechain
from tools.platform_policy.ci_contract import (
    CiControlCatalog,
    CiJob,
    CountKindValue,
    EvidenceIntegrityError,
    ci_catalog_root,
    ci_catalog_source_root,
    load_checked_in_ci_catalog,
)
from tools.platform_policy.ci_rechain import (
    RechainJobMetadata,
    rechain_checked_in_catalog,
)
from tools.platform_policy.ci_runner import (
    CountKind,
    ci_commands,
    inventory_root_sha256,
    portable_ci_argv,
    verify_ci_control_catalog_commands,
)

CATALOG_RELATIVE_PATH: Final = Path(".ci") / "ci-contract.json"
TEMPORARY_RELATIVE_PATH: Final = Path(".ci") / "ci-contract.json.rechain-tmp"
REQUIREMENTS_RELATIVE_PATH: Final = Path("docs") / "requirements" / "requirements.yaml"
FIXTURE_MODULE_RELATIVE_PATH: Final = Path(
    "tools/platform_policy/rechain_fixture_module.py"
)

CORRUPT_DOCUMENTS: Final = (
    b"not json\n",
    b'{"catalog":{},"catalog":{}}\n',
    b'{"catalog":{},"unexpected":1}\n',
    b'{"catalog":"text"}\n',
    b'{"catalog":{"version":2,"source_identity":"x","security_catalog_id":"y","jobs":[]}}\n',
    b'{"catalog":{"version":1,"source_identity":1,"security_catalog_id":"y","jobs":[]}}\n',
    b'{"catalog":{"version":1,"source_identity":"x","security_catalog_id":"y","jobs":["lint"]}}\n',
)


def _seed_root(root: Path) -> Path:
    module = root / FIXTURE_MODULE_RELATIVE_PATH
    module.parent.mkdir(parents=True)
    _ = module.write_text("FIXTURE_VALUE = 1\n", encoding="utf-8")
    requirements = root / REQUIREMENTS_RELATIVE_PATH
    requirements.parent.mkdir(parents=True)
    _ = requirements.write_text("requirements: fixture\n", encoding="utf-8")
    (root / ".ci").mkdir()
    return module


def _seed_catalog(root: Path) -> CiControlCatalog:
    jobs = tuple(
        ci_contract.CiCatalogJob(
            job=command.job,
            argv=portable_ci_argv(command, root),
            count_kind=cast("CountKindValue", str(command.count_kind)),
            parser_version=1,
            analyzer_inventory_root_sha256=(
                inventory_root_sha256(command.inventory, root)
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
            control_ids=(f"CI-TEST-{command.job}",),
            requirement_ids=(),
        )
        for command in ci_commands(root)
    )
    provisional = CiControlCatalog.model_construct(
        version=1,
        source_identity="test-checked-in",
        requirements_sha256=hashlib.sha256(
            (root / REQUIREMENTS_RELATIVE_PATH).read_bytes()
        ).hexdigest(),
        source_root_sha256="0" * 64,
        catalog_root_sha256="0" * 64,
        security_catalog_id="test-high-threat",
        jobs=jobs,
        requirement_case_bindings=(),
        unverified_requirement_ids=tuple(sorted(ci_contract.TRUSTED_REQUIREMENT_IDS)),
    )
    with_source = provisional.model_copy(
        update={"source_root_sha256": ci_catalog_source_root(provisional)}
    )
    complete = with_source.model_copy(
        update={"catalog_root_sha256": ci_catalog_root(with_source)}
    )
    return CiControlCatalog.model_validate(complete.model_dump())


def _write_document(
    root: Path,
    catalog: CiControlCatalog,
    extras: dict[str, object] | None = None,
) -> Path:
    document: dict[str, object] = {"catalog": catalog.model_dump(mode="json")}
    document.update(extras or {"evidence": {"aggregate": "sha256"}})
    path = root / CATALOG_RELATIVE_PATH
    _ = path.write_text(
        json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _rewrite_document(root: Path, mutate: Callable[[dict[str, object]], None]) -> None:
    path = root / CATALOG_RELATIVE_PATH
    document = cast("dict[str, object]", json.loads(path.read_bytes()))
    mutate(document)
    _ = path.write_text(
        json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _catalog_jobs(document: dict[str, object]) -> list[object]:
    catalog = cast("dict[str, object]", document["catalog"])
    return cast("list[object]", catalog["jobs"])


def test_rechain_is_byte_idempotent_for_a_current_catalog(tmp_path: Path) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))
    original = catalog.read_bytes()

    result = rechain_checked_in_catalog(tmp_path)

    assert result.content == original
    assert catalog.read_bytes() == original
    assert result.added_jobs == ()
    assert result.removed_jobs == ()
    assert len(result.catalog.jobs) == len(CiJob)
    verified = load_checked_in_ci_catalog(catalog)
    assert verified == result.catalog
    bound = verify_ci_control_catalog_commands(
        verified, ci_commands(tmp_path), tmp_path
    )
    assert set(bound) == set(CiJob)


def test_rechain_rewrites_changed_argv_with_an_unchanged_job_count(
    tmp_path: Path,
) -> None:
    _ = _seed_root(tmp_path)
    seed = _seed_catalog(tmp_path)
    stale_jobs = tuple(
        job.model_copy(
            update={
                "argv": (
                    "make",
                    "--no-print-directory",
                    "-C",
                    "<root>",
                    "verify-spec-v04",
                )
            }
        )
        if job.job is CiJob.SPEC
        else job
        for job in seed.jobs
    )
    catalog = _write_document(tmp_path, seed.model_copy(update={"jobs": stale_jobs}))

    result = rechain_checked_in_catalog(tmp_path)

    assert len(result.catalog.jobs) == len(CiJob)
    assert result.added_jobs == ()
    assert result.removed_jobs == ()
    commands = {command.job: command for command in ci_commands(tmp_path)}
    expected = portable_ci_argv(commands[CiJob.SPEC], tmp_path)
    item = next(job for job in result.catalog.jobs if job.job is CiJob.SPEC)
    assert item.argv == expected
    assert load_checked_in_ci_catalog(catalog) == result.catalog


def test_rechain_recomputes_analyzer_inventory(tmp_path: Path) -> None:
    module = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))
    _ = module.write_text("FIXTURE_VALUE = 2\n", encoding="utf-8")
    extra = tmp_path / "tools" / "platform_policy" / "rechain_extra_module.py"
    _ = extra.write_text("EXTRA_VALUE = 3\n", encoding="utf-8")

    result = rechain_checked_in_catalog(tmp_path)

    commands = {command.job: command for command in ci_commands(tmp_path)}
    for job in (CiJob.LINT, CiJob.TYPECHECK):
        command = commands[job]
        item = next(item for item in result.catalog.jobs if item.job is job)
        assert item.analyzer_inventory_root_sha256 == inventory_root_sha256(
            command.inventory, tmp_path
        )
        assert item.analyzer_inventory_count == len(command.inventory)
    assert load_checked_in_ci_catalog(catalog) == result.catalog


def test_rechain_removes_retired_jobs(tmp_path: Path) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))

    def add_legacy_job(document: dict[str, object]) -> None:
        jobs = _catalog_jobs(document)
        legacy = dict(cast("dict[str, object]", jobs[0]))
        legacy["job"] = "product-legacy"
        jobs.append(legacy)

    _rewrite_document(tmp_path, add_legacy_job)

    result = rechain_checked_in_catalog(tmp_path)

    assert result.removed_jobs == ("product-legacy",)
    assert result.added_jobs == ()
    assert len(result.catalog.jobs) == len(CiJob)
    assert {str(job.job) for job in result.catalog.jobs} == {str(job) for job in CiJob}
    assert load_checked_in_ci_catalog(catalog) == result.catalog


def test_rechain_adds_a_job_with_supplied_metadata(tmp_path: Path) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))

    def drop_spec_job(document: dict[str, object]) -> None:
        jobs = _catalog_jobs(document)
        jobs[:] = [
            job
            for job in jobs
            if cast("dict[str, object]", job)["job"] != str(CiJob.SPEC)
        ]

    _rewrite_document(tmp_path, drop_spec_job)
    metadata = {
        CiJob.SPEC: RechainJobMetadata(
            control_ids=("CI-005",),
            category="contract",
            environment_profile="local-ci",
        )
    }

    result = rechain_checked_in_catalog(tmp_path, new_job_metadata=metadata)

    assert result.added_jobs == (str(CiJob.SPEC),)
    assert result.removed_jobs == ()
    assert len(result.catalog.jobs) == len(CiJob)
    item = next(job for job in result.catalog.jobs if job.job is CiJob.SPEC)
    assert item.control_ids == ("CI-005",)
    assert item.category == "contract"
    assert load_checked_in_ci_catalog(catalog) == result.catalog


def test_rechain_requires_metadata_for_a_job_missing_from_the_prior_catalog(
    tmp_path: Path,
) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))

    def drop_spec_job(document: dict[str, object]) -> None:
        jobs = _catalog_jobs(document)
        jobs[:] = [
            job
            for job in jobs
            if cast("dict[str, object]", job)["job"] != str(CiJob.SPEC)
        ]

    _rewrite_document(tmp_path, drop_spec_job)
    original = catalog.read_bytes()

    with pytest.raises(EvidenceIntegrityError, match="metadata is missing"):
        _ = rechain_checked_in_catalog(tmp_path)
    assert catalog.read_bytes() == original
    assert not (tmp_path / TEMPORARY_RELATIVE_PATH).exists()


def test_rechain_rejects_metadata_that_no_missing_job_can_consume(
    tmp_path: Path,
) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))
    original = catalog.read_bytes()
    metadata = {
        CiJob.SPEC: RechainJobMetadata(control_ids=("CI-005",), category="contract")
    }

    with pytest.raises(EvidenceIntegrityError, match="not needed"):
        _ = rechain_checked_in_catalog(tmp_path, new_job_metadata=metadata)
    assert catalog.read_bytes() == original
    assert not (tmp_path / TEMPORARY_RELATIVE_PATH).exists()


def test_rechain_regenerates_unverified_ids_after_trusted_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))
    replacement = frozenset({"AC-L01", "AC-L02", "LS01"})
    monkeypatch.setattr(ci_contract, "TRUSTED_REQUIREMENT_IDS", replacement)
    with pytest.raises(EvidenceIntegrityError, match="invalid"):
        _ = load_checked_in_ci_catalog(catalog)

    result = rechain_checked_in_catalog(tmp_path)

    assert result.catalog.unverified_requirement_ids == tuple(sorted(replacement))
    verified = load_checked_in_ci_catalog(catalog)
    assert frozenset(verified.unverified_requirement_ids) == replacement
    assert verified == result.catalog


@pytest.mark.parametrize("content", CORRUPT_DOCUMENTS)
def test_rechain_rejects_corrupt_catalogs_without_writing(
    tmp_path: Path, content: bytes
) -> None:
    _ = _seed_root(tmp_path)
    catalog = tmp_path / CATALOG_RELATIVE_PATH
    _ = catalog.write_bytes(content)

    with pytest.raises(EvidenceIntegrityError, match="invalid"):
        _ = rechain_checked_in_catalog(tmp_path)
    assert catalog.read_bytes() == content
    assert not (tmp_path / TEMPORARY_RELATIVE_PATH).exists()


def test_rechain_rejects_corrupt_surviving_job_metadata(tmp_path: Path) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))

    def corrupt_control_ids(document: dict[str, object]) -> None:
        jobs = _catalog_jobs(document)
        cast("dict[str, object]", jobs[0])["control_ids"] = "CI-TEST"

    _rewrite_document(tmp_path, corrupt_control_ids)
    original = catalog.read_bytes()
    with pytest.raises(EvidenceIntegrityError, match="invalid"):
        _ = rechain_checked_in_catalog(tmp_path)
    assert catalog.read_bytes() == original
    assert not (tmp_path / TEMPORARY_RELATIVE_PATH).exists()


def test_rechain_self_check_blocks_a_catalog_that_would_not_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))
    original = catalog.read_bytes()

    def reject(_path: Path) -> NoReturn:
        raise EvidenceIntegrityError(None, "injected self-check failure")

    monkeypatch.setattr(ci_contract, "load_checked_in_ci_catalog", reject)

    with pytest.raises(EvidenceIntegrityError, match="injected self-check"):
        _ = rechain_checked_in_catalog(tmp_path)
    assert catalog.read_bytes() == original
    assert not (tmp_path / TEMPORARY_RELATIVE_PATH).exists()


def test_main_rechains_the_checked_in_catalog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _ = _seed_root(tmp_path)
    seed = _seed_catalog(tmp_path)
    stale_jobs = tuple(
        job.model_copy(update={"argv": ("stale", "argv")})
        if job.job is CiJob.SPEC
        else job
        for job in seed.jobs
    )
    catalog = _write_document(tmp_path, seed.model_copy(update={"jobs": stale_jobs}))
    monkeypatch.setattr(sys, "argv", ["ci_rechain", str(tmp_path)])

    assert ci_rechain.main() == 0

    assert "CI_RECHAINED" in capsys.readouterr().out
    commands = {command.job: command for command in ci_commands(tmp_path)}
    verified = load_checked_in_ci_catalog(catalog)
    item = next(job for job in verified.jobs if job.job is CiJob.SPEC)
    assert item.argv == portable_ci_argv(commands[CiJob.SPEC], tmp_path)


_SPEC_METADATA_JSON: Final = (
    '{"spec":{"control_ids":["CI-005"],"category":"contract",'
    '"environment_profile":"local-ci","prerequisites":[],"blockers":[]}}\n'
)
INVALID_METADATA_DOCUMENTS: Final = (
    b"not json\n",
    b'{"spec":{}}\n',
    b'{"spec":"text"}\n',
    b'{"spec":{"control_ids":[],"category":"contract"}}\n',
    b'{"spec":{"control_ids":["CI-005"],"category":"contract","rogue":1}}\n',
)


def _drop_spec_job(document: dict[str, object]) -> None:
    jobs = _catalog_jobs(document)
    jobs[:] = [
        job for job in jobs if cast("dict[str, object]", job)["job"] != str(CiJob.SPEC)
    ]


def _write_metadata(root: Path, payload: bytes) -> Path:
    path = root / "new-job-metadata.json"
    _ = path.write_bytes(payload)
    return path


def test_main_consumes_a_metadata_file_for_a_job_missing_from_the_catalog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))
    _rewrite_document(tmp_path, _drop_spec_job)
    metadata_path = _write_metadata(tmp_path, _SPEC_METADATA_JSON.encode())
    monkeypatch.setattr(sys, "argv", ["ci_rechain", str(tmp_path), str(metadata_path)])

    assert ci_rechain.main() == 0

    captured = capsys.readouterr()
    assert "CI_RECHAINED" in captured.out
    assert f"added={CiJob.SPEC}" in captured.out
    item = next(
        job for job in load_checked_in_ci_catalog(catalog).jobs if job.job is CiJob.SPEC
    )
    assert item.control_ids == ("CI-005",)
    assert item.category == "contract"


def test_main_rejects_a_metadata_file_for_a_job_already_in_the_catalog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))
    original = catalog.read_bytes()
    metadata_path = _write_metadata(tmp_path, _SPEC_METADATA_JSON.encode())
    monkeypatch.setattr(sys, "argv", ["ci_rechain", str(tmp_path), str(metadata_path)])

    assert ci_rechain.main() == 1

    assert "CI re-chain failed" in capsys.readouterr().err
    assert catalog.read_bytes() == original
    assert not (tmp_path / TEMPORARY_RELATIVE_PATH).exists()


def test_main_rejects_a_missing_metadata_file_when_a_job_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _ = _seed_root(tmp_path)
    catalog = _write_document(tmp_path, _seed_catalog(tmp_path))
    _rewrite_document(tmp_path, _drop_spec_job)
    original = catalog.read_bytes()
    monkeypatch.setattr(sys, "argv", ["ci_rechain", str(tmp_path)])

    assert ci_rechain.main() == 1

    assert "CI re-chain failed" in capsys.readouterr().err
    assert catalog.read_bytes() == original


def test_main_rejects_invalid_metadata_documents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for index, payload in enumerate(INVALID_METADATA_DOCUMENTS):
        case_root = tmp_path / f"case{index}"
        _ = case_root.mkdir()
        _ = _seed_root(case_root)
        _ = _write_document(case_root, _seed_catalog(case_root))
        metadata_path = _write_metadata(case_root, payload)
        monkeypatch.setattr(
            sys, "argv", ["ci_rechain", str(case_root), str(metadata_path)]
        )

        assert ci_rechain.main() == 1, payload

        assert "CI re-chain failed" in capsys.readouterr().err


def test_main_rejects_a_metadata_document_with_an_unknown_job_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _ = _seed_root(tmp_path)
    _ = _write_document(tmp_path, _seed_catalog(tmp_path))
    metadata_path = _write_metadata(
        tmp_path, b'{"rogue-job":{"control_ids":["CI-005"],"category":"contract"}}\n'
    )
    monkeypatch.setattr(sys, "argv", ["ci_rechain", str(tmp_path), str(metadata_path)])

    assert ci_rechain.main() == 1

    assert "CI re-chain failed" in capsys.readouterr().err


def test_main_rejects_excess_argv(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["ci_rechain", "a", "b", "c"])

    assert ci_rechain.main() == 2

    captured = capsys.readouterr()
    assert "usage:" in captured.err
