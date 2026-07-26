"""Start the real local Nipo Science API for the browser e2e suite.

This is not a mock. It builds a throwaway data root, opens the real
`LocalArtifactStore`, the real `ProviderRegistry`, and the real `LocalReadModel`,
then calls `start_local_api`, which binds a real loopback socket, mints a real
per-run session credential, installs the real `LocalGuard`, and serves the real
`apps/web/local` front end from that same origin. Every assertion the Playwright
suite makes about status codes, error bodies, security headers, and credential
handling is therefore made against the production surface.

The seeded content is produced by the real workbench chain rather than written
by hand: `approve_analysis` plus `run_analysis` execute the actual deterministic
analysis and commit the four Artifact Versions (csv, png, markdown, ledger) with
the digests the store itself computed. The Run projection is served by the real
`StoreRunSurface` over the durable `runs`, `executions`, and `run_outputs`
tables, so `execution_isolation` reaches the browser from the column the
producing execution wrote rather than from a value the fixture supplied.

Handshake: this process prints one JSON line on stdout when the listener is up,
then blocks until stdin closes.

    {"base_url": ..., "port": ..., "token": ..., "header": ..., "root": ...,
     "project_id": ..., "run_id": ..., "artifacts": [...]}

The credential is handed to the test runner over the pipe rather than being read
out of the token file, because the file is mode 0600 and the point of the
handshake is to prove the browser can only reach the API when it presents it.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import mkdtemp
from typing import Final
from uuid import UUID

REPOSITORY: Final = Path(__file__).resolve().parents[2]
for entry in ("apps/local", "packages/science", "."):
    candidate = str(REPOSITORY / entry) if entry != "." else str(REPOSITORY)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from nipo_local.api import default_deps, start_local_api  # noqa: E402
from nipo_local.apiquery import LocalReadModel  # noqa: E402
from nipo_local.config import DEFAULT_PROJECT_ID, resolve_paths  # noqa: E402
from nipo_local.providers import (  # noqa: E402
    InMemoryCredentialBackend,
    ProviderRegistry,
)
from nipo_local.runsurface import StoreRunSurface  # noqa: E402
from nipo_local.store import LocalArtifactStore, ProjectRecord  # noqa: E402
from nipo_local.workbench import (  # noqa: E402
    approve_analysis,
    assemble_artifact_runtime,
    local_scope,
    read_run_record,
    run_analysis,
)
from science_workbench_science import (  # noqa: E402
    CalibrationMetadata,
    DataOrigin,
    InputMetadata,
    MeasurementUnit,
    ProbeInput,
    ResearchIntent,
    ResearchMode,
    SpectrumInput,
)

CALIBRATED_AT: Final = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
LINEAGE: Final = (UUID("018f47a0-7b9c-7aaa-8def-0123456789ab"),)
WAVELENGTHS: Final = (400.0, 410.0, 420.0, 430.0, 440.0, 450.0, 460.0)
INTENSITIES: Final = (0.10, 0.35, 0.20, 0.55, 0.25, 0.30, 0.15)
PROJECT_NAME: Final = "프로브 스펙트럼 재현 2026"

INTENT: Final = ResearchIntent(
    question="Does the calibrated 430 nm band persist across replicate runs?",
    rationale="A stable corrected maximum would justify a targeted follow-up.",
    intended_benefit="Avoid bench time spent on non-reproducible bands.",
    success_criteria=("A corrected local maximum is reported near 430 nm.",),
    constraints=("Observed calibrated spectra only.",),
    stop_conditions=("Stop when calibration metadata is absent.",),
    research_mode=ResearchMode.AI_FOR_SCIENCE,
    data_origin=DataOrigin.OBSERVED,
)


def _probe() -> ProbeInput:
    """Build the calibrated spectrum the seeded run actually analyses."""
    return ProbeInput(
        spectrum=SpectrumInput(
            wavelengths=WAVELENGTHS,
            intensities=INTENSITIES,
            metadata=InputMetadata(
                units=(
                    MeasurementUnit(quantity="wavelength", ucum_code="nm"),
                    MeasurementUnit(quantity="intensity", ucum_code="1"),
                ),
                calibration=CalibrationMetadata(
                    method="two-point-standard",
                    reference="NIST-SRM-2242",
                    calibrated_at=CALIBRATED_AT,
                    calibration_sha256="c" * 64,
                ),
                lineage_version_ids=LINEAGE,
                research_only=True,
                non_clinical=True,
            ),
        )
    )


def _seed(store: LocalArtifactStore, root: Path) -> dict[str, object]:
    """Register the Project and execute one real analysis chain inside it."""
    paths = resolve_paths(root)
    scope = local_scope(DEFAULT_PROJECT_ID)
    _ = store.create_project(
        scope,
        ProjectRecord(
            id=DEFAULT_PROJECT_ID,
            org_id=scope.org_id,
            name=PROJECT_NAME,
            created_at=datetime.now(UTC),
        ),
    )
    runtime = assemble_artifact_runtime(store, paths, project_id=DEFAULT_PROJECT_ID)
    approved = approve_analysis(runtime, INTENT)
    run = run_analysis(runtime, INTENT, _probe(), approved)
    record = read_run_record(paths, runtime.execution_id) or {}
    return {
        "project_id": str(DEFAULT_PROJECT_ID),
        "project_name": PROJECT_NAME,
        "run_id": str(record.get("run_id", "")),
        "execution_id": str(runtime.execution_id),
        "execution_isolation": record.get("execution_isolation"),
        "artifacts": [
            {
                "role": item.role,
                "name": item.name,
                "artifact_id": str(item.artifact.id),
                "version_id": str(item.version.id),
                "version_no": item.version.version_no,
                "content_sha256": item.version.content_sha256,
                "media_type": item.version.media_type,
                "size_bytes": item.version.size_bytes,
            }
            for item in run.outputs
        ],
    }


def main() -> int:
    """Start the real listener, publish the handshake, and serve until stdin ends."""
    root = Path(mkdtemp(prefix="nipo-e2e-"))
    paths = resolve_paths(root)
    paths.ensure()
    store = LocalArtifactStore(paths)
    seeded = _seed(store, root)
    registry = ProviderRegistry(paths, InMemoryCredentialBackend(), {})
    read_model = LocalReadModel(paths)
    # `NIPO_E2E_RUN_SURFACE=0` leaves the declared Run seam unbound, which is
    # the state a stock install is in today. The UI must then say so rather
    # than render an empty list that would read as "this Project has no Runs".
    bind_runs = os.environ.get("NIPO_E2E_RUN_SURFACE", "1") != "0"
    running = start_local_api(
        paths,
        default_deps(
            store,
            registry,
            read_model,
            paths,
            StoreRunSurface(store) if bind_runs else None,
        ),
    )
    handshake = {
        "base_url": running.base_url,
        "port": running.port,
        "token": running.token.value,
        "header": "X-Nipo-Token",
        "root": str(root),
        "run_surface_bound": bind_runs,
        **seeded,
    }
    _ = sys.stdout.write(f"{json.dumps(handshake)}\n")
    _ = sys.stdout.flush()
    try:
        # Block until the test runner closes the pipe.
        for _ in sys.stdin:
            pass
    finally:
        running.close()
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
