"""Command-line assembly for external provider qualification capture."""

from __future__ import annotations

import argparse
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from services.api.provider_live_capture_cases import load_cases
from services.api.provider_live_capture_errors import (
    ERROR_BINARY_INVALID,
    ERROR_LIVE_QUALIFICATION,
    CaptureError,
    capture_error,
)
from services.api.provider_live_capture_qualification import (
    QualificationAdoptionSnapshot,
    adopt_live_qualification,
    capture_live_qualification,
    require_valid_adoption_target,
)
from services.api.provider_live_capture_sandbox import (
    OPERATOR_ACCOUNT_REF_GRAMMAR,
    CodexBinaryPolicy,
    operator_account_ref_is_valid,
)
from services.api.provider_live_capture_service import QualificationCaptureAuthority
from services.api.provider_live_capture_storage import (
    CaptureRoots,
    CaptureTarget,
    atomic_publish,
)
from services.api.provider_qualification_adopter import UnixSocketQualificationWriter
from services.api.provider_qualification_authority import (
    QualificationAuthorityClientConfig,
    QualificationAuthorityError,
    UnixSocketQualificationIssuer,
    load_qualification_verifier,
    qualification_receipt_json,
)
from services.api.provider_qualification_receipt import QualificationReceiptSubject
from services.api.provider_qualification_writer import QualificationWriterError
from services.api.provider_uds import ProviderUdsClientConfig, ProviderUdsError

if TYPE_CHECKING:
    from services.api.provider_live_capture_runtime_policy import ApprovedRuntimePolicy
    from services.api.provider_runtime import Health


class RuntimePolicyLoader(Protocol):
    """Load one approved runtime policy from pinned protected bytes."""

    def __call__(
        self,
        policy_id: str,
        policy_file: Path,
        *,
        expected_sha256: str,
    ) -> ApprovedRuntimePolicy:
        """Return the exact approved policy or fail closed."""
        ...


class _CliArguments(argparse.Namespace):
    def __init__(self) -> None:
        super().__init__()
        self.cases: Path = Path()
        self.output: Path = Path()
        self.output_root: Path = Path()
        self.scratch_root: Path = Path()
        self.codex_executable: Path = Path()
        self.approved_runtime_policy: str = ""
        self.approved_runtime_policy_file: Path = Path()
        self.approved_runtime_policy_sha256: str = ""
        self.operator_account_ref: str = ""
        self.authority_public_keys: Path = Path()
        self.authority_public_keys_sha256: str = ""
        self.authority_active_key_id: str = ""
        self.authority_socket: Path = Path()
        self.receipt_output: Path = Path()
        self.org_id: str = ""
        self.user_id: str = ""
        self.connection_id: str = ""
        self.connection_revision: int = 0
        self.qualification_adopter_socket: Path = Path()
        self.runtime_home_ref: str = ""
        self.provider_account_id: str = ""
        self.eligible_models: list[str] = []
        self.selected_model: str = ""
        self.connection_health: Health = "pending"
        self.connection_created_at: str = ""


def run_cli(policy_loader: RuntimePolicyLoader) -> int:
    """Parse CLI inputs and execute the fail-closed capture/adoption workflow."""
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--cases", required=True, type=Path)
    _ = parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="absolute profile path within --output-root",
    )
    _ = parser.add_argument(
        "--output-root",
        required=True,
        type=Path,
        help="existing absolute owner-private (0700) artifact directory",
    )
    _ = parser.add_argument(
        "--scratch-root",
        required=True,
        type=Path,
        help="existing absolute owner-private (0700) transient-work directory",
    )
    _ = parser.add_argument("--codex-executable", required=True, type=Path)
    _ = parser.add_argument("--approved-runtime-policy", required=True)
    _ = parser.add_argument("--approved-runtime-policy-file", required=True, type=Path)
    _ = parser.add_argument("--approved-runtime-policy-sha256", required=True)
    _ = parser.add_argument("--authority-public-keys", required=True, type=Path)
    _ = parser.add_argument("--authority-public-keys-sha256", required=True)
    _ = parser.add_argument("--authority-active-key-id", required=True)
    _ = parser.add_argument("--authority-socket", required=True, type=Path)
    _ = parser.add_argument(
        "--receipt-output",
        required=True,
        type=Path,
        help="absolute receipt path within --output-root",
    )
    _ = parser.add_argument("--org-id", required=True)
    _ = parser.add_argument("--user-id", required=True)
    _ = parser.add_argument("--connection-id", required=True)
    _ = parser.add_argument("--connection-revision", required=True, type=int)
    _ = parser.add_argument(
        "--qualification-adopter-socket",
        required=True,
        type=Path,
    )
    _ = parser.add_argument("--runtime-home-ref", required=True)
    _ = parser.add_argument("--provider-account-id", required=True)
    _ = parser.add_argument(
        "--eligible-model",
        dest="eligible_models",
        required=True,
        action="append",
    )
    _ = parser.add_argument("--selected-model", required=True)
    _ = parser.add_argument(
        "--connection-health",
        required=True,
        choices=(
            "pending",
            "healthy",
            "reauth_required",
            "unavailable",
            "quota_exhausted",
        ),
    )
    _ = parser.add_argument("--connection-created-at", required=True)
    _ = parser.add_argument(
        "--operator-account-ref",
        required=True,
        help=(
            "operator-supplied policy metadata matching "
            f"{OPERATOR_ACCOUNT_REF_GRAMMAR}; not inferred from Codex output"
        ),
    )
    arguments = parser.parse_args(namespace=_CliArguments())
    try:
        roots = CaptureRoots(arguments.output_root, arguments.scratch_root).validate()
        if not operator_account_ref_is_valid(arguments.operator_account_ref):
            raise capture_error(ERROR_BINARY_INVALID)
        subject = QualificationReceiptSubject(
            arguments.org_id,
            arguments.user_id,
            arguments.connection_id,
            arguments.connection_revision,
        )
        snapshot = QualificationAdoptionSnapshot(
            runtime_home_ref=arguments.runtime_home_ref,
            account_id=arguments.provider_account_id,
            eligible_models=tuple(arguments.eligible_models),
            selected_model=arguments.selected_model,
            health=arguments.connection_health,
            created_at=datetime.fromisoformat(arguments.connection_created_at),
        )
        require_valid_adoption_target(subject, snapshot)
        approved = policy_loader(
            arguments.approved_runtime_policy,
            arguments.approved_runtime_policy_file,
            expected_sha256=arguments.approved_runtime_policy_sha256,
        )
        verifier = load_qualification_verifier(
            arguments.authority_public_keys,
            expected_sha256=arguments.authority_public_keys_sha256,
        )
        authority = QualificationCaptureAuthority(
            subject,
            UnixSocketQualificationIssuer(
                QualificationAuthorityClientConfig(arguments.authority_socket),
                verifier,
                active_key_id=arguments.authority_active_key_id,
            ),
            verifier,
        )
        result = capture_live_qualification(
            load_cases(arguments.cases),
            CaptureTarget(arguments.output, roots),
            CodexBinaryPolicy(
                executable=arguments.codex_executable,
                expected_sha256=approved.identity.executable_sha256,
                operator_account_ref=arguments.operator_account_ref,
                owner_uid=os.getuid(),
                expected_runtime_version=approved.identity.runtime_version,
            ),
            authority=authority,
        )
        if result.receipt is None:
            raise capture_error(ERROR_LIVE_QUALIFICATION)
        atomic_publish(
            roots,
            arguments.receipt_output,
            qualification_receipt_json(result.receipt).decode(),
        )
        _ = adopt_live_qualification(
            result,
            subject,
            UnixSocketQualificationWriter(
                ProviderUdsClientConfig(arguments.qualification_adopter_socket)
            ),
            runtime_identity=approved.identity,
            snapshot=snapshot,
        )
    except (
        CaptureError,
        QualificationAuthorityError,
        QualificationWriterError,
        ProviderUdsError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0
