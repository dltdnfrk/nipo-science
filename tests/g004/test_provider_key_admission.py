import json
import os
import socket
import tempfile
from collections.abc import Awaitable, Callable, Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from threading import Thread

import pytest
from services.api.provider_qualification_adopter import (
    QualificationAdopterServerConfig,
    build_qualification_adopter_server,
)
from services.api.provider_qualification_adopter import (
    main as qualification_adopter_main,
)
from services.api.provider_qualification_authority import (
    QualificationAuthorityClientConfig,
    QualificationAuthorityError,
    UnixSocketQualificationIssuer,
    qualification_receipt_json,
)
from services.api.provider_qualification_receipt import (
    QualificationReceiptAdmissionPolicy,
    QualificationReceiptClaim,
    QualificationReceiptSubject,
    RsaQualificationReceiptVerifier,
    qualification_receipt_sha256,
)
from services.api.provider_qualification_writer import (
    PostgresQualificationWriter,
    QualificationWriterError,
)
from services.api.provider_runtime import (
    ProviderConnection,
    ProviderPrincipal,
    ProviderQualificationIdentity,
    ProviderRuntimeIdentity,
)

from .provider_qualification_support import (
    TestQualificationAuthority,
    qualification_public_key_document,
)

_ACTIVE_KEY_ID = "test-qualification-rsa-3072-active"
_RETIRED_KEY_ID = "test-qualification-rsa-3072-retired"


@contextmanager
def _short_socket(name: str) -> Generator[Path]:
    with tempfile.TemporaryDirectory(prefix="swb-key-") as directory:
        root = Path(directory).resolve()
        root.chmod(0o700)
        yield root / name


def _claim() -> QualificationReceiptClaim:
    return QualificationReceiptClaim(
        subject=QualificationReceiptSubject(
            "018f0d7d-6b17-7a91-8b31-2f7331677d01",
            "018f0d7d-6b17-7a91-8b31-2f7331677d02",
            "018f0d7d-6b17-7a91-8b31-2f7331677d03",
            2,
        ),
        profile_sha256="1" * 64,
        cases_sha256="2" * 64,
        adapter_id="openai_codex",
        oauth_mode="official_subscription_oauth",
        oauth_provider="openai",
        operator_account_ref="acct_key_admission_test",
        runtime_version="codex-cli-0.144.1",
        executable_sha256="3" * 64,
        protocol_attempts=30,
        cleanup_terminal=True,
        cleanup_redaction_complete=True,
    )


def test_retired_receipt_remains_cryptographically_verifiable() -> None:
    issued_at = datetime(2025, 1, 1, tzinfo=UTC)
    retired = TestQualificationAuthority(issued_at, key_id=_RETIRED_KEY_ID)
    active = TestQualificationAuthority(issued_at, key_id=_ACTIVE_KEY_ID)
    historical_verifier = RsaQualificationReceiptVerifier(
        (retired.verifier.keys[0], active.verifier.keys[0])
    )

    receipt = retired.issue(_claim())

    assert historical_verifier.verify(receipt)


@pytest.mark.parametrize(
    ("receipt_key_id", "accepted"),
    [(_ACTIVE_KEY_ID, True), (_RETIRED_KEY_ID, False)],
)
def test_capture_authority_response_requires_active_key(
    receipt_key_id: str,
    accepted: bool,
) -> None:
    issued_at = datetime(2025, 1, 1, tzinfo=UTC)
    active = TestQualificationAuthority(issued_at, key_id=_ACTIVE_KEY_ID)
    retired = TestQualificationAuthority(issued_at, key_id=_RETIRED_KEY_ID)
    authorities = {_ACTIVE_KEY_ID: active, _RETIRED_KEY_ID: retired}
    historical_verifier = RsaQualificationReceiptVerifier(
        (retired.verifier.keys[0], active.verifier.keys[0])
    )
    receipt = authorities[receipt_key_id].issue(_claim())
    response = json.dumps(
        {
            "schema_version": 1,
            "receipt": json.loads(qualification_receipt_json(receipt)),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode() + b"\n"
    with _short_socket("capture.sock") as socket_path:
        issuer = UnixSocketQualificationIssuer(
            QualificationAuthorityClientConfig(socket_path),
            historical_verifier,
            active_key_id=_ACTIVE_KEY_ID,
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(os.fspath(socket_path))
            socket_path.chmod(0o600)
            listener.listen(1)

            def serve() -> None:
                with listener.accept()[0] as connection:
                    _ = connection.recv(65536)
                    connection.sendall(response)

            server = Thread(target=serve)
            server.start()
            try:
                if accepted:
                    assert issuer.issue(_claim()) == receipt
                else:
                    with pytest.raises(QualificationAuthorityError):
                        _ = issuer.issue(_claim())
            finally:
                server.join(timeout=2)
                socket_path.unlink(missing_ok=True)
            assert not server.is_alive()


def test_adopter_configuration_requires_active_key_in_pinned_ring(
    tmp_path: Path,
) -> None:
    source = qualification_public_key_document(
        key_ids=(_RETIRED_KEY_ID, _ACTIVE_KEY_ID)
    )
    public_keys = tmp_path / "authority-public-keys.json"
    _ = public_keys.write_bytes(source)
    public_keys.chmod(0o600)
    with _short_socket("adopter.sock") as socket_path:
        with pytest.raises(QualificationAuthorityError):
            _ = build_qualification_adopter_server(
                QualificationAdopterServerConfig(
                    socket_path,
                    "postgresql+asyncpg://unused",
                    "science_workbench_qualification_test",
                    public_keys,
                    sha256(source).hexdigest(),
                    "unknown-active-key",
                )
            )

        server = build_qualification_adopter_server(
            QualificationAdopterServerConfig(
                socket_path,
                "postgresql+asyncpg://unused",
                "science_workbench_qualification_test",
                public_keys,
                sha256(source).hexdigest(),
                _ACTIVE_KEY_ID,
            )
        )
        server.server_close()


def test_adopter_process_requires_explicit_active_key_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        os,
        "environ",
        {
            "PROVIDER_QUALIFICATION_ADOPTER_SOCKET": "/protected/adopter.sock",
            "PROVIDER_QUALIFICATION_ADOPTER_DATABASE_URL": "postgresql://unused",
            "PROVIDER_QUALIFICATION_ADOPTER_LOGIN_ROLE": "qualification_login",
            "PROVIDER_QUALIFICATION_AUTHORITY_PUBLIC_KEYS_FILE": "/protected/keys",
            "PROVIDER_QUALIFICATION_AUTHORITY_PUBLIC_KEYS_SHA256": "1" * 64,
        },
    )

    with pytest.raises(SystemExit) as exit_status:
        qualification_adopter_main()
    assert exit_status.value.code == 2


def test_adopter_rejects_retired_receipt_before_database_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issued_at = datetime(2025, 1, 1, tzinfo=UTC)
    retired = TestQualificationAuthority(issued_at, key_id=_RETIRED_KEY_ID)
    active = TestQualificationAuthority(issued_at, key_id=_ACTIVE_KEY_ID)
    historical_verifier = RsaQualificationReceiptVerifier(
        (retired.verifier.keys[0], active.verifier.keys[0])
    )
    policy = QualificationReceiptAdmissionPolicy(
        historical_verifier,
        _ACTIVE_KEY_ID,
    )
    receipt = retired.issue(_claim())
    runtime = ProviderRuntimeIdentity(
        receipt.claim.adapter_id,
        receipt.claim.runtime_version,
        receipt.claim.executable_sha256,
    )
    qualification = ProviderQualificationIdentity(
        runtime,
        receipt.claim.profile_sha256,
        receipt,
        qualification_receipt_sha256(receipt),
    )
    principal = ProviderPrincipal(
        receipt.claim.subject.user_id,
        receipt.claim.subject.org_id,
    )
    connection = ProviderConnection(
        connection_id=receipt.claim.subject.connection_id,
        adapter_id=receipt.claim.adapter_id,
        account_id="official-account",
        eligible_models=("codex-mini",),
        selected_model="codex-mini",
        health="healthy",
        cleanup_verified=True,
        qualified_live=True,
        created_at=issued_at,
        revision=receipt.claim.subject.connection_revision,
        qualification=qualification,
    )
    database_runs: list[bool] = []

    def forbidden_run(function: Callable[[], Awaitable[None]]) -> None:
        del function
        database_runs.append(True)

    monkeypatch.setattr(
        "services.api.provider_qualification_writer.anyio.run",
        forbidden_run,
    )
    writer = PostgresQualificationWriter(
        "postgresql+asyncpg://unused",
        policy,
        expected_login_role="science_workbench_qualification_test",
    )

    with pytest.raises(QualificationWriterError):
        writer.adopt(
            principal,
            connection,
            "vault://runtime/connection/qualification",
            receipt,
            expected_revision=1,
        )
    assert database_runs == []
