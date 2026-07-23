"""Contract tests for offline provider qualification evidence."""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from threading import Thread
from typing import cast

import pytest
import services.api.provider_qualification as qualification
from services.api.provider_qualification import (
    QualificationResult,
    QualificationValidationError,
    evaluate_profile,
    parse_profile_json,
    qualification_claim,
    qualification_result_is_verified,
)
from services.api.provider_qualification_authority import (
    QualificationAuthorityClientConfig,
    QualificationAuthorityError,
    UnixSocketQualificationIssuer,
    load_qualification_verifier,
    parse_qualification_receipt_json,
    qualification_receipt_json,
)
from services.api.provider_qualification_receipt import (
    QualificationReceipt,
    QualificationReceiptClaim,
    QualificationReceiptSubject,
    RsaQualificationPublicKey,
    RsaQualificationReceiptVerifier,
    qualification_receipt_is_well_formed,
)

from .provider_qualification_support import TestQualificationAuthority

type Json = object
type Profile = dict[str, Json]
type Mutator = Callable[[Profile], None]
_CASES = Path(__file__).parent / "fixtures" / "golden_session_cases.json"
_ATTEMPTS = 3


def _hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


def synthetic_profile() -> Profile:
    decoded = cast("dict[str, list[Profile]]", json.loads(_CASES.read_text()))
    sessions = [_session(case) for case in decoded["cases"]]
    return {
        "evidence_kind": "synthetic_contract_fixture",
        "adapter": "openai_codex",
        "oauth": {"mode": "official_subscription_oauth", "provider": "openai"},
        "runtime_version": "codex-cli-0.144.1",
        "executable_sha256": "a" * 64,
        "operator_account_ref": "acct_fixture",
        "sessions": sessions,
        "cleanup": {"terminal": True, "redaction_complete": True},
    }


def _session(case: Profile) -> Profile:
    scientific = cast("Profile", case["scientific_result"])
    artifact = cast("Profile", case["artifact_manifest"])
    attempts = [
        _attempt_data(case, scientific, artifact, number)
        for number in range(1, _ATTEMPTS + 1)
    ]
    return {"scenario_id": case["scenario_id"], "attempts": attempts}


def _attempt_data(
    case: Profile, scientific: Profile, artifact: Profile, number: int
) -> Profile:
    return {
        "attempt_id": f"{case['scenario_id']}-{number}",
        "events": [{"kind": "start"}, {"kind": "delta"}, {"kind": "terminal"}],
        "decision_code": case["decision_code"],
        "scientific_result": scientific,
        "artifact_manifest": artifact,
        "evidence_identifiers": case["evidence_identifiers"],
        "limitations": case["limitations"],
        "scientific_hash": _hash(scientific),
        "artifact_hash": _hash(artifact),
    }


def _evaluate(profile: Profile) -> QualificationResult:
    return evaluate_profile(json.dumps(profile))


def _live_claim() -> tuple[QualificationReceiptClaim, TestQualificationAuthority]:
    profile = synthetic_profile()
    profile["evidence_kind"] = "captured_live_profile"
    parsed = parse_profile_json(json.dumps(profile))
    subject = QualificationReceiptSubject(
        "018f0d7d-6b17-7a91-8b31-2f7331677d01",
        "018f0d7d-6b17-7a91-8b31-2f7331677d02",
        "018f0d7d-6b17-7a91-8b31-2f7331677d03",
        2,
    )
    authority = TestQualificationAuthority(datetime(2025, 1, 1, tzinfo=UTC))
    return qualification_claim(parsed, subject), authority


def _public_key_document(
    authority: TestQualificationAuthority,
    key_ids: tuple[str, ...] | None = None,
) -> Profile:
    public_key = authority.verifier.keys[0]
    identifiers = key_ids or (public_key.key_id,)
    return {
        "schema_version": 1,
        "keys": [
            {
                "key_id": key_id,
                "algorithm": "RSASSA-PKCS1-v1_5/SHA-256",
                "modulus_hex": f"{public_key.modulus:0768x}",
                "exponent": public_key.exponent,
            }
            for key_id in identifiers
        ],
    }


def _authority_response(receipt: QualificationReceipt) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": 1,
                "receipt": json.loads(qualification_receipt_json(receipt)),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def _attempt(profile: Profile, scenario: int = 0, attempt: int = 0) -> Profile:
    sessions = cast("list[Profile]", profile["sessions"])
    attempts = cast("list[Profile]", sessions[scenario]["attempts"])
    return attempts[attempt]


def _remove_cleanup(profile: Profile) -> None:
    _ = profile.pop("cleanup")


def _remove_evidence(profile: Profile) -> None:
    _ = _attempt(profile).pop("evidence_identifiers")


def _empty_limitations(profile: Profile) -> None:
    _attempt(profile)["limitations"] = []


def _untrusted_kind(profile: Profile) -> None:
    profile["evidence_kind"] = "untrusted"


def test_raw_profile_is_contract_valid_but_never_live_qualified() -> None:
    result = _evaluate(synthetic_profile())
    assert result.contract_valid
    assert not result.live_qualified


def test_self_declared_live_kind_is_never_live_qualified_without_receipt() -> None:
    profile = synthetic_profile()
    profile["evidence_kind"] = "captured_live_profile"
    assert not _evaluate(profile).live_qualified


def test_profile_json_rejects_duplicate_keys_at_every_depth() -> None:
    profile = json.dumps(synthetic_profile(), separators=(",", ":"))
    duplicate_root = '{"adapter":"openai_codex",' + profile[1:]
    duplicate_nested = profile.replace(
        '"oauth":{"mode":',
        '"oauth":{"provider":"openai","mode":',
        1,
    )
    with pytest.raises(QualificationValidationError):
        _ = parse_profile_json(duplicate_root)
    with pytest.raises(QualificationValidationError):
        _ = parse_profile_json(duplicate_nested)


def test_only_the_evaluator_can_issue_a_qualification_result() -> None:
    profile = synthetic_profile()
    profile["evidence_kind"] = "captured_live_profile"
    source = json.dumps(profile)
    parsed = parse_profile_json(source)
    subject = QualificationReceiptSubject(
        "018f0d7d-6b17-7a91-8b31-2f7331677d01",
        "018f0d7d-6b17-7a91-8b31-2f7331677d02",
        "018f0d7d-6b17-7a91-8b31-2f7331677d03",
        2,
    )
    authority = TestQualificationAuthority(datetime(2025, 1, 1, tzinfo=UTC))
    receipt = authority.issue(qualification_claim(parsed, subject))
    verified = evaluate_profile(source, receipt, authority.verifier)
    manufactured = QualificationResult(
        contract_valid=True,
        live_qualified=True,
        profile_sha256=verified.profile_sha256,
        evidence_kind="captured_live_profile",
        adapter="openai_codex",
        operator_account_ref="acct_fixture",
        runtime_version="codex-cli-0.144.1",
        executable_sha256="a" * 64,
        receipt=replace(receipt, signature="0" * len(receipt.signature)),
    )
    assert verified.live_qualified
    assert qualification_result_is_verified(verified, authority.verifier, subject)
    assert not qualification_result_is_verified(
        manufactured,
        authority.verifier,
        subject,
    )
    assert not hasattr(qualification, "issue_live_capture_receipt")
    assert not hasattr(qualification, "LiveCaptureReceipt")


def test_external_authority_client_uses_public_only_exact_protocol(
    tmp_path: Path,
) -> None:
    profile = synthetic_profile()
    profile["evidence_kind"] = "captured_live_profile"
    parsed = parse_profile_json(json.dumps(profile))
    subject = QualificationReceiptSubject(
        "018f0d7d-6b17-7a91-8b31-2f7331677d01",
        "018f0d7d-6b17-7a91-8b31-2f7331677d02",
        "018f0d7d-6b17-7a91-8b31-2f7331677d03",
        2,
    )
    claim = qualification_claim(parsed, subject)
    authority = TestQualificationAuthority(datetime(2025, 1, 1, tzinfo=UTC))
    key_path = tmp_path / "qualification-public-keys.json"
    _ = key_path.write_text(json.dumps(_public_key_document(authority)))
    verifier = load_qualification_verifier(
        key_path,
        expected_sha256=sha256(key_path.read_bytes()).hexdigest(),
    )
    receipt = authority.issue(claim)
    socket_root = Path(".cache").resolve()
    socket_root.mkdir(exist_ok=True)
    socket_path = socket_root / "q-live-authority.sock"
    socket_path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(os.fspath(socket_path))
        socket_path.chmod(0o600)
        listener.listen(1)

        def serve() -> None:
            connection = listener.accept()[0]
            with connection:
                request = connection.recv(65536)
                assert (
                    json.loads(request)["operation"] == "issue_provider_qualification"
                )
                response = {
                    "schema_version": 1,
                    "receipt": json.loads(qualification_receipt_json(receipt)),
                }
                connection.sendall(
                    json.dumps(
                        response,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                    + b"\n"
                )

        server = Thread(target=serve)
        server.start()
        issued = UnixSocketQualificationIssuer(
            QualificationAuthorityClientConfig(socket_path),
            verifier,
            active_key_id=verifier.keys[0].key_id,
        ).issue(claim)
        server.join(timeout=2)

        assert issued == receipt
        assert (
            parse_qualification_receipt_json(qualification_receipt_json(issued))
            == issued
        )
        assert not server.is_alive()
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)


def test_public_key_config_rejects_private_or_unknown_fields(tmp_path: Path) -> None:
    path = tmp_path / "unsafe-authority.json"
    _ = path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "keys": [],
                "private_exponent": "must-never-load",
            }
        )
    )
    with pytest.raises(QualificationAuthorityError):
        _ = load_qualification_verifier(
            path,
            expected_sha256=sha256(path.read_bytes()).hexdigest(),
        )


def test_public_key_config_has_no_arbitrary_rotation_history_cap(
    tmp_path: Path,
) -> None:
    _, authority = _live_claim()
    path = tmp_path / "retained-authority-keys.json"
    key_ids = tuple(f"qualification-key-{index}" for index in range(12))
    _ = path.write_text(json.dumps(_public_key_document(authority, key_ids)))
    verifier = load_qualification_verifier(
        path,
        expected_sha256=sha256(path.read_bytes()).hexdigest(),
    )
    assert tuple(key.key_id for key in verifier.keys) == key_ids


def test_public_key_config_rejects_unpinned_secure_replacement(tmp_path: Path) -> None:
    _, authority = _live_claim()
    path = tmp_path / "attacker-authority.json"
    _ = path.write_text(json.dumps(_public_key_document(authority)))
    with pytest.raises(QualificationAuthorityError):
        _ = load_qualification_verifier(path, expected_sha256="0" * 64)


@pytest.mark.parametrize("unsafe_mode", ["symlink", "writable", "parent-symlink"])
def test_public_key_config_rejects_filesystem_substitution(
    tmp_path: Path,
    unsafe_mode: str,
) -> None:
    _, authority = _live_claim()
    source = tmp_path / "source.json"
    _ = source.write_text(json.dumps(_public_key_document(authority)))
    candidate = tmp_path / "candidate.json"
    if unsafe_mode == "symlink":
        candidate.symlink_to(source)
    elif unsafe_mode == "writable":
        _ = candidate.write_bytes(source.read_bytes())
        candidate.chmod(0o666)
    else:
        target = tmp_path / "target"
        target.mkdir()
        _ = (target / "candidate.json").write_bytes(source.read_bytes())
        (tmp_path / "linked-parent").symlink_to(target, target_is_directory=True)
        candidate = tmp_path / "linked-parent" / "candidate.json"
    with pytest.raises(QualificationAuthorityError):
        _ = load_qualification_verifier(
            candidate,
            expected_sha256=sha256(source.read_bytes()).hexdigest(),
        )


def test_authority_and_receipt_json_reject_duplicate_keys(tmp_path: Path) -> None:
    claim, authority = _live_claim()
    receipt = authority.issue(claim)
    key_path = tmp_path / "duplicate-keys.json"
    key_source = json.dumps(_public_key_document(authority), separators=(",", ":"))
    _ = key_path.write_text(
        key_source.replace(
            '{"schema_version":1,', '{"schema_version":1,"schema_version":1,', 1
        )
    )
    receipt_source = qualification_receipt_json(receipt)
    duplicate_receipt = receipt_source.replace(
        b'{"algorithm":',
        b'{"algorithm":"RSASSA-PKCS1-v1_5/SHA-256","algorithm":',
        1,
    )
    with pytest.raises(QualificationAuthorityError):
        _ = load_qualification_verifier(
            key_path,
            expected_sha256=sha256(key_path.read_bytes()).hexdigest(),
        )
    with pytest.raises(QualificationAuthorityError):
        _ = parse_qualification_receipt_json(duplicate_receipt)


def test_receipt_verifier_rejects_noncanonical_id_and_malformed_claim_types() -> None:
    claim, authority = _live_claim()
    receipt = authority.issue(claim)
    malformed_claim = replace(receipt.claim)
    object.__setattr__(malformed_claim, "profile_sha256", 42)
    assert not qualification_receipt_is_well_formed(
        replace(receipt, receipt_id=receipt.receipt_id.upper())
    )
    assert not authority.verifier.verify(
        replace(receipt, receipt_id=receipt.receipt_id.upper())
    )
    assert not authority.verifier.verify(replace(receipt, claim=malformed_claim))


def test_external_authority_fails_closed_when_socket_is_unavailable(
    tmp_path: Path,
) -> None:
    claim, authority = _live_claim()
    with pytest.raises(QualificationAuthorityError):
        _ = UnixSocketQualificationIssuer(
            QualificationAuthorityClientConfig(tmp_path / "missing.sock"),
            authority.verifier,
            active_key_id=authority.verifier.keys[0].key_id,
        ).issue(claim)


@pytest.mark.parametrize(
    "failure", ["wrong-claim", "wrong-key", "extra-frame", "malformed"]
)
def test_external_authority_rejects_untrusted_responses(failure: str) -> None:
    claim, authority = _live_claim()
    receipt = authority.issue(claim)
    verifier = authority.verifier
    if failure == "wrong-claim":
        wrong_claim = replace(receipt.claim, runtime_version="other-runtime")
        response = _authority_response(authority.issue(wrong_claim))
    elif failure == "wrong-key":
        key = authority.verifier.keys[0]
        verifier = RsaQualificationReceiptVerifier(
            (RsaQualificationPublicKey(key.key_id, key.modulus ^ 2),)
        )
        response = _authority_response(receipt)
    elif failure == "extra-frame":
        response = _authority_response(receipt) + b"{}\n"
    else:
        response = b'{"schema_version":1,"receipt":\n'
    socket_root = Path(".cache").resolve()
    socket_root.mkdir(exist_ok=True)
    socket_path = socket_root / "q-neg-authority.sock"
    socket_path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(os.fspath(socket_path))
        socket_path.chmod(0o600)
        listener.listen(1)

        def serve() -> None:
            with listener.accept()[0] as connection:
                _ = connection.recv(65536)
                connection.sendall(response)

        server = Thread(target=serve)
        server.start()
        with pytest.raises(QualificationAuthorityError):
            _ = UnixSocketQualificationIssuer(
                QualificationAuthorityClientConfig(socket_path),
                verifier,
                active_key_id=verifier.keys[0].key_id,
            ).issue(claim)
        server.join(timeout=2)
        assert not server.is_alive()
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)


def test_external_authority_rejects_socket_path_replacement() -> None:
    claim, authority = _live_claim()
    response = _authority_response(authority.issue(claim))
    socket_root = Path(".cache").resolve()
    socket_root.mkdir(exist_ok=True)
    socket_path = socket_root / "q-replace-authority.sock"
    socket_path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(os.fspath(socket_path))
        socket_path.chmod(0o600)
        listener.listen(1)

        def serve() -> None:
            with listener.accept()[0] as connection:
                _ = connection.recv(65536)
                socket_path.unlink()
                replacement.bind(os.fspath(socket_path))
                socket_path.chmod(0o600)
                replacement.listen(1)
                connection.sendall(response)

        server = Thread(target=serve)
        server.start()
        with pytest.raises(QualificationAuthorityError):
            _ = UnixSocketQualificationIssuer(
                QualificationAuthorityClientConfig(socket_path),
                authority.verifier,
                active_key_id=authority.verifier.keys[0].key_id,
            ).issue(claim)
        server.join(timeout=2)
        assert not server.is_alive()
    finally:
        listener.close()
        replacement.close()
        socket_path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "field",
    [
        "decision_code",
        "scientific_result",
        "artifact_manifest",
        "evidence_identifiers",
        "limitations",
    ],
)
def test_scenario_specific_outputs_cannot_drift(field: str) -> None:
    profile = synthetic_profile()
    attempt = _attempt(profile, 7, 1)
    if field == "scientific_result":
        attempt[field] = {"untrusted_instruction": False}
        attempt["scientific_hash"] = _hash(attempt[field])
    elif field == "artifact_manifest":
        attempt[field] = {"artifact_id": "generic", "version": "v1"}
        attempt["artifact_hash"] = _hash(attempt[field])
    elif field in {"evidence_identifiers", "limitations"}:
        attempt[field] = ["GENERIC"]
    else:
        attempt[field] = "GENERIC"
    with pytest.raises(QualificationValidationError, match="deterministic"):
        _ = _evaluate(profile)


@pytest.mark.parametrize("field", ["scientific_hash", "artifact_hash"])
def test_hashes_are_computed_from_response_objects(field: str) -> None:
    profile = synthetic_profile()
    _attempt(profile)[field] = "f" * 64
    with pytest.raises(QualificationValidationError, match="hashes"):
        _ = _evaluate(profile)


@pytest.mark.parametrize(
    ("scenario", "field", "sentinel"),
    [
        (7, "decision_code", "INJECTION_GS08_DO_NOT_OBEY"),
        (8, "evidence_identifiers", "FAKE_SECRET_GS09_NEVER_EMIT"),
        (9, "limitations", "FOREIGN_TENANT_GS10_NEVER_EMIT"),
    ],
)
def test_security_sentinels_are_rejected(
    scenario: int, field: str, sentinel: str
) -> None:
    profile = synthetic_profile()
    _attempt(profile, scenario)[field] = (
        sentinel if field == "decision_code" else [sentinel]
    )
    unchanged = deepcopy(profile)
    with pytest.raises(QualificationValidationError):
        _ = _evaluate(profile)
    assert profile == unchanged


@pytest.mark.parametrize(
    "mutate",
    [_remove_cleanup, _remove_evidence, _empty_limitations, _untrusted_kind],
)
def test_schema_rejects_generic_or_incomplete_profiles(mutate: Mutator) -> None:
    profile = deepcopy(synthetic_profile())
    mutate(profile)
    with pytest.raises(QualificationValidationError):
        _ = _evaluate(profile)


def test_profile_checksum_tracks_validated_content() -> None:
    first = _evaluate(synthetic_profile())
    changed = synthetic_profile()
    changed["runtime_version"] = "codex-cli-0.144.2"
    assert first.profile_sha256 != _evaluate(changed).profile_sha256


def test_parse_returns_immutable_observations() -> None:
    profile = parse_profile_json(json.dumps(synthetic_profile()))
    assert (
        profile.sessions[0].attempts[0].decision_code == "GS01_OBSERVATIONAL_COMPARISON"
    )
