"""Cryptographic interoperability tests for qualification receipts."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from services.api.provider_qualification_authority_server import (
    QualificationAuthorityServerError,
    RsaQualificationPrivateKey,
    RsaQualificationReceiptSigner,
    load_qualification_private_key,
)
from services.api.provider_qualification_receipt import (
    QUALIFICATION_SIGNATURE_ALGORITHM,
    QualificationReceiptClaim,
    QualificationReceiptError,
    QualificationReceiptSubject,
    RsaQualificationPublicKey,
    RsaQualificationReceiptVerifier,
    qualification_receipt_payload,
)

from .provider_qualification_support import (
    TestQualificationAuthority,
    qualification_private_key_document,
)

if TYPE_CHECKING:
    from pathlib import Path


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
        operator_account_ref="acct_provider_test",
        runtime_version="codex-cli-0.144.1",
        executable_sha256="3" * 64,
        protocol_attempts=30,
        cleanup_terminal=True,
        cleanup_redaction_complete=True,
    )


def _private_key_path(tmp_path: Path, source: bytes) -> Path:
    path = tmp_path / "authority-private-key.json"
    _ = path.write_bytes(source)
    path.chmod(0o600)
    return path


def _external_private_key(
    key: RsaQualificationPrivateKey,
) -> rsa.RSAPrivateKey:
    prime_p, prime_q = rsa.rsa_recover_prime_factors(
        key.modulus,
        65537,
        key.private_exponent,
    )
    return rsa.RSAPrivateNumbers(
        prime_p,
        prime_q,
        key.private_exponent,
        rsa.rsa_crt_dmp1(key.private_exponent, prime_p),
        rsa.rsa_crt_dmq1(key.private_exponent, prime_q),
        rsa.rsa_crt_iqmp(prime_p, prime_q),
        rsa.RSAPublicNumbers(65537, key.modulus),
    ).private_key()


def test_private_key_loader_rejects_incoherent_private_exponent(
    tmp_path: Path,
) -> None:
    # Given: an exact-format document whose private exponent does not match n and e.
    source = qualification_private_key_document()
    marker = b'"private_exponent_hex":"'
    prefix, encoded_exponent = source.split(marker, maxsplit=1)
    _, suffix = encoded_exponent.split(b'"', maxsplit=1)
    path = _private_key_path(tmp_path, prefix + marker + b'2"' + suffix)

    # When/Then: key construction fails before the signer can be created.
    with pytest.raises(QualificationAuthorityServerError):
        _ = load_qualification_private_key(path)


def test_private_key_repr_redacts_private_material(tmp_path: Path) -> None:
    # Given: a validated authority key loaded from the unchanged deployment format.
    private_key = load_qualification_private_key(
        _private_key_path(tmp_path, qualification_private_key_document())
    )

    # When: generic diagnostics render the frozen key value object.
    rendered = repr(private_key)

    # Then: neither the exponent nor backend-held private material is disclosed.
    assert "private_exponent" not in rendered
    assert str(private_key.private_exponent) not in rendered
    assert f"{private_key.private_exponent:x}" not in rendered
    assert "_backend_key" not in rendered


def test_public_key_rejects_nonstandard_exponent() -> None:
    # Given: a valid RSA-3072 modulus paired with an odd but unapproved exponent.
    public_key = TestQualificationAuthority(
        datetime(2025, 1, 1, tzinfo=UTC)
    ).verifier.keys[0]

    # When/Then: the public-key value object enforces the exact 65537 policy.
    with pytest.raises(QualificationReceiptError):
        _ = RsaQualificationPublicKey("test-key", public_key.modulus, 3)


def test_authority_signature_is_standard_pkcs1v15_sha256(
    tmp_path: Path,
) -> None:
    # Given: the unchanged six-field private document and canonical receipt claim.
    private_key = load_qualification_private_key(
        _private_key_path(tmp_path, qualification_private_key_document())
    )
    receipt = RsaQualificationReceiptSigner(
        private_key,
        clock=lambda: datetime(2025, 1, 1, tzinfo=UTC),
        id_factory=lambda: "018f0d7d-6b17-7a91-8b31-2f7331677d04",
    ).issue(_claim())
    public_number = TestQualificationAuthority(
        datetime(2025, 1, 1, tzinfo=UTC)
    ).verifier.keys[0]
    public_key = rsa.RSAPublicNumbers(
        public_number.exponent,
        public_number.modulus,
    ).public_key()

    # When: an independent cryptography verifier checks the external receipt bytes.
    public_key.verify(
        bytes.fromhex(receipt.signature),
        qualification_receipt_payload(receipt),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    # Then: wire shape and application verification remain exactly compatible.
    assert len(receipt.signature) == 768
    assert receipt.signature == receipt.signature.lower()
    assert receipt.algorithm == QUALIFICATION_SIGNATURE_ALGORITHM
    assert RsaQualificationReceiptVerifier(
        (
            RsaQualificationPublicKey(
                public_number.key_id,
                public_number.modulus,
                public_number.exponent,
            ),
        )
    ).verify(receipt)


def test_backend_verifier_rejects_signature_and_payload_tampering(
    tmp_path: Path,
) -> None:
    # Given: one receipt produced by the deployment signer.
    private_key = load_qualification_private_key(
        _private_key_path(tmp_path, qualification_private_key_document())
    )
    signer = RsaQualificationReceiptSigner(
        private_key,
        clock=lambda: datetime(2025, 1, 1, tzinfo=UTC),
        id_factory=lambda: "018f0d7d-6b17-7a91-8b31-2f7331677d05",
    )
    receipt = signer.issue(_claim())
    public_key = TestQualificationAuthority(
        datetime(2025, 1, 1, tzinfo=UTC)
    ).verifier.keys[0]
    verifier = RsaQualificationReceiptVerifier(
        (
            RsaQualificationPublicKey(
                public_key.key_id,
                public_key.modulus,
                public_key.exponent,
            ),
        )
    )

    # When: either the signature or canonical payload is changed.
    tampered_signature = replace(
        receipt,
        signature=("0" if receipt.signature[0] != "0" else "1") + receipt.signature[1:],
    )
    tampered_payload = replace(
        receipt,
        claim=replace(receipt.claim, runtime_version="codex-cli-0.144.2"),
    )

    # Then: both untrusted variants fail closed.
    assert not verifier.verify(tampered_signature)
    assert not verifier.verify(tampered_payload)


def test_external_backend_signature_is_accepted_without_wire_conversion(
    tmp_path: Path,
) -> None:
    # Given: an external backend key reconstructed from the unchanged n/e/d document.
    private_key = load_qualification_private_key(
        _private_key_path(tmp_path, qualification_private_key_document())
    )
    receipt = RsaQualificationReceiptSigner(
        private_key,
        clock=lambda: datetime(2025, 1, 1, tzinfo=UTC),
        id_factory=lambda: "018f0d7d-6b17-7a91-8b31-2f7331677d06",
    ).issue(_claim())
    public_key = RsaQualificationPublicKey(receipt.key_id, private_key.modulus)
    external_signature = _external_private_key(private_key).sign(
        qualification_receipt_payload(receipt),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    # When: the application receives the backend's raw fixed-width signature as hex.
    external_receipt = replace(receipt, signature=external_signature.hex())

    # Then: no payload or signature translation is needed for verification.
    assert external_receipt.signature == receipt.signature
    assert RsaQualificationReceiptVerifier((public_key,)).verify(external_receipt)


def test_verifier_rejects_invalid_signature_encodings() -> None:
    # Given: one valid receipt and malformed or out-of-range fixed-width variants.
    authority = TestQualificationAuthority(datetime(2025, 1, 1, tzinfo=UTC))
    receipt = authority.issue(_claim())
    public_key = authority.verifier.keys[0]
    invalid_signatures = (
        "",
        "0",
        "00" * 383,
        "00" * 385,
        f"{public_key.modulus:0768x}",
    )

    # When/Then: every invalid representation is rejected without an exception.
    assert all(
        not authority.verifier.verify(replace(receipt, signature=signature))
        for signature in invalid_signatures
    )


def test_verifier_rejects_unapproved_padding_and_hash(
    tmp_path: Path,
) -> None:
    # Given: valid canonical bytes signed with two unapproved RSA policies.
    private_key = load_qualification_private_key(
        _private_key_path(tmp_path, qualification_private_key_document())
    )
    receipt = RsaQualificationReceiptSigner(
        private_key,
        clock=lambda: datetime(2025, 1, 1, tzinfo=UTC),
        id_factory=lambda: "018f0d7d-6b17-7a91-8b31-2f7331677d07",
    ).issue(_claim())
    payload = qualification_receipt_payload(receipt)
    external_key = _external_private_key(private_key)
    unapproved_signatures = (
        external_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        ),
        external_key.sign(payload, padding.PKCS1v15(), hashes.SHA384()),
    )
    verifier = RsaQualificationReceiptVerifier(
        (RsaQualificationPublicKey(receipt.key_id, private_key.modulus),)
    )

    # When/Then: only PKCS#1 v1.5 with SHA-256 satisfies the receipt contract.
    assert all(
        not verifier.verify(replace(receipt, signature=signature.hex()))
        for signature in unapproved_signatures
    )
