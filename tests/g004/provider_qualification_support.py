"""Test-only external authority for provider qualification receipts."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import Final, final, override

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from services.api.provider_live_capture import QualificationCaptureAuthority
from services.api.provider_qualification_receipt import (
    QUALIFICATION_SIGNATURE_ALGORITHM,
    QualificationReceipt,
    QualificationReceiptClaim,
    QualificationReceiptIssuer,
    QualificationReceiptSubject,
    RsaQualificationPublicKey,
    RsaQualificationReceiptVerifier,
    qualification_receipt_payload,
)

_MODULUS: Final = int(
    "bf16a05e8202f9cced7ad212ea7d4e8faea710716b945883a7ef0bdf465450874"
    "7870921a9cdeeb1c1cba545f96521f856811accfdbad1fc9975e5cd40b9714699"
    "d4a440cdd0309884d66935939241d5f8fa152268c0ee1b0503e552ee3339d4949"
    "bd61ddd48284396d803087e663f080516dc243ac84c0cc88f949964839591ee39"
    "dd91bbf99a643de3b0d3bc667f77db1f00c1390bf86b0581eaa0df3b95434777"
    "e098af84b28106634b7361760620596650d9fd0e4cbc9001375bf3eeee3baaffeb"
    "bf6588ab35eac2c876e15722230b0494d6c2b9659a2050d7f56d74330dfa30090"
    "d55162c9ca6f3f5a0862d79ffb9a0b6da5e0c898650ace9a8e45a7d0affef73e"
    "5d65ef8979b34382902ad6ae065ba2cc78ba03fac6b9c0672e44188e3fd435c48"
    "b1074970f05f937b44779d78da24657b2b04ff345a35432734f95f91b6a41086"
    "b2f7561bf5975b82d8e6613d5e8f850a4ac083cfe8b9e9f439f0dd2d2f6a594"
    "98b78b0d8b93aea8fa02e6b2fb34ad1b4cca8c15c65245efe5a612c61",
    16,
)
_PRIVATE_EXPONENT: Final = int(
    "2b562752a7aba3196db650144827d8fc4f00c682e282073cfc86032c44d7f457"
    "69ca5f30ca40d0e4716e0cf27ca809f7372f1a73e90b487a401773e183cf4ab8"
    "5744d9677505c52fa1d8ba8d93053577207b1ef5e9c9ef76234209ed2fe660342"
    "cebd6b87929d72fd4f2f26527bd6a881817621fb95119a6408a078a6e3845608e"
    "2583717caf13ebadf9886dcca976392971b38b1eb3ef47de3ce3884e7845d6b74"
    "ba19d1f193a1e76e3680627d14b7c64aa06a61974f7c43fe876b49cf2d006451"
    "2f176212519cc075cc36f1ebebcd61215ae15a7162f378be8f07e6248288b7edf"
    "8a5b5b16587bf5ef94cbd57f0b8386f8054ed3ef3719611a6c6914decd1e93cf"
    "c4da8a6683671c24c9fda1bc7a087d90dfd70148003c8d0572b46ed5b12d429"
    "b8cfa08d9f550359522575dd8dfd189f9a1d18727ce8353f0a5b485ebddf3d8a"
    "1d521208012a2748fac28f03e4b8598d9acaf31d86e2443e1972babaed29f6eb7"
    "db0ca7ee907813fcec5e9931a4781858875517a4d39b61a59c90ac814cad",
    16,
)
_KEY_ID: Final = "test-qualification-rsa-3072-v1"
_PRIME_P, _PRIME_Q = rsa.rsa_recover_prime_factors(
    _MODULUS,
    65537,
    _PRIVATE_EXPONENT,
)
_PRIVATE_KEY = rsa.RSAPrivateNumbers(
    _PRIME_P,
    _PRIME_Q,
    _PRIVATE_EXPONENT,
    rsa.rsa_crt_dmp1(_PRIVATE_EXPONENT, _PRIME_P),
    rsa.rsa_crt_dmq1(_PRIVATE_EXPONENT, _PRIME_Q),
    rsa.rsa_crt_iqmp(_PRIME_P, _PRIME_Q),
    rsa.RSAPublicNumbers(65537, _MODULUS),
).private_key()


def qualification_public_key_document(
    *, key_ids: tuple[str, ...] = (_KEY_ID,)
) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "keys": [
                {
                    "key_id": key_id,
                    "algorithm": QUALIFICATION_SIGNATURE_ALGORITHM,
                    "modulus_hex": f"{_MODULUS:0768x}",
                    "exponent": 65537,
                }
                for key_id in key_ids
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def qualification_private_key_document() -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "key_id": _KEY_ID,
            "algorithm": QUALIFICATION_SIGNATURE_ALGORITHM,
            "modulus_hex": f"{_MODULUS:0768x}",
            "public_exponent": 65537,
            "private_exponent_hex": f"{_PRIVATE_EXPONENT:x}",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


@final
class TestQualificationAuthority(QualificationReceiptIssuer):
    __test__ = False

    def __init__(self, issued_at: datetime, *, key_id: str = _KEY_ID) -> None:
        self._issued_at = issued_at.astimezone(UTC)
        self._sequence = 0
        self._key_id = key_id
        self.verifier = RsaQualificationReceiptVerifier(
            (RsaQualificationPublicKey(key_id, _MODULUS),)
        )

    @override
    def issue(self, claim: QualificationReceiptClaim) -> QualificationReceipt:
        self._sequence += 1
        receipt_id = f"018f0d7d-6b17-7a91-8b31-{self._sequence:012x}"
        unsigned = QualificationReceipt(
            receipt_id=receipt_id,
            issued_at=self._issued_at,
            key_id=self._key_id,
            algorithm=QUALIFICATION_SIGNATURE_ALGORITHM,
            claim=claim,
            signature="0" * 768,
        )
        signature = _PRIVATE_KEY.sign(
            qualification_receipt_payload(unsigned),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return replace(unsigned, signature=signature.hex())

    def capture_authority(
        self,
        subject: QualificationReceiptSubject,
    ) -> QualificationCaptureAuthority:
        return QualificationCaptureAuthority(subject, self, self.verifier)
