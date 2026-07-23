"""Validated private-key boundary for the qualification authority."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from services.api.provider_qualification_authority_files import (
    UnsafeAuthorityPathError,
    read_secure_authority_file,
)
from services.api.provider_qualification_receipt import (
    QUALIFICATION_SIGNATURE_ALGORITHM,
)
from services.api.provider_uds import ProviderUdsError, strict_provider_json

if TYPE_CHECKING:
    from pathlib import Path

_RSA_3072_HEX_LENGTH: Final = 768
_RSA_BITS: Final = 3072
_RSA_PUBLIC_EXPONENT: Final = 65537
_MAX_PRIVATE_KEY_BYTES: Final = 16 * 1024


class QualificationAuthorityServerError(RuntimeError):
    """Reject an unsafe signer configuration or authority request."""


@dataclass(frozen=True, slots=True)
class RsaQualificationPrivateKey:
    """Backend-owned RSA private signer confined to the authority process."""

    key_id: str
    modulus: int
    private_exponent: int = field(repr=False, compare=False)
    _backend_key: rsa.RSAPrivateKey = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Construct a validated backend key from the stable n/e/d format."""
        if (
            type(self.modulus) is not int
            or type(self.private_exponent) is not int
            or self.modulus.bit_length() != _RSA_BITS
            or self.modulus % 2 == 0
            or self.private_exponent <= 1
            or self.private_exponent >= self.modulus
        ):
            raise QualificationAuthorityServerError
        try:
            prime_p, prime_q = rsa.rsa_recover_prime_factors(
                self.modulus,
                _RSA_PUBLIC_EXPONENT,
                self.private_exponent,
            )
            backend_key = rsa.RSAPrivateNumbers(
                prime_p,
                prime_q,
                self.private_exponent,
                rsa.rsa_crt_dmp1(self.private_exponent, prime_p),
                rsa.rsa_crt_dmq1(self.private_exponent, prime_q),
                rsa.rsa_crt_iqmp(prime_p, prime_q),
                rsa.RSAPublicNumbers(_RSA_PUBLIC_EXPONENT, self.modulus),
            ).private_key()
        except ValueError as error:
            raise QualificationAuthorityServerError from error
        public_numbers = backend_key.public_key().public_numbers()
        if (
            backend_key.key_size != _RSA_BITS
            or public_numbers.n != self.modulus
            or public_numbers.e != _RSA_PUBLIC_EXPONENT
        ):
            raise QualificationAuthorityServerError
        object.__setattr__(self, "_backend_key", backend_key)

    def sign(self, payload: bytes) -> bytes:
        """Sign canonical receipt bytes through the maintained crypto backend."""
        try:
            return self._backend_key.sign(
                payload,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except UnsupportedAlgorithm as error:
            raise QualificationAuthorityServerError from error


def load_qualification_private_key(path: Path) -> RsaQualificationPrivateKey:
    """Load and validate one exact owner-only private-key document."""
    try:
        before = path.lstat()
        source = read_secure_authority_file(
            path,
            maximum_bytes=_MAX_PRIVATE_KEY_BYTES,
        )
        after = path.lstat()
    except (OSError, UnsafeAuthorityPathError) as error:
        raise QualificationAuthorityServerError from error
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_mode & 0o077
        or after.st_mode & 0o077
    ):
        raise QualificationAuthorityServerError
    try:
        root = strict_provider_json(source)
    except ProviderUdsError as error:
        raise QualificationAuthorityServerError from error
    if (
        set(root)
        != {
            "schema_version",
            "key_id",
            "algorithm",
            "modulus_hex",
            "public_exponent",
            "private_exponent_hex",
        }
        or root.get("schema_version") != 1
    ):
        raise QualificationAuthorityServerError
    key_id = root.get("key_id")
    algorithm = root.get("algorithm")
    modulus_hex = root.get("modulus_hex")
    public_exponent = root.get("public_exponent")
    private_exponent_hex = root.get("private_exponent_hex")
    if (
        not isinstance(key_id, str)
        or not key_id
        or algorithm != QUALIFICATION_SIGNATURE_ALGORITHM
        or not isinstance(modulus_hex, str)
        or len(modulus_hex) != _RSA_3072_HEX_LENGTH
        or public_exponent != _RSA_PUBLIC_EXPONENT
        or not isinstance(private_exponent_hex, str)
        or not 1 <= len(private_exponent_hex) <= _RSA_3072_HEX_LENGTH
        or any(
            character not in "0123456789abcdef"
            for character in modulus_hex + private_exponent_hex
        )
    ):
        raise QualificationAuthorityServerError
    modulus = int(modulus_hex, 16)
    private_exponent = int(private_exponent_hex, 16)
    return RsaQualificationPrivateKey(key_id, modulus, private_exponent)
