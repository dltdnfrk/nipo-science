r"""Provider registry and credential storage for the local Nipo Science app.

Nipo Science local runs on the researcher's own Mac against the researcher's own
provider subscriptions, so there is no multi-tenancy and no server-side
credential custody. This module carries the whole credential story.

Transport
---------
API keys are **not** stored in the Keychain directly. Measured against the real
``/usr/bin/security`` binary, the generic-password transport corrupts realistic
keys silently and still reports success:

* a key containing ``\n`` or ``\r`` stores an *empty* password at exit 0,
  because ``security`` prompts twice and retries on mismatch until it hits EOF;
* anything over 128 bytes is truncated to 128 (the ``readpassphrase`` buffer),
  which would silently mangle every current ``sk-proj-...`` OpenAI key;
* non-ASCII or non-printable data comes back hex-encoded from ``-w``.

So the Keychain holds exactly one value that is immune to all three by
construction: a 32-byte random master key, base64 encoded to 44 printable ASCII
characters with no newlines. Provider keys are sealed with AES-256-GCM under
that master key and stored as ciphertext in ``LocalPaths.credentials``. The
provider id is passed as additional authenticated data, so a ciphertext cannot
be moved from one provider's slot into another's.

Invariants
----------
* No plaintext key ever reaches disk: ``LocalPaths.credentials`` holds only
  ciphertext, and ``LocalPaths.settings`` holds only non-secret metadata.
* Every write is read back and compared before it is reported as successful, so
  silent corruption becomes a loud :class:`CredentialVerificationError`.
* Keys are stored byte-exact. ``set_key`` never normalises silently: it rejects
  input it would not store verbatim, and says why.
* Reads distinguish "absent" from "failed". A failure raises rather than falling
  through to the environment, which would otherwise resolve the *wrong* key.
* No object here retains key material, and no exception message embeds a key.

When no credential store is reachable the registry falls back to reading
``NIPO_<PROVIDER_ID>_API_KEY``. That fallback is read-only: a failed write
raises rather than degrading to some other file on disk.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast, final, override

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nipo_local.config import resolve_paths

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from nipo_local.config import LocalPaths

KEYCHAIN_SERVICE: Final = "nipo-science"
"""Keychain generic-password service holding the local master key."""

KEYCHAIN_LABEL_PREFIX: Final = "Nipo Science"
"""Human-readable label prefix shown for our item in Keychain Access."""

SECURITY_BIN: Final = Path("/usr/bin/security")
"""Absolute path to the macOS `security` CLI, never resolved through PATH."""

KEYCHAIN_ITEM_NOT_FOUND: Final = 44
"""Exit status `security` returns for errSecItemNotFound."""

KEYCHAIN_MAX_SECRET_BYTES: Final = 128
"""Measured `readpassphrase` buffer size; longer values are truncated."""

MASTER_KEY_ACCOUNT: Final = "__master_key__"
"""Keychain account holding the master key; never a provider id."""

MASTER_KEY_BYTES: Final = 32
"""AES-256 master key length, base64 encoded to 44 ASCII characters."""

ENV_KEY_TEMPLATE: Final = "NIPO_{provider}_API_KEY"
"""Environment variable consulted when no stored credential is available."""

SETTINGS_SECTION: Final = "models"
"""Settings-file section owned by this module; sibling sections are preserved."""

MODEL_ID_SEPARATOR: Final = ":"
"""Separator between the provider id and the model name in a model id."""

_ADD_COMMAND: Final = "add-generic-password"
_FIND_COMMAND: Final = "find-generic-password"
_DELETE_COMMAND: Final = "delete-generic-password"

_NO_STORE_REASON: Final = "no credential store is available"
_MISSING_MASTER_REASON: Final = "it is missing from the credential store"
_BAD_BASE64_REASON: Final = "it is not valid base64"
_BAD_LENGTH_REASON: Final = f"it is not {MASTER_KEY_BYTES} bytes"

_NONCE_BYTES: Final = 12
_CREDENTIALS_VERSION: Final = 1
_PRIVATE_FILE_MODE: Final = 0o600
_CONFIGURED_KEY: Final = "configured_providers"
_ENABLED_KEY: Final = "enabled_models"
_DEFAULT_KEY: Final = "default_model"
_VERSION_KEY: Final = "version"
_ENTRIES_KEY: Final = "entries"

# Control, format, surrogate, private-use and unassigned code points. These are
# invisible when pasted, so in an API key they are always a paste artefact. The
# zero-width space that web pages inject is `Cf`, and `str.strip` misses it.
_INVISIBLE_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})


@final
@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """Static, non-secret description of one model provider."""

    provider_id: str
    display_name: str
    requires_key: bool


PROVIDERS: Final[tuple[ProviderSpec, ...]] = (
    ProviderSpec("anthropic", "Claude (Anthropic)", requires_key=True),
    ProviderSpec("openai", "OpenAI", requires_key=True),
    ProviderSpec("google", "Gemini (Google)", requires_key=True),
    ProviderSpec("ollama", "Ollama (local models)", requires_key=False),
    ProviderSpec("fireworks", "Fireworks AI", requires_key=True),
    ProviderSpec("together", "Together AI", requires_key=True),
    ProviderSpec("zai", "Z AI (GLM)", requires_key=True),
    ProviderSpec("moonshot", "Kimi (Moonshot AI)", requires_key=True),
    ProviderSpec("deepseek", "DeepSeek", requires_key=True),
    ProviderSpec("mistral", "Mistral", requires_key=True),
    ProviderSpec("qwen", "Qwen (Alibaba)", requires_key=True),
    ProviderSpec("minimax", "MiniMax", requires_key=True),
    ProviderSpec("xai", "xAI (Grok)", requires_key=True),
)
"""Provider catalogue in the order the Settings > Models cards are rendered."""

_BY_ID: Final[Mapping[str, ProviderSpec]] = {
    spec.provider_id: spec for spec in PROVIDERS
}


class ProviderStatus(StrEnum):
    """Credential state rendered on one Settings > Models card."""

    CONFIGURED = "configured"
    NOT_SET_UP = "not_set_up"
    NO_KEY_NEEDED = "no_key_needed"


class ProviderError(Exception):
    """Base class for every provider registry failure."""


@final
class UnknownProviderError(ProviderError):
    """Raised when a provider id is absent from the catalogue."""

    provider_id: str

    def __init__(self, provider_id: str) -> None:
        """Record the rejected id and name the ids that are valid."""
        known = ", ".join(spec.provider_id for spec in PROVIDERS)
        super().__init__(f"Unknown provider id {provider_id!r}; known: {known}.")
        self.provider_id = provider_id


@final
class KeyNotRequiredError(ProviderError):
    """Raised when a key is written for a provider that needs none."""

    provider_id: str

    def __init__(self, provider_id: str) -> None:
        """Explain that this provider is usable without any credential."""
        super().__init__(f"Provider {provider_id!r} needs no API key.")
        self.provider_id = provider_id


@final
class EmptyKeyError(ProviderError):
    """Raised when a blank API key is submitted."""

    provider_id: str

    def __init__(self, provider_id: str) -> None:
        """Explain that a blank key is never stored."""
        super().__init__(f"Refusing to store a blank API key for {provider_id!r}.")
        self.provider_id = provider_id


@final
class SurroundingWhitespaceError(ProviderError):
    """Raised when a key is padded with leading or trailing whitespace."""

    provider_id: str

    def __init__(self, provider_id: str) -> None:
        """Ask the caller to trim the key rather than silently trimming it."""
        detail = "trim it before saving so the stored value is what you pasted"
        super().__init__(
            f"Key for {provider_id!r} has leading or trailing whitespace; {detail}."
        )
        self.provider_id = provider_id


@final
class InvisibleCharacterError(ProviderError):
    """Raised when a key contains an invisible or control character."""

    provider_id: str
    position: int
    code_point: str

    def __init__(self, provider_id: str, position: int, character: str) -> None:
        """Locate the offending code point without echoing the key itself."""
        code_point = f"U+{ord(character):04X}"
        detail = f"invisible character {code_point} at position {position}"
        super().__init__(
            f"Key for {provider_id!r} contains {detail}; remove the paste artefact."
        )
        self.provider_id = provider_id
        self.position = position
        self.code_point = code_point


@final
class MalformedModelIdError(ProviderError):
    """Raised when a model id is not `<provider_id>:<model_name>`."""

    model_id: str

    def __init__(self, model_id: str) -> None:
        """Show the required model id shape without echoing anything secret."""
        super().__init__(f"Model id {model_id!r} must look like 'provider:model'.")
        self.model_id = model_id


@final
class ModelNotEnabledError(ProviderError):
    """Raised when a default model is chosen outside the enabled set."""

    model_id: str

    def __init__(self, model_id: str) -> None:
        """Explain that the composer default must be an enabled model."""
        super().__init__(f"Model {model_id!r} is not in the enabled model set.")
        self.model_id = model_id


@final
class LocalStateUnreadableError(ProviderError):
    """Raised when a local state file exists but cannot be read."""

    path: Path

    def __init__(self, path: Path) -> None:
        """Name the unreadable file so nothing is silently overwritten."""
        super().__init__(f"Cannot read {path}; refusing to overwrite it.")
        self.path = path


class CredentialBackendError(ProviderError):
    """Base class for credential backend failures."""


@final
class CredentialBackendUnavailableError(CredentialBackendError):
    """Raised when no credential store is usable on this machine."""

    provider_id: str

    def __init__(self, provider_id: str) -> None:
        """Point the researcher at the read-only environment fallback."""
        env_name = _env_var_name_unchecked(provider_id)
        super().__init__(f"No credential store for {provider_id!r}; set {env_name}.")
        self.provider_id = provider_id


@final
class CredentialVerificationError(CredentialBackendError):
    """Raised when a stored credential does not read back as it was written."""

    account: str

    def __init__(self, account: str) -> None:
        """Report the corrupted account without echoing either value."""
        detail = "nothing may rely on it, and the store may be corrupt"
        super().__init__(
            f"Credential for {account!r} did not read back as written; {detail}."
        )
        self.account = account


@final
class CredentialDecryptionError(CredentialBackendError):
    """Raised when a stored credential cannot be decrypted."""

    account: str

    def __init__(self, account: str) -> None:
        """Report the undecryptable account and the likely cause."""
        detail = "the master key may have changed; re-enter the key"
        super().__init__(
            f"Cannot decrypt the stored credential for {account!r}; {detail}."
        )
        self.account = account


@final
class CredentialStoreCorruptError(CredentialBackendError):
    """Raised when the encrypted credential file cannot be parsed."""

    path: Path

    def __init__(self, path: Path) -> None:
        """Name the corrupt store rather than silently discarding every key."""
        super().__init__(f"Credential store {path} is corrupt; refusing to use it.")
        self.path = path


@final
class MasterKeyUnusableError(CredentialBackendError):
    """Raised when the stored master key is missing or malformed."""

    def __init__(self, detail: str) -> None:
        """Explain why the master key cannot be used, without revealing it."""
        super().__init__(f"Master key is unusable: {detail}.")


@final
class KeychainValueUnsupportedError(CredentialBackendError):
    """Raised when a value cannot survive the Keychain transport intact."""

    account: str
    reason: str

    def __init__(self, account: str, reason: str) -> None:
        """Refuse up front rather than let `security` corrupt the value."""
        super().__init__(f"Keychain cannot store the value for {account!r}: {reason}.")
        self.account = account
        self.reason = reason


@final
class KeychainWriteError(CredentialBackendError):
    """Raised when the Keychain rejects a credential write."""

    account: str
    status: int

    def __init__(self, account: str, status: int) -> None:
        """Report the account and exit status, never the secret or the stderr."""
        super().__init__(f"Keychain write for {account!r} failed (status {status}).")
        self.account = account
        self.status = status


@final
class KeychainCommandError(CredentialBackendError):
    """Raised when a `security` invocation that carries no secret fails."""

    command: str
    status: int

    def __init__(self, command: str, status: int, detail: str) -> None:
        """Report the failing subcommand, its exit status, and its stderr."""
        message = f"security {command} failed (status {status}): {detail.strip()}"
        super().__init__(message)
        self.command = command
        self.status = status


def _env_var_name_unchecked(provider_id: str) -> str:
    """Format the environment variable name without catalogue validation."""
    return ENV_KEY_TEMPLATE.format(provider=provider_id.upper())


def list_provider_specs() -> tuple[ProviderSpec, ...]:
    """Return the static provider catalogue in Settings card order."""
    return PROVIDERS


def get_provider(provider_id: str) -> ProviderSpec:
    """Return the catalogue entry for a provider id."""
    spec = _BY_ID.get(provider_id)
    if spec is None:
        raise UnknownProviderError(provider_id)
    return spec


def env_var_name(provider_id: str) -> str:
    """Return the environment variable consulted when no key is stored."""
    return _env_var_name_unchecked(get_provider(provider_id).provider_id)


def parse_model_id(model_id: str) -> tuple[ProviderSpec, str]:
    """Split a `<provider_id>:<model_name>` reference into its spec and name."""
    provider_id, separator, model_name = model_id.partition(MODEL_ID_SEPARATOR)
    if not separator or not model_name:
        raise MalformedModelIdError(model_id)
    return get_provider(provider_id), model_name


def validate_api_key(provider_id: str, key: str) -> None:
    """Reject a key that would not be stored exactly as the researcher typed it."""
    if not key or not key.strip():
        raise EmptyKeyError(provider_id)
    if key != key.strip():
        raise SurroundingWhitespaceError(provider_id)
    for position, character in enumerate(key):
        if unicodedata.category(character) in _INVISIBLE_CATEGORIES:
            raise InvisibleCharacterError(provider_id, position, character)


def _write_private_file(path: Path, payload: str) -> None:
    """Write a file that is owner-only from the instant it first exists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    # O_EXCL plus the creation mode is what keeps the payload from ever being
    # visible at the default 0644: chmod-after-write leaves a readable window.
    descriptor = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        _PRIVATE_FILE_MODE,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            _ = handle.write(payload)
        _ = temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json_object(path: Path) -> dict[str, object] | None:
    """Return a JSON object, an empty one when absent, or None when corrupt."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return {}
    except OSError as error:
        # A transient read failure must never license a rewrite: doing so would
        # drop every sibling section the file happened to be holding.
        raise LocalStateUnreadableError(path) from error
    try:
        decoded = cast("object", json.loads(data.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return cast("dict[str, object]", decoded)


def _as_str_tuple(value: object) -> tuple[str, ...]:
    """Coerce a decoded JSON value into a tuple of unique non-empty strings."""
    if not isinstance(value, list):
        return ()
    ordered: dict[str, None] = {}
    for item in cast("list[object]", value):
        if isinstance(item, str) and item:
            ordered[item] = None
    return tuple(ordered)


class CredentialBackend(Protocol):
    """Storage contract for provider API keys that never reach disk in plaintext."""

    def available(self) -> bool:
        """Report whether this backend can be used on this machine."""
        ...

    def has(self, account: str) -> bool:
        """Report whether an entry exists, without materialising its secret."""
        ...

    def read(self, account: str) -> str | None:
        """Return the secret, None when absent, raising on any failure."""
        ...

    def write(self, account: str, secret: str) -> None:
        """Store a secret and verify it reads back byte-exact."""
        ...

    def remove(self, account: str) -> None:
        """Delete any secret held for an account."""
        ...


@final
class KeychainBackend:
    """Credential backend over the macOS Keychain via the `security` CLI.

    The transport silently corrupts values containing newlines, values over
    ``KEYCHAIN_MAX_SECRET_BYTES``, and values that are not printable ASCII, so
    this backend refuses them up front and verifies every write by reading it
    back. It is sized for the master key, not for arbitrary provider keys.
    """

    def __init__(
        self,
        service: str = KEYCHAIN_SERVICE,
        security_path: Path = SECURITY_BIN,
    ) -> None:
        """Bind the backend to a Keychain service and a `security` executable."""
        self._service = service
        self._security_path = security_path

    @override
    def __repr__(self) -> str:
        """Describe the backend without revealing any stored secret."""
        return f"{type(self).__name__}(service={self._service!r})"

    def available(self) -> bool:
        """Report whether this host is macOS and ships the `security` CLI."""
        return sys.platform == "darwin" and self._security_path.is_file()

    def has(self, account: str) -> bool:
        """Report whether an item exists, without asking for its secret."""
        status, _, stderr = self._run(self._locate_args(account))
        if status == 0:
            return True
        if status == KEYCHAIN_ITEM_NOT_FOUND:
            return False
        raise KeychainCommandError(_FIND_COMMAND, status, stderr)

    def read(self, account: str) -> str | None:
        """Return the stored secret, None when absent, raising on any failure."""
        status, stdout, stderr = self._run([*self._locate_args(account), "-w"])
        if status == KEYCHAIN_ITEM_NOT_FOUND:
            return None
        if status != 0:
            # A locked keychain or a denied ACL is NOT "no key": treating it as
            # absent would fall through to the environment and use a wrong key.
            raise KeychainCommandError(_FIND_COMMAND, status, stderr)
        return stdout.removesuffix("\n")

    def write(self, account: str, secret: str) -> None:
        """Store a Keychain-safe secret and verify it reads back byte-exact."""
        self._reject_unsupported(account, secret)
        args = [
            _ADD_COMMAND,
            "-s",
            self._service,
            "-a",
            account,
            "-l",
            f"{KEYCHAIN_LABEL_PREFIX} ({account})",
            "-U",
            # `-w` with no value must come last: `security` then reads the
            # secret from stdin, so it never lands in argv or the process table.
            "-w",
        ]
        status, _, _ = self._run(args, stdin=f"{secret}\n{secret}\n")
        if status != 0:
            # Deliberately no stderr here: this is the one call that touched the
            # secret, so the failure is reported by exit status alone.
            raise KeychainWriteError(account, status)
        if self.read(account) != secret:
            raise CredentialVerificationError(account)

    def remove(self, account: str) -> None:
        """Delete an account item, tolerating one that is already absent."""
        args = [_DELETE_COMMAND, "-s", self._service, "-a", account]
        status, _, stderr = self._run(args)
        if status not in {0, KEYCHAIN_ITEM_NOT_FOUND}:
            raise KeychainCommandError(_DELETE_COMMAND, status, stderr)

    def _reject_unsupported(self, account: str, secret: str) -> None:
        """Refuse values the `security` transport is measured to mangle."""
        if not secret:
            raise KeychainValueUnsupportedError(account, "value is empty")
        size = len(secret.encode("utf-8"))
        if size > KEYCHAIN_MAX_SECRET_BYTES:
            reason = f"{size} bytes exceeds the {KEYCHAIN_MAX_SECRET_BYTES}-byte cap"
            raise KeychainValueUnsupportedError(account, reason)
        if not secret.isascii():
            raise KeychainValueUnsupportedError(account, "value is not ASCII")
        if not secret.isprintable():
            raise KeychainValueUnsupportedError(account, "value is not printable")

    def _locate_args(self, account: str) -> list[str]:
        """Build the argument list that finds one item of this service."""
        return [_FIND_COMMAND, "-s", self._service, "-a", account]

    def _run(self, args: list[str], stdin: str | None = None) -> tuple[int, str, str]:
        """Invoke `security` with an explicit argv and return its raw outcome."""
        # `check=False` is load-bearing: CalledProcessError renders the whole
        # command, and only the plain outcome is allowed to escape this method.
        completed = subprocess.run(  # noqa: S603
            [str(self._security_path), *args],
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.returncode, completed.stdout, completed.stderr


@final
class EncryptedFileBackend:
    """Credential backend sealing provider keys under a Keychain master key.

    Provider keys never pass through `security`, so the newline, length and
    encoding defects of that transport cannot reach them. Ciphertext is bound to
    its provider id with AES-GCM additional data, so an entry cannot be moved
    from one provider's slot into another's.
    """

    def __init__(
        self,
        paths: LocalPaths,
        master: CredentialBackend | None = None,
    ) -> None:
        """Bind the store to a local layout and the holder of the master key."""
        self._paths = paths
        self._master: CredentialBackend = (
            KeychainBackend() if master is None else master
        )

    @override
    def __repr__(self) -> str:
        """Name the accounts held without revealing any of their secrets."""
        holder = type(self._master).__name__
        return f"{type(self).__name__}(path={self._paths.credentials}, master={holder})"

    def available(self) -> bool:
        """Report whether the master key holder can be used on this machine."""
        return self._master.available()

    def has(self, account: str) -> bool:
        """Report whether an entry exists, without decrypting or unlocking."""
        return account in self._entries()

    def read(self, account: str) -> str | None:
        """Return the decrypted secret, or None when no entry exists."""
        token = self._entries().get(account)
        if token is None:
            return None
        return self._unseal(account, token)

    def write(self, account: str, secret: str) -> None:
        """Seal a secret of any length or encoding and verify the round trip."""
        key = self._ensure_master_key()
        entries = dict(self._entries())
        entries[account] = self._seal(key, account, secret)
        self._store_entries(entries)
        if self.read(account) != secret:
            raise CredentialVerificationError(account)

    def remove(self, account: str) -> None:
        """Delete an entry, tolerating one that is already absent."""
        entries = dict(self._entries())
        if entries.pop(account, None) is None:
            return
        self._store_entries(entries)

    def _seal(self, key: bytes, account: str, secret: str) -> str:
        """Encrypt a secret, binding it to the account it belongs to."""
        nonce = secrets.token_bytes(_NONCE_BYTES)
        sealed = AESGCM(key).encrypt(
            nonce,
            secret.encode("utf-8"),
            account.encode("utf-8"),
        )
        return base64.b64encode(nonce + sealed).decode("ascii")

    def _unseal(self, account: str, token: str) -> str:
        """Decrypt one entry, raising rather than guessing when it fails."""
        key = self._master_key()
        try:
            blob = base64.b64decode(token, validate=True)
        except ValueError as error:
            raise CredentialDecryptionError(account) from error
        if len(blob) <= _NONCE_BYTES:
            raise CredentialDecryptionError(account)
        try:
            opened = AESGCM(key).decrypt(
                blob[:_NONCE_BYTES],
                blob[_NONCE_BYTES:],
                account.encode("utf-8"),
            )
        except InvalidTag as error:
            raise CredentialDecryptionError(account) from error
        try:
            return opened.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CredentialDecryptionError(account) from error

    def _master_key(self) -> bytes:
        """Return the master key, never creating one on a read path."""
        if not self._master.available():
            raise MasterKeyUnusableError(_NO_STORE_REASON)
        encoded = self._master.read(MASTER_KEY_ACCOUNT)
        if encoded is None:
            raise MasterKeyUnusableError(_MISSING_MASTER_REASON)
        return self._decode_master_key(encoded)

    def _ensure_master_key(self) -> bytes:
        """Return the master key, creating one the first time a key is saved."""
        if not self._master.available():
            raise MasterKeyUnusableError(_NO_STORE_REASON)
        encoded = self._master.read(MASTER_KEY_ACCOUNT)
        if encoded is None:
            # 32 random bytes base64 encode to 44 printable ASCII characters:
            # no newline, well under the byte cap, never returned hex-encoded.
            encoded = base64.urlsafe_b64encode(
                secrets.token_bytes(MASTER_KEY_BYTES),
            ).decode("ascii")
            self._master.write(MASTER_KEY_ACCOUNT, encoded)
        return self._decode_master_key(encoded)

    def _decode_master_key(self, encoded: str) -> bytes:
        """Decode and length-check the master key without ever logging it."""
        try:
            key = base64.urlsafe_b64decode(encoded)
        except ValueError as error:
            raise MasterKeyUnusableError(_BAD_BASE64_REASON) from error
        if len(key) != MASTER_KEY_BYTES:
            raise MasterKeyUnusableError(_BAD_LENGTH_REASON)
        return key

    def _entries(self) -> Mapping[str, str]:
        """Read the sealed entries, refusing to guess when the file is corrupt."""
        document = _read_json_object(self._paths.credentials)
        if document is None:
            # Never quarantine or discard: that would silently destroy keys.
            raise CredentialStoreCorruptError(self._paths.credentials)
        section = document.get(_ENTRIES_KEY, {})
        if not isinstance(section, dict):
            raise CredentialStoreCorruptError(self._paths.credentials)
        entries: dict[str, str] = {}
        for account, token in cast("dict[str, object]", section).items():
            if not isinstance(token, str):
                raise CredentialStoreCorruptError(self._paths.credentials)
            entries[account] = token
        return entries

    def _store_entries(self, entries: Mapping[str, str]) -> None:
        """Write the sealed entries to an owner-only file, atomically."""
        document = {
            _VERSION_KEY: _CREDENTIALS_VERSION,
            _ENTRIES_KEY: dict(sorted(entries.items())),
        }
        payload = json.dumps(document, indent=2, sort_keys=True)
        _write_private_file(self._paths.credentials, f"{payload}\n")


@final
class InMemoryCredentialBackend:
    """Process-local credential backend for tests and for non-macOS hosts.

    Like :class:`EncryptedFileBackend` and unlike the raw Keychain transport,
    this store is lossless: it round-trips any string byte-exact.
    """

    def __init__(self, *, available: bool = True) -> None:
        """Create an empty store that can pretend to be unusable."""
        self._items: dict[str, str] = {}
        self._available = available

    @override
    def __repr__(self) -> str:
        """List the accounts held without revealing any of their secrets."""
        return f"{type(self).__name__}(accounts={sorted(self._items)!r})"

    def available(self) -> bool:
        """Report whether this backend was created in a usable state."""
        return self._available

    def has(self, account: str) -> bool:
        """Report whether an entry exists, without materialising its secret."""
        return account in self._items

    def read(self, account: str) -> str | None:
        """Return the secret stored for an account, or None when absent."""
        return self._items.get(account)

    def write(self, account: str, secret: str) -> None:
        """Store a secret and verify it reads back byte-exact."""
        self._items[account] = secret
        if self._items.get(account) != secret:  # pragma: no cover - defensive
            raise CredentialVerificationError(account)

    def remove(self, account: str) -> None:
        """Delete any secret held for an account."""
        _ = self._items.pop(account, None)


@final
@dataclass(frozen=True, slots=True)
class ProviderView:
    """Non-secret Settings card state for one provider."""

    provider_id: str
    display_name: str
    status: ProviderStatus
    requires_key: bool
    env_var: str | None

    @property
    def is_ready(self) -> bool:
        """Report whether the provider is usable without further setup."""
        return self.status is not ProviderStatus.NOT_SET_UP


@final
@dataclass(frozen=True, slots=True)
class ComposerModel:
    """One entry of the composer model picker."""

    model_id: str
    provider_id: str
    display_name: str
    is_default: bool


@final
@dataclass(frozen=True, slots=True)
class _ModelSettings:
    """Non-secret model metadata persisted in the local settings file."""

    configured_providers: tuple[str, ...] = ()
    enabled_models: tuple[str, ...] = ()
    default_model: str | None = None


@final
class ProviderRegistry:
    """Provider catalogue, credential access, and composer state for one install."""

    def __init__(
        self,
        paths: LocalPaths,
        backend: CredentialBackend | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        """Bind the registry to a layout, a credential backend, and an environment."""
        self._paths = paths
        self._backend: CredentialBackend = (
            EncryptedFileBackend(paths) if backend is None else backend
        )
        self._env: Mapping[str, str] = os.environ if env is None else env

    @override
    def __repr__(self) -> str:
        """Describe the registry without reading any credential state."""
        backend = type(self._backend).__name__
        return f"{type(self).__name__}(root={self._paths.root}, backend={backend})"

    def list_providers(self) -> tuple[ProviderView, ...]:
        """Return the non-secret Settings card state for every known provider."""
        return tuple(self._view(spec) for spec in PROVIDERS)

    def describe(self, provider_id: str) -> ProviderView:
        """Return the non-secret Settings card state for one provider."""
        return self._view(get_provider(provider_id))

    def status(self, provider_id: str) -> ProviderStatus:
        """Return one provider's credential status, resolved at call time."""
        return self._status(get_provider(provider_id))

    def set_key(self, provider_id: str, key: str) -> None:
        """Store one provider's API key verbatim, verifying it round-trips."""
        spec = get_provider(provider_id)
        if not spec.requires_key:
            raise KeyNotRequiredError(spec.provider_id)
        validate_api_key(spec.provider_id, key)
        if not self._backend.available():
            raise CredentialBackendUnavailableError(spec.provider_id)
        self._backend.write(spec.provider_id, key)
        self._remember_configured(spec.provider_id, configured=True)

    def clear_key(self, provider_id: str) -> None:
        """Forget one provider's API key; safe to call when none is stored."""
        spec = get_provider(provider_id)
        self._backend.remove(spec.provider_id)
        self._remember_configured(spec.provider_id, configured=False)

    def resolve_key(self, provider_id: str) -> str | None:
        """Resolve one provider's API key now, never caching or persisting it."""
        spec = get_provider(provider_id)
        if not spec.requires_key:
            return None
        stored = self._backend.read(spec.provider_id)
        if stored is not None:
            return stored
        return self._env.get(_env_var_name_unchecked(spec.provider_id)) or None

    def configured_provider_ids(self) -> tuple[str, ...]:
        """Return the provider ids the researcher has set up on this machine."""
        return self._load().configured_providers

    def enabled_models(self) -> tuple[str, ...]:
        """Return the model ids the composer picker offers."""
        return self._load().enabled_models

    def set_enabled_models(self, model_ids: Iterable[str]) -> tuple[str, ...]:
        """Replace the composer model list, keeping the default consistent."""
        accepted: dict[str, None] = {}
        for model_id in model_ids:
            _ = parse_model_id(model_id)
            accepted[model_id] = None
        settings = self._load()
        keep_default = settings.default_model in accepted
        self._store(
            replace(
                settings,
                enabled_models=tuple(accepted),
                default_model=settings.default_model if keep_default else None,
            )
        )
        return tuple(accepted)

    def default_model(self) -> str | None:
        """Return the composer default model id, when one is set."""
        return self._load().default_model

    def set_default_model(self, model_id: str | None) -> None:
        """Mark one enabled model as the composer default, or clear the default."""
        settings = self._load()
        if model_id is None:
            self._store(replace(settings, default_model=None))
            return
        _ = parse_model_id(model_id)
        if model_id not in settings.enabled_models:
            raise ModelNotEnabledError(model_id)
        self._store(replace(settings, default_model=model_id))

    def composer_models(self) -> tuple[ComposerModel, ...]:
        """Return the composer picker entries with the default one marked."""
        settings = self._load()
        entries: list[ComposerModel] = []
        for model_id in settings.enabled_models:
            spec, _ = parse_model_id(model_id)
            entries.append(
                ComposerModel(
                    model_id=model_id,
                    provider_id=spec.provider_id,
                    display_name=spec.display_name,
                    is_default=model_id == settings.default_model,
                )
            )
        return tuple(entries)

    def _view(self, spec: ProviderSpec) -> ProviderView:
        """Build the non-secret card state for one catalogue entry."""
        env_var = (
            _env_var_name_unchecked(spec.provider_id) if spec.requires_key else None
        )
        return ProviderView(
            provider_id=spec.provider_id,
            display_name=spec.display_name,
            status=self._status(spec),
            requires_key=spec.requires_key,
            env_var=env_var,
        )

    def _status(self, spec: ProviderSpec) -> ProviderStatus:
        """Resolve a provider's status without decrypting or unlocking anything."""
        if not spec.requires_key:
            return ProviderStatus.NO_KEY_NEEDED
        if self._backend.has(spec.provider_id):
            return ProviderStatus.CONFIGURED
        if self._env.get(_env_var_name_unchecked(spec.provider_id)):
            return ProviderStatus.CONFIGURED
        return ProviderStatus.NOT_SET_UP

    def _remember_configured(self, provider_id: str, *, configured: bool) -> None:
        """Record, without any secret, whether a provider was set up here."""
        settings = self._load()
        remaining = [
            item for item in settings.configured_providers if item != provider_id
        ]
        if configured:
            remaining.append(provider_id)
        order = {spec.provider_id: index for index, spec in enumerate(PROVIDERS)}
        remaining.sort(key=lambda item: order.get(item, len(order)))
        self._store(replace(settings, configured_providers=tuple(remaining)))

    def _load(self) -> _ModelSettings:
        """Read the non-secret settings, tolerating unparseable content."""
        section = self._document(quarantine=False).get(SETTINGS_SECTION)
        if not isinstance(section, dict):
            return _ModelSettings()
        values = cast("dict[str, object]", section)
        default = values.get(_DEFAULT_KEY)
        return _ModelSettings(
            configured_providers=_as_str_tuple(values.get(_CONFIGURED_KEY)),
            enabled_models=_as_str_tuple(values.get(_ENABLED_KEY)),
            default_model=default if isinstance(default, str) and default else None,
        )

    def _document(self, *, quarantine: bool) -> dict[str, object]:
        """Return the settings document, moving an unparseable one aside first."""
        document = _read_json_object(self._paths.settings)
        if document is not None:
            return document
        if quarantine:
            path = self._paths.settings
            spoiled = path.with_name(f"{path.name}.corrupt.{os.getpid()}")
            with contextlib.suppress(OSError):
                _ = path.replace(spoiled)
        return {}

    def _store(self, settings: _ModelSettings) -> None:
        """Write the non-secret settings atomically, preserving other sections."""
        document = self._document(quarantine=True)
        document[SETTINGS_SECTION] = {
            _CONFIGURED_KEY: list(settings.configured_providers),
            _ENABLED_KEY: list(settings.enabled_models),
            _DEFAULT_KEY: settings.default_model,
        }
        payload = json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True)
        _write_private_file(self._paths.settings, f"{payload}\n")


def default_registry(root: Path | None = None) -> ProviderRegistry:
    """Build a registry over the default local layout and the macOS Keychain."""
    return ProviderRegistry(resolve_paths(root))
