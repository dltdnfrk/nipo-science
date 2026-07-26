from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn, cast, final

import pytest

from nipo_local.config import LocalPaths
from nipo_local.providers import (
    KEYCHAIN_MAX_SECRET_BYTES,
    MASTER_KEY_ACCOUNT,
    MASTER_KEY_BYTES,
    PROVIDERS,
    SECURITY_BIN,
    CredentialBackend,
    CredentialBackendError,
    CredentialBackendUnavailableError,
    CredentialDecryptionError,
    CredentialStoreCorruptError,
    CredentialVerificationError,
    EmptyKeyError,
    EncryptedFileBackend,
    InMemoryCredentialBackend,
    InvisibleCharacterError,
    KeychainBackend,
    KeychainCommandError,
    KeychainValueUnsupportedError,
    KeychainWriteError,
    KeyNotRequiredError,
    LocalStateUnreadableError,
    MalformedModelIdError,
    MasterKeyUnusableError,
    ModelNotEnabledError,
    ProviderRegistry,
    ProviderStatus,
    SurroundingWhitespaceError,
    UnknownProviderError,
    env_var_name,
    validate_api_key,
)

if TYPE_CHECKING:
    from collections.abc import Callable

# Adversarial by default. This is longer than the 128-byte Keychain cap and
# contains non-ASCII, so it would have been silently truncated AND hex-mangled
# by the original transport. It contains nothing invisible, so it is a value
# `set_key` must accept and store byte-exact.
FAKE_KEY: Final = "sk-proj-" + "Zq7" * 55 + "-café-λ-Ω"

# Written as escapes: these are invisible in a source file, which is exactly
# what makes them dangerous when they ride along in a pasted key.
ZERO_WIDTH: Final = "\u200b"
NBSP: Final = "\u00a0"

# Values the storage layer must round-trip exactly, whatever they contain.
# Every one of these was measured to corrupt under the original transport.
ADVERSARIAL: Final[tuple[tuple[str, str], ...]] = (
    ("internal-newline", "sk-abc\ndef-tail"),
    ("carriage-return", "sk-abc\rdef-tail"),
    ("crlf", "sk-abc\r\ndef"),
    ("tab", "sk-abc\tdef"),
    ("len-129", "k" * 129),
    ("len-200", "k" * 200),
    ("len-4096", "k" * 4096),
    ("unicode", "sk-café-λ-Ω"),
    ("emoji", "sk-🔑-key"),
    ("zero-width-lead", f"{ZERO_WIDTH}sk-abcdef"),
    ("nul-byte", "sk-a\x00b"),
    ("empty", ""),
    ("only-spaces", "   "),
)

_KEYCHAIN_TESTS_ENABLED: Final = (
    sys.platform == "darwin"
    and SECURITY_BIN.is_file()
    and not os.environ.get("NIPO_SKIP_KEYCHAIN_TESTS")
)

requires_keychain = pytest.mark.skipif(
    not _KEYCHAIN_TESTS_ENABLED,
    reason="needs macOS and /usr/bin/security; set NIPO_SKIP_KEYCHAIN_TESTS=1 to skip",
)


@pytest.fixture
def allow_real_security() -> bool:
    """Opt one test out of the real-`security` guard below."""
    return True


@pytest.fixture(autouse=True)
def forbid_real_security(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Block the real `security` binary unless a test explicitly opts in."""
    if "allow_real_security" in request.fixturenames:
        return

    def _fail(*_args: object, **_kwargs: object) -> NoReturn:
        message = "this test must not invoke the real `security` binary"
        raise AssertionError(message)

    monkeypatch.setattr(subprocess, "run", _fail)


@pytest.fixture
def paths(tmp_path: Path) -> LocalPaths:
    layout = LocalPaths(root=tmp_path)
    layout.ensure()
    return layout


@pytest.fixture
def master() -> InMemoryCredentialBackend:
    """Stand in for the Keychain as the holder of the master key only."""
    return InMemoryCredentialBackend()


@pytest.fixture
def backend(
    paths: LocalPaths,
    master: InMemoryCredentialBackend,
) -> EncryptedFileBackend:
    """The real production credential store: real crypto, real files on disk."""
    return EncryptedFileBackend(paths, master)


@pytest.fixture
def registry(
    paths: LocalPaths,
    backend: EncryptedFileBackend,
) -> ProviderRegistry:
    return ProviderRegistry(paths, backend, env={})


def _files_under(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


def _completed(
    status: int,
    stdout: str = "",
    stderr: str = "",
) -> Callable[..., subprocess.CompletedProcess[str]]:
    def _run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, status, stdout, stderr)

    return _run


@final
class BrokenReadBackend:
    """Stands in for a locked keychain: reads fail rather than report absence."""

    def available(self) -> bool:
        return True

    def has(self, account: str) -> bool:
        return bool(account)

    def read(self, account: str) -> str | None:
        command = "find-generic-password"
        raise KeychainCommandError(command, 36, f"locked: {account}")

    def write(self, account: str, secret: str) -> None:
        raise KeychainWriteError(account, len(secret))

    def remove(self, account: str) -> None:
        command = "delete-generic-password"
        raise KeychainCommandError(command, 36, account)


# --------------------------------------------------------------------------
# Catalogue
# --------------------------------------------------------------------------


def test_catalogue_matches_the_settings_screen() -> None:
    assert [spec.provider_id for spec in PROVIDERS] == [
        "anthropic",
        "openai",
        "google",
        "ollama",
        "fireworks",
        "together",
        "zai",
        "moonshot",
        "deepseek",
        "mistral",
        "qwen",
        "minimax",
        "xai",
    ]
    keyless = [spec.provider_id for spec in PROVIDERS if not spec.requires_key]
    assert keyless == ["ollama"]
    assert PROVIDERS[0].display_name == "Claude (Anthropic)"


def test_ollama_needs_no_key(registry: ProviderRegistry) -> None:
    assert registry.status("ollama") is ProviderStatus.NO_KEY_NEEDED
    assert registry.resolve_key("ollama") is None

    view = registry.describe("ollama")
    assert view.display_name == "Ollama (local models)"
    assert view.requires_key is False
    assert view.env_var is None
    assert view.is_ready is True

    with pytest.raises(KeyNotRequiredError):
        registry.set_key("ollama", FAKE_KEY)


@pytest.mark.parametrize(
    "provider_id",
    ["", "claude", "gpt", "ANTHROPIC", "anthropic ", "openai:gpt-5"],
)
def test_unknown_provider_raises(
    registry: ProviderRegistry,
    provider_id: str,
) -> None:
    with pytest.raises(UnknownProviderError):
        _ = registry.status(provider_id)
    with pytest.raises(UnknownProviderError):
        _ = registry.describe(provider_id)
    with pytest.raises(UnknownProviderError):
        registry.set_key(provider_id, FAKE_KEY)
    with pytest.raises(UnknownProviderError):
        registry.clear_key(provider_id)
    with pytest.raises(UnknownProviderError):
        _ = registry.resolve_key(provider_id)
    with pytest.raises(UnknownProviderError):
        _ = env_var_name(provider_id)


def test_unknown_provider_error_is_actionable() -> None:
    with pytest.raises(UnknownProviderError) as caught:
        _ = env_var_name("claude")

    message = str(caught.value)
    assert "claude" in message
    assert "anthropic" in message
    assert caught.value.provider_id == "claude"


# --------------------------------------------------------------------------
# Integrity: the storage layer must never silently differ
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "value"),
    [pytest.param(label, value, id=label) for label, value in ADVERSARIAL],
)
def test_backend_round_trips_adversarial_values_exactly(
    backend: EncryptedFileBackend,
    label: str,
    value: str,
) -> None:
    backend.write("openai", value)
    assert backend.read("openai") == value, label
    assert backend.has("openai") is True


@pytest.mark.parametrize(
    ("label", "value"),
    [
        pytest.param("len-200", "k" * 200, id="len-200"),
        pytest.param("openai-proj", "sk-proj-" + "B" * 156, id="openai-proj-164"),
        pytest.param("unicode", "sk-café-λ-Ω", id="unicode"),
        pytest.param("default", FAKE_KEY, id="default-fake-key"),
    ],
)
def test_set_key_stores_realistic_keys_byte_exact(
    registry: ProviderRegistry,
    label: str,
    value: str,
) -> None:
    registry.set_key("openai", value)
    assert registry.resolve_key("openai") == value, label
    assert registry.status("openai") is ProviderStatus.CONFIGURED


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param("", EmptyKeyError, id="empty"),
        pytest.param("   ", EmptyKeyError, id="only-spaces"),
        pytest.param("\n\t ", EmptyKeyError, id="only-whitespace"),
        pytest.param(" sk-abc", SurroundingWhitespaceError, id="leading-space"),
        pytest.param("sk-abc\n", SurroundingWhitespaceError, id="trailing-newline"),
        pytest.param("sk-abc ", SurroundingWhitespaceError, id="trailing-space"),
        pytest.param(f"{NBSP}sk-abc", SurroundingWhitespaceError, id="nbsp-lead"),
        pytest.param("sk-abc\ndef", InvisibleCharacterError, id="internal-newline"),
        pytest.param("sk-abc\rdef", InvisibleCharacterError, id="carriage-return"),
        pytest.param("sk-abc\tdef", InvisibleCharacterError, id="internal-tab"),
        pytest.param(f"{ZERO_WIDTH}sk-abc", InvisibleCharacterError, id="zw-lead"),
        pytest.param("sk-a\x00b", InvisibleCharacterError, id="nul-byte"),
    ],
)
def test_set_key_rejects_input_it_would_not_store_verbatim(
    registry: ProviderRegistry,
    value: str,
    expected: type[Exception],
) -> None:
    with pytest.raises(expected):
        registry.set_key("openai", value)
    # Nothing was stored, and nothing was silently normalised into place.
    assert registry.status("openai") is ProviderStatus.NOT_SET_UP
    assert registry.resolve_key("openai") is None


def test_rejection_messages_locate_the_problem_without_echoing_the_key() -> None:
    pasted = f"{ZERO_WIDTH}sk-{'secret-value-here'}"
    with pytest.raises(InvisibleCharacterError) as caught:
        validate_api_key("openai", pasted)

    message = str(caught.value)
    assert "U+200B" in message
    assert "position 0" in message
    assert "sk-" + "secret-value-here" not in message
    assert caught.value.code_point == "U+200B"


def test_keychain_backend_refuses_what_it_cannot_carry_intact() -> None:
    keychain = KeychainBackend()
    unsupported = [
        "x" * (KEYCHAIN_MAX_SECRET_BYTES + 1),
        "has\nnewline",
        "has\rreturn",
        "café",
        "nul\x00byte",
        "",
    ]
    for value in unsupported:
        with pytest.raises(KeychainValueUnsupportedError):
            keychain.write("probe", value)


def test_keychain_write_raises_when_the_value_does_not_read_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A truncating or blanking transport must become a loud failure."""

    def _run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[1] == "add-generic-password":
            return subprocess.CompletedProcess(args, 0, "", "")
        # Exactly what the real binary did for over-long input: silent truncation.
        return subprocess.CompletedProcess(args, 0, "the-full-original\n", "")

    monkeypatch.setattr(subprocess, "run", _run)
    # Passes the up-front guardrail, so only the read-back check can catch it.
    with pytest.raises(CredentialVerificationError):
        KeychainBackend().write("probe", "the-full-original-value")


def test_keychain_write_blanked_by_the_transport_is_caught(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The newline defect stored an empty password at exit 0; catch it."""

    def _run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[1] == "add-generic-password":
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "\n", "")

    monkeypatch.setattr(subprocess, "run", _run)
    with pytest.raises(CredentialVerificationError):
        KeychainBackend().write("probe", "a-real-value")


# --------------------------------------------------------------------------
# Confidentiality
# --------------------------------------------------------------------------


def test_list_providers_never_exposes_key_material(
    registry: ProviderRegistry,
) -> None:
    registry.set_key("anthropic", FAKE_KEY)
    views = registry.list_providers()

    assert len(views) == len(PROVIDERS)
    by_id = {view.provider_id: view for view in views}
    assert by_id["anthropic"].status is ProviderStatus.CONFIGURED
    assert by_id["openai"].status is ProviderStatus.NOT_SET_UP
    assert by_id["ollama"].status is ProviderStatus.NO_KEY_NEEDED

    assert FAKE_KEY not in repr(views)
    for view in views:
        assert FAKE_KEY not in repr(view)
        assert FAKE_KEY not in str(view)
        assert FAKE_KEY not in view.display_name
        assert view.env_var is None or FAKE_KEY not in view.env_var


def test_no_file_on_disk_ever_contains_key_material(
    registry: ProviderRegistry,
    paths: LocalPaths,
) -> None:
    registry.set_key("anthropic", FAKE_KEY)
    registry.set_key("openai", FAKE_KEY)
    _ = registry.set_enabled_models(
        ["anthropic:claude-sonnet-4-5", "ollama:llama3.1"],
    )
    registry.set_default_model("anthropic:claude-sonnet-4-5")

    written = _files_under(paths.root)
    assert written == sorted([paths.settings, paths.credentials])
    for path in written:
        assert FAKE_KEY not in path.read_text(encoding="utf-8")

    settings_text = paths.settings.read_text(encoding="utf-8")
    assert "anthropic" in settings_text
    assert "claude-sonnet-4-5" in settings_text
    # The credential file holds ciphertext only.
    assert FAKE_KEY not in paths.credentials.read_text(encoding="utf-8")
    assert registry.resolve_key("anthropic") == FAKE_KEY


def test_private_files_are_owner_only_even_before_the_rename(
    registry: ProviderRegistry,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The payload must never exist at 0644, not even for an instant."""
    observed: list[int] = []
    original = Path.replace

    def _spy(self: Path, target: str | os.PathLike[str]) -> Path:
        observed.append(self.stat().st_mode & 0o777)
        return original(self, target)

    monkeypatch.setattr(Path, "replace", _spy)
    registry.set_key("openai", FAKE_KEY)

    assert observed
    assert all(mode == 0o600 for mode in observed)
    assert paths.settings.stat().st_mode & 0o777 == 0o600
    assert paths.credentials.stat().st_mode & 0o777 == 0o600


def test_repr_never_leaks_key_material(
    registry: ProviderRegistry,
    backend: EncryptedFileBackend,
    master: InMemoryCredentialBackend,
) -> None:
    registry.set_key("anthropic", FAKE_KEY)
    _ = registry.set_enabled_models(["anthropic:claude-sonnet-4-5"])
    registry.set_default_model("anthropic:claude-sonnet-4-5")
    keychain = KeychainBackend()

    master_value = master.read(MASTER_KEY_ACCOUNT)
    assert master_value is not None

    renderings = [
        repr(registry),
        str(registry),
        repr(backend),
        str(backend),
        repr(master),
        str(master),
        repr(keychain),
        str(keychain),
        repr(PROVIDERS),
        repr(registry.list_providers()),
        repr(registry.describe("anthropic")),
        repr(registry.composer_models()),
        repr(registry.enabled_models()),
        repr(registry.configured_provider_ids()),
    ]
    for rendering in renderings:
        assert FAKE_KEY not in rendering
        assert master_value not in rendering

    assert "nipo-science" in repr(keychain)


def test_error_messages_never_embed_key_material(
    paths: LocalPaths,
    backend: EncryptedFileBackend,
) -> None:
    backend.write("openai", FAKE_KEY)
    _ = paths.credentials.write_text("{ not json", encoding="utf-8")

    with pytest.raises(CredentialStoreCorruptError) as corrupt:
        _ = backend.read("openai")
    assert FAKE_KEY not in str(corrupt.value)

    # The two errors raised on paths that handled the secret carry no value.
    for error in (
        KeychainWriteError("openai", 161),
        CredentialVerificationError("openai"),
        KeychainValueUnsupportedError("openai", "value is not ASCII"),
    ):
        assert FAKE_KEY not in str(error)
        assert FAKE_KEY not in repr(error)


# --------------------------------------------------------------------------
# Resolution: absent vs failed
# --------------------------------------------------------------------------


def test_set_resolve_clear_round_trip(
    registry: ProviderRegistry,
    backend: EncryptedFileBackend,
) -> None:
    assert registry.status("openai") is ProviderStatus.NOT_SET_UP
    assert registry.resolve_key("openai") is None

    registry.set_key("openai", FAKE_KEY)
    assert registry.status("openai") is ProviderStatus.CONFIGURED
    assert registry.resolve_key("openai") == FAKE_KEY
    assert registry.configured_provider_ids() == ("openai",)
    assert backend.has("openai")

    registry.clear_key("openai")
    assert registry.status("openai") is ProviderStatus.NOT_SET_UP
    assert registry.resolve_key("openai") is None
    assert registry.configured_provider_ids() == ()
    assert not backend.has("openai")


def test_clear_key_is_idempotent(registry: ProviderRegistry) -> None:
    registry.clear_key("openai")
    registry.clear_key("openai")
    registry.clear_key("ollama")
    assert registry.configured_provider_ids() == ()


def test_env_fallback_resolves_when_nothing_is_stored(paths: LocalPaths) -> None:
    assert env_var_name("openai") == "NIPO_OPENAI_API_KEY"
    env = {"NIPO_OPENAI_API_KEY": FAKE_KEY}
    store = EncryptedFileBackend(paths, InMemoryCredentialBackend())
    registry = ProviderRegistry(paths, store, env=env)

    assert registry.resolve_key("openai") == FAKE_KEY
    assert registry.status("openai") is ProviderStatus.CONFIGURED
    assert registry.status("google") is ProviderStatus.NOT_SET_UP


def test_env_fallback_resolves_when_the_store_is_unavailable(
    paths: LocalPaths,
) -> None:
    env = {env_var_name("google"): FAKE_KEY}
    store = EncryptedFileBackend(paths, InMemoryCredentialBackend(available=False))
    registry = ProviderRegistry(paths, store, env=env)

    assert registry.resolve_key("google") == FAKE_KEY
    assert registry.status("google") is ProviderStatus.CONFIGURED


def test_stored_key_wins_over_the_environment(
    paths: LocalPaths,
    backend: EncryptedFileBackend,
) -> None:
    env = {env_var_name("openai"): "env-value-that-must-not-win"}
    registry = ProviderRegistry(paths, backend, env=env)

    registry.set_key("openai", FAKE_KEY)
    assert registry.resolve_key("openai") == FAKE_KEY


def test_a_failed_read_never_falls_back_to_the_environment(
    paths: LocalPaths,
) -> None:
    """A locked keychain must not silently resolve the wrong key."""
    env = {env_var_name("openai"): "wrong-key-from-the-environment"}
    registry = ProviderRegistry(paths, BrokenReadBackend(), env=env)

    with pytest.raises(KeychainCommandError):
        _ = registry.resolve_key("openai")


def test_keychain_read_failure_is_not_reported_as_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "run", _completed(36, "", "keychain is locked"))
    keychain = KeychainBackend()

    with pytest.raises(KeychainCommandError):
        _ = keychain.read("anthropic")
    with pytest.raises(KeychainCommandError):
        _ = keychain.has("anthropic")


def test_keychain_reports_a_genuinely_missing_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "run", _completed(44, "", "not found"))
    keychain = KeychainBackend()

    assert keychain.read("anthropic") is None
    assert keychain.has("anthropic") is False
    keychain.remove("anthropic")


def test_unavailable_store_never_writes_a_fallback_file(
    paths: LocalPaths,
) -> None:
    store = EncryptedFileBackend(paths, InMemoryCredentialBackend(available=False))
    registry = ProviderRegistry(paths, store, env={})

    with pytest.raises(CredentialBackendUnavailableError):
        registry.set_key("openai", FAKE_KEY)

    assert not paths.credentials.exists()
    for path in _files_under(paths.root):
        assert FAKE_KEY not in path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Master key and sealing
# --------------------------------------------------------------------------


def test_master_key_is_keychain_safe_and_reused(
    backend: EncryptedFileBackend,
    master: InMemoryCredentialBackend,
) -> None:
    backend.write("openai", FAKE_KEY)
    encoded = master.read(MASTER_KEY_ACCOUNT)
    assert encoded is not None

    # Immune by construction to all three measured transport defects.
    assert len(encoded) == 44
    assert encoded.isascii()
    assert encoded.isprintable()
    assert len(encoded.encode("utf-8")) <= KEYCHAIN_MAX_SECRET_BYTES
    assert len(base64.urlsafe_b64decode(encoded)) == MASTER_KEY_BYTES

    backend.write("anthropic", FAKE_KEY)
    assert master.read(MASTER_KEY_ACCOUNT) == encoded


def test_losing_the_master_key_is_loud_not_silent(
    backend: EncryptedFileBackend,
    master: InMemoryCredentialBackend,
) -> None:
    backend.write("openai", FAKE_KEY)
    master.remove(MASTER_KEY_ACCOUNT)

    with pytest.raises(MasterKeyUnusableError):
        _ = backend.read("openai")


def test_a_ciphertext_cannot_be_moved_between_providers(
    backend: EncryptedFileBackend,
    paths: LocalPaths,
) -> None:
    backend.write("anthropic", FAKE_KEY)
    raw = paths.credentials.read_text(encoding="utf-8")
    document = cast("dict[str, object]", json.loads(raw))
    entries = cast("dict[str, str]", document["entries"])
    entries["openai"] = entries["anthropic"]
    _ = paths.credentials.write_text(json.dumps(document), encoding="utf-8")

    assert backend.read("anthropic") == FAKE_KEY
    with pytest.raises(CredentialDecryptionError):
        _ = backend.read("openai")


def test_a_corrupt_credential_store_is_never_silently_discarded(
    backend: EncryptedFileBackend,
    paths: LocalPaths,
) -> None:
    backend.write("openai", FAKE_KEY)
    _ = paths.credentials.write_text("{ not json", encoding="utf-8")

    with pytest.raises(CredentialStoreCorruptError):
        _ = backend.read("openai")
    with pytest.raises(CredentialStoreCorruptError):
        _ = backend.has("openai")


def test_every_backend_agrees_on_absence_and_round_trip(
    paths: LocalPaths,
) -> None:
    stores: list[CredentialBackend] = [
        InMemoryCredentialBackend(),
        EncryptedFileBackend(paths, InMemoryCredentialBackend()),
    ]
    for store in stores:
        assert store.available() is True
        assert store.has("openai") is False
        assert store.read("openai") is None
        store.remove("openai")

        store.write("openai", FAKE_KEY)
        assert store.has("openai") is True
        assert store.read("openai") == FAKE_KEY

        store.remove("openai")
        assert store.has("openai") is False
        assert store.read("openai") is None


# --------------------------------------------------------------------------
# argv hygiene
# --------------------------------------------------------------------------


def test_keychain_write_never_puts_the_secret_in_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert the property, not the payload shape."""
    value = base64.urlsafe_b64encode(secrets.token_bytes(MASTER_KEY_BYTES)).decode()
    seen_argv: list[str] = []
    seen_stdin: list[str] = []

    def _run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen_argv.extend(args)
        stdin = kwargs.get("input")
        if isinstance(stdin, str):
            seen_stdin.append(stdin)
        if args[1] == "add-generic-password":
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, f"{value}\n", "")

    monkeypatch.setattr(subprocess, "run", _run)
    KeychainBackend().write("probe", value)

    assert value not in " ".join(seen_argv)
    assert not any(value in argument for argument in seen_argv)
    # It was delivered, just not through the process table.
    assert any(value in payload for payload in seen_stdin)


def test_existence_check_never_asks_for_the_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[list[str]] = []

    def _run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", _run)
    assert KeychainBackend().has("anthropic") is True
    assert captured
    assert all("-w" not in args for args in captured)


def test_status_screen_never_touches_the_keychain(
    registry: ProviderRegistry,
) -> None:
    """`forbid_real_security` would fail this test if any subprocess ran."""
    registry.set_key("anthropic", FAKE_KEY)
    views = registry.list_providers()
    assert len(views) == len(PROVIDERS)


# --------------------------------------------------------------------------
# Settings file
# --------------------------------------------------------------------------


def test_settings_write_preserves_sibling_sections(
    registry: ProviderRegistry,
    paths: LocalPaths,
) -> None:
    _ = paths.settings.write_text(
        json.dumps({"store": {"schema": 3}}),
        encoding="utf-8",
    )

    registry.set_key("openai", FAKE_KEY)

    raw = paths.settings.read_text(encoding="utf-8")
    document = cast("dict[str, object]", json.loads(raw))
    assert document["store"] == {"schema": 3}
    assert document["models"] == {
        "configured_providers": ["openai"],
        "enabled_models": [],
        "default_model": None,
    }
    assert FAKE_KEY not in raw


def test_a_transient_read_error_never_wipes_sibling_sections(
    registry: ProviderRegistry,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = paths.settings.write_text(
        json.dumps({"store": {"schema": 3}}),
        encoding="utf-8",
    )
    original = Path.read_bytes
    settings_path = paths.settings

    def _selective(self: Path) -> bytes:
        if self == settings_path:
            message = "simulated transient I/O error"
            raise OSError(5, message)
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", _selective)
    with pytest.raises(LocalStateUnreadableError):
        registry.set_key("openai", FAKE_KEY)
    monkeypatch.undo()

    document = cast(
        "dict[str, object]",
        json.loads(paths.settings.read_text(encoding="utf-8")),
    )
    assert document["store"] == {"schema": 3}


def test_corrupt_settings_are_quarantined_not_destroyed(
    registry: ProviderRegistry,
    paths: LocalPaths,
) -> None:
    spoiled_bytes = b"\xff\xfe not utf-8 at all"
    _ = paths.settings.write_bytes(spoiled_bytes)

    assert registry.enabled_models() == ()
    assert registry.configured_provider_ids() == ()

    registry.set_key("openai", FAKE_KEY)
    assert registry.configured_provider_ids() == ("openai",)

    quarantined = list(paths.root.glob("settings.json.corrupt.*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == spoiled_bytes


def test_settings_holding_a_json_array_is_tolerated(
    registry: ProviderRegistry,
    paths: LocalPaths,
) -> None:
    _ = paths.settings.write_text(json.dumps(["not", "an", "object"]))

    assert registry.default_model() is None
    registry.set_key("openai", FAKE_KEY)
    assert registry.configured_provider_ids() == ("openai",)


def test_configured_providers_follow_catalogue_order(
    registry: ProviderRegistry,
) -> None:
    registry.set_key("xai", FAKE_KEY)
    registry.set_key("anthropic", FAKE_KEY)
    registry.set_key("google", FAKE_KEY)
    assert registry.configured_provider_ids() == ("anthropic", "google", "xai")


# --------------------------------------------------------------------------
# Composer picker
# --------------------------------------------------------------------------


def test_composer_picker_round_trip(registry: ProviderRegistry) -> None:
    enabled = registry.set_enabled_models(
        [
            "anthropic:claude-sonnet-4-5",
            "ollama:llama3.1",
            "anthropic:claude-sonnet-4-5",
        ],
    )
    assert enabled == ("anthropic:claude-sonnet-4-5", "ollama:llama3.1")
    assert registry.enabled_models() == enabled
    assert registry.default_model() is None

    registry.set_default_model("ollama:llama3.1")
    assert registry.default_model() == "ollama:llama3.1"

    models = registry.composer_models()
    assert [model.model_id for model in models] == list(enabled)
    assert [model.is_default for model in models] == [False, True]
    assert models[0].provider_id == "anthropic"
    assert models[1].display_name == "Ollama (local models)"

    registry.set_default_model(None)
    assert registry.default_model() is None


def test_default_model_must_be_enabled(registry: ProviderRegistry) -> None:
    _ = registry.set_enabled_models(["openai:gpt-5"])
    with pytest.raises(ModelNotEnabledError):
        registry.set_default_model("anthropic:claude-sonnet-4-5")
    assert registry.default_model() is None


def test_disabling_the_default_model_clears_it(
    registry: ProviderRegistry,
) -> None:
    _ = registry.set_enabled_models(["openai:gpt-5", "xai:grok-4"])
    registry.set_default_model("xai:grok-4")
    assert registry.default_model() == "xai:grok-4"

    _ = registry.set_enabled_models(["openai:gpt-5"])
    assert registry.default_model() is None


def test_model_ids_are_validated(registry: ProviderRegistry) -> None:
    with pytest.raises(MalformedModelIdError):
        _ = registry.set_enabled_models(["claude-sonnet-4-5"])
    with pytest.raises(MalformedModelIdError):
        _ = registry.set_enabled_models(["anthropic:"])
    with pytest.raises(UnknownProviderError):
        _ = registry.set_enabled_models(["bogus:some-model"])
    assert registry.enabled_models() == ()


# --------------------------------------------------------------------------
# Against the REAL `security` binary
# --------------------------------------------------------------------------


@requires_keychain
def test_real_keychain_round_trip_and_guardrails(
    allow_real_security: bool,
) -> None:
    """Exercise the real binary on a throwaway service, cleaning up after."""
    assert allow_real_security
    service = f"nipo-test-{secrets.token_hex(6)}"
    keychain = KeychainBackend(service=service)
    value = base64.urlsafe_b64encode(secrets.token_bytes(MASTER_KEY_BYTES)).decode()

    try:
        assert keychain.has("probe") is False
        assert keychain.read("probe") is None

        try:
            keychain.write("probe", value)
        except KeychainWriteError:  # pragma: no cover - environment dependent
            pytest.skip("this environment cannot write to the login keychain")

        assert keychain.has("probe") is True
        assert keychain.read("probe") == value

        # Everything the transport would mangle is refused, not corrupted.
        for bad in ("x" * 129, "a\nb", "a\rb", "café", "a\x00b", ""):
            with pytest.raises(KeychainValueUnsupportedError):
                keychain.write("probe", bad)

        # The good value survived every rejected attempt.
        assert keychain.read("probe") == value

        keychain.remove("probe")
        assert keychain.has("probe") is False
        keychain.remove("probe")
    finally:
        with contextlib.suppress(CredentialBackendError):
            keychain.remove("probe")


@requires_keychain
def test_real_stack_stores_an_adversarial_key_end_to_end(
    tmp_path: Path,
    allow_real_security: bool,
) -> None:
    """The production stack against the real Keychain, with a hostile key."""
    assert allow_real_security
    service = f"nipo-test-{secrets.token_hex(6)}"
    keychain = KeychainBackend(service=service)
    layout = LocalPaths(root=tmp_path)
    layout.ensure()
    store = EncryptedFileBackend(layout, keychain)
    registry = ProviderRegistry(layout, store, env={})

    try:
        try:
            registry.set_key("openai", FAKE_KEY)
        except KeychainWriteError:  # pragma: no cover - environment dependent
            pytest.skip("this environment cannot write to the login keychain")

        assert registry.resolve_key("openai") == FAKE_KEY
        assert registry.status("openai") is ProviderStatus.CONFIGURED

        raw = layout.credentials.read_text(encoding="utf-8")
        assert FAKE_KEY not in raw
        assert layout.credentials.stat().st_mode & 0o777 == 0o600

        registry.clear_key("openai")
        assert registry.resolve_key("openai") is None
    finally:
        with contextlib.suppress(CredentialBackendError):
            keychain.remove(MASTER_KEY_ACCOUNT)
