import re
import unicodedata
from typing import Final

from pydantic import JsonValue

MONETARY_STEMS: Final = ("cost", "price", "spend", "budget", "monetary", "currency")
CREDENTIAL_NAMES: Final = (
    "authorization",
    "token",
    "credential",
    "credentials",
    "apikey",
    "cookie",
    "password",
    "passwd",
    "secret",
    "privatekey",
    "bearer",
)
BENIGN_PREFIXES: Final = ("tokenization", "passwordless", "secretory", "secretome")
FORBIDDEN_EVENT_ERROR: Final = "forbidden_run_event_semantics"
FORBIDDEN_EVENT_MESSAGE: Final = "Run event data contains forbidden semantics"

VALUE_CHARACTER: Final = r"[A-Za-z0-9._~+/=-]"
PROVIDER_PREFIX_A: Final = r"sk-(?:proj-)?|gh[pousr]_|github_pat_|xox[baprs]-"
PROVIDER_PREFIX_B: Final = r"[rs]k_live_|AIza|ya29\."
SECRET_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        rf"^\s*(?:authorization\s*:\s*)?(?:bearer|basic)\s+{VALUE_CHARACTER}{{24,}}\s*$",
        re.IGNORECASE,
    ),
    re.compile(
        "".join(
            (
                r"^\s*(?:client[\s_-]*(?:secret|password)|api[\s_-]*(?:key|token|secret)",
                r"|(?:access|refresh|auth)[\s_-]*token|secret|token|password|passwd)",
                rf"\s*[:=]\s*[\"']?{VALUE_CHARACTER}{{24,}}[\"']?\s*$",
            )
        ),
        re.IGNORECASE,
    ),
    re.compile(
        "".join(
            (
                rf"^\s*(?:(?:{PROVIDER_PREFIX_A}|{PROVIDER_PREFIX_B})",
                r"[A-Za-z0-9_-]{24,}|(?:AKIA|ASIA)[0-9A-Z]{16})\s*$",
            )
        ),
        re.IGNORECASE,
    ),
    re.compile(r"^\s*-{5}BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-{5}", re.IGNORECASE),
)


def _forbidden_event_key(key: str) -> bool:
    normalized = "".join(
        character
        for character in unicodedata.normalize("NFKC", key).casefold()
        if character.isascii() and character.isalnum()
    )
    monetary = any(stem in normalized for stem in MONETARY_STEMS)
    prefix = normalized.startswith(CREDENTIAL_NAMES)
    credential = normalized.endswith(CREDENTIAL_NAMES)
    credential = credential or (prefix and not normalized.startswith(BENIGN_PREFIXES))
    fallback = "provider" in normalized and "fallback" in normalized
    return monetary or credential or fallback


def _forbidden_event_value(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", value)
    return any(
        pattern.search(normalized) is not None for pattern in SECRET_VALUE_PATTERNS
    )


def contains_forbidden_event_data(value: JsonValue) -> bool:
    if isinstance(value, dict):
        return any(
            _forbidden_event_key(key) or contains_forbidden_event_data(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(contains_forbidden_event_data(item) for item in value)
    return isinstance(value, str) and _forbidden_event_value(value)
