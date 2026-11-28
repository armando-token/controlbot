"""Strict M2 secret redaction extending frozen src/contracts/redaction.py.

Handles camelCase/PascalCase secret keys (e.g. accessToken, sessionToken, apiKey,
clientSecret, csrfToken) and query-param/evidence_refs secret strings without
modifying frozen src/contracts/redaction.py.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from src.contracts.redaction import (
    REDACTED_PLACEHOLDER,
    contains_unredacted_secret,
    is_sensitive_key,
    redact_string,
)

_CAMEL_BOUNDARY_1 = re.compile(r"([a-z0-9])([A-Z])")
_CAMEL_BOUNDARY_2 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_REDACTED_AUTH_PUNCT_RE = re.compile(
    r"(?i)\b(Bearer|Basic)\s+\[REDACTED\](?=[\s,;:'\"\)\}\]]|$)"
)
_QUERY_SECRET_RE = re.compile(
    r"(?i)\b("
    r"[A-Za-z0-9_.-]*[_-](?:password|passwd|secret(?:[_-]?key)?|private[_-]?key|"
    r"api[_-]?key|apikey|token|cookies?|credentials?|auth|webhook[_-]?key)"
    r"|(?-i:[a-z0-9][A-Za-z0-9]*(?:Password|Passwd|Secret(?:Key)?|PrivateKey|"
    r"ApiKey|Token|Cookies?|Credentials?|Auth|WebhookKey))"
    r"|password|passwd|secret|secret_key|secretKey|secret-key|"
    r"api_key|api-key|apikey|x_api_key|x-api-key|xApiKey|token|"
    r"access_token|accessToken|refresh_token|refreshToken|auth_token|authToken|"
    r"cap_token|capToken|cap-token|webhook_key|webhookKey|webhook-key|auth|"
    r"session_token|sessionToken|csrf_token|csrfToken|id_token|idToken|"
    r"client_secret|clientSecret|private_key|privateKey|credential|credentials|"
    r"authorization|cookie|cookies|set_cookie|set-cookie|setCookie|bearer)"
    r"=(?!\[REDACTED\](?:[\s&;,'\"]|$))([^\s&;,'\"]+)"
)
_RAW_SECRET_TOKEN_RE = re.compile(
    r"(?:"
    r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}\b"
    r"|(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{12,}\b"
    r"|(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{8,}\b"
    r"|(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{8,}\b"
    r"|(?<![A-Za-z0-9])sk-(?:proj-|live-|test-|svcacct-)?[A-Za-z0-9_-]{8,}\b"
    r"|(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{16,}\b"
    r"|(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r")"
)


_EXTRA_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "secret_value",
        "vault_value",
        "passphrase",
        "private_pem",
    }
)
_EXTRA_SENSITIVE_SUFFIXES: tuple[str, ...] = (
    "_secret_value",
    "_vault_value",
    "_passphrase",
    "_private_pem",
)


def _camel_to_snake(key: str) -> str:
    step1 = _CAMEL_BOUNDARY_2.sub(r"\1_\2", key.strip())
    step2 = _CAMEL_BOUNDARY_1.sub(r"\1_\2", step1)
    return step2.lower().replace("-", "_")


def is_sensitive_key_strict(key: str) -> bool:
    """Return True if key (snake_case, kebab-case, or camelCase) denotes secret material."""
    if is_sensitive_key(key):
        return True
    snake = _camel_to_snake(key)
    if is_sensitive_key(snake):
        return True
    return snake in _EXTRA_SENSITIVE_KEYS or snake.endswith(_EXTRA_SENSITIVE_SUFFIXES)


def redact_string_strict(value: str) -> str:
    """Scrub Bearer/Basic headers, URL userinfo, inline secret=value pairs, and raw tokens."""
    scrubbed = redact_string(value)
    scrubbed = _QUERY_SECRET_RE.sub(rf"\1={REDACTED_PLACEHOLDER}", scrubbed)
    return _RAW_SECRET_TOKEN_RE.sub(REDACTED_PLACEHOLDER, scrubbed)


def redact_payload_strict(value: Any) -> Any:
    """Recursively deep-copy and redact secrets including camelCase keys and evidence strings."""
    if isinstance(value, Mapping):
        redacted: dict[Any, Any] = {}
        for k, v in value.items():
            sensitive_key = is_sensitive_key_strict(str(k))
            if isinstance(k, str):
                safe_key: Any = redact_string_strict(k)
            elif isinstance(k, (tuple, frozenset)):
                safe_key = redact_payload_strict(k)
            elif (
                not isinstance(k, (int, float, bool, type(None)))
                and contains_unredacted_secret_strict(str(k))
            ):
                safe_key = redact_string_strict(str(k))
            else:
                safe_key = k

            if sensitive_key:
                scrubbed_value: Any = None if v is None else REDACTED_PLACEHOLDER
            else:
                scrubbed_value = redact_payload_strict(v)
            redacted[safe_key] = scrubbed_value
        return redacted
    if isinstance(value, list):
        return [redact_payload_strict(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_payload_strict(item) for item in value)
    if isinstance(value, set):
        return {redact_payload_strict(item) for item in value}
    if isinstance(value, frozenset):
        return frozenset(redact_payload_strict(item) for item in value)
    if isinstance(value, str):
        return redact_string_strict(value)
    return value


def _is_non_empty_unredacted(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value != "" and value != REDACTED_PLACEHOLDER
    if isinstance(value, (list, tuple, dict, set, frozenset)):
        return len(value) > 0
    return True


def contains_unredacted_secret_strict(value: Any) -> bool:
    """Detect unredacted secrets including camelCase keys and inline secret=value strings."""
    if isinstance(value, Mapping):
        for k, v in value.items():
            if isinstance(k, (str, tuple, frozenset)) and contains_unredacted_secret_strict(k):
                return True
            if (
                not isinstance(k, (str, int, float, bool, type(None), tuple, frozenset))
                and contains_unredacted_secret_strict(str(k))
            ):
                return True
            if is_sensitive_key_strict(str(k)) and _is_non_empty_unredacted(v):
                return True
            if contains_unredacted_secret_strict(v):
                return True
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_unredacted_secret_strict(item) for item in value)
    if isinstance(value, str):
        normalized = _REDACTED_AUTH_PUNCT_RE.sub(r"\1 [REDACTED] ", value)
        if contains_unredacted_secret(normalized):
            return True
        if _QUERY_SECRET_RE.search(normalized):
            return True
        return bool(_RAW_SECRET_TOKEN_RE.search(normalized))
    return bool(contains_unredacted_secret(value))
