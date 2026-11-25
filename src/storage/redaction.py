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
_QUERY_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|secret_key|secretKey|api_key|apikey|token|"
    r"access_token|accessToken|refresh_token|refreshToken|auth_token|authToken|"
    r"session_token|sessionToken|csrf_token|csrfToken|client_secret|clientSecret|"
    r"private_key|privateKey|credential|credentials)"
    r"=(?!\[REDACTED\](?:[\s&;,'\"]|$))([^\s&;,'\"]+)"
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
    return is_sensitive_key(snake)


def redact_string_strict(value: str) -> str:
    """Scrub Bearer/Basic headers, URL userinfo, and inline secret=value pairs."""
    scrubbed = redact_string(value)
    return _QUERY_SECRET_RE.sub(rf"\1={REDACTED_PLACEHOLDER}", scrubbed)


def redact_payload_strict(value: Any) -> Any:
    """Recursively deep-copy and redact secrets including camelCase keys and evidence strings."""
    if isinstance(value, Mapping):
        redacted: dict[Any, Any] = {}
        for k, v in value.items():
            if is_sensitive_key_strict(str(k)):
                redacted[k] = None if v is None else REDACTED_PLACEHOLDER
            else:
                redacted[k] = redact_payload_strict(v)
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
    if contains_unredacted_secret(value):
        return True
    if isinstance(value, Mapping):
        for k, v in value.items():
            if is_sensitive_key_strict(str(k)) and _is_non_empty_unredacted(v):
                return True
            if contains_unredacted_secret_strict(v):
                return True
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_unredacted_secret_strict(item) for item in value)
    if isinstance(value, str):
        return bool(_QUERY_SECRET_RE.search(value))
    return False
