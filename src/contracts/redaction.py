"""Fail-closed secret redaction utilities for logs and ActionReceipts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED_PLACEHOLDER = "[REDACTED]"

SENSITIVE_KEY_TOKENS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "secret_key",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "auth_token",
        "session_token",
        "csrf_token",
        "authorization",
        "cookie",
        "cookies",
        "set_cookie",
        "private_key",
        "client_secret",
        "credential",
        "credentials",
    }
)

_SENSITIVE_KEY_SUFFIXES: tuple[str, ...] = (
    "_password",
    "_passwd",
    "_secret",
    "_secret_key",
    "_api_key",
    "_apikey",
    "_token",
    "_access_token",
    "_refresh_token",
    "_auth_token",
    "_cookie",
    "_cookies",
    "_set_cookie",
    "_private_key",
    "_client_secret",
    "_credential",
    "_credentials",
)

_SAFE_KEY_TOKENS: frozenset[str] = frozenset(
    {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "max_total_tokens",
        "tokens_reserved",
        "prompt_tokens_used",
        "completion_tokens_used",
        "session_id",
        "task_id",
        "run_id",
        "step_id",
        "operation_key",
    }
)

_BEARER_RE = re.compile(r"(?i)\b(Bearer)\s+(?!\[REDACTED\](?:\s|$))(\S+)")
_BASIC_RE = re.compile(r"(?i)\b(Basic)\s+(?!\[REDACTED\](?:\s|$))(\S+)")
_URL_USERINFO_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]*://)(?:([^/\s?#:@]+)(?::([^/\s?#@]*))?|:([^/\s?#@]+))@"
)


def is_sensitive_key(key: str) -> bool:
    """Return True if a mapping key represents secret or credential material."""
    normalized = key.strip().lower().replace("-", "_")
    if normalized in _SAFE_KEY_TOKENS:
        return False
    if normalized in SENSITIVE_KEY_TOKENS:
        return True
    return normalized.endswith(_SENSITIVE_KEY_SUFFIXES)


def _is_userinfo_redacted(match: re.Match[str]) -> bool:
    user = match.group(2)
    pwd = match.group(3)
    colon_only_pwd = match.group(4)
    if colon_only_pwd is not None:
        return colon_only_pwd == REDACTED_PLACEHOLDER
    return user == REDACTED_PLACEHOLDER and (pwd is None or pwd == REDACTED_PLACEHOLDER)


def redact_string(value: str) -> str:
    """Scrub Bearer/Basic auth headers and embedded URL userinfo credentials."""
    scrubbed = _BEARER_RE.sub(rf"\1 {REDACTED_PLACEHOLDER}", value)
    scrubbed = _BASIC_RE.sub(rf"\1 {REDACTED_PLACEHOLDER}", scrubbed)

    def _mask_userinfo(match: re.Match[str]) -> str:
        if _is_userinfo_redacted(match):
            return match.group(0)
        scheme_prefix = match.group(1)
        has_colon_password = match.group(3) is not None or match.group(4) is not None
        if has_colon_password:
            return f"{scheme_prefix}{REDACTED_PLACEHOLDER}:{REDACTED_PLACEHOLDER}@"
        return f"{scheme_prefix}{REDACTED_PLACEHOLDER}@"

    return _URL_USERINFO_RE.sub(_mask_userinfo, scrubbed)


def redact_secrets(value: Any) -> Any:
    """Recursively deep-copy and redact secrets from dicts, lists, tuples, sets, and strings."""
    if isinstance(value, Mapping):
        redacted: dict[Any, Any] = {}
        for k, v in value.items():
            if is_sensitive_key(str(k)):
                redacted[k] = None if v is None else REDACTED_PLACEHOLDER
            else:
                redacted[k] = redact_secrets(v)
        return redacted
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    if isinstance(value, set):
        return {redact_secrets(item) for item in value}
    if isinstance(value, frozenset):
        return frozenset(redact_secrets(item) for item in value)
    if isinstance(value, str):
        return redact_string(value)
    return value


def _is_non_empty_unredacted(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value != "" and value != REDACTED_PLACEHOLDER
    if isinstance(value, (list, tuple, dict, set, frozenset)):
        return len(value) > 0
    return True


def contains_unredacted_secret(value: Any) -> bool:
    """Detect whether an object still contains unredacted secret keys or auth strings."""
    if isinstance(value, Mapping):
        for k, v in value.items():
            if is_sensitive_key(str(k)) and _is_non_empty_unredacted(v):
                return True
            if contains_unredacted_secret(v):
                return True
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_unredacted_secret(item) for item in value)
    if isinstance(value, str):
        if _BEARER_RE.search(value) or _BASIC_RE.search(value):
            return True
        return any(not _is_userinfo_redacted(match) for match in _URL_USERINFO_RE.finditer(value))
    return False
