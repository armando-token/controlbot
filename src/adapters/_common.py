"""Shared adapter helpers for credential lookup, error types, and fail-closed redaction."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from src.contracts.redaction import REDACTED_PLACEHOLDER, redact_secrets

_CAMEL_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "accesstoken",
        "refreshtoken",
        "authtoken",
        "sessiontoken",
        "csrftoken",
        "apikey",
        "secretkey",
        "privatekey",
        "clientsecret",
        "setcookie",
    }
)


class SourceUnavailableError(RuntimeError):
    """Raised when an industrial source returns 503 or is unreachable."""


class AdapterPermissionError(PermissionError):
    """Raised when an adapter operation violates read-only or tool/origin permissions."""


@runtime_checkable
class CredentialProvider(Protocol):
    """External credential lookup kept strictly outside LLM prompt/receipt context."""

    def get_credentials(
        self,
        user_id: str,
        profile_id: str,
        app_id: str,
    ) -> tuple[str, str] | None:
        """Return (username, password) for the given session identity, or None."""


class MappingCredentialProvider:
    """In-memory mapping-backed CredentialProvider for tests and local labs."""

    def __init__(self, mapping: Mapping[tuple[str, str, str], tuple[str, str]]) -> None:
        self._mapping = dict(mapping)

    def get_credentials(
        self,
        user_id: str,
        profile_id: str,
        app_id: str,
    ) -> tuple[str, str] | None:
        for key in (
            (user_id, profile_id, app_id),
            (user_id, "*", app_id),
            ("*", "*", app_id),
        ):
            if key in self._mapping:
                return self._mapping[key]
        return None


def scrub_for_receipt(value: Any) -> Any:
    """Scrub camelCase and snake_case secrets recursively before constructing ActionReceipts."""
    if isinstance(value, Mapping):
        cleaned: dict[Any, Any] = {}
        for k, v in value.items():
            key_norm = str(k).strip().lower().replace("_", "").replace("-", "")
            if key_norm in _CAMEL_SENSITIVE_KEYS:
                cleaned[k] = None if v is None else REDACTED_PLACEHOLDER
            else:
                cleaned[k] = scrub_for_receipt(v)
        return redact_secrets(cleaned)
    if isinstance(value, list):
        return [scrub_for_receipt(item) for item in value]
    if isinstance(value, tuple):
        return tuple(scrub_for_receipt(item) for item in value)
    return redact_secrets(value)
