"""Shared contract primitives, validators, and exception types."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import urlparse

from pydantic import AfterValidator, BaseModel, ConfigDict


class ContractError(ValueError):
    """Base error for domain contract violations."""


class InvalidStateTransitionError(ContractError):
    """Raised when attempting an illegal task state transition."""


class PlanValidationError(ContractError):
    """Raised when an execution plan violates task scope, budget, or tool contracts."""


def utc_now() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(UTC)


def ensure_utc(dt: datetime) -> datetime:
    """Validate that a datetime is timezone-aware and normalize it to UTC."""
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("Datetime must be timezone-aware (UTC).")
    return dt.astimezone(UTC)


def _validate_non_empty_str(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError("String value must not be empty or whitespace-only.")
    return stripped


def validate_http_origin(origin: str) -> str:
    """Validate and normalize an HTTP/HTTPS origin (scheme://host[:port])."""
    raw = origin.strip()
    if "?" in raw or "#" in raw:
        raise ValueError(f"Origin must not include path, query, or fragment: {origin!r}")
    cleaned = raw.rstrip("/")
    parsed = urlparse(cleaned)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid HTTP origin: {origin!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"Origin must not embed credentials: {origin!r}")
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise ValueError(f"Origin must not include path, query, or fragment: {origin!r}")
    if parsed.netloc.endswith(":"):
        raise ValueError(f"Invalid port in HTTP origin: {origin!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Invalid HTTP origin host: {origin!r}")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in HTTP origin: {origin!r}") from exc

    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Invalid port in HTTP origin: {origin!r}")

    normalized_host = hostname.lower()
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"

    if port is not None:
        return f"{scheme}://{normalized_host}:{port}"
    return f"{scheme}://{normalized_host}"


NonEmptyStr = Annotated[str, AfterValidator(_validate_non_empty_str)]
UtcDatetime = Annotated[datetime, AfterValidator(ensure_utc)]
HttpOrigin = Annotated[str, AfterValidator(validate_http_origin)]


class FrozenModel(BaseModel):
    """Base immutable domain model rejecting unknown fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")
