"""Deterministic EvidenceAirlock enforcing industrial -> general sanitization (CB-11)."""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.parse import urlparse

from pydantic import Field

from src.contracts.common import FrozenModel, utc_now
from src.contracts.envelope import AirlockProvenance
from src.engine.redaction import contains_unredacted_secret_strict, redact_string_strict

AuditSink = Callable[[dict[str, Any]], int | str | None]


class AirlockBlockedError(RuntimeError):
    """Raised when EvidenceAirlock detects residual sensitive/plant data or audit failure."""


_ALLOWED_TOP_FIELDS: tuple[str, ...] = (
    "manufacturer",
    "model",
    "device_category",
    "sensor_type",
    "input_signal",
    "output_signal",
    "supply_voltage",
    "process_range",
    "mounting",
)

_ALLOWED_PUBLIC_ATTR_KEYS: frozenset[str] = frozenset(
    {
        "accuracy",
        "ip_rating",
        "material",
        "connection",
        "protocol",
        "enclosure",
        "certification",
        "temperature_range",
        "pressure_range",
        "power_supply",
        "response_time",
    }
)

_FORBIDDEN_KEY_HINTS: frozenset[str] = frozenset(
    {
        "asset_id",
        "tag",
        "tag_id",
        "line",
        "linea",
        "línea",
        "area",
        "facility",
        "facility_id",
        "plant",
        "planta",
        "ip",
        "host",
        "hostname",
        "endpoint",
        "url",
        "work_order",
        "wo",
        "cost",
        "costo",
        "precio_interno",
        "internal_price",
        "budget",
        "password",
        "secret",
        "token",
        "api_key",
        "credential",
    }
)

_INTERNAL_TAG_RE = re.compile(
    r"\b(?:TT|PT|FT|LT|VFD|TIC|PIC|FIC|LIC|ALM|CN|P)-[A-Z0-9_-]+\b",
    re.IGNORECASE,
)
_WORK_ORDER_RE = re.compile(r"\bWO-[A-Z0-9_-]+\b", re.IGNORECASE)
_INTERNAL_AREA_LINE_RE = re.compile(
    r"\b(?:"
    r"[aá]rea[\s-]+[a-z0-9_-]+"
    r"|l[ií]nea[\s-]+[a-z0-9_-]+"
    r"|line[\s-]+(?:[a-z_-]*\d+[a-z0-9_-]*|[a-z])\b"
    r"|planta[\s-]+[a-z0-9_-]+"
    r"|plant[\s-]+(?:[a-z_-]*\d+[a-z0-9_-]*|[a-z])\b"
    r"|facility[\s-]+[a-z0-9_-]+"
    r")\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_IPV6_RE = re.compile(
    r"(?<![A-Za-z0-9:])\[?(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:[0-9A-Fa-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?:%[A-Za-z0-9._-]+)?\]?(?::\d{1,5})?(?![A-Za-z0-9:])"
)
_INTERNAL_HOST_RE = re.compile(
    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|lan|internal|corp|intranet)\b(?::\d{1,5})?",
    re.IGNORECASE,
)
_INTERNAL_COST_RE = re.compile(
    r"\b(?:"
    r"(?:cost[eo]|precio|price|valor)\s*(?:[:=]|(?:\s+(?:interno|internal)(?:\s*[:=]|\s+de|\s+is|\s+)?))"
    r"|(?:(?:internal|interno)\s+(?:cost[eo]?|precio|price)|internal_cost|precio_interno)"
    r"(?:\s*[:=]|\s+de|\s+is|\s+)?"
    r")"
    r"\s*[$€£]?\s*\d+(?:[.,]\d+)?(?:\s*(?:USD|EUR|MXN|GBP))?",
    re.IGNORECASE,
)
_URL_HOST_RE = re.compile(
    r"https?://(\[[0-9A-Fa-f:%._-]+\](?::\d+)?|[A-Za-z0-9._-]+(?::\d+)?)(?:/[^\s]*)?",
    re.IGNORECASE,
)
_RAW_SECRET_TOKEN_RE = re.compile(
    r"(?:"
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{12,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{8,}\b"
    r"|\bsk-ant-[A-Za-z0-9_-]{12,}\b"
    r"|\bsk-(?:proj-|live-|test-|svcacct-)?[A-Za-z0-9_-]{16,}\b"
    r"|\bAIza[0-9A-Za-z_-]{20,}\b"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r")"
)
_INTERNAL_TLDS: tuple[str, ...] = (".local", ".lan", ".internal", ".corp", ".intranet")


def _is_internal_ip(candidate: str) -> bool:
    raw = candidate.strip()
    if raw.startswith("[") and "]" in raw:
        host = raw[1 : raw.index("]")]
    elif raw.count(":") == 1:
        host = raw.split(":", 1)[0]
    else:
        host = raw
    host = host.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _is_internal_url_host(url: str) -> bool:
    host = (urlparse(url).hostname or "").strip().lower()
    if not host:
        return False
    return (
        _is_internal_ip(host)
        or host in {"localhost", "localhost.localdomain"}
        or host.endswith(_INTERNAL_TLDS)
    )


def _scrub_value(
    raw: Any,
    *,
    blocked_patterns: Sequence[re.Pattern[str]],
) -> tuple[str | None, int]:
    if raw is None:
        return None, 0
    text = str(raw).strip()
    if not text:
        return None, 0

    stripped_count = 0
    cleaned = redact_string_strict(text)
    if cleaned != text:
        stripped_count += 1

    cleaned, raw_sec_count = _RAW_SECRET_TOKEN_RE.subn("[REDACTED]", cleaned)
    stripped_count += raw_sec_count

    for pat in (
        _INTERNAL_TAG_RE,
        _WORK_ORDER_RE,
        _INTERNAL_AREA_LINE_RE,
        _INTERNAL_HOST_RE,
        _INTERNAL_COST_RE,
    ):
        cleaned, count = pat.subn("[STRIPPED]", cleaned)
        stripped_count += count

    def _replace_internal_url(match: re.Match[str]) -> str:
        nonlocal stripped_count
        if _is_internal_url_host(match.group(0)):
            stripped_count += 1
            return "[STRIPPED_URL]"
        return match.group(0)

    cleaned = _URL_HOST_RE.sub(_replace_internal_url, cleaned)

    def _replace_ip(match: re.Match[str]) -> str:
        nonlocal stripped_count
        token = match.group(0)
        if _is_internal_ip(token):
            stripped_count += 1
            return "[STRIPPED_IP]"
        return token

    cleaned = _IPV4_RE.sub(_replace_ip, cleaned)
    cleaned = _IPV6_RE.sub(_replace_ip, cleaned)

    for bpat in blocked_patterns:
        cleaned, count = bpat.subn("[STRIPPED]", cleaned)
        stripped_count += count

    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
    return (cleaned if cleaned else None), stripped_count


def _has_forbidden_leak(
    spec: PublicEquipmentSpec,
    *,
    blocked_patterns: Sequence[re.Pattern[str]],
) -> str | None:
    dumped = spec.model_dump(mode="json")
    if contains_unredacted_secret_strict(dumped):
        return "unredacted_secret"
    flat_values: list[str] = []
    for k, v in dumped.items():
        if k == "public_attributes" and isinstance(v, dict):
            flat_values.extend(str(sub_v) for sub_v in v.values())
        elif isinstance(v, str):
            flat_values.append(v)

    for val in flat_values:
        if _RAW_SECRET_TOKEN_RE.search(val) is not None:
            return "unredacted_secret"
        for pat_name, pat in (
            ("internal_tag", _INTERNAL_TAG_RE),
            ("work_order", _WORK_ORDER_RE),
            ("internal_area_or_line", _INTERNAL_AREA_LINE_RE),
            ("internal_hostname", _INTERNAL_HOST_RE),
            ("internal_cost", _INTERNAL_COST_RE),
        ):
            if pat.search(val) is not None:
                return pat_name
        for m_url in _URL_HOST_RE.finditer(val):
            if _is_internal_url_host(m_url.group(0)):
                return "internal_url"
        for ip_match in _IPV4_RE.findall(val):
            if _is_internal_ip(ip_match):
                return "internal_ip"
        for ip6_match in _IPV6_RE.findall(val):
            if _is_internal_ip(ip6_match):
                return "internal_ip"
        for bpat in blocked_patterns:
            if bpat.search(val) is not None:
                return "blocked_facility_identifier"
    return None


class PublicEquipmentSpec(FrozenModel):
    """Allowlisted non-confidential technical specification safe for external web lane."""

    manufacturer: str | None = None
    model: str | None = None
    device_category: str | None = None
    sensor_type: str | None = None
    input_signal: str | None = None
    output_signal: str | None = None
    supply_voltage: str | None = None
    process_range: str | None = None
    mounting: str | None = None
    public_attributes: dict[str, str] = Field(default_factory=dict)


class AirlockProjectionResult(FrozenModel):
    """Audited result returned by EvidenceAirlock.project()."""

    spec: PublicEquipmentSpec
    stripped_fields: tuple[str, ...] = ()
    stripped_tokens_count: int = Field(default=0, ge=0)
    audit_id: str | None = None
    sanitized_summary: str


class EvidenceAirlock:
    """Deterministic schema projection boundary stripping internal plant data before web lane."""

    def __init__(self, *, audit_sink: AuditSink | None = None) -> None:
        self._audit_sink = audit_sink

    def project(
        self,
        raw_industrial: Mapping[str, Any],
        *,
        blocked_identifiers: Sequence[str] = (),
        task_id: str | None = None,
        run_id: str | None = None,
    ) -> AirlockProjectionResult:
        """Project ONLY allowlisted public equipment specs and scrub all internal plant details."""
        blocked_patterns = [
            re.compile(rf"(?<![a-z0-9]){re.escape(ident.strip())}(?![a-z0-9])", re.IGNORECASE)
            for ident in blocked_identifiers
            if ident and ident.strip()
        ]

        stripped_fields: list[str] = []
        total_tokens_stripped = 0
        for key in raw_industrial:
            k_low = str(key).strip().lower()
            if k_low in _FORBIDDEN_KEY_HINTS or (
                k_low not in _ALLOWED_TOP_FIELDS and k_low not in {"specs", "public_attributes"}
            ):
                stripped_fields.append(str(key))

        projected_kwargs: dict[str, Any] = {}
        for field_name in _ALLOWED_TOP_FIELDS:
            if field_name in raw_industrial:
                cleaned_val, count = _scrub_value(
                    raw_industrial[field_name],
                    blocked_patterns=blocked_patterns,
                )
                total_tokens_stripped += count
                projected_kwargs[field_name] = cleaned_val

        public_attrs: dict[str, str] = {}
        for nested_key in ("specs", "public_attributes"):
            nested = raw_industrial.get(nested_key)
            if isinstance(nested, Mapping):
                for attr_k, attr_v in nested.items():
                    norm_k = str(attr_k).strip().lower()
                    if norm_k not in _ALLOWED_PUBLIC_ATTR_KEYS:
                        stripped_fields.append(f"{nested_key}.{attr_k}")
                        continue
                    cleaned_attr, count = _scrub_value(attr_v, blocked_patterns=blocked_patterns)
                    total_tokens_stripped += count
                    if cleaned_attr is not None:
                        public_attrs[norm_k] = cleaned_attr

        spec = PublicEquipmentSpec(**projected_kwargs, public_attributes=public_attrs)

        # Fail-closed post-projection leak verification
        leak = _has_forbidden_leak(spec, blocked_patterns=blocked_patterns)
        if leak is not None:
            raise AirlockBlockedError(
                f"EvidenceAirlock fail-closed block: residual sensitive pattern detected ({leak})."
            )

        summary_parts = [
            f"{k}={v}"
            for k, v in spec.model_dump(mode="json").items()
            if v and k != "public_attributes"
        ]
        for attr_k, attr_v in spec.public_attributes.items():
            summary_parts.append(f"{attr_k}={attr_v}")
        sanitized_summary = (
            ", ".join(summary_parts) if summary_parts else "No public equipment specs projected."
        )

        audit_id: str | None = f"air_{uuid.uuid4().hex[:12]}"
        if self._audit_sink is not None:
            try:
                sink_ret = self._audit_sink(
                    {
                        "event_type": "airlock_projection",
                        "audit_id": audit_id,
                        "task_id": task_id,
                        "run_id": run_id,
                        "projected_spec": spec.model_dump(mode="json"),
                        "stripped_fields": stripped_fields,
                        "stripped_tokens_count": total_tokens_stripped,
                        "recorded_at": utc_now().isoformat(),
                    }
                )
                if sink_ret is not None:
                    audit_id = str(sink_ret)
            except Exception as exc:  # noqa: BLE001
                raise AirlockBlockedError(
                    f"EvidenceAirlock fail-closed block: audit recording failed ({exc})."
                ) from exc

        return AirlockProjectionResult(
            spec=spec,
            stripped_fields=tuple(sorted(set(stripped_fields))),
            stripped_tokens_count=total_tokens_stripped,
            audit_id=audit_id,
            sanitized_summary=sanitized_summary,
        )


def build_airlock_provenance(
    *,
    plant_facts: Sequence[str],
    web_facts: Sequence[str],
    airlock_audit_id: str | None,
    projected_spec: PublicEquipmentSpec,
) -> AirlockProvenance:
    """Build explicit Planta vs Web AirlockProvenance metadata for VerifiedResponseMeta."""
    projected_fields: dict[str, str] = {}
    for field_name in _ALLOWED_TOP_FIELDS:
        val = getattr(projected_spec, field_name)
        if val is not None:
            projected_fields[field_name] = str(val)
    for k, v in projected_spec.public_attributes.items():
        projected_fields[k] = v

    clean_plant = tuple(f.strip() for f in plant_facts if f and f.strip())
    clean_web = tuple(f.strip() for f in web_facts if f and f.strip())
    return AirlockProvenance(
        plant_sources=clean_plant,
        web_sources=clean_web,
        airlock_audit_id=airlock_audit_id,
        projected_fields=projected_fields,
    )


__all__ = [
    "AirlockBlockedError",
    "AirlockProjectionResult",
    "AuditSink",
    "EvidenceAirlock",
    "PublicEquipmentSpec",
    "build_airlock_provenance",
]
