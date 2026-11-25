"""Local OpenAI/llama.cpp HTTP ModelClient with origin allowlist and E09 token fallback."""

from __future__ import annotations

import asyncio
import ipaddress
import json
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import Field, ValidationError, field_validator, model_validator

from src.adapters.sessions import OriginNotAllowedError
from src.contracts.common import FrozenModel, HttpOrigin, NonEmptyStr, validate_http_origin
from src.contracts.enums import BackendMode
from src.contracts.models import ToolSpec
from src.model.emulator import EmulatedModelClient
from src.model.protocol import (
    BudgetRemaining,
    ModelClient,
    ModelDecision,
    ModelPermissionError,
    ModelProtocolError,
    ModelToolCall,
    ModelUsage,
    PromptContext,
    TransientModelError,
)

_TRANSIENT_HTTP_STATUSES: frozenset[int] = frozenset({408, 429, 500, 502, 503, 504})
_VALID_DECISION_TYPES: frozenset[str] = frozenset(
    {"tool_call", "delegate", "request_input", "final"}
)


def validate_local_model_origin(
    origin: str,
    *,
    allowed_origins: Sequence[str] = (),
    allow_private_lan: bool = False,
) -> str:
    """Validate that a model endpoint origin is local-only (loopback or allowlisted LAN)."""
    normalized = validate_http_origin(origin)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    if not host:
        raise OriginNotAllowedError(f"Invalid local model origin host: {origin!r}")

    is_ip = False
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        ip = None

    if is_ip and ip is not None:
        if not (
            ip.is_loopback
            or (
                allow_private_lan
                and not ip.is_unspecified
                and not ip.is_multicast
                and (ip.is_private or ip.is_link_local)
            )
        ):
            raise OriginNotAllowedError(
                f"Model origin {normalized!r} is outside allowed local/loopback addresses."
            )
    elif not (
        host in {"localhost", "localhost.localdomain"}
        or (
            allow_private_lan
            and ("." not in host or host.endswith((".local", ".lan", ".internal")))
        )
    ):
        raise OriginNotAllowedError(
            f"Model origin {normalized!r} is an external/public host and is blocked."
        )

    if allowed_origins:
        allowed_set = {validate_http_origin(o) for o in allowed_origins}
        if normalized not in allowed_set:
            raise OriginNotAllowedError(
                f"Model origin {normalized!r} not in allowed_origins {sorted(allowed_set)}."
            )

    return normalized


class LocalModelConfig(FrozenModel):
    """Pinned local inference server configuration and model metadata."""

    origin: HttpOrigin
    endpoint_path: NonEmptyStr = "/v1/chat/completions"
    model_id: NonEmptyStr
    quantization: NonEmptyStr = "Q4_K_M"
    prompt_template: NonEmptyStr = "chatml-json-tools-v1"
    weights_sha256: str | None = None
    allowed_origins: tuple[HttpOrigin, ...] = ()
    allow_private_lan: bool = False
    timeout_s: float = Field(default=30.0, gt=0.0)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int = Field(default=1024, ge=1)
    max_transport_retries: int = Field(default=0, ge=0, le=2)
    retry_backoff_s: float = Field(default=0.1, ge=0.0)
    strict_model_id_check: bool = False
    api_key: str | None = Field(default=None, repr=False, exclude=True)

    @field_validator("endpoint_path")
    @classmethod
    def _validate_endpoint_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError(f"endpoint_path must start with '/', got {value!r}")
        return value

    @model_validator(mode="after")
    def _validate_local_origin(self) -> LocalModelConfig:
        validate_local_model_origin(
            self.origin,
            allowed_origins=self.allowed_origins,
            allow_private_lan=self.allow_private_lan,
        )
        return self


def _strip_json_fences(raw_text: str) -> str:
    stripped = raw_text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            inner = "\n".join(lines[1:-1]).strip()
            return inner
    return stripped


def _extract_non_neg_int(usage_obj: dict[str, Any], key: str) -> int | None:
    if key not in usage_obj or usage_obj[key] is None:
        return None
    val = usage_obj[key]
    if isinstance(val, bool) or not isinstance(val, int) or val < 0:
        raise ModelProtocolError(
            f"Invalid token count for usage.{key!r}: expected non-negative int, got {val!r}."
        )
    return int(val)


def _serialize_tools(tools: Sequence[ToolSpec]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for spec in tools:
        origins = ", ".join(spec.allowed_origins) if spec.allowed_origins else "none"
        serialized.append(
            {
                "type": "function",
                "function": {
                    "name": spec.tool_id,
                    "description": (
                        f"Effect={spec.effect_class.value}; Origins={origins}; "
                        f"Verifier={spec.verifier_name}"
                    ),
                    "parameters": spec.input_schema,
                },
            }
        )
    return serialized


class LocalHttpModelClient:
    """Async ModelClient calling a local OpenAI/llama.cpp /v1/chat/completions endpoint."""

    def __init__(self, config: LocalModelConfig) -> None:
        validate_local_model_origin(
            config.origin,
            allowed_origins=config.allowed_origins,
            allow_private_lan=config.allow_private_lan,
        )
        self._config = config
        self.call_history: list[PromptContext] = []
        self.last_response_metadata: dict[str, Any] = {}

    @property
    def config(self) -> LocalModelConfig:
        return self._config

    async def decide(
        self,
        prompt_ctx: PromptContext,
        tools: Sequence[ToolSpec],
        budget_remaining: BudgetRemaining,
    ) -> ModelDecision:
        """Send redacted PromptContext to local HTTP LLM server and parse ModelDecision."""
        normalized_origin = validate_local_model_origin(
            self._config.origin,
            allowed_origins=self._config.allowed_origins,
            allow_private_lan=self._config.allow_private_lan,
        )
        self.call_history.append(prompt_ctx)

        system_prompt = (
            f"Template={self._config.prompt_template}; "
            "Respond with either a tool call or a JSON object matching ModelDecision "
            "(decision_type in tool_call|delegate|request_input|final)."
        )
        user_payload = json.dumps(
            {
                "prompt_context": prompt_ctx.model_dump(mode="json"),
                "budget_remaining": budget_remaining.model_dump(mode="json"),
                "available_tool_ids": [t.tool_id for t in tools],
            },
            sort_keys=True,
        )

        req_body: dict[str, Any] = {
            "model": self._config.model_id,
            "temperature": self._config.temperature,
            "max_tokens": self._config.max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_payload},
            ],
            "response_format": {"type": "json_object"},
        }
        if tools:
            req_body["tools"] = _serialize_tools(tools)
            req_body["tool_choice"] = "auto"

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"

        url = f"{normalized_origin}{self._config.endpoint_path}"
        response = await self._post_with_retries(url, req_body, headers)

        try:
            payload = response.json()
        except (ValueError, TypeError) as exc:
            raise ModelProtocolError(f"Model response is not valid JSON: {exc}") from exc

        if not isinstance(payload, dict):
            raise ModelProtocolError("Model JSON response must be an object.")

        observed_model = payload.get("model")
        if self._config.strict_model_id_check and observed_model != self._config.model_id:
            raise ModelProtocolError(
                f"Model ID mismatch: expected {self._config.model_id!r}, got {observed_model!r}."
            )

        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ModelProtocolError("Model response missing non-empty 'choices' list.")
        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise ModelProtocolError("Model choices[0] must be an object.")
        message = first_choice.get("message")
        if not isinstance(message, dict):
            raise ModelProtocolError("Model choices[0].message must be an object.")

        raw_completion_text = self._extract_completion_text(message)
        usage = self._parse_usage(
            payload.get("usage"),
            prompt_text=user_payload,
            completion_text=raw_completion_text,
        )
        decision = self._parse_decision(message, tools=tools, usage=usage)

        self.last_response_metadata = {
            "model_id": self._config.model_id,
            "quantization": self._config.quantization,
            "prompt_template": self._config.prompt_template,
            "weights_sha256": self._config.weights_sha256,
            "observed_model": observed_model,
            "usage_mode": usage.usage_mode,
            "endpoint_origin": normalized_origin,
        }
        return decision

    async def _post_with_retries(
        self,
        url: str,
        body: dict[str, Any],
        headers: dict[str, str],
    ) -> httpx.Response:
        max_attempts = 1 + self._config.max_transport_retries
        last_exc: Exception | None = None

        async with httpx.AsyncClient(
            timeout=self._config.timeout_s,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            for attempt_idx in range(max_attempts):
                try:
                    resp = await client.post(url, json=body, headers=headers)
                except (httpx.TimeoutException, httpx.ConnectError, httpx.TransportError) as exc:
                    last_exc = exc
                    if attempt_idx + 1 < max_attempts:
                        if self._config.retry_backoff_s > 0:
                            await asyncio.sleep(self._config.retry_backoff_s)
                        continue
                    raise TransientModelError(f"Local model HTTP transport failed: {exc}") from exc

                if 300 <= resp.status_code < 400:
                    location = resp.headers.get("location", "")
                    raise OriginNotAllowedError(
                        f"Redirect blocked by local-only model policy "
                        f"(HTTP {resp.status_code} -> {location!r})."
                    )
                if resp.status_code in _TRANSIENT_HTTP_STATUSES:
                    if attempt_idx + 1 < max_attempts:
                        if self._config.retry_backoff_s > 0:
                            await asyncio.sleep(self._config.retry_backoff_s)
                        continue
                    raise TransientModelError(
                        f"Local model HTTP transient status {resp.status_code}."
                    )
                if resp.status_code != 200:
                    raise ModelProtocolError(
                        f"Local model HTTP error status {resp.status_code}."
                    )
                return resp

        raise TransientModelError(f"Local model HTTP transport failed: {last_exc}")

    @staticmethod
    def _extract_completion_text(message: dict[str, Any]) -> str:
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list) and tool_calls:
            return json.dumps(tool_calls[0], sort_keys=True)
        return ""

    @staticmethod
    def _parse_usage(
        raw_usage: Any,
        *,
        prompt_text: str,
        completion_text: str,
    ) -> ModelUsage:
        if raw_usage is None:
            return ModelUsage.from_raw(
                prompt_tokens=None,
                completion_tokens=None,
                total_tokens=None,
                prompt_text=prompt_text,
                completion_text=completion_text,
            )
        if not isinstance(raw_usage, dict):
            raise ModelProtocolError(
                f"Model response 'usage' must be an object, got {type(raw_usage).__name__}."
            )
        pt = _extract_non_neg_int(raw_usage, "prompt_tokens")
        ct = _extract_non_neg_int(raw_usage, "completion_tokens")
        tt = _extract_non_neg_int(raw_usage, "total_tokens")
        try:
            return ModelUsage.from_raw(
                prompt_tokens=pt,
                completion_tokens=ct,
                total_tokens=tt,
                prompt_text=prompt_text,
                completion_text=completion_text,
            )
        except ValidationError as exc:
            raise ModelProtocolError(f"Invalid model usage payload: {exc}") from exc

    @staticmethod
    def _parse_decision(
        message: dict[str, Any],
        *,
        tools: Sequence[ToolSpec],
        usage: ModelUsage,
    ) -> ModelDecision:
        tool_map = {t.tool_id: t for t in tools}

        tool_calls = message.get("tool_calls")
        if tool_calls is not None:
            if not isinstance(tool_calls, list):
                raise ModelProtocolError("message.tool_calls must be a list when present.")
            if tool_calls:
                tc = tool_calls[0]
                if not isinstance(tc, dict):
                    raise ModelProtocolError("message.tool_calls[0] must be an object.")
                fn = tc.get("function")
                if not isinstance(fn, dict):
                    raise ModelProtocolError("tool_calls[0].function must be an object.")
                tool_id = fn.get("name")
                if not isinstance(tool_id, str) or not tool_id.strip():
                    raise ModelProtocolError("tool_calls[0].function.name must be non-empty.")
                tool_id = tool_id.strip()
                if tool_id not in tool_map:
                    raise ModelPermissionError(
                        f"Permission denied: tool_id {tool_id!r} is not allowed "
                        "(outside allowed tool list)."
                    )
                raw_args = fn.get("arguments", "{}")
                if isinstance(raw_args, str):
                    try:
                        parsed_args = json.loads(raw_args) if raw_args.strip() else {}
                    except ValueError as exc:
                        raise ModelProtocolError(
                            f"Invalid JSON in tool_calls[0].function.arguments: {exc}"
                        ) from exc
                elif isinstance(raw_args, dict):
                    parsed_args = dict(raw_args)
                else:
                    raise ModelProtocolError("tool_calls[0].function.arguments must be JSON/dict.")
                if not isinstance(parsed_args, dict):
                    raise ModelProtocolError(
                        "tool_calls[0].function.arguments must decode to dict."
                    )

                explicit_origin: Any = parsed_args.pop("__target_origin__", None)
                if explicit_origin is None:
                    explicit_origin = parsed_args.get("target_origin")
                if explicit_origin is None:
                    explicit_origin = parsed_args.get("origin")
                if explicit_origin is None:
                    explicit_origin = tc.get("target_origin") or fn.get("target_origin")
                if explicit_origin is None:
                    for url_key in ("url", "target_url"):
                        candidate_url = parsed_args.get(url_key)
                        if isinstance(candidate_url, str) and candidate_url.startswith(
                            ("http://", "https://")
                        ):
                            parsed_url = urlparse(candidate_url)
                            if parsed_url.scheme and parsed_url.netloc:
                                explicit_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                break
                spec = tool_map.get(tool_id)
                resolved_origin: str | None = None
                if explicit_origin is not None:
                    try:
                        resolved_origin = validate_http_origin(str(explicit_origin))
                    except ValueError as exc:
                        raise ModelProtocolError(f"Invalid target_origin: {exc}") from exc
                elif spec is not None and spec.allowed_origins:
                    resolved_origin = spec.allowed_origins[0]

                rationale = message.get("content")
                try:
                    return ModelDecision(
                        decision_type="tool_call",
                        tool_call=ModelToolCall(
                            tool_id=tool_id,
                            args=parsed_args,
                            target_origin=resolved_origin,
                            completion_verifier=spec.verifier_name if spec is not None else None,
                            rationale=rationale if isinstance(rationale, str) else "",
                        ),
                        usage=usage,
                    )
                except ValidationError as exc:
                    raise ModelProtocolError(f"Invalid ModelDecision tool_call: {exc}") from exc

        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ModelProtocolError(
                "Model message must include non-empty JSON 'content' or 'tool_calls'."
            )
        cleaned = _strip_json_fences(content)
        try:
            parsed_obj = json.loads(cleaned)
        except ValueError as exc:
            raise ModelProtocolError(f"Model content is not valid JSON: {exc}") from exc
        if not isinstance(parsed_obj, dict):
            raise ModelProtocolError("Model JSON content must decode to an object.")

        decision_type = parsed_obj.get("decision_type")
        if not isinstance(decision_type, str) or decision_type not in _VALID_DECISION_TYPES:
            raise ModelProtocolError(f"Invalid or missing decision_type: {decision_type!r}.")

        if decision_type == "tool_call":
            raw_tc = parsed_obj.get("tool_call")
            if not isinstance(raw_tc, dict):
                raise ModelProtocolError("tool_call decision must include 'tool_call' object.")
            tc_tool_id = raw_tc.get("tool_id")
            if not isinstance(tc_tool_id, str) or not tc_tool_id.strip():
                raise ModelProtocolError("tool_call.tool_id must be a non-empty string.")
            tc_tool_id = tc_tool_id.strip()
            if tc_tool_id not in tool_map:
                raise ModelPermissionError(
                    f"Permission denied: tool_id {tc_tool_id!r} is not allowed "
                    "(outside allowed tool list)."
                )
            spec = tool_map.get(tc_tool_id)
            raw_tc_args = raw_tc.get("args")
            clean_tc_args = dict(raw_tc_args) if isinstance(raw_tc_args, dict) else None
            popped_origin: Any = None
            if clean_tc_args is not None and "__target_origin__" in clean_tc_args:
                popped_origin = clean_tc_args.pop("__target_origin__", None)
                raw_tc = {**raw_tc, "args": clean_tc_args}
                parsed_obj = {**parsed_obj, "tool_call": raw_tc}
            if raw_tc.get("target_origin") is None:
                inferred_origin: Any = popped_origin
                if inferred_origin is None and clean_tc_args is not None:
                    inferred_origin = clean_tc_args.get("target_origin")
                    if inferred_origin is None:
                        inferred_origin = clean_tc_args.get("origin")
                    if inferred_origin is None:
                        for url_key in ("url", "target_url"):
                            candidate_url = clean_tc_args.get(url_key)
                            if isinstance(candidate_url, str) and candidate_url.startswith(
                                ("http://", "https://")
                            ):
                                parsed_url = urlparse(candidate_url)
                                if parsed_url.scheme and parsed_url.netloc:
                                    inferred_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                    break
                if inferred_origin is not None:
                    try:
                        validated_origin = validate_http_origin(str(inferred_origin))
                    except ValueError as exc:
                        raise ModelProtocolError(f"Invalid target_origin: {exc}") from exc
                    raw_tc = {**raw_tc, "target_origin": validated_origin}
                    parsed_obj = {**parsed_obj, "tool_call": raw_tc}
                elif spec is not None and spec.allowed_origins:
                    raw_tc = {**raw_tc, "target_origin": spec.allowed_origins[0]}
                    parsed_obj = {**parsed_obj, "tool_call": raw_tc}
            if (
                raw_tc.get("completion_verifier") is None
                and spec is not None
            ):
                raw_tc = {**raw_tc, "completion_verifier": spec.verifier_name}
                parsed_obj = {**parsed_obj, "tool_call": raw_tc}

        if decision_type == "final" and parsed_obj.get("partial_info") == {}:
            parsed_obj = {**parsed_obj, "partial_info": None}

        try:
            return ModelDecision.model_validate({**parsed_obj, "usage": usage.model_dump()})
        except (ValidationError, ValueError) as exc:
            raise ModelProtocolError(f"Invalid structured ModelDecision: {exc}") from exc


def build_model_client(
    backend_mode: BackendMode,
    *,
    local_http_config: LocalModelConfig | None = None,
    emulator: ModelClient | None = None,
) -> ModelClient:
    """Resolve ModelClient by BackendMode; never silently fall back to emulation."""
    if backend_mode == BackendMode.EMULATED:
        return emulator if emulator is not None else EmulatedModelClient(mode="happy_path")
    if backend_mode == BackendMode.LOCAL_HTTP:
        if local_http_config is None:
            raise ModelProtocolError(
                "backend_mode='local_http' requires LocalModelConfig; "
                "silent fallback to EmulatedModelClient is forbidden."
            )
        return LocalHttpModelClient(local_http_config)
    raise ValueError(f"Unsupported backend_mode: {backend_mode!r}")
