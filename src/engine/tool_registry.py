"""Typed ToolRegistry with schema validation, outside-LLM policy gates, and MCP stub (F08)."""

from __future__ import annotations

import asyncio
import inspect
import math
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from pydantic import Field, ValidationError

from src.contracts.common import (
    FrozenModel,
    HttpOrigin,
    NonEmptyStr,
    UtcDatetime,
    ensure_utc,
    utc_now,
)
from src.contracts.enums import EffectClass, ReceiptOutcome
from src.contracts.models import ActionReceipt, Observation, TaskScope, ToolSpec
from src.engine.redaction import (
    contains_unredacted_secret_strict,
    redact_payload_strict,
    redact_string_strict,
)


class TransientToolError(RuntimeError):
    """Retryable transport/timeout/temporary failure from a tool handler."""


class SemanticToolError(RuntimeError):
    """Non-retryable validation or semantic failure from a tool handler."""


class PermissionToolError(RuntimeError):
    """Authorization or policy denial raised by a tool handler."""


class AuthToolError(RuntimeError):
    """Expired authentication error raised by a tool handler (triggers A10 pause)."""


class ToolExecutionContext(FrozenModel):
    """Execution metadata and policy scope passed to ToolRegistry.invoke()."""

    task_id: NonEmptyStr
    run_id: NonEmptyStr
    step_id: NonEmptyStr
    attempt: int = Field(ge=1)
    operation_key: NonEmptyStr
    scope: TaskScope
    granted_permissions: tuple[NonEmptyStr, ...] = ()
    target_origin: HttpOrigin | None = None
    deadline_at: UtcDatetime
    session_id: NonEmptyStr | None = None
    takeover_locked: bool = False
    idempotency_key: NonEmptyStr | None = None
    now: UtcDatetime | None = None


class ToolExecutionResult(FrozenModel):
    """Redacted result of a ToolRegistry.invoke() call."""

    outcome: ReceiptOutcome
    output: dict[str, Any] = Field(default_factory=dict)
    observed_before: dict[str, Any] | None = None
    observed_after: dict[str, Any] | None = None
    observations: tuple[Observation, ...] = ()
    evidence_refs: tuple[NonEmptyStr, ...] = ()
    verifier_passed: bool = False
    verifier_reason: str = ""
    duration_ms: float = Field(ge=0.0)
    error_detail: str | None = None
    receipt: ActionReceipt


class McpToolDescriptor(FrozenModel):
    """Local MCP tool descriptor mapped into ToolRegistry."""

    spec: ToolSpec
    server_name: NonEmptyStr
    remote_tool_name: NonEmptyStr


@runtime_checkable
class McpToolAdapter(Protocol):
    """Local MCP adapter stub interface (F08.4)."""

    def list_tools(self) -> Sequence[McpToolDescriptor]:
        """Return descriptors of tools exposed by this local MCP adapter."""
        ...

    async def call_tool(
        self,
        remote_tool_name: str,
        args: dict[str, Any],
        ctx: ToolExecutionContext,
    ) -> dict[str, Any]:
        """Execute a tool call through the MCP adapter."""
        ...


ToolHandler = Callable[
    [dict[str, Any], ToolExecutionContext],
    dict[str, Any] | Awaitable[dict[str, Any]],
]
VerifierFn = Callable[
    [
        dict[str, Any],
        dict[str, Any] | None,
        dict[str, Any],
        dict[str, Any] | None,
        ToolExecutionContext,
    ],
    tuple[bool, str],
]
ReconcilerFn = Callable[
    [str, str, ToolExecutionContext],
    tuple[bool, dict[str, Any] | None] | Awaitable[tuple[bool, dict[str, Any] | None]],
]


class _RegisteredTool:
    def __init__(
        self,
        *,
        spec: ToolSpec,
        handler: ToolHandler,
        verifier: VerifierFn | None,
        reconciler: ReconcilerFn | None,
        supports_idempotency: bool,
        is_poller: bool,
    ) -> None:
        self.spec = spec
        self.handler = handler
        self.verifier = verifier
        self.reconciler = reconciler
        self.supports_idempotency = supports_idempotency
        self.is_poller = is_poller


def _matches_json_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(
            value
        )
    if expected == "null":
        return value is None
    return True


def validate_json_schema(
    data: Any, schema: Mapping[str, Any], path: str = "$"
) -> list[str]:
    """Validate data against a structural JSON Schema subset using stdlib only."""
    if not schema:
        return []
    errors: list[str] = []

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed_types = (
            list(expected_type) if isinstance(expected_type, (list, tuple)) else [expected_type]
        )
        if not any(_matches_json_type(data, str(t)) for t in allowed_types):
            errors.append(
                f"{path}: expected type {expected_type!r}, got {type(data).__name__}"
            )
            return errors

    if "enum" in schema:
        enum_vals = schema["enum"]
        if not any(data == e and type(data) is type(e) for e in enum_vals):
            errors.append(f"{path}: value {data!r} not in enum {enum_vals!r}")

    if isinstance(data, str):
        if "minLength" in schema and len(data) < int(schema["minLength"]):
            errors.append(f"{path}: string length {len(data)} < minLength {schema['minLength']}")
        if "maxLength" in schema and len(data) > int(schema["maxLength"]):
            errors.append(f"{path}: string length {len(data)} > maxLength {schema['maxLength']}")

    if isinstance(data, (int, float)) and not isinstance(data, bool):
        if not math.isfinite(data):
            errors.append(f"{path}: non-finite number {data!r} is not valid JSON")
        else:
            if "minimum" in schema and data < schema["minimum"]:
                errors.append(f"{path}: value {data} < minimum {schema['minimum']}")
            if "maximum" in schema and data > schema["maximum"]:
                errors.append(f"{path}: value {data} > maximum {schema['maximum']}")

    if isinstance(data, list):
        if "minItems" in schema and len(data) < int(schema["minItems"]):
            errors.append(f"{path}: array length {len(data)} < minItems {schema['minItems']}")
        if "maxItems" in schema and len(data) > int(schema["maxItems"]):
            errors.append(f"{path}: array length {len(data)} > maxItems {schema['maxItems']}")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for idx, item in enumerate(data):
                errors.extend(validate_json_schema(item, item_schema, f"{path}[{idx}]"))

    if isinstance(data, dict):
        required_keys = schema.get("required") or []
        for req_key in required_keys:
            if req_key not in data:
                errors.append(f"{path}: missing required property {req_key!r}")

        properties = schema.get("properties")
        prop_map: Mapping[str, Any] = properties if isinstance(properties, Mapping) else {}
        additional = schema.get("additionalProperties", True)

        for k, v in data.items():
            if k in prop_map and isinstance(prop_map[k], Mapping):
                errors.extend(validate_json_schema(v, prop_map[k], f"{path}.{k}"))
            elif additional is False:
                errors.append(f"{path}: unexpected additional property {k!r}")
            elif isinstance(additional, Mapping):
                errors.extend(validate_json_schema(v, additional, f"{path}.{k}"))

    return errors


def _default_verifier(
    args: dict[str, Any],
    observed_before: dict[str, Any] | None,
    output: dict[str, Any],
    observed_after: dict[str, Any] | None,
    ctx: ToolExecutionContext,
) -> tuple[bool, str]:
    del args, observed_before, observed_after, ctx
    if output.get("error") is True:
        return False, str(output.get("error_detail") or "tool output indicated error=True")
    return True, "ok"


def _scrub_evidence_refs(raw_refs: Sequence[Any]) -> tuple[str, ...]:
    cleaned: list[str] = []
    for item in raw_refs:
        s = redact_string_strict(str(item)).strip()
        if s:
            cleaned.append(s)
    return tuple(cleaned)


class ToolRegistry:
    """Typed registry enforcing permissions, origin allowlists, schemas, timeouts, and redaction."""

    def __init__(
        self,
        *,
        strict_tool_allowlist: bool = False,
        takeover_checker: Callable[[str], bool] | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._strict_tool_allowlist = strict_tool_allowlist
        self._takeover_checker = takeover_checker
        self._clock = clock
        self._tools: dict[str, _RegisteredTool] = {}

    def register(
        self,
        spec: ToolSpec,
        handler: ToolHandler,
        verifier: VerifierFn | None = None,
        reconciler: ReconcilerFn | None = None,
        *,
        supports_idempotency: bool = False,
        is_poller: bool = False,
        replace: bool = False,
    ) -> None:
        """Register a typed tool with handler and optional post-action verifier/reconciler."""
        if not replace and spec.tool_id in self._tools:
            raise ValueError(f"Tool {spec.tool_id!r} is already registered.")
        self._tools[spec.tool_id] = _RegisteredTool(
            spec=spec,
            handler=handler,
            verifier=verifier,
            reconciler=reconciler,
            supports_idempotency=supports_idempotency,
            is_poller=is_poller,
        )

    def register_mcp_adapter(
        self,
        adapter: McpToolAdapter,
        *,
        verifier: VerifierFn | None = None,
        replace: bool = False,
    ) -> list[ToolSpec]:
        """Register tools exposed by a local McpToolAdapter through uniform policy gates."""
        registered: list[ToolSpec] = []
        for desc in adapter.list_tools():

            async def _mcp_handler(
                args: dict[str, Any],
                ctx: ToolExecutionContext,
                _remote: str = desc.remote_tool_name,
            ) -> dict[str, Any]:
                return await adapter.call_tool(_remote, args, ctx)

            self.register(
                desc.spec,
                _mcp_handler,
                verifier=verifier,
                replace=replace,
            )
            registered.append(desc.spec)
        return registered

    def get_spec(self, tool_id: str) -> ToolSpec | None:
        entry = self._tools.get(tool_id)
        return entry.spec if entry is not None else None

    def list_specs(self) -> dict[str, ToolSpec]:
        return {tid: entry.spec for tid, entry in self._tools.items()}

    def get_reconciler(self, tool_id: str) -> ReconcilerFn | None:
        entry = self._tools.get(tool_id)
        return entry.reconciler if entry is not None else None

    def supports_idempotency(self, tool_id: str) -> bool:
        entry = self._tools.get(tool_id)
        return entry.supports_idempotency if entry is not None else False

    def is_poller(self, tool_id: str) -> bool:
        entry = self._tools.get(tool_id)
        return entry.is_poller if entry is not None else False

    def _build_redacted_result(
        self,
        *,
        tool_id: str,
        ctx: ToolExecutionContext,
        raw_args: dict[str, Any],
        outcome: ReceiptOutcome,
        output: dict[str, Any] | None = None,
        observed_before: dict[str, Any] | None = None,
        observed_after: dict[str, Any] | None = None,
        observations: tuple[Observation, ...] = (),
        evidence_refs: Sequence[Any] = (),
        verifier_passed: bool = False,
        verifier_reason: str = "",
        duration_ms: float = 0.0,
        error_detail: str | None = None,
    ) -> ToolExecutionResult:
        redacted_args = redact_payload_strict(dict(raw_args))
        redacted_output = redact_payload_strict(dict(output or {}))
        redacted_before = (
            redact_payload_strict(dict(observed_before))
            if observed_before is not None
            else None
        )
        redacted_after = (
            redact_payload_strict(dict(observed_after))
            if observed_after is not None
            else None
        )
        scrubbed_refs = _scrub_evidence_refs(evidence_refs)
        scrubbed_err = redact_string_strict(error_detail) if error_detail is not None else None
        scrubbed_observations = tuple(
            obs.model_copy(update={"metadata": redact_payload_strict(dict(obs.metadata))})
            for obs in observations
        )

        now = ensure_utc(ctx.now) if ctx.now is not None else ensure_utc(self._clock())
        receipt = ActionReceipt(
            receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
            task_id=ctx.task_id,
            run_id=ctx.run_id,
            step_id=ctx.step_id,
            attempt=ctx.attempt,
            tool_id=tool_id,
            redacted_args=redacted_args,
            operation_key=ctx.operation_key,
            observed_before=redacted_before,
            observed_after=redacted_after,
            duration_ms=max(0.0, float(duration_ms)),
            evidence_refs=scrubbed_refs,
            outcome=outcome,
            error_detail=scrubbed_err,
            recorded_at=now,
        )
        if contains_unredacted_secret_strict(receipt.model_dump()):
            raise ValueError("Fail-closed redaction check failed on ActionReceipt.")

        return ToolExecutionResult(
            outcome=outcome,
            output=redacted_output,
            observed_before=redacted_before,
            observed_after=redacted_after,
            observations=scrubbed_observations,
            evidence_refs=scrubbed_refs,
            verifier_passed=verifier_passed,
            verifier_reason=redact_string_strict(verifier_reason),
            duration_ms=max(0.0, float(duration_ms)),
            error_detail=scrubbed_err,
            receipt=receipt,
        )

    def _check_policy(
        self, entry: _RegisteredTool, ctx: ToolExecutionContext
    ) -> str | None:
        spec = entry.spec

        if ctx.takeover_locked or (
            ctx.session_id is not None
            and self._takeover_checker is not None
            and self._takeover_checker(ctx.session_id)
        ):
            return f"Session {ctx.session_id!r} is locked under human takeover."

        if ctx.scope.allowed_tools:
            if spec.tool_id not in ctx.scope.allowed_tools:
                return f"Tool {spec.tool_id!r} is not in TaskScope.allowed_tools."
        elif self._strict_tool_allowlist:
            return (
                f"Strict tool allowlist enabled and TaskScope.allowed_tools is empty "
                f"(denying {spec.tool_id!r})."
            )

        if ctx.scope.read_only and spec.effect_class == EffectClass.EFFECT:
            return f"Effect tool {spec.tool_id!r} is disallowed when TaskScope.read_only=True."

        missing_perms = set(spec.permissions) - set(ctx.granted_permissions)
        if missing_perms:
            return (
                f"Missing required permission(s) for tool {spec.tool_id!r}: "
                f"{sorted(missing_perms)}"
            )

        if spec.allowed_origins:
            if ctx.target_origin is None:
                return f"Tool {spec.tool_id!r} requires an explicit target_origin."
            if not ctx.scope.allowed_origins:
                return (
                    f"Tool {spec.tool_id!r} requires allowed_origins, "
                    "but TaskScope.allowed_origins is empty."
                )
            if ctx.target_origin not in ctx.scope.allowed_origins:
                return (
                    f"target_origin {ctx.target_origin!r} is outside TaskScope.allowed_origins."
                )
            if ctx.target_origin not in spec.allowed_origins:
                return (
                    f"target_origin {ctx.target_origin!r} is outside "
                    f"ToolSpec({spec.tool_id!r}).allowed_origins."
                )
        elif ctx.target_origin is not None and ctx.target_origin not in ctx.scope.allowed_origins:
            return f"target_origin {ctx.target_origin!r} is outside TaskScope.allowed_origins."

        return None

    async def invoke(
        self, tool_id: str, args: dict[str, Any], ctx: ToolExecutionContext
    ) -> ToolExecutionResult:
        """Validate policy/schemas, execute with timeout, verify, and return redacted result."""
        entry = self._tools.get(tool_id)
        if entry is None:
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_SEMANTIC,
                error_detail=f"Unknown tool_id {tool_id!r}.",
                verifier_reason="unknown_tool",
            )

        spec = entry.spec
        policy_denial = self._check_policy(entry, ctx)
        if policy_denial is not None:
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_PERMISSION,
                error_detail=policy_denial,
                verifier_reason="permission_denied",
            )

        input_errors = validate_json_schema(args, spec.input_schema, path="args")
        if input_errors:
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_SEMANTIC,
                error_detail=f"Input schema validation failed: {'; '.join(input_errors)}",
                verifier_reason="invalid_input_schema",
            )

        current_time = (
            ensure_utc(ctx.now) if ctx.now is not None else ensure_utc(self._clock())
        )
        remaining_s = (ensure_utc(ctx.deadline_at) - current_time).total_seconds()
        if remaining_s <= 0:
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_TRANSIENT,
                duration_ms=0.0,
                error_detail=(
                    f"Task deadline already exceeded (remaining_s={remaining_s:.3f}s)."
                ),
                verifier_reason="deadline_exceeded",
            )
        effective_timeout = min(float(spec.timeout_s), remaining_s)

        started = time.perf_counter()
        try:
            if inspect.iscoroutinefunction(entry.handler):
                raw_result = await asyncio.wait_for(
                    entry.handler(dict(args), ctx),
                    timeout=effective_timeout,
                )
            else:
                call_res = await asyncio.wait_for(
                    asyncio.to_thread(entry.handler, dict(args), ctx),
                    timeout=effective_timeout,
                )
                if inspect.isawaitable(call_res):
                    raw_result = await asyncio.wait_for(call_res, timeout=effective_timeout)
                else:
                    raw_result = call_res
        except TimeoutError as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            outcome = (
                ReceiptOutcome.UNKNOWN_NEEDS_RECONCILIATION
                if spec.effect_class == EffectClass.EFFECT
                else ReceiptOutcome.FAILED_TRANSIENT
            )
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=outcome,
                duration_ms=elapsed_ms,
                error_detail=f"Tool execution timed out after {effective_timeout:.3f}s: {exc}",
                verifier_reason="timeout",
            )
        except AuthToolError as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_PERMISSION,
                duration_ms=elapsed_ms,
                error_detail=str(exc),
                verifier_reason="auth_expired",
            )
        except PermissionToolError as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_PERMISSION,
                duration_ms=elapsed_ms,
                error_detail=str(exc),
                verifier_reason="handler_permission_error",
            )
        except (TransientToolError, OSError) as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_TRANSIENT,
                duration_ms=elapsed_ms,
                error_detail=str(exc),
                verifier_reason="transient_error",
            )
        except (SemanticToolError, ValueError) as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_SEMANTIC,
                duration_ms=elapsed_ms,
                error_detail=str(exc),
                verifier_reason="semantic_error",
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_SEMANTIC,
                duration_ms=elapsed_ms,
                error_detail=f"Unexpected handler error: {exc}",
                verifier_reason="handler_exception",
            )

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if not isinstance(raw_result, dict):
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_SEMANTIC,
                duration_ms=elapsed_ms,
                error_detail=f"Tool handler must return dict, got {type(raw_result).__name__}.",
                verifier_reason="invalid_output_type",
            )

        schema_props = spec.output_schema.get("properties", {})
        if (
            "output" in raw_result
            and isinstance(raw_result["output"], dict)
            and "output" not in schema_props
        ):
            output_payload: dict[str, Any] = dict(raw_result["output"])
        else:
            output_payload = dict(raw_result)

        observed_before = raw_result.get("observed_before")
        observed_after = raw_result.get("observed_after")
        evidence_refs = raw_result.get("evidence_refs") or ()
        raw_obs = raw_result.get("observations") or ()
        try:
            if not isinstance(raw_obs, (list, tuple)):
                raise TypeError(
                    f"Tool 'observations' must be a list or tuple, got {type(raw_obs).__name__}."
                )
            parsed_obs: list[Observation] = []
            for obs in raw_obs:
                validated = obs if isinstance(obs, Observation) else Observation.model_validate(obs)
                parsed_obs.append(
                    validated.model_copy(
                        update={"metadata": redact_payload_strict(dict(validated.metadata))}
                    )
                )
            observations = tuple(parsed_obs)
        except (ValidationError, TypeError, ValueError) as exc:
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_SEMANTIC,
                output=output_payload,
                observed_before=observed_before if isinstance(observed_before, dict) else None,
                observed_after=observed_after if isinstance(observed_after, dict) else None,
                evidence_refs=evidence_refs if isinstance(evidence_refs, (list, tuple)) else (),
                duration_ms=elapsed_ms,
                error_detail=f"Invalid observations payload: {exc}",
                verifier_reason="invalid_observations",
            )

        output_errors = validate_json_schema(output_payload, spec.output_schema, path="output")
        if output_errors:
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_SEMANTIC,
                output=output_payload,
                observed_before=observed_before if isinstance(observed_before, dict) else None,
                observed_after=observed_after if isinstance(observed_after, dict) else None,
                evidence_refs=evidence_refs if isinstance(evidence_refs, (list, tuple)) else (),
                duration_ms=elapsed_ms,
                error_detail=f"Output schema validation failed: {'; '.join(output_errors)}",
                verifier_reason="invalid_output_schema",
            )

        verifier = entry.verifier or _default_verifier
        verified, verifier_msg = verifier(
            redact_payload_strict(dict(args)),
            observed_before if isinstance(observed_before, dict) else None,
            output_payload,
            observed_after if isinstance(observed_after, dict) else None,
            ctx,
        )
        if not verified:
            return self._build_redacted_result(
                tool_id=tool_id,
                ctx=ctx,
                raw_args=args,
                outcome=ReceiptOutcome.FAILED_SEMANTIC,
                output=output_payload,
                observed_before=observed_before if isinstance(observed_before, dict) else None,
                observed_after=observed_after if isinstance(observed_after, dict) else None,
                observations=observations,
                evidence_refs=evidence_refs if isinstance(evidence_refs, (list, tuple)) else (),
                verifier_passed=False,
                verifier_reason=verifier_msg,
                duration_ms=elapsed_ms,
                error_detail=f"Post-action verifier failed: {verifier_msg}",
            )

        return self._build_redacted_result(
            tool_id=tool_id,
            ctx=ctx,
            raw_args=args,
            outcome=ReceiptOutcome.SUCCEEDED,
            output=output_payload,
            observed_before=observed_before if isinstance(observed_before, dict) else None,
            observed_after=observed_after if isinstance(observed_after, dict) else None,
            observations=observations,
            evidence_refs=evidence_refs if isinstance(evidence_refs, (list, tuple)) else (),
            verifier_passed=True,
            verifier_reason=verifier_msg,
            duration_ms=elapsed_ms,
        )
