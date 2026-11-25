"""EffectSim HTTP adapter with origin checks, idempotent apply, and crash reconciliation."""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from typing import Any

import httpx

from src.adapters._common import AdapterPermissionError, scrub_for_receipt
from src.adapters.sessions import OriginNotAllowedError
from src.contracts.common import validate_http_origin
from src.contracts.enums import EffectClass, ReceiptOutcome
from src.contracts.models import ActionReceipt, RetryPolicy, TaskSpec, ToolSpec


def get_effect_tool_specs(allowed_origins: Sequence[str] = ()) -> dict[str, ToolSpec]:
    """Return ToolSpec definitions for EffectSim side-effect and reconciliation tools."""
    origins = tuple(validate_http_origin(o) for o in allowed_origins)
    return {
        "effect.apply": ToolSpec(
            tool_id="effect.apply",
            version="1.0.0",
            input_schema={
                "type": "object",
                "required": ["operation_key", "asset_id", "action"],
                "properties": {
                    "operation_key": {"type": "string"},
                    "asset_id": {"type": "string"},
                    "action": {"type": "string"},
                    "params": {"type": "object"},
                },
            },
            output_schema={"type": "object"},
            permissions=("effect:write",),
            allowed_origins=origins,
            effect_class=EffectClass.EFFECT,
            timeout_s=15.0,
            verifier_name="verify_effect_applied",
            retry_policy=RetryPolicy(max_retries=1, retry_on_transient=True, backoff_seconds=0.5),
        ),
        "effect.inspect_state": ToolSpec(
            tool_id="effect.inspect_state",
            version="1.0.0",
            input_schema={
                "type": "object",
                "properties": {"operation_key": {"type": "string"}},
            },
            output_schema={"type": "object"},
            permissions=("effect:read",),
            allowed_origins=origins,
            effect_class=EffectClass.READ,
            timeout_s=15.0,
            verifier_name="verify_effect_state",
            retry_policy=RetryPolicy(max_retries=1, retry_on_transient=True, backoff_seconds=0.5),
        ),
    }


class EffectSimAdapter:
    """Adapter for EffectSim idempotent apply and crash-recovery reconciliation (A08)."""

    def __init__(self, *, timeout_s: float = 10.0) -> None:
        self._timeout_s = timeout_s

    def _validate_origin(self, task: TaskSpec, origin: str) -> str:
        normalized = validate_http_origin(origin)
        if task.scope.allowed_origins and normalized not in task.scope.allowed_origins:
            raise OriginNotAllowedError(
                f"Origin {normalized!r} not allowed by task.scope.allowed_origins."
            )
        return normalized

    async def inspect_state(
        self,
        *,
        task: TaskSpec,
        origin: str,
        operation_key: str | None = None,
    ) -> dict[str, Any]:
        """Inspect EffectSim state endpoint before or after applying an effect."""
        base = self._validate_origin(task, origin)
        params = {"idempotency_key": operation_key} if operation_key is not None else {}
        async with httpx.AsyncClient(timeout=self._timeout_s) as client:
            resp = await client.get(f"{base}/api/effects/state", params=params)
            resp.raise_for_status()
            data = resp.json()
            assert isinstance(data, dict)
            return data

    async def apply_effect(
        self,
        *,
        task: TaskSpec,
        origin: str,
        run_id: str,
        step_id: str,
        attempt: int,
        operation_key: str,
        asset_id: str,
        action: str,
        params: dict[str, Any] | None = None,
        fail_after_apply: bool | str = False,
    ) -> tuple[dict[str, Any] | None, ActionReceipt]:
        """Apply an idempotent side effect with pre/post state observation and redaction."""
        started = time.perf_counter()
        if task.scope.read_only:
            raise AdapterPermissionError("EffectSim apply_effect denied when task.scope.read_only.")
        if task.scope.allowed_tools and "effect.apply" not in task.scope.allowed_tools:
            raise AdapterPermissionError("Tool 'effect.apply' not in task.scope.allowed_tools.")

        base = self._validate_origin(task, origin)
        clean_params = dict(params or {})
        redacted_args = scrub_for_receipt(
            {
                "origin": base,
                "operation_key": operation_key,
                "asset_id": asset_id,
                "action": action,
                "params": clean_params,
                "fail_after_apply": fail_after_apply,
            }
        )

        observed_before: dict[str, Any] | None = None
        async with httpx.AsyncClient(timeout=self._timeout_s) as client:
            try:
                before_resp = await client.get(
                    f"{base}/api/effects/state",
                    params={"idempotency_key": operation_key},
                )
                if before_resp.status_code == 200:
                    observed_before = scrub_for_receipt(before_resp.json())

                resp = await client.post(
                    f"{base}/api/effects/apply",
                    json={
                        "idempotency_key": operation_key,
                        "asset_id": asset_id,
                        "action": action,
                        "params": clean_params,
                        "fail_after_apply": fail_after_apply,
                    },
                )
            except httpx.HTTPError as exc:
                duration_ms = (time.perf_counter() - started) * 1000.0
                receipt = ActionReceipt(
                    receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                    task_id=task.task_id,
                    run_id=run_id,
                    step_id=step_id,
                    attempt=attempt,
                    tool_id="effect.apply",
                    redacted_args=redacted_args,
                    operation_key=operation_key,
                    observed_before=observed_before,
                    observed_after=None,
                    duration_ms=duration_ms,
                    outcome=ReceiptOutcome.UNKNOWN_NEEDS_RECONCILIATION,
                    error_detail=scrub_for_receipt(str(exc)),
                )
                return None, receipt

            duration_ms = (time.perf_counter() - started) * 1000.0
            if resp.status_code >= 500:
                receipt = ActionReceipt(
                    receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                    task_id=task.task_id,
                    run_id=run_id,
                    step_id=step_id,
                    attempt=attempt,
                    tool_id="effect.apply",
                    redacted_args=redacted_args,
                    operation_key=operation_key,
                    observed_before=observed_before,
                    observed_after=None,
                    duration_ms=duration_ms,
                    outcome=ReceiptOutcome.UNKNOWN_NEEDS_RECONCILIATION,
                    error_detail=scrub_for_receipt(
                        f"HTTP {resp.status_code}: {resp.text}"
                    ),
                )
                return None, receipt

            if resp.status_code == 409:
                receipt = ActionReceipt(
                    receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                    task_id=task.task_id,
                    run_id=run_id,
                    step_id=step_id,
                    attempt=attempt,
                    tool_id="effect.apply",
                    redacted_args=redacted_args,
                    operation_key=operation_key,
                    observed_before=observed_before,
                    observed_after=scrub_for_receipt(resp.json()),
                    duration_ms=duration_ms,
                    outcome=ReceiptOutcome.FAILED_SEMANTIC,
                    error_detail=scrub_for_receipt(f"HTTP 409: {resp.text}"),
                )
                return None, receipt

            resp.raise_for_status()
            payload = resp.json()
            assert isinstance(payload, dict)

            after_resp = await client.get(
                f"{base}/api/effects/state",
                params={"idempotency_key": operation_key},
            )
            observed_after = (
                scrub_for_receipt(after_resp.json())
                if after_resp.status_code == 200
                else scrub_for_receipt(payload)
            )
            receipt = ActionReceipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                task_id=task.task_id,
                run_id=run_id,
                step_id=step_id,
                attempt=attempt,
                tool_id="effect.apply",
                redacted_args=redacted_args,
                operation_key=operation_key,
                observed_before=observed_before,
                observed_after=observed_after,
                duration_ms=duration_ms,
                evidence_refs=(f"effect:{payload.get('effect_id', operation_key)}",),
                outcome=ReceiptOutcome.SUCCEEDED,
            )
            return payload, receipt

    async def reconcile_effect(
        self,
        *,
        task: TaskSpec,
        origin: str,
        run_id: str,
        step_id: str,
        attempt: int,
        operation_key: str,
        asset_id: str,
        action: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[bool, dict[str, Any] | None, ActionReceipt]:
        """Reconcile an ambiguous effect by checking GET /api/effects/state before any replay."""
        started = time.perf_counter()
        if task.scope.read_only:
            raise AdapterPermissionError("EffectSim reconcile_effect denied when read_only=True.")
        base = self._validate_origin(task, origin)
        clean_params = dict(params or {})
        state = await self.inspect_state(task=task, origin=base, operation_key=operation_key)
        existing = state.get("effect")
        if isinstance(existing, dict):
            matches = (
                existing.get("asset_id") == asset_id
                and existing.get("action") == action
                and existing.get("params", {}) == clean_params
            )
            duration_ms = (time.perf_counter() - started) * 1000.0
            outcome = (
                ReceiptOutcome.SUCCEEDED if matches else ReceiptOutcome.FAILED_SEMANTIC
            )
            receipt = ActionReceipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                task_id=task.task_id,
                run_id=run_id,
                step_id=step_id,
                attempt=attempt,
                tool_id="effect.inspect_state",
                redacted_args=scrub_for_receipt(
                    {
                        "operation_key": operation_key,
                        "asset_id": asset_id,
                        "action": action,
                        "params": clean_params,
                    }
                ),
                operation_key=operation_key,
                observed_before=scrub_for_receipt(state),
                observed_after=scrub_for_receipt({"reconciled": matches, "replayed": False}),
                duration_ms=duration_ms,
                evidence_refs=(f"effect:{existing.get('effect_id', operation_key)}",),
                outcome=outcome,
                error_detail=None if matches else "Existing effect payload differs from request.",
            )
            return matches, existing, receipt

        applied, apply_receipt = await self.apply_effect(
            task=task,
            origin=base,
            run_id=run_id,
            step_id=step_id,
            attempt=attempt,
            operation_key=operation_key,
            asset_id=asset_id,
            action=action,
            params=clean_params,
            fail_after_apply=False,
        )
        return applied is not None, applied, apply_receipt
