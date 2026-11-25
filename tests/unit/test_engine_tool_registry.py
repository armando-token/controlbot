"""N1 unit tests for ToolRegistry schemas, outside-LLM policy, timeouts, and MCP stub (F08)."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from src.contracts.budgets import BudgetConfig
from src.contracts.enums import DataQuality, EffectClass, ReceiptOutcome, TaskStatus
from src.contracts.models import Observation, TaskScope, TaskSpec, ToolSpec
from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.engine.coordinator import Coordinator
from src.engine.redaction import contains_unredacted_secret_strict
from src.engine.tool_registry import (
    McpToolDescriptor,
    ToolExecutionContext,
    ToolRegistry,
)
from src.model.emulator import EmulatedModelClient
from src.storage import StorageRepo


def _ctx(
    *,
    scope: TaskScope | None = None,
    granted_permissions: tuple[str, ...] = ("scada:read",),
    target_origin: str | None = "https://scada.local",
    takeover_locked: bool = False,
    session_id: str | None = None,
) -> ToolExecutionContext:
    now = datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)
    return ToolExecutionContext(
        task_id="task-tr-1",
        run_id="run-tr-1",
        step_id="step-tr-1",
        attempt=1,
        operation_key="op-tr-1",
        scope=scope
        or TaskScope(
            facility_id="plant-a",
            allowed_origins=("https://scada.local",),
            allowed_areas=("area-1",),
            allowed_tools=("read_sensor", "write_valve"),
            read_only=True,
        ),
        granted_permissions=granted_permissions,
        target_origin=target_origin,
        deadline_at=now + timedelta(seconds=30),
        session_id=session_id,
        takeover_locked=takeover_locked,
    )


@pytest.mark.n1
async def test_schema_validation_input_and_output() -> None:
    clock_now = datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)
    registry = ToolRegistry(clock=lambda: clock_now)
    called = 0

    spec = ToolSpec(
        tool_id="read_sensor",
        version="1.0.0",
        input_schema={
            "type": "object",
            "required": ["sensor_id", "count"],
            "additionalProperties": False,
            "properties": {
                "sensor_id": {"type": "string", "minLength": 2},
                "count": {"type": "integer", "minimum": 1},
            },
        },
        output_schema={
            "type": "object",
            "required": ["value"],
            "properties": {"value": {"type": "number"}},
        },
        permissions=("scada:read",),
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=5.0,
        verifier_name="sensor_verifier",
    )

    def handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        nonlocal called
        del ctx
        called += 1
        if args["sensor_id"] == "bad-output":
            return {"value": "not-a-number"}
        return {"value": 12.5}

    registry.register(spec, handler)

    # Bool rejected for integer + missing required field -> FAILED_SEMANTIC, handler NOT run
    res_bad_in = await registry.invoke(
        "read_sensor", {"sensor_id": "s1", "count": True}, _ctx()
    )
    assert res_bad_in.outcome == ReceiptOutcome.FAILED_SEMANTIC
    assert called == 0

    # Invalid output fails output schema -> FAILED_SEMANTIC
    res_bad_out = await registry.invoke(
        "read_sensor", {"sensor_id": "bad-output", "count": 1}, _ctx()
    )
    assert res_bad_out.outcome == ReceiptOutcome.FAILED_SEMANTIC
    assert called == 1

    # Valid call succeeds
    res_ok = await registry.invoke("read_sensor", {"sensor_id": "s1", "count": 2}, _ctx())
    assert res_ok.outcome == ReceiptOutcome.SUCCEEDED
    assert res_ok.verifier_passed is True
    assert res_ok.output["value"] == 12.5


@pytest.mark.n1
async def test_outside_llm_policy_and_origin_enforcement() -> None:
    clock_now = datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)
    registry = ToolRegistry(clock=lambda: clock_now)
    invocations = 0

    effect_spec = ToolSpec(
        tool_id="write_valve",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        permissions=("scada:write",),
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.EFFECT,
        timeout_s=5.0,
        verifier_name="valve_verifier",
    )
    read_spec = ToolSpec(
        tool_id="read_sensor",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        permissions=("scada:read",),
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=5.0,
        verifier_name="sensor_verifier",
    )

    def handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        nonlocal invocations
        del args, ctx
        invocations += 1
        return {"ok": True}

    registry.register(effect_spec, handler)
    registry.register(read_spec, handler)

    # 1. read_only=True blocks EFFECT
    res_ro = await registry.invoke(
        "write_valve",
        {},
        _ctx(granted_permissions=("scada:write",)),
    )
    assert res_ro.outcome == ReceiptOutcome.FAILED_PERMISSION

    # 2. Tool not in TaskScope.allowed_tools -> FAILED_PERMISSION
    res_allow = await registry.invoke(
        "read_sensor",
        {},
        _ctx(
            scope=TaskScope(
                facility_id="plant-a",
                allowed_origins=("https://scada.local",),
                allowed_tools=("other_tool",),
                read_only=True,
            )
        ),
    )
    assert res_allow.outcome == ReceiptOutcome.FAILED_PERMISSION

    # 3. Missing required permission -> FAILED_PERMISSION
    res_perm = await registry.invoke(
        "read_sensor", {}, _ctx(granted_permissions=())
    )
    assert res_perm.outcome == ReceiptOutcome.FAILED_PERMISSION

    # 4. Missing or disallowed target_origin -> FAILED_PERMISSION
    res_no_orig = await registry.invoke("read_sensor", {}, _ctx(target_origin=None))
    assert res_no_orig.outcome == ReceiptOutcome.FAILED_PERMISSION

    res_bad_orig = await registry.invoke(
        "read_sensor", {}, _ctx(target_origin="https://evil.local")
    )
    assert res_bad_orig.outcome == ReceiptOutcome.FAILED_PERMISSION

    # 5. Takeover lock blocks invocation
    res_lock = await registry.invoke(
        "read_sensor", {}, _ctx(session_id="sess-1", takeover_locked=True)
    )
    assert res_lock.outcome == ReceiptOutcome.FAILED_PERMISSION
    assert invocations == 0

    # 6. strict_tool_allowlist=True fails closed when allowed_tools == ()
    strict_reg = ToolRegistry(strict_tool_allowlist=True, clock=lambda: clock_now)
    strict_reg.register(read_spec, handler)
    res_strict = await strict_reg.invoke(
        "read_sensor",
        {},
        _ctx(
            scope=TaskScope(
                facility_id="plant-a",
                allowed_origins=("https://scada.local",),
                allowed_tools=(),
                read_only=True,
            )
        ),
    )
    assert res_strict.outcome == ReceiptOutcome.FAILED_PERMISSION
    assert invocations == 0


@pytest.mark.n1
async def test_timeout_and_post_action_verifier() -> None:
    clock_now = datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)
    registry = ToolRegistry(clock=lambda: clock_now)

    async def slow_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del args, ctx
        await asyncio.sleep(0.5)
        return {"ok": True}

    read_spec = ToolSpec(
        tool_id="read_slow",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        effect_class=EffectClass.READ,
        timeout_s=0.02,
        verifier_name="v",
    )
    effect_spec = ToolSpec(
        tool_id="effect_slow",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        effect_class=EffectClass.EFFECT,
        timeout_s=0.02,
        verifier_name="v",
    )
    verified_spec = ToolSpec(
        tool_id="read_verified",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        effect_class=EffectClass.READ,
        timeout_s=5.0,
        verifier_name="strict_v",
    )

    registry.register(read_spec, slow_handler)
    registry.register(effect_spec, slow_handler)
    registry.register(
        verified_spec,
        lambda a, c: {"value": -1},
        verifier=lambda a, b, out, after, c: (
            int(out["value"]) >= 0,
            "negative reading invalid",
        ),
    )

    rw_scope = TaskScope(
        facility_id="plant-a",
        allowed_tools=("read_slow", "effect_slow", "read_verified"),
        read_only=False,
    )
    res_read_to = await registry.invoke(
        "read_slow", {}, _ctx(scope=rw_scope, granted_permissions=(), target_origin=None)
    )
    assert res_read_to.outcome == ReceiptOutcome.FAILED_TRANSIENT

    res_eff_to = await registry.invoke(
        "effect_slow", {}, _ctx(scope=rw_scope, granted_permissions=(), target_origin=None)
    )
    assert res_eff_to.outcome == ReceiptOutcome.UNKNOWN_NEEDS_RECONCILIATION

    res_ver_fail = await registry.invoke(
        "read_verified", {}, _ctx(scope=rw_scope, granted_permissions=(), target_origin=None)
    )
    assert res_ver_fail.outcome == ReceiptOutcome.FAILED_SEMANTIC
    assert res_ver_fail.verifier_passed is False


@pytest.mark.n1
async def test_strict_redaction_camelcase_and_evidence_refs() -> None:
    clock_now = datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)
    registry = ToolRegistry(clock=lambda: clock_now)

    spec = ToolSpec(
        tool_id="read_sensor",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=5.0,
        verifier_name="v",
    )

    def handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del args, ctx
        return {
            "sessionToken": "raw-session-tok",
            "observed_before": {"clientSecret": "raw-client-secret"},
            "observed_after": {"header": "Bearer secret-jwt-123"},
            "evidence_refs": [
                "https://op:s3cr3t@scada.local/view?access_token=abc123",
            ],
            "ok": True,
        }

    registry.register(spec, handler)
    res = await registry.invoke(
        "read_sensor",
        {"accessToken": "arg-secret", "password": "pw"},
        _ctx(granted_permissions=()),
    )
    assert res.outcome == ReceiptOutcome.SUCCEEDED
    assert res.receipt.redacted_args["accessToken"] == REDACTED_PLACEHOLDER
    assert res.receipt.redacted_args["password"] == REDACTED_PLACEHOLDER
    assert res.receipt.observed_before == {"clientSecret": REDACTED_PLACEHOLDER}
    assert res.receipt.observed_after == {"header": f"Bearer {REDACTED_PLACEHOLDER}"}
    assert res.receipt.evidence_refs == (
        f"https://{REDACTED_PLACEHOLDER}:{REDACTED_PLACEHOLDER}@scada.local/view"
        f"?access_token={REDACTED_PLACEHOLDER}",
    )
    assert not contains_unredacted_secret_strict(res.receipt.model_dump())


@pytest.mark.n1
async def test_local_mcp_adapter_stub_enforces_policy_and_redaction() -> None:
    clock_now = datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)
    registry = ToolRegistry(clock=lambda: clock_now)

    class StubMcpAdapter:
        def list_tools(self) -> Sequence[McpToolDescriptor]:
            return (
                McpToolDescriptor(
                    server_name="local-scada-mcp",
                    remote_tool_name="get_alarm_count",
                    spec=ToolSpec(
                        tool_id="mcp.scada.alarms",
                        version="1.0.0",
                        input_schema={
                            "type": "object",
                            "required": ["area"],
                            "properties": {"area": {"type": "string"}},
                        },
                        output_schema={
                            "type": "object",
                            "required": ["count"],
                            "properties": {"count": {"type": "integer"}},
                        },
                        permissions=("mcp:read",),
                        allowed_origins=("https://scada.local",),
                        effect_class=EffectClass.READ,
                        timeout_s=5.0,
                        verifier_name="mcp_v",
                    ),
                ),
            )

        async def call_tool(
            self,
            remote_tool_name: str,
            args: dict[str, Any],
            ctx: ToolExecutionContext,
        ) -> dict[str, Any]:
            del ctx
            assert remote_tool_name == "get_alarm_count"
            return {"count": 3, "area": args["area"], "apiKey": "mcp-secret-key"}

    specs = registry.register_mcp_adapter(StubMcpAdapter())
    assert len(specs) == 1

    scope = TaskScope(
        facility_id="plant-a",
        allowed_origins=("https://scada.local",),
        allowed_tools=("mcp.scada.alarms",),
        read_only=True,
    )
    # Permission gate still blocks unauthorized caller
    denied = await registry.invoke(
        "mcp.scada.alarms", {"area": "area-1"}, _ctx(scope=scope, granted_permissions=())
    )
    assert denied.outcome == ReceiptOutcome.FAILED_PERMISSION

    # Authorized caller gets validated + redacted result
    ok = await registry.invoke(
        "mcp.scada.alarms",
        {"area": "area-1"},
        _ctx(scope=scope, granted_permissions=("mcp:read",)),
    )
    assert ok.outcome == ReceiptOutcome.SUCCEEDED
    assert ok.output["count"] == 3
    assert ok.output["apiKey"] == REDACTED_PLACEHOLDER


@pytest.mark.n1
async def test_coordinator_past_clock_aligns_with_default_tool_registry(tmp_path: Path) -> None:
    past_now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    clock = lambda: past_now  # noqa: E731
    db_path = tmp_path / "clock_align.db"
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    # ToolRegistry() constructed with default utc_now clock while Coordinator uses past_clock
    registry = ToolRegistry()
    invoked = 0

    async def async_read(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        nonlocal invoked
        del args, ctx
        await asyncio.sleep(0.05)
        invoked += 1
        return {"pressure": 4.1}

    spec = ToolSpec(
        tool_id="read_sensor",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=5.0,
        verifier_name="v",
    )
    registry.register(spec, async_read)

    coord = Coordinator(repo, EmulatedModelClient(mode="happy_path"), registry, clock=clock)
    task_spec = TaskSpec(
        task_id="t-clock-align",
        user_id="user-1",
        profile_id="prof-1",
        scope=TaskScope(
            facility_id="plant-a",
            allowed_origins=("https://scada.local",),
            allowed_tools=("read_sensor",),
            read_only=True,
        ),
        query="Read sensor with default ToolRegistry clock",
        budget=BudgetConfig(max_wall_seconds=30.0),
    )
    run = coord.submit_task(task_spec)
    res = await coord.run_until_settled(run.run_id)
    assert res.status == TaskStatus.SUCCEEDED
    assert invoked == 1

    # Standalone ToolRegistry(clock=...) still enforces its own clock when ctx.now is None
    standalone_reg = ToolRegistry(clock=lambda: past_now + timedelta(seconds=60))
    standalone_reg.register(spec, async_read)
    expired_ctx = _ctx(granted_permissions=()).model_copy(
        update={"deadline_at": past_now + timedelta(seconds=30)}
    )
    res_to = await standalone_reg.invoke("read_sensor", {}, expired_ctx)
    assert res_to.outcome == ReceiptOutcome.FAILED_TRANSIENT


@pytest.mark.n1
async def test_invalid_observations_returns_semantic_failure_and_metadata_scrubbed() -> None:
    clock_now = datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)
    registry = ToolRegistry(clock=lambda: clock_now)

    spec_bad = ToolSpec(
        tool_id="bad_obs_tool",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=5.0,
        verifier_name="v",
    )
    spec_secret_meta = spec_bad.model_copy(update={"tool_id": "secret_meta_obs_tool"})

    registry.register(
        spec_bad,
        lambda a, c: {"ok": True, "observations": [{"asset_id": "pump-34"}]},
    )
    registry.register(
        spec_secret_meta,
        lambda a, c: {
            "ok": True,
            "observations": [
                Observation(
                    source="scada",
                    session_id="sess-1",
                    asset_id="pump-34",
                    observed_label="pressure",
                    value=4.5,
                    unit="bar",
                    source_time=clock_now,
                    observed_at=clock_now,
                    quality=DataQuality.GOOD,
                    metadata={
                        "accessToken": "raw-token-999",
                        "note": "Bearer raw-jwt-token",
                    },
                )
            ],
        },
    )

    res_bad = await registry.invoke("bad_obs_tool", {}, _ctx(
        scope=TaskScope(
            facility_id="plant-a",
            allowed_origins=("https://scada.local",),
            allowed_tools=("bad_obs_tool", "secret_meta_obs_tool"),
            read_only=True,
        ),
        granted_permissions=(),
    ))
    assert res_bad.outcome == ReceiptOutcome.FAILED_SEMANTIC
    assert res_bad.verifier_reason == "invalid_observations"

    res_scrub = await registry.invoke("secret_meta_obs_tool", {}, _ctx(
        scope=TaskScope(
            facility_id="plant-a",
            allowed_origins=("https://scada.local",),
            allowed_tools=("bad_obs_tool", "secret_meta_obs_tool"),
            read_only=True,
        ),
        granted_permissions=(),
    ))
    assert res_scrub.outcome == ReceiptOutcome.SUCCEEDED
    assert len(res_scrub.observations) == 1
    meta = res_scrub.observations[0].metadata
    assert meta["accessToken"] == REDACTED_PLACEHOLDER
    assert meta["note"] == f"Bearer {REDACTED_PLACEHOLDER}"
    assert not contains_unredacted_secret_strict(res_scrub.observations[0].model_dump())
