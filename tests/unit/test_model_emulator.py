"""N1 unit tests for ModelClient protocol and deterministic EmulatedModelClient (F09)."""

from __future__ import annotations

import pytest
from src.contracts.enums import EffectClass
from src.contracts.models import ToolSpec
from src.model import (
    BudgetRemaining,
    EmulatedModelClient,
    EmulatedTurn,
    ModelClient,
    ModelDecision,
    ModelToolCall,
    ModelUsage,
    PromptContext,
    TransientModelError,
)


def _prompt_ctx(
    *, turn_index: int = 0, human_input: dict[str, object] | None = None
) -> PromptContext:
    return PromptContext(
        task_id="task-m-1",
        run_id="run-m-1",
        depth=0,
        query="Read pump 34 pressure",
        facility_id="plant-a",
        allowed_areas=("area-1",),
        turn_index=turn_index,
        human_input=human_input,
    )


def _budget_rem() -> BudgetRemaining:
    return BudgetRemaining(
        active_children_remaining=2,
        depth_remaining=1,
        tool_calls_remaining=16,
        model_calls_remaining=8,
        wall_seconds_remaining=120.0,
        tokens_remaining=24000,
    )


def _sample_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            tool_id="scada_read",
            version="1.0.0",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            allowed_origins=("https://scada.local",),
            effect_class=EffectClass.READ,
            verifier_name="scada_v",
        ),
        ToolSpec(
            tool_id="maint_read",
            version="1.0.0",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            allowed_origins=("https://maint.local",),
            effect_class=EffectClass.READ,
            verifier_name="maint_v",
        ),
    ]


@pytest.mark.n1
async def test_all_builtin_emulation_modes() -> None:
    tools = _sample_tools()
    budget = _budget_rem()

    # 1. happy_path
    c_happy = EmulatedModelClient(mode="happy_path")
    d0 = await c_happy.decide(_prompt_ctx(turn_index=0), tools, budget)
    d1 = await c_happy.decide(_prompt_ctx(turn_index=1), tools, budget)
    assert d0.decision_type == "tool_call" and d0.tool_call is not None
    assert d0.tool_call.tool_id == "scada_read"
    assert d0.usage.usage_mode == "actual"
    assert d1.decision_type == "final"

    # 2. delegation
    c_del = EmulatedModelClient(mode="delegation")
    dd = await c_del.decide(_prompt_ctx(turn_index=0), tools, budget)
    assert dd.decision_type == "delegate"
    assert len(dd.delegations) == 2

    # 3. ambiguity
    c_amb = EmulatedModelClient(mode="ambiguity")
    da0 = await c_amb.decide(_prompt_ctx(turn_index=0), tools, budget)
    assert da0.decision_type == "request_input"
    da1 = await c_amb.decide(
        _prompt_ctx(turn_index=1, human_input={"area": "area-1"}), tools, budget
    )
    assert da1.decision_type == "tool_call"

    # 4. transient_error (raises once on call 0, succeeds on retry)
    c_err = EmulatedModelClient(mode="transient_error")
    with pytest.raises(TransientModelError):
        await c_err.decide(_prompt_ctx(turn_index=0), tools, budget)
    d_retry = await c_err.decide(_prompt_ctx(turn_index=0), tools, budget)
    assert d_retry.decision_type == "tool_call"

    # 5. loop_a06 (identical tool_call repeatedly)
    c_a06 = EmulatedModelClient(mode="loop_a06")
    calls_a06 = [
        await c_a06.decide(_prompt_ctx(turn_index=i), tools, budget) for i in range(3)
    ]
    assert all(c.tool_call == calls_a06[0].tool_call for c in calls_a06)

    # 6. cycle_a07 (alternates tool 0 and tool 1)
    c_a07 = EmulatedModelClient(mode="cycle_a07")
    c0 = await c_a07.decide(_prompt_ctx(turn_index=0), tools, budget)
    c1 = await c_a07.decide(_prompt_ctx(turn_index=1), tools, budget)
    c2 = await c_a07.decide(_prompt_ctx(turn_index=2), tools, budget)
    assert c0.tool_call is not None and c1.tool_call is not None and c2.tool_call is not None
    assert c0.tool_call.tool_id == "scada_read"
    assert c1.tool_call.tool_id == "maint_read"
    assert c2.tool_call.tool_id == "scada_read"

    # 7. omitted_tokens (usage_mode="estimated")
    c_omit = EmulatedModelClient(mode="omitted_tokens")
    d_omit = await c_omit.decide(_prompt_ctx(turn_index=0), tools, budget)
    assert d_omit.usage.usage_mode == "estimated"
    assert d_omit.usage.total_tokens >= d_omit.usage.prompt_tokens + d_omit.usage.completion_tokens


@pytest.mark.n1
async def test_protocol_conformance_determinism_and_error_modes() -> None:
    tools = _sample_tools()
    budget = _budget_rem()
    ctx = _prompt_ctx(turn_index=0)

    c1 = EmulatedModelClient(mode="happy_path", seed=42)
    c2 = EmulatedModelClient(mode="happy_path", seed=42)
    assert isinstance(c1, ModelClient)

    assert await c1.decide(ctx, tools, budget) == await c2.decide(ctx, tools, budget)
    assert c1.call_history == [ctx]

    # Invalid/unrecognized mode raises ValueError
    with pytest.raises(ValueError, match="Invalid emulator mode"):
        EmulatedModelClient(mode="bogus_mode")  # type: ignore[arg-type]

    # PromptContext rejects raw secrets fail-closed
    with pytest.raises(ValueError, match="unredacted secret"):
        PromptContext(
            task_id="t1",
            run_id="r1",
            depth=0,
            query="Use Bearer super-secret-jwt",
            facility_id="plant-a",
        )
    with pytest.raises(ValueError, match="unredacted secret"):
        PromptContext(
            task_id="t1",
            run_id="r1",
            depth=0,
            query="Check status",
            facility_id="plant-a",
            human_input={"accessToken": "raw-token"},
        )

    # ModelUsage.from_raw conservative fallback + bool rejection
    est = ModelUsage.from_raw(prompt_text="hello world", completion_text="ok")
    assert est.usage_mode == "estimated"
    assert est.total_tokens >= est.prompt_tokens + est.completion_tokens

    actual = ModelUsage.from_raw(prompt_tokens=15, completion_tokens=10)
    assert actual.usage_mode == "actual"
    assert actual.total_tokens == 25

    with pytest.raises(ValueError, match="Boolean"):
        ModelUsage(prompt_tokens=True, completion_tokens=1, total_tokens=2)

    # Scripted EmulatedTurn with omit_tokens=True overrides actual usage with estimated
    scripted = EmulatedModelClient(
        mode="custom",
        default_turns=[
            EmulatedTurn(
                decision=ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(tool_id="scada_read", args={}),
                    usage=ModelUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
                ),
                omit_tokens=True,
            )
        ],
    )
    scripted_dec = await scripted.decide(ctx, tools, budget)
    assert scripted_dec.usage.usage_mode == "estimated"
