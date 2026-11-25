"""N1 unit tests for root-shared budgets, reservations, A06 loops, and A07 cycles (F07)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from src.contracts.budgets import BudgetConfig
from src.contracts.enums import DataQuality, EffectClass, TaskStatus
from src.contracts.models import Observation, TaskScope, TaskSpec, ToolSpec
from src.engine.coordinator import Coordinator
from src.engine.loop_detector import LoopConfig, LoopDetector
from src.engine.tool_registry import ToolExecutionContext, ToolRegistry
from src.model.emulator import EmulatedModelClient, EmulatedTurn
from src.model.protocol import ModelDecision, ModelDelegationRequest, ModelToolCall, ModelUsage
from src.storage import BudgetExceededError, StorageRepo


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def _task(
    task_id: str,
    *,
    budget: BudgetConfig | None = None,
    allowed_tools: tuple[str, ...] = ("read_a", "read_b"),
) -> TaskSpec:
    return TaskSpec(
        task_id=task_id,
        user_id="user-1",
        profile_id="prof-1",
        scope=TaskScope(
            facility_id="plant-a",
            allowed_origins=("https://scada.local",),
            allowed_areas=("area-1",),
            allowed_tools=allowed_tools,
            read_only=True,
        ),
        query="Analyze pump 34 telemetry",
        budget=budget or BudgetConfig(),
    )


def _tool_spec(tool_id: str) -> ToolSpec:
    return ToolSpec(
        tool_id=tool_id,
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=10.0,
        verifier_name="v",
    )


@pytest.mark.n1
def test_root_shared_budget_across_parent_and_children(tmp_path: Path) -> None:
    db_path = tmp_path / "shared_budget.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    cfg = BudgetConfig()  # 2 children, 16 tools, 8 models, 24000 tokens, 120s, 1 retry
    _, root = repo.create_task_and_run(_task("t-shared", budget=cfg))
    repo.transition_run_status(root.run_id, TaskStatus.RUNNING, "start")
    c1 = repo.create_child_run(root.run_id, "c1")
    c2 = repo.create_child_run(root.run_id, "c2")

    # 16th tool call allowed (split across root + c1 + c2); 17th rejected & audited
    for idx in range(16):
        target_run = (root.run_id, c1.run_id, c2.run_id)[idx % 3]
        res = repo.reserve_budget("t-shared", target_run, "tool", tool_calls=1)
        repo.reconcile_budget(res.reservation_id, tool_calls_used=1)

    with pytest.raises(BudgetExceededError):
        repo.reserve_budget("t-shared", c1.run_id, "tool", tool_calls=1)

    # 8th model call and 24000th token allowed; 9th model call or +1 token rejected
    for idx in range(8):
        target_run = (root.run_id, c1.run_id)[idx % 2]
        res = repo.reserve_budget("t-shared", target_run, "model", model_calls=1, tokens=3000)
        repo.reconcile_budget(
            res.reservation_id,
            prompt_tokens=2000,
            completion_tokens=1000,
            model_calls_used=1,
        )

    usage = repo.get_budget_usage("t-shared")
    assert usage.tool_calls_used == 16
    assert usage.model_calls_used == 8
    assert usage.total_tokens_used == 24000

    with pytest.raises(BudgetExceededError):
        repo.reserve_budget("t-shared", root.run_id, "model", model_calls=1, tokens=1)

    # Transient retries: 1 allowed, 2nd rejected
    repo.increment_transient_retry("t-shared", run_id=c1.run_id)
    with pytest.raises(BudgetExceededError):
        repo.increment_transient_retry("t-shared", run_id=c2.run_id)

    audits = repo.list_audit_logs(task_id="t-shared")
    assert any(a.action == "budget_exceeded" for a in audits)
    assert any(a.action == "transient_retry_exhausted" for a in audits)


@pytest.mark.n1
async def test_reservation_and_reconciliation_actual_vs_estimated(tmp_path: Path) -> None:
    db_path = tmp_path / "est_budget.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    # Pre-call reservation blocks concurrent overspend
    _, root = repo.create_task_and_run(
        _task("t-res", budget=BudgetConfig(max_total_tokens=1000, max_model_calls=4))
    )
    repo.transition_run_status(root.run_id, TaskStatus.RUNNING, "start")
    res1 = repo.reserve_budget("t-res", root.run_id, "model", model_calls=1, tokens=700)
    with pytest.raises(BudgetExceededError):
        repo.reserve_budget("t-res", root.run_id, "model", model_calls=1, tokens=400)

    # Downward reconciliation frees unused reserved tokens
    after_rec = repo.reconcile_budget(
        res1.reservation_id, prompt_tokens=100, completion_tokens=50, model_calls_used=1
    )
    assert after_rec.tokens_reserved == 0
    assert after_rec.total_tokens_used == 150
    res2 = repo.reserve_budget("t-res", root.run_id, "model", model_calls=1, tokens=400)
    repo.reconcile_budget(res2.reservation_id, release_only=True)

    # Omitted token counts in Coordinator charge conservative estimate + usage_estimated=True
    registry = ToolRegistry(clock=clock)
    registry.register(_tool_spec("read_a"), lambda a, c: {"pressure": 4.0})
    coord = Coordinator(repo, EmulatedModelClient(mode="omitted_tokens"), registry, clock=clock)
    run = coord.submit_task(_task("t-omitted", allowed_tools=("read_a",)))
    result = await coord.run_until_settled(run.run_id)

    assert result.status == TaskStatus.SUCCEEDED
    assert result.execution_metrics.usage_estimated is True
    assert result.execution_metrics.total_tokens > 0
    assert repo.get_budget_usage("t-omitted").usage_estimated is True


@pytest.mark.n1
async def test_a06_repeated_equivalent_call_halts_even_on_succeeded(tmp_path: Path) -> None:
    db_path = tmp_path / "loop_a06.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    registry = ToolRegistry(clock=clock)
    registry.register(_tool_spec("read_a"), lambda a, c: {"reading": 42, "status": "ok"})

    coord = Coordinator(
        repo,
        EmulatedModelClient(mode="loop_a06"),
        registry,
        loop_detector=LoopDetector(LoopConfig(identical_repeat_threshold=3)),
        clock=clock,
    )
    run = coord.submit_task(_task("t-a06", allowed_tools=("read_a",)))
    result = await coord.run_until_settled(run.run_id)

    assert result.status == TaskStatus.FAILED
    assert result.execution_metrics.tool_calls == 3
    assert result.execution_metrics.tool_calls < 16
    assert result.partial_info is not None
    assert result.partial_info["loop_kind"] == "identical_repeat"

    audits = repo.list_audit_logs(task_id="t-a06")
    assert any(a.action == "loop_halted" for a in audits)

    # Contrast case: registered poller with advancing progress_token is NOT halted at 3 calls
    poll_count = 0

    def poller_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        nonlocal poll_count
        del args
        poll_count += 1
        obs = Observation(
            source="scada",
            session_id="s1",
            asset_id="pump-34",
            observed_label="pressure",
            value=4.0 + poll_count,
            unit="bar",
            source_time=clock.advance(1.0),
            observed_at=clock(),
            quality=DataQuality.GOOD,
        )
        return {"value": obs.value, "observations": [obs]}

    registry.register(_tool_spec("poll_a"), poller_handler, is_poller=True, replace=True)
    usage = ModelUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20)
    turns = [
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id="poll_a",
                    args={"asset": "pump-34"},
                    target_origin="https://scada.local",
                ),
                usage=usage,
            )
        )
        for _ in range(4)
    ] + [
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="final",
                final_answer="Polling observed steady ramp.",
                usage=usage,
            )
        )
    ]
    coord_poll = Coordinator(
        repo,
        EmulatedModelClient(mode="custom", default_turns=turns),
        registry,
        loop_detector=LoopDetector(LoopConfig(identical_repeat_threshold=3)),
        clock=clock,
    )
    poll_run = coord_poll.submit_task(_task("t-poller", allowed_tools=("poll_a",)))
    poll_res = await coord_poll.run_until_settled(poll_run.run_id)
    assert poll_res.status == TaskStatus.SUCCEEDED
    assert poll_res.execution_metrics.tool_calls == 4


@pytest.mark.n1
async def test_a07_alternating_cycle_halts_with_zero_progress(tmp_path: Path) -> None:
    db_path = tmp_path / "cycle_a07.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    registry = ToolRegistry(clock=clock)
    registry.register(_tool_spec("read_a"), lambda a, c: {"state": "unchanged_a"})
    registry.register(_tool_spec("read_b"), lambda a, c: {"state": "unchanged_b"})

    coord = Coordinator(
        repo,
        EmulatedModelClient(mode="cycle_a07"),
        registry,
        loop_detector=LoopDetector(LoopConfig(identical_repeat_threshold=3, max_cycle_period=4)),
        clock=clock,
    )
    run = coord.submit_task(_task("t-a07", allowed_tools=("read_a", "read_b")))
    result = await coord.run_until_settled(run.run_id)

    assert result.status == TaskStatus.FAILED
    assert result.execution_metrics.tool_calls == 4  # A -> B -> A -> B
    assert result.partial_info is not None
    assert result.partial_info["loop_kind"] == "alternating_cycle"
    assert "alternating cycle" in repo.get_run(run.run_id).transition_reason

    audits = repo.list_audit_logs(task_id="t-a07")
    assert any(a.action == "loop_halted" for a in audits)


@pytest.mark.n1
async def test_loop_state_persists_across_pause_and_coordinator_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "loop_persist.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    registry = ToolRegistry(clock=clock)
    registry.register(_tool_spec("read_a"), lambda a, c: {"val": 100})

    usage = ModelUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20)
    call_turn = EmulatedTurn(
        decision=ModelDecision(
            decision_type="tool_call",
            tool_call=ModelToolCall(
                tool_id="read_a",
                args={"asset": "pump-34"},
                target_origin="https://scada.local",
            ),
            usage=usage,
        )
    )
    pause_turn = EmulatedTurn(
        decision=ModelDecision(
            decision_type="request_input",
            required_action="confirm_continue",
            usage=usage,
        )
    )

    # First coordinator executes 2 identical calls then pauses for input
    coord1 = Coordinator(
        repo,
        EmulatedModelClient(mode="custom", default_turns=[call_turn, call_turn, pause_turn]),
        registry,
        clock=clock,
    )
    run = coord1.submit_task(_task("t-loop-persist", allowed_tools=("read_a",)))
    paused = await coord1.run_until_settled(run.run_id)
    assert paused.status == TaskStatus.WAITING_FOR_INPUT
    assert len(repo.get_step_signatures(run.run_id)) == 2

    # Second Coordinator instance resumes and makes 3rd identical call -> A06 triggers
    coord2 = Coordinator(
        repo,
        EmulatedModelClient(mode="custom", default_turns=[call_turn, call_turn]),
        registry,
        clock=clock,
    )
    coord2.resume_task(run.run_id, {"continue": True})
    final = await coord2.run_until_settled(run.run_id)
    assert final.status == TaskStatus.FAILED
    assert final.partial_info is not None
    assert final.partial_info["loop_kind"] == "identical_repeat"
    assert len(repo.get_step_signatures(run.run_id)) == 3


@pytest.mark.n1
async def test_transient_model_error_retries_within_budget_and_exhausts(tmp_path: Path) -> None:
    db_path = tmp_path / "transient_retry.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    registry = ToolRegistry(clock=clock)
    registry.register(_tool_spec("read_a"), lambda a, c: {"pressure": 3.8})

    # Succeeds on 1 retry when max_transient_retries=1
    coord_ok = Coordinator(
        repo,
        EmulatedModelClient(mode="transient_error"),
        registry,
        clock=clock,
    )
    run_ok = coord_ok.submit_task(
        _task(
            "t-transient-ok",
            allowed_tools=("read_a",),
            budget=BudgetConfig(max_transient_retries=1),
        )
    )
    res_ok = await coord_ok.run_until_settled(run_ok.run_id)
    assert res_ok.status == TaskStatus.SUCCEEDED
    assert res_ok.execution_metrics.retries == 1

    # Fails cleanly when max_transient_retries=0
    coord_fail = Coordinator(
        repo,
        EmulatedModelClient(mode="transient_error"),
        registry,
        clock=clock,
    )
    run_fail = coord_fail.submit_task(
        _task(
            "t-transient-fail",
            allowed_tools=("read_a",),
            budget=BudgetConfig(max_transient_retries=0),
        )
    )
    res_fail = await coord_fail.run_until_settled(run_fail.run_id)
    assert res_fail.status == TaskStatus.FAILED
    assert repo.get_run(run_fail.run_id).transition_reason == "model_transient_retries_exhausted"


@pytest.mark.n1
async def test_child_run_active_wall_clock_counts_from_root_after_human_wait(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "child_wall_clock.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    def slow_child_tool(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del args, ctx
        clock.advance(15.0)
        return {"ok": True}

    registry = ToolRegistry(clock=clock)
    registry.register(_tool_spec("read_a"), slow_child_tool)

    usage = ModelUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20)
    root_turns = [
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="request_input",
                required_action="confirm_area",
                usage=usage,
            )
        ),
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="delegate",
                delegations=(
                    ModelDelegationRequest(
                        child_label="branch-1",
                        query="Check child telemetry",
                        allowed_tools=("read_a",),
                        allowed_origins=("https://scada.local",),
                    ),
                ),
                usage=usage,
            )
        ),
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="final",
                final_answer="Should not succeed after wall timeout",
                usage=usage,
            )
        ),
    ]
    child_turns = [
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id="read_a",
                    args={},
                    target_origin="https://scada.local",
                ),
                usage=usage,
            )
        ),
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="final",
                final_answer="Child should not succeed over max_wall_seconds",
                usage=usage,
            )
        ),
    ]

    budget = BudgetConfig(max_wall_seconds=10.0, human_wait_timeout_seconds=300.0)
    task_spec = _task("t-child-wall", budget=budget, allowed_tools=("read_a",))
    task_spec = task_spec.model_copy(
        update={
            "evidence_requirements": task_spec.evidence_requirements.model_copy(
                update={"allow_partial_on_source_failure": False}
            )
        }
    )

    def turn_factory(
        prompt_ctx: Any, tools: Any, budget_rem: Any
    ) -> EmulatedTurn:
        del tools, budget_rem
        if prompt_ctx.depth == 0:
            idx = sum(1 for c in model.call_history[:-1] if c.depth == 0)
            return root_turns[min(idx, len(root_turns) - 1)]
        idx = sum(1 for c in model.call_history[:-1] if c.depth > 0)
        return child_turns[min(idx, len(child_turns) - 1)]

    model = EmulatedModelClient(mode="custom", turn_factory=turn_factory)
    coord = Coordinator(repo, model, registry, clock=clock)
    root_run = coord.submit_task(task_spec)

    paused = await coord.run_until_settled(root_run.run_id)
    assert paused.status == TaskStatus.WAITING_FOR_INPUT

    # Wait 100s in waiting_for_input (excluded from active wall clock)
    clock.advance(100.0)
    coord.resume_task(root_run.run_id, {"area": "area-1"})

    final = await coord.run_until_settled(root_run.run_id)
    assert final.status == TaskStatus.FAILED
    assert final.execution_metrics.human_wait_seconds == pytest.approx(100.0)
    assert final.execution_metrics.wall_seconds >= 15.0

    snap = repo.get_run_snapshot(root_run.run_id)
    assert len(snap.child_runs) == 1
    assert snap.child_runs[0].status == TaskStatus.FAILED
    assert snap.child_runs[0].transition_reason == "wall_clock_budget_exceeded"
