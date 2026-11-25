"""N1 unit tests for Task State Machine, pause/resume, and depth=1 delegation (F04)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from src.contracts.budgets import BudgetConfig
from src.contracts.common import InvalidStateTransitionError, PlanValidationError
from src.contracts.enums import (
    ALLOWED_TASK_TRANSITIONS,
    TERMINAL_TASK_STATUSES,
    EffectClass,
    TaskStatus,
)
from src.contracts.models import Result, TaskScope, TaskSpec, ToolSpec
from src.engine.coordinator import Coordinator
from src.engine.tool_registry import ToolExecutionContext, ToolRegistry
from src.model.emulator import EmulatedModelClient
from src.storage import BudgetExceededError, StorageRepo, TerminalStateError


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def _make_task(
    task_id: str = "task-life-1",
    *,
    budget: BudgetConfig | None = None,
    allowed_tools: tuple[str, ...] = ("read_scada",),
    read_only: bool = True,
) -> TaskSpec:
    return TaskSpec(
        task_id=task_id,
        user_id="user-1",
        profile_id="prof-1",
        scope=TaskScope(
            facility_id="plant-a",
            allowed_origins=("https://scada.local",),
            allowed_areas=("area-1", "area-2"),
            allowed_tools=allowed_tools,
            read_only=read_only,
        ),
        query="Check pump 34 status",
        budget=budget or BudgetConfig(),
    )


def _register_scada_tool(registry: ToolRegistry) -> None:
    spec = ToolSpec(
        tool_id="read_scada",
        version="1.0.0",
        input_schema={"type": "object", "properties": {"asset": {"type": "string"}}},
        output_schema={"type": "object", "required": ["status"]},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=10.0,
        verifier_name="scada_verifier",
    )

    def handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del ctx
        return {
            "status": "running",
            "asset": args.get("asset", "pump-34"),
            "area": args.get("area"),
        }

    registry.register(spec, handler)


@pytest.mark.n1
def test_valid_and_invalid_state_transitions_and_event_trail(tmp_path: Path) -> None:
    db_path = tmp_path / "transitions.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    # Exercise every legal edge in ALLOWED_TASK_TRANSITIONS
    legal_paths: list[tuple[str, list[tuple[TaskStatus, str, str | None]]]] = [
        ("t-q-f", [(TaskStatus.FAILED, "preflight_failed", None)]),
        ("t-q-c", [(TaskStatus.CANCELLED, "user_cancelled", None)]),
        (
            "t-wait-rec",
            [
                (TaskStatus.RUNNING, "started", None),
                (TaskStatus.WAITING_FOR_INPUT, "need_area", "select_area"),
                (TaskStatus.RECOVERING, "recover_after_wait", None),
                (TaskStatus.WAITING_FOR_INPUT, "need_confirm", "confirm_action"),
                (TaskStatus.RUNNING, "resumed", None),
                (TaskStatus.RECOVERING, "transient_hiccup", None),
                (TaskStatus.PARTIAL, "partial_result", None),
            ],
        ),
        (
            "t-rec-ok",
            [
                (TaskStatus.RUNNING, "started", None),
                (TaskStatus.RECOVERING, "crash_recovery", None),
                (TaskStatus.SUCCEEDED, "recovered_ok", None),
            ],
        ),
    ]

    for tid, path in legal_paths:
        _, run = repo.create_task_and_run(_make_task(tid))
        prev_ver = run.version
        for target, reason, req in path:
            clock.advance(1.0)
            updated = repo.transition_run_status(
                run.run_id, target, reason, required_action=req
            )
            assert updated.status == target
            assert updated.transition_reason == reason
            assert updated.version == prev_ver + 1
            prev_ver = updated.version

        events = [
            e
            for e in repo.list_events(run_id=run.run_id)
            if e.event_type == "run_transition"
        ]
        assert [(TaskStatus(e.to_status or ""), e.reason) for e in events] == [
            (t, r) for t, r, _ in path
        ]

    # Verify illegal transitions raise InvalidStateTransitionError and are audited
    _, bad_run = repo.create_task_and_run(_make_task("t-illegal"))
    for illegal_target in set(TaskStatus) - ALLOWED_TASK_TRANSITIONS[TaskStatus.QUEUED]:
        with pytest.raises(InvalidStateTransitionError):
            repo.transition_run_status(bad_run.run_id, illegal_target, "bad_jump")
    audits = repo.list_audit_logs(task_id="t-illegal")
    assert len(audits) >= 1
    assert audits[0].action == "illegal_transition_rejected"


@pytest.mark.n1
def test_immutable_terminal_states(tmp_path: Path) -> None:
    db_path = tmp_path / "terminals.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    for idx, terminal in enumerate(sorted(TERMINAL_TASK_STATUSES, key=lambda s: s.value)):
        tid = f"t-term-{idx}"
        _, run = repo.create_task_and_run(_make_task(tid))
        if terminal != TaskStatus.FAILED and terminal != TaskStatus.CANCELLED:
            repo.transition_run_status(run.run_id, TaskStatus.RUNNING, "started")
        expected_result = Result(
            task_id=tid,
            run_id=run.run_id,
            status=terminal,
            answer=f"Final {terminal.value}",
        )
        settled = repo.transition_run_status(
            run.run_id, terminal, f"settled_{terminal.value}", result=expected_result
        )
        assert settled.status == terminal

        for candidate in TaskStatus:
            with pytest.raises(InvalidStateTransitionError):
                repo.transition_run_status(run.run_id, candidate, "reopen_attempt")

        snap = repo.get_run_snapshot(run.run_id)
        assert snap.run.status == terminal
        assert snap.result == expected_result


@pytest.mark.n1
async def test_pause_and_resume_waiting_for_input_and_timeout(tmp_path: Path) -> None:
    db_path = tmp_path / "pause_resume.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()
    registry = ToolRegistry(clock=clock)
    _register_scada_tool(registry)

    budget = BudgetConfig(max_wall_seconds=120.0, human_wait_timeout_seconds=300.0)
    task_spec = _make_task("task-ambiguity", budget=budget)

    coord1 = Coordinator(repo, EmulatedModelClient(mode="ambiguity"), registry, clock=clock)
    run = coord1.submit_task(task_spec)
    clock.advance(5.0)
    paused = await coord1.run_until_settled(run.run_id)
    assert paused.status == TaskStatus.WAITING_FOR_INPUT
    assert paused.required_action is not None

    # Wait 200s (> max_wall_seconds=120s, but < human_wait_timeout_seconds=300s)
    clock.advance(200.0)

    # Fresh Coordinator instance resumes from SQLite WAL persisted state
    coord2 = Coordinator(repo, EmulatedModelClient(mode="ambiguity"), registry, clock=clock)

    # Attempting to widen read_only on resume is rejected
    with pytest.raises(PlanValidationError):
        coord2.resume_task(run.run_id, {"read_only": False})

    resumed_run = coord2.resume_task(run.run_id, {"area": "area-2"})
    assert resumed_run.status == TaskStatus.RUNNING

    clock.advance(5.0)
    final = await coord2.run_until_settled(run.run_id)
    assert final.status == TaskStatus.SUCCEEDED
    assert final.execution_metrics.human_wait_seconds == pytest.approx(200.0)
    assert final.execution_metrics.wall_seconds < 20.0

    # Exceeding human_wait_timeout_seconds transitions to FAILED
    task_timeout = _make_task("task-wait-timeout", budget=budget)
    run_to = coord2.submit_task(task_timeout)
    paused_to = await coord2.run_until_settled(run_to.run_id)
    assert paused_to.status == TaskStatus.WAITING_FOR_INPUT
    clock.advance(301.0)
    with pytest.raises(BudgetExceededError, match="Human wait timeout"):
        coord2.resume_task(run_to.run_id, {"area": "area-1"})
    assert repo.get_run(run_to.run_id).status == TaskStatus.FAILED


@pytest.mark.n1
async def test_depth1_delegation_active_cap_and_scope_narrowing(tmp_path: Path) -> None:
    db_path = tmp_path / "delegation.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()
    registry = ToolRegistry(clock=clock)
    _register_scada_tool(registry)

    coord = Coordinator(repo, EmulatedModelClient(mode="delegation"), registry, clock=clock)
    task_spec = _make_task("task-delegation")
    root_run = coord.submit_task(task_spec)

    # Run full delegation lifecycle: root spawns 2 depth=1 children concurrently
    result = await coord.run_until_settled(root_run.run_id)
    assert result.status == TaskStatus.SUCCEEDED

    snap = repo.get_run_snapshot(root_run.run_id)
    assert len(snap.child_runs) == 2
    assert all(c.depth == 1 and c.status == TaskStatus.SUCCEEDED for c in snap.child_runs)
    # Completing children frees active_children slot while retaining root tool/model usage
    assert snap.budget_usage.active_children == 0
    assert snap.budget_usage.tool_calls_used >= 2
    assert snap.budget_usage.model_calls_used >= 4

    # Direct cap and depth=2 and scope widening checks
    _, root2 = repo.create_task_and_run(_make_task("task-caps"))
    repo.transition_run_status(root2.run_id, TaskStatus.RUNNING, "started")
    c1 = repo.create_child_run(root2.run_id, "c1")
    c2 = repo.create_child_run(root2.run_id, "c2")

    # 3rd active child exceeds max_active_children=2
    with pytest.raises(BudgetExceededError, match="max_active_children"):
        repo.create_child_run(root2.run_id, "c3")

    # Grandchild (depth=2 > max_depth=1) rejected
    repo.transition_run_status(c1.run_id, TaskStatus.RUNNING, "started")
    with pytest.raises(BudgetExceededError, match="max_depth"):
        repo.create_child_run(c1.run_id, "grandchild")

    # Child scope widening rejected & audited
    repo.transition_run_status(c2.run_id, TaskStatus.RUNNING, "started")
    repo.transition_run_status(c2.run_id, TaskStatus.SUCCEEDED, "done")
    assert repo.get_budget_usage("task-caps").active_children == 1

    with pytest.raises(PlanValidationError, match="widening"):
        repo.create_child_run(
            root2.run_id,
            "c-widen-ro",
            child_scope=TaskScope(
                facility_id="plant-a",
                allowed_origins=("https://scada.local",),
                allowed_areas=("area-1",),
                allowed_tools=("read_scada",),
                read_only=False,
            ),
        )
    with pytest.raises(PlanValidationError, match="widening"):
        repo.create_child_run(
            root2.run_id,
            "c-widen-origin",
            child_scope=TaskScope(
                facility_id="plant-a",
                allowed_origins=("https://evil.local",),
                allowed_areas=("area-1",),
                allowed_tools=("read_scada",),
                read_only=True,
            ),
        )
    audits = repo.list_audit_logs(task_id="task-caps")
    assert any(a.action == "child_scope_widening_rejected" for a in audits)

    # Terminal parent cannot spawn child
    repo.transition_run_status(root2.run_id, TaskStatus.FAILED, "stop")
    with pytest.raises(TerminalStateError):
        repo.create_child_run(root2.run_id, "c-after-terminal")


@pytest.mark.n1
async def test_final_decision_with_empty_or_false_partial_info_settles_succeeded(
    tmp_path: Path,
) -> None:
    from collections.abc import Sequence

    from src.model.protocol import BudgetRemaining, ModelDecision, ModelUsage, PromptContext

    class _PartialInfoClient:
        def __init__(self, partial_info: dict[str, Any] | None) -> None:
            self._partial_info = partial_info

        async def decide(
            self,
            prompt_ctx: PromptContext,
            tools: Sequence[ToolSpec],
            budget_remaining: BudgetRemaining,
        ) -> ModelDecision:
            del prompt_ctx, tools, budget_remaining
            return ModelDecision(
                decision_type="final",
                final_answer="Complete answer.",
                partial_info=self._partial_info,
                usage=ModelUsage(
                    prompt_tokens=10,
                    completion_tokens=10,
                    total_tokens=20,
                    usage_mode="actual",
                ),
            )

    for idx, pinfo in enumerate([{}, {"is_partial": False, "note": "complete"}]):
        clock = FakeClock()
        repo = StorageRepo(tmp_path / f"empty_partial_{idx}.db", clock=clock)
        repo.init_db()
        reg = ToolRegistry(clock=clock)
        _register_scada_tool(reg)
        coord = Coordinator(repo, _PartialInfoClient(pinfo), reg, clock=clock)
        run = coord.submit_task(_make_task(f"task-empty-partial-{idx}"))
        res = await coord.run_until_settled(run.run_id)
        assert res.status == TaskStatus.SUCCEEDED

    # Non-empty partial_info without is_partial=False continues to settle PARTIAL
    clock_p = FakeClock()
    repo_p = StorageRepo(tmp_path / "real_partial.db", clock=clock_p)
    repo_p.init_db()
    reg_p = ToolRegistry(clock=clock_p)
    _register_scada_tool(reg_p)
    coord_p = Coordinator(
        repo_p,
        _PartialInfoClient({"missing_sources": ["maintenance"]}),
        reg_p,
        clock=clock_p,
    )
    run_p = coord_p.submit_task(_make_task("task-real-partial"))
    res_p = await coord_p.run_until_settled(run_p.run_id)
    assert res_p.status == TaskStatus.PARTIAL


@pytest.mark.n1
async def test_coordinator_accumulates_human_inputs_chronologically_across_resumes(
    tmp_path: Path,
) -> None:
    from collections.abc import Sequence

    from src.model.protocol import (
        BudgetRemaining,
        ModelDecision,
        ModelToolCall,
        ModelUsage,
        PromptContext,
    )

    seen_prompt_inputs: list[dict[str, Any] | None] = []
    seen_verifier_input: list[dict[str, Any] | None] = []

    class _MultiPauseClient:
        async def decide(
            self,
            prompt_ctx: PromptContext,
            tools: Sequence[ToolSpec],
            budget_remaining: BudgetRemaining,
        ) -> ModelDecision:
            del tools, budget_remaining
            seen_prompt_inputs.append(
                dict(prompt_ctx.human_input) if prompt_ctx.human_input is not None else None
            )
            usage = ModelUsage(
                prompt_tokens=10,
                completion_tokens=10,
                total_tokens=20,
                usage_mode="actual",
            )
            if prompt_ctx.human_input is None:
                return ModelDecision(
                    decision_type="request_input",
                    required_action="Select target area.",
                    usage=usage,
                )
            if not prompt_ctx.human_input.get("reauthenticated"):
                return ModelDecision(
                    decision_type="request_input",
                    required_action="Reauthenticate session.",
                    usage=usage,
                )
            if not prompt_ctx.history:
                return ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id="read_scada",
                        args={"asset": "pump-34", "area": prompt_ctx.human_input["area"]},
                        target_origin="https://scada.local",
                        completion_verifier="scada_verifier",
                        rationale="Query clarified area.",
                    ),
                    usage=usage,
                )
            return ModelDecision(
                decision_type="final",
                final_answer="Done.",
                usage=usage,
            )

    def _capture_verifier(
        task_spec: TaskSpec,
        run_id: str,
        observations: tuple[Any, ...],
        history: Sequence[dict[str, Any]],
        candidate: Result,
        last_human_input: dict[str, Any] | None,
    ) -> Result:
        del task_spec, run_id, observations, history
        seen_verifier_input.append(
            dict(last_human_input) if last_human_input is not None else None
        )
        return candidate

    clock = FakeClock()
    repo = StorageRepo(tmp_path / "multi_resume.db", clock=clock)
    repo.init_db()
    reg = ToolRegistry(clock=clock)
    _register_scada_tool(reg)
    coord = Coordinator(
        repo,
        _MultiPauseClient(),
        reg,
        clock=clock,
        result_verifier=_capture_verifier,
    )
    run = coord.submit_task(_make_task("task-multi-resume"))

    res1 = await coord.run_until_settled(run.run_id)
    assert res1.status == TaskStatus.WAITING_FOR_INPUT

    coord.resume_task(run.run_id, {"area": "area-1", "note": "first"})
    res2 = await coord.run_until_settled(run.run_id)
    assert res2.status == TaskStatus.WAITING_FOR_INPUT

    coord.resume_task(run.run_id, {"reauthenticated": True, "note": "second"})
    res3 = await coord.run_until_settled(run.run_id)
    assert res3.status == TaskStatus.SUCCEEDED

    expected = {"area": "area-1", "reauthenticated": True, "note": "second"}
    assert seen_prompt_inputs == [None, {"area": "area-1", "note": "first"}, expected, expected]
    assert seen_verifier_input == [expected]


@pytest.mark.n1
def test_make_industrial_turn_factory_area_resolution_and_requery() -> None:
    from src.adapters.config import load_facility_config
    from src.adapters.maintenance import get_maintenance_tool_specs
    from src.adapters.scada import get_scada_tool_specs
    from src.model.protocol import BudgetRemaining, ModelDecision, PromptContext
    from src.runtime import make_industrial_turn_factory

    cfg = load_facility_config(Path("lab/configs/facility_a.json"))
    turn_factory = make_industrial_turn_factory(cfg)
    tools = [
        *get_scada_tool_specs((cfg.apps["scada"].origin,)).values(),
        *get_maintenance_tool_specs((cfg.apps["maintenance"].origin,)).values(),
    ]
    budget = BudgetRemaining(
        active_children_remaining=2,
        depth_remaining=1,
        tool_calls_remaining=16,
        model_calls_remaining=8,
        wall_seconds_remaining=120.0,
        tokens_remaining=24000,
    )

    # 1. Unscoped multi-area initial turn queries source without area so Verifier checks records
    initial_turn = turn_factory(
        PromptContext(
            task_id="t-ambig",
            run_id="r-ambig",
            depth=0,
            query="Check bomba 34",
            facility_id="facility-a",
            allowed_areas=("area-1", "area-2"),
            history=(),
            observations=(),
            human_input=None,
            turn_index=0,
        ),
        tools,
        budget,
    )
    assert isinstance(initial_turn.decision, ModelDecision)
    assert initial_turn.decision.decision_type == "tool_call"
    assert initial_turn.decision.tool_call is not None
    assert initial_turn.decision.tool_call.tool_id == "scada.read_alarms"
    assert "area" not in initial_turn.decision.tool_call.args

    # 2. If chosen_area is set and prior tool call lacked area, re-query with area
    requery_turn = turn_factory(
        PromptContext(
            task_id="t-ambig",
            run_id="r-ambig",
            depth=0,
            query="Check bomba 34",
            facility_id="facility-a",
            allowed_areas=("area-1", "area-2"),
            history=({"tool_id": "scada.read_alarms", "args": {"asset": "bomba 34"}},),
            observations=(),
            human_input={"area": "area-1", "reauthenticated": True},
            turn_index=1,
        ),
        tools,
        budget,
    )
    assert isinstance(requery_turn.decision, ModelDecision)
    assert requery_turn.decision.decision_type == "tool_call"
    assert requery_turn.decision.tool_call is not None
    assert requery_turn.decision.tool_call.tool_id == "scada.read_alarms"
    assert requery_turn.decision.tool_call.args.get("area") == "area-1"

    # 3. Once all 3 tools ran for chosen_area, proceed to final
    final_turn = turn_factory(
        PromptContext(
            task_id="t-ambig",
            run_id="r-ambig",
            depth=0,
            query="Check bomba 34",
            facility_id="facility-a",
            allowed_areas=("area-1", "area-2"),
            history=(
                {"tool_id": "scada.read_alarms", "args": {"asset": "bomba 34", "area": "area-1"}},
                {
                    "tool_id": "scada.read_readings",
                    "args": {"asset": "bomba 34", "area": "area-1"},
                },
                {
                    "tool_id": "maint.read_work_orders",
                    "args": {"asset": "bomba 34", "area": "area-1"},
                },
            ),
            observations=(),
            human_input={"area": "area-1", "reauthenticated": True},
            turn_index=4,
        ),
        tools,
        budget,
    )
    assert isinstance(final_turn.decision, ModelDecision)
    assert final_turn.decision.decision_type == "final"

    # 4. Unambiguous area mention in query ("Area 2" vs "area-2", "area-3") resolves without pause
    explicit_turn = turn_factory(
        PromptContext(
            task_id="t-area2-explicit",
            run_id="r-area2-explicit",
            depth=0,
            query="¿Qué alarma apareció primero en Area 2?",
            facility_id="facility-b",
            allowed_areas=("area-2", "area-3"),
            history=(),
            observations=(),
            human_input=None,
            turn_index=0,
        ),
        tools,
        budget,
    )
    assert isinstance(explicit_turn.decision, ModelDecision)
    assert explicit_turn.decision.decision_type == "tool_call"
    assert explicit_turn.decision.tool_call is not None
    assert explicit_turn.decision.tool_call.args.get("area") == "area-2"
