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


@pytest.mark.n1
async def test_disambiguation_resume_with_asset_id_only_succeeds_on_area_1(tmp_path: Path) -> None:
    from src.adapters.config import load_facility_config
    from src.adapters.maintenance import get_maintenance_tool_specs
    from src.adapters.scada import get_scada_tool_specs
    from src.contracts.enums import DataQuality
    from src.contracts.models import Observation
    from src.engine.coordinator import CoordinatorConfig
    from src.engine.tool_registry import PermissionToolError
    from src.runtime import build_industrial_result_verifier, make_industrial_turn_factory

    cfg = load_facility_config(Path("lab/configs/facility_a.json"))
    clock = FakeClock()
    repo = StorageRepo(tmp_path / "asset_id_resume.db", clock=clock)
    repo.init_db()
    reg = ToolRegistry(clock=clock)

    scada_specs = get_scada_tool_specs((cfg.apps["scada"].origin,))
    maint_specs = get_maintenance_tool_specs((cfg.apps["maintenance"].origin,))
    obs_time = clock() - timedelta(minutes=5)

    def _make_obs(
        *,
        source: str,
        asset_id: str,
        area: str,
        value: str,
        unit: str,
        record_type: str,
    ) -> Observation:
        return Observation(
            source=source,
            session_id=f"user-1:prof-1:{source}",
            asset_id=asset_id,
            observed_label="bomba 34",
            value=value,
            unit=unit,
            source_time=obs_time,
            observed_at=clock(),
            quality=DataQuality.GOOD,
            authorized_evidence=True,
            area=area,
            metadata={"record_type": record_type, "record_id": f"{source}-{asset_id}"},
        )

    def _scada_alarms_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        area = args.get("area")
        if ctx.scope.allowed_areas and area is not None and area not in ctx.scope.allowed_areas:
            raise PermissionToolError(f"Area {area!r} outside allowed_areas.")
        all_obs = [
            _make_obs(
                source="scada",
                asset_id="bomba-34-a1",
                area="area-1",
                value="HIGH_VIBRATION",
                unit="alarm_code",
                record_type="alarm",
            ),
            _make_obs(
                source="scada",
                asset_id="bomba-34-a2",
                area="area-2",
                value="LOW_PRESSURE",
                unit="alarm_code",
                record_type="alarm",
            ),
        ]
        selected = [o for o in all_obs if area is None or o.area == area]
        return {
            "output": {
                "source": "scada",
                "count": len(selected),
                "records": [o.model_dump(mode="json") for o in selected],
            },
            "observations": selected,
        }

    def _scada_readings_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        area = args.get("area")
        if ctx.scope.allowed_areas and area is not None and area not in ctx.scope.allowed_areas:
            raise PermissionToolError(f"Area {area!r} outside allowed_areas.")
        all_obs = [
            _make_obs(
                source="scada",
                asset_id="bomba-34-a1",
                area="area-1",
                value="8.4",
                unit="mm/s",
                record_type="reading",
            ),
            _make_obs(
                source="scada",
                asset_id="bomba-34-a2",
                area="area-2",
                value="3.1",
                unit="mm/s",
                record_type="reading",
            ),
        ]
        selected = [o for o in all_obs if area is None or o.area == area]
        return {
            "output": {
                "source": "scada",
                "count": len(selected),
                "records": [o.model_dump(mode="json") for o in selected],
            },
            "observations": selected,
        }

    def _maint_wo_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        area = args.get("area")
        if ctx.scope.allowed_areas and area is not None and area not in ctx.scope.allowed_areas:
            raise PermissionToolError(f"Area {area!r} outside allowed_areas.")
        all_obs = [
            _make_obs(
                source="maintenance",
                asset_id="bomba-34-a1",
                area="area-1",
                value="Bearing replacement scheduled",
                unit="event",
                record_type="work_order",
            ),
            _make_obs(
                source="maintenance",
                asset_id="bomba-34-a2",
                area="area-2",
                value="Seal inspection completed",
                unit="event",
                record_type="work_order",
            ),
        ]
        selected = [o for o in all_obs if area is None or o.area == area]
        return {
            "output": {
                "source": "maintenance",
                "count": len(selected),
                "records": [o.model_dump(mode="json") for o in selected],
            },
            "observations": selected,
        }

    reg.register(scada_specs["scada.read_alarms"], _scada_alarms_handler, is_poller=True)
    reg.register(scada_specs["scada.read_readings"], _scada_readings_handler, is_poller=True)
    reg.register(maint_specs["maint.read_work_orders"], _maint_wo_handler, is_poller=True)

    coord = Coordinator(
        repo,
        EmulatedModelClient(turn_factory=make_industrial_turn_factory(cfg)),
        reg,
        config=CoordinatorConfig(default_granted_permissions=("scada:read", "maint:read")),
        clock=clock,
        result_verifier=build_industrial_result_verifier(cfg, reference_time_fn=clock),
    )
    task = TaskSpec(
        task_id="task-asset-id-resume",
        user_id="operator_ro",
        profile_id="prof-1",
        scope=TaskScope(
            facility_id="facility-a",
            allowed_origins=(cfg.apps["scada"].origin, cfg.apps["maintenance"].origin),
            allowed_areas=("area-1", "area-2"),
            allowed_tools=("scada.read_alarms", "scada.read_readings", "maint.read_work_orders"),
            read_only=True,
        ),
        query="¿Qué alarma apareció primero en la bomba 34?",
    )

    run = coord.submit_task(task)
    res1 = await coord.run_until_settled(run.run_id)
    assert res1.status == TaskStatus.WAITING_FOR_INPUT
    assert res1.required_action is not None
    assert "specify area or asset_id" in res1.required_action
    assert res1.verified_observations == ()
    assert res1.execution_metrics.model_calls == 4

    # Resume specifying ONLY asset_id (without "area"), as instructed by Verifier.detect_ambiguity
    coord.resume_task(run.run_id, {"asset_id": "bomba-34-a1"})
    res2 = await coord.run_until_settled(run.run_id)
    assert res2.status == TaskStatus.SUCCEEDED
    assert len(res2.verified_observations) == 6
    assert {
        str(obs.metadata.get("record_type")) for obs in res2.verified_observations
    } == {"alarm", "reading", "work_order"}
    assert all(
        obs.area == "area-1" and obs.asset_id == "bomba-34-a1"
        for obs in res2.verified_observations
    )
    assert res2.execution_metrics.model_calls == 8
    assert res2.execution_metrics.tool_calls == 6


@pytest.mark.n1
def test_resolve_area_from_human_input_choice_source_ids_and_scope_guard() -> None:
    from src.adapters.config import load_facility_config
    from src.contracts.enums import DataQuality
    from src.contracts.models import ExecutionMetrics, Observation
    from src.runtime import _resolve_area_from_human_input, build_industrial_result_verifier

    cfg_a = load_facility_config(Path("lab/configs/facility_a.json"))
    cfg_b = load_facility_config(Path("lab/configs/facility_b.json"))

    assert _resolve_area_from_human_input(None, cfg_a) is None
    assert _resolve_area_from_human_input({}, cfg_a) is None
    assert _resolve_area_from_human_input({"area": " area-1 "}, cfg_a) == "area-1"
    assert _resolve_area_from_human_input({"choice": "area-2"}, cfg_a) == "area-2"
    assert _resolve_area_from_human_input({"asset_id": "bomba-34-a1"}, cfg_a) == "area-1"
    assert _resolve_area_from_human_input({"area": "   ", "asset_id": "bomba-34-a1"}, cfg_a) == (
        "area-1"
    )
    assert _resolve_area_from_human_input({"asset_id": "SC-77"}, cfg_b) == "area-2"
    assert _resolve_area_from_human_input({"asset_id": "CMMS-77"}, cfg_b) == "area-2"
    assert _resolve_area_from_human_input({"asset_id": "unknown-asset"}, cfg_b) is None

    now = FakeClock()()
    verifier_b = build_industrial_result_verifier(cfg_b, reference_time_fn=lambda: now)
    task_b = TaskSpec(
        task_id="t-b-source-id",
        user_id="operator_ro",
        profile_id="prof-1",
        scope=TaskScope(
            facility_id="facility-b",
            allowed_origins=(cfg_b.apps["scada"].origin, cfg_b.apps["maintenance"].origin),
            allowed_areas=("area-2", "area-3"),
            allowed_tools=("scada.read_alarms", "maint.read_work_orders"),
            read_only=True,
        ),
        query="Check bomba 77",
    )
    obs_b2_scada = Observation(
        source="scada",
        session_id="u:p:scada",
        asset_id="SC-77",
        observed_label="bomba 77",
        value="HIGH_TEMP",
        unit="alarm_code",
        source_time=now - timedelta(minutes=2),
        observed_at=now,
        quality=DataQuality.GOOD,
        authorized_evidence=True,
        area="area-2",
        metadata={"record_type": "alarm"},
    )
    obs_b2_maint = Observation(
        source="maintenance",
        session_id="u:p:maintenance",
        asset_id="CMMS-77",
        observed_label="bomba 77",
        value="Valve checked",
        unit="event",
        source_time=now - timedelta(minutes=1),
        observed_at=now,
        quality=DataQuality.GOOD,
        authorized_evidence=True,
        area="area-2",
        metadata={"record_type": "work_order"},
    )
    obs_b3 = Observation(
        source="scada",
        session_id="u:p:scada",
        asset_id="bomba-77-b3",
        observed_label="bomba 77",
        value="OK",
        unit="alarm_code",
        source_time=now - timedelta(minutes=2),
        observed_at=now,
        quality=DataQuality.GOOD,
        authorized_evidence=True,
        area="area-3",
        metadata={"record_type": "alarm"},
    )
    candidate_b = Result(
        task_id=task_b.task_id,
        run_id="run-b",
        status=TaskStatus.SUCCEEDED,
        answer="ok",
        execution_metrics=ExecutionMetrics(),
    )
    history_b = [{"tool_id": "scada.read_alarms", "outcome": "succeeded"}]

    # source_id ("SC-77") resolves area-2 cleanly in verifier
    res_source_id = verifier_b(
        task_b,
        "run-b",
        (obs_b2_scada, obs_b2_maint, obs_b3),
        history_b,
        candidate_b,
        {"asset_id": "SC-77"},
    )
    assert res_source_id.status == TaskStatus.SUCCEEDED
    assert all(o.area == "area-2" for o in res_source_id.verified_observations)

    # choice ("area-2") resolves area-2 cleanly in verifier
    res_choice = verifier_b(
        task_b,
        "run-b",
        (obs_b2_scada, obs_b2_maint, obs_b3),
        history_b,
        candidate_b,
        {"choice": "area-2"},
    )
    assert res_choice.status == TaskStatus.SUCCEEDED
    assert all(o.area == "area-2" for o in res_choice.verified_observations)

    # Out-of-scope area in human_input ("area-99") cannot hijack target_area
    res_out_of_scope = verifier_b(
        task_b,
        "run-b",
        (obs_b2_scada, obs_b2_maint, obs_b3),
        history_b,
        candidate_b,
        {"area": "area-99"},
    )
    assert res_out_of_scope.status == TaskStatus.WAITING_FOR_INPUT

    # Single-area task ignores human_input attempting to switch to another area
    task_single_area = task_b.model_copy(
        update={
            "scope": task_b.scope.model_copy(update={"allowed_areas": ("area-2",)}),
        }
    )
    res_single = verifier_b(
        task_single_area,
        "run-b",
        (obs_b2_scada, obs_b2_maint, obs_b3),
        history_b,
        candidate_b,
        {"area": "area-3"},
    )
    assert res_single.status == TaskStatus.SUCCEEDED
    assert all(o.area == "area-2" for o in res_single.verified_observations)


@pytest.mark.tier5
@pytest.mark.n1
async def test_t5_08_coordinator_does_not_misclassify_arbitrary_model_error_as_policy_denial(
    tmp_path: Path,
) -> None:
    from collections.abc import Sequence

    from src.model.emulator import EmulatedTurn
    from src.model.protocol import (
        BudgetRemaining,
        ModelDecision,
        ModelProtocolError,
        ModelToolCall,
        ModelUsage,
        PromptContext,
    )

    class _BadDecisionModel:
        async def decide(
            self,
            prompt_ctx: PromptContext,
            tools: Sequence[ToolSpec],
            budget_remaining: BudgetRemaining,
        ) -> ModelDecision:
            del prompt_ctx, tools, budget_remaining
            raise ModelProtocolError(
                "Invalid or missing decision_type: 'outside allowed tool list'."
            )

    clock = FakeClock()
    repo = StorageRepo(tmp_path / "t5_08a.db", clock=clock)
    repo.init_db()
    reg = ToolRegistry(clock=clock)
    _register_scada_tool(reg)
    coord = Coordinator(repo, _BadDecisionModel(), reg, clock=clock)
    run = coord.submit_task(_make_task("t5-08-proto"))
    res = await coord.run_until_settled(run.run_id)
    assert res.status == TaskStatus.FAILED
    assert repo.get_run(run.run_id).transition_reason == "model_error"
    audits = repo.list_audit_logs(task_id="t5-08-proto")
    assert not any(a.action == "tool_permission_denied" for a in audits)

    # Real disallowed tool call via EmulatedModelClient still raises ModelPermissionError & logs
    repo2 = StorageRepo(tmp_path / "t5_08b.db", clock=clock)
    repo2.init_db()
    usage = ModelUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    emu = EmulatedModelClient(
        mode="custom",
        default_turns=[
            EmulatedTurn(
                decision=ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id="effect.apply",
                        args={},
                        target_origin="https://scada.local",
                    ),
                    usage=usage,
                )
            )
        ],
    )
    coord2 = Coordinator(repo2, emu, reg, clock=clock)
    run2 = coord2.submit_task(_make_task("t5-08-perm"))
    res2 = await coord2.run_until_settled(run2.run_id)
    assert res2.status == TaskStatus.FAILED
    assert repo2.get_run(run2.run_id).transition_reason == "read_only_policy_denied"
    audits2 = repo2.list_audit_logs(task_id="t5-08-perm")
    assert any(a.action == "tool_permission_denied" for a in audits2)


@pytest.mark.tier5
@pytest.mark.n1
async def test_t5_09_resume_task_rejects_malformed_scope_override_types(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    repo = StorageRepo(tmp_path / "t5_09.db", clock=clock)
    repo.init_db()
    reg = ToolRegistry(clock=clock)
    _register_scada_tool(reg)
    coord = Coordinator(repo, EmulatedModelClient(mode="ambiguity"), reg, clock=clock)
    run = coord.submit_task(_make_task("t5-09", read_only=True))
    paused = await coord.run_until_settled(run.run_id)
    assert paused.status == TaskStatus.WAITING_FOR_INPUT

    bad_payloads: list[dict[str, Any]] = [
        {"allowed_origins": "https://evil.com"},
        {"allowed_tools": "effect.tool"},
        {"read_only": 0},
        {"allowed_origins": []},
        {"allowed_tools": []},
    ]
    for bad_input in bad_payloads:
        with pytest.raises(PlanValidationError):
            coord.resume_task(run.run_id, bad_input)
    audits = repo.list_audit_logs(task_id="t5-09")
    assert sum(1 for a in audits if a.action == "resume_scope_widening_rejected") == len(
        bad_payloads
    )


@pytest.mark.tier5
@pytest.mark.n1
async def test_t5_11_parent_does_not_succeed_with_waiting_child_run(
    tmp_path: Path,
) -> None:
    from src.engine.tool_registry import AuthToolError
    from src.model.emulator import EmulatedTurn
    from src.model.protocol import (
        ModelDecision,
        ModelDelegationRequest,
        ModelToolCall,
        ModelUsage,
    )

    clock = FakeClock()
    repo = StorageRepo(tmp_path / "t5_11.db", clock=clock)
    repo.init_db()
    reg = ToolRegistry(clock=clock)
    auth_ok = {"ready": False}

    def _auth_gated_read(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del args, ctx
        if not auth_ok["ready"]:
            raise AuthToolError("Session expired for scada")
        return {"ok": True}

    reg.register(
        ToolSpec(
            tool_id="read_scada",
            version="1.0.0",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            allowed_origins=("https://scada.local",),
            effect_class=EffectClass.READ,
            timeout_s=5.0,
            verifier_name="v",
        ),
        _auth_gated_read,
    )

    usage = ModelUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)

    def _turn_factory(
        prompt_ctx: Any, tools: Any, budget_rem: Any
    ) -> EmulatedTurn:
        del tools, budget_rem
        if prompt_ctx.depth == 0:
            if any(isinstance(h, dict) and "delegation" in h for h in prompt_ctx.history):
                return EmulatedTurn(
                    decision=ModelDecision(
                        decision_type="final",
                        final_answer="Parent complete after child.",
                        usage=usage,
                    )
                )
            return EmulatedTurn(
                decision=ModelDecision(
                    decision_type="delegate",
                    delegations=(
                        ModelDelegationRequest(
                            child_label="scada-child",
                            query="Read scada",
                            allowed_tools=("read_scada",),
                            allowed_origins=("https://scada.local",),
                        ),
                    ),
                    usage=usage,
                )
            )
        if prompt_ctx.history and prompt_ctx.history[-1].get("outcome") == "succeeded":
            return EmulatedTurn(
                decision=ModelDecision(
                    decision_type="final",
                    final_answer="Child complete.",
                    usage=usage,
                )
            )
        return EmulatedTurn(
            decision=ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id="read_scada",
                    args={},
                    target_origin="https://scada.local",
                ),
                usage=usage,
            )
        )

    coord = Coordinator(repo, EmulatedModelClient(turn_factory=_turn_factory), reg, clock=clock)
    run = coord.submit_task(_make_task("t5-11"))
    paused = await coord.run_until_settled(run.run_id)
    assert paused.status == TaskStatus.WAITING_FOR_INPUT
    assert paused.required_action is not None
    assert "scada" in paused.required_action.lower()

    auth_ok["ready"] = True
    coord.resume_task(run.run_id, {"reauthenticated": True})
    final = await coord.run_until_settled(run.run_id)
    assert final.status == TaskStatus.SUCCEEDED
    snap = repo.get_run_snapshot(run.run_id)
    assert snap.budget_usage.active_children == 0
    assert all(c.status == TaskStatus.SUCCEEDED for c in snap.child_runs)


@pytest.mark.tier5
@pytest.mark.n1
def test_t5_19_resolve_area_falls_back_from_whitespace_or_non_string_area_to_choice() -> None:
    from src.adapters.config import load_facility_config
    from src.runtime import _resolve_area_from_human_input

    cfg = load_facility_config(Path("lab/configs/facility_a.json"))
    assert _resolve_area_from_human_input({"area": "   ", "choice": "area-1"}, cfg) == "area-1"
    assert _resolve_area_from_human_input({"area": 123, "choice": "area-1"}, cfg) == "area-1"


@pytest.mark.tier5
@pytest.mark.n1
def test_t5_20_verifier_preserves_partial_scada_tool_failure_and_query_area() -> None:
    from src.adapters.config import load_facility_config
    from src.contracts.common import utc_now
    from src.contracts.enums import DataQuality
    from src.contracts.models import EvidenceRequirements, ExecutionMetrics, Observation, Result
    from src.runtime import build_industrial_result_verifier

    cfg = load_facility_config(Path("lab/configs/facility_a.json"))
    now = utc_now()
    verifier_fn = build_industrial_result_verifier(cfg, reference_time_fn=lambda: now)

    obs_alarm = Observation(
        source="scada",
        session_id="u:p:scada",
        asset_id="bomba-34-a1",
        observed_label="bomba 34",
        value="HIGH_VIBRATION",
        unit="alarm_code",
        source_time=now - timedelta(minutes=2),
        observed_at=now,
        quality=DataQuality.GOOD,
        authorized_evidence=True,
        area="area-1",
        metadata={"record_type": "alarm", "record_id": "ALM-3401"},
    )
    cand = Result(
        task_id="t5-20a",
        run_id="r5-20a",
        status=TaskStatus.SUCCEEDED,
        answer="ok",
        execution_metrics=ExecutionMetrics(),
    )

    # (a) Partial SCADA tool failure (read_alarms succeeded, read_readings failed_transient)
    history_partial_scada = [
        {"tool_id": "scada.read_alarms", "outcome": "succeeded"},
        {"tool_id": "scada.read_readings", "outcome": "failed_transient", "error": "503"},
    ]
    task_strict = TaskSpec(
        task_id="t5-20a",
        user_id="operator_ro",
        profile_id="p1",
        scope=TaskScope(facility_id="facility-a", allowed_areas=("area-1",), read_only=True),
        query="Check bomba 34",
        evidence_requirements=EvidenceRequirements(allow_partial_on_source_failure=False),
    )
    res_fail = verifier_fn(task_strict, "r5-20a", (obs_alarm,), history_partial_scada, cand, None)
    assert res_fail.status == TaskStatus.FAILED
    assert res_fail.partial_info is not None
    assert "scada:read_readings" in res_fail.partial_info["source_errors"]

    task_allow_partial = task_strict.model_copy(
        update={
            "evidence_requirements": EvidenceRequirements(allow_partial_on_source_failure=True)
        }
    )
    res_partial = verifier_fn(
        task_allow_partial, "r5-20a", (obs_alarm,), history_partial_scada, cand, None
    )
    assert res_partial.status == TaskStatus.PARTIAL

    # (b) Query mentioning single area under 2-area scope matches planner without false pause
    task_query_area = TaskSpec(
        task_id="t5-20b",
        user_id="operator_ro",
        profile_id="p1",
        scope=TaskScope(
            facility_id="facility-a",
            allowed_areas=("area-1", "area-2"),
            read_only=True,
        ),
        query="Check bomba 34 in area-1",
    )
    res_area = verifier_fn(
        task_query_area,
        "r5-20b",
        (obs_alarm,),
        [{"tool_id": "scada.read_alarms", "outcome": "succeeded"}],
        cand,
        None,
    )
    assert res_area.status == TaskStatus.SUCCEEDED
    assert all(o.area == "area-1" for o in res_area.verified_observations)


@pytest.mark.tier5
@pytest.mark.n1
def test_t5_23_wait_timeout_on_parent_resume_fails_waiting_children_and_clears_active_children(
    tmp_path: Path,
) -> None:
    import asyncio

    from src.engine.tool_registry import AuthToolError
    from src.model.emulator import EmulatedTurn
    from src.model.protocol import (
        ModelDecision,
        ModelDelegationRequest,
        ModelToolCall,
        ModelUsage,
    )

    clock = FakeClock()
    repo = StorageRepo(tmp_path / "t5_23.db", clock=clock)
    repo.init_db()
    reg = ToolRegistry(clock=clock)

    def _auth_gated_read(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del args, ctx
        raise AuthToolError("Session expired for scada")

    reg.register(
        ToolSpec(
            tool_id="read_scada",
            version="1.0.0",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            allowed_origins=("https://scada.local",),
            effect_class=EffectClass.READ,
            timeout_s=5.0,
            verifier_name="v",
        ),
        _auth_gated_read,
    )

    usage = ModelUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)

    def _turn_factory(
        prompt_ctx: Any, tools: Any, budget_rem: Any
    ) -> EmulatedTurn:
        del tools, budget_rem
        if prompt_ctx.depth == 0:
            return EmulatedTurn(
                decision=ModelDecision(
                    decision_type="delegate",
                    delegations=(
                        ModelDelegationRequest(
                            child_label="scada-child",
                            query="Read scada",
                            allowed_tools=("read_scada",),
                            allowed_origins=("https://scada.local",),
                        ),
                    ),
                    usage=usage,
                )
            )
        return EmulatedTurn(
            decision=ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id="read_scada",
                    args={},
                    target_origin="https://scada.local",
                ),
                usage=usage,
            )
        )

    async def _run() -> None:
        coord = Coordinator(repo, EmulatedModelClient(turn_factory=_turn_factory), reg, clock=clock)
        task = _make_task("t5-23", budget=BudgetConfig(human_wait_timeout_seconds=1.0))
        run = coord.submit_task(task)
        paused = await coord.run_until_settled(run.run_id)
        assert paused.status == TaskStatus.WAITING_FOR_INPUT

        snap_before = repo.get_run_snapshot(run.run_id)
        assert len(snap_before.child_runs) == 1
        assert snap_before.child_runs[0].status == TaskStatus.WAITING_FOR_INPUT
        assert snap_before.budget_usage.active_children == 1

        clock.advance(2.0)
        with pytest.raises(BudgetExceededError, match="Human wait timeout exceeded"):
            coord.resume_task(run.run_id, {"choice": "ok"})

        snap_after = repo.get_run_snapshot(run.run_id)
        assert snap_after.run.status == TaskStatus.FAILED
        assert snap_after.run.transition_reason == "human_wait_timeout_exceeded"
        assert len(snap_after.child_runs) == 1
        assert snap_after.child_runs[0].status == TaskStatus.FAILED
        assert snap_after.child_runs[0].transition_reason == "parent_human_wait_timeout_exceeded"
        assert snap_after.child_runs[0].required_action is None
        assert snap_after.budget_usage.active_children == 0

        await coord.recover_inflight_runs()
        snap_recovered = repo.get_run_snapshot(run.run_id)
        assert snap_recovered.run.status == TaskStatus.FAILED
        assert snap_recovered.child_runs[0].status == TaskStatus.FAILED
        assert snap_recovered.budget_usage.active_children == 0

    asyncio.run(_run())


@pytest.mark.tier5
@pytest.mark.n1
def test_t5_24_delegated_parent_and_children_do_not_double_count_human_wait_seconds(
    tmp_path: Path,
) -> None:
    import asyncio

    from src.engine.tool_registry import AuthToolError
    from src.model.emulator import EmulatedTurn
    from src.model.protocol import (
        ModelDecision,
        ModelDelegationRequest,
        ModelToolCall,
        ModelUsage,
    )

    usage = ModelUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)

    def _build_coordinator(
        db_name: str,
        *,
        auth_state: dict[str, Any],
        clock: FakeClock,
    ) -> tuple[StorageRepo, Coordinator]:
        repo = StorageRepo(tmp_path / db_name, clock=clock)
        repo.init_db()
        reg = ToolRegistry(clock=clock)

        def _auth_gated_read(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
            del ctx
            branch = str(args.get("branch", "area-1"))
            remaining_failures = int(auth_state.get(branch, 0))
            if remaining_failures > 0:
                auth_state[branch] = remaining_failures - 1
                raise AuthToolError(f"Session expired for {branch}")
            return {"ok": True, "branch": branch}

        reg.register(
            ToolSpec(
                tool_id="read_scada",
                version="1.0.0",
                input_schema={"type": "object"},
                output_schema={"type": "object"},
                allowed_origins=("https://scada.local",),
                effect_class=EffectClass.READ,
                timeout_s=5.0,
                verifier_name="v",
            ),
            _auth_gated_read,
        )

        def _turn_factory(
            prompt_ctx: Any, tools: Any, budget_rem: Any
        ) -> EmulatedTurn:
            del tools, budget_rem
            if prompt_ctx.depth == 0:
                if any(isinstance(h, dict) and "delegation" in h for h in prompt_ctx.history):
                    return EmulatedTurn(
                        decision=ModelDecision(
                            decision_type="final",
                            final_answer="Parent complete after both children.",
                            usage=usage,
                        )
                    )
                return EmulatedTurn(
                    decision=ModelDecision(
                        decision_type="delegate",
                        delegations=(
                            ModelDelegationRequest(
                                child_label="branch-1",
                                query="Read area-1",
                                allowed_tools=("read_scada",),
                                allowed_origins=("https://scada.local",),
                                allowed_areas=("area-1",),
                            ),
                            ModelDelegationRequest(
                                child_label="branch-2",
                                query="Read area-2",
                                allowed_tools=("read_scada",),
                                allowed_origins=("https://scada.local",),
                                allowed_areas=("area-2",),
                            ),
                        ),
                        usage=usage,
                    )
                )
            branch = (
                str(prompt_ctx.allowed_areas[0])
                if prompt_ctx.allowed_areas
                else "area-1"
            )
            if prompt_ctx.history and prompt_ctx.history[-1].get("outcome") == "succeeded":
                return EmulatedTurn(
                    decision=ModelDecision(
                        decision_type="final",
                        final_answer=f"{branch} complete.",
                        usage=usage,
                    )
                )
            return EmulatedTurn(
                decision=ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id="read_scada",
                        args={"branch": branch},
                        target_origin="https://scada.local",
                    ),
                    usage=usage,
                )
            )

        coord = Coordinator(repo, EmulatedModelClient(turn_factory=_turn_factory), reg, clock=clock)
        return repo, coord

    async def _run() -> None:
        # 1. 2-child overlapping pause of 120.0s under 300.0s timeout counts 120.0s (not 360.0s)
        clock1 = FakeClock()
        auth1 = {"area-1": 1, "area-2": 1}
        repo1, coord1 = _build_coordinator("t5_24_overlap.db", auth_state=auth1, clock=clock1)
        run1 = coord1.submit_task(
            _make_task("t5-24-overlap", budget=BudgetConfig(human_wait_timeout_seconds=300.0))
        )
        paused1 = await coord1.run_until_settled(run1.run_id)
        assert paused1.status == TaskStatus.WAITING_FOR_INPUT
        snap1_paused = repo1.get_run_snapshot(run1.run_id)
        assert len(snap1_paused.child_runs) == 2
        assert all(c.status == TaskStatus.WAITING_FOR_INPUT for c in snap1_paused.child_runs)

        clock1.advance(120.0)
        coord1.resume_task(run1.run_id, {"reauthenticated": True})
        res1 = await coord1.run_until_settled(run1.run_id)
        assert res1.status == TaskStatus.SUCCEEDED
        snap1 = repo1.get_run_snapshot(run1.run_id)
        assert len(snap1.child_runs) == 2
        assert all(c.status == TaskStatus.SUCCEEDED for c in snap1.child_runs)
        assert snap1.budget_usage.active_children == 0
        assert snap1.budget_usage.human_wait_seconds_elapsed == pytest.approx(120.0, abs=0.01)
        assert res1.execution_metrics.human_wait_seconds == pytest.approx(120.0, abs=0.01)

        # 2. Sequential non-overlapping pauses (120.0s + 190.0s = 310.0s > 300.0s) fail cleanly
        clock2 = FakeClock()
        auth2 = {"area-1": 2, "area-2": 1}
        repo2, coord2 = _build_coordinator("t5_24_seq.db", auth_state=auth2, clock=clock2)
        run2 = coord2.submit_task(
            _make_task("t5-24-seq", budget=BudgetConfig(human_wait_timeout_seconds=300.0))
        )
        paused2a = await coord2.run_until_settled(run2.run_id)
        assert paused2a.status == TaskStatus.WAITING_FOR_INPUT

        clock2.advance(120.0)
        coord2.resume_task(run2.run_id, {"reauthenticated": True})
        paused2b = await coord2.run_until_settled(run2.run_id)
        assert paused2b.status == TaskStatus.WAITING_FOR_INPUT

        clock2.advance(190.0)
        with pytest.raises(BudgetExceededError, match="Human wait timeout exceeded"):
            coord2.resume_task(run2.run_id, {"reauthenticated": True})
        snap2 = repo2.get_run_snapshot(run2.run_id)
        assert snap2.run.status == TaskStatus.FAILED
        assert snap2.run.transition_reason == "human_wait_timeout_exceeded"
        child2_statuses = {c.transition_reason: c.status for c in snap2.child_runs}
        assert child2_statuses["parent_human_wait_timeout_exceeded"] == TaskStatus.FAILED
        assert child2_statuses["completed_succeeded"] == TaskStatus.SUCCEEDED
        assert snap2.budget_usage.active_children == 0
        assert snap2.budget_usage.human_wait_seconds_elapsed == pytest.approx(310.0, abs=0.01)

        # 3. Child resume exceeding timeout inside Coordinator._run_loop_body settles parent FAILED
        clock3 = FakeClock()
        auth3 = {"area-1": 1, "area-2": 1}
        repo3, coord3 = _build_coordinator("t5_24_child_to.db", auth_state=auth3, clock=clock3)
        run3 = coord3.submit_task(
            _make_task("t5-24-child-to", budget=BudgetConfig(human_wait_timeout_seconds=300.0))
        )
        paused3 = await coord3.run_until_settled(run3.run_id)
        assert paused3.status == TaskStatus.WAITING_FOR_INPUT

        clock3.advance(299.0)
        coord3.resume_task(run3.run_id, {"reauthenticated": True})
        # Extra 2s elapses before coordinator resumes waiting children (299 + 2 = 301 > 300)
        clock3.advance(2.0)
        res3 = await coord3.run_until_settled(run3.run_id)
        assert res3.status == TaskStatus.FAILED
        snap3 = repo3.get_run_snapshot(run3.run_id)
        assert snap3.run.status == TaskStatus.FAILED
        assert snap3.run.transition_reason == "human_wait_timeout_exceeded"
        assert all(c.status == TaskStatus.FAILED for c in snap3.child_runs)
        assert snap3.budget_usage.active_children == 0
        assert snap3.budget_usage.human_wait_seconds_elapsed == pytest.approx(301.0, abs=0.01)

    asyncio.run(_run())
