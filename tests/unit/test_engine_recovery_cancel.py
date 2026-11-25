"""N1 unit tests for lease fencing, A08 crash recovery, A09 cancel, and A14 restart (F06, F07)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from src.contracts.budgets import BudgetConfig
from src.contracts.enums import EffectClass, ReceiptOutcome, StepStatus, TaskStatus
from src.contracts.models import ActionReceipt, TaskScope, TaskSpec, ToolSpec
from src.engine.coordinator import Coordinator
from src.engine.tool_registry import ToolExecutionContext, ToolRegistry
from src.model.emulator import EmulatedModelClient, EmulatedTurn
from src.model.protocol import ModelDecision, ModelToolCall, ModelUsage
from src.storage import LeaseFencingError, StorageRepo, TerminalStateError


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
    read_only: bool = False,
    allowed_tools: tuple[str, ...] = ("apply_valve", "read_scada"),
    budget: BudgetConfig | None = None,
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
            read_only=read_only,
        ),
        query="Reconcile pump 34 action",
        budget=budget or BudgetConfig(),
    )


@pytest.mark.n1
def test_lease_fencing_stale_generation_and_expiry(tmp_path: Path) -> None:
    db_path = tmp_path / "fencing.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    task_spec, run = repo.create_task_and_run(_task("t-fence"))
    repo.transition_run_status(run.run_id, TaskStatus.RUNNING, "started")
    step = repo.enqueue_step(
        run.run_id, "read_scada", {"asset": "pump-34"}, "v", EffectClass.READ
    )

    lease_a = repo.acquire_step_lease("worker-a", 10.0, run_id=run.run_id)
    assert lease_a is not None and lease_a.lease_generation == 1

    # Clock advances past Worker A lease expiry; Worker B reclaims step -> generation=2
    clock.advance(15.0)
    lease_b = repo.acquire_step_lease("worker-b", 30.0, run_id=run.run_id)
    assert lease_b is not None
    assert lease_b.lease_generation == 2
    assert lease_b.lease_owner == "worker-b"

    # Worker A attempts late commit with stale lease_generation=1 -> rejected & audited
    stale_rcpt = ActionReceipt(
        receipt_id="rcpt-stale",
        task_id=task_spec.task_id,
        run_id=run.run_id,
        step_id=step.step_id,
        attempt=1,
        tool_id="read_scada",
        redacted_args={"asset": "pump-34"},
        operation_key=step.operation_key,
        duration_ms=5.0,
        outcome=ReceiptOutcome.SUCCEEDED,
        recorded_at=clock(),
    )
    with pytest.raises(LeaseFencingError):
        repo.commit_step_result(
            step.step_id,
            1,
            StepStatus.SUCCEEDED,
            "succeeded",
            stale_rcpt,
            expected_worker="worker-a",
        )
    audits = repo.list_audit_logs(task_id=task_spec.task_id)
    assert any(a.action == "stale_result_rejected" for a in audits)

    # Worker B with lease_generation=2 succeeds
    repo.prepare_step_attempt(step.step_id, 2, step.operation_key)
    repo.mark_step_executing(step.step_id, 2)
    valid_rcpt = ActionReceipt(
        receipt_id="rcpt-valid",
        task_id=task_spec.task_id,
        run_id=run.run_id,
        step_id=step.step_id,
        attempt=2,
        tool_id="read_scada",
        redacted_args={"asset": "pump-34"},
        operation_key=step.operation_key,
        duration_ms=5.0,
        outcome=ReceiptOutcome.SUCCEEDED,
        recorded_at=clock(),
    )
    committed = repo.commit_step_result(
        step.step_id,
        2,
        StepStatus.SUCCEEDED,
        "succeeded",
        valid_rcpt,
        expected_worker="worker-b",
    )
    assert committed.status == StepStatus.SUCCEEDED
    assert committed.lease_generation == 2


@pytest.mark.n1
async def test_a08_crash_after_effect_three_branches_and_read(tmp_path: Path) -> None:
    db_path = tmp_path / "a08.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    # Branch 1: Reconciler confirms EFFECT already applied -> SUCCEEDED without replay
    applied_exec_count = 0
    seen_op_keys: list[str] = []

    def eff_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        nonlocal applied_exec_count
        del args
        applied_exec_count += 1
        seen_op_keys.append(ctx.operation_key)
        return {"applied": True}

    eff_spec = ToolSpec(
        tool_id="apply_valve",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.EFFECT,
        timeout_s=10.0,
        verifier_name="v",
    )
    reg1 = ToolRegistry(clock=clock)
    reg1.register(
        eff_spec,
        eff_handler,
        reconciler=lambda op_key, idem_key, ctx: (True, {"valve": "open", "op": op_key}),
        supports_idempotency=True,
    )

    _, r1 = repo.create_task_and_run(_task("t-a08-applied"))
    repo.transition_run_status(r1.run_id, TaskStatus.RUNNING, "start")
    s1 = repo.enqueue_step(
        r1.run_id,
        "apply_valve",
        {"valve": "v1"},
        "v",
        EffectClass.EFFECT,
        target_origin="https://scada.local",
    )
    l1 = repo.acquire_step_lease("crashed-worker", 5.0, step_id=s1.step_id)
    assert l1 is not None
    repo.prepare_step_attempt(s1.step_id, l1.lease_generation, s1.operation_key)
    repo.mark_step_executing(s1.step_id, l1.lease_generation)
    applied_exec_count = 1  # Simulated external execution occurred before crash

    clock.advance(10.0)  # Lease expired
    coord1 = Coordinator(repo, EmulatedModelClient(mode="happy_path"), reg1, clock=clock)
    summary1 = await coord1.recover_inflight_runs()
    assert summary1.unknown_steps_reconciled == 1
    assert repo.get_step(s1.step_id).status == StepStatus.SUCCEEDED
    assert applied_exec_count == 1  # Zero replay!

    # Branch 2: Reconciler confirms NOT applied + idempotency -> retry once with same operation_key
    retry_exec_count = 0
    retry_op_keys: list[str] = []

    def eff_retry_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        nonlocal retry_exec_count
        del args
        retry_exec_count += 1
        retry_op_keys.append(ctx.operation_key)
        return {"applied": True, "idempotency_key": ctx.idempotency_key}

    reg2 = ToolRegistry(clock=clock)
    reg2.register(
        eff_spec,
        eff_retry_handler,
        reconciler=lambda op_key, idem_key, ctx: (False, {"confirmed_unapplied": True}),
        supports_idempotency=True,
    )
    _, r2 = repo.create_task_and_run(_task("t-a08-unapplied"))
    repo.transition_run_status(r2.run_id, TaskStatus.RUNNING, "start")
    s2 = repo.enqueue_step(
        r2.run_id,
        "apply_valve",
        {"valve": "v2"},
        "v",
        EffectClass.EFFECT,
        target_origin="https://scada.local",
        operation_key="op-idem-fixed-1",
    )
    l2 = repo.acquire_step_lease("crashed-worker", 5.0, step_id=s2.step_id)
    assert l2 is not None
    repo.prepare_step_attempt(s2.step_id, l2.lease_generation, s2.operation_key)
    repo.mark_step_executing(s2.step_id, l2.lease_generation)

    clock.advance(10.0)
    coord2 = Coordinator(repo, EmulatedModelClient(mode="happy_path"), reg2, clock=clock)
    summary2 = await coord2.recover_inflight_runs()
    assert summary2.reset_steps == 1
    assert repo.get_step(s2.step_id).status == StepStatus.PENDING
    res2 = await coord2.run_until_settled(r2.run_id)
    assert res2.status == TaskStatus.SUCCEEDED
    assert retry_exec_count == 1
    assert retry_op_keys == ["op-idem-fixed-1"]

    # Branch 3: Ambiguous effect (no reconciler confirmation) -> UNKNOWN + waiting_for_input
    reg3 = ToolRegistry(clock=clock)
    reg3.register(eff_spec, eff_retry_handler, reconciler=None, supports_idempotency=False)
    _, r3 = repo.create_task_and_run(_task("t-a08-ambig"))
    repo.transition_run_status(r3.run_id, TaskStatus.RUNNING, "start")
    s3 = repo.enqueue_step(
        r3.run_id,
        "apply_valve",
        {"valve": "v3"},
        "v",
        EffectClass.EFFECT,
        target_origin="https://scada.local",
    )
    l3 = repo.acquire_step_lease("crashed-worker", 5.0, step_id=s3.step_id)
    assert l3 is not None
    repo.prepare_step_attempt(s3.step_id, l3.lease_generation, s3.operation_key)
    repo.mark_step_executing(s3.step_id, l3.lease_generation)

    clock.advance(10.0)
    coord3 = Coordinator(repo, EmulatedModelClient(mode="happy_path"), reg3, clock=clock)
    summary3 = await coord3.recover_inflight_runs()
    assert summary3.waiting_for_human_runs == 1
    assert repo.get_step(s3.step_id).status == StepStatus.UNKNOWN
    paused_r3 = repo.get_run(r3.run_id)
    assert paused_r3.status == TaskStatus.WAITING_FOR_INPUT
    assert paused_r3.required_action is not None

    # Branch 4: READ crash reconciles safely and re-queries
    read_exec_count = 0
    read_spec = ToolSpec(
        tool_id="read_scada",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=10.0,
        verifier_name="v",
    )
    reg4 = ToolRegistry(clock=clock)

    def read_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        nonlocal read_exec_count
        del args, ctx
        read_exec_count += 1
        return {"pressure": 4.5}

    reg4.register(read_spec, read_handler)
    _, r4 = repo.create_task_and_run(_task("t-a08-read", read_only=True))
    repo.transition_run_status(r4.run_id, TaskStatus.RUNNING, "start")
    s4 = repo.enqueue_step(
        r4.run_id,
        "read_scada",
        {"asset": "pump-34"},
        "v",
        EffectClass.READ,
        target_origin="https://scada.local",
    )
    l4 = repo.acquire_step_lease("crashed-worker", 5.0, step_id=s4.step_id)
    assert l4 is not None
    repo.prepare_step_attempt(s4.step_id, l4.lease_generation, s4.operation_key)
    repo.mark_step_executing(s4.step_id, l4.lease_generation)

    clock.advance(10.0)
    coord4 = Coordinator(repo, EmulatedModelClient(mode="happy_path"), reg4, clock=clock)
    summary4 = await coord4.recover_inflight_runs()
    assert summary4.reset_steps == 1
    res4 = await coord4.run_until_settled(r4.run_id)
    assert res4.status == TaskStatus.SUCCEEDED
    assert read_exec_count == 1


@pytest.mark.n1
async def test_a09_cascading_cancellation_and_late_result_fencing(tmp_path: Path) -> None:
    db_path = tmp_path / "cancel_a09.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    tool_started = asyncio.Event()
    allow_late_finish = asyncio.Event()
    read_spec = ToolSpec(
        tool_id="read_scada",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=10.0,
        verifier_name="v",
    )

    async def blocking_read(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del args, ctx
        tool_started.set()
        await allow_late_finish.wait()
        return {"pressure": 9.9}

    registry = ToolRegistry(clock=clock)
    registry.register(read_spec, blocking_read)

    # Create root + active child + in-flight step
    coord = Coordinator(repo, EmulatedModelClient(mode="happy_path"), registry, clock=clock)
    root_run = coord.submit_task(_task("t-a09", read_only=True))
    repo.transition_run_status(root_run.run_id, TaskStatus.RUNNING, "started")
    child_run = repo.create_child_run(root_run.run_id, "child-a09")
    repo.transition_run_status(child_run.run_id, TaskStatus.RUNNING, "child_started")

    in_flight_step = repo.enqueue_step(
        child_run.run_id,
        "read_scada",
        {"asset": "pump-34"},
        "v",
        EffectClass.READ,
        target_origin="https://scada.local",
    )
    leased = repo.acquire_step_lease("worker-late", 30.0, step_id=in_flight_step.step_id)
    assert leased is not None
    repo.prepare_step_attempt(in_flight_step.step_id, leased.lease_generation, leased.operation_key)
    repo.mark_step_executing(in_flight_step.step_id, leased.lease_generation)

    # Cancel root task -> cascades CANCELLED to root & child, increments lease_generation
    cancelled_root = coord.cancel_task(root_run.run_id, reason="operator_abort")
    assert cancelled_root.status == TaskStatus.CANCELLED
    assert repo.get_run(child_run.run_id).status == TaskStatus.CANCELLED
    assert repo.is_cancel_requested("t-a09") is True
    assert repo.get_step(in_flight_step.step_id).lease_generation > leased.lease_generation

    # New dispatches (enqueue step, reserve budget, spawn child) are blocked
    with pytest.raises(TerminalStateError):
        repo.enqueue_step(root_run.run_id, "read_scada", {}, "v", EffectClass.READ)
    with pytest.raises(TerminalStateError):
        repo.reserve_budget("t-a09", root_run.run_id, "model", model_calls=1, tokens=100)
    with pytest.raises(TerminalStateError):
        repo.create_child_run(root_run.run_id, "child-after-cancel")

    # Late tool commit arrives after cancel -> fenced & audited, CANCELLED remains immutable
    late_rcpt = ActionReceipt(
        receipt_id="rcpt-late",
        task_id="t-a09",
        run_id=child_run.run_id,
        step_id=in_flight_step.step_id,
        attempt=leased.attempt,
        tool_id="read_scada",
        redacted_args={"asset": "pump-34"},
        operation_key=in_flight_step.operation_key,
        duration_ms=25.0,
        outcome=ReceiptOutcome.SUCCEEDED,
        recorded_at=clock(),
    )
    with pytest.raises(TerminalStateError):
        repo.commit_step_result(
            in_flight_step.step_id,
            leased.lease_generation,
            StepStatus.SUCCEEDED,
            "succeeded",
            late_rcpt,
            expected_worker="worker-late",
        )
    assert repo.get_run(root_run.run_id).status == TaskStatus.CANCELLED
    assert repo.get_run(child_run.run_id).status == TaskStatus.CANCELLED
    audits = repo.list_audit_logs(task_id="t-a09")
    assert any(a.action == "stale_result_rejected" for a in audits)

    # Also verify active asyncio run_until_settled cancels cleanly when cancel_task is called
    coord2 = Coordinator(repo, EmulatedModelClient(mode="happy_path"), registry, clock=clock)
    live_run = coord2.submit_task(_task("t-a09-live", read_only=True))
    task = asyncio.create_task(coord2.run_until_settled(live_run.run_id))
    await asyncio.wait_for(tool_started.wait(), timeout=2.0)
    coord2.cancel_task(live_run.run_id, reason="live_cancel")
    res_live = await asyncio.wait_for(task, timeout=2.0)
    allow_late_finish.set()
    assert res_live.status == TaskStatus.CANCELLED
    assert repo.get_run(live_run.run_id).status == TaskStatus.CANCELLED


@pytest.mark.n1
async def test_a14_budget_and_signature_preservation_on_coordinator_restart(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "a14.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    read_spec = ToolSpec(
        tool_id="read_scada",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=10.0,
        verifier_name="v",
    )
    registry = ToolRegistry(clock=clock)
    registry.register(read_spec, lambda a, c: {"pressure": 5.1})

    budget = BudgetConfig(max_tool_calls=16, max_model_calls=8, max_total_tokens=24000)
    task_spec, run = repo.create_task_and_run(
        _task("t-a14", read_only=True, budget=budget)
    )
    repo.transition_run_status(run.run_id, TaskStatus.RUNNING, "started")

    # Simulate prior consumption: 4 tool calls, 2 model calls, 5000 tokens
    for _ in range(4):
        tr = repo.reserve_budget(task_spec.task_id, run.run_id, "tool", tool_calls=1)
        repo.reconcile_budget(tr.reservation_id, tool_calls_used=1)
    for _ in range(2):
        mr = repo.reserve_budget(
            task_spec.task_id, run.run_id, "model", model_calls=1, tokens=2500
        )
        repo.reconcile_budget(
            mr.reservation_id,
            prompt_tokens=1500,
            completion_tokens=1000,
            model_calls_used=1,
        )

    # Simulate stranded/expired in-flight reservation (1 model call + 2000 tokens) + expired step
    stranded_step = repo.enqueue_step(
        run.run_id,
        "read_scada",
        {"asset": "pump-34"},
        "v",
        EffectClass.READ,
        target_origin="https://scada.local",
    )
    leased = repo.acquire_step_lease("old-coord", 5.0, step_id=stranded_step.step_id)
    assert leased is not None
    repo.reserve_budget(
        task_spec.task_id,
        run.run_id,
        "model",
        model_calls=1,
        tokens=2000,
        ttl_s=5.0,
    )

    # Advance clock past lease & reservation expiry and boot a brand-new Coordinator
    clock.advance(15.0)
    restarted_coord = Coordinator(
        StorageRepo(db_path, clock=clock),
        EmulatedModelClient(mode="happy_path"),
        registry,
        clock=clock,
    )
    summary = await restarted_coord.recover_inflight_runs("coord-2")
    assert summary.expired_reservations_cleaned == 1
    assert summary.reset_steps == 1

    post_recovery_usage = repo.get_budget_usage(task_spec.task_id)
    assert post_recovery_usage.tool_calls_used == 4
    assert post_recovery_usage.model_calls_used == 3  # 2 + 1 conservatively charged
    assert post_recovery_usage.total_tokens_used == 7000  # 5000 + 2000 stranded
    assert post_recovery_usage.tokens_reserved == 0
    assert post_recovery_usage.usage_estimated is True

    # Complete remaining work within original root budget
    final = await restarted_coord.run_until_settled(run.run_id)
    assert final.status == TaskStatus.SUCCEEDED
    final_usage = repo.get_budget_usage(task_spec.task_id)
    assert final_usage.tool_calls_used == 5
    assert final_usage.model_calls_used >= 4
    assert final_usage.within_limits(budget)


@pytest.mark.n1
async def test_a08_applied_effect_charges_tool_budget_and_blocks_bypass(tmp_path: Path) -> None:
    db_path = tmp_path / "a08_budget_bypass.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    eff_spec = ToolSpec(
        tool_id="apply_valve",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.EFFECT,
        timeout_s=10.0,
        verifier_name="v",
    )
    read_spec = ToolSpec(
        tool_id="read_scada",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=10.0,
        verifier_name="v",
    )

    read_invocations = 0

    def read_handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        nonlocal read_invocations
        del args, ctx
        read_invocations += 1
        return {"ok": True}

    reg = ToolRegistry(clock=clock)
    reg.register(
        eff_spec,
        lambda a, c: {"ok": True},
        reconciler=lambda op, idem, c: (True, {"applied": True}),
    )
    reg.register(read_spec, read_handler)

    spec = _task(
        "t-a08-budget-applied",
        budget=BudgetConfig(max_tool_calls=1, max_model_calls=4),
    )
    _, run = repo.create_task_and_run(spec, run_id="r-a08-applied")
    repo.transition_run_status(run.run_id, TaskStatus.RUNNING, "go")
    st = repo.enqueue_step(
        run.run_id,
        "apply_valve",
        {},
        "v",
        EffectClass.EFFECT,
        target_origin="https://scada.local",
    )
    ls = repo.acquire_step_lease("old-worker", 5.0, run_id=run.run_id, step_id=st.step_id)
    assert ls is not None
    repo.reserve_budget(
        spec.task_id,
        run.run_id,
        "tool",
        step_id=st.step_id,
        tool_calls=1,
        lease_generation=ls.lease_generation,
    )
    repo.prepare_step_attempt(st.step_id, ls.lease_generation, st.operation_key)
    repo.mark_step_executing(st.step_id, ls.lease_generation)

    clock.advance(10.0)
    usage = ModelUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2)
    model = EmulatedModelClient(
        mode="custom",
        default_turns=[
            EmulatedTurn(
                decision=ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id="read_scada",
                        args={},
                        target_origin="https://scada.local",
                    ),
                    usage=usage,
                )
            ),
            EmulatedTurn(
                decision=ModelDecision(
                    decision_type="final",
                    final_answer="done",
                    usage=usage,
                )
            ),
        ],
    )
    coord = Coordinator(repo, model, reg, clock=clock)
    summary = await coord.recover_inflight_runs()
    assert summary.unknown_steps_reconciled == 1
    assert repo.get_step(st.step_id).status == StepStatus.SUCCEEDED

    after_rec_usage = repo.get_budget_usage(spec.task_id)
    assert after_rec_usage.tool_calls_used == 1
    assert after_rec_usage.tool_calls_reserved == 0

    res = await coord.run_until_settled(run.run_id)
    assert res.status == TaskStatus.FAILED
    assert read_invocations == 0
    assert res.execution_metrics.tool_calls == 1
    assert repo.get_run(run.run_id).transition_reason == "tool_budget_exceeded"

    # Verify timeout -> UNKNOWN -> resume({"effect_applied": True}) does NOT double-charge
    async def timeout_eff(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del args, ctx
        await asyncio.sleep(0.2)
        return {"ok": True}

    reg_to = ToolRegistry(clock=clock)
    reg_to.register(eff_spec.model_copy(update={"timeout_s": 0.01}), timeout_eff)
    model_to = EmulatedModelClient(
        mode="custom",
        default_turns=[
            EmulatedTurn(
                decision=ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id="apply_valve",
                        args={},
                        target_origin="https://scada.local",
                    ),
                    usage=usage,
                )
            ),
            EmulatedTurn(
                decision=ModelDecision(decision_type="final", final_answer="done", usage=usage)
            ),
        ],
    )
    coord_to = Coordinator(repo, model_to, reg_to, clock=clock)
    run_to = coord_to.submit_task(
        _task("t-a08-no-double-charge", budget=BudgetConfig(max_tool_calls=2, max_model_calls=4))
    )
    paused = await coord_to.run_until_settled(run_to.run_id)
    assert paused.status == TaskStatus.WAITING_FOR_INPUT
    assert repo.get_budget_usage("t-a08-no-double-charge").tool_calls_used == 1

    coord_to.resume_task(run_to.run_id, {"effect_applied": True})
    res_to = await coord_to.run_until_settled(run_to.run_id)
    assert res_to.status == TaskStatus.SUCCEEDED
    assert res_to.execution_metrics.tool_calls == 1


@pytest.mark.n1
async def test_concurrent_recover_inflight_runs_is_race_safe(tmp_path: Path) -> None:
    db_path = tmp_path / "concurrent_recover.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    eff_spec = ToolSpec(
        tool_id="apply_valve",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.EFFECT,
        timeout_s=10.0,
        verifier_name="v",
    )
    read_spec = ToolSpec(
        tool_id="read_scada",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=10.0,
        verifier_name="v",
    )

    async def slow_reconciler(
        op_key: str, idem_key: str, ctx: ToolExecutionContext
    ) -> tuple[bool, dict[str, Any]]:
        del idem_key, ctx
        await asyncio.sleep(0.05)
        if "unapplied" in op_key:
            return False, {"confirmed_unapplied": True}
        if "ambig" in op_key:
            return False, {"ambiguous": True}
        return True, {"applied": True}

    reg = ToolRegistry(clock=clock)
    reg.register(
        eff_spec,
        lambda a, c: {"ok": True},
        reconciler=slow_reconciler,
        supports_idempotency=True,
    )
    reg.register(read_spec, lambda a, c: {"ok": True})

    # 1) EXECUTING applied EFFECT
    _, r_applied = repo.create_task_and_run(_task("t-conc-applied"))
    repo.transition_run_status(r_applied.run_id, TaskStatus.RUNNING, "go")
    s_applied = repo.enqueue_step(
        r_applied.run_id,
        "apply_valve",
        {},
        "v",
        EffectClass.EFFECT,
        target_origin="https://scada.local",
        operation_key="op-conc-applied",
    )
    l_app = repo.acquire_step_lease("old", 5.0, step_id=s_applied.step_id)
    assert l_app is not None
    repo.reserve_budget(
        "t-conc-applied",
        r_applied.run_id,
        "tool",
        step_id=s_applied.step_id,
        tool_calls=1,
    )
    repo.prepare_step_attempt(s_applied.step_id, l_app.lease_generation, s_applied.operation_key)
    repo.mark_step_executing(s_applied.step_id, l_app.lease_generation)

    # 2) EXECUTING unapplied idempotent EFFECT
    _, r_unapp = repo.create_task_and_run(_task("t-conc-unapplied"))
    repo.transition_run_status(r_unapp.run_id, TaskStatus.RUNNING, "go")
    s_unapp = repo.enqueue_step(
        r_unapp.run_id,
        "apply_valve",
        {},
        "v",
        EffectClass.EFFECT,
        target_origin="https://scada.local",
        operation_key="op-conc-unapplied",
    )
    l_un = repo.acquire_step_lease("old", 5.0, step_id=s_unapp.step_id)
    assert l_un is not None
    repo.prepare_step_attempt(s_unapp.step_id, l_un.lease_generation, s_unapp.operation_key)
    repo.mark_step_executing(s_unapp.step_id, l_un.lease_generation)

    # 3) EXECUTING ambiguous EFFECT
    _, r_ambig = repo.create_task_and_run(_task("t-conc-ambig"))
    repo.transition_run_status(r_ambig.run_id, TaskStatus.RUNNING, "go")
    s_ambig = repo.enqueue_step(
        r_ambig.run_id,
        "apply_valve",
        {},
        "v",
        EffectClass.EFFECT,
        target_origin="https://scada.local",
        operation_key="op-conc-ambig",
    )
    l_amb = repo.acquire_step_lease("old", 5.0, step_id=s_ambig.step_id)
    assert l_amb is not None
    repo.prepare_step_attempt(s_ambig.step_id, l_amb.lease_generation, s_ambig.operation_key)
    repo.mark_step_executing(s_ambig.step_id, l_amb.lease_generation)

    # 4) LEASED pre-exec step + 5) EXECUTING READ step
    _, r_pre = repo.create_task_and_run(_task("t-conc-pre", read_only=True))
    repo.transition_run_status(r_pre.run_id, TaskStatus.RUNNING, "go")
    s_pre = repo.enqueue_step(
        r_pre.run_id, "read_scada", {}, "v", EffectClass.READ, target_origin="https://scada.local"
    )
    repo.acquire_step_lease("old", 5.0, step_id=s_pre.step_id)

    _, r_read = repo.create_task_and_run(_task("t-conc-read", read_only=True))
    repo.transition_run_status(r_read.run_id, TaskStatus.RUNNING, "go")
    s_read = repo.enqueue_step(
        r_read.run_id, "read_scada", {}, "v", EffectClass.READ, target_origin="https://scada.local"
    )
    l_rd = repo.acquire_step_lease("old", 5.0, step_id=s_read.step_id)
    assert l_rd is not None
    repo.prepare_step_attempt(s_read.step_id, l_rd.lease_generation, s_read.operation_key)
    repo.mark_step_executing(s_read.step_id, l_rd.lease_generation)

    clock.advance(10.0)
    c1 = Coordinator(
        StorageRepo(db_path, clock=clock),
        EmulatedModelClient(mode="happy_path"),
        reg,
        clock=clock,
    )
    c2 = Coordinator(
        StorageRepo(db_path, clock=clock),
        EmulatedModelClient(mode="happy_path"),
        reg,
        clock=clock,
    )

    sum1, sum2 = await asyncio.gather(
        c1.recover_inflight_runs("c1"),
        c2.recover_inflight_runs("c2"),
    )
    assert sum1.unknown_steps_reconciled + sum2.unknown_steps_reconciled == 3
    assert repo.get_step(s_applied.step_id).status == StepStatus.SUCCEEDED
    assert repo.get_budget_usage("t-conc-applied").tool_calls_used == 1
    assert len(repo.get_run_snapshot(r_applied.run_id).receipts) == 1

    assert repo.get_step(s_unapp.step_id).status == StepStatus.PENDING
    assert repo.get_budget_usage("t-conc-unapplied").transient_retries_used == 1

    assert repo.get_step(s_ambig.step_id).status == StepStatus.UNKNOWN
    assert repo.get_run(r_ambig.run_id).status == TaskStatus.WAITING_FOR_INPUT

    assert repo.get_step(s_pre.step_id).status == StepStatus.PENDING
    assert repo.get_step(s_read.step_id).status == StepStatus.PENDING
    assert repo.get_budget_usage("t-conc-read").transient_retries_used == 1


@pytest.mark.n1
async def test_resume_without_effect_applied_repauses_and_blocks_succeeded_with_unknown(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "unknown_resume_guard.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    eff_spec = ToolSpec(
        tool_id="apply_valve",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.EFFECT,
        timeout_s=10.0,
        verifier_name="v",
    )
    reg = ToolRegistry(clock=clock)
    reg.register(eff_spec, lambda a, c: {"ok": True}, reconciler=None, supports_idempotency=False)

    task_spec = _task("t-unk-guard")
    _, run = repo.create_task_and_run(task_spec)
    repo.transition_run_status(run.run_id, TaskStatus.RUNNING, "go")
    step = repo.enqueue_step(
        run.run_id,
        "apply_valve",
        {},
        "v",
        EffectClass.EFFECT,
        target_origin="https://scada.local",
    )
    ls = repo.acquire_step_lease("old", 5.0, step_id=step.step_id)
    assert ls is not None
    repo.reserve_budget(task_spec.task_id, run.run_id, "tool", step_id=step.step_id, tool_calls=1)
    repo.prepare_step_attempt(step.step_id, ls.lease_generation, step.operation_key)
    repo.mark_step_executing(step.step_id, ls.lease_generation)

    clock.advance(10.0)
    usage = ModelUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2)
    model = EmulatedModelClient(
        mode="custom",
        default_turns=[
            EmulatedTurn(
                decision=ModelDecision(decision_type="final", final_answer="done", usage=usage)
            )
        ],
    )
    coord = Coordinator(repo, model, reg, clock=clock)
    await coord.recover_inflight_runs()
    assert repo.get_run(run.run_id).status == TaskStatus.WAITING_FOR_INPUT
    assert repo.get_step(step.step_id).status == StepStatus.UNKNOWN

    # Resuming without 'effect_applied' re-pauses rather than settling SUCCEEDED with UNKNOWN step
    coord.resume_task(run.run_id, {"comment": "looks fine"})
    res_missing = await coord.run_until_settled(run.run_id)
    assert res_missing.status == TaskStatus.WAITING_FOR_INPUT
    assert repo.get_step(step.step_id).status == StepStatus.UNKNOWN
    assert len(model.call_history) == 0

    # Non-bool 'effect_applied' also re-pauses safely
    coord.resume_task(run.run_id, {"effect_applied": "yes"})
    res_nonbool = await coord.run_until_settled(run.run_id)
    assert res_nonbool.status == TaskStatus.WAITING_FOR_INPUT
    assert repo.get_step(step.step_id).status == StepStatus.UNKNOWN

    # Explicit boolean 'effect_applied=True' reconciles step, charges tool call, and settles
    coord.resume_task(run.run_id, {"effect_applied": True})
    res_ok = await coord.run_until_settled(run.run_id)
    assert res_ok.status == TaskStatus.SUCCEEDED
    assert repo.get_step(step.step_id).status == StepStatus.SUCCEEDED
    assert res_ok.execution_metrics.tool_calls == 1

    # Direct _settle_terminal guard never settles SUCCEEDED while an UNKNOWN step exists
    _, run2 = repo.create_task_and_run(_task("t-settle-guard"))
    repo.transition_run_status(run2.run_id, TaskStatus.RUNNING, "go")
    step2 = repo.enqueue_step(
        run2.run_id,
        "apply_valve",
        {},
        "v",
        EffectClass.EFFECT,
        target_origin="https://scada.local",
    )
    repo.mark_step_unknown(step2.step_id, reason="direct_unknown")
    guarded = coord._settle_terminal(
        task_spec=repo.get_task_spec("t-settle-guard"),
        run_id=run2.run_id,
        target_status=TaskStatus.SUCCEEDED,
        reason="completed_succeeded",
        answer="should not succeed",
        observations=(),
    )
    assert guarded.status == TaskStatus.FAILED
    assert repo.get_run(run2.run_id).transition_reason == "unresolved_unknown_steps"


@pytest.mark.n1
def test_mark_step_unknown_without_lease_generation_rejects_terminal_and_cancelled(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "mark_unknown_guard.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    _, r_term = repo.create_task_and_run(_task("t-term-unk"))
    repo.transition_run_status(r_term.run_id, TaskStatus.RUNNING, "go")
    s_term = repo.enqueue_step(
        r_term.run_id, "apply_valve", {}, "v", EffectClass.EFFECT
    )
    repo.transition_run_status(r_term.run_id, TaskStatus.SUCCEEDED, "done")
    with pytest.raises(TerminalStateError):
        repo.mark_step_unknown(s_term.step_id, reason="late_timeout")
    assert any(
        a.action == "stale_unknown_rejected" for a in repo.list_audit_logs(task_id="t-term-unk")
    )

    _, r_canc = repo.create_task_and_run(_task("t-canc-unk"))
    repo.transition_run_status(r_canc.run_id, TaskStatus.RUNNING, "go")
    s_canc = repo.enqueue_step(
        r_canc.run_id, "apply_valve", {}, "v", EffectClass.EFFECT
    )
    repo.request_cancel("t-canc-unk", reason="abort")
    with pytest.raises(TerminalStateError):
        repo.mark_step_unknown(s_canc.step_id, reason="late_timeout")
    assert any(
        a.action == "stale_unknown_rejected" for a in repo.list_audit_logs(task_id="t-canc-unk")
    )


@pytest.mark.n1
async def test_assume_previous_worker_dead_reclaims_unexpired_model_reservation_and_reconciles_step(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "startup_reclaim.db"
    clock = FakeClock()
    repo = StorageRepo(db_path, clock=clock)
    repo.init_db()

    eff_spec = ToolSpec(
        tool_id="apply_valve",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.EFFECT,
        timeout_s=10.0,
        verifier_name="v",
    )
    applied_calls = 0

    async def timeout_after_apply(
        args: dict[str, Any], ctx: ToolExecutionContext
    ) -> dict[str, Any]:
        nonlocal applied_calls
        del args, ctx
        applied_calls += 1
        raise TimeoutError("simulated post-apply timeout")

    reg = ToolRegistry(clock=clock)
    reg.register(
        eff_spec,
        timeout_after_apply,
        reconciler=lambda op, idem, ctx: (True, {"valve": "reset", "op": op}),
        supports_idempotency=True,
    )

    usage = ModelUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    model = EmulatedModelClient(
        mode="custom",
        default_turns=[
            EmulatedTurn(
                decision=ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id="apply_valve",
                        args={},
                        target_origin="https://scada.local",
                    ),
                    usage=usage,
                )
            ),
            EmulatedTurn(
                decision=ModelDecision(
                    decision_type="final", final_answer="reconciled", usage=usage
                )
            ),
        ],
    )
    coord = Coordinator(repo, model, reg, clock=clock)
    run = coord.submit_task(_task("t-reconcile-inline"))
    res = await coord.run_until_settled(run.run_id)
    assert res.status == TaskStatus.SUCCEEDED
    assert applied_calls == 1

    # Unexpired model reservation is preserved when assume_previous_worker_dead=False,
    # and reclaimed immediately when assume_previous_worker_dead=True.
    _, r2 = repo.create_task_and_run(_task("t-unexpired-res"))
    repo.transition_run_status(r2.run_id, TaskStatus.RUNNING, "go")
    repo.reserve_budget(
        "t-unexpired-res", r2.run_id, "model", model_calls=1, tokens=500, ttl_s=60.0
    )
    sum_default = await coord.recover_inflight_runs()
    assert sum_default.expired_reservations_cleaned == 0
    assert repo.get_budget_usage("t-unexpired-res").model_calls_reserved == 1

    sum_startup = await coord.recover_inflight_runs(assume_previous_worker_dead=True)
    assert sum_startup.expired_reservations_cleaned == 1
    post_usage = repo.get_budget_usage("t-unexpired-res")
    assert post_usage.model_calls_reserved == 0
    assert post_usage.model_calls_used == 1
    assert post_usage.total_tokens_used == 500
