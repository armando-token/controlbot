"""N1 unit tests for frozen core domain contracts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError
from src.contracts import (
    REDACTED_PLACEHOLDER,
    TERMINAL_TASK_STATUSES,
    ActionReceipt,
    BackendMode,
    BudgetConfig,
    BudgetUsage,
    ContradictionClaim,
    ContradictionRecord,
    DataQuality,
    EffectClass,
    EvidenceRequirements,
    ExecutionMetrics,
    ExecutionPlan,
    InvalidStateTransitionError,
    Observation,
    PlanStep,
    PlanValidationError,
    ReceiptOutcome,
    Result,
    Run,
    Step,
    StepStatus,
    TaskScope,
    TaskSpec,
    TaskStatus,
    ToolSpec,
    assert_valid_plan,
    can_transition_status,
    contains_unredacted_secret,
    is_terminal_status,
    redact_secrets,
    validate_http_origin,
    validate_plan_for_task,
    validate_status_transition,
)


def _make_task_spec(**overrides: Any) -> TaskSpec:
    base: dict[str, Any] = {
        "task_id": "task-pump34-001",
        "user_id": "operator-1",
        "profile_id": "lab-default",
        "scope": TaskScope(
            facility_id="facility-a",
            allowed_origins=("http://127.0.0.1:8101", "http://127.0.0.1:8102"),
            allowed_areas=("area-1",),
            allowed_tools=("scada.read_alarms", "maint.read_work_orders"),
            read_only=True,
        ),
        "query": (
            "Que alarma aparecio primero en la bomba 34 "
            "y que se cambio en su ultima intervencion?"
        ),
        "backend_mode": BackendMode.EMULATED,
    }
    base.update(overrides)
    return TaskSpec(**base)


def _make_tool_specs() -> dict[str, ToolSpec]:
    return {
        "scada.read_alarms": ToolSpec(
            tool_id="scada.read_alarms",
            version="1.0.0",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            permissions=("scada:read",),
            allowed_origins=("http://127.0.0.1:8101",),
            effect_class=EffectClass.READ,
            verifier_name="verify_scada_alarms",
        ),
        "maint.read_work_orders": ToolSpec(
            tool_id="maint.read_work_orders",
            version="1.0.0",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            permissions=("maint:read",),
            allowed_origins=("http://127.0.0.1:8102",),
            effect_class=EffectClass.READ,
            verifier_name="verify_maint_work_orders",
        ),
        "effect.apply": ToolSpec(
            tool_id="effect.apply",
            version="1.0.0",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            permissions=("effect:write",),
            allowed_origins=("http://127.0.0.1:8103",),
            effect_class=EffectClass.EFFECT,
            verifier_name="verify_effect_applied",
        ),
    }


@pytest.mark.n1
def test_task_status_enum_and_terminal_transitions() -> None:
    expected = {
        "queued",
        "running",
        "waiting_for_input",
        "recovering",
        "succeeded",
        "partial",
        "failed",
        "cancelled",
    }
    assert {s.value for s in TaskStatus} == expected
    expected_terminals = frozenset(
        {TaskStatus.SUCCEEDED, TaskStatus.PARTIAL, TaskStatus.FAILED, TaskStatus.CANCELLED}
    )
    assert expected_terminals == TERMINAL_TASK_STATUSES

    for status in TaskStatus:
        assert is_terminal_status(status) == (status in TERMINAL_TASK_STATUSES)

    # Valid forward transitions
    validate_status_transition(TaskStatus.QUEUED, TaskStatus.RUNNING)
    validate_status_transition(TaskStatus.RUNNING, TaskStatus.WAITING_FOR_INPUT)
    validate_status_transition(TaskStatus.WAITING_FOR_INPUT, TaskStatus.RUNNING)
    validate_status_transition(TaskStatus.RUNNING, TaskStatus.RECOVERING)
    validate_status_transition(TaskStatus.RECOVERING, TaskStatus.PARTIAL)

    # Terminal states cannot transition anywhere (including to themselves)
    for terminal in TERMINAL_TASK_STATUSES:
        for target in TaskStatus:
            assert can_transition_status(terminal, target) is False
            with pytest.raises(InvalidStateTransitionError):
                validate_status_transition(terminal, target)


@pytest.mark.n1
def test_budget_config_defaults_bounds_and_usage_arithmetic() -> None:
    cfg = BudgetConfig()
    assert cfg.max_active_children == 2
    assert cfg.max_depth == 1
    assert cfg.max_tool_calls == 16
    assert cfg.max_model_calls == 8
    assert cfg.max_wall_seconds == 120.0
    assert cfg.max_total_tokens == 24000
    assert cfg.max_transient_retries == 1
    assert cfg.human_wait_timeout_seconds == 300.0

    with pytest.raises(ValidationError):
        BudgetConfig(max_tool_calls=0)
    with pytest.raises(ValidationError):
        BudgetConfig(max_wall_seconds=0.0)
    with pytest.raises(ValidationError):
        BudgetConfig(max_active_children=-1)

    usage = BudgetUsage(
        active_children=2,
        tool_calls_used=10,
        tool_calls_reserved=6,
        model_calls_used=5,
        model_calls_reserved=3,
        wall_seconds_elapsed=60.0,
        human_wait_seconds_elapsed=150.0,
        prompt_tokens_used=12000,
        completion_tokens_used=8000,
        tokens_reserved=4000,
        transient_retries_used=1,
    )
    assert usage.total_tokens_used == 20000
    assert usage.effective_tokens == 24000
    assert usage.effective_tool_calls == 16
    assert usage.effective_model_calls == 8
    assert usage.within_limits(cfg) is True

    over_tokens = usage.model_copy(update={"tokens_reserved": 4001})
    assert over_tokens.within_limits(cfg) is False

    over_tools = usage.model_copy(update={"tool_calls_reserved": 7})
    assert over_tools.within_limits(cfg) is False


@pytest.mark.n1
def test_models_immutability_and_extra_forbid() -> None:
    now = datetime(2026, 11, 25, 9, 0, tzinfo=UTC)
    task = _make_task_spec(created_at=now)
    run = Run(
        run_id="run-1",
        task_id=task.task_id,
        deadline_at=now + timedelta(seconds=120),
        created_at=now,
        updated_at=now,
    )
    step = Step(
        step_id="step-1",
        run_id=run.run_id,
        step_index=0,
        tool_id="scada.read_alarms",
        operation_key="op-1",
        completion_verifier="verify_scada_alarms",
    )
    tool = _make_tool_specs()["scada.read_alarms"]
    receipt = ActionReceipt(
        receipt_id="rcpt-1",
        task_id=task.task_id,
        run_id=run.run_id,
        step_id=step.step_id,
        attempt=1,
        tool_id=step.tool_id,
        redacted_args={"asset": "bomba 34"},
        operation_key=step.operation_key,
        duration_ms=12.5,
        outcome=ReceiptOutcome.SUCCEEDED,
        recorded_at=now,
    )
    obs = Observation(
        source="scada",
        session_id="sess-1",
        asset_id="bomba-34-a1",
        observed_label="bomba 34",
        value=4.2,
        unit="bar",
        source_time=now,
        observed_at=now,
        quality=DataQuality.GOOD,
    )
    result = Result(
        task_id=task.task_id,
        run_id=run.run_id,
        status=TaskStatus.SUCCEEDED,
        answer="Alarma inicial registrada.",
        verified_observations=(obs,),
    )
    plan = ExecutionPlan(
        plan_id="plan-1",
        task_id=task.task_id,
        steps=(
            PlanStep(
                step_index=0,
                tool_id="scada.read_alarms",
                completion_verifier="verify_scada_alarms",
            ),
        ),
    )

    for model in (task, run, step, tool, receipt, obs, result, plan):
        with pytest.raises(ValidationError):
            setattr(model, "task_id" if hasattr(model, "task_id") else "tool_id", "mutated")

    with pytest.raises(ValidationError):
        TaskScope(facility_id="fac-a", unknown_field="nope")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        EvidenceRequirements(extra_flag=True)  # type: ignore[call-arg]


@pytest.mark.n1
def test_utc_datetime_enforcement_and_json_round_trip() -> None:
    naive = datetime(2026, 11, 25, 9, 0)
    with pytest.raises(ValidationError):
        _make_task_spec(created_at=naive)

    plus_two = timezone(timedelta(hours=2))
    aware_non_utc = datetime(2026, 11, 25, 11, 0, tzinfo=plus_two)
    task = _make_task_spec(created_at=aware_non_utc)
    assert task.created_at == datetime(2026, 11, 25, 9, 0, tzinfo=UTC)

    run = Run(
        run_id="run-rt",
        task_id=task.task_id,
        deadline_at=aware_non_utc + timedelta(minutes=2),
        created_at=aware_non_utc,
        updated_at=aware_non_utc,
    )
    step = Step(
        step_id="step-rt",
        run_id=run.run_id,
        step_index=0,
        status=StepStatus.LEASED,
        attempt=1,
        tool_id="scada.read_alarms",
        operation_key="op-rt",
        lease_owner="worker-1",
        lease_expiry=aware_non_utc + timedelta(seconds=30),
        lease_generation=1,
        completion_verifier="verify_scada_alarms",
    )
    receipt = ActionReceipt(
        receipt_id="rcpt-rt",
        task_id=task.task_id,
        run_id=run.run_id,
        step_id=step.step_id,
        attempt=1,
        tool_id="scada.read_alarms",
        redacted_args={"asset": "bomba 34"},
        operation_key="op-rt",
        duration_ms=5.0,
        evidence_refs=("ev-1",),
        outcome=ReceiptOutcome.SUCCEEDED,
        recorded_at=aware_non_utc,
    )
    obs = Observation(
        source="scada",
        session_id="sess-1",
        asset_id="bomba-34",
        observed_label="bomba 34",
        value="HIGH_VIBRATION",
        source_time=aware_non_utc,
        observed_at=aware_non_utc,
        quality=DataQuality.GOOD,
    )
    result = Result(
        task_id=task.task_id,
        run_id=run.run_id,
        status=TaskStatus.SUCCEEDED,
        answer="Verified",
        verified_observations=(obs,),
        execution_metrics=ExecutionMetrics(tool_calls=1, model_calls=1, total_tokens=100),
    )

    assert TaskSpec.model_validate_json(task.model_dump_json()) == task
    assert Run.model_validate_json(run.model_dump_json()) == run
    assert Step.model_validate_json(step.model_dump_json()) == step
    assert ActionReceipt.model_validate_json(receipt.model_dump_json()) == receipt
    assert Observation.model_validate_json(obs.model_dump_json()) == obs
    assert Result.model_validate_json(result.model_dump_json()) == result


@pytest.mark.n1
def test_run_and_step_structural_invariants() -> None:
    now = datetime(2026, 11, 25, 9, 0, tzinfo=UTC)
    deadline = now + timedelta(seconds=120)

    # depth=0 forbids parent_run_id
    with pytest.raises(ValidationError):
        Run(
            run_id="r0",
            task_id="t1",
            depth=0,
            parent_run_id="parent-1",
            deadline_at=deadline,
            created_at=now,
            updated_at=now,
        )

    # depth=1 requires parent_run_id
    with pytest.raises(ValidationError):
        Run(
            run_id="r1",
            task_id="t1",
            depth=1,
            parent_run_id=None,
            deadline_at=deadline,
            created_at=now,
            updated_at=now,
        )

    # waiting_for_input requires required_action
    with pytest.raises(ValidationError):
        Run(
            run_id="r-wait",
            task_id="t1",
            status=TaskStatus.WAITING_FOR_INPUT,
            required_action=None,
            deadline_at=deadline,
            created_at=now,
            updated_at=now,
        )

    # Valid child run
    child = Run(
        run_id="r-child",
        task_id="t1",
        depth=1,
        parent_run_id="r0",
        status=TaskStatus.WAITING_FOR_INPUT,
        required_action="Select area for bomba 34",
        deadline_at=deadline,
        created_at=now,
        updated_at=now,
    )
    assert child.depth == 1

    # Step lease_owner requires lease_expiry and lease_generation >= 1
    with pytest.raises(ValidationError):
        Step(
            step_id="s1",
            run_id="r0",
            step_index=0,
            tool_id="scada.read_alarms",
            operation_key="op-1",
            lease_owner="worker-1",
            lease_expiry=None,
            lease_generation=1,
            completion_verifier="verify_scada_alarms",
        )
    with pytest.raises(ValidationError):
        Step(
            step_id="s2",
            run_id="r0",
            step_index=0,
            tool_id="scada.read_alarms",
            operation_key="op-2",
            lease_owner="worker-1",
            lease_expiry=deadline,
            lease_generation=0,
            completion_verifier="verify_scada_alarms",
        )


@pytest.mark.n1
def test_result_gating_contradictions_and_partial_info() -> None:
    now = datetime(2026, 11, 25, 9, 0, tzinfo=UTC)

    for disallowed in (TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.RECOVERING):
        with pytest.raises(ValidationError):
            Result(task_id="t1", run_id="r1", status=disallowed, answer="invalid")

    with pytest.raises(ValidationError):
        Result(
            task_id="t1",
            run_id="r1",
            status=TaskStatus.WAITING_FOR_INPUT,
            answer="need input",
            required_action=None,
        )

    contradiction = ContradictionRecord(
        summary="Work order and web label reference different assets",
        claims=(
            ContradictionClaim(
                source="scada",
                asset_id="bomba-34-a1",
                field="label",
                value="Bomba 34 Norte",
                observed_at=now,
            ),
            ContradictionClaim(
                source="maintenance",
                asset_id="bomba-34-a2",
                field="work_order_asset",
                value="Bomba 34 Sur",
                observed_at=now,
            ),
        ),
    )
    partial_res = Result(
        task_id="t1",
        run_id="r1",
        status=TaskStatus.PARTIAL,
        answer="SCADA verified; Maintenance unavailable; contradiction recorded.",
        partial_info={"missing_sources": ["maintenance"], "available_sources": ["scada"]},
        contradictions=(contradiction,),
    )
    assert partial_res.status == TaskStatus.PARTIAL
    assert len(partial_res.contradictions) == 1
    assert partial_res.partial_info == {
        "missing_sources": ["maintenance"],
        "available_sources": ["scada"],
    }


@pytest.mark.n1
def test_execution_plan_dag_and_task_validation() -> None:
    task = _make_task_spec()
    tools = _make_tool_specs()

    # Non-contiguous indices rejected
    with pytest.raises(ValidationError):
        ExecutionPlan(
            plan_id="p-bad-idx",
            task_id=task.task_id,
            steps=(
                PlanStep(
                    step_index=1,
                    tool_id="scada.read_alarms",
                    completion_verifier="verify_scada_alarms",
                ),
            ),
        )

    # Self/forward dependency rejected
    with pytest.raises(ValidationError):
        ExecutionPlan(
            plan_id="p-bad-dep",
            task_id=task.task_id,
            steps=(
                PlanStep(
                    step_index=0,
                    tool_id="scada.read_alarms",
                    completion_verifier="verify_scada_alarms",
                    depends_on=(0,),
                ),
            ),
        )

    # Valid read-only SCADA + Maintenance plan
    valid_plan = ExecutionPlan(
        plan_id="p-valid",
        task_id=task.task_id,
        steps=(
            PlanStep(
                step_index=0,
                tool_id="scada.read_alarms",
                args={"asset": "bomba 34"},
                completion_verifier="verify_scada_alarms",
                target_origin="http://127.0.0.1:8101",
                effect_class=EffectClass.READ,
            ),
            PlanStep(
                step_index=1,
                tool_id="maint.read_work_orders",
                args={"asset": "bomba 34"},
                completion_verifier="verify_maint_work_orders",
                depends_on=(0,),
                target_origin="http://127.0.0.1:8102",
                effect_class=EffectClass.READ,
            ),
        ),
    )
    assert validate_plan_for_task(valid_plan, task, tools) == []
    assert_valid_plan(valid_plan, task, tools)

    # Reject unknown tool, read_only effect, disallowed origin, verifier mismatch
    bad_plan = ExecutionPlan(
        plan_id="p-violations",
        task_id=task.task_id,
        steps=(
            PlanStep(
                step_index=0,
                tool_id="unknown.tool",
                completion_verifier="v",
            ),
            PlanStep(
                step_index=1,
                tool_id="effect.apply",
                completion_verifier="wrong_verifier",
                target_origin="http://evil.example.com",
                effect_class=EffectClass.EFFECT,
            ),
        ),
    )
    errors = validate_plan_for_task(bad_plan, task, tools)
    assert any("unknown tool_id" in e for e in errors)
    assert any("not in scope.allowed_tools" in e for e in errors)
    assert any("scope.read_only=True" in e for e in errors)
    assert any("not in scope.allowed_origins" in e for e in errors)
    assert any("completion_verifier" in e for e in errors)
    with pytest.raises(PlanValidationError):
        assert_valid_plan(bad_plan, task, tools)

    # Budget max_tool_calls overflow
    tight_task = _make_task_spec(budget=BudgetConfig(max_tool_calls=1))
    overflow_errors = validate_plan_for_task(valid_plan, tight_task, tools)
    assert any("max_tool_calls" in e for e in overflow_errors)


@pytest.mark.n1
def test_secret_redaction_and_action_receipt_fail_closed() -> None:
    raw_args: dict[str, Any] = {
        "session_id": "sess-lab-1",
        "task_id": "task-pump34-001",
        "operation_key": "op-123",
        "query": "bomba 34",
        "password": "lab-password-123",
        "nested": {
            "api_key": "sk-secret-key",
            "cookie": "session=abc123",
            "auth_header": "Bearer supersecrettoken",
            "basic_header": "Basic dXNlcjpwYXNz",
            "endpoint": "https://labuser:labpass@scada.local:8101/api",
        },
    }

    assert contains_unredacted_secret(raw_args) is True
    redacted = redact_secrets(raw_args)

    # Non-secret operational IDs preserved
    assert redacted["session_id"] == "sess-lab-1"
    assert redacted["task_id"] == "task-pump34-001"
    assert redacted["operation_key"] == "op-123"
    assert redacted["query"] == "bomba 34"

    # Secrets masked
    assert redacted["password"] == REDACTED_PLACEHOLDER
    assert redacted["nested"]["api_key"] == REDACTED_PLACEHOLDER
    assert redacted["nested"]["cookie"] == REDACTED_PLACEHOLDER
    assert redacted["nested"]["auth_header"] == f"Bearer {REDACTED_PLACEHOLDER}"
    assert redacted["nested"]["basic_header"] == f"Basic {REDACTED_PLACEHOLDER}"
    assert (
        redacted["nested"]["endpoint"]
        == f"https://{REDACTED_PLACEHOLDER}:{REDACTED_PLACEHOLDER}@scada.local:8101/api"
    )
    assert contains_unredacted_secret(redacted) is False

    # ActionReceipt rejects unredacted args
    with pytest.raises(ValidationError):
        ActionReceipt(
            receipt_id="rcpt-fail",
            task_id="task-1",
            run_id="run-1",
            step_id="step-1",
            attempt=1,
            tool_id="scada.read_alarms",
            redacted_args=raw_args,
            operation_key="op-1",
            duration_ms=10.0,
            outcome=ReceiptOutcome.SUCCEEDED,
        )

    # ActionReceipt succeeds with redacted args
    ok_receipt = ActionReceipt(
        receipt_id="rcpt-ok",
        task_id="task-1",
        run_id="run-1",
        step_id="step-1",
        attempt=1,
        tool_id="scada.read_alarms",
        redacted_args=redacted,
        operation_key="op-1",
        duration_ms=10.0,
        outcome=ReceiptOutcome.SUCCEEDED,
    )
    assert ok_receipt.redacted_args["password"] == REDACTED_PLACEHOLDER


@pytest.mark.n1
def test_origin_normalization_blank_strings_and_plan_task_mismatch() -> None:
    scope = TaskScope(
        facility_id="  fac-a  ",
        allowed_origins=("HTTP://127.0.0.1:8101/",),
    )
    assert scope.facility_id == "fac-a"
    assert scope.allowed_origins == ("http://127.0.0.1:8101",)

    for bad_origin in (
        "ftp://127.0.0.1:8101",
        "http://user:pass@127.0.0.1:8101",
        "http://127.0.0.1:8101/path",
        "http://127.0.0.1:8101?x=1",
    ):
        with pytest.raises(ValidationError):
            TaskScope(facility_id="fac-a", allowed_origins=(bad_origin,))

    with pytest.raises(ValidationError):
        TaskScope(facility_id="   ")

    task = _make_task_spec()
    tools = _make_tool_specs()
    mismatched_plan = ExecutionPlan(
        plan_id="p-mismatch",
        task_id="other-task",
        steps=(
            PlanStep(
                step_index=0,
                tool_id="scada.read_alarms",
                completion_verifier="verify_scada_alarms",
                target_origin="http://127.0.0.1:8102",
            ),
        ),
    )
    errors = validate_plan_for_task(mismatched_plan, task, tools)
    assert any("plan.task_id" in e for e in errors)
    assert any("not in tool 'scada.read_alarms'.allowed_origins" in e for e in errors)


@pytest.mark.n1
def test_redaction_hardening_regression() -> None:
    # Token-only URL userinfo and already-redacted URL userinfo
    token_url = {"url": "https://ghp_superSecretToken123@scada.local/login"}
    assert contains_unredacted_secret(token_url) is True
    redacted_token_url = redact_secrets(token_url)
    assert redacted_token_url == {"url": f"https://{REDACTED_PLACEHOLDER}@scada.local/login"}
    assert contains_unredacted_secret(redacted_token_url) is False
    assert contains_unredacted_secret("https://[REDACTED]extra@scada.local/login") is True

    # Bearer / Basic partial-[REDACTED] prefix bypasses
    for leaked in ("Bearer [REDACTED]leaked_suffix", "Basic [REDACTED]leaked_suffix"):
        assert contains_unredacted_secret(leaked) is True
        redacted_hdr = redact_secrets(leaked)
        assert redacted_hdr.endswith(f" {REDACTED_PLACEHOLDER}")
        assert contains_unredacted_secret(redacted_hdr) is False
    assert contains_unredacted_secret("Bearer [REDACTED]") is False
    assert contains_unredacted_secret("Basic [REDACTED] trailing") is False

    # set and frozenset containers
    set_payload: dict[str, Any] = {
        "headers": {"Bearer secret_inside_set", "Accept: application/json"},
        "frozen": frozenset({"Basic c2VjcmV0", "ok"}),
    }
    assert contains_unredacted_secret(set_payload) is True
    redacted_sets = redact_secrets(set_payload)
    assert isinstance(redacted_sets["headers"], set)
    assert isinstance(redacted_sets["frozen"], frozenset)
    assert f"Bearer {REDACTED_PLACEHOLDER}" in redacted_sets["headers"]
    assert f"Basic {REDACTED_PLACEHOLDER}" in redacted_sets["frozen"]
    assert contains_unredacted_secret(redacted_sets) is False

    # Expanded sensitive keys and safe telemetry/ID allowlist
    secret_keys_payload = {
        "token": "jwt.secret",
        "session_token": "sess-sec",
        "csrf_token": "csrf-sec",
        "cookies": "sid=abc",
        "secret_key": "sk-1",
        "app_secret_key": "sk-2",
        "custom_secret": "s-3",
        "custom_token": "t-4",
    }
    assert contains_unredacted_secret(secret_keys_payload) is True
    redacted_keys = redact_secrets(secret_keys_payload)
    assert all(v == REDACTED_PLACEHOLDER for v in redacted_keys.values())
    assert contains_unredacted_secret(redacted_keys) is False

    safe_keys_payload = {
        "prompt_tokens": 100,
        "completion_tokens": 50,
        "total_tokens": 150,
        "max_total_tokens": 24000,
        "tokens_reserved": 500,
        "prompt_tokens_used": 100,
        "completion_tokens_used": 50,
        "session_id": "sess-1",
        "task_id": "task-1",
        "run_id": "run-1",
        "step_id": "step-1",
        "operation_key": "op-1",
    }
    assert contains_unredacted_secret(safe_keys_payload) is False
    assert redact_secrets(safe_keys_payload) == safe_keys_payload


@pytest.mark.n1
def test_action_receipt_aliasing_and_all_secret_fields() -> None:
    shared_args: dict[str, Any] = {"asset": "bomba 34", "nested": {"k": "v"}}
    shared_before: dict[str, Any] = {"state": "idle"}
    shared_after: dict[str, Any] = {"state": "running"}

    receipt = ActionReceipt(
        receipt_id="rcpt-alias",
        task_id="t1",
        run_id="r1",
        step_id="s1",
        attempt=1,
        tool_id="scada.read_alarms",
        redacted_args=shared_args,
        operation_key="op-1",
        observed_before=shared_before,
        observed_after=shared_after,
        duration_ms=2.0,
        outcome=ReceiptOutcome.SUCCEEDED,
        error_detail=f"Authorization: Bearer {REDACTED_PLACEHOLDER}",
    )

    # Mutating caller dicts after construction must not mutate receipt
    shared_args["password"] = "LEAKED"
    shared_args["nested"]["token"] = "LEAKED"
    shared_before["cookie"] = "LEAKED"
    shared_after["secret"] = "LEAKED"
    assert "password" not in receipt.redacted_args
    assert "token" not in receipt.redacted_args["nested"]
    assert receipt.observed_before == {"state": "idle"}
    assert receipt.observed_after == {"state": "running"}

    # Unredacted secrets rejected in observed_before, observed_after, and error_detail
    with pytest.raises(ValidationError):
        ActionReceipt(
            receipt_id="rcpt-b",
            task_id="t1",
            run_id="r1",
            step_id="s1",
            attempt=1,
            tool_id="scada.read_alarms",
            redacted_args={"asset": "bomba 34"},
            operation_key="op-1",
            observed_before={"cookie": "raw_cookie"},
            duration_ms=1.0,
            outcome=ReceiptOutcome.SUCCEEDED,
        )
    with pytest.raises(ValidationError):
        ActionReceipt(
            receipt_id="rcpt-a",
            task_id="t1",
            run_id="r1",
            step_id="s1",
            attempt=1,
            tool_id="scada.read_alarms",
            redacted_args={"asset": "bomba 34"},
            operation_key="op-1",
            observed_after={"url": "https://ghp_secret@scada.local"},
            duration_ms=1.0,
            outcome=ReceiptOutcome.SUCCEEDED,
        )
    with pytest.raises(ValidationError):
        ActionReceipt(
            receipt_id="rcpt-e",
            task_id="t1",
            run_id="r1",
            step_id="s1",
            attempt=1,
            tool_id="scada.read_alarms",
            redacted_args={"asset": "bomba 34"},
            operation_key="op-1",
            duration_ms=1.0,
            outcome=ReceiptOutcome.FAILED_PERMISSION,
            error_detail="401 with Bearer raw_secret_token",
        )


@pytest.mark.n1
def test_origin_case_ipv6_ports_and_fragment_query_rejection() -> None:
    assert validate_http_origin("HTTP://LOCALHOST:8001/") == "http://localhost:8001"
    assert validate_http_origin("https://SCADA.Local") == "https://scada.local"
    assert validate_http_origin("http://[2001:DB8::1]:8080/") == "http://[2001:db8::1]:8080"
    assert validate_http_origin("http://[::1]/") == "http://[::1]"

    for invalid_origin in (
        "http://127.0.0.1:notaport",
        "http://127.0.0.1:99999",
        "http://127.0.0.1:0",
        "http://127.0.0.1:",
        "http://127.0.0.1:8001#",
        "http://127.0.0.1:8001?",
        "http://127.0.0.1:8001/#",
    ):
        with pytest.raises(ValueError):
            validate_http_origin(invalid_origin)


@pytest.mark.n1
def test_run_deadline_step_orphan_lease_and_budget_bool_inf() -> None:
    now = datetime(2026, 11, 25, 9, 0, tzinfo=UTC)
    with pytest.raises(ValidationError):
        Run(
            run_id="r-bad-deadline",
            task_id="t1",
            deadline_at=now - timedelta(seconds=1),
            created_at=now,
            updated_at=now,
        )

    with pytest.raises(ValidationError):
        Step(
            step_id="s-orphan-expiry",
            run_id="r1",
            step_index=0,
            tool_id="scada.read_alarms",
            operation_key="op-1",
            lease_owner=None,
            lease_expiry=now + timedelta(seconds=30),
            lease_generation=1,
            completion_verifier="verify_scada_alarms",
        )

    with pytest.raises(ValidationError):
        BudgetConfig(max_tool_calls=True)
    with pytest.raises(ValidationError):
        BudgetConfig(max_wall_seconds=float("inf"))
    with pytest.raises(ValidationError):
        BudgetConfig(max_wall_seconds=float("nan"))
    with pytest.raises(ValidationError):
        BudgetUsage(tool_calls_used=False)
    with pytest.raises(ValidationError):
        BudgetUsage(wall_seconds_elapsed=float("inf"))


@pytest.mark.n1
def test_planning_fail_closed_origins_and_effect_class_mismatch() -> None:
    tools = _make_tool_specs()
    local_tool = ToolSpec(
        tool_id="local.inspect",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=(),
        effect_class=EffectClass.READ,
        verifier_name="verify_local",
    )
    all_tools = {**tools, "local.inspect": local_tool}

    # Empty TaskScope.allowed_origins=() must fail-closed on target_origin and origin tools
    empty_origin_task = _make_task_spec(
        scope=TaskScope(
            facility_id="fac-a",
            allowed_origins=(),
            allowed_tools=("local.inspect", "scada.read_alarms"),
            read_only=True,
        )
    )
    # Local tool without origin passes when target_origin is None
    local_ok_plan = ExecutionPlan(
        plan_id="p-local-ok",
        task_id=empty_origin_task.task_id,
        steps=(
            PlanStep(
                step_index=0,
                tool_id="local.inspect",
                completion_verifier="verify_local",
                target_origin=None,
            ),
        ),
    )
    assert validate_plan_for_task(local_ok_plan, empty_origin_task, all_tools) == []

    # Local tool with explicit target_origin fails-closed against empty allowed_origins
    local_evil_origin_plan = ExecutionPlan(
        plan_id="p-local-evil",
        task_id=empty_origin_task.task_id,
        steps=(
            PlanStep(
                step_index=0,
                tool_id="local.inspect",
                completion_verifier="verify_local",
                target_origin="http://evil.example.com",
            ),
        ),
    )
    evil_errs = validate_plan_for_task(local_evil_origin_plan, empty_origin_task, all_tools)
    assert any("not in scope.allowed_origins" in e for e in evil_errs)

    # Origin-restricted tool with target_origin=None fails empty scope and missing origin
    missing_origin_plan = ExecutionPlan(
        plan_id="p-missing-origin",
        task_id=empty_origin_task.task_id,
        steps=(
            PlanStep(
                step_index=0,
                tool_id="scada.read_alarms",
                completion_verifier="verify_scada_alarms",
                target_origin=None,
            ),
        ),
    )
    missing_errs = validate_plan_for_task(missing_origin_plan, empty_origin_task, all_tools)
    assert any("scope.allowed_origins is empty" in e for e in missing_errs)
    assert any("target_origin is required" in e for e in missing_errs)

    # Disjoint scope.allowed_origins vs tool.allowed_origins, plus target_origin=None
    disjoint_task = _make_task_spec(
        scope=TaskScope(
            facility_id="fac-a",
            allowed_origins=("http://127.0.0.1:8102",),
            allowed_tools=("scada.read_alarms",),
            read_only=True,
        )
    )
    disjoint_errs = validate_plan_for_task(
        ExecutionPlan(
            plan_id="p-disjoint",
            task_id=disjoint_task.task_id,
            steps=(
                PlanStep(
                    step_index=0,
                    tool_id="scada.read_alarms",
                    completion_verifier="verify_scada_alarms",
                    target_origin=None,
                ),
            ),
        ),
        disjoint_task,
        all_tools,
    )
    assert any("no overlap with scope.allowed_origins" in e for e in disjoint_errs)
    assert any("target_origin is required" in e for e in disjoint_errs)

    # step.effect_class != tool_spec.effect_class rejected even when read_only=False
    rw_task = _make_task_spec(
        scope=TaskScope(
            facility_id="fac-a",
            allowed_origins=("http://127.0.0.1:8103",),
            allowed_tools=("effect.apply",),
            read_only=False,
        )
    )
    mismatch_effect_errs = validate_plan_for_task(
        ExecutionPlan(
            plan_id="p-effect-mismatch",
            task_id=rw_task.task_id,
            steps=(
                PlanStep(
                    step_index=0,
                    tool_id="effect.apply",
                    completion_verifier="verify_effect_applied",
                    target_origin="http://127.0.0.1:8103",
                    effect_class=EffectClass.READ,
                ),
            ),
        ),
        rw_task,
        all_tools,
    )
    assert any("effect_class" in e for e in mismatch_effect_errs)


