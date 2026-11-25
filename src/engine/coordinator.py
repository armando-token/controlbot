"""Task coordinator: 6-step leases, depth=1 delegation, recovery, and fencing (F04, F06, F07)."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from typing import Any

from pydantic import Field

from src.contracts.common import FrozenModel, NonEmptyStr, PlanValidationError, ensure_utc, utc_now
from src.contracts.enums import (
    BackendMode,
    EffectClass,
    ReceiptOutcome,
    StepStatus,
    TaskStatus,
    is_terminal_status,
)
from src.contracts.models import (
    ActionReceipt,
    ContradictionRecord,
    Observation,
    Result,
    Run,
    Step,
    TaskScope,
    TaskSpec,
)
from src.engine.budget import BudgetManager
from src.engine.loop_detector import LoopDetector, canonical_json_hash
from src.engine.redaction import (
    contains_unredacted_secret_strict,
    redact_payload_strict,
    redact_string_strict,
)
from src.engine.tool_registry import ToolExecutionContext, ToolExecutionResult, ToolRegistry
from src.model.http_client import LocalHttpModelClient
from src.model.protocol import (
    ModelClient,
    ModelDecision,
    ModelDelegationRequest,
    ModelProtocolError,
    PromptContext,
    TransientModelError,
)
from src.storage.errors import (
    BudgetExceededError,
    LeaseFencingError,
    TerminalStateError,
)
from src.storage.repo import StepExecutionDetails, StorageRepo


def _collect_human_inputs(
    events: Sequence[Any],
    pending_human_input: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Accumulate human_input payloads chronologically and overlay pending_human_input."""
    merged: dict[str, Any] = {}
    found = False
    for ev in events:
        if getattr(ev, "event_type", None) == "human_input_received":
            payload = getattr(ev, "payload", None)
            if isinstance(payload, dict) and isinstance(payload.get("human_input"), dict):
                merged.update(payload["human_input"])
                found = True
    if pending_human_input is not None:
        merged.update(pending_human_input)
        found = True
    return merged if found else None


class CoordinatorConfig(FrozenModel):
    """Runtime parameters for Coordinator."""

    coordinator_id: NonEmptyStr = "coord-1"
    lease_ttl_seconds: float = Field(default=30.0, gt=0.0)
    model_call_reserve_tokens: int | None = Field(default=None, ge=1)
    default_granted_permissions: tuple[NonEmptyStr, ...] = ()
    max_loop_turns: int = Field(default=32, ge=1)


class RecoverySummary(FrozenModel):
    """Summary returned by Coordinator.recover_inflight_runs()."""

    recovered_runs: int = Field(ge=0)
    reset_steps: int = Field(ge=0)
    unknown_steps_reconciled: int = Field(ge=0)
    waiting_for_human_runs: int = Field(ge=0)
    expired_reservations_cleaned: int = Field(ge=0)


SessionIdResolver = Callable[[TaskSpec, str], str | None]
ResultVerifier = Callable[
    [
        TaskSpec,
        str,
        tuple[Observation, ...],
        Sequence[dict[str, Any]],
        Result,
        dict[str, Any] | None,
    ],
    Result,
]
PermissionRevalidator = Callable[[TaskSpec, dict[str, Any]], tuple[bool, str]]


class Coordinator:
    """Orchestrates task lifecycle, 6-step lease execution, budgets, loops, and recovery."""

    def __init__(
        self,
        repo: StorageRepo,
        model_client: ModelClient,
        tool_registry: ToolRegistry,
        *,
        config: CoordinatorConfig | None = None,
        loop_detector: LoopDetector | None = None,
        budget_manager: BudgetManager | None = None,
        clock: Callable[[], datetime] = utc_now,
        session_id_resolver: SessionIdResolver | None = None,
        result_verifier: ResultVerifier | None = None,
        permission_revalidator: PermissionRevalidator | None = None,
        emulated_model_client: ModelClient | None = None,
    ) -> None:
        self._repo = repo
        self._model_client = model_client
        self._emulated_model_client = emulated_model_client
        self._tool_registry = tool_registry
        self._config = config or CoordinatorConfig()
        self._loop_detector = loop_detector or LoopDetector()
        self._budget_manager = budget_manager or BudgetManager()
        self._clock = clock
        self._session_id_resolver = session_id_resolver
        self._result_verifier = result_verifier
        self._permission_revalidator = permission_revalidator
        self._active_tasks: dict[str, set[asyncio.Task[Any]]] = {}

    @property
    def repo(self) -> StorageRepo:
        return self._repo

    @property
    def tool_registry(self) -> ToolRegistry:
        return self._tool_registry

    @property
    def model_client(self) -> ModelClient:
        return self._model_client

    def validate_backend_mode(self, task_spec: TaskSpec) -> None:
        """Fail closed if TaskSpec requires LOCAL_HTTP without a LocalHttpModelClient."""
        if task_spec.backend_mode == BackendMode.LOCAL_HTTP and not isinstance(
            self._model_client, LocalHttpModelClient
        ):
            raise PlanValidationError(
                "TaskSpec.backend_mode='local_http' requires LocalHttpModelClient; "
                f"bound model client is {type(self._model_client).__name__}."
            )

    def _validate_task_identifiers(self, task_spec: TaskSpec) -> None:
        """Fail closed if task/user/profile identifiers contain unredacted secret material."""
        for field_name, value in (
            ("task_id", task_spec.task_id),
            ("user_id", task_spec.user_id),
            ("profile_id", task_spec.profile_id),
        ):
            if contains_unredacted_secret_strict(value):
                raise PlanValidationError(
                    f"TaskSpec.{field_name} must not contain unredacted secret material."
                )

    def _now(self) -> datetime:
        return ensure_utc(self._clock())

    def submit_task(self, task_spec: TaskSpec, run_id: str | None = None) -> Run:
        """Persist a new TaskSpec and root Run in QUEUED status."""
        self._validate_task_identifiers(task_spec)
        self.validate_backend_mode(task_spec)
        _, run = self._repo.create_task_and_run(task_spec, run_id=run_id)
        return run

    def cancel_task(self, run_id: str, reason: str = "user_cancelled") -> Run:
        """Persist cancel_requested, cascade CANCELLED to root+children, and fence leases."""
        run = self._repo.get_run(run_id)
        self._repo.request_cancel(run.task_id, reason=reason)
        tasks = self._active_tasks.get(run.task_id, set())
        for task in list(tasks):
            if not task.done():
                task.cancel()
        return self._repo.get_run(run_id)

    def resume_task(self, run_id: str, human_input: dict[str, Any]) -> Run:
        """Persist human_input in SQLite WAL, validate wait timeout/scope, and resume to RUNNING."""
        snapshot = self._repo.get_run_snapshot(run_id)
        requested_tools = human_input.get("allowed_tools")
        if (
            isinstance(requested_tools, (list, tuple))
            and snapshot.effective_scope.allowed_tools
            and not set(requested_tools).issubset(snapshot.effective_scope.allowed_tools)
        ):
                self._repo.append_audit_log(
                    task_id=snapshot.task_spec.task_id,
                    run_id=run_id,
                    actor="coordinator",
                    action="resume_scope_widening_rejected",
                    decision="deny",
                    detail={"requested_tools": list(requested_tools)},
                )
                raise PlanValidationError(
                    "human_input cannot widen TaskScope.allowed_tools on resume."
                )
        if human_input.get("read_only") is False and snapshot.effective_scope.read_only:
            self._repo.append_audit_log(
                task_id=snapshot.task_spec.task_id,
                run_id=run_id,
                actor="coordinator",
                action="resume_scope_widening_rejected",
                decision="deny",
                detail={"reason": "cannot_clear_read_only"},
            )
            raise PlanValidationError("human_input cannot disable read_only=True on resume.")

        requested_origins = human_input.get("allowed_origins")
        if (
            "allowed_origins" in human_input
            and isinstance(requested_origins, (list, tuple))
            and requested_origins
            and (
                not snapshot.effective_scope.allowed_origins
                or not set(requested_origins).issubset(snapshot.effective_scope.allowed_origins)
            )
        ):
            self._repo.append_audit_log(
                task_id=snapshot.task_spec.task_id,
                run_id=run_id,
                actor="coordinator",
                action="resume_scope_widening_rejected",
                decision="deny",
                detail={"requested_origins": list(requested_origins)},
            )
            raise PlanValidationError(
                "human_input cannot widen TaskScope.allowed_origins on resume."
            )

        requested_areas = human_input.get("allowed_areas")
        if (
            "allowed_areas" in human_input
            and snapshot.effective_scope.allowed_areas
            and (
                not isinstance(requested_areas, (list, tuple))
                or not requested_areas
                or not set(requested_areas).issubset(snapshot.effective_scope.allowed_areas)
            )
        ):
            self._repo.append_audit_log(
                task_id=snapshot.task_spec.task_id,
                run_id=run_id,
                actor="coordinator",
                action="resume_scope_widening_rejected",
                decision="deny",
                detail={
                    "requested_areas": (
                        list(requested_areas)
                        if isinstance(requested_areas, (list, tuple))
                        else str(requested_areas)
                    )
                },
            )
            raise PlanValidationError(
                "human_input cannot widen TaskScope.allowed_areas on resume."
            )

        if self._permission_revalidator is not None:
            ok, msg = self._permission_revalidator(snapshot.task_spec, human_input)
            self._repo.append_audit_log(
                task_id=snapshot.task_spec.task_id,
                run_id=run_id,
                actor="coordinator",
                action="resume_permissions_reevaluated",
                decision="allow" if ok else "deny",
                detail={"reason": msg},
            )
            if not ok:
                raise PlanValidationError(msg or "Permission re-evaluation denied on resume.")

        return self._repo.resume_from_input(run_id, human_input)

    def _active_wall_seconds(self, snapshot: Any) -> float:
        base_created_at = getattr(snapshot, "root_created_at", None) or snapshot.run.created_at
        return self._budget_manager.compute_active_wall_seconds(
            run_created_at=base_created_at,
            now=self._now(),
            stored_wall_seconds=snapshot.budget_usage.wall_seconds_elapsed,
            human_wait_seconds_elapsed=snapshot.budget_usage.human_wait_seconds_elapsed,
            is_waiting_for_input=(snapshot.run.status == TaskStatus.WAITING_FOR_INPUT),
        )

    def _build_settled_result(
        self,
        *,
        task_spec: TaskSpec,
        run: Run,
        answer: str,
        observations: tuple[Observation, ...],
        contradictions: tuple[ContradictionRecord, ...] = (),
        partial_info: dict[str, Any] | None = None,
        required_action: str | None = None,
    ) -> Result:
        usage = self._repo.get_budget_usage(task_spec.task_id)
        metrics = self._budget_manager.to_execution_metrics(usage)
        return Result(
            task_id=task_spec.task_id,
            run_id=run.run_id,
            status=run.status,
            answer=answer,
            verified_observations=observations,
            partial_info=partial_info,
            contradictions=contradictions,
            required_action=required_action,
            execution_metrics=metrics,
        )

    def _settle_terminal(
        self,
        *,
        task_spec: TaskSpec,
        run_id: str,
        target_status: TaskStatus,
        reason: str,
        answer: str,
        observations: tuple[Observation, ...],
        contradictions: tuple[ContradictionRecord, ...] = (),
        partial_info: dict[str, Any] | None = None,
    ) -> Result:
        snapshot = self._repo.get_run_snapshot(run_id)
        if is_terminal_status(snapshot.run.status):
            if snapshot.result is not None:
                return snapshot.result
            return self._build_settled_result(
                task_spec=task_spec,
                run=snapshot.run,
                answer=answer,
                observations=observations,
                contradictions=contradictions,
                partial_info=partial_info,
            )

        if target_status == TaskStatus.SUCCEEDED and self._repo.list_unknown_steps(run_id):
            allow_partial = task_spec.evidence_requirements.allow_partial_on_source_failure
            target_status = (
                TaskStatus.PARTIAL if observations and allow_partial else TaskStatus.FAILED
            )
            reason = "unresolved_unknown_steps"
            answer = "Cannot settle as succeeded while unresolved unknown steps remain."

        wall_s = self._active_wall_seconds(snapshot)
        updated_usage = self._repo.update_wall_seconds(task_spec.task_id, wall_s)
        metrics = self._budget_manager.to_execution_metrics(updated_usage)
        result = Result(
            task_id=task_spec.task_id,
            run_id=run_id,
            status=target_status,
            answer=answer,
            verified_observations=observations,
            partial_info=partial_info,
            contradictions=contradictions,
            required_action=None,
            execution_metrics=metrics,
        )
        try:
            self._repo.transition_run_status(
                run_id,
                target_status,
                reason,
                progress=1.0 if target_status == TaskStatus.SUCCEEDED else snapshot.run.progress,
                result=result,
                wall_seconds_elapsed=wall_s,
            )
        except Exception:
            latest = self._repo.get_run_snapshot(run_id)
            if latest.result is not None:
                return latest.result
            raise
        return result

    async def recover_inflight_runs(
        self,
        coordinator_id: str | None = None,
        *,
        assume_previous_worker_dead: bool = False,
    ) -> RecoverySummary:
        """Recover interrupted runs, expired leases, UNKNOWN effects (A08), and budgets (A14)."""
        del coordinator_id
        now = self._now()
        cutoff = now + timedelta(days=1) if assume_previous_worker_dead else now
        expired_res_cleaned = 0
        reset_steps = 0
        unknown_reconciled = 0
        waiting_human = 0
        recovered_run_ids: set[str] = set()

        # Step A: Reconcile expired budget reservations (and active reservations on expired steps)
        expired_step_ids = {s.step_id for s in self._repo.list_expired_leased_steps(as_of=cutoff)}
        seen_res_ids: set[str] = set()
        for res in self._repo.list_expired_reservations(as_of=cutoff):
            seen_res_ids.add(res.reservation_id)
            if self._repo.try_expire_stranded_reservation(res.reservation_id):
                expired_res_cleaned += 1

        for res in self._repo.list_active_reservations():
            if res.reservation_id in seen_res_ids:
                continue
            if res.step_id is not None and res.step_id in expired_step_ids:
                seen_res_ids.add(res.reservation_id)
                if self._repo.try_expire_stranded_reservation(res.reservation_id):
                    expired_res_cleaned += 1

        # Step B: Inspect expired step leases (atomic, race-safe across concurrent coordinators)
        for step in self._repo.list_expired_leased_steps(as_of=cutoff):
            if step.status in (StepStatus.LEASED, StepStatus.PREPARED):
                if (
                    self._repo.try_reset_pre_exec_step_to_pending(step.step_id, as_of=cutoff)
                    is not None
                ):
                    recovered_run_ids.add(step.run_id)
                    reset_steps += 1
            elif (
                step.status in (StepStatus.EXECUTING, StepStatus.VERIFYING)
                and self._repo.try_mark_expired_inflight_step_unknown(
                    step.step_id,
                    as_of=cutoff,
                    reason="crash_recovery_lease_expired_in_flight",
                )
                is not None
            ):
                recovered_run_ids.add(step.run_id)

        # Step C: Reconcile all StepStatus.UNKNOWN steps (A08)
        for step in self._repo.list_unknown_steps():
            details = self._repo.get_step_execution_details(step.step_id)
            snapshot = self._repo.get_run_snapshot(step.run_id)
            if (
                is_terminal_status(snapshot.run.status)
                or snapshot.run.status == TaskStatus.WAITING_FOR_INPUT
                or snapshot.cancel_requested
            ):
                continue

            if details.effect_class == EffectClass.READ:
                read_outcome = self._repo.try_reconcile_unknown_read_step(step.step_id)
                if read_outcome == "retry":
                    recovered_run_ids.add(step.run_id)
                    reset_steps += 1
                    unknown_reconciled += 1
                elif read_outcome == "failed":
                    recovered_run_ids.add(step.run_id)
                    unknown_reconciled += 1
            else:
                self._repo.try_transition_run_status(
                    step.run_id,
                    TaskStatus.RUNNING,
                    TaskStatus.RECOVERING,
                    "reconciling_unknown_step",
                )
                outcome_kind = await self._reconcile_unknown_effect(details, snapshot)
                if outcome_kind == "reconciled":
                    recovered_run_ids.add(step.run_id)
                    unknown_reconciled += 1
                elif outcome_kind == "retry":
                    recovered_run_ids.add(step.run_id)
                    reset_steps += 1
                    unknown_reconciled += 1
                elif outcome_kind == "waiting_for_human":
                    recovered_run_ids.add(step.run_id)
                    waiting_human += 1

        # Step D: Transition RECOVERING runs with no remaining UNKNOWN steps back to RUNNING
        for run in self._repo.list_inflight_runs():
            if (
                run.status == TaskStatus.RECOVERING
                and self._repo.try_transition_run_status(
                    run.run_id,
                    TaskStatus.RECOVERING,
                    TaskStatus.RUNNING,
                    "recovery_completed",
                    require_no_unknown_steps=True,
                )
                is not None
            ):
                recovered_run_ids.add(run.run_id)

        # Step E: Re-sync active_children
        self._repo.sync_active_children()

        return RecoverySummary(
            recovered_runs=len(recovered_run_ids),
            reset_steps=reset_steps,
            unknown_steps_reconciled=unknown_reconciled,
            waiting_for_human_runs=waiting_human,
            expired_reservations_cleaned=expired_res_cleaned,
        )

    async def _reconcile_unknown_effect(
        self, details: StepExecutionDetails, snapshot: Any
    ) -> str:
        step = details.step
        reconciler = self._tool_registry.get_reconciler(step.tool_id)
        supports_idem = self._tool_registry.supports_idempotency(step.tool_id)
        idem_key = details.idempotency_key or step.operation_key

        ctx = ToolExecutionContext(
            task_id=details.task_id,
            run_id=step.run_id,
            step_id=step.step_id,
            attempt=max(1, step.attempt),
            operation_key=step.operation_key,
            scope=snapshot.effective_scope,
            granted_permissions=self._config.default_granted_permissions,
            target_origin=details.target_origin,
            deadline_at=snapshot.run.deadline_at,
            session_id=(
                self._session_id_resolver(snapshot.task_spec, step.tool_id)
                if self._session_id_resolver is not None
                else None
            ),
            idempotency_key=idem_key,
            now=self._now(),
        )

        if reconciler is not None:
            try:
                res = reconciler(step.operation_key, idem_key, ctx)
                if inspect.isawaitable(res):
                    applied, info = await res
                else:
                    applied, info = res
            except Exception as exc:
                applied, info = False, {"ambiguous": True, "error": str(exc)}

            if applied:
                scrubbed_info = redact_payload_strict(info) if info is not None else None
                receipt = ActionReceipt(
                    receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                    task_id=details.task_id,
                    run_id=step.run_id,
                    step_id=step.step_id,
                    attempt=max(1, step.attempt),
                    tool_id=step.tool_id,
                    redacted_args=details.redacted_args,
                    operation_key=step.operation_key,
                    observed_before=None,
                    observed_after=scrubbed_info,
                    duration_ms=0.0,
                    evidence_refs=(),
                    outcome=ReceiptOutcome.SUCCEEDED,
                    error_detail=None,
                    recorded_at=self._now(),
                )
                reconciled_step = self._repo.try_reconcile_step_unknown(
                    step.step_id,
                    StepStatus.SUCCEEDED,
                    ReceiptOutcome.SUCCEEDED.value,
                    "reconciler_confirmed_applied",
                    receipt=receipt,
                    step_output=scrubbed_info,
                )
                return "reconciled" if reconciled_step is not None else "noop"

            is_ambiguous = bool(info and info.get("ambiguous"))
            if not is_ambiguous and supports_idem:
                retry_outcome = self._repo.try_reconcile_unknown_effect_retry(
                    step.step_id,
                    reason="reconciled_unapplied_idempotent_retry",
                )
                if retry_outcome == "retry":
                    return "retry"
                if retry_outcome == "noop":
                    return "noop"

        required_action = f"Human review required for unconfirmed effect {step.operation_key}"
        paused = self._repo.try_pause_for_unknown_step(
            step.run_id,
            step.step_id,
            required_action,
            reason="ambiguous_effect_requires_human_review",
        )
        return "waiting_for_human" if paused is not None else "noop"

    async def run_until_settled(self, run_id: str) -> Result:
        """Execute a run (depth=0 or depth=1) until terminal status or waiting_for_input."""
        snapshot = self._repo.get_run_snapshot(run_id)
        task_spec = snapshot.task_spec
        task_id = task_spec.task_id

        current_task = asyncio.current_task()
        if current_task is not None:
            self._active_tasks.setdefault(task_id, set()).add(current_task)

        try:
            return await self._run_loop(run_id)
        except asyncio.CancelledError:
            if self._repo.is_cancel_requested(task_id):
                latest = self._repo.get_run_snapshot(run_id)
                return self._build_settled_result(
                    task_spec=latest.task_spec,
                    run=latest.run,
                    answer=f"Run cancelled: {latest.run.transition_reason}",
                    observations=latest.observations,
                )
            raise
        finally:
            if current_task is not None and task_id in self._active_tasks:
                self._active_tasks[task_id].discard(current_task)

    async def _run_loop(self, run_id: str) -> Result:
        snapshot = self._repo.get_run_snapshot(run_id)
        task_spec = snapshot.task_spec
        task_id = task_spec.task_id

        if is_terminal_status(snapshot.run.status):
            if snapshot.result is not None:
                return snapshot.result
            return self._build_settled_result(
                task_spec=task_spec,
                run=snapshot.run,
                answer=f"Run already terminal ({snapshot.run.status.value}).",
                observations=snapshot.observations,
            )

        if snapshot.run.status == TaskStatus.WAITING_FOR_INPUT:
            if snapshot.result is not None:
                return snapshot.result
            return self._build_settled_result(
                task_spec=task_spec,
                run=snapshot.run,
                answer="Run is waiting for human input.",
                observations=snapshot.observations,
                required_action=snapshot.run.required_action or "input_required",
            )

        self.validate_backend_mode(task_spec)

        if snapshot.run.status in (TaskStatus.QUEUED, TaskStatus.RECOVERING):
            self._repo.transition_run_status(
                run_id,
                TaskStatus.RUNNING,
                "coordinator_started"
                if snapshot.run.status == TaskStatus.QUEUED
                else "resumed_after_recovery",
            )

        observations: list[Observation] = list(snapshot.observations)
        contradictions: list[ContradictionRecord] = []
        try:
            return await self._run_loop_body(
                run_id=run_id,
                snapshot=snapshot,
                task_spec=task_spec,
                task_id=task_id,
                observations=observations,
                contradictions=contradictions,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            latest = self._repo.get_run_snapshot(run_id)
            if is_terminal_status(latest.run.status):
                if latest.result is not None:
                    return latest.result
                return self._build_settled_result(
                    task_spec=task_spec,
                    run=latest.run,
                    answer=f"Run reached terminal status {latest.run.status.value}.",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                )
            if latest.run.status == TaskStatus.WAITING_FOR_INPUT:
                if latest.result is not None:
                    return latest.result
                return self._build_settled_result(
                    task_spec=task_spec,
                    run=latest.run,
                    answer="Run is waiting for human input.",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                    required_action=latest.run.required_action or "input_required",
                )
            safe_err = redact_string_strict(str(exc))
            self._repo.append_audit_log(
                task_id=task_id,
                run_id=run_id,
                actor="coordinator",
                action="unexpected_execution_error",
                decision="deny",
                detail={"error_type": type(exc).__name__, "error": safe_err},
            )
            return self._settle_terminal(
                task_spec=task_spec,
                run_id=run_id,
                target_status=TaskStatus.FAILED,
                reason="unexpected_execution_error",
                answer=f"Run failed due to unexpected execution error: {safe_err}",
                observations=tuple(observations),
                contradictions=tuple(contradictions),
            )

    async def _run_loop_body(
        self,
        *,
        run_id: str,
        snapshot: Any,
        task_spec: TaskSpec,
        task_id: str,
        observations: list[Observation],
        contradictions: list[ContradictionRecord],
    ) -> Result:
        pending_human_input = self._repo.consume_pending_human_input(run_id)
        last_human_input: dict[str, Any] | None = _collect_human_inputs(
            snapshot.events,
            pending_human_input,
        )
        history: list[dict[str, Any]] = [
            {
                "tool_id": r.tool_id,
                "args": r.redacted_args,
                "outcome": r.outcome.value,
                "observed_after": r.observed_after,
                "error": r.error_detail,
            }
            for r in snapshot.receipts
        ]

        # Resolve any UNKNOWN effect step if human_input explicitly answered it;
        # otherwise re-pause for confirmation instead of allowing SUCCEEDED with UNKNOWN steps.
        unknown_steps = self._repo.list_unknown_steps(run_id)
        if unknown_steps:
            if pending_human_input is not None and isinstance(
                pending_human_input.get("effect_applied"), bool
            ):
                applied = pending_human_input["effect_applied"]
                step_target = StepStatus.SUCCEEDED if applied else StepStatus.FAILED
                for unk_step in unknown_steps:
                    self._repo.try_reconcile_step_unknown(
                        unk_step.step_id,
                        step_target,
                        ReceiptOutcome.SUCCEEDED.value
                        if applied
                        else ReceiptOutcome.FAILED_SEMANTIC.value,
                        "human_reconciled_unknown_effect",
                    )
            else:
                step_list = ", ".join(s.step_id for s in unknown_steps)
                req_action = (
                    "Human confirmation ('effect_applied': true/false) required for "
                    f"unconfirmed step(s): {step_list}"
                )
                latest_snap = self._repo.get_run_snapshot(run_id)
                active_wall = self._active_wall_seconds(latest_snap)
                usage_now = self._repo.get_budget_usage(task_id)
                paused_res = Result(
                    task_id=task_id,
                    run_id=run_id,
                    status=TaskStatus.WAITING_FOR_INPUT,
                    answer=req_action,
                    verified_observations=tuple(observations),
                    contradictions=tuple(contradictions),
                    required_action=req_action,
                    execution_metrics=self._budget_manager.to_execution_metrics(usage_now),
                )
                self._repo.pause_for_input(
                    run_id,
                    req_action,
                    reason="unknown_effect_confirmation_required",
                    result=paused_res,
                    wall_seconds_elapsed=active_wall,
                )
                return paused_res

        turn_index = len(snapshot.receipts)

        for _ in range(self._config.max_loop_turns):
            snapshot = self._repo.get_run_snapshot(run_id)
            if snapshot.cancel_requested or snapshot.run.status == TaskStatus.CANCELLED:
                return self._settle_terminal(
                    task_spec=task_spec,
                    run_id=run_id,
                    target_status=TaskStatus.CANCELLED,
                    reason=snapshot.run.transition_reason or "cancelled",
                    answer="Task cancelled.",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                )
            if is_terminal_status(snapshot.run.status):
                return self._build_settled_result(
                    task_spec=task_spec,
                    run=snapshot.run,
                    answer=f"Run reached terminal status {snapshot.run.status.value}.",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                )

            # Execute any pre-queued / recovery-reset PENDING steps before asking the model
            pending_steps = self._repo.list_pending_steps(run_id)
            if pending_steps:
                for p_step in pending_steps:
                    early_result = await self._execute_step_six_phase(
                        snapshot=self._repo.get_run_snapshot(run_id),
                        existing_step=p_step,
                        observations=observations,
                        history=history,
                        contradictions=contradictions,
                    )
                    if early_result is not None:
                        return early_result
                turn_index += len(pending_steps)
                continue

            # Check active wall-clock budget (excluding human_wait_seconds_elapsed)
            active_wall = self._active_wall_seconds(snapshot)
            self._repo.update_wall_seconds(task_id, active_wall)
            if active_wall >= task_spec.budget.max_wall_seconds:
                allow_partial = task_spec.evidence_requirements.allow_partial_on_source_failure
                target = TaskStatus.PARTIAL if observations and allow_partial else TaskStatus.FAILED
                return self._settle_terminal(
                    task_spec=task_spec,
                    run_id=run_id,
                    target_status=target,
                    reason="wall_clock_budget_exceeded",
                    answer="Active wall-clock budget exceeded.",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                    partial_info={"reason": "wall_clock_budget_exceeded"},
                )

            # Build redacted PromptContext and reserve model call budget
            safe_query = redact_string_strict(task_spec.query)
            safe_history = tuple(redact_payload_strict(item) for item in history)
            safe_human = (
                redact_payload_strict(last_human_input)
                if last_human_input is not None
                else None
            )
            prompt_ctx = PromptContext(
                task_id=task_spec.task_id,
                run_id=run_id,
                depth=snapshot.run.depth,
                query=safe_query,
                facility_id=snapshot.effective_scope.facility_id,
                allowed_areas=snapshot.effective_scope.allowed_areas,
                history=safe_history,
                observations=tuple(observations),
                human_input=safe_human,
                turn_index=turn_index,
                min_sources=task_spec.evidence_requirements.min_sources,
            )
            reserve_tokens = self._budget_manager.estimate_model_reserve_tokens(
                prompt_ctx,
                task_spec.budget,
                self._config.model_call_reserve_tokens,
            )

            try:
                model_res = self._repo.reserve_budget(
                    task_id,
                    run_id,
                    "model",
                    model_calls=1,
                    tokens=reserve_tokens,
                    wall_seconds_elapsed=active_wall,
                    ttl_s=self._config.lease_ttl_seconds,
                )
            except BudgetExceededError as exc:
                allow_partial = task_spec.evidence_requirements.allow_partial_on_source_failure
                target = TaskStatus.PARTIAL if observations and allow_partial else TaskStatus.FAILED
                return self._settle_terminal(
                    task_spec=task_spec,
                    run_id=run_id,
                    target_status=target,
                    reason="model_budget_exceeded",
                    answer=f"Budget exhausted before model call: {exc}",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                    partial_info={"reason": "model_budget_exceeded"},
                )
            except TerminalStateError:
                latest = self._repo.get_run_snapshot(run_id)
                return self._build_settled_result(
                    task_spec=task_spec,
                    run=latest.run,
                    answer="Run cancelled or terminal before model call.",
                    observations=tuple(observations),
                )

            all_specs = self._tool_registry.list_specs()
            if snapshot.effective_scope.allowed_tools:
                visible_tools = [
                    spec
                    for tid, spec in all_specs.items()
                    if tid in snapshot.effective_scope.allowed_tools
                ]
            else:
                visible_tools = list(all_specs.values())

            budget_remaining = self._budget_manager.to_budget_remaining(
                task_spec.budget,
                self._repo.get_budget_usage(task_id),
                snapshot.run.depth,
            )

            # Step 3 (outside SQLite tx): invoke model client
            active_model_client = (
                self._emulated_model_client
                if (
                    task_spec.backend_mode == BackendMode.EMULATED
                    and self._emulated_model_client is not None
                )
                else self._model_client
            )
            try:
                decision = await active_model_client.decide(
                    prompt_ctx, visible_tools, budget_remaining
                )
            except TransientModelError as exc:
                self._repo.reconcile_budget(model_res.reservation_id, release_only=True)
                try:
                    self._repo.increment_transient_retry(task_id, run_id=run_id)
                    continue
                except BudgetExceededError:
                    target = (
                        TaskStatus.PARTIAL
                        if observations
                        and task_spec.evidence_requirements.allow_partial_on_source_failure
                        else TaskStatus.FAILED
                    )
                    return self._settle_terminal(
                        task_spec=task_spec,
                        run_id=run_id,
                        target_status=target,
                        reason="model_transient_retries_exhausted",
                        answer=f"Model transient failure: {exc}",
                        observations=tuple(observations),
                        contradictions=tuple(contradictions),
                        partial_info={"reason": "model_transient_retries_exhausted"},
                    )
            except asyncio.CancelledError:
                self._repo.reconcile_budget(model_res.reservation_id, release_only=True)
                raise
            except Exception as exc:
                self._repo.reconcile_budget(model_res.reservation_id, release_only=True)
                if isinstance(exc, ModelProtocolError) and (
                    "outside allowed tool list" in str(exc)
                ):
                    policy_reason = (
                        "read_only_policy_denied"
                        if task_spec.scope.read_only
                        else "permission_denied"
                    )
                    self._repo.append_audit_log(
                        task_id=task_id,
                        run_id=run_id,
                        actor="coordinator",
                        action="tool_permission_denied",
                        decision="deny",
                        detail={"reason": policy_reason, "error": str(exc)},
                    )
                    return self._settle_terminal(
                        task_spec=task_spec,
                        run_id=run_id,
                        target_status=TaskStatus.FAILED,
                        reason=policy_reason,
                        answer=f"Permission denied: {exc}",
                        observations=tuple(observations),
                        contradictions=tuple(contradictions),
                    )
                return self._settle_terminal(
                    task_spec=task_spec,
                    run_id=run_id,
                    target_status=TaskStatus.FAILED,
                    reason="model_error",
                    answer=f"Model decision error: {exc}",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                )

            # Reconcile model reservation (actual or conservative estimated)
            post_wall = self._active_wall_seconds(self._repo.get_run_snapshot(run_id))
            self._repo.reconcile_budget(
                model_res.reservation_id,
                prompt_tokens=decision.usage.prompt_tokens,
                completion_tokens=decision.usage.completion_tokens,
                model_calls_used=1,
                usage_estimated=(decision.usage.usage_mode == "estimated"),
                wall_seconds_elapsed=post_wall,
            )

            # A09 Fence: discard late model decision if cancelled during inference
            post_snapshot = self._repo.get_run_snapshot(run_id)
            if post_snapshot.cancel_requested or is_terminal_status(post_snapshot.run.status):
                self._repo.append_audit_log(
                    task_id=task_id,
                    run_id=run_id,
                    actor="coordinator",
                    action="stale_model_decision_rejected",
                    decision="deny",
                    detail={"decision_type": decision.decision_type},
                )
                return self._build_settled_result(
                    task_spec=task_spec,
                    run=post_snapshot.run,
                    answer="Run cancelled/terminal; model decision fenced.",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                )

            pending_human_input = None
            turn_index += 1

            # Dispatch model decision
            if decision.decision_type == "request_input":
                req_action = decision.required_action or "Human clarification required."
                usage_now = self._repo.get_budget_usage(task_id)
                paused_result = Result(
                    task_id=task_id,
                    run_id=run_id,
                    status=TaskStatus.WAITING_FOR_INPUT,
                    answer=req_action,
                    verified_observations=tuple(observations),
                    partial_info=decision.partial_info,
                    contradictions=tuple(contradictions),
                    required_action=req_action,
                    execution_metrics=self._budget_manager.to_execution_metrics(usage_now),
                )
                self._repo.pause_for_input(
                    run_id,
                    req_action,
                    reason="model_requested_input",
                    result=paused_result,
                    wall_seconds_elapsed=post_wall,
                )
                return paused_result

            if decision.decision_type == "final":
                remaining_unknown = self._repo.list_unknown_steps(run_id)
                if remaining_unknown:
                    allow_partial = (
                        task_spec.evidence_requirements.allow_partial_on_source_failure
                    )
                    target = (
                        TaskStatus.PARTIAL if observations and allow_partial else TaskStatus.FAILED
                    )
                    return self._settle_terminal(
                        task_spec=task_spec,
                        run_id=run_id,
                        target_status=target,
                        reason="unresolved_unknown_steps",
                        answer="Cannot settle as succeeded while unresolved unknown steps remain.",
                        observations=tuple(observations),
                        contradictions=tuple(contradictions),
                        partial_info={
                            "unknown_step_ids": [s.step_id for s in remaining_unknown],
                        },
                    )
                is_partial = bool(
                    decision.partial_info
                    and decision.partial_info.get("is_partial", True)
                )
                candidate_status = TaskStatus.PARTIAL if is_partial else TaskStatus.SUCCEEDED
                if self._result_verifier is not None:
                    usage_now = self._repo.get_budget_usage(task_id)
                    candidate_result = Result(
                        task_id=task_id,
                        run_id=run_id,
                        status=candidate_status,
                        answer=decision.final_answer or "",
                        verified_observations=tuple(observations),
                        partial_info=decision.partial_info,
                        contradictions=tuple(contradictions),
                        required_action=None,
                        execution_metrics=self._budget_manager.to_execution_metrics(usage_now),
                    )
                    verified_result = self._result_verifier(
                        task_spec,
                        run_id,
                        tuple(observations),
                        history,
                        candidate_result,
                        last_human_input,
                    )
                    if verified_result.status == TaskStatus.WAITING_FOR_INPUT:
                        req_action = (
                            verified_result.required_action or "Human clarification required."
                        )
                        self._repo.pause_for_input(
                            run_id,
                            req_action,
                            reason="verifier_requires_input",
                            result=verified_result,
                            wall_seconds_elapsed=post_wall,
                        )
                        return verified_result
                    if verified_result.status == TaskStatus.PARTIAL:
                        settle_reason = "completed_partial"
                    elif verified_result.status == TaskStatus.FAILED:
                        settle_reason = "completed_failed"
                    else:
                        settle_reason = "completed_succeeded"
                    return self._settle_terminal(
                        task_spec=task_spec,
                        run_id=run_id,
                        target_status=verified_result.status,
                        reason=settle_reason,
                        answer=verified_result.answer,
                        observations=verified_result.verified_observations,
                        contradictions=verified_result.contradictions,
                        partial_info=verified_result.partial_info,
                    )
                return self._settle_terminal(
                    task_spec=task_spec,
                    run_id=run_id,
                    target_status=candidate_status,
                    reason="completed_partial" if is_partial else "completed_succeeded",
                    answer=decision.final_answer or "",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                    partial_info=decision.partial_info,
                )

            if decision.decision_type == "delegate":
                delegation_result = await self._execute_delegations(
                    snapshot=post_snapshot,
                    delegations=decision.delegations,
                    observations=observations,
                    contradictions=contradictions,
                    history=history,
                )
                if delegation_result is not None:
                    return delegation_result
                continue

            if decision.decision_type == "tool_call" and decision.tool_call is not None:
                early_result = await self._execute_step_six_phase(
                    snapshot=post_snapshot,
                    decision=decision,
                    observations=observations,
                    history=history,
                    contradictions=contradictions,
                )
                if early_result is not None:
                    return early_result

        return self._settle_terminal(
            task_spec=task_spec,
            run_id=run_id,
            target_status=TaskStatus.PARTIAL if observations else TaskStatus.FAILED,
            reason="max_loop_turns_reached",
            answer="Coordinator max loop turns reached.",
            observations=tuple(observations),
            contradictions=tuple(contradictions),
            partial_info={"reason": "max_loop_turns_reached"},
        )

    async def _execute_delegations(
        self,
        *,
        snapshot: Any,
        delegations: tuple[ModelDelegationRequest, ...],
        observations: list[Observation],
        contradictions: list[ContradictionRecord],
        history: list[dict[str, Any]],
    ) -> Result | None:
        task_spec = snapshot.task_spec
        parent_run = snapshot.run
        parent_scope = snapshot.effective_scope

        if parent_run.depth >= task_spec.budget.max_depth:
            self._repo.append_audit_log(
                task_id=task_spec.task_id,
                run_id=parent_run.run_id,
                actor="coordinator",
                action="delegate_rejected",
                decision="deny",
                detail={"depth": parent_run.depth, "max_depth": task_spec.budget.max_depth},
            )
            return self._settle_terminal(
                task_spec=task_spec,
                run_id=parent_run.run_id,
                target_status=TaskStatus.FAILED,
                reason="max_depth_exceeded",
                answer="Child delegation disallowed beyond max_depth.",
                observations=tuple(observations),
                contradictions=tuple(contradictions),
            )

        batch_limit = max(1, task_spec.budget.max_active_children)
        for idx in range(0, len(delegations), batch_limit):
            batch = delegations[idx : idx + batch_limit]
            child_runs: list[Run] = []
            for req in batch:
                child_scope = TaskScope(
                    facility_id=parent_scope.facility_id,
                    allowed_origins=req.allowed_origins or parent_scope.allowed_origins,
                    allowed_areas=req.allowed_areas or parent_scope.allowed_areas,
                    allowed_tools=req.allowed_tools or parent_scope.allowed_tools,
                    read_only=(
                        req.read_only
                        if req.read_only is not None
                        else parent_scope.read_only
                    ),
                )
                try:
                    c_run = self._repo.create_child_run(
                        parent_run.run_id,
                        child_scope=child_scope,
                        reason=f"delegate:{req.child_label}",
                    )
                    child_runs.append(c_run)
                except (BudgetExceededError, PlanValidationError, TerminalStateError) as exc:
                    return self._settle_terminal(
                        task_spec=task_spec,
                        run_id=parent_run.run_id,
                        target_status=TaskStatus.FAILED,
                        reason="delegation_rejected",
                        answer=f"Child delegation rejected: {exc}",
                        observations=tuple(observations),
                        contradictions=tuple(contradictions),
                    )

            child_results = await asyncio.gather(
                *(self.run_until_settled(c.run_id) for c in child_runs)
            )
            for req, c_run, c_res in zip(batch, child_runs, child_results, strict=True):
                observations.extend(c_res.verified_observations)
                contradictions.extend(c_res.contradictions)
                history.append(
                    {
                        "delegation": req.child_label,
                        "child_run_id": c_run.run_id,
                        "status": c_res.status.value,
                        "answer": c_res.answer,
                    }
                )
                if self._repo.is_cancel_requested(task_spec.task_id):
                    latest = self._repo.get_run_snapshot(parent_run.run_id)
                    return self._build_settled_result(
                        task_spec=task_spec,
                        run=latest.run,
                        answer="Parent run cancelled during child delegation.",
                        observations=tuple(observations),
                        contradictions=tuple(contradictions),
                    )

        return None

    async def _execute_step_six_phase(
        self,
        *,
        snapshot: Any,
        observations: list[Observation],
        history: list[dict[str, Any]],
        contradictions: list[ContradictionRecord],
        decision: ModelDecision | None = None,
        existing_step: Step | None = None,
    ) -> Result | None:
        task_spec = snapshot.task_spec
        task_id = task_spec.task_id
        run_id = snapshot.run.run_id

        if existing_step is not None:
            details = self._repo.get_step_execution_details(existing_step.step_id)
            tool_id = existing_step.tool_id
            args = dict(details.exec_args)
            target_origin = details.target_origin
            op_key = existing_step.operation_key
            step_to_claim = existing_step
        else:
            assert decision is not None and decision.tool_call is not None
            call = decision.tool_call
            tool_id = call.tool_id
            args = dict(call.args)
            target_origin = call.target_origin
            spec = self._tool_registry.get_spec(tool_id)
            effect_class = spec.effect_class if spec is not None else EffectClass.READ
            verifier_name = call.completion_verifier or (
                spec.verifier_name if spec is not None else "default_verifier"
            )
            try:
                step_to_claim = self._repo.enqueue_step(
                    run_id,
                    tool_id,
                    args,
                    verifier_name,
                    effect_class,
                    target_origin=target_origin,
                )
            except TerminalStateError:
                latest = self._repo.get_run_snapshot(run_id)
                return self._build_settled_result(
                    task_spec=task_spec,
                    run=latest.run,
                    answer="Run terminal/cancelled while enqueuing step.",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                )
            op_key = step_to_claim.operation_key

        spec = self._tool_registry.get_spec(tool_id)
        local_retries = 0

        while True:
            loop_snapshot = self._repo.get_run_snapshot(run_id)
            # Step 1: Acquire lease
            leased = self._repo.acquire_step_lease(
                self._config.coordinator_id,
                self._config.lease_ttl_seconds,
                run_id=run_id,
                step_id=step_to_claim.step_id,
            )
            if leased is None:
                latest = self._repo.get_run_snapshot(run_id)
                return self._build_settled_result(
                    task_spec=task_spec,
                    run=latest.run,
                    answer="Step lease unavailable (run cancelled or claimed elsewhere).",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                )

            # Step 2: Reserve tool budget + Prepare attempt + Mark executing
            active_wall = self._active_wall_seconds(loop_snapshot)
            try:
                tool_res = self._repo.reserve_budget(
                    task_id,
                    run_id,
                    "tool",
                    step_id=leased.step_id,
                    tool_calls=1,
                    wall_seconds_elapsed=active_wall,
                    lease_generation=leased.lease_generation,
                    ttl_s=self._config.lease_ttl_seconds,
                )
            except BudgetExceededError as exc:
                self._repo.append_audit_log(
                    task_id=task_id,
                    run_id=run_id,
                    step_id=leased.step_id,
                    actor="coordinator",
                    action="tool_budget_exceeded",
                    decision="deny",
                    detail={"tool_id": tool_id},
                )
                target = (
                    TaskStatus.PARTIAL
                    if observations
                    and task_spec.evidence_requirements.allow_partial_on_source_failure
                    else TaskStatus.FAILED
                )
                return self._settle_terminal(
                    task_spec=task_spec,
                    run_id=run_id,
                    target_status=target,
                    reason="tool_budget_exceeded",
                    answer=f"Tool call budget exhausted: {exc}",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                    partial_info={"reason": "tool_budget_exceeded"},
                )
            except TerminalStateError:
                latest = self._repo.get_run_snapshot(run_id)
                return self._build_settled_result(
                    task_spec=task_spec,
                    run=latest.run,
                    answer="Run cancelled before tool preparation.",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                )

            try:
                self._repo.prepare_step_attempt(
                    leased.step_id,
                    leased.lease_generation,
                    op_key,
                    idempotency_key=op_key,
                )
                self._repo.mark_step_executing(leased.step_id, leased.lease_generation)
            except (LeaseFencingError, TerminalStateError):
                self._repo.reconcile_budget(tool_res.reservation_id, release_only=True)
                latest = self._repo.get_run_snapshot(run_id)
                return self._build_settled_result(
                    task_spec=task_spec,
                    run=latest.run,
                    answer="Step fenced or cancelled before execution.",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                )

            # Step 3: Execute outside DB transaction
            try:
                exec_ctx = ToolExecutionContext(
                    task_id=task_id,
                    run_id=run_id,
                    step_id=leased.step_id,
                    attempt=leased.attempt,
                    operation_key=op_key,
                    scope=loop_snapshot.effective_scope,
                    granted_permissions=self._config.default_granted_permissions,
                    target_origin=target_origin,
                    deadline_at=loop_snapshot.run.deadline_at,
                    session_id=(
                        self._session_id_resolver(task_spec, tool_id)
                        if self._session_id_resolver is not None
                        else None
                    ),
                    idempotency_key=op_key,
                    now=self._now(),
                )
                exec_result: ToolExecutionResult = await self._tool_registry.invoke(
                    tool_id, args, exec_ctx
                )
            except asyncio.CancelledError:
                self._repo.reconcile_budget(tool_res.reservation_id, release_only=True)
                raise
            except Exception as exc:
                self._repo.reconcile_budget(tool_res.reservation_id, release_only=True)
                safe_err = redact_string_strict(str(exc))
                with contextlib.suppress(Exception):
                    err_receipt = ActionReceipt(
                        receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                        task_id=task_id,
                        run_id=run_id,
                        step_id=leased.step_id,
                        attempt=max(1, leased.attempt),
                        tool_id=tool_id,
                        redacted_args=redact_payload_strict(dict(args)),
                        operation_key=op_key,
                        observed_before=None,
                        observed_after=None,
                        duration_ms=0.0,
                        evidence_refs=(),
                        outcome=ReceiptOutcome.FAILED_SEMANTIC,
                        error_detail=safe_err,
                        recorded_at=self._now(),
                    )
                    self._repo.commit_step_result(
                        leased.step_id,
                        leased.lease_generation,
                        StepStatus.FAILED,
                        ReceiptOutcome.FAILED_SEMANTIC.value,
                        err_receipt,
                        step_output=None,
                        expected_worker=self._config.coordinator_id,
                    )
                raise

            # Reconcile tool reservation (1 call consumed)
            post_wall = self._active_wall_seconds(self._repo.get_run_snapshot(run_id))
            self._repo.reconcile_budget(
                tool_res.reservation_id,
                tool_calls_used=1,
                wall_seconds_elapsed=post_wall,
            )

            # Handle expired authentication -> requeue step & pause in WAITING_FOR_INPUT (A10)
            if (
                exec_result.outcome == ReceiptOutcome.FAILED_PERMISSION
                and exec_result.verifier_reason == "auth_expired"
            ):
                try:
                    self._repo.requeue_step_for_auth_retry(
                        leased.step_id,
                        leased.lease_generation,
                        exec_result.receipt,
                    )
                except (LeaseFencingError, TerminalStateError):
                    latest = self._repo.get_run_snapshot(run_id)
                    return self._build_settled_result(
                        task_spec=task_spec,
                        run=latest.run,
                        answer="Run fenced/cancelled on auth expiry.",
                        observations=tuple(observations),
                        contradictions=tuple(contradictions),
                    )
                self._repo.append_audit_log(
                    task_id=task_id,
                    run_id=run_id,
                    step_id=leased.step_id,
                    actor="tool_registry",
                    action="tool_auth_expired",
                    decision="deny",
                    detail={"tool_id": tool_id, "error": exec_result.error_detail},
                )
                req_action = (
                    exec_result.error_detail
                    or f"Re-authenticate expired session for {tool_id}"
                )
                usage_now = self._repo.get_budget_usage(task_id)
                paused_res = Result(
                    task_id=task_id,
                    run_id=run_id,
                    status=TaskStatus.WAITING_FOR_INPUT,
                    answer=req_action,
                    verified_observations=tuple(observations),
                    partial_info={
                        "auth_expired_tool": tool_id,
                        "session_id": exec_ctx.session_id,
                    },
                    contradictions=tuple(contradictions),
                    required_action=req_action,
                    execution_metrics=self._budget_manager.to_execution_metrics(usage_now),
                )
                self._repo.pause_for_input(
                    run_id,
                    req_action,
                    reason="auth_expired",
                    result=paused_res,
                    wall_seconds_elapsed=post_wall,
                )
                return paused_res

            # Ambiguous EFFECT timeout -> reconcile if registered, else pause (A08)
            if exec_result.outcome == ReceiptOutcome.UNKNOWN_NEEDS_RECONCILIATION:
                try:
                    self._repo.mark_step_unknown(
                        leased.step_id,
                        lease_generation=leased.lease_generation,
                        reason=exec_result.error_detail or "effect_timeout_unknown",
                        receipt=exec_result.receipt,
                    )
                except (LeaseFencingError, TerminalStateError):
                    latest = self._repo.get_run_snapshot(run_id)
                    return self._build_settled_result(
                        task_spec=task_spec,
                        run=latest.run,
                        answer="Run fenced/cancelled on unknown effect.",
                        observations=tuple(observations),
                        contradictions=tuple(contradictions),
                    )
                if self._tool_registry.get_reconciler(tool_id) is not None:
                    rec_details = self._repo.get_step_execution_details(leased.step_id)
                    rec_snap = self._repo.get_run_snapshot(run_id)
                    outcome_kind = await self._reconcile_unknown_effect(rec_details, rec_snap)
                    if outcome_kind == "reconciled":
                        reconciled_snap = self._repo.get_run_snapshot(run_id)
                        latest_receipt = next(
                            (
                                r
                                for r in reversed(reconciled_snap.receipts)
                                if r.step_id == leased.step_id
                            ),
                            None,
                        )
                        history.append(
                            {
                                "tool_id": tool_id,
                                "args": exec_result.receipt.redacted_args,
                                "outcome": ReceiptOutcome.SUCCEEDED.value,
                                "output": (
                                    latest_receipt.observed_after
                                    if latest_receipt is not None
                                    else None
                                ),
                                "error": None,
                            }
                        )
                        return None
                    if outcome_kind == "retry":
                        local_retries += 1
                        continue
                    if outcome_kind == "waiting_for_human":
                        paused_snap = self._repo.get_run_snapshot(run_id)
                        req_action = (
                            paused_snap.run.required_action
                            or f"Human review required for unconfirmed effect {op_key} ({tool_id})"
                        )
                        usage_now = self._repo.get_budget_usage(task_id)
                        return Result(
                            task_id=task_id,
                            run_id=run_id,
                            status=TaskStatus.WAITING_FOR_INPUT,
                            answer=req_action,
                            verified_observations=tuple(observations),
                            contradictions=tuple(contradictions),
                            required_action=req_action,
                            execution_metrics=self._budget_manager.to_execution_metrics(usage_now),
                        )

                req_action = (
                    f"Human review required for unconfirmed effect {op_key} ({tool_id})"
                )
                usage_now = self._repo.get_budget_usage(task_id)
                paused_res = Result(
                    task_id=task_id,
                    run_id=run_id,
                    status=TaskStatus.WAITING_FOR_INPUT,
                    answer=req_action,
                    verified_observations=tuple(observations),
                    contradictions=tuple(contradictions),
                    required_action=req_action,
                    execution_metrics=self._budget_manager.to_execution_metrics(usage_now),
                )
                self._repo.pause_for_input(
                    run_id,
                    req_action,
                    reason="effect_timeout_needs_reconciliation",
                    result=paused_res,
                    wall_seconds_elapsed=post_wall,
                )
                return paused_res

            # Handle transient READ failure with bounded retry
            if (
                exec_result.outcome == ReceiptOutcome.FAILED_TRANSIENT
                and spec is not None
                and spec.retry_policy.retry_on_transient
                and local_retries < spec.retry_policy.max_retries
            ):
                try:
                    self._repo.increment_transient_retry(task_id, run_id=run_id)
                    self._repo.requeue_step_after_transient_failure(
                        leased.step_id,
                        leased.lease_generation,
                        exec_result.receipt,
                        reason="transient_retry_scheduled",
                    )
                except (BudgetExceededError, LeaseFencingError, TerminalStateError):
                    pass
                else:
                    local_retries += 1
                    continue

            # Step 4: Verify & fenced commit
            final_step_status = (
                StepStatus.SUCCEEDED
                if exec_result.outcome == ReceiptOutcome.SUCCEEDED
                else StepStatus.FAILED
            )
            try:
                self._repo.commit_step_result(
                    leased.step_id,
                    leased.lease_generation,
                    final_step_status,
                    exec_result.outcome.value,
                    exec_result.receipt,
                    step_output=exec_result.output,
                    expected_worker=self._config.coordinator_id,
                )
            except (LeaseFencingError, TerminalStateError):
                latest = self._repo.get_run_snapshot(run_id)
                return self._build_settled_result(
                    task_spec=task_spec,
                    run=latest.run,
                    answer="Late step completion rejected by lease/cancel fence.",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                )

            if exec_result.outcome == ReceiptOutcome.FAILED_PERMISSION:
                self._repo.append_audit_log(
                    task_id=task_id,
                    run_id=run_id,
                    step_id=leased.step_id,
                    actor="tool_registry",
                    action="tool_permission_denied",
                    decision="deny",
                    detail={"tool_id": tool_id, "error": exec_result.error_detail},
                )

            if exec_result.observations:
                observations.extend(exec_result.observations)
                self._repo.append_observations(
                    task_id=task_id,
                    run_id=run_id,
                    step_id=leased.step_id,
                    observations=exec_result.observations,
                )

            history.append(
                {
                    "tool_id": tool_id,
                    "args": exec_result.receipt.redacted_args,
                    "outcome": exec_result.outcome.value,
                    "output": exec_result.output,
                    "error": exec_result.error_detail,
                }
            )

            # Step 5: Persist signature & evaluate LoopDetector (A06 / A07)
            progress_token = self._compute_progress_token(exec_result)
            self._repo.record_step_signature(
                task_id=task_id,
                run_id=run_id,
                step_index=leased.step_index,
                tool_id=tool_id,
                target_key=target_origin or snapshot.effective_scope.facility_id,
                canonical_args_hash=canonical_json_hash(exec_result.receipt.redacted_args),
                result_hash=canonical_json_hash(
                    {"outcome": exec_result.outcome.value, "output": exec_result.output}
                ),
                progress_token=progress_token,
                succeeded=(exec_result.outcome == ReceiptOutcome.SUCCEEDED),
            )
            sigs = self._repo.get_step_signatures(run_id)
            poller_tools = {
                tid
                for tid in self._tool_registry.list_specs()
                if self._tool_registry.is_poller(tid)
            }
            loop_decision = self._loop_detector.evaluate(sigs, poller_tools=poller_tools)
            if loop_decision.action == "halt":
                self._repo.append_event(
                    task_id=task_id,
                    run_id=run_id,
                    step_id=leased.step_id,
                    event_type="loop_detected",
                    reason=loop_decision.reason,
                    payload={"kind": loop_decision.kind},
                )
                self._repo.append_audit_log(
                    task_id=task_id,
                    run_id=run_id,
                    step_id=leased.step_id,
                    actor="loop_detector",
                    action="loop_halted",
                    decision="deny",
                    detail={"kind": loop_decision.kind, "reason": loop_decision.reason},
                )
                target = (
                    TaskStatus.PARTIAL
                    if observations
                    and task_spec.evidence_requirements.allow_partial_on_source_failure
                    else TaskStatus.FAILED
                )
                return self._settle_terminal(
                    task_spec=task_spec,
                    run_id=run_id,
                    target_status=target,
                    reason=loop_decision.reason,
                    answer=f"Execution halted by loop guard: {loop_decision.reason}",
                    observations=tuple(observations),
                    contradictions=tuple(contradictions),
                    partial_info={
                        "loop_kind": loop_decision.kind,
                        "reason": loop_decision.reason,
                    },
                )

            return None

    @staticmethod
    def _compute_progress_token(exec_result: ToolExecutionResult) -> str | None:
        if exec_result.observations:
            obs_payload = [
                {
                    "asset_id": o.asset_id,
                    "value": o.value,
                    "source_time": o.source_time.isoformat() if o.source_time else None,
                    "quality": o.quality.value,
                }
                for o in exec_result.observations
            ]
            return canonical_json_hash(obs_payload)
        if "progress_token" in exec_result.output:
            return str(exec_result.output["progress_token"])
        return None
