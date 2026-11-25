"""In-memory CoordinatorProtocol stub for standalone M3 web server execution."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from src.contracts.budgets import BudgetUsage
from src.contracts.common import utc_now
from src.contracts.enums import TaskStatus, validate_status_transition
from src.contracts.models import ActionReceipt, Result, Run, TaskSpec
from src.web.protocols import TaskSnapshot, TransitionRecord


class InMemoryCoordinatorStub:
    """Standalone CoordinatorProtocol implementation for M3 web API & UI testing."""

    def __init__(self) -> None:
        self._snapshots: dict[str, TaskSnapshot] = {}
        self._order: list[str] = []

    def submit_task(self, task_spec: TaskSpec) -> Run:
        now = utc_now()
        run_id = f"run-{uuid.uuid4().hex[:12]}"
        deadline = now + timedelta(seconds=task_spec.budget.max_wall_seconds)
        run = Run(
            run_id=run_id,
            task_id=task_spec.task_id,
            depth=0,
            status=TaskStatus.QUEUED,
            attempt=1,
            version=1,
            deadline_at=deadline,
            progress=0.0,
            transition_reason="submitted",
            created_at=now,
            updated_at=now,
        )
        snapshot = TaskSnapshot(
            run=run,
            task=task_spec,
            budget_config=task_spec.budget,
            budget_usage=BudgetUsage(),
            transitions=(
                TransitionRecord(
                    from_status=None,
                    to_status=TaskStatus.QUEUED,
                    reason="submitted",
                    timestamp=now,
                ),
            ),
        )
        self._snapshots[run_id] = snapshot
        self._order.append(run_id)
        return run

    def get_task_snapshot(self, run_id: str) -> TaskSnapshot | None:
        return self._snapshots.get(run_id)

    def list_task_snapshots(self) -> list[TaskSnapshot]:
        return [self._snapshots[rid] for rid in reversed(self._order) if rid in self._snapshots]

    def transition_run(
        self,
        run_id: str,
        target_status: TaskStatus,
        reason: str,
        *,
        required_action: str | None = None,
        progress: float | None = None,
        result: Result | None = None,
        receipts: tuple[ActionReceipt, ...] | None = None,
        budget_usage: BudgetUsage | None = None,
    ) -> Run:
        snap = self._snapshots.get(run_id)
        if snap is None:
            raise KeyError(f"Unknown run_id: {run_id!r}")
        validate_status_transition(snap.run.status, target_status)
        now = utc_now()
        updated_run = snap.run.model_copy(
            update={
                "status": target_status,
                "version": snap.run.version + 1,
                "transition_reason": reason,
                "required_action": required_action,
                "progress": snap.run.progress if progress is None else progress,
                "updated_at": now,
            }
        )
        new_transition = TransitionRecord(
            from_status=snap.run.status,
            to_status=target_status,
            reason=reason,
            timestamp=now,
        )
        if result is not None:
            next_result: Result | None = result
        elif (
            snap.run.status == TaskStatus.WAITING_FOR_INPUT
            and target_status != TaskStatus.WAITING_FOR_INPUT
        ):
            next_result = None
        else:
            next_result = snap.result
        self._snapshots[run_id] = snap.model_copy(
            update={
                "run": updated_run,
                "transitions": (*snap.transitions, new_transition),
                "result": next_result,
                "receipts": snap.receipts if receipts is None else receipts,
                "budget_usage": snap.budget_usage if budget_usage is None else budget_usage,
            }
        )
        return updated_run

    def cancel_task(self, run_id: str, reason: str = "cancelled_by_user") -> Run:
        snap = self._snapshots.get(run_id)
        if snap is None:
            raise KeyError(f"Unknown run_id: {run_id!r}")
        validate_status_transition(snap.run.status, TaskStatus.CANCELLED)
        return self.transition_run(run_id, TaskStatus.CANCELLED, reason, progress=1.0)

    def resume_task(self, run_id: str, human_input: dict[str, Any]) -> Run:
        snap = self._snapshots.get(run_id)
        if snap is None:
            raise KeyError(f"Unknown run_id: {run_id!r}")
        if snap.run.status != TaskStatus.WAITING_FOR_INPUT:
            validate_status_transition(snap.run.status, TaskStatus.WAITING_FOR_INPUT)
        validate_status_transition(snap.run.status, TaskStatus.RUNNING)
        detail = str(human_input.get("choice") or human_input.get("note") or "human_resumed")
        return self.transition_run(
            run_id,
            TaskStatus.RUNNING,
            f"resumed:{detail}",
            required_action=None,
        )
