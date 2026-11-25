"""Structural DI protocols and snapshot DTOs decoupling src/web from M2 engine internals."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Sequence
from typing import Any, Protocol, runtime_checkable

from pydantic import Field

from src.adapters.sessions import SessionLockState
from src.contracts.budgets import BudgetConfig, BudgetUsage
from src.contracts.common import FrozenModel, NonEmptyStr, UtcDatetime, utc_now
from src.contracts.enums import TaskStatus
from src.contracts.models import ActionReceipt, Result, Run, TaskSpec


class TransitionRecord(FrozenModel):
    """Recorded task status transition with reason and timestamp."""

    from_status: TaskStatus | None = None
    to_status: TaskStatus
    reason: NonEmptyStr
    timestamp: UtcDatetime = Field(default_factory=utc_now)


class TaskSnapshot(FrozenModel):
    """Full observability snapshot for a submitted task run."""

    run: Run
    task: TaskSpec
    budget_config: BudgetConfig
    budget_usage: BudgetUsage = Field(default_factory=BudgetUsage)
    transitions: tuple[TransitionRecord, ...] = ()
    result: Result | None = None
    receipts: tuple[ActionReceipt, ...] = ()


@runtime_checkable
class CoordinatorProtocol(Protocol):
    """Structural protocol satisfied by M2/M4 Coordinator or M3 InMemoryCoordinatorStub."""

    def submit_task(self, task_spec: TaskSpec) -> Run | Awaitable[Run]:
        """Submit a validated TaskSpec and return the initial Run."""

    def get_task_snapshot(
        self,
        run_id: str,
    ) -> TaskSnapshot | None | Awaitable[TaskSnapshot | None]:
        """Return full TaskSnapshot for run_id or None if unknown."""

    def list_task_snapshots(self) -> Sequence[TaskSnapshot] | Awaitable[Sequence[TaskSnapshot]]:
        """Return all known TaskSnapshots ordered most-recent-first."""

    def cancel_task(
        self,
        run_id: str,
        reason: str = "cancelled_by_user",
    ) -> Run | Awaitable[Run]:
        """Cancel a non-terminal run or raise KeyError / InvalidStateTransitionError."""

    def resume_task(
        self,
        run_id: str,
        human_input: dict[str, Any],
    ) -> Run | Awaitable[Run]:
        """Resume a waiting_for_input run or raise KeyError / InvalidStateTransitionError."""


@runtime_checkable
class SessionManagerProtocol(Protocol):
    """Structural protocol satisfied by SessionManager for takeover/release endpoints."""

    def request_takeover(
        self,
        session_id: str,
        owner: str = "operator",
        reason: str = "manual_intervention",
    ) -> SessionLockState | Awaitable[SessionLockState]:
        """Acquire human takeover lock for session_id."""

    def release_takeover(
        self,
        session_id: str,
        owner: str | None = None,
    ) -> SessionLockState | Awaitable[SessionLockState]:
        """Release human takeover lock for session_id."""

    def get_session_state(
        self,
        session_id: str,
    ) -> SessionLockState | None | Awaitable[SessionLockState | None]:
        """Return SessionLockState for session_id or None if unknown."""

    def list_sessions(
        self,
    ) -> Sequence[SessionLockState] | Awaitable[Sequence[SessionLockState]]:
        """Return all tracked session lock states."""


async def maybe_await[T](value: T | Awaitable[T]) -> T:
    """Await value if it is an Awaitable, otherwise return it directly."""
    if inspect.isawaitable(value):
        return await value
    return value
