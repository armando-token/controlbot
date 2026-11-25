"""Domain enums and task state transition rules."""

from __future__ import annotations

from enum import StrEnum

from src.contracts.common import InvalidStateTransitionError


class TaskStatus(StrEnum):
    """Lifecycle states of a task/run."""

    QUEUED = "queued"
    RUNNING = "running"
    WAITING_FOR_INPUT = "waiting_for_input"
    RECOVERING = "recovering"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_TASK_STATUSES: frozenset[TaskStatus] = frozenset(
    {
        TaskStatus.SUCCEEDED,
        TaskStatus.PARTIAL,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
    }
)

ALLOWED_TASK_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.QUEUED: frozenset(
        {TaskStatus.RUNNING, TaskStatus.CANCELLED, TaskStatus.FAILED}
    ),
    TaskStatus.RUNNING: frozenset(
        {
            TaskStatus.WAITING_FOR_INPUT,
            TaskStatus.RECOVERING,
            TaskStatus.SUCCEEDED,
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }
    ),
    TaskStatus.WAITING_FOR_INPUT: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.RECOVERING,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.RECOVERING: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.WAITING_FOR_INPUT,
            TaskStatus.SUCCEEDED,
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }
    ),
    TaskStatus.SUCCEEDED: frozenset(),
    TaskStatus.PARTIAL: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}


def is_terminal_status(status: TaskStatus) -> bool:
    """Return True if the given TaskStatus is immutable/terminal."""
    return status in TERMINAL_TASK_STATUSES


def can_transition_status(current: TaskStatus, target: TaskStatus) -> bool:
    """Return True if transitioning from current to target is valid."""
    return target in ALLOWED_TASK_TRANSITIONS[current]


def validate_status_transition(current: TaskStatus, target: TaskStatus) -> None:
    """Validate transition from current to target; raise InvalidStateTransitionError if illegal."""
    if not can_transition_status(current, target):
        raise InvalidStateTransitionError(
            f"Illegal task status transition: {current.value!r} -> {target.value!r}"
        )


class StepStatus(StrEnum):
    """Lifecycle states of an individual step within a run."""

    PENDING = "pending"
    LEASED = "leased"
    PREPARED = "prepared"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    CANCELLED = "cancelled"


class BackendMode(StrEnum):
    """Model inference backend mode."""

    EMULATED = "emulated"
    LOCAL_HTTP = "local_http"


class EffectClass(StrEnum):
    """Tool side-effect classification."""

    READ = "read"
    EFFECT = "effect"


class DataQuality(StrEnum):
    """Industrial observation data quality classification."""

    GOOD = "good"
    UNCERTAIN = "uncertain"
    BAD = "bad"
    STALE = "stale"
    UNKNOWN = "unknown"


class ReceiptOutcome(StrEnum):
    """Outcome classification for an ActionReceipt."""

    SUCCEEDED = "succeeded"
    FAILED_TRANSIENT = "failed_transient"
    FAILED_SEMANTIC = "failed_semantic"
    FAILED_PERMISSION = "failed_permission"
    UNKNOWN_NEEDS_RECONCILIATION = "unknown_needs_reconciliation"
    CANCELLED = "cancelled"
