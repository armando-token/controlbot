"""SQLite WAL repository for tasks, runs, fenced steps, budgets, receipts, and logs."""

from __future__ import annotations

import json
import math
import sqlite3
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any, Literal

from pydantic import Field

from src.contracts.budgets import BudgetConfig, BudgetUsage
from src.contracts.common import (
    FrozenModel,
    NonEmptyStr,
    PlanValidationError,
    UtcDatetime,
    ensure_utc,
    utc_now,
)
from src.contracts.enums import (
    TERMINAL_TASK_STATUSES,
    EffectClass,
    ReceiptOutcome,
    StepStatus,
    TaskStatus,
    is_terminal_status,
    validate_status_transition,
)
from src.contracts.models import (
    ActionReceipt,
    Observation,
    Result,
    Run,
    Step,
    TaskScope,
    TaskSpec,
)
from src.storage.db import open_connection, read_transaction, write_transaction
from src.storage.errors import (
    BudgetExceededError,
    ConflictError,
    IdempotencyConflictError,
    LeaseFencingError,
    NotFoundError,
    TerminalStateError,
)
from src.storage.migrations import apply_migrations
from src.storage.redaction import (
    contains_unredacted_secret_strict,
    redact_payload_strict,
)

ClockFn = Callable[[], datetime]
_NON_TERMINAL_STATUS_VALUES: tuple[str, ...] = tuple(
    s.value for s in TaskStatus if s not in TERMINAL_TASK_STATUSES
)
_CLAIMABLE_RUN_STATUS_VALUES: tuple[str, ...] = (
    TaskStatus.QUEUED.value,
    TaskStatus.RUNNING.value,
    TaskStatus.RECOVERING.value,
)


def _reject_bool_float(value: float, field_name: str, *, allow_zero: bool = True) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a numeric float, got {type(value).__name__}.")
    fval = float(value)
    if not math.isfinite(fval):
        raise ValueError(f"{field_name} must be finite, got {value!r}.")
    if allow_zero and fval < 0.0:
        raise ValueError(f"{field_name} must be >= 0.0, got {fval}.")
    if not allow_zero and fval <= 0.0:
        raise ValueError(f"{field_name} must be > 0.0, got {fval}.")
    return fval


def _parse_dt(value: str) -> datetime:
    return ensure_utc(datetime.fromisoformat(value))


def _format_dt(dt: datetime) -> str:
    return ensure_utc(dt).isoformat()


def _safe_json_dumps(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


class BudgetReservation(FrozenModel):
    """Persisted reservation record against root task_budgets."""

    reservation_id: NonEmptyStr
    task_id: NonEmptyStr
    run_id: NonEmptyStr
    step_id: NonEmptyStr | None = None
    kind: Literal["tool", "model"]
    tool_calls_reserved: int = Field(ge=0)
    model_calls_reserved: int = Field(ge=0)
    tokens_reserved: int = Field(ge=0)
    status: Literal["active", "reconciled", "released", "expired"]
    lease_generation: int | None = None
    expires_at: UtcDatetime | None = None
    created_at: UtcDatetime
    updated_at: UtcDatetime


class OperationKeyRecord(FrozenModel):
    """Persisted operation/idempotency tracking record for Step 2 & A08 recovery."""

    operation_key: NonEmptyStr
    task_id: NonEmptyStr
    run_id: NonEmptyStr
    step_id: NonEmptyStr
    latest_attempt: int = Field(ge=1)
    tool_id: NonEmptyStr
    effect_class: EffectClass
    idempotency_key: NonEmptyStr
    status: NonEmptyStr
    redacted_args: dict[str, Any]
    reconciliation_note: str | None = None
    created_at: UtcDatetime
    updated_at: UtcDatetime


class EventRecord(FrozenModel):
    """Persisted task/run/step event stream item."""

    event_id: int = Field(ge=1)
    task_id: NonEmptyStr
    run_id: NonEmptyStr | None = None
    step_id: NonEmptyStr | None = None
    event_type: NonEmptyStr
    from_status: str | None = None
    to_status: str | None = None
    reason: NonEmptyStr
    payload: dict[str, Any]
    created_at: UtcDatetime


class AuditRecord(FrozenModel):
    """Append-only redacted audit log entry."""

    audit_id: int = Field(ge=1)
    task_id: str | None = None
    run_id: str | None = None
    step_id: str | None = None
    actor: NonEmptyStr
    action: NonEmptyStr
    decision: NonEmptyStr
    detail: dict[str, Any]
    recorded_at: UtcDatetime


class StepSignatureRecord(FrozenModel):
    """Persisted canonical call signature for A06/A07 loop & cycle detection."""

    sig_id: int = Field(ge=1)
    task_id: NonEmptyStr
    run_id: NonEmptyStr
    step_index: int = Field(ge=0)
    tool_id: NonEmptyStr
    target_key: str
    canonical_args_hash: NonEmptyStr
    result_hash: NonEmptyStr
    progress_token: str | None = None
    succeeded: bool
    created_at: UtcDatetime


class StepExecutionDetails(FrozenModel):
    """Step plus internal execution metadata needed by Coordinator/ToolRegistry."""

    step: Step
    task_id: NonEmptyStr
    exec_args: dict[str, Any]
    redacted_args: dict[str, Any]
    target_origin: str | None = None
    effect_class: EffectClass
    idempotency_key: str | None = None
    step_output: dict[str, Any] | None = None


class RunSnapshot(FrozenModel):
    """Point-in-time consistent snapshot of a run and its task state."""

    task_spec: TaskSpec
    run: Run
    effective_scope: TaskScope
    steps: tuple[Step, ...]
    receipts: tuple[ActionReceipt, ...]
    budget_usage: BudgetUsage
    events: tuple[EventRecord, ...]
    child_runs: tuple[Run, ...]
    cancel_requested: bool
    result: Result | None = None
    pending_human_input: dict[str, Any] | None = None
    observations: tuple[Observation, ...] = ()
    waiting_since: UtcDatetime | None = None
    root_created_at: UtcDatetime | None = None


class StorageRepo:
    """Short-transaction SQLite WAL repository enforcing lease, budget, and redaction rules."""

    def __init__(self, db_path: Path, clock: ClockFn = utc_now) -> None:
        self._db_path = Path(db_path)
        self._clock = clock
        self._lock = RLock()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _now(self) -> datetime:
        return ensure_utc(self._clock())

    def init_db(self) -> int:
        """Initialize WAL mode, foreign keys, busy timeout, and forward migrations."""
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            return apply_migrations(conn, now_iso)

    def get_pragma_settings(self) -> dict[str, Any]:
        """Inspect active SQLite PRAGMA settings for diagnostics/tests."""
        conn = open_connection(self._db_path)
        try:
            jm = conn.execute("PRAGMA journal_mode;").fetchone()
            fk = conn.execute("PRAGMA foreign_keys;").fetchone()
            bt = conn.execute("PRAGMA busy_timeout;").fetchone()
            return {
                "journal_mode": str(jm[0]).lower() if jm is not None else "",
                "foreign_keys": int(fk[0]) if fk is not None else 0,
                "busy_timeout": int(bt[0]) if bt is not None else 0,
            }
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Row deserializers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> Run:
        return Run(
            run_id=str(row["run_id"]),
            task_id=str(row["task_id"]),
            parent_run_id=row["parent_run_id"],
            depth=int(row["depth"]),
            status=TaskStatus(str(row["status"])),
            attempt=int(row["attempt"]),
            version=int(row["version"]),
            deadline_at=_parse_dt(str(row["deadline_at"])),
            progress=float(row["progress"]),
            transition_reason=str(row["transition_reason"]),
            required_action=row["required_action"],
            created_at=_parse_dt(str(row["created_at"])),
            updated_at=_parse_dt(str(row["updated_at"])),
        )

    @staticmethod
    def _row_to_step(row: sqlite3.Row) -> Step:
        expiry = row["lease_expiry"]
        return Step(
            step_id=str(row["step_id"]),
            run_id=str(row["run_id"]),
            step_index=int(row["step_index"]),
            status=StepStatus(str(row["status"])),
            attempt=int(row["attempt"]),
            tool_id=str(row["tool_id"]),
            operation_key=str(row["operation_key"]),
            lease_owner=row["lease_owner"],
            lease_expiry=_parse_dt(str(expiry)) if expiry is not None else None,
            lease_generation=int(row["lease_generation"]),
            completion_verifier=str(row["completion_verifier"]),
            outcome=row["outcome"],
        )

    @staticmethod
    def _row_to_budget_usage(row: sqlite3.Row) -> BudgetUsage:
        return BudgetUsage(
            active_children=int(row["active_children"]),
            tool_calls_used=int(row["tool_calls_used"]),
            tool_calls_reserved=int(row["tool_calls_reserved"]),
            model_calls_used=int(row["model_calls_used"]),
            model_calls_reserved=int(row["model_calls_reserved"]),
            wall_seconds_elapsed=float(row["wall_seconds_elapsed"]),
            human_wait_seconds_elapsed=float(row["human_wait_seconds_elapsed"]),
            prompt_tokens_used=int(row["prompt_tokens_used"]),
            completion_tokens_used=int(row["completion_tokens_used"]),
            tokens_reserved=int(row["tokens_reserved"]),
            transient_retries_used=int(row["transient_retries_used"]),
            usage_estimated=bool(row["usage_estimated"]),
        )

    @staticmethod
    def _row_to_reservation(row: sqlite3.Row) -> BudgetReservation:
        expires_raw = row["expires_at"]
        return BudgetReservation(
            reservation_id=str(row["reservation_id"]),
            task_id=str(row["task_id"]),
            run_id=str(row["run_id"]),
            step_id=row["step_id"],
            kind=row["kind"],
            tool_calls_reserved=int(row["tool_calls_reserved"]),
            model_calls_reserved=int(row["model_calls_reserved"]),
            tokens_reserved=int(row["tokens_reserved"]),
            status=row["status"],
            lease_generation=row["lease_generation"],
            expires_at=_parse_dt(str(expires_raw)) if expires_raw is not None else None,
            created_at=_parse_dt(str(row["created_at"])),
            updated_at=_parse_dt(str(row["updated_at"])),
        )

    @staticmethod
    def _row_to_op_key(row: sqlite3.Row) -> OperationKeyRecord:
        return OperationKeyRecord(
            operation_key=str(row["operation_key"]),
            task_id=str(row["task_id"]),
            run_id=str(row["run_id"]),
            step_id=str(row["step_id"]),
            latest_attempt=int(row["latest_attempt"]),
            tool_id=str(row["tool_id"]),
            effect_class=EffectClass(str(row["effect_class"])),
            idempotency_key=str(row["idempotency_key"]),
            status=str(row["status"]),
            redacted_args=json.loads(str(row["redacted_args_json"])),
            reconciliation_note=row["reconciliation_note"],
            created_at=_parse_dt(str(row["created_at"])),
            updated_at=_parse_dt(str(row["updated_at"])),
        )

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> EventRecord:
        return EventRecord(
            event_id=int(row["event_id"]),
            task_id=str(row["task_id"]),
            run_id=row["run_id"],
            step_id=row["step_id"],
            event_type=str(row["event_type"]),
            from_status=row["from_status"],
            to_status=row["to_status"],
            reason=str(row["reason"]),
            payload=json.loads(str(row["payload_json"])),
            created_at=_parse_dt(str(row["created_at"])),
        )

    @staticmethod
    def _row_to_audit(row: sqlite3.Row) -> AuditRecord:
        return AuditRecord(
            audit_id=int(row["audit_id"]),
            task_id=row["task_id"],
            run_id=row["run_id"],
            step_id=row["step_id"],
            actor=str(row["actor"]),
            action=str(row["action"]),
            decision=str(row["decision"]),
            detail=json.loads(str(row["detail_json"])),
            recorded_at=_parse_dt(str(row["recorded_at"])),
        )

    @staticmethod
    def _row_to_step_signature(row: sqlite3.Row) -> StepSignatureRecord:
        return StepSignatureRecord(
            sig_id=int(row["sig_id"]),
            task_id=str(row["task_id"]),
            run_id=str(row["run_id"]),
            step_index=int(row["step_index"]),
            tool_id=str(row["tool_id"]),
            target_key=str(row["target_key"]),
            canonical_args_hash=str(row["canonical_args_hash"]),
            result_hash=str(row["result_hash"]),
            progress_token=row["progress_token"],
            succeeded=bool(row["succeeded"]),
            created_at=_parse_dt(str(row["created_at"])),
        )

    # ------------------------------------------------------------------
    # Internal event & audit helpers (inside active tx)
    # ------------------------------------------------------------------

    @staticmethod
    def _insert_event(
        conn: sqlite3.Connection,
        *,
        task_id: str,
        run_id: str | None,
        step_id: str | None,
        event_type: str,
        from_status: str | None,
        to_status: str | None,
        reason: str,
        payload: dict[str, Any] | None,
        created_at_iso: str,
    ) -> int:
        scrubbed_payload = redact_payload_strict(payload or {})
        if contains_unredacted_secret_strict(scrubbed_payload):
            raise ValueError("Event payload contains unredacted secret material.")
        scrubbed_reason = str(redact_payload_strict(reason))
        cur = conn.execute(
            """
            INSERT INTO events (
                task_id, run_id, step_id, event_type,
                from_status, to_status, reason, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                run_id,
                step_id,
                event_type,
                from_status,
                to_status,
                scrubbed_reason,
                _safe_json_dumps(scrubbed_payload),
                created_at_iso,
            ),
        )
        return int(cur.lastrowid or 0)

    @staticmethod
    def _insert_audit(
        conn: sqlite3.Connection,
        *,
        task_id: str | None,
        run_id: str | None,
        step_id: str | None,
        actor: str,
        action: str,
        decision: str,
        detail: dict[str, Any] | None,
        recorded_at_iso: str,
    ) -> int:
        scrubbed_detail = redact_payload_strict(detail or {})
        if contains_unredacted_secret_strict(scrubbed_detail):
            raise ValueError("Audit log detail contains unredacted secret material.")
        cur = conn.execute(
            """
            INSERT INTO audit_log (
                task_id, run_id, step_id, actor, action, decision, detail_json, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                run_id,
                step_id,
                actor,
                action,
                decision,
                _safe_json_dumps(scrubbed_detail),
                recorded_at_iso,
            ),
        )
        return int(cur.lastrowid or 0)

    @staticmethod
    def _insert_receipt_row(conn: sqlite3.Connection, receipt: ActionReceipt) -> None:
        receipt_dict = receipt.model_dump()
        if contains_unredacted_secret_strict(receipt_dict):
            raise ValueError("ActionReceipt contains unredacted secret material.")
        conn.execute(
            """
            INSERT INTO action_receipts (
                receipt_id, task_id, run_id, step_id, attempt,
                tool_id, operation_key, outcome, duration_ms, receipt_json, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.receipt_id,
                receipt.task_id,
                receipt.run_id,
                receipt.step_id,
                receipt.attempt,
                receipt.tool_id,
                receipt.operation_key,
                receipt.outcome.value,
                float(receipt.duration_ms),
                receipt.model_dump_json(),
                _format_dt(receipt.recorded_at),
            ),
        )

    @staticmethod
    def _load_task_row(conn: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if not isinstance(row, sqlite3.Row):
            raise NotFoundError(f"Task {task_id!r} not found.")
        return row

    @staticmethod
    def _load_run_row(conn: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not isinstance(row, sqlite3.Row):
            raise NotFoundError(f"Run {run_id!r} not found.")
        return row

    @staticmethod
    def _load_budget_row(conn: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM task_budgets WHERE task_id = ?", (task_id,)
        ).fetchone()
        if not isinstance(row, sqlite3.Row):
            raise NotFoundError(f"Budget row for task {task_id!r} not found.")
        return row

    @staticmethod
    def _compute_human_wait_deltas(
        *,
        waiting_since_raw: Any,
        accounted_until_raw: Any,
        now: datetime,
    ) -> tuple[float, float, str | None]:
        """Return (run_wait_delta, non_overlapping_budget_delta, new_accounted_until_iso)."""
        accounted_until = (
            _parse_dt(str(accounted_until_raw))
            if accounted_until_raw is not None
            else None
        )
        if waiting_since_raw is None:
            return (
                0.0,
                0.0,
                _format_dt(accounted_until) if accounted_until is not None else None,
            )
        waiting_since = _parse_dt(str(waiting_since_raw))
        wait_delta = max(0.0, (now - waiting_since).total_seconds())
        effective_start = (
            max(waiting_since, accounted_until)
            if accounted_until is not None
            else waiting_since
        )
        budget_wait_delta = max(0.0, (now - effective_start).total_seconds())
        new_accounted_until = (
            max(accounted_until, now) if accounted_until is not None else now
        )
        return wait_delta, budget_wait_delta, _format_dt(new_accounted_until)

    @staticmethod
    def _validate_child_scope_narrowing(
        parent_scope: TaskScope, child_scope: TaskScope
    ) -> list[str]:
        violations: list[str] = []
        if child_scope.facility_id != parent_scope.facility_id:
            violations.append(
                f"facility_id mismatch ({child_scope.facility_id!r} != "
                f"{parent_scope.facility_id!r})"
            )
        if parent_scope.read_only and not child_scope.read_only:
            violations.append("cannot widen read_only=True to read_only=False")
        if parent_scope.allowed_origins:
            if not child_scope.allowed_origins:
                violations.append("child cannot clear non-empty parent allowed_origins")
            elif not set(child_scope.allowed_origins).issubset(parent_scope.allowed_origins):
                violations.append("child allowed_origins exceeds parent allowed_origins")
        if parent_scope.allowed_tools:
            if not child_scope.allowed_tools:
                violations.append("child cannot clear non-empty parent allowed_tools")
            elif not set(child_scope.allowed_tools).issubset(parent_scope.allowed_tools):
                violations.append("child allowed_tools exceeds parent allowed_tools")
        if parent_scope.allowed_areas:
            if not child_scope.allowed_areas:
                violations.append("child cannot clear non-empty parent allowed_areas")
            elif not set(child_scope.allowed_areas).issubset(parent_scope.allowed_areas):
                violations.append("child allowed_areas exceeds parent allowed_areas")
        return violations

    # ------------------------------------------------------------------
    # Tasks & Runs lifecycle
    # ------------------------------------------------------------------

    def create_task_and_run(
        self,
        task_spec: TaskSpec,
        run_id: str | None = None,
        reason: str = "task_submitted",
    ) -> tuple[TaskSpec, Run]:
        """Atomically persist TaskSpec, zeroed root BudgetUsage, and root Run."""
        now = self._now()
        now_iso = _format_dt(now)
        actual_run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
        deadline = now + timedelta(seconds=float(task_spec.budget.max_wall_seconds))
        deadline_iso = _format_dt(deadline)

        root_run = Run(
            run_id=actual_run_id,
            task_id=task_spec.task_id,
            parent_run_id=None,
            depth=0,
            status=TaskStatus.QUEUED,
            attempt=1,
            version=1,
            deadline_at=deadline,
            progress=0.0,
            transition_reason=reason,
            required_action=None,
            created_at=now,
            updated_at=now,
        )

        with write_transaction(self._db_path, self._lock) as conn:
            existing = conn.execute(
                "SELECT 1 FROM tasks WHERE task_id = ?", (task_spec.task_id,)
            ).fetchone()
            if existing is not None:
                raise ConflictError(f"Task {task_spec.task_id!r} already exists.")
            existing_run = conn.execute(
                "SELECT 1 FROM runs WHERE run_id = ?", (root_run.run_id,)
            ).fetchone()
            if existing_run is not None:
                raise ConflictError(f"Run {root_run.run_id!r} already exists.")

            conn.execute(
                """
                INSERT INTO tasks (
                    task_id, user_id, profile_id, facility_id, query,
                    policy_version, backend_mode, read_only,
                    spec_json, budget_config_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_spec.task_id,
                    task_spec.user_id,
                    task_spec.profile_id,
                    task_spec.scope.facility_id,
                    task_spec.query,
                    task_spec.policy_version,
                    task_spec.backend_mode.value,
                    1 if task_spec.scope.read_only else 0,
                    task_spec.model_dump_json(),
                    task_spec.budget.model_dump_json(),
                    now_iso,
                ),
            )
            conn.execute(
                """
                INSERT INTO task_budgets (task_id, updated_at) VALUES (?, ?)
                """,
                (task_spec.task_id, now_iso),
            )
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, task_id, parent_run_id, depth, status, attempt, version,
                    deadline_at, progress, transition_reason, required_action,
                    scope_json, created_at, updated_at
                ) VALUES (?, ?, NULL, 0, ?, 1, 1, ?, 0.0, ?, NULL, ?, ?, ?)
                """,
                (
                    root_run.run_id,
                    root_run.task_id,
                    root_run.status.value,
                    deadline_iso,
                    root_run.transition_reason,
                    task_spec.scope.model_dump_json(),
                    now_iso,
                    now_iso,
                ),
            )
            self._insert_event(
                conn,
                task_id=task_spec.task_id,
                run_id=root_run.run_id,
                step_id=None,
                event_type="task_created",
                from_status=None,
                to_status=root_run.status.value,
                reason=reason,
                payload={"depth": 0, "facility_id": task_spec.scope.facility_id},
                created_at_iso=now_iso,
            )

        return task_spec, root_run

    def create_child_run(
        self,
        parent_run_id: str,
        child_run_id: str | None = None,
        *,
        child_scope: TaskScope | None = None,
        reason: str = "delegated_to_child",
    ) -> Run:
        """Spawn a depth=1 child run sharing root budget with optional narrowed scope."""
        now = self._now()
        now_iso = _format_dt(now)
        actual_child_id = child_run_id or f"run-{uuid.uuid4().hex[:12]}"

        rejection: Exception | None = None
        child_run: Run | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            parent_row = self._load_run_row(conn, parent_run_id)
            parent_run = self._row_to_run(parent_row)
            task_row = self._load_task_row(conn, parent_run.task_id)
            task_spec = TaskSpec.model_validate_json(str(task_row["spec_json"]))
            budget_cfg = BudgetConfig.model_validate_json(str(task_row["budget_config_json"]))
            budget_row = self._load_budget_row(conn, parent_run.task_id)
            cancel_requested = bool(task_row["cancel_requested"])

            if is_terminal_status(parent_run.status) or cancel_requested:
                self._insert_audit(
                    conn,
                    task_id=parent_run.task_id,
                    run_id=parent_run_id,
                    step_id=None,
                    actor="coordinator",
                    action="child_spawn_rejected",
                    decision="deny",
                    detail={"reason": "parent_terminal_or_cancelled"},
                    recorded_at_iso=now_iso,
                )
                rejection = TerminalStateError(
                    f"Cannot spawn child run from terminal/cancelled run {parent_run_id!r}."
                )
            elif parent_run.depth + 1 > budget_cfg.max_depth:
                self._insert_audit(
                    conn,
                    task_id=parent_run.task_id,
                    run_id=parent_run_id,
                    step_id=None,
                    actor="coordinator",
                    action="child_spawn_rejected",
                    decision="deny",
                    detail={
                        "reason": "max_depth_exceeded",
                        "parent_depth": parent_run.depth,
                        "max_depth": budget_cfg.max_depth,
                    },
                    recorded_at_iso=now_iso,
                )
                rejection = BudgetExceededError(
                    f"Child depth {parent_run.depth + 1} exceeds max_depth={budget_cfg.max_depth}."
                )
            else:
                active_children = int(budget_row["active_children"])
                if active_children + 1 > budget_cfg.max_active_children:
                    self._insert_audit(
                        conn,
                        task_id=parent_run.task_id,
                        run_id=parent_run_id,
                        step_id=None,
                        actor="coordinator",
                        action="child_spawn_rejected",
                        decision="deny",
                        detail={
                            "reason": "max_active_children_exceeded",
                            "active_children": active_children,
                            "max_active_children": budget_cfg.max_active_children,
                        },
                        recorded_at_iso=now_iso,
                    )
                    rejection = BudgetExceededError(
                        f"Active children ({active_children}) reached "
                        f"max_active_children={budget_cfg.max_active_children}."
                    )
                else:
                    parent_scope = (
                        TaskScope.model_validate_json(str(parent_row["scope_json"]))
                        if parent_row["scope_json"] is not None
                        else task_spec.scope
                    )
                    effective_child_scope = child_scope or parent_scope
                    violations = self._validate_child_scope_narrowing(
                        parent_scope, effective_child_scope
                    )
                    if violations:
                        self._insert_audit(
                            conn,
                            task_id=parent_run.task_id,
                            run_id=parent_run_id,
                            step_id=None,
                            actor="coordinator",
                            action="child_scope_widening_rejected",
                            decision="deny",
                            detail={"violations": violations},
                            recorded_at_iso=now_iso,
                        )
                        rejection = PlanValidationError(
                            f"Child scope widening rejected: {'; '.join(violations)}"
                        )
                    else:
                        deadline_dt = max(now, parent_run.deadline_at)
                        child_run = Run(
                            run_id=actual_child_id,
                            task_id=parent_run.task_id,
                            parent_run_id=parent_run.run_id,
                            depth=parent_run.depth + 1,
                            status=TaskStatus.QUEUED,
                            attempt=1,
                            version=1,
                            deadline_at=deadline_dt,
                            progress=0.0,
                            transition_reason=reason,
                            required_action=None,
                            created_at=now,
                            updated_at=now,
                        )
                        conn.execute(
                            """
                            UPDATE task_budgets
                            SET active_children = active_children + 1, updated_at = ?
                            WHERE task_id = ?
                            """,
                            (now_iso, parent_run.task_id),
                        )
                        conn.execute(
                            """
                            INSERT INTO runs (
                                run_id, task_id, parent_run_id, depth, status, attempt, version,
                                deadline_at, progress, transition_reason, required_action,
                                scope_json, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, 1, 1, ?, 0.0, ?, NULL, ?, ?, ?)
                            """,
                            (
                                child_run.run_id,
                                child_run.task_id,
                                child_run.parent_run_id,
                                child_run.depth,
                                child_run.status.value,
                                _format_dt(child_run.deadline_at),
                                child_run.transition_reason,
                                effective_child_scope.model_dump_json(),
                                now_iso,
                                now_iso,
                            ),
                        )
                        self._insert_event(
                            conn,
                            task_id=parent_run.task_id,
                            run_id=child_run.run_id,
                            step_id=None,
                            event_type="child_spawned",
                            from_status=None,
                            to_status=child_run.status.value,
                            reason=reason,
                            payload={
                                "parent_run_id": parent_run.run_id,
                                "depth": child_run.depth,
                            },
                            created_at_iso=now_iso,
                        )

        if rejection is not None:
            raise rejection
        assert child_run is not None
        return child_run

    def _transition_run_status_tx(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        target_status: TaskStatus,
        reason: str,
        *,
        now: datetime,
        now_iso: str,
        progress: float | None = None,
        required_action: str | None = None,
        result: Result | None = None,
        wall_seconds_elapsed: float | None = None,
    ) -> Run:
        current_run = self._row_to_run(row)
        validate_status_transition(current_run.status, target_status)
        if target_status == TaskStatus.WAITING_FOR_INPUT and (
            required_action is None or not required_action.strip()
        ):
            raise ValueError(
                "waiting_for_input transition requires non-empty required_action."
            )

        new_required_action = (
            required_action.strip()
            if target_status == TaskStatus.WAITING_FOR_INPUT and required_action
            else None
        )
        new_progress = (
            float(progress)
            if progress is not None
            else (1.0 if target_status == TaskStatus.SUCCEEDED else current_run.progress)
        )
        new_version = current_run.version + 1
        new_waiting_since: str | None = row["waiting_since"]
        new_deadline_dt = current_run.deadline_at

        if (
            current_run.status == TaskStatus.WAITING_FOR_INPUT
            and row["waiting_since"] is not None
        ):
            budget_row = self._load_budget_row(conn, current_run.task_id)
            wait_delta, budget_wait_delta, new_accounted_until = (
                self._compute_human_wait_deltas(
                    waiting_since_raw=row["waiting_since"],
                    accounted_until_raw=budget_row["human_wait_accounted_until"],
                    now=now,
                )
            )
            conn.execute(
                """
                UPDATE task_budgets
                SET human_wait_seconds_elapsed = human_wait_seconds_elapsed + ?,
                    human_wait_accounted_until = ?,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (budget_wait_delta, new_accounted_until, now_iso, current_run.task_id),
            )
            new_waiting_since = None
            new_deadline_dt = new_deadline_dt + timedelta(seconds=wait_delta)
        elif target_status == TaskStatus.WAITING_FOR_INPUT:
            new_waiting_since = now_iso

        if wall_seconds_elapsed is not None:
            conn.execute(
                """
                UPDATE task_budgets
                SET wall_seconds_elapsed = MAX(wall_seconds_elapsed, ?), updated_at = ?
                WHERE task_id = ?
                """,
                (float(wall_seconds_elapsed), now_iso, current_run.task_id),
            )

        if is_terminal_status(target_status) and current_run.depth > 0:
            conn.execute(
                """
                UPDATE task_budgets
                SET active_children = MAX(0, active_children - 1), updated_at = ?
                WHERE task_id = ?
                """,
                (now_iso, current_run.task_id),
            )

        if result is not None:
            result_json: str | None = result.model_dump_json()
        elif (
            current_run.status == TaskStatus.WAITING_FOR_INPUT
            and target_status != TaskStatus.WAITING_FOR_INPUT
        ):
            result_json = None
        else:
            result_json = row["result_json"]
        updated_at_dt = max(now, current_run.updated_at)
        if new_deadline_dt < current_run.created_at:
            new_deadline_dt = current_run.created_at

        updated_run = Run(
            run_id=current_run.run_id,
            task_id=current_run.task_id,
            parent_run_id=current_run.parent_run_id,
            depth=current_run.depth,
            status=target_status,
            attempt=current_run.attempt,
            version=new_version,
            deadline_at=new_deadline_dt,
            progress=new_progress,
            transition_reason=reason,
            required_action=new_required_action,
            created_at=current_run.created_at,
            updated_at=updated_at_dt,
        )

        conn.execute(
            """
            UPDATE runs
            SET status = ?, version = ?, deadline_at = ?, progress = ?,
                transition_reason = ?, required_action = ?,
                waiting_since = ?, result_json = ?, updated_at = ?
            WHERE run_id = ?
            """,
            (
                updated_run.status.value,
                updated_run.version,
                _format_dt(updated_run.deadline_at),
                updated_run.progress,
                updated_run.transition_reason,
                updated_run.required_action,
                new_waiting_since,
                result_json,
                _format_dt(updated_run.updated_at),
                current_run.run_id,
            ),
        )
        self._insert_event(
            conn,
            task_id=current_run.task_id,
            run_id=current_run.run_id,
            step_id=None,
            event_type="run_transition",
            from_status=current_run.status.value,
            to_status=target_status.value,
            reason=reason,
            payload={"version": new_version, "depth": current_run.depth},
            created_at_iso=now_iso,
        )
        return updated_run

    def transition_run_status(
        self,
        run_id: str,
        target_status: TaskStatus,
        reason: str,
        *,
        progress: float | None = None,
        required_action: str | None = None,
        result: Result | None = None,
        expected_version: int | None = None,
        wall_seconds_elapsed: float | None = None,
    ) -> Run:
        """Atomically validate and apply a TaskStatus transition."""
        if wall_seconds_elapsed is not None:
            _reject_bool_float(wall_seconds_elapsed, "wall_seconds_elapsed")
        now = self._now()
        now_iso = _format_dt(now)

        rejection: Exception | None = None
        updated_run: Run | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            row = self._load_run_row(conn, run_id)
            current_run = self._row_to_run(row)

            if expected_version is not None and current_run.version != expected_version:
                raise ConflictError(
                    f"Version mismatch for run {run_id!r}: "
                    f"expected {expected_version}, got {current_run.version}."
                )

            try:
                validate_status_transition(current_run.status, target_status)
            except Exception as exc:
                self._insert_audit(
                    conn,
                    task_id=current_run.task_id,
                    run_id=run_id,
                    step_id=None,
                    actor="engine",
                    action="illegal_transition_rejected",
                    decision="deny",
                    detail={
                        "from_status": current_run.status.value,
                        "to_status": target_status.value,
                        "reason": reason,
                    },
                    recorded_at_iso=now_iso,
                )
                rejection = exc

            if rejection is None:
                updated_run = self._transition_run_status_tx(
                    conn,
                    row,
                    target_status,
                    reason,
                    now=now,
                    now_iso=now_iso,
                    progress=progress,
                    required_action=required_action,
                    result=result,
                    wall_seconds_elapsed=wall_seconds_elapsed,
                )

        if rejection is not None:
            raise rejection
        assert updated_run is not None
        return updated_run

    def try_transition_run_status(
        self,
        run_id: str,
        expected_from: TaskStatus,
        target_status: TaskStatus,
        reason: str,
        *,
        require_no_unknown_steps: bool = False,
    ) -> Run | None:
        """Atomically transition run_id if still in expected_from; otherwise return None."""
        now = self._now()
        now_iso = _format_dt(now)
        with write_transaction(self._db_path, self._lock) as conn:
            row = self._load_run_row(conn, run_id)
            current_run = self._row_to_run(row)
            if current_run.status != expected_from:
                return None
            task_row = self._load_task_row(conn, current_run.task_id)
            if bool(task_row["cancel_requested"]) and target_status != TaskStatus.CANCELLED:
                return None
            if require_no_unknown_steps:
                unk = conn.execute(
                    "SELECT 1 FROM steps WHERE run_id = ? AND status = 'unknown' LIMIT 1",
                    (run_id,),
                ).fetchone()
                if unk is not None:
                    return None
            return self._transition_run_status_tx(
                conn,
                row,
                target_status,
                reason,
                now=now,
                now_iso=now_iso,
            )

    def persist_terminal_result_if_missing(self, run_id: str, result: Result) -> None:
        """Persist a terminal Result if the run is terminal and lacks a matching Result."""
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            row = self._load_run_row(conn, run_id)
            current_run = self._row_to_run(row)
            if not is_terminal_status(current_run.status):
                return
            if result.status != current_run.status:
                return
            existing_raw = row["result_json"]
            if existing_raw is not None:
                existing = Result.model_validate_json(str(existing_raw))
                if existing.status == current_run.status:
                    return
            conn.execute(
                "UPDATE runs SET result_json = ?, updated_at = ? WHERE run_id = ?",
                (result.model_dump_json(), now_iso, run_id),
            )

    def pause_for_input(
        self,
        run_id: str,
        required_action: str,
        reason: str = "input_required",
        *,
        result: Result | None = None,
        wall_seconds_elapsed: float | None = None,
    ) -> Run:
        """Pause a running/recovering run into waiting_for_input with required_action."""
        updated = self.transition_run_status(
            run_id,
            TaskStatus.WAITING_FOR_INPUT,
            reason,
            required_action=required_action,
            result=result,
            wall_seconds_elapsed=wall_seconds_elapsed,
        )
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            self._insert_event(
                conn,
                task_id=updated.task_id,
                run_id=run_id,
                step_id=None,
                event_type="human_input_requested",
                from_status=None,
                to_status=TaskStatus.WAITING_FOR_INPUT.value,
                reason=reason,
                payload={"required_action": updated.required_action},
                created_at_iso=now_iso,
            )
        return updated

    def resume_from_input(
        self,
        run_id: str,
        human_input: dict[str, Any],
        reason: str = "human_input_received",
    ) -> Run:
        """Persist human_input, enforce human_wait_timeout_seconds, and transition to RUNNING."""
        now = self._now()
        now_iso = _format_dt(now)
        scrubbed_input = redact_payload_strict(dict(human_input))
        if contains_unredacted_secret_strict(scrubbed_input):
            raise ValueError("human_input contains unredacted secret material.")

        rejection: Exception | None = None
        updated_run: Run | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            row = self._load_run_row(conn, run_id)
            current_run = self._row_to_run(row)
            task_row = self._load_task_row(conn, current_run.task_id)
            budget_cfg = BudgetConfig.model_validate_json(str(task_row["budget_config_json"]))
            budget_row = self._load_budget_row(conn, current_run.task_id)
            cancel_requested = bool(task_row["cancel_requested"])

            if cancel_requested or is_terminal_status(current_run.status):
                self._insert_audit(
                    conn,
                    task_id=current_run.task_id,
                    run_id=run_id,
                    step_id=None,
                    actor="engine",
                    action="resume_rejected",
                    decision="deny",
                    detail={"reason": "run_terminal_or_cancelled"},
                    recorded_at_iso=now_iso,
                )
                rejection = TerminalStateError(
                    f"Cannot resume terminal or cancelled run {run_id!r}."
                )
            elif current_run.status != TaskStatus.WAITING_FOR_INPUT:
                validate_status_transition(current_run.status, TaskStatus.RUNNING)
                rejection = ConflictError(
                    f"Run {run_id!r} is in status {current_run.status.value!r}, "
                    "expected 'waiting_for_input'."
                )
            else:
                wait_delta, budget_wait_delta, new_accounted_until = (
                    self._compute_human_wait_deltas(
                        waiting_since_raw=row["waiting_since"],
                        accounted_until_raw=budget_row["human_wait_accounted_until"],
                        now=now,
                    )
                )
                new_human_wait = (
                    float(budget_row["human_wait_seconds_elapsed"]) + budget_wait_delta
                )

                if new_human_wait > budget_cfg.human_wait_timeout_seconds:
                    new_version = current_run.version + 1
                    conn.execute(
                        """
                        UPDATE task_budgets
                        SET human_wait_seconds_elapsed = ?,
                            human_wait_accounted_until = ?,
                            active_children = CASE
                                WHEN ? = 0 THEN 0
                                ELSE MAX(0, active_children - 1)
                            END,
                            updated_at = ?
                        WHERE task_id = ?
                        """,
                        (
                            new_human_wait,
                            new_accounted_until,
                            current_run.depth,
                            now_iso,
                            current_run.task_id,
                        ),
                    )
                    conn.execute(
                        """
                        UPDATE runs
                        SET status = ?, version = ?, transition_reason = ?,
                            required_action = NULL, waiting_since = NULL,
                            result_json = NULL, pending_human_input_json = NULL,
                            updated_at = ?
                        WHERE run_id = ?
                        """,
                        (
                            TaskStatus.FAILED.value,
                            new_version,
                            "human_wait_timeout_exceeded",
                            now_iso,
                            run_id,
                        ),
                    )
                    self._insert_event(
                        conn,
                        task_id=current_run.task_id,
                        run_id=run_id,
                        step_id=None,
                        event_type="run_transition",
                        from_status=TaskStatus.WAITING_FOR_INPUT.value,
                        to_status=TaskStatus.FAILED.value,
                        reason="human_wait_timeout_exceeded",
                        payload={
                            "human_wait_seconds_elapsed": new_human_wait,
                            "human_wait_timeout_seconds": budget_cfg.human_wait_timeout_seconds,
                        },
                        created_at_iso=now_iso,
                    )
                    if current_run.depth == 0:
                        placeholders = ", ".join("?" for _ in _NON_TERMINAL_STATUS_VALUES)
                        descendants = conn.execute(
                            f"""
                            SELECT run_id, status, version
                            FROM runs
                            WHERE task_id = ? AND run_id != ? AND status IN ({placeholders})
                            """,
                            (current_run.task_id, run_id, *_NON_TERMINAL_STATUS_VALUES),
                        ).fetchall()
                        for desc in descendants:
                            desc_run_id = str(desc["run_id"])
                            desc_status = str(desc["status"])
                            desc_version = int(desc["version"]) + 1
                            conn.execute(
                                """
                                UPDATE runs
                                SET status = ?, version = ?, transition_reason = ?,
                                    required_action = NULL, waiting_since = NULL,
                                    result_json = NULL, pending_human_input_json = NULL,
                                    updated_at = ?
                                WHERE run_id = ?
                                """,
                                (
                                    TaskStatus.FAILED.value,
                                    desc_version,
                                    "parent_human_wait_timeout_exceeded",
                                    now_iso,
                                    desc_run_id,
                                ),
                            )
                            self._insert_event(
                                conn,
                                task_id=current_run.task_id,
                                run_id=desc_run_id,
                                step_id=None,
                                event_type="run_transition",
                                from_status=desc_status,
                                to_status=TaskStatus.FAILED.value,
                                reason="parent_human_wait_timeout_exceeded",
                                payload={
                                    "parent_run_id": run_id,
                                    "human_wait_seconds_elapsed": new_human_wait,
                                    "human_wait_timeout_seconds": (
                                        budget_cfg.human_wait_timeout_seconds
                                    ),
                                },
                                created_at_iso=now_iso,
                            )
                    self._insert_audit(
                        conn,
                        task_id=current_run.task_id,
                        run_id=run_id,
                        step_id=None,
                        actor="engine",
                        action="human_wait_timeout",
                        decision="deny",
                        detail={
                            "human_wait_seconds_elapsed": new_human_wait,
                            "limit": budget_cfg.human_wait_timeout_seconds,
                        },
                        recorded_at_iso=now_iso,
                    )
                    rejection = BudgetExceededError(
                        f"Human wait timeout exceeded ({new_human_wait:.2f}s > "
                        f"{budget_cfg.human_wait_timeout_seconds:.2f}s)."
                    )
                else:
                    new_version = current_run.version + 1
                    new_deadline = current_run.deadline_at + timedelta(seconds=wait_delta)
                    updated_at = max(now, current_run.updated_at)
                    updated_run = Run(
                        run_id=current_run.run_id,
                        task_id=current_run.task_id,
                        parent_run_id=current_run.parent_run_id,
                        depth=current_run.depth,
                        status=TaskStatus.RUNNING,
                        attempt=current_run.attempt,
                        version=new_version,
                        deadline_at=new_deadline,
                        progress=current_run.progress,
                        transition_reason=reason,
                        required_action=None,
                        created_at=current_run.created_at,
                        updated_at=updated_at,
                    )
                    conn.execute(
                        """
                        UPDATE task_budgets
                        SET human_wait_seconds_elapsed = ?,
                            human_wait_accounted_until = ?,
                            updated_at = ?
                        WHERE task_id = ?
                        """,
                        (new_human_wait, new_accounted_until, now_iso, current_run.task_id),
                    )
                    conn.execute(
                        """
                        UPDATE runs
                        SET status = ?, version = ?, deadline_at = ?, transition_reason = ?,
                            required_action = NULL, waiting_since = NULL, result_json = NULL,
                            pending_human_input_json = ?, updated_at = ?
                        WHERE run_id = ?
                        """,
                        (
                            TaskStatus.RUNNING.value,
                            new_version,
                            _format_dt(new_deadline),
                            reason,
                            _safe_json_dumps(scrubbed_input),
                            _format_dt(updated_at),
                            run_id,
                        ),
                    )
                    self._insert_event(
                        conn,
                        task_id=current_run.task_id,
                        run_id=run_id,
                        step_id=None,
                        event_type="human_input_received",
                        from_status=TaskStatus.WAITING_FOR_INPUT.value,
                        to_status=TaskStatus.RUNNING.value,
                        reason=reason,
                        payload={"human_input": scrubbed_input, "wait_seconds": wait_delta},
                        created_at_iso=now_iso,
                    )

        if rejection is not None:
            raise rejection
        assert updated_run is not None
        return updated_run

    def consume_pending_human_input(self, run_id: str) -> dict[str, Any] | None:
        """Atomically fetch and clear persisted pending human_input for a resumed run."""
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            row = self._load_run_row(conn, run_id)
            raw = row["pending_human_input_json"]
            if raw is None:
                return None
            conn.execute(
                "UPDATE runs SET pending_human_input_json = NULL, updated_at = ? WHERE run_id = ?",
                (now_iso, run_id),
            )
            parsed: dict[str, Any] = json.loads(str(raw))
            return parsed

    # ------------------------------------------------------------------
    # Steps, 6-Step Lease Fencing & Crash Recovery (F06, A08, A09)
    # ------------------------------------------------------------------

    def enqueue_step(
        self,
        run_id: str,
        tool_id: str,
        args: dict[str, Any],
        completion_verifier: str,
        effect_class: EffectClass,
        *,
        target_origin: str | None = None,
        operation_key: str | None = None,
        step_id: str | None = None,
    ) -> Step:
        """Enqueue a new PENDING step on a non-terminal, non-cancelled run."""
        now_iso = _format_dt(self._now())
        actual_step_id = step_id or f"step-{uuid.uuid4().hex[:12]}"
        scrubbed_args = redact_payload_strict(dict(args))
        if contains_unredacted_secret_strict(scrubbed_args):
            raise ValueError("Redacted step args still contain unredacted secrets.")

        with write_transaction(self._db_path, self._lock) as conn:
            run_row = self._load_run_row(conn, run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)
            if is_terminal_status(run.status) or bool(task_row["cancel_requested"]):
                raise TerminalStateError(
                    f"Cannot enqueue step on terminal/cancelled run {run_id!r}."
                )

            idx_row = conn.execute(
                "SELECT COALESCE(MAX(step_index), -1) + 1 AS next_idx FROM steps WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            next_index = int(idx_row["next_idx"]) if idx_row is not None else 0
            actual_op_key = operation_key or f"{run.task_id}:{run_id}:{next_index}:{actual_step_id}"

            step = Step(
                step_id=actual_step_id,
                run_id=run_id,
                step_index=next_index,
                status=StepStatus.PENDING,
                attempt=0,
                tool_id=tool_id,
                operation_key=actual_op_key,
                lease_owner=None,
                lease_expiry=None,
                lease_generation=0,
                completion_verifier=completion_verifier,
                outcome=None,
            )
            conn.execute(
                """
                INSERT INTO steps (
                    step_id, run_id, step_index, status, attempt, tool_id,
                    redacted_args_json, exec_args_json, target_origin, effect_class,
                    operation_key, lease_owner, lease_expiry, lease_generation,
                    completion_verifier, outcome, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, NULL, NULL, 0, ?, NULL, ?, ?)
                """,
                (
                    step.step_id,
                    step.run_id,
                    step.step_index,
                    step.status.value,
                    step.tool_id,
                    _safe_json_dumps(scrubbed_args),
                    _safe_json_dumps(dict(args)),
                    target_origin,
                    effect_class.value,
                    step.operation_key,
                    step.completion_verifier,
                    now_iso,
                    now_iso,
                ),
            )
            self._insert_event(
                conn,
                task_id=run.task_id,
                run_id=run_id,
                step_id=step.step_id,
                event_type="step_enqueued",
                from_status=None,
                to_status=step.status.value,
                reason="step_enqueued",
                payload={"tool_id": tool_id, "step_index": next_index},
                created_at_iso=now_iso,
            )
            return step

    def acquire_step_lease(
        self,
        worker_id: str,
        ttl_s: float,
        *,
        run_id: str | None = None,
        step_id: str | None = None,
    ) -> Step | None:
        """Step 1: Claim lowest-index pending or expired-pre-prepare leased step."""
        _reject_bool_float(ttl_s, "ttl_s", allow_zero=False)
        now = self._now()
        now_iso = _format_dt(now)
        expiry = now + timedelta(seconds=float(ttl_s))
        expiry_iso = _format_dt(expiry)

        with write_transaction(self._db_path, self._lock) as conn:
            filters = [
                "r.status IN (?, ?, ?)",
                "t.cancel_requested = 0",
                (
                    "((s.status = 'pending' AND s.lease_owner IS NULL) "
                    "OR (s.status = 'leased' AND s.lease_expiry IS NOT NULL "
                    "AND s.lease_expiry <= ?))"
                ),
            ]
            params: list[Any] = [*_CLAIMABLE_RUN_STATUS_VALUES, now_iso]
            if run_id is not None:
                filters.append("s.run_id = ?")
                params.append(run_id)
            if step_id is not None:
                filters.append("s.step_id = ?")
                params.append(step_id)

            query = f"""
                SELECT s.*, r.task_id
                FROM steps s
                JOIN runs r ON r.run_id = s.run_id
                JOIN tasks t ON t.task_id = r.task_id
                WHERE {' AND '.join(filters)}
                ORDER BY s.step_index ASC, s.created_at ASC
                LIMIT 1
            """
            row = conn.execute(query, params).fetchone()
            if row is None:
                return None

            claimed_step_id = str(row["step_id"])
            task_id = str(row["task_id"])
            new_gen = int(row["lease_generation"]) + 1
            new_attempt = int(row["attempt"]) + 1
            prev_status = str(row["status"])

            conn.execute(
                """
                UPDATE steps
                SET status = ?, attempt = ?, lease_owner = ?, lease_expiry = ?,
                    lease_generation = ?, updated_at = ?
                WHERE step_id = ?
                """,
                (
                    StepStatus.LEASED.value,
                    new_attempt,
                    worker_id,
                    expiry_iso,
                    new_gen,
                    now_iso,
                    claimed_step_id,
                ),
            )
            self._insert_event(
                conn,
                task_id=task_id,
                run_id=str(row["run_id"]),
                step_id=claimed_step_id,
                event_type="step_leased",
                from_status=prev_status,
                to_status=StepStatus.LEASED.value,
                reason="lease_acquired",
                payload={"lease_owner": worker_id, "lease_generation": new_gen},
                created_at_iso=now_iso,
            )
            updated_row = conn.execute(
                "SELECT * FROM steps WHERE step_id = ?", (claimed_step_id,)
            ).fetchone()
            assert updated_row is not None
            return self._row_to_step(updated_row)

    def prepare_step_attempt(
        self,
        step_id: str,
        lease_generation: int,
        op_key: str,
        *,
        idempotency_key: str | None = None,
    ) -> Step:
        """Step 2: Validate lease, persist operation_key + step_attempt, set PREPARED."""
        now = self._now()
        now_iso = _format_dt(now)
        actual_idem = idempotency_key or op_key
        rejection: Exception | None = None
        updated_step: Step | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                raise NotFoundError(f"Step {step_id!r} not found.")
            step = self._row_to_step(step_row)
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)
            cancel_requested = bool(task_row["cancel_requested"])

            if is_terminal_status(run.status) or cancel_requested:
                self._insert_audit(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    actor=step.lease_owner or "unknown",
                    action="prepare_rejected",
                    decision="deny",
                    detail={
                        "reason": "run_terminal_or_cancelled",
                        "lease_generation": lease_generation,
                    },
                    recorded_at_iso=now_iso,
                )
                rejection = TerminalStateError(
                    f"Cannot prepare step {step_id!r} on terminal/cancelled run {run.run_id!r}."
                )
            elif (
                step.lease_generation != lease_generation
                or step.lease_owner is None
                or step.lease_expiry is None
                or step.lease_expiry <= now
                or step.status != StepStatus.LEASED
            ):
                self._insert_audit(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    actor=step.lease_owner or "unknown",
                    action="stale_prepare_rejected",
                    decision="deny",
                    detail={
                        "expected_generation": step.lease_generation,
                        "provided_generation": lease_generation,
                        "step_status": step.status.value,
                    },
                    recorded_at_iso=now_iso,
                )
                rejection = LeaseFencingError(
                    f"Lease fencing check failed preparing step {step_id!r} "
                    f"(gen={lease_generation}, current={step.lease_generation})."
                )
            elif op_key != step.operation_key:
                raise IdempotencyConflictError(
                    f"operation_key mismatch for step {step_id!r}: "
                    f"{op_key!r} != {step.operation_key!r}"
                )
            else:
                conn.execute(
                    """
                    INSERT INTO operation_keys (
                        operation_key, task_id, run_id, step_id, latest_attempt,
                        tool_id, effect_class, idempotency_key, status,
                        redacted_args_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?, ?)
                    ON CONFLICT(operation_key) DO UPDATE SET
                        latest_attempt = excluded.latest_attempt,
                        idempotency_key = excluded.idempotency_key,
                        status = 'prepared',
                        updated_at = excluded.updated_at
                    """,
                    (
                        op_key,
                        run.task_id,
                        run.run_id,
                        step_id,
                        step.attempt,
                        step.tool_id,
                        str(step_row["effect_class"]),
                        actual_idem,
                        str(step_row["redacted_args_json"]),
                        now_iso,
                        now_iso,
                    ),
                )
                attempt_id = f"att-{step_id}-{step.attempt}"
                conn.execute(
                    """
                    INSERT INTO step_attempts (
                        attempt_id, step_id, run_id, task_id, attempt,
                        operation_key, idempotency_key, lease_generation,
                        status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?)
                    ON CONFLICT(step_id, attempt) DO UPDATE SET
                        status = 'prepared',
                        lease_generation = excluded.lease_generation,
                        updated_at = excluded.updated_at
                    """,
                    (
                        attempt_id,
                        step_id,
                        run.run_id,
                        run.task_id,
                        step.attempt,
                        op_key,
                        actual_idem,
                        lease_generation,
                        now_iso,
                        now_iso,
                    ),
                )
                conn.execute(
                    "UPDATE steps SET status = ?, updated_at = ? WHERE step_id = ?",
                    (StepStatus.PREPARED.value, now_iso, step_id),
                )
                self._insert_event(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    event_type="step_prepared",
                    from_status=StepStatus.LEASED.value,
                    to_status=StepStatus.PREPARED.value,
                    reason="step_prepared",
                    payload={"operation_key": op_key, "attempt": step.attempt},
                    created_at_iso=now_iso,
                )
                updated_row = conn.execute(
                    "SELECT * FROM steps WHERE step_id = ?", (step_id,)
                ).fetchone()
                assert updated_row is not None
                updated_step = self._row_to_step(updated_row)

        if rejection is not None:
            raise rejection
        assert updated_step is not None
        return updated_step

    def mark_step_executing(self, step_id: str, lease_generation: int) -> Step:
        """Transition PREPARED step to EXECUTING before releasing DB lock for external I/O."""
        now = self._now()
        now_iso = _format_dt(now)
        rejection: Exception | None = None
        updated_step: Step | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                raise NotFoundError(f"Step {step_id!r} not found.")
            step = self._row_to_step(step_row)
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)

            if is_terminal_status(run.status) or bool(task_row["cancel_requested"]):
                rejection = TerminalStateError(
                    f"Cannot mark executing on terminal/cancelled run {run.run_id!r}."
                )
            elif (
                step.lease_generation != lease_generation
                or step.lease_owner is None
                or step.lease_expiry is None
                or step.lease_expiry <= now
                or step.status != StepStatus.PREPARED
            ):
                self._insert_audit(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    actor=step.lease_owner or "unknown",
                    action="stale_execute_rejected",
                    decision="deny",
                    detail={
                        "expected_generation": step.lease_generation,
                        "provided_generation": lease_generation,
                        "step_status": step.status.value,
                    },
                    recorded_at_iso=now_iso,
                )
                rejection = LeaseFencingError(
                    f"Lease fencing failed before execution on step {step_id!r}."
                )
            else:
                conn.execute(
                    "UPDATE steps SET status = ?, updated_at = ? WHERE step_id = ?",
                    (StepStatus.EXECUTING.value, now_iso, step_id),
                )
                conn.execute(
                    "UPDATE operation_keys SET status = 'executing', updated_at = ? "
                    "WHERE operation_key = ?",
                    (now_iso, step.operation_key),
                )
                conn.execute(
                    """
                    UPDATE step_attempts SET status = 'executing', updated_at = ?
                    WHERE step_id = ? AND attempt = ?
                    """,
                    (now_iso, step_id, step.attempt),
                )
                updated_row = conn.execute(
                    "SELECT * FROM steps WHERE step_id = ?", (step_id,)
                ).fetchone()
                assert updated_row is not None
                updated_step = self._row_to_step(updated_row)

        if rejection is not None:
            raise rejection
        assert updated_step is not None
        return updated_step

    def commit_step_result(
        self,
        step_id: str,
        lease_generation: int,
        final_step_status: StepStatus,
        outcome: str,
        receipt: ActionReceipt,
        *,
        step_output: dict[str, Any] | None = None,
        expected_worker: str | None = None,
    ) -> Step:
        """Step 4: Fenced commit of verified step result + ActionReceipt (keeps generation)."""
        if contains_unredacted_secret_strict(receipt.model_dump()):
            raise ValueError("ActionReceipt contains unredacted secret material.")

        scrubbed_output = redact_payload_strict(step_output) if step_output is not None else None
        if scrubbed_output is not None and contains_unredacted_secret_strict(scrubbed_output):
            raise ValueError("step_output contains unredacted secret material.")

        now = self._now()
        now_iso = _format_dt(now)
        rejection: Exception | None = None
        updated_step: Step | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                raise NotFoundError(f"Step {step_id!r} not found.")
            step = self._row_to_step(step_row)
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)
            cancel_requested = bool(task_row["cancel_requested"])

            valid_active_step_statuses = (
                StepStatus.LEASED,
                StepStatus.PREPARED,
                StepStatus.EXECUTING,
                StepStatus.VERIFYING,
            )
            if is_terminal_status(run.status) or cancel_requested:
                self._insert_event(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    event_type="stale_result_rejected",
                    from_status=step.status.value,
                    to_status=step.status.value,
                    reason="run_terminal_or_cancelled",
                    payload={"lease_generation": lease_generation, "run_status": run.status.value},
                    created_at_iso=now_iso,
                )
                self._insert_audit(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    actor=expected_worker or step.lease_owner or "worker",
                    action="stale_result_rejected",
                    decision="deny",
                    detail={
                        "reason": "run_terminal_or_cancelled",
                        "run_status": run.status.value,
                        "cancel_requested": cancel_requested,
                        "lease_generation": lease_generation,
                    },
                    recorded_at_iso=now_iso,
                )
                rejection = TerminalStateError(
                    f"Rejected late step result for terminal/cancelled run {run.run_id!r}."
                )
            elif (
                step.lease_generation != lease_generation
                or step.lease_owner is None
                or (expected_worker is not None and step.lease_owner != expected_worker)
                or step.lease_expiry is None
                or step.lease_expiry <= now
                or step.status not in valid_active_step_statuses
            ):
                self._insert_event(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    event_type="stale_result_rejected",
                    from_status=step.status.value,
                    to_status=step.status.value,
                    reason="stale_or_expired_lease",
                    payload={
                        "provided_generation": lease_generation,
                        "current_generation": step.lease_generation,
                        "expected_worker": expected_worker,
                        "current_owner": step.lease_owner,
                    },
                    created_at_iso=now_iso,
                )
                self._insert_audit(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    actor=expected_worker or "worker",
                    action="stale_result_rejected",
                    decision="deny",
                    detail={
                        "reason": "stale_or_expired_lease",
                        "provided_generation": lease_generation,
                        "current_generation": step.lease_generation,
                        "step_status": step.status.value,
                    },
                    recorded_at_iso=now_iso,
                )
                rejection = LeaseFencingError(
                    f"Stale/expired lease rejected committing step {step_id!r} "
                    f"(provided gen={lease_generation}, current gen={step.lease_generation})."
                )
            else:
                # Preserve lease_generation while clearing lease_owner/lease_expiry.
                conn.execute(
                    """
                    UPDATE steps
                    SET status = ?, outcome = ?, lease_owner = NULL, lease_expiry = NULL,
                        exec_args_json = '{}', step_output_json = ?, updated_at = ?
                    WHERE step_id = ?
                    """,
                    (
                        final_step_status.value,
                        outcome,
                        _safe_json_dumps(scrubbed_output) if scrubbed_output is not None else None,
                        now_iso,
                        step_id,
                    ),
                )
                op_status = (
                    "succeeded"
                    if final_step_status == StepStatus.SUCCEEDED
                    else final_step_status.value
                )
                conn.execute(
                    "UPDATE operation_keys SET status = ?, updated_at = ? WHERE operation_key = ?",
                    (op_status, now_iso, step.operation_key),
                )
                conn.execute(
                    """
                    UPDATE step_attempts SET status = ?, updated_at = ?
                    WHERE step_id = ? AND attempt = ?
                    """,
                    (op_status, now_iso, step_id, step.attempt),
                )
                self._insert_receipt_row(conn, receipt)
                self._insert_event(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    event_type="step_verified",
                    from_status=step.status.value,
                    to_status=final_step_status.value,
                    reason=outcome,
                    payload={"receipt_id": receipt.receipt_id, "outcome": receipt.outcome.value},
                    created_at_iso=now_iso,
                )
                updated_row = conn.execute(
                    "SELECT * FROM steps WHERE step_id = ?", (step_id,)
                ).fetchone()
                assert updated_row is not None
                updated_step = self._row_to_step(updated_row)

        if rejection is not None:
            raise rejection
        assert updated_step is not None
        return updated_step

    def mark_step_unknown(
        self,
        step_id: str,
        *,
        lease_generation: int | None = None,
        reason: str = "crash_or_timeout_unknown",
        receipt: ActionReceipt | None = None,
    ) -> Step:
        """Transition an interrupted or timed-out step to StepStatus.UNKNOWN (A08)."""
        if receipt is not None and contains_unredacted_secret_strict(receipt.model_dump()):
            raise ValueError("ActionReceipt contains unredacted secret material.")

        now_iso = _format_dt(self._now())
        rejection: Exception | None = None
        updated_step: Step | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                raise NotFoundError(f"Step {step_id!r} not found.")
            step = self._row_to_step(step_row)
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)

            if is_terminal_status(run.status) or bool(task_row["cancel_requested"]):
                self._insert_audit(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    actor="coordinator",
                    action="stale_unknown_rejected",
                    decision="deny",
                    detail={
                        "reason": "run_terminal_or_cancelled",
                        "run_status": run.status.value,
                        "cancel_requested": bool(task_row["cancel_requested"]),
                        "lease_generation": lease_generation,
                    },
                    recorded_at_iso=now_iso,
                )
                rejection = TerminalStateError(
                    f"Cannot mark step {step_id!r} unknown on terminal/cancelled run "
                    f"{run.run_id!r}."
                )
            elif lease_generation is not None and step.lease_generation != lease_generation:
                self._insert_audit(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    actor="coordinator",
                    action="stale_unknown_rejected",
                    decision="deny",
                    detail={
                        "provided_generation": lease_generation,
                        "current_generation": step.lease_generation,
                    },
                    recorded_at_iso=now_iso,
                )
                rejection = LeaseFencingError(
                    f"Lease generation mismatch marking step {step_id!r} unknown."
                )
            else:
                new_gen = step.lease_generation + 1 if step.lease_generation >= 1 else 1
                conn.execute(
                    """
                    UPDATE steps
                    SET status = ?, outcome = 'unknown_needs_reconciliation',
                        lease_owner = NULL, lease_expiry = NULL,
                        lease_generation = ?, updated_at = ?
                    WHERE step_id = ?
                    """,
                    (StepStatus.UNKNOWN.value, new_gen, now_iso, step_id),
                )
                conn.execute(
                    """
                    INSERT INTO operation_keys (
                        operation_key, task_id, run_id, step_id, latest_attempt,
                        tool_id, effect_class, idempotency_key, status,
                        redacted_args_json, reconciliation_note, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unknown', ?, ?, ?, ?)
                    ON CONFLICT(operation_key) DO UPDATE SET
                        status = 'unknown',
                        reconciliation_note = excluded.reconciliation_note,
                        updated_at = excluded.updated_at
                    """,
                    (
                        step.operation_key,
                        run.task_id,
                        run.run_id,
                        step_id,
                        max(1, step.attempt),
                        step.tool_id,
                        str(step_row["effect_class"]),
                        step.operation_key,
                        str(step_row["redacted_args_json"]),
                        reason,
                        now_iso,
                        now_iso,
                    ),
                )
                if receipt is not None:
                    self._insert_receipt_row(conn, receipt)
                self._insert_event(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    event_type="step_unknown",
                    from_status=step.status.value,
                    to_status=StepStatus.UNKNOWN.value,
                    reason=reason,
                    payload={"operation_key": step.operation_key, "lease_generation": new_gen},
                    created_at_iso=now_iso,
                )
                updated_row = conn.execute(
                    "SELECT * FROM steps WHERE step_id = ?", (step_id,)
                ).fetchone()
                assert updated_row is not None
                updated_step = self._row_to_step(updated_row)

        if rejection is not None:
            raise rejection
        assert updated_step is not None
        return updated_step

    def reset_pre_exec_step_to_pending(
        self, step_id: str, reason: str = "lease_expired_pre_exec"
    ) -> Step:
        """Reset an expired LEASED/PREPARED step (no external I/O started) back to PENDING."""
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                raise NotFoundError(f"Step {step_id!r} not found.")
            step = self._row_to_step(step_row)
            if step.status not in (StepStatus.LEASED, StepStatus.PREPARED):
                raise ConflictError(
                    f"Cannot reset step {step_id!r} from status {step.status.value!r}."
                )
            run_row = self._load_run_row(conn, step.run_id)
            task_id = str(run_row["task_id"])
            new_gen = step.lease_generation + 1
            conn.execute(
                """
                UPDATE steps
                SET status = ?, lease_owner = NULL, lease_expiry = NULL,
                    lease_generation = ?, updated_at = ?
                WHERE step_id = ?
                """,
                (StepStatus.PENDING.value, new_gen, now_iso, step_id),
            )
            self._insert_event(
                conn,
                task_id=task_id,
                run_id=step.run_id,
                step_id=step_id,
                event_type="step_reset_pending",
                from_status=step.status.value,
                to_status=StepStatus.PENDING.value,
                reason=reason,
                payload={"lease_generation": new_gen},
                created_at_iso=now_iso,
            )
            updated_row = conn.execute(
                "SELECT * FROM steps WHERE step_id = ?", (step_id,)
            ).fetchone()
            assert updated_row is not None
            return self._row_to_step(updated_row)

    def requeue_step_after_transient_failure(
        self,
        step_id: str,
        lease_generation: int,
        receipt: ActionReceipt,
        reason: str = "transient_retry_scheduled",
    ) -> Step:
        """Atomically record a transient-failure receipt and reset step to PENDING for retry."""
        if contains_unredacted_secret_strict(receipt.model_dump()):
            raise ValueError("ActionReceipt contains unredacted secret material.")
        now = self._now()
        now_iso = _format_dt(now)
        rejection: Exception | None = None
        updated_step: Step | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                raise NotFoundError(f"Step {step_id!r} not found.")
            step = self._row_to_step(step_row)
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)

            if is_terminal_status(run.status) or bool(task_row["cancel_requested"]):
                rejection = TerminalStateError(
                    f"Cannot requeue step {step_id!r} on terminal/cancelled run {run.run_id!r}."
                )
            elif step.lease_generation != lease_generation or step.lease_owner is None:
                rejection = LeaseFencingError(
                    f"Lease fencing failed requeuing step {step_id!r} after transient error."
                )
            else:
                new_gen = step.lease_generation + 1
                conn.execute(
                    """
                    UPDATE steps
                    SET status = ?, outcome = ?, lease_owner = NULL, lease_expiry = NULL,
                        lease_generation = ?, updated_at = ?
                    WHERE step_id = ?
                    """,
                    (
                        StepStatus.PENDING.value,
                        receipt.outcome.value,
                        new_gen,
                        now_iso,
                        step_id,
                    ),
                )
                self._insert_receipt_row(conn, receipt)
                self._insert_event(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    event_type="step_requeued_for_retry",
                    from_status=step.status.value,
                    to_status=StepStatus.PENDING.value,
                    reason=reason,
                    payload={"attempt": step.attempt, "lease_generation": new_gen},
                    created_at_iso=now_iso,
                )
                updated_row = conn.execute(
                    "SELECT * FROM steps WHERE step_id = ?", (step_id,)
                ).fetchone()
                assert updated_row is not None
                updated_step = self._row_to_step(updated_row)

        if rejection is not None:
            raise rejection
        assert updated_step is not None
        return updated_step

    def requeue_step_for_auth_retry(
        self,
        step_id: str,
        lease_generation: int,
        receipt: ActionReceipt,
        reason: str = "auth_expired_retry_pending",
    ) -> Step:
        """Record FAILED_PERMISSION receipt and return step to PENDING without burning retries."""
        if contains_unredacted_secret_strict(receipt.model_dump()):
            raise ValueError("ActionReceipt contains unredacted secret material.")
        now = self._now()
        now_iso = _format_dt(now)
        rejection: Exception | None = None
        updated_step: Step | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                raise NotFoundError(f"Step {step_id!r} not found.")
            step = self._row_to_step(step_row)
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)

            if is_terminal_status(run.status) or bool(task_row["cancel_requested"]):
                rejection = TerminalStateError(
                    f"Cannot requeue step {step_id!r} on terminal/cancelled run {run.run_id!r}."
                )
            elif step.lease_generation != lease_generation or step.lease_owner is None:
                rejection = LeaseFencingError(
                    f"Lease fencing failed requeuing step {step_id!r} after auth expiry."
                )
            else:
                new_gen = step.lease_generation + 1
                conn.execute(
                    """
                    UPDATE steps
                    SET status = ?, outcome = ?, lease_owner = NULL, lease_expiry = NULL,
                        lease_generation = ?, updated_at = ?
                    WHERE step_id = ?
                    """,
                    (
                        StepStatus.PENDING.value,
                        receipt.outcome.value,
                        new_gen,
                        now_iso,
                        step_id,
                    ),
                )
                self._insert_receipt_row(conn, receipt)
                self._insert_event(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    event_type="step_requeued_auth_expired",
                    from_status=step.status.value,
                    to_status=StepStatus.PENDING.value,
                    reason=reason,
                    payload={"attempt": step.attempt, "lease_generation": new_gen},
                    created_at_iso=now_iso,
                )
                updated_row = conn.execute(
                    "SELECT * FROM steps WHERE step_id = ?", (step_id,)
                ).fetchone()
                assert updated_row is not None
                updated_step = self._row_to_step(updated_row)

        if rejection is not None:
            raise rejection
        assert updated_step is not None
        return updated_step

    def _reconcile_step_unknown_tx(
        self,
        conn: sqlite3.Connection,
        step_row: sqlite3.Row,
        step: Step,
        task_id: str,
        target_status: StepStatus,
        outcome: str,
        reason: str,
        *,
        now_iso: str,
        receipt: ActionReceipt | None = None,
        scrubbed_output: dict[str, Any] | None = None,
    ) -> Step:
        del step_row
        clear_exec = target_status in (
            StepStatus.SUCCEEDED,
            StepStatus.FAILED,
            StepStatus.CANCELLED,
        )
        conn.execute(
            """
            UPDATE steps
            SET status = ?, outcome = ?, lease_owner = NULL, lease_expiry = NULL,
                exec_args_json = CASE WHEN ? THEN '{}' ELSE exec_args_json END,
                step_output_json = COALESCE(?, step_output_json),
                updated_at = ?
            WHERE step_id = ?
            """,
            (
                target_status.value,
                outcome,
                1 if clear_exec else 0,
                _safe_json_dumps(scrubbed_output) if scrubbed_output is not None else None,
                now_iso,
                step.step_id,
            ),
        )
        conn.execute(
            """
            UPDATE operation_keys
            SET status = 'reconciled', reconciliation_note = ?, updated_at = ?
            WHERE operation_key = ?
            """,
            (reason, now_iso, step.operation_key),
        )

        # Reconcile tool budget for this step so applied EFFECT steps never bypass max_tool_calls
        # and active reservations are not stranded, without double-charging timed-out steps.
        active_tool_rows = conn.execute(
            """
            SELECT * FROM budget_reservations
            WHERE step_id = ? AND kind = 'tool' AND status = 'active'
            ORDER BY created_at DESC, rowid DESC
            """,
            (step.step_id,),
        ).fetchall()
        if active_tool_rows:
            reserved_sum = sum(int(r["tool_calls_reserved"]) for r in active_tool_rows)
            add_used = 1 if target_status == StepStatus.SUCCEEDED else 0
            new_res_status = "reconciled" if target_status == StepStatus.SUCCEEDED else "released"
            conn.execute(
                """
                UPDATE task_budgets
                SET tool_calls_used = tool_calls_used + ?,
                    tool_calls_reserved = MAX(0, tool_calls_reserved - ?),
                    updated_at = ?
                WHERE task_id = ?
                """,
                (add_used, reserved_sum, now_iso, task_id),
            )
            conn.execute(
                """
                UPDATE budget_reservations
                SET status = ?, updated_at = ?
                WHERE step_id = ? AND kind = 'tool' AND status = 'active'
                """,
                (new_res_status, now_iso, step.step_id),
            )
            self._insert_event(
                conn,
                task_id=task_id,
                run_id=step.run_id,
                step_id=step.step_id,
                event_type="budget_reconciled",
                from_status=None,
                to_status=None,
                reason=f"unknown_step_{new_res_status}",
                payload={"tool_calls_used": add_used, "released_reserved": reserved_sum},
                created_at_iso=now_iso,
            )
        elif target_status == StepStatus.SUCCEEDED:
            latest_tool_res = conn.execute(
                """
                SELECT status FROM budget_reservations
                WHERE step_id = ? AND kind = 'tool'
                ORDER BY created_at DESC, rowid DESC
                LIMIT 1
                """,
                (step.step_id,),
            ).fetchone()
            if latest_tool_res is None or str(latest_tool_res["status"]) != "reconciled":
                conn.execute(
                    """
                    UPDATE task_budgets
                    SET tool_calls_used = tool_calls_used + 1,
                        updated_at = ?
                    WHERE task_id = ?
                    """,
                    (now_iso, task_id),
                )
                self._insert_event(
                    conn,
                    task_id=task_id,
                    run_id=step.run_id,
                    step_id=step.step_id,
                    event_type="budget_reconciled",
                    from_status=None,
                    to_status=None,
                    reason="applied_unknown_step_charged",
                    payload={"tool_calls_used": 1},
                    created_at_iso=now_iso,
                )

        if receipt is not None:
            self._insert_receipt_row(conn, receipt)
        self._insert_event(
            conn,
            task_id=task_id,
            run_id=step.run_id,
            step_id=step.step_id,
            event_type="step_reconciled",
            from_status=StepStatus.UNKNOWN.value,
            to_status=target_status.value,
            reason=reason,
            payload={"outcome": outcome, "operation_key": step.operation_key},
            created_at_iso=now_iso,
        )
        updated_row = conn.execute(
            "SELECT * FROM steps WHERE step_id = ?", (step.step_id,)
        ).fetchone()
        assert updated_row is not None
        return self._row_to_step(updated_row)

    def reconcile_step_unknown(
        self,
        step_id: str,
        target_status: StepStatus,
        outcome: str,
        reason: str,
        *,
        receipt: ActionReceipt | None = None,
        step_output: dict[str, Any] | None = None,
    ) -> Step:
        """Reconcile a StepStatus.UNKNOWN step to SUCCEEDED, PENDING (retry), or FAILED."""
        if receipt is not None and contains_unredacted_secret_strict(receipt.model_dump()):
            raise ValueError("ActionReceipt contains unredacted secret material.")
        scrubbed_output = redact_payload_strict(step_output) if step_output is not None else None
        if scrubbed_output is not None and contains_unredacted_secret_strict(scrubbed_output):
            raise ValueError("step_output contains unredacted secret material.")

        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                raise NotFoundError(f"Step {step_id!r} not found.")
            step = self._row_to_step(step_row)
            if step.status != StepStatus.UNKNOWN:
                raise ConflictError(
                    f"Step {step_id!r} is in status {step.status.value!r}, expected 'unknown'."
                )
            run_row = self._load_run_row(conn, step.run_id)
            task_id = str(run_row["task_id"])
            return self._reconcile_step_unknown_tx(
                conn,
                step_row,
                step,
                task_id,
                target_status,
                outcome,
                reason,
                now_iso=now_iso,
                receipt=receipt,
                scrubbed_output=scrubbed_output,
            )

    def try_reconcile_step_unknown(
        self,
        step_id: str,
        target_status: StepStatus,
        outcome: str,
        reason: str,
        *,
        receipt: ActionReceipt | None = None,
        step_output: dict[str, Any] | None = None,
    ) -> Step | None:
        """Race-safe reconciliation of StepStatus.UNKNOWN; returns None if already handled."""
        if receipt is not None and contains_unredacted_secret_strict(receipt.model_dump()):
            raise ValueError("ActionReceipt contains unredacted secret material.")
        scrubbed_output = redact_payload_strict(step_output) if step_output is not None else None
        if scrubbed_output is not None and contains_unredacted_secret_strict(scrubbed_output):
            raise ValueError("step_output contains unredacted secret material.")

        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                return None
            step = self._row_to_step(step_row)
            if step.status != StepStatus.UNKNOWN:
                return None
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)
            if is_terminal_status(run.status) or bool(task_row["cancel_requested"]):
                return None
            return self._reconcile_step_unknown_tx(
                conn,
                step_row,
                step,
                run.task_id,
                target_status,
                outcome,
                reason,
                now_iso=now_iso,
                receipt=receipt,
                scrubbed_output=scrubbed_output,
            )

    def try_reset_pre_exec_step_to_pending(
        self,
        step_id: str,
        *,
        as_of: datetime | None = None,
        reason: str = "lease_expired_pre_exec",
    ) -> Step | None:
        """Race-safe reset of an expired LEASED/PREPARED step to PENDING; None if handled."""
        cutoff = ensure_utc(as_of) if as_of is not None else self._now()
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                return None
            step = self._row_to_step(step_row)
            if step.status not in (StepStatus.LEASED, StepStatus.PREPARED):
                return None
            if step.lease_expiry is None or step.lease_expiry > cutoff:
                return None
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)
            if is_terminal_status(run.status) or bool(task_row["cancel_requested"]):
                return None
            new_gen = step.lease_generation + 1
            conn.execute(
                """
                UPDATE steps
                SET status = ?, lease_owner = NULL, lease_expiry = NULL,
                    lease_generation = ?, updated_at = ?
                WHERE step_id = ?
                """,
                (StepStatus.PENDING.value, new_gen, now_iso, step_id),
            )
            self._insert_event(
                conn,
                task_id=run.task_id,
                run_id=step.run_id,
                step_id=step_id,
                event_type="step_reset_pending",
                from_status=step.status.value,
                to_status=StepStatus.PENDING.value,
                reason=reason,
                payload={"lease_generation": new_gen},
                created_at_iso=now_iso,
            )
            updated_row = conn.execute(
                "SELECT * FROM steps WHERE step_id = ?", (step_id,)
            ).fetchone()
            assert updated_row is not None
            return self._row_to_step(updated_row)

    def try_mark_expired_inflight_step_unknown(
        self,
        step_id: str,
        *,
        as_of: datetime | None = None,
        reason: str = "crash_recovery_lease_expired_in_flight",
    ) -> Step | None:
        """Atomically transition RUNNING->RECOVERING and expired EXECUTING/VERIFYING->UNKNOWN."""
        now = self._now()
        cutoff = ensure_utc(as_of) if as_of is not None else now
        now_iso = _format_dt(now)
        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                return None
            step = self._row_to_step(step_row)
            if step.status not in (StepStatus.EXECUTING, StepStatus.VERIFYING):
                return None
            if step.lease_expiry is None or step.lease_expiry > cutoff:
                return None
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)
            if is_terminal_status(run.status) or bool(task_row["cancel_requested"]):
                return None

            if run.status == TaskStatus.RUNNING:
                self._transition_run_status_tx(
                    conn,
                    run_row,
                    TaskStatus.RECOVERING,
                    "crash_recovery_unknown_step",
                    now=now,
                    now_iso=now_iso,
                )

            new_gen = step.lease_generation + 1 if step.lease_generation >= 1 else 1
            conn.execute(
                """
                UPDATE steps
                SET status = ?, outcome = 'unknown_needs_reconciliation',
                    lease_owner = NULL, lease_expiry = NULL,
                    lease_generation = ?, updated_at = ?
                WHERE step_id = ?
                """,
                (StepStatus.UNKNOWN.value, new_gen, now_iso, step_id),
            )
            conn.execute(
                """
                INSERT INTO operation_keys (
                    operation_key, task_id, run_id, step_id, latest_attempt,
                    tool_id, effect_class, idempotency_key, status,
                    redacted_args_json, reconciliation_note, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unknown', ?, ?, ?, ?)
                ON CONFLICT(operation_key) DO UPDATE SET
                    status = 'unknown',
                    reconciliation_note = excluded.reconciliation_note,
                    updated_at = excluded.updated_at
                """,
                (
                    step.operation_key,
                    run.task_id,
                    run.run_id,
                    step_id,
                    max(1, step.attempt),
                    step.tool_id,
                    str(step_row["effect_class"]),
                    step.operation_key,
                    str(step_row["redacted_args_json"]),
                    reason,
                    now_iso,
                    now_iso,
                ),
            )
            self._insert_event(
                conn,
                task_id=run.task_id,
                run_id=run.run_id,
                step_id=step_id,
                event_type="step_unknown",
                from_status=step.status.value,
                to_status=StepStatus.UNKNOWN.value,
                reason=reason,
                payload={"operation_key": step.operation_key, "lease_generation": new_gen},
                created_at_iso=now_iso,
            )
            updated_row = conn.execute(
                "SELECT * FROM steps WHERE step_id = ?", (step_id,)
            ).fetchone()
            assert updated_row is not None
            return self._row_to_step(updated_row)

    def try_reconcile_unknown_read_step(
        self, step_id: str
    ) -> Literal["retry", "failed", "noop"]:
        """Atomically reconcile an UNKNOWN READ step to PENDING (retry) or FAILED."""
        now = self._now()
        now_iso = _format_dt(now)
        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                return "noop"
            step = self._row_to_step(step_row)
            if step.status != StepStatus.UNKNOWN:
                return "noop"
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)
            if (
                is_terminal_status(run.status)
                or run.status == TaskStatus.WAITING_FOR_INPUT
                or bool(task_row["cancel_requested"])
            ):
                return "noop"

            if run.status == TaskStatus.RUNNING:
                self._transition_run_status_tx(
                    conn,
                    run_row,
                    TaskStatus.RECOVERING,
                    "reconciling_unknown_step",
                    now=now,
                    now_iso=now_iso,
                )

            budget_cfg = BudgetConfig.model_validate_json(str(task_row["budget_config_json"]))
            budget_row = self._load_budget_row(conn, run.task_id)
            current = self._row_to_budget_usage(budget_row)
            if current.transient_retries_used + 1 <= budget_cfg.max_transient_retries:
                conn.execute(
                    """
                    UPDATE task_budgets
                    SET transient_retries_used = transient_retries_used + 1, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (now_iso, run.task_id),
                )
                self._reconcile_step_unknown_tx(
                    conn,
                    step_row,
                    step,
                    run.task_id,
                    StepStatus.PENDING,
                    "retry_read_after_crash",
                    "read_safe_requery",
                    now_iso=now_iso,
                )
                return "retry"

            self._insert_audit(
                conn,
                task_id=run.task_id,
                run_id=run.run_id,
                step_id=step_id,
                actor="budget",
                action="transient_retry_exhausted",
                decision="deny",
                detail={
                    "used": current.transient_retries_used,
                    "max": budget_cfg.max_transient_retries,
                },
                recorded_at_iso=now_iso,
            )
            redacted_args = redact_payload_strict(
                json.loads(str(step_row["redacted_args_json"]))
            )
            failed_receipt = ActionReceipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                task_id=run.task_id,
                run_id=run.run_id,
                step_id=step_id,
                attempt=max(1, step.attempt),
                tool_id=step.tool_id,
                redacted_args=redacted_args if isinstance(redacted_args, dict) else {},
                operation_key=step.operation_key,
                observed_before=None,
                observed_after=None,
                duration_ms=0.0,
                evidence_refs=(),
                outcome=ReceiptOutcome.FAILED_TRANSIENT,
                error_detail="read_retries_exhausted_during_recovery",
                recorded_at=now,
            )
            self._reconcile_step_unknown_tx(
                conn,
                step_row,
                step,
                run.task_id,
                StepStatus.FAILED,
                "failed_transient",
                "read_retries_exhausted_during_recovery",
                now_iso=now_iso,
                receipt=failed_receipt,
            )
            return "failed"

    def try_reconcile_unknown_effect_retry(
        self,
        step_id: str,
        reason: str = "reconciled_unapplied_idempotent_retry",
    ) -> Literal["retry", "exhausted", "noop"]:
        """Atomically retry an unapplied idempotent UNKNOWN effect step within retry budget."""
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                return "noop"
            step = self._row_to_step(step_row)
            if step.status != StepStatus.UNKNOWN:
                return "noop"
            run_row = self._load_run_row(conn, step.run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)
            if is_terminal_status(run.status) or bool(task_row["cancel_requested"]):
                return "noop"
            budget_cfg = BudgetConfig.model_validate_json(str(task_row["budget_config_json"]))
            budget_row = self._load_budget_row(conn, run.task_id)
            current = self._row_to_budget_usage(budget_row)
            if current.transient_retries_used + 1 > budget_cfg.max_transient_retries:
                self._insert_audit(
                    conn,
                    task_id=run.task_id,
                    run_id=run.run_id,
                    step_id=step_id,
                    actor="budget",
                    action="transient_retry_exhausted",
                    decision="deny",
                    detail={
                        "used": current.transient_retries_used,
                        "max": budget_cfg.max_transient_retries,
                    },
                    recorded_at_iso=now_iso,
                )
                return "exhausted"

            conn.execute(
                """
                UPDATE task_budgets
                SET transient_retries_used = transient_retries_used + 1, updated_at = ?
                WHERE task_id = ?
                """,
                (now_iso, run.task_id),
            )
            self._reconcile_step_unknown_tx(
                conn,
                step_row,
                step,
                run.task_id,
                StepStatus.PENDING,
                "retry_unapplied_idempotent",
                reason,
                now_iso=now_iso,
            )
            return "retry"

    def try_pause_for_unknown_step(
        self,
        run_id: str,
        step_id: str,
        required_action: str,
        reason: str = "ambiguous_effect_requires_human_review",
    ) -> Run | None:
        """Atomically pause run for human input if step is still UNKNOWN and run is active."""
        now = self._now()
        now_iso = _format_dt(now)
        with write_transaction(self._db_path, self._lock) as conn:
            step_row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if step_row is None:
                return None
            step = self._row_to_step(step_row)
            if step.status != StepStatus.UNKNOWN:
                return None
            run_row = self._load_run_row(conn, run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)
            if (
                bool(task_row["cancel_requested"])
                or run.status not in (TaskStatus.RUNNING, TaskStatus.RECOVERING)
            ):
                return None
            updated = self._transition_run_status_tx(
                conn,
                run_row,
                TaskStatus.WAITING_FOR_INPUT,
                reason,
                now=now,
                now_iso=now_iso,
                required_action=required_action,
            )
            self._insert_event(
                conn,
                task_id=updated.task_id,
                run_id=run_id,
                step_id=step_id,
                event_type="human_input_requested",
                from_status=None,
                to_status=TaskStatus.WAITING_FOR_INPUT.value,
                reason=reason,
                payload={"required_action": updated.required_action},
                created_at_iso=now_iso,
            )
            return updated

    def try_expire_stranded_reservation(self, reservation_id: str) -> bool:
        """Atomically reconcile an active stranded reservation on recovery; False if not active."""
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            res_row = conn.execute(
                "SELECT * FROM budget_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if res_row is None:
                return False
            res = self._row_to_reservation(res_row)
            if res.status != "active":
                return False

            budget_row = self._load_budget_row(conn, res.task_id)
            current = self._row_to_budget_usage(budget_row)
            new_tool_res = max(0, current.tool_calls_reserved - res.tool_calls_reserved)
            new_model_res = max(0, current.model_calls_reserved - res.model_calls_reserved)
            new_tok_res = max(0, current.tokens_reserved - res.tokens_reserved)

            if res.kind == "tool":
                add_models = 0
                add_prompt = 0
                add_completion = 0
                new_est = current.usage_estimated
            else:
                add_models = res.model_calls_reserved
                add_prompt = res.tokens_reserved // 2
                add_completion = res.tokens_reserved - add_prompt
                new_est = True

            conn.execute(
                """
                UPDATE task_budgets
                SET tool_calls_reserved = ?,
                    model_calls_used = model_calls_used + ?,
                    model_calls_reserved = ?,
                    prompt_tokens_used = prompt_tokens_used + ?,
                    completion_tokens_used = completion_tokens_used + ?,
                    tokens_reserved = ?,
                    usage_estimated = ?,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (
                    new_tool_res,
                    add_models,
                    new_model_res,
                    add_prompt,
                    add_completion,
                    new_tok_res,
                    1 if new_est else 0,
                    now_iso,
                    res.task_id,
                ),
            )
            conn.execute(
                "UPDATE budget_reservations SET status = 'expired', updated_at = ? "
                "WHERE reservation_id = ?",
                (now_iso, reservation_id),
            )
            self._insert_event(
                conn,
                task_id=res.task_id,
                run_id=res.run_id,
                step_id=res.step_id,
                event_type="budget_reconciled",
                from_status=None,
                to_status=None,
                reason="budget_expired",
                payload={
                    "reservation_id": reservation_id,
                    "tool_calls_used": 0,
                    "model_calls_used": add_models,
                    "prompt_tokens": add_prompt,
                    "completion_tokens": add_completion,
                    "usage_estimated": new_est,
                },
                created_at_iso=now_iso,
            )
            return True

    # ------------------------------------------------------------------
    # Budget Reservations & Reconciliations (F07, A14)
    # ------------------------------------------------------------------

    def reserve_budget(
        self,
        task_id: str,
        run_id: str,
        kind: Literal["tool", "model"],
        *,
        step_id: str | None = None,
        tool_calls: int = 0,
        model_calls: int = 0,
        tokens: int = 0,
        wall_seconds_elapsed: float | None = None,
        lease_generation: int | None = None,
        ttl_s: float = 60.0,
    ) -> BudgetReservation:
        """Transactionally reserve budget slots/tokens before external model/tool calls."""
        if any(isinstance(v, bool) for v in (tool_calls, model_calls, tokens)):
            raise ValueError("Boolean value is not valid for integer reservation count.")
        if tool_calls < 0 or model_calls < 0 or tokens < 0:
            raise ValueError("Reservation amounts must be non-negative.")
        _reject_bool_float(ttl_s, "ttl_s", allow_zero=False)
        if wall_seconds_elapsed is not None:
            _reject_bool_float(wall_seconds_elapsed, "wall_seconds_elapsed")

        now = self._now()
        now_iso = _format_dt(now)
        expires_at = now + timedelta(seconds=float(ttl_s))
        res_id = f"res-{uuid.uuid4().hex[:12]}"

        rejection: Exception | None = None
        reservation: BudgetReservation | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            task_row = self._load_task_row(conn, task_id)
            run_row = self._load_run_row(conn, run_id)
            run = self._row_to_run(run_row)
            if is_terminal_status(run.status) or bool(task_row["cancel_requested"]):
                self._insert_audit(
                    conn,
                    task_id=task_id,
                    run_id=run_id,
                    step_id=step_id,
                    actor="budget",
                    action="budget_reserve_rejected",
                    decision="deny",
                    detail={"reason": "run_terminal_or_cancelled", "kind": kind},
                    recorded_at_iso=now_iso,
                )
                rejection = TerminalStateError(
                    f"Cannot reserve budget for terminal/cancelled run {run_id!r}."
                )
            else:
                budget_cfg = BudgetConfig.model_validate_json(str(task_row["budget_config_json"]))
                budget_row = self._load_budget_row(conn, task_id)
                current = self._row_to_budget_usage(budget_row)

                new_wall = (
                    max(current.wall_seconds_elapsed, float(wall_seconds_elapsed))
                    if wall_seconds_elapsed is not None
                    else current.wall_seconds_elapsed
                )
                candidate = BudgetUsage(
                    active_children=current.active_children,
                    tool_calls_used=current.tool_calls_used,
                    tool_calls_reserved=current.tool_calls_reserved + tool_calls,
                    model_calls_used=current.model_calls_used,
                    model_calls_reserved=current.model_calls_reserved + model_calls,
                    wall_seconds_elapsed=new_wall,
                    human_wait_seconds_elapsed=current.human_wait_seconds_elapsed,
                    prompt_tokens_used=current.prompt_tokens_used,
                    completion_tokens_used=current.completion_tokens_used,
                    tokens_reserved=current.tokens_reserved + tokens,
                    transient_retries_used=current.transient_retries_used,
                    usage_estimated=current.usage_estimated,
                )

                if not candidate.within_limits(budget_cfg):
                    self._insert_audit(
                        conn,
                        task_id=task_id,
                        run_id=run_id,
                        step_id=step_id,
                        actor="budget",
                        action="budget_exceeded",
                        decision="deny",
                        detail={
                            "kind": kind,
                            "requested": {
                                "tool_calls": tool_calls,
                                "model_calls": model_calls,
                                "tokens": tokens,
                                "wall_seconds_elapsed": new_wall,
                            },
                            "limits": budget_cfg.model_dump(),
                            "current": current.model_dump(),
                        },
                        recorded_at_iso=now_iso,
                    )
                    rejection = BudgetExceededError(
                        f"Budget limit exceeded reserving {kind} for task {task_id!r}."
                    )
                else:
                    conn.execute(
                        """
                        UPDATE task_budgets
                        SET tool_calls_reserved = ?,
                            model_calls_reserved = ?,
                            tokens_reserved = ?,
                            wall_seconds_elapsed = ?,
                            updated_at = ?
                        WHERE task_id = ?
                        """,
                        (
                            candidate.tool_calls_reserved,
                            candidate.model_calls_reserved,
                            candidate.tokens_reserved,
                            candidate.wall_seconds_elapsed,
                            now_iso,
                            task_id,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO budget_reservations (
                            reservation_id, task_id, run_id, step_id, kind,
                            tool_calls_reserved, model_calls_reserved, tokens_reserved,
                            status, lease_generation, expires_at, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
                        """,
                        (
                            res_id,
                            task_id,
                            run_id,
                            step_id,
                            kind,
                            tool_calls,
                            model_calls,
                            tokens,
                            lease_generation,
                            _format_dt(expires_at),
                            now_iso,
                            now_iso,
                        ),
                    )
                    self._insert_event(
                        conn,
                        task_id=task_id,
                        run_id=run_id,
                        step_id=step_id,
                        event_type="budget_reserved",
                        from_status=None,
                        to_status=None,
                        reason=f"reserve_{kind}",
                        payload={
                            "reservation_id": res_id,
                            "tool_calls": tool_calls,
                            "model_calls": model_calls,
                            "tokens": tokens,
                        },
                        created_at_iso=now_iso,
                    )
                    reservation = BudgetReservation(
                        reservation_id=res_id,
                        task_id=task_id,
                        run_id=run_id,
                        step_id=step_id,
                        kind=kind,
                        tool_calls_reserved=tool_calls,
                        model_calls_reserved=model_calls,
                        tokens_reserved=tokens,
                        status="active",
                        lease_generation=lease_generation,
                        expires_at=expires_at,
                        created_at=now,
                        updated_at=now,
                    )

        if rejection is not None:
            raise rejection
        assert reservation is not None
        return reservation

    def reconcile_budget(
        self,
        reservation_id: str,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        tool_calls_used: int = 0,
        model_calls_used: int = 0,
        transient_retries_used: int = 0,
        usage_estimated: bool = False,
        wall_seconds_elapsed: float | None = None,
        release_only: bool = False,
        mark_expired: bool = False,
    ) -> BudgetUsage:
        """Reconcile an active budget reservation with actual/estimated usage or release it."""
        if wall_seconds_elapsed is not None:
            _reject_bool_float(wall_seconds_elapsed, "wall_seconds_elapsed")
        now_iso = _format_dt(self._now())

        with write_transaction(self._db_path, self._lock) as conn:
            res_row = conn.execute(
                "SELECT * FROM budget_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if res_row is None:
                raise NotFoundError(f"Reservation {reservation_id!r} not found.")
            res = self._row_to_reservation(res_row)
            budget_row = self._load_budget_row(conn, res.task_id)
            current = self._row_to_budget_usage(budget_row)

            if res.status != "active":
                return current

            new_tool_res = max(0, current.tool_calls_reserved - res.tool_calls_reserved)
            new_model_res = max(0, current.model_calls_reserved - res.model_calls_reserved)
            new_tok_res = max(0, current.tokens_reserved - res.tokens_reserved)

            add_tools = 0 if release_only else tool_calls_used
            add_models = 0 if release_only else model_calls_used
            add_prompt = 0 if release_only else prompt_tokens
            add_completion = 0 if release_only else completion_tokens

            new_wall = (
                max(current.wall_seconds_elapsed, float(wall_seconds_elapsed))
                if wall_seconds_elapsed is not None
                else current.wall_seconds_elapsed
            )
            new_est = current.usage_estimated or usage_estimated
            new_status = (
                "expired"
                if mark_expired
                else ("released" if release_only else "reconciled")
            )

            conn.execute(
                """
                UPDATE task_budgets
                SET tool_calls_used = tool_calls_used + ?,
                    tool_calls_reserved = ?,
                    model_calls_used = model_calls_used + ?,
                    model_calls_reserved = ?,
                    prompt_tokens_used = prompt_tokens_used + ?,
                    completion_tokens_used = completion_tokens_used + ?,
                    tokens_reserved = ?,
                    transient_retries_used = transient_retries_used + ?,
                    wall_seconds_elapsed = ?,
                    usage_estimated = ?,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (
                    add_tools,
                    new_tool_res,
                    add_models,
                    new_model_res,
                    add_prompt,
                    add_completion,
                    new_tok_res,
                    transient_retries_used,
                    new_wall,
                    1 if new_est else 0,
                    now_iso,
                    res.task_id,
                ),
            )
            conn.execute(
                "UPDATE budget_reservations SET status = ?, updated_at = ? "
                "WHERE reservation_id = ?",
                (new_status, now_iso, reservation_id),
            )
            self._insert_event(
                conn,
                task_id=res.task_id,
                run_id=res.run_id,
                step_id=res.step_id,
                event_type="budget_reconciled",
                from_status=None,
                to_status=None,
                reason=f"budget_{new_status}",
                payload={
                    "reservation_id": reservation_id,
                    "tool_calls_used": add_tools,
                    "model_calls_used": add_models,
                    "prompt_tokens": add_prompt,
                    "completion_tokens": add_completion,
                    "usage_estimated": new_est,
                },
                created_at_iso=now_iso,
            )
            updated_budget = self._load_budget_row(conn, res.task_id)
            return self._row_to_budget_usage(updated_budget)

    def increment_transient_retry(self, task_id: str, *, run_id: str | None = None) -> BudgetUsage:
        """Atomically consume one transient retry slot from shared root budget."""
        now_iso = _format_dt(self._now())
        rejection: Exception | None = None
        updated_usage: BudgetUsage | None = None

        with write_transaction(self._db_path, self._lock) as conn:
            task_row = self._load_task_row(conn, task_id)
            budget_cfg = BudgetConfig.model_validate_json(str(task_row["budget_config_json"]))
            budget_row = self._load_budget_row(conn, task_id)
            current = self._row_to_budget_usage(budget_row)

            if current.transient_retries_used + 1 > budget_cfg.max_transient_retries:
                self._insert_audit(
                    conn,
                    task_id=task_id,
                    run_id=run_id,
                    step_id=None,
                    actor="budget",
                    action="transient_retry_exhausted",
                    decision="deny",
                    detail={
                        "used": current.transient_retries_used,
                        "max": budget_cfg.max_transient_retries,
                    },
                    recorded_at_iso=now_iso,
                )
                rejection = BudgetExceededError(
                    f"Transient retries exhausted ({current.transient_retries_used}/"
                    f"{budget_cfg.max_transient_retries})."
                )
            else:
                conn.execute(
                    """
                    UPDATE task_budgets
                    SET transient_retries_used = transient_retries_used + 1, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (now_iso, task_id),
                )
                updated_usage = self._row_to_budget_usage(self._load_budget_row(conn, task_id))

        if rejection is not None:
            raise rejection
        assert updated_usage is not None
        return updated_usage

    def update_wall_seconds(self, task_id: str, wall_seconds_elapsed: float) -> BudgetUsage:
        """Persist monotonic active execution wall_seconds_elapsed."""
        val = _reject_bool_float(wall_seconds_elapsed, "wall_seconds_elapsed")
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            self._load_task_row(conn, task_id)
            conn.execute(
                """
                UPDATE task_budgets
                SET wall_seconds_elapsed = MAX(wall_seconds_elapsed, ?), updated_at = ?
                WHERE task_id = ?
                """,
                (val, now_iso, task_id),
            )
            return self._row_to_budget_usage(self._load_budget_row(conn, task_id))

    # ------------------------------------------------------------------
    # Cancellation (A09)
    # ------------------------------------------------------------------

    def request_cancel(self, task_id: str, reason: str = "user_cancelled") -> list[Run]:
        """Set cancel_requested, cascade CANCELLED to all non-terminal runs, and fence leases."""
        now_iso = _format_dt(self._now())
        cancelled_runs: list[Run] = []

        with write_transaction(self._db_path, self._lock) as conn:
            self._load_task_row(conn, task_id)
            conn.execute(
                """
                UPDATE tasks
                SET cancel_requested = 1,
                    cancel_reason = COALESCE(cancel_reason, ?),
                    cancel_requested_at = COALESCE(cancel_requested_at, ?)
                WHERE task_id = ?
                """,
                (reason, now_iso, task_id),
            )
            self._insert_event(
                conn,
                task_id=task_id,
                run_id=None,
                step_id=None,
                event_type="cancel_requested",
                from_status=None,
                to_status=TaskStatus.CANCELLED.value,
                reason=reason,
                payload={"task_id": task_id},
                created_at_iso=now_iso,
            )

            run_rows = conn.execute(
                "SELECT * FROM runs WHERE task_id = ? ORDER BY depth ASC, created_at ASC",
                (task_id,),
            ).fetchall()

            for r_row in run_rows:
                run = self._row_to_run(r_row)
                if not is_terminal_status(run.status):
                    validate_status_transition(run.status, TaskStatus.CANCELLED)
                    new_ver = run.version + 1
                    conn.execute(
                        """
                        UPDATE runs
                        SET status = ?, version = ?, transition_reason = ?,
                            required_action = NULL, waiting_since = NULL,
                            result_json = NULL, pending_human_input_json = NULL,
                            updated_at = ?
                        WHERE run_id = ?
                        """,
                        (
                            TaskStatus.CANCELLED.value,
                            new_ver,
                            reason,
                            now_iso,
                            run.run_id,
                        ),
                    )
                    self._insert_event(
                        conn,
                        task_id=task_id,
                        run_id=run.run_id,
                        step_id=None,
                        event_type="run_transition",
                        from_status=run.status.value,
                        to_status=TaskStatus.CANCELLED.value,
                        reason=reason,
                        payload={"version": new_ver, "depth": run.depth},
                        created_at_iso=now_iso,
                    )
                updated_row = self._load_run_row(conn, run.run_id)
                cancelled_runs.append(self._row_to_run(updated_row))

            # Fence all active/pending steps immediately by incrementing lease_generation.
            conn.execute(
                """
                UPDATE steps
                SET status = ?, lease_owner = NULL, lease_expiry = NULL,
                    lease_generation = lease_generation + 1,
                    outcome = COALESCE(outcome, 'cancelled'),
                    updated_at = ?
                WHERE run_id IN (SELECT run_id FROM runs WHERE task_id = ?)
                  AND status IN (
                      'pending', 'leased', 'prepared', 'executing', 'verifying', 'unknown'
                  )
                """,
                (StepStatus.CANCELLED.value, now_iso, task_id),
            )
            conn.execute(
                """
                UPDATE budget_reservations
                SET status = 'released', updated_at = ?
                WHERE task_id = ? AND status = 'active'
                """,
                (now_iso, task_id),
            )
            conn.execute(
                """
                UPDATE task_budgets
                SET active_children = 0,
                    tool_calls_reserved = 0,
                    model_calls_reserved = 0,
                    tokens_reserved = 0,
                    updated_at = ?
                WHERE task_id = ?
                """,
                (now_iso, task_id),
            )

        return cancelled_runs

    # ------------------------------------------------------------------
    # Receipts, Observations, Signatures, Events & Audit Logs
    # ------------------------------------------------------------------

    def append_receipt(self, receipt: ActionReceipt) -> ActionReceipt:
        """Persist an immutable, fail-closed redacted ActionReceipt."""
        if contains_unredacted_secret_strict(receipt.model_dump()):
            raise ValueError("ActionReceipt contains unredacted secret material.")
        with write_transaction(self._db_path, self._lock) as conn:
            self._insert_receipt_row(conn, receipt)
        return receipt

    def append_observations(
        self,
        *,
        task_id: str,
        run_id: str,
        step_id: str | None,
        observations: list[Observation] | tuple[Observation, ...],
    ) -> None:
        """Persist verified observations for a run."""
        if not observations:
            return
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            for obs in observations:
                obs_dict = obs.model_dump()
                if contains_unredacted_secret_strict(obs_dict):
                    raise ValueError("Observation contains unredacted secret material.")
                conn.execute(
                    """
                    INSERT INTO observations (
                        observation_id, task_id, run_id, step_id, observation_json, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"obs-{uuid.uuid4().hex[:12]}",
                        task_id,
                        run_id,
                        step_id,
                        obs.model_dump_json(),
                        now_iso,
                    ),
                )

    def append_event(
        self,
        *,
        task_id: str,
        event_type: str,
        reason: str,
        run_id: str | None = None,
        step_id: str | None = None,
        from_status: str | None = None,
        to_status: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> int:
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            return self._insert_event(
                conn,
                task_id=task_id,
                run_id=run_id,
                step_id=step_id,
                event_type=event_type,
                from_status=from_status,
                to_status=to_status,
                reason=reason,
                payload=payload,
                created_at_iso=now_iso,
            )

    def append_audit_log(
        self,
        *,
        actor: str,
        action: str,
        decision: str,
        detail: dict[str, Any] | None = None,
        task_id: str | None = None,
        run_id: str | None = None,
        step_id: str | None = None,
    ) -> int:
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            return self._insert_audit(
                conn,
                task_id=task_id,
                run_id=run_id,
                step_id=step_id,
                actor=actor,
                action=action,
                decision=decision,
                detail=detail,
                recorded_at_iso=now_iso,
            )

    def record_step_signature(
        self,
        *,
        task_id: str,
        run_id: str,
        step_index: int,
        tool_id: str,
        target_key: str,
        canonical_args_hash: str,
        result_hash: str,
        progress_token: str | None,
        succeeded: bool,
    ) -> StepSignatureRecord:
        """Persist step call signature for A06/A07 loop detection across restarts."""
        now_iso = _format_dt(self._now())
        with write_transaction(self._db_path, self._lock) as conn:
            cur = conn.execute(
                """
                INSERT INTO step_signatures (
                    task_id, run_id, step_index, tool_id, target_key,
                    canonical_args_hash, result_hash, progress_token, succeeded, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    run_id,
                    step_index,
                    tool_id,
                    target_key,
                    canonical_args_hash,
                    result_hash,
                    progress_token,
                    1 if succeeded else 0,
                    now_iso,
                ),
            )
            row = conn.execute(
                "SELECT * FROM step_signatures WHERE sig_id = ?", (int(cur.lastrowid or 0),)
            ).fetchone()
            assert row is not None
            return self._row_to_step_signature(row)

    def sync_active_children(self, task_id: str | None = None) -> dict[str, int]:
        """Re-compute exact active_children counts from non-terminal depth>0 runs."""
        now_iso = _format_dt(self._now())
        updated: dict[str, int] = {}
        placeholders = ", ".join("?" for _ in _NON_TERMINAL_STATUS_VALUES)

        with write_transaction(self._db_path, self._lock) as conn:
            if task_id is not None:
                task_ids = [task_id]
            else:
                rows = conn.execute("SELECT task_id FROM tasks").fetchall()
                task_ids = [str(r["task_id"]) for r in rows]

            for tid in task_ids:
                cnt_row = conn.execute(
                    f"""
                    SELECT COUNT(*) AS cnt
                    FROM runs
                    WHERE task_id = ? AND depth > 0 AND status IN ({placeholders})
                    """,
                    (tid, *_NON_TERMINAL_STATUS_VALUES),
                ).fetchone()
                cnt = int(cnt_row["cnt"]) if cnt_row is not None else 0
                conn.execute(
                    "UPDATE task_budgets SET active_children = ?, updated_at = ? WHERE task_id = ?",
                    (cnt, now_iso, tid),
                )
                updated[tid] = cnt
        return updated

    # ------------------------------------------------------------------
    # Read queries & snapshots
    # ------------------------------------------------------------------

    def get_run(self, run_id: str) -> Run:
        with read_transaction(self._db_path) as conn:
            return self._row_to_run(self._load_run_row(conn, run_id))

    def get_task_spec(self, task_id: str) -> TaskSpec:
        with read_transaction(self._db_path) as conn:
            row = self._load_task_row(conn, task_id)
            return TaskSpec.model_validate_json(str(row["spec_json"]))

    def is_cancel_requested(self, task_id: str) -> bool:
        with read_transaction(self._db_path) as conn:
            row = self._load_task_row(conn, task_id)
            return bool(row["cancel_requested"])

    def get_budget_usage(self, task_id: str) -> BudgetUsage:
        with read_transaction(self._db_path) as conn:
            return self._row_to_budget_usage(self._load_budget_row(conn, task_id))

    def get_step(self, step_id: str) -> Step:
        with read_transaction(self._db_path) as conn:
            row = conn.execute("SELECT * FROM steps WHERE step_id = ?", (step_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"Step {step_id!r} not found.")
            return self._row_to_step(row)

    def get_step_execution_details(self, step_id: str) -> StepExecutionDetails:
        with read_transaction(self._db_path) as conn:
            row = conn.execute(
                """
                SELECT s.*, r.task_id
                FROM steps s
                JOIN runs r ON r.run_id = s.run_id
                WHERE s.step_id = ?
                """,
                (step_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"Step {step_id!r} not found.")
            op_row = conn.execute(
                "SELECT idempotency_key FROM operation_keys WHERE operation_key = ?",
                (str(row["operation_key"]),),
            ).fetchone()
            return StepExecutionDetails(
                step=self._row_to_step(row),
                task_id=str(row["task_id"]),
                exec_args=json.loads(str(row["exec_args_json"])),
                redacted_args=json.loads(str(row["redacted_args_json"])),
                target_origin=row["target_origin"],
                effect_class=EffectClass(str(row["effect_class"])),
                idempotency_key=str(op_row["idempotency_key"]) if op_row is not None else None,
                step_output=(
                    json.loads(str(row["step_output_json"]))
                    if row["step_output_json"] is not None
                    else None
                ),
            )

    def get_operation_key(self, operation_key: str) -> OperationKeyRecord | None:
        with read_transaction(self._db_path) as conn:
            row = conn.execute(
                "SELECT * FROM operation_keys WHERE operation_key = ?", (operation_key,)
            ).fetchone()
            return self._row_to_op_key(row) if row is not None else None

    def get_step_signatures(self, run_id: str) -> list[StepSignatureRecord]:
        with read_transaction(self._db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM step_signatures WHERE run_id = ? ORDER BY sig_id ASC",
                (run_id,),
            ).fetchall()
            return [self._row_to_step_signature(r) for r in rows]

    def list_pending_steps(self, run_id: str) -> list[Step]:
        with read_transaction(self._db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM steps WHERE run_id = ? AND status = 'pending' "
                "ORDER BY step_index ASC",
                (run_id,),
            ).fetchall()
            return [self._row_to_step(r) for r in rows]

    def list_unknown_steps(self, run_id: str | None = None) -> list[Step]:
        with read_transaction(self._db_path) as conn:
            if run_id is not None:
                rows = conn.execute(
                    "SELECT * FROM steps WHERE run_id = ? AND status = 'unknown' "
                    "ORDER BY step_index ASC",
                    (run_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM steps WHERE status = 'unknown' "
                    "ORDER BY created_at ASC, step_index ASC"
                ).fetchall()
            return [self._row_to_step(r) for r in rows]

    def list_inflight_runs(self) -> list[Run]:
        placeholders = ", ".join("?" for _ in _NON_TERMINAL_STATUS_VALUES)
        with read_transaction(self._db_path) as conn:
            rows = conn.execute(
                f"SELECT * FROM runs WHERE status IN ({placeholders}) ORDER BY created_at ASC",
                _NON_TERMINAL_STATUS_VALUES,
            ).fetchall()
            return [self._row_to_run(r) for r in rows]

    def list_runs(self, *, limit: int = 100, root_only: bool = False) -> list[Run]:
        """List runs ordered most-recent-first."""
        if limit < 1:
            return []
        where_clause = "WHERE depth = 0" if root_only else ""
        with read_transaction(self._db_path) as conn:
            rows = conn.execute(
                f"SELECT * FROM runs {where_clause} ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_run(r) for r in rows]

    def list_expired_leased_steps(self, as_of: datetime | None = None) -> list[Step]:
        cutoff_iso = _format_dt(ensure_utc(as_of) if as_of is not None else self._now())
        with read_transaction(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT * FROM steps
                WHERE status IN ('leased', 'prepared', 'executing', 'verifying')
                  AND lease_expiry IS NOT NULL
                  AND lease_expiry <= ?
                ORDER BY created_at ASC, step_index ASC
                """,
                (cutoff_iso,),
            ).fetchall()
            return [self._row_to_step(r) for r in rows]

    def list_expired_reservations(self, as_of: datetime | None = None) -> list[BudgetReservation]:
        cutoff_iso = _format_dt(ensure_utc(as_of) if as_of is not None else self._now())
        with read_transaction(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT * FROM budget_reservations
                WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?
                ORDER BY created_at ASC
                """,
                (cutoff_iso,),
            ).fetchall()
            return [self._row_to_reservation(r) for r in rows]

    def list_active_reservations(self, task_id: str | None = None) -> list[BudgetReservation]:
        with read_transaction(self._db_path) as conn:
            if task_id is not None:
                rows = conn.execute(
                    "SELECT * FROM budget_reservations "
                    "WHERE task_id = ? AND status = 'active' ORDER BY created_at ASC",
                    (task_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM budget_reservations "
                    "WHERE status = 'active' ORDER BY created_at ASC"
                ).fetchall()
            return [self._row_to_reservation(r) for r in rows]

    def list_events(
        self, *, run_id: str | None = None, task_id: str | None = None
    ) -> list[EventRecord]:
        with read_transaction(self._db_path) as conn:
            if run_id is not None:
                rows = conn.execute(
                    "SELECT * FROM events WHERE run_id = ? ORDER BY event_id ASC", (run_id,)
                ).fetchall()
            elif task_id is not None:
                rows = conn.execute(
                    "SELECT * FROM events WHERE task_id = ? ORDER BY event_id ASC", (task_id,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM events ORDER BY event_id ASC").fetchall()
            return [self._row_to_event(r) for r in rows]

    def list_audit_logs(self, *, task_id: str | None = None) -> list[AuditRecord]:
        with read_transaction(self._db_path) as conn:
            if task_id is not None:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE task_id = ? ORDER BY audit_id ASC", (task_id,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM audit_log ORDER BY audit_id ASC").fetchall()
            return [self._row_to_audit(r) for r in rows]

    def get_run_snapshot(self, run_id: str) -> RunSnapshot:
        """Load consistent read snapshot of run, task spec, steps, receipts, budget, and events."""
        with read_transaction(self._db_path) as conn:
            run_row = self._load_run_row(conn, run_id)
            run = self._row_to_run(run_row)
            task_row = self._load_task_row(conn, run.task_id)
            task_spec = TaskSpec.model_validate_json(str(task_row["spec_json"]))
            budget_row = self._load_budget_row(conn, run.task_id)
            budget_usage = self._row_to_budget_usage(budget_row)

            step_rows = conn.execute(
                "SELECT * FROM steps WHERE run_id = ? ORDER BY step_index ASC", (run_id,)
            ).fetchall()
            receipt_rows = conn.execute(
                "SELECT receipt_json FROM action_receipts "
                "WHERE run_id = ? ORDER BY recorded_at ASC",
                (run_id,),
            ).fetchall()
            event_rows = conn.execute(
                "SELECT * FROM events WHERE run_id = ? ORDER BY event_id ASC", (run_id,)
            ).fetchall()
            child_rows = conn.execute(
                "SELECT * FROM runs WHERE parent_run_id = ? ORDER BY created_at ASC", (run_id,)
            ).fetchall()
            obs_rows = conn.execute(
                "SELECT observation_json FROM observations "
                "WHERE run_id = ? ORDER BY recorded_at ASC",
                (run_id,),
            ).fetchall()

            effective_scope = (
                TaskScope.model_validate_json(str(run_row["scope_json"]))
                if run_row["scope_json"] is not None
                else task_spec.scope
            )
            result = (
                Result.model_validate_json(str(run_row["result_json"]))
                if run_row["result_json"] is not None
                else None
            )
            pending_input = (
                json.loads(str(run_row["pending_human_input_json"]))
                if run_row["pending_human_input_json"] is not None
                else None
            )
            waiting_since = (
                _parse_dt(str(run_row["waiting_since"]))
                if run_row["waiting_since"] is not None
                else None
            )
            if run.depth == 0:
                root_created_at = run.created_at
            else:
                root_row = conn.execute(
                    "SELECT created_at FROM runs WHERE task_id = ? AND depth = 0 "
                    "ORDER BY created_at ASC LIMIT 1",
                    (run.task_id,),
                ).fetchone()
                root_created_at = (
                    _parse_dt(str(root_row["created_at"]))
                    if root_row is not None
                    else _parse_dt(str(task_row["created_at"]))
                )

            return RunSnapshot(
                task_spec=task_spec,
                run=run,
                effective_scope=effective_scope,
                steps=tuple(self._row_to_step(r) for r in step_rows),
                receipts=tuple(
                    ActionReceipt.model_validate_json(str(r["receipt_json"])) for r in receipt_rows
                ),
                budget_usage=budget_usage,
                events=tuple(self._row_to_event(r) for r in event_rows),
                child_runs=tuple(self._row_to_run(r) for r in child_rows),
                cancel_requested=bool(task_row["cancel_requested"]),
                result=result,
                pending_human_input=pending_input,
                observations=tuple(
                    Observation.model_validate_json(str(r["observation_json"])) for r in obs_rows
                ),
                waiting_since=waiting_since,
                root_created_at=root_created_at,
            )
