"""Core frozen domain models for tasks, runs, steps, tools, receipts, and results."""

from __future__ import annotations

from typing import Any

from pydantic import Field, model_validator

from src.contracts.budgets import BudgetConfig
from src.contracts.common import FrozenModel, HttpOrigin, NonEmptyStr, UtcDatetime, utc_now
from src.contracts.enums import (
    TERMINAL_TASK_STATUSES,
    BackendMode,
    DataQuality,
    EffectClass,
    ReceiptOutcome,
    StepStatus,
    TaskStatus,
)
from src.contracts.redaction import contains_unredacted_secret


class TaskScope(FrozenModel):
    """Authorized facility, origins, areas, tools, and mutation boundary for a task."""

    facility_id: NonEmptyStr
    allowed_origins: tuple[HttpOrigin, ...] = ()
    allowed_areas: tuple[NonEmptyStr, ...] = ()
    allowed_tools: tuple[NonEmptyStr, ...] = ()
    read_only: bool = True


class EvidenceRequirements(FrozenModel):
    """Minimum verification requirements for task answers."""

    min_sources: int = Field(default=1, ge=1)
    require_source_timestamp: bool = True
    require_quality_check: bool = True
    max_staleness_seconds: float | None = Field(default=3600.0, gt=0.0)
    allow_partial_on_source_failure: bool = True


class TaskSpec(FrozenModel):
    """Immutable specification of a submitted task."""

    task_id: NonEmptyStr
    user_id: NonEmptyStr
    profile_id: NonEmptyStr
    scope: TaskScope
    query: NonEmptyStr
    policy_version: NonEmptyStr = "1.0.0"
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    evidence_requirements: EvidenceRequirements = Field(default_factory=EvidenceRequirements)
    backend_mode: BackendMode = BackendMode.EMULATED
    installation_config_path: str | None = None
    created_at: UtcDatetime = Field(default_factory=utc_now)


class Run(FrozenModel):
    """Execution run instance (root depth=0 or delegated child depth=1)."""

    run_id: NonEmptyStr
    task_id: NonEmptyStr
    parent_run_id: NonEmptyStr | None = None
    depth: int = Field(default=0, ge=0)
    status: TaskStatus = TaskStatus.QUEUED
    attempt: int = Field(default=1, ge=1)
    version: int = Field(default=1, ge=1)
    deadline_at: UtcDatetime
    progress: float = Field(default=0.0, ge=0.0, le=1.0)
    transition_reason: NonEmptyStr = "created"
    required_action: NonEmptyStr | None = None
    created_at: UtcDatetime = Field(default_factory=utc_now)
    updated_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _validate_run_invariants(self) -> Run:
        if self.depth == 0 and self.parent_run_id is not None:
            raise ValueError("Root run (depth=0) must not define parent_run_id.")
        if self.depth > 0 and self.parent_run_id is None:
            raise ValueError("Child run (depth>0) must define parent_run_id.")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not be earlier than created_at.")
        if self.status == TaskStatus.WAITING_FOR_INPUT and self.required_action is None:
            raise ValueError("waiting_for_input run must specify required_action.")
        return self


class Step(FrozenModel):
    """Single step in a run with lease fencing and completion verifier metadata."""

    step_id: NonEmptyStr
    run_id: NonEmptyStr
    step_index: int = Field(ge=0)
    status: StepStatus = StepStatus.PENDING
    attempt: int = Field(default=0, ge=0)
    tool_id: NonEmptyStr
    operation_key: NonEmptyStr
    lease_owner: NonEmptyStr | None = None
    lease_expiry: UtcDatetime | None = None
    lease_generation: int = Field(default=0, ge=0)
    completion_verifier: NonEmptyStr
    outcome: str | None = None

    @model_validator(mode="after")
    def _validate_lease_invariants(self) -> Step:
        if self.lease_owner is not None and (
            self.lease_expiry is None or self.lease_generation < 1
        ):
            raise ValueError(
                "Leased step with lease_owner must set lease_expiry and lease_generation >= 1."
            )
        return self


class RetryPolicy(FrozenModel):
    """Retry policy declared by a ToolSpec."""

    max_retries: int = Field(default=1, ge=0)
    retry_on_transient: bool = True
    backoff_seconds: float = Field(default=0.5, ge=0.0)


class ToolSpec(FrozenModel):
    """Typed contract for a registered tool."""

    tool_id: NonEmptyStr
    version: NonEmptyStr
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    permissions: tuple[NonEmptyStr, ...] = ()
    allowed_origins: tuple[HttpOrigin, ...] = ()
    effect_class: EffectClass
    timeout_s: float = Field(default=15.0, gt=0.0)
    verifier_name: NonEmptyStr
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)


class ActionReceipt(FrozenModel):
    """Fail-closed redacted audit receipt for a tool execution attempt."""

    receipt_id: NonEmptyStr
    task_id: NonEmptyStr
    run_id: NonEmptyStr
    step_id: NonEmptyStr
    attempt: int = Field(ge=1)
    tool_id: NonEmptyStr
    redacted_args: dict[str, Any]
    operation_key: NonEmptyStr
    observed_before: dict[str, Any] | None = None
    observed_after: dict[str, Any] | None = None
    duration_ms: float = Field(ge=0.0)
    evidence_refs: tuple[NonEmptyStr, ...] = ()
    outcome: ReceiptOutcome
    error_detail: str | None = None
    recorded_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _enforce_redacted_args(self) -> ActionReceipt:
        if contains_unredacted_secret(self.redacted_args):
            raise ValueError("ActionReceipt.redacted_args contains unredacted secret material.")
        return self


class Observation(FrozenModel):
    """Verified, source-attributed industrial observation."""

    source: NonEmptyStr
    session_id: NonEmptyStr
    asset_id: NonEmptyStr
    observed_label: NonEmptyStr
    value: str | int | float | bool | None
    unit: str | None = None
    source_time: UtcDatetime | None = None
    observed_at: UtcDatetime = Field(default_factory=utc_now)
    quality: DataQuality
    authorized_evidence: bool = True
    area: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContradictionClaim(FrozenModel):
    """Single source claim participating in a contradiction."""

    source: NonEmptyStr
    asset_id: NonEmptyStr
    field: NonEmptyStr
    value: str | int | float | bool | None
    observed_at: UtcDatetime = Field(default_factory=utc_now)


class ContradictionRecord(FrozenModel):
    """Preserved cross-source contradiction record (never silently merged)."""

    summary: NonEmptyStr
    claims: tuple[ContradictionClaim, ...] = Field(min_length=2)
    unresolved: bool = True


class ExecutionMetrics(FrozenModel):
    """Summary execution counters reported with a task result."""

    tool_calls: int = Field(default=0, ge=0)
    model_calls: int = Field(default=0, ge=0)
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    wall_seconds: float = Field(default=0.0, ge=0.0)
    human_wait_seconds: float = Field(default=0.0, ge=0.0)
    retries: int = Field(default=0, ge=0)
    usage_estimated: bool = False


class Result(FrozenModel):
    """Final or waiting_for_input outcome of a task run."""

    task_id: NonEmptyStr
    run_id: NonEmptyStr
    status: TaskStatus
    answer: str
    verified_observations: tuple[Observation, ...] = ()
    partial_info: dict[str, Any] | None = None
    contradictions: tuple[ContradictionRecord, ...] = ()
    required_action: NonEmptyStr | None = None
    execution_metrics: ExecutionMetrics = Field(default_factory=ExecutionMetrics)

    @model_validator(mode="after")
    def _validate_result_status(self) -> Result:
        allowed_statuses = TERMINAL_TASK_STATUSES | {TaskStatus.WAITING_FOR_INPUT}
        if self.status not in allowed_statuses:
            raise ValueError(
                f"Result.status must be terminal or waiting_for_input, got {self.status.value!r}."
            )
        if self.status == TaskStatus.WAITING_FOR_INPUT and self.required_action is None:
            raise ValueError("Result with waiting_for_input status must specify required_action.")
        return self
