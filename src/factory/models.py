"""Frozen Pydantic domain contracts for the M7 local software factory (F16)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Literal

from pydantic import Field

from src.contracts.common import FrozenModel, NonEmptyStr, UtcDatetime, utc_now


class FactoryStatus(StrEnum):
    """Lifecycle and pause states for the autonomous software factory."""

    IDLE = "idle"
    PAUSED_EMPTY_BACKLOG = "paused_empty_backlog"
    PAUSED_BUDGET_EXHAUSTED = "paused_budget_exhausted"
    PAUSED_MAX_ATTEMPTS = "paused_max_attempts"
    PAUSED_NO_PROGRESS = "paused_no_progress"
    PROMOTED = "promoted"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"


class BacklogItem(FrozenModel):
    """Persistent prioritized improvement item in factory_backlog."""

    item_id: NonEmptyStr
    title: NonEmptyStr
    priority: int = Field(default=1, ge=1)
    status: Literal["pending", "in_progress", "completed", "rejected", "paused"] = "pending"
    hypothesis: NonEmptyStr
    target_metric: NonEmptyStr
    baseline_repro_cmd: NonEmptyStr
    max_attempts: int = Field(default=2, ge=1)
    attempts_used: int = Field(default=0, ge=0)
    created_at: UtcDatetime = Field(default_factory=utc_now)
    updated_at: UtcDatetime = Field(default_factory=utc_now)


class FactoryLease(FrozenModel):
    """Fenced persistent backlog item lease with generation monotonicity."""

    lease_id: NonEmptyStr
    item_id: NonEmptyStr
    owner: NonEmptyStr
    expiry: UtcDatetime
    generation: int = Field(ge=1)
    status: Literal["active", "released", "expired"] = "active"
    acquired_at: UtcDatetime = Field(default_factory=utc_now)
    updated_at: UtcDatetime = Field(default_factory=utc_now)


class CycleBudget(FrozenModel):
    """Persistent cycle, attempt, and wall-clock budget across pause/restart."""

    budget_id: NonEmptyStr = "default"
    max_cycles: int = Field(default=4, ge=1)
    cycles_used: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=2, ge=1)
    attempts_used: int = Field(default=0, ge=0)
    max_wall_seconds: float = Field(default=300.0, gt=0.0)
    wall_seconds_used: float = Field(default=0.0, ge=0.0)


def compute_proposal_hash(
    *,
    item_id: str,
    target_metric: str,
    files_to_modify: Mapping[str, str],
    repro_test_path: str | None = None,
    repro_test_content: str | None = None,
) -> str:
    """Compute a deterministic SHA-256 hash of a normalized candidate proposal."""
    normalized = json.dumps(
        {
            "item_id": item_id.strip(),
            "target_metric": target_metric.strip(),
            "files_to_modify": dict(sorted(files_to_modify.items())),
            "repro_test_path": repro_test_path,
            "repro_test_content": repro_test_content,
        },
        sort_keys=True,
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class CandidatePatch(FrozenModel):
    """Bounded candidate patch evaluated on an isolated branch."""

    candidate_id: NonEmptyStr
    item_id: NonEmptyStr
    branch_name: NonEmptyStr
    hypothesis: NonEmptyStr
    target_metric: NonEmptyStr
    proposal_hash: NonEmptyStr
    new_evidence: bool = False
    files_to_modify: dict[str, str] = Field(default_factory=dict)
    repro_test_path: str | None = None
    repro_test_content: str | None = None


class RollbackManifest(FrozenModel):
    """Machine-readable rollback manifest emitted on candidate promotion."""

    version: NonEmptyStr = "1.0.0"
    candidate_id: NonEmptyStr
    item_id: NonEmptyStr
    repo_path: NonEmptyStr
    branch_name: NonEmptyStr
    previous_commit: NonEmptyStr
    new_commit: NonEmptyStr
    uv_lock_hash: NonEmptyStr
    config_hash: NonEmptyStr
    restore_command: NonEmptyStr
    restore_script: str | None = None
    promoted_at: UtcDatetime = Field(default_factory=utc_now)


class CandidateRunRecord(FrozenModel):
    """Recorded evaluation outcome for a single factory candidate attempt."""

    run_id: NonEmptyStr
    candidate_id: NonEmptyStr
    item_id: NonEmptyStr
    branch_name: NonEmptyStr
    base_commit: NonEmptyStr
    candidate_commit: str | None = None
    proposal_hash: NonEmptyStr
    baseline_metric: float | None = None
    candidate_metric: float | None = None
    baseline_passed: bool
    regression_passed: bool
    identity_gate_passed: bool
    policy_passed: bool
    status: Literal["PROMOTED", "REJECTED"]
    reason: NonEmptyStr
    manifest_path: str | None = None
    created_at: UtcDatetime = Field(default_factory=utc_now)


class LessonRecord(FrozenModel):
    """Recorded learning / regression artifact from a promoted or rejected candidate."""

    lesson_id: NonEmptyStr
    item_id: NonEmptyStr
    candidate_id: NonEmptyStr
    proposal_hash: NonEmptyStr
    outcome: Literal["PROMOTED", "REJECTED"]
    reason: NonEmptyStr
    regression_test_path: str | None = None
    reopen_condition: str | None = None
    created_at: UtcDatetime = Field(default_factory=utc_now)


class FactoryCycleResult(FrozenModel):
    """Summary returned by FactoryEngine.run_candidate_cycle / run_next_cycle."""

    status: FactoryStatus
    item_id: str | None = None
    candidate_id: str | None = None
    branch_name: str | None = None
    base_commit: str | None = None
    candidate_commit: str | None = None
    baseline_metric: float | None = None
    candidate_metric: float | None = None
    manifest_path: str | None = None
    reason: str = ""
    lesson: LessonRecord | None = None
    budget: CycleBudget | None = None
