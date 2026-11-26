"""Request and response Pydantic schemas for the local Web API."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import Field, ValidationInfo, field_validator

from src.adapters.sessions import validate_session_segment
from src.contracts.budgets import BudgetConfig
from src.contracts.common import FrozenModel, HttpOrigin, NonEmptyStr
from src.contracts.enums import BackendMode
from src.contracts.models import EvidenceRequirements, TaskScope, TaskSpec
from src.storage.redaction import contains_unredacted_secret_strict


class TaskSubmitRequest(FrozenModel):
    """API request payload for POST /api/tasks."""

    task_id: NonEmptyStr | None = None
    user_id: NonEmptyStr = "operator"
    profile_id: NonEmptyStr = "default"
    facility_id: NonEmptyStr = "facility-a"
    allowed_origins: tuple[HttpOrigin, ...] = ()
    allowed_areas: tuple[NonEmptyStr, ...] = ()
    allowed_tools: tuple[NonEmptyStr, ...] = ()
    read_only: bool = True
    query: NonEmptyStr
    policy_version: NonEmptyStr = "1.0.0"
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    evidence_requirements: EvidenceRequirements = Field(default_factory=EvidenceRequirements)
    backend_mode: BackendMode = BackendMode.EMULATED
    installation_config_path: str | None = None

    @field_validator("user_id", "profile_id", mode="after")
    @classmethod
    def _validate_safe_session_segments(cls, value: str, info: ValidationInfo) -> str:
        field_name = info.field_name or "segment"
        if contains_unredacted_secret_strict(value):
            raise ValueError(f"{field_name} must not contain unredacted secret material.")
        return validate_session_segment(field_name, value)

    def to_task_spec(self) -> TaskSpec:
        """Convert validated submit request into a frozen TaskSpec contract."""
        return TaskSpec(
            task_id=self.task_id or f"task-{uuid.uuid4().hex[:12]}",
            user_id=self.user_id,
            profile_id=self.profile_id,
            scope=TaskScope(
                facility_id=self.facility_id,
                allowed_origins=self.allowed_origins,
                allowed_areas=self.allowed_areas,
                allowed_tools=self.allowed_tools,
                read_only=self.read_only,
            ),
            query=self.query,
            policy_version=self.policy_version,
            budget=self.budget,
            evidence_requirements=self.evidence_requirements,
            backend_mode=self.backend_mode,
            installation_config_path=self.installation_config_path,
        )


class CancelRequest(FrozenModel):
    """API request payload for POST /api/tasks/{run_id}/cancel."""

    reason: NonEmptyStr = "cancelled_by_user"


class ResumeRequest(FrozenModel):
    """API request payload for POST /api/tasks/{run_id}/resume."""

    human_input: dict[str, Any] = Field(default_factory=dict)


class TakeoverRequest(FrozenModel):
    """API request payload for POST /api/sessions/{session_id}/takeover."""

    owner: NonEmptyStr = "operator"
    reason: NonEmptyStr = "manual_intervention"


class ReleaseRequest(FrozenModel):
    """API request payload for POST /api/sessions/{session_id}/release."""

    owner: NonEmptyStr | None = None


class AgySendRequest(FrozenModel):
    """API request payload for POST /api/agy/send."""

    prompt: NonEmptyStr
    conversation_id: str | None = None
    project_name: str | None = None
    model: NonEmptyStr = "gemini-4-carbon-low"
    allow_hydrogen: bool = False
