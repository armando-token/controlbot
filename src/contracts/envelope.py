"""Domain-agnostic TaskEnvelope, Lane, VerdictState, and VerifiedResponseMeta contracts (CB-01)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import Field, model_validator

from src.contracts.budgets import BudgetConfig
from src.contracts.common import FrozenModel, HttpOrigin, NonEmptyStr, UtcDatetime, utc_now
from src.contracts.enums import BackendMode
from src.contracts.models import ContradictionRecord, EvidenceRequirements, TaskScope, TaskSpec


class Lane(StrEnum):
    """Execution lane routing policy for dual-lane work assistant tasks."""

    GENERAL = "general"
    INDUSTRIAL = "industrial"
    MIXED = "mixed"


class VerdictState(StrEnum):
    """Tri-state / structured verification verdict attached to assistant responses."""

    VERIFIED = "verified"
    CONTRADICTED = "contradicted"
    NOT_DOCUMENTED = "not_documented"
    PARTIAL_EVIDENCE = "partial_evidence"
    STALE_DATA = "stale_data"
    ASSET_NOT_FOUND = "asset_not_found"
    NEEDS_CLARIFICATION = "needs_clarification"


class ActorContext(FrozenModel):
    """Authenticated caller identity attached to a TaskEnvelope."""

    user_id: NonEmptyStr
    profile_id: NonEmptyStr
    role: NonEmptyStr = "operator"
    tenant_id: NonEmptyStr | None = None


class AirlockProvenance(FrozenModel):
    """Explicit Planta vs Web provenance split emitted by EvidenceAirlock."""

    plant_sources: tuple[NonEmptyStr, ...] = ()
    web_sources: tuple[NonEmptyStr, ...] = ()
    airlock_audit_id: str | None = None
    projected_fields: dict[str, str] = Field(default_factory=dict)


class VerifiedResponseMeta(FrozenModel):
    """Structured verification metadata persisted on assistant messages and SSE events."""

    verdict: VerdictState
    lane: Lane
    domain_profile: NonEmptyStr
    agreements: tuple[str, ...] = ()
    contradictions: tuple[ContradictionRecord, ...] = ()
    partial_evidence: tuple[str, ...] = ()
    missing_attributes: tuple[str, ...] = ()
    clarification_candidates: tuple[dict[str, str], ...] = ()
    nearest_assets: tuple[dict[str, str], ...] = ()
    stale_info: dict[str, Any] | None = None
    degraded_banner: str | None = None
    excel_verification: dict[str, Any] | None = None
    airlock_provenance: AirlockProvenance | None = None
    citations: tuple[str, ...] = ()


class TaskEnvelope(FrozenModel):
    """Domain-agnostic task contract supporting general, industrial, and mixed lanes."""

    task_id: NonEmptyStr
    thread_id: NonEmptyStr | None = None
    lane: Lane = Lane.GENERAL
    domain_profile: NonEmptyStr = "general_office"
    actor: ActorContext
    query: NonEmptyStr
    budget_root_id: NonEmptyStr
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    required_verifiers: tuple[NonEmptyStr, ...] = ()
    facility_id: NonEmptyStr | None = None
    asset_refs: tuple[NonEmptyStr, ...] = ()
    allowed_origins: tuple[HttpOrigin, ...] = ()
    allowed_tools: tuple[NonEmptyStr, ...] = ()
    read_only: bool = True
    evidence_requirements: EvidenceRequirements = Field(default_factory=EvidenceRequirements)
    created_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _validate_lane_constraints(self) -> TaskEnvelope:
        if self.lane == Lane.INDUSTRIAL and self.read_only is False and not self.allowed_tools:
            raise ValueError(
                "Write-capable industrial TaskEnvelope requires explicit allowed_tools "
                "(fail-closed)."
            )
        return self

    def to_legacy_task_spec(
        self,
        *,
        fallback_facility_id: str = "general-sandbox",
        backend_mode: BackendMode = BackendMode.EMULATED,
        policy_version: str = "2.0.0",
    ) -> TaskSpec:
        """Bridge TaskEnvelope to frozen M1 TaskSpec without requiring facility_id in general."""
        facility = self.facility_id or fallback_facility_id
        scope = TaskScope(
            facility_id=facility,
            allowed_origins=self.allowed_origins,
            allowed_areas=(),
            allowed_tools=self.allowed_tools,
            read_only=self.read_only,
        )
        return TaskSpec(
            task_id=self.task_id,
            user_id=self.actor.user_id,
            profile_id=self.actor.profile_id,
            scope=scope,
            query=self.query,
            policy_version=policy_version,
            budget=self.budget,
            evidence_requirements=self.evidence_requirements,
            backend_mode=backend_mode,
            created_at=self.created_at,
        )

    @classmethod
    def from_task_spec(
        cls,
        task_spec: TaskSpec,
        *,
        lane: Lane = Lane.INDUSTRIAL,
        domain_profile: str = "industrial_ot",
        role: str = "operator",
        thread_id: str | None = None,
        required_verifiers: tuple[str, ...] = ("industrial_reconciler",),
    ) -> TaskEnvelope:
        """Construct a TaskEnvelope from a legacy M1 TaskSpec."""
        return cls(
            task_id=task_spec.task_id,
            thread_id=thread_id,
            lane=lane,
            domain_profile=domain_profile,
            actor=ActorContext(
                user_id=task_spec.user_id,
                profile_id=task_spec.profile_id,
                role=role,
            ),
            query=task_spec.query,
            budget_root_id=task_spec.task_id,
            budget=task_spec.budget,
            required_verifiers=required_verifiers,
            facility_id=task_spec.scope.facility_id,
            allowed_origins=task_spec.scope.allowed_origins,
            allowed_tools=task_spec.scope.allowed_tools,
            read_only=task_spec.scope.read_only,
            evidence_requirements=task_spec.evidence_requirements,
            created_at=task_spec.created_at,
        )


__all__ = [
    "ActorContext",
    "AirlockProvenance",
    "Lane",
    "TaskEnvelope",
    "VerdictState",
    "VerifiedResponseMeta",
]
