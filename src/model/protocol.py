"""Model client protocol and structured decision/usage contracts (F09)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import ConfigDict, Field, field_validator, model_validator

from src.contracts.common import FrozenModel, HttpOrigin, NonEmptyStr
from src.contracts.models import Observation, ToolSpec
from src.storage.redaction import contains_unredacted_secret_strict


class ModelProtocolError(RuntimeError):
    """Raised when a model backend returns malformed or invalid structured output."""


class ModelPermissionError(ModelProtocolError):
    """Raised when a model attempts to call a tool outside its allowed tool list."""


class TransientModelError(RuntimeError):
    """Raised on retryable model transport or temporary backend failures."""


class ModelUsage(FrozenModel):
    """Token usage reported by a model backend or conservatively estimated."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    usage_mode: Literal["actual", "estimated"] = "actual"

    @field_validator("prompt_tokens", "completion_tokens", "total_tokens", mode="before")
    @classmethod
    def _reject_bool_for_int(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("Boolean value is not valid for token count.")
        return value

    @model_validator(mode="after")
    def _validate_total(self) -> ModelUsage:
        if self.total_tokens < self.prompt_tokens + self.completion_tokens:
            raise ValueError(
                "total_tokens must be >= prompt_tokens + completion_tokens."
            )
        return self

    @classmethod
    def from_raw(
        cls,
        *,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
        total_tokens: int | None = None,
        prompt_text: str = "",
        completion_text: str = "",
    ) -> ModelUsage:
        """Build ModelUsage from backend counts, falling back conservatively if omitted."""
        if prompt_tokens is not None and completion_tokens is not None:
            computed_total = (
                total_tokens if total_tokens is not None else prompt_tokens + completion_tokens
            )
            return cls(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=max(computed_total, prompt_tokens + completion_tokens),
                usage_mode="actual",
            )

        est_prompt = (
            max(1, len(prompt_text) // 4 + 64) if prompt_tokens is None else prompt_tokens
        )
        est_completion = (
            max(1, len(completion_text) // 4 + 32)
            if completion_tokens is None
            else completion_tokens
        )
        est_total = max(est_prompt + est_completion, total_tokens or 0)
        return cls(
            prompt_tokens=est_prompt,
            completion_tokens=est_completion,
            total_tokens=est_total,
            usage_mode="estimated",
        )


class ModelToolCall(FrozenModel):
    """Structured tool invocation proposed by a model decision."""

    tool_id: NonEmptyStr
    args: dict[str, Any] = Field(default_factory=dict)
    target_origin: HttpOrigin | None = None
    completion_verifier: NonEmptyStr | None = None
    rationale: str = ""


class ModelDelegationRequest(FrozenModel):
    """Structured depth=1 child delegation request proposed by a model decision."""

    child_label: NonEmptyStr
    query: NonEmptyStr
    allowed_tools: tuple[NonEmptyStr, ...] = ()
    allowed_origins: tuple[HttpOrigin, ...] = ()
    allowed_areas: tuple[NonEmptyStr, ...] = ()
    read_only: bool | None = None


class ModelDecision(FrozenModel):
    """Structured decision emitted by ModelClient.decide()."""

    decision_type: Literal["tool_call", "delegate", "request_input", "final"]
    tool_call: ModelToolCall | None = None
    delegations: tuple[ModelDelegationRequest, ...] = ()
    required_action: NonEmptyStr | None = None
    final_answer: str | None = None
    partial_info: dict[str, Any] | None = None
    usage: ModelUsage

    @model_validator(mode="after")
    def _validate_payload_alignment(self) -> ModelDecision:
        if self.decision_type == "tool_call" and self.tool_call is None:
            raise ValueError("tool_call decision must include tool_call payload.")
        if self.decision_type == "delegate" and not self.delegations:
            raise ValueError("delegate decision must include at least one delegation request.")
        if self.decision_type == "request_input" and self.required_action is None:
            raise ValueError("request_input decision must include required_action.")
        if self.decision_type == "final" and self.final_answer is None:
            raise ValueError("final decision must include final_answer.")
        return self


class PromptContext(FrozenModel):
    """Redacted prompt state passed into ModelClient.decide()."""

    task_id: NonEmptyStr
    run_id: NonEmptyStr
    depth: int = Field(ge=0)
    query: NonEmptyStr
    facility_id: NonEmptyStr
    allowed_areas: tuple[NonEmptyStr, ...] = ()
    history: tuple[dict[str, Any], ...] = ()
    observations: tuple[Observation, ...] = ()
    human_input: dict[str, Any] | None = None
    turn_index: int = Field(default=0, ge=0)
    min_sources: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _enforce_no_secrets(self) -> PromptContext:
        for field_name in ("query", "history", "human_input"):
            val = getattr(self, field_name)
            if val is not None and contains_unredacted_secret_strict(val):
                raise ValueError(
                    f"PromptContext.{field_name} contains unredacted secret material."
                )
        return self


class BudgetRemaining(FrozenModel):
    """Remaining shared quota summary visible to the model client."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    active_children_remaining: int = Field(ge=0)
    depth_remaining: int = Field(ge=0)
    tool_calls_remaining: int = Field(ge=0)
    model_calls_remaining: int = Field(ge=0)
    wall_seconds_remaining: float = Field(ge=0.0)
    tokens_remaining: int = Field(ge=0)


@runtime_checkable
class ModelClient(Protocol):
    """Asynchronous local model inference protocol."""

    async def decide(
        self,
        prompt_ctx: PromptContext,
        tools: Sequence[ToolSpec],
        budget_remaining: BudgetRemaining,
    ) -> ModelDecision:
        """Select the next tool call, child delegation, human input pause, or final answer."""
        ...
