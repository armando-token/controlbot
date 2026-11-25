"""Hierarchical root-shared budget configuration and usage accounting contracts."""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field, field_validator

from src.contracts.common import FrozenModel


class BudgetConfig(FrozenModel):
    """Execution budget defaults matching Megaplan §4.4 laboratory limits."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    max_active_children: int = Field(default=2, ge=0)
    max_depth: int = Field(default=1, ge=0)
    max_tool_calls: int = Field(default=16, ge=1)
    max_model_calls: int = Field(default=8, ge=1)
    max_wall_seconds: float = Field(default=120.0, gt=0.0)
    max_total_tokens: int = Field(default=24000, ge=1)
    max_transient_retries: int = Field(default=1, ge=0)
    human_wait_timeout_seconds: float = Field(default=300.0, gt=0.0)

    @field_validator(
        "max_active_children",
        "max_depth",
        "max_tool_calls",
        "max_model_calls",
        "max_total_tokens",
        "max_transient_retries",
        mode="before",
    )
    @classmethod
    def _reject_bool_for_int(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("Boolean value is not valid for integer budget field.")
        return value


class BudgetUsage(FrozenModel):
    """Tracked resource usage and in-flight reservations shared by root + child runs."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    active_children: int = Field(default=0, ge=0)
    tool_calls_used: int = Field(default=0, ge=0)
    tool_calls_reserved: int = Field(default=0, ge=0)
    model_calls_used: int = Field(default=0, ge=0)
    model_calls_reserved: int = Field(default=0, ge=0)
    wall_seconds_elapsed: float = Field(default=0.0, ge=0.0)
    human_wait_seconds_elapsed: float = Field(default=0.0, ge=0.0)
    prompt_tokens_used: int = Field(default=0, ge=0)
    completion_tokens_used: int = Field(default=0, ge=0)
    tokens_reserved: int = Field(default=0, ge=0)
    transient_retries_used: int = Field(default=0, ge=0)
    usage_estimated: bool = False

    @field_validator(
        "active_children",
        "tool_calls_used",
        "tool_calls_reserved",
        "model_calls_used",
        "model_calls_reserved",
        "prompt_tokens_used",
        "completion_tokens_used",
        "tokens_reserved",
        "transient_retries_used",
        mode="before",
    )
    @classmethod
    def _reject_bool_for_int(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("Boolean value is not valid for integer usage field.")
        return value

    @property
    def total_tokens_used(self) -> int:
        return self.prompt_tokens_used + self.completion_tokens_used

    @property
    def effective_tokens(self) -> int:
        return self.total_tokens_used + self.tokens_reserved

    @property
    def effective_tool_calls(self) -> int:
        return self.tool_calls_used + self.tool_calls_reserved

    @property
    def effective_model_calls(self) -> int:
        return self.model_calls_used + self.model_calls_reserved

    def within_limits(self, config: BudgetConfig) -> bool:
        """Return True iff all effective usage counters are within configured caps."""
        return (
            self.active_children <= config.max_active_children
            and self.effective_tool_calls <= config.max_tool_calls
            and self.effective_model_calls <= config.max_model_calls
            and self.wall_seconds_elapsed <= config.max_wall_seconds
            and self.effective_tokens <= config.max_total_tokens
            and self.transient_retries_used <= config.max_transient_retries
            and self.human_wait_seconds_elapsed <= config.human_wait_timeout_seconds
        )
