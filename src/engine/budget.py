"""Shared hierarchical budget accounting and duration helpers (F07, A14)."""

from __future__ import annotations

import math
from datetime import datetime

from src.contracts.budgets import BudgetConfig, BudgetUsage
from src.contracts.common import ensure_utc
from src.contracts.models import ExecutionMetrics
from src.model.protocol import BudgetRemaining, PromptContext


def validate_duration_seconds(value: float, field_name: str) -> float:
    """Reject booleans, NaN, inf, and negative durations."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be float/int, got {type(value).__name__}.")
    fval = float(value)
    if not math.isfinite(fval) or fval < 0.0:
        raise ValueError(f"{field_name} must be finite and >= 0.0, got {value!r}.")
    return fval


class BudgetManager:
    """Computes conservative reservations, active wall-clock elapsed, and metrics."""

    def estimate_model_reserve_tokens(
        self,
        prompt_ctx: PromptContext,
        budget_config: BudgetConfig,
        configured_reserve: int | None = None,
    ) -> int:
        """Compute conservative pre-call token reservation for a model request."""
        if configured_reserve is not None:
            if isinstance(configured_reserve, bool) or configured_reserve < 1:
                raise ValueError("configured_reserve must be positive integer.")
            return configured_reserve

        prompt_chars = len(prompt_ctx.query) + sum(len(str(h)) for h in prompt_ctx.history)
        est_prompt = max(16, prompt_chars // 4 + 32)
        est_completion = min(1024, max(32, budget_config.max_total_tokens // 4))
        return est_prompt + est_completion

    def compute_active_wall_seconds(
        self,
        *,
        run_created_at: datetime,
        now: datetime,
        stored_wall_seconds: float,
        human_wait_seconds_elapsed: float,
        is_waiting_for_input: bool,
    ) -> float:
        """Compute active execution wall seconds excluding human waiting_for_input pauses."""
        stored = validate_duration_seconds(stored_wall_seconds, "stored_wall_seconds")
        human_wait = validate_duration_seconds(
            human_wait_seconds_elapsed, "human_wait_seconds_elapsed"
        )
        if is_waiting_for_input:
            return stored
        total_since_created = max(
            0.0, (ensure_utc(now) - ensure_utc(run_created_at)).total_seconds()
        )
        active = max(0.0, total_since_created - human_wait)
        return max(stored, active)

    def to_budget_remaining(
        self,
        config: BudgetConfig,
        usage: BudgetUsage,
        current_depth: int,
    ) -> BudgetRemaining:
        """Build BudgetRemaining summary for ModelClient.decide()."""
        return BudgetRemaining(
            active_children_remaining=max(0, config.max_active_children - usage.active_children),
            depth_remaining=max(0, config.max_depth - current_depth),
            tool_calls_remaining=max(0, config.max_tool_calls - usage.effective_tool_calls),
            model_calls_remaining=max(0, config.max_model_calls - usage.effective_model_calls),
            wall_seconds_remaining=max(0.0, config.max_wall_seconds - usage.wall_seconds_elapsed),
            tokens_remaining=max(0, config.max_total_tokens - usage.effective_tokens),
        )

    def to_execution_metrics(self, usage: BudgetUsage) -> ExecutionMetrics:
        """Convert persisted BudgetUsage into frozen ExecutionMetrics for Result."""
        return ExecutionMetrics(
            tool_calls=usage.tool_calls_used,
            model_calls=usage.model_calls_used,
            prompt_tokens=usage.prompt_tokens_used,
            completion_tokens=usage.completion_tokens_used,
            total_tokens=usage.total_tokens_used,
            wall_seconds=usage.wall_seconds_elapsed,
            human_wait_seconds=usage.human_wait_seconds_elapsed,
            retries=usage.transient_retries_used,
            usage_estimated=usage.usage_estimated,
        )
