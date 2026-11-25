"""Execution plan models and pre-execution validation against TaskSpec and ToolSpecs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, model_validator

from src.contracts.common import FrozenModel, HttpOrigin, NonEmptyStr, PlanValidationError
from src.contracts.enums import EffectClass
from src.contracts.models import TaskSpec, ToolSpec


class PlanStep(FrozenModel):
    """Single planned step in an ExecutionPlan DAG."""

    step_index: int = Field(ge=0)
    tool_id: NonEmptyStr
    args: dict[str, Any] = Field(default_factory=dict)
    completion_verifier: NonEmptyStr
    depends_on: tuple[int, ...] = ()
    target_origin: HttpOrigin | None = None
    effect_class: EffectClass = EffectClass.READ


class ExecutionPlan(FrozenModel):
    """Validated acyclic plan of steps for a task."""

    plan_id: NonEmptyStr
    task_id: NonEmptyStr
    steps: tuple[PlanStep, ...] = Field(min_length=1)
    rationale: str = ""

    @model_validator(mode="after")
    def _validate_dag_structure(self) -> ExecutionPlan:
        for expected_idx, step in enumerate(self.steps):
            if step.step_index != expected_idx:
                raise ValueError(
                    f"Plan steps must have contiguous indices 0..N-1; "
                    f"expected {expected_idx}, got {step.step_index}."
                )
            for dep in step.depends_on:
                if dep < 0 or dep >= step.step_index:
                    raise ValueError(
                        f"Step {step.step_index} has invalid dependency {dep}; "
                        "dependencies must satisfy 0 <= dep < step_index."
                    )
        return self


def validate_plan_for_task(
    plan: ExecutionPlan,
    task: TaskSpec,
    tool_specs: Mapping[str, ToolSpec],
) -> list[str]:
    """Validate an ExecutionPlan against TaskSpec scope, budget, and registered ToolSpecs."""
    errors: list[str] = []

    if plan.task_id != task.task_id:
        errors.append(f"plan.task_id ({plan.task_id}) != task.task_id ({task.task_id})")

    if len(plan.steps) > task.budget.max_tool_calls:
        errors.append(
            f"plan step count ({len(plan.steps)}) exceeds "
            f"budget.max_tool_calls ({task.budget.max_tool_calls})"
        )

    for step in plan.steps:
        tool_spec = tool_specs.get(step.tool_id)
        if tool_spec is None:
            errors.append(f"step[{step.step_index}]: unknown tool_id {step.tool_id!r}")
            continue

        if task.scope.allowed_tools and step.tool_id not in task.scope.allowed_tools:
            errors.append(
                f"step[{step.step_index}]: tool_id {step.tool_id!r} not in scope.allowed_tools"
            )

        if step.effect_class != tool_spec.effect_class:
            errors.append(
                f"step[{step.step_index}]: effect_class {step.effect_class.value!r} "
                f"!= tool {step.tool_id!r} effect_class {tool_spec.effect_class.value!r}"
            )

        if task.scope.read_only and (
            step.effect_class == EffectClass.EFFECT
            or tool_spec.effect_class == EffectClass.EFFECT
        ):
            errors.append(
                f"step[{step.step_index}]: effect tool {step.tool_id!r} disallowed when "
                "scope.read_only=True"
            )

        if tool_spec.allowed_origins:
            if not task.scope.allowed_origins:
                errors.append(
                    f"step[{step.step_index}]: tool {step.tool_id!r} requires allowed_origins, "
                    "but scope.allowed_origins is empty"
                )
            elif not (set(tool_spec.allowed_origins) & set(task.scope.allowed_origins)):
                errors.append(
                    f"step[{step.step_index}]: tool {step.tool_id!r}.allowed_origins has no "
                    "overlap with scope.allowed_origins"
                )
            if step.target_origin is None:
                errors.append(
                    f"step[{step.step_index}]: target_origin is required for "
                    f"origin-restricted tool {step.tool_id!r}"
                )

        if step.target_origin is not None:
            if step.target_origin not in task.scope.allowed_origins:
                errors.append(
                    f"step[{step.step_index}]: target_origin {step.target_origin!r} "
                    "not in scope.allowed_origins"
                )
            if (
                tool_spec.allowed_origins
                and step.target_origin not in tool_spec.allowed_origins
            ):
                errors.append(
                    f"step[{step.step_index}]: target_origin {step.target_origin!r} "
                    f"not in tool {step.tool_id!r}.allowed_origins"
                )

        if step.completion_verifier != tool_spec.verifier_name:
            errors.append(
                f"step[{step.step_index}]: completion_verifier {step.completion_verifier!r} "
                f"!= tool verifier_name {tool_spec.verifier_name!r}"
            )

    return errors


def assert_valid_plan(
    plan: ExecutionPlan,
    task: TaskSpec,
    tool_specs: Mapping[str, ToolSpec],
) -> None:
    """Raise PlanValidationError if validate_plan_for_task reports any violation."""
    errors = validate_plan_for_task(plan, task, tool_specs)
    if errors:
        raise PlanValidationError("; ".join(errors))
