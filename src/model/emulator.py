"""Deterministic offline EmulatedModelClient for N1/M2 verification (F09)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, get_args

from src.contracts.models import ToolSpec
from src.model.protocol import (
    BudgetRemaining,
    ModelDecision,
    ModelDelegationRequest,
    ModelToolCall,
    ModelUsage,
    PromptContext,
    TransientModelError,
)

EmulatorMode = Literal[
    "happy_path",
    "delegation",
    "ambiguity",
    "transient_error",
    "loop_a06",
    "cycle_a07",
    "omitted_tokens",
    "custom",
]

VALID_EMULATOR_MODES: frozenset[str] = frozenset(get_args(EmulatorMode))


@dataclass(frozen=True)
class EmulatedTurn:
    """Single scripted or dynamic turn for EmulatedModelClient."""

    decision: (
        ModelDecision | Callable[[PromptContext, Sequence[ToolSpec]], ModelDecision] | None
    ) = None
    raise_transient: bool = False
    omit_tokens: bool = False
    delay_s: float = 0.0


def _pick_tool(
    tools: Sequence[ToolSpec],
    index: int = 0,
    fallback_id: str = "read_status",
) -> tuple[str, str | None, str | None]:
    if not tools:
        return fallback_id, None, None
    tool = tools[index % len(tools)]
    origin = tool.allowed_origins[0] if tool.allowed_origins else None
    return tool.tool_id, origin, tool.verifier_name


def _default_args_for_tool(
    tool_id: str,
    overrides: Mapping[str, dict[str, Any]] | None,
    prompt_ctx: PromptContext,
    variant: int = 0,
) -> dict[str, Any]:
    if overrides and tool_id in overrides:
        return dict(overrides[tool_id])
    area = prompt_ctx.allowed_areas[0] if prompt_ctx.allowed_areas else "area-1"
    if variant > 0:
        return {"asset": f"pump-34-v{variant}", "area": area}
    return {"asset": "pump-34", "area": area}


class EmulatedModelClient:
    """Deterministic offline ModelClient supporting scripted turns and 6+ built-in modes."""

    def __init__(
        self,
        *,
        mode: EmulatorMode = "happy_path",
        scripted_turns: Mapping[str, Sequence[EmulatedTurn]] | None = None,
        default_turns: Sequence[EmulatedTurn] | None = None,
        turn_factory: (
            Callable[[PromptContext, Sequence[ToolSpec], BudgetRemaining], EmulatedTurn] | None
        ) = None,
        tool_args_overrides: Mapping[str, dict[str, Any]] | None = None,
        seed: int = 0,
    ) -> None:
        if mode not in VALID_EMULATOR_MODES:
            raise ValueError(
                f"Invalid emulator mode {mode!r}; expected one of {sorted(VALID_EMULATOR_MODES)}."
            )
        self._mode: EmulatorMode = mode
        self._scripted_turns: dict[str, list[EmulatedTurn]] = {
            k: list(v) for k, v in (scripted_turns or {}).items()
        }
        self._default_turns: list[EmulatedTurn] = list(default_turns or [])
        self._turn_factory = turn_factory
        self._tool_args_overrides = dict(tool_args_overrides or {})
        self._seed = seed
        self.call_history: list[PromptContext] = []
        self._run_call_counts: dict[str, int] = {}
        self._transient_raised_keys: set[tuple[str, int]] = set()

    @property
    def mode(self) -> EmulatorMode:
        return self._mode

    def _next_call_index(self, run_id: str) -> int:
        idx = self._run_call_counts.get(run_id, 0)
        self._run_call_counts[run_id] = idx + 1
        return idx

    async def decide(
        self,
        prompt_ctx: PromptContext,
        tools: Sequence[ToolSpec],
        budget_remaining: BudgetRemaining,
    ) -> ModelDecision:
        """Return a deterministic ModelDecision or raise TransientModelError when configured."""
        self.call_history.append(prompt_ctx)
        call_idx = self._next_call_index(prompt_ctx.run_id)

        if self._turn_factory is not None:
            turn = self._turn_factory(prompt_ctx, tools, budget_remaining)
            return await self._execute_turn(turn, prompt_ctx, tools)

        script = self._scripted_turns.get(prompt_ctx.run_id) or self._scripted_turns.get(
            prompt_ctx.task_id
        )
        if script is None and self._default_turns:
            script = self._default_turns

        if script is not None:
            if not script:
                raise ValueError("Configured scripted turn list must not be empty.")
            turn = script[min(call_idx, len(script) - 1)]
            return await self._execute_turn(turn, prompt_ctx, tools)

        return await self._decide_builtin_mode(prompt_ctx, tools, call_idx)

    async def _execute_turn(
        self,
        turn: EmulatedTurn,
        prompt_ctx: PromptContext,
        tools: Sequence[ToolSpec],
    ) -> ModelDecision:
        if turn.delay_s > 0.0:
            await asyncio.sleep(turn.delay_s)
        if turn.raise_transient:
            raise TransientModelError("Emulated transient model failure.")
        if turn.decision is None:
            raise ValueError("EmulatedTurn must define decision when raise_transient is False.")
        decision = (
            turn.decision(prompt_ctx, tools) if callable(turn.decision) else turn.decision
        )
        if turn.omit_tokens:
            prompt_text = prompt_ctx.query
            completion_text = decision.final_answer or (
                decision.tool_call.tool_id if decision.tool_call else "decision"
            )
            estimated = ModelUsage.from_raw(
                prompt_tokens=None,
                completion_tokens=None,
                total_tokens=None,
                prompt_text=prompt_text,
                completion_text=completion_text,
            )
            return decision.model_copy(update={"usage": estimated})
        return decision

    async def _decide_builtin_mode(
        self,
        prompt_ctx: PromptContext,
        tools: Sequence[ToolSpec],
        call_idx: int,
    ) -> ModelDecision:
        actual_usage = ModelUsage(
            prompt_tokens=40 + (self._seed % 17),
            completion_tokens=20 + (self._seed % 13),
            total_tokens=60 + (self._seed % 17) + (self._seed % 13),
            usage_mode="actual",
        )
        tool_id, origin, verifier = _pick_tool(tools, 0)
        args = _default_args_for_tool(tool_id, self._tool_args_overrides, prompt_ctx)

        if self._mode == "happy_path":
            if prompt_ctx.turn_index == 0 and tools:
                return ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id=tool_id,
                        args=args,
                        target_origin=origin,
                        completion_verifier=verifier,
                        rationale="Query initial source reading.",
                    ),
                    usage=actual_usage,
                )
            return ModelDecision(
                decision_type="final",
                final_answer=(
                    f"Completed query '{prompt_ctx.query}' with "
                    f"{len(prompt_ctx.observations)} verified observation(s)."
                ),
                usage=actual_usage,
            )

        if self._mode == "delegation":
            if prompt_ctx.depth == 0:
                if prompt_ctx.turn_index == 0:
                    allowed_tools = tuple(t.tool_id for t in tools[:1]) if tools else ()
                    allowed_origins = (origin,) if origin else ()
                    return ModelDecision(
                        decision_type="delegate",
                        delegations=(
                            ModelDelegationRequest(
                                child_label="scada-branch",
                                query=f"{prompt_ctx.query} [branch-1]",
                                allowed_tools=allowed_tools,
                                allowed_origins=allowed_origins,
                            ),
                            ModelDelegationRequest(
                                child_label="maint-branch",
                                query=f"{prompt_ctx.query} [branch-2]",
                                allowed_tools=allowed_tools,
                                allowed_origins=allowed_origins,
                            ),
                        ),
                        usage=actual_usage,
                    )
                return ModelDecision(
                    decision_type="final",
                    final_answer=(
                        f"Synthesized parent answer from {len(prompt_ctx.observations)} "
                        "child observation(s)."
                    ),
                    usage=actual_usage,
                )
            if prompt_ctx.turn_index == 0 and tools:
                return ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id=tool_id,
                        args=args,
                        target_origin=origin,
                        completion_verifier=verifier,
                        rationale="Child branch tool query.",
                    ),
                    usage=actual_usage,
                )
            return ModelDecision(
                decision_type="final",
                final_answer=f"Child {prompt_ctx.run_id} finished.",
                usage=actual_usage,
            )

        if self._mode == "ambiguity":
            if prompt_ctx.human_input is None and prompt_ctx.turn_index == 0:
                return ModelDecision(
                    decision_type="request_input",
                    required_action="Multiple matching assets found; specify target area.",
                    usage=actual_usage,
                )
            if tools and not prompt_ctx.observations and not prompt_ctx.history:
                chosen_area = (
                    str(prompt_ctx.human_input.get("area"))
                    if prompt_ctx.human_input and "area" in prompt_ctx.human_input
                    else args.get("area", "area-1")
                )
                resolved_args = {**args, "area": chosen_area}
                return ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id=tool_id,
                        args=resolved_args,
                        target_origin=origin,
                        completion_verifier=verifier,
                        rationale="Query clarified target area.",
                    ),
                    usage=actual_usage,
                )
            return ModelDecision(
                decision_type="final",
                final_answer=f"Resolved with human input: {prompt_ctx.human_input}",
                usage=actual_usage,
            )

        if self._mode == "transient_error":
            key = (prompt_ctx.run_id, prompt_ctx.turn_index)
            if prompt_ctx.turn_index == 0 and key not in self._transient_raised_keys:
                self._transient_raised_keys.add(key)
                raise TransientModelError("Emulated transient model timeout.")
            if prompt_ctx.turn_index == 0 and tools:
                return ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id=tool_id,
                        args=args,
                        target_origin=origin,
                        completion_verifier=verifier,
                        rationale="Retry after transient model failure.",
                    ),
                    usage=actual_usage,
                )
            return ModelDecision(
                decision_type="final",
                final_answer="Succeeded after transient model retry.",
                usage=actual_usage,
            )

        if self._mode == "loop_a06":
            return ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id=tool_id,
                    args=args,
                    target_origin=origin,
                    completion_verifier=verifier,
                    rationale="Repeated identical call (A06).",
                ),
                usage=actual_usage,
            )

        if self._mode == "cycle_a07":
            if len(tools) >= 2:
                idx = call_idx % 2
                c_tool_id, c_origin, c_verifier = _pick_tool(tools, idx)
                c_args = _default_args_for_tool(
                    c_tool_id, self._tool_args_overrides, prompt_ctx
                )
            else:
                idx = call_idx % 2
                c_tool_id, c_origin, c_verifier = tool_id, origin, verifier
                c_args = _default_args_for_tool(
                    c_tool_id, self._tool_args_overrides, prompt_ctx, variant=idx
                )
            return ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id=c_tool_id,
                    args=c_args,
                    target_origin=c_origin,
                    completion_verifier=c_verifier,
                    rationale=f"Alternating cycle step {idx} (A07).",
                ),
                usage=actual_usage,
            )

        if self._mode == "omitted_tokens":
            if prompt_ctx.turn_index == 0 and tools:
                est_usage = ModelUsage.from_raw(
                    prompt_tokens=None,
                    completion_tokens=None,
                    total_tokens=None,
                    prompt_text=prompt_ctx.query,
                    completion_text=tool_id,
                )
                return ModelDecision(
                    decision_type="tool_call",
                    tool_call=ModelToolCall(
                        tool_id=tool_id,
                        args=args,
                        target_origin=origin,
                        completion_verifier=verifier,
                        rationale="Omitted token count turn.",
                    ),
                    usage=est_usage,
                )
            final_text = f"Completed with estimated tokens for '{prompt_ctx.query}'."
            est_usage = ModelUsage.from_raw(
                prompt_tokens=None,
                completion_tokens=None,
                total_tokens=None,
                prompt_text=prompt_ctx.query,
                completion_text=final_text,
            )
            return ModelDecision(
                decision_type="final",
                final_answer=final_text,
                usage=est_usage,
            )

        raise ValueError(
            "Mode 'custom' requires scripted_turns, default_turns, or turn_factory."
        )
