"""Persisted loop and alternating cycle detection (F07, A06, A07)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from typing import Any, Literal

from pydantic import Field

from src.contracts.common import FrozenModel
from src.storage.repo import StepSignatureRecord


def canonical_json_hash(data: Any) -> str:
    """Compute stable SHA-256 hash over canonical JSON representation."""
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


class LoopConfig(FrozenModel):
    """Thresholds for A06 identical repetition and A07 alternating cycle detection."""

    identical_repeat_threshold: int = Field(default=3, ge=2)
    max_cycle_period: int = Field(default=4, ge=2)
    cycle_repeats: int = Field(default=2, ge=2)


class LoopGuardDecision(FrozenModel):
    """Evaluation verdict produced by LoopDetector."""

    action: Literal["allow", "halt"]
    kind: Literal["identical_repeat", "alternating_cycle"] | None = None
    reason: str = ""


class LoopDetector:
    """Detects identical repeated calls (A06) and alternating cycles (A07) with zero progress."""

    def __init__(self, config: LoopConfig | None = None) -> None:
        self._config = config or LoopConfig()

    @property
    def config(self) -> LoopConfig:
        return self._config

    @staticmethod
    def _sig_key(
        rec: StepSignatureRecord, poller_tools: AbstractSet[str]
    ) -> tuple[str, str, str, str, str | None]:
        # Registered pollers advance progress_token when observed state changes;
        # ignore raw ephemeral result_hash when progress_token is present for a poller.
        if rec.tool_id in poller_tools and rec.progress_token is not None:
            return (
                rec.tool_id,
                rec.target_key,
                rec.canonical_args_hash,
                "__poller__",
                rec.progress_token,
            )
        return (
            rec.tool_id,
            rec.target_key,
            rec.canonical_args_hash,
            rec.result_hash,
            rec.progress_token,
        )

    def evaluate(
        self,
        history: Sequence[StepSignatureRecord],
        *,
        poller_tools: AbstractSet[str] = frozenset(),
    ) -> LoopGuardDecision:
        """Inspect persisted step signature history for A06 repeats or A07 alternating cycles."""
        n = self._config.identical_repeat_threshold
        if len(history) >= n:
            tail = history[-n:]
            tail_keys = [self._sig_key(rec, poller_tools) for rec in tail]
            if len(set(tail_keys)) == 1:
                sample = tail[-1]
                return LoopGuardDecision(
                    action="halt",
                    kind="identical_repeat",
                    reason=(
                        f"loop_detected: identical repeated call to {sample.tool_id!r} "
                        f"({n} times with zero net progress, succeeded={sample.succeeded})"
                    ),
                )

        for period in range(2, self._config.max_cycle_period + 1):
            window_len = period * self._config.cycle_repeats
            if len(history) < window_len:
                continue
            window = history[-window_len:]
            window_keys = [self._sig_key(rec, poller_tools) for rec in window]
            # Verify periodic repetition across cycle_repeats cycles
            matches_period = all(
                window_keys[i] == window_keys[i + period]
                for i in range(period * (self._config.cycle_repeats - 1))
            )
            if not matches_period:
                continue
            # Ensure at least 2 distinct call signatures in the period (otherwise A06 handles it)
            if len(set(window_keys[:period])) < 2:
                continue
            cycle_tools = " -> ".join(rec.tool_id for rec in window[:period])
            return LoopGuardDecision(
                action="halt",
                kind="alternating_cycle",
                reason=(
                    f"loop_detected: alternating cycle of period {period} "
                    f"({cycle_tools}) repeated {self._config.cycle_repeats} times "
                    "with zero net progress"
                ),
            )

        return LoopGuardDecision(action="allow")
