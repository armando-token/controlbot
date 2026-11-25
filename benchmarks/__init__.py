"""Comparative benchmark suite for GrokbotEngine vs RuleBasedBaseline (Megaplan §6.2-6.3)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from benchmarks.baseline import RuleBasedBaseline
from benchmarks.report import (
    A12AdaptationMetrics,
    BenchmarkReport,
    ProvenanceMetadata,
    ScenarioTrialResult,
    SystemAggregateMetrics,
    aggregate_trials,
    evaluate_promotion_gate,
    format_markdown_report,
)
from benchmarks.scenarios import (
    BENCHMARK_SCENARIOS,
    BenchmarkScenario,
    get_all_scenarios,
    get_runnable_scenarios,
)

if TYPE_CHECKING:
    from benchmarks.runner import run_benchmarks as run_benchmarks

__all__ = [
    "A12AdaptationMetrics",
    "BENCHMARK_SCENARIOS",
    "BenchmarkReport",
    "BenchmarkScenario",
    "ProvenanceMetadata",
    "RuleBasedBaseline",
    "ScenarioTrialResult",
    "SystemAggregateMetrics",
    "aggregate_trials",
    "evaluate_promotion_gate",
    "format_markdown_report",
    "get_all_scenarios",
    "get_runnable_scenarios",
    "run_benchmarks",
]


def __getattr__(name: str) -> Any:
    if name == "run_benchmarks":
        from benchmarks.runner import run_benchmarks as _run_benchmarks

        return _run_benchmarks
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
