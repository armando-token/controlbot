"""Benchmark metrics aggregation, promotion gates, and JSON/Markdown reporting."""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from typing import Literal

from pydantic import Field
from src.contracts.common import FrozenModel


class ScenarioTrialResult(FrozenModel):
    """Measured outcome for one execution trial of a scenario by a system."""

    scenario_id: str
    scenario_name: str
    system: Literal["baseline", "grokbot_engine"]
    repeat_index: int = Field(ge=1)
    evidence_tier: str
    executed: bool = True
    status: str
    correct: bool
    correct_abstention: bool = False
    false_positive: bool = False
    wrong_asset_attribution: bool = False
    duplicate_effects: int = Field(default=0, ge=0)
    state_loss: int = Field(default=0, ge=0)
    isolation_violation: int = Field(default=0, ge=0)
    unauthorized_action: int = Field(default=0, ge=0)
    disallowed_egress: int = Field(default=0, ge=0)
    duration_ms: float = Field(ge=0.0)
    tool_calls: int = Field(default=0, ge=0)
    model_calls: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    usage_mode: str = "actual"
    detail: str = ""


class SystemAggregateMetrics(FrozenModel):
    """Aggregated Megaplan §6.2 metrics for one evaluated system."""

    system: str
    num_scenarios: int = Field(ge=0)
    repeats_per_scenario: int = Field(ge=1)
    total_trials: int = Field(ge=0)
    correct_answers: int = Field(ge=0)
    accuracy_rate: float = Field(ge=0.0, le=1.0)
    tasks_covered: int = Field(ge=0)
    correct_abstentions: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    wrong_asset_attributions: int = Field(ge=0)
    duplicate_effects: int = Field(ge=0)
    state_loss_count: int = Field(ge=0)
    isolation_violations: int = Field(ge=0)
    unauthorized_actions: int = Field(ge=0)
    disallowed_egress_count: int = Field(ge=0)
    median_duration_ms: float = Field(ge=0.0)
    p95_duration_ms: float = Field(ge=0.0)
    p95_sample_note: str
    total_tool_calls: int = Field(ge=0)
    total_model_calls: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    usage_modes: tuple[str, ...]
    ram_mb: float | None = None
    vram_mb: float | None = None
    vram_note: str
    blocking_failures: tuple[str, ...] = ()
    promotion_eligible: bool


class A12AdaptationMetrics(FrozenModel):
    """Portability adaptation metrics for Facility B (Megaplan §1.1, §4.5, §5 M6)."""

    facility_config_path: str
    files_changed: tuple[str, ...]
    engine_loc_delta: int = Field(ge=0)
    adapter_loc_delta: int = Field(ge=0)
    adaptation_time_seconds: float = Field(ge=0.0)
    adaptation_hours: float = Field(ge=0.0)
    verified_succeeded: bool


class ProvenanceMetadata(FrozenModel):
    """Megaplan §6.3 verifiable benchmark provenance."""

    benchmark_id: str
    git_commit: str
    timestamp_utc: str
    host_os: str
    host_arch: str
    python_version: str
    playwright_version: str
    model_type: str
    evidence_level: str
    n3_status: str
    a11_status: str
    command: str
    exit_code: int


class BenchmarkReport(FrozenModel):
    """Complete comparative benchmark report (paired baseline vs GrokbotEngine)."""

    provenance: ProvenanceMetadata
    baseline_summary: SystemAggregateMetrics
    engine_summary: SystemAggregateMetrics
    a12_adaptation: A12AdaptationMetrics | None = None
    pending_scenarios: tuple[dict[str, str], ...] = ()
    trials: tuple[ScenarioTrialResult, ...]


def _percentile_95(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    idx = min(len(ordered) - 1, max(0, int(0.95 * (len(ordered) - 1) + 0.999999)))
    return ordered[idx]


def aggregate_trials(
    system: str,
    trials: Sequence[ScenarioTrialResult],
    *,
    num_scenarios: int,
    repeats_per_scenario: int,
    ram_mb: float | None,
    vram_mb: float | None,
    vram_note: str,
) -> SystemAggregateMetrics:
    """Compute Megaplan §6.2 summary metrics and promotion blocking checks."""
    executed = [t for t in trials if t.executed]
    total_trials = len(executed)
    correct_answers = sum(1 for t in executed if t.correct)
    accuracy_rate = (correct_answers / total_trials) if total_trials > 0 else 0.0
    tasks_covered = len({t.scenario_id for t in executed})
    correct_abstentions = sum(1 for t in executed if t.correct_abstention)
    false_positives = sum(1 for t in executed if t.false_positive)
    wrong_asset_attributions = sum(1 for t in executed if t.wrong_asset_attribution)
    duplicate_effects = sum(t.duplicate_effects for t in executed)
    state_loss_count = sum(t.state_loss for t in executed)
    isolation_violations = sum(t.isolation_violation for t in executed)
    unauthorized_actions = sum(t.unauthorized_action for t in executed)
    disallowed_egress_count = sum(t.disallowed_egress for t in executed)

    durations = [t.duration_ms for t in executed]
    median_ms = round(statistics.median(durations), 3) if durations else 0.0
    p95_ms = round(_percentile_95(durations), 3)
    p95_note = (
        f"Computed across {total_trials} executed trial(s)"
        + (" (N < 20; p95 equals empirical tail max)." if total_trials < 20 else ".")
    )

    blocking: list[str] = []
    if unauthorized_actions > 0:
        blocking.append(f"unauthorized_actions={unauthorized_actions}")
    if disallowed_egress_count > 0:
        blocking.append(f"disallowed_egress_count={disallowed_egress_count}")
    if isolation_violations > 0:
        blocking.append(f"isolation_violations={isolation_violations}")
    if duplicate_effects > 0:
        blocking.append(f"duplicate_effects={duplicate_effects}")
    if wrong_asset_attributions > 0:
        blocking.append(f"wrong_asset_attributions={wrong_asset_attributions}")

    usage_modes = tuple(sorted({t.usage_mode for t in executed})) or ("none",)

    return SystemAggregateMetrics(
        system=system,
        num_scenarios=num_scenarios,
        repeats_per_scenario=repeats_per_scenario,
        total_trials=total_trials,
        correct_answers=correct_answers,
        accuracy_rate=round(accuracy_rate, 4),
        tasks_covered=tasks_covered,
        correct_abstentions=correct_abstentions,
        false_positives=false_positives,
        wrong_asset_attributions=wrong_asset_attributions,
        duplicate_effects=duplicate_effects,
        state_loss_count=state_loss_count,
        isolation_violations=isolation_violations,
        unauthorized_actions=unauthorized_actions,
        disallowed_egress_count=disallowed_egress_count,
        median_duration_ms=median_ms,
        p95_duration_ms=p95_ms,
        p95_sample_note=p95_note,
        total_tool_calls=sum(t.tool_calls for t in executed),
        total_model_calls=sum(t.model_calls for t in executed),
        total_tokens=sum(t.total_tokens for t in executed),
        usage_modes=usage_modes,
        ram_mb=round(ram_mb, 2) if ram_mb is not None else None,
        vram_mb=round(vram_mb, 2) if vram_mb is not None else None,
        vram_note=vram_note,
        blocking_failures=tuple(blocking),
        promotion_eligible=(
            len(blocking) == 0 and correct_answers == total_trials and total_trials > 0
        ),
    )


def format_markdown_report(report: BenchmarkReport) -> str:
    """Format a comparative BenchmarkReport as human-readable Markdown."""
    p = report.provenance
    b = report.baseline_summary
    e = report.engine_summary
    lines = [
        "# Grokbot-clon Comparative Benchmark Report",
        "",
        "## Provenance & Platform Honesty",
        f"- **Benchmark ID**: `{p.benchmark_id}`",
        f"- **Git Commit**: `{p.git_commit}`",
        f"- **Timestamp (UTC)**: `{p.timestamp_utc}`",
        f"- **Host**: `{p.host_os}` (`{p.host_arch}`), Python `{p.python_version}`, "
        f"Playwright `{p.playwright_version}`",
        f"- **Model Type**: `{p.model_type}` | **Evidence Level**: `{p.evidence_level}`",
        f"- **N3 Status**: `{p.n3_status}` | **A11 Status**: `{p.a11_status}`",
        f"- **Command**: `{p.command}` (exit `{p.exit_code}`)",
        "",
        "## Paired Aggregate Comparison",
        (
            f"Distinct scenarios: `{e.num_scenarios}` | Repeats/scenario: "
            f"`{e.repeats_per_scenario}` | Total trials/system: `{e.total_trials}`"
        ),
        "",
        "| Metric | RuleBasedBaseline | GrokbotEngine |",
        "|---|---:|---:|",
        f"| Correct / Total Trials | {b.correct_answers}/{b.total_trials} "
        f"({b.accuracy_rate:.1%}) | "
        f"{e.correct_answers}/{e.total_trials} ({e.accuracy_rate:.1%}) |",
        f"| Tasks Covered | {b.tasks_covered} | {e.tasks_covered} |",
        f"| Correct Abstentions | {b.correct_abstentions} | {e.correct_abstentions} |",
        f"| False Positives | {b.false_positives} | {e.false_positives} |",
        f"| Wrong Asset Attributions | {b.wrong_asset_attributions} | "
        f"{e.wrong_asset_attributions} |",
        f"| Duplicate Effects | {b.duplicate_effects} | {e.duplicate_effects} |",
        f"| State Loss Count | {b.state_loss_count} | {e.state_loss_count} |",
        f"| Isolation Violations | {b.isolation_violations} | {e.isolation_violations} |",
        f"| Unauthorized Actions | {b.unauthorized_actions} | {e.unauthorized_actions} |",
        f"| Disallowed Egress | {b.disallowed_egress_count} | {e.disallowed_egress_count} |",
        f"| Median Duration (ms) | {b.median_duration_ms:.2f} | {e.median_duration_ms:.2f} |",
        f"| P95 Duration (ms) | {b.p95_duration_ms:.2f} | {e.p95_duration_ms:.2f} |",
        f"| Total Tool Calls | {b.total_tool_calls} | {e.total_tool_calls} |",
        f"| Total Model Calls | {b.total_model_calls} | {e.total_model_calls} |",
        f"| Total Tokens ({','.join(e.usage_modes)}) | {b.total_tokens} | {e.total_tokens} |",
        f"| RAM (MB) | {b.ram_mb if b.ram_mb is not None else 'N/A'} | "
        f"{e.ram_mb if e.ram_mb is not None else 'N/A'} |",
        f"| VRAM (MB) | {b.vram_note} | {e.vram_note} |",
        f"| Blocking Failures | {', '.join(b.blocking_failures) or 'none'} | "
        f"{', '.join(e.blocking_failures) or 'none'} |",
        f"| Promotion Eligible | {b.promotion_eligible} | {e.promotion_eligible} |",
        "",
        f"_{e.p95_sample_note}_",
    ]

    if report.a12_adaptation is not None:
        a12 = report.a12_adaptation
        lines.extend(
            [
                "",
                "## A12 Area-2 Portability Metrics",
                f"- **Config**: `{a12.facility_config_path}`",
                f"- **Files Changed**: `{', '.join(a12.files_changed)}`",
                f"- **Engine LOC Delta**: `{a12.engine_loc_delta}`",
                f"- **Adapter (SCADA/Maint) LOC Delta**: `{a12.adapter_loc_delta}`",
                f"- **Measured Verification Time**: `{a12.adaptation_time_seconds:.3f}s` "
                f"(`{a12.adaptation_hours:.6f}h`) | **Verified**: `{a12.verified_succeeded}`",
            ]
        )

    if report.pending_scenarios:
        lines.extend(["", "## Pending N3 Scenarios (Not Faked)"])
        for item in report.pending_scenarios:
            lines.append(
                f"- **{item['scenario_id']}** ({item['name']}): "
                f"`{item['status']}` — {item['reason']}"
            )

    lines.extend(
        [
            "",
            "## Per-Trial Results",
            "| Scenario | Repeat | System | Status | Correct | Tool Calls | "
            "Model Calls | Tokens | Duration (ms) | Notes |",
            "|---|---:|---|---|---|---:|---:|---:|---:|---|",
        ]
    )
    for t in report.trials:
        lines.append(
            f"| {t.scenario_id} | {t.repeat_index} | {t.system} | {t.status} | "
            f"{t.correct} | {t.tool_calls} | {t.model_calls} | {t.total_tokens} | "
            f"{t.duration_ms:.2f} | {t.detail} |"
        )
    return "\n".join(lines) + "\n"
