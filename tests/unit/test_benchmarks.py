"""Deterministic N1 unit tests for the M5 comparative benchmark suite."""

from __future__ import annotations

import pytest
from benchmarks.report import (
    A12AdaptationMetrics,
    BenchmarkReport,
    ProvenanceMetadata,
    ScenarioTrialResult,
    aggregate_trials,
    format_markdown_report,
)
from benchmarks.runner import _trial_detail, run_benchmarks
from benchmarks.scenarios import get_all_scenarios, get_runnable_scenarios
from src.adapters import OriginNotAllowedError


@pytest.mark.n1
def test_benchmark_scenario_catalog_has_at_least_12_runnable_and_honest_a11() -> None:
    all_scenarios = get_all_scenarios()
    runnable = get_runnable_scenarios()
    assert len(all_scenarios) == 14
    assert len(runnable) >= 12
    assert len(runnable) == 13
    a11 = next(s for s in all_scenarios if s.scenario_id == "A11")
    assert a11.n3_pending is True
    assert a11.evidence_tier == "N3"
    assert a11.expected_status == "PENDING_N3_LINUX_ENV"
    assert "A11" not in {s.scenario_id for s in runnable}

    with pytest.raises(ValueError, match="Unknown scenario"):
        get_all_scenarios(["A99"])


@pytest.mark.n1
def test_aggregate_trials_blocking_gates_and_repeat_separation() -> None:
    trials = [
        ScenarioTrialResult(
            scenario_id="A01",
            scenario_name="Normal",
            system="grokbot_engine",
            repeat_index=1,
            evidence_tier="N2",
            status="succeeded",
            correct=True,
            duration_ms=10.0,
            tool_calls=3,
            model_calls=4,
            total_tokens=200,
        ),
        ScenarioTrialResult(
            scenario_id="A01",
            scenario_name="Normal",
            system="grokbot_engine",
            repeat_index=2,
            evidence_tier="N2",
            status="succeeded",
            correct=True,
            duration_ms=20.0,
            tool_calls=3,
            model_calls=4,
            total_tokens=200,
        ),
    ]
    agg = aggregate_trials(
        "GrokbotEngine",
        trials,
        num_scenarios=1,
        repeats_per_scenario=2,
        ram_mb=128.5,
        vram_mb=None,
        vram_note="N/A (emulated)",
    )
    assert agg.num_scenarios == 1
    assert agg.repeats_per_scenario == 2
    assert agg.total_trials == 2
    assert agg.tasks_covered == 1
    assert agg.promotion_eligible is True
    assert agg.median_duration_ms == 15.0
    assert agg.p95_duration_ms == 20.0
    assert "N < 20" in agg.p95_sample_note

    bad_trials = [
        ScenarioTrialResult(
            scenario_id="A08",
            scenario_name="Effect",
            system="baseline",
            repeat_index=1,
            evidence_tier="N2",
            status="succeeded",
            correct=False,
            duplicate_effects=1,
            isolation_violation=1,
            wrong_asset_attribution=True,
            unauthorized_action=1,
            disallowed_egress=1,
            duration_ms=5.0,
        )
    ]
    bad_agg = aggregate_trials(
        "RuleBasedBaseline",
        bad_trials,
        num_scenarios=1,
        repeats_per_scenario=1,
        ram_mb=100.0,
        vram_mb=None,
        vram_note="N/A (baseline)",
    )
    assert bad_agg.promotion_eligible is False
    assert "unauthorized_actions=1" in bad_agg.blocking_failures
    assert "disallowed_egress_count=1" in bad_agg.blocking_failures
    assert "duplicate_effects=1" in bad_agg.blocking_failures
    assert "isolation_violations=1" in bad_agg.blocking_failures
    assert "wrong_asset_attributions=1" in bad_agg.blocking_failures

    report = BenchmarkReport(
        provenance=ProvenanceMetadata(
            benchmark_id="bench-test",
            git_commit="abc123",
            timestamp_utc="2026-11-25T12:00:00Z",
            host_os="Darwin",
            host_arch="arm64",
            python_version="3.12.15",
            playwright_version="1.64.0",
            model_type="emulated",
            evidence_level="N1/N2",
            n3_status="PENDING_N3_LINUX_ENV",
            a11_status="PENDING_N3_LINUX_ENV",
            command="python -m benchmarks.runner",
            exit_code=0,
        ),
        baseline_summary=bad_agg,
        engine_summary=agg,
        a12_adaptation=A12AdaptationMetrics(
            facility_config_path="lab/configs/facility_b.json",
            files_changed=("lab/configs/facility_b.json",),
            engine_loc_delta=0,
            adapter_loc_delta=0,
            adaptation_time_seconds=1.25,
            adaptation_hours=0.000347,
            verified_succeeded=True,
        ),
        pending_scenarios=(
            {
                "scenario_id": "A11",
                "name": "Linux Network Isolation",
                "status": "PENDING_N3_LINUX_ENV",
                "reason": "Linux required",
            },
        ),
        trials=(*trials, *bad_trials),
    )
    md = format_markdown_report(report)
    assert "PENDING_N3_LINUX_ENV" in md
    assert "RuleBasedBaseline" in md
    assert "GrokbotEngine" in md
    assert "Engine LOC Delta" in md
    assert "Measured Verification Time" in md


@pytest.mark.n1
async def test_local_http_mode_blocks_external_origin_without_fallback() -> None:
    with pytest.raises(OriginNotAllowedError):
        await run_benchmarks(
            mode="local_http",
            scenarios=("A01",),
            llm_origin="https://api.openai.com",
        )


@pytest.mark.n1
async def test_failed_trial_detail_reflects_actual_failure_without_success_string() -> None:
    assert _trial_detail(True, "ok msg", status="succeeded") == "ok msg"
    fail_msg = _trial_detail(
        False,
        "Cross-source verified ALM-3401 and WO-3408.",
        status="failed",
        answer="Local HTTP model unreachable | detail",
        extra="paused_status=failed",
    )
    assert "Trial failed (status=failed)" in fail_msg
    assert "paused_status=failed" in fail_msg
    assert "Cross-source verified" not in fail_msg
    assert "|" not in fail_msg

    # Unreachable loopback LLM fails closed and records failure reason in trial.detail
    report = await run_benchmarks(
        mode="local_http",
        scenarios=("A06",),
        llm_origin="http://127.0.0.1:9",
    )
    engine_trials = [t for t in report.trials if t.system == "grokbot_engine"]
    assert len(engine_trials) == 1
    trial = engine_trials[0]
    assert trial.status == "failed"
    assert trial.correct is False
    assert "Trial failed (status=failed)" in trial.detail
    assert "Halted identical_repeat" not in trial.detail
    assert report.engine_summary.promotion_eligible is False
    assert report.provenance.exit_code == 1
