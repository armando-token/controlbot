"""N2 integration tests for comparative benchmarks against live lab/ FastAPI servers."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from benchmarks.baseline import RuleBasedBaseline
from benchmarks.report import format_markdown_report
from benchmarks.runner import main as bench_main
from benchmarks.runner import run_benchmarks
from benchmarks.scenarios import get_runnable_scenarios


@pytest.mark.n2
async def test_rule_based_baseline_executes_genuinely_against_lab_apps() -> None:
    baseline = RuleBasedBaseline()
    scenarios = {s.scenario_id: s for s in get_runnable_scenarios(["A01", "A02", "A08", "A12"])}

    r_a01 = await baseline.run_scenario(scenarios["A01"])
    r_a02 = await baseline.run_scenario(scenarios["A02"])
    r_a08 = await baseline.run_scenario(scenarios["A08"])
    r_a12 = await baseline.run_scenario(scenarios["A12"])

    assert r_a01.correct is True
    assert r_a01.tool_calls == 3
    assert r_a02.correct is False
    assert r_a02.false_positive is True
    assert r_a02.wrong_asset_attribution is True
    assert r_a08.correct is False
    assert r_a08.duplicate_effects == 1
    assert r_a12.correct is False
    assert r_a12.status == "failed"


@pytest.mark.n2
async def test_runner_repeats_and_local_http_mock_mode() -> None:
    rep_emulated = await run_benchmarks(
        mode="emulated",
        repeats=2,
        scenarios=("A01", "A06", "A11"),
    )
    assert rep_emulated.provenance.model_type == "emulated"
    assert rep_emulated.provenance.a11_status == "PENDING_N3_LINUX_ENV"
    assert rep_emulated.engine_summary.num_scenarios == 2
    assert rep_emulated.engine_summary.repeats_per_scenario == 2
    assert rep_emulated.engine_summary.total_trials == 4
    assert rep_emulated.engine_summary.correct_answers == 4
    assert (
        rep_emulated.engine_summary.p95_duration_ms
        >= rep_emulated.engine_summary.median_duration_ms
    )

    rep_http = await run_benchmarks(
        mode="local_http",
        repeats=1,
        scenarios=("A01", "A06", "A11", "A12"),
    )
    assert rep_http.provenance.model_type == "local_http_mock"
    assert rep_http.provenance.a11_status == "PENDING_N3_LINUX_ENV"
    assert rep_http.engine_summary.num_scenarios == 3
    assert rep_http.engine_summary.correct_answers == 3
    assert rep_http.engine_summary.promotion_eligible is True
    assert rep_http.a12_adaptation is not None
    assert rep_http.a12_adaptation.verified_succeeded is True
    assert rep_http.a12_adaptation.engine_loc_delta == 0
    md = format_markdown_report(rep_http)
    assert "PENDING_N3_LINUX_ENV" in md
    assert "RuleBasedBaseline" in md
    assert "GrokbotEngine" in md


@pytest.mark.n2
def test_benchmark_cli_writes_to_output_dir_and_prints_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = bench_main(
        [
            "--mode",
            "emulated",
            "--scenarios",
            "A01,A11",
            "--output-dir",
            str(tmp_path),
            "--json",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["engine_summary"]["num_scenarios"] == 1
    assert parsed["engine_summary"]["correct_answers"] == 1
    assert parsed["provenance"]["a11_status"] == "PENDING_N3_LINUX_ENV"
    assert (tmp_path / "benchmark_report.json").exists()
    assert (tmp_path / "benchmark_report.md").exists()


@pytest.mark.n2
def test_benchmark_module_subprocess_smoke(tmp_path: Path) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.runner",
            "--scenarios",
            "A01,A11",
            "--output-dir",
            str(tmp_path),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["provenance"]["model_type"] == "emulated"
    assert payload["provenance"]["a11_status"] == "PENDING_N3_LINUX_ENV"
