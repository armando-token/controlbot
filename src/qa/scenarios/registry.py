"""Scenario registry and dispatch entrypoint for CB-00..CB-13."""

from __future__ import annotations

import contextlib
import json
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from src.n3_probe import N3ProbeReport
from src.qa.isolation import IsolationBoundaryError
from src.qa.models import CampaignState, ReferenceBehaviorCard, RunRecord
from src.qa.scenarios import (
    cb_00,
    cb_01,
    cb_02,
    cb_03,
    cb_04,
    cb_05,
    cb_06,
    cb_07,
    cb_08,
    cb_09,
    cb_10,
    cb_11,
    cb_12,
    cb_13,
)
from src.qa.scenarios._common import (
    ScenarioContext,
    build_blocked_run_record,
    finalize_scenario,
    probe_target_capabilities,
)
from src.qa.ux_metrics import redact_payload_m3

IMPLEMENTED_CASES: frozenset[str] = frozenset({f"CB-{i:02d}" for i in range(14)})

ScenarioRunner = Callable[[ScenarioContext], tuple[RunRecord, list[dict[str, Any]]]]

SCENARIO_RUNNERS: dict[str, ScenarioRunner] = {
    "CB-00": cb_00.run,
    "CB-01": cb_01.run,
    "CB-02": cb_02.run,
    "CB-03": cb_03.run,
    "CB-04": cb_04.run,
    "CB-05": cb_05.run,
    "CB-06": cb_06.run,
    "CB-07": cb_07.run,
    "CB-08": cb_08.run,
    "CB-09": cb_09.run,
    "CB-10": cb_10.run,
    "CB-11": cb_11.run,
    "CB-12": cb_12.run,
    "CB-13": cb_13.run,
}


def _read_valve_fixture_version(campaign_dir: Path) -> str:
    fixture_path = campaign_dir / "fixtures" / "cb_valve_104.json"
    if fixture_path.is_file():
        with contextlib.suppress(json.JSONDecodeError, OSError):
            data = json.loads(fixture_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("fixture_version"):
                return str(data["fixture_version"])
    return "1.0"


def run_scenario(
    *,
    case_id: str,
    campaign_dir: Path,
    state: CampaignState,
    target_url: str | None,
    token: str | None = None,
    repo_root: Path | None = None,
    extra_artifacts: Sequence[str] = (),
    reference_cards: Sequence[ReferenceBehaviorCard] = (),
    n3_report: N3ProbeReport | None = None,
) -> tuple[RunRecord, list[dict[str, Any]]] | None:
    """Dispatch `case_id` to its CB-00..CB-13 runner, returning `None` if unknown."""
    normalized = case_id.strip().upper()
    if normalized not in SCENARIO_RUNNERS:
        return None

    if not target_url:
        if normalized == "CB-13":
            return cb_13.run_without_target(
                campaign_dir=campaign_dir,
                state=state,
                repo_root=repo_root,
                extra_artifacts=extra_artifacts,
                reference_cards=reference_cards,
                n3_report=n3_report,
            )
        fixture_ver = _read_valve_fixture_version(campaign_dir) if normalized == "CB-02" else "1.0"
        return build_blocked_run_record(
            case_id=normalized,
            campaign_dir=campaign_dir,
            state=state,
            blocked_reason=f"{normalized} requires --target-url or baseline target_url.",
            repo_root=repo_root,
            fixture_version=fixture_ver,
            assertions={"target_url_configured": False, "scenario_runner_available": True},
            extra_artifacts=extra_artifacts,
            subsystem="scenario",
        )

    caps = probe_target_capabilities(target_url, token=token)
    if not caps.health_ok:
        fixture_ver = _read_valve_fixture_version(campaign_dir) if normalized == "CB-02" else "1.0"
        return build_blocked_run_record(
            case_id=normalized,
            campaign_dir=campaign_dir,
            state=state,
            blocked_reason=f"{normalized} target {target_url} failed /health probe.",
            repo_root=repo_root,
            fixture_version=fixture_ver,
            assertions={"target_reachable": False, "scenario_runner_available": True},
            extra_artifacts=extra_artifacts,
            subsystem="web",
        )

    if state.lane == "agy_real" and not caps.is_live_agent_target:
        fixture_ver = _read_valve_fixture_version(campaign_dir) if normalized == "CB-02" else "1.0"
        return build_blocked_run_record(
            case_id=normalized,
            campaign_dir=campaign_dir,
            state=state,
            blocked_reason="agy_real lane requires available agy or local_http backend",
            repo_root=repo_root,
            fixture_version=fixture_ver,
            assertions={"agy_real_backend_available": False, "scenario_runner_available": True},
            extra_artifacts=extra_artifacts,
            subsystem="agy",
        )

    ctx = ScenarioContext.create(
        case_id=normalized,
        campaign_dir=campaign_dir,
        state=state,
        target_url=target_url,
        token=token,
        repo_root=repo_root,
        caps=caps,
        extra_artifacts=extra_artifacts,
        reference_cards=reference_cards,
    )
    if normalized == "CB-02":
        ctx.fixture_version = _read_valve_fixture_version(campaign_dir)
    try:
        if normalized == "CB-13":
            return cb_13.run(ctx, n3_report=n3_report)
        return SCENARIO_RUNNERS[normalized](ctx)
    except IsolationBoundaryError:
        raise
    except Exception as exc:
        redacted_msg = str(redact_payload_m3(f"{type(exc).__name__}: {exc}"))
        redacted_tb = str(redact_payload_m3(traceback.format_exc()[-1200:]))
        ctx.assertions["scenario_execution_completed"] = False
        ctx.error_notes.append(f"Scenario {normalized} aborted: {redacted_msg}")
        ctx.evidence["exception_type"] = type(exc).__name__
        ctx.evidence["exception_summary"] = redacted_msg
        ctx.evidence["exception_traceback"] = redacted_tb
        ctx.error_actionable = False
        try:
            return finalize_scenario(ctx)
        except Exception:
            assertions = {**ctx.assertions, "scenario_execution_completed": False}
            return build_blocked_run_record(
                case_id=normalized,
                campaign_dir=campaign_dir,
                state=state,
                blocked_reason=f"Scenario {normalized} crashed: {redacted_msg}",
                repo_root=repo_root,
                fixture_version=ctx.fixture_version,
                assertions=assertions,
                extra_artifacts=extra_artifacts,
                subsystem=ctx.subsystem,
            )


__all__ = [
    "IMPLEMENTED_CASES",
    "SCENARIO_RUNNERS",
    "run_scenario",
]
