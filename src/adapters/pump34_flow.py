"""Concurrent cross-source Pump 34 adapter workflow helper."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime

from src.adapters._common import CredentialProvider, SourceUnavailableError
from src.adapters.config import FacilityConfig
from src.adapters.maintenance import MaintenanceAdapter
from src.adapters.scada import ScadaAdapter
from src.adapters.sessions import AuthExpiredError, SessionManager
from src.adapters.verifier import Verifier
from src.contracts.models import ActionReceipt, ExecutionMetrics, Observation, Result, TaskSpec


async def run_pump34_flow(
    *,
    task: TaskSpec,
    config: FacilityConfig,
    session_manager: SessionManager,
    credential_provider: CredentialProvider | None = None,
    run_id: str = "run-pump34",
    target_asset_query: str = "bomba 34",
    target_area: str | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    reference_time: datetime | None = None,
) -> tuple[Result, tuple[ActionReceipt, ...]]:
    """Query SCADA and Maintenance concurrently in isolated sessions and verify results."""
    started = time.perf_counter()
    scada_adapter = ScadaAdapter(session_manager, credential_provider)
    maint_adapter = MaintenanceAdapter(session_manager, credential_provider)
    verifier = Verifier()

    async def _fetch_scada() -> tuple[list[Observation], list[ActionReceipt]]:
        alarms_obs, alarms_rcpt = await scada_adapter.read_alarms(
            task=task,
            config=config,
            run_id=run_id,
            step_id="step-scada-alarms",
            operation_key=f"{run_id}-scada-alarms",
            asset_query=target_asset_query,
            area=target_area,
        )
        readings_obs, readings_rcpt = await scada_adapter.read_readings(
            task=task,
            config=config,
            run_id=run_id,
            step_id="step-scada-readings",
            operation_key=f"{run_id}-scada-readings",
            asset_query=target_asset_query,
            area=target_area,
        )
        return [*alarms_obs, *readings_obs], [alarms_rcpt, readings_rcpt]

    async def _fetch_maint() -> tuple[list[Observation], list[ActionReceipt]]:
        wo_obs, wo_rcpt = await maint_adapter.read_work_orders(
            task=task,
            config=config,
            run_id=run_id,
            step_id="step-maint-work-orders",
            operation_key=f"{run_id}-maint-wo",
            asset_query=target_asset_query,
            area=target_area,
        )
        return list(wo_obs), [wo_rcpt]

    scada_res, maint_res = await asyncio.gather(
        _fetch_scada(),
        _fetch_maint(),
        return_exceptions=True,
    )

    observations: list[Observation] = []
    receipts: list[ActionReceipt] = []
    source_errors: dict[str, str] = {}

    for source_name, outcome in (("scada", scada_res), ("maintenance", maint_res)):
        if isinstance(outcome, BaseException):
            if isinstance(outcome, AuthExpiredError):
                source_errors[source_name] = f"auth_expired: {outcome}"
            elif isinstance(outcome, SourceUnavailableError):
                source_errors[source_name] = f"source_unavailable: {outcome}"
            else:
                source_errors[source_name] = f"{type(outcome).__name__}: {outcome}"
        else:
            obs_list, rcpt_list = outcome
            observations.extend(obs_list)
            receipts.extend(rcpt_list)

    wall_seconds = time.perf_counter() - started
    metrics = ExecutionMetrics(
        tool_calls=len(receipts) + len(source_errors),
        model_calls=0,
        wall_seconds=wall_seconds,
    )
    result = verifier.verify_and_synthesize(
        task=task,
        config=config,
        observations=observations,
        source_errors=source_errors,
        run_id=run_id,
        target_asset_query=target_asset_query,
        target_area=target_area,
        window_start=window_start,
        window_end=window_end,
        reference_time=reference_time,
        metrics=metrics,
    )
    return result, tuple(receipts)
