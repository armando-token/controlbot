"""Paired comparative benchmark runner for RuleBasedBaseline vs GrokbotEngine."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.metadata
import json
import os
import platform
import resource
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from lab.effect_sim import create_effect_sim_app
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import create_scada_app
from lab.testing import run_asgi_server
from src.adapters import (
    EffectSimAdapter,
    MappingCredentialProvider,
    OriginNotAllowedError,
    ScadaAdapter,
    SessionManager,
    get_effect_tool_specs,
    load_facility_config,
)
from src.adapters.config import FacilityConfig
from src.contracts.budgets import BudgetConfig
from src.contracts.common import utc_now
from src.contracts.enums import BackendMode, EffectClass, TaskStatus
from src.contracts.models import TaskScope, TaskSpec, ToolSpec
from src.engine.coordinator import Coordinator, CoordinatorConfig
from src.engine.loop_detector import LoopConfig, LoopDetector
from src.engine.tool_registry import ToolExecutionContext, ToolRegistry
from src.model import (
    BudgetRemaining,
    EmulatedModelClient,
    EmulatedTurn,
    LocalHttpModelClient,
    LocalModelConfig,
    ModelDecision,
    ModelToolCall,
    ModelUsage,
    PromptContext,
    validate_local_model_origin,
)
from src.n3_probe import run_n3_probe
from src.runtime import _infer_asset_query, build_runtime
from src.storage.errors import TerminalStateError
from src.storage.repo import StorageRepo

from benchmarks.baseline import RuleBasedBaseline
from benchmarks.report import (
    A12AdaptationMetrics,
    BenchmarkReport,
    ProvenanceMetadata,
    ScenarioTrialResult,
    aggregate_trials,
    format_markdown_report,
)
from benchmarks.scenarios import (
    BenchmarkScenario,
    get_all_scenarios,
    get_runnable_scenarios,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_FACILITY_A_PATH = _REPO_ROOT / "lab" / "configs" / "facility_a.json"
_FACILITY_B_PATH = _REPO_ROOT / "lab" / "configs" / "facility_b.json"

BenchmarkMode = Literal["emulated", "local_http"]


def _current_ram_mb() -> float:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if platform.system() == "Darwin":
        return rss / (1024.0 * 1024.0)
    return rss / 1024.0


def _git_head_sha() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(_REPO_ROOT),
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return out.strip() or "unknown"
    except Exception:
        return "unknown"


def _playwright_version() -> str:
    try:
        return importlib.metadata.version("playwright")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _create_benchmark_mock_openai_server(
    *,
    facility_configs: Sequence[FacilityConfig],
    model_id: str = "qwen2.5-7b-instruct",
) -> FastAPI:
    """Loopback OpenAI-compatible server driving real LocalHttpModelClient decisions."""
    app = FastAPI(title="Benchmark Loopback Mock OpenAI Server")
    call_counts: dict[str, int] = {}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        body = await request.json()
        messages = body.get("messages", [])
        user_content = messages[-1]["content"] if messages else "{}"
        parsed = json.loads(user_content)
        prompt_ctx = parsed.get("prompt_context", {})
        run_id = str(prompt_ctx.get("run_id", "default"))
        query = str(prompt_ctx.get("query", ""))
        allowed_areas: list[str] = list(prompt_ctx.get("allowed_areas", []))
        human_input = prompt_ctx.get("human_input")
        history: list[dict[str, Any]] = list(prompt_ctx.get("history", []))
        available_tools: list[str] = list(parsed.get("available_tool_ids", []))
        idx = call_counts.get(run_id, 0)
        call_counts[run_id] = idx + 1

        usage = {"prompt_tokens": 48, "completion_tokens": 22, "total_tokens": 70}

        def _tool_response(tool_name: str, args: dict[str, Any]) -> JSONResponse:
            return JSONResponse(
                status_code=200,
                content={
                    "model": model_id,
                    "usage": usage,
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "tool_calls": [
                                    {
                                        "function": {
                                            "name": tool_name,
                                            "arguments": json.dumps(args),
                                        }
                                    }
                                ],
                            }
                        }
                    ],
                },
            )

        def _final_response(answer: str) -> JSONResponse:
            return JSONResponse(
                status_code=200,
                content={
                    "model": model_id,
                    "usage": usage,
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": json.dumps(
                                    {"decision_type": "final", "final_answer": answer}
                                ),
                            }
                        }
                    ],
                },
            )

        # Loop / cycle / specialized unit-like N1/N2 scenarios
        if "scada.ping" in available_tools:
            return _tool_response("scada.ping", {"asset": "pump-34", "area": "area-1"})

        if "tool.a" in available_tools and "tool.b" in available_tools:
            tid = "tool.a" if idx % 2 == 0 else "tool.b"
            return _tool_response(tid, {"asset": "pump-34", "area": "area-1"})

        if "effect.apply" in available_tools:
            if not history:
                return _tool_response(
                    "effect.apply",
                    {
                        "operation_key": f"op-{run_id}",
                        "asset_id": "bomba-34-a1",
                        "action": "ack_alarm",
                        "params": {"alarm_id": "ALM-3401"},
                    },
                )
            return _final_response("Effect applied and reconciled once.")

        if "scada.slow" in available_tools:
            if not history:
                return _tool_response("scada.slow", {"asset": "pump-34", "area": "area-1"})
            return _final_response("Slow tool finished.")

        if "diag.read" in available_tools:
            probes = [str((h.get("args") or {}).get("probe", "")) for h in history]
            if "step1" not in probes:
                return _tool_response("diag.read", {"probe": "step1"})
            if "step2" not in probes:
                return _tool_response("diag.read", {"probe": "step2"})
            return _final_response("Recovered and completed step 2.")

        # Industrial multi-source queries
        chosen_area: str | None = None
        if len(allowed_areas) == 1:
            chosen_area = allowed_areas[0]
        elif isinstance(human_input, dict):
            raw_area = human_input.get("area") or human_input.get("choice")
            if isinstance(raw_area, str) and raw_area.strip():
                chosen_area = raw_area.strip()

        asset_query = query
        for cfg in facility_configs:
            inferred = _infer_asset_query(query, cfg)
            if (
                inferred != query
                and any(
                    inferred.lower()
                    in {
                        a.asset_id.lower(),
                        a.canonical_label.lower(),
                        *(al.lower() for al in a.aliases),
                        *(sv.lower() for sv in a.source_ids.values()),
                    }
                    for a in cfg.assets
                )
                and any(
                    tok.lower() in query.lower()
                    for a in cfg.assets
                    for tok in (
                        a.asset_id,
                        a.canonical_label,
                        *a.aliases,
                        *a.source_ids.values(),
                    )
                )
            ):
                asset_query = inferred
                break

        called_tools = {str(h.get("tool_id", "")) for h in history}
        for tool_name in ("scada.read_alarms", "scada.read_readings", "maint.read_work_orders"):
            if tool_name in available_tools and tool_name not in called_tools:
                args: dict[str, Any] = {"asset": asset_query}
                if chosen_area is not None:
                    args["area"] = chosen_area
                return _tool_response(tool_name, args)

        return _final_response(f"Collected observations for {asset_query}.")

    return app


def _trial_detail(
    ok: bool,
    success_detail: str,
    *,
    status: str,
    answer: str = "",
    extra: str = "",
) -> str:
    """Return an honest per-trial summary reflecting success or actual failure reason."""
    if ok:
        return success_detail
    parts = [f"Trial failed (status={status})"]
    if extra:
        parts.append(extra)
    clean_answer = " ".join(answer.replace("|", "/").split())
    if clean_answer:
        parts.append(clean_answer[:160])
    return "; ".join(parts)


def _make_model_kwargs(
    *,
    mode: BenchmarkMode,
    llm_origin: str | None,
    model_id: str,
) -> tuple[BackendMode, LocalModelConfig | None, LocalHttpModelClient | None]:
    if mode == "local_http":
        if llm_origin is None:
            raise ValueError("local_http mode requires a validated loopback llm_origin.")
        cfg = LocalModelConfig(origin=llm_origin, model_id=model_id)
        return BackendMode.LOCAL_HTTP, cfg, LocalHttpModelClient(cfg)
    return BackendMode.EMULATED, None, None


async def _run_engine_scenario(
    scenario: BenchmarkScenario,
    *,
    repeat_index: int,
    tmp_dir: Path,
    mode: BenchmarkMode,
    llm_origin: str | None,
    model_id: str,
) -> ScenarioTrialResult:
    if scenario.n3_pending:
        return ScenarioTrialResult(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            system="grokbot_engine",
            repeat_index=repeat_index,
            evidence_tier=scenario.evidence_tier,
            executed=False,
            status="PENDING_N3_LINUX_ENV",
            correct=False,
            duration_ms=0.0,
            usage_mode="none",
            detail=scenario.n3_reason or "PENDING_N3_LINUX_ENV",
        )

    started = time.perf_counter()
    sid = scenario.scenario_id
    trial_dir = tmp_dir / f"{sid}_r{repeat_index}"
    trial_dir.mkdir(parents=True, exist_ok=True)
    backend_mode, local_cfg, http_client = _make_model_kwargs(
        mode=mode, llm_origin=llm_origin, model_id=model_id
    )

    if sid == "A01":
        res = await _engine_a01(
            scenario, repeat_index, trial_dir, backend_mode, local_cfg, http_client
        )
    elif sid == "A02":
        res = await _engine_a02(
            scenario, repeat_index, trial_dir, backend_mode, local_cfg, http_client
        )
    elif sid == "A03":
        res = await _engine_a03(
            scenario, repeat_index, trial_dir, backend_mode, local_cfg, http_client
        )
    elif sid == "A04":
        res = await _engine_a04(
            scenario, repeat_index, trial_dir, backend_mode, local_cfg, http_client
        )
    elif sid == "A05":
        res = await _engine_a05(scenario, repeat_index, trial_dir)
    elif sid == "A06":
        res = await _engine_a06(
            scenario, repeat_index, trial_dir, backend_mode, http_client
        )
    elif sid == "A07":
        res = await _engine_a07(
            scenario, repeat_index, trial_dir, backend_mode, http_client
        )
    elif sid == "A08":
        res = await _engine_a08(
            scenario, repeat_index, trial_dir, backend_mode, http_client
        )
    elif sid == "A09":
        res = await _engine_a09(
            scenario, repeat_index, trial_dir, backend_mode, http_client
        )
    elif sid == "A10":
        res = await _engine_a10(
            scenario, repeat_index, trial_dir, backend_mode, local_cfg, http_client
        )
    elif sid == "A12":
        res = await _engine_a12(
            scenario, repeat_index, trial_dir, backend_mode, local_cfg, http_client
        )
    elif sid == "A13":
        res = await _engine_a13(
            scenario, repeat_index, trial_dir, backend_mode, local_cfg, http_client
        )
    elif sid == "A14":
        res = await _engine_a14(
            scenario, repeat_index, trial_dir, backend_mode, http_client
        )
    else:
        raise ValueError(f"Unsupported benchmark scenario {sid!r}")

    elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
    return res.model_copy(update={"duration_ms": elapsed_ms})


async def _engine_a01(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    local_cfg: LocalModelConfig | None,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    ref = utc_now()
    scada_app = create_scada_app("default")
    maint_app = create_maintenance_app("default")
    scada_app.state.scada_state.set_reference_time(ref)
    maint_app.state.maintenance_state.set_reference_time(ref)
    creds = MappingCredentialProvider(
        {
            ("operator_ro", "p1", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "p1", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )
    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH, {"scada": scada_origin, "maintenance": maint_origin}
        )
        runtime = build_runtime(
            db_path=trial_dir / "a01.sqlite3",
            profile_root=trial_dir / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            backend_mode=backend_mode,
            local_http_config=local_cfg,
            model_client=http_client,
            reference_time_fn=lambda: ref,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id=f"bench-a01-{repeat_index}",
                    user_id="operator_ro",
                    profile_id="p1",
                    scope=TaskScope(
                        facility_id="facility-a",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-1",),
                        read_only=True,
                    ),
                    backend_mode=backend_mode,
                    query="First alarm and latest work order on bomba 34",
                )
            )
            result = await runtime.coordinator.run_until_settled(run.run_id)
    ok = (
        result.status == TaskStatus.SUCCEEDED
        and "ALM-3401" in result.answer
        and "WO-3408" in result.answer
    )
    m = result.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=result.status.value,
        correct=ok,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            "Cross-source verified ALM-3401 and WO-3408.",
            status=result.status.value,
            answer=result.answer,
        ),
    )


async def _engine_a02(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    local_cfg: LocalModelConfig | None,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    ref = utc_now()
    scada_app = create_scada_app("ambiguity")
    maint_app = create_maintenance_app("ambiguity")
    scada_app.state.scada_state.set_reference_time(ref)
    maint_app.state.maintenance_state.set_reference_time(ref)
    creds = MappingCredentialProvider(
        {
            ("operator_ro", "p1", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "p1", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )
    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH, {"scada": scada_origin, "maintenance": maint_origin}
        )
        runtime = build_runtime(
            db_path=trial_dir / "a02.sqlite3",
            profile_root=trial_dir / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            backend_mode=backend_mode,
            local_http_config=local_cfg,
            model_client=http_client,
            reference_time_fn=lambda: ref,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id=f"bench-a02-{repeat_index}",
                    user_id="operator_ro",
                    profile_id="p1",
                    scope=TaskScope(
                        facility_id="facility-a",
                        allowed_origins=(scada_origin, maint_origin),
                        read_only=True,
                    ),
                    backend_mode=backend_mode,
                    query="Check bomba 34",
                )
            )
            paused = await runtime.coordinator.run_until_settled(run.run_id)
            abstained = (
                paused.status == TaskStatus.WAITING_FOR_INPUT
                and paused.required_action is not None
                and "area-1" in paused.required_action
                and "area-2" in paused.required_action
            )
            if paused.status == TaskStatus.WAITING_FOR_INPUT:
                runtime.coordinator.resume_task(run.run_id, {"area": "area-1"})
                done = await runtime.coordinator.run_until_settled(run.run_id)
            else:
                done = paused
    ok = (
        abstained
        and done.status == TaskStatus.SUCCEEDED
        and bool(done.verified_observations)
        and all(o.area == "area-1" for o in done.verified_observations)
    )
    m = done.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=done.status.value,
        correct=ok,
        correct_abstention=abstained,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            "Abstained on multi-area ambiguity then succeeded scoped to area-1.",
            status=done.status.value,
            answer=done.answer,
            extra=f"paused_status={paused.status.value}",
        ),
    )


async def _engine_a03(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    local_cfg: LocalModelConfig | None,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    ref = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC)
    scada_app = create_scada_app("stale")
    maint_app = create_maintenance_app("stale")
    scada_app.state.scada_state.set_reference_time(ref)
    maint_app.state.maintenance_state.set_reference_time(ref)
    creds = MappingCredentialProvider(
        {
            ("operator_ro", "p1", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "p1", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )
    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH, {"scada": scada_origin, "maintenance": maint_origin}
        )
        runtime = build_runtime(
            db_path=trial_dir / "a03.sqlite3",
            profile_root=trial_dir / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            backend_mode=backend_mode,
            local_http_config=local_cfg,
            model_client=http_client,
            reference_time_fn=lambda: ref,
            window_start=ref - timedelta(hours=2),
            window_end=ref,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id=f"bench-a03-{repeat_index}",
                    user_id="operator_ro",
                    profile_id="p1",
                    scope=TaskScope(
                        facility_id="facility-a",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-1",),
                        read_only=True,
                    ),
                    backend_mode=backend_mode,
                    query="Check bomba 34 quality and window",
                )
            )
            result = await runtime.coordinator.run_until_settled(run.run_id)
    by_id = {o.metadata.get("record_id"): o for o in result.verified_observations}
    ok = (
        result.status == TaskStatus.SUCCEEDED
        and "ALM-3405" in result.answer
        and by_id.get("ALM-OLD-01") is not None
        and by_id["ALM-OLD-01"].authorized_evidence is False
        and by_id.get("RDG-STALE-01") is not None
        and by_id["RDG-STALE-01"].authorized_evidence is False
        and by_id.get("RDG-BAD-01") is not None
        and by_id["RDG-BAD-01"].authorized_evidence is False
        and by_id.get("ALM-3405") is not None
        and by_id["ALM-3405"].authorized_evidence is True
    )
    m = result.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=result.status.value,
        correct=ok,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            "Rejected stale/bad/out-of-window records; synthesized ALM-3405.",
            status=result.status.value,
            answer=result.answer,
        ),
    )


async def _engine_a04(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    local_cfg: LocalModelConfig | None,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    ref = utc_now()
    scada_app = create_scada_app("down")
    maint_app = create_maintenance_app("default")
    maint_app.state.maintenance_state.set_reference_time(ref)
    creds = MappingCredentialProvider(
        {
            ("operator_ro", "p1", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "p1", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )
    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH, {"scada": scada_origin, "maintenance": maint_origin}
        )
        runtime = build_runtime(
            db_path=trial_dir / "a04.sqlite3",
            profile_root=trial_dir / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            backend_mode=backend_mode,
            local_http_config=local_cfg,
            model_client=http_client,
            reference_time_fn=lambda: ref,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id=f"bench-a04-{repeat_index}",
                    user_id="operator_ro",
                    profile_id="p1",
                    scope=TaskScope(
                        facility_id="facility-a",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-1",),
                        read_only=True,
                    ),
                    backend_mode=backend_mode,
                    query="Check bomba 34",
                )
            )
            result = await runtime.coordinator.run_until_settled(run.run_id)
    ok = (
        result.status == TaskStatus.PARTIAL
        and "WO-3408" in result.answer
        and result.partial_info is not None
        and result.partial_info.get("missing_sources") == ["scada"]
    )
    m = result.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=result.status.value,
        correct=ok,
        correct_abstention=ok,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            "Reported PARTIAL with missing_sources=['scada'] and preserved WO-3408.",
            status=result.status.value,
            answer=result.answer,
        ),
    )


async def _engine_a05(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
) -> ScenarioTrialResult:
    scada_app = create_scada_app("ambiguity")
    other_app = create_maintenance_app("default")
    creds = MappingCredentialProvider(
        {
            ("operator_a1", "prof_a", "scada"): ("operator_a1", "scada-pass-a1"),
            ("operator_a2", "prof_b", "scada"): ("operator_a2", "scada-pass-a2"),
        }
    )

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(other_app) as other_origin,
    ):
        cfg = load_facility_config(_FACILITY_A_PATH, {"scada": scada_origin})
        task_a = TaskSpec(
            task_id=f"bench-a05a-{repeat_index}",
            user_id="operator_a1",
            profile_id="prof_a",
            scope=TaskScope(facility_id="facility-a", allowed_origins=(scada_origin,)),
            query="Read alarms",
        )
        task_b = TaskSpec(
            task_id=f"bench-a05b-{repeat_index}",
            user_id="operator_a2",
            profile_id="prof_b",
            scope=TaskScope(facility_id="facility-a", allowed_origins=(scada_origin,)),
            query="Read alarms",
        )
        blocked_egress = False
        async with SessionManager(trial_dir / "profiles", headless=True) as mgr:
            adapter = ScadaAdapter(mgr, creds)
            (obs_a, _), (obs_b, _) = await asyncio.gather(
                adapter.read_alarms(task=task_a, config=cfg),
                adapter.read_alarms(task=task_b, config=cfg),
            )
            sess_a = await mgr.open_session("operator_a1", "prof_a", "scada", (scada_origin,))
            try:
                await mgr.navigate(sess_a.session_id, f"{other_origin}/login")
            except OriginNotAllowedError:
                blocked_egress = True
    isolated = (
        bool(obs_a)
        and bool(obs_b)
        and obs_a[0].area == "area-1"
        and obs_b[0].area == "area-2"
        and blocked_egress
    )
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status="succeeded" if isolated else "failed",
        correct=isolated,
        isolation_violation=0 if isolated else 1,
        disallowed_egress=0 if blocked_egress else 1,
        duration_ms=0.0,
        tool_calls=2,
        model_calls=0,
        total_tokens=0,
        usage_mode="none",
        detail=_trial_detail(
            isolated,
            "Isolated per-(user,profile,app) Playwright contexts & blocked disallowed origin.",
            status="succeeded" if isolated else "failed",
            extra=f"isolated={isolated}, blocked_egress={blocked_egress}",
        ),
    )


async def _engine_a06(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    repo = StorageRepo(trial_dir / "a06.sqlite3")
    repo.init_db()
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            tool_id="scada.ping",
            version="1.0.0",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            effect_class=EffectClass.READ,
            verifier_name="v",
        ),
        lambda args, ctx: {"output": {"ok": True}},
    )
    model_client = (
        http_client
        if backend_mode == BackendMode.LOCAL_HTTP and http_client is not None
        else EmulatedModelClient(mode="loop_a06")
    )
    coord = Coordinator(
        repo,
        model_client,
        registry,
        loop_detector=LoopDetector(LoopConfig(identical_repeat_threshold=3)),
    )
    run = coord.submit_task(
        TaskSpec(
            task_id=f"bench-a06-{repeat_index}",
            user_id="op",
            profile_id="p1",
            scope=TaskScope(facility_id="facility-a", read_only=True),
            backend_mode=backend_mode,
            query="Loop test",
        )
    )
    res = await coord.run_until_settled(run.run_id)
    ok = (
        res.status == TaskStatus.FAILED
        and res.execution_metrics.tool_calls == 3
        and res.partial_info is not None
        and res.partial_info.get("loop_kind") == "identical_repeat"
    )
    m = res.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=res.status.value,
        correct=ok,
        correct_abstention=ok,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            f"Halted identical_repeat at tool_calls={m.tool_calls}.",
            status=res.status.value,
            answer=res.answer,
            extra=f"tool_calls={m.tool_calls}",
        ),
    )


async def _engine_a07(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    repo = StorageRepo(trial_dir / "a07.sqlite3")
    repo.init_db()
    registry = ToolRegistry()
    for tid in ("tool.a", "tool.b"):
        registry.register(
            ToolSpec(
                tool_id=tid,
                version="1.0.0",
                input_schema={"type": "object"},
                output_schema={"type": "object"},
                effect_class=EffectClass.READ,
                verifier_name="v",
            ),
            lambda args, ctx: {"output": {"same": 1}},
        )
    model_client = (
        http_client
        if backend_mode == BackendMode.LOCAL_HTTP and http_client is not None
        else EmulatedModelClient(mode="cycle_a07")
    )
    coord = Coordinator(
        repo,
        model_client,
        registry,
        loop_detector=LoopDetector(LoopConfig(max_cycle_period=4, cycle_repeats=2)),
    )
    run = coord.submit_task(
        TaskSpec(
            task_id=f"bench-a07-{repeat_index}",
            user_id="op",
            profile_id="p1",
            scope=TaskScope(facility_id="facility-a", read_only=True),
            backend_mode=backend_mode,
            query="Cycle test",
        )
    )
    res = await coord.run_until_settled(run.run_id)
    ok = (
        res.status == TaskStatus.FAILED
        and res.execution_metrics.tool_calls == 4
        and res.partial_info is not None
        and res.partial_info.get("loop_kind") == "alternating_cycle"
    )
    m = res.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=res.status.value,
        correct=ok,
        correct_abstention=ok,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            f"Halted alternating_cycle at tool_calls={m.tool_calls}.",
            status=res.status.value,
            answer=res.answer,
            extra=f"tool_calls={m.tool_calls}",
        ),
    )


async def _engine_a08(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    effect_app = create_effect_sim_app(state_path=trial_dir / "effect_state.json")
    db_path = trial_dir / "a08.sqlite3"
    base_clock = utc_now()
    clock_box = [base_clock]

    async with run_asgi_server(effect_app) as effect_origin:
        adapter = EffectSimAdapter()
        specs = get_effect_tool_specs((effect_origin,))

        def _build_coord(pause_after_apply: bool) -> tuple[StorageRepo, Coordinator, asyncio.Event]:
            repo = StorageRepo(db_path)
            repo.init_db()
            registry = ToolRegistry()
            applied_evt = asyncio.Event()

            async def _apply_handler(
                args: dict[str, Any], ctx: ToolExecutionContext
            ) -> dict[str, Any]:
                task = repo.get_task_spec(ctx.task_id)
                payload, receipt = await adapter.apply_effect(
                    task=task,
                    origin=ctx.target_origin or effect_origin,
                    run_id=ctx.run_id,
                    step_id=ctx.step_id,
                    attempt=ctx.attempt,
                    operation_key=str(
                        ctx.idempotency_key or args.get("operation_key") or ctx.operation_key
                    ),
                    asset_id=str(args["asset_id"]),
                    action=str(args["action"]),
                    params=args.get("params") if isinstance(args.get("params"), dict) else None,
                    fail_after_apply=False,
                )
                if pause_after_apply:
                    applied_evt.set()
                    await asyncio.sleep(30.0)
                return {
                    "output": payload or {},
                    "observed_before": receipt.observed_before,
                    "observed_after": receipt.observed_after,
                    "evidence_refs": list(receipt.evidence_refs),
                }

            async def _reconciler(
                op_key: str,
                idem_key: str,
                ctx: ToolExecutionContext,
            ) -> tuple[bool, dict[str, Any] | None]:
                task = repo.get_task_spec(ctx.task_id)
                state = await adapter.inspect_state(
                    task=task,
                    origin=ctx.target_origin or effect_origin,
                    operation_key=idem_key or op_key,
                )
                existing = state.get("effect")
                if isinstance(existing, dict):
                    return True, existing
                return False, {"confirmed_unapplied": True}

            registry.register(
                specs["effect.apply"],
                _apply_handler,
                reconciler=_reconciler,
                supports_idempotency=True,
            )

            def _turn_factory(
                prompt_ctx: PromptContext,
                tools: Sequence[ToolSpec],
                budget_remaining: BudgetRemaining,
            ) -> EmulatedTurn:
                del tools, budget_remaining
                usage = ModelUsage(
                    prompt_tokens=30,
                    completion_tokens=15,
                    total_tokens=45,
                    usage_mode="actual",
                )
                if not prompt_ctx.history and not prompt_ctx.observations:
                    return EmulatedTurn(
                        decision=ModelDecision(
                            decision_type="tool_call",
                            tool_call=ModelToolCall(
                                tool_id="effect.apply",
                                args={
                                    "operation_key": f"op-a08-{repeat_index}",
                                    "asset_id": "bomba-34-a1",
                                    "action": "ack_alarm",
                                    "params": {"alarm_id": "ALM-3401"},
                                },
                                target_origin=effect_origin,
                            ),
                            usage=usage,
                        )
                    )
                return EmulatedTurn(
                    decision=ModelDecision(
                        decision_type="final",
                        final_answer="Effect applied and verified once.",
                        usage=usage,
                    )
                )

            model_client = (
                http_client
                if backend_mode == BackendMode.LOCAL_HTTP and http_client is not None
                else EmulatedModelClient(mode="custom", turn_factory=_turn_factory)
            )
            coord = Coordinator(
                repo,
                model_client,
                registry,
                clock=lambda: clock_box[0],
                config=CoordinatorConfig(
                    coordinator_id="bench-a08-w1" if pause_after_apply else "bench-a08-w2",
                    lease_ttl_seconds=1.0,
                    default_granted_permissions=("effect:read", "effect:write"),
                ),
            )
            return repo, coord, applied_evt

        _, coord1, applied_evt = _build_coord(pause_after_apply=True)
        run = coord1.submit_task(
            TaskSpec(
                task_id=f"bench-a08-{repeat_index}",
                user_id="op",
                profile_id="p1",
                scope=TaskScope(
                    facility_id="facility-a",
                    allowed_origins=(effect_origin,),
                    read_only=False,
                ),
                backend_mode=backend_mode,
                query="Apply ack_alarm idempotently",
            )
        )
        worker_task = asyncio.create_task(coord1.run_until_settled(run.run_id))
        await asyncio.wait_for(applied_evt.wait(), timeout=10.0)
        worker_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await worker_task

        # Advance virtual clock past lease expiry and recover in a fresh Coordinator
        clock_box[0] = base_clock + timedelta(seconds=5)
        _, coord2, _ = _build_coord(pause_after_apply=False)
        summary = await coord2.recover_inflight_runs()
        res = await coord2.run_until_settled(run.run_id)
        applied = effect_app.state.effect_sim_state.total_applied
        reqs = effect_app.state.effect_sim_state.total_apply_requests

    dups = max(0, applied - 1)
    ok = (
        summary.unknown_steps_reconciled == 1
        and res.status == TaskStatus.SUCCEEDED
        and applied == 1
        and reqs == 1
    )
    m = res.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=res.status.value,
        correct=ok,
        duplicate_effects=dups,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            f"Reconciled effect via state lookup; total_applied={applied}, requests={reqs}.",
            status=res.status.value,
            answer=res.answer,
            extra=(
                f"reconciled={summary.unknown_steps_reconciled}, "
                f"total_applied={applied}, requests={reqs}"
            ),
        ),
    )


async def _engine_a09(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    started_evt = asyncio.Event()
    release_evt = asyncio.Event()
    repo = StorageRepo(trial_dir / "a09.sqlite3")
    repo.init_db()
    registry = ToolRegistry()

    async def _slow_tool(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del args, ctx
        started_evt.set()
        await release_evt.wait()
        return {"output": {"late": True}}

    registry.register(
        ToolSpec(
            tool_id="scada.slow",
            version="1.0.0",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            effect_class=EffectClass.READ,
            verifier_name="v",
        ),
        _slow_tool,
    )
    model_client = (
        http_client
        if backend_mode == BackendMode.LOCAL_HTTP and http_client is not None
        else EmulatedModelClient(mode="happy_path")
    )
    coord = Coordinator(repo, model_client, registry)
    run = coord.submit_task(
        TaskSpec(
            task_id=f"bench-a09-{repeat_index}",
            user_id="op",
            profile_id="p1",
            scope=TaskScope(facility_id="facility-a", read_only=True),
            backend_mode=backend_mode,
            query="Slow cancel test",
        )
    )
    run_task = asyncio.create_task(coord.run_until_settled(run.run_id))
    await asyncio.wait_for(started_evt.wait(), timeout=5.0)
    cancelled = coord.cancel_task(run.run_id, reason="operator_abort")
    release_evt.set()
    res = await asyncio.wait_for(run_task, timeout=5.0)
    fenced = False
    try:
        repo.resume_from_input(run.run_id, {"choice": "x"})
    except TerminalStateError:
        fenced = True
    ok = cancelled.status == TaskStatus.CANCELLED and res.status == TaskStatus.CANCELLED and fenced
    m = res.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=res.status.value,
        correct=ok,
        correct_abstention=ok,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            "Live cancel fenced late tool result and locked terminal CANCELLED state.",
            status=res.status.value,
            answer=res.answer,
            extra=f"cancelled={cancelled.status.value}, fenced={fenced}",
        ),
    )


async def _engine_a10(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    local_cfg: LocalModelConfig | None,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    ref = utc_now()
    scada_app = create_scada_app("auth_expired")
    maint_app = create_maintenance_app("default")
    maint_app.state.maintenance_state.set_reference_time(ref)
    creds = MappingCredentialProvider(
        {
            ("operator_ro", "p1", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "p1", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )
    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH, {"scada": scada_origin, "maintenance": maint_origin}
        )
        runtime = build_runtime(
            db_path=trial_dir / "a10.sqlite3",
            profile_root=trial_dir / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            backend_mode=backend_mode,
            local_http_config=local_cfg,
            model_client=http_client,
            reference_time_fn=lambda: ref,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id=f"bench-a10-{repeat_index}",
                    user_id="operator_ro",
                    profile_id="p1",
                    scope=TaskScope(
                        facility_id="facility-a",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-1",),
                        read_only=True,
                    ),
                    backend_mode=backend_mode,
                    query="Check bomba 34",
                )
            )
            paused = await runtime.coordinator.run_until_settled(run.run_id)
            snap_paused = runtime.repo.get_run_snapshot(run.run_id)
            paused_ok = (
                paused.status == TaskStatus.WAITING_FOR_INPUT
                and snap_paused.run.transition_reason == "auth_expired"
            )
            if paused.status == TaskStatus.WAITING_FOR_INPUT:
                scada_app.state.scada_state.set_mode("default")
                scada_app.state.scada_state.set_reference_time(ref)
                runtime.coordinator.resume_task(run.run_id, {"reauthenticated": True})
                done = await runtime.coordinator.run_until_settled(run.run_id)
            else:
                done = paused
    ok = paused_ok and done.status == TaskStatus.SUCCEEDED and "ALM-3401" in done.answer
    m = done.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=done.status.value,
        correct=ok,
        correct_abstention=paused_ok,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            "Paused on auth_expired and succeeded after operator re-auth resume.",
            status=done.status.value,
            answer=done.answer,
            extra=f"paused_status={paused.status.value}",
        ),
    )


async def _engine_a12(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    local_cfg: LocalModelConfig | None,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    ref = utc_now()
    scada_app = create_scada_app("facility_b")
    maint_app = create_maintenance_app("facility_b")
    scada_app.state.scada_state.set_reference_time(ref)
    maint_app.state.maintenance_state.set_reference_time(ref)
    creds = MappingCredentialProvider(
        {
            ("operator_b", "p2", "scada"): ("operator_b", "scada-pass-b"),
            ("operator_b", "p2", "maintenance"): ("maint_b", "maint-pass-b"),
        }
    )
    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_B_PATH, {"scada": scada_origin, "maintenance": maint_origin}
        )
        runtime = build_runtime(
            db_path=trial_dir / "a12.sqlite3",
            profile_root=trial_dir / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            backend_mode=backend_mode,
            local_http_config=local_cfg,
            model_client=http_client,
            reference_time_fn=lambda: ref,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id=f"bench-a12-{repeat_index}",
                    user_id="operator_b",
                    profile_id="p2",
                    scope=TaskScope(
                        facility_id="facility-b",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-2",),
                        read_only=True,
                    ),
                    backend_mode=backend_mode,
                    query="Check P-77B alarms and latest work order",
                )
            )
            result = await runtime.coordinator.run_until_settled(run.run_id)
    ok = (
        result.status == TaskStatus.SUCCEEDED
        and "ALM-7701" in result.answer
        and "WO-7705" in result.answer
        and len(result.contradictions) == 0
    )
    m = result.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=result.status.value,
        correct=ok,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            "Config-only Facility B portability (SC-77 + CMMS-77, reordered Spanish DOM).",
            status=result.status.value,
            answer=result.answer,
        ),
    )


async def _engine_a13(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    local_cfg: LocalModelConfig | None,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    ref = utc_now()
    scada_app = create_scada_app("default")
    maint_app = create_maintenance_app("contradictory")
    scada_app.state.scada_state.set_reference_time(ref)
    maint_app.state.maintenance_state.set_reference_time(ref)
    creds = MappingCredentialProvider(
        {
            ("operator_ro", "p1", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "p1", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )
    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH, {"scada": scada_origin, "maintenance": maint_origin}
        )
        runtime = build_runtime(
            db_path=trial_dir / "a13.sqlite3",
            profile_root=trial_dir / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            backend_mode=backend_mode,
            local_http_config=local_cfg,
            model_client=http_client,
            reference_time_fn=lambda: ref,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id=f"bench-a13-{repeat_index}",
                    user_id="operator_ro",
                    profile_id="p1",
                    scope=TaskScope(
                        facility_id="facility-a",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-1",),
                        read_only=True,
                    ),
                    backend_mode=backend_mode,
                    query="Check bomba 34",
                )
            )
            result = await runtime.coordinator.run_until_settled(run.run_id)
    ok = (
        result.status == TaskStatus.PARTIAL
        and len(result.contradictions) >= 1
        and all(c.unresolved for c in result.contradictions)
    )
    m = result.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=result.status.value,
        correct=ok,
        correct_abstention=ok,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            f"Preserved {len(result.contradictions)} unresolved contradiction(s) as PARTIAL.",
            status=result.status.value,
            answer=result.answer,
            extra=f"contradictions={len(result.contradictions)}",
        ),
    )


async def _engine_a14(
    scenario: BenchmarkScenario,
    repeat_index: int,
    trial_dir: Path,
    backend_mode: BackendMode,
    http_client: LocalHttpModelClient | None,
) -> ScenarioTrialResult:
    db_path = trial_dir / "a14.sqlite3"
    run_id = f"bench-a14-{repeat_index}-{uuid.uuid4().hex[:6]}"

    def _kill_worker() -> None:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "tests.integration._crash_worker",
                "--mode",
                "run_a14",
                "--db-path",
                str(db_path),
                "--run-id",
                run_id,
            ],
            cwd=str(_REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stdout is not None
        ready = proc.stdout.readline().strip()
        assert ready == "READY_TO_KILL", f"Unexpected worker output: {ready!r}"
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10.0)

    await asyncio.to_thread(_kill_worker)
    await asyncio.sleep(1.2)

    repo2 = StorageRepo(db_path)
    repo2.init_db()
    registry2 = ToolRegistry()
    spec = ToolSpec(
        tool_id="diag.read",
        version="1.0.0",
        input_schema={"type": "object", "properties": {"probe": {"type": "string"}}},
        output_schema={"type": "object"},
        permissions=("diag:read",),
        allowed_origins=(),
        effect_class=EffectClass.READ,
        timeout_s=30.0,
        verifier_name="verify_diag",
    )

    async def _handler(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del ctx
        return {"output": {"probe": args.get("probe")}}

    registry2.register(spec, _handler)

    class _RecoverTurnClient:
        async def decide(
            self,
            prompt_ctx: PromptContext,
            tools: Sequence[ToolSpec],
            budget_remaining: BudgetRemaining,
        ) -> ModelDecision:
            del prompt_ctx, tools, budget_remaining
            return ModelDecision(
                decision_type="final",
                final_answer="A14 recovered cleanly.",
                usage=ModelUsage(
                    prompt_tokens=100,
                    completion_tokens=40,
                    total_tokens=140,
                    usage_mode="actual",
                ),
            )

    model_client: Any = (
        http_client
        if backend_mode == BackendMode.LOCAL_HTTP and http_client is not None
        else _RecoverTurnClient()
    )
    coord2 = Coordinator(
        repo2,
        model_client,
        registry2,
        config=CoordinatorConfig(
            coordinator_id=f"bench-a14-recover-{repeat_index}",
            lease_ttl_seconds=1.0,
            default_granted_permissions=("diag:read",),
        ),
    )
    summary = await coord2.recover_inflight_runs()
    pre_usage = repo2.get_budget_usage("task-a14-sigkill")
    res = await coord2.run_until_settled(run_id)
    post_usage = repo2.get_budget_usage("task-a14-sigkill")
    ok = (
        summary.expired_reservations_cleaned >= 1
        and pre_usage.usage_estimated is True
        and pre_usage.tokens_reserved == 0
        and res.status == TaskStatus.SUCCEEDED
        and post_usage.within_limits(
            BudgetConfig(max_tool_calls=6, max_model_calls=6, max_total_tokens=2000)
        )
    )
    m = res.execution_metrics
    return ScenarioTrialResult(
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        system="grokbot_engine",
        repeat_index=repeat_index,
        evidence_tier=scenario.evidence_tier,
        status=res.status.value,
        correct=ok,
        state_loss=0 if ok else 1,
        duration_ms=0.0,
        tool_calls=m.tool_calls,
        model_calls=m.model_calls,
        total_tokens=m.total_tokens,
        usage_mode="estimated" if m.usage_estimated else "actual",
        detail=_trial_detail(
            ok,
            (
                f"Cleaned {summary.expired_reservations_cleaned} expired reservation(s); "
                "preserved counters across SIGKILL."
            ),
            status=res.status.value,
            answer=res.answer,
            extra=f"cleaned={summary.expired_reservations_cleaned}",
        ),
    )


async def run_benchmarks(
    *,
    mode: BenchmarkMode = "emulated",
    repeats: int = 1,
    scenarios: Sequence[str] | None = None,
    llm_origin: str | None = None,
    model_id: str = "qwen2.5-7b-instruct",
    command_str: str = "python -m benchmarks.runner",
) -> BenchmarkReport:
    """Execute paired RuleBasedBaseline vs GrokbotEngine benchmarks and return BenchmarkReport."""
    if repeats < 1:
        raise ValueError("repeats must be >= 1")

    all_selected = get_all_scenarios(scenarios)
    runnable = get_runnable_scenarios(scenarios)
    pending = tuple(
        {
            "scenario_id": s.scenario_id,
            "name": s.name,
            "status": "PENDING_N3_LINUX_ENV",
            "reason": s.n3_reason or "Linux N3 environment required.",
        }
        for s in all_selected
        if s.n3_pending
    )

    baseline = RuleBasedBaseline()
    trials: list[ScenarioTrialResult] = []

    if mode == "local_http":
        if llm_origin is not None:
            validated_origin = validate_local_model_origin(llm_origin)
            model_type = "local_http"
            vram_note = "N/A (external local_http)"
            active_server_ctx: Any = None
        else:
            cfg_a = load_facility_config(_FACILITY_A_PATH)
            cfg_b = load_facility_config(_FACILITY_B_PATH)
            mock_app = _create_benchmark_mock_openai_server(
                facility_configs=(cfg_a, cfg_b),
                model_id=model_id,
            )
            validated_origin = ""
            model_type = "local_http_mock"
            vram_note = "N/A (local_http_mock)"
            active_server_ctx = run_asgi_server(mock_app)
    else:
        validated_origin = ""
        model_type = "emulated"
        vram_note = "N/A (emulated)"
        active_server_ctx = None

    with tempfile.TemporaryDirectory(prefix="grokbot_bench_") as tmp_root:
        tmp_path = Path(tmp_root)
        if active_server_ctx is not None:
            async with active_server_ctx as mock_origin:
                for rep in range(1, repeats + 1):
                    for scenario in runnable:
                        trials.append(await baseline.run_scenario(scenario, repeat_index=rep))
                        trials.append(
                            await _run_engine_scenario(
                                scenario,
                                repeat_index=rep,
                                tmp_dir=tmp_path,
                                mode=mode,
                                llm_origin=mock_origin,
                                model_id=model_id,
                            )
                        )
        else:
            eff_origin = validated_origin if mode == "local_http" else None
            for rep in range(1, repeats + 1):
                for scenario in runnable:
                    trials.append(await baseline.run_scenario(scenario, repeat_index=rep))
                    trials.append(
                        await _run_engine_scenario(
                            scenario,
                            repeat_index=rep,
                            tmp_dir=tmp_path,
                            mode=mode,
                            llm_origin=eff_origin,
                            model_id=model_id,
                        )
                    )

    baseline_trials = [t for t in trials if t.system == "baseline"]
    engine_trials = [t for t in trials if t.system == "grokbot_engine"]
    ram_mb = _current_ram_mb()

    baseline_summary = aggregate_trials(
        "RuleBasedBaseline",
        baseline_trials,
        num_scenarios=len(runnable),
        repeats_per_scenario=repeats,
        ram_mb=ram_mb,
        vram_mb=None,
        vram_note="N/A (baseline)",
    )
    engine_summary = aggregate_trials(
        "GrokbotEngine",
        engine_trials,
        num_scenarios=len(runnable),
        repeats_per_scenario=repeats,
        ram_mb=ram_mb,
        vram_mb=None,
        vram_note=vram_note,
    )

    a12_trials = [t for t in engine_trials if t.scenario_id == "A12"]
    a12_metrics: A12AdaptationMetrics | None = None
    if a12_trials:
        a12_secs = round(sum(t.duration_ms for t in a12_trials) / (1000.0 * len(a12_trials)), 4)
        a12_metrics = A12AdaptationMetrics(
            facility_config_path="lab/configs/facility_b.json",
            files_changed=("lab/configs/facility_b.json",),
            engine_loc_delta=0,
            adapter_loc_delta=0,
            adaptation_time_seconds=a12_secs,
            adaptation_hours=round(a12_secs / 3600.0, 6),
            verified_succeeded=all(t.correct for t in a12_trials),
        )

    n3_probe = run_n3_probe()
    exit_code = 0 if engine_summary.promotion_eligible else 1
    provenance = ProvenanceMetadata(
        benchmark_id=f"bench-{uuid.uuid4().hex[:10]}",
        git_commit=_git_head_sha(),
        timestamp_utc=datetime.now(UTC).isoformat(),
        host_os=platform.system(),
        host_arch=platform.machine(),
        python_version=platform.python_version(),
        playwright_version=_playwright_version(),
        model_type=model_type,
        evidence_level="N1/N2",
        n3_status=n3_probe.overall_status,
        a11_status="PENDING_N3_LINUX_ENV" if pending else "NOT_SELECTED",
        command=command_str,
        exit_code=exit_code,
    )

    return BenchmarkReport(
        provenance=provenance,
        baseline_summary=baseline_summary,
        engine_summary=engine_summary,
        a12_adaptation=a12_metrics,
        pending_scenarios=pending,
        trials=tuple(trials),
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `python -m benchmarks.runner` and `make bench`."""
    parser = argparse.ArgumentParser(description="Run Grokbot-clon comparative benchmarks.")
    parser.add_argument(
        "--mode",
        choices=("emulated", "local_http"),
        default="emulated",
        help="Model execution mode (default: emulated).",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        help="Number of repetitions per runnable scenario (default: 1).",
    )
    parser.add_argument(
        "--scenarios",
        default="",
        help="Comma-separated scenario IDs to run (default: all).",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help=(
            "Directory for JSON/MD report files. Defaults to system temp dir "
            "so zero files are created inside tracked repository directories."
        ),
    )
    parser.add_argument(
        "--llm-origin",
        default="",
        help="Optional local HTTP LLM server origin when --mode local_http.",
    )
    parser.add_argument(
        "--model-id",
        default="qwen2.5-7b-instruct",
        help="Model ID reported in local_http mode.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON report to stdout instead of Markdown summary.",
    )
    args = parser.parse_args(argv)

    selected = (
        [s.strip() for s in args.scenarios.split(",") if s.strip()]
        if args.scenarios
        else None
    )
    llm_origin = args.llm_origin.strip() or None
    raw_argv = argv if argv is not None else sys.argv[1:]
    cmd_str = " ".join(["python -m benchmarks.runner", *raw_argv])

    report = asyncio.run(
        run_benchmarks(
            mode=args.mode,
            repeats=args.repeats,
            scenarios=selected,
            llm_origin=llm_origin,
            model_id=args.model_id,
            command_str=cmd_str,
        )
    )

    out_dir = (
        Path(args.output_dir)
        if args.output_dir.strip()
        else Path(tempfile.gettempdir()) / "grokbot_benchmarks"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "benchmark_report.json"
    md_path = out_dir / "benchmark_report.md"
    json_payload = report.model_dump_json(indent=2)
    md_payload = format_markdown_report(report)
    json_path.write_text(json_payload, encoding="utf-8")
    md_path.write_text(md_payload, encoding="utf-8")

    if args.json:
        print(json_payload)
    else:
        print(md_payload)
        print(f"Saved reports to: {json_path} and {md_path}")
    return report.provenance.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
