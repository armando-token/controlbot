"""Megaplan §6.1 acceptance oracle suite (A01-A14) with honest N1/N2/N3 markers."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import signal
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from benchmarks.runner import run_benchmarks
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from lab.effect_sim import create_effect_sim_app
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import create_scada_app
from lab.testing import run_asgi_server
from src.adapters import (
    MappingCredentialProvider,
    OriginNotAllowedError,
    ScadaAdapter,
    SessionManager,
    SessionOwnershipError,
    check_desktop_capabilities,
    load_facility_config,
)
from src.contracts.common import utc_now
from src.contracts.enums import BackendMode, DataQuality, EffectClass, TaskStatus
from src.contracts.models import TaskScope, TaskSpec, ToolSpec
from src.contracts.redaction import contains_unredacted_secret
from src.doctor import run_doctor
from src.engine.coordinator import Coordinator
from src.engine.loop_detector import LoopConfig, LoopDetector
from src.engine.tool_registry import ToolExecutionContext, ToolRegistry
from src.model import (
    EmulatedModelClient,
    LocalHttpModelClient,
    LocalModelConfig,
    validate_local_model_origin,
)
from src.n3_probe import run_n3_probe
from src.runtime import build_runtime
from src.storage.errors import TerminalStateError
from src.storage.repo import StorageRepo

_FACILITY_A_PATH = Path("lab/configs/facility_a.json")
_FACILITY_B_PATH = Path("lab/configs/facility_b.json")


def _create_mock_openai_server(
    handler: Callable[[dict[str, Any], int], tuple[int, dict[str, Any], dict[str, str] | None]],
) -> FastAPI:
    app = FastAPI(title="Mock Acceptance OpenAI Server")
    count = 0

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        nonlocal count
        body = await request.json()
        idx = count
        count += 1
        code, payload, headers = handler(body, idx)
        return JSONResponse(content=payload, status_code=code, headers=headers)

    return app


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a01_normal_cross_source_query_emulated_and_local_http(tmp_path: Path) -> None:
    ref_time = utc_now()
    scada_app = create_scada_app(fixture_mode="default")
    maint_app = create_maintenance_app(fixture_mode="default")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

    creds = MappingCredentialProvider(
        {
            ("operator_ro", "p1", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "p1", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )

    def _mock_llm_handler(
        body: dict[str, Any],
        idx: int,
    ) -> tuple[int, dict[str, Any], dict[str, str] | None]:
        del body
        tools_plan = ("scada.read_alarms", "scada.read_readings", "maint.read_work_orders")
        if idx < len(tools_plan):
            return (
                200,
                {
                    "model": "qwen2.5-7b-instruct",
                    "usage": {"prompt_tokens": 40, "completion_tokens": 15, "total_tokens": 55},
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "tool_calls": [
                                    {
                                        "function": {
                                            "name": tools_plan[idx],
                                            "arguments": json.dumps(
                                                {"asset": "bomba 34", "area": "area-1"}
                                            ),
                                        }
                                    }
                                ],
                            }
                        }
                    ],
                },
                None,
            )
        return (
            200,
            {
                "model": "qwen2.5-7b-instruct",
                "usage": {"prompt_tokens": 60, "completion_tokens": 20, "total_tokens": 80},
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {
                                    "decision_type": "final",
                                    "final_answer": "ALM-3401 and WO-3408 verified.",
                                }
                            ),
                        }
                    }
                ],
            },
            None,
        )

    llm_app = _create_mock_openai_server(_mock_llm_handler)

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
        run_asgi_server(llm_app) as llm_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "a01.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            backend_mode=BackendMode.LOCAL_HTTP,
            local_http_config=LocalModelConfig(
                origin=llm_origin,
                model_id="qwen2.5-7b-instruct",
            ),
            model_client=LocalHttpModelClient(
                LocalModelConfig(origin=llm_origin, model_id="qwen2.5-7b-instruct")
            ),
            reference_time_fn=lambda: ref_time,
        )
        async with (
            runtime,
            run_asgi_server(runtime.app) as web_origin,
            httpx.AsyncClient(base_url=web_origin, trust_env=False) as client,
        ):
                sub = await client.post(
                    "/api/tasks",
                    json={
                        "user_id": "operator_ro",
                        "profile_id": "p1",
                        "facility_id": "facility-a",
                        "allowed_origins": [scada_origin, maint_origin],
                        "allowed_areas": ["area-1"],
                        "backend_mode": "local_http",
                        "query": "First alarm and latest intervention on bomba 34",
                    },
                )
                assert sub.status_code == 201
                run_id = sub.json()["run_id"]
                await runtime.web_coordinator.wait_for_run(run_id, timeout=20.0)
                snap = (await client.get(f"/api/tasks/{run_id}")).json()

        assert snap["status"] == TaskStatus.SUCCEEDED.value
        answer = snap["result"]["answer"]
        assert "ALM-3401" in answer
        assert "WO-3408" in answer
        obs_list = snap["result"]["verified_observations"]
        assert {o["source"] for o in obs_list} == {"scada", "maintenance"}
        assert all(o["source_time"] is not None for o in obs_list)
        assert all(o["quality"] == DataQuality.GOOD.value for o in obs_list)
        assert len(snap["receipts"]) == 3
        assert not contains_unredacted_secret(snap)


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a02_ambiguous_identity_pauses_and_resumes_by_area(tmp_path: Path) -> None:
    ref_time = utc_now()
    scada_app = create_scada_app(fixture_mode="ambiguity")
    maint_app = create_maintenance_app(fixture_mode="ambiguity")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

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
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "a02.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            reference_time_fn=lambda: ref_time,
        )
        async with (
            runtime,
            run_asgi_server(runtime.app) as web_origin,
            httpx.AsyncClient(base_url=web_origin, trust_env=False) as client,
        ):
                sub = await client.post(
                    "/api/tasks",
                    json={
                        "user_id": "operator_ro",
                        "profile_id": "p1",
                        "facility_id": "facility-a",
                        "allowed_origins": [scada_origin, maint_origin],
                        "query": "Check bomba 34",
                    },
                )
                run_id = sub.json()["run_id"]
                await runtime.web_coordinator.wait_for_run(run_id, timeout=20.0)
                paused = (await client.get(f"/api/tasks/{run_id}")).json()
                assert paused["status"] == TaskStatus.WAITING_FOR_INPUT.value
                assert "area-1" in paused["required_action"]
                assert "area-2" in paused["required_action"]

                resumed = await client.post(
                    f"/api/tasks/{run_id}/resume",
                    json={"human_input": {"area": "area-1"}},
                )
                assert resumed.status_code == 200
                await runtime.web_coordinator.wait_for_run(run_id, timeout=20.0)
                done = (await client.get(f"/api/tasks/{run_id}")).json()

        assert done["status"] == TaskStatus.SUCCEEDED.value
        verified = done["result"]["verified_observations"]
        assert verified
        assert all(o["area"] == "area-1" for o in verified)


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a03_quality_and_time_window_filtering(tmp_path: Path) -> None:
    ref_time = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC)
    scada_app = create_scada_app(fixture_mode="stale")
    maint_app = create_maintenance_app(fixture_mode="stale")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

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
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "a03.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            reference_time_fn=lambda: ref_time,
            window_start=ref_time - timedelta(hours=2),
            window_end=ref_time,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id="task-a03",
                    user_id="operator_ro",
                    profile_id="p1",
                    scope=TaskScope(
                        facility_id="facility-a",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-1",),
                        read_only=True,
                    ),
                    query="Check bomba 34 quality and window",
                )
            )
            res = await runtime.coordinator.run_until_settled(run.run_id)

        assert res.status == TaskStatus.SUCCEEDED
        assert "ALM-3405" in res.answer
        assert "First authorized alarm [ALM-OLD-01]" not in res.answer
        by_id = {o.metadata.get("record_id"): o for o in res.verified_observations}
        assert by_id["ALM-OLD-01"].authorized_evidence is False
        assert by_id["RDG-STALE-01"].authorized_evidence is False
        assert by_id["RDG-BAD-01"].authorized_evidence is False
        assert by_id["ALM-3405"].authorized_evidence is True


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a04_source_down_returns_partial_with_missing_source(tmp_path: Path) -> None:
    ref_time = utc_now()
    scada_app = create_scada_app(fixture_mode="down")
    maint_app = create_maintenance_app(fixture_mode="default")
    maint_app.state.maintenance_state.set_reference_time(ref_time)

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
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "a04.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            reference_time_fn=lambda: ref_time,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id="task-a04",
                    user_id="operator_ro",
                    profile_id="p1",
                    scope=TaskScope(
                        facility_id="facility-a",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-1",),
                        read_only=True,
                    ),
                    query="Check bomba 34",
                )
            )
            res = await runtime.coordinator.run_until_settled(run.run_id)

        assert res.status == TaskStatus.PARTIAL
        assert "WO-3408" in res.answer
        assert res.partial_info is not None
        assert res.partial_info["missing_sources"] == ["scada"]
        assert res.partial_info["available_sources"] == ["maintenance"]


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a05_session_isolation_restart_and_tamper_rejection(tmp_path: Path) -> None:
    scada_app = create_scada_app(fixture_mode="ambiguity")
    other_app = create_maintenance_app(fixture_mode="default")
    profile_root = tmp_path / "profiles"

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
            task_id="t-a",
            user_id="operator_a1",
            profile_id="prof_a",
            scope=TaskScope(facility_id="facility-a", allowed_origins=(scada_origin,)),
            query="Read alarms",
        )
        task_b = TaskSpec(
            task_id="t-b",
            user_id="operator_a2",
            profile_id="prof_b",
            scope=TaskScope(facility_id="facility-a", allowed_origins=(scada_origin,)),
            query="Read alarms",
        )

        async with SessionManager(profile_root, headless=True) as mgr:
            adapter = ScadaAdapter(mgr, creds)
            (obs_a, _), (obs_b, _) = await asyncio.gather(
                adapter.read_alarms(task=task_a, config=cfg),
                adapter.read_alarms(task=task_b, config=cfg),
            )
            assert obs_a[0].area == "area-1"
            assert obs_b[0].area == "area-2"
            dir_a = profile_root / "operator_a1" / "prof_a" / "scada"
            assert stat.S_IMODE(dir_a.stat().st_mode) == 0o700
            assert stat.S_IMODE((dir_a / "session_meta.json").stat().st_mode) == 0o600

            sess_a = await mgr.open_session("operator_a1", "prof_a", "scada", (scada_origin,))
            with pytest.raises(OriginNotAllowedError):
                await mgr.navigate(sess_a.session_id, f"{other_origin}/login")

        # Restart without credentials: cookie persistence keeps session authenticated
        async with SessionManager(profile_root, headless=True) as mgr2:
            adapter2 = ScadaAdapter(mgr2, credential_provider=None)
            obs_reopen, _ = await adapter2.read_alarms(task=task_a, config=cfg)
            assert obs_reopen[0].metadata["did_login"] is False

            meta_path = profile_root / "operator_a1" / "prof_a" / "scada" / "session_meta.json"
            tampered = json.loads(meta_path.read_text(encoding="utf-8"))
            tampered["user_id"] = "intruder"
            meta_path.write_text(json.dumps(tampered), encoding="utf-8")
            with pytest.raises(SessionOwnershipError):
                await mgr2.open_session("operator_a1", "prof_a", "scada", (scada_origin,))


@pytest.mark.acceptance
@pytest.mark.n1
async def test_a06_identical_repeat_loop_halts_before_budget(tmp_path: Path) -> None:
    repo = StorageRepo(tmp_path / "a06.sqlite3")
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
    coord = Coordinator(
        repo,
        EmulatedModelClient(mode="loop_a06"),
        registry,
        loop_detector=LoopDetector(LoopConfig(identical_repeat_threshold=3)),
    )
    run = coord.submit_task(
        TaskSpec(
            task_id="task-a06",
            user_id="op",
            profile_id="p1",
            scope=TaskScope(facility_id="facility-a", read_only=True),
            query="Loop test",
        )
    )
    res = await coord.run_until_settled(run.run_id)
    assert res.status == TaskStatus.FAILED
    assert res.execution_metrics.tool_calls == 3
    assert res.partial_info is not None
    assert res.partial_info["loop_kind"] == "identical_repeat"
    audits = repo.list_audit_logs(task_id="task-a06")
    assert any(a.action == "loop_halted" for a in audits)


@pytest.mark.acceptance
@pytest.mark.n1
async def test_a07_alternating_cycle_loop_halts_before_budget(tmp_path: Path) -> None:
    repo = StorageRepo(tmp_path / "a07.sqlite3")
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
    coord = Coordinator(
        repo,
        EmulatedModelClient(mode="cycle_a07"),
        registry,
        loop_detector=LoopDetector(LoopConfig(max_cycle_period=4, cycle_repeats=2)),
    )
    run = coord.submit_task(
        TaskSpec(
            task_id="task-a07",
            user_id="op",
            profile_id="p1",
            scope=TaskScope(facility_id="facility-a", read_only=True),
            query="Cycle test",
        )
    )
    res = await coord.run_until_settled(run.run_id)
    assert res.status == TaskStatus.FAILED
    assert res.execution_metrics.tool_calls == 4
    assert res.partial_info is not None
    assert res.partial_info["loop_kind"] == "alternating_cycle"


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a08_sigkill_after_effect_reconciles_without_replay(tmp_path: Path) -> None:
    state_path = tmp_path / "a08_effect_state.json"
    effect_app = create_effect_sim_app(state_path=state_path)
    db_path = tmp_path / "a08.sqlite3"
    run_id = "run-acc-a08"

    async with run_asgi_server(effect_app) as effect_origin:
        def _kill_worker() -> None:
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "tests.integration._crash_worker",
                    "--mode",
                    "run_a08",
                    "--db-path",
                    str(db_path),
                    "--run-id",
                    run_id,
                    "--effect-origin",
                    effect_origin,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert proc.stdout is not None
            assert proc.stdout.readline().strip() == "READY_TO_KILL"
            os.kill(proc.pid, signal.SIGKILL)
            assert proc.wait(timeout=10.0) == -signal.SIGKILL

        await asyncio.to_thread(_kill_worker)
        await asyncio.sleep(1.2)

        rec = await asyncio.to_thread(
            subprocess.run,
            [
                sys.executable,
                "-m",
                "tests.integration._crash_worker",
                "--mode",
                "recover_a08",
                "--db-path",
                str(db_path),
                "--run-id",
                run_id,
                "--effect-origin",
                effect_origin,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert rec.returncode == 0, rec.stderr
        data = json.loads(rec.stdout.strip())
        assert data["summary"]["unknown_steps_reconciled"] == 1
        assert data["status"] == TaskStatus.SUCCEEDED.value
        assert effect_app.state.effect_sim_state.total_applied == 1
        assert effect_app.state.effect_sim_state.total_apply_requests == 1


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a09_live_cancel_and_late_result_fencing(tmp_path: Path) -> None:
    started_evt = asyncio.Event()
    release_evt = asyncio.Event()

    repo = StorageRepo(tmp_path / "a09.sqlite3")
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
    coord = Coordinator(repo, EmulatedModelClient(mode="happy_path"), registry)
    run = coord.submit_task(
        TaskSpec(
            task_id="task-a09",
            user_id="op",
            profile_id="p1",
            scope=TaskScope(facility_id="facility-a", read_only=True),
            query="Slow cancel test",
        )
    )
    run_task = asyncio.create_task(coord.run_until_settled(run.run_id))
    await asyncio.wait_for(started_evt.wait(), timeout=5.0)

    cancelled = coord.cancel_task(run.run_id, reason="operator_abort")
    assert cancelled.status == TaskStatus.CANCELLED
    release_evt.set()
    res = await asyncio.wait_for(run_task, timeout=5.0)
    assert res.status == TaskStatus.CANCELLED

    # Attempting to resume or mutate terminal CANCELLED run must fail closed
    with pytest.raises(TerminalStateError):
        repo.resume_from_input(run.run_id, {"choice": "x"})


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a10_auth_expiry_takeover_and_resume_reevaluation(tmp_path: Path) -> None:
    ref_time = utc_now()
    scada_app = create_scada_app(fixture_mode="auth_expired")
    maint_app = create_maintenance_app(fixture_mode="default")
    maint_app.state.maintenance_state.set_reference_time(ref_time)

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
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "a10.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            reference_time_fn=lambda: ref_time,
        )
        async with (
            runtime,
            run_asgi_server(runtime.app) as web_origin,
            httpx.AsyncClient(base_url=web_origin, trust_env=False) as client,
        ):
                sub = await client.post(
                    "/api/tasks",
                    json={
                        "user_id": "operator_ro",
                        "profile_id": "p1",
                        "facility_id": "facility-a",
                        "allowed_origins": [scada_origin, maint_origin],
                        "allowed_areas": ["area-1"],
                        "query": "Check bomba 34",
                    },
                )
                run_id = sub.json()["run_id"]
                await runtime.web_coordinator.wait_for_run(run_id, timeout=20.0)
                paused = (await client.get(f"/api/tasks/{run_id}")).json()
                assert paused["status"] == TaskStatus.WAITING_FOR_INPUT.value
                assert paused["transition_reason"] == "auth_expired"

                scada_app.state.scada_state.set_mode("default")
                scada_app.state.scada_state.set_reference_time(ref_time)
                resumed = await client.post(
                    f"/api/tasks/{run_id}/resume",
                    json={"human_input": {"reauthenticated": True}},
                )
                assert resumed.status_code == 200
                await runtime.web_coordinator.wait_for_run(run_id, timeout=20.0)
                done = (await client.get(f"/api/tasks/{run_id}")).json()
                assert done["status"] == TaskStatus.SUCCEEDED.value
                assert "ALM-3401" in done["result"]["answer"]


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a11_local_loopback_egress_blocking_and_n3_honesty(tmp_path: Path) -> None:
    # Local origin allowlist blocks external internet origins before any socket connect
    with pytest.raises(OriginNotAllowedError):
        validate_local_model_origin("https://api.openai.com")
    with pytest.raises(OriginNotAllowedError):
        validate_local_model_origin("http://8.8.8.8:8080")

    # On macOS, doctor, n3_probe, and desktop probe MUST honestly report PENDING_N3_LINUX_ENV
    if platform.system() != "Linux":
        assert run_doctor().n3_status == "PENDING_N3_LINUX_ENV"
        assert run_n3_probe().overall_status == "PENDING_N3_LINUX_ENV"
        assert check_desktop_capabilities().status == "PENDING_N3_LINUX_ENV"

    # Loopback-only run succeeds with zero external requests
    def _handler(
        body: dict[str, Any],
        idx: int,
    ) -> tuple[int, dict[str, Any], dict[str, str] | None]:
        del body, idx
        return (
            200,
            {
                "model": "qwen2.5-7b-instruct",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {"decision_type": "final", "final_answer": "Local loopback ok."}
                            ),
                        }
                    }
                ],
            },
            None,
        )

    llm_app = _create_mock_openai_server(_handler)
    async with run_asgi_server(llm_app) as llm_origin:
        repo = StorageRepo(tmp_path / "a11.sqlite3")
        repo.init_db()
        client = LocalHttpModelClient(
            LocalModelConfig(origin=llm_origin, model_id="qwen2.5-7b-instruct")
        )
        coord = Coordinator(repo, client, ToolRegistry())
        run = coord.submit_task(
            TaskSpec(
                task_id="task-a11-n2",
                user_id="op",
                profile_id="p1",
                scope=TaskScope(facility_id="facility-a", read_only=True),
                query="Local loopback check",
                backend_mode=BackendMode.LOCAL_HTTP,
            )
        )
        res = await coord.run_until_settled(run.run_id)
        assert res.status == TaskStatus.SUCCEEDED


@pytest.mark.acceptance
@pytest.mark.n3
@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="PENDING_N3_LINUX_ENV: Linux kernel netns/iptables and local LLM required.",
)
def test_a11_linux_kernel_netns_and_local_llm_n3() -> None:
    report = run_n3_probe()
    assert report.linux_os_ready is True
    assert report.network_isolation_ready is True
    assert report.overall_status == "READY"


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a12_reordered_columns_and_alias_with_zero_adapter_edits(tmp_path: Path) -> None:
    # M4 baseline A12 hook; M5 extends this with lab/configs/facility_b.json Area-2 portability.
    ref_time = utc_now()
    scada_app = create_scada_app(fixture_mode="reordered")
    maint_app = create_maintenance_app(fixture_mode="reordered")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

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
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "a12.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            reference_time_fn=lambda: ref_time,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id="task-a12",
                    user_id="operator_ro",
                    profile_id="p1",
                    scope=TaskScope(
                        facility_id="facility-a",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-1",),
                        read_only=True,
                    ),
                    query="Check P-34 alarms and latest work order",
                )
            )
            res = await runtime.coordinator.run_until_settled(run.run_id)

        assert res.status == TaskStatus.SUCCEEDED
        assert "ALM-3401" in res.answer
        assert "WO-3408" in res.answer


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a12_facility_b_area2_config_only_portability(tmp_path: Path) -> None:
    started = time.perf_counter()
    ref_time = utc_now()
    scada_app = create_scada_app(fixture_mode="facility_b")
    maint_app = create_maintenance_app(fixture_mode="facility_b")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

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
            _FACILITY_B_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / f"a12_b_{uuid.uuid4().hex[:6]}.sqlite3",
            profile_root=tmp_path / "profiles_b",
            facility_config=cfg,
            credential_provider=creds,
            reference_time_fn=lambda: ref_time,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id="task-a12-facility-b",
                    user_id="operator_b",
                    profile_id="p2",
                    scope=TaskScope(
                        facility_id="facility-b",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-2",),
                        read_only=True,
                    ),
                    query="Check P-77B alarms and latest work order",
                )
            )
            res = await runtime.coordinator.run_until_settled(run.run_id)

    elapsed_s = time.perf_counter() - started
    assert elapsed_s > 0.0
    assert res.status == TaskStatus.SUCCEEDED
    assert "ALM-7701" in res.answer
    assert "WO-7705" in res.answer
    assert len(res.contradictions) == 0
    assert {o.source for o in res.verified_observations} == {"scada", "maintenance"}
    assert all(o.area == "area-2" for o in res.verified_observations)
    assert any(o.asset_id == "SC-77" for o in res.verified_observations if o.source == "scada")
    assert any(
        o.asset_id == "CMMS-77" for o in res.verified_observations if o.source == "maintenance"
    )
    # Verify src/engine/ has zero facility-specific coupling (engine_loc_delta == 0)
    engine_files = list(Path("src/engine").glob("*.py"))
    assert engine_files
    for engine_file in engine_files:
        text = engine_file.read_text(encoding="utf-8").lower()
        assert "bomba" not in text
        assert "sc-77" not in text
        assert "cmms-77" not in text
        assert "facility-b" not in text


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a13_contradictory_evidence_preserved_as_partial(tmp_path: Path) -> None:
    ref_time = utc_now()
    scada_app = create_scada_app(fixture_mode="default")
    maint_app = create_maintenance_app(fixture_mode="contradictory")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

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
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "a13.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            reference_time_fn=lambda: ref_time,
            auto_run=False,
        )
        async with runtime:
            run = runtime.coordinator.submit_task(
                TaskSpec(
                    task_id="task-a13",
                    user_id="operator_ro",
                    profile_id="p1",
                    scope=TaskScope(
                        facility_id="facility-a",
                        allowed_origins=(scada_origin, maint_origin),
                        allowed_areas=("area-1",),
                        read_only=True,
                    ),
                    query="Check bomba 34",
                )
            )
            res = await runtime.coordinator.run_until_settled(run.run_id)

        assert res.status == TaskStatus.PARTIAL
        assert len(res.contradictions) >= 1
        assert all(c.unresolved for c in res.contradictions)


@pytest.mark.acceptance
@pytest.mark.n2
async def test_a14_sigkill_preserves_budget_and_reconciles_reservation(tmp_path: Path) -> None:
    db_path = tmp_path / "a14.sqlite3"
    run_id = "run-acc-a14"

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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "READY_TO_KILL"
        os.kill(proc.pid, signal.SIGKILL)
        assert proc.wait(timeout=10.0) == -signal.SIGKILL

    await asyncio.to_thread(_kill_worker)
    await asyncio.sleep(1.2)

    rec = await asyncio.to_thread(
        subprocess.run,
        [
            sys.executable,
            "-m",
            "tests.integration._crash_worker",
            "--mode",
            "recover_a14",
            "--db-path",
            str(db_path),
            "--run-id",
            run_id,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rec.returncode == 0, rec.stderr
    data = json.loads(rec.stdout.strip())
    assert data["summary"]["expired_reservations_cleaned"] >= 1
    assert data["pre_usage"]["usage_estimated"] is True
    assert data["pre_usage"]["tokens_reserved"] == 0
    assert data["pre_signatures_count"] >= 1
    assert data["status"] == TaskStatus.SUCCEEDED.value
    assert data["within_limits"] is True


@pytest.mark.acceptance
@pytest.mark.n2
async def test_m5_comparative_benchmark_paired_emulated() -> None:
    report = await run_benchmarks(mode="emulated", repeats=1)
    assert report.engine_summary.num_scenarios >= 12
    assert report.engine_summary.total_trials == 13
    assert report.engine_summary.correct_answers == 13
    assert report.engine_summary.accuracy_rate == 1.0
    assert report.engine_summary.promotion_eligible is True
    assert report.engine_summary.duplicate_effects == 0
    assert report.engine_summary.isolation_violations == 0
    assert report.engine_summary.wrong_asset_attributions == 0
    assert report.baseline_summary.promotion_eligible is False
    assert report.baseline_summary.duplicate_effects >= 1
    assert report.baseline_summary.isolation_violations >= 1
    assert report.provenance.a11_status == "PENDING_N3_LINUX_ENV"
    assert report.a12_adaptation is not None
    assert report.a12_adaptation.engine_loc_delta == 0
    assert report.a12_adaptation.verified_succeeded is True
