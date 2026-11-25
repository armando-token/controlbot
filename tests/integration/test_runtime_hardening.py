"""N2 integration tests for runtime hardening: E10 takeover, A10 auth expiry, SIGKILL A08/A14."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sqlite3
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from lab.effect_sim import create_effect_sim_app
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import create_scada_app
from lab.testing import run_asgi_server
from src.adapters import MappingCredentialProvider, load_facility_config, make_session_id
from src.contracts.common import PlanValidationError, utc_now
from src.contracts.enums import BackendMode, EffectClass, ReceiptOutcome, TaskStatus
from src.contracts.models import TaskScope, TaskSpec, ToolSpec
from src.engine.coordinator import Coordinator, CoordinatorConfig
from src.engine.tool_registry import ToolExecutionContext, ToolRegistry
from src.model import (
    EmulatedModelClient,
    EmulatedTurn,
    ModelDecision,
    ModelProtocolError,
    ModelToolCall,
    ModelUsage,
)
from src.runtime import build_runtime
from src.storage.redaction import contains_unredacted_secret_strict
from src.storage.repo import StorageRepo

_FACILITY_A_PATH = Path("lab/configs/facility_a.json")


@pytest.mark.n2
async def test_runtime_e10_human_takeover_blocks_and_release_resumes(tmp_path: Path) -> None:
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

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "takeover.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            reference_time_fn=lambda: ref_time,
        )
        async with runtime, run_asgi_server(runtime.app) as web_origin:
            scada_sess = await runtime.session_manager.open_session(
                "operator_ro", "p1", "scada", (scada_origin,)
            )
            async with httpx.AsyncClient(base_url=web_origin, trust_env=False) as client:
                # 1. Put SCADA session under human takeover via Web API
                to_resp = await client.post(
                    f"/api/sessions/{scada_sess.session_id}/takeover",
                    json={"owner": "alice", "reason": "manual_inspection"},
                )
                assert to_resp.status_code == 200
                assert to_resp.json()["takeover_active"] is True

                # 2. Task while takeover active -> SCADA blocked with FAILED_PERMISSION
                sub1 = await client.post(
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
                assert sub1.status_code == 201
                run1_id = sub1.json()["run_id"]
                await runtime.web_coordinator.wait_for_run(run1_id, timeout=20.0)
                snap1 = (await client.get(f"/api/tasks/{run1_id}")).json()
                assert snap1["status"] == "partial"
                scada_receipts = [
                    r for r in snap1["receipts"] if r["tool_id"].startswith("scada.")
                ]
                assert scada_receipts
                assert all(
                    r["outcome"] == ReceiptOutcome.FAILED_PERMISSION.value for r in scada_receipts
                )

                # 3. Release takeover -> next task completes SUCCEEDED
                rel_resp = await client.post(
                    f"/api/sessions/{scada_sess.session_id}/release",
                    json={"owner": "alice"},
                )
                assert rel_resp.status_code == 200
                assert rel_resp.json()["takeover_active"] is False

                sub2 = await client.post(
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
                run2_id = sub2.json()["run_id"]
                await runtime.web_coordinator.wait_for_run(run2_id, timeout=20.0)
                snap2 = (await client.get(f"/api/tasks/{run2_id}")).json()
                assert snap2["status"] == "succeeded"
                assert "ALM-3401" in snap2["result"]["answer"]


@pytest.mark.n2
async def test_runtime_a10_auth_expiry_pauses_and_resume_reevaluates_and_completes(
    tmp_path: Path,
) -> None:
    ref_time = utc_now()
    scada_app = create_scada_app(fixture_mode="default")
    maint_app = create_maintenance_app(fixture_mode="default")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

    # First run succeeds, then session expires (auth_expired) and no auto re-login credentials
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
        async with runtime, run_asgi_server(runtime.app) as web_origin:
            # Force SCADA to auth_expired mode
            scada_app.state.scada_state.set_mode("auth_expired")

            async with httpx.AsyncClient(base_url=web_origin, trust_env=False) as client:
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
                assert sub.status_code == 201
                run_id = sub.json()["run_id"]
                await runtime.web_coordinator.wait_for_run(run_id, timeout=20.0)
                paused_snap = (await client.get(f"/api/tasks/{run_id}")).json()
                assert paused_snap["status"] == TaskStatus.WAITING_FOR_INPUT.value
                assert paused_snap["transition_reason"] == "auth_expired"
                assert "scada" in paused_snap["required_action"].lower()

                # Scope widening on resume must be rejected with 409
                widen = await client.post(
                    f"/api/tasks/{run_id}/resume",
                    json={"human_input": {"allowed_areas": ["area-1", "area-2"]}},
                )
                assert widen.status_code == 409

                # Takeover active blocks resume (permission_revalidator) -> 409
                scada_sid = make_session_id("operator_ro", "p1", "scada")
                await runtime.session_manager.request_takeover(scada_sid, owner="op1")
                blocked_resume = await client.post(
                    f"/api/tasks/{run_id}/resume",
                    json={"human_input": {"reauthenticated": True}},
                )
                assert blocked_resume.status_code == 409

                # Release takeover and restore SCADA auth -> resume completes SUCCEEDED
                await runtime.session_manager.release_takeover(scada_sid, owner="op1")
                scada_app.state.scada_state.set_mode("default")
                resumed = await client.post(
                    f"/api/tasks/{run_id}/resume",
                    json={"human_input": {"reauthenticated": True}},
                )
                assert resumed.status_code == 200
                await runtime.web_coordinator.wait_for_run(run_id, timeout=20.0)
                done_snap = (await client.get(f"/api/tasks/{run_id}")).json()
                assert done_snap["status"] == TaskStatus.SUCCEEDED.value
                assert "ALM-3401" in done_snap["result"]["answer"]
                assert "WO-3408" in done_snap["result"]["answer"]

                # Verify permission re-evaluation audit log exists
                audits = runtime.repo.list_audit_logs(task_id=done_snap["task"]["task_id"])
                assert any(a.action == "resume_permissions_reevaluated" for a in audits)


def _run_sigkill_worker_sync(
    *,
    mode: str,
    db_path: Path,
    run_id: str,
    effect_origin: str = "",
) -> int:
    cmd = [
        sys.executable,
        "-m",
        "tests.integration._crash_worker",
        "--mode",
        mode,
        "--db-path",
        str(db_path),
        "--run-id",
        run_id,
        "--effect-origin",
        effect_origin,
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    line = proc.stdout.readline().strip()
    if line != "READY_TO_KILL":
        err_out = proc.stderr.read() if proc.stderr else ""
        proc.kill()
        proc.wait(timeout=5.0)
        raise AssertionError(f"Unexpected worker output: {line!r} stderr={err_out}")
    os.kill(proc.pid, signal.SIGKILL)
    rc = proc.wait(timeout=10.0)
    assert rc == -signal.SIGKILL
    return rc


@pytest.mark.n2
async def test_runtime_a08_real_sigkill_crash_reconciles_single_apply(tmp_path: Path) -> None:
    state_path = tmp_path / "effect_sim_state.json"
    effect_app = create_effect_sim_app(state_path=state_path)
    db_path = tmp_path / "a08_sigkill.sqlite3"
    run_id = "run-a08-sigkill-1"

    async with run_asgi_server(effect_app) as effect_origin:
        await asyncio.to_thread(
            _run_sigkill_worker_sync,
            mode="run_a08",
            db_path=db_path,
            run_id=run_id,
            effect_origin=effect_origin,
        )
        # Wait past 1.0s lease TTL so lease genuinely expires
        await asyncio.sleep(1.2)

        # Verify EffectSim already applied once on disk before recovery
        assert effect_app.state.effect_sim_state.total_applied == 1
        assert effect_app.state.effect_sim_state.total_apply_requests == 1

        # Verify SQLite WAL integrity after SIGKILL
        conn = sqlite3.connect(db_path)
        try:
            integrity = conn.execute("PRAGMA integrity_check;").fetchone()
            assert integrity is not None and integrity[0] == "ok"
        finally:
            conn.close()

        # Spawn fresh recovery subprocess against same WAL DB and EffectSim
        rec_proc = await asyncio.to_thread(
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
        assert rec_proc.returncode == 0, rec_proc.stderr
        rec_data: dict[str, Any] = json.loads(rec_proc.stdout.strip())
        assert rec_data["summary"]["unknown_steps_reconciled"] == 1
        assert rec_data["status"] == TaskStatus.SUCCEEDED.value
        assert rec_data["step_statuses"] == ["succeeded"]
        assert rec_data["tool_calls_used"] == 1
        # Zero duplicate side-effect replay!
        assert effect_app.state.effect_sim_state.total_applied == 1
        assert effect_app.state.effect_sim_state.total_apply_requests == 1


@pytest.mark.n2
async def test_runtime_a14_real_sigkill_preserves_budget_and_loop_signatures(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "a14_sigkill.sqlite3"
    run_id = "run-a14-sigkill-1"

    await asyncio.to_thread(
        _run_sigkill_worker_sync,
        mode="run_a14",
        db_path=db_path,
        run_id=run_id,
    )
    await asyncio.sleep(1.2)

    rec_proc = await asyncio.to_thread(
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
    assert rec_proc.returncode == 0, rec_proc.stderr
    rec_data: dict[str, Any] = json.loads(rec_proc.stdout.strip())
    assert rec_data["summary"]["expired_reservations_cleaned"] >= 1
    assert rec_data["pre_usage"]["usage_estimated"] is True
    assert rec_data["pre_usage"]["tokens_reserved"] == 0
    assert rec_data["pre_usage"]["tool_calls_used"] >= 1
    assert rec_data["pre_usage"]["model_calls_used"] >= 2
    assert rec_data["pre_signatures_count"] >= 1
    assert rec_data["status"] == TaskStatus.SUCCEEDED.value
    assert rec_data["within_limits"] is True


@pytest.mark.n2
async def test_web_http_exception_scrubbing_and_conflict_status_codes(tmp_path: Path) -> None:
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
            db_path=tmp_path / "web_seam.sqlite3",
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
                secret = "TOP_SECRET_ERR_999"
                bad_id = f"Bearer {secret}"
                for method, url, json_body in (
                    ("GET", f"/api/tasks/{bad_id}", None),
                    ("POST", f"/api/tasks/{bad_id}/cancel", None),
                    ("POST", f"/api/tasks/{bad_id}/resume", {"human_input": {}}),
                    ("POST", f"/api/sessions/{bad_id}/takeover", None),
                    ("POST", f"/api/sessions/{bad_id}/release", None),
                ):
                    resp = (
                        await client.request(method, url, json=json_body)
                        if json_body is not None
                        else await client.request(method, url)
                    )
                    assert resp.status_code == 404
                    assert secret not in resp.text

                sub1 = await client.post(
                    "/api/tasks",
                    json={
                        "task_id": "dup-task-1",
                        "user_id": "operator_ro",
                        "profile_id": "p1",
                        "facility_id": "facility-a",
                        "allowed_origins": [scada_origin, maint_origin],
                        "query": "Check bomba 34",
                    },
                )
                assert sub1.status_code == 201
                run1_id = sub1.json()["run_id"]

                # Duplicate task_id -> 409 Conflict (not 500)
                dup = await client.post(
                    "/api/tasks",
                    json={
                        "task_id": "dup-task-1",
                        "user_id": "operator_ro",
                        "profile_id": "p1",
                        "facility_id": "facility-a",
                        "query": "Duplicate",
                    },
                )
                assert dup.status_code == 409

                # Wait for ambiguity pause and verify allowed_origins widening -> 409
                await runtime.web_coordinator.wait_for_run(run1_id, timeout=20.0)
                widen_origin = await client.post(
                    f"/api/tasks/{run1_id}/resume",
                    json={"human_input": {"allowed_origins": ["http://127.0.0.1:9999"]}},
                )
                assert widen_origin.status_code == 409

                # List tasks returns snapshots
                listed = await client.get("/api/tasks")
                assert listed.status_code == 200
                assert any(t["run"]["run_id"] == run1_id for t in listed.json()["tasks"])


@pytest.mark.n2
async def test_runtime_rejects_local_http_task_on_emulated_runtime_with_409(
    tmp_path: Path,
) -> None:
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

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        with pytest.raises(ModelProtocolError, match="silent fallback"):
            build_runtime(
                db_path=tmp_path / "mismatch.sqlite3",
                profile_root=tmp_path / "profiles_mismatch",
                facility_config=cfg,
                credential_provider=creds,
                backend_mode=BackendMode.LOCAL_HTTP,
                model_client=EmulatedModelClient(mode="happy_path"),
            )

        runtime = build_runtime(
            db_path=tmp_path / "emulated_only.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            backend_mode=BackendMode.EMULATED,
            reference_time_fn=lambda: ref_time,
        )
        assert isinstance(runtime.model_client, EmulatedModelClient)

        async with (
            runtime,
            run_asgi_server(runtime.app) as web_origin,
            httpx.AsyncClient(base_url=web_origin, trust_env=False) as client,
        ):
            resp = await client.post(
                "/api/tasks",
                json={
                    "user_id": "operator_ro",
                    "profile_id": "p1",
                    "facility_id": "facility-a",
                    "allowed_origins": [scada_origin, maint_origin],
                    "allowed_areas": ["area-1"],
                    "backend_mode": "local_http",
                    "query": "Check bomba 34",
                },
            )
            assert resp.status_code == 409
            assert "LocalHttpModelClient" in resp.text
            assert runtime.model_client.call_history == []

            spec = TaskSpec(
                task_id="task-direct-mismatch",
                user_id="operator_ro",
                profile_id="p1",
                scope=TaskScope(
                    facility_id="facility-a",
                    allowed_origins=(scada_origin, maint_origin),
                    allowed_areas=("area-1",),
                    read_only=True,
                ),
                query="Check bomba 34",
                backend_mode=BackendMode.LOCAL_HTTP,
            )
            with pytest.raises(PlanValidationError, match="LocalHttpModelClient"):
                runtime.coordinator.submit_task(spec)

            # Even if persisted directly in storage, _run_loop must fail closed
            _, bypassed_run = runtime.repo.create_task_and_run(spec)
            with pytest.raises(PlanValidationError, match="LocalHttpModelClient"):
                await runtime.coordinator.run_until_settled(bypassed_run.run_id)
            assert runtime.model_client.call_history == []


@pytest.mark.n2
async def test_web_strict_redaction_on_404_409_and_html_responses(tmp_path: Path) -> None:
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

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "strict_redaction.sqlite3",
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
            for method, path, expected_redacted, forbidden in (
                ("GET", "/api/tasks/token%3Dxyz", "token=[REDACTED]", "token=xyz"),
                ("POST", "/api/tasks/token%3Dxyz/cancel", "token=[REDACTED]", "token=xyz"),
                ("POST", "/api/sessions/token%3Dxyz/takeover", "token=[REDACTED]", "token=xyz"),
                ("GET", "/tasks/token%3Dxyz", "token=[REDACTED]", "token=xyz"),
                (
                    "GET",
                    "/api/tasks/password%3Dsupersecret99",
                    "password=[REDACTED]",
                    "supersecret99",
                ),
                (
                    "GET",
                    "/api/tasks/api_key%3Dsk-live-999",
                    "api_key=[REDACTED]",
                    "sk-live-999",
                ),
            ):
                resp = await client.request(method, path)
                assert resp.status_code == 404
                assert forbidden not in resp.text
                assert expected_redacted in resp.text

            sess = await runtime.session_manager.open_session(
                "operator_ro", "p1", "scada", (scada_origin,)
            )
            first_to = await client.post(
                f"/api/sessions/{sess.session_id}/takeover",
                json={"owner": "token=xyz", "reason": "manual"},
            )
            assert first_to.status_code == 200
            assert "token=xyz" not in first_to.text
            assert "token=[REDACTED]" in first_to.text

            conflict_to = await client.post(
                f"/api/sessions/{sess.session_id}/takeover",
                json={"owner": "bob", "reason": "conflict"},
            )
            assert conflict_to.status_code == 409
            assert "token=xyz" not in conflict_to.text
            assert "token=[REDACTED]" in conflict_to.text


@pytest.mark.n2
async def test_runtime_inline_secret_in_query_scrubbed_for_prompt_context_and_settles(
    tmp_path: Path,
) -> None:
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

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "query_secret.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            reference_time_fn=lambda: ref_time,
        )
        assert isinstance(runtime.model_client, EmulatedModelClient)

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
                    "query": "check bomba 34 token=xyz",
                },
            )
            assert sub.status_code == 201
            run_id = sub.json()["run_id"]
            await runtime.web_coordinator.wait_for_run(run_id, timeout=20.0)
            snap_resp = await client.get(f"/api/tasks/{run_id}")
            assert snap_resp.status_code == 200
            assert "token=xyz" not in snap_resp.text
            snap = snap_resp.json()
            assert snap["status"] == TaskStatus.SUCCEEDED.value
            assert not contains_unredacted_secret_strict(snap)
            assert runtime.model_client.call_history
            assert all(
                ctx.query == "check bomba 34 token=[REDACTED]"
                for ctx in runtime.model_client.call_history
            )


@pytest.mark.n2
async def test_web_rejects_invalid_or_secret_task_user_profile_ids_without_stranding_runs(
    tmp_path: Path,
) -> None:
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

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "invalid_ids.sqlite3",
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
            bad_payloads = [
                (
                    {
                        "user_id": "operator_ro",
                        "profile_id": "password=secret",
                        "facility_id": "facility-a",
                        "allowed_origins": [scada_origin, maint_origin],
                        "allowed_areas": ["area-1"],
                        "query": "check bomba 34",
                    },
                    422,
                    True,
                ),
                (
                    {
                        "user_id": "password=secret",
                        "profile_id": "p1",
                        "facility_id": "facility-a",
                        "allowed_origins": [scada_origin, maint_origin],
                        "allowed_areas": ["area-1"],
                        "query": "check bomba 34",
                    },
                    422,
                    True,
                ),
                (
                    {
                        "user_id": "operator_ro",
                        "profile_id": "../evil",
                        "facility_id": "facility-a",
                        "allowed_origins": [scada_origin, maint_origin],
                        "allowed_areas": ["area-1"],
                        "query": "check bomba 34",
                    },
                    422,
                    False,
                ),
                (
                    {
                        "task_id": "password=secret",
                        "user_id": "operator_ro",
                        "profile_id": "p1",
                        "facility_id": "facility-a",
                        "allowed_origins": [scada_origin, maint_origin],
                        "allowed_areas": ["area-1"],
                        "query": "check bomba 34",
                    },
                    409,
                    False,
                ),
            ]
            for payload, expected_status, expect_redacted in bad_payloads:
                resp = await client.post("/api/tasks", json=payload)
                assert resp.status_code == expected_status
                assert "password=secret" not in resp.text
                assert not contains_unredacted_secret_strict(resp.json())
                if expect_redacted:
                    assert "password=[REDACTED]" in resp.text

            # Direct adapter submit_task also rejects unsafe segments with PlanValidationError
            with pytest.raises(PlanValidationError):
                runtime.web_coordinator.submit_task(
                    TaskSpec(
                        task_id="task-bad-seg",
                        user_id="operator_ro",
                        profile_id="../evil",
                        scope=TaskScope(
                            facility_id="facility-a",
                            allowed_origins=(scada_origin, maint_origin),
                            allowed_areas=("area-1",),
                        ),
                        query="check bomba 34",
                    )
                )

            listed = (await client.get("/api/tasks")).json()
            assert listed["tasks"] == []


@pytest.mark.n2
async def test_web_422_validation_error_scrubs_secrets_in_evidence_requirements(
    tmp_path: Path,
) -> None:
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

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "validation_422.sqlite3",
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
            r1 = await client.post(
                "/api/tasks",
                json={
                    "query": "check bomba 34",
                    "evidence_requirements": {"password=secret": 1},
                },
            )
            assert r1.status_code == 422
            assert "password=secret" not in r1.text
            assert "password=[REDACTED]" in r1.text
            assert not contains_unredacted_secret_strict(r1.json())

            r2 = await client.post(
                "/api/tasks",
                json={
                    "query": "check bomba 34",
                    "evidence_requirements": {"min_sources": "password=secret"},
                },
            )
            assert r2.status_code == 422
            assert "password=secret" not in r2.text
            assert "password=[REDACTED]" in r2.text
            assert not contains_unredacted_secret_strict(r2.json())

            r3 = await client.post(
                "/api/tasks",
                json={
                    "query": "check bomba 34",
                    "evidence_requirements": {"password": "raw_secret_val_99"},
                },
            )
            assert r3.status_code == 422
            assert "raw_secret_val_99" not in r3.text
            assert "[REDACTED]" in r3.text
            assert not contains_unredacted_secret_strict(r3.json())


@pytest.mark.n2
async def test_coordinator_run_loop_settles_failed_on_unexpected_step_value_error(
    tmp_path: Path,
) -> None:
    repo = StorageRepo(tmp_path / "coord_defense.sqlite3")
    repo.init_db()

    registry = ToolRegistry()
    tool_spec = ToolSpec(
        tool_id="scada.read_alarms",
        version="1.0.0",
        input_schema={"type": "object", "properties": {}, "additionalProperties": True},
        output_schema={"type": "object", "properties": {}, "additionalProperties": True},
        permissions=(),
        allowed_origins=("http://127.0.0.1:9001",),
        effect_class=EffectClass.READ,
        verifier_name="default_verifier",
    )

    async def _handler(_args: dict[str, Any], _ctx: ToolExecutionContext) -> dict[str, Any]:
        return {"output": {"ok": True}}

    registry.register(tool_spec, _handler)

    model = EmulatedModelClient(
        mode="custom",
        turn_factory=lambda _ctx, _tools, _rem: EmulatedTurn(
            decision=ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id="scada.read_alarms",
                    args={"asset": "bomba 34"},
                    target_origin="http://127.0.0.1:9001",
                    completion_verifier="default_verifier",
                ),
                usage=ModelUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            )
        ),
    )

    def _failing_resolver(_task: TaskSpec, _tool_id: str) -> str | None:
        raise ValueError("Invalid profile_id segment for profile path: 'password=secret'")

    coord = Coordinator(
        repo,
        model,
        registry,
        config=CoordinatorConfig(),
        session_id_resolver=_failing_resolver,
    )

    # Bypass submit_task directly via StorageRepo to verify _run_loop defense-in-depth
    spec = TaskSpec(
        task_id="task-defense-1",
        user_id="operator_ro",
        profile_id="password=secret",
        scope=TaskScope(
            facility_id="facility-a",
            allowed_origins=("http://127.0.0.1:9001",),
            allowed_areas=("area-1",),
        ),
        query="check bomba 34",
    )
    _, run = repo.create_task_and_run(spec)
    result = await coord.run_until_settled(run.run_id)

    assert result.status == TaskStatus.FAILED
    assert "password=secret" not in result.answer
    assert "password=[REDACTED]" in result.answer

    snap = repo.get_run_snapshot(run.run_id)
    assert snap.run.status == TaskStatus.FAILED
    assert snap.run.transition_reason == "unexpected_execution_error"
    assert repo.list_active_reservations() == []
    audits = repo.list_audit_logs(task_id=spec.task_id)
    assert any(a.action == "unexpected_execution_error" for a in audits)
    assert not contains_unredacted_secret_strict([a.model_dump() for a in audits])


@pytest.mark.n2
async def test_web_422_and_tool_registry_scrub_secret_dict_keys_and_auth_tokens(
    tmp_path: Path,
) -> None:
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

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        runtime = build_runtime(
            db_path=tmp_path / "dict_keys_422.sqlite3",
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
            r_nested = await client.post(
                "/api/tasks",
                json={
                    "query": "check bomba 34",
                    "evidence_requirements": {"min_sources": {"password=secret": 1}},
                },
            )
            assert r_nested.status_code == 422
            assert "password=secret" not in r_nested.text
            assert "password=[REDACTED]" in r_nested.text
            assert not contains_unredacted_secret_strict(r_nested.json())

            r_extra = await client.post(
                "/api/tasks",
                json={
                    "query": "check bomba 34",
                    "extra_obj": {
                        "api_key=sk-live-999": 1,
                        "Bearer topsecret": 2,
                        "token=xyz": 3,
                    },
                },
            )
            assert r_extra.status_code == 422
            for raw in ("api_key=sk-live-999", "sk-live-999", "Bearer topsecret", "token=xyz"):
                assert raw not in r_extra.text
            assert not contains_unredacted_secret_strict(r_extra.json())

            r_auth = await client.post(
                "/api/tasks",
                json={
                    "query": "check bomba 34",
                    "user_id": "authorization=topsecret",
                },
            )
            assert r_auth.status_code == 422
            assert "topsecret" not in r_auth.text
            assert "authorization=[REDACTED]" in r_auth.text
            assert not contains_unredacted_secret_strict(r_auth.json())

    # Verify ToolRegistry.invoke scrubs secret-bearing dict keys before ActionReceipt storage
    repo = StorageRepo(tmp_path / "tool_dict_keys.sqlite3")
    repo.init_db()
    spec = TaskSpec(
        task_id="task-tool-dict-key",
        user_id="operator_ro",
        profile_id="p1",
        scope=TaskScope(
            facility_id="facility-a",
            allowed_origins=("http://127.0.0.1:9001",),
            allowed_areas=("area-1",),
            allowed_tools=("dummy.tool",),
        ),
        query="check bomba 34",
    )
    _, run = repo.create_task_and_run(spec)
    step = repo.enqueue_step(run.run_id, "dummy.tool", {}, "default_verifier", EffectClass.READ)

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            tool_id="dummy.tool",
            version="1.0.0",
            input_schema={"type": "object", "properties": {}, "additionalProperties": True},
            output_schema={"type": "object", "properties": {}, "additionalProperties": True},
            allowed_origins=("http://127.0.0.1:9001",),
            effect_class=EffectClass.READ,
            verifier_name="default_verifier",
        ),
        lambda _args, _ctx: {"output": {"ok": True}},
    )
    ctx = ToolExecutionContext(
        task_id=spec.task_id,
        run_id=run.run_id,
        step_id=step.step_id,
        attempt=1,
        operation_key=step.operation_key,
        scope=spec.scope,
        target_origin="http://127.0.0.1:9001",
        deadline_at=utc_now() + timedelta(seconds=30),
    )
    tool_res = await registry.invoke(
        "dummy.tool",
        {"password=secret": 1, "Bearer topsecret": 2, "cookie=abc": "set_cookie=xyz"},
        ctx,
    )
    assert tool_res.receipt.redacted_args == {
        "password=[REDACTED]": 1,
        "Bearer [REDACTED]": 2,
        "cookie=[REDACTED]": "set_cookie=[REDACTED]",
    }
    assert not contains_unredacted_secret_strict(tool_res.receipt.model_dump())
    repo.append_receipt(tool_res.receipt)
    stored = repo.get_run_snapshot(run.run_id).receipts
    assert len(stored) == 1
    assert stored[0].redacted_args == {
        "password=[REDACTED]": 1,
        "Bearer [REDACTED]": 2,
        "cookie=[REDACTED]": "set_cookie=[REDACTED]",
    }

