"""N2 real HTTP + Playwright integration tests for src/web local operator API & UI."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from lab.scada_app import create_scada_app
from lab.testing import run_asgi_server
from playwright.async_api import async_playwright
from src.adapters import SessionManager
from src.contracts.budgets import BudgetUsage
from src.contracts.common import utc_now
from src.contracts.enums import DataQuality, ReceiptOutcome, TaskStatus
from src.contracts.models import (
    ActionReceipt,
    ContradictionClaim,
    ContradictionRecord,
    ExecutionMetrics,
    Observation,
    Result,
)
from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.web import InMemoryCoordinatorStub, create_app


@pytest.mark.n2
async def test_web_api_lifecycle_budget_receipts_and_takeover(tmp_path: Path) -> None:
    scada_app = create_scada_app(fixture_mode="default")
    coordinator = InMemoryCoordinatorStub()

    async with (
        run_asgi_server(scada_app) as scada_origin,
        SessionManager(tmp_path / "profiles", headless=True) as session_mgr,
    ):
        sess = await session_mgr.open_session("operator_a1", "prof1", "scada", (scada_origin,))
        web_app = create_app(
            db_path=tmp_path / "grokbot.sqlite3",
            coordinator=coordinator,
            session_manager=session_mgr,
        )

        async with (
            run_asgi_server(web_app) as web_origin,
            httpx.AsyncClient(base_url=web_origin) as client,
        ):
            # Health
            health = await client.get("/health")
            assert health.status_code == 200
            assert health.json()["status"] == "ok"

            # Submit task -> 201
            submit = await client.post(
                "/api/tasks",
                json={
                    "user_id": "operator_a1",
                    "profile_id": "prof1",
                    "facility_id": "facility-a",
                    "allowed_origins": [scada_origin],
                    "query": "Diagnose bomba 34",
                },
            )
            assert submit.status_code == 201
            run_id = submit.json()["run_id"]

            # Unknown run -> 404
            assert (await client.get("/api/tasks/run-missing")).status_code == 404

            # Resume when not waiting_for_input -> 409
            bad_resume = await client.post(
                f"/api/tasks/{run_id}/resume",
                json={"human_input": {"choice": "area-1"}},
            )
            assert bad_resume.status_code == 409

            # Move run -> running -> waiting_for_input, then resume -> running
            coordinator.transition_run(run_id, TaskStatus.RUNNING, "started_execution")
            coordinator.transition_run(
                run_id,
                TaskStatus.WAITING_FOR_INPUT,
                "ambiguous_asset",
                required_action="Select area-1 or area-2",
            )
            resumed = await client.post(
                f"/api/tasks/{run_id}/resume",
                json={"human_input": {"choice": "area-1"}},
            )
            assert resumed.status_code == 200
            assert resumed.json()["status"] == "running"

            # Attach redacted receipt, estimated budget, partial_info, and contradiction -> PARTIAL
            now = utc_now()
            receipt = ActionReceipt(
                receipt_id="rcpt-1",
                task_id=submit.json()["task_id"],
                run_id=run_id,
                step_id="step-1",
                attempt=1,
                tool_id="scada.read_alarms",
                redacted_args={"password": REDACTED_PLACEHOLDER, "asset": "bomba 34"},
                operation_key="op-1",
                duration_ms=12.5,
                outcome=ReceiptOutcome.SUCCEEDED,
            )
            obs = Observation(
                source="scada",
                session_id=sess.session_id,
                asset_id="bomba-34-a1",
                observed_label="bomba 34",
                value="HIGH_VIBRATION",
                unit="alarm_code",
                source_time=now,
                quality=DataQuality.GOOD,
                area="area-1",
            )
            contradiction = ContradictionRecord(
                summary="Cross-source mismatch",
                claims=(
                    ContradictionClaim(
                        source="scada",
                        asset_id="bomba-34-a1",
                        field="asset_id",
                        value="bomba-34-a1",
                    ),
                    ContradictionClaim(
                        source="maintenance",
                        asset_id="bomba-99-a1",
                        field="asset_id",
                        value="bomba-99-a1",
                    ),
                ),
            )
            result = Result(
                task_id=submit.json()["task_id"],
                run_id=run_id,
                status=TaskStatus.PARTIAL,
                answer="Partial cross-source result with unresolved conflict.",
                verified_observations=(obs,),
                partial_info={"available_sources": ["scada"], "missing_sources": ["maintenance"]},
                contradictions=(contradiction,),
                execution_metrics=ExecutionMetrics(
                    tool_calls=1,
                    model_calls=1,
                    usage_estimated=True,
                ),
            )
            coordinator.transition_run(
                run_id,
                TaskStatus.PARTIAL,
                "contradiction_and_partial",
                progress=1.0,
                result=result,
                receipts=(receipt,),
                budget_usage=BudgetUsage(
                    tool_calls_used=1,
                    model_calls_used=1,
                    prompt_tokens_used=120,
                    completion_tokens_used=45,
                    usage_estimated=True,
                ),
            )

            detail = await client.get(f"/api/tasks/{run_id}")
            assert detail.status_code == 200
            body = detail.json()
            assert body["status"] == "partial"
            assert body["last_transition"]["to_status"] == "partial"
            assert body["transition_reason"] == "contradiction_and_partial"
            assert body["budget"]["usage_estimated"] is True
            assert body["budget"]["usage"]["tool_calls_used"] == 1
            assert body["receipts"][0]["redacted_args"]["password"] == REDACTED_PLACEHOLDER
            assert len(body["result"]["contradictions"]) == 1
            assert body["result"]["partial_info"]["missing_sources"] == ["maintenance"]

            # Cancel on terminal PARTIAL run -> 409
            bad_cancel = await client.post(f"/api/tasks/{run_id}/cancel", json={"reason": "late"})
            assert bad_cancel.status_code == 409

            # Submit second task and cancel cleanly -> 200
            submit2 = await client.post("/api/tasks", json={"query": "Cancelable task"})
            run2_id = submit2.json()["run_id"]
            cancelled = await client.post(f"/api/tasks/{run2_id}/cancel", json={"reason": "stop"})
            assert cancelled.status_code == 200
            assert cancelled.json()["status"] == "cancelled"

            # Session takeover conflicts while lease active, succeeds when idle, releases cleanly
            async with session_mgr.acquire_lease(sess.session_id):
                conflict = await client.post(
                    f"/api/sessions/{sess.session_id}/takeover",
                    json={"owner": "op1", "reason": "login"},
                )
                assert conflict.status_code == 409

            takeover = await client.post(
                f"/api/sessions/{sess.session_id}/takeover",
                json={"owner": "op1", "reason": "login"},
            )
            assert takeover.status_code == 200
            assert takeover.json()["takeover_active"] is True

            bad_release = await client.post(
                f"/api/sessions/{sess.session_id}/release",
                json={"owner": "wrong_op"},
            )
            assert bad_release.status_code == 409

            released = await client.post(
                f"/api/sessions/{sess.session_id}/release",
                json={"owner": "op1"},
            )
            assert released.status_code == 200
            assert released.json()["takeover_active"] is False

            assert (await client.post("/api/sessions/missing/takeover")).status_code == 404


@pytest.mark.n2
async def test_web_ui_playwright_form_submission_and_xss_escaping(tmp_path: Path) -> None:
    web_app = create_app(db_path=tmp_path / "ui.sqlite3")

    async with (
        run_asgi_server(web_app) as web_origin,
        async_playwright() as pw,
    ):
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        external_requests: list[str] = []

        async def _check_origin(route: object) -> None:
            # Verify zero external CDN requests are ever attempted by the UI
            from playwright.async_api import Route

            assert isinstance(route, Route)
            if not route.request.url.startswith(web_origin):
                external_requests.append(route.request.url)
                await route.abort()
            else:
                await route.continue_()

        await context.route("**/*", _check_origin)
        page = await context.new_page()

        xss_probe = "<script>window.__xss=1</script>Check bomba 34"
        await page.goto(f"{web_origin}/", wait_until="domcontentloaded")
        await page.get_by_label("Task Query").fill(xss_probe)
        async with page.expect_navigation(wait_until="domcontentloaded"):
            await page.get_by_role("button", name="Submit Task").click()

        assert "/tasks/run-" in page.url
        assert await page.evaluate("Boolean(window.__xss)") is False
        assert xss_probe in await page.locator("main").inner_text()
        assert await page.locator("[data-testid='task-status']").inner_text() == "queued"
        assert external_requests == []

        await context.close()
        await browser.close()


@pytest.mark.n2
async def test_web_api_and_ui_secret_redaction_release_owner_and_blank_query(
    tmp_path: Path,
) -> None:
    scada_app = create_scada_app(fixture_mode="default")
    coordinator = InMemoryCoordinatorStub()

    secret_url = "SUP3R_S3CR3T_URLPASS_000"
    secret_bearer = "SUP3R_S3CR3T_BEARER_XYZ"
    secret_pass = "SUP3R_S3CR3T_PASS_123"
    secret_token = "SUP3R_S3CR3T_TOKEN_456"
    secret_access = "SUP3R_S3CR3T_ACCESSTOKEN_789"
    secret_sess = "SUP3R_S3CR3T_SESS_999"
    all_secrets = (
        secret_url,
        secret_bearer,
        secret_pass,
        secret_token,
        secret_access,
        secret_sess,
    )

    async with (
        run_asgi_server(scada_app) as scada_origin,
        SessionManager(tmp_path / "profiles", headless=True) as session_mgr,
    ):
        sess = await session_mgr.open_session("operator_a1", "prof1", "scada", (scada_origin,))
        web_app = create_app(
            db_path=tmp_path / "redaction.sqlite3",
            coordinator=coordinator,
            session_manager=session_mgr,
        )

        async with (
            run_asgi_server(web_app) as web_origin,
            httpx.AsyncClient(base_url=web_origin) as client,
        ):
            # Submit task with secrets in task_id and query
            submit = await client.post(
                "/api/tasks",
                json={
                    "task_id": f"task-http://admin:{secret_url}@scada.local/api",
                    "user_id": "operator_a1",
                    "profile_id": "prof1",
                    "query": f"Check Bearer {secret_bearer}",
                },
            )
            assert submit.status_code == 201
            assert secret_url not in submit.text
            run_id = submit.json()["run_id"]

            # Move through waiting_for_input & resume with Bearer secret
            coordinator.transition_run(run_id, TaskStatus.RUNNING, f"Bearer {secret_bearer}")
            coordinator.transition_run(
                run_id,
                TaskStatus.WAITING_FOR_INPUT,
                f"Bearer {secret_bearer}",
                required_action=f"Check http://op:{secret_url}@scada.local",
            )
            resumed = await client.post(
                f"/api/tasks/{run_id}/resume",
                json={"human_input": {"choice": f"Bearer {secret_bearer}"}},
            )
            assert resumed.status_code == 200
            assert secret_bearer not in resumed.text
            assert secret_url not in resumed.text

            # Attach Result containing secrets in answer + partial_info + contradictions
            result = Result(
                task_id=submit.json()["task_id"],
                run_id=run_id,
                status=TaskStatus.PARTIAL,
                answer=f"Diagnostic Bearer {secret_bearer}",
                partial_info={
                    "password": secret_pass,
                    "token": secret_token,
                    "accessToken": secret_access,
                    "sessionToken": secret_sess,
                },
                contradictions=(
                    ContradictionRecord(
                        summary=f"Conflict Bearer {secret_bearer}",
                        claims=(
                            ContradictionClaim(
                                source="scada",
                                asset_id="bomba-34-a1",
                                field="endpoint",
                                value=f"http://u:{secret_url}@scada.local",
                            ),
                            ContradictionClaim(
                                source="maintenance",
                                asset_id="bomba-99-a1",
                                field="endpoint",
                                value="http://maint.local",
                            ),
                        ),
                    ),
                ),
            )
            coordinator.transition_run(
                run_id,
                TaskStatus.PARTIAL,
                f"done Bearer {secret_bearer}",
                progress=1.0,
                result=result,
            )

            # Cancelable second task with secret in cancel reason
            submit2 = await client.post(
                "/api/tasks",
                json={
                    "task_id": f"task2-http://admin:{secret_url}@scada.local/api",
                    "query": "Second task",
                },
            )
            assert submit2.status_code == 201
            assert secret_url not in submit2.text
            run2_id = submit2.json()["run_id"]
            cancelled = await client.post(
                f"/api/tasks/{run2_id}/cancel",
                json={"reason": f"Bearer {secret_bearer}"},
            )
            assert cancelled.status_code == 200
            assert secret_bearer not in cancelled.text
            assert secret_url not in cancelled.text

            # Session takeover with secret reason + release ownership enforcement
            takeover = await client.post(
                f"/api/sessions/{sess.session_id}/takeover",
                json={"owner": "alice", "reason": f"Bearer {secret_bearer}"},
            )
            assert takeover.status_code == 200
            assert secret_bearer not in takeover.text

            # Empty {} or missing body must NOT bypass takeover ownership -> 409
            release_empty_json = await client.post(
                f"/api/sessions/{sess.session_id}/release",
                json={},
            )
            assert release_empty_json.status_code == 409

            release_no_body = await client.post(f"/api/sessions/{sess.session_id}/release")
            assert release_no_body.status_code == 409

            # Verify zero secrets across JSON endpoints and HTML UI pages
            for path in (
                f"/api/tasks/{run_id}",
                "/api/tasks",
                "/api/sessions",
                "/",
                f"/tasks/{run_id}",
            ):
                resp = await client.get(path)
                assert resp.status_code == 200
                for secret_val in all_secrets:
                    assert secret_val not in resp.text, f"Leaked secret in {path}"

            # Owner can release cleanly
            released = await client.post(
                f"/api/sessions/{sess.session_id}/release",
                json={"owner": "alice"},
            )
            assert released.status_code == 200
            assert released.json()["takeover_active"] is False

            # POST /ui/tasks with blank/whitespace query redirects 303 to /?error=... (never 500)
            blank_ui = await client.post(
                "/ui/tasks",
                data={"query": "   ", "facility_id": "facility-a"},
                follow_redirects=False,
            )
            assert blank_ui.status_code == 303
            assert blank_ui.headers["location"].startswith("/?error=")
            err_page = await client.get(blank_ui.headers["location"])
            assert err_page.status_code == 200
            assert "error-banner" in err_page.text


@pytest.mark.tier5
@pytest.mark.n2
async def test_t5_01_ui_submit_enforces_origin_and_config_gates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    web_app = create_app(db_path=tmp_path / "ui_gate.sqlite3")
    async with (
        run_asgi_server(web_app) as web_origin,
        httpx.AsyncClient(base_url=web_origin, trust_env=False) as client,
    ):
        resp_ext = await client.post(
            "/ui/tasks",
            data={
                "query": "Check bomba 34",
                "facility_id": "facility-a",
                "allowed_origins": "https://evil.example.com",
            },
            follow_redirects=False,
        )
        assert resp_ext.status_code == 303
        assert resp_ext.headers["location"].startswith("/?error=")
        assert (await client.get("/api/tasks")).json()["tasks"] == []

    # With GROKBOT_INSTALLATION_CONFIG active, unconfigured loopback origin is also rejected
    scada_app = create_scada_app(fixture_mode="default")
    async with run_asgi_server(scada_app) as scada_origin:
        from src.adapters.config import load_facility_config

        cfg_obj = load_facility_config(
            Path("lab/configs/facility_a.json"),
            origin_overrides={"scada": scada_origin},
        )
        cfg_path = tmp_path / "facility_t5_01.json"
        cfg_path.write_text(cfg_obj.model_dump_json(indent=2), encoding="utf-8")
        monkeypatch.setenv("GROKBOT_DB_PATH", str(tmp_path / "ui_cfg.sqlite3"))
        monkeypatch.setenv("GROKBOT_PROFILE_ROOT", str(tmp_path / "profiles"))
        monkeypatch.setenv("GROKBOT_INSTALLATION_CONFIG", str(cfg_path))
        web_cfg_app = create_app()
        async with (
            web_cfg_app.router.lifespan_context(web_cfg_app),
            run_asgi_server(web_cfg_app) as web_cfg_origin,
            httpx.AsyncClient(base_url=web_cfg_origin, trust_env=False) as client2,
        ):
            resp_loop = await client2.post(
                "/ui/tasks",
                data={
                    "query": "Check bomba 34",
                    "facility_id": "facility-a",
                    "allowed_origins": "http://127.0.0.1:19999",
                },
                follow_redirects=False,
            )
            assert resp_loop.status_code == 303
            assert resp_loop.headers["location"].startswith("/?error=")
            assert (await client2.get("/api/tasks")).json()["tasks"] == []


@pytest.mark.tier5
@pytest.mark.n2
async def test_t5_02_api_submit_rejects_unconfigured_origin_under_partial_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scada_origin = "http://127.0.0.1:18101"
    maint_origin = "http://127.0.0.1:18102"
    monkeypatch.setenv("GROKBOT_DB_PATH", str(tmp_path / "partial_override.sqlite3"))
    monkeypatch.setenv("GROKBOT_PROFILE_ROOT", str(tmp_path / "profiles_partial"))
    monkeypatch.setenv("GROKBOT_SCADA_URL", scada_origin)
    monkeypatch.setenv("GROKBOT_MAINTENANCE_URL", maint_origin)
    monkeypatch.setenv("GROKBOT_ALLOWED_ORIGINS", f"{scada_origin},{maint_origin}")
    monkeypatch.delenv("GROKBOT_EFFECT_SIM_URL", raising=False)
    monkeypatch.delenv("GROKBOT_INSTALLATION_CONFIG", raising=False)

    app1 = create_app()
    async with (
        app1.router.lifespan_context(app1),
        run_asgi_server(app1) as origin1,
        httpx.AsyncClient(base_url=origin1, trust_env=False) as client1,
    ):
        bad = await client1.post(
            "/api/tasks",
            json={
                "user_id": "operator_ro",
                "profile_id": "p1",
                "facility_id": "facility-a",
                "allowed_origins": ["http://127.0.0.1:19999"],
                "query": "Check bomba 34",
            },
        )
        assert bad.status_code == 422

    # GROKBOT_ALLOWED_ORIGINS alone (no app URL overrides) also enforces configured_origins
    monkeypatch.delenv("GROKBOT_SCADA_URL", raising=False)
    monkeypatch.delenv("GROKBOT_MAINTENANCE_URL", raising=False)
    monkeypatch.setenv("GROKBOT_DB_PATH", str(tmp_path / "allowed_only.sqlite3"))
    monkeypatch.setenv("GROKBOT_PROFILE_ROOT", str(tmp_path / "profiles_allowed_only"))
    monkeypatch.setenv("GROKBOT_ALLOWED_ORIGINS", scada_origin)

    app2 = create_app()
    async with (
        app2.router.lifespan_context(app2),
        run_asgi_server(app2) as origin2,
        httpx.AsyncClient(base_url=origin2, trust_env=False) as client2,
    ):
        bad2 = await client2.post(
            "/api/tasks",
            json={
                "user_id": "operator_ro",
                "profile_id": "p1",
                "facility_id": "facility-a",
                "allowed_origins": ["http://127.0.0.1:19999"],
                "query": "Check bomba 34",
            },
        )
        assert bad2.status_code == 422


@pytest.mark.tier5
@pytest.mark.n2
async def test_t5_21_web_app_bad_creds_json_non_utf8_form_and_quoted_redirects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json as _json

    monkeypatch.setenv("GROKBOT_CREDENTIALS_JSON", "{bad json")
    monkeypatch.setenv("GROKBOT_DB_PATH", str(tmp_path / "bad_creds.sqlite3"))
    monkeypatch.setenv("GROKBOT_PROFILE_ROOT", str(tmp_path / "profiles_bad_creds"))
    with pytest.raises(ValueError) as exc_info:
        create_app()
    assert type(exc_info.value) is ValueError
    assert not isinstance(exc_info.value, _json.JSONDecodeError)
    monkeypatch.delenv("GROKBOT_CREDENTIALS_JSON", raising=False)

    coordinator = InMemoryCoordinatorStub()
    web_app = create_app(db_path=tmp_path / "ui_edge.sqlite3", coordinator=coordinator)
    async with (
        run_asgi_server(web_app) as web_origin,
        httpx.AsyncClient(base_url=web_origin, trust_env=False) as client,
    ):
        bad_utf8 = await client.post(
            "/ui/tasks",
            content=b"\xff\xfe",
            headers={"content-type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
        assert bad_utf8.status_code == 400

        special_run_id = "run+1 2"
        submit_spec = await client.post(
            "/api/tasks",
            json={"query": "Test quoted redirect"},
        )
        assert submit_spec.status_code == 201
        real_run_id = submit_spec.json()["run_id"]
        # Seed a run with URL-unsafe characters in run_id on the stub
        base_snap = coordinator._snapshots[real_run_id]
        coordinator._snapshots[special_run_id] = base_snap.model_copy(
            update={"run": base_snap.run.model_copy(update={"run_id": special_run_id})}
        )
        coordinator._order.append(special_run_id)
        coordinator.transition_run(special_run_id, TaskStatus.RUNNING, "go")
        coordinator.transition_run(
            special_run_id,
            TaskStatus.WAITING_FOR_INPUT,
            "need_input",
            required_action="Choose area",
        )
        res_resume = await client.post(
            "/ui/tasks/run%2B1%202/resume",
            data={"choice": "area-1"},
            follow_redirects=False,
        )
        assert res_resume.status_code == 303
        assert res_resume.headers["location"] == "/tasks/run%2B1+2"

        res_cancel = await client.post(
            "/ui/tasks/run%2B1%202/cancel",
            data={"reason": "stop"},
            follow_redirects=False,
        )
        assert res_cancel.status_code == 303
        assert res_cancel.headers["location"] == "/tasks/run%2B1+2"
