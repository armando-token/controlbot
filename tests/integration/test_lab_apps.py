"""N2 integration tests for synthetic lab apps (SCADA, Maintenance, EffectSim) and config."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from lab.effect_sim import create_effect_sim_app
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import create_scada_app
from lab.testing import run_asgi_server
from src.adapters.config import load_facility_config, resolve_asset_candidates


@pytest.mark.n2
async def test_scada_app_auth_routes_fixtures_and_readonly() -> None:
    app = create_scada_app(fixture_mode="default")
    state = app.state.scada_state
    state.set_reference_time(datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC))

    async with run_asgi_server(app) as origin, httpx.AsyncClient(base_url=origin) as client:
        # /health always 200
        health = await client.get("/health")
        assert health.status_code == 200
        assert health.json()["available"] is True
        assert health.json()["service"] == "scada"

        # Unauthenticated API -> 401; HTML -> 303 redirect to /login
        unauth_api = await client.get("/api/alarms")
        assert unauth_api.status_code == 401
        assert unauth_api.json()["code"] == "AUTH_EXPIRED"

        unauth_html = await client.get("/alarms", follow_redirects=False)
        assert unauth_html.status_code == 303
        assert "/login" in unauth_html.headers["location"]

        # Invalid login -> 401
        bad_login = await client.post(
            "/login",
            json={"username": "operator_a1", "password": "wrong"},
        )
        assert bad_login.status_code == 401

        # Valid login -> HttpOnly SameSite=Lax cookie
        login_resp = await client.post(
            "/login",
            data={"username": "operator_a1", "password": "scada-pass-a1"},
            follow_redirects=False,
        )
        assert login_resp.status_code == 303
        set_cookie = login_resp.headers["set-cookie"]
        assert "scada_session=" in set_cookie
        assert "httponly" in set_cookie.lower()
        assert "samesite=lax" in set_cookie.lower()

        # Alarms & Readings API schema
        alarms_resp = await client.get("/api/alarms")
        assert alarms_resp.status_code == 200
        alarms = alarms_resp.json()["alarms"]
        assert len(alarms) == 2
        assert alarms[0]["asset_id"] == "bomba-34-a1"
        assert set(alarms[0]).issuperset(
            {"id", "asset_id", "asset_label", "value", "unit", "time", "quality", "area"}
        )

        readings_resp = await client.get("/api/readings")
        assert readings_resp.status_code == 200
        assert len(readings_resp.json()["readings"]) == 2

        # Area enforcement: operator_a1 cannot query area-2
        forbidden = await client.get("/api/alarms", params={"area": "area-2"})
        assert forbidden.status_code == 403

        # Semantic HTML table check
        html_page = await client.get("/alarms")
        assert html_page.status_code == 200
        assert '<table aria-label="SCADA Alarms">' in html_page.text
        assert 'data-testid="current-user">operator_a1<' in html_page.text

        # Read-only enforcement
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            ro_resp = await client.request(method, "/api/alarms")
            assert ro_resp.status_code in (403, 405)

        # Runtime auth expiry -> 401 / 303 to /login?expired=1
        state.expire_all_sessions()
        assert (await client.get("/api/alarms")).status_code == 401
        expired_html = await client.get("/alarms", follow_redirects=False)
        assert expired_html.status_code == 303
        assert "/login?expired=1" in expired_html.headers["location"]

        # Down mode -> business routes 503 while /health stays 200 with available=False
        state.set_mode("down")
        health_down = await client.get("/health")
        assert health_down.status_code == 200
        assert health_down.json()["available"] is False
        assert (await client.get("/api/alarms")).status_code == 503
        assert (await client.get("/alarms")).status_code == 503


@pytest.mark.n2
async def test_maintenance_app_modes_and_contradictory_fixture() -> None:
    app = create_maintenance_app(fixture_mode="contradictory")
    state = app.state.maintenance_state

    async with run_asgi_server(app) as origin, httpx.AsyncClient(base_url=origin) as client:
        health = await client.get("/health")
        assert health.status_code == 200
        assert health.json()["service"] == "maintenance"

        login = await client.post(
            "/login",
            json={"username": "maint_a1", "password": "maint-pass-a1"},
        )
        assert login.status_code == 200
        assert "maint_session=" in login.headers["set-cookie"]

        wo_resp = await client.get("/api/work_orders")
        assert wo_resp.status_code == 200
        work_orders = wo_resp.json()["work_orders"]
        assert len(work_orders) == 2
        assert any(
            w["asset_id"] == "bomba-34-a1" and w["asset_label"] == "bomba 35"
            for w in work_orders
        )
        assert any(
            w["asset_id"] == "bomba-99-a1" and w["asset_label"] == "bomba 34"
            for w in work_orders
        )

        # Read-only enforcement
        assert (await client.post("/api/work_orders", json={})).status_code in (403, 405)

        # Logout clears cookie/session
        logout = await client.post("/logout", headers={"accept": "application/json"})
        assert logout.status_code == 200
        assert (await client.get("/api/work_orders")).status_code == 401

        # Ambiguity mode with maint_ro sees area-1 and area-2
        state.set_mode("ambiguity")
        await client.post("/login", json={"username": "maint_ro", "password": "maint-pass-ro"})
        amb_rows = (await client.get("/api/work_orders")).json()["work_orders"]
        assert {r["area"] for r in amb_rows} == {"area-1", "area-2"}


@pytest.mark.n2
async def test_effect_sim_idempotency_crash_hook_and_disk_persistence(tmp_path: Path) -> None:
    state_file = tmp_path / "effect_state.json"
    app1 = create_effect_sim_app(state_path=state_file)

    async with run_asgi_server(app1) as origin, httpx.AsyncClient(base_url=origin) as client:
        # Blank key -> 422
        bad = await client.post(
            "/api/effects/apply",
            json={"idempotency_key": "  ", "asset_id": "bomba-34-a1", "action": "ack_alarm"},
        )
        assert bad.status_code == 422

        # Simulated crash after persisting effect -> 500
        crash_resp = await client.post(
            "/api/effects/apply",
            json={
                "idempotency_key": "op-crash-1",
                "asset_id": "bomba-34-a1",
                "action": "ack_alarm",
                "params": {"alarm_id": "ALM-3401"},
                "fail_after_apply": True,
            },
        )
        assert crash_resp.status_code == 500

        # State confirms effect was persisted exactly once
        state_resp = await client.get(
            "/api/effects/state",
            params={"idempotency_key": "op-crash-1"},
        )
        assert state_resp.status_code == 200
        state_json = state_resp.json()
        assert state_json["found"] is True
        assert state_json["total_applied"] == 1

        by_path = await client.get("/api/effects/state/op-crash-1")
        assert by_path.status_code == 200
        assert by_path.json()["effect"]["asset_id"] == "bomba-34-a1"

        # Matching replay deduplicates without incrementing total_applied
        replay = await client.post(
            "/api/effects/apply",
            json={
                "idempotency_key": "op-crash-1",
                "asset_id": "bomba-34-a1",
                "action": "ack_alarm",
                "params": {"alarm_id": "ALM-3401"},
            },
        )
        assert replay.status_code == 200
        assert replay.json()["deduplicated"] is True
        assert replay.json()["total_applied"] == 1

        # Conflicting payload for same key -> 409
        conflict = await client.post(
            "/api/effects/apply",
            json={
                "idempotency_key": "op-crash-1",
                "asset_id": "bomba-34-a1",
                "action": "restart_pump",
                "params": {},
            },
        )
        assert conflict.status_code == 409

    # Restart EffectSim app from persisted state_file
    app2 = create_effect_sim_app(state_path=state_file)
    async with run_asgi_server(app2) as origin2, httpx.AsyncClient(base_url=origin2) as client2:
        reloaded = await client2.get("/api/effects/state/op-crash-1")
        assert reloaded.status_code == 200
        assert reloaded.json()["found"] is True


@pytest.mark.n2
def test_facility_a_config_loads_with_origin_overrides() -> None:
    cfg = load_facility_config(
        Path("lab/configs/facility_a.json"),
        origin_overrides={"scada": "http://127.0.0.1:41001/"},
    )
    assert cfg.facility_id == "facility-a"
    assert cfg.apps["scada"].origin == "http://127.0.0.1:41001"
    assert cfg.apps["scada"].read_only is True
    assert cfg.apps["maintenance"].read_only is True
    matches = resolve_asset_candidates(cfg, "Pump 34")
    assert len(matches) == 1
    assert matches[0].asset_id == "bomba-34-a1"


@pytest.mark.n2
async def test_lab_apps_distinguish_unknown_restart_cookie_from_expired_session() -> None:
    scada_app = create_scada_app(fixture_mode="default")
    maint_app = create_maintenance_app(fixture_mode="contradictory")

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
        httpx.AsyncClient(
            base_url=scada_origin,
            cookies={"scada_session": "stale-unknown-cookie"},
        ) as scada_client,
        httpx.AsyncClient(
            base_url=maint_origin,
            cookies={"maint_session": "stale-unknown-cookie"},
        ) as maint_client,
    ):
        for route in ("/alarms", "/readings"):
            resp = await scada_client.get(route, follow_redirects=False)
            assert resp.status_code == 303
            assert resp.headers["location"] == "/login"
            assert "scada_session=" in resp.headers.get("set-cookie", "")

        m_resp = await maint_client.get("/work-orders", follow_redirects=False)
        assert m_resp.status_code == 303
        assert m_resp.headers["location"] == "/login"
        assert "maint_session=" in m_resp.headers.get("set-cookie", "")

        # Explicit expire_all_sessions still redirects to /login?expired=1
        await maint_client.post(
            "/login",
            json={"username": "maint_a1", "password": "maint-pass-a1"},
        )
        maint_app.state.maintenance_state.expire_all_sessions()
        expired_m = await maint_client.get("/work-orders", follow_redirects=False)
        assert expired_m.status_code == 303
        assert expired_m.headers["location"] == "/login?expired=1"
