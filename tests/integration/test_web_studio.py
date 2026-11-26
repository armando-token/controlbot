"""N2 integration tests for ControlBot Studio UX (/app), /api/system/info, and local_server."""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.local_server import running_local_stack
from src.storage.redaction import contains_unredacted_secret_strict
from src.web import create_app


@pytest.mark.n2
async def test_studio_html_and_system_info_stub_mode(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "stub.sqlite3")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        studio_resp = await client.get("/app")
        assert studio_resp.status_code == 200
        assert "text/html" in studio_resp.headers["content-type"].lower()
        body_low = studio_resp.text.lower()
        assert "controlbot studio" in body_low
        assert not re.search(r'(?:src|href)\s*=\s*["\']https?://', body_low)
        assert "https://" not in body_low

        root_resp = await client.get("/")
        assert root_resp.status_code == 200
        assert "/app" in root_resp.text

        info_resp = await client.get("/api/system/info")
        assert info_resp.status_code == 200
        info = info_resp.json()
        assert info["service"] == "controlbot"
        assert info["runtime_mode"] == "stub"
        assert info["backend_mode"] == "stub"
        assert not contains_unredacted_secret_strict(info)


@pytest.mark.n2
async def test_system_info_redacts_secret_in_llm_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GROKBOT_LLM_BASE_URL", "http://127.0.0.1:11434/v1?api_key=sk-secret-xyz")
    app = create_app(db_path=tmp_path / "stub2.sqlite3")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        info = (await client.get("/api/system/info")).json()
        assert "sk-secret-xyz" not in str(info)
        assert REDACTED_PLACEHOLDER in str(info["llm_origin"]) or info["llm_origin"] is None


@pytest.mark.n2
async def test_unified_local_server_stack_boots_and_completes_pump34_task(tmp_path: Path) -> None:
    async with running_local_stack(
        port=0,
        scada_port=0,
        maintenance_port=0,
        effect_port=0,
        db_path=tmp_path / "controlbot.sqlite3",
        profile_root=tmp_path / "profiles",
        start_lab=True,
    ) as (info, runtime, _):
        assert info.scada_origin is not None
        assert info.maintenance_origin is not None
        assert info.effect_origin is not None

        async with httpx.AsyncClient(base_url=info.web_origin, timeout=15.0) as client:
            sys_resp = await client.get("/api/system/info")
            assert sys_resp.status_code == 200
            sys_json = sys_resp.json()
            assert sys_json["runtime_mode"] == "live_runtime"
            assert sys_json["backend_mode"] == "emulated"
            assert sys_json["facility"]["facility_id"] == "facility-a"
            app_ids = {item["app_id"] for item in sys_json["facility"]["apps"]}
            assert app_ids == {"scada", "maintenance", "effect_sim"}

            studio_resp = await client.get("/app")
            assert studio_resp.status_code == 200
            assert "ControlBot Studio" in studio_resp.text

            submit = await client.post(
                "/api/tasks",
                json={
                    "user_id": "operator_ro",
                    "profile_id": "studio_test",
                    "facility_id": "facility-a",
                    "allowed_origins": [info.scada_origin, info.maintenance_origin],
                    "allowed_areas": ["area-1"],
                    "read_only": True,
                    "query": "¿Qué alarma apareció primero en la bomba 34 y qué se cambió?",
                },
            )
            assert submit.status_code == 201
            run_id = submit.json()["run_id"]
            await runtime.web_coordinator.wait_for_run(run_id, timeout=25.0)

            snap = (await client.get(f"/api/tasks/{run_id}")).json()
            assert snap["status"] == "succeeded"
            answer = snap["result"]["answer"]
            assert "ALM-3401" in answer
            assert "WO-3408" in answer
