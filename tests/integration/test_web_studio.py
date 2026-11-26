"""N2 integration tests for ControlBot Studio UX (/app), workspace APIs, and local_server."""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest
from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.local_server import running_local_stack
from src.storage.redaction import contains_unredacted_secret_strict
from src.web import create_app


@pytest.mark.n2
async def test_studio_html_light_mode_hidden_plant_and_system_info(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "stub.sqlite3")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        studio_resp = await client.get("/app")
        assert studio_resp.status_code == 200
        assert "text/html" in studio_resp.headers["content-type"].lower()
        body = studio_resp.text
        body_low = body.lower()
        assert "controlbot studio" in body_low
        assert "color-scheme: light" in body_low
        assert "#f8fafc" in body_low
        assert "controlbot.showplantmodule" in body_low
        assert "conversaciones antigravity" in body_low
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
async def test_projects_and_agy_workspace_apis_with_safety_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects_dir = tmp_path / "Projects"
    proj_alpha = projects_dir / "AlphaApp"
    proj_alpha.mkdir(parents=True)
    (proj_alpha / "README.md").write_text("# AlphaApp\n", encoding="utf-8")

    brain_dir = tmp_path / "brain"
    conv_uuid = "11111111-2222-3333-4444-555555555555"
    log_file = brain_dir / conv_uuid / ".system_generated" / "logs" / "transcript.jsonl"
    log_file.parent.mkdir(parents=True)
    log_file.write_text(
        json.dumps(
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "content": (
                    "<USER_REQUEST>\n"
                    "Hola ControlBot api_key=mysecret123 y sk-secret-abc123456\n"
                    "</USER_REQUEST>"
                ),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("CONTROLBOT_PROJECTS_ROOT", str(projects_dir))
    monkeypatch.setenv("CONTROLBOT_AGY_BRAIN_ROOT", str(brain_dir))

    app = create_app(db_path=tmp_path / "ws.sqlite3")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        proj_resp = await client.get("/api/projects")
        assert proj_resp.status_code == 200
        proj_json = proj_resp.json()
        assert [p["name"] for p in proj_json["projects"]] == ["AlphaApp"]
        assert proj_json["projects"][0]["has_readme"] is True

        convs_resp = await client.get("/api/agy/conversations")
        assert convs_resp.status_code == 200
        convs = convs_resp.json()["conversations"]
        assert len(convs) == 1
        assert convs[0]["conversation_id"] == conv_uuid
        assert "mysecret123" not in convs[0]["preview"]
        assert "sk-secret-abc123456" not in convs[0]["preview"]
        assert convs[0]["resume_command"] == f"agy --resume {conv_uuid}"

        bad_model = await client.post(
            "/api/agy/send",
            json={"prompt": "hola", "model": "gemini-4-hydrogen-low"},
        )
        assert bad_model.status_code == 422

        bad_proj = await client.post(
            "/api/agy/send",
            json={"prompt": "hola", "project_name": "../etc", "model": "gemini-4-carbon-low"},
        )
        assert bad_proj.status_code == 422


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
