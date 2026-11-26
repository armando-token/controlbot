"""N2 integration tests for ControlBot Studio UX (/app), live browser/terminal & workspace."""

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
from src.web.workspace import parse_agy_models_output
from starlette.testclient import TestClient


@pytest.mark.n1
def test_parse_agy_models_output_handles_spinner_and_hydrogen_flag() -> None:
    raw = (
        "\r⠋ Fetching available models...\r⠙ Fetching available models...\n"
        "gemini-4-neon-high             Gemini 4 Neon (High)\n"
        "gemini-4-carbon-low            Gemini 4 Carbon (Low)\n"
        "gemini-4-hydrogen-low          Gemini 4 Hydrogen (Low)\n"
        "claude-sonnet-4-6              Claude Sonnet 4.6 (Thinking)\n"
        "claude-opus-4-6-thinking       Claude Opus 4.6 (Thinking)\n"
        "gpt-oss-120b-medium            GPT-OSS 120B (Medium)\n"
    )
    parsed = parse_agy_models_output(raw)
    ids = [m["id"] for m in parsed]
    assert ids == [
        "gemini-4-neon-high",
        "gemini-4-carbon-low",
        "gemini-4-hydrogen-low",
        "claude-sonnet-4-6",
        "claude-opus-4-6-thinking",
        "gpt-oss-120b-medium",
    ]
    hydrogen_flags = {m["id"]: m["is_hydrogen"] for m in parsed}
    assert hydrogen_flags["gemini-4-hydrogen-low"] is True
    assert hydrogen_flags["claude-sonnet-4-6"] is False


@pytest.mark.n2
async def test_studio_html_light_mode_hidden_plant_and_system_info(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "stub.sqlite3")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        studio_resp = await client.get("/app")
        assert studio_resp.status_code == 200
        assert "text/html" in studio_resp.headers["content-type"].lower()
        body_low = studio_resp.text.lower()
        assert "controlbot studio" in body_low
        assert "color-scheme: light" in body_low
        assert "#f8fafc" in body_low
        assert "controlbot.showplantmodule" in body_low
        assert "computador en vivo" in body_low
        assert "mostrar hydrogen" in body_low
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
async def test_projects_files_models_and_agy_workspace_apis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects_dir = tmp_path / "Projects"
    proj_alpha = projects_dir / "AlphaApp"
    (proj_alpha / "src").mkdir(parents=True)
    (proj_alpha / "README.md").write_text(
        "# AlphaApp\napi_key=secret-readme-999\n",
        encoding="utf-8",
    )
    (proj_alpha / ".env").write_text("SECRET=123\n", encoding="utf-8")
    (proj_alpha / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")

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

        files_resp = await client.get("/api/projects/AlphaApp/files")
        assert files_resp.status_code == 200
        entry_names = [e["name"] for e in files_resp.json()["entries"]]
        assert "README.md" in entry_names
        assert "src" in entry_names

        read_resp = await client.get("/api/projects/AlphaApp/file", params={"path": "README.md"})
        assert read_resp.status_code == 200
        assert "secret-readme-999" not in read_resp.json()["content"]
        assert REDACTED_PLACEHOLDER in read_resp.json()["content"]

        env_blocked = await client.get("/api/projects/AlphaApp/file", params={"path": ".env"})
        assert env_blocked.status_code == 422

        trav_blocked = await client.get("/api/projects/AlphaApp/file", params={"path": "../etc"})
        assert trav_blocked.status_code == 422

        models_resp = await client.get("/api/agy/models")
        assert models_resp.status_code == 200
        models_json = models_resp.json()
        assert models_json["default_model"] == "gemini-4-carbon-low"
        assert len(models_json["models"]) >= 5

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
def test_lazy_browser_and_live_terminal_websocket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects_dir = tmp_path / "Projects"
    proj = projects_dir / "DemoProj"
    proj.mkdir(parents=True)
    monkeypatch.setenv("CONTROLBOT_PROJECTS_ROOT", str(projects_dir))

    app = create_app(db_path=tmp_path / "ws_live.sqlite3")
    with TestClient(app) as client:
        st0 = client.get("/api/browser/status")
        assert st0.status_code == 200
        assert st0.json()["running"] is False

        started = client.post("/api/browser/start", json={})
        assert started.status_code == 200
        assert started.json()["running"] is True

        stopped = client.post("/api/browser/stop")
        assert stopped.status_code == 200
        assert stopped.json()["running"] is False

        with client.websocket_connect("/ws/terminal?project=DemoProj") as ws:
            ready = ws.receive_json()
            assert ready["type"] == "ready"
            assert str(proj.resolve()) == ready["cwd"]
            ws.send_json({"type": "input", "data": "echo CONTROLBOT_PTY_OK\n"})
            collected = ""
            for _ in range(30):
                msg = ws.receive_json()
                if msg.get("type") == "output":
                    collected += str(msg.get("data", ""))
                    if "CONTROLBOT_PTY_OK" in collected:
                        break
            assert "CONTROLBOT_PTY_OK" in collected


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
