"""N2 integration regression tests for Milestone M4-1 backend live and routing fixes."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from lab.testing import run_asgi_server
from src.adapters import MappingCredentialProvider, load_facility_config
from src.contracts.enums import BackendMode
from src.contracts.envelope import Lane
from src.model import LocalModelConfig
from src.qa.ux_metrics import evaluate_error_actionability
from src.runtime import build_runtime
from src.web.app import create_app
from src.web.live_browser import LiveBrowserController
from src.web.stub import InMemoryCoordinatorStub
from src.web.v1.events import EventBus
from src.web.v1.runner import AgentTurnRunner
from src.web.v1.store import WorkspaceStore

_FACILITY_A_PATH = Path("lab/configs/facility_a.json")


async def _wait_for_runner_idle(runner: AgentTurnRunner, *, iterations: int = 100) -> None:
    for _ in range(iterations):
        if runner.active_turns_count == 0:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("Runner did not become idle before timeout.")


@pytest.mark.n2
async def test_execute_agy_engine_streaming_syntax_deferral_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = WorkspaceStore(tmp_path / "ws_agy.sqlite3")
    bus = EventBus()
    browser = LiveBrowserController(profile_root=tmp_path / "browser")
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=browser,
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    await runner.start_scheduler()
    monkeypatch.setattr("src.web.v1.runner.find_agy_executable", lambda: "/bin/true")

    partial_cmd = (
        "curl -s --max-time 20 -X POST http://127.0.0.1:8000/api/browser/action "
        '-H "Content-Type: application/json" -d \'{"type":"'
    )
    complete_cmd = (
        "curl -s --max-time 20 -X POST http://127.0.0.1:8000/api/browser/action "
        '-H "Content-Type: application/json" '
        '-d \'{"type":"navigate","url":"https://example.com"}\''
    )

    try:
        bot = store.get_bot("bot_browser")
        assert bot is not None
        thread_id = str(bot["thread_id"])

        # Case 1: ACTIVE partial command + ACTIVE command=None -> DONE complete command -> succeeds
        async def _fake_happy(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            yield {
                "type": "tool",
                "step_index": 2,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "summary": partial_cmd[:120],
                "command": partial_cmd,
            }
            yield {
                "type": "tool",
                "step_index": 3,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "summary": partial_cmd[:120],
            }
            yield {
                "type": "tool",
                "step_index": 2,
                "state": "DONE",
                "tool_name": "run_command",
                "summary": complete_cmd[:120],
                "command": complete_cmd,
            }
            yield {
                "type": "tool",
                "step_index": 3,
                "state": "DONE",
                "tool_name": "run_command",
                "summary": complete_cmd[:120],
                "command": complete_cmd,
            }
            yield {"type": "done", "response": "Navigation completed."}

        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_happy)
        u1 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Op",
            content="Navigate browser to example.com",
        )
        runner.start_turn(thread_id=thread_id, user_message=u1, ui_lane=Lane.GENERAL)
        await _wait_for_runner_idle(runner)
        msgs1, _ = store.list_thread_messages(thread_id)
        last1 = msgs1[-1]
        assert last1["status"] == "done"
        assert last1["content"] == "Navigation completed."
        assert len(last1["tool_calls"]) == 2
        assert all(tc["status"] == "ok" for tc in last1["tool_calls"])

        # Case 2: ACTIVE partial -> DONE genuinely unparseable -> MUST block
        async def _fake_bad_done(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            yield {
                "type": "tool",
                "step_index": 0,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "summary": partial_cmd[:120],
                "command": partial_cmd,
            }
            yield {
                "type": "tool",
                "step_index": 0,
                "state": "DONE",
                "tool_name": "run_command",
                "summary": 'echo "unclosed',
                "command": 'echo "unclosed',
            }
            yield {"type": "done", "response": "Should be blocked"}

        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_bad_done)
        u2 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Op",
            content="Run unclosed echo",
        )
        runner.start_turn(thread_id=thread_id, user_message=u2, ui_lane=Lane.GENERAL)
        await _wait_for_runner_idle(runner)
        msgs2, _ = store.list_thread_messages(thread_id)
        last2 = msgs2[-1]
        assert last2["status"] == "error"
        assert "unparseable_shell_syntax" in last2["content"]
        assert last2["tool_calls"][0]["status"] == "error"

        # Case 3: ACTIVE partial -> stream ends with NO terminal DONE -> fail-closed end-of-stream
        async def _fake_missing_done(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            yield {
                "type": "tool",
                "step_index": 5,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "summary": partial_cmd[:120],
                "command": partial_cmd,
            }
            yield {"type": "done", "response": "Sneaky done without DONE tool event"}

        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_missing_done)
        u3 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Op",
            content="Run sneaky stream",
        )
        runner.start_turn(thread_id=thread_id, user_message=u3, ui_lane=Lane.GENERAL)
        await _wait_for_runner_idle(runner)
        msgs3, _ = store.list_thread_messages(thread_id)
        last3 = msgs3[-1]
        assert last3["status"] == "error"
        assert "unparseable_shell_syntax" in last3["content"]
        assert last3["tool_calls"][0]["status"] == "error"

        # Case 4: Destructive ACTIVE command aborts immediately without waiting for DONE
        reached_after_destructive = False

        async def _fake_destructive_active(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            nonlocal reached_after_destructive
            del kwargs
            yield {
                "type": "tool",
                "step_index": 0,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "summary": 'rm -rf / && echo "unclosed',
                "command": 'rm -rf / && echo "unclosed',
            }
            reached_after_destructive = True
            yield {"type": "done", "response": "Should never execute"}

        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_destructive_active)
        u4 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Op",
            content="Check active destructive block",
        )
        runner.start_turn(thread_id=thread_id, user_message=u4, ui_lane=Lane.GENERAL)
        await _wait_for_runner_idle(runner)
        assert reached_after_destructive is False
        msgs4, _ = store.list_thread_messages(thread_id)
        assert msgs4[-1]["status"] == "error"
        assert "[Policy Block]" in msgs4[-1]["content"]
    finally:
        await runner.stop_scheduler()
        bus.close()
        store.close()


@pytest.mark.n2
async def test_sse_headers_and_event_bus_clean_close(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "sse_hdr.sqlite3")
    async with app.router.lifespan_context(app):
        bus: EventBus = app.state.event_bus
        bus.publish("turn.started", {"turn_id": "trn_sse_1"})

        # Verify SSE response headers directly via ASGI app and bus.close() clean exit
        async with (
            run_asgi_server(app) as base_url,
            httpx.AsyncClient(base_url=base_url, timeout=5.0) as client,
            client.stream("GET", "/api/v1/events/stream") as resp,
        ):
            assert resp.status_code == 200
            assert resp.headers.get("cache-control") == "no-cache, no-transform"
            assert resp.headers.get("x-accel-buffering") == "no"
            assert "connection" not in {k.lower() for k in resp.headers}

            lines: list[str] = []
            async for line in resp.aiter_lines():
                lines.append(line)
                if line.startswith("retry:"):
                    break
            assert ": connected" in lines
            assert "retry: 2000" in lines

    # Direct EventBus.close() wakes suspended stream_sse subscribers cleanly
    standalone_bus = EventBus(epoch="ep_close_1")
    first_ev = standalone_bus.publish("turn.started", {"turn_id": "t1"})
    assert str(first_ev["id"]).startswith("evt_000001_ep_close_1")

    frames: list[str] = []

    async def _consume() -> None:
        async for frame in standalone_bus.stream_sse(
            last_event_id="ep_close_1:0",
            keepalive_seconds=30.0,
        ):
            frames.append(frame)

    task = asyncio.create_task(_consume())
    await asyncio.sleep(0.05)
    standalone_bus.close()
    await asyncio.wait_for(task, timeout=2.0)
    joined = "".join(frames)
    assert ": connected\n\n" in joined
    assert "retry: 2000\n\n" in joined
    assert "evt_000001_ep_close_1" in joined


@pytest.mark.n2
async def test_desktop_status_endpoint_and_system_info_normalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1. Auth protection + 200 payload for /api/desktop/status
    app_auth = create_app(db_path=tmp_path / "desktop_auth.sqlite3", web_token="tok-secret-123")
    async with app_auth.router.lifespan_context(app_auth):
        transport = httpx.ASGITransport(app=app_auth)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:
            unauth = await c.get("/api/desktop/status")
            assert unauth.status_code == 401

            authed = await c.get(
                "/api/desktop/status",
                headers={"Authorization": "Bearer tok-secret-123"},
            )
            assert authed.status_code == 200
            data = authed.json()
            assert data["vm_id"] == "default"
            assert "status" in data
            assert "control_owner" in data
            assert "vnc_available" in data
            assert "browser_running" in data
            assert "display_mode" in data
            assert isinstance(data["running"], bool)
            assert "vnc_host" in data
            assert isinstance(data["vnc_port"], int)
            assert "tok-secret-123" not in json.dumps(data)

    # 2. Clean GROKBOT_LLM_BASE_URL normalizes path to scheme://host:port
    monkeypatch.setenv("GROKBOT_LLM_BASE_URL", "http://127.0.0.1:11434/v1")
    app_norm = create_app(db_path=tmp_path / "sys_norm.sqlite3")
    async with app_norm.router.lifespan_context(app_norm):
        transport = httpx.ASGITransport(app=app_norm)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:
            info_norm = (await c.get("/api/system/info")).json()
            assert info_norm["llm_origin"] == "http://127.0.0.1:11434"

    # 3. Userinfo + query secret in GROKBOT_LLM_BASE_URL fallback is never leaked
    monkeypatch.setenv(
        "GROKBOT_LLM_BASE_URL",
        "http://user:pass-secret@127.0.0.1:11434/v1?api_key=leak-secret",
    )
    app_sec = create_app(
        db_path=tmp_path / "sys_sec.sqlite3",
        coordinator=InMemoryCoordinatorStub(),
    )
    async with app_sec.router.lifespan_context(app_sec):
        transport = httpx.ASGITransport(app=app_sec)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:
            info_sec = (await c.get("/api/system/info")).json()
            dumped = json.dumps(info_sec)
            assert "pass-secret" not in dumped
            assert "leak-secret" not in dumped
            assert info_sec["llm_origin"] is None


@pytest.mark.n2
async def test_simple_chat_and_cb_valve_104_under_emulated_runtime_without_scada(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = load_facility_config(
        _FACILITY_A_PATH,
        {
            "scada": "http://127.0.0.1:59991",
            "maintenance": "http://127.0.0.1:59992",
        },
    )
    runtime = build_runtime(
        db_path=tmp_path / "rt_emu.sqlite3",
        profile_root=tmp_path / "profiles",
        facility_config=cfg,
        credential_provider=MappingCredentialProvider({}),
        backend_mode=BackendMode.EMULATED,
    )
    runner: AgentTurnRunner = runtime.app.state.v1_runner
    store: WorkspaceStore = runtime.app.state.workspace_store

    async with runtime, runtime.app.router.lifespan_context(runtime.app):
        bot = store.create_bot({"name": "Runtime Probe", "engine_id": "controlbot_runtime"})
        thread_id = str(bot["thread_id"])

        # 1. Simple chat with agy mocked -> routes to agy (Lane.GENERAL), never touches SCADA
        async def _fake_probe_agy(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            yield {"type": "done", "response": "OK_M3_PROBE"}

        monkeypatch.setattr("src.web.v1.runner.find_agy_executable", lambda: "/bin/true")
        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_probe_agy)

        u1 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Op",
            content="Reply with exactly OK_M3_PROBE",
        )
        runner.start_turn(thread_id=thread_id, user_message=u1)
        await _wait_for_runner_idle(runner)
        msgs1, _ = store.list_thread_messages(thread_id)
        m1 = msgs1[-1]
        assert m1["status"] == "done"
        assert m1["content"] == "OK_M3_PROBE"
        assert (m1.get("metadata") or {}).get("lane") == "general"
        assert (m1.get("metadata") or {}).get("domain_profile") == "general_office"

        # 2. CB-VALVE-104 price query with app_runtime enabled -> Lane.GENERAL (web_research)
        u_valve = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Op",
            content="Busca el precio vigente de CB-VALVE-104 y dime en qué página lo encontraste",
        )
        runner.start_turn(thread_id=thread_id, user_message=u_valve)
        await _wait_for_runner_idle(runner)
        msgs_v, _ = store.list_thread_messages(thread_id)
        mv = msgs_v[-1]
        assert mv["status"] == "done"
        assert (mv.get("metadata") or {}).get("lane") == "general"
        assert (mv.get("metadata") or {}).get("domain_profile") == "general_office"

        # 3. Simple chat when agy is unavailable -> actionable error, zero raw SCADA errors
        monkeypatch.setattr("src.web.v1.runner.find_agy_executable", lambda: None)
        u2 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Op",
            content="Reply with exactly OK_M3_PROBE",
        )
        runner.start_turn(thread_id=thread_id, user_message=u2)
        await _wait_for_runner_idle(runner)
        msgs2, _ = store.list_thread_messages(thread_id)
        m2 = msgs2[-1]
        assert m2["status"] == "error"
        ok2, reason2 = evaluate_error_actionability(m2["content"])
        assert ok2 is True, reason2
        assert "net::ERR_" not in m2["content"]
        assert "available_sources" not in json.dumps(m2.get("metadata") or {})

        # 4. Real Lane.INDUSTRIAL query when SCADA/Maint are offline -> sanitized actionable error
        u3 = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Op",
            content="Check bomba 34 alarms and readings in SCADA and maintenance",
        )
        runner.start_turn(thread_id=thread_id, user_message=u3)
        await _wait_for_runner_idle(runner, iterations=200)
        msgs3, _ = store.list_thread_messages(thread_id)
        m3 = msgs3[-1]
        assert m3["status"] == "error"
        ok3, reason3 = evaluate_error_actionability(m3["content"])
        assert ok3 is True, reason3
        assert "net::ERR_" not in m3["content"]
        partial_str = json.dumps((m3.get("metadata") or {}).get("partial_evidence", []))
        assert '"available_sources": [' not in partial_str
        assert '"missing_sources": [' not in partial_str


@pytest.mark.n2
async def test_simple_chat_under_local_http_runtime_with_mock_openai_server(
    tmp_path: Path,
) -> None:
    recorded_bodies: list[dict[str, Any]] = []
    mock_llm = FastAPI(title="Mock OpenAI M4-1")

    @mock_llm.post("/v1/chat/completions")
    async def completions(request: Request) -> JSONResponse:
        body = await request.json()
        recorded_bodies.append(body)
        return JSONResponse(
            {
                "id": "cmpl-m4-1",
                "model": "qwen2.5-7b-instruct",
                "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16},
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {
                                    "decision_type": "final",
                                    "final_answer": "OK_M3_PROBE",
                                }
                            ),
                        },
                    }
                ],
            }
        )

    async with run_asgi_server(mock_llm) as llm_origin:
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {
                "scada": "http://127.0.0.1:59993",
                "maintenance": "http://127.0.0.1:59994",
            },
        )
        llm_cfg = LocalModelConfig(
            origin=llm_origin,
            model_id="qwen2.5-7b-instruct",
            strict_model_id_check=True,
        )
        runtime = build_runtime(
            db_path=tmp_path / "rt_http.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=MappingCredentialProvider({}),
            backend_mode=BackendMode.LOCAL_HTTP,
            local_http_config=llm_cfg,
        )
        runner: AgentTurnRunner = runtime.app.state.v1_runner
        store: WorkspaceStore = runtime.app.state.workspace_store

        async with runtime, runtime.app.router.lifespan_context(runtime.app):
            bot = store.create_bot({"name": "LocalHttp Bot", "engine_id": "controlbot_runtime"})
            thread_id = str(bot["thread_id"])

            u1 = store.create_message(
                thread_id=thread_id,
                sender_type="user",
                sender_name="Op",
                content="Reply with exactly OK_M3_PROBE",
            )
            runner.start_turn(thread_id=thread_id, user_message=u1)
            await _wait_for_runner_idle(runner)

            msgs, _ = store.list_thread_messages(thread_id)
            last = msgs[-1]
            assert last["status"] == "done"
            assert last["content"] == "OK_M3_PROBE"
            meta = last.get("metadata") or {}
            assert meta.get("lane") == "general"
            assert meta.get("domain_profile") == "general_office"

            assert len(recorded_bodies) == 1
            user_msg_payload = json.loads(recorded_bodies[0]["messages"][1]["content"])
            assert user_msg_payload["available_tool_ids"] == []
            assert "tools" not in recorded_bodies[0]


@pytest.mark.n2
async def test_execute_agy_engine_tool_state_retention_and_unnamed_step_correlation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = WorkspaceStore(tmp_path / "ws_agy_iter2.sqlite3")
    bus = EventBus()
    browser = LiveBrowserController(profile_root=tmp_path / "browser")
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=browser,
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    await runner.start_scheduler()
    monkeypatch.setattr("src.web.v1.runner.find_agy_executable", lambda: "/bin/true")

    try:
        bot = store.get_bot("bot_browser")
        assert bot is not None
        thread_id = str(bot["thread_id"])

        # BUG-1a: ACTIVE(unparseable) -> ACTIVE(command=None, summary=tool_name)
        # -> DONE(command=None) MUST block
        async def _fake_bug1_intermediate(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            yield {
                "type": "tool",
                "step_index": 0,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "summary": 'echo "unclosed',
                "command": 'echo "unclosed',
            }
            yield {
                "type": "tool",
                "step_index": 0,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "summary": "run_command",
            }
            yield {
                "type": "tool",
                "step_index": 0,
                "state": "DONE",
                "tool_name": "run_command",
                "summary": "run_command",
            }
            yield {"type": "done", "response": "Bypassed unparseable check!"}

        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_bug1_intermediate)
        u1 = store.create_message(
            thread_id=thread_id, sender_type="user", sender_name="Op", content="bug1a"
        )
        runner.start_turn(thread_id=thread_id, user_message=u1, ui_lane=Lane.GENERAL)
        await _wait_for_runner_idle(runner)
        m1 = store.list_thread_messages(thread_id)[0][-1]
        assert m1["status"] == "error"
        assert "unparseable_shell_syntax" in m1["content"]

        # BUG-1b: ACTIVE(command=None, summary='curl "unclosed')
        # -> DONE(command=None, summary='run_command') MUST block
        async def _fake_bug1_summary(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            yield {
                "type": "tool",
                "step_index": 0,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "summary": 'curl "unclosed',
            }
            yield {
                "type": "tool",
                "step_index": 0,
                "state": "DONE",
                "tool_name": "run_command",
                "summary": "run_command",
            }
            yield {"type": "done", "response": "Bypassed summary check!"}

        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_bug1_summary)
        u2 = store.create_message(
            thread_id=thread_id, sender_type="user", sender_name="Op", content="bug1b"
        )
        runner.start_turn(thread_id=thread_id, user_message=u2, ui_lane=Lane.GENERAL)
        await _wait_for_runner_idle(runner)
        m2 = store.list_thread_messages(thread_id)[0][-1]
        assert m2["status"] == "error"
        assert "unparseable_shell_syntax" in m2["content"]

        # BUG-2: Wrapper-quoted destructive ACTIVE commands abort immediately
        for bad_cmd in ('bash -c "rm -rf /', "sh -c 'rm -rf /"):
            reached_after = False

            async def _fake_bug2(
                _cmd: str = bad_cmd, **kwargs: Any
            ) -> AsyncIterator[dict[str, Any]]:
                nonlocal reached_after
                del kwargs
                yield {
                    "type": "tool",
                    "step_index": 0,
                    "state": "ACTIVE",
                    "tool_name": "run_command",
                    "summary": _cmd,
                    "command": _cmd,
                }
                reached_after = True
                yield {"type": "done", "response": "Should not reach"}

            monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_bug2)
            u_b2 = store.create_message(
                thread_id=thread_id, sender_type="user", sender_name="Op", content="bug2"
            )
            runner.start_turn(thread_id=thread_id, user_message=u_b2, ui_lane=Lane.GENERAL)
            await _wait_for_runner_idle(runner)
            assert reached_after is False
            m_b2 = store.list_thread_messages(thread_id)[0][-1]
            assert m_b2["status"] == "error"
            assert "[Policy Block]" in m_b2["content"]

        # BUG-3: Valid ACTIVE >120 chars followed by DONE(command=None, summary=cmd[:120])
        # MUST succeed despite open quote in truncated summary
        long_valid_cmd = (
            "curl -s -X POST http://127.0.0.1:8000/api/browser/action "
            '-H "Content-Type: application/json" '
            "-d '{\"type\":\"navigate\",\"url\":\"https://example.com/"
            + ("x" * 60)
            + "\"}'"
        )
        assert len(long_valid_cmd) > 120
        assert long_valid_cmd[:120].count("'") == 1

        async def _fake_bug3(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            yield {
                "type": "tool",
                "step_index": 0,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "summary": long_valid_cmd[:120],
                "command": long_valid_cmd,
            }
            yield {
                "type": "tool",
                "step_index": 0,
                "state": "DONE",
                "tool_name": "run_command",
                "summary": long_valid_cmd[:120],
            }
            yield {"type": "done", "response": "Long command succeeded."}

        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_bug3)
        u3 = store.create_message(
            thread_id=thread_id, sender_type="user", sender_name="Op", content="bug3"
        )
        runner.start_turn(thread_id=thread_id, user_message=u3, ui_lane=Lane.GENERAL)
        await _wait_for_runner_idle(runner)
        m3 = store.list_thread_messages(thread_id)[0][-1]
        assert m3["status"] == "done"
        assert m3["content"] == "Long command succeeded."
        assert m3["tool_calls"][0]["status"] == "ok"

        # BUG-4: Omitted/None step_index correlates ACTIVE -> DONE without drifting tc_0 -> tc_1
        async def _fake_bug4(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            yield {
                "type": "tool",
                "step_index": None,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "summary": 'echo "a',
                "command": 'echo "a',
            }
            yield {
                "type": "tool",
                "state": "DONE",
                "tool_name": "run_command",
                "summary": 'echo "a"',
                "command": 'echo "a"',
            }
            yield {"type": "done", "response": "Correlated unnamed tool."}

        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_bug4)
        u4 = store.create_message(
            thread_id=thread_id, sender_type="user", sender_name="Op", content="bug4"
        )
        runner.start_turn(thread_id=thread_id, user_message=u4, ui_lane=Lane.GENERAL)
        await _wait_for_runner_idle(runner)
        m4 = store.list_thread_messages(thread_id)[0][-1]
        assert m4["status"] == "done"
        assert m4["content"] == "Correlated unnamed tool."
        assert len(m4["tool_calls"]) == 1
        assert m4["tool_calls"][0]["call_id"] == "tc_0"
        assert m4["tool_calls"][0]["status"] == "ok"
    finally:
        await runner.stop_scheduler()
        bus.close()
        store.close()


@pytest.mark.n2
async def test_event_bus_subscribe_on_closed_bus_yields_nothing() -> None:
    bus = EventBus(epoch="ep_sub_closed")
    bus.publish("turn.started", {"turn_id": "t_before_close"})
    bus.close()
    items = [ev async for ev in bus.subscribe(last_event_id="ep_sub_closed:0")]
    assert items == []
    assert len(bus._subscribers) == 0


@pytest.mark.n2
async def test_legacy_browser_action_publishes_computer_state_sse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(
        db_path=tmp_path / "browser_sse.sqlite3",
        web_token="",
        coordinator=InMemoryCoordinatorStub(),
    )
    fake_state: dict[str, Any] = {
        "running": False,
        "url": "",
        "title": "",
        "viewport": {"width": 1280, "height": 800},
    }

    async def _fake_perform_action(
        event: dict[str, Any],
        *,
        screenshot_path: Path | None = None,
    ) -> dict[str, Any]:
        del screenshot_path
        url = str(event.get("url") or "https://example.com/")
        fake_state.update({"running": True, "url": url, "title": "Example Domain"})
        return {"status": dict(fake_state), "context": {"running": True, "url": url}}

    async def _fake_status() -> dict[str, Any]:
        return dict(fake_state)

    monkeypatch.setattr(app.state.live_browser, "perform_action", _fake_perform_action)
    monkeypatch.setattr(app.state.live_browser, "status", _fake_status)

    event_bus: EventBus = app.state.event_bus
    received: list[dict[str, Any]] = []

    async def _reader() -> None:
        async for ev in event_bus.subscribe(last_event_id=None):
            if ev.get("type") == "computer.state":
                received.append(ev)
                return

    reader_task = asyncio.create_task(_reader())
    await asyncio.sleep(0.05)
    try:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://testserver",
            ) as client,
        ):
            resp = await client.post(
                "/api/browser/action",
                json={"type": "navigate", "url": "https://example.com/product"},
            )
            assert resp.status_code == 200, resp.text
        await asyncio.wait_for(reader_task, timeout=3.0)
    finally:
        if not reader_task.done():
            reader_task.cancel()

    assert len(received) == 1
    payload = received[0]["payload"]
    assert payload["browser_running"] is True
    assert payload["active_url"] == "https://example.com/product"
    assert payload["active_tab_title"] == "Example Domain"


