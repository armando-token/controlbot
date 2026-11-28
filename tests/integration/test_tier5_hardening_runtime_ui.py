"""Tier-5 integration & Playwright UI behavioral hardening tests."""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
import websockets
from fastapi import FastAPI
from fastapi.testclient import TestClient
from playwright.async_api import Request as PwRequest
from playwright.async_api import Route as PwRoute
from playwright.async_api import async_playwright
from src.adapters.config import load_facility_config
from src.contracts.common import PlanValidationError
from src.contracts.models import TaskScope, TaskSpec
from src.qa.isolation import LIVE_FORBIDDEN_PORTS, alloc_ephemeral_port
from src.runtime import build_runtime
from src.web import app as web_app_mod
from src.web.app import create_app
from src.web.v1 import runner as v1_runner_mod
from src.web.workspace import parse_agy_stream_event

pytestmark = [pytest.mark.n2, pytest.mark.tier5]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FACILITY_A_PATH = _REPO_ROOT / "lab" / "configs" / "facility_a.json"

_SECRET_NINE_FORMATS: tuple[tuple[str, str], ...] = (
    ("sk-proj-LEAKED999999999999", "sk-proj-LEAKED999999999999"),
    ("area_sk-LEAKED999999999", "sk-LEAKED999999999"),
    ("ghp_1234567890abcdef", "ghp_1234567890abcdef"),
    ("github_pat_1234567890abcdef1234", "github_pat_1234567890abcdef1234"),
    ("AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123", "AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123"),
    ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("xoxb-123456789-987654321-abcdef12", "xoxb-123456789-987654321-abcdef12"),
    (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig12345678",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig12345678",
    ),
    ("https://alice:hunter2@example.com/ws?auth=secret99", "hunter2"),
    ("bad-sk-proj-LEAK422SECRET123456", "sk-proj-LEAK422SECRET123456"),
    ("fac-sk-1234567890abcdef", "sk-1234567890abcdef"),
    ("bot-ghp_1234567890abcdef", "ghp_1234567890abcdef"),
    ("aws-AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    (
        "key-AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123",
        "AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123",
    ),
)


class _NoSignalServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        return None


@contextlib.contextmanager
def _run_isolated_uvicorn(app: FastAPI) -> Iterator[str]:
    port = alloc_ephemeral_port()
    assert port not in LIVE_FORBIDDEN_PORTS
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = _NoSignalServer(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 10.0
    with httpx.Client(timeout=1.0, trust_env=False) as client:
        while time.monotonic() < deadline:
            try:
                if client.get(f"{base_url}/health").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


def test_agy_api_send_and_stream_enforce_connected_apps_safety_floor_and_policy_gateway(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    send_calls: list[str] = []
    stream_calls: list[str] = []

    async def _fake_send_agy_prompt(**kwargs: Any) -> dict[str, Any]:
        send_calls.append(str(kwargs.get("prompt", "")))
        return {
            "conversation_id": "22222222-3333-4444-5555-666666666666",
            "status": "SUCCESS",
            "response": "benign ok",
            "model": str(kwargs.get("model", "gemini-4-carbon-low")),
            "usage": {},
            "resume_command": "",
        }

    tool_script: list[dict[str, Any]] = []

    async def _fake_stream_agy_prompt(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        stream_calls.append(str(kwargs.get("prompt", "")))
        yield {"type": "init", "conversation_id": "conv-1", "model": kwargs["model"]}
        for ev in tool_script:
            yield dict(ev)
        yield {"type": "delta", "text": "finished"}
        yield {
            "type": "done",
            "conversation_id": "conv-1",
            "status": "SUCCESS",
            "response": "finished",
            "model": kwargs["model"],
            "usage": {},
            "resume_command": "",
        }

    monkeypatch.setattr(web_app_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(web_app_mod, "send_agy_prompt", _fake_send_agy_prompt)
    monkeypatch.setattr(web_app_mod, "stream_agy_prompt", _fake_stream_agy_prompt)

    app = create_app(db_path=tmp_path / "agy_gate.sqlite3")
    with TestClient(app) as client:
        # 1. Disabling app_agy blocks both /api/agy/send and /api/agy/stream with 403
        assert (
            client.patch("/api/v1/apps/app_agy", json={"enabled": False}).status_code == 200
        )
        r_send_disabled = client.post(
            "/api/agy/send",
            json={"prompt": "Say hello", "model": "gemini-4-carbon-low"},
        )
        assert r_send_disabled.status_code == 403

        r_stream_disabled = client.post(
            "/api/agy/stream",
            json={"prompt": "Say hello", "model": "gemini-4-carbon-low"},
        )
        assert r_stream_disabled.status_code == 403
        assert send_calls == []
        assert stream_calls == []

        # 2. Re-enable app_agy -> destructive prompts blocked at preflight with 403
        assert client.patch("/api/v1/apps/app_agy", json={"enabled": True}).status_code == 200
        for bad_prompt in ("Please run rm -rf /", "shred -u /etc/passwd"):
            r_bad_send = client.post(
                "/api/agy/send",
                json={"prompt": bad_prompt, "model": "gemini-4-carbon-low"},
            )
            assert r_bad_send.status_code == 403
            r_bad_stream = client.post(
                "/api/agy/stream",
                json={"prompt": bad_prompt, "model": "gemini-4-carbon-low"},
            )
            assert r_bad_stream.status_code == 403
        assert send_calls == []
        assert stream_calls == []

        # 3. Benign prompt + streamed destructive tool event -> blocked mid-stream via PolicyGateway
        tool_script[:] = [
            {
                "type": "tool",
                "name": "run_command",
                "command": "rm -rf /",
                "status": "completed",
            }
        ]
        with client.stream(
            "POST",
            "/api/agy/stream",
            json={"prompt": "Inspect workspace", "model": "gemini-4-carbon-low"},
        ) as resp:
            assert resp.status_code == 200
            raw = "".join(resp.iter_text())
        events = [
            json.loads(line[5:].strip())
            for line in raw.splitlines()
            if line.startswith("data:")
        ]
        assert any(ev["type"] == "error" and "PolicyGateway" in ev["message"] for ev in events)
        assert not any(ev["type"] == "done" for ev in events)
        assert any(
            entry["tool_id"] == "run_command" and entry["decision"] == "deny"
            for entry in app.state.v1_runner.policy_audit_log
        )

        # 4. Disabling app_pty blocks streamed terminal tool events cleanly
        assert (
            client.patch("/api/v1/apps/app_pty", json={"enabled": False}).status_code == 200
        )
        tool_script[:] = [
            {
                "type": "tool",
                "step_index": 1,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "command": "echo safe",
            }
        ]
        with client.stream(
            "POST",
            "/api/agy/stream",
            json={"prompt": "Inspect workspace", "model": "gemini-4-carbon-low"},
        ) as resp_pty:
            assert resp_pty.status_code == 200
            raw_pty = "".join(resp_pty.iter_text())
        events_pty = [
            json.loads(line[5:].strip())
            for line in raw_pty.splitlines()
            if line.startswith("data:")
        ]
        assert any(ev["type"] == "error" and "disabled" in ev["message"] for ev in events_pty)
        assert not any(ev["type"] == "done" for ev in events_pty)


async def test_execute_routine_bg_use_agy_gates_streamed_tools_and_connected_apps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streamed_events: list[dict[str, Any]] = [
        {"type": "tool", "name": "run_command", "command": "rm -rf /", "status": "completed"},
        {"type": "tool", "name": "write_file", "summary": "/etc/passwd", "status": "completed"},
        {"type": "delta", "text": "should not succeed"},
        {"type": "done", "status": "SUCCESS", "response": "should not succeed"},
    ]

    async def _fake_stream_agy_prompt(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        del kwargs
        for ev in streamed_events:
            yield dict(ev)

    monkeypatch.setattr(v1_runner_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(v1_runner_mod, "stream_agy_prompt", _fake_stream_agy_prompt)

    app = create_app(db_path=tmp_path / "routine_agy_gate.sqlite3")
    async with app.router.lifespan_context(app):
        store = app.state.workspace_store
        runner = app.state.v1_runner
        store.update_bot("bot_chief", {"engine_id": "agy"})
        routine = store.create_routine(
            "bot_chief",
            {
                "name": "Safety Check",
                "instruction": "check things",
                "schedule_type": "manual",
                "enabled": True,
            },
        )

        # Case A: app_pty=True, destructive rm -rf / -> blocked by PolicyGateway & logged
        run_a = store.create_routine_run(str(routine["id"]), "bot_chief", trigger="manual")
        await runner._execute_routine_bg(routine=routine, run=run_a, skip_auto_review=True)
        fetched_a = store.get_routine_run(str(run_a["id"]))
        assert fetched_a is not None
        assert fetched_a["status"] == "failed"
        assert "PolicyGateway" in str(fetched_a.get("error") or "")
        assert any(
            e["tool_id"] == "run_command" and e["decision"] == "deny"
            for e in runner.policy_audit_log
        )

        # Case B: app_files=False, write_file tool event -> blocked by Connected App check
        store.update_connected_app("app_files", {"enabled": False})
        streamed_events[:] = [
            {"type": "tool", "name": "write_file", "summary": "/etc/passwd", "status": "completed"},
            {"type": "delta", "text": "wrote"},
            {"type": "done", "status": "SUCCESS", "response": "wrote"},
        ]
        run_b = store.create_routine_run(str(routine["id"]), "bot_chief", trigger="manual")
        await runner._execute_routine_bg(routine=routine, run=run_b, skip_auto_review=True)
        fetched_b = store.get_routine_run(str(run_b["id"]))
        assert fetched_b is not None
        assert fetched_b["status"] == "failed"
        assert "Workspace Files app is disabled" in str(fetched_b.get("error") or "")


def test_http_validation_handler_and_agy_stream_error_scrub_all_secret_formats(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _crashing_stream(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        del kwargs
        joined = " | ".join(raw for raw, _ in _SECRET_NINE_FORMATS)
        raise RuntimeError(f"CLI crashed with secrets: {joined}")
        yield {}  # pragma: no cover

    monkeypatch.setattr(web_app_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(web_app_mod, "stream_agy_prompt", _crashing_stream)

    app = create_app(db_path=tmp_path / "redact_http.sqlite3")
    with TestClient(app) as client:
        for raw_secret, leak_needle in _SECRET_NINE_FORMATS:
            resp = client.post(
                "/api/v1/bots",
                json={"name": "b1", "engine_id": f"invalid_engine_{raw_secret}"},
            )
            assert resp.status_code == 422
            assert leak_needle not in resp.text, f"422 leaked {leak_needle}"
            assert "alice" not in resp.text

        failures_resp = client.get("/api/v1/diagnostics/failures?limit=50")
        assert failures_resp.status_code == 200
        failures_txt = failures_resp.text
        for _, leak_needle in _SECRET_NINE_FORMATS:
            assert leak_needle not in failures_txt, f"diagnostics leaked {leak_needle}"
        assert "alice" not in failures_txt

        with client.stream(
            "POST",
            "/api/agy/stream",
            json={"prompt": "hello", "model": "gemini-4-carbon-low"},
        ) as sresp:
            assert sresp.status_code == 200
            stream_body = "".join(sresp.iter_text())
        for _, leak_needle in _SECRET_NINE_FORMATS:
            assert leak_needle not in stream_body, f"/api/agy/stream leaked {leak_needle}"
        assert "alice" not in stream_body


def test_runtime_coordinator_adapter_fails_closed_on_facility_id_mismatch(
    tmp_path: Path,
) -> None:
    fac_a = load_facility_config(_FACILITY_A_PATH)
    rt = build_runtime(
        db_path=tmp_path / "fac_mismatch.sqlite3",
        profile_root=tmp_path / "profiles",
        facility_config=fac_a,
        auto_run=False,
        headless=True,
    )
    mismatched = TaskSpec(
        task_id="task_fac_b_mismatch",
        user_id="operator",
        profile_id="default",
        scope=TaskScope(facility_id="facility-b", allowed_areas=("area-1",), read_only=True),
        query="Check bomba 34",
    )
    with pytest.raises(PlanValidationError, match="does not match configured facility"):
        rt.web_coordinator.submit_task(mismatched)

    # Matching facility_id succeeds
    matched = TaskSpec(
        task_id="task_fac_a_ok",
        user_id="operator",
        profile_id="default",
        scope=TaskScope(facility_id="facility-a", allowed_areas=("area-1",), read_only=True),
        query="Check bomba 34",
    )
    run_ok = rt.web_coordinator.submit_task(matched)
    assert run_ok.task_id == "task_fac_a_ok"


async def test_playwright_ui_behaviors_sse_modal_composer_terminal_and_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist_index = _REPO_ROOT / "frontend" / "dist" / "index.html"
    assert dist_index.is_file(), "frontend/dist/index.html must exist for UI behavioral tests"

    async def _slow_stream_agy(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        yield {"type": "init", "conversation_id": "conv-ui-1", "model": kwargs["model"]}
        await asyncio.sleep(3.0)
        yield {
            "type": "done",
            "conversation_id": "conv-ui-1",
            "status": "SUCCESS",
            "response": "late reply",
            "model": kwargs["model"],
            "usage": {},
            "resume_command": "",
        }

    monkeypatch.setattr(v1_runner_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(v1_runner_mod, "stream_agy_prompt", _slow_stream_agy)

    app = create_app(db_path=tmp_path / "ui_behav.sqlite3")
    with _run_isolated_uvicorn(app) as base_url:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(viewport={"width": 1280, "height": 800})
            page_errors: list[str] = []
            sse_urls: list[str] = []
            interrupt_called = asyncio.Event()
            sse_route_count = 0

            async def _handle_routes(route: PwRoute) -> None:
                nonlocal sse_route_count
                req = route.request
                if "/api/v1/events/stream" in req.url:
                    sse_urls.append(req.url)
                    sse_route_count += 1
                    if sse_route_count == 1:
                        body = (
                            ": connected\n\n"
                            "retry: 150\n\n"
                            "id: evt_000001_uitest\n"
                            'data: {"id":"evt_000001_uitest","ts":"2026-11-27T00:00:00Z",'
                            '"bot_id":"bot_chief","thread_id":null,"turn_id":null,'
                            '"type":"bot.presence","payload":'
                            '{"state":"idle","subtext":"Live SSE OK"}}\n\n'
                        )
                        await route.fulfill(
                            status=200,
                            headers={
                                "Content-Type": "text/event-stream",
                                "Cache-Control": "no-cache",
                            },
                            body=body,
                        )
                        return
                    if sse_route_count == 2:
                        # Simulate stream.resync without id: followed by live event
                        body = (
                            ": connected\n\n"
                            'data: {"id":null,"ts":"2026-11-27T00:00:01Z",'
                            '"bot_id":null,"thread_id":null,"turn_id":null,'
                            '"type":"stream.resync","payload":'
                            '{"reason":"slow_consumer_overflow",'
                            '"epoch":"uitest","latest_seq":3,'
                            '"last_event_id":"evt_000003_uitest"}}\n\n'
                            "id: evt_000003_uitest\n"
                            'data: {"id":"evt_000003_uitest","ts":"2026-11-27T00:00:01Z",'
                            '"bot_id":"bot_chief","thread_id":null,"turn_id":null,'
                            '"type":"bot.presence","payload":'
                            '{"state":"idle","subtext":"Resynced OK"}}\n\n'
                        )
                        await route.fulfill(
                            status=200,
                            headers={
                                "Content-Type": "text/event-stream",
                                "Cache-Control": "no-cache",
                            },
                            body=body,
                        )
                        return
                await route.continue_()

            def _on_request(req: PwRequest) -> None:
                if "/interrupt" in req.url and req.method == "POST":
                    interrupt_called.set()

            page = await context.new_page()
            page.on("pageerror", lambda err: page_errors.append(str(err)))
            page.on("request", _on_request)
            await page.route("**/*", _handle_routes)

            await page.goto(f"{base_url}/app", wait_until="domcontentloaded")
            await page.get_by_text("Chief of Staff").first.wait_for(state="visible", timeout=10000)

            # 1. Verify sse.ts reconnect & stream.resync cursor propagation
            deadline = time.monotonic() + 8.0
            while len(sse_urls) < 3 and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            assert len(sse_urls) >= 3, f"Expected SSE reconnects, got {sse_urls}"
            assert "last_event_id=evt_000001_uitest" in sse_urls[1]
            assert "last_event_id=evt_000003_uitest" in sse_urls[2]

            # 2. Verify Modal focus trap + Escape close + focus restore
            settings_btn = page.locator('button[aria-label="Settings"]')
            await settings_btn.focus()
            await settings_btn.click()
            dialog = page.locator('[role="dialog"][aria-modal="true"]')
            await dialog.wait_for(state="visible", timeout=5000)

            for _ in range(8):
                await page.keyboard.press("Tab")
                inside = await page.evaluate(
                    "Boolean(document.querySelector('[role=\"dialog\"][aria-modal=\"true\"]')"
                    "?.contains(document.activeElement))"
                )
                assert inside is True, "Focus escaped modal during Tab cycling"

            await page.keyboard.press("Shift+Tab")
            inside_shift = await page.evaluate(
                "Boolean(document.querySelector('[role=\"dialog\"][aria-modal=\"true\"]')"
                "?.contains(document.activeElement))"
            )
            assert inside_shift is True

            await page.keyboard.press("Escape")
            await dialog.wait_for(state="hidden", timeout=5000)
            restored_label = await page.evaluate(
                "document.activeElement?.getAttribute('aria-label')"
            )
            assert restored_label == "Settings"

            # 3. Verify ComposerBox layout & Stop button during active turn
            composer = page.locator('textarea[aria-label="Message composer"]')
            await composer.wait_for(state="visible")
            overflow_ok = await page.evaluate(
                "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
            )
            assert overflow_ok is True

            await composer.fill("Hold turn open for stop button check")
            send_btn = page.locator('button[aria-label="Send message"]')
            assert await send_btn.is_enabled() is True
            await send_btn.click()

            stop_btn = page.locator('button[aria-label="Stop current generation"]')
            await stop_btn.wait_for(state="visible", timeout=5000)
            await stop_btn.click()
            await asyncio.wait_for(interrupt_called.wait(), timeout=5.0)
            await stop_btn.wait_for(state="hidden", timeout=5000)

            # 4. Verify TerminalTab renders local bot@local badge
            comp_btn = page.locator('button[aria-label="Open Bot Computer"]')
            await comp_btn.click()
            term_tab_btn = page.locator(
                '[role="tablist"][aria-label="Computer view"] button[aria-label="Terminal"]'
            )
            await term_tab_btn.wait_for(state="visible", timeout=5000)
            await term_tab_btn.click()
            await page.locator("span.font-mono", has_text="bot@local:").wait_for(
                state="visible", timeout=5000
            )

            # 5. Verify diagnostics.ts client-error reporting & backend redaction
            await page.evaluate(
                "window.dispatchEvent(new ErrorEvent('error', {"
                "message: 'UI crash Bearer sk-proj-CLIENTERRSECRET999',"
                "filename: 'https://alice:hunter2@127.0.0.1/app?auth=cliSecret88',"
                "lineno: 1, colno: 1}))"
            )

            async with httpx.AsyncClient(base_url=base_url, timeout=5.0, trust_env=False) as api:
                fe_failures: list[dict[str, Any]] = []
                diag_deadline = time.monotonic() + 5.0
                while time.monotonic() < diag_deadline:
                    r_diag = await api.get("/api/v1/diagnostics/failures?source=frontend&limit=10")
                    assert r_diag.status_code == 200
                    fe_failures = [
                        f
                        for f in r_diag.json()["failures"]
                        if "UI crash" in str(f.get("message", ""))
                    ]
                    if fe_failures:
                        break
                    await asyncio.sleep(0.1)
                assert fe_failures, "diagnostics.ts did not report client error to backend"
                serialized_fe = json.dumps(fe_failures)
                assert "sk-proj-CLIENTERRSECRET999" not in serialized_fe
                assert "hunter2" not in serialized_fe
                assert "cliSecret88" not in serialized_fe

            assert page_errors == [], f"Unexpected uncaught page errors: {page_errors}"
            await context.close()
            await browser.close()


async def test_agy_non_terminal_tool_names_blocked_across_stream_routine_and_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool_names = (
        "sh",
        "zsh",
        "run_cmd",
        "cmd",
        "spawn_process",
        "subprocess",
        "python3",
        "eval_tool",
        "read_workspace_info",
    )
    active_tool: dict[str, str] = {"name": "run_cmd"}

    async def _fake_stream_agy_prompt(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        yield {"type": "init", "conversation_id": "conv-w2", "model": kwargs["model"]}
        yield {
            "type": "tool",
            "step_index": 1,
            "state": "COMPLETED",
            "tool_name": active_tool["name"],
            "summary": "checking workspace status",
            "command": "rm -rf /",
        }
        yield {"type": "delta", "text": "all clean"}
        yield {
            "type": "done",
            "conversation_id": "conv-w2",
            "status": "SUCCESS",
            "response": "all clean",
            "model": kwargs["model"],
            "usage": {},
            "resume_command": "",
        }

    monkeypatch.setattr(web_app_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(web_app_mod, "stream_agy_prompt", _fake_stream_agy_prompt)
    monkeypatch.setattr(v1_runner_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(v1_runner_mod, "stream_agy_prompt", _fake_stream_agy_prompt)

    app = create_app(db_path=tmp_path / "w2_nonterm_gate.sqlite3")
    with TestClient(app) as client:
        app.state.workspace_store.update_bot("bot_chief", {"engine_id": "agy"})

        # 1. /api/agy/stream blocks every non-"terminal" tool name when app_pty is False or True
        for pty_enabled in (False, True):
            assert (
                client.patch("/api/v1/apps/app_pty", json={"enabled": pty_enabled}).status_code
                == 200
            )
            for t_name in tool_names:
                active_tool["name"] = t_name
                with client.stream(
                    "POST",
                    "/api/agy/stream",
                    json={"prompt": "Inspect workspace", "model": "gemini-4-carbon-low"},
                ) as resp:
                    assert resp.status_code == 200
                    raw = "".join(resp.iter_text())
                events = [
                    json.loads(line[5:].strip())
                    for line in raw.splitlines()
                    if line.startswith("data:")
                ]
                assert any(ev["type"] == "error" for ev in events), (pty_enabled, t_name)
                assert not any(ev["type"] == "done" for ev in events), (pty_enabled, t_name)

    # 2. _execute_routine_bg & _execute_agy_engine block non-"terminal" command tools
    app2 = create_app(db_path=tmp_path / "w2_nonterm_gate_runner.sqlite3")
    async with app2.router.lifespan_context(app2):
        store = app2.state.workspace_store
        runner = app2.state.v1_runner
        store.update_bot("bot_chief", {"engine_id": "agy"})
        routine = store.create_routine(
            "bot_chief",
            {
                "name": "W2 Bypass Check",
                "instruction": "check workspace",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        bot = store.get_bot("bot_chief")
        assert bot is not None

        for pty_enabled in (False, True):
            store.update_connected_app("app_pty", {"enabled": pty_enabled})
            active_tool["name"] = "run_cmd"
            run = store.create_routine_run(str(routine["id"]), "bot_chief", trigger="manual")
            await runner._execute_routine_bg(routine=routine, run=run, skip_auto_review=True)
            fetched = store.get_routine_run(str(run["id"]))
            assert fetched is not None
            assert fetched["status"] == "failed"

            msg = store.create_message(
                thread_id=str(bot["thread_id"]),
                sender_type="bot",
                sender_bot_id="bot_chief",
                sender_name=str(bot["name"]),
                content="",
                status="streaming",
            )
            final_content = await runner._execute_agy_engine(
                bot=bot,
                thread_id=str(bot["thread_id"]),
                turn_id=f"trn_w2_{pty_enabled}",
                message_id=str(msg["id"]),
                prompt="check workspace",
                model_id="gemini-4-carbon-low",
                allow_hydrogen=False,
                use_browser_context=False,
                is_channel=False,
            )
            assert "[Policy Block]" in final_content
            stored_msg = store.get_message(str(msg["id"]))
            assert stored_msg is not None
            assert stored_msg["status"] == "error"
            if pty_enabled:
                last_audit = runner.policy_audit_log[-1]
                assert last_audit["tool_id"] == "run_cmd"
                assert last_audit["effective_action_kind"] == "write"
                assert last_audit["decision"] == "deny"
                assert "command" in last_audit["arguments"]


async def test_playwright_sse_resync_cursor_never_regresses_on_stale_frame(
    tmp_path: Path,
) -> None:
    app = create_app(db_path=tmp_path / "ui_resync_noregress.sqlite3")
    with _run_isolated_uvicorn(app) as base_url:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(viewport={"width": 1280, "height": 800})
            sse_urls: list[str] = []
            sse_route_count = 0

            async def _handle_routes(route: PwRoute) -> None:
                nonlocal sse_route_count
                req = route.request
                if "/api/v1/events/stream" in req.url:
                    sse_urls.append(req.url)
                    sse_route_count += 1
                    if sse_route_count == 1:
                        body = (
                            ": connected\n\n"
                            "retry: 100\n\n"
                            'data: {"id":null,"ts":"2026-11-27T00:00:01Z",'
                            '"bot_id":null,"thread_id":null,"turn_id":null,'
                            '"type":"stream.resync","payload":'
                            '{"reason":"slow_consumer_overflow",'
                            '"epoch":"e1","latest_seq":5,'
                            '"last_event_id":"evt_000005_e1"}}\n\n'
                            "id: evt_000004_e1\n"
                            'data: {"id":"evt_000004_e1","ts":"2026-11-27T00:00:01Z",'
                            '"bot_id":"bot_chief","thread_id":null,"turn_id":null,'
                            '"type":"bot.presence","payload":'
                            '{"state":"idle","subtext":"Stale Frame"}}\n\n'
                        )
                        await route.fulfill(
                            status=200,
                            headers={
                                "Content-Type": "text/event-stream",
                                "Cache-Control": "no-cache",
                            },
                            body=body,
                        )
                        return
                    await route.fulfill(
                        status=200,
                        headers={
                            "Content-Type": "text/event-stream",
                            "Cache-Control": "no-cache",
                        },
                        body=": connected\n\nretry: 5000\n\n",
                    )
                    return
                await route.continue_()

            page = await context.new_page()
            await page.route("**/*", _handle_routes)
            await page.goto(f"{base_url}/app", wait_until="domcontentloaded")
            await page.get_by_text("Chief of Staff").first.wait_for(state="visible", timeout=10000)

            deadline = time.monotonic() + 8.0
            while len(sse_urls) < 2 and time.monotonic() < deadline:
                await asyncio.sleep(0.05)

            assert len(sse_urls) >= 2, f"Expected SSE reconnect, got {sse_urls}"
            assert "last_event_id=evt_000005_e1" in sse_urls[1]
            assert "evt_000004_e1" not in sse_urls[1]

            await context.close()
            await browser.close()


# ---------------------------------------------------------------------------
# Wave 3 Adversarial Regression Tests (Findings 1, 3, 4)
# ---------------------------------------------------------------------------


async def test_agy_empty_command_shadowing_cmd_blocked_across_stream_routine_and_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_ev: dict[str, Any] = {
        "type": "tool",
        "step_index": 1,
        "state": "COMPLETED",
        "tool_name": "custom_helper",
        "summary": "checking",
        "command": "",
        "cmd": "rm -rf /",
    }

    async def _fake_stream_agy_prompt(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        yield {"type": "init", "conversation_id": "conv-w3", "model": kwargs["model"]}
        yield dict(active_ev)
        yield {"type": "delta", "text": "wiped"}
        yield {
            "type": "done",
            "conversation_id": "conv-w3",
            "status": "SUCCESS",
            "response": "wiped",
            "model": kwargs["model"],
            "usage": {},
            "resume_command": "",
        }

    monkeypatch.setattr(web_app_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(web_app_mod, "stream_agy_prompt", _fake_stream_agy_prompt)
    monkeypatch.setattr(v1_runner_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(v1_runner_mod, "stream_agy_prompt", _fake_stream_agy_prompt)

    for shadow_case in (
        {"command": "", "cmd": "rm -rf /"},
        {"command": "   ", "command_line": "rm -rf /"},
    ):
        active_ev.clear()
        active_ev.update(
            {
                "type": "tool",
                "step_index": 1,
                "state": "COMPLETED",
                "tool_name": "custom_helper",
                "summary": "checking",
                **shadow_case,
            }
        )

        db_name = f"w3_shadow_{len(shadow_case.get('command', ''))}.sqlite3"
        app = create_app(db_path=tmp_path / db_name)
        with TestClient(app) as client:
            for pty_enabled in (False, True):
                assert (
                    client.patch("/api/v1/apps/app_pty", json={"enabled": pty_enabled}).status_code
                    == 200
                )
                with client.stream(
                    "POST",
                    "/api/agy/stream",
                    json={"prompt": "Inspect workspace", "model": "gemini-4-carbon-low"},
                ) as resp:
                    assert resp.status_code == 200
                    raw = "".join(resp.iter_text())
                events = [
                    json.loads(line[5:].strip())
                    for line in raw.splitlines()
                    if line.startswith("data:")
                ]
                assert any(ev["type"] == "error" for ev in events), (pty_enabled, shadow_case)
                assert not any(ev["type"] == "done" for ev in events), (pty_enabled, shadow_case)

    app2 = create_app(db_path=tmp_path / "w3_shadow_runner.sqlite3")
    async with app2.router.lifespan_context(app2):
        store = app2.state.workspace_store
        runner = app2.state.v1_runner
        store.update_bot("bot_chief", {"engine_id": "agy"})
        routine = store.create_routine(
            "bot_chief",
            {
                "name": "W3 Shadow Check",
                "instruction": "check workspace",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        bot = store.get_bot("bot_chief")
        assert bot is not None
        active_ev.clear()
        active_ev.update(
            {
                "type": "tool",
                "step_index": 1,
                "state": "COMPLETED",
                "tool_name": "custom_helper",
                "summary": "checking",
                "command": "",
                "cmd": "rm -rf /",
            }
        )

        for pty_enabled in (False, True):
            store.update_connected_app("app_pty", {"enabled": pty_enabled})
            run = store.create_routine_run(str(routine["id"]), "bot_chief", trigger="manual")
            await runner._execute_routine_bg(routine=routine, run=run, skip_auto_review=True)
            fetched = store.get_routine_run(str(run["id"]))
            assert fetched is not None
            assert fetched["status"] == "failed"

            msg = store.create_message(
                thread_id=str(bot["thread_id"]),
                sender_type="bot",
                sender_bot_id="bot_chief",
                sender_name=str(bot["name"]),
                content="",
                status="streaming",
            )
            final_content = await runner._execute_agy_engine(
                bot=bot,
                thread_id=str(bot["thread_id"]),
                turn_id=f"trn_w3_{pty_enabled}",
                message_id=str(msg["id"]),
                prompt="check workspace",
                model_id="gemini-4-carbon-low",
                allow_hydrogen=False,
                use_browser_context=False,
                is_channel=False,
            )
            assert "[Policy Block]" in final_content or "disabled" in final_content
            stored_msg = store.get_message(str(msg["id"]))
            assert stored_msg is not None
            assert stored_msg["status"] == "error"


async def test_websocket_browser_and_screencast_scrub_url_title_and_errors(
    tmp_path: Path,
) -> None:
    from fastapi.responses import HTMLResponse

    fixture_app = FastAPI()

    @fixture_app.get("/health")
    async def _fixture_health() -> dict[str, str]:
        return {"status": "ok"}

    @fixture_app.get("/login")
    async def _secret_page() -> HTMLResponse:
        return HTMLResponse(
            "<html><head><title>Portal sk-proj-REALBROWSERSECRET12 area_sk-12345678</title></head>"
            "<body><h1>Secret Login</h1></body></html>"
        )

    app = create_app(db_path=tmp_path / "ws_browser_scrub.sqlite3")
    with _run_isolated_uvicorn(fixture_app) as fixture_url, _run_isolated_uvicorn(app) as base_url:
        target_url = f"{fixture_url}/login?token=sk-proj-REALURLSECRET123456&k=area-sk-12345678"
        ws_base = base_url.replace("http://", "ws://", 1)
        needles = (
            "sk-proj-REALURLSECRET123456",
            "sk-proj-REALBROWSERSECRET12",
            "sk-12345678",
        )

        try:
            async with websockets.connect(f"{ws_base}/ws/browser") as ws_br:
                await ws_br.recv()  # initial stopped status
                await ws_br.send(json.dumps({"type": "navigate", "url": target_url}))
                seen_status = False
                seen_frame = False
                for _ in range(8):
                    msg = json.loads(await asyncio.wait_for(ws_br.recv(), timeout=10.0))
                    dumped = json.dumps(msg)
                    for needle in needles:
                        assert needle not in dumped, f"/ws/browser leaked {needle}: {dumped}"
                    if msg.get("type") == "status" and msg.get("running"):
                        seen_status = True
                        assert "[REDACTED]" in msg.get("url", "")
                        assert "[REDACTED]" in msg.get("title", "")
                    if msg.get("type") == "frame":
                        seen_frame = True
                        assert "[REDACTED]" in msg.get("url", "")
                        assert "[REDACTED]" in msg.get("title", "")
                    if seen_status and seen_frame:
                        break
                assert seen_status and seen_frame

                # Trigger ValueError error path with secret in invalid URL
                await ws_br.send(
                    json.dumps(
                        {
                            "type": "navigate",
                            "url": "ftp://evil.example/login?token=sk-proj-WSERRSECRET99",
                        }
                    )
                )
                err_msg = json.loads(await asyncio.wait_for(ws_br.recv(), timeout=5.0))
                while err_msg.get("type") == "frame":
                    err_msg = json.loads(await asyncio.wait_for(ws_br.recv(), timeout=5.0))
                assert err_msg.get("type") == "error"
                assert "sk-proj-WSERRSECRET99" not in json.dumps(err_msg)

            async with httpx.AsyncClient(base_url=base_url, timeout=5.0, trust_env=False) as api:
                tok_resp = await api.post("/api/v1/computers/default/vnc-token")
                assert tok_resp.status_code == 200
                ws_sc_path = str(tok_resp.json()["ws_screencast_url"])

            async with websockets.connect(f"{ws_base}{ws_sc_path}") as ws_sc:
                seen_sc_status = False
                seen_sc_frame = False
                for _ in range(6):
                    msg = json.loads(await asyncio.wait_for(ws_sc.recv(), timeout=5.0))
                    dumped = json.dumps(msg)
                    for needle in needles:
                        assert needle not in dumped, f"screencast leaked {needle}: {dumped}"
                    if msg.get("type") == "status" and msg.get("running"):
                        seen_sc_status = True
                        assert "[REDACTED]" in msg.get("url", "")
                        assert "[REDACTED]" in msg.get("title", "")
                    if msg.get("type") == "frame":
                        seen_sc_frame = True
                        assert "[REDACTED]" in msg.get("url", "")
                        assert "[REDACTED]" in msg.get("title", "")
                    if seen_sc_status and seen_sc_frame:
                        break
                assert seen_sc_status and seen_sc_frame

                await ws_sc.send(
                    json.dumps(
                        {
                            "type": "navigate",
                            "url": "ftp://evil.example/login?token=sk-proj-SCERRSECRET99",
                        }
                    )
                )
                sc_err = json.loads(await asyncio.wait_for(ws_sc.recv(), timeout=5.0))
                while sc_err.get("type") == "frame":
                    sc_err = json.loads(await asyncio.wait_for(ws_sc.recv(), timeout=5.0))
                assert sc_err.get("type") == "error"
                assert "sk-proj-SCERRSECRET99" not in json.dumps(sc_err)
        finally:
            async with httpx.AsyncClient(base_url=base_url, timeout=5.0, trust_env=False) as api:
                await api.post("/api/browser/stop")


def test_http_422_and_diagnostics_scrub_short_8_to_11_char_sk_tokens(
    tmp_path: Path,
) -> None:
    app = create_app(db_path=tmp_path / "w3_short_422.sqlite3")
    short_tokens = (
        ("area_sk-12345678", "sk-12345678"),
        ("area-sk-12345678", "sk-12345678"),
        ("sk-1234567890", "sk-1234567890"),
    )
    with TestClient(app) as client:
        for raw_tok, needle in short_tokens:
            resp = client.post(
                "/api/v1/bots",
                json={"name": "b1", "engine_id": f"bad_engine_{raw_tok}"},
            )
            assert resp.status_code == 422
            assert needle not in resp.text, f"422 leaked {needle}"

        diag_resp = client.get("/api/v1/diagnostics/failures?limit=50")
        assert diag_resp.status_code == 200
        for _, needle in short_tokens:
            assert needle not in diag_resp.text, f"diagnostics leaked {needle}"


# ---------------------------------------------------------------------------
# Wave 4 Adversarial Regression Tests (Findings 1 & 4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"command": ["rm", "-rf", "/"]},
        {"COMMAND": "rm -rf /"},
        {"args": {"command": ["rm", "-rf", "/"]}},
        {"tool_info": {"parameters": {"command": ["rm", "-rf", "/"]}}},
    ],
)
async def test_agy_structured_list_case_and_nested_commands_blocked_across_stream_routine_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, Any],
) -> None:
    active_ev: dict[str, Any] = {
        "type": "tool",
        "step_index": 1,
        "state": "COMPLETED",
        "tool_name": "custom_helper",
        "summary": "checking",
        **payload,
    }

    async def _fake_stream_agy_prompt(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        yield {"type": "init", "conversation_id": "conv-w4", "model": kwargs["model"]}
        yield dict(active_ev)
        yield {"type": "delta", "text": "wiped"}
        yield {
            "type": "done",
            "conversation_id": "conv-w4",
            "status": "SUCCESS",
            "response": "wiped",
            "model": kwargs["model"],
            "usage": {},
            "resume_command": "",
        }

    monkeypatch.setattr(web_app_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(web_app_mod, "stream_agy_prompt", _fake_stream_agy_prompt)
    monkeypatch.setattr(v1_runner_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(v1_runner_mod, "stream_agy_prompt", _fake_stream_agy_prompt)

    app = create_app(db_path=tmp_path / "w4_stream.sqlite3")
    with TestClient(app) as client:
        for pty_enabled in (False, True):
            assert (
                client.patch("/api/v1/apps/app_pty", json={"enabled": pty_enabled}).status_code
                == 200
            )
            with client.stream(
                "POST",
                "/api/agy/stream",
                json={"prompt": "Inspect workspace", "model": "gemini-4-carbon-low"},
            ) as resp:
                assert resp.status_code == 200
                raw = "".join(resp.iter_text())
            events = [
                json.loads(line[5:].strip())
                for line in raw.splitlines()
                if line.startswith("data:")
            ]
            assert any(ev["type"] == "error" for ev in events), (pty_enabled, payload)
            assert not any(ev["type"] == "done" for ev in events), (pty_enabled, payload)

    app2 = create_app(db_path=tmp_path / "w4_runner.sqlite3")
    async with app2.router.lifespan_context(app2):
        store = app2.state.workspace_store
        runner = app2.state.v1_runner
        store.update_bot("bot_chief", {"engine_id": "agy"})
        routine = store.create_routine(
            "bot_chief",
            {
                "name": "W4 Command Check",
                "instruction": "check workspace",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        bot = store.get_bot("bot_chief")
        assert bot is not None

        for pty_enabled in (False, True):
            store.update_connected_app("app_pty", {"enabled": pty_enabled})
            run = store.create_routine_run(str(routine["id"]), "bot_chief", trigger="manual")
            await runner._execute_routine_bg(routine=routine, run=run, skip_auto_review=True)
            fetched = store.get_routine_run(str(run["id"]))
            assert fetched is not None
            assert fetched["status"] == "failed"

            msg = store.create_message(
                thread_id=str(bot["thread_id"]),
                sender_type="bot",
                sender_bot_id="bot_chief",
                sender_name=str(bot["name"]),
                content="",
                status="streaming",
            )
            final_content = await runner._execute_agy_engine(
                bot=bot,
                thread_id=str(bot["thread_id"]),
                turn_id=f"trn_w4_{pty_enabled}",
                message_id=str(msg["id"]),
                prompt="check workspace",
                model_id="gemini-4-carbon-low",
                allow_hydrogen=False,
                use_browser_context=False,
                is_channel=False,
            )
            assert "[Policy Block]" in final_content or "disabled" in final_content
            stored_msg = store.get_message(str(msg["id"]))
            assert stored_msg is not None
            assert stored_msg["status"] == "error"


def test_browser_start_and_computer_files_http_errors_scrub_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proj_root = tmp_path / "projects"
    proj_dir = proj_root / "Grokbotclon"
    proj_dir.mkdir(parents=True)
    (proj_dir / "blocking_file").write_text("blocker", encoding="utf-8")
    monkeypatch.setenv("CONTROLBOT_PROJECTS_ROOT", str(proj_root))

    app = create_app(db_path=tmp_path / "w4_http_scrub.sqlite3")
    with TestClient(app) as client:
        # 1. /api/browser/start 422 must scrub URL secrets & userinfo
        for bad_url, needle in (
            (
                "ftp://evil.example/login?token=sk-proj-STARTLEAKSECRET123",
                "sk-proj-STARTLEAKSECRET123",
            ),
            ("ftp://alice:hunter2@evil.example/login?auth=querySecretVal", "hunter2"),
        ):
            r_start = client.post("/api/browser/start", json={"url": bad_url})
            assert r_start.status_code == 422
            assert needle not in r_start.text
            assert "querySecretVal" not in r_start.text

        # 2. /api/v1/computers/default/files/{mkdir,write,upload} OSError paths scrub secrets
        r_mkdir = client.post(
            "/api/v1/computers/default/files/mkdir",
            json={"project": "Grokbotclon", "path": "blocking_file/sk-proj-MKDIREXPOSE1234"},
        )
        assert r_mkdir.status_code == 400
        assert "sk-proj-MKDIREXPOSE1234" not in r_mkdir.text

        r_write = client.post(
            "/api/v1/computers/default/files/write",
            json={
                "project": "Grokbotclon",
                "path": "blocking_file/sk-proj-WRITEEXPOSE1234",
                "content": "hello",
            },
        )
        assert r_write.status_code == 400
        assert "sk-proj-WRITEEXPOSE1234" not in r_write.text

        r_upload = client.post(
            "/api/v1/computers/default/files/upload",
            params={
                "project": "Grokbotclon",
                "path": "blocking_file/sub",
                "name": "sk-proj-UPLEXPOSE1234.txt",
            },
            content=b"hello",
        )
        assert r_upload.status_code == 400
        assert "sk-proj-UPLEXPOSE1234" not in r_upload.text

        # 3. DELETE /api/v1/computers/default/files OSError detail scrubs secret path
        locked_dir = proj_dir / "locked_sk-proj-DELEXPOSE1234"
        locked_dir.mkdir()
        (locked_dir / "inner.txt").write_text("x", encoding="utf-8")

        def _failing_rmtree(path: Any, *args: Any, **kwargs: Any) -> None:
            del args, kwargs
            raise PermissionError(13, "Permission denied", str(path))

        import shutil

        monkeypatch.setattr(shutil, "rmtree", _failing_rmtree)
        r_del = client.delete(
            "/api/v1/computers/default/files",
            params={"project": "Grokbotclon", "path": "locked_sk-proj-DELEXPOSE1234"},
        )
        assert r_del.status_code == 400
        assert "sk-proj-DELEXPOSE1234" not in r_del.text


# ---------------------------------------------------------------------------
# Wave 5 Adversarial Regression Tests (Findings 3 & 4 + ws_live_terminal)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"args": ["rm", "-rf", "/"]},
        {"argv": ["rm", "-rf", "/"]},
        {"toolSummary": "Check", "code": "import shutil; shutil.rmtree('/')"},
        {"toolSummary": "Check", "shell": "rm -rf /"},
        {"toolSummary": "Check", "bash": "rm -rf /"},
        {"data": ["rm", "-rf", "/"]},
    ],
)
def test_wave5_agy_stream_blocks_alternate_keys_and_list_containers_over_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, Any],
) -> None:
    raw_ndjson = json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "step_type": "tool",
                "step_index": 1,
                "state": "COMPLETED",
                "tool_name": "run_command",
                "tool_info": {"name": "run_command", "parameters": payload},
            },
        }
    )
    parsed_ev = parse_agy_stream_event(raw_ndjson)
    assert parsed_ev is not None
    assert "command" in parsed_ev

    async def _fake_stream_agy_prompt(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        yield {"type": "init", "conversation_id": "conv-w5", "model": kwargs["model"]}
        yield dict(parsed_ev)
        yield {"type": "delta", "text": "should not reach"}
        yield {
            "type": "done",
            "conversation_id": "conv-w5",
            "status": "SUCCESS",
            "response": "should not reach",
            "model": kwargs["model"],
            "usage": {},
            "resume_command": "",
        }

    monkeypatch.setattr(web_app_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(web_app_mod, "stream_agy_prompt", _fake_stream_agy_prompt)

    app = create_app(db_path=tmp_path / "w5_agy_stream.sqlite3")
    with TestClient(app) as client:
        with client.stream(
            "POST",
            "/api/agy/stream",
            json={"prompt": "Inspect workspace", "model": "gemini-4-carbon-low"},
        ) as resp:
            assert resp.status_code == 200
            body = "".join(resp.iter_text())
        events = [
            json.loads(line[5:].strip())
            for line in body.splitlines()
            if line.startswith("data:")
        ]
        assert any(ev["type"] == "error" and "PolicyGateway" in ev["message"] for ev in events)
        assert not any(ev["type"] == "done" for ev in events)


def test_wave5_memory_http_errors_and_ws_terminal_error_scrub_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proj_root = tmp_path / "projects"
    proj_root.mkdir(parents=True)
    monkeypatch.setenv("CONTROLBOT_PROJECTS_ROOT", str(proj_root))

    app = create_app(db_path=tmp_path / "w5_mem_scrub.sqlite3")
    with TestClient(app) as client:
        for raw_secret, needle in _SECRET_NINE_FORMATS:
            if "/" in raw_secret or "?" in raw_secret or "#" in raw_secret:
                continue
            r_del = client.delete(
                f"/api/v1/memory/{raw_secret}",
                params={"scope": "bot", "bot_id": "main"},
            )
            assert r_del.status_code == 404
            assert needle not in r_del.text, f"memory DELETE 404 leaked {needle}: {r_del.text}"

            r_patch = client.patch(
                f"/api/v1/memory/{raw_secret}",
                params={"scope": "bot", "bot_id": "main"},
                json={"revision": 1, "content": "updated"},
            )
            assert r_patch.status_code == 404
            assert needle not in r_patch.text, f"memory PATCH 404 leaked {needle}: {r_patch.text}"

        r_bad_scope = client.get(
            "/api/v1/memory",
            params={"scope": "invalid_scope_sk-1234567890abcdef"},
        )
        assert r_bad_scope.status_code == 422
        assert "sk-1234567890abcdef" not in r_bad_scope.text

        with client.websocket_connect("/ws/terminal?project=../sk-1234567890abcdef") as ws:
            err_msg = ws.receive_json()
            assert err_msg.get("type") == "error"
            assert "sk-1234567890abcdef" not in json.dumps(err_msg)


# ---------------------------------------------------------------------------
# Wave 6 Adversarial Integration Regression Tests (Findings 1 & 3)
# ---------------------------------------------------------------------------


def test_wave6_agy_stream_blocks_long_command_past_16384_and_allows_benign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    padding = "a" * 16384
    long_bad = f"echo {padding}; rm -rf /"
    long_safe = f"echo {padding}; ls /tmp"

    def _make_event(cmd_text: str, step_idx: int) -> dict[str, Any]:
        raw = json.dumps(
            {
                "event": "step_update",
                "step_update": {
                    "step_type": "tool",
                    "step_index": step_idx,
                    "state": "ACTIVE",
                    "tool_name": "run_command",
                    "tool_info": {"name": "run_command", "parameters": {"command": cmd_text}},
                },
            }
        )
        ev = parse_agy_stream_event(raw)
        assert ev is not None
        assert ev.get("command") == cmd_text
        return ev

    stream_events: list[dict[str, Any]] = []

    async def _fake_stream_agy_prompt(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        yield {"type": "init", "conversation_id": "conv-w6", "model": kwargs["model"]}
        for ev in stream_events:
            yield dict(ev)
        yield {"type": "delta", "text": "finished"}
        yield {
            "type": "done",
            "conversation_id": "conv-w6",
            "status": "SUCCESS",
            "response": "finished",
            "model": kwargs["model"],
            "usage": {},
            "resume_command": "",
        }

    monkeypatch.setattr(web_app_mod, "find_agy_executable", lambda: "/usr/local/bin/agy")
    monkeypatch.setattr(web_app_mod, "stream_agy_prompt", _fake_stream_agy_prompt)

    app = create_app(db_path=tmp_path / "w6_long_stream.sqlite3")
    with TestClient(app) as client:
        stream_events[:] = [_make_event(long_bad, 1)]
        with client.stream(
            "POST",
            "/api/agy/stream",
            json={"prompt": "Run workspace task", "model": "gemini-4-carbon-low"},
        ) as resp:
            assert resp.status_code == 200
            body = "".join(resp.iter_text())
        events = [
            json.loads(line[5:].strip())
            for line in body.splitlines()
            if line.startswith("data:")
        ]
        assert any(
            ev["type"] == "error"
            and "safety_floor:destructive_rm_root_or_glob" in ev["message"]
            for ev in events
        )
        assert not any(ev["type"] == "done" for ev in events)

        stream_events[:] = [_make_event(long_safe, 2)]
        with client.stream(
            "POST",
            "/api/agy/stream",
            json={"prompt": "Run safe workspace task", "model": "gemini-4-carbon-low"},
        ) as resp_ok:
            assert resp_ok.status_code == 200
            body_ok = "".join(resp_ok.iter_text())
        events_ok = [
            json.loads(line[5:].strip())
            for line in body_ok.splitlines()
            if line.startswith("data:")
        ]
        assert any(ev["type"] == "done" for ev in events_ok)
        assert not any(ev["type"] == "error" for ev in events_ok)


@pytest.mark.parametrize("bad_field", ["from", "to", "cc", "bcc", "subject"])
def test_wave6_draft_resolve_smtp_crlf_headers_return_200_with_clean_feedback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bad_field: str,
) -> None:
    import smtplib

    sent_subjects: list[str] = []

    class _FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float = 10.0) -> None:
            del host, port, timeout

        def __enter__(self) -> _FakeSMTP:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def send_message(self, msg: Any) -> None:
            sent_subjects.append(str(msg["Subject"]))

    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)

    app = create_app(db_path=tmp_path / f"w6_draft_http_{bad_field}.sqlite3")
    with TestClient(app) as client:
        store = app.state.workspace_store
        store.update_settings({"smtp": {"host": "127.0.0.1", "port": 2525}})

        bad_fields: dict[str, Any] = {
            "from": "sender@example.com",
            "to": "recipient@example.com",
            "cc": "cc@example.com",
            "bcc": "bcc@example.com",
            "subject": "Quarterly Report",
            "body": "Body text",
        }
        bad_fields[bad_field] = f"{bad_fields[bad_field]}\nBcc: attacker@evil.test"

        r_create = client.post(
            "/api/v1/drafts",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "channel_type": "email",
                "title": "Bad Header Email",
                "fields": bad_fields,
            },
        )
        assert r_create.status_code == 201
        draft_id = r_create.json()["id"]

        r_res = client.post(f"/api/v1/drafts/{draft_id}/resolve", json={"action": "send"})
        assert r_res.status_code == 200
        assert r_res.json()["status"] == "sent"
        assert sent_subjects == []

        msgs, _ = store.list_thread_messages("thr_bot_chief")
        assert any(
            m["status"] == "error" and "Invalid CR/LF" in str(m["content"])
            for m in msgs
        )

        # Benign control sends normally
        r_ok = client.post(
            "/api/v1/drafts",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "channel_type": "email",
                "title": "Clean Email",
                "fields": {
                    "from": "sender@example.com",
                    "to": "recipient@example.com",
                    "subject": "Clean Subject",
                    "body": "All good",
                },
            },
        )
        assert r_ok.status_code == 201
        ok_id = r_ok.json()["id"]
        r_ok_res = client.post(f"/api/v1/drafts/{ok_id}/resolve", json={"action": "send"})
        assert r_ok_res.status_code == 200
        assert sent_subjects == ["Clean Subject"]


# =============================================================================
# Wave 7 Integration Tests (AGY Multi-Key Command Shadowing, Python Reflection,
# and xargs Here-String/Heredoc End-to-End via /api/agy/stream & Runner)
# =============================================================================


@pytest.mark.parametrize(
    ("label", "raw_tool_line"),
    [
        (
            "multi_key_script_shadowing",
            json.dumps(
                {
                    "event": "step_update",
                    "step_update": {
                        "step_type": "tool",
                        "step_index": 1,
                        "state": "WAITING",
                        "tool_name": "run_command",
                        "tool_info": {
                            "name": "run_command",
                            "parameters": {"command": "echo safe", "script": "rm -rf /"},
                        },
                    },
                }
            ),
        ),
        (
            "python_reflection_dict",
            json.dumps(
                {
                    "event": "step_update",
                    "step_update": {
                        "step_type": "tool",
                        "step_index": 1,
                        "state": "WAITING",
                        "tool_name": "run_command",
                        "tool_info": {
                            "name": "run_command",
                            "parameters": {
                                "command": (
                                    'python3 -c \'import os; os.__dict__["sys"+"tem"]("rm -rf /")\''
                                ),
                            },
                        },
                    },
                }
            ),
        ),
        (
            "xargs_herestring_etc",
            json.dumps(
                {
                    "event": "step_update",
                    "step_update": {
                        "step_type": "tool",
                        "step_index": 1,
                        "state": "WAITING",
                        "tool_name": "run_command",
                        "tool_info": {
                            "name": "run_command",
                            "parameters": {"command": "xargs rm -rf <<< /etc"},
                        },
                    },
                }
            ),
        ),
    ],
)
def test_wave7_agy_stream_blocks_shadowed_and_obfuscated_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    raw_tool_line: str,
) -> None:
    from src.web.workspace import parse_agy_stream_event

    db_path = tmp_path / f"wave7_{label}.sqlite3"
    app = create_app(db_path=db_path)

    async def _fake_stream_agy_prompt(**_kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        ev = parse_agy_stream_event(raw_tool_line)
        assert ev is not None
        yield ev
        yield {"type": "delta", "text": "should not reach"}
        yield {"type": "result", "status": "SUCCESS", "conversation_id": "conv_w7"}

    monkeypatch.setattr(web_app_mod, "find_agy_executable", lambda: "/usr/bin/agy")
    monkeypatch.setattr(web_app_mod, "stream_agy_prompt", _fake_stream_agy_prompt)

    with TestClient(app) as client:
        resp = client.post(
            "/api/agy/stream",
            json={"prompt": "run check", "include_browser_context": False},
        )
        assert resp.status_code == 200
        events = [
            json.loads(line[len("data: ") :])
            for line in resp.text.splitlines()
            if line.startswith("data: ")
        ]
        err_events = [e for e in events if e.get("type") == "error"]
        assert err_events, f"Expected error SSE event for {label}, got: {events}"
        assert "safety_floor:" in str(err_events[0].get("message", ""))
        assert not any(e.get("type") in {"done", "result"} for e in events)


def test_wave7_agy_stream_allows_benign_multi_key_tool_control(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.web.workspace import parse_agy_stream_event

    db_path = tmp_path / "wave7_benign_multi.sqlite3"
    app = create_app(db_path=db_path)

    raw_tool_line = json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "step_type": "tool",
                "step_index": 1,
                "state": "WAITING",
                "tool_name": "run_command",
                "tool_info": {
                    "name": "run_command",
                    "parameters": {"command": "echo safe", "script": "ls /tmp"},
                },
            },
        }
    )

    async def _fake_stream_agy_prompt(**_kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        ev = parse_agy_stream_event(raw_tool_line)
        assert ev is not None
        yield ev
        yield {"type": "delta", "text": "done ok"}
        yield {"type": "result", "status": "SUCCESS", "conversation_id": "conv_w7_ok"}

    monkeypatch.setattr(web_app_mod, "find_agy_executable", lambda: "/usr/bin/agy")
    monkeypatch.setattr(web_app_mod, "stream_agy_prompt", _fake_stream_agy_prompt)

    with TestClient(app) as client:
        resp = client.post(
            "/api/agy/stream",
            json={"prompt": "run safe check", "include_browser_context": False},
        )
        assert resp.status_code == 200
        events = [
            json.loads(line[len("data: ") :])
            for line in resp.text.splitlines()
            if line.startswith("data: ")
        ]
        assert not any(e.get("type") == "error" for e in events), events
        assert any(
            e.get("type") == "result" and e.get("status") == "SUCCESS" for e in events
        ), events


def test_wave7_runner_stream_gate_blocks_multi_key_command_without_preparsed_commands(
    tmp_path: Path,
) -> None:
    """Runner extraction catches secondary keys even if an event omits pre-parsed commands."""
    from src.contracts.envelope import Lane

    app = create_app(db_path=tmp_path / "wave7_runner_direct.sqlite3")
    with TestClient(app):
        runner = app.state.v1_runner
        ev = {
            "type": "tool",
            "tool_name": "run_command",
            "step_index": 1,
            "state": "WAITING",
            "tool_params": {"command": "echo safe", "script": "rm -rf /"},
        }
        allowed, reason, meta = runner.gate_agy_stream_tool_event(
            ev=ev,
            bot_id="bot_chief",
            turn_id="turn_w7_raw_shadow",
            lane=Lane.GENERAL,
            pending_syntax_tools={},
            tool_state_by_call={},
            active_unnamed_calls_by_tool={},
        )
        assert allowed is False
        assert reason is not None and "safety_floor:" in reason
        assert meta["tool_name"] == "run_command"

