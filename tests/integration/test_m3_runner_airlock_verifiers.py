"""N2 integration tests for M3 HTTP client, AgentTurnRunner, Airlock, & Draft delivery."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from lab.testing import run_asgi_server
from src.adapters.config import AreaConfig, AssetMapping, FacilityConfig
from src.adapters.web_search import EgressBlockedError, EgressGuard, PlaywrightMcpBridge
from src.contracts.enums import EffectClass, TaskStatus
from src.contracts.envelope import Lane
from src.contracts.models import ToolSpec
from src.engine.coordinator import Coordinator
from src.engine.tool_registry import ToolRegistry
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
)
from src.runtime import RuntimeCoordinatorAdapter
from src.storage.repo import StorageRepo
from src.web.live_browser import LiveBrowserController
from src.web.v1.events import EventBus
from src.web.v1.runner import AgentTurnRunner
from src.web.v1.store import WorkspaceStore


def _dummy_prompt() -> PromptContext:
    return PromptContext(
        task_id="task-m3-1",
        run_id="run-m3-1",
        depth=0,
        query="Inspect pump 34",
        facility_id="facility-a",
        allowed_areas=("area-1",),
    )


def _dummy_budget() -> BudgetRemaining:
    return BudgetRemaining(
        active_children_remaining=1,
        depth_remaining=1,
        tool_calls_remaining=10,
        model_calls_remaining=5,
        wall_seconds_remaining=60.0,
        tokens_remaining=8000,
    )


def _sample_tools() -> tuple[ToolSpec, ...]:
    return (
        ToolSpec(
            tool_id="scada.read_alarms",
            version="1.0.0",
            input_schema={"type": "object", "properties": {"asset": {"type": "string"}}},
            output_schema={"type": "object"},
            effect_class=EffectClass.READ,
            verifier_name="scada_verifier",
        ),
        ToolSpec(
            tool_id="maint.read_work_orders",
            version="1.0.0",
            input_schema={"type": "object", "properties": {"asset": {"type": "string"}}},
            output_schema={"type": "object"},
            effect_class=EffectClass.READ,
            verifier_name="maint_verifier",
        ),
    )


@pytest.mark.n2
async def test_local_http_client_response_format_multi_tool_calls_and_streaming() -> None:
    recorded_bodies: list[dict[str, Any]] = []
    app = FastAPI()

    @app.post("/v1/chat/completions")
    async def completions(request: Request) -> Response:
        body = await request.json()
        recorded_bodies.append(body)
        if body.get("stream"):

            async def _sse() -> AsyncIterator[bytes]:
                chunks = [
                    {
                        "id": "c1",
                        "model": "qwen2.5-7b-instruct",
                        "choices": [{"index": 0, "delta": {"content": "Checking "}}],
                    },
                    {
                        "id": "c1",
                        "model": "qwen2.5-7b-instruct",
                        "choices": [
                            {
                                "index": 0,
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": "call_a",
                                            "type": "function",
                                            "function": {
                                                "name": "scada.read_alarms",
                                                "arguments": '{"asset":',
                                            },
                                        }
                                    ]
                                },
                            }
                        ],
                    },
                    {
                        "id": "c1",
                        "model": "qwen2.5-7b-instruct",
                        "choices": [
                            {
                                "index": 0,
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "function": {"arguments": '"pump 34"}'},
                                        },
                                        {
                                            "index": 1,
                                            "id": "call_b",
                                            "type": "function",
                                            "function": {
                                                "name": "maint.read_work_orders",
                                                "arguments": '{"asset":"pump 34"}',
                                            },
                                        },
                                    ]
                                },
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 40,
                            "completion_tokens": 20,
                            "total_tokens": 60,
                        },
                    },
                ]
                for ch in chunks:
                    yield f"data: {json.dumps(ch)}\n\n".encode()
                yield b"data: [DONE]\n\n"

            return StreamingResponse(_sse(), media_type="text/event-stream")

        if not body.get("tools"):
            return JSONResponse(
                {
                    "id": "cmpl-final",
                    "model": "qwen2.5-7b-instruct",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": json.dumps(
                                    {"decision_type": "final", "final_answer": "All clear."}
                                ),
                            },
                        }
                    ],
                }
            )

        return JSONResponse(
            {
                "id": "cmpl-multi",
                "model": "qwen2.5-7b-instruct",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Calling both OT tools",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "scada.read_alarms",
                                        "arguments": '{"asset":"pump 34"}',
                                    },
                                },
                                {
                                    "id": "call_2",
                                    "type": "function",
                                    "function": {
                                        "name": "maint.read_work_orders",
                                        "arguments": '{"asset":"pump 34"}',
                                    },
                                },
                            ],
                        },
                    }
                ],
            }
        )

    tools = _sample_tools()
    async with run_asgi_server(app) as origin:
        client = LocalHttpModelClient(
            LocalModelConfig(origin=origin, model_id="qwen2.5-7b-instruct")
        )
        # 1. With tools -> NO response_format sent, ALL tool_calls parsed
        dec, all_calls = await client.decide_all_tool_calls(_dummy_prompt(), tools, _dummy_budget())
        assert "response_format" not in recorded_bodies[-1]
        assert dec.tool_call is not None
        assert dec.tool_call.tool_id == "scada.read_alarms"
        assert len(all_calls) == 2
        assert [c.tool_id for c in client.last_tool_calls] == [
            "scada.read_alarms",
            "maint.read_work_orders",
        ]

        # 2. Without tools -> response_format IS sent
        dec_no_tools = await client.decide(_dummy_prompt(), (), _dummy_budget())
        assert recorded_bodies[-1]["response_format"] == {"type": "json_object"}
        assert dec_no_tools.decision_type == "final"

        # 3. Streaming decide with delta callback and multi-tool assembly
        streamed_deltas: list[str] = []
        dec_stream = await client.stream_decide(
            _dummy_prompt(),
            tools,
            _dummy_budget(),
            on_delta=lambda txt: streamed_deltas.append(txt),
        )
        assert streamed_deltas == ["Checking "]
        assert dec_stream.decision_type == "tool_call"
        assert len(client.last_tool_calls) == 2
        assert dec_stream.usage.total_tokens == 60


def _build_real_runtime_adapter(
    tmp_path: Path,
    *,
    turns: list[EmulatedTurn],
    failing_resume: bool = False,
) -> tuple[RuntimeCoordinatorAdapter, StorageRepo]:
    repo = StorageRepo(tmp_path / "coord.sqlite3")
    repo.init_db()
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            tool_id="scada.read_alarms",
            version="1.0.0",
            input_schema={"type": "object", "properties": {"asset": {"type": "string"}}},
            output_schema={"type": "object"},
            effect_class=EffectClass.READ,
            verifier_name="scada_verifier",
        ),
        lambda args, ctx: {"alarms": ["ALM-3401"], "asset": args.get("asset", "pump-34")},
    )
    model_client = EmulatedModelClient(mode="custom", default_turns=turns)
    coordinator = Coordinator(repo=repo, tool_registry=registry, model_client=model_client)
    if failing_resume:

        class _FailingResumeAdapter(RuntimeCoordinatorAdapter):
            def resume_task(self, run_id: str, human_input: dict[str, Any]) -> Any:
                del run_id, human_input
                raise RuntimeError("Coordinator resume backend crashed")

        return _FailingResumeAdapter(repo=repo, coordinator=coordinator), repo
    return RuntimeCoordinatorAdapter(repo=repo, coordinator=coordinator), repo


@pytest.mark.n2
async def test_runner_runtime_hitl_resume_receipt_outcome_and_routine_await(
    tmp_path: Path,
) -> None:
    usage = ModelUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20)
    turns = [
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id="scada.read_alarms",
                    args={"asset": "pump-34"},
                ),
                usage=usage,
            )
        ),
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="request_input",
                required_action="Confirm SCADA acknowledgment",
                usage=usage,
            )
        ),
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="final",
                final_answer="Resumed runtime check succeeded: ALM-3401 verified.",
                usage=usage,
            )
        ),
    ]
    adapter, _repo = _build_real_runtime_adapter(tmp_path, turns=turns)
    store = WorkspaceStore(tmp_path / "ws.sqlite3")
    bus = EventBus()
    browser = LiveBrowserController(profile_root=tmp_path / "browser")
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=browser,
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
    )

    try:
        store.update_bot("bot_ops", {"engine_id": "controlbot_runtime"})
        bot = store.get_bot("bot_ops")
        assert bot is not None
        thread_id = str(bot["thread_id"])
        u_msg = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Operator",
            content="Check pump-34 alarms in SCADA",
        )

        # Turn 1: executes tool (ReceiptOutcome.SUCCEEDED -> ok) and pauses WAITING_FOR_INPUT
        runner.start_turn(thread_id=thread_id, user_message=u_msg)
        for _ in range(80):
            approvals = store.list_thread_approvals(thread_id)
            if approvals:
                break
            await asyncio.sleep(0.05)

        approvals = store.list_thread_approvals(thread_id)
        assert len(approvals) == 1
        appr = approvals[0]
        assert "run_id" in appr["arguments"]

        # Verify presence is waiting_human (NOT overwritten with idle) and ReceiptOutcome fixed
        bot_after_pause = store.get_bot("bot_ops")
        assert bot_after_pause is not None
        assert bot_after_pause["status_state"] == "waiting_human"
        assert bot_after_pause["needs_attention"] is True

        events = bus.recent_events(limit=100)
        tool_events = [
            ev
            for ev in events
            if ev["type"] == "tool.call.updated"
            and ev["payload"].get("tool_name") == "scada.read_alarms"
        ]
        assert tool_events and tool_events[0]["payload"]["status"] == "ok"

        # Resolve approval -> resumes Coordinator, awaits wait_for_run, posts final answer
        resolved = store.resolve_approval(appr["id"], "allow_once")
        await runner.on_approval_resolved(resolved, decision="allow_once")

        msgs, _ = store.list_thread_messages(thread_id)
        assert any("ALM-3401 verified" in str(m["content"]) for m in msgs)
        bot_after_resume = store.get_bot("bot_ops")
        assert bot_after_resume is not None
        assert bot_after_resume["status_state"] == "idle"
    finally:
        await runner.stop_scheduler()
        await adapter.shutdown()
        store.close()

@pytest.mark.n2
async def test_runner_hitl_resume_error_not_swallowed_and_deny_cancels(tmp_path: Path) -> None:
    usage = ModelUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20)
    turns = [
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="request_input",
                required_action="Approve override",
                usage=usage,
            )
        ),
    ]
    adapter, _repo = _build_real_runtime_adapter(tmp_path, turns=turns, failing_resume=True)
    store = WorkspaceStore(tmp_path / "ws_err.sqlite3")
    bus = EventBus()
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
    )

    try:
        store.update_bot("bot_ops", {"engine_id": "controlbot_runtime"})
        bot = store.get_bot("bot_ops")
        assert bot is not None
        thread_id = str(bot["thread_id"])
        u_msg = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_name="Operator",
            content="Run SCADA diagnostic",
        )
        runner.start_turn(thread_id=thread_id, user_message=u_msg)
        for _ in range(80):
            if store.list_thread_approvals(thread_id):
                break
            await asyncio.sleep(0.05)

        appr = store.list_thread_approvals(thread_id)[0]
        resolved = store.resolve_approval(appr["id"], "allow_once")
        await runner.on_approval_resolved(resolved, decision="allow_once")

        msgs, _ = store.list_thread_messages(thread_id)
        err_msgs = [m for m in msgs if m["status"] == "error"]
        assert err_msgs
        assert "Failed to resume runtime run" in str(err_msgs[-1]["content"])

        # Test deny cancels a paused run
        snap_before = adapter.get_task_snapshot(appr["arguments"]["run_id"])
        assert snap_before is not None and snap_before.run.status == TaskStatus.WAITING_FOR_INPUT
        appr2 = store.create_approval(
            bot_id="bot_ops",
            thread_id=thread_id,
            kind="standard",
            title="Deny test",
            target=f"run:{appr['arguments']['run_id']}",
            arguments={"run_id": appr["arguments"]["run_id"]},
        )
        res_deny = store.resolve_approval(appr2["id"], "deny")
        await runner.on_approval_resolved(res_deny, decision="deny")
        snap_after = adapter.get_task_snapshot(appr["arguments"]["run_id"])
        assert snap_after is not None and snap_after.run.status == TaskStatus.CANCELLED
    finally:
        await runner.stop_scheduler()
        await adapter.shutdown()
        store.close()

@pytest.mark.n2
async def test_runner_routine_runtime_awaits_and_connected_app_toggles(tmp_path: Path) -> None:
    usage = ModelUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20)
    adapter, _repo = _build_real_runtime_adapter(
        tmp_path,
        turns=[
            EmulatedTurn(
                decision=ModelDecision(
                    decision_type="final",
                    final_answer="Shift summary: all sensors nominal.",
                    usage=usage,
                )
            )
        ],
    )
    store = WorkspaceStore(tmp_path / "ws_rtn.sqlite3")
    bus = EventBus()
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
    )
    try:
        store.update_bot("bot_ops", {"engine_id": "controlbot_runtime"})
        rtn = store.create_routine(
            "bot_ops",
            {
                "name": "Shift Check",
                "instruction": "Check plant health",
                "schedule_type": "manual",
            },
        )
        run = await runner.execute_routine(rtn["id"], trigger="manual")
        for _ in range(80):
            runs = store.list_routine_runs(rtn["id"])
            if runs and runs[0]["status"] in {"succeeded", "failed"}:
                break
            await asyncio.sleep(0.05)

        latest = store.list_routine_runs(rtn["id"])[0]
        assert latest["status"] == "succeeded"
        assert "all sensors nominal" in str(latest["summary"])

        # Disable app_webhooks -> webhook trigger returns failed without running bg task
        store.update_connected_app("app_webhooks", {"enabled": False})
        blocked_run = await runner.execute_routine(rtn["id"], trigger="webhook")
        assert blocked_run["status"] == "failed"
        assert "disabled" in str(blocked_run["error"]).lower()
        del run
    finally:
        await runner.stop_scheduler()
        await adapter.shutdown()
        store.close()


@pytest.mark.n2
async def test_runner_mentions_page_context_memory_cancel_race_and_airlock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = WorkspaceStore(tmp_path / "ws_features.sqlite3")
    bus = EventBus()

    class _FakeBrowser(LiveBrowserController):
        def __init__(self, profile_root: Path) -> None:
            super().__init__(profile_root=profile_root)
            self.extract_calls = 0

        @property
        def running(self) -> bool:
            return True

        async def extract_page_context(
            self,
            *,
            max_text_chars: int = 4000,
            max_elements: int = 20,
            screenshot_path: Path | None = None,
        ) -> dict[str, Any] | None:
            del max_text_chars, max_elements, screenshot_path
            self.extract_calls += 1
            return {"url": "https://example.com", "title": "Example"}

    browser = _FakeBrowser(tmp_path / "browser")
    usage = ModelUsage(prompt_tokens=5, completion_tokens=5, total_tokens=10)
    adapter, _repo = _build_real_runtime_adapter(
        tmp_path,
        turns=[
            EmulatedTurn(
                decision=ModelDecision(
                    decision_type="final",
                    final_answer="Done.",
                    usage=usage,
                )
            )
        ]
        * 4,
    )

    class _FakeMemory:
        def build_prompt_context(self, **kwargs: Any) -> str:
            del kwargs
            return (
                "[MEMORY kind=fact observed_at=2026-11-26T00:00:00Z "
                "valid_until=2026-12-26T00:00:00Z authority=advisory_only]\n"
                "Preferred OEM: Emerson"
            )

    cfg = FacilityConfig(
        facility_id="facility-a",
        facility_name="Planta A",
        areas={"area-1": AreaConfig(display_name="Area 1")},
        assets=(
            AssetMapping(
                asset_id="tt-402b",
                area="area-1",
                canonical_label="TT-402B",
                aliases=("TT-402B",),
                allowed_units={"reading": ("C",)},
            ),
        ),
    )

    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=browser,
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
        memory_store=_FakeMemory(),
        facility_config=cfg,
    )

    try:
        # 1. @Bot_Name mentions (hyphen, underscore, full name, first_word fallback)
        chan = store.create_channel({"name": "Ops Room", "bot_ids": ["bot_chief", "bot_ops"]})
        t_chan = str(chan["thread_id"])
        bots_1, _ = runner._resolve_target_bots(
            t_chan, {"content": "Please check @controlbot_ops"}
        )
        assert [b["id"] for b in bots_1] == ["bot_ops"]
        bots_2, _ = runner._resolve_target_bots(
            t_chan, {"content": "Please check @controlbot-ops"}
        )
        assert [b["id"] for b in bots_2] == ["bot_ops"]
        bots_3, _ = runner._resolve_target_bots(
            t_chan, {"content": "Please check @ControlBot Ops now"}
        )
        assert [b["id"] for b in bots_3] == ["bot_ops"]
        bots_4, _ = runner._resolve_target_bots(t_chan, {"content": "Hey @Chief, quick check"})
        assert [b["id"] for b in bots_4] == ["bot_chief"]

        # 2. page_context_id + Memory injection ordering
        page, _ = store.create_or_version_page(
            bot_id="bot_chief",
            title="Q4 Spec",
            content_md="Target range: 4-20 mA",
            share_scope="team",
        )
        bot_chief = store.get_bot("bot_chief")
        assert bot_chief is not None
        prompt = runner._build_bot_prompt(
            bot=bot_chief,
            thread_id=str(bot_chief["thread_id"]),
            user_message={"content": "Review active spec"},
            skill_ids=[],
            thinking_level="medium",
            page_context_id=str(page["id"]),
        )
        assert "[ACTIVE PAGE CONTEXT]" in prompt
        assert "Target range: 4-20 mA" in prompt
        assert "[MEMORY kind=fact" in prompt
        assert prompt.index("[MEMORY kind=fact") < prompt.index("[USER MESSAGE]")

        # 3. app_playwright toggle blocks browser context extraction + mid-turn safety_floor
        store.update_connected_app("app_playwright", {"enabled": False})
        captured_prompts: list[str] = []

        async def _fake_stream_agy(
            *,
            prompt: str,
            **kwargs: Any,
        ) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            captured_prompts.append(prompt)
            yield {
                "type": "tool",
                "step_index": 0,
                "tool_name": "bash",
                "state": "ACTIVE",
                "summary": "echo $(id)",
            }
            await asyncio.sleep(0.1)
            yield {"type": "done", "response": "Should not reach"}

        monkeypatch.setattr("src.web.v1.runner.find_agy_executable", lambda: "/bin/true")
        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_stream_agy)

        t_chief = str(bot_chief["thread_id"])
        u_msg = store.create_message(
            thread_id=t_chief,
            sender_type="user",
            sender_name="Op",
            content="Run safe check",
        )
        u_msg["page_context_id"] = str(page["id"])
        runner.start_turn(thread_id=t_chief, user_message=u_msg, page_context_id=str(page["id"]))
        for _ in range(80):
            if runner.active_turns_count == 0:
                break
            await asyncio.sleep(0.05)

        assert browser.extract_calls == 0  # app_playwright disabled!
        msgs, _ = store.list_thread_messages(t_chief)
        assert any("Policy Block" in str(m["content"]) for m in msgs)

        # 4. Cancellation race: rapid double start_turn serializes cleanup strictly before turn 2
        order_log: list[str] = []

        async def _slow_then_fast_agy(
            *,
            prompt: str,
            **kwargs: Any,
        ) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            if "TURN_ONE" in prompt:
                order_log.append("turn1_start")
                try:
                    await asyncio.sleep(1.0)
                    yield {"type": "done", "response": "Turn 1 done"}
                except asyncio.CancelledError:
                    order_log.append("turn1_cancelled")
                    raise
            else:
                order_log.append("turn2_start")
                yield {"type": "done", "response": "Turn 2 completed"}

        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _slow_then_fast_agy)
        m1 = store.create_message(
            thread_id=t_chief, sender_type="user", sender_name="Op", content="TURN_ONE"
        )
        m2 = store.create_message(
            thread_id=t_chief, sender_type="user", sender_name="Op", content="TURN_TWO"
        )
        runner.start_turn(thread_id=t_chief, user_message=m1)
        await asyncio.sleep(0.03)
        runner.start_turn(thread_id=t_chief, user_message=m2)
        for _ in range(80):
            if runner.active_turns_count == 0:
                break
            await asyncio.sleep(0.05)

        assert order_log == ["turn1_start", "turn1_cancelled", "turn2_start"]

        # 5. Mixed lane Airlock strips plant tag/IP/WO before general synthesis
        store.update_bot("bot_ops", {"engine_id": "controlbot_runtime"})
        bot_ops = store.get_bot("bot_ops")
        assert bot_ops is not None
        t_ops = str(bot_ops["thread_id"])
        mix_msg = {
            "content": "Buscar reemplazo datasheet web para TT-402B en 10.1.2.3 WO-2026500",
            "manufacturer": "Emerson",
            "model": "Rosemount 3144P (TT-402B 10.1.2.3 WO-2026500)",
            "output_signal": "4-20 mA",
        }
        runner.start_turn(thread_id=t_ops, user_message=mix_msg)
        for _ in range(80):
            if runner.active_turns_count == 0:
                break
            await asyncio.sleep(0.05)

        completed_ops = [
            ev
            for ev in bus.recent_events(limit=50)
            if ev["type"] == "message.completed" and ev["thread_id"] == t_ops
        ]
        assert completed_ops
        last_meta = completed_ops[-1]["payload"]["message"].get("metadata")
        assert last_meta is not None
        assert last_meta["lane"] == "mixed"
        proj_json = json.dumps(last_meta["airlock_provenance"])
        assert "TT-402B" not in proj_json
        assert "10.1.2.3" not in proj_json
        assert "WO-2026500" not in proj_json
    finally:
        await runner.stop_scheduler()
        await adapter.shutdown()
        store.close()


@pytest.mark.n2
async def test_runner_draft_delivery_real_webhook_and_smtp_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. Real ASGI Webhook server checking HMAC-SHA256 signature
    webhook_hits: list[dict[str, Any]] = []
    wh_app = FastAPI()

    @wh_app.post("/hook")
    async def hook(request: Request) -> JSONResponse:
        raw = await request.body()
        webhook_hits.append(
            {
                "sig": request.headers.get("x-controlbot-signature", ""),
                "raw": raw,
                "json": json.loads(raw.decode("utf-8")),
            }
        )
        return JSONResponse({"ok": True})

    # 2. Real asyncio TCP SMTP server capturing full DATA payload
    smtp_received: list[str] = []

    async def _handle_smtp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"220 localhost ESMTP Ready\r\n")
        await writer.drain()
        in_data = False
        data_lines: list[str] = []
        while True:
            line_bytes = await reader.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
            if in_data:
                if line == ".":
                    smtp_received.append("\n".join(data_lines))
                    in_data = False
                    writer.write(b"250 OK queued\r\n")
                    await writer.drain()
                else:
                    data_lines.append(line)
                continue
            cmd = line.upper()
            if cmd.startswith(("EHLO", "HELO")):
                writer.write(b"250-localhost\r\n250 OK\r\n")
            elif cmd.startswith(("MAIL FROM", "RCPT TO")):
                writer.write(b"250 OK\r\n")
            elif cmd == "DATA":
                in_data = True
                writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif cmd == "QUIT":
                writer.write(b"221 Bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"250 OK\r\n")
            await writer.drain()
        writer.close()

    smtp_server = await asyncio.start_server(_handle_smtp, "127.0.0.1", 0)
    smtp_port = int(smtp_server.sockets[0].getsockname()[1])

    store = WorkspaceStore(tmp_path / "ws_drafts.sqlite3")
    bus = EventBus()
    adapter, _repo = _build_real_runtime_adapter(tmp_path, turns=[])
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
        smtp_config={
            "host": "127.0.0.1",
            "port": smtp_port,
            "use_tls": False,
            "use_ssl": False,
            "from_addr": "bot@controlbot.local",
        },
    )

    try:
        async with smtp_server, run_asgi_server(wh_app) as wh_origin:
            monkeypatch.setenv("CONTROLBOT_DRAFT_WEBHOOK_SECRET", "whsec_test_123")
            # Webhook draft
            drf_wh = store.create_draft(
                bot_id="bot_chief",
                thread_id="thr_bot_chief",
                channel_type="webhook",
                fields={
                    "webhook_url": f"{wh_origin}/hook",
                    "message": "Shift report ready",
                },
            )
            res_wh = store.resolve_draft(drf_wh["id"], "send")
            deliv_wh = await runner.on_draft_resolved(res_wh, action="send")
            assert deliv_wh["delivered"] is True
            assert deliv_wh["transport"] == "webhook"
            assert len(webhook_hits) == 1
            expected_sig = (
                "sha256="
                + hmac.new(
                    b"whsec_test_123",
                    webhook_hits[0]["raw"],
                    hashlib.sha256,
                ).hexdigest()
            )
            assert webhook_hits[0]["sig"] == expected_sig
            # Secret must not leak into webhook payload
            assert "whsec_test_123" not in json.dumps(webhook_hits[0]["json"])

            # SMTP email draft
            drf_mail = store.create_draft(
                bot_id="bot_chief",
                thread_id="thr_bot_chief",
                channel_type="email",
                fields={
                    "from": "chief@controlbot.local",
                    "to": "plant-lead@example.com",
                    "subject": "Pump 34 Verified Report",
                    "body": "All telemetry checks passed.",
                },
            )
            res_mail = store.resolve_draft(drf_mail["id"], "send")
            deliv_mail = await runner.on_draft_resolved(res_mail, action="send")
            assert deliv_mail["delivered"] is True
            assert deliv_mail["transport"] == "smtp"
            assert len(smtp_received) == 1
            assert "Subject: Pump 34 Verified Report" in smtp_received[0]
            assert "All telemetry checks passed." in smtp_received[0]
    finally:
        await runner.stop_scheduler()
        await adapter.shutdown()
        store.close()


@pytest.mark.n2
async def test_runner_apostrophe_prompts_and_ui_general_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = WorkspaceStore(tmp_path / "ws_apostrophe.sqlite3")
    bus = EventBus()
    adapter, _repo = _build_real_runtime_adapter(tmp_path, turns=[])
    cfg = FacilityConfig(
        facility_id="facility-a",
        facility_name="Planta A",
        areas={
            "area-1": AreaConfig(display_name="Linea 1"),
            "area-2": AreaConfig(display_name="Linea 2"),
        },
        assets=(
            AssetMapping(
                asset_id="pump-34-a1",
                area="area-1",
                canonical_label="Pump 34",
                aliases=("P-34A",),
                allowed_units={"reading": ("bar",)},
            ),
            AssetMapping(
                asset_id="pump-34-a2",
                area="area-2",
                canonical_label="Pump 34",
                aliases=("P-34B",),
                allowed_units={"reading": ("bar",)},
            ),
        ),
    )
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
        facility_config=cfg,
    )
    try:
        captured_prompts: list[str] = []

        async def _fake_stream_agy(*, prompt: str, **kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            captured_prompts.append(prompt)
            yield {"type": "done", "response": "Ok, processed."}

        monkeypatch.setattr("src.web.v1.runner.find_agy_executable", lambda: "/bin/true")
        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_stream_agy)

        bot = store.get_bot("bot_chief")
        assert bot is not None
        t_chief = str(bot["thread_id"])

        for idx, safe_txt in enumerate(
            (
                "What's the temperature of Pump 34?",
                "Don't restart line 2",
            ),
            start=1,
        ):
            u_msg = store.create_message(
                thread_id=t_chief, sender_type="user", sender_name="Op", content=safe_txt
            )
            runner.start_turn(thread_id=t_chief, user_message=u_msg, ui_lane=Lane.GENERAL)
            for _ in range(80):
                if runner.active_turns_count == 0:
                    break
                await asyncio.sleep(0.05)
            assert len(captured_prompts) == idx

        # Destructive prompts MUST still be blocked by safety_floor
        for bad_txt in ("Please run rm -rf /", "echo $(cat /etc/shadow)"):
            u_bad = store.create_message(
                thread_id=t_chief, sender_type="user", sender_name="Op", content=bad_txt
            )
            runner.start_turn(thread_id=t_chief, user_message=u_bad, ui_lane=Lane.GENERAL)
            for _ in range(80):
                if runner.active_turns_count == 0:
                    break
                await asyncio.sleep(0.05)

        msgs, _ = store.list_thread_messages(t_chief)
        err_msgs = [m for m in msgs if m["status"] == "error"]
        assert len(err_msgs) == 2
        assert all("safety floor" in str(m["content"]).lower() for m in err_msgs)
    finally:
        await runner.stop_scheduler()
        await adapter.shutdown()
        store.close()


@pytest.mark.n2
async def test_runner_trailing_punctuation_mentions_and_skills(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "ws_mentions.sqlite3")
    bus = EventBus()
    adapter, _repo = _build_real_runtime_adapter(tmp_path, turns=[])
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
    )
    try:
        ops_analyst = store.create_bot(
            {
                "name": "Ops Analyst",
                "role_prompt": "Analyze plant ops.",
                "engine_id": "controlbot_runtime",
            }
        )
        chan = store.create_channel(
            {
                "name": "Triage Room",
                "bot_ids": ["bot_chief", "bot_ops", ops_analyst["id"]],
            }
        )
        t_chan = str(chan["thread_id"])

        b1, _ = runner._resolve_target_bots(
            t_chan, {"content": "Ask @ops-analyst.", "mentions": []}
        )
        assert [b["id"] for b in b1] == [ops_analyst["id"]]

        b2, _ = runner._resolve_target_bots(t_chan, {"content": "Hello @Chief.", "mentions": []})
        assert [b["id"] for b in b2] == ["bot_chief"]

        b3, _ = runner._resolve_target_bots(
            t_chan, {"content": "Check @controlbot-ops!", "mentions": []}
        )
        assert [b["id"] for b in b3] == ["bot_ops"]

        b4, _ = runner._resolve_target_bots(t_chan, {"content": "Run @all.", "mentions": []})
        assert {b["id"] for b in b4} == {"bot_chief", "bot_ops", ops_analyst["id"]}

        b5, _ = runner._resolve_target_bots(
            t_chan, {"content": "Route explicitly", "mentions": ["@ops-analyst."]}
        )
        assert [b["id"] for b in b5] == [ops_analyst["id"]]

        # Skill trailing period activation
        store.create_skill(
            {
                "bot_id": "bot_chief",
                "name": "Summarize Workspace",
                "content_md": "Produce concise executive bullets.",
            }
        )
        bot_chief = store.get_bot("bot_chief")
        assert bot_chief is not None
        prompt = runner._build_bot_prompt(
            bot=bot_chief,
            thread_id=str(bot_chief["thread_id"]),
            user_message={"content": "Use @summarize-workspace."},
            skill_ids=[],
            thinking_level="medium",
        )
        assert "[ACTIVE SKILLS]" in prompt
        assert "Produce concise executive bullets." in prompt
    finally:
        await runner.stop_scheduler()
        await adapter.shutdown()
        store.close()


@pytest.mark.n2
async def test_runner_mid_turn_unknown_mcp_blocked_and_allowlisted_permitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = WorkspaceStore(tmp_path / "ws_mcp.sqlite3")
    bus = EventBus()
    adapter, _repo = _build_real_runtime_adapter(tmp_path, turns=[])
    runner_default = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
    )
    runner_allow = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
        known_read_only_mcp_tools={"mcp.scada.read_tags"},
    )
    try:
        # Unknown MCP tools MUST be blocked in Lane.INDUSTRIAL even if named *_read_* / get_*
        for bad_mcp in ("mcp_unknown_read_secrets", "custom.mcp.get_tokens"):
            ok, reason = runner_default._gate_mid_turn_tool(
                bot_id="bot_ops",
                turn_id="trn_mcp_1",
                lane=Lane.INDUSTRIAL,
                tool_name=bad_mcp,
                category="search",
                summary="dump",
            )
            assert ok is False
            assert reason is not None and "industrial_read_only_lane" in reason

        # Allowlisted MCP tool is permitted in Lane.INDUSTRIAL, unknown still blocked
        ok_allow, reason_allow = runner_allow._gate_mid_turn_tool(
            bot_id="bot_ops",
            turn_id="trn_mcp_2",
            lane=Lane.INDUSTRIAL,
            tool_name="mcp.scada.read_tags",
            category="search",
            summary="read tag",
        )
        assert ok_allow is True and reason_allow is None

        ok_still_bad, _ = runner_allow._gate_mid_turn_tool(
            bot_id="bot_ops",
            turn_id="trn_mcp_3",
            lane=Lane.INDUSTRIAL,
            tool_name="mcp_unknown_read_secrets",
            category="search",
            summary="dump",
        )
        assert ok_still_bad is False

        # Mid-turn stream_agy_prompt yielding mcp_unknown_read_secrets aborts with [Policy Block]
        reached_after_block = False

        async def _fake_mcp_agy(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            nonlocal reached_after_block
            del kwargs
            yield {
                "type": "tool",
                "step_index": 0,
                "tool_name": "mcp_unknown_read_secrets",
                "state": "ACTIVE",
                "summary": "dump secrets",
            }
            reached_after_block = True
            yield {"type": "done", "response": "Should never finish"}

        monkeypatch.setattr("src.web.v1.runner.find_agy_executable", lambda: "/bin/true")
        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_mcp_agy)

        bot_ops = store.get_bot("bot_ops")
        assert bot_ops is not None
        t_ops = str(bot_ops["thread_id"])
        u_msg = store.create_message(
            thread_id=t_ops,
            sender_type="user",
            sender_name="Op",
            content="Check SCADA alarm status",
        )
        runner_default.start_turn(thread_id=t_ops, user_message=u_msg, ui_lane=Lane.INDUSTRIAL)
        for _ in range(80):
            if runner_default.active_turns_count == 0:
                break
            await asyncio.sleep(0.05)

        assert reached_after_block is False
        msgs, _ = store.list_thread_messages(t_ops)
        assert any("[Policy Block]" in str(m["content"]) for m in msgs)
    finally:
        await runner_default.stop_scheduler()
        await runner_allow.stop_scheduler()
        await adapter.shutdown()
        store.close()


@pytest.mark.n2
async def test_runner_webhook_vault_secret_ref_and_redacted_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CONTROLBOT_DRAFT_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("CONTROLBOT_DRAFT_WEBHOOK_URL", raising=False)

    webhook_hits: list[dict[str, Any]] = []
    wh_app = FastAPI()

    @wh_app.post("/hook")
    async def hook(request: Request) -> JSONResponse:
        raw = await request.body()
        webhook_hits.append(
            {
                "sig": request.headers.get("x-controlbot-signature", ""),
                "raw": raw,
                "json": json.loads(raw.decode("utf-8")),
            }
        )
        return JSONResponse({"ok": True})

    smtp_auth_attempts: list[str] = []

    async def _handle_smtp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"220 localhost ESMTP Ready\r\n")
        await writer.drain()
        in_data = False
        while True:
            line_bytes = await reader.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
            if in_data:
                if line == ".":
                    in_data = False
                    writer.write(b"250 OK\r\n")
                    await writer.drain()
                continue
            cmd = line.upper()
            if cmd.startswith(("EHLO", "HELO")):
                writer.write(b"250-localhost\r\n250 AUTH PLAIN LOGIN\r\n")
            elif cmd.startswith("AUTH PLAIN"):
                smtp_auth_attempts.append(line)
                writer.write(b"235 Authentication successful\r\n")
            elif cmd.startswith(("MAIL FROM", "RCPT TO")):
                writer.write(b"250 OK\r\n")
            elif cmd == "DATA":
                in_data = True
                writer.write(b"354 End data\r\n")
            elif cmd == "QUIT":
                writer.write(b"221 Bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"250 OK\r\n")
            await writer.drain()
        writer.close()

    smtp_server = await asyncio.start_server(_handle_smtp, "127.0.0.1", 0)
    smtp_port = int(smtp_server.sockets[0].getsockname()[1])

    store = WorkspaceStore(tmp_path / "ws_vault_wh.sqlite3")
    bus = EventBus()
    adapter, _repo = _build_real_runtime_adapter(tmp_path, turns=[])
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
    )
    runner_injected = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
        webhook_secrets={"app_webhooks": "injected_hmac_42"},
    )
    try:
        async with smtp_server, run_asgi_server(wh_app) as wh_origin:
            # 1. Fail closed when webhook_secret is scrubbed to [REDACTED] without Vault ref
            store.update_connected_app(
                "app_webhooks",
                {
                    "enabled": True,
                    "config": {
                        "draft_webhook_url": f"{wh_origin}/hook",
                        "webhook_secret": "raw_scrubbed",
                    },
                },
            )
            drf_fail = store.create_draft(
                bot_id="bot_chief",
                thread_id="thr_bot_chief",
                channel_type="webhook",
                fields={"message": "Should fail closed"},
            )
            res_fail = store.resolve_draft(drf_fail["id"], "send")
            deliv_fail = await runner.on_draft_resolved(res_fail, action="send")
            assert deliv_fail["delivered"] is False
            assert len(webhook_hits) == 0

            # 2. Injected webhook_secrets signs cleanly when no Vault ref is set
            deliv_inj = await runner_injected.on_draft_resolved(res_fail, action="send")
            assert deliv_inj["delivered"] is True
            assert len(webhook_hits) == 1
            expected_inj_sig = (
                "sha256="
                + hmac.new(b"injected_hmac_42", webhook_hits[0]["raw"], hashlib.sha256).hexdigest()
            )
            assert webhook_hits[0]["sig"] == expected_inj_sig

            # 3. Vault-backed webhook_secret_id signs with valid HMAC and zero secret leak
            sec = store.create_vault_secret(
                bot_id=None,
                name="Draft Webhook HMAC",
                domain="webhook.local",
                fields={"webhook_secret": "vlt_hmac_key_99"},
            )
            store.update_connected_app(
                "app_webhooks",
                {
                    "enabled": True,
                    "config": {
                        "draft_webhook_url": f"{wh_origin}/hook",
                        "webhook_secret_id": sec["id"],
                    },
                },
            )
            drf_vault = store.create_draft(
                bot_id="bot_chief",
                thread_id="thr_bot_chief",
                channel_type="webhook",
                fields={"message": "Vault signed report"},
            )
            res_vault = store.resolve_draft(drf_vault["id"], "send")
            deliv_vault = await runner.on_draft_resolved(res_vault, action="send")
            assert deliv_vault["delivered"] is True
            assert len(webhook_hits) == 2
            expected_vlt_sig = (
                "sha256="
                + hmac.new(b"vlt_hmac_key_99", webhook_hits[1]["raw"], hashlib.sha256).hexdigest()
            )
            assert webhook_hits[1]["sig"] == expected_vlt_sig
            assert "vlt_hmac_key_99" not in json.dumps(webhook_hits[1]["json"])

            # 4. Vault-backed smtp_password_secret_id in settings["smtp"] authenticates SMTP
            smtp_sec = store.create_vault_secret(
                bot_id=None,
                name="SMTP Auth Pass",
                domain="smtp.local",
                fields={"password": "smtp_vault_pass_77"},
            )
            store.update_settings(
                {
                    "smtp": {
                        "host": "127.0.0.1",
                        "port": smtp_port,
                        "username": "bot@controlbot.local",
                        "smtp_password_secret_id": smtp_sec["id"],
                        "from_addr": "bot@controlbot.local",
                        "use_tls": False,
                        "use_ssl": False,
                    }
                }
            )
            drf_mail = store.create_draft(
                bot_id="bot_chief",
                thread_id="thr_bot_chief",
                channel_type="email",
                fields={"to": "lead@example.com", "subject": "Vault SMTP", "body": "Hi"},
            )
            res_mail = store.resolve_draft(drf_mail["id"], "send")
            deliv_mail = await runner.on_draft_resolved(res_mail, action="send")
            assert deliv_mail["delivered"] is True
            assert len(smtp_auth_attempts) == 1
    finally:
        await runner.stop_scheduler()
        await runner_injected.stop_scheduler()
        await adapter.shutdown()
        store.close()


@pytest.mark.n2
async def test_runner_mixed_lane_agy_prompt_airlock_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = WorkspaceStore(tmp_path / "ws_mixed_agy.sqlite3")
    bus = EventBus()
    adapter, _repo = _build_real_runtime_adapter(tmp_path, turns=[])

    class _LeakyMemory:
        def build_prompt_context(self, **kwargs: Any) -> str:
            del kwargs
            return (
                "[MEMORY kind=fact observed_at=2026-11-26T00:00:00Z "
                "valid_until=2026-12-26T00:00:00Z authority=advisory_only]\n"
                "TT-402B on Planta A Area 1 host 10.1.2.3 key sk-ant-api03-secretkey999999"
            )

    cfg = FacilityConfig(
        facility_id="facility-a",
        facility_name="Planta A",
        areas={"area-1": AreaConfig(display_name="Area 1")},
        assets=(
            AssetMapping(
                asset_id="tt-402b",
                area="area-1",
                canonical_label="TT-402B",
                aliases=("TT-402B",),
                allowed_units={"reading": ("C",)},
            ),
        ),
    )
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
        memory_store=_LeakyMemory(),
        facility_config=cfg,
    )
    try:
        captured_prompts: list[str] = []

        async def _fake_agy(*, prompt: str, **kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            captured_prompts.append(prompt)
            yield {"type": "done", "response": "Public replacement: Emerson 3144P."}

        monkeypatch.setattr("src.web.v1.runner.find_agy_executable", lambda: "/bin/true")
        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_agy)

        store.update_bot(
            "bot_ops",
            {
                "engine_id": "agy",
                "role_prompt": "Helper for Plant TT-402B at 192.168.1.50",
            },
        )
        skl = store.create_skill(
            {
                "bot_id": "bot_ops",
                "name": "Plant Lookup",
                "content_md": "Use internal Linea-3 and Area 3 data for diagnostics.",
            }
        )
        page, _ = store.create_or_version_page(
            bot_id="bot_ops",
            title="Plant Page TT-402B",
            content_md="Plant spec 4-20 mA at 10.1.2.3 WO-2026500",
            share_scope="team",
        )
        bot_ops = store.get_bot("bot_ops")
        assert bot_ops is not None
        t_ops = str(bot_ops["thread_id"])
        u_msg = store.create_message(
            thread_id=t_ops,
            sender_type="user",
            sender_name="Op",
            content=(
                "Buscar reemplazo datasheet web para TT-402B en Planta A Area 1 "
                "10.1.2.3 WO-2026500 token sk-ant-api03-secretkey999999"
            ),
        )
        u_msg["output_signal"] = "4-20 mA"
        u_msg["page_context_id"] = str(page["id"])
        u_msg["skill_ids"] = [str(skl["id"])]

        runner.start_turn(
            thread_id=t_ops,
            user_message=u_msg,
            skill_ids=[str(skl["id"])],
            page_context_id=str(page["id"]),
        )
        for _ in range(80):
            if runner.active_turns_count == 0:
                break
            await asyncio.sleep(0.05)

        assert len(captured_prompts) == 1
        sent_prompt = captured_prompts[0]
        assert "[BOT PERSONA:" in sent_prompt
        assert "[ACTIVE SKILLS]" in sent_prompt
        assert "[SANITIZED PLANT SPECS (AIRLOCK)]" in sent_prompt
        assert "4-20 mA" in sent_prompt
        for forbidden in (
            "TT-402B",
            "10.1.2.3",
            "192.168.1.50",
            "WO-2026500",
            "Planta A",
            "Area 1",
            "Area 3",
            "Linea-3",
            "sk-ant-api03-secretkey999999",
        ):
            assert forbidden not in sent_prompt

        # Fail-closed check: if _build_bot_prompt ever emits an unsanitized leak, mixed-lane blocks
        monkeypatch.setattr(
            runner,
            "_build_bot_prompt",
            lambda **kwargs: "Injected unsanitized TT-402B at 192.168.1.50",
        )
        u_msg_leak = store.create_message(
            thread_id=t_ops,
            sender_type="user",
            sender_name="Op",
            content="Buscar reemplazo datasheet web",
        )
        runner.start_turn(thread_id=t_ops, user_message=u_msg_leak, ui_lane=Lane.MIXED)
        for _ in range(80):
            if runner.active_turns_count == 0:
                break
            await asyncio.sleep(0.05)
        assert len(captured_prompts) == 1  # stream_agy_prompt MUST NOT have been called
        msgs_after, _ = store.list_thread_messages(t_ops)
        assert any(
            m["status"] == "error" and "Evidence Airlock blocked" in str(m["content"])
            for m in msgs_after
        )
    finally:
        await runner.stop_scheduler()
        await adapter.shutdown()
        store.close()


@pytest.mark.n2
async def test_playwright_mcp_bridge_blocks_redirect_bounce_and_subresource_ssrf() -> None:
    hits: list[str] = []
    app = FastAPI()

    @app.get("/redir-back")
    async def redir_back(request: Request) -> Response:
        hits.append("/redir-back")
        port = request.url.port
        return Response(status_code=302, headers={"Location": f"http://localhost:{port}/bounce"})

    @app.get("/bounce")
    async def bounce(request: Request) -> Response:
        hits.append("/bounce-on-localhost")
        port = request.url.port
        return Response(status_code=302, headers={"Location": f"http://127.0.0.1:{port}/ok"})

    @app.get("/ok")
    async def ok() -> Response:
        hits.append("/ok")
        return Response("<html><title>OK</title><body>ok</body></html>", media_type="text/html")

    @app.get("/subresource")
    async def subresource(request: Request) -> Response:
        hits.append("/subresource")
        port = request.url.port
        html = (
            f"<html><title>Sub</title><body>"
            f'<img src="http://localhost:{port}/secret">'
            f'<script>fetch("http://localhost:{port}/secret").catch(()=>{{}})</script>'
            f"</body></html>"
        )
        return Response(html, media_type="text/html")

    @app.get("/meta-refresh")
    async def meta_refresh(request: Request) -> Response:
        hits.append("/meta-refresh")
        port = request.url.port
        html = (
            f"<html><head>"
            f'<meta http-equiv="refresh" content="0; url=http://localhost:{port}/secret-meta">'
            f"</head><body>Redirecting...</body></html>"
        )
        return Response(html, media_type="text/html")

    @app.get("/secret")
    async def secret() -> Response:
        hits.append("/secret")
        return Response("TOP_SECRET", media_type="text/plain")

    @app.get("/secret-meta")
    async def secret_meta() -> Response:
        hits.append("/secret-meta")
        return Response("META_SECRET", media_type="text/plain")

    guard = EgressGuard(allowed_domains=("127.0.0.1",), allow_loopback_for_tests=True)
    bridge = PlaywrightMcpBridge(egress_guard=guard)

    async with run_asgi_server(app) as origin:
        # 1. Redirect-bounce SSRF must be blocked before hitting localhost
        with pytest.raises(EgressBlockedError):
            await bridge.fetch_rendered(f"{origin}/redir-back")
        assert "/bounce-on-localhost" not in hits

        # 2. Subresource <img> + fetch() SSRF to localhost must be aborted
        hits.clear()
        extract = await bridge.fetch_rendered(f"{origin}/subresource")
        assert extract.status_code == 200
        assert "/secret" not in hits
        assert hits == ["/subresource"]

        # 3. <meta http-equiv="refresh"> SSRF must raise EgressBlockedError cleanly
        hits.clear()
        with pytest.raises(EgressBlockedError):
            await bridge.fetch_rendered(f"{origin}/meta-refresh")
        assert "/secret-meta" not in hits


@pytest.mark.n2
async def test_runner_mixed_lane_agy_browser_context_airlock_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from src.engine.airlock import AirlockBlockedError
    from src.web.workspace import build_agy_prompt_with_browser_context

    store = WorkspaceStore(tmp_path / "ws_mixed_browser.sqlite3")
    bus = EventBus()
    adapter, _repo = _build_real_runtime_adapter(tmp_path, turns=[])

    class _FakeLiveBrowser:
        running = True

        async def extract_page_context(self) -> dict[str, Any]:
            return {
                "running": True,
                "url": "http://192.168.1.50/hmi",
                "title": "Plant TT-402B HMI",
                "visible_text": "Internal Linea-3 Area 3 WO-2026500",
                "elements": [
                    {
                        "tag": "button",
                        "text": "Ack TT-402B",
                        "placeholder": "Area 3 WO-2026500",
                        "href": "http://192.168.1.50/linea-3",
                        "x": 120,
                        "y": 240,
                    }
                ],
            }

    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=_FakeLiveBrowser(),  # type: ignore[arg-type]
        coordinator=adapter,
        uploads_dir=tmp_path / "uploads",
    )
    try:
        captured: list[tuple[str, dict[str, Any] | None]] = []

        async def _fake_agy(
            *,
            prompt: str,
            browser_context: dict[str, Any] | None = None,
            **kwargs: Any,
        ) -> AsyncIterator[dict[str, Any]]:
            del kwargs
            captured.append((prompt, browser_context))
            yield {"type": "done", "response": "Public datasheet replacement checked."}

        monkeypatch.setattr("src.web.v1.runner.find_agy_executable", lambda: "/bin/true")
        monkeypatch.setattr("src.web.v1.runner.stream_agy_prompt", _fake_agy)

        store.update_bot("bot_ops", {"engine_id": "agy"})
        bot_ops = store.get_bot("bot_ops")
        assert bot_ops is not None
        t_ops = str(bot_ops["thread_id"])

        u_msg = store.create_message(
            thread_id=t_ops,
            sender_type="user",
            sender_name="Op",
            content="Buscar reemplazo datasheet web para transmisor",
        )
        runner.start_turn(
            thread_id=t_ops,
            user_message=u_msg,
            include_browser_context=True,
            ui_lane=Lane.MIXED,
        )
        for _ in range(80):
            if runner.active_turns_count == 0:
                break
            await asyncio.sleep(0.05)

        assert len(captured) == 1
        sent_prompt, captured_browser_context = captured[0]
        assert captured_browser_context is not None
        dumped_ctx = json.dumps(captured_browser_context)
        rendered_ctx = build_agy_prompt_with_browser_context(sent_prompt, captured_browser_context)
        for forbidden in ("192.168.1.50", "TT-402B", "Linea-3", "Area 3", "WO-2026500"):
            assert forbidden not in dumped_ctx
            assert forbidden not in rendered_ctx

        # Fail-closed verification: if residual leaks survive sanitization, Airlock blocks
        with pytest.raises(AirlockBlockedError):
            runner._sanitize_browser_context_via_airlock(
                {
                    "running": True,
                    "url": "http://192.168.1.50/hmi",
                    "title": "TT-402B",
                    "visible_text": "Linea-3 Area 3 WO-2026500",
                    "elements": [],
                },
                lambda txt: txt,
            )
    finally:
        await runner.stop_scheduler()
        await adapter.shutdown()
        store.close()
