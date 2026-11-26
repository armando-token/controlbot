"""Opaque-box E2E tests for HITL approvals, drafts, secure forms, auto-review, routines & skills.

Covers Milestone E2E-M2 (Tier 1 & Tier 2) against real isolated uvicorn subprocesses
over real HTTP/REST and SSE without mocks or ASGITransport shortcuts.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from tests.e2e._helpers import (
    IsolatedServer,
    SseFrame,
    trigger_and_wait_turn,
    wait_for_sse_event,
)

pytestmark = pytest.mark.e2e

_CONV_ID = "22222222-3333-4444-5555-666666666666"
_MOCK_AGY_CAPTURE_SCRIPT = f"""#!/usr/bin/env python3
import json
import sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

prompt_val = ""
if "-p" in args:
    idx = args.index("-p")
    if idx + 1 < len(args):
        prompt_val = args[idx + 1]

log_path = Path.home() / "captured_prompts.jsonl"
with log_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps({{"prompt": prompt_val}}) + "\\n")

cid = "{_CONV_ID}"
reply = "Mock agy executed successfully."
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({{
        "event": "init",
        "conversation_id": cid,
        "init": {{"model": "gemini-4-carbon-low"}},
    }}), flush=True)
    print(json.dumps({{
        "event": "step_update",
        "step_update": {{
            "step_type": "agent_response",
            "text_delta": reply,
        }},
    }}), flush=True)
    print(json.dumps({{
        "event": "result",
        "result": {{
            "status": "SUCCESS",
            "conversation_id": cid,
            "response": reply,
        }},
    }}), flush=True)
    sys.exit(0)

print(json.dumps({{
    "status": "SUCCESS",
    "conversation_id": cid,
    "response": reply,
}}))
"""


def _read_captured_prompts(srv: IsolatedServer) -> list[str]:
    log_path = srv.fake_home / "captured_prompts.jsonl"
    if not log_path.is_file():
        return []
    prompts: list[str] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            obj = json.loads(line)
            prompts.append(str(obj.get("prompt", "")))
    return prompts


def _get_bot(client: httpx.Client, bot_id: str) -> dict[str, Any]:
    resp = client.get("/api/v1/bots")
    resp.raise_for_status()
    bots: list[dict[str, Any]] = resp.json()["bots"]
    for bot in bots:
        if bot["id"] == bot_id:
            return bot
    raise AssertionError(f"Bot {bot_id!r} not found in /api/v1/bots")


async def _resolve_approval_and_collect_sse(
    aclient: httpx.AsyncClient,
    approval_id: str,
    payload: dict[str, Any],
    *,
    expect_resumed_message: bool = False,
    expect_ack_message: bool = False,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> tuple[httpx.Response, list[SseFrame]]:
    """Open SSE before resolving an approval and wait for resolution + follow-up events."""
    from tests.e2e._helpers import iter_sse_events

    sse_connected = asyncio.Event()
    sse_first_line = asyncio.Event()
    collected: list[SseFrame] = []
    done_event = asyncio.Event()

    def _has_required_events() -> bool:
        saw_resolved = any(
            (f.event_type or f.event) == "hitl.approval.resolved"
            and isinstance(f.data, dict)
            and f.data.get("payload", {}).get("approval", {}).get("id") == approval_id
            for f in collected
        )
        if not saw_resolved:
            return False
        if expect_resumed_message or expect_ack_message:
            saw_msg = any(
                (f.event_type or f.event) == "message.completed" for f in collected
            )
            if not saw_msg:
                return False
        if expect_ack_message:
            saw_idle = any(
                (f.event_type or f.event) == "bot.presence"
                and isinstance(f.data, dict)
                and f.data.get("payload", {}).get("state") == "idle"
                for f in collected
            )
            if not saw_idle:
                return False
        return True

    async def _listen() -> None:
        async for frame in iter_sse_events(
            aclient,
            timeout=timeout,
            on_connected=sse_connected,
            on_first_line=sse_first_line,
        ):
            collected.append(frame)
            if _has_required_events():
                done_event.set()
                return

    listen_task = asyncio.create_task(_listen())
    try:
        await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(sse_first_line.wait(), timeout=0.25)
        resp = await aclient.post(
            f"/api/v1/approvals/{approval_id}/resolve",
            json=payload,
            headers=headers,
        )
        if resp.status_code == 200:
            await asyncio.wait_for(done_event.wait(), timeout=timeout)
    finally:
        if not listen_task.done():
            listen_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await listen_task
    return resp, collected


# ---------------------------------------------------------------------------
# 1. HITL Approvals, Drafts, SecureForms & Auto-Review (Tier 1 & Tier 2)
# ---------------------------------------------------------------------------


async def test_slash_approval_creates_card_emits_sse_and_sets_waiting_human(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as aclient:
        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "/approval Deploy release",
        )
        assert turn.terminal_event.event_type == "hitl.approval.requested"
        assert isinstance(turn.terminal_event.data, dict)
        appr = turn.terminal_event.data["payload"]["approval"]
        assert appr["title"] == "Deploy release"
        assert appr["status"] == "pending"
        assert appr["kind"] == "standard"
        assert appr["allow_always_allowed"] is True
        assert appr["bot_id"] == "bot_chief"
        assert appr["thread_id"] == "thr_bot_chief"

        thread_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
        assert thread_resp.status_code == 200
        approvals = thread_resp.json()["approvals"]
        assert any(a["id"] == appr["id"] and a["status"] == "pending" for a in approvals)

    with server.client() as client:
        bot = _get_bot(client, "bot_chief")
        assert bot["status_state"] == "waiting_human"
        assert bot["needs_attention"] is True


async def test_slash_draft_creates_draft_card_and_emits_sse(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as aclient:
        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "/draft ops@example.com | Subject | Body",
        )
        assert turn.terminal_event.event_type == "hitl.draft.created"
        assert isinstance(turn.terminal_event.data, dict)
        draft = turn.terminal_event.data["payload"]["draft"]
        assert draft["status"] == "pending"
        assert draft["channel_type"] == "email"
        assert draft["bot_id"] == "bot_chief"
        assert draft["thread_id"] == "thr_bot_chief"
        assert draft["fields"]["to"] == "ops@example.com"
        assert draft["fields"]["subject"] == "Subject"
        assert draft["fields"]["body"] == "Body"

        thread_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
        assert thread_resp.status_code == 200
        drafts = thread_resp.json()["drafts"]
        assert any(d["id"] == draft["id"] and d["status"] == "pending" for d in drafts)


async def test_slash_secure_form_creates_form_card_and_emits_sse(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as aclient:
        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "/secure-form portal.example.com",
        )
        assert turn.terminal_event.event_type == "hitl.secure_form.requested"
        assert isinstance(turn.terminal_event.data, dict)
        form = turn.terminal_event.data["payload"]["form"]
        assert form["status"] == "pending"
        assert form["domain"] == "portal.example.com"
        assert form["kind"] == "form"
        assert form["allow_vault_save"] is True
        field_names = {f["name"]: f for f in form["fields"]}
        assert field_names["username"]["secret"] is False
        assert field_names["password"]["secret"] is True

        thread_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
        assert thread_resp.status_code == 200
        forms = thread_resp.json()["secure_forms"]
        assert any(f["id"] == form["id"] and f["status"] == "pending" for f in forms)


async def test_ask_first_seeded_rm_rf_triggers_approval_card(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as aclient:
        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "Please run rm -rf ./scratch_dir",
        )
        assert turn.terminal_event.event_type == "hitl.approval.requested"
        assert isinstance(turn.terminal_event.data, dict)
        appr = turn.terminal_event.data["payload"]["approval"]
        assert appr["kind"] == "ask_first"
        assert appr["status"] == "pending"
        assert appr["allow_always_allowed"] is True
        assert appr["arguments"]["prompt"] == "Please run rm -rf ./scratch_dir"

    with server.client() as client:
        bot = _get_bot(client, "bot_chief")
        assert bot["status_state"] == "waiting_human"
        assert bot["needs_attention"] is True


async def test_custom_ask_first_rule_triggers_approval_and_ignores_unrelated(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_CAPTURE_SCRIPT, name="custom_ask")
    with srv.client() as client:
        put_resp = client.put(
            "/api/v1/settings/auto-review",
            json={
                "rules": [
                    {
                        "bucket": "ask_first",
                        "rule_text": "Ask before restarting turbine telemetry services",
                    }
                ]
            },
        )
        assert put_resp.status_code == 200
        rules = put_resp.json()["rules"]
        assert len(rules) == 1
        assert rules[0]["bucket"] == "ask_first"

    async with srv.async_client() as aclient:
        hit_turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "Please restart turbine telemetry services now",
        )
        assert hit_turn.terminal_event.event_type == "hitl.approval.requested"
        assert isinstance(hit_turn.terminal_event.data, dict)
        appr = hit_turn.terminal_event.data["payload"]["approval"]
        assert appr["kind"] == "ask_first"
        assert appr["allow_always_allowed"] is True

        # Resolve so bot is no longer waiting_human, then test non-matching prompt
        res_resp = await aclient.post(
            f"/api/v1/approvals/{appr['id']}/resolve",
            json={"decision": "skip"},
        )
        assert res_resp.status_code == 200

        benign_turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "Summarize quarterly weather outlook",
        )
        assert benign_turn.terminal_event.event_type == "message.completed"
        assert benign_turn.assistant_message is not None
        assert "Mock agy executed successfully." in benign_turn.assistant_message["content"]


async def test_approval_allow_once_resumes_pending_turn_and_sets_idle(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_CAPTURE_SCRIPT, name="allow_once")
    async with srv.async_client() as aclient:
        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "Please run rm -rf ./scratch_dir",
        )
        assert turn.terminal_event.event_type == "hitl.approval.requested"
        assert isinstance(turn.terminal_event.data, dict)
        appr_id = str(turn.terminal_event.data["payload"]["approval"]["id"])

        resp, sse_frames = await _resolve_approval_and_collect_sse(
            aclient,
            appr_id,
            {"decision": "allow_once"},
            expect_resumed_message=True,
        )
        assert resp.status_code == 200
        resolved = resp.json()
        assert resolved["status"] == "allowed_once"
        assert resolved["decision_by"] == "operator"
        assert resolved["resolved_at"] is not None

        completed_frames = [
            f for f in sse_frames if (f.event_type or f.event) == "message.completed"
        ]
        assert completed_frames
        prompts = _read_captured_prompts(srv)
        assert any("Please run rm -rf ./scratch_dir" in p for p in prompts)

    with srv.client() as client:
        bot = _get_bot(client, "bot_chief")
        assert bot["status_state"] == "idle"
        assert bot["needs_attention"] is False


async def test_approval_always_allow_creates_rule_resumes_and_skips_next_gate(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_CAPTURE_SCRIPT, name="always_allow")
    prompt_text = "Please run rm -rf ./scratch_dir workspace cleanup"
    rule_text = "Allow scratch_dir workspace cleanup"

    async with srv.async_client() as aclient:
        turn1 = await trigger_and_wait_turn(aclient, "thr_bot_chief", prompt_text)
        assert turn1.terminal_event.event_type == "hitl.approval.requested"
        assert isinstance(turn1.terminal_event.data, dict)
        appr_id = str(turn1.terminal_event.data["payload"]["approval"]["id"])

        resp, sse_frames = await _resolve_approval_and_collect_sse(
            aclient,
            appr_id,
            {"decision": "always_allow", "rule_text": rule_text},
            expect_resumed_message=True,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "allowed_always"
        assert any((f.event_type or f.event) == "message.completed" for f in sse_frames)

        rules_resp = await aclient.get("/api/v1/settings/auto-review")
        assert rules_resp.status_code == 200
        rules = rules_resp.json()["rules"]
        assert any(
            r["bucket"] == "allow_auto" and r["rule_text"] == rule_text for r in rules
        )

        # Subsequent matching prompt must bypass ask_first directly via allow_auto
        turn2 = await trigger_and_wait_turn(aclient, "thr_bot_chief", prompt_text)
        assert turn2.terminal_event.event_type == "message.completed"
        assert turn2.assistant_message is not None
        assert "Mock agy executed successfully." in turn2.assistant_message["content"]

        thread_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
        assert len(thread_resp.json()["approvals"]) == 1


async def test_approval_deny_sets_denied_idle_and_posts_acknowledgement(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as aclient:
        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "/approval Reboot production cluster",
        )
        assert turn.terminal_event.event_type == "hitl.approval.requested"
        assert isinstance(turn.terminal_event.data, dict)
        appr_id = str(turn.terminal_event.data["payload"]["approval"]["id"])

        resp, sse_frames = await _resolve_approval_and_collect_sse(
            aclient,
            appr_id,
            {"decision": "deny"},
            expect_ack_message=True,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "denied"

        msg_frames = [
            f
            for f in sse_frames
            if (f.event_type or f.event) == "message.completed"
            and isinstance(f.data, dict)
        ]
        assert msg_frames
        ack_content = str(msg_frames[-1].data["payload"]["message"]["content"])  # type: ignore[index]
        assert "did not proceed" in ack_content
        assert "Action denied" in ack_content

    with server.client() as client:
        bot = _get_bot(client, "bot_chief")
        assert bot["status_state"] == "idle"
        assert bot["needs_attention"] is False


async def test_approval_skip_sets_skipped_idle_and_posts_acknowledgement(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as aclient:
        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "/approval Skip optional audit step",
        )
        assert turn.terminal_event.event_type == "hitl.approval.requested"
        assert isinstance(turn.terminal_event.data, dict)
        appr_id = str(turn.terminal_event.data["payload"]["approval"]["id"])

        resp, sse_frames = await _resolve_approval_and_collect_sse(
            aclient,
            appr_id,
            {"decision": "skip"},
            expect_ack_message=True,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"

        msg_frames = [
            f
            for f in sse_frames
            if (f.event_type or f.event) == "message.completed"
            and isinstance(f.data, dict)
        ]
        assert msg_frames
        ack_content = str(msg_frames[-1].data["payload"]["message"]["content"])  # type: ignore[index]
        assert "Action skipped" in ack_content

    with server.client() as client:
        bot = _get_bot(client, "bot_chief")
        assert bot["status_state"] == "idle"
        assert bot["needs_attention"] is False


def test_approval_re_resolve_and_disallowed_always_allow_return_409(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        # 1. Re-resolving an already resolved approval -> 409
        create_1 = client.post(
            "/api/v1/approvals",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "title": "Single resolve check",
                "allow_always_allowed": True,
            },
        )
        assert create_1.status_code == 201
        apr1_id = create_1.json()["id"]

        res1 = client.post(
            f"/api/v1/approvals/{apr1_id}/resolve",
            json={"decision": "allow_once"},
        )
        assert res1.status_code == 200
        assert res1.json()["status"] == "allowed_once"

        res1_again = client.post(
            f"/api/v1/approvals/{apr1_id}/resolve",
            json={"decision": "deny"},
        )
        assert res1_again.status_code == 409

        # 2. always_allow on allow_always_allowed=False -> 409, keeps pending
        create_2 = client.post(
            "/api/v1/approvals",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "title": "Strict single-use approval",
                "allow_always_allowed": False,
            },
        )
        assert create_2.status_code == 201
        apr2_id = create_2.json()["id"]
        assert create_2.json()["allow_always_allowed"] is False

        bad_always = client.post(
            f"/api/v1/approvals/{apr2_id}/resolve",
            json={"decision": "always_allow"},
        )
        assert bad_always.status_code == 409

        still_ok = client.post(
            f"/api/v1/approvals/{apr2_id}/resolve",
            json={"decision": "allow_once"},
        )
        assert still_ok.status_code == 200
        assert still_ok.json()["status"] == "allowed_once"


async def test_draft_update_merges_fields_then_send_and_discard_with_409_re_resolve(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as aclient:
        t1 = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "/draft ops@example.com | Initial Subject | Initial Body",
        )
        assert t1.terminal_event.event_type == "hitl.draft.created"
        assert isinstance(t1.terminal_event.data, dict)
        draft1_id = str(t1.terminal_event.data["payload"]["draft"]["id"])

        # update merges fields & keeps status="pending"
        upd_resp = await aclient.post(
            f"/api/v1/drafts/{draft1_id}/resolve",
            json={
                "action": "update",
                "fields": {"subject": "Revised Subject", "cc": "lead@example.com"},
            },
        )
        assert upd_resp.status_code == 200
        upd = upd_resp.json()
        assert upd["status"] == "pending"
        assert upd["resolved_at"] is None
        assert upd["fields"]["to"] == "ops@example.com"
        assert upd["fields"]["subject"] == "Revised Subject"
        assert upd["fields"]["cc"] == "lead@example.com"
        assert upd["fields"]["body"] == "Initial Body"

        # send resolves pending draft -> sent
        send_resp = await aclient.post(
            f"/api/v1/drafts/{draft1_id}/resolve",
            json={"action": "send"},
        )
        assert send_resp.status_code == 200
        assert send_resp.json()["status"] == "sent"
        assert send_resp.json()["resolved_at"] is not None

        # re-resolving sent draft -> 409
        re_send = await aclient.post(
            f"/api/v1/drafts/{draft1_id}/resolve",
            json={"action": "discard"},
        )
        assert re_send.status_code == 409

        # Second draft -> discard -> 409 on re-resolve
        t2 = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "/draft sec@example.com | Discard Me | Body",
        )
        assert isinstance(t2.terminal_event.data, dict)
        draft2_id = str(t2.terminal_event.data["payload"]["draft"]["id"])

        disc_resp = await aclient.post(
            f"/api/v1/drafts/{draft2_id}/resolve",
            json={"action": "discard"},
        )
        assert disc_resp.status_code == 200
        assert disc_resp.json()["status"] == "discarded"
        assert disc_resp.json()["resolved_at"] is not None

        re_disc = await aclient.post(
            f"/api/v1/drafts/{draft2_id}/resolve",
            json={"action": "send"},
        )
        assert re_disc.status_code == 409


async def test_secure_form_cancel_emits_sse_and_subsequent_resolve_returns_409(
    server: IsolatedServer,
) -> None:
    from tests.e2e._helpers import iter_sse_events

    async with server.async_client() as aclient:
        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "/secure-form portal.example.com",
        )
        assert turn.terminal_event.event_type == "hitl.secure_form.requested"
        assert isinstance(turn.terminal_event.data, dict)
        form_id = str(turn.terminal_event.data["payload"]["form"]["id"])

        # Submitting while live browser is inactive returns 409 and keeps form pending
        submit_inactive = await aclient.post(
            "/api/v1/vault/secure-fill",
            json={
                "form_id": form_id,
                "action": "submit",
                "values": {"username": "alice", "password": "secret"},
            },
        )
        assert submit_inactive.status_code == 409

        # Listen on SSE before cancelling
        sse_connected = asyncio.Event()
        resolved_frames: list[SseFrame] = []

        async def _listen_cancel() -> None:
            async for frame in iter_sse_events(
                aclient, timeout=10.0, on_connected=sse_connected
            ):
                if (
                    (frame.event_type or frame.event) == "hitl.secure_form.resolved"
                    and isinstance(frame.data, dict)
                    and frame.data.get("payload", {}).get("form", {}).get("id") == form_id
                ):
                    resolved_frames.append(frame)
                    return

        task = asyncio.create_task(_listen_cancel())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            await asyncio.sleep(0.05)
            cancel_resp = await aclient.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": form_id, "action": "cancel"},
            )
            assert cancel_resp.status_code == 200
            body = cancel_resp.json()
            assert body["status"] == "cancelled"
            assert body["filled"] is False
            assert body["saved_secret_id"] is None
            await asyncio.wait_for(task, timeout=5.0)
        finally:
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

        assert len(resolved_frames) == 1
        assert isinstance(resolved_frames[0].data, dict)
        assert resolved_frames[0].data["payload"]["form"]["status"] == "cancelled"

        # Subsequent cancel or submit -> 409
        re_cancel = await aclient.post(
            "/api/v1/vault/secure-fill",
            json={"form_id": form_id, "action": "cancel"},
        )
        assert re_cancel.status_code == 409

        re_submit = await aclient.post(
            "/api/v1/vault/secure-fill",
            json={
                "form_id": form_id,
                "action": "submit",
                "values": {"username": "alice", "password": "secret"},
            },
        )
        assert re_submit.status_code == 409


def test_idempotency_key_duplicate_returns_409_on_approval_and_draft(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        # Approval duplicate Idempotency-Key -> 409
        a1 = client.post(
            "/api/v1/approvals",
            json={"bot_id": "bot_chief", "thread_id": "thr_bot_chief", "title": "Idem A1"},
        ).json()
        a2 = client.post(
            "/api/v1/approvals",
            json={"bot_id": "bot_chief", "thread_id": "thr_bot_chief", "title": "Idem A2"},
        ).json()

        r1 = client.post(
            f"/api/v1/approvals/{a1['id']}/resolve",
            json={"decision": "allow_once"},
            headers={"Idempotency-Key": "idem-apr-dup-1"},
        )
        assert r1.status_code == 200

        r2 = client.post(
            f"/api/v1/approvals/{a2['id']}/resolve",
            json={"decision": "allow_once"},
            headers={"Idempotency-Key": "idem-apr-dup-1"},
        )
        assert r2.status_code == 409

        # a2 must remain pending and resolvable with a fresh key
        r2_fresh = client.post(
            f"/api/v1/approvals/{a2['id']}/resolve",
            json={"decision": "allow_once"},
            headers={"Idempotency-Key": "idem-apr-dup-2"},
        )
        assert r2_fresh.status_code == 200

        # Draft duplicate Idempotency-Key -> 409
        d1 = client.post(
            "/api/v1/drafts",
            json={"bot_id": "bot_chief", "thread_id": "thr_bot_chief", "fields": {"body": "1"}},
        ).json()
        d2 = client.post(
            "/api/v1/drafts",
            json={"bot_id": "bot_chief", "thread_id": "thr_bot_chief", "fields": {"body": "2"}},
        ).json()

        dr1 = client.post(
            f"/api/v1/drafts/{d1['id']}/resolve",
            json={"action": "send"},
            headers={"Idempotency-Key": "idem-drf-dup-1"},
        )
        assert dr1.status_code == 200

        dr2 = client.post(
            f"/api/v1/drafts/{d2['id']}/resolve",
            json={"action": "send"},
            headers={"Idempotency-Key": "idem-drf-dup-1"},
        )
        assert dr2.status_code == 409

        dr2_fresh = client.post(
            f"/api/v1/drafts/{d2['id']}/resolve",
            json={"action": "send"},
            headers={"Idempotency-Key": "idem-drf-dup-2"},
        )
        assert dr2_fresh.status_code == 200


def test_idempotency_key_not_burned_on_failed_draft_resolve_validation(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        d1 = client.post(
            "/api/v1/drafts",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "fields": {"to": "ops@example.com", "subject": "Idem Test", "body": "Payload"},
            },
        ).json()
        d2 = client.post(
            "/api/v1/drafts",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "fields": {"to": "ops@example.com", "subject": "Idem Test 2", "body": "Payload"},
            },
        ).json()

        idem_key = "idem-nonburn-draft-001"

        # 1. Invalid action -> 422 MUST NOT burn idem_key
        bad_action = client.post(
            f"/api/v1/drafts/{d1['id']}/resolve",
            json={"action": "invalid_action"},
            headers={"Idempotency-Key": idem_key},
        )
        assert bad_action.status_code == 422

        # 2. Non-dict fields -> 422 MUST NOT burn idem_key
        bad_fields = client.post(
            f"/api/v1/drafts/{d1['id']}/resolve",
            json={"action": "send", "fields": ["not", "a", "dict"]},
            headers={"Idempotency-Key": idem_key},
        )
        assert bad_fields.status_code == 422

        # 3. Retrying with exact same Idempotency-Key and valid action="send" MUST succeed (200)
        valid_retry = client.post(
            f"/api/v1/drafts/{d1['id']}/resolve",
            json={"action": "send"},
            headers={"Idempotency-Key": idem_key},
        )
        assert valid_retry.status_code == 200
        assert valid_retry.json()["status"] == "sent"

        # 4. Now idem_key IS recorded, so reusing it on d2 returns 409
        after_burn = client.post(
            f"/api/v1/drafts/{d2['id']}/resolve",
            json={"action": "send"},
            headers={"Idempotency-Key": idem_key},
        )
        assert after_burn.status_code == 409


def test_idempotency_key_not_burned_on_store_level_404_and_409_draft_errors(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        d_sent_resp = client.post(
            "/api/v1/drafts",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "fields": {"to": "ops@example.com", "subject": "Already Sent", "body": "Done"},
            },
        )
        assert d_sent_resp.status_code == 201
        d_sent = d_sent_resp.json()

        d_pending_resp = client.post(
            "/api/v1/drafts",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "fields": {"to": "ops@example.com", "subject": "Pending Draft", "body": "Ready"},
            },
        )
        assert d_pending_resp.status_code == 201
        d_pending = d_pending_resp.json()

        d_extra_resp = client.post(
            "/api/v1/drafts",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "fields": {"to": "ops@example.com", "subject": "Extra Draft", "body": "Wait"},
            },
        )
        assert d_extra_resp.status_code == 201
        d_extra = d_extra_resp.json()

        # Pre-resolve d_sent to "sent" without touching idem_key
        pre_send = client.post(
            f"/api/v1/drafts/{d_sent['id']}/resolve",
            json={"action": "send"},
        )
        assert pre_send.status_code == 200
        assert pre_send.json()["status"] == "sent"

        idem_key = "idem-nonburn-store-001"

        # 1. Store-level 404 (nonexistent draft) MUST NOT burn idem_key
        missing_resp = client.post(
            "/api/v1/drafts/drf_missing/resolve",
            json={"action": "send"},
            headers={"Idempotency-Key": idem_key},
        )
        assert missing_resp.status_code == 404

        # 2. Store-level 409 (already-sent draft) MUST NOT burn idem_key
        conflict_resp = client.post(
            f"/api/v1/drafts/{d_sent['id']}/resolve",
            json={"action": "send"},
            headers={"Idempotency-Key": idem_key},
        )
        assert conflict_resp.status_code == 409

        # 3. Retrying on a valid pending draft with the exact same key MUST succeed (200)
        ok_resp = client.post(
            f"/api/v1/drafts/{d_pending['id']}/resolve",
            json={"action": "send"},
            headers={"Idempotency-Key": idem_key},
        )
        assert ok_resp.status_code == 200
        assert ok_resp.json()["status"] == "sent"

        # 4. Now idem_key IS burned, so reusing it on d_extra returns 409 (leaving d_extra pending)
        after_burn = client.post(
            f"/api/v1/drafts/{d_extra['id']}/resolve",
            json={"action": "send"},
            headers={"Idempotency-Key": idem_key},
        )
        assert after_burn.status_code == 409

        fresh_resp = client.post(
            f"/api/v1/drafts/{d_extra['id']}/resolve",
            json={"action": "send"},
            headers={"Idempotency-Key": "idem-nonburn-store-002"},
        )
        assert fresh_resp.status_code == 200
        assert fresh_resp.json()["status"] == "sent"


def test_put_auto_review_atomic_rollback_preserves_existing_rules(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        baseline_resp = client.put(
            "/api/v1/settings/auto-review",
            json={
                "rules": [
                    {"bucket": "allow_auto", "rule_text": "Allow read-only status checks"},
                    {"bucket": "ask_first", "rule_text": "Ask before deleting workspace files"},
                ]
            },
        )
        assert baseline_resp.status_code == 200
        baseline_rules = baseline_resp.json()["rules"]
        assert len(baseline_rules) == 2

        # 1. Invalid bucket mixed with valid rule -> 422, baseline preserved
        bad_bucket = client.put(
            "/api/v1/settings/auto-review",
            json={
                "rules": [
                    {"bucket": "allow_auto", "rule_text": "Should roll back"},
                    {"bucket": "invalid_bucket", "rule_text": "Bad bucket"},
                ]
            },
        )
        assert bad_bucket.status_code == 422
        assert client.get("/api/v1/settings/auto-review").json()["rules"] == baseline_rules

        # 2. Empty rule_text mixed with valid rule -> 422, baseline preserved
        empty_text = client.put(
            "/api/v1/settings/auto-review",
            json={
                "rules": [
                    {"bucket": "allow_auto", "rule_text": "Should also roll back"},
                    {"bucket": "ask_first", "rule_text": "   "},
                ]
            },
        )
        assert empty_text.status_code == 422
        assert client.get("/api/v1/settings/auto-review").json()["rules"] == baseline_rules

        # 3. > 20 rules in one bucket -> 422, baseline preserved
        too_many = client.put(
            "/api/v1/settings/auto-review",
            json={
                "rules": [
                    {"bucket": "ask_first", "rule_text": f"Rule number {i}"}
                    for i in range(21)
                ]
            },
        )
        assert too_many.status_code == 422
        assert client.get("/api/v1/settings/auto-review").json()["rules"] == baseline_rules


def test_safety_floor_blocks_root_rm_before_ask_first_without_creating_approval(
    server: IsolatedServer,
) -> None:
    async def _run() -> None:
        async with server.async_client() as aclient:
            turn = await trigger_and_wait_turn(
                aclient,
                "thr_bot_chief",
                "Run rm -rf /",
            )
            assert turn.terminal_event.event_type == "message.completed"
            assert turn.assistant_message is not None
            assert turn.assistant_message["status"] == "error"
            assert "safety floor" in turn.assistant_message["content"].lower()

            thread_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
            assert thread_resp.status_code == 200
            assert thread_resp.json()["approvals"] == []

    asyncio.run(_run())


def test_vault_secrets_crud_never_exposes_plaintext_secret_values(
    server: IsolatedServer,
) -> None:
    secret_val = "VaultTopSecret-XYZ-98765"
    with server.client() as client:
        create_resp = client.post(
            "/api/v1/vault/secrets",
            json={
                "bot_id": "bot_chief",
                "name": "Portal Creds",
                "domain": "portal.example.com",
                "username": "ops_admin",
                "secret_value": secret_val,
            },
        )
        assert create_resp.status_code == 201
        created = create_resp.json()
        assert secret_val not in json.dumps(created)
        assert "encrypted_payload" not in created
        assert created["username_hint"] == "ops_admin"
        assert set(created["field_names"]) == {"username", "password"}

        list_resp = client.get("/api/v1/vault/secrets", params={"bot_id": "bot_chief"})
        assert list_resp.status_code == 200
        assert secret_val not in list_resp.text
        assert any(s["id"] == created["id"] for s in list_resp.json()["secrets"])

        del_resp = client.delete(f"/api/v1/vault/secrets/{created['id']}")
        assert del_resp.status_code == 200
        assert del_resp.json() == {"deleted": True}

        del_again = client.delete(f"/api/v1/vault/secrets/{created['id']}")
        assert del_again.status_code == 404


def test_hitl_404_and_secure_form_bot_mismatch_403(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        assert (
            client.post(
                "/api/v1/approvals/apr_nonexistent/resolve",
                json={"decision": "allow_once"},
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/api/v1/drafts/drf_nonexistent/resolve",
                json={"action": "send"},
            ).status_code
            == 404
        )
        assert client.post("/api/v1/routines/rtn_nonexistent/test").status_code == 404
        assert client.get("/api/v1/routines/rtn_nonexistent/runs").status_code == 404

        form = client.post(
            "/api/v1/secure-forms",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "domain": "portal.example.com",
                "title": "Bot Scoped Login",
                "fields": [{"name": "username", "label": "User", "secret": False}],
            },
        ).json()

        mismatch = client.post(
            "/api/v1/vault/secure-fill",
            json={"form_id": form["id"], "bot_id": "bot_ops", "action": "cancel"},
        )
        assert mismatch.status_code == 403

        # Form remains pending for owning bot
        ok_cancel = client.post(
            "/api/v1/vault/secure-fill",
            json={"form_id": form["id"], "bot_id": "bot_chief", "action": "cancel"},
        )
        assert ok_cancel.status_code == 200
        assert ok_cancel.json()["status"] == "cancelled"


# ---------------------------------------------------------------------------
# 2. Routines, Webhooks & Skills (Tier 1 & Tier 2)
# ---------------------------------------------------------------------------


def test_routines_crud_types_visibility_patch_and_delete(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        r_cron = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Daily Cron Check",
                "instruction": "Check workspace status",
                "schedule_type": "cron",
                "cron_expr": "0 8 * * *",
                "timezone": "UTC",
                "enabled": True,
                "visibility": "only_me",
            },
        )
        assert r_cron.status_code == 201
        cron_data = r_cron.json()
        assert cron_data["schedule_type"] == "cron"
        assert cron_data["visibility"] == "only_me"
        assert cron_data["webhook_key"].startswith("whk_")
        assert f"/api/v1/webhooks/routines/{cron_data['id']}" in cron_data["webhook_url"]

        r_webhook = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Team CI Webhook",
                "instruction": "Report CI failure",
                "schedule_type": "webhook",
                "enabled": True,
                "visibility": "team",
            },
        )
        assert r_webhook.status_code == 201
        assert r_webhook.json()["schedule_type"] == "webhook"
        assert r_webhook.json()["visibility"] == "team"

        r_manual = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Manual Audit",
                "instruction": "Run manual checklist",
                "schedule_type": "manual",
                "enabled": False,
                "visibility": "only_me",
            },
        )
        assert r_manual.status_code == 201
        assert r_manual.json()["schedule_type"] == "manual"
        assert r_manual.json()["enabled"] is False

        listed = client.get("/api/v1/bots/bot_chief/routines")
        assert listed.status_code == 200
        ids = {r["id"] for r in listed.json()["routines"]}
        assert {cron_data["id"], r_webhook.json()["id"], r_manual.json()["id"]} <= ids

        old_key = cron_data["webhook_key"]
        patched = client.patch(
            f"/api/v1/routines/{cron_data['id']}",
            json={
                "name": "Renamed Daily Check",
                "instruction": "Updated instruction",
                "visibility": "team",
                "enabled": False,
                "regenerate_webhook_key": True,
            },
        )
        assert patched.status_code == 200
        patched_data = patched.json()
        assert patched_data["name"] == "Renamed Daily Check"
        assert patched_data["instruction"] == "Updated instruction"
        assert patched_data["visibility"] == "team"
        assert patched_data["enabled"] is False
        assert patched_data["webhook_key"] != old_key
        assert patched_data["webhook_key"].startswith("whk_")

        deleted = client.delete(f"/api/v1/routines/{cron_data['id']}")
        assert deleted.status_code == 200
        assert deleted.json() == {"deleted": True}

        deleted_again = client.delete(f"/api/v1/routines/{cron_data['id']}")
        assert deleted_again.status_code == 404

        listed_after = client.get("/api/v1/bots/bot_chief/routines").json()["routines"]
        assert all(r["id"] != cron_data["id"] for r in listed_after)


async def test_routine_manual_test_returns_202_and_completes_via_sse(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_CAPTURE_SCRIPT, name="rtn_test")
    with srv.client() as client:
        routine = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Health Probe",
                "instruction": "Summarize service health",
                "schedule_type": "manual",
                "enabled": True,
            },
        ).json()
    routine_id = str(routine["id"])

    async with srv.async_client() as aclient:
        from tests.e2e._helpers import iter_sse_events

        sse_connected = asyncio.Event()
        completed_runs: list[dict[str, Any]] = []
        run_id_holder: dict[str, str] = {}
        run_id_ready = asyncio.Event()

        async def _watch() -> None:
            async for frame in iter_sse_events(
                aclient, timeout=15.0, on_connected=sse_connected
            ):
                if (frame.event_type or frame.event) != "routine.run.status":
                    continue
                if not isinstance(frame.data, dict):
                    continue
                payload = frame.data.get("payload", {})
                if payload.get("routine_id") != routine_id:
                    continue
                run_obj = payload.get("run", {})
                if not run_id_ready.is_set():
                    await run_id_ready.wait()
                if (
                    run_obj.get("id") == run_id_holder["id"]
                    and run_obj.get("status") in {"succeeded", "failed"}
                ):
                    completed_runs.append(run_obj)
                    return

        watch_task = asyncio.create_task(_watch())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            await asyncio.sleep(0.05)
            test_resp = await aclient.post(f"/api/v1/routines/{routine_id}/test")
            assert test_resp.status_code == 202
            run_data = test_resp.json()
            assert run_data["routine_id"] == routine_id
            assert run_data["trigger"] == "manual"
            assert run_data["status"] == "running"
            run_id_holder["id"] = str(run_data["id"])
            run_id_ready.set()

            await asyncio.wait_for(watch_task, timeout=12.0)
        finally:
            if not watch_task.done():
                watch_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await watch_task

        assert len(completed_runs) == 1
        assert completed_runs[0]["status"] == "succeeded"
        assert completed_runs[0]["finished_at"] is not None

        runs_resp = await aclient.get(f"/api/v1/routines/{routine_id}/runs")
        assert runs_resp.status_code == 200
        runs = runs_resp.json()["runs"]
        assert len(runs) == 1
        assert runs[0]["id"] == run_id_holder["id"]
        assert runs[0]["status"] == "succeeded"
        assert "Mock agy executed successfully." in runs[0]["summary"]


async def test_routine_runs_pruned_to_latest_20_after_exceeding_20_runs(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_CAPTURE_SCRIPT, name="rtn_prune")
    with srv.client() as client:
        routine = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Pruning Routine",
                "instruction": "NO_FINDINGS",
                "schedule_type": "webhook",
                "enabled": True,
            },
        ).json()
    routine_id = str(routine["id"])
    webhook_key = str(routine["webhook_key"])

    created_run_ids: list[str] = []
    async with srv.async_client() as aclient:
        for idx in range(23):
            if idx % 2 == 0:
                resp = await aclient.post(f"/api/v1/routines/{routine_id}/test")
            else:
                resp = await aclient.post(
                    f"/api/v1/webhooks/routines/{routine_id}",
                    headers={"Authorization": f"Bearer {webhook_key}"},
                )
            assert resp.status_code == 202
            created_run_ids.append(str(resp.json()["id"]))

        # Wait until retained background runs settle cleanly
        deadline = asyncio.get_running_loop().time() + 15.0
        runs: list[dict[str, Any]] = []
        while asyncio.get_running_loop().time() < deadline:
            runs_resp = await aclient.get(f"/api/v1/routines/{routine_id}/runs")
            assert runs_resp.status_code == 200
            runs = runs_resp.json()["runs"]
            if len(runs) == 20 and all(r["status"] == "succeeded" for r in runs):
                break
            await asyncio.sleep(0.1)

        assert len(runs) == 20
        assert all(r["status"] == "succeeded" for r in runs)
        retained_ids = {str(r["id"]) for r in runs}
        assert retained_ids == set(created_run_ids[-20:])
        for dropped_id in created_run_ids[:3]:
            assert dropped_id not in retained_ids


async def test_routine_webhook_auth_disabled_conflict_and_unknown_routine(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_CAPTURE_SCRIPT, name="webhook_auth")
    with srv.client() as client:
        routine = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Webhook Auth Check",
                "instruction": "Handle webhook trigger",
                "schedule_type": "webhook",
                "enabled": True,
            },
        ).json()
        routine_id = str(routine["id"])
        webhook_key = str(routine["webhook_key"])

        # Missing Authorization header -> 401
        assert client.post(f"/api/v1/webhooks/routines/{routine_id}").status_code == 401
        # Non-Bearer header -> 401
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{routine_id}",
                headers={"Authorization": f"Basic {webhook_key}"},
            ).status_code
            == 401
        )
        # Wrong Bearer key -> 401
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{routine_id}",
                headers={"Authorization": "Bearer whk_wrong_key"},
            ).status_code
            == 401
        )
        # Unknown routine -> 404
        assert (
            client.post(
                "/api/v1/webhooks/routines/rtn_does_not_exist",
                headers={"Authorization": f"Bearer {webhook_key}"},
            ).status_code
            == 404
        )

    async with srv.async_client() as aclient:
        valid_resp = await aclient.post(
            f"/api/v1/webhooks/routines/{routine_id}",
            headers={"Authorization": f"Bearer {webhook_key}"},
        )
        assert valid_resp.status_code == 202
        run_id = str(valid_resp.json()["id"])
        assert valid_resp.json()["trigger"] == "webhook"

        done_ev = await wait_for_sse_event(
            aclient,
            lambda f: (
                (f.event_type or f.event) == "routine.run.status"
                and isinstance(f.data, dict)
                and f.data.get("payload", {}).get("run", {}).get("id") == run_id
                and f.data.get("payload", {}).get("run", {}).get("status")
                in {"succeeded", "failed"}
            ),
            timeout=10.0,
        )
        assert isinstance(done_ev.data, dict)
        assert done_ev.data["payload"]["run"]["status"] == "succeeded"

    # Disabled routine -> 409
    with srv.client() as client:
        patch_resp = client.patch(f"/api/v1/routines/{routine_id}", json={"enabled": False})
        assert patch_resp.status_code == 200
        disabled_resp = client.post(
            f"/api/v1/webhooks/routines/{routine_id}",
            headers={"Authorization": f"Bearer {webhook_key}"},
        )
        assert disabled_resp.status_code == 409


def test_routine_regenerate_webhook_key_invalidates_old_and_accepts_new(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        routine = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Key Rotation Routine",
                "instruction": "Rotate key check",
                "schedule_type": "webhook",
                "enabled": True,
            },
        ).json()
        routine_id = str(routine["id"])
        old_key = str(routine["webhook_key"])

        assert (
            client.post(
                f"/api/v1/webhooks/routines/{routine_id}",
                headers={"Authorization": f"Bearer {old_key}"},
            ).status_code
            == 202
        )

        regen_resp = client.patch(
            f"/api/v1/routines/{routine_id}",
            json={"regenerate_webhook_key": True},
        )
        assert regen_resp.status_code == 200
        new_key = str(regen_resp.json()["webhook_key"])
        assert new_key != old_key
        assert new_key.startswith("whk_")

        # Old key must now fail with 401
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{routine_id}",
                headers={"Authorization": f"Bearer {old_key}"},
            ).status_code
            == 401
        )
        # New key succeeds with 202
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{routine_id}",
                headers={"Authorization": f"Bearer {new_key}"},
            ).status_code
            == 202
        )


def test_skills_crud_scoping_validation_and_delete(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        initial = client.get("/api/v1/skills")
        assert initial.status_code == 200
        assert any(s["id"] == "skl_summarize_workspace" for s in initial.json()["skills"])

        # Empty content_md rejected with 422
        bad = client.post(
            "/api/v1/skills",
            json={"name": "Empty Skill", "content_md": "   "},
        )
        assert bad.status_code == 422

        bot_skill_resp = client.post(
            "/api/v1/skills",
            json={
                "bot_id": "bot_ops",
                "name": "Ops Incident Runbook",
                "description": "Triage procedure",
                "content_md": "Check service logs before restarting workers.",
                "source": "custom",
            },
        )
        assert bot_skill_resp.status_code == 201
        bot_skill = bot_skill_resp.json()
        assert bot_skill["slug"] == "ops-incident-runbook"
        assert bot_skill["bot_id"] == "bot_ops"

        global_skill_resp = client.post(
            "/api/v1/skills",
            json={
                "bot_id": None,
                "name": "Global Formatting",
                "content_md": "Use concise bullet summaries.",
            },
        )
        assert global_skill_resp.status_code == 201
        global_skill = global_skill_resp.json()
        assert global_skill["bot_id"] is None

        ops_skills = client.get("/api/v1/skills", params={"bot_id": "bot_ops"}).json()["skills"]
        ops_ids = {s["id"] for s in ops_skills}
        assert {bot_skill["id"], global_skill["id"]} <= ops_ids

        chief_skills = client.get(
            "/api/v1/skills", params={"bot_id": "bot_chief"}
        ).json()["skills"]
        chief_ids = {s["id"] for s in chief_skills}
        assert global_skill["id"] in chief_ids
        assert bot_skill["id"] not in chief_ids

        del_resp = client.delete(f"/api/v1/skills/{bot_skill['id']}")
        assert del_resp.status_code == 200
        assert del_resp.json() == {"deleted": True}

        assert client.delete(f"/api/v1/skills/{bot_skill['id']}").status_code == 404


async def test_at_skill_mention_injects_active_skills_and_content_into_agy_prompt(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_CAPTURE_SCRIPT, name="skill_inject")
    skill_md = "Always verify staging canary metrics and rollback plan before release."

    with srv.client() as client:
        skill_resp = client.post(
            "/api/v1/skills",
            json={
                "bot_id": "bot_chief",
                "name": "Deploy Checklist",
                "description": "Pre-release safety gates",
                "content_md": skill_md,
            },
        )
        assert skill_resp.status_code == 201
        assert skill_resp.json()["slug"] == "deploy-checklist"

    async with srv.async_client() as aclient:
        turn_with_skill = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "Please run @deploy-checklist for release v2",
        )
        assert turn_with_skill.terminal_event.event_type == "message.completed"

        turn_without_skill = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "Summarize daily notes without invoking skills",
        )
        assert turn_without_skill.terminal_event.event_type == "message.completed"

    captured = _read_captured_prompts(srv)
    assert len(captured) == 2

    with_skill_prompt = captured[0]
    assert "[ACTIVE SKILLS]" in with_skill_prompt
    assert "## Skill: Deploy Checklist" in with_skill_prompt
    assert skill_md in with_skill_prompt

    without_skill_prompt = captured[1]
    assert "[ACTIVE SKILLS]" not in without_skill_prompt
    assert skill_md not in without_skill_prompt
