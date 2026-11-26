"""Opaque-box E2E tests for ControlBot Studio REST & SSE `/api/v1` API (E2E-M2)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import sqlite3
from collections.abc import Callable
from typing import Any

import pytest
from tests.e2e._helpers import (
    IsolatedServer,
    SseFrame,
    iter_sse_events,
    trigger_and_wait_turn,
)

pytestmark = pytest.mark.e2e

_DEFAULT_CONV_ID = "11111111-2222-3333-4444-555555555555"

_CAPTURING_MOCK_AGY_SCRIPT = f"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

prompt_val = ""
if "-p" in args:
    idx = args.index("-p")
    if idx + 1 < len(args):
        prompt_val = args[idx + 1]

model_val = "gemini-4-carbon-low"
if "--model" in args:
    idx = args.index("--model")
    if idx + 1 < len(args):
        model_val = args[idx + 1]

log_path = Path.home() / "agy_prompts.jsonl"
with log_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps({{"prompt": prompt_val, "model": model_val, "args": args}}) + "\\n")

reply = "Mock agy studio reply"
if "[BOT PERSONA:" in prompt_val:
    first_line = prompt_val.splitlines()[0]
    reply = f"Reply from {{first_line}}"

cid = "{_DEFAULT_CONV_ID}"
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({{
        "event": "init",
        "conversation_id": cid,
        "init": {{"model": model_val}},
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

_SLOW_STREAMING_MOCK_AGY_SCRIPT = f"""#!/usr/bin/env python3
import json
import sys
import time

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

cid = "{_DEFAULT_CONV_ID}"
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
            "text_delta": "Partial streaming chunk before interrupt ",
        }},
    }}), flush=True)
    time.sleep(12.0)
    print(json.dumps({{
        "event": "result",
        "result": {{
            "status": "SUCCESS",
            "conversation_id": cid,
            "response": "Completed after sleep",
        }},
    }}), flush=True)
    sys.exit(0)

print(json.dumps({{
    "status": "SUCCESS",
    "conversation_id": cid,
    "response": "Slow sync fallback",
}}))
"""


def _read_captured_prompts(srv: IsolatedServer) -> list[dict[str, Any]]:
    log_path = srv.fake_home / "agy_prompts.jsonl"
    if not log_path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped:
            records.append(json.loads(stripped))
    return records


async def _collect_turn_events_until(
    srv: IsolatedServer,
    thread_id: str,
    payload: dict[str, Any],
    *,
    expected_completed_count: int = 1,
    timeout: float = 15.0,
) -> tuple[dict[str, Any], list[SseFrame]]:
    """Open SSE before posting a message and collect frames until N message.completed events."""
    collected: list[SseFrame] = []
    sse_connected = asyncio.Event()
    sse_first_line = asyncio.Event()
    turn_id_ready = asyncio.Event()
    target_turn: dict[str, str] = {}

    async with srv.async_client(timeout=timeout + 5.0) as aclient:
        async def _listen() -> None:
            completed = 0
            async for frame in iter_sse_events(
                aclient,
                timeout=timeout,
                on_connected=sse_connected,
                on_first_line=sse_first_line,
            ):
                collected.append(frame)
                if not turn_id_ready.is_set():
                    await turn_id_ready.wait()
                if (
                    isinstance(frame.data, dict)
                    and frame.data.get("turn_id") == target_turn["id"]
                    and frame.event_type == "message.completed"
                ):
                    completed += 1
                    if completed >= expected_completed_count:
                        return

        listen_task = asyncio.create_task(_listen())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(sse_first_line.wait(), timeout=0.5)

            resp = await aclient.post(f"/api/v1/threads/{thread_id}/messages", json=payload)
            resp.raise_for_status()
            post_body: dict[str, Any] = resp.json()
            turn_id = str(post_body["turn_id"])
            target_turn["id"] = turn_id
            turn_id_ready.set()

            already_done = sum(
                1
                for f in collected
                if isinstance(f.data, dict)
                and f.data.get("turn_id") == turn_id
                and f.event_type == "message.completed"
            )
            if already_done < expected_completed_count:
                await asyncio.wait_for(listen_task, timeout=timeout)
            else:
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await listen_task
        finally:
            if not listen_task.done():
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await listen_task

    turn_frames = [
        f
        for f in collected
        if isinstance(f.data, dict) and f.data.get("turn_id") == target_turn["id"]
    ]
    return post_body, turn_frames


# ---------------------------------------------------------------------------
# 1. Bots, Sections & Channels CRUD + Boundaries (Tier 1 & Tier 2)
# ---------------------------------------------------------------------------


def test_bot_create_patch_and_make_primary_switches_previous_primary(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        initial = client.get("/api/v1/bots")
        assert initial.status_code == 200
        bots_before = initial.json()["bots"]
        chief_before = next(b for b in bots_before if b["id"] == "bot_chief")
        assert chief_before["is_primary"] is True

        create_resp = client.post(
            "/api/v1/bots",
            json={
                "name": "Reliability Analyst",
                "role_prompt": "Inspect pump telemetry and write daily summaries.",
                "about": "OT analyst bot",
                "avatar_shape": "clover",
                "avatar_color": "#0EA5E9",
                "thinking_level": "high",
                "pinned": True,
                "is_primary": False,
            },
        )
        assert create_resp.status_code == 201
        created = create_resp.json()
        bot_id = created["id"]
        assert created["name"] == "Reliability Analyst"
        assert created["thread_id"] == f"thr_{bot_id}"
        assert created["pinned"] is True
        assert created["hidden"] is False
        assert created["is_primary"] is False

        patch_resp = client.patch(
            f"/api/v1/bots/{bot_id}",
            json={
                "name": "Lead Reliability Analyst",
                "role_prompt": "Updated primary role prompt.",
                "pinned": False,
                "hidden": True,
                "is_primary": True,
            },
        )
        assert patch_resp.status_code == 200
        patched = patch_resp.json()
        assert patched["name"] == "Lead Reliability Analyst"
        assert patched["role_prompt"] == "Updated primary role prompt."
        assert patched["pinned"] is False
        assert patched["hidden"] is True
        assert patched["is_primary"] is True

        roster_after = client.get("/api/v1/bots")
        assert roster_after.status_code == 200
        bots_after = roster_after.json()["bots"]
        chief_after = next(b for b in bots_after if b["id"] == "bot_chief")
        new_after = next(b for b in bots_after if b["id"] == bot_id)
        assert chief_after["is_primary"] is False
        assert new_after["is_primary"] is True


def test_bot_delete_cascades_across_all_child_tables_and_usage(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        usage_before = client.get("/api/v1/usage").json()

        bot_resp = client.post(
            "/api/v1/bots",
            json={"name": "Cascade Cleanup Bot", "role_prompt": "Temporary bot."},
        )
        assert bot_resp.status_code == 201
        bot = bot_resp.json()
        bot_id = bot["id"]
        thread_id = bot["thread_id"]

        msg_resp = client.post(
            f"/api/v1/threads/{thread_id}/messages",
            json={"content": "Message to be cascaded on bot delete"},
        )
        assert msg_resp.status_code == 202

        page_resp = client.post(
            "/api/v1/pages",
            json={"bot_id": bot_id, "title": "Cascade Page", "content_md": "Body"},
        )
        assert page_resp.status_code == 201

        appr_resp = client.post(
            "/api/v1/approvals",
            json={"bot_id": bot_id, "thread_id": thread_id, "title": "Cascade Approval"},
        )
        assert appr_resp.status_code == 201

        draft_resp = client.post(
            "/api/v1/drafts",
            json={
                "bot_id": bot_id,
                "thread_id": thread_id,
                "channel_type": "email",
                "fields": {"to": "ops@example.com", "subject": "Cascade"},
            },
        )
        assert draft_resp.status_code == 201

        form_resp = client.post(
            "/api/v1/secure-forms",
            json={
                "bot_id": bot_id,
                "thread_id": thread_id,
                "domain": "example.com",
                "title": "Cascade Login",
                "fields": [{"name": "username", "label": "User", "secret": False}],
            },
        )
        assert form_resp.status_code == 201

        vault_resp = client.post(
            "/api/v1/vault/secrets",
            json={
                "bot_id": bot_id,
                "name": "Cascade Secret",
                "domain": "example.com",
                "username": "alice",
                "secret_value": "s3cr3t-value",
            },
        )
        assert vault_resp.status_code == 201

        skill_resp = client.post(
            "/api/v1/skills",
            json={
                "bot_id": bot_id,
                "name": "Cascade Skill",
                "content_md": "Do cascade check.",
            },
        )
        assert skill_resp.status_code == 201

        rtn_resp = client.post(
            f"/api/v1/bots/{bot_id}/routines",
            json={
                "name": "Cascade Routine",
                "instruction": "Check health.",
                "schedule_type": "manual",
            },
        )
        assert rtn_resp.status_code == 201
        rtn_id = rtn_resp.json()["id"]
        run_resp = client.post(f"/api/v1/routines/{rtn_id}/test")
        assert run_resp.status_code == 202

        usage_mid = client.get("/api/v1/usage").json()
        assert usage_mid["bots_count"] == usage_before["bots_count"] + 1
        assert usage_mid["pages_count"] >= usage_before["pages_count"] + 1
        assert usage_mid["routines_count"] >= usage_before["routines_count"] + 1
        assert usage_mid["approvals_count"] >= usage_before["approvals_count"] + 1

        del_resp = client.delete(f"/api/v1/bots/{bot_id}")
        assert del_resp.status_code == 200
        assert del_resp.json() == {"deleted": True, "bot_id": bot_id}

        assert client.delete(f"/api/v1/bots/{bot_id}").status_code == 404
        assert client.get(f"/api/v1/threads/{thread_id}/messages").status_code == 404
        vault_after = client.get("/api/v1/vault/secrets", params={"bot_id": bot_id}).json()
        assert all(s["bot_id"] != bot_id for s in vault_after["secrets"])
        skills_after = client.get("/api/v1/skills", params={"bot_id": bot_id}).json()
        assert all(s["bot_id"] != bot_id for s in skills_after["skills"])
        assert any(s["id"] == "skl_summarize_workspace" for s in skills_after["skills"])
        assert client.get(f"/api/v1/bots/{bot_id}/routines").status_code == 404

        usage_after = client.get("/api/v1/usage").json()
        assert usage_after["bots_count"] == usage_before["bots_count"]
        assert usage_after["pages_count"] == usage_before["pages_count"]
        assert usage_after["routines_count"] == usage_before["routines_count"]
        assert usage_after["approvals_count"] == usage_before["approvals_count"]

    server.stop()
    conn = sqlite3.connect(str(server.workspace_db_path))
    try:
        for table, col, val in (
            ("bots", "id", bot_id),
            ("messages", "thread_id", thread_id),
            ("attachments", "bot_id", bot_id),
            ("artifacts", "bot_id", bot_id),
            ("approvals", "bot_id", bot_id),
            ("drafts", "bot_id", bot_id),
            ("secure_forms", "bot_id", bot_id),
            ("vault_secrets", "bot_id", bot_id),
            ("skills", "bot_id", bot_id),
            ("routines", "bot_id", bot_id),
            ("routine_runs", "bot_id", bot_id),
        ):
            count = int(
                conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {col} = ?", (val,)).fetchone()[0]
            )
            assert count == 0, f"Expected 0 rows in {table} for {col}={val}, found {count}"
    finally:
        conn.close()


async def test_bot_clone_template_creates_page_message_and_emits_sse(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as client:
        bot_resp = await client.post(
            "/api/v1/bots",
            json={
                "name": "Template Specialist",
                "role_prompt": "Always cite telemetry units.",
                "thinking_level": "high",
            },
        )
        assert bot_resp.status_code == 201
        bot = bot_resp.json()
        bot_id = str(bot["id"])
        thread_id = str(bot["thread_id"])

        skill_resp = await client.post(
            "/api/v1/skills",
            json={
                "bot_id": bot_id,
                "name": "Telemetry Audit",
                "description": "Audit sensor drifts",
                "content_md": "Compare SCADA tags against nameplate.",
            },
        )
        assert skill_resp.status_code == 201

        rtn_resp = await client.post(
            f"/api/v1/bots/{bot_id}/routines",
            json={
                "name": "Morning Digest",
                "instruction": "Summarize alarms",
                "schedule_type": "cron",
                "cron_expr": "0 8 * * *",
            },
        )
        assert rtn_resp.status_code == 201

        seen_events: list[SseFrame] = []
        sse_connected = asyncio.Event()
        sse_first_line = asyncio.Event()

        async def _listen() -> None:
            got_page = False
            got_msg = False
            async for frame in iter_sse_events(
                client,
                timeout=10.0,
                on_connected=sse_connected,
                on_first_line=sse_first_line,
            ):
                if isinstance(frame.data, dict) and frame.data.get("thread_id") == thread_id:
                    seen_events.append(frame)
                    if frame.event_type == "artifact.page.updated":
                        got_page = True
                    elif frame.event_type == "message.completed":
                        got_msg = True
                    if got_page and got_msg:
                        return

        listen_task = asyncio.create_task(_listen())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(sse_first_line.wait(), timeout=0.5)

            clone_resp = await client.post(f"/api/v1/bots/{bot_id}/clone-template")
            assert clone_resp.status_code == 201
            body = clone_resp.json()
            artifact = body["artifact"]
            message = body["message"]

            assert artifact["type"] == "page"
            assert artifact["title"] == "Template Specialist — Bot Template"
            assert artifact["share_scope"] == "team"
            assert "Always cite telemetry units." in artifact["content_md"]
            assert "@telemetry-audit" in artifact["content_md"]
            assert "Morning Digest" in artifact["content_md"]

            assert message["sender_type"] == "bot"
            assert message["sender_bot_id"] == bot_id
            assert message["status"] == "done"
            assert any(a["id"] == artifact["id"] for a in message["artifacts"])

            await asyncio.wait_for(listen_task, timeout=5.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await listen_task

        event_types = [f.event_type for f in seen_events]
        assert "artifact.page.updated" in event_types
        assert "message.completed" in event_types


def test_sections_crud_and_delete_sets_null_on_bots_and_channels(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        sec_resp = client.post(
            "/api/v1/sections",
            json={"name": "Plant Operations", "sort_order": 5},
        )
        assert sec_resp.status_code == 201
        sec = sec_resp.json()
        sec_id = sec["id"]
        assert sec["name"] == "Plant Operations"
        assert sec["sort_order"] == 5

        patch_resp = client.patch(
            f"/api/v1/sections/{sec_id}",
            json={"name": "OT & SCADA Operations", "sort_order": 1},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["name"] == "OT & SCADA Operations"
        assert patch_resp.json()["sort_order"] == 1

        bot_resp = client.post(
            "/api/v1/bots",
            json={"name": "Sectioned Bot", "section_id": sec_id},
        )
        assert bot_resp.status_code == 201
        bot_id = bot_resp.json()["id"]
        assert bot_resp.json()["section_id"] == sec_id

        chn_resp = client.post(
            "/api/v1/channels",
            json={
                "name": "Sectioned Channel",
                "bot_ids": ["bot_chief", "bot_ops"],
                "section_id": sec_id,
            },
        )
        assert chn_resp.status_code == 201
        chn_id = chn_resp.json()["id"]
        assert chn_resp.json()["section_id"] == sec_id

        del_resp = client.delete(f"/api/v1/sections/{sec_id}")
        assert del_resp.status_code == 200
        assert del_resp.json() == {"deleted": True}
        assert client.delete(f"/api/v1/sections/{sec_id}").status_code == 404
        assert client.patch(f"/api/v1/sections/{sec_id}", json={"name": "Nope"}).status_code == 404

        roster = client.get("/api/v1/bots").json()
        assert all(s["id"] != sec_id for s in roster["sections"])
        bot_after = next(b for b in roster["bots"] if b["id"] == bot_id)
        chn_after = next(c for c in roster["channels"] if c["id"] == chn_id)
        assert bot_after["section_id"] is None
        assert chn_after["section_id"] is None


def test_channel_crud_and_delete_cascades_channel_messages_and_artifacts(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        create_resp = client.post(
            "/api/v1/channels",
            json={
                "name": "Shift Handoff",
                "bot_ids": ["bot_chief", "bot_ops"],
                "pinned": False,
            },
        )
        assert create_resp.status_code == 201
        chn = create_resp.json()
        chn_id = chn["id"]
        thr_id = chn["thread_id"]
        assert thr_id == f"thr_{chn_id}"
        assert chn["bot_ids"] == ["bot_chief", "bot_ops"]

        patch_resp = client.patch(
            f"/api/v1/channels/{chn_id}",
            json={
                "name": "Shift Handoff Plus",
                "bot_ids": ["bot_chief", "bot_ops", "bot_browser"],
                "pinned": True,
                "hidden": True,
            },
        )
        assert patch_resp.status_code == 200
        patched = patch_resp.json()
        assert patched["name"] == "Shift Handoff Plus"
        assert patched["bot_ids"] == ["bot_chief", "bot_ops", "bot_browser"]
        assert patched["pinned"] is True
        assert patched["hidden"] is True

        msg_resp = client.post(
            f"/api/v1/threads/{thr_id}/messages",
            json={"content": "Channel message for cascade delete"},
        )
        assert msg_resp.status_code == 202

        page_resp = client.post(
            "/api/v1/pages",
            json={"channel_id": chn_id, "title": "Channel Brief", "content_md": "# Brief"},
        )
        assert page_resp.status_code == 201
        page_id = page_resp.json()["id"]

        del_resp = client.delete(f"/api/v1/channels/{chn_id}")
        assert del_resp.status_code == 200
        assert del_resp.json() == {"deleted": True}
        assert client.delete(f"/api/v1/channels/{chn_id}").status_code == 404
        assert client.get(f"/api/v1/threads/{thr_id}/messages").status_code == 404
        assert client.get(f"/api/v1/pages/{page_id}").status_code == 404

        roster = client.get("/api/v1/bots").json()
        assert all(c["id"] != chn_id for c in roster["channels"])
        assert {b["id"] for b in roster["bots"]} >= {"bot_chief", "bot_ops", "bot_browser"}

    server.stop()
    conn = sqlite3.connect(str(server.workspace_db_path))
    try:
        for table in ("messages", "artifacts", "approvals", "drafts", "secure_forms"):
            cnt = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE thread_id = ?", (thr_id,)
                ).fetchone()[0]
            )
            assert cnt == 0
    finally:
        conn.close()


def test_channel_validation_boundaries_422(server: IsolatedServer) -> None:
    with server.client() as client:
        extra_bots: list[str] = ["bot_chief", "bot_ops", "bot_browser"]
        for idx in range(4):
            b = client.post("/api/v1/bots", json={"name": f"Extra Bot {idx}"})
            assert b.status_code == 201
            extra_bots.append(b.json()["id"])

        # < 2 bots
        r_one = client.post(
            "/api/v1/channels",
            json={"name": "Too Small", "bot_ids": ["bot_chief"]},
        )
        assert r_one.status_code == 422

        # > 6 bots (7 unique bots)
        r_seven = client.post(
            "/api/v1/channels",
            json={"name": "Too Big", "bot_ids": extra_bots[:7]},
        )
        assert r_seven.status_code == 422

        # Duplicate bot_ids collapsing below 2
        r_dup = client.post(
            "/api/v1/channels",
            json={"name": "Dup Collapse", "bot_ids": ["bot_chief", "bot_chief"]},
        )
        assert r_dup.status_code == 422

        # Unknown bot_id
        r_unk = client.post(
            "/api/v1/channels",
            json={"name": "Unknown Member", "bot_ids": ["bot_chief", "bot_nonexistent"]},
        )
        assert r_unk.status_code == 422

        # Unknown section_id
        r_sec = client.post(
            "/api/v1/channels",
            json={
                "name": "Bad Section",
                "bot_ids": ["bot_chief", "bot_ops"],
                "section_id": "sec_does_not_exist",
            },
        )
        assert r_sec.status_code == 422

        # Valid 2-bot channel for PATCH validation boundaries
        valid = client.post(
            "/api/v1/channels",
            json={"name": "Valid Channel", "bot_ids": ["bot_chief", "bot_ops"]},
        )
        assert valid.status_code == 201
        chn_id = valid.json()["id"]

        assert client.patch(f"/api/v1/channels/{chn_id}", json={"name": "   "}).status_code == 422
        assert (
            client.patch(f"/api/v1/channels/{chn_id}", json={"unread_count": -1}).status_code == 422
        )
        assert (
            client.patch(f"/api/v1/channels/{chn_id}", json={"bot_ids": ["bot_chief"]}).status_code
            == 422
        )
        assert (
            client.patch(
                f"/api/v1/channels/{chn_id}", json={"section_id": "sec_missing"}
            ).status_code
            == 422
        )


def test_roster_max_50_items_cap_across_bots_and_channels(server: IsolatedServer) -> None:
    with server.client() as client:
        roster = client.get("/api/v1/bots").json()
        initial_count = len(roster["bots"]) + len(roster["channels"])
        assert initial_count == 3

        # Create 46 bots + 1 channel -> 3 + 46 + 1 = 50 total roster items
        for i in range(46):
            resp = client.post("/api/v1/bots", json={"name": f"Cap Bot {i}"})
            assert resp.status_code == 201

        chn_resp = client.post(
            "/api/v1/channels",
            json={"name": "Cap Channel 50th", "bot_ids": ["bot_chief", "bot_ops"]},
        )
        assert chn_resp.status_code == 201
        chn_id = chn_resp.json()["id"]

        # 51st bot and 51st channel must both fail with 422
        bot_51 = client.post("/api/v1/bots", json={"name": "Overflow Bot 51"})
        assert bot_51.status_code == 422

        chn_51 = client.post(
            "/api/v1/channels",
            json={"name": "Overflow Channel 51", "bot_ids": ["bot_chief", "bot_ops"]},
        )
        assert chn_51.status_code == 422

        # Deleting 1 channel frees 1 slot -> next bot succeeds, then 51st fails again
        assert client.delete(f"/api/v1/channels/{chn_id}").status_code == 200
        bot_50_again = client.post("/api/v1/bots", json={"name": "Slot Freed Bot"})
        assert bot_50_again.status_code == 201
        assert (
            client.post("/api/v1/bots", json={"name": "Overflow Again"}).status_code == 422
        )


def test_bot_create_and_patch_validation_boundaries_422_and_404(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        assert client.post("/api/v1/bots", json={"name": "   "}).status_code == 422
        assert (
            client.post(
                "/api/v1/bots", json={"name": "Bad Sec", "section_id": "sec_missing"}
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/v1/bots", json={"name": "Bad Shape", "avatar_shape": "triangle"}
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/v1/bots", json={"name": "Bad Thinking", "thinking_level": "ultra"}
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/v1/bots", json={"name": "Bad Color", "avatar_color": "#1"}
            ).status_code
            == 422
        )

        # PATCH validation boundaries on bot_chief
        assert (
            client.patch("/api/v1/bots/bot_chief", json={"unread_count": -1}).status_code == 422
        )
        assert client.patch("/api/v1/bots/bot_chief", json={"name": "  "}).status_code == 422
        assert (
            client.patch("/api/v1/bots/bot_chief", json={"status_state": "sleeping"}).status_code
            == 422
        )
        assert (
            client.patch(
                "/api/v1/bots/bot_chief", json={"thinking_level": "extreme"}
            ).status_code
            == 422
        )
        assert (
            client.patch("/api/v1/bots/bot_chief", json={"avatar_shape": "octagon"}).status_code
            == 422
        )
        assert (
            client.patch("/api/v1/bots/bot_chief", json={"section_id": "sec_missing"}).status_code
            == 422
        )
        assert client.patch("/api/v1/bots/bot_nonexistent", json={"name": "X"}).status_code == 404


# ---------------------------------------------------------------------------
# 2. Messages, @ Mentions, Interrupt, Reactions & Message-to-Page
# ---------------------------------------------------------------------------


async def test_thread_message_reply_to_id_persists_and_missing_thread_404(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_CAPTURING_MOCK_AGY_SCRIPT, name="reply_to")
    async with srv.async_client() as client:
        t1 = await trigger_and_wait_turn(client, "thr_bot_chief", "Initial message")
        parent_id = str(t1.user_message["id"])

        t2 = await trigger_and_wait_turn(
            client,
            "thr_bot_chief",
            "Follow-up reply",
            reply_to_id=parent_id,
        )
        assert t2.user_message["reply_to_id"] == parent_id

        history = await client.get("/api/v1/threads/thr_bot_chief/messages")
        assert history.status_code == 200
        msgs = history.json()["messages"]
        replied = next(m for m in msgs if m["id"] == t2.user_message["id"])
        assert replied["reply_to_id"] == parent_id

        missing_get = await client.get("/api/v1/threads/thr_does_not_exist/messages")
        assert missing_get.status_code == 404
        missing_post = await client.post(
            "/api/v1/threads/thr_does_not_exist/messages",
            json={"content": "Hello"},
        )
        assert missing_post.status_code == 404


async def test_message_page_context_id_forwarded_to_bot_prompt(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_CAPTURING_MOCK_AGY_SCRIPT, name="page_ctx")
    async with srv.async_client() as client:
        page_resp = await client.post(
            "/api/v1/pages",
            json={
                "bot_id": "bot_chief",
                "title": "Turbine Inspection SOP",
                "content_md": "Check bearing vibration <= 2.5 mm/s [PAGE_CTX_MARKER_741].",
            },
        )
        assert page_resp.status_code == 201
        page_id = str(page_resp.json()["id"])

        turn = await trigger_and_wait_turn(
            client,
            "thr_bot_chief",
            "Summarize the active page threshold.",
            page_context_id=page_id,
        )
        assert turn.assistant_message is not None

    captured = _read_captured_prompts(srv)
    assert len(captured) >= 1
    last_prompt = str(captured[-1]["prompt"])
    assert "[ACTIVE PAGE CONTEXT]" in last_prompt
    assert "Turbine Inspection SOP" in last_prompt
    assert "PAGE_CTX_MARKER_741" in last_prompt


async def test_group_channel_at_slug_and_underscore_mentions_trigger_handoff(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_CAPTURING_MOCK_AGY_SCRIPT, name="mentions")
    with srv.client() as sync_client:
        chn_resp = sync_client.post(
            "/api/v1/channels",
            json={
                "name": "Ops War Room",
                "bot_ids": ["bot_chief", "bot_ops", "bot_browser"],
            },
        )
        assert chn_resp.status_code == 201
        thr_id = str(chn_resp.json()["thread_id"])

    # 1) Hyphenated @slug mentions: @controlbot-ops and @browser-runner
    _, slug_frames = await _collect_turn_events_until(
        srv,
        thr_id,
        {"content": "@controlbot-ops and @browser-runner please inspect telemetry."},
        expected_completed_count=2,
        timeout=15.0,
    )
    slug_handoffs = [f for f in slug_frames if f.event_type == "handoff.dispatched"]
    assert len(slug_handoffs) == 1
    assert isinstance(slug_handoffs[0].data, dict)
    assert slug_handoffs[0].data["payload"]["from_bot_id"] == "bot_ops"
    assert slug_handoffs[0].data["payload"]["to_bot_id"] == "bot_browser"

    slug_completed = [
        f.data["payload"]["message"]
        for f in slug_frames
        if f.event_type == "message.completed" and isinstance(f.data, dict)
    ]
    assert [m["sender_bot_id"] for m in slug_completed] == ["bot_ops", "bot_browser"]

    # 2) Underscore @Bot_Name variants: @Chief_of_Staff and @ControlBot_Ops
    _, under_frames = await _collect_turn_events_until(
        srv,
        thr_id,
        {"content": "@Chief_of_Staff hand off to @ControlBot_Ops for action."},
        expected_completed_count=2,
        timeout=15.0,
    )
    under_handoffs = [f for f in under_frames if f.event_type == "handoff.dispatched"]
    assert len(under_handoffs) == 1
    assert isinstance(under_handoffs[0].data, dict)
    assert under_handoffs[0].data["payload"]["from_bot_id"] == "bot_chief"
    assert under_handoffs[0].data["payload"]["to_bot_id"] == "bot_ops"

    under_completed = [
        f.data["payload"]["message"]
        for f in under_frames
        if f.event_type == "message.completed" and isinstance(f.data, dict)
    ]
    assert [m["sender_bot_id"] for m in under_completed] == ["bot_chief", "bot_ops"]


async def test_channel_mention_fallback_to_primary_and_at_all(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_CAPTURING_MOCK_AGY_SCRIPT, name="mentions_all")
    with srv.client() as sync_client:
        chn_resp = sync_client.post(
            "/api/v1/channels",
            json={
                "name": "All Hands",
                "bot_ids": ["bot_ops", "bot_chief", "bot_browser"],
            },
        )
        assert chn_resp.status_code == 201
        thr_id = str(chn_resp.json()["thread_id"])

    # No @mention falls back to channel's primary bot (bot_chief)
    async with srv.async_client() as aclient:
        fallback_turn = await trigger_and_wait_turn(
            aclient, thr_id, "General question without mentions"
        )
        assert fallback_turn.assistant_message is not None
        assert fallback_turn.assistant_message["sender_bot_id"] == "bot_chief"

    # @all triggers all 3 bots in order with 2 handoffs
    _, all_frames = await _collect_turn_events_until(
        srv,
        thr_id,
        {"content": "@all give status update"},
        expected_completed_count=3,
        timeout=20.0,
    )
    handoffs = [f for f in all_frames if f.event_type == "handoff.dispatched"]
    assert len(handoffs) == 2
    completed = [
        f.data["payload"]["message"]
        for f in all_frames
        if f.event_type == "message.completed" and isinstance(f.data, dict)
    ]
    assert [m["sender_bot_id"] for m in completed] == ["bot_ops", "bot_chief", "bot_browser"]


async def test_thread_interrupt_cancels_streaming_turn_and_sets_presence_idle(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_SLOW_STREAMING_MOCK_AGY_SCRIPT, name="interrupt")
    collected: list[SseFrame] = []
    sse_connected = asyncio.Event()
    sse_first_line = asyncio.Event()
    delta_seen = asyncio.Event()
    completed_and_idle = asyncio.Event()
    target_turn: dict[str, str] = {}

    async with srv.async_client(timeout=15.0) as aclient:
        async def _listen() -> None:
            saw_completed = False
            saw_idle = False
            async for frame in iter_sse_events(
                aclient,
                timeout=12.0,
                on_connected=sse_connected,
                on_first_line=sse_first_line,
            ):
                collected.append(frame)
                if not isinstance(frame.data, dict):
                    continue
                if frame.event_type == "message.delta":
                    delta_seen.set()
                tid = target_turn.get("id")
                if tid and frame.data.get("turn_id") == tid:
                    if frame.event_type == "message.completed":
                        saw_completed = True
                    elif (
                        frame.event_type == "bot.presence"
                        and frame.data.get("payload", {}).get("state") == "idle"
                    ):
                        saw_idle = True
                    if saw_completed and saw_idle:
                        completed_and_idle.set()
                        return

        listen_task = asyncio.create_task(_listen())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(sse_first_line.wait(), timeout=0.5)

            post_resp = await aclient.post(
                "/api/v1/threads/thr_bot_chief/messages",
                json={"content": "Start a long streaming turn"},
            )
            assert post_resp.status_code == 202
            target_turn["id"] = str(post_resp.json()["turn_id"])

            await asyncio.wait_for(delta_seen.wait(), timeout=8.0)

            intr_resp = await aclient.post("/api/v1/threads/thr_bot_chief/interrupt")
            assert intr_resp.status_code == 200
            assert intr_resp.json() == {"interrupted": True, "thread_id": "thr_bot_chief"}

            await asyncio.wait_for(completed_and_idle.wait(), timeout=6.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await listen_task

        completed_frame = next(
            f
            for f in collected
            if isinstance(f.data, dict)
            and f.data.get("turn_id") == target_turn["id"]
            and f.event_type == "message.completed"
        )
        assert isinstance(completed_frame.data, dict)
        assert completed_frame.data["payload"]["message"]["status"] == "interrupted"

        idle_frames = [
            f
            for f in collected
            if isinstance(f.data, dict)
            and f.data.get("turn_id") == target_turn["id"]
            and f.event_type == "bot.presence"
            and f.data["payload"]["state"] == "idle"
        ]
        assert len(idle_frames) >= 1

        # Calling interrupt again when idle returns interrupted: False
        intr_again = await aclient.post("/api/v1/threads/thr_bot_chief/interrupt")
        assert intr_again.status_code == 200
        assert intr_again.json()["interrupted"] is False


async def test_message_reactions_add_toggle_remove_and_sse_event(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as client:
        post_resp = await client.post(
            "/api/v1/threads/thr_bot_chief/messages",
            json={"content": "React to this message"},
        )
        assert post_resp.status_code == 202
        msg_id = str(post_resp.json()["user_message"]["id"])

        sse_events: list[SseFrame] = []
        sse_connected = asyncio.Event()
        sse_first_line = asyncio.Event()

        async def _listen() -> None:
            async for frame in iter_sse_events(
                client,
                timeout=8.0,
                on_connected=sse_connected,
                on_first_line=sse_first_line,
            ):
                if (
                    frame.event_type == "message.reaction"
                    and isinstance(frame.data, dict)
                    and frame.data.get("payload", {}).get("message_id") == msg_id
                ):
                    sse_events.append(frame)
                    if len(sse_events) >= 5:
                        return

        listen_task = asyncio.create_task(_listen())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(sse_first_line.wait(), timeout=0.5)

            r1 = await client.post(
                f"/api/v1/messages/{msg_id}/reactions",
                json={"emoji": "👍", "action": "add"},
            )
            assert r1.status_code == 200
            assert r1.json()["reactions"] == {"👍": 1}

            r2 = await client.post(
                f"/api/v1/messages/{msg_id}/reactions",
                json={"emoji": "👍", "action": "add"},
            )
            assert r2.status_code == 200
            assert r2.json()["reactions"] == {"👍": 2}

            r3 = await client.post(
                f"/api/v1/messages/{msg_id}/reactions",
                json={"emoji": "👍", "action": "remove"},
            )
            assert r3.status_code == 200
            assert r3.json()["reactions"] == {"👍": 1}

            r4 = await client.post(
                f"/api/v1/messages/{msg_id}/reactions",
                json={"emoji": "👍", "action": "toggle"},
            )
            assert r4.status_code == 200
            assert r4.json()["reactions"] == {}

            r5 = await client.post(
                f"/api/v1/messages/{msg_id}/reactions",
                json={"emoji": "🚀", "action": "toggle"},
            )
            assert r5.status_code == 200
            assert r5.json()["reactions"] == {"🚀": 1}

            await asyncio.wait_for(listen_task, timeout=5.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await listen_task

        assert len(sse_events) == 5
        last_payload = sse_events[-1].data
        assert isinstance(last_payload, dict)
        assert last_payload["payload"]["reactions"] == {"🚀": 1}

        msgs = (await client.get("/api/v1/threads/thr_bot_chief/messages")).json()["messages"]
        persisted = next(m for m in msgs if m["id"] == msg_id)
        assert persisted["reactions"] == {"🚀": 1}

        assert (
            await client.post(
                "/api/v1/messages/msg_missing/reactions",
                json={"emoji": "👍", "action": "add"},
            )
        ).status_code == 404
        assert (
            await client.post(
                f"/api/v1/messages/{msg_id}/reactions",
                json={"emoji": "   ", "action": "add"},
            )
        ).status_code == 422


async def test_message_to_page_creates_page_updates_message_and_emits_sse(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as client:
        post_resp = await client.post(
            "/api/v1/threads/thr_bot_chief/messages",
            json={"content": "# Pump Check Report\nAll bearings nominal."},
        )
        assert post_resp.status_code == 202
        msg_id = str(post_resp.json()["user_message"]["id"])

        events: list[SseFrame] = []
        sse_connected = asyncio.Event()
        sse_first_line = asyncio.Event()

        async def _listen() -> None:
            got_page = False
            got_msg = False
            async for frame in iter_sse_events(
                client,
                timeout=8.0,
                on_connected=sse_connected,
                on_first_line=sse_first_line,
            ):
                if isinstance(frame.data, dict) and frame.data.get("thread_id") == "thr_bot_chief":
                    events.append(frame)
                    if frame.event_type == "artifact.page.updated":
                        got_page = True
                    elif (
                        frame.event_type == "message.completed"
                        and frame.data.get("payload", {}).get("message_id") == msg_id
                    ):
                        got_msg = True
                    if got_page and got_msg:
                        return

        listen_task = asyncio.create_task(_listen())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(sse_first_line.wait(), timeout=0.5)

            conv_resp = await client.post(
                f"/api/v1/messages/{msg_id}/to-page",
                json={"share_scope": "team"},
            )
            assert conv_resp.status_code == 201
            body = conv_resp.json()
            assert body["page"]["type"] == "page"
            assert body["page"]["title"] == "Pump Check Report"
            assert body["page"]["share_scope"] == "team"
            assert any(a["id"] == body["page"]["id"] for a in body["message"]["artifacts"])

            await asyncio.wait_for(listen_task, timeout=5.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await listen_task

        assert {"artifact.page.updated", "message.completed"}.issubset(
            {f.event_type for f in events}
        )


# ---------------------------------------------------------------------------
# 3. Pages, Library & Artifact Delete
# ---------------------------------------------------------------------------


def test_pages_create_with_bot_id_and_channel_only_channel_id(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        bot_page = client.post(
            "/api/v1/pages",
            json={
                "bot_id": "bot_chief",
                "title": "Bot Direct Page",
                "content_md": "Direct content",
            },
        )
        assert bot_page.status_code == 201
        assert bot_page.json()["bot_id"] == "bot_chief"
        assert bot_page.json()["thread_id"] == "thr_bot_chief"

        chn_resp = client.post(
            "/api/v1/channels",
            json={"name": "Page Channel", "bot_ids": ["bot_ops", "bot_browser"]},
        )
        assert chn_resp.status_code == 201
        chn = chn_resp.json()

        chn_page = client.post(
            "/api/v1/pages",
            json={
                "channel_id": chn["id"],
                "title": "Channel Only Page",
                "content_md": "Shared channel page",
                "share_scope": "team",
            },
        )
        assert chn_page.status_code == 201
        cp_data = chn_page.json()
        assert cp_data["bot_id"] == "bot_ops"
        assert cp_data["thread_id"] == chn["thread_id"]
        assert cp_data["share_scope"] == "team"

        fetched = client.get(f"/api/v1/pages/{cp_data['id']}")
        assert fetched.status_code == 200
        assert fetched.json()["title"] == "Channel Only Page"

        assert (
            client.post("/api/v1/pages", json={"title": "Missing Target"}).status_code == 422
        )
        assert client.get("/api/v1/pages/art_missing").status_code == 404


async def test_pages_same_title_versioning_and_patch_bumps_version_with_sse(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as client:
        v1_resp = await client.post(
            "/api/v1/pages",
            json={
                "bot_id": "bot_chief",
                "title": "Runbook Alpha",
                "content_md": "Version 1 body",
            },
        )
        assert v1_resp.status_code == 201
        v1 = v1_resp.json()
        assert v1["version"] == 1
        assert v1["superseded_by_id"] is None

        v2_resp = await client.post(
            "/api/v1/pages",
            json={
                "bot_id": "bot_chief",
                "title": "runbook alpha",
                "content_md": "Version 2 body",
            },
        )
        assert v2_resp.status_code == 201
        v2 = v2_resp.json()
        assert v2["version"] == 2
        assert v2["superseded_by_id"] is None

        v1_after = (await client.get(f"/api/v1/pages/{v1['id']}")).json()
        assert v1_after["superseded_by_id"] == v2["id"]

        sse_events: list[SseFrame] = []
        sse_connected = asyncio.Event()
        sse_first_line = asyncio.Event()

        async def _listen() -> None:
            async for frame in iter_sse_events(
                client,
                timeout=8.0,
                on_connected=sse_connected,
                on_first_line=sse_first_line,
            ):
                if (
                    frame.event_type == "artifact.page.updated"
                    and isinstance(frame.data, dict)
                    and frame.data.get("payload", {}).get("artifact", {}).get("id") == v2["id"]
                ):
                    sse_events.append(frame)
                    return

        listen_task = asyncio.create_task(_listen())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(sse_first_line.wait(), timeout=0.5)

            patch_resp = await client.patch(
                f"/api/v1/pages/{v2['id']}",
                json={"content_md": "Version 3 body"},
            )
            assert patch_resp.status_code == 200
            v3 = patch_resp.json()
            assert v3["version"] == 3
            assert v3["content_md"] == "Version 3 body"

            await asyncio.wait_for(listen_task, timeout=5.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await listen_task

        assert len(sse_events) == 1
        # Title-only patch does not bump version
        title_patch = await client.patch(
            f"/api/v1/pages/{v2['id']}",
            json={"title": "Runbook Alpha Renamed"},
        )
        assert title_patch.status_code == 200
        assert title_patch.json()["version"] == 3


def test_library_filters_latest_version_type_pinned_and_q(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        v1 = client.post(
            "/api/v1/pages",
            json={"bot_id": "bot_chief", "title": "Deploy Guide", "content_md": "v1"},
        ).json()
        v2 = client.post(
            "/api/v1/pages",
            json={"bot_id": "bot_chief", "title": "Deploy Guide", "content_md": "v2"},
        ).json()
        other = client.post(
            "/api/v1/pages",
            json={"bot_id": "bot_chief", "title": "Other Notes", "content_md": "misc"},
        ).json()

        pin_resp = client.patch(
            f"/api/v1/artifacts/{other['id']}/pin",
            json={"pinned": True},
        )
        assert pin_resp.status_code == 200
        assert pin_resp.json()["pinned"] is True

        att_resp = client.post(
            "/api/v1/attachments",
            params={"filename": "sensor_dump.csv", "thread_id": "thr_bot_chief"},
            content=b"tag,val\nPT-101,42\n",
            headers={"Content-Type": "text/csv"},
        )
        assert att_resp.status_code == 201

        lib_all = client.get("/api/v1/bots/bot_chief/library")
        assert lib_all.status_code == 200
        all_ids = {item["id"] for item in lib_all.json()["items"]}
        assert v2["id"] in all_ids
        assert v1["id"] not in all_ids
        assert other["id"] in all_ids
        assert "grouped" in lib_all.json()

        lib_pages = client.get("/api/v1/bots/bot_chief/library", params={"type": "page"}).json()
        assert all(item["type"] == "page" for item in lib_pages["items"])
        assert {item["id"] for item in lib_pages["items"]} == {v2["id"], other["id"]}

        lib_files = client.get("/api/v1/bots/bot_chief/library", params={"type": "file"}).json()
        assert len(lib_files["items"]) == 1
        assert lib_files["items"][0]["title"] == "sensor_dump.csv"

        lib_pinned = client.get(
            "/api/v1/bots/bot_chief/library", params={"pinned": "true"}
        ).json()
        assert [item["id"] for item in lib_pinned["items"]] == [other["id"]]

        lib_q = client.get("/api/v1/bots/bot_chief/library", params={"q": "Deploy"}).json()
        assert [item["id"] for item in lib_q["items"]] == [v2["id"]]


async def test_delete_artifact_unlinks_disk_file_and_emits_sse(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as client:
        att_resp = await client.post(
            "/api/v1/attachments",
            params={"filename": "unlink_target.txt", "thread_id": "thr_bot_chief"},
            content=b"physical file content to unlink",
            headers={"Content-Type": "text/plain"},
        )
        assert att_resp.status_code == 201
        att_id = str(att_resp.json()["id"])

        uploads_dir = server.tmp_dir / "uploads"
        disk_files = list(uploads_dir.glob(f"{att_id}_*"))
        assert len(disk_files) == 1
        disk_file = disk_files[0]
        assert disk_file.is_file()

        lib_files = (
            await client.get("/api/v1/bots/bot_chief/library", params={"type": "file"})
        ).json()["items"]
        art = next(item for item in lib_files if item["title"] == "unlink_target.txt")
        art_id = str(art["id"])

        deleted_events: list[SseFrame] = []
        sse_connected = asyncio.Event()
        sse_first_line = asyncio.Event()

        async def _listen() -> None:
            async for frame in iter_sse_events(
                client,
                timeout=8.0,
                on_connected=sse_connected,
                on_first_line=sse_first_line,
            ):
                if (
                    frame.event_type == "artifact.deleted"
                    and isinstance(frame.data, dict)
                    and frame.data.get("payload", {}).get("artifact_id") == art_id
                ):
                    deleted_events.append(frame)
                    return

        listen_task = asyncio.create_task(_listen())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(sse_first_line.wait(), timeout=0.5)

            del_resp = await client.delete(f"/api/v1/artifacts/{art_id}")
            assert del_resp.status_code == 200
            assert del_resp.json() == {"deleted": True}

            await asyncio.wait_for(listen_task, timeout=5.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await listen_task

        assert len(deleted_events) == 1
        assert not disk_file.exists()
        assert (await client.get(f"/api/v1/attachments/{att_id}")).status_code == 404


def test_artifact_pin_and_page_not_found_and_non_page_get_404(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        att_resp = client.post(
            "/api/v1/attachments",
            params={"filename": "not_a_page.txt", "thread_id": "thr_bot_chief"},
            content=b"plain text",
            headers={"Content-Type": "text/plain"},
        )
        assert att_resp.status_code == 201
        lib = client.get("/api/v1/bots/bot_chief/library", params={"type": "file"}).json()
        file_art_id = lib["items"][0]["id"]

        assert client.get(f"/api/v1/pages/{file_art_id}").status_code == 404
        assert client.patch("/api/v1/pages/art_missing", json={"title": "X"}).status_code == 404
        assert (
            client.patch("/api/v1/artifacts/art_missing/pin", json={"pinned": True}).status_code
            == 404
        )
        assert client.delete("/api/v1/artifacts/art_missing").status_code == 404


# ---------------------------------------------------------------------------
# 4. Settings, Connected Apps, Usage & Search
# ---------------------------------------------------------------------------


def test_settings_get_and_patch_persists_fields_across_restart(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        initial = client.get("/api/v1/settings")
        assert initial.status_code == 200
        assert initial.json()["theme"] == "light"

        patch_resp = client.patch(
            "/api/v1/settings",
            json={
                "theme": "dark",
                "accent_mode": "black",
                "default_model_id": "gemini-4-neon-medium",
                "default_engine_id": "controlbot_runtime",
                "default_thinking_level": "high",
                "allow_hydrogen": True,
                "include_browser_context": False,
                "notifications_enabled": False,
                "sound_enabled": True,
                "auto_open_computer": False,
                "timezone": "America/New_York",
                "display_name": "Shift Supervisor",
            },
        )
        assert patch_resp.status_code == 200
        updated = patch_resp.json()
        assert updated["theme"] == "dark"
        assert updated["accent_mode"] == "black"
        assert updated["default_model"] == "gemini-4-neon-medium"
        assert updated["default_engine"] == "controlbot_runtime"
        assert updated["allow_hydrogen"] is True
        assert updated["display_name"] == "Shift Supervisor"

    server.restart(keep_port=True)
    with server.client() as client:
        after = client.get("/api/v1/settings")
        assert after.status_code == 200
        data = after.json()
        assert data["theme"] == "dark"
        assert data["default_model_id"] == "gemini-4-neon-medium"
        assert data["default_engine_id"] == "controlbot_runtime"
        assert data["default_thinking_level"] == "high"
        assert data["allow_hydrogen"] is True
        assert data["auto_open_computer"] is False
        assert data["timezone"] == "America/New_York"
        assert data["display_name"] == "Shift Supervisor"


async def test_connected_apps_account_label_persists_and_enabled_false_enforced(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_CAPTURING_MOCK_AGY_SCRIPT, name="apps_enforce")
    with srv.client() as client:
        apps_resp = client.get("/api/v1/apps")
        assert apps_resp.status_code == 200
        apps = {a["id"]: a for a in apps_resp.json()["apps"]}
        assert "app_agy" in apps
        assert apps["app_agy"]["enabled"] is True

        patch_label = client.patch(
            "/api/v1/apps/app_agy",
            json={"account_label": "Plant Workstation A"},
        )
        assert patch_label.status_code == 200
        assert patch_label.json()["account_label"] == "Plant Workstation A"

        apps_after = {a["id"]: a for a in client.get("/api/v1/apps").json()["apps"]}
        assert apps_after["app_agy"]["account_label"] == "Plant Workstation A"

        disable_resp = client.patch(
            "/api/v1/apps/app_agy",
            json={"enabled": False},
        )
        assert disable_resp.status_code == 200
        assert disable_resp.json()["enabled"] is False
        assert disable_resp.json()["status"] == "disabled"
        assert disable_resp.json()["account_label"] == "Plant Workstation A"

    async with srv.async_client() as aclient:
        disabled_turn = await trigger_and_wait_turn(
            aclient, "thr_bot_chief", "Should fail while agy is disabled"
        )
        assert disabled_turn.assistant_message is not None
        assert disabled_turn.assistant_message["status"] == "error"
        assert (
            "Antigravity CLI (`agy`) is disabled in Connected Apps."
            in disabled_turn.assistant_message["content"]
        )
        assert _read_captured_prompts(srv) == []

        enable_resp = await aclient.patch("/api/v1/apps/app_agy", json={"enabled": True})
        assert enable_resp.status_code == 200
        assert enable_resp.json()["enabled"] is True
        assert enable_resp.json()["status"] == "connected"

        enabled_turn = await trigger_and_wait_turn(
            aclient, "thr_bot_chief", "Should succeed after re-enabling agy"
        )
        assert enabled_turn.assistant_message is not None
        assert enabled_turn.assistant_message["status"] == "done"
        assert len(_read_captured_prompts(srv)) == 1


def test_usage_endpoint_tracks_counts_accurately(server: IsolatedServer) -> None:
    with server.client() as client:
        u0 = client.get("/api/v1/usage").json()
        assert u0["bots_count"] == 3
        assert u0["channels_count"] == 0
        assert u0["active_turns"] == 0

        bot = client.post("/api/v1/bots", json={"name": "Usage Bot"}).json()
        chn = client.post(
            "/api/v1/channels",
            json={"name": "Usage Channel", "bot_ids": ["bot_chief", bot["id"]]},
        ).json()
        client.post(
            "/api/v1/pages",
            json={"bot_id": bot["id"], "title": "Usage Page", "content_md": "hi"},
        )
        client.post(
            f"/api/v1/bots/{bot['id']}/routines",
            json={"name": "Usage Routine", "instruction": "run", "schedule_type": "manual"},
        )
        client.post(
            "/api/v1/approvals",
            json={"bot_id": bot["id"], "thread_id": bot["thread_id"], "title": "Usage Appr"},
        )
        client.post(
            f"/api/v1/threads/{chn['thread_id']}/messages",
            json={"content": "Usage message"},
        )

        u1 = client.get("/api/v1/usage").json()
        assert u1["bots_count"] == u0["bots_count"] + 1
        assert u1["channels_count"] == u0["channels_count"] + 1
        assert u1["pages_count"] == u0["pages_count"] + 1
        assert u1["routines_count"] == u0["routines_count"] + 1
        assert u1["approvals_count"] == u0["approvals_count"] + 1
        assert u1["messages_count"] >= u0["messages_count"] + 1


def test_search_workspace_across_entities_and_empty_query(
    server: IsolatedServer,
) -> None:
    token = "ZxQuasar91"
    with server.client() as client:
        empty_res = client.get("/api/v1/search", params={"q": "   "}).json()
        assert empty_res == {
            "bots": [],
            "channels": [],
            "messages": [],
            "pages": [],
            "routines": [],
            "skills": [],
        }

        bot = client.post("/api/v1/bots", json={"name": f"Bot {token}"}).json()
        client.post(
            "/api/v1/channels",
            json={"name": f"Channel {token}", "bot_ids": ["bot_chief", bot["id"]]},
        )
        client.post(
            f"/api/v1/threads/{bot['thread_id']}/messages",
            json={"content": f"Message {token}"},
        )
        v1_page = client.post(
            "/api/v1/pages",
            json={"bot_id": bot["id"], "title": f"Page {token}", "content_md": "v1"},
        ).json()
        v2_page = client.post(
            "/api/v1/pages",
            json={"bot_id": bot["id"], "title": f"Page {token}", "content_md": "v2"},
        ).json()
        client.post(
            f"/api/v1/bots/{bot['id']}/routines",
            json={"name": f"Routine {token}", "instruction": "Check", "schedule_type": "manual"},
        )
        client.post(
            "/api/v1/skills",
            json={"bot_id": bot["id"], "name": f"Skill {token}", "content_md": "Skill body"},
        )

        res = client.get("/api/v1/search", params={"q": token})
        assert res.status_code == 200
        body = res.json()
        assert len(body["bots"]) == 1
        assert len(body["channels"]) == 1
        assert len(body["messages"]) >= 1
        assert [p["id"] for p in body["pages"]] == [v2_page["id"]]
        assert v1_page["id"] not in [p["id"] for p in body["pages"]]
        assert len(body["routines"]) == 1
        assert len(body["skills"]) == 1


# ---------------------------------------------------------------------------
# 5. Tier 2 Boundaries (before_id, LIKE escaping, unread_count)
# ---------------------------------------------------------------------------


def test_thread_messages_before_id_pagination_and_nonexistent_cursor(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        posted_ids: list[str] = []
        for idx in range(5):
            r = client.post(
                "/api/v1/threads/thr_bot_chief/messages",
                json={"content": f"Paginated msg {idx}"},
            )
            assert r.status_code == 202
            posted_ids.append(str(r.json()["user_message"]["id"]))

        page1_resp = client.get(
            "/api/v1/threads/thr_bot_chief/messages", params={"limit": 3}
        )
        assert page1_resp.status_code == 200
        page1 = page1_resp.json()
        assert len(page1["messages"]) == 3
        assert page1["has_more"] is True

        cursor_id = str(page1["messages"][0]["id"])
        page2_resp = client.get(
            "/api/v1/threads/thr_bot_chief/messages",
            params={"limit": 3, "before_id": cursor_id},
        )
        assert page2_resp.status_code == 200
        page2 = page2_resp.json()
        assert len(page2["messages"]) >= 2
        assert {m["id"] for m in page1["messages"]}.isdisjoint(
            {m["id"] for m in page2["messages"]}
        )

        # Tier 2 boundary: nonexistent before_id must NEVER silently return newest page
        bad_cursor = client.get(
            "/api/v1/threads/thr_bot_chief/messages",
            params={"limit": 50, "before_id": "msg_does_not_exist"},
        )
        assert bad_cursor.status_code in {200, 404}
        if bad_cursor.status_code == 200:
            assert bad_cursor.json()["messages"] == []
            assert bad_cursor.json()["has_more"] is False

        assert (
            client.get("/api/v1/threads/thr_bot_chief/messages", params={"limit": 0}).status_code
            == 422
        )
        assert (
            client.get("/api/v1/threads/thr_bot_chief/messages", params={"limit": 201}).status_code
            == 422
        )


def test_search_and_library_like_wildcards_percent_and_underscore_escaped(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        client.post("/api/v1/bots", json={"name": "Plain Alpha Bot"})
        client.post("/api/v1/bots", json={"name": "100% Efficiency Bot"})
        client.post("/api/v1/bots", json={"name": "pump_v2_monitor"})

        client.post(
            "/api/v1/pages",
            json={"bot_id": "bot_chief", "title": "Normal Page", "content_md": "No symbols"},
        )
        pct_page = client.post(
            "/api/v1/pages",
            json={"bot_id": "bot_chief", "title": "99% Uptime SLA", "content_md": "Target 99%"},
        ).json()
        und_page = client.post(
            "/api/v1/pages",
            json={"bot_id": "bot_chief", "title": "v2_draft_spec", "content_md": "snake_case"},
        ).json()

        search_pct = client.get("/api/v1/search", params={"q": "%"}).json()
        assert [b["name"] for b in search_pct["bots"]] == ["100% Efficiency Bot"]
        assert [p["id"] for p in search_pct["pages"]] == [pct_page["id"]]

        search_und = client.get("/api/v1/search", params={"q": "_"}).json()
        assert [b["name"] for b in search_und["bots"]] == ["pump_v2_monitor"]
        assert [p["id"] for p in search_und["pages"]] == [und_page["id"]]

        lib_pct = client.get("/api/v1/bots/bot_chief/library", params={"q": "%"}).json()
        assert [item["id"] for item in lib_pct["items"]] == [pct_page["id"]]

        lib_und = client.get("/api/v1/bots/bot_chief/library", params={"q": "_"}).json()
        assert [item["id"] for item in lib_und["items"]] == [und_page["id"]]


async def test_unread_count_increments_on_completion_and_clears_via_patch(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_CAPTURING_MOCK_AGY_SCRIPT, name="unread_cnt")
    async with srv.async_client() as client:
        roster0 = (await client.get("/api/v1/bots")).json()
        chief0 = next(b for b in roster0["bots"] if b["id"] == "bot_chief")
        assert chief0["unread_count"] == 0

        await trigger_and_wait_turn(client, "thr_bot_chief", "Increment bot unread count")
        roster1 = (await client.get("/api/v1/bots")).json()
        chief1 = next(b for b in roster1["bots"] if b["id"] == "bot_chief")
        assert chief1["unread_count"] >= 1

        clear_bot = await client.patch("/api/v1/bots/bot_chief", json={"unread_count": 0})
        assert clear_bot.status_code == 200
        assert clear_bot.json()["unread_count"] == 0

        chn = (
            await client.post(
                "/api/v1/channels",
                json={"name": "Unread Channel", "bot_ids": ["bot_chief", "bot_ops"]},
            )
        ).json()
        assert chn["unread_count"] == 0

        await trigger_and_wait_turn(client, chn["thread_id"], "Increment channel unread")
        roster2 = (await client.get("/api/v1/bots")).json()
        chn_after = next(c for c in roster2["channels"] if c["id"] == chn["id"])
        assert chn_after["unread_count"] >= 1

        clear_chn = await client.patch(
            f"/api/v1/channels/{chn['id']}", json={"unread_count": 0}
        )
        assert clear_chn.status_code == 200
        assert clear_chn.json()["unread_count"] == 0
