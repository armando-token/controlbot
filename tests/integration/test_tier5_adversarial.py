"""Tier-5 adversarial integration tests (Findings 1, 2, 4, 5)."""

from __future__ import annotations

import asyncio
import socket
import struct
import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from src.contracts.budgets import BudgetConfig
from src.contracts.common import utc_now
from src.contracts.enums import TaskStatus
from src.contracts.models import Result, Run, TaskSpec
from src.web.app import create_app
from src.web.protocols import TaskSnapshot
from src.web.v1.runner import AgentTurnRunner
from src.web.v1.store import StoreValidationError, WorkspaceStore

pytestmark = [pytest.mark.n2, pytest.mark.tier5]


@dataclass
class _RunEntry:
    spec: TaskSpec
    run: Run
    result: Result | None = None
    resume_event: asyncio.Event = field(default_factory=asyncio.Event)
    settled_event: asyncio.Event = field(default_factory=asyncio.Event)
    bg_task: asyncio.Task[None] | None = None


class _SlowInterruptibleCoordinator:
    """In-memory CoordinatorProtocol stub that blocks resume until cancelled or settled."""

    def __init__(self, *, resume_delay_s: float = 1.5) -> None:
        self._resume_delay_s = resume_delay_s
        self._runs: dict[str, _RunEntry] = {}
        self.cancel_calls: list[tuple[str, str]] = []
        self.resumed_calls: list[tuple[str, dict[str, Any]]] = []

    def submit_task(self, task_spec: TaskSpec, run_id: str | None = None) -> Run:
        del run_id
        rid = "run_tier5_slow_1"
        now = utc_now()
        run = Run(
            run_id=rid,
            task_id=task_spec.task_id,
            status=TaskStatus.WAITING_FOR_INPUT,
            required_action="Operator confirmation required",
            transition_reason="waiting_for_input",
            deadline_at=now + timedelta(minutes=5),
            created_at=now,
            updated_at=now,
        )
        self._runs[rid] = _RunEntry(spec=task_spec, run=run)
        return run

    def get_task_snapshot(self, run_id: str) -> TaskSnapshot | None:
        entry = self._runs.get(run_id)
        if entry is None:
            return None
        return TaskSnapshot(
            run=entry.run,
            task=entry.spec,
            budget_config=BudgetConfig(),
            result=entry.result,
        )

    def list_task_snapshots(self) -> list[TaskSnapshot]:
        return [
            snap
            for rid in self._runs
            if (snap := self.get_task_snapshot(rid)) is not None
        ]

    async def resume_task(self, run_id: str, human_input: dict[str, Any]) -> Run:
        entry = self._runs[run_id]
        self.resumed_calls.append((run_id, dict(human_input)))
        now = utc_now()
        entry.run = entry.run.model_copy(
            update={
                "status": TaskStatus.RUNNING,
                "required_action": None,
                "transition_reason": "resumed_by_operator",
                "updated_at": now,
            }
        )
        entry.resume_event.set()

        async def _complete_later() -> None:
            try:
                await asyncio.sleep(self._resume_delay_s)
                if entry.run.status == TaskStatus.RUNNING:
                    fin = utc_now()
                    entry.result = Result(
                        task_id=entry.spec.task_id,
                        run_id=run_id,
                        status=TaskStatus.SUCCEEDED,
                        answer="Resumed runtime answer",
                    )
                    entry.run = entry.run.model_copy(
                        update={
                            "status": TaskStatus.SUCCEEDED,
                            "transition_reason": "completed",
                            "updated_at": fin,
                        }
                    )
            finally:
                entry.settled_event.set()

        entry.bg_task = asyncio.create_task(_complete_later())
        return entry.run

    async def wait_for_run(self, run_id: str, *, timeout: float | None = None) -> Result | None:
        entry = self._runs[run_id]
        if entry.run.status == TaskStatus.WAITING_FOR_INPUT:
            return entry.result
        if timeout is not None:
            await asyncio.wait_for(entry.settled_event.wait(), timeout=timeout)
        else:
            await entry.settled_event.wait()
        return entry.result

    def cancel_task(self, run_id: str, reason: str = "cancelled_by_user") -> Run:
        entry = self._runs[run_id]
        self.cancel_calls.append((run_id, reason))
        now = utc_now()
        entry.run = entry.run.model_copy(
            update={
                "status": TaskStatus.CANCELLED,
                "transition_reason": reason,
                "updated_at": now,
            }
        )
        if entry.bg_task is not None and not entry.bg_task.done():
            entry.bg_task.cancel()
        entry.settled_event.set()
        return entry.run


async def test_finding1_runtime_hitl_resolve_nonblocking_and_interruptible(
    tmp_path: Path,
) -> None:
    coord = _SlowInterruptibleCoordinator(resume_delay_s=1.5)
    app = create_app(db_path=tmp_path / "t5_hitl.sqlite3", coordinator=coord)

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            patch_resp = await client.patch(
                "/api/v1/bots/bot_chief",
                json={"engine_id": "controlbot_runtime"},
            )
            assert patch_resp.status_code == 200

            post_resp = await client.post(
                "/api/v1/threads/thr_bot_chief/messages",
                json={"content": "Inspect SCADA status"},
            )
            assert post_resp.status_code == 202

            approvals: list[dict[str, Any]] = []
            for _ in range(60):
                msgs_resp = await client.get("/api/v1/threads/thr_bot_chief/messages")
                assert msgs_resp.status_code == 200
                approvals = msgs_resp.json()["approvals"]
                if approvals:
                    break
                await asyncio.sleep(0.02)
            assert len(approvals) == 1
            apr_id = str(approvals[0]["id"])
            run_id = str(approvals[0]["arguments"]["run_id"])

            loop = asyncio.get_running_loop()
            t0 = loop.time()
            res_resp = await client.post(
                f"/api/v1/approvals/{apr_id}/resolve",
                json={"decision": "allow_once"},
            )
            elapsed = loop.time() - t0
            assert res_resp.status_code == 200
            # Must return promptly rather than blocking for the 1.5s runtime run
            assert elapsed < 0.5, f"resolve_approval blocked for {elapsed:.3f}s"

            # Wait briefly until resume_task has been invoked, then interrupt
            await asyncio.wait_for(coord._runs[run_id].resume_event.wait(), timeout=2.0)
            int_resp = await client.post("/api/v1/threads/thr_bot_chief/interrupt")
            assert int_resp.status_code == 200
            assert int_resp.json()["interrupted"] is True
            assert (run_id, "interrupted_by_operator") in coord.cancel_calls
            snap = coord.get_task_snapshot(run_id)
            assert snap is not None and snap.run.status == TaskStatus.CANCELLED

            # Even after the original 1.5s window passes, no "done" answer overwrites it
            await asyncio.sleep(0.25)
            msgs_after = (
                await client.get("/api/v1/threads/thr_bot_chief/messages")
            ).json()["messages"]
            assert not any("Resumed runtime answer" in str(m["content"]) for m in msgs_after)
            resumed_msgs = [
                m
                for m in msgs_after
                if m["sender_type"] == "bot" and m["status"] == "interrupted"
            ]
            assert len(resumed_msgs) >= 1

            bots = (await client.get("/api/v1/bots")).json()["bots"]
            chief = next(b for b in bots if b["id"] == "bot_chief")
            assert chief["status_state"] == "idle"


@pytest.mark.parametrize(
    "payload",
    [
        {"name": None},
        {"role_prompt": None},
        {"about": None},
        {"avatar_shape": None},
        {"avatar_color": None},
        {"avatar_eyes_large": None},
        {"engine_id": None},
        {"model_id": None},
        {"thinking_level": None},
        {"pinned": None},
        {"hidden": None},
        {"is_primary": None},
        {"is_team_bot": None},
        {"unread_count": None},
        {"needs_attention": None},
        {"status_state": None},
        {"status_subtext": None},
        {"computer_active": None},
        {"timezone": None},
        {"drafts_enabled": None},
    ],
)
async def test_finding2_patch_bot_explicit_null_non_nullable_returns_422(
    tmp_path: Path,
    payload: dict[str, Any],
) -> None:
    app = create_app(db_path=tmp_path / "t5_patch_bot.sqlite3")
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            resp = await client.patch("/api/v1/bots/bot_chief", json=payload)
            assert resp.status_code == 422
            # Nullable bot fields must still succeed
            ok_resp = await client.patch(
                "/api/v1/bots/bot_chief",
                json={"project_name": None, "section_id": None, "conversation_id": None},
            )
            assert ok_resp.status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        {"name": None},
        {"instruction": None},
        {"schedule_type": None},
        {"timezone": None},
        {"enabled": None},
        {"visibility": None},
        {"regenerate_webhook_key": None},
    ],
)
async def test_finding2_patch_routine_explicit_null_non_nullable_returns_422(
    tmp_path: Path,
    payload: dict[str, Any],
) -> None:
    app = create_app(db_path=tmp_path / "t5_patch_rtn.sqlite3")
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            created = (
                await client.post(
                    "/api/v1/bots/bot_chief/routines",
                    json={
                        "name": "Shift Check",
                        "instruction": "Summarize shift status",
                        "schedule_type": "cron",
                        "cron_expr": "0 9 * * *",
                    },
                )
            ).json()
            rtn_id = str(created["id"])

            resp = await client.patch(f"/api/v1/routines/{rtn_id}", json=payload)
            assert resp.status_code == 422

            # Nullable cron_expr must still allow null
            ok_resp = await client.patch(
                f"/api/v1/routines/{rtn_id}",
                json={"cron_expr": None},
            )
            assert ok_resp.status_code == 200
            assert ok_resp.json()["cron_expr"] is None


async def test_finding2_store_guards_and_other_patch_endpoints_never_500(
    tmp_path: Path,
) -> None:
    store = WorkspaceStore(tmp_path / "t5_store.sqlite3")
    try:
        with pytest.raises(StoreValidationError):
            store.update_bot("bot_chief", {"name": None})
        rtn = store.create_routine(
            "bot_chief",
            {
                "name": "Store Guard Routine",
                "instruction": "Check telemetry",
                "schedule_type": "manual",
            },
        )
        with pytest.raises(StoreValidationError):
            store.update_routine(str(rtn["id"]), {"visibility": None})
    finally:
        store.close()

    app = create_app(db_path=tmp_path / "t5_other_patches.sqlite3")
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            sec = (
                await client.post("/api/v1/sections", json={"name": "Ops", "sort_order": 1})
            ).json()
            chn = (
                await client.post(
                    "/api/v1/channels",
                    json={"name": "Ops Room", "bot_ids": ["bot_chief", "bot_ops"]},
                )
            ).json()
            page = (
                await client.post(
                    "/api/v1/pages",
                    json={"bot_id": "bot_chief", "title": "Spec", "content_md": "Body"},
                )
            ).json()
            mem = (
                await client.post(
                    "/api/v1/memory",
                    json={
                        "scope": "user",
                        "scope_id": "operator",
                        "kind": "preference",
                        "title": "Units",
                        "content": "Prefer metric units",
                    },
                )
            ).json()

            checks = [
                await client.patch(
                    f"/api/v1/sections/{sec['id']}",
                    json={"name": None, "sort_order": None},
                ),
                await client.patch(
                    f"/api/v1/channels/{chn['id']}",
                    json={"name": None, "section_id": None, "pinned": None},
                ),
                await client.patch(
                    f"/api/v1/pages/{page['id']}",
                    json={"title": None, "content_md": None, "pinned": None},
                ),
                await client.patch(
                    "/api/v1/apps/app_webhooks",
                    json={"enabled": None, "status": None, "account_label": None},
                ),
                await client.patch(
                    "/api/v1/settings",
                    json={"theme": None, "default_project_name": None, "display_name": None},
                ),
                await client.patch(
                    f"/api/v1/memory/{mem['id']}",
                    json={
                        "revision": mem["revision"],
                        "title": None,
                        "content": None,
                        "valid_until": None,
                    },
                ),
            ]
            for resp in checks:
                assert resp.status_code in {200, 400, 422}, resp.text


async def test_finding4_computer_files_upload_onto_regular_file_returns_400(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects_root = tmp_path / "projects"
    proj_dir = projects_root / "Grokbotclon"
    proj_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CONTROLBOT_PROJECTS_ROOT", str(projects_root))

    app = create_app(db_path=tmp_path / "t5_files.sqlite3")
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            write_resp = await client.post(
                "/api/v1/computers/default/files/write",
                json={
                    "path": "regular_file.txt",
                    "project": "Grokbotclon",
                    "content": "hello",
                },
            )
            assert write_resp.status_code == 200

            upload_resp = await client.post(
                "/api/v1/computers/default/files/upload",
                params={
                    "path": "regular_file.txt",
                    "name": "child.txt",
                    "project": "Grokbotclon",
                },
                content=b"payload",
            )
            assert upload_resp.status_code == 400

            nested_resp = await client.post(
                "/api/v1/computers/default/files/upload",
                params={
                    "path": "regular_file.txt/nested",
                    "name": "child.txt",
                    "project": "Grokbotclon",
                },
                content=b"payload",
            )
            assert nested_resp.status_code == 400

            mkdir_resp = await client.post(
                "/api/v1/computers/default/files/mkdir",
                json={"path": "existing_dir", "project": "Grokbotclon"},
            )
            assert mkdir_resp.status_code == 201
            dir_target_resp = await client.post(
                "/api/v1/computers/default/files/upload",
                params={"path": "", "name": "existing_dir", "project": "Grokbotclon"},
                content=b"payload",
            )
            assert dir_target_resp.status_code == 400


async def test_finding5_delete_artifact_prunes_messages_artifacts(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "t5_del_art.sqlite3")
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            store: WorkspaceStore = app.state.workspace_store
            msg = store.create_message(
                thread_id="thr_bot_chief",
                sender_type="bot",
                sender_bot_id="bot_chief",
                sender_name="Chief of Staff",
                content="# Summary\n\nDetailed shift summary.",
                status="done",
            )
            page1_resp = await client.post(
                f"/api/v1/messages/{msg['id']}/to-page",
                json={"title": "Summary One"},
            )
            assert page1_resp.status_code == 201
            page1_id = str(page1_resp.json()["page"]["id"])

            page2_resp = await client.post(
                f"/api/v1/messages/{msg['id']}/to-page",
                json={"title": "Summary Two"},
            )
            assert page2_resp.status_code == 201
            page2_id = str(page2_resp.json()["page"]["id"])

            del_resp = await client.delete(f"/api/v1/artifacts/{page1_id}")
            assert del_resp.status_code == 200

            get_deleted = await client.get(f"/api/v1/pages/{page1_id}")
            assert get_deleted.status_code == 404

            msgs_resp = await client.get("/api/v1/threads/thr_bot_chief/messages")
            assert msgs_resp.status_code == 200
            target_msg = next(
                m for m in msgs_resp.json()["messages"] if m["id"] == msg["id"]
            )
            remaining_ids = [a["id"] for a in target_msg["artifacts"]]
            assert page1_id not in remaining_ids
            assert page2_id in remaining_ids


# ---------------------------------------------------------------------------
# Iteration 2 Tier-5 Adversarial Regressions (Defects 1–4)
# ---------------------------------------------------------------------------


async def test_r2_defect1_auto_review_duplicate_id_returns_422_never_500(
    tmp_path: Path,
) -> None:
    store = WorkspaceStore(tmp_path / "t5_r2_dup_store.sqlite3")
    try:
        seeded = store.replace_auto_review_rules(
            [{"id": "arr_keep", "bucket": "allow_auto", "rule_text": "Keep existing rule"}]
        )
        assert len(seeded) == 1
        with pytest.raises(StoreValidationError, match="Duplicate auto-review rule id"):
            store.replace_auto_review_rules(
                [
                    {"id": "arr_dup", "bucket": "allow_auto", "rule_text": "Rule 1"},
                    {"id": "arr_dup", "bucket": "ask_first", "rule_text": "Rule 2"},
                ]
            )
        # Existing rules must remain intact after validation failure
        assert [r["id"] for r in store.list_auto_review_rules()] == ["arr_keep"]
    finally:
        store.close()

    app = create_app(db_path=tmp_path / "t5_r2_dup_api.sqlite3")
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            dup_resp = await client.put(
                "/api/v1/settings/auto-review",
                json={
                    "rules": [
                        {"id": "arr_dup", "bucket": "allow_auto", "rule_text": "Rule 1"},
                        {"id": "arr_dup", "bucket": "ask_first", "rule_text": "Rule 2"},
                    ]
                },
            )
            assert dup_resp.status_code == 422

            # Empty/whitespace IDs should normalize to distinct generated IDs
            empty_id_resp = await client.put(
                "/api/v1/settings/auto-review",
                json={
                    "rules": [
                        {"id": "", "bucket": "allow_auto", "rule_text": "Allow read ops"},
                        {"id": "   ", "bucket": "ask_first", "rule_text": "Ask before deploy"},
                    ]
                },
            )
            assert empty_id_resp.status_code == 200
            rules = empty_id_resp.json()["rules"]
            assert len(rules) == 2
            assert len({r["id"] for r in rules}) == 2


async def test_r2_defect2_delete_bot_scrubs_channels_and_rejects_empty_channel(
    tmp_path: Path,
) -> None:
    app = create_app(db_path=tmp_path / "t5_r2_del_bot.sqlite3")
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            b1 = (
                await client.post(
                    "/api/v1/bots",
                    json={"name": "Alpha Bot", "engine_id": "controlbot_runtime"},
                )
            ).json()
            b2 = (
                await client.post(
                    "/api/v1/bots",
                    json={"name": "Beta Bot", "engine_id": "controlbot_runtime"},
                )
            ).json()
            b1_id = str(b1["id"])
            b2_id = str(b2["id"])

            chn = (
                await client.post(
                    "/api/v1/channels",
                    json={"name": "TwoBotCh", "bot_ids": [b1_id, b2_id]},
                )
            ).json()
            chn_id = str(chn["id"])
            chn_thr = str(chn["thread_id"])

            del1 = await client.delete(f"/api/v1/bots/{b1_id}")
            assert del1.status_code == 200

            roster1 = (await client.get("/api/v1/bots")).json()
            chn_after1 = next(c for c in roster1["channels"] if c["id"] == chn_id)
            assert chn_after1["bot_ids"] == [b2_id]

            # Page creation on channel must succeed on surviving bot b2
            page_ok = await client.post(
                "/api/v1/pages",
                json={"channel_id": chn_id, "title": "Surviving Page", "content_md": "ok"},
            )
            assert page_ok.status_code == 201
            assert page_ok.json()["bot_id"] == b2_id

            # Delete second bot: channel now has 0 bots
            del2 = await client.delete(f"/api/v1/bots/{b2_id}")
            assert del2.status_code == 200

            roster2 = (await client.get("/api/v1/bots")).json()
            chn_after2 = next(c for c in roster2["channels"] if c["id"] == chn_id)
            assert chn_after2["bot_ids"] == []

            # Page creation and posting to a 0-bot channel must fail cleanly with 409
            page_empty = await client.post(
                "/api/v1/pages",
                json={"channel_id": chn_id, "title": "Dead Channel Page", "content_md": "no"},
            )
            assert page_empty.status_code == 409

            msg_empty = await client.post(
                f"/api/v1/threads/{chn_thr}/messages",
                json={"content": "hello dead channel"},
            )
            assert msg_empty.status_code == 409


async def test_r2_defect3_zero_delay_interrupt_after_routine_approval_resolve(
    tmp_path: Path,
) -> None:
    coord = _SlowInterruptibleCoordinator(resume_delay_s=1.5)
    app = create_app(db_path=tmp_path / "t5_r2_rtn_race.sqlite3", coordinator=coord)

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            patch_resp = await client.patch(
                "/api/v1/bots/bot_chief",
                json={"engine_id": "controlbot_runtime"},
            )
            assert patch_resp.status_code == 200

            rtn_resp = await client.post(
                "/api/v1/bots/bot_chief/routines",
                json={
                    "name": "SCADA Runtime Routine",
                    "instruction": "Inspect SCADA tank pressure",
                    "schedule_type": "manual",
                    "enabled": True,
                },
            )
            assert rtn_resp.status_code == 201
            rtn_id = str(rtn_resp.json()["id"])

            run_resp = await client.post(f"/api/v1/routines/{rtn_id}/test")
            assert run_resp.status_code == 202
            rtn_run_id = str(run_resp.json()["id"])

            approvals: list[dict[str, Any]] = []
            for _ in range(60):
                msgs_resp = await client.get("/api/v1/threads/thr_bot_chief/messages")
                assert msgs_resp.status_code == 200
                approvals = [
                    a for a in msgs_resp.json()["approvals"] if a["status"] == "pending"
                ]
                runs_resp = await client.get(f"/api/v1/routines/{rtn_id}/runs")
                runs_list = runs_resp.json()["runs"]
                if approvals and runs_list and runs_list[0]["status"] == "waiting_approval":
                    break
                await asyncio.sleep(0.02)
            assert len(approvals) == 1
            apr_id = str(approvals[0]["id"])
            coord_run_id = str(approvals[0]["arguments"]["run_id"])

            # Resolve approval and immediately interrupt with 0 delay (before task starts!)
            res_resp = await client.post(
                f"/api/v1/approvals/{apr_id}/resolve",
                json={"decision": "allow_once"},
            )
            assert res_resp.status_code == 200

            int_resp = await client.post("/api/v1/threads/thr_bot_chief/interrupt")
            assert int_resp.status_code == 200
            assert int_resp.json()["interrupted"] is True
            assert (coord_run_id, "interrupted_by_operator") in coord.cancel_calls

            runs_after = (await client.get(f"/api/v1/routines/{rtn_id}/runs")).json()["runs"]
            target_run = next(r for r in runs_after if r["id"] == rtn_run_id)
            assert target_run["status"] == "failed"

            await asyncio.sleep(0.15)
            runs_settled = (await client.get(f"/api/v1/routines/{rtn_id}/runs")).json()["runs"]
            target_settled = next(r for r in runs_settled if r["id"] == rtn_run_id)
            assert target_settled["status"] == "failed"


def test_r2_defect4_websockets_survive_malformed_json_and_binary_frames(
    tmp_path: Path,
) -> None:
    from fastapi.testclient import TestClient

    app = create_app(db_path=tmp_path / "t5_r2_ws.sqlite3")
    with TestClient(app, raise_server_exceptions=True) as client:
        tok_resp = client.post("/api/v1/computers/vm_local/vnc-token", json={})
        assert tok_resp.status_code == 200
        cap_tok = str(tok_resp.json()["cap_token"])

        # 1. /ws/v1/computers/{vm_id}/control
        with client.websocket_connect(
            f"/ws/v1/computers/vm_local/control?cap_token={cap_tok}"
        ) as ws_ctrl:
            init_msg = ws_ctrl.receive_json()
            assert init_msg["op"] == "computer.state"
            ws_ctrl.send_text("{bad json")
            ws_ctrl.send_bytes(b"\x00\x01")
            ws_ctrl.send_json({"op": "ping"})
            pong = ws_ctrl.receive_json()
            assert pong["op"] == "pong"

        # 2. /ws/v1/computers/{vm_id}/screencast
        with client.websocket_connect(
            f"/ws/v1/computers/vm_local/screencast?cap_token={cap_tok}"
        ) as ws_sc:
            init_st = ws_sc.receive_json()
            assert init_st["type"] == "status"
            ws_sc.send_text("{bad json")
            ws_sc.send_bytes(b"\x00\x01")
            ws_sc.send_json({"type": "ping"})
            pong_sc = ws_sc.receive_json()
            assert pong_sc["type"] == "pong"
            ws_sc.send_json({"type": "status"})
            st_sc = ws_sc.receive_json()
            assert st_sc["type"] == "status"

        # 3. /ws/browser
        with client.websocket_connect("/ws/browser") as ws_br:
            init_br = ws_br.receive_json()
            assert init_br["type"] == "status"
            ws_br.send_text("{bad json")
            ws_br.send_bytes(b"\x00\x01")
            ws_br.send_json({"type": "status"})
            st_br = ws_br.receive_json()
            assert st_br["type"] == "status"

        # 4. /ws/terminal
        with client.websocket_connect("/ws/terminal") as ws_term:
            ready = ws_term.receive_json()
            assert ready["type"] == "ready"
            ws_term.send_text("{bad json")
            ws_term.send_bytes(b"\x00\x01")
            ws_term.send_json({"type": "resize", "cols": "bad_col", "rows": "bad_row"})
            ws_term.send_json({"type": "input", "data": "echo WS_TERMINAL_OK\n"})
            collected = ""
            for _ in range(30):
                ev = ws_term.receive_json()
                if ev.get("type") == "output":
                    collected += str(ev.get("data") or "")
                    if "WS_TERMINAL_OK" in collected:
                        break
            assert "WS_TERMINAL_OK" in collected


# ---------------------------------------------------------------------------
# Iteration 3 Tier-5 Adversarial Regressions (Gaps 1–3)
# ---------------------------------------------------------------------------


def test_r3_gap1_vnc_websocket_survives_text_frames_pre_and_post_handshake(
    tmp_path: Path,
) -> None:
    from fastapi.testclient import TestClient

    received_payloads: list[bytes] = []
    srv_ready = threading.Event()
    stop_flag = threading.Event()

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(4)
    port = int(srv_sock.getsockname()[1])
    srv_sock.settimeout(0.2)

    def _rfb_stub() -> None:
        srv_ready.set()
        while not stop_flag.is_set():
            try:
                conn, _ = srv_sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2.0)
                conn.sendall(b"RFB 003.008\n")
                _ = conn.recv(12)
                # Offer SecurityType None (1)
                conn.sendall(b"\x01\x01")
                _ = conn.recv(1)
                # SecurityResult OK
                conn.sendall(b"\x00\x00\x00\x00")
                # ClientInit (1 byte)
                client_init = conn.recv(1)
                received_payloads.append(client_init)
                # ServerInit (minimal 24 bytes + 4-byte name "Stub")
                srv_init = struct.pack(
                    "!HHBBBBHHHBBB3xI",
                    640,
                    480,
                    32,
                    24,
                    0,
                    1,
                    255,
                    255,
                    255,
                    16,
                    8,
                    0,
                    4,
                ) + b"Stub"
                conn.sendall(srv_init)
                # Read post-handshake RFB FramebufferUpdateRequest
                try:
                    data = conn.recv(64)
                    if data:
                        received_payloads.append(data)
                except OSError:
                    pass

    thread = threading.Thread(target=_rfb_stub, daemon=True)
    thread.start()
    srv_ready.wait(timeout=2.0)

    app = create_app(db_path=tmp_path / "t5_r3_vnc_text.sqlite3")
    try:
        with TestClient(app, raise_server_exceptions=True) as client:
            gw = app.state.computer_gateway
            gw.vnc_host = "127.0.0.1"
            gw.vnc_port = port

            tok_resp = client.post("/api/v1/computers/vm_local/vnc-token", json={})
            assert tok_resp.status_code == 200
            cap_tok = str(tok_resp.json()["cap_token"])

            # 1. Pre-handshake text frame must be ignored cleanly, then handshake proceeds
            with client.websocket_connect(
                f"/ws/v1/computers/vm_local/vnc?cap_token={cap_tok}"
            ) as ws:
                ver = ws.receive_bytes()
                assert ver == b"RFB 003.008\n"
                ws.send_text("hello text before handshake")
                ws.send_bytes(b"RFB 003.008\n")
                sec_types = ws.receive_bytes()
                assert sec_types == b"\x01\x01"
                ws.send_text("text before security type")
                ws.send_bytes(b"\x01")
                sec_res = ws.receive_bytes()
                assert sec_res == b"\x00\x00\x00\x00"
                # Text frame before ClientInit
                ws.send_text("text before client init")
                ws.send_bytes(b"\x01")
                srv_init_bytes = ws.receive_bytes()
                assert srv_init_bytes.endswith(b"Stub")
                # 2. Post-handshake text frame must not crash _ws_to_vnc
                ws.send_text("post-handshake-text")
                fb_req = struct.pack("!BBHHHH", 3, 1, 0, 0, 640, 480)
                ws.send_bytes(fb_req)

        assert b"\x01" in received_payloads
        assert any(fb_req in chunk for chunk in received_payloads)
    finally:
        stop_flag.set()
        srv_sock.close()
        thread.join(timeout=2.0)


def test_r3_gap2_non_finite_float_json_returns_422_and_ws_survives(
    tmp_path: Path,
) -> None:
    from fastapi.testclient import TestClient

    app = create_app(db_path=tmp_path / "t5_r3_inf.sqlite3")
    with TestClient(app, raise_server_exceptions=False) as err_client:
        for bad_raw in (
            '{"ttl_seconds": 1e400}',
            '{"ttl_seconds": Infinity}',
            '{"ttl_seconds": NaN}',
            '{"ttl_seconds": true}',
        ):
            r1 = err_client.post(
                "/api/v1/computers/vm_local/vnc-token",
                content=bad_raw,
                headers={"Content-Type": "application/json"},
            )
            assert r1.status_code == 422, f"{bad_raw}: {r1.status_code} {r1.text}"

            r2 = err_client.post(
                "/api/v1/computers/vm_local/takeover",
                content=bad_raw,
                headers={"Content-Type": "application/json"},
            )
            assert r2.status_code == 422, f"{bad_raw}: {r2.status_code} {r2.text}"

        # /actions with non-finite coordinates when browser is stopped must return 422, not 500
        r_act = err_client.post(
            "/api/v1/computers/vm_local/actions",
            content='{"type": "click", "x": 1e400, "y": 100}',
            headers={"Content-Type": "application/json"},
        )
        assert r_act.status_code == 422

    with TestClient(app, raise_server_exceptions=True) as client:
        tok_resp = client.post("/api/v1/computers/vm_local/vnc-token", json={})
        cap_tok = str(tok_resp.json()["cap_token"])

        with client.websocket_connect(
            f"/ws/v1/computers/vm_local/control?cap_token={cap_tok}"
        ) as ws_ctrl:
            assert ws_ctrl.receive_json()["op"] == "computer.state"
            ws_ctrl.send_text('{"op": "viewport.resize", "width": 1e400, "height": 800}')
            ack1 = ws_ctrl.receive_json()
            assert ack1["op"] == "viewport.resize.ack"
            assert (ack1["width"], ack1["height"]) == (1280, 800)

            ws_ctrl.send_text('{"op": "viewport.resize", "width": true, "height": NaN}')
            ack2 = ws_ctrl.receive_json()
            assert ack2["op"] == "viewport.resize.ack"

            ws_ctrl.send_json({"op": "viewport.resize", "width": 1440, "height": 900})
            ack3 = ws_ctrl.receive_json()
            assert (ack3["width"], ack3["height"]) == (1440, 900)

        with client.websocket_connect(
            f"/ws/v1/computers/vm_local/pty/s1?cap_token={cap_tok}"
        ) as ws_pty:
            ws_pty.send_text('{"type": "resize", "cols": 1e400, "rows": 24}')
            ws_pty.send_text('{"type": "resize", "cols": true, "rows": NaN}')
            ws_pty.send_json({"type": "input", "data": "echo PTY_INF_OK\n"})
            collected = ""
            for _ in range(30):
                chunk = ws_pty.receive_text()
                collected += chunk
                if "PTY_INF_OK" in collected:
                    break
            assert "PTY_INF_OK" in collected

        with client.websocket_connect("/ws/terminal") as ws_term:
            assert ws_term.receive_json()["type"] == "ready"
            ws_term.send_text('{"type": "resize", "cols": 1e400, "rows": 24}')
            ws_term.send_text('{"type": "resize", "cols": NaN, "rows": true}')
            ws_term.send_json({"type": "input", "data": "echo TERM_INF_OK\n"})
            collected_term = ""
            for _ in range(30):
                ev = ws_term.receive_json()
                if ev.get("type") == "output":
                    collected_term += str(ev.get("data") or "")
                    if "TERM_INF_OK" in collected_term:
                        break
            assert "TERM_INF_OK" in collected_term


class _SlowRunningCoordinator:
    """In-memory coordinator whose runs stay RUNNING until cancelled."""

    def __init__(self) -> None:
        self._runs: dict[str, _RunEntry] = {}
        self.cancelled: list[tuple[str, str]] = []
        self._seq = 0

    def submit_task(self, task_spec: TaskSpec, run_id: str | None = None) -> Run:
        del run_id
        self._seq += 1
        rid = f"run_slow_rt_{self._seq}"
        now = utc_now()
        is_routine = task_spec.task_id.startswith("rtn-")
        run = Run(
            run_id=rid,
            task_id=task_spec.task_id,
            status=TaskStatus.RUNNING if is_routine else TaskStatus.SUCCEEDED,
            transition_reason="running" if is_routine else "completed",
            deadline_at=now + timedelta(minutes=5),
            created_at=now,
            updated_at=now,
        )
        result = (
            None
            if is_routine
            else Result(
                task_id=task_spec.task_id,
                run_id=rid,
                status=TaskStatus.SUCCEEDED,
                answer="Superseding turn completed",
            )
        )
        entry = _RunEntry(spec=task_spec, run=run, result=result)
        if not is_routine:
            entry.settled_event.set()
        self._runs[rid] = entry
        return run

    def get_task_snapshot(self, run_id: str) -> TaskSnapshot | None:
        entry = self._runs.get(run_id)
        if entry is None:
            return None
        return TaskSnapshot(
            run=entry.run,
            task=entry.spec,
            budget_config=BudgetConfig(),
            result=entry.result,
        )

    def list_task_snapshots(self) -> list[TaskSnapshot]:
        return [
            snap
            for rid in self._runs
            if (snap := self.get_task_snapshot(rid)) is not None
        ]

    async def resume_task(self, run_id: str, human_input: dict[str, Any]) -> Run:
        del human_input
        return self._runs[run_id].run

    async def wait_for_run(self, run_id: str, *, timeout: float | None = None) -> Result | None:
        entry = self._runs[run_id]
        if timeout is not None:
            await asyncio.wait_for(entry.settled_event.wait(), timeout=timeout)
        else:
            await entry.settled_event.wait()
        return entry.result

    def cancel_task(self, run_id: str, reason: str = "cancelled_by_user") -> Run:
        entry = self._runs[run_id]
        self.cancelled.append((run_id, reason))
        now = utc_now()
        entry.run = entry.run.model_copy(
            update={
                "status": TaskStatus.CANCELLED,
                "transition_reason": reason,
                "updated_at": now,
            }
        )
        entry.settled_event.set()
        return entry.run


async def test_r3_gap3_ask_first_runtime_and_agy_routines_interrupt_and_supersede(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.web.v1 import runner as runner_mod

    coord = _SlowRunningCoordinator()
    app = create_app(db_path=tmp_path / "t5_r3_gap3.sqlite3", coordinator=coord)

    async with app.router.lifespan_context(app):
        store: WorkspaceStore = app.state.workspace_store
        turn_runner: AgentTurnRunner = app.state.v1_runner

        store.replace_auto_review_rules(
            [{"id": "ask_dep", "bucket": "ask_first", "rule_text": "Ask before deploying release"}]
        )
        store.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})
        bot_rt = store.get_bot("bot_chief")
        assert bot_rt is not None
        rt_thread = str(bot_rt["thread_id"])

        rtn_rt = store.create_routine(
            "bot_chief",
            {
                "name": "AskFirst Runtime Routine",
                "instruction": "Deploy release to staging",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        rtn_rt_id = str(rtn_rt["id"])

        # Case A: ask_first runtime routine -> allow_once -> zero-delay interrupt()
        run_a = await turn_runner.execute_routine(rtn_rt_id, trigger="manual")
        for _ in range(50):
            cur = store.get_routine_run(str(run_a["id"]))
            apprs = [a for a in store.list_thread_approvals(rt_thread) if a["status"] == "pending"]
            if cur is not None and cur["status"] == "waiting_approval" and apprs:
                break
            await asyncio.sleep(0.02)
        apprs_a = [a for a in store.list_thread_approvals(rt_thread) if a["status"] == "pending"]
        assert len(apprs_a) == 1
        resolved_a = store.resolve_approval(str(apprs_a[0]["id"]), "allow_once")
        await turn_runner.on_approval_resolved(resolved_a, decision="allow_once")

        # Zero-delay interrupt
        assert await turn_runner.interrupt(rt_thread) is True
        settled_a = store.get_routine_run(str(run_a["id"]))
        assert settled_a is not None and settled_a["status"] == "failed"

        # Case B: ask_first runtime routine -> allow_once -> zero-delay superseding start_turn()
        run_b = await turn_runner.execute_routine(rtn_rt_id, trigger="manual")
        for _ in range(50):
            cur = store.get_routine_run(str(run_b["id"]))
            apprs = [a for a in store.list_thread_approvals(rt_thread) if a["status"] == "pending"]
            if cur is not None and cur["status"] == "waiting_approval" and apprs:
                break
            await asyncio.sleep(0.02)
        apprs_b = [a for a in store.list_thread_approvals(rt_thread) if a["status"] == "pending"]
        assert len(apprs_b) == 1
        resolved_b = store.resolve_approval(str(apprs_b[0]["id"]), "allow_once")
        await turn_runner.on_approval_resolved(resolved_b, decision="allow_once")

        user_msg = store.create_message(
            thread_id=rt_thread,
            sender_type="human",
            sender_name="Operator",
            content="Supersede routine immediately",
            status="done",
        )
        turn_runner.start_turn(thread_id=rt_thread, user_message=user_msg)
        settled_b = store.get_routine_run(str(run_b["id"]))
        assert settled_b is not None and settled_b["status"] == "failed"
        await turn_runner.wait_for_active_turn(rt_thread)
        settled_b_after = store.get_routine_run(str(run_b["id"]))
        assert settled_b_after is not None and settled_b_after["status"] == "failed"

        # Case C: ask_first agy routine -> allow_once -> zero-delay & active-streaming interrupt()
        agy_closed: list[bool] = []

        async def _slow_agy_stream(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
            prompt_str = str(kwargs.get("prompt") or "")
            if "[SCHEDULED ROUTINE:" not in prompt_str:
                yield {"type": "done", "response": "Superseding agy turn done"}
                return
            try:
                yield {"type": "delta", "text": "Deploying... "}
                await asyncio.sleep(5.0)
                yield {"type": "done", "response": "Deploying... done"}
            finally:
                agy_closed.append(True)

        monkeypatch.setattr(runner_mod, "find_agy_executable", lambda: Path("/usr/bin/true"))
        monkeypatch.setattr(runner_mod, "stream_agy_prompt", _slow_agy_stream)

        agy_bot = store.create_bot({"name": "Agy Routine Bot", "engine_id": "agy"})
        agy_bot_id = str(agy_bot["id"])
        agy_thread = str(agy_bot["thread_id"])
        rtn_agy = store.create_routine(
            agy_bot_id,
            {
                "name": "AskFirst Agy Routine",
                "instruction": "Deploy release to staging",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        rtn_agy_id = str(rtn_agy["id"])

        # C1: zero-delay interrupt on ask_first agy routine
        run_c1 = await turn_runner.execute_routine(rtn_agy_id, trigger="manual")
        for _ in range(50):
            cur = store.get_routine_run(str(run_c1["id"]))
            apprs = [a for a in store.list_thread_approvals(agy_thread) if a["status"] == "pending"]
            if cur is not None and cur["status"] == "waiting_approval" and apprs:
                break
            await asyncio.sleep(0.02)
        apprs_c1 = [a for a in store.list_thread_approvals(agy_thread) if a["status"] == "pending"]
        assert len(apprs_c1) == 1
        resolved_c1 = store.resolve_approval(str(apprs_c1[0]["id"]), "allow_once")
        await turn_runner.on_approval_resolved(resolved_c1, decision="allow_once")
        assert agy_thread in turn_runner._active_tasks
        assert agy_thread in turn_runner._active_routine_runs
        assert await turn_runner.interrupt(agy_thread) is True
        settled_c1 = store.get_routine_run(str(run_c1["id"]))
        assert settled_c1 is not None and settled_c1["status"] == "failed"

        # C2: interrupt while stream_agy_prompt is actively streaming
        agy_closed.clear()
        run_c2 = await turn_runner.execute_routine(rtn_agy_id, trigger="manual")
        for _ in range(50):
            cur = store.get_routine_run(str(run_c2["id"]))
            apprs = [a for a in store.list_thread_approvals(agy_thread) if a["status"] == "pending"]
            if cur is not None and cur["status"] == "waiting_approval" and apprs:
                break
            await asyncio.sleep(0.02)
        apprs_c2 = [a for a in store.list_thread_approvals(agy_thread) if a["status"] == "pending"]
        resolved_c2 = store.resolve_approval(str(apprs_c2[0]["id"]), "allow_once")
        await turn_runner.on_approval_resolved(resolved_c2, decision="allow_once")
        await asyncio.sleep(0.05)
        assert agy_thread in turn_runner._active_tasks
        assert agy_thread in turn_runner._active_routine_runs
        assert await turn_runner.interrupt(agy_thread) is True
        settled_c2 = store.get_routine_run(str(run_c2["id"]))
        assert settled_c2 is not None and settled_c2["status"] == "failed"
        assert agy_closed == [True]

        # C3: superseding start_turn() while stream_agy_prompt is actively streaming
        agy_closed.clear()
        run_c3 = await turn_runner.execute_routine(rtn_agy_id, trigger="manual")
        for _ in range(50):
            cur = store.get_routine_run(str(run_c3["id"]))
            apprs = [a for a in store.list_thread_approvals(agy_thread) if a["status"] == "pending"]
            if cur is not None and cur["status"] == "waiting_approval" and apprs:
                break
            await asyncio.sleep(0.02)
        apprs_c3 = [a for a in store.list_thread_approvals(agy_thread) if a["status"] == "pending"]
        resolved_c3 = store.resolve_approval(str(apprs_c3[0]["id"]), "allow_once")
        await turn_runner.on_approval_resolved(resolved_c3, decision="allow_once")
        await asyncio.sleep(0.05)
        agy_msg = store.create_message(
            thread_id=agy_thread,
            sender_type="human",
            sender_name="Operator",
            content="Supersede agy routine",
            status="done",
        )
        turn_runner.start_turn(thread_id=agy_thread, user_message=agy_msg)
        settled_c3 = store.get_routine_run(str(run_c3["id"]))
        assert settled_c3 is not None and settled_c3["status"] == "failed"
        await turn_runner.wait_for_active_turn(agy_thread)
        settled_c3_after = store.get_routine_run(str(run_c3["id"]))
        assert settled_c3_after is not None and settled_c3_after["status"] == "failed"
        assert agy_closed == [True]


def test_r4_gap1_4305_digit_json_int_returns_400_and_ws_survives(
    tmp_path: Path,
) -> None:
    from fastapi.testclient import TestClient

    app = create_app(db_path=tmp_path / "t5_r4_gap1.sqlite3")
    big_int = "9" * 4305
    big_ttl_json = f'{{"ttl_seconds": {big_int}}}'
    big_action_json = f'{{"type": "click", "x": {big_int}, "y": 10}}'
    big_start_json = f'{{"url": "https://example.com", "pad": {big_int}}}'

    with TestClient(app, raise_server_exceptions=False) as err_client:
        for url, payload in (
            ("/api/v1/computers/vm_local/vnc-token", big_ttl_json),
            ("/api/v1/computers/vm_local/takeover", big_ttl_json),
            ("/api/browser/action", big_action_json),
            ("/api/v1/computers/vm_local/actions", big_action_json),
            ("/api/browser/start", big_start_json),
        ):
            resp = err_client.post(
                url,
                content=payload,
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 400, f"{url}: {resp.status_code} {resp.text}"

    with TestClient(app, raise_server_exceptions=True) as client:
        tok_resp = client.post("/api/v1/computers/vm_local/vnc-token", json={})
        assert tok_resp.status_code == 200
        cap_tok = str(tok_resp.json()["cap_token"])

        with client.websocket_connect(
            f"/ws/v1/computers/vm_local/control?cap_token={cap_tok}"
        ) as ws_ctrl:
            assert ws_ctrl.receive_json()["op"] == "computer.state"
            ws_ctrl.send_text(f'{{"op": "viewport.resize", "width": {big_int}, "height": 800}}')
            ws_ctrl.send_json({"op": "ping"})
            pong = ws_ctrl.receive_json()
            assert pong["op"] == "pong"

        with client.websocket_connect(
            f"/ws/v1/computers/vm_local/screencast?cap_token={cap_tok}"
        ) as ws_sc:
            assert ws_sc.receive_json()["type"] == "status"
            ws_sc.send_text(f'{{"type": "click", "x": {big_int}, "y": 10}}')
            ws_sc.send_json({"type": "ping"})
            pong_sc = ws_sc.receive_json()
            assert pong_sc["type"] == "pong"

        with client.websocket_connect("/ws/browser") as ws_br:
            assert ws_br.receive_json()["type"] == "status"
            ws_br.send_text(f'{{"type": "click", "x": {big_int}, "y": 10}}')
            ws_br.send_json({"type": "status"})
            st_br = ws_br.receive_json()
            assert st_br["type"] == "status"

        with client.websocket_connect("/ws/terminal") as ws_term:
            assert ws_term.receive_json()["type"] == "ready"
            ws_term.send_text(f'{{"type": "resize", "cols": {big_int}, "rows": 24}}')
            ws_term.send_json({"type": "input", "data": "echo TERM_4305_OK\n"})
            collected_term = ""
            for _ in range(30):
                ev = ws_term.receive_json()
                if ev.get("type") == "output":
                    collected_term += str(ev.get("data") or "")
                    if "TERM_4305_OK" in collected_term:
                        break
            assert "TERM_4305_OK" in collected_term

        with client.websocket_connect(
            f"/ws/v1/computers/vm_local/pty/s1?cap_token={cap_tok}"
        ) as ws_pty:
            ws_pty.send_text(f'{{"type": "resize", "cols": {big_int}, "rows": 24}}')
            ws_pty.send_json({"type": "input", "data": "echo PTY_4305_OK\n"})
            collected_pty = ""
            for _ in range(30):
                chunk = ws_pty.receive_text()
                collected_pty += chunk
                if "PTY_4305_OK" in collected_pty:
                    break
            assert "PTY_4305_OK" in collected_pty


class _GatedRoutineCoordinator:
    """Coordinator stub whose routine run blocks until gated_event is set or cancelled."""

    def __init__(self) -> None:
        self._runs: dict[str, _RunEntry] = {}
        self.submitted_event = asyncio.Event()
        self.release_event = asyncio.Event()
        self.cancel_calls: list[tuple[str, str]] = []
        self._seq = 0

    def submit_task(self, task_spec: TaskSpec, run_id: str | None = None) -> Run:
        del run_id
        self._seq += 1
        rid = f"run_gated_{self._seq}"
        now = utc_now()
        run = Run(
            run_id=rid,
            task_id=task_spec.task_id,
            status=TaskStatus.RUNNING,
            transition_reason="running",
            deadline_at=now + timedelta(minutes=5),
            created_at=now,
            updated_at=now,
        )
        entry = _RunEntry(spec=task_spec, run=run)
        self._runs[rid] = entry
        self.submitted_event.set()
        return run

    def get_task_snapshot(self, run_id: str) -> TaskSnapshot | None:
        entry = self._runs.get(run_id)
        if entry is None:
            return None
        return TaskSnapshot(
            run=entry.run,
            task=entry.spec,
            budget_config=BudgetConfig(),
            result=entry.result,
        )

    def list_task_snapshots(self) -> list[TaskSnapshot]:
        return [
            snap
            for rid in self._runs
            if (snap := self.get_task_snapshot(rid)) is not None
        ]

    async def resume_task(self, run_id: str, human_input: dict[str, Any]) -> Run:
        del human_input
        return self._runs[run_id].run

    async def wait_for_run(self, run_id: str, *, timeout: float | None = None) -> Result | None:
        entry = self._runs[run_id]
        wait_settled = asyncio.create_task(entry.settled_event.wait())
        wait_release = asyncio.create_task(self.release_event.wait())
        try:
            done, pending = await asyncio.wait(
                {wait_settled, wait_release},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for p in pending:
                p.cancel()
            if wait_release in done and entry.run.status == TaskStatus.RUNNING:
                now = utc_now()
                entry.run = entry.run.model_copy(
                    update={"status": TaskStatus.SUCCEEDED, "updated_at": now}
                )
                entry.result = Result(
                    task_id=entry.spec.task_id,
                    run_id=run_id,
                    status=TaskStatus.SUCCEEDED,
                    answer="Routine finished after release",
                )
        finally:
            for t in (wait_settled, wait_release):
                if not t.done():
                    t.cancel()
        return entry.result

    def cancel_task(self, run_id: str, reason: str = "cancelled_by_user") -> Run:
        entry = self._runs[run_id]
        self.cancel_calls.append((run_id, reason))
        now = utc_now()
        entry.run = entry.run.model_copy(
            update={
                "status": TaskStatus.CANCELLED,
                "transition_reason": reason,
                "updated_at": now,
            }
        )
        entry.settled_event.set()
        return entry.run


async def test_r4_gap2_delete_routine_in_flight_cancels_cleanly_with_no_orphan_messages(
    tmp_path: Path,
) -> None:
    coord = _GatedRoutineCoordinator()
    app = create_app(db_path=tmp_path / "t5_r4_gap2.sqlite3", coordinator=coord)

    async with app.router.lifespan_context(app):
        store: WorkspaceStore = app.state.workspace_store
        turn_runner: AgentTurnRunner = app.state.v1_runner
        store.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})
        bot = store.get_bot("bot_chief")
        assert bot is not None
        thread_id = str(bot["thread_id"])

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            r_create = await client.post(
                "/api/v1/bots/bot_chief/routines",
                json={
                    "name": "In-Flight Delete Routine",
                    "instruction": "Check plant health",
                    "schedule_type": "manual",
                    "enabled": True,
                },
            )
            assert r_create.status_code == 201
            rtn_id = str(r_create.json()["id"])

            bg_tasks_before = list(turn_runner._routine_tasks)
            assert bg_tasks_before == []

            r_run = await client.post(f"/api/v1/routines/{rtn_id}/test")
            assert r_run.status_code == 202
            assert r_run.json()["status"] == "running"

            await asyncio.wait_for(coord.submitted_event.wait(), timeout=2.0)
            tracked_tasks = list(turn_runner._routine_tasks)
            assert len(tracked_tasks) == 1

            r_del = await client.delete(f"/api/v1/routines/{rtn_id}")
            assert r_del.status_code == 200
            assert r_del.json() == {"deleted": True}

            # Coordinator run cancelled; tracked task settled with no unhandled exception
            assert len(coord.cancel_calls) >= 1
            assert coord.cancel_calls[0][0] == "run_gated_1"
            for t in tracked_tasks:
                assert t.done()
                with pytest.raises(asyncio.CancelledError):
                    t.result()

            coord.release_event.set()
            await asyncio.sleep(0.05)

            msgs, _ = store.list_thread_messages(thread_id)
            assert msgs == []

        # Also verify direct store.delete_routine while _execute_routine_bg finishes normally
        coord2 = _GatedRoutineCoordinator()
        app2 = create_app(db_path=tmp_path / "t5_r4_gap2_direct.sqlite3", coordinator=coord2)
        async with app2.router.lifespan_context(app2):
            store2: WorkspaceStore = app2.state.workspace_store
            runner2: AgentTurnRunner = app2.state.v1_runner
            store2.update_bot("bot_chief", {"engine_id": "controlbot_runtime"})
            rtn2 = store2.create_routine(
                "bot_chief",
                {
                    "name": "Direct Store Delete Routine",
                    "instruction": "Check telemetry",
                    "schedule_type": "manual",
                    "enabled": True,
                },
            )
            rtn2_id = str(rtn2["id"])
            await runner2.execute_routine(rtn2_id, trigger="manual")
            await asyncio.wait_for(coord2.submitted_event.wait(), timeout=2.0)
            tasks2 = list(runner2._routine_tasks)
            assert len(tasks2) == 1

            assert store2.delete_routine(rtn2_id) is True
            coord2.release_event.set()
            await asyncio.gather(*tasks2)
            for t in tasks2:
                assert t.exception() is None
            msgs2, _ = store2.list_thread_messages("thr_bot_chief")
            assert msgs2 == []


@pytest.mark.parametrize(
    "ssrf_url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/hook",
        "http://localhost./hook",
        "http://foo.localhost/hook",
        "http://127.0.0.1:9999/hook",
    ],
)
async def test_r4_gap3_draft_resolve_ssrf_fails_closed_with_zero_outbound_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ssrf_url: str,
) -> None:
    attempted_urls: list[str] = []
    orig_async_client = httpx.AsyncClient

    class _RecordingAsyncClient(orig_async_client):  # type: ignore[valid-type, misc]
        async def post(self, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
            attempted_urls.append(str(url))
            resp: httpx.Response = await super().post(url, *args, **kwargs)
            return resp

    monkeypatch.setattr("src.web.v1.runner.httpx.AsyncClient", _RecordingAsyncClient)

    app = create_app(db_path=tmp_path / "t5_r4_gap3.sqlite3")
    async with app.router.lifespan_context(app):
        store: WorkspaceStore = app.state.workspace_store
        transport = httpx.ASGITransport(app=app)
        async with orig_async_client(transport=transport, base_url="http://testserver") as client:
            drf_resp = await client.post(
                "/api/v1/drafts",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "channel_type": "webhook",
                    "fields": {"webhook_url": ssrf_url, "message": "ssrf"},
                },
            )
            assert drf_resp.status_code == 201
            drf_id = str(drf_resp.json()["id"])

            res_resp = await client.post(
                f"/api/v1/drafts/{drf_id}/resolve",
                json={"action": "send"},
            )
            assert res_resp.status_code == 200
            assert attempted_urls == []

            msgs, _ = store.list_thread_messages("thr_bot_chief")
            assert len(msgs) == 1
            assert msgs[0]["status"] == "error"
            assert "SSRF policy" in str(msgs[0]["content"])


async def test_r4_gap3_draft_redirect_3xx_is_not_followed_or_marked_delivered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastapi import FastAPI
    from fastapi.responses import RedirectResponse

    wh_app = FastAPI()
    redirect_hits: list[str] = []
    internal_hits: list[str] = []

    @wh_app.post("/redir")
    async def redir() -> RedirectResponse:
        redirect_hits.append("/redir")
        return RedirectResponse("http://169.254.169.254/latest/meta-data/", status_code=302)

    @wh_app.post("/latest/meta-data/")
    async def meta() -> dict[str, bool]:
        internal_hits.append("/latest/meta-data/")
        return {"ok": True}

    wh_transport = httpx.ASGITransport(app=wh_app)
    orig_async_client = httpx.AsyncClient

    class _MockRedirectClient(orig_async_client):  # type: ignore[valid-type, misc]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs.pop("trust_env", None)
            kwargs["transport"] = wh_transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("src.web.v1.runner.httpx.AsyncClient", _MockRedirectClient)

    app = create_app(db_path=tmp_path / "t5_r4_gap3_redir.sqlite3")
    async with app.router.lifespan_context(app):
        store: WorkspaceStore = app.state.workspace_store
        runner: AgentTurnRunner = app.state.v1_runner
        draft = store.create_draft(
            bot_id="bot_chief",
            thread_id="thr_bot_chief",
            channel_type="webhook",
            fields={"webhook_url": "http://public-hook.example.com/redir", "message": "hi"},
        )
        deliv = await runner.deliver_draft(draft)
        assert deliv["delivered"] is False
        assert deliv["status_code"] == 302
        assert "redirect" in str(deliv.get("error") or "").lower()
        assert redirect_hits == ["/redir"]
        assert internal_hits == []


async def test_r4_gap4_active_live_browser_rejects_null_and_inf_actions_with_422(
    tmp_path: Path,
) -> None:
    class _FakeMouse:
        def __init__(self) -> None:
            self.calls: list[tuple[str, tuple[Any, ...]]] = []

        async def click(self, x: float, y: float, *, button: str = "left") -> None:
            self.calls.append(("click", (x, y, button)))

        async def dblclick(self, x: float, y: float) -> None:
            self.calls.append(("dblclick", (x, y)))

        async def move(self, x: float, y: float) -> None:
            self.calls.append(("move", (x, y)))

        async def wheel(self, dx: float, dy: float) -> None:
            self.calls.append(("wheel", (dx, dy)))

    class _FakeKeyboard:
        async def type(self, text: str) -> None:
            del text

        async def press(self, key: str) -> None:
            del key

    class _FakePage:
        def __init__(self) -> None:
            self.mouse = _FakeMouse()
            self.keyboard = _FakeKeyboard()
            self.url = "https://example.com/"

        def is_closed(self) -> bool:
            return False

        async def title(self) -> str:
            return "Fake"

        async def evaluate(self, script: str, max_elements: int) -> dict[str, Any]:
            del script, max_elements
            return {"visible_text": "Fake", "elements": []}

        async def screenshot(self, **kwargs: Any) -> bytes:
            del kwargs
            return b""

    app = create_app(db_path=tmp_path / "t5_r4_gap4.sqlite3")
    async with app.router.lifespan_context(app):
        fake_page = _FakePage()
        app.state.live_browser._context = object()
        app.state.live_browser._page = fake_page

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            for endpoint in ("/api/browser/action", "/api/v1/computers/vm_local/actions"):
                for bad_json in (
                    '{"type": "click", "x": null, "y": 10}',
                    '{"type": "click", "x": true, "y": 10}',
                    '{"type": "wheel", "dx": 1e400, "dy": 0}',
                    '{"type": "wheel", "dx": 0, "dy": null}',
                ):
                    resp = await client.post(
                        endpoint,
                        content=bad_json,
                        headers={"Content-Type": "application/json"},
                    )
                    assert resp.status_code == 422, (
                        f"{endpoint} {bad_json}: {resp.status_code} {resp.text}"
                    )

            assert fake_page.mouse.calls == []

            ok_resp = await client.post(
                "/api/v1/computers/vm_local/actions",
                json={"type": "wheel", "dx": 0, "dy": 120},
            )
            assert ok_resp.status_code == 200
            assert fake_page.mouse.calls == [("wheel", (0.0, 120.0))]
