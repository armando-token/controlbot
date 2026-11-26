"""Integration tests for M2: WAL, atomic WorkspaceStore, durable SSE, audit, & memory HTTP."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from src.storage.audit_chain import append_chained_audit_row
from src.storage.memory import MemoryStore
from src.web.v1.events import EventBus, parse_event_cursor
from src.web.v1.memory_routes import create_memory_router
from src.web.v1.schemas import (
    ConnectedAppPatchRequest,
    MessageCreateRequest,
    PageCreateRequest,
    SecureFormSubmitRequest,
)
from src.web.v1.store import (
    SCHEMA_VERSION,
    StoreConflictError,
    StoreNotFoundError,
    StoreValidationError,
    WorkspaceStore,
)


@pytest.mark.n2
def test_workspace_store_pragmas_migrations_and_nested_write_tx(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "ws.sqlite3")
    row_mode = store._conn.execute("PRAGMA journal_mode;").fetchone()
    row_sync = store._conn.execute("PRAGMA synchronous;").fetchone()
    row_fk = store._conn.execute("PRAGMA foreign_keys;").fetchone()
    row_busy = store._conn.execute("PRAGMA busy_timeout;").fetchone()
    row_ver = store._conn.execute("PRAGMA user_version;").fetchone()

    assert row_mode is not None and str(row_mode[0]).lower() == "wal"
    assert row_sync is not None and int(row_sync[0]) == 1  # NORMAL
    assert row_fk is not None and int(row_fk[0]) == 1
    assert row_busy is not None and int(row_busy[0]) == 5000
    assert row_ver is not None and int(row_ver[0]) >= SCHEMA_VERSION

    migs = store._conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    assert [int(r[0]) for r in migs] == [1, 2]

    # Nested write_tx savepoint rollback preserves outer tx while reverting inner failure
    with store.write_tx():
        outer_sec = store.create_section("Outer Section", sort_order=1)
        try:
            with store.write_tx():
                store.create_section("Inner Rolled Back", sort_order=2)
                raise RuntimeError("boom inside nested savepoint")
        except RuntimeError:
            pass

    names = [s["name"] for s in store.list_sections()]
    assert "Outer Section" in names
    assert "Inner Rolled Back" not in names
    assert store.get_section(outer_sec["id"]) is not None

    # Top-level write_tx rollback reverts everything
    try:
        with store.write_tx():
            store.create_section("Top Rolled Back", sort_order=3)
            raise RuntimeError("boom at depth 0")
    except RuntimeError:
        pass
    assert "Top Rolled Back" not in [s["name"] for s in store.list_sections()]
    store.close()


@pytest.mark.n2
def test_workspace_store_8_thread_concurrent_wal_stress(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "stress.sqlite3")
    errors: list[BaseException] = []

    def _worker(worker_idx: int) -> None:
        try:
            for step in range(15):
                store.create_message(
                    thread_id="thr_bot_chief",
                    sender_type="assistant",
                    sender_bot_id="bot_chief",
                    sender_name="Chief of Staff",
                    content=f"worker={worker_idx} step={step}",
                )
                apr = store.create_approval(
                    bot_id="bot_chief",
                    thread_id="thr_bot_chief",
                    title=f"Approve {worker_idx}-{step}",
                    arguments={"cmd": f"echo {worker_idx}-{step}"},
                )
                store.resolve_approval(
                    apr["id"],
                    "allow_once",
                    idempotency_key=f"idem-{worker_idx}-{step}",
                )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_worker, i) for i in range(8)]
        for fut in futures:
            fut.result()

    assert errors == []
    usage = store.get_usage()
    assert usage["messages_count"] == 8 * 15
    assert usage["approvals_count"] == 8 * 15

    audit_check = store.verify_audit_chain()
    assert audit_check["valid"] is True
    assert audit_check["checked"] == 8 * 15 * 2  # create + resolve per step
    store.close()


@pytest.mark.n2
def test_workspace_store_atomicity_cascade_escaping_unread_vault_and_vm_state(
    tmp_path: Path,
) -> None:
    db_file = tmp_path / "hardened.sqlite3"
    store = WorkspaceStore(db_file)

    # 1. resolve_draft invalid action / malformed fields MUST NOT burn Idempotency-Key
    drf = store.create_draft(
        bot_id="bot_chief",
        thread_id="thr_bot_chief",
        fields={"to": "ops@example.com", "subject": "Shift"},
    )
    with pytest.raises(StoreValidationError):
        store.resolve_draft(drf["id"], "bad_action", idempotency_key="idem-draft-save")
    with pytest.raises(StoreValidationError):
        store.resolve_draft(
            drf["id"],
            "send",
            fields="not-a-dict",  # type: ignore[arg-type]
            idempotency_key="idem-draft-save",
        )
    # Same Idempotency-Key succeeds on valid call, and subsequent duplicate raises conflict!
    sent = store.resolve_draft(
        drf["id"],
        "send",
        fields={"subject": "Shift Final"},
        idempotency_key="idem-draft-save",
    )
    assert sent["status"] == "sent"
    assert sent["fields"]["subject"] == "Shift Final"
    drf2 = store.create_draft(
        bot_id="bot_chief",
        thread_id="thr_bot_chief",
        fields={"to": "ops@example.com"},
    )
    with pytest.raises(StoreConflictError):
        store.resolve_draft(drf2["id"], "send", idempotency_key="idem-draft-save")

    # 2. replace_auto_review_rules invalid rule preserves existing rules
    initial_rules = store.replace_auto_review_rules(
        [{"bucket": "allow_auto", "rule_text": "Allow read-only ls"}]
    )
    assert len(initial_rules) == 1
    with pytest.raises(StoreValidationError):
        store.replace_auto_review_rules(
            [
                {"bucket": "allow_auto", "rule_text": "Valid rule"},
                {"bucket": "ask_first", "rule_text": "   "},
            ]
        )
    preserved = store.list_auto_review_rules()
    assert len(preserved) == 1
    assert preserved[0]["rule_text"] == "Allow read-only ls"

    # 3. create_approval scrubs pending_context
    apr = store.create_approval(
        bot_id="bot_chief",
        thread_id="thr_bot_chief",
        title="Deploy",
        arguments={"token": "sk-secret-args-12345678"},
        pending_context={"api_key": "sk-secret-pending-12345678", "step": 2},
    )
    assert apr["arguments"]["token"] == "[REDACTED]"
    pctx = store.get_approval_pending_context(apr["id"])
    assert pctx is not None
    assert pctx["api_key"] == "[REDACTED]"
    assert pctx["step"] == 2

    # 4. list_bot_library & search exclude superseded pages and escape LIKE wildcards
    p1, _ = store.create_or_version_page(
        bot_id="bot_chief",
        title="100%_val\\check",
        content_md="Version 1 body",
    )
    p2, _ = store.create_or_version_page(
        bot_id="bot_chief",
        title="100%_val\\check",
        content_md="Version 2 body",
    )
    # Distractor that would match unescaped SQL LIKE wildcards % and _
    p_distractor, _ = store.create_or_version_page(
        bot_id="bot_chief",
        title="100XYZvalQcheck",
        content_md="Should not match literal %_\\",
    )
    lib = store.list_bot_library("bot_chief", artifact_type="page", query="100%_val\\")
    lib_ids = [item["id"] for item in lib["items"]]
    assert lib_ids == [p2["id"]]
    assert p1["id"] not in lib_ids
    assert p_distractor["id"] not in lib_ids

    srch = store.search("100%_val\\")
    assert [p["id"] for p in srch["pages"]] == [p2["id"]]

    # 5. list_thread_messages unknown before_id NEVER returns newest page
    store.create_message(
        thread_id="thr_bot_chief",
        sender_type="user",
        sender_name="You",
        content="Hello",
    )
    msgs_miss, has_more_miss = store.list_thread_messages(
        "thr_bot_chief", before_id="msg_does_not_exist"
    )
    assert msgs_miss == []
    assert has_more_miss is False
    with pytest.raises(StoreNotFoundError):
        store.list_thread_messages(
            "thr_bot_chief", before_id="msg_does_not_exist", strict_before_id=True
        )

    # 6. unread_count increments on non-user finalized messages and resets via mark_thread_read
    assert store.get_bot("bot_chief")["unread_count"] == 0  # type: ignore[index]
    streaming_msg = store.create_message(
        thread_id="thr_bot_chief",
        sender_type="assistant",
        sender_bot_id="bot_chief",
        sender_name="Chief",
        content="Thinking...",
        status="streaming",
    )
    assert store.get_bot("bot_chief")["unread_count"] == 0  # type: ignore[index]
    store.update_message(streaming_msg["id"], {"content": "Final reply", "status": "done"})
    assert store.get_bot("bot_chief")["unread_count"] == 1  # type: ignore[index]
    store.create_message(
        thread_id="thr_bot_chief",
        sender_type="assistant",
        sender_bot_id="bot_chief",
        sender_name="Chief",
        content="Routine update",
        status="done",
    )
    assert store.get_bot("bot_chief")["unread_count"] == 2  # type: ignore[index]
    read_res = store.mark_thread_read("thr_bot_chief")
    assert read_res["unread_count"] == 0
    assert store.get_bot("bot_chief")["unread_count"] == 0  # type: ignore[index]

    # 7. update_connected_app supports kwargs & updates dict + persists account_label
    upd_app = store.update_connected_app(
        "app_pty",
        {"enabled": True},
        account_label="plant-edge-01",
        config={"region": "us-east"},
    )
    assert upd_app["account_label"] == "plant-edge-01"
    assert upd_app["config"]["region"] == "us-east"
    apps = {a["id"]: a for a in store.list_connected_apps()}
    assert apps["app_pty"]["account_label"] == "plant-edge-01"

    # 8. Vault v2h AEAD + v1 legacy backwards compatibility + 0600 key permissions
    key_path = store.db_path.with_name(f".{store.db_path.stem}.vault.key")
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    v_global = store.create_vault_secret(
        bot_id=None,
        name="Global ERP",
        domain="erp.local",
        fields={"username": "admin", "password": "global-password"},
    )
    assert store.decrypt_vault_secret(v_global["id"]) == {
        "username": "admin",
        "password": "global-password",
    }

    # Verify legacy v1: ciphertext still decrypts seamlessly
    import base64
    import hashlib
    import hmac
    import secrets

    legacy_plain = json.dumps({"api_key": "legacy-v1-val"}).encode("utf-8")
    nonce = secrets.token_bytes(16)
    enc_k = hmac.new(store._vault_key, b"enc:" + nonce, hashlib.sha256).digest()
    mac_k = hmac.new(store._vault_key, b"mac:" + nonce, hashlib.sha256).digest()
    ks = hmac.new(enc_k, (0).to_bytes(8, "big"), hashlib.sha256).digest()
    ct = bytes(a ^ b for a, b in zip(legacy_plain, ks, strict=False))
    tag = hmac.new(mac_k, nonce + ct, hashlib.sha256).digest()
    v1_blob = base64.b64encode(b"v1:" + nonce + tag + ct).decode("ascii")
    assert store._decrypt_vault_payload(v1_blob) == {"api_key": "legacy-v1-val"}

    # 9. record_reaction & delete_artifact (including attachment reference tracking)
    react_msg = store.record_reaction(streaming_msg["id"], "👍", actor="alice", action="toggle")
    assert react_msg["reactions"] == {"👍": 1}

    att_path = tmp_path / "uploads" / "att_demo.txt"
    att_path.parent.mkdir(parents=True, exist_ok=True)
    att_path.write_text("demo", encoding="utf-8")
    store.create_attachment(
        "att_demo",
        thread_id="thr_bot_chief",
        bot_id="bot_chief",
        filename="att_demo.txt",
        mime_type="text/plain",
        size_bytes=4,
        storage_path=str(att_path),
    )
    art_att = store.create_artifact(
        bot_id="bot_chief",
        artifact_type="file",
        title="att_demo.txt",
        url="/api/v1/attachments/att_demo",
    )
    assert store.delete_artifact("art_missing") is None
    del_art = store.delete_artifact(art_att["id"])
    assert del_art is not None
    assert del_art["deleted"] is True
    assert del_art["attachment_path"] == str(att_path)

    # 10. delete_bot cascades bot-owned rows while preserving global (bot_id IS NULL) items
    temp_bot = store.create_bot({"name": "Disposable Bot"})
    temp_id = temp_bot["id"]
    temp_thr = temp_bot["thread_id"]
    store.create_message(
        thread_id=temp_thr,
        sender_type="user",
        sender_name="You",
        content="hi",
    )
    store.create_artifact(
        bot_id=temp_id,
        artifact_type="page",
        title="Temp Page",
        thread_id=temp_thr,
    )
    store.create_approval(bot_id=temp_id, thread_id=temp_thr, title="Temp Apr")
    store.create_draft(bot_id=temp_id, thread_id=temp_thr, fields={"body": "draft"})
    store.create_secure_form(
        bot_id=temp_id,
        thread_id=temp_thr,
        title="Login",
        fields=[{"name": "password", "label": "Password", "secret": True}],
    )
    store.create_vault_secret(bot_id=temp_id, name="Bot Secret", fields={"password": "bot"})
    store.create_skill({"bot_id": temp_id, "name": "Bot Skill", "content_md": "# Skill"})
    rtn = store.create_routine(temp_id, {"name": "Bot Routine", "instruction": "Run"})
    store.create_routine_run(rtn["id"], temp_id)

    assert store.delete_bot(temp_id) is True
    assert store.get_bot(temp_id) is None
    assert (
        store._conn.execute(
            "SELECT COUNT(*) FROM messages WHERE thread_id = ?", (temp_thr,)
        ).fetchone()[0]
        == 0
    )
    for table in (
        "artifacts",
        "approvals",
        "drafts",
        "secure_forms",
        "vault_secrets",
        "skills",
        "routines",
        "routine_runs",
    ):
        cnt = store._conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE bot_id = ?", (temp_id,)
        ).fetchone()[0]
        assert cnt == 0, f"Orphaned rows left in {table}"

    # Global vault secret & global skill remain intact!
    assert len(store.list_vault_secrets()) == 1
    assert any(s["id"] == "skl_summarize_workspace" for s in store.list_skills())

    # 11. computer_vms & teach_steps persistence across store close/reopen
    store.save_computer_vm(
        "default",
        {
            "control_owner": "human_takeover",
            "lease_id": "lease_1",
            "lease_owner": "operator",
            "active_url": "https://scada.local/view",
            "display_mode": "browser",
            "is_teaching_task": True,
            "teach_name": "Inspect Alarm",
        },
    )
    store.save_teach_steps(
        "default",
        [
            {"step_index": 1, "action": "navigate", "description": "Open SCADA", "url": "https://scada.local"},
            {"step_index": 2, "action": "click", "description": "Click Alarms", "url": "https://scada.local/alarms"},
        ],
    )
    store.close()

    reopened = WorkspaceStore(db_file)
    vm = reopened.get_computer_vm("default")
    assert vm is not None
    assert vm["control_owner"] == "human_takeover"
    assert vm["display_mode"] == "browser"
    steps = reopened.get_teach_steps("default")
    assert [s["action"] for s in steps] == ["navigate", "click"]

    # 12. Audit chain valid, then detect DB tamper
    assert reopened.verify_audit_chain()["valid"] is True
    # Verify raw vault secret never appeared in audit log
    audit_rows = reopened.list_audit_events(limit=500)
    assert "global-password" not in json.dumps(audit_rows)

    reopened._conn.execute("DROP TRIGGER trg_workspace_audit_log_no_update")
    reopened._conn.execute(
        "UPDATE workspace_audit_log SET decision = 'forged' WHERE seq = 2"
    )
    tamper = reopened.verify_audit_chain()
    assert tamper["valid"] is False
    assert tamper["broken_seq"] == 2
    reopened.close()


@pytest.mark.n2
async def test_durable_sse_restart_replay_and_resync_modes(tmp_path: Path) -> None:
    db_path = tmp_path / "sse.sqlite3"
    store1 = WorkspaceStore(db_path)
    bus1 = EventBus(store=store1)

    e1 = bus1.publish("bot.presence", {"state": "working", "step": 1}, bot_id="bot_chief")
    e2 = bus1.publish("bot.presence", {"state": "idle", "step": 2}, bot_id="bot_chief")
    assert int(e2["id"].split("_")[1]) > int(e1["id"].split("_")[1])
    assert parse_event_cursor(e2["id"]) == (bus1.epoch, 2)
    store1.close()

    # Simulated server restart: new WorkspaceStore & EventBus on same DB
    store2 = WorkspaceStore(db_path)
    bus2 = EventBus(store=store2)
    assert bus2.epoch == bus1.epoch
    e3 = bus2.publish("message.completed", {"content": "post-restart-1"}, bot_id="bot_chief")
    e4 = bus2.publish("message.completed", {"content": "post-restart-2"}, bot_id="bot_chief")
    assert int(e3["id"].split("_")[1]) == 3
    assert int(e4["id"].split("_")[1]) == 4

    # Reconnect with pre-restart Last-Event-ID e2 -> receives ': connected', 'retry: 2000', e3, e4
    frames: list[str] = []
    async with contextlib.aclosing(bus2.stream_sse(e2["id"], keepalive_seconds=0.1)) as stream:
        for _ in range(4):
            frames.append(await asyncio.wait_for(stream.__anext__(), timeout=2.0))

    assert frames[0] == ": connected\n\n"
    assert frames[1] == "retry: 2000\n\n"
    assert e3["id"] in frames[2]
    assert "post-restart-1" in frames[2]
    assert e4["id"] in frames[3]
    assert "post-restart-2" in frames[3]

    # Cross-epoch cursor emits stream.resync AND still delivers current epoch events
    async with contextlib.aclosing(
        bus2.stream_sse("evt_000050_oldepoch", keepalive_seconds=0.1)
    ) as cross_stream:
        cross_frames = [
            await asyncio.wait_for(cross_stream.__anext__(), timeout=2.0) for _ in range(4)
        ]
    assert "stream.resync" in cross_frames[2]
    assert "epoch_mismatch" in cross_frames[2]
    assert e1["id"] in cross_frames[3]

    # Legacy numeric / evt_<seq> format ahead of in-memory bus emits stream.resync
    mem_bus = EventBus(max_buffer=3, subscriber_queue_size=2)
    for i in range(6):
        mem_bus.publish("tick", {"n": i})
    # Buffer only holds seq 4, 5, 6 -> cursor at seq 1 is evicted
    evicted_items: list[dict[str, Any]] = []
    async with contextlib.aclosing(mem_bus.subscribe("evt_000001")) as sub_gen:
        for _ in range(4):
            evicted_items.append(await asyncio.wait_for(sub_gen.__anext__(), timeout=2.0))
    assert evicted_items[0]["type"] == "stream.resync"
    assert evicted_items[0]["payload"]["reason"] == "sequence_evicted"
    assert [it["payload"]["n"] for it in evicted_items[1:]] == [3, 4, 5]

    # Slow consumer overflow emits stream.resync instead of silent drop
    async with contextlib.aclosing(mem_bus.subscribe(None)) as slow_gen:
        async def _next_ev() -> dict[str, Any]:
            return await slow_gen.__anext__()

        task_first = asyncio.create_task(_next_ev())
        await asyncio.sleep(0.02)
        for i in range(5):
            mem_bus.publish("burst", {"b": i})
        first_item = await asyncio.wait_for(task_first, timeout=2.0)
        second_item = await asyncio.wait_for(slow_gen.__anext__(), timeout=2.0)
    assert "stream.resync" in {first_item["type"], second_item["type"]}

    # Also check <epoch>:<seq> cursor format parsing
    assert parse_event_cursor(f"{bus2.epoch}:2") == (bus2.epoch, 2)
    store2.close()


@pytest.mark.n2
async def test_schemas_and_memory_http_routes(tmp_path: Path) -> None:
    # 1. Schema validations
    p_chan = PageCreateRequest(channel_id="chn_1", title="Channel Page", content_md="hi")
    assert p_chan.channel_id == "chn_1"
    p_thr = PageCreateRequest(thread_id="thr_chn_1", title="Thread Page", content_md="hi")
    assert p_thr.thread_id == "thr_chn_1"
    with pytest.raises(ValidationError):
        PageCreateRequest(title="Missing target", content_md="hi")

    msg_req = MessageCreateRequest(content="Hello", page_context_id="art_123")
    assert msg_req.page_context_id == "art_123"

    sf_req = SecureFormSubmitRequest(
        action="cancel",
        fields={"user": "alice"},
        secret_name="My Vault",
    )
    assert sf_req.action == "cancel"
    assert sf_req.values == {"user": "alice"}
    assert sf_req.vault_name == "My Vault"

    app_patch = ConnectedAppPatchRequest(account_label="  prod-vm  ")
    assert app_patch.account_label == "prod-vm"

    # 2. FastAPI /api/v1/memory/* endpoints
    ws_store = WorkspaceStore(tmp_path / "mem_api.sqlite3")
    mem_store = MemoryStore(
        ws_store.db_path,
        lock=ws_store._lock,
        audit_fn=lambda conn, **kw: append_chained_audit_row(conn, **kw),
    )
    app = FastAPI()
    app.include_router(create_memory_router(mem_store))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        # POST without X-User-Id for user="alice" must be rejected (403)
        spoof_post = await client.post(
            "/api/v1/memory",
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "source_reference",
                "title": "Spoof",
                "content": "Should fail without X-User-Id: alice",
            },
        )
        assert spoof_post.status_code == 403

        # POST creates & redacts secrets for authenticated Alice
        secret_val = "sk-http-secret-token-998877"
        create_resp = await client.post(
            "/api/v1/memory",
            headers={"X-User-Id": "alice"},
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "source_reference",
                "title": "WO-2026500 Note",
                "content": f"Check WO-2026500. Do not leak {secret_val}",
            },
        )
        assert create_resp.status_code == 201
        created = create_resp.json()
        assert secret_val not in created["content"]
        assert f"redacted {len(secret_val)} chars" in created["content"]
        item_id = created["id"]

        # Seed isolated thread, project_area, agent_role, operator, and org_approved items
        op_create = await client.post(
            "/api/v1/memory",
            json={
                "scope": "user",
                "scope_id": "operator",
                "kind": "preference",
                "title": "Operator local pref",
                "content": "Local operator default workflow",
            },
        )
        assert op_create.status_code == 201
        op_id = op_create.json()["id"]

        thr_item = mem_store.create_memory(
            scope="thread",
            scope_id="thr_1",
            kind="source_reference",
            title="Thread secret",
            content="Thread thr_1 exclusive note",
        )
        proj_item = mem_store.create_memory(
            scope="project_area",
            scope_id="boiler",
            kind="source_reference",
            title="Boiler secret",
            content="Boiler exclusive note",
        )
        role_item = mem_store.create_memory(
            scope="agent_role",
            scope_id="safety_bot",
            kind="source_reference",
            title="Safety role note",
            content="Safety bot exclusive note",
        )
        org_item = mem_store.create_memory(
            scope="org_approved",
            scope_id="global",
            kind="approved_procedure",
            title="Plant SOP",
            content="Shared approved procedure",
            actor_role="Manager",
        )

        # GET /api/v1/memory with FTS5 query & cross-user SQL ACL isolation
        alice_get = await client.get(
            "/api/v1/memory",
            headers={"X-User-Id": "alice"},
            params={"q": "WO-2026500."},
        )
        assert alice_get.status_code == 200
        assert [it["id"] for it in alice_get.json()["items"]] == [item_id]

        # Cross-scope escalation probes (bob & headerless) MUST return []
        for req_headers, req_params in [
            ({"X-User-Id": "bob"}, {"scope": "user", "scope_id": "alice"}),
            ({"X-User-Id": "bob"}, {"scope": "thread", "scope_id": "thr_1"}),
            ({"X-User-Id": "bob"}, {"scope": "project_area", "scope_id": "boiler"}),
            ({"X-User-Id": "bob"}, {"scope": "agent_role", "scope_id": "safety_bot"}),
            ({}, {"scope": "user", "scope_id": "alice"}),
            ({}, {"scope": "thread", "scope_id": "thr_1"}),
            ({}, {"scope": "project_area", "scope_id": "boiler"}),
            ({}, {"scope": "agent_role", "scope_id": "safety_bot"}),
        ]:
            resp = await client.get("/api/v1/memory", headers=req_headers, params=req_params)
            assert resp.status_code == 200
            assert resp.json()["items"] == []

            exp_resp = await client.get(
                "/api/v1/memory/export",
                headers=req_headers,
                params={"format": "json", **req_params},
            )
            assert exp_resp.status_code == 200
            assert exp_resp.json()["items"] == []

        # Headerless local GET returns only operator + org_approved items
        local_get = await client.get("/api/v1/memory")
        assert local_get.status_code == 200
        local_ids = {it["id"] for it in local_get.json()["items"]}
        assert local_ids == {op_id, org_item["id"]}

        # Matching explicit headers grant access to thread / project_area / agent_role
        assert [
            it["id"]
            for it in (
                await client.get("/api/v1/memory", headers={"X-Thread-Id": "thr_1"})
            ).json()["items"]
            if it["scope"] == "thread"
        ] == [thr_item["id"]]
        assert [
            it["id"]
            for it in (
                await client.get("/api/v1/memory", headers={"X-Project-Area": "boiler"})
            ).json()["items"]
            if it["scope"] == "project_area"
        ] == [proj_item["id"]]
        assert [
            it["id"]
            for it in (
                await client.get("/api/v1/memory", headers={"X-Agent-Role": "safety_bot"})
            ).json()["items"]
            if it["scope"] == "agent_role"
        ] == [role_item["id"]]

        # 403 on untrusted approved_procedure and non-Manager role
        untrusted_resp = await client.post(
            "/api/v1/memory",
            json={
                "scope": "org_approved",
                "scope_id": "global",
                "kind": "approved_procedure",
                "title": "Bad SOP",
                "content": "Nope",
                "provenance": "untrusted",
                "actor_role": "Manager",
            },
        )
        assert untrusted_resp.status_code == 403

        op_resp = await client.post(
            "/api/v1/memory",
            json={
                "scope": "org_approved",
                "scope_id": "global",
                "kind": "approved_procedure",
                "title": "Op SOP",
                "content": "Nope",
                "actor_role": "Operator",
            },
        )
        assert op_resp.status_code == 403

        # GET /api/v1/memory/export MUST route before /{item_id}
        exp_json = await client.get(
            "/api/v1/memory/export",
            headers={"X-User-Id": "alice"},
            params={"format": "json", "scope": "user", "scope_id": "alice"},
        )
        assert exp_json.status_code == 200
        assert len(exp_json.json()["items"]) == 1

        exp_md = await client.get(
            "/api/v1/memory/export",
            headers={"X-User-Id": "alice"},
            params={"format": "md", "scope": "user", "scope_id": "alice"},
        )
        assert exp_md.status_code == 200
        assert "text/markdown" in exp_md.headers["content-type"]
        assert secret_val not in exp_md.text

        # Headerless & cross-user PATCH/DELETE on Alice's item -> 403
        for attack_headers in ({}, {"X-User-Id": "bob"}):
            p_403 = await client.patch(
                f"/api/v1/memory/{item_id}",
                headers=attack_headers,
                json={"revision": 1, "content": "Hijack"},
            )
            assert p_403.status_code == 403
            d_403 = await client.delete(
                f"/api/v1/memory/{item_id}",
                headers=attack_headers,
            )
            assert d_403.status_code == 403

        # Headerless PATCH & DELETE work for local operator item
        op_patch = await client.patch(
            f"/api/v1/memory/{op_id}",
            json={"revision": 1, "content": "Updated operator preference"},
        )
        assert op_patch.status_code == 200
        op_del = await client.delete(f"/api/v1/memory/{op_id}")
        assert op_del.status_code == 200

        # PATCH optimistic revision locking for authenticated Alice -> 200 then 409
        patch_ok = await client.patch(
            f"/api/v1/memory/{item_id}",
            headers={"X-User-Id": "alice"},
            json={"revision": 1, "content": "Check WO-2026500 updated"},
        )
        assert patch_ok.status_code == 200
        assert patch_ok.json()["revision"] == 2

        patch_409 = await client.patch(
            f"/api/v1/memory/{item_id}",
            headers={"X-User-Id": "alice"},
            json={"revision": 1, "content": "Stale"},
        )
        assert patch_409.status_code == 409

        # DELETE for authenticated Alice -> 200 then 404
        del_ok = await client.delete(
            f"/api/v1/memory/{item_id}",
            headers={"X-User-Id": "alice"},
        )
        assert del_ok.status_code == 200
        assert del_ok.json() == {"deleted": True, "id": item_id}
        del_404 = await client.delete(
            f"/api/v1/memory/{item_id}",
            headers={"X-User-Id": "alice"},
        )
        assert del_404.status_code == 404

    assert ws_store.verify_audit_chain()["valid"] is True
    mem_store.close()
    ws_store.close()


@pytest.mark.n2
def test_vault_key_whitespace_bytes_preserved_and_audit_head_hash_checked(
    tmp_path: Path,
) -> None:
    # 1. Vault 32-byte binary key starting with '\n' (0x0a) and ending with ' ' (0x20)
    db_file = tmp_path / "vault_ws_workspace.sqlite3"
    key_file = tmp_path / ".vault_ws_workspace.vault.key"
    fixed_key = b"\n" + bytes(range(1, 31)) + b" "
    assert len(fixed_key) == 32
    key_file.write_bytes(fixed_key)
    os.chmod(key_file, 0o600)

    store1 = WorkspaceStore(db_file)
    assert store1.db_path == db_file
    secret_rec = store1.create_vault_secret(
        bot_id=None,
        name="Whitespace Edge Secret",
        domain="plant.local",
        fields={"api_key": "vault-whitespace-secret"},
    )
    assert key_file.read_bytes() == fixed_key
    store1.close()

    store2 = WorkspaceStore(db_file)
    assert key_file.read_bytes() == fixed_key
    assert store2.decrypt_vault_secret(secret_rec["id"]) == {
        "api_key": "vault-whitespace-secret",
    }

    # Audit tail-replacement (same seq, validly chained from seq - 1) MUST fail head_hash_mismatch
    store2.append_audit_event(
        actor="operator",
        action="vault.create",
        entity_type="vault_secret",
        entity_id="vlt_1",
        detail={"step": 1},
    )
    store2.append_audit_event(
        actor="operator",
        action="vault.read",
        entity_type="vault_secret",
        entity_id="vlt_1",
        detail={"step": 2},
    )
    store2.append_audit_event(
        actor="operator",
        action="vault.rotate",
        entity_type="vault_secret",
        entity_id="vlt_1",
        detail={"step": 3},
    )
    assert store2.verify_audit_chain()["valid"] is True

    kv_seq = int(
        store2._conn.execute(
            "SELECT value FROM kv_meta WHERE key = 'audit_head_seq'"
        ).fetchone()[0]
    )
    store2._conn.execute("DROP TRIGGER trg_workspace_audit_log_no_delete")
    store2._conn.execute("DELETE FROM workspace_audit_log WHERE seq = ?", (kv_seq,))
    append_chained_audit_row(
        store2._conn,
        actor="attacker",
        action="vault.forged",
        entity_type="vault_secret",
        entity_id="vlt_forged",
        detail={"forged": True},
    )
    forged_check = store2.verify_audit_chain()
    assert forged_check["valid"] is False
    assert forged_check["reason"] == "head_hash_mismatch"
    assert forged_check["broken_seq"] == kv_seq
    store2.close()

    # Corrupt short vault key (0 < len < 32) MUST raise StoreValidationError, never overwrite
    bad_db = tmp_path / "bad_vault_workspace.sqlite3"
    bad_key_file = tmp_path / ".bad_vault_workspace.vault.key"
    bad_key_file.write_bytes(b"short-key-123")
    with pytest.raises(StoreValidationError, match="Corrupt vault key file"):
        WorkspaceStore(bad_db)
    assert bad_key_file.read_bytes() == b"short-key-123"


@pytest.mark.n2
async def test_memory_http_cross_scope_write_rejections_and_enclosed_redaction(
    tmp_path: Path,
) -> None:
    ws_store = WorkspaceStore(tmp_path / "mem_r3_api.sqlite3")
    mem_store = MemoryStore(
        ws_store.db_path,
        lock=ws_store._lock,
        audit_fn=lambda conn, **kw: append_chained_audit_row(conn, **kw),
    )
    app = FastAPI()
    app.include_router(create_memory_router(mem_store))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        # All 5 cross-scope POST write gaps MUST be rejected with 403
        cross_scope_attacks: list[tuple[dict[str, str], dict[str, Any]]] = [
            (
                {"X-Thread-Id": "thr_bob"},
                {
                    "scope": "user",
                    "scope_id": "operator",
                    "kind": "preference",
                    "title": "Hijack operator",
                    "content": "Thread caller cannot write user:operator",
                },
            ),
            (
                {"X-User-Id": "bob"},
                {
                    "scope": "thread",
                    "scope_id": "thr_secret",
                    "kind": "source_reference",
                    "title": "Hijack thread",
                    "content": "Missing X-Thread-Id cannot write thread:thr_secret",
                },
            ),
            (
                {"X-User-Id": "bob"},
                {
                    "scope": "project_area",
                    "scope_id": "secret_proj",
                    "kind": "source_reference",
                    "title": "Hijack project",
                    "content": "Missing X-Project-Area cannot write project_area:secret_proj",
                },
            ),
            (
                {"X-User-Id": "bob"},
                {
                    "scope": "agent_role",
                    "scope_id": "safety_bot",
                    "kind": "source_reference",
                    "title": "Hijack agent role",
                    "content": "Missing X-Agent-Role cannot write agent_role:safety_bot",
                },
            ),
            (
                {"X-User-Id": "bob"},
                {
                    "scope": "org_approved",
                    "scope_id": "global",
                    "kind": "preference",
                    "title": "Hijack org pref",
                    "content": "Non-Manager cannot write org_approved preference",
                    "actor_role": "Operator",
                },
            ),
        ]
        for hdrs, body in cross_scope_attacks:
            resp = await client.post("/api/v1/memory", headers=hdrs, json=body)
            assert resp.status_code == 403, f"Expected 403 for {hdrs} {body}: {resp.text}"

        # Matching headers succeed (201), and enclosed KV secrets are cleanly redacted (201)
        ok_thread = await client.post(
            "/api/v1/memory",
            headers={"X-Thread-Id": "thr_bob"},
            json={
                "scope": "thread",
                "scope_id": "thr_bob",
                "kind": "source_reference",
                "title": "Enclosed secret test",
                "content": (
                    "User pasted (token=abc123), [api_key=secret123], "
                    "{password=secret123}, (bearer=secret123) and Authorization: Bearer tok"
                ),
            },
        )
        assert ok_thread.status_code == 201, ok_thread.text
        created = ok_thread.json()
        for raw_secret in ("abc123", "secret123", "Bearer tok"):
            assert raw_secret not in created["content"]
        assert "(token=redacted 6 chars)" in created["content"]
        assert "[api_key=redacted 9 chars]" in created["content"]
        assert "{password=redacted 9 chars}" in created["content"]
        assert "(bearer=redacted 9 chars)" in created["content"]
        assert "Authorization: Bearer redacted 3 chars" in created["content"]

        ok_org_pref = await client.post(
            "/api/v1/memory",
            headers={"X-User-Id": "mgr_alice", "X-Actor-Role": "Manager"},
            json={
                "scope": "org_approved",
                "scope_id": "global",
                "kind": "preference",
                "title": "Org formatting standard",
                "content": "Use ISO dates everywhere.",
            },
        )
        assert ok_org_pref.status_code == 201, ok_org_pref.text

        # Non-Manager (Operator & headerless) MUST receive 403 on PATCH & DELETE
        # for ALL org_approved kinds (preference, dated_observation, source_reference)
        org_items_to_test: list[dict[str, Any]] = [ok_org_pref.json()]
        for kind_name, extra_fields in (
            (
                "dated_observation",
                {
                    "observed_at": "2026-11-26T00:00:00Z",
                    "valid_until": "2099-01-01T00:00:00Z",
                },
            ),
            ("source_reference", {}),
        ):
            r_seed = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "mgr_alice", "X-Actor-Role": "Manager"},
                json={
                    "scope": "org_approved",
                    "scope_id": "global",
                    "kind": kind_name,
                    "title": f"Org {kind_name}",
                    "content": f"Baseline {kind_name}",
                    **extra_fields,
                },
            )
            assert r_seed.status_code == 201, r_seed.text
            org_items_to_test.append(r_seed.json())

        for org_obj in org_items_to_test:
            oid = org_obj["id"]
            for bad_headers in (
                {"X-User-Id": "bob", "X-Actor-Role": "Operator"},
                {"X-User-Id": "bob"},
                {},
            ):
                p_403 = await client.patch(
                    f"/api/v1/memory/{oid}",
                    headers=bad_headers,
                    json={"revision": 1, "content": "HIJACKED"},
                )
                assert p_403.status_code == 403, (
                    f"Expected 403 PATCH {org_obj['kind']}: {p_403.text}"
                )
                d_403 = await client.delete(f"/api/v1/memory/{oid}", headers=bad_headers)
                assert d_403.status_code == 403, (
                    f"Expected 403 DELETE {org_obj['kind']}: {d_403.text}"
                )

            p_200 = await client.patch(
                f"/api/v1/memory/{oid}",
                headers={"X-User-Id": "mgr_alice", "X-Actor-Role": "Manager"},
                json={"revision": 1, "content": "Approved Manager update"},
            )
            assert p_200.status_code == 200, p_200.text
            assert p_200.json()["revision"] == 2

            d_200 = await client.delete(
                f"/api/v1/memory/{oid}",
                headers={"X-User-Id": "mgr_alice", "X-Actor-Role": "Manager"},
            )
            assert d_200.status_code == 200, d_200.text

        # Authorization=Bearer/Basic, delimiter preservation, and crafted bypasses via HTTP
        for raw_content, expected_substr, forbidden in (
            (
                "Authorization=Bearer tok",
                "Authorization=redacted 6 chars redacted 3 chars",
                "tok",
            ),
            (
                "authorization=Basic dXNlcjpwYXNz",
                "authorization=redacted 5 chars redacted 12 chars",
                "dXNlcjpwYXNz",
            ),
            (
                "(Authorization: Bearer tok)",
                "(Authorization: Bearer redacted 3 chars)",
                "tok",
            ),
            (
                '{"Authorization": "Bearer tok"}',
                '{"Authorization": "Bearer redacted 3 chars"}',
                "tok",
            ),
        ):
            r_auth = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": "Auth redaction test",
                    "content": raw_content,
                },
            )
            assert r_auth.status_code == 201, r_auth.text
            body_content = r_auth.json()["content"]
            assert expected_substr in body_content
            assert forbidden not in body_content

        for crafted in (
            "token=redacted 6 chars_REAL_SECRET",
            "Authorization: Bearer redacted 3 chars_REAL_SECRET",
            "token=redacted 6 chars)REAL_SECRET",
            "Bearer redacted 3 chars)REAL_SECRET",
            "token=redacted 6 chars))REAL_SECRET",
            "token=redacted 6 chars)]REAL_SECRET",
            "token=redacted 6 chars)}REAL_SECRET",
            'token=redacted 6 chars)"REAL_SECRET',
            "token=redacted 6 chars)'REAL_SECRET",
            "token=redacted 6 chars),REAL_SECRET",
            "Bearer redacted 3 chars))REAL_SECRET",
            "Authorization: Bearer redacted 3 chars))REAL_SECRET",
            "token=[REDACTED]))REAL_SECRET",
            "Bearer [REDACTED]))REAL_SECRET",
            "Bearer [REDACTED],REAL_SECRET",
            "Authorization: Bearer redacted 3 chars,REAL_SECRET",
            "Authorization: Bearer [REDACTED];REAL_SECRET",
        ):
            r_crafted = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": "Crafted secret bypass test",
                    "content": crafted,
                },
            )
            assert r_crafted.status_code in {201, 422}, r_crafted.text
            if r_crafted.status_code == 201:
                body = r_crafted.json()["content"]
                assert "REAL_SECRET" not in body
                assert "]," not in body and "];" not in body

        # JSON KV secrets, quoted Bearer, enclosures, and directives via HTTP
        http_redaction_cases: tuple[tuple[str, str, tuple[str, ...]], ...] = (
            ('{"token": "REAL_SECRET"}', '{"token": "redacted 11 chars"}', ("REAL_SECRET",)),
            ('{"api_key": "REAL_SECRET"}', '{"api_key": "redacted 11 chars"}', ("REAL_SECRET",)),
            ('{"password": "REAL_SECRET"}', '{"password": "redacted 11 chars"}', ("REAL_SECRET",)),
            (
                '{"Authorization": "rawsecret123"}',
                '{"Authorization": "redacted 12 chars"}',
                ("rawsecret123",),
            ),
            (
                '{"token": "REAL_SECRET", "next": "ok"}',
                '{"token": "redacted 11 chars", "next": "ok"}',
                ("REAL_SECRET",),
            ),
            (
                'Authorization: Bearer "REAL_SECRET"',
                'Authorization: Bearer "redacted 11 chars"',
                ("REAL_SECRET",),
            ),
            (
                "Authorization: Bearer 'REAL_SECRET'",
                "Authorization: Bearer 'redacted 11 chars'",
                ("REAL_SECRET",),
            ),
            ("((token=abc123))", "((token=redacted 6 chars))", ("abc123",)),
            (
                "[(Authorization: Bearer tok)]",
                "[(Authorization: Bearer redacted 3 chars)]",
                ("tok",),
            ),
            ("Bearer tok, next", "Bearer redacted 3 chars, next", ("tok",)),
            ("Bearer tok;realm=foo", "Bearer redacted 3 chars;realm=foo", ("tok",)),
            (
                "https://api.local/hook?api_key=secret123&mode=fast",
                "https://api.local/hook?api_key=redacted 9 chars&mode=fast",
                ("secret123",),
            ),
        )
        for raw_content, expected_content, forbidden_tokens in http_redaction_cases:
            r_json = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": "R5 redaction HTTP test",
                    "content": raw_content,
                },
            )
            assert r_json.status_code == 201, r_json.text
            saved_content = r_json.json()["content"]
            assert saved_content == expected_content
            for bad in forbidden_tokens:
                assert bad not in saved_content

        # R6 adversarial bypasses via HTTP POST /api/v1/memory (zero leaks & idempotent)
        r6_http_leak_cases: tuple[str, ...] = (
            'Bearer redacted 3 chars,"REAL_SECRET"',
            "Bearer redacted 3 chars,'REAL_SECRET'",
            'Bearer redacted 3 chars;"REAL_SECRET"',
            "Bearer redacted 3 chars,}REAL_SECRET",
            'token=redacted 6 chars,"REAL_SECRET"',
            'Bearer [REDACTED],"REAL_SECRET"',
            'token=[REDACTED],"REAL_SECRET"',
        )
        for raw_content in r6_http_leak_cases:
            r_r6 = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": "R6 unquoted tail HTTP test",
                    "content": raw_content,
                },
            )
            assert r_r6.status_code == 201, r_r6.text
            saved = r_r6.json()["content"]
            assert "REAL_SECRET" not in saved, f"Leaked on {raw_content!r}: {saved!r}"

        r6_http_exact_cases: tuple[tuple[str, str, tuple[str, ...]], ...] = (
            (
                '{"credentials": {"note": "REAL_SECRET"}}',
                '{"credentials": {"note": "redacted 11 chars"}}',
                ("REAL_SECRET",),
            ),
            (
                '{"credentials": ["REAL_SECRET", "SECOND_SECRET"]}',
                '{"credentials": ["redacted 11 chars", "redacted 13 chars"]}',
                ("REAL_SECRET", "SECOND_SECRET"),
            ),
            (
                '{"token": ["REAL_SECRET", "SECOND_SECRET"]}',
                '{"token": ["redacted 11 chars", "redacted 13 chars"]}',
                ("REAL_SECRET", "SECOND_SECRET"),
            ),
            (
                '{"authorization": {"raw": "REAL_SECRET"}}',
                '{"authorization": {"raw": "redacted 11 chars"}}',
                ("REAL_SECRET",),
            ),
            (
                '{"token": "abc\\" REAL_SECRET"}',
                '{"token": "redacted 17 chars"}',
                ("REAL_SECRET",),
            ),
            (
                '{"Authorization": "Bearer \\"REAL_SECRET\\""}',
                '{"Authorization": "Bearer \\"redacted 11 chars\\""}',
                ("REAL_SECRET",),
            ),
            (
                '{"note": "Bearer \\"REAL_SECRET\\""}',
                '{"note": "Bearer \\"redacted 11 chars\\""}',
                ("REAL_SECRET",),
            ),
            (
                '{"Authorization": "Bearer \\"[REDACTED]\\""}',
                '{"Authorization": "Bearer \\"redacted 10 chars\\""}',
                ("[REDACTED]",),
            ),
            (
                'token="REAL_SECRET",SECOND_SECRET',
                "token=redacted 27 chars",
                ("REAL_SECRET", "SECOND_SECRET"),
            ),
            (
                "token='REAL_SECRET';SECOND_SECRET",
                "token=redacted 27 chars",
                ("REAL_SECRET", "SECOND_SECRET"),
            ),
            (
                '{"auth":"Bearer tok","a":1}',
                '{"auth":"Bearer redacted 3 chars","a":1}',
                ("tok",),
            ),
        )
        for raw_content, expected_content, forbidden_tokens in r6_http_exact_cases:
            r_r6_exact = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": "R6 exact redaction HTTP test",
                    "content": raw_content,
                },
            )
            assert r_r6_exact.status_code == 201, r_r6_exact.text
            saved_content = r_r6_exact.json()["content"]
            assert saved_content == expected_content
            for bad in forbidden_tokens:
                assert bad not in saved_content

    assert ws_store.verify_audit_chain()["valid"] is True
    mem_store.close()
    ws_store.close()


@pytest.mark.n2
@pytest.mark.asyncio
async def test_memory_http_r7_redaction_post_patch_export_roundtrip(tmp_path: Path) -> None:
    ws_store = WorkspaceStore(tmp_path / "r7_http.sqlite3")
    mem_store = MemoryStore(
        ws_store.db_path,
        lock=ws_store._lock,
        audit_fn=lambda conn, **kw: append_chained_audit_row(conn, **kw),
    )
    app = FastAPI()
    app.include_router(create_memory_router(mem_store))

    post_cases: tuple[str, ...] = (
        'token=[REDACTED]{"a": "REAL_SECRET"}',
        'token=abc{"a": "REAL_SECRET"}',
        'Bearer [REDACTED]{"a": "REAL_SECRET"}',
        'Authorization: Bearer [REDACTED]{"a": "REAL_SECRET"}',
        'Bearer redacted 3 chars" REAL_SECRET',
        'Bearer redacted 3 chars","a":"REAL_SECRET"',
        '{\n  "token": [\n    "REAL_SECRET",\n    "SECOND_SECRET"\n',
        'credentials=[\n  "REAL_SECRET"\n',
        json.dumps({"outer": json.dumps({"credentials": {"note": "REAL_SECRET"}})}),
        '{"note": "{\\"Authorization\\": \\"Bearer \\\\\\"REAL_SECRET\\\\\\"\\"}"}',
        json.dumps({"note": 'Bearer "abc\\" REAL_SECRET"'}),
        r'Authorization: Bearer \"abc\\\" REAL_SECRET\"',
        r'Bearer \"REAL_SECRET,SECOND_SECRET',
        r'token=\"REAL_SECRET,SECOND_SECRET',
        'token={"a": "REAL_SECRET"}',
        'token=["REAL_SECRET", "SECOND_SECRET"]',
        'token={"a": "REAL_SECRET"}, next=ok',
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        stored_by_id: dict[str, str] = {}
        for idx, raw_content in enumerate(post_cases):
            resp = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": f"R7 HTTP post {idx}",
                    "content": raw_content,
                },
            )
            assert resp.status_code == 201, f"Expected 201 on {raw_content!r}: {resp.text}"
            body = resp.json()
            assert "REAL_SECRET" not in body["content"]
            assert "SECOND_SECRET" not in body["content"]
            stored_by_id[body["id"]] = body["content"]
            if raw_content == 'token={"a": "REAL_SECRET"}':
                assert body["content"] == 'token={"a": "redacted 11 chars"}'

        # Preserved clean JSON cases must return 201 untouched
        for clean_raw in (
            '{"note": "token=redacted 6 chars"}',
            '{"note": "token=redacted 6 chars", "a": 1}',
            '{"note": "Bearer redacted 3 chars", "a": 1}',
        ):
            r_clean = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": "R7 clean preserve",
                    "content": clean_raw,
                },
            )
            assert r_clean.status_code == 201, r_clean.text
            assert r_clean.json()["content"] == clean_raw
            stored_by_id[r_clean.json()["id"]] = clean_raw

        # PATCH /api/v1/memory/{item_id} on R6 bypasses + token={"a": "REAL_SECRET"}
        patch_seed = await client.post(
            "/api/v1/memory",
            headers={"X-User-Id": "alice"},
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "source_reference",
                "title": "R7 patch target",
                "content": "Initial clean content",
            },
        )
        assert patch_seed.status_code == 201, patch_seed.text
        patch_id = patch_seed.json()["id"]
        patch_rev = patch_seed.json()["revision"]
        for patch_raw in (
            'Bearer redacted 3 chars" REAL_SECRET',
            '{\n  "credentials": {\n    "note": "REAL_SECRET"\n',
            json.dumps({"note": 'Bearer "abc\\" REAL_SECRET"'}),
            r'token=\"REAL_SECRET,SECOND_SECRET',
            'token={"a": "REAL_SECRET"}',
        ):
            r_patch = await client.patch(
                f"/api/v1/memory/{patch_id}",
                headers={"X-User-Id": "alice"},
                json={"revision": patch_rev, "content": patch_raw},
            )
            assert r_patch.status_code == 200, f"Expected 200 on {patch_raw!r}: {r_patch.text}"
            p_body = r_patch.json()
            patch_rev = p_body["revision"]
            assert "REAL_SECRET" not in p_body["content"]
            assert "SECOND_SECRET" not in p_body["content"]
            stored_by_id[patch_id] = p_body["content"]
        assert patch_rev == 6
        assert stored_by_id[patch_id] == 'token={"a": "redacted 11 chars"}'

        # GET /api/v1/memory/export?format=json & format=md must succeed (200) and be idempotent
        exp_json = await client.get(
            "/api/v1/memory/export?format=json&scope=user&scope_id=alice",
            headers={"X-User-Id": "alice"},
        )
        assert exp_json.status_code == 200, exp_json.text
        exp_items = {item["id"]: item["content"] for item in exp_json.json()["items"]}
        assert exp_items == stored_by_id
        for exported_val in exp_items.values():
            assert "REAL_SECRET" not in exported_val
            assert "SECOND_SECRET" not in exported_val

        exp_md = await client.get(
            "/api/v1/memory/export?format=md&scope=user&scope_id=alice",
            headers={"X-User-Id": "alice"},
        )
        assert exp_md.status_code == 200, exp_md.text
        assert "REAL_SECRET" not in exp_md.text
        assert "SECOND_SECRET" not in exp_md.text
        assert 'token={"a": "redacted 11 chars"}' in exp_md.text

        # FTS5 search must find zero unredacted secrets
        for q_secret in ("REAL_SECRET", "SECOND_SECRET"):
            q_resp = await client.get(
                f"/api/v1/memory?q={q_secret}",
                headers={"X-User-Id": "alice"},
            )
            assert q_resp.status_code == 200, q_resp.text
            assert q_resp.json()["items"] == []

    assert ws_store.verify_audit_chain()["valid"] is True
    mem_store.close()
    ws_store.close()


@pytest.mark.n2
@pytest.mark.asyncio
async def test_memory_http_r8_redaction_scalars_keys_quotes_and_redos_roundtrip(
    tmp_path: Path,
) -> None:
    ws_store = WorkspaceStore(tmp_path / "r8_http.sqlite3")
    mem_store = MemoryStore(
        ws_store.db_path,
        lock=ws_store._lock,
        audit_fn=lambda conn, **kw: append_chained_audit_row(conn, **kw),
    )
    app = FastAPI()
    app.include_router(create_memory_router(mem_store))

    exact_post_cases: tuple[tuple[str, str | None, tuple[str, ...]], ...] = (
        # Violation 1
        (
            'token={"a": "REAL_SECRET"} token=SECOND_SECRET',
            'token={"a": "redacted 11 chars"} token=redacted 13 chars',
            ("REAL_SECRET", "SECOND_SECRET"),
        ),
        # Violation 2
        (
            'token={"Authorization": "Bearer REAL_SECRET"}',
            'token={"Authorization": "Bearer redacted 11 chars"}',
            ("REAL_SECRET",),
        ),
        (
            'credentials={"Authorization": "Basic REAL_SECRET"}',
            'credentials={"Authorization": "Basic redacted 11 chars"}',
            ("REAL_SECRET",),
        ),
        (
            'token=[{"Authorization": "Bearer REAL_SECRET"}]',
            'token=[{"Authorization": "Bearer redacted 11 chars"}]',
            ("REAL_SECRET",),
        ),
        # Violation 3 & Challenger Bug 1
        (
            json.dumps({"note": 'token="REAL_SECRET"'}),
            '{"note": "token=\\"redacted 11 chars\\""}',
            ("REAL_SECRET",),
        ),
        (
            json.dumps({"note": 'token="abc\\" REAL_SECRET"'}),
            '{"note": "token=\\"redacted 17 chars\\""}',
            ("REAL_SECRET",),
        ),
        (
            r'token=\\\"abc\\\\\\\" REAL_SECRET\\\"',
            None,
            ("REAL_SECRET",),
        ),
        # Reviewer Finding 1
        (
            json.dumps({"note": 'Authorization: "Bearer REAL_SECRET"'}),
            '{"note": "Authorization: \\"Bearer redacted 11 chars\\""}',
            ("REAL_SECRET",),
        ),
        (
            r'Authorization: \"Bearer REAL_SECRET\"',
            r'Authorization: \"Bearer redacted 11 chars\"',
            ("REAL_SECRET",),
        ),
        (
            r'Authorization: \"Basic dXNlcjpwYXNz\"',
            r'Authorization: \"Basic redacted 12 chars\"',
            ("dXNlcjpwYXNz",),
        ),
        # Reviewer Finding 2
        ('{"token": 123456}', '{"token": "redacted 6 chars"}', ("123456",)),
        ('token={"pin": 4321}', 'token={"pin": "redacted 4 chars"}', ("4321",)),
        ('password=[123456]', 'password=["redacted 6 chars"]', ("123456",)),
        (
            '{"credentials": [123456, "REAL_SECRET"]}',
            '{"credentials": ["redacted 6 chars", "redacted 11 chars"]}',
            ("123456", "REAL_SECRET"),
        ),
        (
            '{"token": {"nested": {"pin": 9876}}}',
            '{"token": {"nested": {"pin": "redacted 4 chars"}}}',
            ("9876",),
        ),
        ('{"token": null}', '{"token": null}', ()),
        # Auditor Violation 4
        (
            '{"Bearer MY_SECRET": 1}',
            '{"Bearer redacted 9 chars": "redacted 1 chars"}',
            ("MY_SECRET",),
        ),
        (
            '{"token=MY_SECRET": 1}',
            '{"token=redacted 9 chars": "redacted 1 chars"}',
            ("MY_SECRET",),
        ),
        (
            '{"token=MY_SECRET": "REAL_SECRET"}',
            '{"token=redacted 9 chars": "redacted 11 chars"}',
            ("MY_SECRET", "REAL_SECRET"),
        ),
        # Challenger Bug 4 + Reviewer Finding 3 + outer-quote leak
        ('"a"token=redacted 6 chars" REAL_SECRET', None, ("REAL_SECRET",)),
        ('"a"Bearer redacted 3 chars" REAL_SECRET', None, ("REAL_SECRET",)),
        ('foo"token=redacted 6 chars" REAL_SECRET', None, ("REAL_SECRET",)),
        ('1"Bearer redacted 3 chars" REAL_SECRET', None, ("REAL_SECRET",)),
        ('Bearer \\"redacted 3 chars\\"" REAL_SECRET', None, ("REAL_SECRET",)),
        # Reviewer Finding 4
        (
            r'Authorization: \"Bearer \\\"abc\\\\\\\" REAL_SECRET\\\"\"',
            r'Authorization: \"Bearer \\\"redacted 23 chars\\\"\"',
            ("REAL_SECRET",),
        ),
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        stored_by_id: dict[str, str] = {}
        for idx, (raw_content, expected_content, forbidden) in enumerate(exact_post_cases):
            resp = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": f"R8 HTTP post {idx}",
                    "content": raw_content,
                },
            )
            assert resp.status_code == 201, f"Expected 201 on {raw_content!r}: {resp.text}"
            body = resp.json()
            if expected_content is not None:
                assert body["content"] == expected_content
            for bad in forbidden:
                assert bad not in body["content"], f"Leaked {bad!r} on {raw_content!r}"
            stored_by_id[body["id"]] = body["content"]

        # PATCH roundtrip on R8 scalar & nested auth payloads
        patch_seed = await client.post(
            "/api/v1/memory",
            headers={"X-User-Id": "alice"},
            json={
                "scope": "user",
                "scope_id": "alice",
                "kind": "source_reference",
                "title": "R8 patch target",
                "content": "Initial clean content",
            },
        )
        assert patch_seed.status_code == 201, patch_seed.text
        patch_id = patch_seed.json()["id"]
        patch_rev = patch_seed.json()["revision"]
        for patch_raw, patch_expected in (
            ('{"token": 123456}', '{"token": "redacted 6 chars"}'),
            (
                'token={"Authorization": "Bearer REAL_SECRET"}',
                'token={"Authorization": "Bearer redacted 11 chars"}',
            ),
            (
                json.dumps({"note": 'Authorization: "Bearer REAL_SECRET"'}),
                '{"note": "Authorization: \\"Bearer redacted 11 chars\\""}',
            ),
        ):
            r_patch = await client.patch(
                f"/api/v1/memory/{patch_id}",
                headers={"X-User-Id": "alice"},
                json={"revision": patch_rev, "content": patch_raw},
            )
            assert r_patch.status_code == 200, r_patch.text
            p_body = r_patch.json()
            patch_rev = p_body["revision"]
            assert p_body["content"] == patch_expected
            stored_by_id[patch_id] = p_body["content"]

        # ReDoS HTTP end-to-end latency < 0.5s per payload
        for redos_raw in ("a-" * 5000, '[{"a":1},' * 2000 + "bad]", "[" * 5000 + "]"):
            t0 = time.perf_counter()
            r_redos = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": "R8 ReDoS latency check",
                    "content": redos_raw,
                },
            )
            elapsed = time.perf_counter() - t0
            assert r_redos.status_code == 201, r_redos.text
            assert elapsed < 0.5, f"HTTP POST too slow ({elapsed:.3f}s)"
            stored_by_id[r_redos.json()["id"]] = r_redos.json()["content"]

        # FTS5 search must find zero scrubbed secrets or numeric/boolean secret values
        for q_secret in ("REAL_SECRET", "SECOND_SECRET", "MY_SECRET", "123456", "4321", "9876"):
            q_resp = await client.get(
                f"/api/v1/memory?q={q_secret}",
                headers={"X-User-Id": "alice"},
            )
            assert q_resp.status_code == 200, q_resp.text
            assert q_resp.json()["items"] == [], f"FTS5 matched {q_secret!r}"

        # Export JSON & MD must return 200 cleanly and match stored redacted items
        t_exp = time.perf_counter()
        exp_json = await client.get(
            "/api/v1/memory/export?format=json&scope=user&scope_id=alice",
            headers={"X-User-Id": "alice"},
        )
        assert exp_json.status_code == 200, exp_json.text
        assert time.perf_counter() - t_exp < 0.5
        exp_items = {item["id"]: item["content"] for item in exp_json.json()["items"]}
        assert exp_items == stored_by_id

        exp_md = await client.get(
            "/api/v1/memory/export?format=md&scope=user&scope_id=alice",
            headers={"X-User-Id": "alice"},
        )
        assert exp_md.status_code == 200, exp_md.text
        for bad in ("REAL_SECRET", "SECOND_SECRET", "MY_SECRET", "123456", "4321", "9876"):
            assert bad not in exp_md.text

    assert ws_store.verify_audit_chain()["valid"] is True
    mem_store.close()
    ws_store.close()


@pytest.mark.n2
@pytest.mark.asyncio
async def test_memory_http_r9_parity_url_redos_and_escaped_quote_enclosure_roundtrip(
    tmp_path: Path,
) -> None:
    ws_store = WorkspaceStore(tmp_path / "r9_http.sqlite3")
    mem_store = MemoryStore(
        ws_store.db_path,
        lock=ws_store._lock,
        audit_fn=lambda conn, **kw: append_chained_audit_row(conn, **kw),
    )
    app = FastAPI()
    app.include_router(create_memory_router(mem_store))

    post_cases: tuple[tuple[str, str | None, tuple[str, ...]], ...] = (
        # Parity cases (Auditor Defect 2, Reviewer F1, Challenger B2)
        ("A" * 16 + ".a" + "A" * 130 + "Token=REAL_SECRET", None, ("REAL_SECRET",)),
        (
            "-" * 130 + "A" * 60 + "Password=REAL_SECRET",
            "-" * 130 + "A" * 60 + "Password=REAL_SECRET",
            (),
        ),
        (
            "a" * 70 + "-" + "A" * 70 + "Password=REAL_SECRET",
            "a" * 70 + "-" + "A" * 70 + "Password=REAL_SECRET",
            (),
        ),
        (
            "a" + "B" * 70 + "-" + "C" * 60 + "Token=123",
            "a" + "B" * 70 + "-" + "C" * 60 + "Token=123",
            (),
        ),
        (
            "a" + "B" * 70 + "." + "C" * 60 + "ApiKey=123",
            "a" + "B" * 70 + "." + "C" * 60 + "ApiKey=123",
            (),
        ),
        # Reviewer R8 Finding 2 positive cases
        (r'\"token=redacted 6 chars\"', r'\"token=redacted 6 chars\"', ()),
        (
            json.dumps({"note": r'\"token=redacted 6 chars\"'}),
            json.dumps({"note": r'\"token=redacted 6 chars\"'}),
            (),
        ),
        (r'"\"token=redacted 6 chars\""', r'"\"token=redacted 6 chars\""', ()),
        (r'\"token=REAL_SECRET\"', r'\"token=redacted 11 chars\"', ("REAL_SECRET",)),
        (r'\"Bearer REAL_SECRET\"', r'\"Bearer redacted 11 chars\"', ("REAL_SECRET",)),
        (
            r'\"token=\\\"REAL_SECRET\\\"\"',
            r'\"token=\\\"redacted 11 chars\\\"\"',
            ("REAL_SECRET",),
        ),
        (
            r'\"token=redacted 6 chars\" REAL_SECRET',
            r'\"token=redacted 6 chars\" REAL_SECRET',
            (),
        ),
        # Reviewer R8 Finding 2 contrast fail-closed cases
        ('Bearer \\"redacted 3 chars\\"" REAL_SECRET', None, ("REAL_SECRET",)),
        ('token=\\"redacted 6 chars\\"" REAL_SECRET', None, ("REAL_SECRET",)),
        (r'\"a\"token=redacted 6 chars\" REAL_SECRET', None, ("REAL_SECRET",)),
    )

    latency_cases: tuple[tuple[str, tuple[str, ...]], ...] = (
        ('[{"a":1},' * 2000 + "bad]", ()),
        ('[{"a":1},' * 2000 + "bad]", ()),
        ('[{"a":1},' * 2000 + "token=REAL_SECRET]", ("REAL_SECRET",)),
        ('[{"a":1},' * 2000 + '{"token":"REAL_SECRET"}]', ("REAL_SECRET",)),
        ("https://" + "a+" * 15000, ()),
        ("a+" * 13000 + "://" + "x" * 5000, ()),
        ("a+" * 15000 + "://" + "@", ()),
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        stored_by_id: dict[str, str] = {}
        for idx, (raw_content, expected_content, forbidden) in enumerate(post_cases):
            resp = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": f"R9 HTTP post {idx}",
                    "content": raw_content,
                },
            )
            assert resp.status_code == 201, f"Expected 201 on {raw_content!r}: {resp.text}"
            body = resp.json()
            if expected_content is not None:
                assert body["content"] == expected_content
            for bad in forbidden:
                assert bad not in body["content"], f"Leaked {bad!r} on {raw_content!r}"
            stored_by_id[body["id"]] = body["content"]

        for idx, (raw_content, forbidden) in enumerate(latency_cases):
            t0 = time.perf_counter()
            resp = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": f"R9 latency post {idx}",
                    "content": raw_content,
                },
            )
            elapsed = time.perf_counter() - t0
            assert resp.status_code == 201, resp.text
            assert elapsed < 0.5, f"HTTP POST too slow ({elapsed:.3f}s) on idx={idx}"
            body = resp.json()
            for bad in forbidden:
                assert bad not in body["content"]
            stored_by_id[body["id"]] = body["content"]

        q_resp = await client.get(
            "/api/v1/memory?q=REAL_SECRET",
            headers={"X-User-Id": "alice"},
        )
        assert q_resp.status_code == 200, q_resp.text
        # Only non-secret Password=REAL_SECRET and intentionally preserved contrast items?
        # Wait: verify NONE of the scrubbed items leak REAL_SECRET via FTS5.
        returned_ids = {item["id"] for item in q_resp.json()["items"]}
        for item_id, stored_content in stored_by_id.items():
            if "REAL_SECRET" not in stored_content:
                assert item_id not in returned_ids

        exp_json = await client.get(
            "/api/v1/memory/export?format=json&scope=user&scope_id=alice",
            headers={"X-User-Id": "alice"},
        )
        assert exp_json.status_code == 200, exp_json.text
        exp_items = {item["id"]: item["content"] for item in exp_json.json()["items"]}
        assert exp_items == stored_by_id

        exp_md = await client.get(
            "/api/v1/memory/export?format=md&scope=user&scope_id=alice",
            headers={"X-User-Id": "alice"},
        )
        assert exp_md.status_code == 200, exp_md.text
        assert r'\"token=redacted 11 chars\"' in exp_md.text
        assert r'\"Bearer redacted 11 chars\"' in exp_md.text

    assert ws_store.verify_audit_chain()["valid"] is True
    mem_store.close()
    ws_store.close()


@pytest.mark.n2
@pytest.mark.asyncio
async def test_memory_http_r10_dos_unicode_auth_json_in_json_and_parens_roundtrip(
    tmp_path: Path,
) -> None:
    ws_store = WorkspaceStore(tmp_path / "r10_http.sqlite3")
    mem_store = MemoryStore(
        ws_store.db_path,
        lock=ws_store._lock,
        audit_fn=lambda conn, **kw: append_chained_audit_row(conn, **kw),
    )
    app = FastAPI()
    app.include_router(create_memory_router(mem_store))

    post_cases: tuple[tuple[str, str | None, tuple[str, ...]], ...] = (
        # Bug 3: Unicode case-folding secrets
        ("setCookie\u017fsession_token=BASICsecret", None, ("BASICsecret",)),
        ("a\u017fb_token=REAL_SECRET", None, ("REAL_SECRET",)),
        ("a\u212ab_token=REAL_SECRET", None, ("REAL_SECRET",)),
        ("x-\u017f_token=REAL_SECRET", None, ("REAL_SECRET",)),
        ("\u017fecret=REAL_SECRET", None, ("REAL_SECRET",)),
        ("ba\u017fic REAL_SECRET", None, ("REAL_SECRET",)),
        # Bug 4: quoted Authorization: Bearer, nested JSON-in-JSON, quoted (token=...)
        (
            r'\"Authorization: Bearer REAL_SECRET\"',
            r'\"Authorization: Bearer redacted 11 chars\"',
            ("REAL_SECRET",),
        ),
        (
            r'"Authorization: Bearer REAL_SECRET"',
            r'"Authorization: Bearer redacted 11 chars"',
            ("REAL_SECRET",),
        ),
        (
            r'\"Authorization: Bearer redacted 11 chars\"',
            r'\"Authorization: Bearer redacted 11 chars\"',
            (),
        ),
        ('{"note": "{\\"Bearer x\\": 1}"}', '{"note": "{\\"Bearer redacted 1 chars\\": 1}"}', ()),
        ('{"note": "{\\"Basic x\\": 1}"}', '{"note": "{\\"Basic redacted 1 chars\\": 1}"}', ()),
        ('{"note": "{\\"token=x\\": 1}"}', '{"note": "{\\"token=redacted 1 chars\\": 1}"}', ()),
        ('{"{\\"Bearer x\\": 1}": 1}', '{"{\\"Bearer redacted 1 chars\\": 1}": 1}', ()),
        ('{"{\\"Basic x\\": 1}": 1}', '{"{\\"Basic redacted 1 chars\\": 1}": 1}', ()),
        (r'\"(token=REAL_SECRET)\"', r'\"(token=redacted 11 chars)\"', ("REAL_SECRET",)),
        (r'\"(token=redacted 6 chars)\"', r'\"(token=redacted 6 chars)\"', ()),
        (r'"(token=redacted 6 chars)"', r'"(token=redacted 6 chars)"', ()),
    )

    latency_cases: tuple[tuple[str, tuple[str, ...]], ...] = (
        ('[{"note":"token=1"},' * 1500 + "bad]", ()),
        (r'\"token=redacted 6 chars\" ' * 1100, ()),
        (r'\"Bearer redacted 6 chars\" ' * 1000, ()),
        ("a=" * 15000, ()),
        ('[{"token":"1"},' * 2000 + "bad]", ()),
        ("token=1 " * 2000, ()),
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        stored_by_id: dict[str, str] = {}
        for idx, (raw_content, expected_content, forbidden) in enumerate(post_cases):
            resp = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": f"R10 HTTP post {idx}",
                    "content": raw_content,
                },
            )
            assert resp.status_code == 201, f"Expected 201 on {raw_content!r}: {resp.text}"
            body = resp.json()
            if expected_content is not None:
                assert body["content"] == expected_content
            for bad in forbidden:
                assert bad not in body["content"], f"Leaked {bad!r} on {raw_content!r}"
            stored_by_id[body["id"]] = body["content"]

        for idx, (raw_content, forbidden) in enumerate(latency_cases):
            t0 = time.perf_counter()
            resp = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": f"R10 latency post {idx}",
                    "content": raw_content,
                },
            )
            elapsed = time.perf_counter() - t0
            assert resp.status_code == 201, resp.text
            assert elapsed < 0.5, f"HTTP POST too slow ({elapsed:.3f}s) on idx={idx}"
            body = resp.json()
            for bad in forbidden:
                assert bad not in body["content"]
            stored_by_id[body["id"]] = body["content"]

        for q_secret in ("REAL_SECRET", "BASICsecret"):
            q_resp = await client.get(
                f"/api/v1/memory?q={q_secret}",
                headers={"X-User-Id": "alice"},
            )
            assert q_resp.status_code == 200, q_resp.text
            assert q_resp.json()["items"] == []

        exp_json = await client.get(
            "/api/v1/memory/export?format=json&scope=user&scope_id=alice",
            headers={"X-User-Id": "alice"},
        )
        assert exp_json.status_code == 200, exp_json.text
        exp_items = {item["id"]: item["content"] for item in exp_json.json()["items"]}
        assert exp_items == stored_by_id
        for val in exp_items.values():
            assert "REAL_SECRET" not in val
            assert "BASICsecret" not in val

        exp_md = await client.get(
            "/api/v1/memory/export?format=md&scope=user&scope_id=alice",
            headers={"X-User-Id": "alice"},
        )
        assert exp_md.status_code == 200, exp_md.text
        assert "REAL_SECRET" not in exp_md.text
        assert "BASICsecret" not in exp_md.text

    assert ws_store.verify_audit_chain()["valid"] is True
    mem_store.close()
    ws_store.close()


@pytest.mark.n2
@pytest.mark.asyncio
async def test_memory_http_r11_json_in_json_values_arrays_and_skip_step0_roundtrip(
    tmp_path: Path,
) -> None:
    ws_store = WorkspaceStore(tmp_path / "r11_http.sqlite3")
    mem_store = MemoryStore(
        ws_store.db_path,
        lock=ws_store._lock,
        audit_fn=lambda conn, **kw: append_chained_audit_row(conn, **kw),
    )
    app = FastAPI()
    app.include_router(create_memory_router(mem_store))

    post_cases: tuple[tuple[str, tuple[str, ...]], ...] = (
        # Bug 1: nested JSON-in-JSON string values, array items, and quoted key=value
        ('{"note": "{\\"a\\": \\"token=REAL_SECRET\\"}"}', ("REAL_SECRET",)),
        ('{"note": "{\\"a\\": \\"token=redacted 11 chars\\"}"}', ("REAL_SECRET",)),
        ('{"note": "{\\"a\\": [\\"token=REAL_SECRET\\"]}"}', ("REAL_SECRET",)),
        ('{"note": "[\\"token=REAL_SECRET\\"]"}', ("REAL_SECRET",)),
        ('{"note": "{\\"Bearer x\\": \\"token=REAL_SECRET\\"}"}', ("REAL_SECRET",)),
        ('{"note": "{\\"token=x\\": \\"token=REAL_SECRET\\"}"}', ("REAL_SECRET",)),
        ('{"note": "{\\"a\\": {\\"b\\": \\"token=REAL_SECRET\\"}}"}', ("REAL_SECRET",)),
        (
            '{"outer": "{\\"mid\\": \\"{\\\\\\"a\\\\\\": \\\\\\"token=REAL_SECRET\\\\\\"}\\"}"}',
            ("REAL_SECRET",),
        ),
        ('{"note": "{\\"a\\": \\"token=1\\"}"}', ("=1",)),
        ('{"note": "{\\"a\\": \\"secret=1\\"}"}', ("=1",)),
        ('{"note": "{\\"a\\": \\"api_key=1\\"}"}', ("=1",)),
        ('{"note": "see \\"token=abc\\" ok"}', ("abc",)),
        ('{"note": "prefix \\"token=REAL_SECRET\\""}', ("REAL_SECRET",)),
        # Contrast cases
        ('{"note": "{\\"a\\": \\"token=REAL_SECRET token=LEAKED\\"}"}', ("REAL_SECRET", "LEAKED")),
        ('{"note": "see token=redacted 3 chars\\" REAL_SECRET"}', ("REAL_SECRET",)),
        ('{"note": "{\\"a\\": \\"token=[REDACTED]\\"}"} token=LEAKED', ("LEAKED",)),
        # Bug 2: _skip_step0 / _may_normalize_leaf with pre-norm placeholders
        ('{"note":"(token=REAL_SECRET)"}bad', ("REAL_SECRET",)),
        ('{"note":"(token=REAL_SECRET)"}{"a":1}', ("REAL_SECRET",)),
        (
            '{"note":"(token=REAL_SECRET)"},{"a":"token=redacted 1 chars"} '
            r'\"Authorization: Bearer REAL_SECRET\"',
            ("REAL_SECRET",),
        ),
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        stored_by_id: dict[str, str] = {}
        for idx, (raw_content, forbidden) in enumerate(post_cases):
            resp = await client.post(
                "/api/v1/memory",
                headers={"X-User-Id": "alice"},
                json={
                    "scope": "user",
                    "scope_id": "alice",
                    "kind": "source_reference",
                    "title": f"R11 HTTP post {idx}",
                    "content": raw_content,
                },
            )
            assert resp.status_code == 201, f"Expected 201 on {raw_content!r}: {resp.text}"
            body = resp.json()
            for bad in forbidden:
                assert bad not in body["content"], f"Leaked {bad!r} on {raw_content!r}"
            stored_by_id[body["id"]] = body["content"]

        for q_secret in ("REAL_SECRET", "LEAKED"):
            q_resp = await client.get(
                f"/api/v1/memory?q={q_secret}",
                headers={"X-User-Id": "alice"},
            )
            assert q_resp.status_code == 200, q_resp.text
            assert q_resp.json()["items"] == []

        exp_json = await client.get(
            "/api/v1/memory/export?format=json&scope=user&scope_id=alice",
            headers={"X-User-Id": "alice"},
        )
        assert exp_json.status_code == 200, exp_json.text
        exp_items = {item["id"]: item["content"] for item in exp_json.json()["items"]}
        assert exp_items == stored_by_id
        for val in exp_items.values():
            assert "REAL_SECRET" not in val
            assert "LEAKED" not in val

    assert ws_store.verify_audit_chain()["valid"] is True
    mem_store.close()
    ws_store.close()
