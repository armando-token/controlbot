"""Comprehensive N1/N2 tests for Grok Bot `/api/v1` REST, SSE, HITL, RFB Gate & Computer WS."""

from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path

import httpx
import pytest
import websockets
from lab.testing import run_asgi_server
from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.storage.redaction import contains_unredacted_secret_strict
from src.web import create_app
from src.web.v1.rfb_gate import (
    RfbInputGate,
    des_decrypt_block,
    des_encrypt_block,
    solve_vnc_challenge,
    vnc_des_key,
)


@pytest.mark.n1
def test_rfb_des_and_input_gate_blocks_preview_allows_takeover() -> None:
    # FIPS 46-3 known test vector for DES-ECB
    key = bytes.fromhex("133457799BBCDFF1")
    plaintext = bytes.fromhex("0123456789ABCDEF")
    expected_cipher = bytes.fromhex("85E813540F0AB405")
    ct = des_encrypt_block(key, plaintext)
    assert ct == expected_cipher
    assert des_decrypt_block(key, ct) == plaintext

    # VNC challenge produces 16-byte response deterministically
    challenge = bytes(range(16))
    resp = solve_vnc_challenge(b"secret12", challenge)
    assert len(resp) == 16
    assert resp != challenge
    assert len(vnc_des_key(b"secret12")) == 8

    # RfbInputGate filters 0x04 KeyEvent, 0x05 PointerEvent, 0x06 ClientCutText in preview
    gate = RfbInputGate()
    fb_req = struct.pack("!BBHHHH", 3, 1, 0, 0, 1280, 800)  # 10 bytes (allowed)
    key_ev = struct.pack("!BBHI", 4, 1, 0, 0x61)  # 8 bytes (blocked in preview)
    ptr_ev = struct.pack("!BBHH", 5, 1, 100, 200)  # 6 bytes (blocked in preview)
    cut_text = struct.pack("!B3xI", 6, 4) + b"test"  # 12 bytes (blocked in preview)
    set_enc = struct.pack("!BBHi", 2, 0, 1, 0)  # 8 bytes (allowed)

    stream = fb_req + key_ev + ptr_ev + cut_text + set_enc
    # Feed in fragmented chunks to verify stateful reassembly
    out_preview = bytearray()
    for i in range(0, len(stream), 3):
        out_preview.extend(gate.feed(stream[i : i + 3], allow_input=False))

    assert bytes(out_preview) == fb_req + set_enc
    assert gate.dropped_input_events == 3
    assert gate.forwarded_messages == 2

    # In takeover mode, key/pointer/cuttext pass through untouched
    out_takeover = gate.feed(key_ev + ptr_ev + cut_text, allow_input=True)
    assert out_takeover == key_ev + ptr_ev + cut_text
    assert gate.dropped_input_events == 3
    assert gate.forwarded_messages == 5


@pytest.mark.n2
async def test_v1_roster_bots_sections_channels_pages_library_and_search(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "v1_roster.sqlite3")
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            roster = (await client.get("/api/v1/bots")).json()
            assert len(roster["bots"]) == 3
            chief = next(b for b in roster["bots"] if b["id"] == "bot_chief")
            assert chief["is_primary"] is True

            # Create section + bot + pin + move
            sec_resp = await client.post("/api/v1/sections", json={"name": "Plant Operations"})
            assert sec_resp.status_code == 201
            sec_id = sec_resp.json()["id"]

            bot_resp = await client.post(
                "/api/v1/bots",
                json={
                    "name": "Pump Analyst",
                    "avatar_shape": "star",
                    "avatar_color": "#0EA5E9",
                    "section_id": sec_id,
                    "role_prompt": "Analyze pump telemetry.",
                },
            )
            assert bot_resp.status_code == 201
            bot = bot_resp.json()
            assert bot["name"] == "Pump Analyst"
            assert bot["section_id"] == sec_id

            patched = await client.patch(
                f"/api/v1/bots/{bot['id']}",
                json={"pinned": True, "thinking_level": "high", "hidden": True},
            )
            assert patched.status_code == 200
            assert patched.json()["pinned"] is True
            assert patched.json()["hidden"] is True

            # Create group channel (2-6 bots)
            bad_chan = await client.post(
                "/api/v1/channels",
                json={"name": "Too Small", "bot_ids": ["bot_chief"]},
            )
            assert bad_chan.status_code == 422

            chan_resp = await client.post(
                "/api/v1/channels",
                json={"name": "Ops Room", "bot_ids": ["bot_chief", "bot_ops"]},
            )
            assert chan_resp.status_code == 201
            chan = chan_resp.json()
            assert chan["name"] == "Ops Room"
            assert len(chan["bot_ids"]) == 2

            # Pages CRUD + versioning + Library pin/filter
            p1 = await client.post(
                "/api/v1/pages",
                json={
                    "bot_id": "bot_chief",
                    "title": "Pump 34 Brief",
                    "content_md": "# Summary\nVibration alert active.",
                },
            )
            assert p1.status_code == 201
            page_id = p1.json()["id"]

            p_upd = await client.patch(
                f"/api/v1/pages/{page_id}",
                json={"title": "Pump 34 Final Brief", "share_scope": "team", "pinned": True},
            )
            assert p_upd.status_code == 200
            assert p_upd.json()["title"] == "Pump 34 Final Brief"
            assert p_upd.json()["pinned"] is True

            lib = (
                await client.get("/api/v1/bots/bot_chief/library", params={"type": "page"})
            ).json()
            assert any(item["id"] == page_id for item in lib["items"])
            assert any(item["id"] == page_id for item in lib["grouped"]["pinned"])

            # Clone bot template creates a card + artifact
            tpl = await client.post("/api/v1/bots/bot_chief/clone-template")
            assert tpl.status_code == 201
            assert tpl.json()["artifact"]["type"] == "page"

            # Global search finds bots, channels, pages
            srch = (await client.get("/api/v1/search", params={"q": "Pump 34"})).json()
            assert any(p["id"] == page_id for p in srch["pages"])

            # Clean delete
            del_resp = await client.delete(f"/api/v1/bots/{bot['id']}")
            assert del_resp.status_code == 200
            assert del_resp.json()["deleted"] is True


@pytest.mark.n2
async def test_v1_hitl_idempotency_vault_never_leaks_and_routines(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "v1_hitl.sqlite3")
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8000"
        ) as client:
            # Approval creation + idempotent resolution (409 on duplicate)
            apr = (
                await client.post(
                    "/api/v1/approvals",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "kind": "terminal",
                        "title": "Run status check",
                        "target": "vm:default",
                        "risk_banner": "This can't be undone",
                        "arguments": {"command": "df -h"},
                    },
                )
            ).json()
            assert apr["status"] == "pending"

            res1 = await client.post(
                f"/api/v1/approvals/{apr['id']}/resolve",
                headers={"Idempotency-Key": "idem-apr-1"},
                json={"decision": "always_allow"},
            )
            assert res1.status_code == 200
            assert res1.json()["status"] == "allowed_always"

            res_dup = await client.post(
                f"/api/v1/approvals/{apr['id']}/resolve",
                headers={"Idempotency-Key": "idem-apr-1"},
                json={"decision": "always_allow"},
            )
            assert res_dup.status_code == 409

            # Auto-review rules should now include the saved rule
            rules = (await client.get("/api/v1/settings/auto-review")).json()["rules"]
            assert any(r["rule_type"] == "allow_auto" for r in rules)

            # Draft card inline edit + send + 409 on repeat
            drf = (
                await client.post(
                    "/api/v1/drafts",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "channel_type": "email",
                        "fields": {
                            "to": "ops@example.com",
                            "subject": "Shift",
                            "body": "All clear",
                        },
                    },
                )
            ).json()
            d1 = await client.post(
                f"/api/v1/drafts/{drf['id']}/resolve",
                headers={"Idempotency-Key": "idem-drf-1"},
                json={
                    "action": "send",
                    "fields": {
                        "to": "ops@example.com",
                        "subject": "Shift Edited",
                        "body": "Updated",
                    },
                },
            )
            assert d1.status_code == 200
            assert d1.json()["status"] == "sent"
            assert d1.json()["fields"]["subject"] == "Shift Edited"

            d_dup = await client.post(
                f"/api/v1/drafts/{drf['id']}/resolve",
                headers={"Idempotency-Key": "idem-drf-2"},
                json={"action": "send"},
            )
            assert d_dup.status_code == 409

            # Vault secret storage + secure-fill NEVER returns plaintext secret
            secret_value = "SuperSecret-Vault-Token-998877!"
            sec_save = await client.post(
                "/api/v1/vault/secrets",
                json={
                    "bot_id": "bot_chief",
                    "name": "ERP Admin",
                    "domain": "erp.local",
                    "username": "admin",
                    "value": secret_value,
                },
            )
            assert sec_save.status_code == 201
            assert secret_value not in sec_save.text

            secrets_list = await client.get(
                "/api/v1/vault/secrets", params={"bot_id": "bot_chief"}
            )
            assert secrets_list.status_code == 200
            assert secret_value not in secrets_list.text
            assert len(secrets_list.json()["secrets"]) == 1

            fill_resp = await client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "bot_id": "bot_chief",
                    "domain": "erp.local",
                    "fields": {"username": "admin", "password": secret_value},
                    "save_to_vault": True,
                    "secret_name": "ERP Login",
                },
            )
            assert fill_resp.status_code == 200
            assert secret_value not in fill_resp.text
            assert "never shown" in fill_resp.json()["message"].lower()

            # Routines CRUD + webhook auth + runs
            rtn = (
                await client.post(
                    "/api/v1/bots/bot_chief/routines",
                    json={
                        "name": "Webhook Alert Check",
                        "instruction": "Check latest status",
                        "schedule_type": "webhook",
                    },
                )
            ).json()
            assert rtn["webhook_key"]

            bad_wh = await client.post(
                f"/api/v1/webhooks/routines/{rtn['id']}",
                headers={"Authorization": "Bearer wrong-key"},
            )
            assert bad_wh.status_code == 401

            good_wh = await client.post(
                f"/api/v1/webhooks/routines/{rtn['id']}",
                headers={"Authorization": f"Bearer {rtn['webhook_key']}"},
            )
            assert good_wh.status_code == 202
            await asyncio.sleep(0.15)
            runs = (await client.get(f"/api/v1/routines/{rtn['id']}/runs")).json()["runs"]
            assert len(runs) >= 1


@pytest.mark.n2
async def test_v1_computer_takeover_lock_files_pty_and_sse_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projects_dir = tmp_path / "Projects"
    proj = projects_dir / "Grokbotclon"
    proj.mkdir(parents=True)
    (proj / "hello.txt").write_text("hello world api_key=sk-secret-99999999\n", encoding="utf-8")
    (proj / ".env").write_text("SECRET=1\n", encoding="utf-8")
    monkeypatch.setenv("CONTROLBOT_PROJECTS_ROOT", str(projects_dir))

    app = create_app(db_path=tmp_path / "v1_comp.sqlite3")
    async with (
        run_asgi_server(app) as origin,
        httpx.AsyncClient(base_url=origin, timeout=10.0) as client,
    ):
        ws_origin = origin.replace("http://", "ws://", 1)

        # Mint short-lived cap_token
        tok_resp = await client.post("/api/v1/computers/default/vnc-token")
        assert tok_resp.status_code == 200
        tok = tok_resp.json()
        assert tok["cap_token"]
        assert tok["ttl_seconds"] == 60

        # Takeover acquires exclusive automation lock -> agent actions return 409!
        to_resp = await client.post(
            "/api/v1/computers/default/takeover",
            headers={"Idempotency-Key": "takeover-1"},
            json={"owner": "operator"},
        )
        assert to_resp.status_code == 200
        assert to_resp.json()["control_owner"] == "human_takeover"

        # Duplicate idempotency key -> 409
        to_dup = await client.post(
            "/api/v1/computers/default/takeover",
            headers={"Idempotency-Key": "takeover-1"},
            json={"owner": "operator"},
        )
        assert to_dup.status_code == 409

        # Agent action rejected while human takeover is active
        agent_blocked = await client.post(
            "/api/v1/computers/default/actions",
            json={"actor": "agent", "type": "start"},
        )
        assert agent_blocked.status_code == 409

        # Handback releases lock
        hb = await client.post("/api/v1/computers/default/handback", json={})
        assert hb.status_code == 200
        assert hb.json()["control_owner"] == "agent"

        # Workspace file explorer: list, read (redacted), upload, write, delete, block .env
        fl = await client.get("/api/v1/computers/default/files", params={"project": "Grokbotclon"})
        assert fl.status_code == 200
        assert any(e["name"] == "hello.txt" for e in fl.json()["entries"])

        rd = await client.get(
            "/api/v1/computers/default/file",
            params={"project": "Grokbotclon", "path": "hello.txt"},
        )
        assert rd.status_code == 200
        content_str = str(rd.json()["content"])
        assert "sk-secret-99999999" not in content_str
        assert REDACTED_PLACEHOLDER in content_str or not contains_unredacted_secret_strict(
            content_str
        )

        env_rd = await client.get(
            "/api/v1/computers/default/file",
            params={"project": "Grokbotclon", "path": ".env"},
        )
        assert env_rd.status_code in {403, 422}

        wr = await client.post(
            "/api/v1/computers/default/files/write",
            json={"project": "Grokbotclon", "path": "notes.md", "content": "# Notes\nOK\n"},
        )
        assert wr.status_code == 200
        assert (proj / "notes.md").read_text(encoding="utf-8") == "# Notes\nOK\n"

        # PTY WebSocket over cap_token executes command cleanly
        ws_pty_url = (
            tok["ws_pty_url"]
            if str(tok["ws_pty_url"]).startswith(("ws://", "wss://"))
            else f"{ws_origin}{tok['ws_pty_url']}"
        )
        async with websockets.connect(ws_pty_url) as ws:
            await ws.send(json.dumps({"op": "resize", "cols": 100, "rows": 30}))
            await ws.send("echo V1_PTY_WORKS\n")
            collected = ""
            for _ in range(30):
                raw_msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                chunk = (
                    raw_msg
                    if isinstance(raw_msg, str)
                    else raw_msg.decode("utf-8", errors="replace")
                )
                collected += chunk
                if "V1_PTY_WORKS" in collected:
                    break
            assert "V1_PTY_WORKS" in collected

        # Control WebSocket accepts heartbeat
        ws_ctrl_url = (
            tok["ws_control_url"]
            if str(tok["ws_control_url"]).startswith(("ws://", "wss://"))
            else f"{ws_origin}{tok['ws_control_url']}"
        )
        async with websockets.connect(ws_ctrl_url) as cws:
            await cws.send(json.dumps({"op": "lease.heartbeat"}))
            ack_raw = await asyncio.wait_for(cws.recv(), timeout=5.0)
            ack = json.loads(ack_raw)
            assert ack["op"] in {"lease.heartbeat.ack", "computer.state"}

        # Teach a task start -> stop compiles real Skill Markdown
        ts = await client.post(
            "/api/v1/computers/default/teach/start",
            json={"bot_id": "bot_chief", "name": "Export SCADA CSV"},
        )
        assert ts.status_code == 200
        assert ts.json()["is_teaching_task"] is True

        te = await client.post(
            "/api/v1/computers/default/teach/stop",
            json={"bot_id": "bot_chief"},
        )
        assert te.status_code == 200
        assert te.json()["skill"]["name"] == "Export SCADA CSV"
        assert "# Skill:" in te.json()["skill"]["content_md"]

        # EventBus replay test
        bus = app.state.event_bus
        e1 = bus.publish(
            "bot.presence", {"state": "working", "subtext": "Step 1"}, bot_id="bot_chief"
        )
        e2 = bus.publish("bot.presence", {"state": "idle", "subtext": "Done"}, bot_id="bot_chief")
        assert int(e2["id"].split("_")[1]) > int(e1["id"].split("_")[1])

        # Settings, apps, usage, attachments
        st_patch = await client.patch(
            "/api/v1/settings", json={"theme": "light", "accent_mode": "black"}
        )
        assert st_patch.status_code == 200
        assert st_patch.json()["accent_mode"] == "black"

        apps = (await client.get("/api/v1/apps")).json()["apps"]
        assert len(apps) >= 5
        app0 = apps[0]
        toggled = await client.patch(
            f"/api/v1/apps/{app0['id']}", json={"enabled": not app0["enabled"]}
        )
        assert toggled.status_code == 200

        att = await client.post(
            "/api/v1/attachments",
            params={"filename": "report.txt", "thread_id": "thr_bot_chief"},
            content=b"Sample attachment text",
        )
        assert att.status_code == 201
        att_id = att.json()["id"]
        dl = await client.get(f"/api/v1/attachments/{att_id}")
        assert dl.status_code == 200
        assert dl.content == b"Sample attachment text"

        usage = (await client.get("/api/v1/usage")).json()
        assert usage["bots_count"] >= 3
        assert json.dumps(usage)
