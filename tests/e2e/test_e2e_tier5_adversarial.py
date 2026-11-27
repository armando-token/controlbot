"""Opaque-box Tier-5 adversarial E2E tests (REST API + Playwright UI)."""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Callable
from typing import Any

import pytest
import uvicorn
import websockets
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from tests.e2e._helpers import (
    IsolatedServer,
    alloc_free_port,
    mint_cap_token,
    trigger_and_wait_turn,
)
from tests.e2e.conftest import StrictBrowserPage
from websockets.typing import Subprotocol

pytestmark = [pytest.mark.e2e, pytest.mark.tier5]

_PAGE_MOCK_AGY_SCRIPT = """#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

cid = "55555555-6666-7777-8888-999999999999"
reply = ':::page{title="E2E Pruned Page"}\\n# E2E Pruned Page\\nBody content.\\n:::'
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({
        "event": "init",
        "conversation_id": cid,
        "init": {"model": "gemini-4-carbon-low"},
    }), flush=True)
    print(json.dumps({
        "event": "step_update",
        "step_update": {"step_type": "agent_response", "text_delta": reply},
    }), flush=True)
    print(json.dumps({
        "event": "result",
        "result": {"status": "SUCCESS", "conversation_id": cid, "response": reply},
    }), flush=True)
    sys.exit(0)

print(json.dumps({"status": "SUCCESS", "conversation_id": cid, "response": reply}))
"""


async def test_e2e_patch_explicit_null_non_500_and_regular_file_upload_400(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as aclient:
        # 1. Explicit null on non-nullable bot fields must return 422 (never 500)
        for bad_bot_payload in (
            {"name": None},
            {"role_prompt": None},
            {"engine_id": None},
            {"thinking_level": None},
        ):
            r_bot = await aclient.patch("/api/v1/bots/bot_chief", json=bad_bot_payload)
            assert r_bot.status_code == 422, f"{bad_bot_payload}: {r_bot.status_code} {r_bot.text}"

        # Nullable bot fields succeed
        r_bot_ok = await aclient.patch(
            "/api/v1/bots/bot_chief",
            json={"project_name": None, "section_id": None},
        )
        assert r_bot_ok.status_code == 200

        # 2. Explicit null on non-nullable routine fields must return 422 (never 500)
        rtn_resp = await aclient.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "E2E Null Check Routine",
                "instruction": "Inspect shift log",
                "schedule_type": "cron",
                "cron_expr": "0 8 * * *",
            },
        )
        assert rtn_resp.status_code == 201
        rtn_id = str(rtn_resp.json()["id"])

        for bad_rtn_payload in (
            {"visibility": None},
            {"name": None},
            {"instruction": None},
            {"schedule_type": None},
            {"timezone": None},
        ):
            r_rtn = await aclient.patch(f"/api/v1/routines/{rtn_id}", json=bad_rtn_payload)
            assert r_rtn.status_code == 422, f"{bad_rtn_payload}: {r_rtn.status_code} {r_rtn.text}"

        r_rtn_ok = await aclient.patch(f"/api/v1/routines/{rtn_id}", json={"cron_expr": None})
        assert r_rtn_ok.status_code == 200
        assert r_rtn_ok.json()["cron_expr"] is None

        # 3. Uploading into an existing regular file path must return 400 (not 500)
        write_resp = await aclient.post(
            "/api/v1/computers/default/files/write",
            json={"path": "e2e_regular_file.txt", "content": "regular-file-body"},
        )
        assert write_resp.status_code == 200

        upload_resp = await aclient.post(
            "/api/v1/computers/default/files/upload",
            params={"path": "e2e_regular_file.txt", "name": "child.txt"},
            content=b"child-bytes",
        )
        assert upload_resp.status_code == 400


async def test_e2e_delete_artifact_prunes_message_references_and_updates_ui(
    server_factory: Callable[..., IsolatedServer],
    strict_browser_page: StrictBrowserPage,
) -> None:
    srv = server_factory(mock_agy_script=_PAGE_MOCK_AGY_SCRIPT, name="t5_del_art_ui")
    async with srv.async_client() as aclient:
        turn = await trigger_and_wait_turn(
            aclient,
            "thr_bot_chief",
            "Create a summary page",
            timeout=15.0,
        )
        assert turn.assistant_message is not None
        msg_id = str(turn.assistant_message["id"])
        arts: list[dict[str, Any]] = list(turn.assistant_message.get("artifacts") or [])
        assert len(arts) == 1
        page_id = str(arts[0]["id"])

        page = strict_browser_page.page
        await page.goto(srv.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")
        page_card = (
            page.locator("div.mt-2\\.5")
            .filter(has_text="E2E Pruned Page")
            .filter(has_text="Page · v1")
        )
        await page_card.wait_for(state="visible")

        del_resp = await aclient.delete(f"/api/v1/artifacts/{page_id}")
        assert del_resp.status_code == 200

        # SSE artifact.deleted invalidates thread-messages so card disappears cleanly
        await page_card.wait_for(state="hidden", timeout=10000)

        # Persisted messages API must no longer carry the deleted artifact
        msgs_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
        assert msgs_resp.status_code == 200
        persisted = next(m for m in msgs_resp.json()["messages"] if m["id"] == msg_id)
        assert persisted["artifacts"] == []

        # Reloading UI must not show any stale card or produce 404s
        await page.reload(wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")
        assert await page_card.count() == 0
        strict_browser_page.assert_clean()


async def test_e2e_r2_auto_review_dup_channel_delete_and_ws_malformed_frames(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as aclient:
        # 1. Duplicate rule id in PUT /api/v1/settings/auto-review returns 422 (not 500)
        dup_resp = await aclient.put(
            "/api/v1/settings/auto-review",
            json={
                "rules": [
                    {"id": "arr_e2e_dup", "bucket": "allow_auto", "rule_text": "Allow read"},
                    {"id": "arr_e2e_dup", "bucket": "ask_first", "rule_text": "Ask delete"},
                ]
            },
        )
        assert dup_resp.status_code == 422

        # 2. Deleting bots scrubs channel bot_ids and rejects empty-bot channel cleanly
        b1 = (
            await aclient.post(
                "/api/v1/bots",
                json={"name": "E2E Ch Bot 1", "engine_id": "controlbot_runtime"},
            )
        ).json()
        b2 = (
            await aclient.post(
                "/api/v1/bots",
                json={"name": "E2E Ch Bot 2", "engine_id": "controlbot_runtime"},
            )
        ).json()
        b1_id = str(b1["id"])
        b2_id = str(b2["id"])

        chn = (
            await aclient.post(
                "/api/v1/channels",
                json={"name": "E2E Scrub Channel", "bot_ids": [b1_id, b2_id]},
            )
        ).json()
        chn_id = str(chn["id"])
        chn_thr = str(chn["thread_id"])

        assert (await aclient.delete(f"/api/v1/bots/{b1_id}")).status_code == 200
        roster1 = (await aclient.get("/api/v1/bots")).json()
        chn_after1 = next(c for c in roster1["channels"] if c["id"] == chn_id)
        assert chn_after1["bot_ids"] == [b2_id]

        page_ok = await aclient.post(
            "/api/v1/pages",
            json={"channel_id": chn_id, "title": "E2E Surviving Bot Page", "content_md": "ok"},
        )
        assert page_ok.status_code == 201
        assert page_ok.json()["bot_id"] == b2_id

        assert (await aclient.delete(f"/api/v1/bots/{b2_id}")).status_code == 200
        assert (
            await aclient.post(
                "/api/v1/pages",
                json={"channel_id": chn_id, "title": "E2E Empty", "content_md": "no"},
            )
        ).status_code == 409
        assert (
            await aclient.post(
                f"/api/v1/threads/{chn_thr}/messages",
                json={"content": "Hello dead channel"},
            )
        ).status_code == 409

        # 3. WebSocket endpoints survive malformed JSON and binary frames
        cap_payload = await mint_cap_token(aclient, vm_id="vm_local")
        cap_tok = str(cap_payload["cap_token"])
        ctrl_url = server.ws_url(
            f"/ws/v1/computers/vm_local/control?cap_token={cap_tok}",
            include_token=False,
        )
        async with websockets.connect(ctrl_url) as ws_ctrl:
            first = json.loads(await asyncio.wait_for(ws_ctrl.recv(), timeout=3.0))
            assert first["op"] == "computer.state"
            await ws_ctrl.send("{bad json")
            await ws_ctrl.send(b"\x00\x01")
            await ws_ctrl.send(json.dumps({"op": "ping"}))
            pong = json.loads(await asyncio.wait_for(ws_ctrl.recv(), timeout=3.0))
            assert pong["op"] == "pong"

        sc_url = server.ws_url(
            f"/ws/v1/computers/vm_local/screencast?cap_token={cap_tok}",
            include_token=False,
        )
        async with websockets.connect(sc_url) as ws_sc:
            st = json.loads(await asyncio.wait_for(ws_sc.recv(), timeout=3.0))
            assert st["type"] == "status"
            await ws_sc.send("{bad json")
            await ws_sc.send(b"\x00\x01")
            await ws_sc.send(json.dumps({"type": "ping"}))
            pong_sc = json.loads(await asyncio.wait_for(ws_sc.recv(), timeout=3.0))
            assert pong_sc["type"] == "pong"

        br_url = server.ws_url("/ws/browser")
        async with websockets.connect(br_url) as ws_br:
            st_br = json.loads(await asyncio.wait_for(ws_br.recv(), timeout=3.0))
            assert st_br["type"] == "status"
            await ws_br.send("{bad json")
            await ws_br.send(b"\x00\x01")
            await ws_br.send(json.dumps({"type": "status"}))
            st_br2 = json.loads(await asyncio.wait_for(ws_br.recv(), timeout=3.0))
            assert st_br2["type"] == "status"

        term_url = server.ws_url("/ws/terminal")
        async with websockets.connect(term_url) as ws_term:
            ready = json.loads(await asyncio.wait_for(ws_term.recv(), timeout=3.0))
            assert ready["type"] == "ready"
            await ws_term.send("{bad json")
            await ws_term.send(b"\x00\x01")
            await ws_term.send(json.dumps({"type": "input", "data": "echo E2E_WS_OK\n"}))
            collected = ""
            for _ in range(30):
                ev = json.loads(await asyncio.wait_for(ws_term.recv(), timeout=3.0))
                if ev.get("type") == "output":
                    collected += str(ev.get("data") or "")
                    if "E2E_WS_OK" in collected:
                        break
            assert "E2E_WS_OK" in collected


async def test_e2e_r3_non_finite_json_returns_422_and_ws_resize_resilience(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(with_mock_rfb=True, name="t5_r3_e2e")
    async with srv.async_client() as aclient:
        # 1. HTTP 1e400/Infinity/NaN/bool on /vnc-token & /takeover must return 422 (never 500)
        for bad_raw in (
            '{"ttl_seconds": 1e400}',
            '{"ttl_seconds": Infinity}',
            '{"ttl_seconds": NaN}',
            '{"ttl_seconds": true}',
        ):
            r_tok = await aclient.post(
                "/api/v1/computers/vm_local/vnc-token",
                content=bad_raw,
                headers={"Content-Type": "application/json"},
            )
            assert r_tok.status_code == 422, f"{bad_raw}: {r_tok.status_code} {r_tok.text}"

            r_tk = await aclient.post(
                "/api/v1/computers/vm_local/takeover",
                content=bad_raw,
                headers={"Content-Type": "application/json"},
            )
            assert r_tk.status_code == 422, f"{bad_raw}: {r_tk.status_code} {r_tk.text}"

        # 2. Mint valid cap_token and verify WS resize resilience + VNC text frame resilience
        cap_payload = await mint_cap_token(aclient, vm_id="vm_local")
        cap_tok = str(cap_payload["cap_token"])

        ctrl_url = srv.ws_url(
            f"/ws/v1/computers/vm_local/control?cap_token={cap_tok}",
            include_token=False,
        )
        async with websockets.connect(ctrl_url) as ws_ctrl:
            first = json.loads(await asyncio.wait_for(ws_ctrl.recv(), timeout=3.0))
            assert first["op"] == "computer.state"
            await ws_ctrl.send('{"op": "viewport.resize", "width": 1e400, "height": 800}')
            ack1 = json.loads(await asyncio.wait_for(ws_ctrl.recv(), timeout=3.0))
            assert ack1["op"] == "viewport.resize.ack"
            assert (ack1["width"], ack1["height"]) == (1280, 800)

            await ws_ctrl.send(json.dumps({"op": "viewport.resize", "width": 1600, "height": 900}))
            ack2 = json.loads(await asyncio.wait_for(ws_ctrl.recv(), timeout=3.0))
            assert (ack2["width"], ack2["height"]) == (1600, 900)

        pty_url = srv.ws_url(
            f"/ws/v1/computers/vm_local/pty/s1?cap_token={cap_tok}",
            include_token=False,
        )
        async with websockets.connect(pty_url) as ws_pty:
            await ws_pty.send('{"type": "resize", "cols": 1e400, "rows": 24}')
            await ws_pty.send(json.dumps({"type": "input", "data": "echo E2E_PTY_INF_OK\n"}))
            collected_pty = ""
            for _ in range(30):
                chunk = await asyncio.wait_for(ws_pty.recv(), timeout=3.0)
                if isinstance(chunk, str):
                    collected_pty += chunk
                    if "E2E_PTY_INF_OK" in collected_pty:
                        break
            assert "E2E_PTY_INF_OK" in collected_pty

        term_url = srv.ws_url("/ws/terminal")
        async with websockets.connect(term_url) as ws_term:
            ready = json.loads(await asyncio.wait_for(ws_term.recv(), timeout=3.0))
            assert ready["type"] == "ready"
            await ws_term.send('{"type": "resize", "cols": 1e400, "rows": 24}')
            await ws_term.send(json.dumps({"type": "input", "data": "echo E2E_TERM_INF_OK\n"}))
            collected_term = ""
            for _ in range(30):
                ev = json.loads(await asyncio.wait_for(ws_term.recv(), timeout=3.0))
                if ev.get("type") == "output":
                    collected_term += str(ev.get("data") or "")
                    if "E2E_TERM_INF_OK" in collected_term:
                        break
            assert "E2E_TERM_INF_OK" in collected_term

        vnc_url = srv.ws_url(
            f"/ws/v1/computers/vm_local/vnc?cap_token={cap_tok}",
            include_token=False,
        )
        async with websockets.connect(vnc_url, subprotocols=[Subprotocol("binary")]) as ws_vnc:
            ver = await asyncio.wait_for(ws_vnc.recv(), timeout=3.0)
            assert ver == b"RFB 003.008\n"
            await ws_vnc.send("text-frame-pre-handshake")
            await ws_vnc.send(b"RFB 003.008\n")
            sec_types = await asyncio.wait_for(ws_vnc.recv(), timeout=3.0)
            assert sec_types == b"\x01\x01"
            await ws_vnc.send(b"\x01")
            sec_res = await asyncio.wait_for(ws_vnc.recv(), timeout=3.0)
            assert sec_res == b"\x00\x00\x00\x00"
            await ws_vnc.send("text-frame-before-client-init")
            await ws_vnc.send(b"\x01")
            srv_init = await asyncio.wait_for(ws_vnc.recv(), timeout=3.0)
            assert isinstance(srv_init, bytes) and len(srv_init) >= 24
            await ws_vnc.send("text-frame-post-handshake")
            await ws_vnc.send(b"\x03\x01\x00\x00\x00\x00\x02\x80\x01\xe0")


_SLOW_ROUTINE_MOCK_AGY_SCRIPT = """#!/usr/bin/env python3
import json
import sys
import time

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

cid = "77777777-8888-9999-0000-111111111111"
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({
        "event": "init",
        "conversation_id": cid,
        "init": {"model": "gemini-4-carbon-low"},
    }), flush=True)
    time.sleep(2.0)
    print(json.dumps({
        "event": "result",
        "result": {"status": "SUCCESS", "conversation_id": cid, "response": "Late routine output"},
    }), flush=True)
    sys.exit(0)

print(json.dumps({"status": "SUCCESS", "conversation_id": cid, "response": "Late routine output"}))
"""


async def test_e2e_r4_4305_digit_json_400_all_5_ws_resilience_and_ssrf_draft_block(
    server: IsolatedServer,
) -> None:
    big_int = "9" * 4305
    big_ttl = f'{{"ttl_seconds": {big_int}}}'
    big_action = f'{{"type": "click", "x": {big_int}, "y": 10}}'
    big_start = f'{{"url": "https://example.com", "pad": {big_int}}}'

    async with server.async_client() as aclient:
        # 1. All raw json.loads HTTP endpoints return 400 on 4305-digit integer (never 500)
        for path, body in (
            ("/api/v1/computers/vm_local/vnc-token", big_ttl),
            ("/api/v1/computers/vm_local/takeover", big_ttl),
            ("/api/browser/action", big_action),
            ("/api/v1/computers/vm_local/actions", big_action),
            ("/api/browser/start", big_start),
        ):
            resp = await aclient.post(
                path,
                content=body,
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 400, f"{path}: {resp.status_code} {resp.text}"

        # 2. All 5 JSON WebSockets survive 4305-digit integer frame and process subsequent frames
        cap_payload = await mint_cap_token(aclient, vm_id="vm_local")
        cap_tok = str(cap_payload["cap_token"])

        ctrl_url = server.ws_url(
            f"/ws/v1/computers/vm_local/control?cap_token={cap_tok}",
            include_token=False,
        )
        async with websockets.connect(ctrl_url) as ws_ctrl:
            assert json.loads(await asyncio.wait_for(ws_ctrl.recv(), timeout=3.0))["op"] == (
                "computer.state"
            )
            await ws_ctrl.send(f'{{"op": "viewport.resize", "width": {big_int}, "height": 800}}')
            await ws_ctrl.send(json.dumps({"op": "ping"}))
            pong = json.loads(await asyncio.wait_for(ws_ctrl.recv(), timeout=3.0))
            assert pong["op"] == "pong"

        sc_url = server.ws_url(
            f"/ws/v1/computers/vm_local/screencast?cap_token={cap_tok}",
            include_token=False,
        )
        async with websockets.connect(sc_url) as ws_sc:
            assert json.loads(await asyncio.wait_for(ws_sc.recv(), timeout=3.0))["type"] == "status"
            await ws_sc.send(f'{{"type": "click", "x": {big_int}, "y": 10}}')
            await ws_sc.send(json.dumps({"type": "ping"}))
            pong_sc = json.loads(await asyncio.wait_for(ws_sc.recv(), timeout=3.0))
            assert pong_sc["type"] == "pong"

        br_url = server.ws_url("/ws/browser")
        async with websockets.connect(br_url) as ws_br:
            assert json.loads(await asyncio.wait_for(ws_br.recv(), timeout=3.0))["type"] == "status"
            await ws_br.send(f'{{"type": "click", "x": {big_int}, "y": 10}}')
            await ws_br.send(json.dumps({"type": "status"}))
            st_br = json.loads(await asyncio.wait_for(ws_br.recv(), timeout=3.0))
            assert st_br["type"] == "status"

        term_url = server.ws_url("/ws/terminal")
        async with websockets.connect(term_url) as ws_term:
            ready_ev = json.loads(await asyncio.wait_for(ws_term.recv(), timeout=3.0))
            assert ready_ev["type"] == "ready"
            await ws_term.send(f'{{"type": "resize", "cols": {big_int}, "rows": 24}}')
            await ws_term.send(json.dumps({"type": "input", "data": "echo E2E_TERM_4305_OK\n"}))
            collected_term = ""
            for _ in range(30):
                ev = json.loads(await asyncio.wait_for(ws_term.recv(), timeout=3.0))
                if ev.get("type") == "output":
                    collected_term += str(ev.get("data") or "")
                    if "E2E_TERM_4305_OK" in collected_term:
                        break
            assert "E2E_TERM_4305_OK" in collected_term

        pty_url = server.ws_url(
            f"/ws/v1/computers/vm_local/pty/s1?cap_token={cap_tok}",
            include_token=False,
        )
        async with websockets.connect(pty_url) as ws_pty:
            await ws_pty.send(f'{{"type": "resize", "cols": {big_int}, "rows": 24}}')
            await ws_pty.send(json.dumps({"type": "input", "data": "echo E2E_PTY_4305_OK\n"}))
            collected_pty = ""
            for _ in range(30):
                chunk = await asyncio.wait_for(ws_pty.recv(), timeout=3.0)
                if isinstance(chunk, str):
                    collected_pty += chunk
                    if "E2E_PTY_4305_OK" in collected_pty:
                        break
            assert "E2E_PTY_4305_OK" in collected_pty

        # 3. Draft webhook SSRF fails closed on default server (loopback & metadata blocked)
        hits: list[str] = []
        hook_app = FastAPI()

        @hook_app.post("/hook")
        async def _hook(request: Request) -> JSONResponse:
            del request
            hits.append("hit")
            return JSONResponse({"ok": True})

        port = alloc_free_port("127.0.0.1")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        sock.listen(32)
        sock.setblocking(False)
        class _NoSignalServer(uvicorn.Server):
            def install_signal_handlers(self) -> None:
                return None

        uv_srv = _NoSignalServer(
            uvicorn.Config(hook_app, host="127.0.0.1", port=port, log_level="warning")
        )
        srv_task = asyncio.create_task(uv_srv.serve(sockets=[sock]))
        try:
            while not uv_srv.started:
                await asyncio.sleep(0.02)
            for ssrf_url in (
                f"http://127.0.0.1:{port}/hook",
                "http://169.254.169.254/latest/meta-data/",
                "http://10.0.0.1/hook",
                "http://localhost./hook",
                "http://foo.localhost/hook",
            ):
                c_resp = await aclient.post(
                    "/api/v1/drafts",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "channel_type": "webhook",
                        "fields": {"webhook_url": ssrf_url, "message": "ssrf e2e"},
                    },
                )
                assert c_resp.status_code == 201
                drf_id = str(c_resp.json()["id"])

                res_resp = await aclient.post(
                    f"/api/v1/drafts/{drf_id}/resolve",
                    json={"action": "send"},
                )
                assert res_resp.status_code == 200

            assert hits == []
            msgs_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
            assert msgs_resp.status_code == 200
            err_msgs = [
                m
                for m in msgs_resp.json()["messages"]
                if m.get("status") == "error" and "SSRF policy" in str(m.get("content") or "")
            ]
            assert len(err_msgs) == 5
        finally:
            uv_srv.should_exit = True
            await asyncio.wait_for(srv_task, timeout=5.0)
            sock.close()


async def test_e2e_r4_delete_routine_in_flight_leaves_no_orphan_messages(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_SLOW_ROUTINE_MOCK_AGY_SCRIPT, name="t5_r4_rtn_del")
    async with srv.async_client() as aclient:
        c_resp = await aclient.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "E2E In-Flight Delete Routine",
                "instruction": "Wait and report",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        assert c_resp.status_code == 201
        rtn_id = str(c_resp.json()["id"])

        run_resp = await aclient.post(f"/api/v1/routines/{rtn_id}/test")
        assert run_resp.status_code == 202
        assert run_resp.json()["status"] == "running"

        await asyncio.sleep(0.15)
        del_resp = await aclient.delete(f"/api/v1/routines/{rtn_id}")
        assert del_resp.status_code == 200
        assert del_resp.json() == {"deleted": True}

        await asyncio.sleep(2.3)
        msgs_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
        assert msgs_resp.status_code == 200
        assert msgs_resp.json()["messages"] == []
        health_resp = await aclient.get("/health")
        assert health_resp.status_code == 200
