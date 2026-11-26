"""Smoke tests verifying the isolated E2E test harness (E2E-M0)."""

from __future__ import annotations

import asyncio
import json
import shutil
import struct
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from tests.e2e._helpers import (
    FORBIDDEN_PORTS,
    IsolatedServer,
    MockRfbServer,
    mint_cap_token,
    trigger_and_wait_turn,
    wait_for_sse_event,
)
from tests.e2e.conftest import StrictBrowserPage

pytestmark = pytest.mark.e2e

_CONV_ID = "11111111-2222-3333-4444-555555555555"
_MOCK_AGY_SCRIPT = f"""#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

cid = "{_CONV_ID}"
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
            "text_delta": "Mock agy isolated reply",
        }},
    }}), flush=True)
    print(json.dumps({{
        "event": "result",
        "result": {{
            "status": "SUCCESS",
            "conversation_id": cid,
            "response": "Mock agy isolated reply",
        }},
    }}), flush=True)
    sys.exit(0)

print(json.dumps({{
    "status": "SUCCESS",
    "conversation_id": cid,
    "response": "Mock agy isolated reply",
}}))
"""


def test_isolated_server_boot_seeded_bots_and_home_isolation(
    server: IsolatedServer,
    server_factory: Callable[..., IsolatedServer],
) -> None:
    assert server.port not in FORBIDDEN_PORTS
    assert server.vnc_port not in FORBIDDEN_PORTS
    assert server.env["HOME"] == str(server.fake_home)
    assert Path(server.env["HOME"]) != Path("/home/user")
    assert "GROKBOT_LLM_BASE_URL" not in server.env
    assert server.mock_agy_script is None
    assert shutil.which("agy", path=server.env["PATH"]) is None
    assert not (server.fake_home / ".local" / "bin" / "agy").exists()
    assert server.env.get("CONTROLBOT_BASE_URL") == server.base_url
    assert server.env.get("GROKBOT_BASE_URL") == server.base_url
    assert server.env.get("CONTROLBOT_PORT") == str(server.port)
    assert server.env.get("PORT") == str(server.port)
    assert "GROKBOT_X11_DISPLAY" in server.env
    assert server.env["GROKBOT_X11_DISPLAY"] != ":1"
    assert server.env["GROKBOT_X11_DISPLAY"] == ""
    assert "DISPLAY" not in server.env
    assert "WAYLAND_DISPLAY" not in server.env
    assert (server.projects_root / "Grokbotclon" / "README.md").is_file()
    assert server.vnc_passwd_path.is_file()

    with server.client() as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"
        assert health.json()["db_path"] == str(server.db_path)

        sys_info = client.get("/api/system/info")
        assert sys_info.status_code == 200
        assert sys_info.json()["backend_mode"] == "emulated"

        agy_models = client.get("/api/agy/models")
        assert agy_models.status_code == 200
        assert agy_models.json()["available"] is False

        agy_conv = client.get("/api/agy/conversations")
        assert agy_conv.status_code == 200
        assert agy_conv.json()["available"] is False

        bots_resp = client.get("/api/v1/bots")
        assert bots_resp.status_code == 200
        bots = bots_resp.json()["bots"]
        assert len(bots) == 3
        assert {b["id"] for b in bots} == {"bot_chief", "bot_ops", "bot_browser"}

    # Non-slash turn on default server (mock_agy_script=None) must NOT execute host agy
    async def _run_default_turn() -> None:
        async with server.async_client() as aclient:
            turn = await trigger_and_wait_turn(
                aclient,
                "thr_bot_chief",
                "Ping without host agy",
            )
            assert turn.assistant_message is not None
            assert (
                "Antigravity CLI (`agy`) is not installed on this host."
                in turn.assistant_message["content"]
            )

    asyncio.run(_run_default_turn())

    # Verify mock_agy_script dropped into fake_home/.local/bin/agy intercepts agy execution
    agy_srv = server_factory(mock_agy_script=_MOCK_AGY_SCRIPT, name="agy_iso")
    mock_agy_path = agy_srv.fake_home / ".local" / "bin" / "agy"
    assert mock_agy_path.is_file()
    assert shutil.which("agy", path=agy_srv.env["PATH"]) == str(mock_agy_path)
    assert agy_srv.env.get("CONTROLBOT_BASE_URL") == agy_srv.base_url

    async def _run_turn() -> None:
        async with agy_srv.async_client() as aclient:
            turn = await trigger_and_wait_turn(aclient, "thr_bot_chief", "Ping isolated mock agy")
            assert turn.assistant_message is not None
            assert "Mock agy isolated reply" in turn.assistant_message["content"]

    asyncio.run(_run_turn())


def test_isolated_server_restart_preserves_sqlite_wal_state(server: IsolatedServer) -> None:
    with server.client() as client:
        sec_resp = client.post("/api/v1/sections", json={"name": "Turbine Hall"})
        assert sec_resp.status_code == 201
        section_id = sec_resp.json()["id"]

        bot_resp = client.post(
            "/api/v1/bots",
            json={
                "name": "Restart Persistence Bot",
                "section_id": section_id,
                "role_prompt": "Verify WAL durability across SIGTERM.",
            },
        )
        assert bot_resp.status_code == 201
        created_bot_id = bot_resp.json()["id"]

    original_port = server.port
    server.restart(keep_port=False)
    assert server.port not in FORBIDDEN_PORTS
    assert server.port != original_port
    assert server.env.get("CONTROLBOT_BASE_URL") == server.base_url
    assert server.env.get("GROKBOT_BASE_URL") == server.base_url
    assert server.env.get("CONTROLBOT_PORT") == str(server.port)
    assert server.env.get("PORT") == str(server.port)

    with server.client() as client:
        health = client.get("/health")
        assert health.status_code == 200

        roster = client.get("/api/v1/bots").json()
        assert any(
            s["id"] == section_id and s["name"] == "Turbine Hall"
            for s in roster["sections"]
        )
        persisted = next((b for b in roster["bots"] if b["id"] == created_bot_id), None)
        assert persisted is not None
        assert persisted["name"] == "Restart Persistence Bot"
        assert persisted["section_id"] == section_id

    kept_port = server.port
    kept_base_url = server.base_url
    server.restart(keep_port=True)
    assert server.port == kept_port
    assert server.base_url == kept_base_url
    assert server.env.get("CONTROLBOT_BASE_URL") == kept_base_url

    with server.client() as client:
        health_kept = client.get("/health")
        assert health_kept.status_code == 200

        roster_kept = client.get("/api/v1/bots").json()
        assert any(
            s["id"] == section_id and s["name"] == "Turbine Hall"
            for s in roster_kept["sections"]
        )
        persisted_kept = next(
            (b for b in roster_kept["bots"] if b["id"] == created_bot_id), None
        )
        assert persisted_kept is not None
        assert persisted_kept["name"] == "Restart Persistence Bot"
        assert persisted_kept["section_id"] == section_id


async def test_mock_rfb_server_des_handshake_and_message_recording(
    mock_rfb_server: MockRfbServer,
    tmp_path: Path,
) -> None:
    from src.web.v1.rfb_gate import (
        RfbHandshakeError,
        decrypt_vnc_passwd_file,
        perform_backend_vnc_handshake,
    )

    host, port, passwd_path = mock_rfb_server
    assert host == "127.0.0.1"
    assert port not in FORBIDDEN_PORTS
    assert passwd_path.is_file()
    assert decrypt_vnc_passwd_file(passwd_path) == mock_rfb_server.password

    # Verify wrong password fails VNC Auth cleanly
    wrong_pw_path = tmp_path / "wrong_vnc_passwd"
    wrong_pw_path.write_bytes(b"\x00" * 8)
    reader_bad, writer_bad = await asyncio.open_connection(host, port)
    try:
        with pytest.raises(RfbHandshakeError, match="authentication failed"):
            await perform_backend_vnc_handshake(reader_bad, writer_bad, wrong_pw_path)
    finally:
        writer_bad.close()
        await writer_bad.wait_closed()
    assert mock_rfb_server.auth_failures == 1

    # Verify authentic RFB 3.8 DES handshake + ServerInit + client message recording
    reader, writer = await asyncio.open_connection(host, port)
    try:
        await perform_backend_vnc_handshake(reader, writer, passwd_path)
        # ClientInit (shared=1)
        writer.write(b"\x01")
        await writer.drain()

        # ServerInit: 24 bytes header + desktop name
        srv_init_hdr = await reader.readexactly(24)
        width, height, bpp, depth, _big, _true, _rm, _gm, _bm, _rs, _gs, _bs, name_len = (
            struct.unpack("!HHBBBBHHHBBB3xI", srv_init_hdr)
        )
        name_bytes = await reader.readexactly(name_len)
        assert (width, height) == (640, 480)
        assert (bpp, depth) == (32, 24)
        assert name_bytes == b"MockRFB"

        fb_req = struct.pack("!BBHHHH", 3, 1, 0, 0, 640, 480)
        key_ev = struct.pack("!BBHI", 4, 1, 0, 0x0061)
        ptr_ev = struct.pack("!BBHH", 5, 1, 120, 240)
        cut_text = struct.pack("!B3xI", 6, 5) + b"hello"
        writer.write(fb_req + key_ev + ptr_ev + cut_text)
        await writer.drain()

        # FramebufferUpdateRequest triggers a valid 4-byte empty FramebufferUpdate reply
        fb_reply = await reader.readexactly(4)
        assert fb_reply == b"\x00\x00\x00\x00"

        recorded = mock_rfb_server.wait_for_messages(min_count=4, timeout=3.0)
        assert recorded == [0x03, 0x04, 0x05, 0x06]
        assert mock_rfb_server.handshakes_completed == 1
    finally:
        writer.close()
        await writer.wait_closed()


async def test_strict_browser_page_loads_studio_cleanly(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    await strict_browser_page.goto(server.url("/app"), wait_until="networkidle")
    await strict_browser_page.wait_for_selector("text=Grok Bot")

    title = await strict_browser_page.title()
    theme = await strict_browser_page.evaluate(
        "document.documentElement.getAttribute('data-theme')"
    )
    assert title == "Grok Bot — ControlBot Studio"
    assert theme == "light"
    assert strict_browser_page.errors == []
    strict_browser_page.assert_clean()


async def test_strict_browser_page_websocket_route_guard(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default")
    ws_control_url = f"{server.ws_base_url}{tok['ws_control_url']}"

    await strict_browser_page.goto(server.url("/app"), wait_until="networkidle")
    strict_browser_page.assert_clean()

    # Allowed loopback /ws/v1/* connects and exchanges messages cleanly
    ws_ok = await strict_browser_page.evaluate(
        """(wsUrl) => new Promise((resolve, reject) => {
            const ws = new WebSocket(wsUrl);
            const seen = [];
            ws.onmessage = (ev) => {
                const msg = JSON.parse(ev.data);
                seen.push(msg.op);
                if (msg.op === 'computer.state') {
                    ws.send(JSON.stringify({op: 'ping'}));
                } else if (msg.op === 'pong') {
                    ws.close(1000, 'done');
                    resolve(seen);
                }
            };
            ws.onerror = () => reject(new Error('loopback ws error'));
            setTimeout(() => reject(new Error('loopback ws timeout')), 5000);
        })""",
        ws_control_url,
    )
    assert ws_ok == ["computer.state", "pong"]
    strict_browser_page.assert_clean()

    # Disallowed external wss:// is intercepted into external_requests without network I/O
    close_info = await strict_browser_page.evaluate(
        """() => new Promise((resolve) => {
            const ws = new WebSocket('wss://example.com/ws_probe');
            ws.onopen = () => resolve('unexpected_open');
            ws.onclose = (ev) => resolve(`closed:${ev.code}`);
        })"""
    )
    assert close_info == "closed:1008"
    assert strict_browser_page.external_requests == ["wss://example.com/ws_probe"]
    with pytest.raises(AssertionError, match="external_requests"):
        strict_browser_page.assert_clean()
    strict_browser_page.reset_errors()
    strict_browser_page.assert_clean()


def test_isolated_server_with_lab_starts_synthetic_apps(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(with_lab=True, name="lab_srv")
    assert srv.lab_stack is not None
    scada_url = srv.env["GROKBOT_SCADA_URL"]
    maint_url = srv.env["GROKBOT_MAINTENANCE_URL"]
    effect_url = srv.env["GROKBOT_EFFECT_SIM_URL"]

    for port in (
        srv.lab_stack.scada_port,
        srv.lab_stack.maintenance_port,
        srv.lab_stack.effect_sim_port,
    ):
        assert port not in FORBIDDEN_PORTS

    with httpx.Client(timeout=5.0, follow_redirects=True) as lab_client:
        assert lab_client.get(f"{scada_url}/").status_code == 200
        assert lab_client.get(f"{maint_url}/").status_code == 200
        assert lab_client.get(f"{effect_url}/health").status_code == 200

    with srv.client() as client:
        info = client.get("/api/system/info")
        assert info.status_code == 200
        body = info.json()
        assert body["backend_mode"] == "emulated"
        apps_by_id = {app["app_id"]: app["origin"] for app in body["facility"]["apps"]}
        assert apps_by_id["scada"] == scada_url
        assert apps_by_id["maintenance"] == maint_url
        assert apps_by_id["effect_sim"] == effect_url


async def test_auth_server_cap_token_sse_and_browser_token_propagation(
    auth_server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    assert auth_server.web_token == "e2e-web-token-9876"
    assert auth_server.env["GROKBOT_WEB_TOKEN"] == "e2e-web-token-9876"
    assert auth_server.env["CONTROLBOT_WEB_TOKEN"] == "e2e-web-token-9876"
    assert f"token={auth_server.web_token}" in auth_server.url("/app")
    assert f"token={auth_server.web_token}" in auth_server.ws_url("/ws/v1/computers/default/pty/s1")
    assert auth_server.url("/app", include_token=False) == f"{auth_server.base_url}/app"

    with auth_server.client() as sync_client:
        tok_sync = mint_cap_token(sync_client, vm_id="default")
        assert tok_sync["cap_token"]
        assert tok_sync["ws_vnc_url"].startswith("/ws/v1/computers/default/vnc?cap_token=")

    async with auth_server.async_client() as async_client:
        tok_async = await mint_cap_token(async_client, vm_id="default", ttl_seconds=30)
        assert tok_async["ttl_seconds"] == 30

        async def _trigger_approval() -> None:
            await asyncio.sleep(0.1)
            resp = await async_client.post(
                "/api/v1/threads/thr_bot_chief/messages",
                json={"content": "/approval Smoke check gate"},
            )
            assert resp.status_code == 202

        trigger_task = asyncio.create_task(_trigger_approval())
        frame = await wait_for_sse_event(
            async_client,
            lambda f: f.event_type == "hitl.approval.requested",
            timeout=5.0,
        )
        await trigger_task
        assert frame.id is not None
        assert isinstance(frame.data, dict)
        assert frame.data["payload"]["approval"]["title"] == "Smoke check gate"

    await strict_browser_page.goto(auth_server.url("/app"), wait_until="networkidle")
    await strict_browser_page.wait_for_selector("text=Grok Bot")
    strict_browser_page.assert_clean()


def test_extra_env_path_sanitization_mock_rfb_tempdir_and_context_manager(
    tmp_path: Path,
) -> None:
    # Dirty PATH via extra_env must still have host agy directories stripped
    dirty_srv = IsolatedServer(
        tmp_dir=tmp_path / "dirty_path",
        extra_env={"PATH": "/home/user/.local/bin:/home/user/.gemini/antigravity-cli/bin:/usr/bin"},
    )
    assert shutil.which("agy", path=dirty_srv.env["PATH"]) is None
    assert "DISPLAY" not in dirty_srv.env
    assert dirty_srv.env["GROKBOT_X11_DISPLAY"] == ""

    # MockRfbServer(passwd_path=None) must never write relative Path("vnc_passwd") in CWD
    cwd_vnc = Path("vnc_passwd")
    existed_before = cwd_vnc.exists()
    rfb = MockRfbServer()
    assert rfb.passwd_path.is_absolute()
    assert rfb.passwd_path.parent != Path.cwd()
    rfb.start()
    try:
        assert rfb.passwd_path.is_file()
        assert cwd_vnc.exists() == existed_before
    finally:
        rfb.stop()
    assert not rfb.passwd_path.parent.exists()
    assert cwd_vnc.exists() == existed_before

    # IsolatedServer works as a context manager and cleans up on exit
    with IsolatedServer(tmp_dir=tmp_path / "ctx_srv") as ctx_srv:
        with ctx_srv.client() as client:
            assert client.get("/health").status_code == 200
        proc = ctx_srv._proc
        assert proc is not None and proc.poll() is None
    assert ctx_srv._proc is None

    # Failed start() cleans up _proc cleanly
    bad_srv = IsolatedServer(
        tmp_dir=tmp_path / "bad_srv",
        extra_env={"GROKBOT_DB_PATH": "/dev/null/cannot_create.sqlite3"},
    )
    with pytest.raises((RuntimeError, TimeoutError)):
        bad_srv.start(timeout=5.0)
    assert bad_srv._proc is None


async def test_trigger_and_wait_turn_raises_timeout_on_early_sse_eof() -> None:
    sse_closed_gate = asyncio.Event()

    async def _handle_http(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw_head = await reader.readuntil(b"\r\n\r\n")
            first_line = raw_head.decode("ascii", errors="replace").splitlines()[0]
            if first_line.startswith("GET /api/v1/events/stream"):
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/event-stream\r\n"
                    b"Cache-Control: no-cache\r\n"
                    b"Connection: close\r\n\r\n"
                    b": connected\n\n"
                )
                await writer.drain()
                await sse_closed_gate.wait()
            elif first_line.startswith("POST /api/v1/threads/"):
                for line in raw_head.decode("ascii", errors="replace").splitlines()[1:]:
                    if line.lower().startswith("content-length:"):
                        cl = int(line.split(":", 1)[1].strip())
                        if cl > 0:
                            await reader.readexactly(cl)
                        break
                body = json.dumps(
                    {"turn_id": "turn_early_eof", "user_message": {"id": "msg_1"}}
                ).encode("utf-8")
                writer.write(
                    f"HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                    + body
                )
                await writer.drain()
                # Close SSE stream cleanly before any terminal event is sent
                sse_closed_gate.set()
        finally:
            writer.close()
            await writer.wait_closed()

    stub_server = await asyncio.start_server(_handle_http, "127.0.0.1", 0)
    assert stub_server.sockets
    stub_port = int(stub_server.sockets[0].getsockname()[1])
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{stub_port}",
            timeout=5.0,
        ) as aclient:
            with pytest.raises(TimeoutError, match="SSE stream closed before terminal event"):
                await trigger_and_wait_turn(aclient, "thr_stub", "hello", timeout=5.0)
    finally:
        stub_server.close()
        await stub_server.wait_closed()
