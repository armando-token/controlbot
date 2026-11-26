"""Opaque-box Tier 1 & Tier 2 E2E tests for Auth, Vault Origin Check & Takeover Lock (E2E-M1)."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import sqlite3
import stat
import struct
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import websockets
from tests.e2e._helpers import (
    IsolatedServer,
    SseFrame,
    iter_sse_events,
    mint_cap_token,
    wait_for_sse_event,
)
from tests.e2e.conftest import StrictBrowserPage
from websockets.asyncio.client import ClientConnection
from websockets.typing import Subprotocol

pytestmark = pytest.mark.e2e

_SENSITIVE_PASSWORD_1 = "VaultSecret!2026#Alpha"
_SENSITIVE_PASSWORD_2 = "VaultSecret!2026#Bravo"


class LocalLoginFormServer:
    """Ephemeral loopback HTTP server hosting an HTML login form and recording POSTs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._submissions: list[dict[str, str]] = []
        self._submit_event = threading.Event()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def login_url(self) -> str:
        return f"{self.base_url}/login"

    @property
    def domain_with_port(self) -> str:
        return f"127.0.0.1:{self.port}"

    @property
    def submissions(self) -> list[dict[str, str]]:
        with self._lock:
            return [dict(item) for item in self._submissions]

    def wait_for_submissions(
        self,
        min_count: int = 1,
        timeout: float = 5.0,
    ) -> list[dict[str, str]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self._submissions) >= min_count:
                    return [dict(item) for item in self._submissions]
                self._submit_event.clear()
            self._submit_event.wait(timeout=max(0.01, min(0.1, deadline - time.monotonic())))
        return self.submissions

    def start(self) -> LocalLoginFormServer:
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                del format, args

            def do_GET(self) -> None:
                if self.path.startswith("/login") or self.path == "/":
                    html = (
                        b"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                        b"<title>Plant Portal Login</title></head>"
                        b"<body style='padding:24px;font-family:sans-serif;'>"
                        b"<h1>Plant Portal</h1>"
                        b"<form method='POST' action='/submit'>"
                        b"<label>Username <input name='username' type='text' /></label><br/>"
                        b"<label>Password <input name='password' type='password' /></label><br/>"
                        b"<button type='submit'>Sign In</button>"
                        b"</form></body></html>"
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html)))
                    self.end_headers()
                    self.wfile.write(html)
                    return

                body = b"<!DOCTYPE html><html><body><h1>Other Page</h1></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                raw_len = self.headers.get("Content-Length", "0")
                content_len = int(raw_len) if raw_len.isdigit() else 0
                raw_body = self.rfile.read(content_len).decode("utf-8", errors="replace")
                parsed = parse_qs(raw_body, keep_blank_values=True)
                entry = {k: vals[0] if vals else "" for k, vals in parsed.items()}
                with parent._lock:
                    parent._submissions.append(entry)
                    parent._submit_event.set()
                ack = b"<!DOCTYPE html><html><body><h1>Signed In</h1></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(ack)))
                self.end_headers()
                self.wfile.write(ack)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd = httpd
        self.port = int(httpd.server_address[1])
        self._thread = threading.Thread(
            target=httpd.serve_forever,
            daemon=True,
            name="e2e-login-server",
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            with contextlib.suppress(Exception):
                httpd.shutdown()
            with contextlib.suppress(Exception):
                httpd.server_close()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None


@pytest.fixture
def login_server() -> Iterator[LocalLoginFormServer]:
    srv = LocalLoginFormServer().start()
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture
def browser_server(server_factory: Callable[..., IsolatedServer]) -> IsolatedServer:
    """Isolated server with PLAYWRIGHT_BROWSERS_PATH forwarded for LiveBrowserController."""
    browsers_path = Path.home() / ".cache" / "ms-playwright"
    extra_env = (
        {"PLAYWRIGHT_BROWSERS_PATH": str(browsers_path)} if browsers_path.is_dir() else {}
    )
    return server_factory(web_token=None, extra_env=extra_env, name="browser_server")


async def _assert_ws_rejected_handshake(
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> int:
    with pytest.raises(websockets.exceptions.InvalidStatus) as exc_info:
        async with websockets.connect(
            url,
            additional_headers=headers,
            open_timeout=5.0,
        ):
            pass
    status_code = int(exc_info.value.response.status_code)
    assert status_code in {401, 403}
    return status_code


async def _ws_recv_json(ws: Any, timeout: float = 5.0) -> dict[str, Any]:
    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
    assert isinstance(raw, str)
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)
    return parsed


def _navigate_and_find_submit_button(
    client: httpx.Client,
    target_url: str,
) -> tuple[int, int]:
    start_resp = client.post("/api/browser/start", json={"url": target_url})
    assert start_resp.status_code == 200
    nav_resp = client.post(
        "/api/v1/computers/default/actions",
        json={"actor": "human", "type": "navigate", "url": target_url},
    )
    assert nav_resp.status_code == 200

    ctx_resp = client.get("/api/browser/context")
    assert ctx_resp.status_code == 200
    elements = ctx_resp.json().get("elements", [])
    assert isinstance(elements, list)
    for elem in elements:
        if isinstance(elem, dict) and elem.get("tag") == "button":
            return int(elem["x"]), int(elem["y"])
    raise AssertionError(f"Submit button not found in browser context: {elements!r}")


def _assert_no_secret_in_thread(
    client: httpx.Client,
    thread_id: str,
    secret_text: str,
) -> None:
    resp = client.get(f"/api/v1/threads/{thread_id}/messages")
    assert resp.status_code == 200
    assert secret_text not in resp.text


async def _anavigate_and_find_submit_button(
    aclient: httpx.AsyncClient,
    target_url: str,
) -> tuple[int, int]:
    start_resp = await aclient.post("/api/browser/start", json={"url": target_url})
    assert start_resp.status_code == 200
    nav_resp = await aclient.post(
        "/api/v1/computers/default/actions",
        json={"actor": "human", "type": "navigate", "url": target_url},
    )
    assert nav_resp.status_code == 200

    ctx_resp = await aclient.get("/api/browser/context")
    assert ctx_resp.status_code == 200
    elements = ctx_resp.json().get("elements", [])
    assert isinstance(elements, list)
    for elem in elements:
        if isinstance(elem, dict) and elem.get("tag") == "button":
            return int(elem["x"]), int(elem["y"])
    raise AssertionError(f"Submit button not found in browser context: {elements!r}")


class _WsByteReader:
    """Exact byte-stream reader over binary WebSocket frames."""

    def __init__(self, ws: ClientConnection) -> None:
        self._ws = ws
        self._buf = bytearray()

    async def read_exact(self, count: int, *, timeout: float = 5.0) -> bytes:
        deadline = time.monotonic() + timeout
        while len(self._buf) < count:
            remaining = max(0.05, deadline - time.monotonic())
            chunk = await asyncio.wait_for(self._ws.recv(), timeout=remaining)
            if isinstance(chunk, str):
                self._buf.extend(chunk.encode("utf-8"))
            else:
                self._buf.extend(chunk)
        out = bytes(self._buf[:count])
        del self._buf[:count]
        return out


async def _complete_client_rfb_none_handshake(ws: ClientConnection) -> _WsByteReader:
    reader = _WsByteReader(ws)
    banner = await reader.read_exact(12)
    assert banner == b"RFB 003.008\n"
    await ws.send(b"RFB 003.008\n")

    num_types_raw = await reader.read_exact(1)
    num_types = num_types_raw[0]
    assert num_types >= 1
    sec_types = list(await reader.read_exact(num_types))
    assert 1 in sec_types
    await ws.send(b"\x01")

    sec_result = await reader.read_exact(4)
    assert sec_result == b"\x00\x00\x00\x00"

    # ClientInit (shared=1)
    await ws.send(b"\x01")

    # ServerInit: 24 bytes header + desktop name
    srv_init = await reader.read_exact(24)
    width, height, _bpp, _depth, _big, _true, _rm, _gm, _bm, _rs, _gs, _bs, name_len = (
        struct.unpack("!HHBBBBHHHBBB3xI", srv_init)
    )
    desktop_name = await reader.read_exact(int(name_len))
    assert (width, height) == (640, 480)
    assert desktop_name == b"MockRFB"
    return reader


async def _post_secure_fill_and_wait_sse(
    aclient: httpx.AsyncClient,
    *,
    form_id: str,
    payload: dict[str, Any],
    timeout: float = 8.0,
) -> tuple[httpx.Response, SseFrame]:
    """Subscribe to SSE first, POST /api/v1/vault/secure-fill, and capture resolved SSE."""
    sse_connected = asyncio.Event()
    sse_first_line = asyncio.Event()
    resolved_holder: dict[str, SseFrame] = {}

    async def _listen() -> None:
        async for frame in iter_sse_events(
            aclient,
            timeout=timeout,
            on_connected=sse_connected,
            on_first_line=sse_first_line,
        ):
            if (
                frame.event_type == "hitl.secure_form.resolved"
                and isinstance(frame.data, dict)
                and frame.data.get("payload", {}).get("form", {}).get("id") == form_id
            ):
                resolved_holder["frame"] = frame
                return

    listen_task = asyncio.create_task(_listen())
    try:
        await asyncio.wait_for(sse_connected.wait(), timeout=min(5.0, timeout))
        if listen_task.done() and not listen_task.cancelled():
            exc = listen_task.exception()
            if exc is not None:
                raise exc
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(sse_first_line.wait(), timeout=min(0.25, timeout))

        fill_resp = await aclient.post("/api/v1/vault/secure-fill", json=payload)
        await asyncio.wait_for(listen_task, timeout=timeout)
    finally:
        if not listen_task.done():
            listen_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await listen_task

    assert "frame" in resolved_holder
    return fill_resp, resolved_holder["frame"]


# ==============================================================================
# Feature #1: Server-side Auth, Token Propagation, CORS, Rate Limiting & Hygiene
# (6 Tier 1 + 7 Tier 2 = 13 tests)
# ==============================================================================


def test_t1_auth_health_and_app_exempt_while_api_protected(
    auth_server: IsolatedServer,
) -> None:
    """Tier 1 (F1): /health & /app?token= succeed while unauthenticated APIs return 401."""
    token = auth_server.web_token
    assert token is not None

    with httpx.Client(base_url=auth_server.base_url, timeout=10.0) as unauth:
        health = unauth.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        app_resp = unauth.get(f"/app?token={token}")
        assert app_resp.status_code == 200
        assert "no-store" in app_resp.headers.get("cache-control", "").lower()
        assert "window.__GB_TOKEN" in app_resp.text
        assert "importmap" in app_resp.text
        assert token not in app_resp.text

        protected_gets = (
            "/api/v1/bots",
            "/api/system/info",
            "/api/v1/vault/secrets",
            "/api/v1/events/stream",
            "/",
            "/studio-legacy",
            "/tasks/none",
        )
        for path in protected_gets:
            resp = unauth.get(path)
            assert resp.status_code == 401, f"Expected 401 for GET {path}, got {resp.status_code}"
            assert resp.headers.get("www-authenticate") == "Bearer"
            assert "Unauthorized" in resp.json()["detail"]

        vnc_tok = unauth.post("/api/v1/computers/default/vnc-token")
        assert vnc_tok.status_code == 401
        assert vnc_tok.headers.get("www-authenticate") == "Bearer"
        assert "Unauthorized" in vnc_tok.json()["detail"]


async def test_t1_auth_accepts_bearer_header_and_query_token_on_rest_and_sse(
    auth_server: IsolatedServer,
) -> None:
    """Tier 1 (F1): Valid Bearer header and ?token= both authenticate REST and SSE."""
    token = auth_server.web_token
    assert token is not None

    async with httpx.AsyncClient(base_url=auth_server.base_url, timeout=10.0) as raw:
        bearer_headers = {"Authorization": f"Bearer {token}"}
        for endpoint in ("/api/v1/bots", "/api/system/info", "/api/v1/vault/secrets"):
            r_hdr = await raw.get(endpoint, headers=bearer_headers)
            assert r_hdr.status_code == 200
            r_qry = await raw.get(f"{endpoint}?token={token}")
            assert r_qry.status_code == 200

        r_vnc_hdr = await raw.post(
            "/api/v1/computers/default/vnc-token",
            headers=bearer_headers,
        )
        assert r_vnc_hdr.status_code == 200
        assert r_vnc_hdr.json()["cap_token"]

        r_vnc_qry = await raw.post(f"/api/v1/computers/default/vnc-token?token={token}")
        assert r_vnc_qry.status_code == 200
        assert r_vnc_qry.json()["cap_token"]

        async def _trigger() -> None:
            await asyncio.sleep(0.25)
            r_msg = await raw.post(
                "/api/v1/threads/thr_bot_chief/messages",
                headers=bearer_headers,
                json={"content": "/approval Auth SSE Probe"},
            )
            assert r_msg.status_code == 202

        task = asyncio.create_task(_trigger())
        frame = await wait_for_sse_event(
            auth_server.url("/api/v1/events/stream", include_token=True),
            lambda f: f.event_type == "hitl.approval.requested",
            timeout=5.0,
        )
        await task
        assert isinstance(frame.data, dict)
        assert frame.data["payload"]["approval"]["title"] == "Auth SSE Probe"


def test_t1_auth_webhook_uses_own_bearer_key_not_web_token(
    auth_server: IsolatedServer,
) -> None:
    """Tier 1 (F1): Webhook routines bypass web token middleware and enforce webhook_key."""
    with auth_server.client() as client:
        create_resp = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Auth Webhook Probe",
                "instruction": "/approval Webhook triggered",
                "schedule_type": "webhook",
                "enabled": True,
            },
        )
        assert create_resp.status_code == 201
        routine = create_resp.json()
        routine_id = str(routine["id"])
        webhook_key = str(routine["webhook_key"])
        assert webhook_key

    with httpx.Client(base_url=auth_server.base_url, timeout=10.0) as unauth:
        # Missing Bearer key -> 401
        assert unauth.post(f"/api/v1/webhooks/routines/{routine_id}").status_code == 401
        # Web token is NOT accepted as webhook_key -> 401
        assert (
            unauth.post(
                f"/api/v1/webhooks/routines/{routine_id}",
                headers={"Authorization": f"Bearer {auth_server.web_token}"},
            ).status_code
            == 401
        )
        # Valid webhook_key with NO web token -> 202
        ok_resp = unauth.post(
            f"/api/v1/webhooks/routines/{routine_id}",
            headers={"Authorization": f"Bearer {webhook_key}"},
        )
        assert ok_resp.status_code == 202
        assert ok_resp.json()["trigger"] == "webhook"

    # Disable routine -> 409 even with valid webhook_key
    with auth_server.client() as client:
        patch_resp = client.patch(
            f"/api/v1/routines/{routine_id}",
            json={"enabled": False},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["enabled"] is False

    with httpx.Client(base_url=auth_server.base_url, timeout=10.0) as unauth:
        disabled_resp = unauth.post(
            f"/api/v1/webhooks/routines/{routine_id}",
            headers={"Authorization": f"Bearer {webhook_key}"},
        )
        assert disabled_resp.status_code == 409


async def test_t1_auth_ws_terminal_and_ws_browser_accept_valid_token(
    auth_server: IsolatedServer,
    server: IsolatedServer,
) -> None:
    """Tier 1 (F1): /ws/terminal and /ws/browser accept valid query & Bearer tokens."""
    async with websockets.connect(auth_server.ws_url("/ws/terminal")) as ws_term_q:
        msg = await _ws_recv_json(ws_term_q)
        assert msg["type"] == "ready"
        assert isinstance(msg.get("cwd"), str)

    async with websockets.connect(
        auth_server.ws_url("/ws/terminal", include_token=False),
        additional_headers=auth_server.auth_headers(),
    ) as ws_term_h:
        msg_h = await _ws_recv_json(ws_term_h)
        assert msg_h["type"] == "ready"
        await ws_term_h.send(json.dumps({"type": "input", "data": "echo PTY_AUTH_OK\r"}))
        output_buf = ""
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and "PTY_AUTH_OK" not in output_buf:
            frame = await _ws_recv_json(ws_term_h, timeout=3.0)
            if frame.get("type") == "output":
                output_buf += str(frame.get("data", ""))
        assert "PTY_AUTH_OK" in output_buf

    async with websockets.connect(auth_server.ws_url("/ws/browser")) as ws_br_q:
        st_msg = await _ws_recv_json(ws_br_q)
        assert st_msg["type"] == "status"
        assert "running" in st_msg

    async with websockets.connect(
        auth_server.ws_url("/ws/browser", include_token=False),
        additional_headers=auth_server.auth_headers(),
    ) as ws_br_h:
        st_msg_h = await _ws_recv_json(ws_br_h)
        assert st_msg_h["type"] == "status"

    # Also verify /ws/terminal works cleanly when server has no web token configured
    async with websockets.connect(server.ws_url("/ws/terminal")) as ws_noauth:
        ready_noauth = await _ws_recv_json(ws_noauth)
        assert ready_noauth["type"] == "ready"


async def test_t1_auth_computer_ws_dual_token_cap_or_web_token_all_endpoints(
    auth_server: IsolatedServer,
    server: IsolatedServer,
) -> None:
    """Tier 1 (F1): Computer WS endpoints accept cap_token or configured web token."""
    with auth_server.client() as client:
        tok = mint_cap_token(client, vm_id="default")
    cap_token = str(tok["cap_token"])

    # cap_token alone (no web token) succeeds on control, screencast, and pty
    async with websockets.connect(
        f"{auth_server.ws_base_url}/ws/v1/computers/default/control?cap_token={cap_token}"
    ) as ws_ctrl:
        msg = await _ws_recv_json(ws_ctrl)
        assert msg["op"] == "computer.state"

    async with websockets.connect(
        f"{auth_server.ws_base_url}/ws/v1/computers/default/screencast?cap_token={cap_token}"
    ) as ws_scr:
        msg_scr = await _ws_recv_json(ws_scr)
        assert msg_scr["type"] == "status"

    async with websockets.connect(
        f"{auth_server.ws_base_url}/ws/v1/computers/default/pty/s1?cap_token={cap_token}"
    ) as ws_pty:
        await ws_pty.send("echo CAP_PTY_OK\r")
        pty_out = ""
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and "CAP_PTY_OK" not in pty_out:
            chunk = await asyncio.wait_for(ws_pty.recv(), timeout=3.0)
            if isinstance(chunk, str):
                pty_out += chunk
        assert "CAP_PTY_OK" in pty_out

    # web_token alone (no cap_token) also succeeds on auth_server
    async with websockets.connect(
        auth_server.ws_url("/ws/v1/computers/default/control")
    ) as ws_web:
        msg_web = await _ws_recv_json(ws_web)
        assert msg_web["op"] == "computer.state"

    # Without GROKBOT_WEB_TOKEN, /ws/v1/computers/* still strictly requires cap_token
    await _assert_ws_rejected_handshake(f"{server.ws_base_url}/ws/v1/computers/default/control")
    with server.client() as noauth_client:
        noauth_tok = mint_cap_token(noauth_client, vm_id="default")
    async with websockets.connect(
        f"{server.ws_base_url}{noauth_tok['ws_control_url']}"
    ) as ws_noauth_cap:
        st = await _ws_recv_json(ws_noauth_cap)
        assert st["op"] == "computer.state"


async def test_t1_auth_vnc_ws_handshake_and_rfb_input_gate(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    """Tier 1 (F1/F4): /ws/v1/computers/{vm}/vnc authenticates, handshakes DES RFB, gates 0x04."""
    srv = server_factory(web_token="e2e-vnc-tok", with_mock_rfb=True, name="auth_rfb")
    assert srv.mock_rfb is not None

    with srv.client() as client:
        tok = mint_cap_token(client, vm_id="default")

    # web_token alone (no cap_token) succeeds on /vnc and completes RFB 3.8 handshake
    async with websockets.connect(
        srv.ws_url("/ws/v1/computers/default/vnc"),
        subprotocols=[Subprotocol("binary")],
    ) as ws_web:
        await _complete_client_rfb_none_handshake(ws_web)
        assert srv.mock_rfb.handshakes_completed >= 1

    # cap_token alone (no web_token) succeeds on /vnc and enforces RfbInputGate
    vnc_cap_url = f"{srv.ws_base_url}{tok['ws_vnc_url']}"
    with srv.client() as client:
        try:
            async with websockets.connect(
                vnc_cap_url,
                subprotocols=[Subprotocol("binary")],
            ) as ws_cap:
                reader = await _complete_client_rfb_none_handshake(ws_cap)
                assert srv.mock_rfb.handshakes_completed >= 2

                fb_req = struct.pack("!BBHHHH", 3, 1, 0, 0, 640, 480)
                key_ev = struct.pack("!BBHI", 4, 1, 0, 0x0061)

                # Agent mode: 0x03 FramebufferUpdateRequest passes, 0x04 KeyEvent is dropped
                srv.mock_rfb.reset_records()
                await ws_cap.send(fb_req + key_ev)
                reply = await reader.read_exact(4)
                assert reply == b"\x00\x00\x00\x00"
                await asyncio.sleep(0.15)
                assert srv.mock_rfb.wait_for_messages(min_count=1, timeout=2.0) == [0x03]
                assert 0x04 not in srv.mock_rfb.received_message_types

                # Human takeover mode: 0x04 KeyEvent is forwarded intact
                tk_resp = client.post(
                    "/api/v1/computers/default/takeover",
                    json={"owner": "vnc_op"},
                )
                assert tk_resp.status_code == 200
                assert tk_resp.json()["control_owner"] == "human_takeover"

                srv.mock_rfb.reset_records()
                await ws_cap.send(key_ev)
                assert srv.mock_rfb.wait_for_messages(min_count=1, timeout=3.0) == [0x04]
                assert srv.mock_rfb.received_messages == [(0x04, key_ev)]
        finally:
            client.post("/api/v1/computers/default/handback", json={"reason": "cleanup"})


async def test_t1_auth_playwright_studio_app_with_token_loads_cleanly(
    auth_server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Tier 1 (F1): Playwright Studio /app?token=... boots and propagates token cleanly."""
    await strict_browser_page.goto(auth_server.url("/app"), wait_until="networkidle")
    await strict_browser_page.wait_for_selector("text=Grok Bot")

    loaded_token = await strict_browser_page.evaluate("window.__GB_TOKEN")
    assert loaded_token == auth_server.web_token
    strict_browser_page.assert_clean()


def test_t2_auth_rejects_missing_prefix_substring_and_mismatched_dual_tokens(
    auth_server: IsolatedServer,
) -> None:
    """Tier 2 (F1): Prefix/suffix/empty/wrong/mismatched tokens return 401 across APIs."""
    token = auth_server.web_token
    assert token is not None and len(token) > 4

    bad_candidates = (
        token[:-1],
        token + "x",
        token[1:],
        "completely-wrong-token",
        "",
    )
    get_endpoints = (
        "/api/v1/bots",
        "/api/system/info",
        "/api/v1/vault/secrets",
        "/api/v1/events/stream",
    )

    with httpx.Client(base_url=auth_server.base_url, timeout=10.0) as client:
        for bad in bad_candidates:
            for path in get_endpoints:
                r_q = client.get(f"{path}?token={bad}")
                assert r_q.status_code == 401
                assert "Unauthorized" in r_q.json()["detail"]

                if bad:
                    r_h = client.get(path, headers={"Authorization": f"Bearer {bad}"})
                    assert r_h.status_code == 401
                    assert "Unauthorized" in r_h.json()["detail"]

            r_vnc_q = client.post(f"/api/v1/computers/default/vnc-token?token={bad}")
            assert r_vnc_q.status_code == 401
            assert "Unauthorized" in r_vnc_q.json()["detail"]

        # Mismatched dual tokens must NEVER let a valid token mask an invalid one
        for path in get_endpoints:
            r_m1 = client.get(
                f"{path}?token={token}",
                headers={"Authorization": f"Bearer {token[:-1]}"},
            )
            assert r_m1.status_code == 401

            r_m2 = client.get(
                f"{path}?token={token[:-1]}",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r_m2.status_code == 401


async def test_t2_auth_ws_terminal_and_ws_browser_reject_unauthorized(
    auth_server: IsolatedServer,
) -> None:
    """Tier 2 (F1): /ws/terminal and /ws/browser reject missing/prefix/wrong/mismatched tokens."""
    token = auth_server.web_token
    assert token is not None

    for path in ("/ws/terminal", "/ws/browser"):
        await _assert_ws_rejected_handshake(auth_server.ws_url(path, include_token=False))
        await _assert_ws_rejected_handshake(f"{auth_server.ws_base_url}{path}?token=")
        await _assert_ws_rejected_handshake(f"{auth_server.ws_base_url}{path}?token={token[:-1]}")
        await _assert_ws_rejected_handshake(f"{auth_server.ws_base_url}{path}?token={token}x")
        await _assert_ws_rejected_handshake(
            auth_server.ws_url(path, include_token=False),
            headers={"Authorization": f"Bearer {token[:-1]}"},
        )
        await _assert_ws_rejected_handshake(
            auth_server.ws_url(path, include_token=True),
            headers={"Authorization": f"Bearer {token}x"},
        )


async def test_t2_auth_computer_ws_rejects_tampered_empty_and_web_masked_cap_token(
    auth_server: IsolatedServer,
) -> None:
    """Tier 2 (F1): Tampered/empty cap_token is rejected even alongside valid web token."""
    token = auth_server.web_token
    assert token is not None

    with auth_server.client() as client:
        tok = mint_cap_token(client, vm_id="default")
    cap_token = str(tok["cap_token"])
    tampered = cap_token[:-2] + ("AA" if not cap_token.endswith("AA") else "BB")

    for endpoint in ("control", "screencast", "pty/s1", "vnc"):
        base = f"{auth_server.ws_base_url}/ws/v1/computers/default/{endpoint}"
        await _assert_ws_rejected_handshake(base)
        await _assert_ws_rejected_handshake(f"{base}?cap_token=")
        await _assert_ws_rejected_handshake(f"{base}?cap_token={tampered}")
        await _assert_ws_rejected_handshake(f"{base}?cap_token={tampered}&token={token}")
        await _assert_ws_rejected_handshake(f"{base}?cap_token=&token={token}")


async def test_t2_auth_cap_token_cross_vm_scope_rejected(
    auth_server: IsolatedServer,
) -> None:
    """Tier 2 (F1): cap_token minted for vm_alpha is rejected for default and vm_beta."""
    with auth_server.client() as client:
        tok_alpha = mint_cap_token(client, vm_id="vm_alpha")
    cap_alpha = str(tok_alpha["cap_token"])

    async with websockets.connect(
        f"{auth_server.ws_base_url}/ws/v1/computers/vm_alpha/control?cap_token={cap_alpha}"
    ) as ws_ok:
        msg = await _ws_recv_json(ws_ok)
        assert msg["op"] == "computer.state"
        assert msg["status"]["vm_id"] == "vm_alpha"

    for wrong_vm in ("default", "vm_beta"):
        for endpoint in ("control", "screencast", "pty/s1", "vnc"):
            await _assert_ws_rejected_handshake(
                f"{auth_server.ws_base_url}/ws/v1/computers/{wrong_vm}/{endpoint}"
                f"?cap_token={cap_alpha}"
            )


async def test_t2_auth_cap_token_expiry_rejected_after_ttl(
    auth_server: IsolatedServer,
) -> None:
    """Tier 2 (F1): cap_token with minimum 5s TTL works immediately and fails after expiry."""
    with auth_server.client() as client:
        tok = mint_cap_token(client, vm_id="default", ttl_seconds=5)
    assert tok["ttl_seconds"] == 5
    ws_url = f"{auth_server.ws_base_url}{tok['ws_control_url']}"

    async with websockets.connect(ws_url) as ws_ok:
        msg = await _ws_recv_json(ws_ok)
        assert msg["op"] == "computer.state"

    await asyncio.sleep(5.3)
    await _assert_ws_rejected_handshake(ws_url)


def test_t2_cors_loopback_allowed_external_blocked_and_env_override(
    auth_server: IsolatedServer,
    server_factory: Callable[..., IsolatedServer],
) -> None:
    """Tier 2 (F1): Default CORS allows loopback, blocks external, respects env & wildcard."""
    with httpx.Client(base_url=auth_server.base_url, timeout=10.0) as client:
        ok_pre = client.options(
            "/api/v1/bots",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert ok_pre.status_code == 200
        assert ok_pre.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"
        assert ok_pre.headers.get("access-control-allow-credentials") == "true"

        ok_get = client.get(
            "/api/v1/bots",
            headers={**auth_server.auth_headers(), "Origin": "http://127.0.0.1:5173"},
        )
        assert ok_get.status_code == 200
        assert ok_get.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"
        assert ok_get.headers.get("access-control-allow-credentials") == "true"

        evil_pre = client.options(
            "/api/v1/bots",
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-origin" not in evil_pre.headers

        evil_get = client.get(
            "/api/v1/bots",
            headers={**auth_server.auth_headers(), "Origin": "https://evil.example.com"},
        )
        assert evil_get.status_code == 200
        assert "access-control-allow-origin" not in evil_get.headers

    custom_srv = server_factory(
        web_token="cors-tok",
        extra_env={"GROKBOT_CORS_ORIGINS": "https://studio.internal"},
        name="cors_override",
    )
    with httpx.Client(base_url=custom_srv.base_url, timeout=10.0) as custom_client:
        allowed = custom_client.options(
            "/api/v1/bots",
            headers={
                "Origin": "https://studio.internal",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert allowed.status_code == 200
        assert allowed.headers.get("access-control-allow-origin") == "https://studio.internal"

        blocked_loopback = custom_client.options(
            "/api/v1/bots",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-origin" not in blocked_loopback.headers

    wildcard_srv = server_factory(
        web_token="cors-wild",
        extra_env={"GROKBOT_CORS_ORIGINS": "*"},
        name="cors_wildcard",
    )
    with httpx.Client(base_url=wildcard_srv.base_url, timeout=10.0) as wild_client:
        wild_health = wild_client.get(
            "/health",
            headers={"Origin": "https://any.example.com"},
        )
        assert wild_health.status_code == 200
        assert wild_health.headers.get("access-control-allow-origin") == "*"
        assert "access-control-allow-credentials" not in wild_health.headers

        wild_bots = wild_client.get(
            "/api/v1/bots",
            headers={**wildcard_srv.auth_headers(), "Origin": "https://any.example.com"},
        )
        assert wild_bots.status_code == 200
        assert wild_bots.headers.get("access-control-allow-origin") == "*"
        assert "access-control-allow-credentials" not in wild_bots.headers


def test_t2_rate_limit_vnc_token_and_secure_fill_429_and_0600_key_hygiene(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    """Tier 2 (F1): Vault/cap key files have 0o600 mode; vnc-token & secure-fill enforce 429."""
    rl_srv = server_factory(web_token="rl-tok-123", cap_secret="", name="rl_sec")

    vault_key = rl_srv.workspace_db_path.with_name(f".{rl_srv.workspace_db_path.stem}.vault.key")
    cap_key = rl_srv.workspace_db_path.parent / ".grokbot_cap_secret"
    assert vault_key.is_file()
    assert cap_key.is_file()
    assert stat.S_IMODE(vault_key.stat().st_mode) == 0o600
    assert stat.S_IMODE(cap_key.stat().st_mode) == 0o600

    # Unauthenticated requests return 401 before touching the rate limiter
    with httpx.Client(base_url=rl_srv.base_url, timeout=10.0) as unauth:
        for _ in range(35):
            assert unauth.post("/api/v1/computers/default/vnc-token").status_code == 401
            assert unauth.post("/api/v1/vault/secure-fill", json={}).status_code == 401

    with rl_srv.client() as authed:
        # Exhaust vnc_token bucket (30/60s -> 31st returns 429)
        for idx in range(30):
            r = authed.post("/api/v1/computers/default/vnc-token")
            assert r.status_code == 200, f"vnc-token call {idx + 1} failed: {r.status_code}"
        r_vnc_limited = authed.post("/api/v1/computers/default/vnc-token")
        assert r_vnc_limited.status_code == 429
        assert int(r_vnc_limited.headers["retry-after"]) >= 1
        assert "Rate limit exceeded" in r_vnc_limited.json()["detail"]

        # Exhaust secure_fill bucket (20/60s -> 21st returns 429)
        for idx in range(20):
            r_sf = authed.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": f"missing_form_{idx}"},
            )
            assert r_sf.status_code == 404, f"secure-fill call {idx + 1} unexpected: {r_sf.text}"
        r_sf_limited = authed.post(
            "/api/v1/vault/secure-fill",
            json={"form_id": "missing_form_21"},
        )
        assert r_sf_limited.status_code == 429
        assert int(r_sf_limited.headers["retry-after"]) >= 1
        assert "Rate limit exceeded" in r_sf_limited.json()["detail"]


def test_t2_rate_limit_attachments_webhooks_and_messages_429(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    """Tier 2 (F1): attachments (60/60s), webhooks (30/60s per-routine), & messages (60/60s)."""
    rl_srv = server_factory(web_token="rl-buckets-tok", name="rl_buckets")

    with rl_srv.client() as authed:
        # 1) attachments bucket (60/60s -> 61st returns 429)
        for idx in range(60):
            r_att = authed.post(
                "/api/v1/attachments",
                params={"filename": f"rl_{idx}.txt"},
                content=b"x",
            )
            assert r_att.status_code == 201, f"attachment call {idx + 1} failed: {r_att.text}"
        r_att_limited = authed.post(
            "/api/v1/attachments",
            params={"filename": "rl_61.txt"},
            content=b"x",
        )
        assert r_att_limited.status_code == 429
        assert int(r_att_limited.headers["retry-after"]) >= 1
        assert "Rate limit exceeded" in r_att_limited.json()["detail"]

        # 2) webhooks bucket (30/60s, isolated per routine_id)
        r1 = authed.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "RL Webhook 1",
                "instruction": "/note RL1",
                "schedule_type": "webhook",
                "enabled": True,
            },
        )
        assert r1.status_code == 201
        r1_id = str(r1.json()["id"])
        r1_key = str(r1.json()["webhook_key"])

        r2 = authed.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "RL Webhook 2",
                "instruction": "/note RL2",
                "schedule_type": "webhook",
                "enabled": True,
            },
        )
        assert r2.status_code == 201
        r2_id = str(r2.json()["id"])
        r2_key = str(r2.json()["webhook_key"])

        with httpx.Client(base_url=rl_srv.base_url, timeout=10.0) as unauth:
            first_wh = unauth.post(
                f"/api/v1/webhooks/routines/{r1_id}",
                headers={"Authorization": f"Bearer {r1_key}"},
            )
            assert first_wh.status_code == 202

            # Disable r1 so next 29 hits return 409 without spawning 29 background tasks
            assert (
                authed.patch(f"/api/v1/routines/{r1_id}", json={"enabled": False}).status_code
                == 200
            )
            for idx in range(29):
                r_wh = unauth.post(
                    f"/api/v1/webhooks/routines/{r1_id}",
                    headers={"Authorization": f"Bearer {r1_key}"},
                )
                assert r_wh.status_code == 409, f"webhook call {idx + 2} unexpected: {r_wh.text}"

            # Re-enable r1 and verify 31st hit returns 429
            assert (
                authed.patch(f"/api/v1/routines/{r1_id}", json={"enabled": True}).status_code
                == 200
            )
            r_wh_limited = unauth.post(
                f"/api/v1/webhooks/routines/{r1_id}",
                headers={"Authorization": f"Bearer {r1_key}"},
            )
            assert r_wh_limited.status_code == 429
            assert int(r_wh_limited.headers["retry-after"]) >= 1
            assert "Rate limit exceeded" in r_wh_limited.json()["detail"]

            # Separate routine r2 still succeeds (per-routine isolation)
            r2_ok = unauth.post(
                f"/api/v1/webhooks/routines/{r2_id}",
                headers={"Authorization": f"Bearer {r2_key}"},
            )
            assert r2_ok.status_code == 202

        # 3) messages bucket (60/60s per IP across all threads)
        for idx in range(60):
            r_msg = authed.post(
                "/api/v1/threads/thr_rl_missing/messages",
                json={"content": f"rl {idx}"},
            )
            assert r_msg.status_code == 404, f"missing-thread call {idx + 1}: {r_msg.text}"
        r_msg_limited = authed.post(
            "/api/v1/threads/thr_bot_chief/messages",
            json={"content": "should hit rate limit"},
        )
        assert r_msg_limited.status_code == 429
        assert int(r_msg_limited.headers["retry-after"]) >= 1
        assert "Rate limit exceeded" in r_msg_limited.json()["detail"]


# ==============================================================================
# Feature #2: Vault Secrets, Secure Forms, secure-fill Origin & LiveBrowser API
# (5 Tier 1 + 6 Tier 2 = 11 tests)
# ==============================================================================


def test_t1_vault_secrets_crud_never_leaks_plaintext(server: IsolatedServer) -> None:
    """Tier 1 (F2): Vault secrets CRUD encrypts at rest and omits plaintext everywhere."""
    with server.client() as client:
        r_bot = client.post(
            "/api/v1/vault/secrets",
            json={
                "bot_id": "bot_chief",
                "name": "ERP Creds",
                "domain": "erp.internal",
                "username": "alice_op",
                "secret_value": _SENSITIVE_PASSWORD_1,
            },
        )
        assert r_bot.status_code == 201
        sec_bot = r_bot.json()
        assert sec_bot["bot_id"] == "bot_chief"
        assert sec_bot["username_hint"] == "alice_op"
        assert set(sec_bot["field_names"]) == {"username", "password"}
        assert _SENSITIVE_PASSWORD_1 not in r_bot.text

        r_glob = client.post(
            "/api/v1/vault/secrets",
            json={
                "bot_id": None,
                "name": "Global Creds",
                "domain": "sso.internal",
                "username": "global_user",
                "secret_value": _SENSITIVE_PASSWORD_2,
            },
        )
        assert r_glob.status_code == 201
        sec_glob = r_glob.json()

        listed = client.get("/api/v1/vault/secrets?bot_id=bot_chief")
        assert listed.status_code == 200
        ids = {item["id"] for item in listed.json()["secrets"]}
        assert {sec_bot["id"], sec_glob["id"]}.issubset(ids)
        assert _SENSITIVE_PASSWORD_1 not in listed.text
        assert _SENSITIVE_PASSWORD_2 not in listed.text

        # Raw SQLite check: encrypted_payload and audit log never contain plaintext secret
        with sqlite3.connect(server.workspace_db_path) as conn:
            rows = conn.execute("SELECT encrypted_payload FROM vault_secrets").fetchall()
            assert len(rows) >= 2
            for (enc_blob,) in rows:
                decoded = base64.b64decode(str(enc_blob))
                assert decoded.startswith((b"v2g:", b"v2h:"))
                assert _SENSITIVE_PASSWORD_1 not in str(enc_blob)
                assert _SENSITIVE_PASSWORD_2 not in str(enc_blob)
            audit_rows = conn.execute("SELECT detail_json FROM workspace_audit_log").fetchall()
            for (detail,) in audit_rows:
                assert _SENSITIVE_PASSWORD_1 not in str(detail)
                assert _SENSITIVE_PASSWORD_2 not in str(detail)

        del_resp = client.delete(f"/api/v1/vault/secrets/{sec_bot['id']}")
        assert del_resp.status_code == 200
        assert del_resp.json() == {"deleted": True}
        assert client.delete(f"/api/v1/vault/secrets/{sec_bot['id']}").status_code == 404


async def test_t1_secure_form_create_and_cancel_emits_sse(server: IsolatedServer) -> None:
    """Tier 1 (F2): Creating and cancelling a secure form resolves status and emits SSE."""
    async with server.async_client() as aclient:
        create_resp = await aclient.post(
            "/api/v1/secure-forms",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "kind": "form",
                "domain": "erp.internal",
                "title": "ERP Sign In",
                "fields": [
                    {"name": "username", "label": "Username", "secret": False},
                    {"name": "password", "label": "Password", "secret": True},
                ],
                "allow_vault_save": True,
            },
        )
        assert create_resp.status_code == 201
        form = create_resp.json()
        assert form["status"] == "pending"
        form_id = str(form["id"])

        async def _cancel() -> None:
            await asyncio.sleep(0.1)
            r_cancel = await aclient.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": form_id, "action": "cancel"},
            )
            assert r_cancel.status_code == 200
            body = r_cancel.json()
            assert body["filled"] is False
            assert body["saved_secret_id"] is None
            assert body["status"] == "cancelled"

        task = asyncio.create_task(_cancel())
        ev = await wait_for_sse_event(
            aclient,
            lambda f: (
                f.event_type == "hitl.secure_form.resolved"
                and isinstance(f.data, dict)
                and f.data.get("payload", {}).get("form", {}).get("id") == form_id
            ),
            timeout=5.0,
        )
        await task
        assert isinstance(ev.data, dict)
        assert ev.data["payload"]["form"]["status"] == "cancelled"

        thread_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
        assert thread_resp.status_code == 200
        matched = [
            f for f in thread_resp.json()["secure_forms"] if f["id"] == form_id
        ]
        assert len(matched) == 1
        assert matched[0]["status"] == "cancelled"


async def test_t1_secure_fill_real_browser_autofill_and_submit(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 1 (F2): secure-fill fills live Playwright DOM, resolves submitted + SSE, submits."""
    async with browser_server.async_client() as aclient:
        try:
            btn_x, btn_y = await _anavigate_and_find_submit_button(aclient, login_server.login_url)

            form_resp = await aclient.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "kind": "form",
                    "domain": login_server.domain_with_port,
                    "title": "Plant Portal Login",
                    "fields": [
                        {"name": "username", "label": "Username", "secret": False},
                        {"name": "password", "label": "Password", "secret": True},
                    ],
                    "allow_vault_save": False,
                },
            )
            assert form_resp.status_code == 201
            form_id = str(form_resp.json()["id"])

            fill_resp, ev = await _post_secure_fill_and_wait_sse(
                aclient,
                form_id=form_id,
                payload={
                    "form_id": form_id,
                    "bot_id": "bot_chief",
                    "domain": login_server.domain_with_port,
                    "values": {"username": "op_alice", "password": _SENSITIVE_PASSWORD_1},
                    "save_to_vault": False,
                },
            )
            assert fill_resp.status_code == 200
            fill_body = fill_resp.json()
            assert fill_body["filled"] is True
            assert fill_body["saved_secret_id"] is None
            assert _SENSITIVE_PASSWORD_1 not in fill_resp.text
            assert _SENSITIVE_PASSWORD_1 not in ev.raw
            assert isinstance(ev.data, dict)
            assert ev.data["payload"]["form"]["id"] == form_id
            assert ev.data["payload"]["form"]["status"] == "submitted"

            thread_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
            assert thread_resp.status_code == 200
            assert _SENSITIVE_PASSWORD_1 not in thread_resp.text
            matched = [f for f in thread_resp.json()["secure_forms"] if f["id"] == form_id]
            assert len(matched) == 1
            assert matched[0]["status"] == "submitted"

            click_resp = await aclient.post(
                "/api/v1/computers/default/actions",
                json={"actor": "human", "type": "click", "x": btn_x, "y": btn_y},
            )
            assert click_resp.status_code == 200
            subs = await asyncio.to_thread(login_server.wait_for_submissions, 1, 5.0)
            assert subs == [{"username": "op_alice", "password": _SENSITIVE_PASSWORD_1}]
        finally:
            await aclient.post("/api/browser/stop")


async def test_t1_secure_fill_save_to_vault_stores_encrypted_secret(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 1 (F2): save_to_vault=True stores encrypted secret, resolves submitted + SSE."""
    async with browser_server.async_client() as aclient:
        try:
            await _anavigate_and_find_submit_button(aclient, login_server.login_url)
            form_resp = await aclient.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "kind": "form",
                    "domain": login_server.domain_with_port,
                    "title": "Save To Vault Form",
                    "fields": [
                        {"name": "username", "label": "Username", "secret": False},
                        {"name": "password", "label": "Password", "secret": True},
                    ],
                    "allow_vault_save": True,
                },
            )
            assert form_resp.status_code == 201
            form_id = str(form_resp.json()["id"])

            fill_resp, ev = await _post_secure_fill_and_wait_sse(
                aclient,
                form_id=form_id,
                payload={
                    "form_id": form_id,
                    "bot_id": "bot_chief",
                    "values": {"username": "op_bob", "password": _SENSITIVE_PASSWORD_2},
                    "save_to_vault": True,
                    "vault_name": "Plant Portal Bob",
                },
            )
            assert fill_resp.status_code == 200
            body = fill_resp.json()
            assert body["filled"] is True
            saved_id = body["saved_secret_id"]
            assert isinstance(saved_id, str) and saved_id
            assert _SENSITIVE_PASSWORD_2 not in fill_resp.text
            assert _SENSITIVE_PASSWORD_2 not in ev.raw
            assert isinstance(ev.data, dict)
            assert ev.data["payload"]["form"]["status"] == "submitted"

            thread_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
            assert thread_resp.status_code == 200
            assert _SENSITIVE_PASSWORD_2 not in thread_resp.text
            matched = [f for f in thread_resp.json()["secure_forms"] if f["id"] == form_id]
            assert len(matched) == 1
            assert matched[0]["status"] == "submitted"

            secrets_resp = await aclient.get("/api/v1/vault/secrets?bot_id=bot_chief")
            assert secrets_resp.status_code == 200
            assert _SENSITIVE_PASSWORD_2 not in secrets_resp.text
            saved_meta = next(
                (s for s in secrets_resp.json()["secrets"] if s["id"] == saved_id),
                None,
            )
            assert saved_meta is not None
            assert saved_meta["name"] == "Plant Portal Bob"
            assert saved_meta["domain"] == login_server.domain_with_port
            assert saved_meta["username_hint"] == "op_bob"

            with sqlite3.connect(browser_server.workspace_db_path) as conn:
                row = conn.execute(
                    "SELECT encrypted_payload FROM vault_secrets WHERE id = ?",
                    (saved_id,),
                ).fetchone()
                assert row is not None
                decoded = base64.b64decode(str(row[0]))
                assert decoded.startswith((b"v2g:", b"v2h:"))
                assert _SENSITIVE_PASSWORD_2 not in str(row[0])
                audit_rows = conn.execute("SELECT detail_json FROM workspace_audit_log").fetchall()
                for (detail,) in audit_rows:
                    assert _SENSITIVE_PASSWORD_2 not in str(detail)
        finally:
            await aclient.post("/api/browser/stop")


async def test_t1_secure_fill_with_saved_secret_id_autofills_without_client_plaintext(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 1 (F2): secret_id fills DOM server-side, resolves submitted + SSE."""
    async with browser_server.async_client() as aclient:
        try:
            sec_resp = await aclient.post(
                "/api/v1/vault/secrets",
                json={
                    "bot_id": "bot_chief",
                    "name": "Saved Portal Login",
                    "domain": login_server.domain_with_port,
                    "username": "saved_user",
                    "secret_value": _SENSITIVE_PASSWORD_1,
                },
            )
            assert sec_resp.status_code == 201
            secret_id = str(sec_resp.json()["id"])

            btn_x, btn_y = await _anavigate_and_find_submit_button(aclient, login_server.login_url)
            form_resp = await aclient.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "kind": "form",
                    "domain": login_server.domain_with_port,
                    "title": "Autofill With Secret ID",
                    "fields": [
                        {"name": "username", "label": "Username", "secret": False},
                        {"name": "password", "label": "Password", "secret": True},
                    ],
                },
            )
            assert form_resp.status_code == 201
            form_id = str(form_resp.json()["id"])

            fill_resp, ev = await _post_secure_fill_and_wait_sse(
                aclient,
                form_id=form_id,
                payload={"form_id": form_id, "bot_id": "bot_chief", "secret_id": secret_id},
            )
            assert fill_resp.status_code == 200
            assert fill_resp.json()["filled"] is True
            assert _SENSITIVE_PASSWORD_1 not in fill_resp.text
            assert _SENSITIVE_PASSWORD_1 not in ev.raw
            assert isinstance(ev.data, dict)
            assert ev.data["payload"]["form"]["status"] == "submitted"

            thread_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
            assert thread_resp.status_code == 200
            assert _SENSITIVE_PASSWORD_1 not in thread_resp.text
            matched = [f for f in thread_resp.json()["secure_forms"] if f["id"] == form_id]
            assert len(matched) == 1
            assert matched[0]["status"] == "submitted"

            click_resp = await aclient.post(
                "/api/v1/computers/default/actions",
                json={"actor": "human", "type": "click", "x": btn_x, "y": btn_y},
            )
            assert click_resp.status_code == 200
            subs = await asyncio.to_thread(login_server.wait_for_submissions, 1, 5.0)
            assert subs == [{"username": "saved_user", "password": _SENSITIVE_PASSWORD_1}]
        finally:
            await aclient.post("/api/browser/stop")


async def test_t1_secure_fill_kind_secret_offline_save_resolves_submitted_and_sse(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F2): kind='secret' offline save stores secret and resolves form submitted + SSE."""
    async with server.async_client() as aclient:
        assert (await aclient.post("/api/browser/stop")).status_code == 200

        form_resp = await aclient.post(
            "/api/v1/secure-forms",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "kind": "secret",
                "domain": "api.internal",
                "title": "Store API Key",
                "fields": [{"name": "api_key", "label": "API Key", "secret": True}],
                "allow_vault_save": True,
            },
        )
        assert form_resp.status_code == 201
        form_id = str(form_resp.json()["id"])

        fill_resp, ev = await _post_secure_fill_and_wait_sse(
            aclient,
            form_id=form_id,
            payload={
                "form_id": form_id,
                "bot_id": "bot_chief",
                "values": {"api_key": _SENSITIVE_PASSWORD_1},
                "save_to_vault": True,
                "vault_name": "Offline API Key",
            },
        )
        assert fill_resp.status_code == 200
        body = fill_resp.json()
        assert body["filled"] is False
        saved_id = body["saved_secret_id"]
        assert isinstance(saved_id, str) and saved_id
        assert _SENSITIVE_PASSWORD_1 not in fill_resp.text
        assert _SENSITIVE_PASSWORD_1 not in ev.raw
        assert isinstance(ev.data, dict)
        assert ev.data["payload"]["form"]["id"] == form_id
        assert ev.data["payload"]["form"]["status"] == "submitted"

        thread_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
        assert thread_resp.status_code == 200
        assert _SENSITIVE_PASSWORD_1 not in thread_resp.text
        matched = [f for f in thread_resp.json()["secure_forms"] if f["id"] == form_id]
        assert len(matched) == 1
        assert matched[0]["status"] == "submitted"

        secrets_resp = await aclient.get("/api/v1/vault/secrets?bot_id=bot_chief")
        assert secrets_resp.status_code == 200
        assert _SENSITIVE_PASSWORD_1 not in secrets_resp.text
        assert any(s["id"] == saved_id for s in secrets_resp.json()["secrets"])


async def test_t1_secure_fill_global_bot_none_secret_autofills_for_any_bot(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 1 (F2): Global secret (bot_id=None) autofills for any bot on matching domain."""
    async with browser_server.async_client() as aclient:
        try:
            sec_resp = await aclient.post(
                "/api/v1/vault/secrets",
                json={
                    "bot_id": None,
                    "name": "Global Portal Secret",
                    "domain": login_server.domain_with_port,
                    "username": "global_op",
                    "secret_value": _SENSITIVE_PASSWORD_2,
                },
            )
            assert sec_resp.status_code == 201
            global_secret_id = str(sec_resp.json()["id"])
            assert sec_resp.json()["bot_id"] is None

            bot2_resp = await aclient.post(
                "/api/v1/bots",
                json={"name": "Global Vault Tester", "role_prompt": "Uses global secret"},
            )
            assert bot2_resp.status_code == 201
            bot2_id = str(bot2_resp.json()["id"])
            bot2_thread = str(bot2_resp.json()["thread_id"])

            btn_x, btn_y = await _anavigate_and_find_submit_button(aclient, login_server.login_url)
            form_resp = await aclient.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": bot2_id,
                    "thread_id": bot2_thread,
                    "kind": "form",
                    "domain": login_server.domain_with_port,
                    "title": "Bot2 Global Secret Login",
                    "fields": [
                        {"name": "username", "label": "Username", "secret": False},
                        {"name": "password", "label": "Password", "secret": True},
                    ],
                },
            )
            assert form_resp.status_code == 201
            form_id = str(form_resp.json()["id"])

            fill_resp, ev = await _post_secure_fill_and_wait_sse(
                aclient,
                form_id=form_id,
                payload={
                    "form_id": form_id,
                    "bot_id": bot2_id,
                    "secret_id": global_secret_id,
                },
            )
            assert fill_resp.status_code == 200
            assert fill_resp.json()["filled"] is True
            assert _SENSITIVE_PASSWORD_2 not in fill_resp.text
            assert _SENSITIVE_PASSWORD_2 not in ev.raw
            assert isinstance(ev.data, dict)
            assert ev.data["payload"]["form"]["status"] == "submitted"

            thread_resp = await aclient.get(f"/api/v1/threads/{bot2_thread}/messages")
            assert thread_resp.status_code == 200
            assert _SENSITIVE_PASSWORD_2 not in thread_resp.text
            matched = [f for f in thread_resp.json()["secure_forms"] if f["id"] == form_id]
            assert len(matched) == 1
            assert matched[0]["status"] == "submitted"

            click_resp = await aclient.post(
                "/api/v1/computers/default/actions",
                json={"actor": "human", "type": "click", "x": btn_x, "y": btn_y},
            )
            assert click_resp.status_code == 200
            subs = await asyncio.to_thread(login_server.wait_for_submissions, 1, 5.0)
            assert subs == [{"username": "global_op", "password": _SENSITIVE_PASSWORD_2}]
        finally:
            await aclient.post("/api/browser/stop")


def test_t2_secure_fill_inactive_browser_returns_409_and_keeps_pending(
    server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 2 (F2): Stopped live browser returns 409 on form submit and keeps form pending."""
    with server.client() as client:
        assert client.post("/api/browser/stop").status_code == 200

        form_resp = client.post(
            "/api/v1/secure-forms",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "kind": "form",
                "domain": login_server.domain_with_port,
                "title": "Inactive Browser Gate",
                "fields": [
                    {"name": "username", "label": "Username", "secret": False},
                    {"name": "password", "label": "Password", "secret": True},
                ],
            },
        )
        assert form_resp.status_code == 201
        form_id = str(form_resp.json()["id"])

        fill_resp = client.post(
            "/api/v1/vault/secure-fill",
            json={
                "form_id": form_id,
                "bot_id": "bot_chief",
                "values": {"username": "op_alice", "password": _SENSITIVE_PASSWORD_1},
            },
        )
        assert fill_resp.status_code == 409
        assert "not running" in fill_resp.json()["detail"].lower()

        thread_resp = client.get("/api/v1/threads/thr_bot_chief/messages")
        assert thread_resp.status_code == 200
        form_now = next(f for f in thread_resp.json()["secure_forms"] if f["id"] == form_id)
        assert form_now["status"] == "pending"

        # Standalone vault save without form_id still works when browser is stopped
        save_only = client.post(
            "/api/v1/vault/secure-fill",
            json={
                "bot_id": "bot_chief",
                "domain": login_server.domain_with_port,
                "values": {"username": "op_alice", "password": _SENSITIVE_PASSWORD_1},
                "save_to_vault": True,
                "vault_name": "Offline Save",
            },
        )
        assert save_only.status_code == 200
        assert save_only.json()["filled"] is False
        assert save_only.json()["saved_secret_id"] is not None


def test_t2_secure_fill_origin_mismatch_returns_409_and_types_nothing(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 2 (F2): Mismatched host/port/IP-vs-localhost returns 409, keeps pending, 0 submits."""
    with browser_server.client() as client:
        try:
            _navigate_and_find_submit_button(client, login_server.login_url)

            mismatched_domains = (
                "evil.example.com",
                f"http://127.0.0.1:{login_server.port + 1}",
                f"localhost:{login_server.port}",
            )
            for idx, bad_domain in enumerate(mismatched_domains):
                f_resp = client.post(
                    "/api/v1/secure-forms",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "kind": "form",
                        "domain": bad_domain,
                        "title": f"Mismatch Form {idx}",
                        "fields": [{"name": "password", "label": "Password", "secret": True}],
                    },
                )
                assert f_resp.status_code == 201
                fid = str(f_resp.json()["id"])

                r_fill = client.post(
                    "/api/v1/vault/secure-fill",
                    json={
                        "form_id": fid,
                        "bot_id": "bot_chief",
                        "values": {"username": "bad", "password": _SENSITIVE_PASSWORD_1},
                    },
                )
                assert r_fill.status_code == 409
                assert "match" in r_fill.json()["detail"].lower()

                forms = client.get("/api/v1/threads/thr_bot_chief/messages").json()["secure_forms"]
                assert next(f for f in forms if f["id"] == fid)["status"] == "pending"

            # Matching form domain but mismatched payload.domain -> 409
            good_form = client.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "kind": "form",
                    "domain": login_server.domain_with_port,
                    "title": "Payload Domain Mismatch",
                    "fields": [{"name": "password", "label": "Password", "secret": True}],
                },
            ).json()
            r_payload_mismatch = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": good_form["id"],
                    "bot_id": "bot_chief",
                    "domain": "other.local",
                    "values": {"username": "bad", "password": _SENSITIVE_PASSWORD_1},
                },
            )
            assert r_payload_mismatch.status_code == 409
            assert login_server.submissions == []
        finally:
            client.post("/api/browser/stop")


def test_t2_secure_fill_cross_bot_secret_and_form_rejected_403(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 2 (F2): Cross-bot secret_id or cross-bot form access is rejected with 403."""
    with browser_server.client() as client:
        try:
            bot2 = client.post(
                "/api/v1/bots",
                json={"name": "Secondary Bot", "role_prompt": "Isolated peer"},
            )
            assert bot2.status_code == 201
            bot2_id = str(bot2.json()["id"])
            bot2_thread = str(bot2.json()["thread_id"])

            sec1 = client.post(
                "/api/v1/vault/secrets",
                json={
                    "bot_id": "bot_chief",
                    "name": "Chief Secret",
                    "domain": login_server.domain_with_port,
                    "username": "chief_user",
                    "secret_value": _SENSITIVE_PASSWORD_1,
                },
            )
            assert sec1.status_code == 201
            sec1_id = str(sec1.json()["id"])

            _navigate_and_find_submit_button(client, login_server.login_url)

            form_bot2 = client.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": bot2_id,
                    "thread_id": bot2_thread,
                    "kind": "form",
                    "domain": login_server.domain_with_port,
                    "title": "Bot 2 Form",
                    "fields": [{"name": "password", "label": "Password", "secret": True}],
                },
            ).json()
            r_cross_secret = client.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": form_bot2["id"], "bot_id": bot2_id, "secret_id": sec1_id},
            )
            assert r_cross_secret.status_code == 403

            form_chief = client.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "kind": "form",
                    "domain": login_server.domain_with_port,
                    "title": "Chief Form",
                    "fields": [{"name": "password", "label": "Password", "secret": True}],
                },
            ).json()
            r_cross_cancel = client.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": form_chief["id"], "bot_id": bot2_id, "action": "cancel"},
            )
            assert r_cross_cancel.status_code == 403

            forms = client.get("/api/v1/threads/thr_bot_chief/messages").json()["secure_forms"]
            assert next(f for f in forms if f["id"] == form_chief["id"])["status"] == "pending"
        finally:
            client.post("/api/browser/stop")


def test_t2_secure_fill_cross_domain_secret_id_rejected_403(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 2 (F2): Using a secret_id scoped to another domain is rejected with 403."""
    with browser_server.client() as client:
        try:
            sec = client.post(
                "/api/v1/vault/secrets",
                json={
                    "bot_id": "bot_chief",
                    "name": "Portal Only Secret",
                    "domain": login_server.domain_with_port,
                    "username": "chief_user",
                    "secret_value": _SENSITIVE_PASSWORD_1,
                },
            )
            assert sec.status_code == 201
            secret_id = str(sec.json()["id"])

            _navigate_and_find_submit_button(client, login_server.login_url)

            other_form = client.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "kind": "form",
                    "domain": "other.internal",
                    "title": "Other Internal Form",
                    "fields": [{"name": "password", "label": "Password", "secret": True}],
                },
            ).json()
            r_cross_dom = client.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": other_form["id"], "bot_id": "bot_chief", "secret_id": secret_id},
            )
            assert r_cross_dom.status_code == 403
            assert "domain" in r_cross_dom.json()["detail"].lower()

            r_payload_dom = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "bot_id": "bot_chief",
                    "domain": "other.internal",
                    "secret_id": secret_id,
                },
            )
            assert r_payload_dom.status_code == 403
        finally:
            client.post("/api/browser/stop")


def test_t2_secure_fill_allow_vault_save_false_blocks_vault_persistence(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 2 (F2): Form with allow_vault_save=False ignores save_to_vault=True."""
    with browser_server.client() as client:
        try:
            before_ids = {
                s["id"]
                for s in client.get("/api/v1/vault/secrets?bot_id=bot_chief").json()["secrets"]
            }
            _navigate_and_find_submit_button(client, login_server.login_url)

            form = client.post(
                "/api/v1/secure-forms",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "kind": "form",
                    "domain": login_server.domain_with_port,
                    "title": "No Vault Save Form",
                    "fields": [
                        {"name": "username", "label": "Username", "secret": False},
                        {"name": "password", "label": "Password", "secret": True},
                    ],
                    "allow_vault_save": False,
                },
            ).json()

            fill_resp = client.post(
                "/api/v1/vault/secure-fill",
                json={
                    "form_id": form["id"],
                    "bot_id": "bot_chief",
                    "values": {"username": "ephemeral", "password": _SENSITIVE_PASSWORD_1},
                    "save_to_vault": True,
                    "vault_name": "Should Not Save",
                },
            )
            assert fill_resp.status_code == 200
            body = fill_resp.json()
            assert body["filled"] is True
            assert body["saved_secret_id"] is None

            after_ids = {
                s["id"]
                for s in client.get("/api/v1/vault/secrets?bot_id=bot_chief").json()["secrets"]
            }
            assert after_ids == before_ids
        finally:
            client.post("/api/browser/stop")


def test_t2_secure_fill_already_resolved_and_unknown_ids(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F2): Re-resolving returns 409; unknown IDs 404; missing cancel ID 400."""
    with server.client() as client:
        assert (
            client.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": "sf_does_not_exist", "values": {"password": "x"}},
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/api/v1/vault/secure-fill",
                json={"secret_id": "vs_does_not_exist", "domain": "example.com"},
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/api/v1/vault/secure-fill",
                json={"action": "cancel"},
            ).status_code
            == 400
        )

        form = client.post(
            "/api/v1/secure-forms",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "kind": "form",
                "domain": "example.com",
                "title": "Cancel Once",
                "fields": [{"name": "password", "label": "Password", "secret": True}],
            },
        ).json()
        fid = str(form["id"])
        assert (
            client.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": fid, "action": "cancel"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": fid, "action": "cancel"},
            ).status_code
            == 409
        )
        assert (
            client.post(
                "/api/v1/vault/secure-fill",
                json={"form_id": fid, "values": {"password": "x"}},
            ).status_code
            == 409
        )


def test_t2_vault_422_validation_error_redacts_secret_value(server: IsolatedServer) -> None:
    """Tier 2 (F2): 422 validation errors on vault/secure-fill never echo plaintext secrets."""
    with server.client() as client:
        long_secret_1 = _SENSITIVE_PASSWORD_1 * 400  # > 8000 chars
        r1 = client.post(
            "/api/v1/vault/secrets",
            json={"name": "TooLongSecretValue", "secret_value": long_secret_1},
        )
        assert r1.status_code == 422
        assert _SENSITIVE_PASSWORD_1 not in r1.text
        detail1 = r1.json()["detail"]
        assert isinstance(detail1, list) and detail1
        assert detail1[0]["input"] == "[REDACTED]"

        long_secret_2 = _SENSITIVE_PASSWORD_2 * 400  # > 8000 chars
        r2 = client.post(
            "/api/v1/vault/secrets",
            json={"name": "TooLongValue", "value": long_secret_2},
        )
        assert r2.status_code == 422
        assert _SENSITIVE_PASSWORD_2 not in r2.text
        detail2 = r2.json()["detail"]
        assert isinstance(detail2, list) and detail2
        assert detail2[0]["input"] == "[REDACTED]"

        r3 = client.post(
            "/api/v1/vault/secure-fill",
            json={"values": {"password": [_SENSITIVE_PASSWORD_1]}},
        )
        assert r3.status_code == 422
        assert _SENSITIVE_PASSWORD_1 not in r3.text


# ==============================================================================
# Feature #4: Takeover Lock & Automation Isolation (7 tests: T4.1 - T4.7)
# ==============================================================================


def test_t1_takeover_handback_lifecycle_idempotency_and_status(
    server: IsolatedServer,
) -> None:
    """Tier 1 (F4): Takeover/handback lifecycle, lease fields, and Idempotency-Key 409."""
    with server.client() as client:
        st0 = client.get("/api/v1/computers/default/status")
        assert st0.status_code == 200
        assert st0.json()["control_owner"] == "agent"
        assert st0.json()["lease_id"] is None

        tk1 = client.post(
            "/api/v1/computers/default/takeover",
            headers={"Idempotency-Key": "e2e-takeover-k1"},
            json={"owner": "operator_a", "ttl_seconds": 60},
        )
        assert tk1.status_code == 200
        tk1_body = tk1.json()
        assert tk1_body["control_owner"] == "human_takeover"
        assert isinstance(tk1_body["lease_id"], str) and tk1_body["lease_id"].startswith("lse_")
        assert tk1_body["lease_expires_at"] is not None

        tk_dup = client.post(
            "/api/v1/computers/default/takeover",
            headers={"Idempotency-Key": "e2e-takeover-k1"},
            json={"owner": "operator_a", "ttl_seconds": 60},
        )
        assert tk_dup.status_code == 409

        hb = client.post(
            "/api/v1/computers/default/handback",
            json={"reason": "done"},
        )
        assert hb.status_code == 200
        hb_body = hb.json()
        assert hb_body["control_owner"] == "agent"
        assert hb_body["lease_id"] is None


async def test_t2_screencast_ws_blocks_raw_input_and_ignores_force_interactive(
    server: IsolatedServer,
) -> None:
    """Tier 2 (F4): Screencast WS ignores force_interactive=true and returns blocked."""
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default")
    ws_url = f"{server.ws_base_url}{tok['ws_screencast_url']}&force_interactive=true"

    async with websockets.connect(ws_url) as ws:
        init_msg = await _ws_recv_json(ws)
        assert init_msg["type"] == "status"
        assert init_msg["control_owner"] == "agent"

        for payload in (
            {"type": "click", "x": 50, "y": 50, "force_interactive": True},
            {"type": "dblclick", "x": 50, "y": 50, "force_interactive": True},
            {"type": "wheel", "dx": 0, "dy": 120, "force_interactive": True},
            {"type": "type", "text": "bypass_attempt", "force_interactive": True},
            {"type": "key", "key": "Enter", "force_interactive": True},
        ):
            await ws.send(json.dumps(payload))
            reply = await _ws_recv_json(ws)
            assert reply["type"] == "blocked"
            assert "take over" in reply["message"].lower()


async def test_t1_screencast_ws_allows_raw_input_during_human_takeover(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 1 (F4): Screencast WS permits click/dblclick/wheel/key and emits status."""
    with browser_server.client() as client:
        try:
            assert (
                client.post("/api/browser/start", json={"url": login_server.login_url}).status_code
                == 200
            )
            tk = client.post(
                "/api/v1/computers/default/takeover",
                json={"owner": "human_op"},
            )
            assert tk.status_code == 200
            tok = mint_cap_token(client, vm_id="default")
            ws_url = f"{browser_server.ws_base_url}{tok['ws_screencast_url']}"

            async with websockets.connect(ws_url) as ws:
                first = await _ws_recv_json(ws)
                assert first["type"] == "status"
                assert first["control_owner"] == "human_takeover"

                for payload in (
                    {"type": "click", "x": 120, "y": 80},
                    {"type": "dblclick", "x": 120, "y": 80},
                    {"type": "wheel", "dx": 0, "dy": 120},
                    {"type": "key", "key": "Tab"},
                ):
                    await ws.send(json.dumps(payload))
                    saw_status = False
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline:
                        msg = await _ws_recv_json(ws, timeout=3.0)
                        assert msg.get("type") not in {"blocked", "error"}, (
                            f"Unexpected WS message for {payload['type']}: {msg!r}"
                        )
                        if msg.get("type") == "status":
                            assert msg["control_owner"] == "human_takeover"
                            assert msg["running"] is True
                            saw_status = True
                            break
                    assert saw_status, f"Missing status frame for {payload['type']}"
        finally:
            client.post("/api/v1/computers/default/handback", json={"reason": "cleanup"})
            client.post("/api/browser/stop")


def test_t2_legacy_browser_action_returns_423_during_takeover_and_unlocks_on_handback(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 2 (F4): POST /api/browser/action returns 423 during takeover and recovers after."""
    with browser_server.client() as client:
        try:
            assert client.post("/api/v1/computers/default/takeover").status_code == 200
            assert client.post("/api/browser/start").status_code == 200

            locked_nav = client.post(
                "/api/browser/action",
                json={"type": "navigate", "url": login_server.login_url},
            )
            assert locked_nav.status_code == 423
            assert "human takeover" in locked_nav.json()["detail"].lower()

            locked_click = client.post(
                "/api/browser/action",
                json={"type": "click", "x": 10, "y": 10},
            )
            assert locked_click.status_code == 423

            assert client.post("/api/browser/stop").status_code == 200
            assert client.post("/api/v1/computers/default/handback").status_code == 200

            unlocked = client.post(
                "/api/browser/action",
                json={"type": "navigate", "url": login_server.login_url},
            )
            assert unlocked.status_code == 200
        finally:
            client.post("/api/v1/computers/default/handback", json={"reason": "cleanup"})
            client.post("/api/browser/stop")


def test_t2_v1_computer_actions_blocks_agent_409_allows_human_during_takeover(
    browser_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 2 (F4): /api/v1/computers/default/actions blocks actor=agent (409) & allows human."""
    with browser_server.client() as client:
        try:
            assert client.post("/api/v1/computers/default/takeover").status_code == 200

            agent_blocked = client.post(
                "/api/v1/computers/default/actions",
                json={"actor": "agent", "type": "start", "url": login_server.login_url},
            )
            assert agent_blocked.status_code == 409
            assert "human takeover" in agent_blocked.json()["detail"].lower()

            human_ok = client.post(
                "/api/v1/computers/default/actions",
                json={"actor": "human", "type": "start", "url": login_server.login_url},
            )
            assert human_ok.status_code == 200

            assert client.post("/api/v1/computers/default/handback").status_code == 200
            agent_unlocked = client.post(
                "/api/v1/computers/default/actions",
                json={"actor": "agent", "type": "reload"},
            )
            assert agent_unlocked.status_code == 200
        finally:
            client.post("/api/v1/computers/default/handback", json={"reason": "cleanup"})
            client.post("/api/browser/stop")


async def test_t2_ws_browser_rejects_connect_during_takeover(
    auth_server: IsolatedServer,
) -> None:
    """Tier 2 (F4): /ws/browser rejects new connections during takeover and accepts after."""
    with auth_server.client() as client:
        try:
            assert client.post("/api/v1/computers/default/takeover").status_code == 200
            await _assert_ws_rejected_handshake(auth_server.ws_url("/ws/browser"))

            assert client.post("/api/v1/computers/default/handback").status_code == 200
            async with websockets.connect(auth_server.ws_url("/ws/browser")) as ws:
                st = await _ws_recv_json(ws)
                assert st["type"] == "status"
        finally:
            client.post("/api/v1/computers/default/handback", json={"reason": "cleanup"})


async def test_t2_ws_browser_mid_session_takeover_closes_with_4423_before_mutating_op(
    auth_server: IsolatedServer,
    login_server: LocalLoginFormServer,
) -> None:
    """Tier 2 (F4): Existing /ws/browser session closes with 4423 on mutating op after takeover."""
    with auth_server.client() as client:
        try:
            async with websockets.connect(auth_server.ws_url("/ws/browser")) as ws:
                init_st = await _ws_recv_json(ws)
                assert init_st["type"] == "status"

                assert client.post("/api/v1/computers/default/takeover").status_code == 200

                await ws.send(json.dumps({"type": "navigate", "url": login_server.login_url}))

                saw_error = False
                close_code: int | None = None
                try:
                    for _ in range(10):
                        msg = await _ws_recv_json(ws, timeout=5.0)
                        if msg.get("type") == "error":
                            assert "human takeover" in str(msg.get("message", "")).lower()
                            saw_error = True
                except websockets.exceptions.ConnectionClosedError as exc:
                    close_code = exc.rcvd.code if exc.rcvd is not None else None
                except websockets.exceptions.ConnectionClosedOK as exc:
                    close_code = exc.rcvd.code if exc.rcvd is not None else None

                assert saw_error is True
                assert close_code == 4423

                # Browser must not have navigated to login_server
                br_ctx = client.get("/api/browser/context")
                assert br_ctx.status_code == 200
                assert br_ctx.json().get("running") is False
        finally:
            client.post("/api/v1/computers/default/handback", json={"reason": "cleanup"})
            client.post("/api/browser/stop")
