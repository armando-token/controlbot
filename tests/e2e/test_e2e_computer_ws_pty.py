"""E2E Tier 1, 2 & 3 tests: Computer capability tokens, RFB gate, screencast, control & PTY."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import http.server
import json
import os
import struct
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

import pytest
import websockets
from tests.e2e._helpers import IsolatedServer, mint_cap_token
from websockets.asyncio.client import ClientConnection
from websockets.exceptions import ConnectionClosed, ConnectionClosedError, InvalidStatus
from websockets.typing import Subprotocol

pytestmark = pytest.mark.e2e

_PLAYWRIGHT_ENV: dict[str, str] = {
    "PLAYWRIGHT_BROWSERS_PATH": os.environ.get(
        "PLAYWRIGHT_BROWSERS_PATH",
        str(Path.home() / ".cache" / "ms-playwright"),
    )
}


def _ws_close_code(exc: ConnectionClosed) -> int | None:
    if exc.rcvd is not None:
        return exc.rcvd.code
    if exc.sent is not None:
        return exc.sent.code
    return None


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return None


@contextlib.contextmanager
def _local_html_server(html: str) -> Iterator[str]:
    with tempfile.TemporaryDirectory(prefix="e2e_ws_html_") as tmp:
        root = Path(tmp)
        (root / "index.html").write_text(html, encoding="utf-8")
        handler = partial(_QuietHandler, directory=str(root))
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = int(httpd.server_address[1])
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{port}/index.html"
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=3.0)


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
    assert banner.startswith(b"RFB 003.008")
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


def _sign_cap_token(secret: str, vm_id: str, exp: float) -> str:
    payload = {"vm_id": vm_id, "exp": exp, "nonce": "e2etestnonce"}
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    sig = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return f"{payload_b64}.{sig_b64}"


async def _assert_ws_rejected(
    ws_url: str,
    *,
    subprotocols: list[Subprotocol] | None = None,
) -> None:
    try:
        async with websockets.connect(ws_url, subprotocols=subprotocols) as ws:
            await asyncio.wait_for(ws.recv(), timeout=3.0)
    except InvalidStatus as exc:
        assert exc.response.status_code == 403
        return
    except ConnectionClosed as exc:
        assert _ws_close_code(exc) == 4401
        return
    raise AssertionError(f"Expected WebSocket rejection (403/4401) for {ws_url}, got open stream")


async def _recv_ws_json_until(
    ws: ClientConnection,
    predicate: Callable[[dict[str, Any]], bool],
    *,
    timeout: float = 10.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    seen: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        rem = max(0.05, deadline - time.monotonic())
        raw = await asyncio.wait_for(ws.recv(), timeout=rem)
        if not isinstance(raw, str):
            continue
        msg: dict[str, Any] = json.loads(raw)
        seen.append(msg)
        if predicate(msg):
            return msg
    raise TimeoutError(f"Timed out waiting for WS JSON message. Seen: {seen}")


async def _read_pty_until(
    ws: ClientConnection,
    predicate: Callable[[str], bool],
    *,
    timeout: float = 8.0,
    initial_buf: str = "",
) -> str:
    acc = initial_buf
    deadline = time.monotonic() + timeout
    while not predicate(acc):
        rem = max(0.05, deadline - time.monotonic())
        try:
            chunk = await asyncio.wait_for(ws.recv(), timeout=rem)
        except TimeoutError as exc:
            raise TimeoutError(
                f"PTY output predicate not met within {timeout}s. Output: {acc!r}"
            ) from exc
        if isinstance(chunk, bytes):
            acc += chunk.decode("utf-8", errors="replace")
        else:
            acc += chunk
    return acc


# ---------------------------------------------------------------------------
# 1. VNC Capability Token Structure, TTL Clamping & Auth Gate (Tier 1, F1, F4)
# ---------------------------------------------------------------------------


def test_vnc_token_minting_structure_ttl_clamping_and_auth_gate(
    server: IsolatedServer,
    auth_server: IsolatedServer,
) -> None:
    with server.client() as client:
        default_tok = mint_cap_token(client, vm_id="default")
        assert default_tok["ttl_seconds"] == 60
        assert "." in default_tok["cap_token"]
        assert default_tok["expires_at"].endswith("Z")
        assert default_tok["ws_vnc_url"].startswith("/ws/v1/computers/default/vnc?cap_token=")
        assert default_tok["ws_screencast_url"].startswith(
            "/ws/v1/computers/default/screencast?cap_token="
        )
        assert default_tok["ws_control_url"].startswith(
            "/ws/v1/computers/default/control?cap_token="
        )
        assert default_tok["ws_pty_url"].startswith(
            "/ws/v1/computers/default/pty/default?cap_token="
        )

        low_tok = mint_cap_token(client, vm_id="default", ttl_seconds=1)
        assert low_tok["ttl_seconds"] == 5

        high_tok = mint_cap_token(client, vm_id="default", ttl_seconds=9999)
        assert high_tok["ttl_seconds"] == 600

        bad_ttl = client.post("/api/v1/computers/default/vnc-token", json={"ttl_seconds": "bad"})
        assert bad_ttl.status_code == 422

    # Auth server rejects unauthenticated vnc-token calls and accepts Bearer or ?token=
    with auth_server.client() as auth_client:
        unauth_resp = auth_client.post(
            "/api/v1/computers/default/vnc-token",
            headers={"Authorization": ""},
        )
        # Note: auth_client has default auth headers unless overridden cleanly; test raw httpx
        assert unauth_resp.status_code == 401

        bearer_tok = mint_cap_token(auth_client, vm_id="default", ttl_seconds=30)
        assert bearer_tok["ttl_seconds"] == 30

    import httpx

    with httpx.Client(base_url=auth_server.base_url, timeout=10.0) as raw_client:
        assert raw_client.post("/api/v1/computers/default/vnc-token", json={}).status_code == 401
        q_resp = raw_client.post(
            f"/api/v1/computers/default/vnc-token?token={auth_server.web_token}",
            json={"session_id": "sess_q"},
        )
        assert q_resp.status_code == 200
        assert "/pty/sess_q?cap_token=" in q_resp.json()["ws_pty_url"]


# ---------------------------------------------------------------------------
# 2. All 4 Computer WS Endpoints Reject Missing/Bad/Expired/Wrong-VM Tokens (Tier 2, F1, F4)
# ---------------------------------------------------------------------------


async def test_all_4_computer_ws_endpoints_reject_missing_bad_expired_wrong_vm_cap_token(
    server: IsolatedServer,
    auth_server: IsolatedServer,
) -> None:
    with server.client() as client:
        valid_default = str(mint_cap_token(client, vm_id="default")["cap_token"])
        other_vm_tok = str(mint_cap_token(client, vm_id="vm_other")["cap_token"])

    tampered_tok = valid_default[:-4] + ("BBBB" if not valid_default.endswith("BBBB") else "AAAA")
    expired_tok = _sign_cap_token(server.cap_secret, "default", time.time() - 10.0)

    endpoints: list[tuple[str, list[Subprotocol] | None]] = [
        ("/ws/v1/computers/default/vnc", [Subprotocol("binary")]),
        ("/ws/v1/computers/default/screencast", None),
        ("/ws/v1/computers/default/control", None),
        ("/ws/v1/computers/default/pty/s1", None),
    ]

    for path, protos in endpoints:
        # (a) Missing cap_token (no web_token configured)
        await _assert_ws_rejected(f"{server.ws_base_url}{path}", subprotocols=protos)
        # (b) Tampered signature
        await _assert_ws_rejected(
            f"{server.ws_base_url}{path}?cap_token={tampered_tok}",
            subprotocols=protos,
        )
        # (c) Wrong vm_id
        await _assert_ws_rejected(
            f"{server.ws_base_url}{path}?cap_token={other_vm_tok}",
            subprotocols=protos,
        )
        # (d) Expired token
        await _assert_ws_rejected(
            f"{server.ws_base_url}{path}?cap_token={expired_tok}",
            subprotocols=protos,
        )
        # (e) Invalid cap_token paired with valid web_token on auth_server MUST still reject
        await _assert_ws_rejected(
            f"{auth_server.ws_base_url}{path}?token={auth_server.web_token}&cap_token=invalid.sig",
            subprotocols=protos,
        )


# ---------------------------------------------------------------------------
# 3. WS VNC RFB Input Gate Drops During Agent, Forwards During Takeover (Tier 3, F4)
# ---------------------------------------------------------------------------


async def test_ws_vnc_rfb_input_gate_drops_agent_forwards_takeover_drops_handback(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(with_mock_rfb=True, name="vnc_gate")
    assert srv.mock_rfb is not None
    mock_rfb = srv.mock_rfb

    with srv.client() as client:
        tok = mint_cap_token(client, vm_id="default")

    ws_vnc_url = f"{srv.ws_base_url}{tok['ws_vnc_url']}"
    fb_req = struct.pack("!BBHHHH", 3, 1, 0, 0, 640, 480)
    key_ev = struct.pack("!BBHI", 4, 1, 0, 0x0061)
    ptr_ev = struct.pack("!BBHH", 5, 1, 120, 240)
    cut_text = struct.pack("!B3xI", 6, 5) + b"hello"

    async with websockets.connect(ws_vnc_url, subprotocols=[Subprotocol("binary")]) as ws:
        reader = await _complete_client_rfb_none_handshake(ws)

        # Phase 1: agent owns control -> 0x03 passes, 0x04/0x05/0x06 dropped
        await ws.send(fb_req + key_ev + ptr_ev + cut_text)
        fb_reply = await reader.read_exact(4)
        assert fb_reply == b"\x00\x00\x00\x00"
        await asyncio.sleep(0.15)
        assert mock_rfb.wait_for_messages(min_count=1, timeout=2.0) == [0x03]
        assert mock_rfb.received_message_types == [0x03]

        # Phase 2: human_takeover -> 0x04/0x05/0x06 forwarded intact
        with srv.client() as client:
            tk = client.post("/api/v1/computers/default/takeover", json={"owner": "op"})
            assert tk.status_code == 200
            assert tk.json()["control_owner"] == "human_takeover"

        mock_rfb.reset_records()
        await ws.send(key_ev + ptr_ev + cut_text)
        forwarded = mock_rfb.wait_for_messages(min_count=3, timeout=3.0)
        assert forwarded == [0x04, 0x05, 0x06]
        assert mock_rfb.received_messages == [
            (0x04, key_ev),
            (0x05, ptr_ev),
            (0x06, cut_text),
        ]

        # Phase 3: handback -> 0x04/0x05 dropped again, 0x03 still passes
        with srv.client() as client:
            hb = client.post("/api/v1/computers/default/handback", json={})
            assert hb.status_code == 200
            assert hb.json()["control_owner"] == "agent"

        mock_rfb.reset_records()
        await ws.send(fb_req + key_ev + ptr_ev)
        fb_reply2 = await reader.read_exact(4)
        assert fb_reply2 == b"\x00\x00\x00\x00"
        await asyncio.sleep(0.15)
        assert mock_rfb.received_message_types == [0x03]


# ---------------------------------------------------------------------------
# 4. WS VNC RFB Gate Fragmented Frames & QEMU Extended Key (Tier 2, F4)
# ---------------------------------------------------------------------------


async def test_ws_vnc_rfb_gate_handles_fragmented_frames_and_qemu_extended_key(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(with_mock_rfb=True, name="vnc_frag")
    assert srv.mock_rfb is not None
    mock_rfb = srv.mock_rfb

    with srv.client() as client:
        tok = mint_cap_token(client, vm_id="default")

    key_ev = struct.pack("!BBHI", 4, 1, 0, 0x0062)  # 8 bytes
    qemu_ext = struct.pack("!BBHII", 0xFF, 0x00, 1, 0x0063, 0x1E)  # 12 bytes
    fb_req = struct.pack("!BBHHHH", 3, 1, 0, 0, 640, 480)  # 10 bytes

    ws_vnc_url = f"{srv.ws_base_url}{tok['ws_vnc_url']}"
    async with websockets.connect(ws_vnc_url, subprotocols=[Subprotocol("binary")]) as ws:
        reader = await _complete_client_rfb_none_handshake(ws)

        # Fragment 0x04 + 0xFF 0x00 + 0x03 in agent mode -> gate drops inputs without desyncing 0x03
        for chunk in (
            key_ev[:3],
            key_ev[3:6],
            key_ev[6:],
            qemu_ext[:2],
            qemu_ext[2:7],
            qemu_ext[7:],
            fb_req[:4],
            fb_req[4:],
        ):
            await ws.send(chunk)

        fb_reply = await reader.read_exact(4)
        assert fb_reply == b"\x00\x00\x00\x00"
        await asyncio.sleep(0.15)
        assert mock_rfb.received_message_types == [0x03]

        # Acquire takeover -> fragmented 0x04 is reassembled/forwarded cleanly
        with srv.client() as client:
            assert client.post("/api/v1/computers/default/takeover", json={}).status_code == 200

        mock_rfb.reset_records()
        await ws.send(key_ev[:3])
        await ws.send(key_ev[3:])
        assert mock_rfb.wait_for_messages(min_count=1, timeout=3.0) == [0x04]
        assert mock_rfb.received_messages == [(0x04, key_ev)]


# ---------------------------------------------------------------------------
# 5. WS VNC Closed Backend Port Returns 1011 (Tier 2, F4)
# ---------------------------------------------------------------------------


async def test_ws_vnc_closed_backend_port_returns_1011(server: IsolatedServer) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default")

    ws_vnc_url = f"{server.ws_base_url}{tok['ws_vnc_url']}"
    async with websockets.connect(ws_vnc_url, subprotocols=[Subprotocol("binary")]) as ws:
        with pytest.raises(ConnectionClosedError) as exc_info:
            await asyncio.wait_for(ws.recv(), timeout=5.0)
        assert _ws_close_code(exc_info.value) == 1011


# ---------------------------------------------------------------------------
# 6. WS Control State, Ping/Pong, Viewport Resize & Clipboard Push (Tier 1, F4, F15)
# ---------------------------------------------------------------------------


async def test_ws_control_state_ping_pong_viewport_resize_and_clipboard_push(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default")

    ws_ctrl_url = f"{server.ws_base_url}{tok['ws_control_url']}"
    async with websockets.connect(ws_ctrl_url) as ws:
        init_msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
        assert init_msg["op"] == "computer.state"
        assert init_msg["status"]["vm_id"] == "default"

        await ws.send(json.dumps({"op": "ping"}))
        pong = await _recv_ws_json_until(ws, lambda m: m.get("op") == "pong")
        assert isinstance(pong.get("ts"), str)

        await ws.send(json.dumps({"op": "viewport.resize", "width": 1920, "height": 1080}))
        ack1 = await _recv_ws_json_until(ws, lambda m: m.get("op") == "viewport.resize.ack")
        assert ack1["width"] == 1920 and ack1["height"] == 1080

        # Out-of-range dimensions clamp to 320x240
        await ws.send(json.dumps({"op": "viewport.resize", "width": 100, "height": 100}))
        ack2 = await _recv_ws_json_until(ws, lambda m: m.get("op") == "viewport.resize.ack")
        assert ack2["width"] == 320 and ack2["height"] == 240

        await ws.send(json.dumps({"op": "clipboard.push", "text": "hello"}))
        clip = await _recv_ws_json_until(ws, lambda m: m.get("op") == "clipboard.push.ack")
        assert clip["vm_id"] == "default"
        assert isinstance(clip["ok"], bool)


# ---------------------------------------------------------------------------
# 7. WS Control Lease Heartbeat Ack & Revoked on Handback/Mismatch (Tier 1/2, F4, F15)
# ---------------------------------------------------------------------------


async def test_ws_control_lease_heartbeat_ack_and_revoked_on_handback_or_mismatch(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default")

    ws_ctrl_url = f"{server.ws_base_url}{tok['ws_control_url']}"
    async with websockets.connect(ws_ctrl_url) as ws:
        init_msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
        assert init_msg["op"] == "computer.state"

        async with server.async_client() as aclient:
            tk = await aclient.post(
                "/api/v1/computers/default/takeover",
                json={"owner": "ctrl-op", "ttl_seconds": 10},
            )
            assert tk.status_code == 200
            lease_id = str(tk.json()["lease_id"])

            st_ev = await _recv_ws_json_until(
                ws,
                lambda m: (
                    m.get("op") == "computer.state"
                    and m.get("status", {}).get("control_owner") == "human_takeover"
                ),
            )
            assert st_ev["status"]["lease_id"] == lease_id

            await ws.send(json.dumps({"op": "lease.heartbeat", "lease_id": lease_id}))
            hb_ack = await _recv_ws_json_until(ws, lambda m: m.get("op") == "lease.heartbeat.ack")
            assert hb_ack["lease_id"] == lease_id
            assert isinstance(hb_ack["lease_expires_at"], str)

            await ws.send(json.dumps({"op": "lease.heartbeat", "lease_id": "lse_wrong_mismatch"}))
            revoked_mismatch = await _recv_ws_json_until(
                ws, lambda m: m.get("op") == "lease.revoked"
            )
            assert revoked_mismatch["reason"] == "lease_expired_or_inactive"

            hb = await aclient.post(
                "/api/v1/computers/default/handback",
                json={"reason": "human_handback"},
            )
            assert hb.status_code == 200

            revoked_hb = await _recv_ws_json_until(ws, lambda m: m.get("op") == "lease.revoked")
            assert revoked_hb["reason"] == "human_handback"
            back_to_agent = await _recv_ws_json_until(
                ws,
                lambda m: (
                    m.get("op") == "computer.state"
                    and m.get("status", {}).get("control_owner") == "agent"
                ),
            )
            assert back_to_agent["status"]["lease_id"] is None


# ---------------------------------------------------------------------------
# 8. WS Control Receives teach.step_captured & browser.tab_changed (Tier 3, F4, F15)
# ---------------------------------------------------------------------------


async def test_ws_control_receives_teach_step_captured_and_browser_tab_changed(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(extra_env=_PLAYWRIGHT_ENV, name="ws_ctrl_teach")
    html = "<html><head><title>Teach Capture Page</title></head><body><h1>Go</h1></body></html>"
    with _local_html_server(html) as local_url:
        with srv.client() as client:
            tok = mint_cap_token(client, vm_id="default")

        ws_ctrl_url = f"{srv.ws_base_url}{tok['ws_control_url']}"
        try:
            async with websockets.connect(ws_ctrl_url) as ws:
                init_msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                assert init_msg["op"] == "computer.state"

                async with srv.async_client(timeout=25.0) as aclient:
                    ts = await aclient.post(
                        "/api/v1/computers/default/teach/start",
                        json={"name": "WS Capture Flow", "bot_id": "bot_chief"},
                    )
                    assert ts.status_code == 200

                    a1 = await aclient.post(
                        "/api/v1/computers/default/actions",
                        json={"type": "start"},
                    )
                    assert a1.status_code == 200
                    a2 = await aclient.post(
                        "/api/v1/computers/default/actions",
                        json={"type": "navigate", "url": local_url},
                    )
                    assert a2.status_code == 200

                    teach_steps: list[dict[str, Any]] = []
                    tab_changed: dict[str, Any] | None = None
                    deadline = time.monotonic() + 8.0
                    while (
                        len(teach_steps) < 2 or tab_changed is None
                    ) and time.monotonic() < deadline:
                        raw = await asyncio.wait_for(
                            ws.recv(),
                            timeout=max(0.1, deadline - time.monotonic()),
                        )
                        if not isinstance(raw, str):
                            continue
                        msg: dict[str, Any] = json.loads(raw)
                        if msg.get("op") == "teach.step_captured":
                            teach_steps.append(msg["step"])
                        elif (
                            msg.get("op") == "browser.tab_changed"
                            and msg.get("url") == local_url
                        ):
                            tab_changed = msg

                    assert len(teach_steps) >= 2
                    assert [s["step_index"] for s in teach_steps[:2]] == [1, 2]
                    assert all(
                        {"step_index", "action", "description", "url", "ts"} <= set(s.keys())
                        for s in teach_steps[:2]
                    )
                    assert tab_changed is not None
                    assert tab_changed["title"] == "Teach Capture Page"

                    stop_teach = await aclient.post(
                        "/api/v1/computers/default/teach/stop",
                        json={},
                    )
                    assert stop_teach.status_code == 200
                    stop_json = stop_teach.json()
                    assert stop_json["skill"]["name"] == "WS Capture Flow"
                    assert stop_json["artifact"]["type"] == "skill"
        finally:
            with contextlib.suppress(Exception), srv.client() as c:
                c.post("/api/v1/computers/default/actions", json={"type": "stop"})


# ---------------------------------------------------------------------------
# 9. WS Screencast Start, Navigate Local Server, Frames & Stop (Tier 1, F4)
# ---------------------------------------------------------------------------


async def test_ws_screencast_start_navigate_local_server_frames_and_stop(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(extra_env=_PLAYWRIGHT_ENV, name="ws_sc_nav")
    html = "<html><head><title>Local E2E Page</title></head><body><h1>Screencast</h1></body></html>"
    with _local_html_server(html) as local_url:
        with srv.client() as client:
            tok = mint_cap_token(client, vm_id="default")

        ws_url = f"{srv.ws_base_url}{tok['ws_screencast_url']}"
        try:
            async with websockets.connect(ws_url) as ws:
                init_st = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                assert init_st["type"] == "status"
                assert init_st["running"] is False

                await ws.send(json.dumps({"type": "start"}))
                started_st = await _recv_ws_json_until(
                    ws,
                    lambda m: m.get("type") == "status" and m.get("running") is True,
                    timeout=25.0,
                )
                assert started_st["running"] is True

                first_frame = await _recv_ws_json_until(
                    ws, lambda m: m.get("type") == "frame", timeout=10.0
                )
                jpeg_bytes = base64.b64decode(first_frame["data"])
                assert jpeg_bytes[:3] == b"\xff\xd8\xff"

                await ws.send(json.dumps({"type": "navigate", "url": local_url}))
                nav_frame = await _recv_ws_json_until(
                    ws,
                    lambda m: (
                        m.get("type") == "frame"
                        and m.get("url") == local_url
                        and m.get("title") == "Local E2E Page"
                    ),
                    timeout=15.0,
                )
                assert nav_frame["title"] == "Local E2E Page"

                await ws.send(json.dumps({"type": "stop"}))
                stopped = await _recv_ws_json_until(
                    ws,
                    lambda m: m.get("type") == "status" and m.get("running") is False,
                    timeout=10.0,
                )
                assert stopped["running"] is False
        finally:
            with contextlib.suppress(Exception), srv.client() as c:
                c.post("/api/v1/computers/default/actions", json={"type": "stop"})


# ---------------------------------------------------------------------------
# 10. WS Screencast Blocks Raw Input Until Takeover & Rejects force_interactive (Tier 2, F4)
# ---------------------------------------------------------------------------


async def test_ws_screencast_blocks_raw_input_until_takeover_and_rejects_force_interactive(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(extra_env=_PLAYWRIGHT_ENV, name="ws_sc_block")
    html = "<html><head><title>Blocked Page</title></head><body><button>Ok</button></body></html>"
    with _local_html_server(html) as local_url:
        with srv.client() as client:
            tok = mint_cap_token(client, vm_id="default")

        ws_url = f"{srv.ws_base_url}{tok['ws_screencast_url']}"
        try:
            async with websockets.connect(ws_url) as ws:
                await _recv_ws_json_until(ws, lambda m: m.get("type") == "status")
                await ws.send(json.dumps({"type": "start", "url": local_url}))
                await _recv_ws_json_until(
                    ws,
                    lambda m: m.get("type") == "status" and m.get("running") is True,
                    timeout=25.0,
                )

                raw_inputs: list[dict[str, Any]] = [
                    {"type": "click", "x": 50, "y": 50},
                    {"type": "dblclick", "x": 50, "y": 50},
                    {"type": "wheel", "dx": 0, "dy": 120},
                    {"type": "type", "text": "hello"},
                    {"type": "key", "key": "Enter"},
                    {"type": "click", "x": 50, "y": 50, "force_interactive": True},
                    {"type": "wheel", "dx": 0, "dy": 200, "force_interactive": True},
                ]
                for payload in raw_inputs:
                    await ws.send(json.dumps(payload))
                    blk = await _recv_ws_json_until(
                        ws, lambda m: m.get("type") == "blocked", timeout=5.0
                    )
                    assert "take over" in str(blk.get("message", "")).lower()
        finally:
            with contextlib.suppress(Exception), srv.client() as c:
                c.post("/api/v1/computers/default/actions", json={"type": "stop"})


# ---------------------------------------------------------------------------
# 11. WS Screencast Wheel dx/dy, Click & Type During Human Takeover (Tier 1/3, F4, F15)
# ---------------------------------------------------------------------------


async def test_ws_screencast_wheel_dx_dy_click_type_during_human_takeover(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(extra_env=_PLAYWRIGHT_ENV, name="ws_sc_takeover")
    html = """<!doctype html>
<html>
<head><title>sx=0,sy=0,q=</title></head>
<body style="margin:0;width:2500px;height:2500px;">
  <input id="q" style="position:fixed;left:40px;top:40px;width:240px;height:40px;" />
  <script>
    function updateTitle() {
      const val = document.getElementById('q').value;
      document.title = `sx=${Math.round(window.scrollX)},sy=${Math.round(window.scrollY)},q=${val}`;
    }
    window.addEventListener('scroll', updateTitle);
    document.getElementById('q').addEventListener('input', updateTitle);
  </script>
</body>
</html>"""
    with _local_html_server(html) as local_url:
        with srv.client() as client:
            assert client.post("/api/v1/computers/default/takeover", json={}).status_code == 200
            tok = mint_cap_token(client, vm_id="default")

        ws_url = f"{srv.ws_base_url}{tok['ws_screencast_url']}"
        try:
            async with websockets.connect(ws_url) as ws:
                await _recv_ws_json_until(ws, lambda m: m.get("type") == "status")
                await ws.send(json.dumps({"type": "start", "url": local_url}))
                await _recv_ws_json_until(
                    ws,
                    lambda m: m.get("type") == "frame" and m.get("url") == local_url,
                    timeout=25.0,
                )

                await ws.send(json.dumps({"type": "wheel", "dx": 40, "dy": 320}))
                scrolled = await _recv_ws_json_until(
                    ws,
                    lambda m: (
                        m.get("type") == "frame"
                        and "sy=0," not in str(m.get("title", ""))
                        and "sy=" in str(m.get("title", ""))
                    ),
                    timeout=10.0,
                )
                assert "sx=0," not in str(scrolled["title"])

                await ws.send(json.dumps({"type": "click", "x": 120, "y": 60}))
                await _recv_ws_json_until(ws, lambda m: m.get("type") == "frame", timeout=5.0)
                await ws.send(json.dumps({"type": "type", "text": "controlbot"}))
                await ws.send(json.dumps({"type": "key", "key": "Enter"}))
                typed = await _recv_ws_json_until(
                    ws,
                    lambda m: (
                        m.get("type") == "frame"
                        and "q=controlbot" in str(m.get("title", ""))
                    ),
                    timeout=10.0,
                )
                assert "q=controlbot" in str(typed["title"])

                with srv.client() as client:
                    hb_resp = client.post("/api/v1/computers/default/handback", json={})
                    assert hb_resp.status_code == 200

                await ws.send(json.dumps({"type": "wheel", "dx": 0, "dy": 100}))
                blk = await _recv_ws_json_until(
                    ws, lambda m: m.get("type") == "blocked", timeout=5.0
                )
                assert blk["type"] == "blocked"
        finally:
            with contextlib.suppress(Exception), srv.client() as c:
                c.post("/api/v1/computers/default/actions", json={"type": "stop"})


# ---------------------------------------------------------------------------
# 12. WS Screencast Rejects Non-HTTP Schemes (Tier 2, F4)
# ---------------------------------------------------------------------------


async def test_ws_screencast_rejects_non_http_schemes(server: IsolatedServer) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default")

    ws_url = f"{server.ws_base_url}{tok['ws_screencast_url']}"
    async with websockets.connect(ws_url) as ws:
        await _recv_ws_json_until(ws, lambda m: m.get("type") == "status")

        for bad_url in ("javascript:alert(1)", "file:///etc/passwd"):
            await ws.send(json.dumps({"type": "navigate", "url": bad_url}))
            err = await _recv_ws_json_until(ws, lambda m: m.get("type") == "error", timeout=5.0)
            assert err["type"] == "error"

        # WS loop remains healthy after errors
        await ws.send(json.dumps({"type": "stop"}))
        st = await _recv_ws_json_until(ws, lambda m: m.get("type") == "status", timeout=5.0)
        assert st["running"] is False


# ---------------------------------------------------------------------------
# 13. WS PTY Interactive Shell Echo & Project CWD (Tier 1, F4, F15)
# ---------------------------------------------------------------------------


async def test_ws_pty_interactive_shell_echo_and_project_cwd(server: IsolatedServer) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default", session_id="s1")

    ws_url = (
        f"{server.ws_base_url}/ws/v1/computers/default/pty/s1"
        f"?project=Grokbotclon&cap_token={tok['cap_token']}"
    )
    expected_cwd = str((server.projects_root / "Grokbotclon").resolve())
    async with websockets.connect(ws_url) as ws:
        await ws.send("echo E2E_PTY_OK\n")
        await ws.send("pwd\n")
        out = await _read_pty_until(
            ws, lambda s: "E2E_PTY_OK" in s and expected_cwd in s, timeout=8.0
        )
        assert "E2E_PTY_OK" in out
        assert expected_cwd in out
        await ws.send("exit 0\n")


# ---------------------------------------------------------------------------
# 14. WS PTY Multibyte UTF-8 Streaming (Tier 2, F4, F15)
# ---------------------------------------------------------------------------


async def test_ws_pty_multibyte_utf8_streaming(server: IsolatedServer) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default", session_id="s2")

    ws_url = (
        f"{server.ws_base_url}/ws/v1/computers/default/pty/s2"
        f"?project=Grokbotclon&cap_token={tok['cap_token']}"
    )
    expected_utf8 = "RES_café 🚀 — Ω≈ç√"
    async with websockets.connect(ws_url) as ws:
        # Use Python escape sequences so ONLY actual decoded PTY stdout produces the UTF-8 string
        cmd = (
            "python3 -c 'print(\"RES_\" + \"\\u0063af\\u00e9 \\U0001f680 "
            "\\u2014 \\u03a9\\u2248\\u00e7\\u221a\")'\n"
        )
        await ws.send(cmd)
        out = await _read_pty_until(ws, lambda s: expected_utf8 in s, timeout=8.0)
        assert expected_utf8 in out
        assert "\ufffd" not in out
        await ws.send("exit 0\n")


# ---------------------------------------------------------------------------
# 15. WS PTY JSON Stdout Not Swallowed & Shell Stays Alive (Tier 2, F15)
# ---------------------------------------------------------------------------


async def test_ws_pty_json_stdout_not_swallowed_and_shell_stays_alive(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default", session_id="s3")

    ws_url = (
        f"{server.ws_base_url}/ws/v1/computers/default/pty/s3"
        f"?project=Grokbotclon&cap_token={tok['cap_token']}"
    )
    async with websockets.connect(ws_url) as ws:
        await ws.send(
            "python3 -c 'import json; print(json.dumps({\"type\":\"exit\",\"ok\":True}, "
            "separators=(\",\", \":\")))'\n"
        )
        out = await _read_pty_until(
            ws, lambda s: '{"type":"exit","ok":true}' in s, timeout=8.0
        )
        assert '{"type":"exit","ok":true}' in out

        await ws.send("echo STILL_ALIVE_OK\n")
        out2 = await _read_pty_until(
            ws, lambda s: "STILL_ALIVE_OK" in s, timeout=8.0, initial_buf=out
        )
        assert "STILL_ALIVE_OK" in out2
        await ws.send("exit 0\n")


# ---------------------------------------------------------------------------
# 16. WS PTY SIGINT & Ctrl-C Interrupts Foreground Without Closing Shell (Tier 2/3, F4)
# ---------------------------------------------------------------------------


async def test_ws_pty_sigint_ctrl_c_interrupts_foreground_without_closing_shell(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default", session_id="s4")

    ws_url = (
        f"{server.ws_base_url}/ws/v1/computers/default/pty/s4"
        f"?project=Grokbotclon&cap_token={tok['cap_token']}"
    )
    async with websockets.connect(ws_url) as ws:
        await ws.send(
            "python3 -c \"import time; print('SLEEP_STARTED_1', flush=True); time.sleep(30)\"\n"
        )
        buf = await _read_pty_until(ws, lambda s: "SLEEP_STARTED_1" in s, timeout=8.0)

        await ws.send(json.dumps({"op": "signal", "sig": "SIGINT"}))
        await asyncio.sleep(0.2)
        await ws.send("echo AFTER_JSON_SIGINT\n")
        buf = await _read_pty_until(
            ws, lambda s: "AFTER_JSON_SIGINT" in s, timeout=8.0, initial_buf=buf
        )
        assert "AFTER_JSON_SIGINT" in buf

        # Also verify raw Ctrl-C (\x03) interrupts cleanly
        await ws.send(
            "python3 -c \"import time; print('SLEEP_STARTED_2', flush=True); time.sleep(30)\"\n"
        )
        buf = await _read_pty_until(
            ws, lambda s: "SLEEP_STARTED_2" in s, timeout=8.0, initial_buf=buf
        )
        await ws.send("\x03")
        await asyncio.sleep(0.2)
        await ws.send("echo AFTER_RAW_CTRL_C\n")
        buf = await _read_pty_until(
            ws, lambda s: "AFTER_RAW_CTRL_C" in s, timeout=8.0, initial_buf=buf
        )
        assert "AFTER_RAW_CTRL_C" in buf
        await ws.send("exit 0\n")


# ---------------------------------------------------------------------------
# 17. WS PTY Resize Updates Winsize & Clean Exit 1000 (Tier 1/2, F4, F15)
# ---------------------------------------------------------------------------


async def test_ws_pty_resize_updates_terminal_winsize_and_clean_exit_1000(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default", session_id="s5")

    ws_url = (
        f"{server.ws_base_url}/ws/v1/computers/default/pty/s5"
        f"?project=Grokbotclon&cap_token={tok['cap_token']}"
    )
    async with websockets.connect(ws_url) as ws:
        await ws.send(json.dumps({"op": "resize", "cols": 132, "rows": 42}))
        await asyncio.sleep(0.15)
        await ws.send(
            "python3 -c \"import os; s=os.get_terminal_size(); "
            "print(f'WINSIZE={s.columns}x{s.lines}')\"\n"
        )
        out = await _read_pty_until(ws, lambda s: "WINSIZE=132x42" in s, timeout=8.0)
        assert "WINSIZE=132x42" in out

        await ws.send("exit 0\n")
        with pytest.raises(ConnectionClosed) as exc_info:
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                await asyncio.wait_for(ws.recv(), timeout=2.0)
        assert _ws_close_code(exc_info.value) == 1000


# ---------------------------------------------------------------------------
# 18. WS PTY Invalid or Traversal Project Closes 1008 (Tier 2, F4, F15)
# ---------------------------------------------------------------------------


async def test_ws_pty_invalid_or_traversal_project_closes_1008(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        tok = mint_cap_token(client, vm_id="default", session_id="s_bad")

    for bad_project in ("../escape", "nonexistent_proj"):
        ws_url = (
            f"{server.ws_base_url}/ws/v1/computers/default/pty/s_bad"
            f"?project={bad_project}&cap_token={tok['cap_token']}"
        )
        async with websockets.connect(ws_url) as ws:
            with pytest.raises(ConnectionClosed) as exc_info:
                await asyncio.wait_for(ws.recv(), timeout=5.0)
            assert _ws_close_code(exc_info.value) == 1008
