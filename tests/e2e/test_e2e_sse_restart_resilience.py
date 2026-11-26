"""E2E Tier 1, 2 & 3 tests: SSE durability/resync, restarts, routines, HITL & mentions."""

from __future__ import annotations

import asyncio
import contextlib
import http.server
import json
import os
import socket
import threading
import time
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

import httpx
import pytest
import websockets
from tests.e2e._helpers import (
    IsolatedServer,
    SseFrame,
    iter_sse_events,
    mint_cap_token,
    trigger_and_wait_turn,
)

pytestmark = pytest.mark.e2e

_PLAYWRIGHT_ENV: dict[str, str] = {
    "PLAYWRIGHT_BROWSERS_PATH": os.environ.get(
        "PLAYWRIGHT_BROWSERS_PATH",
        str(Path.home() / ".cache" / "ms-playwright"),
    )
}

_CONV_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

_MOCK_AGY_LOGGER_SCRIPT = f"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

prompt = ""
if "-p" in args:
    idx = args.index("-p")
    if idx + 1 < len(args):
        prompt = args[idx + 1]

log_path = Path(os.environ.get("HOME", ".")) / "agy_prompts.jsonl"
with log_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps({{"prompt": prompt, "args": args}}) + "\\n")

reply = "Mock agy response"
for line in prompt.splitlines():
    if line.startswith("[BOT PERSONA:"):
        reply = f"Reply from {{line}}"
        break
if "[SCHEDULED ROUTINE:" in prompt:
    reply = "Routine executed cleanly"

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


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return None


@contextlib.contextmanager
def _local_html_server(html: str) -> Iterator[str]:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="e2e_html_") as tmp:
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


def _parse_event_cursor(event_id: str | None) -> tuple[str | None, int | None]:
    from src.web.v1.events import parse_event_cursor

    return parse_event_cursor(event_id)


def _read_agy_prompts(srv: IsolatedServer) -> list[dict[str, Any]]:
    log_path = srv.fake_home / "agy_prompts.jsonl"
    if not log_path.is_file():
        return []
    entries: list[dict[str, Any]] = []
    for raw in log_path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            entries.append(json.loads(raw))
    return entries


async def _collect_sse_replay(
    client: httpx.AsyncClient,
    *,
    url: str = "/api/v1/events/stream",
    headers: dict[str, str] | None = None,
    idle_timeout: float = 0.6,
) -> list[SseFrame]:
    """Collect immediately replayed SSE frames until stream goes idle."""
    frames: list[SseFrame] = []
    req_headers = dict(headers or {})
    req_timeout = httpx.Timeout(connect=5.0, read=idle_timeout, write=5.0, pool=5.0)
    try:
        async with client.stream("GET", url, headers=req_headers, timeout=req_timeout) as resp:
            resp.raise_for_status()
            buf: list[str] = []
            async for line in resp.aiter_lines():
                if line == "":
                    if buf:
                        frame_id: str | None = None
                        event_name: str | None = None
                        data_lines: list[str] = []
                        for raw_line in buf:
                            if raw_line.startswith(":"):
                                continue
                            if ":" in raw_line:
                                k, v = raw_line.split(":", 1)
                                v = v[1:] if v.startswith(" ") else v
                            else:
                                k, v = raw_line, ""
                            if k == "id":
                                frame_id = v
                            elif k == "event":
                                event_name = v
                            elif k == "data":
                                data_lines.append(v)
                        buf.clear()
                        if data_lines:
                            joined = "\n".join(data_lines)
                            parsed: dict[str, Any] | str = joined
                            with contextlib.suppress(json.JSONDecodeError):
                                obj = json.loads(joined)
                                if isinstance(obj, dict):
                                    parsed = obj
                            ev = (
                                str(parsed["type"])
                                if event_name is None
                                and isinstance(parsed, dict)
                                and isinstance(parsed.get("type"), str)
                                else event_name
                            )
                            frames.append(
                                SseFrame(id=frame_id, event=ev, data=parsed, raw=joined)
                            )
                else:
                    buf.append(line)
    except (httpx.ReadTimeout, TimeoutError):
        pass
    return frames


async def _create_reaction_events(
    client: httpx.AsyncClient,
    message_id: str,
    emojis: list[str],
) -> list[SseFrame]:
    """Listen on SSE while posting reaction events, returning the exact emitted frames."""
    captured: list[SseFrame] = []
    connected = asyncio.Event()

    async def _listen() -> None:
        async for frame in iter_sse_events(client, timeout=10.0, on_connected=connected):
            if (
                frame.event_type == "message.reaction"
                and isinstance(frame.data, dict)
                and frame.data.get("payload", {}).get("message_id") == message_id
            ):
                captured.append(frame)
                if len(captured) >= len(emojis):
                    return

    task = asyncio.create_task(_listen())
    try:
        await asyncio.wait_for(connected.wait(), timeout=5.0)
        await asyncio.sleep(0.05)
        for emoji in emojis:
            resp = await client.post(
                f"/api/v1/messages/{message_id}/reactions",
                json={"emoji": emoji, "action": "add"},
            )
            assert resp.status_code == 200
        await asyncio.wait_for(task, timeout=8.0)
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
    return captured


# ---------------------------------------------------------------------------
# 1. SSE Preamble & Live Event Ordering (Tier 1, F6)
# ---------------------------------------------------------------------------


async def test_sse_preamble_and_live_event_ordering(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_LOGGER_SCRIPT, name="sse_preamble")
    preamble_lines: list[str] = []
    turn_frames: list[SseFrame] = []
    turn_id_holder: dict[str, str] = {}
    turn_id_ready = asyncio.Event()
    preamble_seen = asyncio.Event()

    async with srv.async_client() as client:
        async def _listen() -> None:
            timeout_cfg = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)
            async with client.stream("GET", "/api/v1/events/stream", timeout=timeout_cfg) as resp:
                assert resp.status_code == 200
                buf: list[str] = []
                async for line in resp.aiter_lines():
                    if len(preamble_lines) < 4 and line != "":
                        preamble_lines.append(line)
                        if any(ln == ": connected" for ln in preamble_lines) and any(
                            ln == "retry: 2000" for ln in preamble_lines
                        ):
                            preamble_seen.set()
                    if line == "":
                        if buf:
                            fid: str | None = None
                            data_lines: list[str] = []
                            for raw in buf:
                                if raw.startswith(":"):
                                    continue
                                if raw.startswith("id: "):
                                    fid = raw[4:]
                                elif raw.startswith("data: "):
                                    data_lines.append(raw[6:])
                            buf.clear()
                            if data_lines:
                                obj = json.loads("\n".join(data_lines))
                                frame = SseFrame(
                                    id=fid,
                                    event=obj.get("type"),
                                    data=obj,
                                    raw="\n".join(data_lines),
                                )
                                if not turn_id_ready.is_set():
                                    await turn_id_ready.wait()
                                if obj.get("turn_id") == turn_id_holder["id"]:
                                    turn_frames.append(frame)
                                    if obj.get("type") == "message.completed":
                                        return
                    else:
                        buf.append(line)

        listen_task = asyncio.create_task(_listen())
        try:
            await asyncio.wait_for(preamble_seen.wait(), timeout=5.0)
            resp = await client.post(
                "/api/v1/threads/thr_bot_chief/messages",
                json={"content": "Verify SSE preamble and event order"},
            )
            assert resp.status_code == 202
            turn_id_holder["id"] = resp.json()["turn_id"]
            turn_id_ready.set()
            await asyncio.wait_for(listen_task, timeout=10.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await listen_task

    assert ": connected" in preamble_lines
    assert "retry: 2000" in preamble_lines

    types = [f.event_type for f in turn_frames]
    assert "turn.started" in types
    assert "message.delta" in types
    assert types[-1] == "message.completed"
    t_start = types.index("turn.started")
    t_delta = types.index("message.delta")
    t_done = types.index("message.completed")
    assert t_start < t_delta < t_done

    epochs: set[str] = set()
    seqs: list[int] = []
    for frame in turn_frames:
        assert frame.id is not None
        assert frame.id.startswith("evt_")
        epoch, seq = _parse_event_cursor(frame.id)
        assert epoch is not None
        assert seq is not None
        epochs.add(epoch)
        seqs.append(seq)
    assert len(epochs) == 1
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)


# ---------------------------------------------------------------------------
# 2. SSE Replay via Last-Event-ID Header & Query Param (Tier 1, F6)
# ---------------------------------------------------------------------------


async def test_sse_replay_via_last_event_id_header_and_query_param(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as client:
        turn = await trigger_and_wait_turn(client, "thr_bot_chief", "/approval Seed msg")
        msg_id = str(turn.user_message["id"])
        frames = await _create_reaction_events(client, msg_id, ["👍", "🔥", "🚀", "✅"])
        assert len(frames) == 4
        id1 = str(frames[0].id)
        id2 = str(frames[1].id)
        id3 = str(frames[2].id)
        id4 = str(frames[3].id)

        by_header = await _collect_sse_replay(client, headers={"Last-Event-ID": id2})
        assert [f.event_type for f in by_header] == ["message.reaction", "message.reaction"]
        assert [f.id for f in by_header] == [id3, id4]

        by_query = await _collect_sse_replay(
            client,
            url=f"/api/v1/events/stream?last_event_id={id2}",
        )
        assert [f.event_type for f in by_query] == ["message.reaction", "message.reaction"]
        assert [f.id for f in by_query] == [id3, id4]

        # Query param takes precedence over Last-Event-ID header (routes.py:1316)
        precedence = await _collect_sse_replay(
            client,
            url=f"/api/v1/events/stream?last_event_id={id3}",
            headers={"Last-Event-ID": id1},
        )
        assert [f.id for f in precedence] == [id4]


# ---------------------------------------------------------------------------
# 3. SSE Cursor Formats (<epoch>:<seq>, evt_<seq>, <seq>) (Tier 2, F6)
# ---------------------------------------------------------------------------


async def test_sse_cursor_formats_colon_epoch_and_legacy_numeric_and_evt(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as client:
        turn = await trigger_and_wait_turn(client, "thr_bot_chief", "/approval Cursor format seed")
        msg_id = str(turn.user_message["id"])
        frames = await _create_reaction_events(client, msg_id, ["😀", "😎", "🎉", "💡"])
        assert len(frames) == 4
        epoch2, seq2 = _parse_event_cursor(frames[1].id)
        assert epoch2 is not None and seq2 is not None
        expected_ids = [frames[2].id, frames[3].id]

        for cursor in (
            f"{epoch2}:{seq2}",
            f"evt_{seq2:06d}",
            str(seq2),
        ):
            replayed = await _collect_sse_replay(
                client,
                headers={"Last-Event-ID": cursor},
            )
            assert all(f.event_type != "stream.resync" for f in replayed), cursor
            assert [f.id for f in replayed] == expected_ids, cursor


# ---------------------------------------------------------------------------
# 4. SSE Restart Replay Preserves Epoch & Zero Drops (Tier 3, F6, F17)
#    [STRICT M5 SEAM ORACLE: app.py:850 EventBus(store=workspace_store)]
# ---------------------------------------------------------------------------


async def test_sse_restart_replay_preserves_epoch_and_zero_drops_via_header_and_query(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as client:
        turn = await trigger_and_wait_turn(client, "thr_bot_chief", "/approval Restart SSE seed")
        msg_id = str(turn.user_message["id"])
        pre_frames = await _create_reaction_events(client, msg_id, ["1️⃣", "2️⃣"])
        e2_id = str(pre_frames[1].id)
        epoch_before, _ = _parse_event_cursor(e2_id)
        assert epoch_before is not None

        # Emit e3 while disconnected BEFORE server.restart()
        e3_resp = await client.post(
            f"/api/v1/messages/{msg_id}/reactions",
            json={"emoji": "3️⃣", "action": "add"},
        )
        assert e3_resp.status_code == 200

    server.restart(keep_port=False)

    async with server.async_client() as client:
        # Emit e4 AFTER restart
        e4_resp = await client.post(
            f"/api/v1/messages/{msg_id}/reactions",
            json={"emoji": "4️⃣", "action": "add"},
        )
        assert e4_resp.status_code == 200

        replayed_hdr = await _collect_sse_replay(client, headers={"Last-Event-ID": e2_id})
        assert all(f.event_type != "stream.resync" for f in replayed_hdr), (
            f"Unexpected stream.resync across restart: {replayed_hdr}"
        )
        emojis_hdr = [
            f.data.get("payload", {}).get("emoji")
            for f in replayed_hdr
            if f.event_type == "message.reaction" and isinstance(f.data, dict)
        ]
        assert emojis_hdr == ["3️⃣", "4️⃣"]
        for f in replayed_hdr:
            ep, _ = _parse_event_cursor(f.id)
            assert ep == epoch_before

        replayed_qry = await _collect_sse_replay(
            client,
            url=f"/api/v1/events/stream?last_event_id={e2_id}",
        )
        assert all(f.event_type != "stream.resync" for f in replayed_qry)
        emojis_qry = [
            f.data.get("payload", {}).get("emoji")
            for f in replayed_qry
            if f.event_type == "message.reaction" and isinstance(f.data, dict)
        ]
        assert emojis_qry == ["3️⃣", "4️⃣"]


# ---------------------------------------------------------------------------
# 5. SSE stream.resync on Epoch Mismatch, Invalid Cursor, Sequence Ahead (Tier 2, F6)
# ---------------------------------------------------------------------------


async def test_sse_resync_on_epoch_mismatch_invalid_cursor_and_sequence_ahead(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as client:
        turn = await trigger_and_wait_turn(client, "thr_bot_chief", "/approval Resync seed")
        msg_id = str(turn.user_message["id"])
        frames = await _create_reaction_events(client, msg_id, ["🍎", "🍐"])
        cur_epoch, _ = _parse_event_cursor(frames[-1].id)
        assert cur_epoch is not None

        for cursor in ("oldepoch:1", "evt_000001_oldepoch"):
            res = await _collect_sse_replay(client, headers={"Last-Event-ID": cursor})
            assert len(res) >= 2
            assert res[0].event_type == "stream.resync"
            assert isinstance(res[0].data, dict)
            assert res[0].data["payload"]["reason"] == "epoch_mismatch"
            assert res[0].data["payload"]["epoch"] == cur_epoch
            replayed_ids = {f.id for f in res[1:]}
            assert frames[0].id in replayed_ids
            assert frames[1].id in replayed_ids

        res_bad = await _collect_sse_replay(client, headers={"Last-Event-ID": "not_a_cursor"})
        assert res_bad and res_bad[0].event_type == "stream.resync"
        assert isinstance(res_bad[0].data, dict)
        assert res_bad[0].data["payload"]["reason"] == "invalid_cursor"

        res_ahead = await _collect_sse_replay(client, headers={"Last-Event-ID": "evt_999999"})
        assert res_ahead and res_ahead[0].event_type == "stream.resync"
        assert isinstance(res_ahead[0].data, dict)
        assert res_ahead[0].data["payload"]["reason"] == "sequence_ahead"


# ---------------------------------------------------------------------------
# 6. SSE Slow Consumer Overflow Emits stream.resync (Tier 2, F6)
# ---------------------------------------------------------------------------


async def test_sse_slow_consumer_overflow_emits_stream_resync(
    server: IsolatedServer,
) -> None:
    async with server.async_client() as client:
        turn = await trigger_and_wait_turn(client, "thr_bot_chief", "/approval Overflow seed")
        msg_id = str(turn.user_message["id"])

    # Open raw TCP socket with SO_RCVBUF set BEFORE connect() so TCP SYN advertises a tiny
    # receive window, preventing StreamReader buffering and forcing genuine TCP backpressure.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
    sock.settimeout(5.0)
    sock.connect(("127.0.0.1", server.port))

    try:
        req = (
            f"GET /api/v1/events/stream HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{server.port}\r\n\r\n"
        ).encode("ascii")
        sock.sendall(req)

        preamble = b""
        deadline = time.monotonic() + 5.0
        while b": connected" not in preamble and time.monotonic() < deadline:
            chunk = await asyncio.to_thread(sock.recv, 4096)
            if not chunk:
                break
            preamble += chunk
        assert b": connected" in preamble

        # Burst 650 reaction events without reading from sock so TCP send buffer fills and
        # EventBus subscriber_queue_size=256 overflows.
        emojis = [f"e{i}" for i in range(650)]
        sem = asyncio.Semaphore(16)
        limits = httpx.Limits(max_connections=16, max_keepalive_connections=16)
        async with httpx.AsyncClient(
            base_url=server.base_url,
            headers=server.auth_headers(),
            timeout=30.0,
            limits=limits,
        ) as burst_client:
            async def _post_one(em: str) -> None:
                async with sem:
                    resp = await burst_client.post(
                        f"/api/v1/messages/{msg_id}/reactions",
                        json={"emoji": em, "action": "toggle"},
                    )
                    assert resp.status_code == 200

            await asyncio.gather(*(_post_one(em) for em in emojis))

        # Resume reading on sock and confirm slow_consumer_overflow stream.resync arrives
        sock.settimeout(2.0)
        collected_bytes = bytearray(preamble)
        read_deadline = time.monotonic() + 15.0
        while time.monotonic() < read_deadline:
            try:
                chunk = await asyncio.to_thread(sock.recv, 65536)
            except TimeoutError:
                break
            if not chunk:
                break
            collected_bytes.extend(chunk)
            if b"slow_consumer_overflow" in collected_bytes:
                break

        collected_text = collected_bytes.decode("utf-8", errors="replace")
        assert '"type": "stream.resync"' in collected_text
        assert '"reason": "slow_consumer_overflow"' in collected_text
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# 7. Computer Takeover Lease Persists Across Restart (Tier 3, F4, F17)
# ---------------------------------------------------------------------------


def test_computer_takeover_lease_persists_across_server_restart(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        tk = client.post(
            "/api/v1/computers/default/takeover",
            json={"owner": "e2e-op", "ttl_seconds": 120},
        )
        assert tk.status_code == 200
        tk_body = tk.json()
        assert tk_body["control_owner"] == "human_takeover"
        lease_id = tk_body["lease_id"]
        lease_exp = tk_body["lease_expires_at"]
        assert isinstance(lease_id, str) and lease_id
        assert isinstance(lease_exp, str) and lease_exp

    server.restart(keep_port=False)

    with server.client() as client:
        st = client.get("/api/v1/computers/default/status")
        assert st.status_code == 200
        st_body = st.json()
        assert st_body["control_owner"] == "human_takeover"
        assert st_body["lease_id"] == lease_id
        assert st_body["lease_expires_at"] == lease_exp

        blocked = client.post(
            "/api/v1/computers/default/actions",
            json={"actor": "agent", "type": "stop"},
        )
        assert blocked.status_code == 409

        hb = client.post("/api/v1/computers/default/handback", json={"reason": "done"})
        assert hb.status_code == 200
        assert hb.json()["control_owner"] == "agent"
        assert hb.json()["lease_id"] is None

        allowed = client.post(
            "/api/v1/computers/default/actions",
            json={"actor": "agent", "type": "stop"},
        )
        assert allowed.status_code == 200


# ---------------------------------------------------------------------------
# 8. Teach-a-Task & Steps Survive Server Restart (Tier 3, F4, F17)
# ---------------------------------------------------------------------------


async def test_computer_teach_a_task_and_steps_survive_server_restart(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(extra_env=_PLAYWRIGHT_ENV, name="teach_restart")
    html = (
        "<html><head><title>Teach Local Page</title></head>"
        "<body><h1>Step Target</h1></body></html>"
    )
    with _local_html_server(html) as local_url:
        try:
            async with srv.async_client(timeout=25.0) as client:
                ts = await client.post(
                    "/api/v1/computers/default/teach/start",
                    json={"name": "Restart Skill", "bot_id": "bot_chief"},
                )
                assert ts.status_code == 200
                assert ts.json()["is_teaching_task"] is True

                act1 = await client.post(
                    "/api/v1/computers/default/actions",
                    json={"type": "start", "url": local_url},
                )
                assert act1.status_code == 200
                act2 = await client.post(
                    "/api/v1/computers/default/actions",
                    json={"type": "navigate", "url": local_url},
                )
                assert act2.status_code == 200
                st_pre = await client.get("/api/v1/computers/default/status")
                assert st_pre.status_code == 200
                assert st_pre.json()["is_teaching_task"] is True
                assert st_pre.json()["teach_steps_count"] == 2

            srv.restart(keep_port=False)

            async with srv.async_client(timeout=25.0) as client:
                st_post = await client.get("/api/v1/computers/default/status")
                assert st_post.status_code == 200
                post_json = st_post.json()
                assert post_json["is_teaching_task"] is True
                assert post_json["teach_name"] == "Restart Skill"
                assert post_json["teach_steps_count"] == 2

                act3 = await client.post(
                    "/api/v1/computers/default/actions",
                    json={"type": "reload"},
                )
                assert act3.status_code == 200
                assert act3.json()["status"]["teach_steps_count"] == 3

                seen_events: list[SseFrame] = []
                connected = asyncio.Event()

                async def _listen_stop() -> None:
                    async for frame in iter_sse_events(
                        client, timeout=10.0, on_connected=connected
                    ):
                        if frame.event_type in {"artifact.page.updated", "message.completed"}:
                            seen_events.append(frame)
                            if {f.event_type for f in seen_events} >= {
                                "artifact.page.updated",
                                "message.completed",
                            }:
                                return

                listen_task = asyncio.create_task(_listen_stop())
                try:
                    await asyncio.wait_for(connected.wait(), timeout=5.0)
                    await asyncio.sleep(0.05)
                    stop_resp = await client.post(
                        "/api/v1/computers/default/teach/stop",
                        json={},
                    )
                    assert stop_resp.status_code == 200
                    stop_body = stop_resp.json()
                    await asyncio.wait_for(listen_task, timeout=8.0)
                finally:
                    if not listen_task.done():
                        listen_task.cancel()
                        with contextlib.suppress(asyncio.CancelledError, Exception):
                            await listen_task

                skill_md = str(stop_body["skill"]["content_md"])
                assert "1." in skill_md and "2." in skill_md and "3." in skill_md
                assert stop_body["artifact"]["type"] == "skill"
                assert "Restart Skill" in stop_body["message"]["content"]
        finally:
            with contextlib.suppress(Exception), srv.client() as cleanup_client:
                cleanup_client.post(
                    "/api/v1/computers/default/actions",
                    json={"type": "stop"},
                )


# ---------------------------------------------------------------------------
# 9. Expired Lease Recovers to Agent & Handback Persists Across Restart (Tier 2, F4)
# ---------------------------------------------------------------------------


def test_computer_expired_lease_recovers_to_agent_across_restart_and_handback_persists(
    server: IsolatedServer,
) -> None:
    with server.client() as client:
        tk1 = client.post(
            "/api/v1/computers/default/takeover",
            json={"owner": "op1", "ttl_seconds": 120},
        )
        assert tk1.status_code == 200
        assert tk1.json()["control_owner"] == "human_takeover"
        hb = client.post("/api/v1/computers/default/handback", json={})
        assert hb.status_code == 200
        assert hb.json()["control_owner"] == "agent"

    server.restart(keep_port=False)

    with server.client() as client:
        st_hb = client.get("/api/v1/computers/default/status").json()
        assert st_hb["control_owner"] == "agent"
        assert st_hb["lease_id"] is None

        # Minimum lease TTL is clamped to 10s (computer.py:1017)
        tk2 = client.post(
            "/api/v1/computers/default/takeover",
            json={"owner": "op2", "ttl_seconds": 10},
        )
        assert tk2.status_code == 200
        assert tk2.json()["control_owner"] == "human_takeover"

    time.sleep(6.0)
    server.restart(keep_port=False)
    time.sleep(5.0)

    with server.client() as client:
        st_exp = client.get("/api/v1/computers/default/status").json()
        assert st_exp["control_owner"] == "agent"
        assert st_exp["lease_id"] is None
        assert st_exp["lease_expires_at"] is None


# ---------------------------------------------------------------------------
# 10. Routine Webhook Trigger -> Message & SSE Events (Tier 1, F14)
# ---------------------------------------------------------------------------


async def test_routine_webhook_triggers_execution_delivers_message_and_sse_events(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_LOGGER_SCRIPT, name="rtn_webhook")
    async with srv.async_client() as client:
        create_resp = await client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Webhook Telemetry",
                "instruction": "Collect webhook telemetry",
                "schedule_type": "webhook",
                "enabled": True,
            },
        )
        assert create_resp.status_code == 201
        routine = create_resp.json()
        routine_id = str(routine["id"])
        webhook_key = str(routine["webhook_key"])

        no_auth = await client.post(f"/api/v1/webhooks/routines/{routine_id}")
        assert no_auth.status_code == 401
        bad_auth = await client.post(
            f"/api/v1/webhooks/routines/{routine_id}",
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert bad_auth.status_code == 401

        seen: list[SseFrame] = []
        connected = asyncio.Event()

        async def _listen() -> None:
            async for frame in iter_sse_events(client, timeout=12.0, on_connected=connected):
                if frame.event_type in {"routine.run.status", "message.completed"}:
                    seen.append(frame)
                    has_succeeded = any(
                        f.event_type == "routine.run.status"
                        and isinstance(f.data, dict)
                        and f.data["payload"]["run"]["status"] == "succeeded"
                        for f in seen
                    )
                    has_msg = any(f.event_type == "message.completed" for f in seen)
                    if has_succeeded and has_msg:
                        return

        listen_task = asyncio.create_task(_listen())
        try:
            await asyncio.wait_for(connected.wait(), timeout=5.0)
            await asyncio.sleep(0.05)
            trig = await client.post(
                f"/api/v1/webhooks/routines/{routine_id}",
                headers={"Authorization": f"Bearer {webhook_key}"},
            )
            assert trig.status_code == 202
            assert trig.json()["status"] == "running"
            await asyncio.wait_for(listen_task, timeout=10.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await listen_task

        statuses = [
            f.data["payload"]["run"]["status"]
            for f in seen
            if f.event_type == "routine.run.status" and isinstance(f.data, dict)
        ]
        assert "running" in statuses
        assert "succeeded" in statuses

        runs_resp = await client.get(f"/api/v1/routines/{routine_id}/runs")
        assert runs_resp.status_code == 200
        runs = runs_resp.json()["runs"]
        assert len(runs) == 1
        assert runs[0]["status"] == "succeeded"
        msg_id = runs[0]["message_id"]
        assert isinstance(msg_id, str) and msg_id

        msgs_resp = await client.get("/api/v1/threads/thr_bot_chief/messages")
        assert msgs_resp.status_code == 200
        posted = next((m for m in msgs_resp.json()["messages"] if m["id"] == msg_id), None)
        assert posted is not None
        assert "Webhook Telemetry" in posted["content"]


# ---------------------------------------------------------------------------
# 11. Cron Routine Fires on Startup Scheduler Tick & Survives Restart (Tier 3, F14, F17)
# ---------------------------------------------------------------------------


async def test_cron_routine_fires_on_startup_scheduler_tick_and_survives_restart(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_LOGGER_SCRIPT, name="rtn_cron")
    async with srv.async_client() as client:
        create_resp = await client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Boot Cron Check",
                "instruction": "Perform startup cron check",
                "schedule_type": "cron",
                "cron_expr": "* * * * *",
                "enabled": True,
            },
        )
        assert create_resp.status_code == 201
        routine_id = str(create_resp.json()["id"])

    srv.restart(keep_port=False)

    async with srv.async_client() as client:
        deadline = time.monotonic() + 10.0
        runs: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            r = await client.get(f"/api/v1/routines/{routine_id}/runs")
            assert r.status_code == 200
            runs = r.json()["runs"]
            if runs and runs[0]["status"] == "succeeded":
                break
            await asyncio.sleep(0.15)

        assert runs, "Expected cron routine to fire on startup scheduler tick"
        assert runs[0]["trigger"] == "cron"
        assert runs[0]["status"] == "succeeded"
        msg_id = runs[0]["message_id"]
        assert isinstance(msg_id, str) and msg_id

        # Verify SSE events were published in the post-restart stream
        replayed = await _collect_sse_replay(client, headers={"Last-Event-ID": "0"})
        assert any(
            f.event_type == "routine.run.status"
            and isinstance(f.data, dict)
            and f.data["payload"]["run"]["trigger"] == "cron"
            and f.data["payload"]["run"]["status"] == "succeeded"
            for f in replayed
        )
        assert any(
            f.event_type == "message.completed"
            and isinstance(f.data, dict)
            and f.data["payload"]["message_id"] == msg_id
            for f in replayed
        )


# ---------------------------------------------------------------------------
# 12. Routine Webhook & Cron + ask_first HITL -> allow_once -> Resumed Delivery (Tier 3, F14, F17)
#     [STRICT M5 SEAM ORACLE: runner.py _run_routine_bg ask_first check & resume]
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("trigger_mode", ["webhook", "cron"])
async def test_routine_webhook_and_cron_ask_first_hitl_allow_once_resumes_and_delivers(
    server_factory: Callable[..., IsolatedServer],
    trigger_mode: str,
) -> None:
    srv = server_factory(
        mock_agy_script=_MOCK_AGY_LOGGER_SCRIPT,
        name=f"rtn_hitl_{trigger_mode}",
    )
    async with srv.async_client() as client:
        rules_resp = await client.put(
            "/api/v1/settings/auto-review",
            json={"rules": [{"bucket": "ask_first", "rule_text": "Ask before deploying release"}]},
        )
        assert rules_resp.status_code == 200

        payload: dict[str, Any] = {
            "name": f"Deploy Release {trigger_mode.title()} Routine",
            "instruction": "Deploy release to staging",
            "schedule_type": trigger_mode,
            "enabled": True,
        }
        if trigger_mode == "cron":
            payload["cron_expr"] = "* * * * *"

        create_resp = await client.post("/api/v1/bots/bot_chief/routines", json=payload)
        assert create_resp.status_code == 201
        routine = create_resp.json()
        routine_id = str(routine["id"])
        webhook_key = str(routine["webhook_key"])

    approval_holder: dict[str, Any] = {}
    if trigger_mode == "cron":
        # Restart so the startup scheduler tick immediately triggers the cron routine.
        srv.restart(keep_port=False)
        async with srv.async_client() as client:
            async for frame in iter_sse_events(client, last_event_id="0", timeout=6.0):
                if (
                    frame.event_type == "hitl.approval.requested"
                    and isinstance(frame.data, dict)
                    and frame.data.get("payload", {}).get("approval", {}).get("kind")
                    == "ask_first"
                ):
                    approval_holder["approval"] = frame.data["payload"]["approval"]
                    break
    else:
        async with srv.async_client() as client:
            connected = asyncio.Event()

            async def _wait_for_approval() -> None:
                async for frame in iter_sse_events(client, timeout=6.0, on_connected=connected):
                    if (
                        frame.event_type == "hitl.approval.requested"
                        and isinstance(frame.data, dict)
                        and frame.data.get("payload", {}).get("approval", {}).get("kind")
                        == "ask_first"
                    ):
                        approval_holder["approval"] = frame.data["payload"]["approval"]
                        return

            wait_task = asyncio.create_task(_wait_for_approval())
            try:
                await asyncio.wait_for(connected.wait(), timeout=5.0)
                await asyncio.sleep(0.05)
                trig = await client.post(
                    f"/api/v1/webhooks/routines/{routine_id}",
                    headers={"Authorization": f"Bearer {webhook_key}"},
                )
                assert trig.status_code == 202
                await asyncio.wait_for(wait_task, timeout=6.0)
            finally:
                if not wait_task.done():
                    wait_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await wait_task

    assert "approval" in approval_holder, (
        f"Expected ask_first hitl.approval.requested for {trigger_mode} routine"
    )
    appr = approval_holder["approval"]
    assert appr["kind"] == "ask_first"

    async with srv.async_client() as client:
        resumed_events: list[SseFrame] = []
        resumed_conn = asyncio.Event()

        async def _wait_resumed() -> None:
            async for frame in iter_sse_events(client, timeout=8.0, on_connected=resumed_conn):
                resumed_events.append(frame)
                if frame.event_type == "hitl.approval.requested":
                    raise AssertionError("Routine HITL created an unexpected second approval loop")
                has_done = any(
                    f.event_type == "routine.run.status"
                    and isinstance(f.data, dict)
                    and f.data["payload"]["run"]["routine_id"] == routine_id
                    and f.data["payload"]["run"]["trigger"] == trigger_mode
                    and f.data["payload"]["run"]["status"] == "succeeded"
                    for f in resumed_events
                )
                has_msg = any(f.event_type == "message.completed" for f in resumed_events)
                if has_done and has_msg:
                    return

        res_task = asyncio.create_task(_wait_resumed())
        try:
            await asyncio.wait_for(resumed_conn.wait(), timeout=5.0)
            await asyncio.sleep(0.05)
            resolve_resp = await client.post(
                f"/api/v1/approvals/{appr['id']}/resolve",
                json={"decision": "allow_once"},
            )
            assert resolve_resp.status_code == 200
            await asyncio.wait_for(res_task, timeout=8.0)
        finally:
            if not res_task.done():
                res_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await res_task

        runs_resp = await client.get(f"/api/v1/routines/{routine_id}/runs")
        assert runs_resp.status_code == 200
        runs = runs_resp.json()["runs"]
        assert len(runs) >= 1
        assert runs[0]["trigger"] == trigger_mode
        assert runs[0]["status"] == "succeeded"
        assert isinstance(runs[0]["message_id"], str) and runs[0]["message_id"]


# ---------------------------------------------------------------------------
# 13. Thread ask_first allow_once & always_allow Across Restart (Tier 2/3, F14)
# ---------------------------------------------------------------------------


async def test_thread_ask_first_hitl_allow_once_and_always_allow_across_restart(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_LOGGER_SCRIPT, name="thr_hitl")
    async with srv.async_client() as client:
        rules_resp = await client.put(
            "/api/v1/settings/auto-review",
            json={
                "rules": [
                    {
                        "bucket": "ask_first",
                        "rule_text": "Ask before deleting temp_cache_dir workspace files",
                    }
                ]
            },
        )
        assert rules_resp.status_code == 200

        # 1) allow_once pauses for ask_first, then resumes execution on approval
        turn1 = await trigger_and_wait_turn(
            client,
            "thr_bot_chief",
            "Run rm -rf temp_cache_dir workspace files",
        )
        assert turn1.terminal_event.event_type == "hitl.approval.requested"
        assert isinstance(turn1.terminal_event.data, dict)
        appr1 = turn1.terminal_event.data["payload"]["approval"]
        assert appr1["kind"] == "ask_first"

        connected1 = asyncio.Event()

        async def _wait_msg1() -> SseFrame:
            async for frame in iter_sse_events(client, timeout=8.0, on_connected=connected1):
                if frame.event_type == "message.completed":
                    return frame
            raise TimeoutError("Did not receive message.completed after allow_once")

        t1 = asyncio.create_task(_wait_msg1())
        try:
            await asyncio.wait_for(connected1.wait(), timeout=5.0)
            await asyncio.sleep(0.05)
            r1 = await client.post(
                f"/api/v1/approvals/{appr1['id']}/resolve",
                json={"decision": "allow_once"},
            )
            assert r1.status_code == 200
            done1 = await asyncio.wait_for(t1, timeout=8.0)
        finally:
            if not t1.done():
                t1.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t1
        assert isinstance(done1.data, dict)
        done1_content = str(done1.data["payload"]["message"]["content"])
        assert "Mock agy response" in done1_content or "Reply from" in done1_content

        # 2) always_allow persists allow_auto rule across restart
        turn2 = await trigger_and_wait_turn(
            client,
            "thr_bot_chief",
            "Run rm -rf temp_cache_dir workspace files",
        )
        assert turn2.terminal_event.event_type == "hitl.approval.requested"
        assert isinstance(turn2.terminal_event.data, dict)
        appr2 = turn2.terminal_event.data["payload"]["approval"]

        connected2 = asyncio.Event()

        async def _wait_msg2() -> SseFrame:
            async for frame in iter_sse_events(client, timeout=8.0, on_connected=connected2):
                if frame.event_type == "message.completed":
                    return frame
            raise TimeoutError("Did not receive message.completed after always_allow")

        t2 = asyncio.create_task(_wait_msg2())
        try:
            await asyncio.wait_for(connected2.wait(), timeout=5.0)
            await asyncio.sleep(0.05)
            r2 = await client.post(
                f"/api/v1/approvals/{appr2['id']}/resolve",
                json={
                    "decision": "always_allow",
                    "rule_text": "Allow temp_cache_dir workspace files",
                },
            )
            assert r2.status_code == 200
            await asyncio.wait_for(t2, timeout=8.0)
        finally:
            if not t2.done():
                t2.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t2

    srv.restart(keep_port=False)

    async with srv.async_client() as client:
        rules_after = await client.get("/api/v1/settings/auto-review")
        assert rules_after.status_code == 200
        assert any(
            r["bucket"] == "allow_auto" and "temp_cache_dir" in r["rule_text"]
            for r in rules_after.json()["rules"]
        )

        # Subsequent matching message executes without pausing for HITL
        turn3 = await trigger_and_wait_turn(
            client,
            "thr_bot_chief",
            "Run rm -rf temp_cache_dir workspace files",
        )
        assert turn3.terminal_event.event_type == "message.completed"
        assert turn3.assistant_message is not None


# ---------------------------------------------------------------------------
# 14. Group Channel @mention Hyphen & Underscore Variants + Handoff SSE (Tier 1/3, F14)
# ---------------------------------------------------------------------------


async def test_group_channel_mention_hyphen_and_underscore_variants_handoff_sse(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_LOGGER_SCRIPT, name="grp_mention")
    async with srv.async_client() as client:
        chief = (
            await client.post(
                "/api/v1/bots",
                json={"name": "Chief Bot", "role_prompt": "Lead coordinator"},
            )
        ).json()
        ops = (
            await client.post(
                "/api/v1/bots",
                json={"name": "Ops Bot", "role_prompt": "Operations specialist"},
            )
        ).json()
        qa = (
            await client.post(
                "/api/v1/bots",
                json={"name": "QA Bot", "role_prompt": "Quality verifier"},
            )
        ).json()

        channel = (
            await client.post(
                "/api/v1/channels",
                json={
                    "name": "Ops War Room",
                    "bot_ids": [chief["id"], ops["id"], qa["id"]],
                },
            )
        ).json()
        ch_thread = str(channel["thread_id"])

        # (a) Hyphen variant @Ops-Bot -> only Ops Bot responds
        res_hyphen = await trigger_and_wait_turn(
            client, ch_thread, "@Ops-Bot inspect status"
        )
        assert res_hyphen.assistant_message is not None
        assert res_hyphen.assistant_message["sender_bot_id"] == ops["id"]
        assert all(f.event_type != "handoff.dispatched" for f in res_hyphen.events)

        # (b) Underscore variant @Ops_Bot -> only Ops Bot responds
        res_under = await trigger_and_wait_turn(
            client, ch_thread, "@Ops_Bot inspect status"
        )
        assert res_under.assistant_message is not None
        assert res_under.assistant_message["sender_bot_id"] == ops["id"]
        assert all(f.event_type != "handoff.dispatched" for f in res_under.events)

        # (c) Multi-bot @Chief-Bot @Ops_Bot coordinate -> sequential + handoff.dispatched
        collected: list[SseFrame] = []
        connected = asyncio.Event()
        turn_id_holder: dict[str, str] = {}
        turn_ready = asyncio.Event()

        async def _listen_multi() -> None:
            completed = 0
            async for frame in iter_sse_events(client, timeout=15.0, on_connected=connected):
                if not turn_ready.is_set():
                    await turn_ready.wait()
                if (
                    isinstance(frame.data, dict)
                    and frame.data.get("turn_id") == turn_id_holder["id"]
                ):
                    collected.append(frame)
                    if frame.event_type == "message.completed":
                        completed += 1
                        if completed >= 2:
                            return

        task = asyncio.create_task(_listen_multi())
        try:
            await asyncio.wait_for(connected.wait(), timeout=5.0)
            await asyncio.sleep(0.05)
            post_resp = await client.post(
                f"/api/v1/threads/{ch_thread}/messages",
                json={"content": "@Chief-Bot @Ops_Bot coordinate"},
            )
            assert post_resp.status_code == 202
            turn_id_holder["id"] = post_resp.json()["turn_id"]
            turn_ready.set()
            await asyncio.wait_for(task, timeout=15.0)
        finally:
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

        handoffs = [f for f in collected if f.event_type == "handoff.dispatched"]
        assert len(handoffs) == 1
        assert isinstance(handoffs[0].data, dict)
        h_payload = handoffs[0].data["payload"]
        assert h_payload["from_bot_id"] == chief["id"]
        assert h_payload["to_bot_id"] == ops["id"]

        msg_done = [f for f in collected if f.event_type == "message.completed"]
        sender_ids = [
            f.data["payload"]["message"]["sender_bot_id"]
            for f in msg_done
            if isinstance(f.data, dict)
        ]
        assert sender_ids == [
            chief["id"],
            ops["id"],
        ]

    prompts = _read_agy_prompts(srv)
    assert len(prompts) >= 4
    last_prompt = str(prompts[-1]["prompt"])
    assert "[BOT PERSONA: Ops Bot]" in last_prompt
    assert "[CHANNEL HANDOFF CONTEXT]" in last_prompt


# ---------------------------------------------------------------------------
# 15. Group Channel page_context_id Injection & Private Scope Isolation (Tier 2/3, F14)
#     [STRICT M5 SEAM ORACLE: routes.py:377-384 pass page_context_id=payload.page_context_id]
# ---------------------------------------------------------------------------


async def test_group_channel_page_context_id_injection_and_private_scope_isolation(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    srv = server_factory(mock_agy_script=_MOCK_AGY_LOGGER_SCRIPT, name="page_ctx")
    async with srv.async_client() as client:
        team_page = (
            await client.post(
                "/api/v1/pages",
                json={
                    "bot_id": "bot_chief",
                    "title": "Team Architecture Brief",
                    "content_md": "TEAM_PAGE_MARKER_ALPHA",
                    "share_scope": "team",
                },
            )
        ).json()
        private_page = (
            await client.post(
                "/api/v1/pages",
                json={
                    "bot_id": "bot_browser",
                    "title": "Private Browser Notes",
                    "content_md": "PRIVATE_PAGE_MARKER_OMEGA",
                    "share_scope": "private",
                },
            )
        ).json()

        channel = (
            await client.post(
                "/api/v1/channels",
                json={
                    "name": "Page Context Room",
                    "bot_ids": ["bot_chief", "bot_ops", "bot_browser"],
                },
            )
        ).json()
        ch_thread = str(channel["thread_id"])

        turn_team = await trigger_and_wait_turn(
            client,
            ch_thread,
            "@ControlBot-Ops review attached team page",
            page_context_id=team_page["id"],
        )
        assert turn_team.assistant_message is not None
        assert turn_team.assistant_message["sender_bot_id"] == "bot_ops"

        prompts_after_team = _read_agy_prompts(srv)
        assert prompts_after_team
        team_prompt = str(prompts_after_team[-1]["prompt"])
        assert "[ACTIVE PAGE CONTEXT]" in team_prompt
        assert "TEAM_PAGE_MARKER_ALPHA" in team_prompt

        turn_priv = await trigger_and_wait_turn(
            client,
            ch_thread,
            "@ControlBot-Ops check private page",
            page_context_id=private_page["id"],
        )
        assert turn_priv.assistant_message is not None
        assert turn_priv.assistant_message["sender_bot_id"] == "bot_ops"

        prompts_after_priv = _read_agy_prompts(srv)
        priv_prompt = str(prompts_after_priv[-1]["prompt"])
        assert "PRIVATE_PAGE_MARKER_OMEGA" not in priv_prompt


# ---------------------------------------------------------------------------
# 16. SSE Restart with Auth Token, .grokbot_cap_secret & Rate Limit Headers (Tier 2/3, F1, F6)
# ---------------------------------------------------------------------------


async def test_sse_restart_with_auth_token_and_rate_limit_header_preservation(
    server_factory: Callable[..., IsolatedServer],
) -> None:
    web_tok = "e2e-sse-auth-secret-42"
    srv = server_factory(web_token=web_tok, cap_secret="", name="sse_auth_restart")
    cap_secret_file = srv.workspace_db_path.parent / ".grokbot_cap_secret"
    assert cap_secret_file.is_file()
    assert (os.stat(cap_secret_file).st_mode & 0o777) == 0o600
    secret_before = cap_secret_file.read_bytes()

    async with httpx.AsyncClient(base_url=srv.base_url, timeout=10.0) as unauth_client:
        unauth_sse = await unauth_client.get("/api/v1/events/stream")
        assert unauth_sse.status_code == 401

        q_frames = await _collect_sse_replay(
            unauth_client,
            url=f"/api/v1/events/stream?token={web_tok}",
            idle_timeout=0.35,
        )
        assert q_frames == []

    async with srv.async_client() as auth_client:
        tok_before = await mint_cap_token(auth_client, vm_id="default", ttl_seconds=300)
        cap_tok = str(tok_before["cap_token"])
        turn = await trigger_and_wait_turn(auth_client, "thr_bot_chief", "/approval Auth SSE")
        msg_id = str(turn.user_message["id"])
        frames = await _create_reaction_events(auth_client, msg_id, ["🔐"])
        last_id = str(frames[0].id)

    srv.restart(keep_port=False)
    assert cap_secret_file.read_bytes() == secret_before

    async with httpx.AsyncClient(base_url=srv.base_url, timeout=10.0) as unauth_after:
        assert (await unauth_after.get("/api/v1/events/stream")).status_code == 401

    # Pre-restart cap_token still authenticates WS after restart (persisted .grokbot_cap_secret)
    ws_control_url = f"{srv.ws_base_url}/ws/v1/computers/default/control?cap_token={cap_tok}"
    async with websockets.connect(ws_control_url) as ws:
        init_msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
        assert init_msg["op"] == "computer.state"

    async with srv.async_client() as auth_client:
        # Authenticated SSE handles Last-Event-ID and delivers post-restart events cleanly
        post_rx = await auth_client.post(
            f"/api/v1/messages/{msg_id}/reactions",
            json={"emoji": "🔓", "action": "add"},
        )
        assert post_rx.status_code == 200
        post_turn = await trigger_and_wait_turn(auth_client, "thr_bot_chief", "/approval Post")
        assert post_turn.terminal_event.event_type == "hitl.approval.requested"

        replayed = await _collect_sse_replay(
            auth_client,
            headers={"Last-Event-ID": last_id},
            idle_timeout=0.4,
        )
        reaction_frames = [
            f
            for f in replayed
            if f.event_type == "message.reaction"
            and isinstance(f.data, dict)
            and f.data.get("payload", {}).get("message_id") == msg_id
            and f.data.get("payload", {}).get("emoji") == "🔓"
        ]
        assert len(reaction_frames) == 1, f"Missing post-restart reaction in replay: {replayed}"
        assert any(
            f.event_type == "hitl.approval.requested"
            and isinstance(f.data, dict)
            and f.data.get("turn_id") == post_turn.turn_id
            for f in replayed
        ), f"Missing post-restart approval event in replay: {replayed}"
        for frame in replayed:
            assert frame.id is not None and frame.id.startswith("evt_")
            ep, seq = _parse_event_cursor(frame.id)
            assert ep is not None and seq is not None and seq >= 1

        # Rate limit enforcement returns 429 + Retry-After header (vnc-token limit: 30/60s)
        saw_429 = False
        for _ in range(35):
            r = await auth_client.post("/api/v1/computers/default/vnc-token", json={})
            if r.status_code == 429:
                assert int(r.headers.get("retry-after", "0")) >= 1
                saw_429 = True
                break
            assert r.status_code == 200
        assert saw_429
