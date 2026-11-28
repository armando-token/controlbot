"""Tier 1 isolated happy-path E2E tests for core ControlBot flows CB-00 through CB-06."""

from __future__ import annotations

import asyncio
import contextlib
import http.server
import json
import re
import sqlite3
import struct
import threading
import time
from collections.abc import Callable, Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import websockets
from playwright.async_api import ConsoleMessage, Page, Response, Route, WebSocket
from tests.e2e_qa.conftest import StrictBrowserPage
from tests.e2e_qa.fixtures import ValveCatalogFixture, build_cb_valve_104_catalog
from tests.e2e_qa.helpers import (
    IsolatedQAEnv,
    QACliRunner,
    SseFrame,
    UxTimingResult,
    alloc_qa_free_port,
    assert_no_secret_leak,
    assert_react_app_surface,
    iter_sse_events,
    measure_ttfp_and_completion,
    mint_cap_token,
    trigger_and_wait_turn,
)
from websockets.asyncio.client import ClientConnection
from websockets.typing import Subprotocol

pytestmark = pytest.mark.qa_tier1

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_CONV_ID = "11111111-2222-3333-4444-555555555555"

_CORE_MOCK_AGY_SCRIPT = f"""#!/usr/bin/env python3
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

prompt = ""
for i, arg in enumerate(args):
    if arg == "-p" and i + 1 < len(args):
        prompt = args[i + 1]
        break
    if arg.startswith("--prompt="):
        prompt = arg.split("=", 1)[1]
        break

cid = "{_CONV_ID}"
reply = "Core mock reply: acknowledged."

# CB-03 sleeping cancel side-effect probe
if "CANCEL_SLEEP_PROBE" in prompt:
    marker_match = re.search(r"MARKER=([^\\s]+)", prompt)
    marker_path = Path(marker_match.group(1)) if marker_match else Path("post_cancel_marker.txt")
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
                "text_delta": "Starting slow workspace task... ",
            }},
        }}), flush=True)
        time.sleep(3.5)
        marker_path.write_text("SIDE_EFFECT_EXECUTED_AFTER_SLEEP\\n", encoding="utf-8")
        print(json.dumps({{
            "event": "result",
            "result": {{
                "status": "SUCCESS",
                "conversation_id": cid,
                "response": "Starting slow workspace task... finished.",
            }},
        }}), flush=True)
    sys.exit(0)

# CB-02 dynamic loopback HTML catalog reader
url_match = re.search(r"CATALOG_BASE=(http://127\\.0\\.0\\.1:\\d+)", prompt)
port_match = re.search(r"CATALOG_PORT=(\\d+)", prompt)
if url_match or port_match:
    base = url_match.group(1) if url_match else f"http://127.0.0.1:{{port_match.group(1)}}"
    with urllib.request.urlopen(base + "/index.json", timeout=5) as resp:
        records = json.loads(resp.read().decode("utf-8"))
    sku_match = re.search(r"SKU=([A-Za-z0-9_-]+)", prompt)
    target_sku = sku_match.group(1) if sku_match else ""
    matching = [r for r in records if r.get("sku") == target_sku]
    current = [r for r in matching if r.get("status") == "current"]
    if current:
        chosen = current[0]
        with urllib.request.urlopen(base + chosen["source_url"], timeout=5) as page_resp:
            html_body = page_resp.read().decode("utf-8")
        price_m = re.search(r"data-price='([^']+)'", html_body)
        price_val = price_m.group(1) if price_m else chosen["price"]
        reply = (
            f"{{chosen['sku']}}: {{chosen['currency']}} {{price_val}} "
            f"(effective {{chosen['effective_date']}}, source {{chosen['source_url']}})"
        )
    else:
        reply = f"No current catalog price found for {{target_sku}}."
elif any(
    tok in prompt.upper()
    for tok in ("CONTROLBOT_OPS", "CONTROLBOT-OPS", "CONTROLBOT OPS")
):
    reply = "Ops bot targeted reply: telemetry nominal."
elif "SIMPLE_CHAT_CHECK" in prompt:
    reply = "Simple chat reply verified for CB-01."

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

print(json.dumps({{"status": "SUCCESS", "conversation_id": cid, "response": reply}}))
"""


class _DynamicCatalogState:
    """Mutable holder for loopback HTTP catalog fixture serving."""

    def __init__(self, fixture: ValveCatalogFixture) -> None:
        self.lock = threading.Lock()
        self.fixture = fixture

    def update(self, fixture: ValveCatalogFixture) -> None:
        with self.lock:
            self.fixture = fixture


@contextlib.contextmanager
def _serve_valve_catalog(
    initial: ValveCatalogFixture,
) -> Iterator[tuple[str, _DynamicCatalogState]]:
    state = _DynamicCatalogState(initial)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            with state.lock:
                cur = state.fixture
                pages = cur.render_html_pages()
                records = cur.to_json_records()
            if self.path == "/index.json":
                payload = json.dumps(records).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path in pages:
                payload = pages[self.path].encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    port = alloc_qa_free_port()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3.0)


def _is_loopback_browser_url(url: str) -> bool:
    if url.startswith(("data:", "blob:", "about:")):
        return True
    parsed = urlparse(url)
    if parsed.scheme in {"http", "https", "ws", "wss"}:
        return (parsed.hostname or "").lower() in _LOOPBACK_HOSTS
    return False


@contextlib.asynccontextmanager
async def _vnc_safe_browser_page(
    strict_browser_page: StrictBrowserPage,
) -> Any:
    """Provide a BrowserContext without WebSocketRoute mock so @novnc/novnc attaches cleanly."""
    ctx = await strict_browser_page.browser.new_context(viewport={"width": 1280, "height": 800})

    async def _http_guard(route: Route) -> None:
        req_url = route.request.url
        if _is_loopback_browser_url(req_url):
            await route.continue_()
        else:
            strict_browser_page.external_requests.append(req_url)
            await route.abort()

    await ctx.route("**/*", _http_guard)
    page: Page = await ctx.new_page()

    def _on_console(msg: ConsoleMessage) -> None:
        if msg.type == "error":
            strict_browser_page.console_errors.append(msg.text)

    def _on_pageerror(exc: Exception) -> None:
        strict_browser_page.page_errors.append(repr(exc))

    def _on_response(resp: Response) -> None:
        if resp.status >= 400:
            strict_browser_page.http_errors.append((resp.status, resp.url))

    def _ws_observer(ws: WebSocket) -> None:
        if not _is_loopback_browser_url(ws.url):
            strict_browser_page.external_requests.append(ws.url)

        def _on_ws_socketerror(err_msg: str) -> None:
            strict_browser_page.page_errors.append(f"ws.socketerror({ws.url}): {err_msg}")

        ws.on("socketerror", _on_ws_socketerror)

    page.on("console", _on_console)
    page.on("pageerror", _on_pageerror)
    page.on("response", _on_response)
    page.on("websocket", _ws_observer)

    try:
        yield page
    finally:
        with contextlib.suppress(Exception):
            await ctx.unroute_all(behavior="ignoreErrors")
        with contextlib.suppress(Exception):
            await page.close()
        with contextlib.suppress(Exception):
            await ctx.close()


def _parse_event_cursor(event_id: str | None) -> tuple[str | None, int | None]:
    if not event_id:
        return None, None
    if event_id.startswith("evt_"):
        parts = event_id.split("_", 2)
        if len(parts) == 3 and parts[1].isdigit():
            return parts[2], int(parts[1])
    if ":" in event_id:
        epoch, seq_raw = event_id.split(":", 1)
        if seq_raw.isdigit():
            return epoch, int(seq_raw)
    return None, None


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
    await ws.send(b"\x01")

    srv_init = await reader.read_exact(24)
    width, height, _bpp, _depth, _big, _true, _rm, _gm, _bm, _rs, _gs, _bs, name_len = (
        struct.unpack("!HHBBBBHHHBBB3xI", srv_init)
    )
    desktop_name = await reader.read_exact(int(name_len))
    assert (width, height) == (640, 480)
    assert desktop_name == b"MockRFB"
    return reader


def _load_megaplan_run_records(camp_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for db_file in sorted(camp_dir.glob("**/*.sqlite3")):
        with sqlite3.connect(db_file) as conn:
            conn.row_factory = sqlite3.Row
            tables = {
                str(r[0])
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "qa_run_records" in tables:
                for row in conn.execute("SELECT * FROM qa_run_records").fetchall():
                    row_dict = dict(row)
                    payload_raw = row_dict.get("payload_json")
                    if isinstance(payload_raw, str) and payload_raw.strip():
                        parsed = json.loads(payload_raw)
                        if isinstance(parsed, dict):
                            row_dict = {**row_dict, **parsed}
                    records.append(row_dict)
    if records:
        return records

    for run_file in sorted([*camp_dir.glob("**/run_*.json"), *camp_dir.glob("**/runs.jsonl")]):
        raw_text = run_file.read_text(encoding="utf-8")
        if run_file.suffix == ".jsonl":
            for line in raw_text.splitlines():
                if line.strip():
                    records.append(json.loads(line))
        else:
            records.append(json.loads(raw_text))
    return records


# ---------------------------------------------------------------------------
# CB-00: Startup, Health, System Info, React Navigation & Reload Coherence
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb00_health_system_info_react_nav_and_reload_coherence(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-00: /health, /api/system/info, React /app view navigation & reload coherence."""
    with qa_env.client() as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.headers.get("X-Request-Id", "").startswith("req_")
        assert health.json() == {
            "status": "ok",
            "service": "grokbot-web",
            "db_path": str(qa_env.db_path),
        }

        sys_info = client.get("/api/system/info")
        assert sys_info.status_code == 200
        info_json = sys_info.json()
        assert info_json["service"] == "controlbot"
        assert info_json["db_path"] == str(qa_env.db_path)
        assert_no_secret_leak(info_json, secrets=(qa_env.cap_secret,))

        app_resp = client.get("/app")
        assert app_resp.status_code == 200
        assert "no-store" in app_resp.headers.get("Cache-Control", "")

    surface = await assert_react_app_surface(qa_env.base_url, strict_browser_page)
    assert surface["title"] == "Grok Bot — ControlBot Studio"

    page = strict_browser_page.page
    sidebar = page.locator("aside")
    await sidebar.get_by_text("Chief of Staff").wait_for(state="visible")

    # Navigate across Inspector tabs, Settings dialog, Memory dialog, and sidebar collapse/expand
    await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
    await page.get_by_role("tab", name="Details").wait_for(state="visible")
    await page.get_by_role("tab", name="Library").click()
    await page.get_by_role("button", name="All", exact=True).wait_for(state="visible")

    await sidebar.get_by_role("button", name="Settings").click()
    await page.get_by_role("dialog").wait_for(state="visible")
    await page.keyboard.press("Escape")
    await page.get_by_role("dialog").wait_for(state="hidden")

    await sidebar.get_by_role("button", name="Memory", exact=True).click()
    await page.get_by_role("dialog").wait_for(state="visible")
    await page.keyboard.press("Escape")
    await page.get_by_role("dialog").wait_for(state="hidden")

    await page.keyboard.press("Control+b")
    await page.locator('button[title="Expand sidebar (Cmd/Ctrl+B)"]').wait_for(state="visible")
    await page.keyboard.press("Control+b")
    await page.locator('button[title="Collapse sidebar (Cmd/Ctrl+B)"]').wait_for(state="visible")

    # Reload coherence
    await page.reload(wait_until="networkidle")
    await page.locator('textarea[aria-label="Message composer"]').wait_for(state="visible")
    await sidebar.get_by_text("Chief of Staff").wait_for(state="visible")
    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
async def test_cb00_ttfp_and_primary_navigation_affordances(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-00: Initial boot & navigation meet UX TTFP/action-count expectations."""
    page = strict_browser_page.page

    async def _boot_and_ready() -> str:
        await page.goto(qa_env.base_url + "/app", wait_until="domcontentloaded")
        composer = page.locator('textarea[aria-label="Message composer"]')
        await composer.wait_for(state="visible", timeout=15000)
        return await page.title()

    async def _composer_visible() -> bool:
        return await page.locator('textarea[aria-label="Message composer"]').is_visible()

    title, timing = await measure_ttfp_and_completion(
        _boot_and_ready,
        actions_to_reach=1,
        ttfp_probe=_composer_visible,
        cancel_available=False,
    )
    assert title == "Grok Bot — ControlBot Studio"
    assert isinstance(timing, UxTimingResult)
    assert timing.actions_to_reach <= 2
    assert timing.ttfp_ms is not None
    assert timing.ttfp_ms <= timing.completion_ms
    assert timing.completion_ms < 15000.0
    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# CB-01: Simple Chat Turn, Presence, Streaming & Reopen Persistence
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb01_simple_chat_turn_presence_streaming_and_reopen_persistence(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-01: Simple chat emits user msg, bot.presence working->idle, final reply, and persists."""
    env = qa_env_factory(mock_agy_script=_CORE_MOCK_AGY_SCRIPT, name="cb01_chat")
    page = strict_browser_page.page

    async with env.async_client() as aclient:
        sse_frames: list[SseFrame] = []
        sse_connected = asyncio.Event()

        async def _listen_sse() -> None:
            saw_completed = False
            saw_idle = False
            async for frame in iter_sse_events(
                aclient,
                timeout=15.0,
                on_connected=sse_connected,
            ):
                sse_frames.append(frame)
                ev = frame.event_type or frame.event
                if ev == "message.completed":
                    saw_completed = True
                if (
                    ev == "bot.presence"
                    and isinstance(frame.data, dict)
                    and frame.data.get("bot_id") == "bot_chief"
                    and frame.data.get("payload", {}).get("state") == "idle"
                ):
                    saw_idle = True
                if saw_completed and saw_idle:
                    return

        listen_task = asyncio.create_task(_listen_sse())
        try:
            await asyncio.wait_for(sse_connected.wait(), timeout=5.0)
            await page.goto(env.url("/app"), wait_until="networkidle")
            await page.wait_for_selector("text=Chief of Staff")

            composer = page.locator('textarea[aria-label="Message composer"]')
            await composer.fill("SIMPLE_CHAT_CHECK ping status")
            await composer.press("Enter")

            await page.get_by_text("SIMPLE_CHAT_CHECK ping status").wait_for(
                state="visible", timeout=10000
            )
            await page.get_by_text("Simple chat reply verified for CB-01.").wait_for(
                state="visible", timeout=15000
            )
            await asyncio.wait_for(listen_task, timeout=15.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await listen_task

        presence_states = [
            f.data.get("payload", {}).get("state")
            for f in sse_frames
            if (f.event_type or f.event) == "bot.presence"
            and isinstance(f.data, dict)
            and f.data.get("bot_id") == "bot_chief"
        ]
        assert "working" in presence_states or "thinking" in presence_states
        assert "idle" in presence_states

        # Switch away and reopen thread, plus reload browser, to confirm persistence
        await page.locator("aside").get_by_text("ControlBot Ops").click()
        await page.locator("aside").get_by_text("Chief of Staff").click()
        await page.get_by_text("Simple chat reply verified for CB-01.").wait_for(
            state="visible", timeout=10000
        )

        await page.reload(wait_until="networkidle")
        await page.get_by_text("SIMPLE_CHAT_CHECK ping status").wait_for(state="visible")
        await page.get_by_text("Simple chat reply verified for CB-01.").wait_for(state="visible")

        hist = (await aclient.get("/api/v1/threads/thr_bot_chief/messages")).json()["messages"]
        contents = [str(m.get("content", "")) for m in hist]
        assert any("SIMPLE_CHAT_CHECK ping status" in c for c in contents)
        assert any("Simple chat reply verified for CB-01." in c for c in contents)

    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
async def test_cb01_auth_token_propagation_and_bot_model_persistence(
    qa_auth_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-01: Auth token propagates across Studio requests and bot config persists on reload."""
    page = strict_browser_page.page
    seen_urls: list[str] = []

    def _capture_req(req: Any) -> None:
        if req.url.startswith(qa_auth_env.base_url):
            seen_urls.append(str(req.url))

    page.on("request", _capture_req)

    await page.goto(qa_auth_env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    token = qa_auth_env.web_token
    assert token is not None
    api_calls = [u for u in seen_urls if urlparse(u).path.startswith("/api/v1/")]
    assert api_calls
    for url in api_calls:
        assert parse_qs(urlparse(url).query).get("token") == [token]

    with qa_auth_env.client() as client:
        patch_resp = client.patch(
            "/api/v1/bots/bot_chief",
            json={"thinking_level": "high", "project_name": "Grokbotclon"},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["thinking_level"] == "high"
        assert patch_resp.json()["project_name"] == "Grokbotclon"

    await page.reload(wait_until="networkidle")
    with qa_auth_env.client() as client:
        bots = client.get("/api/v1/bots").json()["bots"]
        chief = next(b for b in bots if b["id"] == "bot_chief")
        assert chief["thinking_level"] == "high"
        assert chief["project_name"] == "Grokbotclon"

    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# CB-02: Dynamic CB-VALVE-104 Grounded Q&A & Price Update
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb02_valve_104_dynamic_catalog_current_vs_superseded_and_price_update(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-02: Dynamic CB-VALVE-104 catalog returns current price & reflects live price update."""
    fixture = build_cb_valve_104_catalog()
    assert fixture.active_record.price != fixture.prior_record.price
    assert fixture.active_record.status == "current"
    assert fixture.prior_record.status == "superseded"

    with _serve_valve_catalog(fixture) as (catalog_origin, state):
        catalog_port = urlparse(catalog_origin).port
        assert catalog_port is not None
        env = qa_env_factory(mock_agy_script=_CORE_MOCK_AGY_SCRIPT, name="cb02_valve")
        with env.client() as client:
            assert (
                client.patch("/api/v1/apps/app_runtime", json={"enabled": False}).status_code
                == 200
            )
        page = strict_browser_page.page
        await page.goto(env.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")

        composer = page.locator('textarea[aria-label="Message composer"]')
        prompt_1 = (
            f"{fixture.prompt_es} CATALOG_PORT={catalog_port} SKU={fixture.sku}"
        )
        await composer.fill(prompt_1)
        await composer.press("Enter")

        expected_cur_price = str(fixture.active_record.price)
        expected_prior_price = str(fixture.prior_record.price)
        expected_cur_text = (
            f"{fixture.sku}: {fixture.active_record.currency} {expected_cur_price}"
        )
        await page.get_by_text(expected_cur_text).wait_for(state="visible", timeout=15000)

        with env.client() as client:
            msgs = client.get("/api/v1/threads/thr_bot_chief/messages").json()["messages"]
            last_bot = next(m for m in reversed(msgs) if m["sender_type"] == "bot")
            body_1 = str(last_bot["content"])
            assert expected_cur_price in body_1
            assert fixture.active_record.currency in body_1
            assert (
                re.search(
                    rf"{re.escape(fixture.active_record.source_url)}(?![A-Za-z0-9_/-])",
                    body_1,
                )
                is not None
            ), f"Exact active source_url missing in {body_1!r}"
            assert fixture.prior_record.source_url not in body_1
            assert expected_prior_price not in body_1

        # Dynamically update the price with a fresh non-hardcoded delta
        new_price = (fixture.active_record.price + Decimal("17.35")).quantize(Decimal("0.01"))
        updated_fixture = fixture.apply_price_update(new_price, effective_date="2026-11-29")
        state.update(updated_fixture)

        prompt_2 = (
            f"Re-check {updated_fixture.sku} price update "
            f"CATALOG_PORT={catalog_port} SKU={updated_fixture.sku}"
        )
        await composer.fill(prompt_2)
        await composer.press("Enter")

        expected_upd_price = str(updated_fixture.active_record.price)
        expected_upd_text = (
            f"{updated_fixture.sku}: {updated_fixture.active_record.currency} {expected_upd_price}"
        )
        await page.get_by_text(expected_upd_text).wait_for(state="visible", timeout=15000)

        with env.client() as client:
            msgs_after = client.get("/api/v1/threads/thr_bot_chief/messages").json()["messages"]
            last_bot_2 = next(m for m in reversed(msgs_after) if m["sender_type"] == "bot")
            body_2 = str(last_bot_2["content"])
            assert expected_upd_price in body_2
            assert expected_cur_price not in body_2
            assert (
                re.search(
                    rf"{re.escape(updated_fixture.active_record.source_url)}(?![A-Za-z0-9_/-])",
                    body_2,
                )
                is not None
            ), f"Exact updated source_url missing in {body_2!r}"
            assert_no_secret_leak(msgs_after, secrets=(env.cap_secret,))

    strict_browser_page.assert_clean()


@pytest.mark.qa_megaplan
def test_megaplan_cb02_scan_executes_dynamic_valve_fixture(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #14: `python -m src.qa scan --cases CB-02` executes dynamic valve fixture."""
    camp_dir = tmp_path / "camp_cb02"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"

    scan_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-02", "--json"]
    )
    combined = (scan_res.stdout + "\n" + scan_res.stderr).lower()
    assert "unrecognized arguments" not in combined, f"CLI rejected scan args: {scan_res.stderr}"
    assert "notimplementederror" not in combined, (
        f"CB-02 scenario scan is not yet implemented: {scan_res.stderr}"
    )
    assert scan_res.returncode == 0, f"scan CB-02 failed: {scan_res.stderr}\n{scan_res.stdout}"

    records = _load_megaplan_run_records(camp_dir)
    cb02_records = [r for r in records if r.get("case_id") == "CB-02"]
    assert cb02_records, f"Expected CB-02 RunRecord in {camp_dir}"
    assert cb02_records[0]["passed"] is True
    assert cb02_records[0].get("fixture_version")


# ---------------------------------------------------------------------------
# CB-03: Cancel Active Turn, Zero Post-Cancel Side Effects & SSE Reconnect
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb03_cancel_active_turn_prevents_post_cancel_workspace_side_effect(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-03: Stop button cancels active turn coherently and kills child before marker write."""
    env = qa_env_factory(mock_agy_script=_CORE_MOCK_AGY_SCRIPT, name="cb03_cancel")
    marker_path = env.projects_root / "Grokbotclon" / "post_cancel_marker.txt"
    assert not marker_path.exists()

    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    composer = page.locator('textarea[aria-label="Message composer"]')
    await composer.fill(f"CANCEL_SLEEP_PROBE MARKER={marker_path}")
    await composer.press("Enter")

    stop_btn = page.locator('button[aria-label="Stop current generation"]')
    await stop_btn.wait_for(state="visible", timeout=10000)
    await page.get_by_text("Starting slow workspace task...").wait_for(
        state="visible", timeout=10000
    )

    await stop_btn.click()
    await page.locator('button[aria-label="Send message"]').wait_for(state="visible", timeout=10000)

    # Wait past the child script's 3.5s sleep window to prove proc.kill() aborted any write
    await asyncio.sleep(4.0)
    assert not marker_path.exists(), f"Post-cancel workspace side effect occurred: {marker_path}"

    with env.client() as client:
        msgs = client.get("/api/v1/threads/thr_bot_chief/messages").json()["messages"]
        bot_msgs = [m for m in msgs if m["sender_type"] == "bot"]
        assert bot_msgs, "Expected interrupted assistant message persisted"
        assert bot_msgs[-1]["status"] == "interrupted"

    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
async def test_cb03_sse_last_event_id_replay_evt_and_colon_formats(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-03: SSE reconnect supports both evt_<seq>_<epoch> and <epoch>:<seq> without dupes."""
    async with qa_env.async_client() as client:
        turn = await trigger_and_wait_turn(client, "thr_bot_chief", "/approval CB-03 SSE seed")
        msg_id = str(turn.user_message["id"])

        frames: list[SseFrame] = []
        connected = asyncio.Event()

        async def _collect_initial() -> None:
            async for frame in iter_sse_events(client, timeout=10.0, on_connected=connected):
                if frame.event_type == "message.reaction":
                    frames.append(frame)
                    if len(frames) >= 2:
                        return

        task = asyncio.create_task(_collect_initial())
        try:
            await asyncio.wait_for(connected.wait(), timeout=5.0)
            for emoji in ("👍", "🔥"):
                resp = await client.post(
                    f"/api/v1/messages/{msg_id}/reactions",
                    json={"emoji": emoji, "action": "add"},
                )
                assert resp.status_code == 200
            await asyncio.wait_for(task, timeout=10.0)
        finally:
            if not task.done():
                task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

        anchor_id = str(frames[0].id)
        epoch, seq = _parse_event_cursor(anchor_id)
        assert epoch is not None and seq is not None
        colon_cursor = f"{epoch}:{seq}"

        # Emit missed event while disconnected
        missed_resp = await client.post(
            f"/api/v1/messages/{msg_id}/reactions",
            json={"emoji": "✅", "action": "add"},
        )
        assert missed_resp.status_code == 200

        async def _replay(headers: dict[str, str] | None = None, query: str = "") -> list[SseFrame]:
            replayed: list[SseFrame] = []
            async for frame in iter_sse_events(
                client,
                url=f"/api/v1/events/stream{query}",
                headers=headers,
                timeout=3.0,
            ):
                replayed.append(frame)
                if (
                    frame.event_type == "message.reaction"
                    and isinstance(frame.data, dict)
                    and frame.data.get("payload", {}).get("emoji") == "✅"
                ):
                    break
            return replayed

        hdr_replay = await _replay(headers={"Last-Event-ID": anchor_id})
        qry_replay = await _replay(query=f"?last_event_id={colon_cursor}")

        for batch in (hdr_replay, qry_replay):
            assert all(f.event_type != "stream.resync" for f in batch)
            emojis = [
                f.data.get("payload", {}).get("emoji")
                for f in batch
                if f.event_type == "message.reaction" and isinstance(f.data, dict)
            ]
            assert emojis == ["🔥", "✅"]
            ids = [f.id for f in batch if f.id]
            assert len(ids) == len(set(ids))


@pytest.mark.qa_existing
async def test_cb03_sse_reconnect_no_duplicate_bubbles_in_ui(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-03: Reconnecting/reloading after SSE events yields zero duplicate UI message bubbles."""
    env = qa_env_factory(mock_agy_script=_CORE_MOCK_AGY_SCRIPT, name="cb03_ui_dedup")
    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    composer = page.locator('textarea[aria-label="Message composer"]')
    await composer.fill("SIMPLE_CHAT_CHECK unique bubble probe")
    await composer.press("Enter")
    await page.get_by_text("Simple chat reply verified for CB-01.").wait_for(
        state="visible", timeout=15000
    )

    await page.reload(wait_until="networkidle")
    await page.get_by_text("Simple chat reply verified for CB-01.").wait_for(state="visible")
    assert await page.get_by_text("Simple chat reply verified for CB-01.").count() == 1
    assert await page.get_by_text("SIMPLE_CHAT_CHECK unique bubble probe").count() == 1
    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# CB-04: Roster, Sections, HiddenBotsDrawer, Thread Switching & Group @Mention
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb04_roster_section_crud_and_hidden_bots_drawer_persistence(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-04: Create/rename/hide/unhide bots and sections with HiddenBotsDrawer & reload persist."""
    page = strict_browser_page.page
    await page.goto(qa_env.base_url + "/app", wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    sidebar = page.locator("aside")

    # Create section
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New section").click()
    sec_input = page.locator('input[placeholder="Section name, press Enter…"]')
    await sec_input.fill("QA Core Section")
    await sec_input.press("Enter")
    await sidebar.get_by_text("QA Core Section").wait_for(state="visible")

    # Create bot
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.locator("button").filter(has_text=re.compile(r"^New bot")).click()
    await page.locator("#new-bot-name").fill("Valve Watcher")
    await page.get_by_role("button", name="Create bot").click()
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message Valve Watcher'"
    )

    # Rename bot via API and verify in UI
    with qa_env.client() as client:
        bots = client.get("/api/v1/bots").json()["bots"]
        watcher = next(b for b in bots if b["name"] == "Valve Watcher")
        rename_resp = client.patch(
            f"/api/v1/bots/{watcher['id']}",
            json={"name": "Valve Auditor"},
        )
        assert rename_resp.status_code == 200
        assert rename_resp.json()["name"] == "Valve Auditor"

    await page.reload(wait_until="networkidle")
    await sidebar.get_by_text("Valve Auditor").wait_for(state="visible")

    # Hide & Unhide via HiddenBotsDrawer
    bot_row = sidebar.locator("div.group").filter(has_text="Valve Auditor").first
    await bot_row.hover()
    await page.locator('button[aria-label="More options for Valve Auditor"]').click()
    await page.get_by_role("button", name="Hide from sidebar").click()
    await sidebar.get_by_text("Valve Auditor").wait_for(state="hidden")

    await sidebar.get_by_role("button", name="Hidden bots").click()
    drawer = page.get_by_role("dialog")
    await drawer.get_by_text("Valve Auditor").wait_for(state="visible")
    await drawer.get_by_role("button", name="Unhide").click()
    await page.keyboard.press("Escape")
    await drawer.wait_for(state="hidden")
    await sidebar.get_by_text("Valve Auditor").wait_for(state="visible")

    await page.reload(wait_until="networkidle")
    await sidebar.get_by_text("QA Core Section").wait_for(state="visible")
    await sidebar.get_by_text("Valve Auditor").wait_for(state="visible")
    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
async def test_cb04_thread_switching_isolation_and_group_channel_mention_routing(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-04: Thread switching isolates messages and group channel @mention routes cleanly."""
    env = qa_env_factory(mock_agy_script=_CORE_MOCK_AGY_SCRIPT, name="cb04_group")
    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    sidebar = page.locator("aside")
    composer = page.locator('textarea[aria-label="Message composer"]')

    # Send message in Chief of Staff thread
    await composer.fill("SIMPLE_CHAT_CHECK chief-only context")
    await composer.press("Enter")
    await page.get_by_text("Simple chat reply verified for CB-01.").wait_for(
        state="visible", timeout=15000
    )

    # Switch to ControlBot Ops -> must not display Chief of Staff messages
    await sidebar.get_by_text("ControlBot Ops").click()
    assert await composer.get_attribute("placeholder") == "Message ControlBot Ops"
    assert await page.get_by_text("SIMPLE_CHAT_CHECK chief-only context").count() == 0

    # Create 2-bot group channel and route via @mention popover
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New group chat").click()
    dlg = page.get_by_role("dialog")
    await dlg.locator("#new-channel-name").fill("Valve Sync")
    await dlg.get_by_role("button", name="Chief of Staff").click()
    await dlg.get_by_role("button", name="ControlBot Ops").click()
    await dlg.get_by_text("2 / 6 selected").wait_for(state="visible")
    await dlg.get_by_role("button", name="Create group chat").click()
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message #Valve Sync (use @ to mention bots)'"
    )

    await composer.click()
    await composer.type("@")
    mention_hdr = page.get_by_text("Mention", exact=True)
    await mention_hdr.wait_for(state="visible")
    await mention_hdr.locator("xpath=..").locator("button").filter(
        has_text="ControlBot Ops"
    ).click()
    await page.wait_for_function(
        "() => /^@controlbot[_-]ops\\s/i.test("
        "document.querySelector('textarea[aria-label=\"Message composer\"]')?.value || '')"
    )
    await composer.type("check status")
    await composer.press("Enter")
    await page.get_by_text("Ops bot targeted reply: telemetry nominal.").wait_for(
        state="visible", timeout=15000
    )

    with env.client() as client:
        channels = client.get("/api/v1/bots").json()["channels"]
        ch = next(c for c in channels if c["name"] == "Valve Sync")
        ch_msgs = client.get(f"/api/v1/threads/{ch['thread_id']}/messages").json()["messages"]
        bot_msgs = [m for m in ch_msgs if m["sender_type"] == "bot"]
        assert len(bot_msgs) == 1, f"Expected single targeted reply, got {bot_msgs!r}"
        assert bot_msgs[0]["sender_bot_id"] == "bot_ops"

    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
def test_cb04_group_channel_supports_up_to_six_bots(qa_env: IsolatedQAEnv) -> None:
    """CB-04: Group channels accept 2 to 6 distinct bots cleanly."""
    with qa_env.client() as client:
        created_ids: list[str] = []
        for idx in range(4):
            resp = client.post(
                "/api/v1/bots",
                json={"name": f"SixBotMember {idx + 1}", "engine_id": "agy"},
            )
            assert resp.status_code == 201
            created_ids.append(str(resp.json()["id"]))

        six_bots = ["bot_chief", "bot_ops", *created_ids]
        assert len(six_bots) == 6
        ch_resp = client.post(
            "/api/v1/channels",
            json={"name": "Six Bot War Room", "bot_ids": six_bots},
        )
        assert ch_resp.status_code == 201, ch_resp.text
        ch = ch_resp.json()
        assert len(ch["bot_ids"]) == 6


# ---------------------------------------------------------------------------
# CB-05: Attachments, Library & Pages
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
def test_cb05_attachments_upload_download_byte_parity_and_library(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-05: Attachments preserve exact byte parity across binary/text/JSON and library index."""
    samples: list[tuple[str, str, bytes]] = [
        ("note.txt", "text/plain", b"ControlBot attachment parity\nline 2\n"),
        ("raw.bin", "application/octet-stream", bytes(range(256))),
        ("cfg.json", "application/json", json.dumps({"valve": "104", "ok": True}).encode("utf-8")),
    ]
    with qa_env.client() as client:
        for fname, mime, payload in samples:
            up = client.post(
                "/api/v1/attachments",
                params={"filename": fname},
                headers={"Content-Type": mime},
                content=payload,
            )
            assert up.status_code == 201, up.text
            meta = up.json()
            assert meta["filename"] == fname
            assert meta["size_bytes"] == len(payload)

            dl = client.get(f"/api/v1/attachments/{meta['id']}")
            assert dl.status_code == 200
            assert dl.content == payload
            assert dl.headers.get("X-Content-Type-Options") == "nosniff"

        lib_resp = client.get("/api/v1/bots/bot_chief/library")
        assert lib_resp.status_code == 200
        assert "items" in lib_resp.json()


@pytest.mark.qa_existing
async def test_cb05_pages_create_edit_pin_share_search_export_and_library_filter(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
    tmp_path: Path,
) -> None:
    """CB-05: Pages create/edit/pin/share/find-in-page/export Markdown & Library filter."""
    page = strict_browser_page.page
    await page.goto(qa_env.base_url + "/app", wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    async with page.expect_response(
        lambda r: r.url.endswith("/api/v1/pages") and r.request.method == "POST"
    ) as create_info:
        await page.locator('button[title="Create new interactive page"]').click()
    create_resp = await create_info.value
    assert create_resp.status == 201
    created_json = await create_resp.json()
    page_id = str(created_json["id"])
    page_title = str(created_json["title"])

    split_page = page.locator(".gb-printable-page")
    await split_page.wait_for(state="visible")

    await split_page.get_by_role("button", name="Edit").click()
    await split_page.locator("textarea").fill(
        "# Inspection Report\n\nVerify **seal** integrity and seal torque."
    )
    await split_page.get_by_role("button", name="Save changes").click()
    await split_page.get_by_role("heading", name="Inspection Report").wait_for(state="visible")

    # Pin, Share, Find in page, Export Markdown
    await split_page.locator('button[title="Pin page"]').click()
    await split_page.locator('button[title="Unpin page"]').wait_for(state="visible")
    await split_page.locator('select[aria-label="Share access"]').select_option("team")
    await split_page.get_by_text("Shared with your team").wait_for(state="visible")

    await split_page.locator('button[title="Find in page (Cmd/Ctrl+F)"]').click()
    await split_page.locator('input[placeholder="Search inside this page…"]').fill("seal")
    await split_page.get_by_text("1 / 2").wait_for(state="visible")
    assert await split_page.locator("mark.gb-search-hit").count() == 2

    async with page.expect_download() as dl_info:
        await split_page.locator('button[title="Export Markdown"]').click()
    dl = await dl_info.value
    export_dest = tmp_path / dl.suggested_filename
    await dl.save_as(export_dest)
    assert "Verify **seal** integrity" in export_dest.read_text(encoding="utf-8")

    # Library API & UI persistence across reload
    await page.reload(wait_until="networkidle")
    await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
    await page.get_by_role("tab", name="Library").click()
    await page.get_by_role("button", name="Pinned", exact=True).click()
    await page.get_by_text(page_title).wait_for(state="visible")

    with qa_env.client() as client:
        lib = client.get("/api/v1/bots/bot_chief/library?type=page&pinned=true").json()
        assert any(item["id"] == page_id for item in lib["items"])

    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
async def test_cb05_artifact_delete_preserves_bound_attachment(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-05: Deleting a page artifact emits artifact.deleted while bound attachment stays 200."""
    async with qa_env.async_client() as client:
        att_bytes = b"Bound attachment survives artifact delete"
        up = await client.post(
            "/api/v1/attachments",
            params={"filename": "bound.txt"},
            headers={"Content-Type": "text/plain"},
            content=att_bytes,
        )
        assert up.status_code == 201
        att_id = str(up.json()["id"])

        page_resp = await client.post(
            "/api/v1/pages",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "title": "Temp Page",
                "content_md": f"See attachment {att_id}",
            },
        )
        assert page_resp.status_code == 201
        art_id = str(page_resp.json()["id"])

        del_events: list[SseFrame] = []
        connected = asyncio.Event()

        async def _listen_del() -> None:
            async for frame in iter_sse_events(client, timeout=8.0, on_connected=connected):
                if (frame.event_type or frame.event) == "artifact.deleted":
                    del_events.append(frame)
                    return

        task = asyncio.create_task(_listen_del())
        try:
            await asyncio.wait_for(connected.wait(), timeout=5.0)
            del_resp = await client.delete(f"/api/v1/artifacts/{art_id}")
            assert del_resp.status_code == 200
            await asyncio.wait_for(task, timeout=8.0)
        finally:
            if not task.done():
                task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

        assert del_events
        assert (await client.get(f"/api/v1/pages/{art_id}")).status_code == 404
        dl = await client.get(f"/api/v1/attachments/{att_id}")
        assert dl.status_code == 200
        assert dl.content == att_bytes


# ---------------------------------------------------------------------------
# CB-06: Computer Panel, Takeover, MockRfbServer Input Gate & PTY Workspace
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_cb06_computer_panel_status_vnc_token_and_pty_workspace_ui(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-06: Computer panel status, vnc-token, PTY in disposable workspace & Files tab."""
    env = qa_env_factory(with_mock_rfb=True, name="cb06_panel")
    with env.client() as client:
        status_resp = client.get("/api/v1/computers/default/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["control_owner"] == "agent"

        tok = mint_cap_token(client, vm_id="default")
        assert tok["cap_token"]
        assert tok["ws_vnc_url"].startswith("/ws/v1/computers/default/vnc?cap_token=")

    async with _vnc_safe_browser_page(strict_browser_page) as page:
        await page.goto(env.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")

        await page.locator('button[title="Open Bot Computer"]').click()
        await page.locator("canvas").first.wait_for(state="visible", timeout=10000)
        await page.get_by_text("Starting display").wait_for(state="hidden", timeout=10000)
        assert await page.get_by_text("Unavailable").count() == 0
        assert await page.get_by_text("Reconnecting").count() == 0
        assert env.mock_rfb is not None and env.mock_rfb.handshakes_completed >= 1

        # Terminal PTY command execution in disposable workspace
        await page.get_by_role("button", name="Terminal", exact=True).click()
        await page.locator('span[title="connected"]').wait_for(state="visible", timeout=10000)
        await page.locator(".xterm-helper-textarea").focus()
        await page.keyboard.type("echo QA_CB06_PTY_OK")
        await page.keyboard.press("Enter")
        await page.wait_for_function(
            "() => (document.querySelector('.xterm-rows')?.innerText || '')"
            ".includes('QA_CB06_PTY_OK')",
            timeout=10000,
        )

        # WorkspaceFilesTab create/edit/delete
        await page.get_by_role("button", name="Files", exact=True).click()
        await page.get_by_role("button", name="New file", exact=True).click()
        await page.locator('input[placeholder="notes.md"]').fill("cb06_note.txt")
        await page.locator('textarea[placeholder="File content…"]').fill("workspace_ok_v1")
        await page.get_by_role("button", name="Create file").click()
        await page.get_by_role("button", name="cb06_note.txt", exact=True).wait_for(
            state="visible"
        )

        file_row = page.locator("div.group").filter(has_text="cb06_note.txt").first
        await file_row.hover()
        await page.locator('button[aria-label="Delete cb06_note.txt"]').click()
        await file_row.wait_for(state="hidden")

    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
async def test_cb06_takeover_handback_and_mock_rfb_input_gate(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """CB-06: MockRfbServer gate drops 0x04/0x05/0x06 unless human takeover is active."""
    env = qa_env_factory(with_mock_rfb=True, name="cb06_rfb_gate")
    assert env.mock_rfb is not None
    mock_rfb = env.mock_rfb

    with env.client() as client:
        tok = mint_cap_token(client, vm_id="default")

    ws_vnc_url = f"{env.ws_base_url}{tok['ws_vnc_url']}"
    fb_req = struct.pack("!BBHHHH", 3, 1, 0, 0, 640, 480)
    key_ev = struct.pack("!BBHI", 4, 1, 0, 0x0061)
    ptr_ev = struct.pack("!BBHH", 5, 1, 120, 240)
    cut_text = struct.pack("!B3xI", 6, 5) + b"hello"

    async with websockets.connect(ws_vnc_url, subprotocols=[Subprotocol("binary")]) as ws:
        reader = await _complete_client_rfb_none_handshake(ws)

        # Agent owns control -> 0x03 passes, 0x04/0x05/0x06 dropped
        await ws.send(fb_req + key_ev + ptr_ev + cut_text)
        assert await reader.read_exact(4) == b"\x00\x00\x00\x00"
        await asyncio.sleep(0.15)
        assert mock_rfb.wait_for_messages(min_count=1, timeout=2.0) == [0x03]
        assert mock_rfb.received_message_types == [0x03]

        # Human takeover -> 0x04/0x05/0x06 forwarded intact
        with env.client() as client:
            tk = client.post("/api/v1/computers/default/takeover", json={"owner": "qa-op"})
            assert tk.status_code == 200
            assert tk.json()["control_owner"] == "human_takeover"

        mock_rfb.reset_records()
        await ws.send(key_ev + ptr_ev + cut_text)
        assert mock_rfb.wait_for_messages(min_count=3, timeout=3.0) == [0x04, 0x05, 0x06]
        assert mock_rfb.received_messages == [
            (0x04, key_ev),
            (0x05, ptr_ev),
            (0x06, cut_text),
        ]

        # Handback -> 0x04/0x05/0x06 dropped again
        with env.client() as client:
            hb = client.post("/api/v1/computers/default/handback", json={})
            assert hb.status_code == 200
            assert hb.json()["control_owner"] == "agent"

        mock_rfb.reset_records()
        await ws.send(fb_req + key_ev + ptr_ev + cut_text)
        assert await reader.read_exact(4) == b"\x00\x00\x00\x00"
        await asyncio.sleep(0.15)
        assert mock_rfb.received_message_types == [0x03]


@pytest.mark.qa_existing
async def test_cb06_ui_takeover_modal_countdown_and_handback(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-06: Take control modal ticks countdown, blocks agent actions, and hands back cleanly."""
    env = qa_env_factory(with_mock_rfb=True, name="cb06_ui_takeover")
    async with _vnc_safe_browser_page(strict_browser_page) as page:
        await page.goto(env.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")

        await page.locator('button[title="Open Bot Computer"]').click()
        await page.get_by_role("button", name="Screen", exact=True).click()
        await page.locator("canvas").first.wait_for(state="visible", timeout=10000)
        await page.get_by_text("Starting display").wait_for(state="hidden", timeout=10000)
        assert await page.get_by_text("Unavailable").count() == 0
        assert await page.get_by_text("Reconnecting").count() == 0
        assert env.mock_rfb is not None and env.mock_rfb.handshakes_completed >= 1
        initial_handshakes = env.mock_rfb.handshakes_completed
        await page.get_by_role("button", name="Take control").click()

        dlg = page.locator('[role="dialog"][aria-label="Full-screen computer view"]')
        await dlg.wait_for(state="visible")
        await dlg.locator("canvas").first.wait_for(state="visible", timeout=10000)
        await dlg.get_by_text("Starting display").wait_for(state="hidden", timeout=10000)
        assert await dlg.get_by_text("Unavailable").count() == 0
        assert await dlg.get_by_text("Reconnecting").count() == 0
        assert env.mock_rfb.handshakes_completed > initial_handshakes
        badge = dlg.locator("span").filter(has_text="You're in control").first
        await badge.wait_for(state="visible")

        m1 = re.search(r"(\d+):(\d{2})", await badge.inner_text())
        assert m1 is not None
        sec1 = int(m1.group(1)) * 60 + int(m1.group(2))
        await asyncio.sleep(2.1)
        m2 = re.search(r"(\d+):(\d{2})", await badge.inner_text())
        assert m2 is not None
        sec2 = int(m2.group(1)) * 60 + int(m2.group(2))
        assert sec2 < sec1

        with env.client() as client:
            blocked = client.post(
                "/api/v1/computers/default/actions",
                json={"type": "start", "url": env.url("/health"), "actor": "agent"},
            )
            assert blocked.status_code == 409

        await dlg.get_by_role("button", name="I'm done").click()
        await dlg.wait_for(state="hidden")
        await page.get_by_text("Control returned to your Bot").wait_for(state="visible")

        with env.client() as client:
            resumed = client.post(
                "/api/v1/computers/default/actions",
                json={"type": "start", "url": env.url("/health"), "actor": "agent"},
            )
            assert resumed.status_code == 200
            assert client.post(
                "/api/v1/computers/default/actions",
                json={"type": "stop", "actor": "agent"},
            ).status_code == 200

    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# Megaplan Core Scenarios Scan Contract (CB-00, CB-01, CB-03..CB-06)
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_megaplan_cb00_through_cb06_scan_contract(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #12-#18: `python -m src.qa scan` executes CB-00..CB-06 and records results."""
    camp_dir = tmp_path / "camp_core"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-00,CB-01,CB-03,CB-04,CB-05,CB-06",
            "--json",
        ]
    )
    combined = (scan_res.stdout + "\n" + scan_res.stderr).lower()
    assert "unrecognized arguments" not in combined, f"CLI rejected scan args: {scan_res.stderr}"
    assert "notimplementederror" not in combined, (
        f"CB-00..CB-06 scan hit NotImplementedError: {scan_res.stderr}"
    )
    assert "validationerror" not in combined, f"Unexpected ValidationError: {scan_res.stderr}"
    assert "traceback (most recent call last)" not in combined, (
        f"Unhandled traceback in scan:\n{scan_res.stdout}\n{scan_res.stderr}"
    )
    for crash_tok in ("keyerror", "attributeerror", "typeerror", "nameerror"):
        assert crash_tok not in combined, (
            f"Unexpected {crash_tok} crash in scan:\n{scan_res.stdout}\n{scan_res.stderr}"
        )
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    records = _load_megaplan_run_records(camp_dir)
    by_case = {str(r.get("case_id")): r for r in records}
    expected_cases = ("CB-00", "CB-01", "CB-03", "CB-04", "CB-05", "CB-06")
    assert set(expected_cases).issubset(by_case), (
        f"Missing cases in records: {set(expected_cases) - set(by_case)}"
    )
    assert all(by_case[c]["passed"] is True for c in expected_cases), (
        f"Expected all core cases CB-00..CB-06 passed=True, got: "
        f"{ {c: by_case[c].get('passed') for c in expected_cases} }"
    )
