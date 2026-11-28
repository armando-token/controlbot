"""Tier 4 realistic multi-step end-to-end QA scenarios covering all 41 Megaplan features."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import http.server
import json
import os
import re
import socket
import socketserver
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import pytest
import uvicorn
import websockets
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from lab.effect_sim import create_effect_sim_app
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import ScadaState, create_scada_app
from playwright.async_api import ConsoleMessage, Page, Response, Route, WebSocket
from src.factory.db import FactoryStore
from src.factory.models import BacklogItem
from tests.e2e._helpers import LabStack, alloc_free_port
from tests.e2e_qa.conftest import StrictBrowserPage
from tests.e2e_qa.fixtures import (
    ValveCatalogFixture,
    build_cb10_three_deliverables_spec,
    build_cb_valve_104_catalog,
    build_grok_bot_reference_card,
    evaluate_csv_to_json_converter,
)
from tests.e2e_qa.helpers import (
    FORBIDDEN_PORTS,
    CliResult,
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

pytestmark = pytest.mark.qa_tier4

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_CONV_ID = "44444444-5555-6666-7777-888888888888"
_MIB = 1024 * 1024
_TEN_MIB = 10 * _MIB
_MAX_ATTACHMENT_BYTES = 25 * _MIB
_ALLOWED_QA_STATES: frozenset[str] = frozenset(
    {
        "observed",
        "reproduced",
        "flaky",
        "in_repair",
        "candidate_verified",
        "accepted_qa",
        "blocked",
        "parked",
    }
)

_T4_MOCK_AGY_SCRIPT = r"""#!/usr/bin/env python3
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

Path.home().joinpath("t4_captured_prompts.jsonl").open("a", encoding="utf-8").write(
    json.dumps({"prompt": prompt}) + "\n"
)

cid = "__CONV_ID__"
reply = "T4 mock reply: acknowledged."
cwd = Path.cwd()

# CB-03 slow workspace side-effect probe
if "CANCEL_SLEEP_PROBE" in prompt:
    marker_match = re.search(r"MARKER=([^\s]+)", prompt)
    marker_path = Path(marker_match.group(1)) if marker_match else Path("post_cancel_marker.txt")
    if "--output-format" in args and "stream-json" in args:
        print(
            json.dumps(
                {
                    "event": "init",
                    "conversation_id": cid,
                    "init": {"model": "gemini-4-carbon-low"},
                }
            ),
            flush=True,
        )
        print(
            json.dumps(
                {
                    "event": "step_update",
                    "step_update": {
                        "step_type": "agent_response",
                        "text_delta": "Starting slow workspace task... ",
                    },
                }
            ),
            flush=True,
        )
        time.sleep(3.5)
        marker_path.write_text("SIDE_EFFECT_EXECUTED_AFTER_SLEEP\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "event": "result",
                    "result": {
                        "status": "SUCCESS",
                        "conversation_id": cid,
                        "response": "Starting slow workspace task... finished.",
                    },
                }
            ),
            flush=True,
        )
    sys.exit(0)

# CB-02 dynamic loopback HTML catalog reader
url_match = re.search(r"CATALOG_BASE=(http://127\.0\.0\.1:\d+)", prompt)
port_match = re.search(r"CATALOG_PORT=(\d+)", prompt)
if url_match or port_match:
    base = url_match.group(1) if url_match else f"http://127.0.0.1:{port_match.group(1)}"
    with urllib.request.urlopen(base + "/index.json", timeout=5) as resp:
        records = json.loads(resp.read().decode("utf-8"))
    if "AMBIGUOUS_QUERY" in prompt:
        ambig = [r for r in records if str(r.get("sku", "")).startswith("CB-VALVE-104-")]
        opts = ", ".join(f"{r['sku']} ({r['currency']} {r['price']})" for r in ambig)
        reply = f"Clarification required: multiple matches found ({opts})."
    elif "MISSING_SKU=" in prompt:
        m_sku = re.search(r"MISSING_SKU=([A-Za-z0-9_-]+)", prompt)
        missing = m_sku.group(1) if m_sku else "UNKNOWN"
        hits = [r for r in records if r.get("sku") == missing]
        if not hits:
            reply = f"Not found in catalog: {missing} does not exist."
    else:
        sku_match = re.search(r"SKU=([A-Za-z0-9_-]+)", prompt)
        target_sku = sku_match.group(1) if sku_match else ""
        current = [
            r for r in records if r.get("sku") == target_sku and r.get("status") == "current"
        ]
        if current:
            chosen = current[0]
            with urllib.request.urlopen(base + chosen["source_url"], timeout=5) as page_resp:
                html_body = page_resp.read().decode("utf-8")
            price_m = re.search(r"data-price='([^']+)'", html_body)
            price_val = price_m.group(1) if price_m else chosen["price"]
            reply = (
                f"{chosen['sku']}: {chosen['currency']} {price_val} "
                f"(effective {chosen['effective_date']}, source {chosen['source_url']})"
            )
        else:
            reply = f"No current catalog price found for {target_sku}."

# CB-09 real CSV -> JSON converter + unit tests in project workspace
elif "CB09_CSV_PROJECT" in prompt:
    proj = cwd / "cb09_proj"
    proj.mkdir(parents=True, exist_ok=True)
    converter_code = '''import csv
import json
import sys
from pathlib import Path


def convert_csv_to_json(csv_path: Path, out_path: Path) -> list[dict[str, str]]:
    raw = csv_path.read_text(encoding="utf-8")
    if raw.count('"') % 2 != 0:
        raise ValueError("Unterminated double quote in CSV")
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        rows = [row for row in csv.reader(fh) if any(cell.strip() for cell in row)]
    if not rows:
        raise ValueError("Empty CSV")
    header = rows[0]
    records: list[dict[str, str]] = []
    for row in rows[1:]:
        if len(row) != len(header):
            raise ValueError(f"Ragged row width: {len(row)} != {len(header)}")
        records.append(dict(zip(header, row, strict=True)))
    out_path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    return records


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write("Usage: csv_to_json.py <input.csv> <output.json>\\n")
        return 2
    try:
        convert_csv_to_json(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        sys.stderr.write(f"CSV error: {exc}\\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    test_code = '''from pathlib import Path
from csv_to_json import convert_csv_to_json


def test_converter_handles_quotes_and_utf8(tmp_path: Path) -> None:
    src = tmp_path / "in.csv"
    dst = tmp_path / "out.json"
    q = chr(34)
    src.write_text(f"sku,name,qty\\n\\nCB-1,{q}Valve, {q}{q}A{q}{q}{q},5\\n", encoding="utf-8")
    rows = convert_csv_to_json(src, dst)
    assert rows == [{"sku": "CB-1", "name": f"Valve, {q}A{q}", "qty": "5"}]
'''
    (proj / "csv_to_json.py").write_text(converter_code, encoding="utf-8")
    (proj / "test_csv_to_json.py").write_text(test_code, encoding="utf-8")
    reply = f"CB-09 project created at {proj} with csv_to_json.py and test_csv_to_json.py."

# CB-10 two-agent 3-deliverable handoff project
elif "CB10_COLLAB" in prompt:
    proj = cwd / "cb10_summary_pkg"
    (proj / "src_pkg").mkdir(parents=True, exist_ok=True)
    (proj / "tests").mkdir(parents=True, exist_ok=True)
    (proj / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    if "AGENT_ALPHA" in prompt and "[CHANNEL HANDOFF CONTEXT]" not in prompt:
        (proj / "src_pkg" / "calc.py").write_text(
            "def compute_summary(values: list[float]) -> dict[str, float]:\n"
            "    if not values:\n"
            "        raise ValueError('values must not be empty')\n"
            "    total = float(sum(values))\n"
            "    return {'count': float(len(values)), 'sum': total, 'avg': total / len(values)}\n",
            encoding="utf-8",
        )
        reply = "D1 delivered: src_pkg/calc.py implements compute_summary."
    else:
        (proj / "src_pkg" / "cli.py").write_text(
            "import json\n"
            "import sys\n"
            "from src_pkg.calc import compute_summary\n\n\n"
            "def main(argv: list[str] | None = None) -> int:\n"
            "    raw = argv if argv is not None else sys.argv[1:]\n"
            "    nums = [float(x) for x in raw]\n"
            "    print(json.dumps(compute_summary(nums), sort_keys=True))\n"
            "    return 0\n",
            encoding="utf-8",
        )
        (proj / "tests" / "test_calc_cli.py").write_text(
            "import json\n"
            "from src_pkg.calc import compute_summary\n"
            "from src_pkg.cli import main\n\n\n"
            "def test_summary_cli_roundtrip(capsys) -> None:\n"
            "    assert compute_summary([2.0, 4.0])['avg'] == 3.0\n"
            "    rc = main(['2', '4', '6'])\n"
            "    assert rc == 0\n"
            "    out = json.loads(capsys.readouterr().out)\n"
            "    assert out == {'avg': 4.0, 'count': 3.0, 'sum': 12.0}\n",
            encoding="utf-8",
        )
        reply = "D2 and D3 delivered: src_pkg/cli.py and tests/test_calc_cli.py integrated."

elif "CONCURRENT_TAG=" in prompt:
    m = re.search(r"CONCURRENT_TAG=([A-Za-z0-9_-]+)", prompt)
    tag = m.group(1) if m else "UNKNOWN"
    reply = f"Concurrent reply isolated for {tag}."

elif any(tok in prompt.upper() for tok in ("CONTROLBOT_OPS", "CONTROLBOT-OPS", "CONTROLBOT OPS")):
    reply = "Ops bot targeted reply: telemetry nominal."

elif "SIMPLE_CHAT_CHECK" in prompt:
    reply = "Simple chat reply verified for T4."

elif "deleting files" in prompt.lower() or "delete files" in prompt.lower():
    reply = "Resumed mock agy reply after approval."

if "--output-format" in args and "stream-json" in args:
    print(
        json.dumps(
            {
                "event": "init",
                "conversation_id": cid,
                "init": {"model": "gemini-4-carbon-low"},
            }
        ),
        flush=True,
    )
    print(
        json.dumps(
            {
                "event": "step_update",
                "step_update": {
                    "step_type": "agent_response",
                    "text_delta": reply,
                },
            }
        ),
        flush=True,
    )
    print(
        json.dumps(
            {
                "event": "result",
                "result": {
                    "status": "SUCCESS",
                    "conversation_id": cid,
                    "response": reply,
                },
            }
        ),
        flush=True,
    )
    sys.exit(0)

print(json.dumps({"status": "SUCCESS", "conversation_id": cid, "response": reply}))
""".replace("__CONV_ID__", _CONV_ID)


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
) -> AsyncIterator[Page]:
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


class _NoSignalUvicornServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        return None


@asynccontextmanager
async def _run_loopback_app(app: FastAPI) -> AsyncIterator[str]:
    port = alloc_qa_free_port()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(128)
    sock.setblocking(False)
    srv = _NoSignalUvicornServer(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            access_log=False,
            lifespan="on",
        )
    )
    task = asyncio.create_task(srv.serve(sockets=[sock]))
    try:
        deadline = asyncio.get_running_loop().time() + 10.0
        while not srv.started:
            if task.done():
                raise RuntimeError(f"Webhook sink exited early: {task.exception()!r}")
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("Timed out starting webhook sink")
            await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.should_exit = True
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await asyncio.wait_for(task, timeout=5.0)
        with contextlib.suppress(OSError):
            sock.close()


class _ControllableLabStack:
    """Loopback synthetic SCADA/Maint/EffectSim stack with mutable ScadaState."""

    def __init__(self, *, scada_fixture_mode: str = "auth_expired") -> None:
        self.scada_state = ScadaState(fixture_mode=scada_fixture_mode)
        self.scada_port: int = 0
        self.maintenance_port: int = 0
        self.effect_sim_port: int = 0
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._servers: list[_NoSignalUvicornServer] = []
        self._ready = threading.Event()
        self._error: BaseException | None = None

    @property
    def scada_url(self) -> str:
        return f"http://127.0.0.1:{self.scada_port}"

    @property
    def maintenance_url(self) -> str:
        return f"http://127.0.0.1:{self.maintenance_port}"

    @property
    def effect_sim_url(self) -> str:
        return f"http://127.0.0.1:{self.effect_sim_port}"

    def env_vars(self) -> dict[str, str]:
        return {
            "GROKBOT_SCADA_URL": self.scada_url,
            "GROKBOT_MAINTENANCE_URL": self.maintenance_url,
            "GROKBOT_EFFECT_SIM_URL": self.effect_sim_url,
        }

    def start(self, timeout: float = 10.0) -> _ControllableLabStack:
        self._ready.clear()
        self._error = None
        self._thread = threading.Thread(
            target=self._run_thread, daemon=True, name="qa-t4-controllable-lab"
        )
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            self.stop()
            raise TimeoutError("Timed out starting controllable lab stack.")
        if self._error is not None:
            err = self._error
            self.stop()
            raise RuntimeError(f"Controllable lab stack failed: {err!r}") from err
        return self

    def _run_thread(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._serve_all())
        except BaseException as exc:  # noqa: BLE001
            self._error = exc
            self._ready.set()
        finally:
            loop.close()

    async def _serve_all(self) -> None:
        now_ref = datetime.now(UTC)
        self.scada_state.set_reference_time(now_ref)
        scada_app = create_scada_app(state=self.scada_state)
        maint_app = create_maintenance_app(fixture_mode="default")
        maint_app.state.maintenance_state.set_reference_time(now_ref)
        effect_app = create_effect_sim_app()

        sockets: list[socket.socket] = []
        used_ports: set[int] = set()
        tasks: list[asyncio.Task[None]] = []
        try:
            for app in (scada_app, maint_app, effect_app):
                port = alloc_free_port("127.0.0.1", exclude=used_ports)
                used_ports.add(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
                sock.listen(128)
                sock.setblocking(False)
                sockets.append(sock)
                srv = _NoSignalUvicornServer(
                    uvicorn.Config(
                        app,
                        host="127.0.0.1",
                        port=port,
                        log_level="warning",
                        access_log=False,
                        lifespan="on",
                    )
                )
                self._servers.append(srv)
                tasks.append(asyncio.create_task(srv.serve(sockets=[sock])))

            for srv, task in zip(self._servers, tasks, strict=True):
                deadline = asyncio.get_running_loop().time() + 10.0
                while not srv.started:
                    if task.done():
                        raise RuntimeError(f"Lab server exited early: {task.exception()!r}")
                    if asyncio.get_running_loop().time() >= deadline:
                        raise TimeoutError("Timed out waiting for lab uvicorn server.")
                    await asyncio.sleep(0.01)

            self.scada_port = int(sockets[0].getsockname()[1])
            self.maintenance_port = int(sockets[1].getsockname()[1])
            self.effect_sim_port = int(sockets[2].getsockname()[1])
            self._ready.set()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for srv in reversed(self._servers):
                srv.should_exit = True
            for task in tasks:
                if not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
            for sock in sockets:
                with contextlib.suppress(OSError):
                    sock.close()

    def stop(self) -> None:
        loop = self._loop
        if loop is not None and not loop.is_closed():
            for srv in reversed(self._servers):
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(setattr, srv, "should_exit", True)
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self._thread = None
        self._servers.clear()


async def _poll_task_terminal(
    aclient: httpx.AsyncClient,
    run_id: str,
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        resp = await aclient.get(f"/api/tasks/{run_id}")
        assert resp.status_code == 200
        snap: dict[str, Any] = resp.json()
        if snap["run"]["status"] in {
            "succeeded",
            "partial",
            "failed",
            "cancelled",
            "waiting_for_input",
        }:
            return snap
        await asyncio.sleep(0.15)
    raise TimeoutError(f"Task {run_id} did not settle within {timeout}s")


def _iter_fixed_bytes(total_bytes: int, chunk_size: int = _MIB) -> Iterator[bytes]:
    full = b"X" * chunk_size
    rem = total_bytes
    while rem >= chunk_size:
        yield full
        rem -= chunk_size
    if rem > 0:
        yield b"X" * rem


def _snapshot_tree(root: Path) -> dict[str, tuple[int, int]]:
    if not root.exists():
        return {}
    return {
        str(p.relative_to(root)): (p.stat().st_mtime_ns, p.stat().st_size)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _git_head_sha(repo_dir: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _init_isolated_git_repo(
    repo_dir: Path,
    *,
    files: dict[str, str] | None = None,
    with_qa_branch: bool = False,
) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "qa-t4@example.local"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "QA Tier4"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    seed_files = files or {
        "app_mod.py": "def fn() -> int:\n    return 1\n",
        "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
    }
    for rel_path, content in seed_files.items():
        target = repo_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial isolated repo"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    if with_qa_branch:
        subprocess.run(
            ["git", "branch", "qa/autopilot"],
            cwd=str(repo_dir),
            check=True,
            capture_output=True,
        )
    return _git_head_sha(repo_dir)


def _create_candidate_branch(
    repo_dir: Path,
    branch_name: str,
    *,
    files: dict[str, str],
    base_ref: str = "main",
) -> str:
    subprocess.run(
        ["git", "checkout", "-B", branch_name, base_ref],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    for rel_path, content in files.items():
        target = repo_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", f"candidate {branch_name}"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return _git_head_sha(repo_dir)


def _seed_jsonl_to_size(path: Path, target_bytes: int) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    written = 0
    idx = 0
    while written < target_bytes:
        idx += 1
        base_obj = {"id": f"seed_{idx}", "source": "seed", "pad": ""}
        base_len = len((json.dumps(base_obj) + "\n").encode("utf-8"))
        remaining = target_bytes - written
        pad_len = min(900, max(0, remaining - base_len))
        obj = {"id": f"seed_{idx}", "source": "seed", "pad": "x" * pad_len}
        line = json.dumps(obj) + "\n"
        lines.append(line)
        written += len(line.encode("utf-8"))
    path.write_text("".join(lines), encoding="utf-8")
    return path.stat().st_size


def _query_sqlite_tables(camp_dir: Path, table_name: str) -> list[dict[str, Any]]:
    rows_out: list[dict[str, Any]] = []
    for db_file in sorted(camp_dir.glob("**/*.sqlite3")):
        with sqlite3.connect(db_file) as conn:
            conn.row_factory = sqlite3.Row
            tables = {
                str(r[0])
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if table_name not in tables:
                continue
            for raw_row in conn.execute(f"SELECT * FROM {table_name}").fetchall():
                row_dict = dict(raw_row)
                payload_raw = row_dict.get("payload_json")
                if isinstance(payload_raw, str) and payload_raw.strip():
                    parsed_payload = json.loads(payload_raw)
                    if isinstance(parsed_payload, dict):
                        row_dict = {**row_dict, **parsed_payload}
                for key, val in list(row_dict.items()):
                    if isinstance(val, str) and val.startswith(("[", "{")):
                        with contextlib.suppress(json.JSONDecodeError):
                            row_dict[key] = json.loads(val)
                rows_out.append(row_dict)
    return rows_out


def _run_baseline_to_dir(
    qa_cli_runner: QACliRunner,
    qa_env: IsolatedQAEnv,
    camp_dir: Path,
    *,
    lane: str = "local_deterministic",
    log_dir: Path | None = None,
    skip_browser: bool = True,
) -> dict[str, Any]:
    cmd = [
        "baseline",
        "--target-url",
        qa_env.base_url,
        "--output-dir",
        str(camp_dir),
        "--lane",
        lane,
        "--no-build-frontend",
    ]
    if skip_browser:
        cmd.append("--skip-browser")
    if log_dir is not None:
        cmd.extend(["--log-dir", str(log_dir)])
    res = qa_cli_runner.run(cmd)
    assert res.returncode == 0, f"baseline failed: {res.stderr}\n{res.stdout}"
    return dict(json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8")))


def _assert_no_cli_false_pass(res: CliResult) -> str:
    combined = (res.stdout + "\n" + res.stderr).lower()
    assert "notimplementederror" not in combined, (
        f"Hit unimplemented stub instead of real CLI behavior:\n{res.stdout}\n{res.stderr}"
    )
    assert "unrecognized arguments" not in combined, (
        f"CLI rejected valid arguments:\n{res.stdout}\n{res.stderr}"
    )
    assert "validationerror" not in combined, (
        f"Unexpected Pydantic ValidationError:\n{res.stdout}\n{res.stderr}"
    )
    assert "extra inputs are not permitted" not in combined, (
        f"Unexpected extra_forbidden schema error:\n{res.stdout}\n{res.stderr}"
    )
    assert "extra_forbidden" not in combined, (
        f"Unexpected extra_forbidden schema error:\n{res.stdout}\n{res.stderr}"
    )
    return combined


@contextlib.contextmanager
def _mock_repairer_server(
    *,
    patch_map: dict[str, tuple[str, str]],
    model_id: str = "mock-repairer-model",
) -> Iterator[dict[str, str]]:
    """Run a test-scoped loopback OpenAI-compatible mock LLM repairer server."""
    port = alloc_qa_free_port()

    class _MockLlmHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            payload = json.dumps({"data": [{"id": model_id}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
            files_out: dict[str, str] = {}
            for key, (rel_path, content) in patch_map.items():
                if key in raw_body or rel_path in raw_body:
                    files_out[rel_path] = content
            resp_obj = {
                "id": "chatcmpl-t4-mock",
                "object": "chat.completion",
                "model": model_id,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps({"files": files_out}),
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
            payload = json.dumps(resp_obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    httpd = _ThreadingServer(("127.0.0.1", port), _MockLlmHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "GROKBOT_LLM_BASE_URL": f"http://127.0.0.1:{port}",
            "GROKBOT_LLM_API_KEY": "mock-t4-api-key",
            "GROKBOT_LLM_MODEL_ID": model_id,
        }
    finally:
        httpd.shutdown()
        httpd.server_close()


def _extract_dist_asset_hashes(dist_dir: Path) -> dict[str, str]:
    index_html = dist_dir / "index.html"
    assert index_html.is_file(), f"Missing prebuilt {index_html}"
    html = index_html.read_text(encoding="utf-8")
    asset_paths = sorted(set(re.findall(r"/assets/[A-Za-z0-9_.-]+\.(?:js|css)", html)))
    hashes: dict[str, str] = {}
    for apath in asset_paths:
        disk_file = dist_dir / apath.lstrip("/")
        if disk_file.is_file():
            hashes[apath] = hashlib.sha256(disk_file.read_bytes()).hexdigest()
    return hashes


# ---------------------------------------------------------------------------
# Scenario 1 (qa_megaplan): QA-0 + QA-1 fresh campaign onboarding & React /app
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
async def test_t4_s01_qa0_qa1_fresh_campaign_onboarding_and_react_surface(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    strict_browser_page: StrictBrowserPage,
    tmp_path: Path,
) -> None:
    """Scenario 1 (Features #1,#2,#3,#4,#6,#9,#32,#33): Fresh QA-0/QA-1 onboarding & /app."""
    dry_make = qa_cli_runner.run_command(["make", "-n", "qa-baseline"])
    assert dry_make.returncode == 0, f"make -n qa-baseline failed: {dry_make.stderr}"
    assert "src.qa" in dry_make.stdout and "baseline" in dry_make.stdout

    camp_dir = tmp_path / "t4_s01_camp"
    res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--lane",
            "local_deterministic",
            "--no-build-frontend",
            "--json",
        ]
    )
    _assert_no_cli_false_pass(res)
    assert res.returncode == 0, f"baseline failed: {res.stderr}\n{res.stdout}"
    payload = res.json_stdout()
    assert payload["ok"] is True

    baseline_path = camp_dir / "baseline.json"
    baseline_md = camp_dir / "BASELINE.md"
    campaign_path = camp_dir / "campaign.json"
    assert baseline_path.is_file()
    assert baseline_md.is_file()
    assert campaign_path.is_file()

    report = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert report["served_surface"] == "react"
    assert report["surface_verified"] is True
    assert report["boot_errors"] == []
    assert report["functional_errors"] == []
    assert report["lane"] == "local_deterministic"
    assert report["emulated"] is True
    assert report["repo_sha"]
    assert report["backend_mode"] == "emulated"
    assert report["runtime_mode"] == "live_runtime"

    expected_hashes = _extract_dist_asset_hashes(_REPO_ROOT / "frontend" / "dist")
    assert expected_hashes
    for asset_path, digest in expected_hashes.items():
        assert report["asset_hashes"].get(asset_path) == digest

    assert_no_secret_leak(report, secrets=(qa_env.cap_secret,))
    assert_no_secret_leak(baseline_md.read_text(encoding="utf-8"), secrets=(qa_env.cap_secret,))

    surface = await assert_react_app_surface(qa_env.base_url, strict_browser_page)
    assert surface["title"] == "Grok Bot — ControlBot Studio"
    assert surface["data_theme"] == "light"
    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# Scenario 2 (qa_megaplan): Live-safe read-only supervision audit during scan
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_t4_s02_live_safe_readonly_supervision_audit_during_full_scan(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Scenario 2 (Features #10,#11,#34,#39): Live ports/DBs untouched during full scan."""
    live_dbs = sorted((_REPO_ROOT / "var").glob("controlbot*.sqlite3*"))
    before_stats = {
        p: (p.stat().st_mtime_ns, p.stat().st_size) for p in live_dbs if p.is_file()
    }

    # Verify mutating scan against live :8000 is refused before network calls
    refused_dir = tmp_path / "refuse_8000"
    refused_dir.mkdir(parents=True, exist_ok=True)
    live_repo = tmp_path / "dummy_repo"
    base_sha = _init_isolated_git_repo(live_repo)
    (refused_dir / "campaign.json").write_text(
        json.dumps(
            {
                "campaign_id": "qa-t4-refuse-8000",
                "base_sha": base_sha,
                "lane": "local_deterministic",
                "target_url": "http://127.0.0.1:8000",
                "status": "active",
                "output_dir": str(refused_dir),
            }
        ),
        encoding="utf-8",
    )
    refused_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(refused_dir), "--cases", "CB-00"]
    )
    refused_combined = _assert_no_cli_false_pass(refused_res)
    assert refused_res.returncode != 0
    assert any(tok in refused_combined for tok in ("forbidden", "live", "isolation", "port"))

    camp_dir = tmp_path / "t4_s02_camp"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )
    baseline_data = json.loads((camp_dir / "baseline.json").read_text(encoding="utf-8"))
    target_url = str(baseline_data.get("target_url") or "")
    for port in FORBIDDEN_PORTS:
        assert f":{port}" not in target_url

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-00",
            "--discover-controls",
            "--ingest-logs",
            "--json",
        ]
    )
    _assert_no_cli_false_pass(scan_res)
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    cov_path = camp_dir / "coverage.json"
    assert cov_path.is_file()
    cov = json.loads(cov_path.read_text(encoding="utf-8"))
    assert cov["total_controls"] > 0
    assert (
        cov["covered_count"]
        + cov["blocked_count"]
        + cov["pending_count"]
        + cov["out_of_scope_count"]
        == cov["total_controls"]
    )
    for item in cov["items"]:
        if item["coverage_status"] != "covered":
            assert str(item.get("blocked_reason") or "").strip()

    after_stats = {
        p: (p.stat().st_mtime_ns, p.stat().st_size) for p in live_dbs if p.is_file()
    }
    assert after_stats == before_stats, "Live var/controlbot*.sqlite3* was mutated!"


# ---------------------------------------------------------------------------
# Scenario 3 (qa_existing): CB-VALVE-104 dynamic catalog + Grok Bot ref card
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s03_cb02_valve_104_dynamic_catalog_update_and_grok_bot_card(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Scenario 3 (Features #7,#8,#14): Dynamic CB-VALVE-104 + update + Grok Bot card."""
    fixture = build_cb_valve_104_catalog()
    assert fixture.active_record.price != fixture.prior_record.price

    with _serve_valve_catalog(fixture) as (catalog_origin, state):
        catalog_port = urlparse(catalog_origin).port
        assert catalog_port is not None
        env = qa_env_factory(mock_agy_script=_T4_MOCK_AGY_SCRIPT, name="t4_s03_valve")
        with env.client() as client:
            assert (
                client.patch("/api/v1/apps/app_runtime", json={"enabled": False}).status_code
                == 200
            )

        page = strict_browser_page.page
        await page.goto(env.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")
        composer = page.locator('textarea[aria-label="Message composer"]')

        # 1. Current price query via React UI
        await composer.fill(
            f"{fixture.prompt_es} CATALOG_PORT={catalog_port} SKU={fixture.sku}"
        )
        await composer.press("Enter")
        cur_price = str(fixture.active_record.price)
        prior_price = str(fixture.prior_record.price)
        await page.get_by_text(
            f"{fixture.sku}: {fixture.active_record.currency} {cur_price}"
        ).wait_for(state="visible", timeout=15000)

        with env.client() as client:
            msgs1 = client.get("/api/v1/threads/thr_bot_chief/messages").json()["messages"]
            bot_reply_1 = str(
                next(m for m in reversed(msgs1) if m["sender_type"] == "bot")["content"]
            )
            assert cur_price in bot_reply_1
            assert fixture.active_record.currency in bot_reply_1
            assert fixture.active_record.source_url in bot_reply_1
            assert prior_price not in bot_reply_1

        # 2. Live price update reflected on re-query
        new_price = (fixture.active_record.price + Decimal("19.45")).quantize(Decimal("0.01"))
        updated = fixture.apply_price_update(new_price, effective_date="2026-11-30")
        state.update(updated)
        await composer.fill(
            f"Re-check price update CATALOG_PORT={catalog_port} SKU={updated.sku}"
        )
        await composer.press("Enter")
        upd_price = str(updated.active_record.price)
        await page.get_by_text(
            f"{updated.sku}: {updated.active_record.currency} {upd_price}"
        ).wait_for(state="visible", timeout=15000)

        with env.client() as client:
            msgs2 = client.get("/api/v1/threads/thr_bot_chief/messages").json()["messages"]
            bot_reply_2 = str(
                next(m for m in reversed(msgs2) if m["sender_type"] == "bot")["content"]
            )
            assert upd_price in bot_reply_2
            assert cur_price not in bot_reply_2

        # 3. Nonexistent SKU abstention (zero fabricated decimal/currency prices)
        await composer.fill(
            f"Check price CATALOG_PORT={catalog_port} MISSING_SKU={fixture.nonexistent_sku}"
        )
        await composer.press("Enter")
        await page.get_by_text(
            f"Not found in catalog: {fixture.nonexistent_sku} does not exist."
        ).wait_for(state="visible", timeout=15000)

        # 4. Ambiguous match returns both variants
        await composer.fill(
            f"Check price CATALOG_PORT={catalog_port} AMBIGUOUS_QUERY={fixture.ambiguous_query}"
        )
        await composer.press("Enter")
        match_a, match_b = fixture.ambiguous_matches
        await page.get_by_text(re.compile(re.escape(match_a.sku))).wait_for(
            state="visible", timeout=15000
        )
        with env.client() as client:
            msgs4 = client.get("/api/v1/threads/thr_bot_chief/messages").json()["messages"]
            ambig_reply = str(
                next(m for m in reversed(msgs4) if m["sender_type"] == "bot")["content"]
            )
            assert match_a.sku in ambig_reply and match_b.sku in ambig_reply
            assert str(match_a.price) in ambig_reply and str(match_b.price) in ambig_reply

    # 5. Grok Bot reference card boundary (main/test ONLY + REF_UNAVAILABLE + truth override)
    main_card = build_grok_bot_reference_card(bot_name="main", case_id="CB-02")
    assert main_card.bot_used == "main"
    assert main_card.status == "observed"
    for dim in (
        main_card.discoverability,
        main_card.state_transition,
        main_card.independent_verification,
        main_card.missing_data_or_permission,
        main_card.efficiency_notes,
    ):
        assert dim.strip()

    test_unavail = build_grok_bot_reference_card(
        bot_name="test",
        case_id="CB-02",
        available=False,
        unavailable_reason="Headless lab session without Grok Bot UI",
    )
    assert test_unavail.bot_used == "test"
    assert test_unavail.status == "REF_UNAVAILABLE"

    for forbidden_bot in ("work", "prod", "other", "admin", ""):
        with pytest.raises(ValueError):
            build_grok_bot_reference_card(bot_name=forbidden_bot, case_id="CB-02")

    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# Scenario 4 (qa_existing): CB-03 cancel snapshot diff & SSE reconnect
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s04_cb03_active_turn_cancel_snapshot_and_sse_reconnect(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Scenario 4 (Features #12,#13,#15,#26): Cancel stops writes & SSE reconnect replays."""
    env = qa_env_factory(mock_agy_script=_T4_MOCK_AGY_SCRIPT, name="t4_s04_cancel")
    marker_path = env.projects_root / "Grokbotclon" / "t4_post_cancel_marker.txt"
    snap_before = _snapshot_tree(env.projects_root)

    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    composer = page.locator('textarea[aria-label="Message composer"]')

    # 1. Measure TTFP & cancel slow probe before workspace write
    async def _send_and_cancel() -> bool:
        await composer.fill(f"CANCEL_SLEEP_PROBE MARKER={marker_path}")
        await composer.press("Enter")
        stop_btn = page.locator('button[aria-label="Stop current generation"]')
        await stop_btn.wait_for(state="visible", timeout=10000)
        await page.get_by_text("Starting slow workspace task...").wait_for(
            state="visible", timeout=10000
        )
        await stop_btn.click()
        await page.locator('button[aria-label="Send message"]').wait_for(
            state="visible", timeout=10000
        )
        return True

    async def _probe_stop() -> bool:
        return await page.locator('button[aria-label="Stop current generation"]').is_visible()

    ok, timing = await measure_ttfp_and_completion(
        _send_and_cancel,
        actions_to_reach=1,
        ttfp_probe=_probe_stop,
        cancel_available=True,
    )
    assert ok is True
    assert isinstance(timing, UxTimingResult)
    assert timing.ttfp_ms is not None and timing.ttfp_ms <= timing.completion_ms

    await asyncio.sleep(4.0)
    assert not marker_path.exists()
    assert _snapshot_tree(env.projects_root) == snap_before

    # 2. SSE Last-Event-ID replay (both evt_<seq>_<epoch> and <epoch>:<seq>) + resync
    async with env.async_client() as client:
        msgs = (await client.get("/api/v1/threads/thr_bot_chief/messages")).json()["messages"]
        bot_msgs = [m for m in msgs if m["sender_type"] == "bot"]
        assert bot_msgs and bot_msgs[-1]["status"] == "interrupted"
        msg_id = str(msgs[0]["id"])

        frames: list[SseFrame] = []
        connected = asyncio.Event()

        async def _collect_two() -> None:
            async for frame in iter_sse_events(client, timeout=10.0, on_connected=connected):
                if frame.event_type == "message.reaction":
                    frames.append(frame)
                    if len(frames) >= 2:
                        return

        task = asyncio.create_task(_collect_two())
        try:
            await asyncio.wait_for(connected.wait(), timeout=5.0)
            for emoji in ("👍", "🔥"):
                assert (
                    await client.post(
                        f"/api/v1/messages/{msg_id}/reactions",
                        json={"emoji": emoji, "action": "add"},
                    )
                ).status_code == 200
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

        assert (
            await client.post(
                f"/api/v1/messages/{msg_id}/reactions",
                json={"emoji": "✅", "action": "add"},
            )
        ).status_code == 200

        async def _replay(
            *, headers: dict[str, str] | None = None, query: str = ""
        ) -> list[SseFrame]:
            out: list[SseFrame] = []
            async for frame in iter_sse_events(
                client,
                url=f"/api/v1/events/stream{query}",
                headers=headers,
                timeout=4.0,
            ):
                out.append(frame)
                if (
                    frame.event_type == "message.reaction"
                    and isinstance(frame.data, dict)
                    and frame.data.get("payload", {}).get("emoji") == "✅"
                ):
                    break
            return out

        for batch in (
            await _replay(headers={"Last-Event-ID": anchor_id}),
            await _replay(query=f"?last_event_id={colon_cursor}"),
        ):
            assert all(f.event_type != "stream.resync" for f in batch)
            emojis = [
                f.data.get("payload", {}).get("emoji")
                for f in batch
                if f.event_type == "message.reaction" and isinstance(f.data, dict)
            ]
            assert emojis == ["🔥", "✅"]
            ids = [f.id for f in batch if f.id]
            assert len(ids) == len(set(ids))

        for bad_cursor, expected_reason in (
            ("oldepoch:1", "epoch_mismatch"),
            ("invalid_cursor_token", "invalid_cursor"),
        ):
            bad_frames: list[SseFrame] = []
            async for frame in iter_sse_events(
                client, headers={"Last-Event-ID": bad_cursor}, timeout=3.0
            ):
                bad_frames.append(frame)
                if frame.event_type == "stream.resync":
                    break
            assert bad_frames and bad_frames[0].event_type == "stream.resync"
            if isinstance(bad_frames[0].data, dict):
                assert bad_frames[0].data["payload"]["reason"] == expected_reason

    await composer.fill("SIMPLE_CHAT_CHECK post-cancel verification")
    await composer.press("Enter")
    await page.get_by_text("Simple chat reply verified for T4.").wait_for(
        state="visible", timeout=15000
    )

    await page.reload(wait_until="networkidle")
    await page.get_by_text("Simple chat reply verified for T4.").wait_for(state="visible")
    assert await page.get_by_text(f"CANCEL_SLEEP_PROBE MARKER={marker_path}").count() == 1
    assert await page.get_by_text("Simple chat reply verified for T4.").count() == 1
    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# Scenario 5 (qa_existing): CB-04 sections, hidden bots drawer, @mention
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s05_cb04_multi_bot_sections_hidden_drawer_and_group_mention(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Scenario 5 (Feature #16): Sections, hidden drawer, group @mention & boundary errors."""
    env = qa_env_factory(mock_agy_script=_T4_MOCK_AGY_SCRIPT, name="t4_s05_roster")
    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    sidebar = page.locator("aside")
    composer = page.locator('textarea[aria-label="Message composer"]')

    # Create section & bot
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New section").click()
    sec_input = page.locator('input[placeholder="Section name, press Enter…"]')
    await sec_input.fill("T4 Ops Section")
    await sec_input.press("Enter")
    await sidebar.get_by_text("T4 Ops Section").wait_for(state="visible")

    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.locator("button").filter(has_text=re.compile(r"^New bot")).click()
    await page.locator("#new-bot-name").fill("T4 Watcher")
    await page.get_by_role("button", name="Create bot").click()
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message T4 Watcher'"
    )

    with env.client() as client:
        bots = client.get("/api/v1/bots").json()["bots"]
        watcher = next(b for b in bots if b["name"] == "T4 Watcher")
        assert (
            client.patch(
                f"/api/v1/bots/{watcher['id']}", json={"name": "T4 Auditor"}
            ).status_code
            == 200
        )

    await page.reload(wait_until="networkidle")
    await sidebar.get_by_text("T4 Ops Section").wait_for(state="visible")
    await sidebar.get_by_text("T4 Auditor").wait_for(state="visible")

    # Hide & unhide via Hidden bots drawer
    bot_row = sidebar.locator("div.group").filter(has_text="T4 Auditor").first
    await bot_row.hover()
    await page.locator('button[aria-label="More options for T4 Auditor"]').click()
    await page.get_by_role("button", name="Hide from sidebar").click()
    await sidebar.get_by_text("T4 Auditor").wait_for(state="hidden")

    await sidebar.get_by_role("button", name="Hidden bots").click()
    drawer = page.get_by_role("dialog")
    await drawer.get_by_text("T4 Auditor").wait_for(state="visible")
    await drawer.get_by_role("button", name="Unhide").click()
    await page.keyboard.press("Escape")
    await drawer.wait_for(state="hidden")
    await sidebar.get_by_text("T4 Auditor").wait_for(state="visible")

    # Zero cross-thread bleed between Chief of Staff & ControlBot Ops
    await sidebar.get_by_text("Chief of Staff").click()
    secret_marker = "SIMPLE_CHAT_CHECK T4_CHIEF_SECRET_MARKER"
    await composer.fill(secret_marker)
    await composer.press("Enter")
    await page.get_by_text("Simple chat reply verified for T4.").wait_for(
        state="visible", timeout=15000
    )

    await sidebar.get_by_text("ControlBot Ops").click()
    assert await composer.get_attribute("placeholder") == "Message ControlBot Ops"
    assert await page.get_by_text("T4_CHIEF_SECRET_MARKER").count() == 0

    # Create 2-bot group channel & target @ControlBot Ops
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New group chat").click()
    dlg = page.get_by_role("dialog")
    await dlg.locator("#new-channel-name").fill("T4 Sync")
    await dlg.get_by_role("button", name="Chief of Staff").click()
    await dlg.get_by_role("button", name="ControlBot Ops").click()
    await dlg.get_by_role("button", name="Create group chat").click()
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message #T4 Sync (use @ to mention bots)'"
    )

    await composer.click()
    await composer.type("@")
    mention_hdr = page.get_by_text("Mention", exact=True)
    await mention_hdr.wait_for(state="visible")
    await mention_hdr.locator("xpath=..").locator("button").filter(
        has_text="ControlBot Ops"
    ).click()
    await composer.type("check status")
    await composer.press("Enter")
    await page.get_by_text("Ops bot targeted reply: telemetry nominal.").wait_for(
        state="visible", timeout=15000
    )

    with env.client() as client:
        channels = client.get("/api/v1/bots").json()["channels"]
        ch = next(c for c in channels if c["name"] == "T4 Sync")
        ch_msgs = client.get(f"/api/v1/threads/{ch['thread_id']}/messages").json()["messages"]
        bot_msgs = [m for m in ch_msgs if m["sender_type"] == "bot"]
        assert len(bot_msgs) == 1
        assert bot_msgs[0]["sender_bot_id"] == "bot_ops"

        # 7-bot channel -> 422; ghost channel -> 409
        extra_ids = [
            str(client.post("/api/v1/bots", json={"name": f"Overflow {i}"}).json()["id"])
            for i in range(5)
        ]
        assert (
            client.post(
                "/api/v1/channels",
                json={"name": "TooMany", "bot_ids": ["bot_chief", "bot_ops", *extra_ids]},
            ).status_code
            == 422
        )
        g1 = str(client.post("/api/v1/bots", json={"name": "GhostA"}).json()["id"])
        g2 = str(client.post("/api/v1/bots", json={"name": "GhostB"}).json()["id"])
        ghost_ch = client.post(
            "/api/v1/channels", json={"name": "GhostCh", "bot_ids": [g1, g2]}
        ).json()
        assert client.delete(f"/api/v1/bots/{g1}").status_code == 200
        assert client.delete(f"/api/v1/bots/{g2}").status_code == 200
        assert (
            client.post(
                f"/api/v1/threads/{ghost_ch['thread_id']}/messages",
                json={"content": "hello"},
            ).status_code
            == 409
        )

    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# Scenario 6 (qa_existing): CB-05 document, page versioning, XSS, isolation
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s06_cb05_document_artifact_lifecycle_xss_and_isolation(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
    tmp_path: Path,
) -> None:
    """Scenario 6 (Feature #17): Attachments, active-MIME XSS, Page versioning, isolation."""
    bound_bytes = b"T4 specification attachment parity\nline 2\n"
    with qa_env.client() as client:
        up_spec = client.post(
            "/api/v1/attachments",
            params={"filename": "spec.txt"},
            headers={"Content-Type": "text/plain"},
            content=bound_bytes,
        )
        assert up_spec.status_code == 201
        spec_id = str(up_spec.json()["id"])
        dl_spec = client.get(f"/api/v1/attachments/{spec_id}")
        assert dl_spec.status_code == 200
        assert dl_spec.content == bound_bytes
        assert dl_spec.headers.get("X-Content-Type-Options") == "nosniff"

        for fname, mime, payload in (
            ("xss.html", "text/html", b"<html><script>alert(1)</script></html>"),
            ("vec.svg", "image/svg+xml", b"<svg onload='alert(1)'></svg>"),
            ("evil.js", "application/javascript", b"alert('xss');"),
        ):
            up_xss = client.post(
                "/api/v1/attachments",
                params={"filename": fname},
                headers={"Content-Type": mime},
                content=payload,
            )
            assert up_xss.status_code == 201
            dl_xss = client.get(f"/api/v1/attachments/{up_xss.json()['id']}")
            assert dl_xss.status_code == 200
            assert dl_xss.headers.get("X-Content-Type-Options") == "nosniff"
            assert dl_xss.headers.get("Content-Security-Policy") == "sandbox; default-src 'none'"
            assert dl_xss.headers.get("Content-Disposition", "").startswith("attachment;")

    page = strict_browser_page.page
    await page.goto(qa_env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    async with page.expect_response(
        lambda r: r.url.endswith("/api/v1/pages") and r.request.method == "POST"
    ) as create_info:
        await page.locator('button[title="Create new interactive page"]').click()
    create_resp = await create_info.value
    assert create_resp.status == 201
    created_page = await create_resp.json()
    page_id = str(created_page["id"])
    page_title = str(created_page["title"])
    v1 = int(created_page["version"])

    split_page = page.locator(".gb-printable-page")
    await split_page.wait_for(state="visible")
    await split_page.get_by_role("button", name="Edit").click()
    await split_page.locator("textarea").fill(
        f"# T4 Valve Spec\n\nVerify **seal** integrity and seal torque. Ref {spec_id}"
    )
    await split_page.get_by_role("button", name="Save changes").click()
    await split_page.get_by_role("heading", name="T4 Valve Spec").wait_for(state="visible")

    with qa_env.client() as client:
        page_after = client.get(f"/api/v1/pages/{page_id}").json()
        assert int(page_after["version"]) > v1

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
    exported = tmp_path / dl.suggested_filename
    await dl.save_as(exported)
    assert "Verify **seal** integrity" in exported.read_text(encoding="utf-8")

    await page.reload(wait_until="networkidle")
    await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
    await page.get_by_role("tab", name="Library").click()
    await page.get_by_role("button", name="Pinned", exact=True).click()
    await page.get_by_text(page_title).wait_for(state="visible")
    strict_browser_page.assert_clean()

    # Cross-thread isolation + artifact delete emits SSE while preserving bound attachment
    async with qa_env.async_client() as aclient:
        ops_lib = (await aclient.get("/api/v1/bots/bot_ops/library")).json()["items"]
        assert all(item["id"] != page_id for item in ops_lib)

        del_events: list[SseFrame] = []
        connected = asyncio.Event()

        async def _listen_del() -> None:
            async for frame in iter_sse_events(aclient, timeout=8.0, on_connected=connected):
                if (frame.event_type or frame.event) == "artifact.deleted":
                    del_events.append(frame)
                    return

        task = asyncio.create_task(_listen_del())
        try:
            await asyncio.wait_for(connected.wait(), timeout=5.0)
            assert (await aclient.delete(f"/api/v1/artifacts/{page_id}")).status_code == 200
            await asyncio.wait_for(task, timeout=8.0)
        finally:
            if not task.done():
                task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

        assert del_events
        assert (await aclient.get(f"/api/v1/pages/{page_id}")).status_code == 404
        dl_surv = await aclient.get(f"/api/v1/attachments/{spec_id}")
        assert dl_surv.status_code == 200
        assert dl_surv.content == bound_bytes


# ---------------------------------------------------------------------------
# Scenario 7 (qa_existing): CB-06 HITL computer takeover, RFB gate, PTY & files
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s07_cb06_hitl_computer_takeover_rfb_gate_pty_and_handback(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Scenario 7 (Feature #18): vnc-token, human takeover RFB gate, 409 lock, PTY, handback."""
    env = qa_env_factory(with_mock_rfb=True, name="t4_s07_comp")
    assert env.mock_rfb is not None
    mock_rfb = env.mock_rfb

    with env.client() as client:
        status_resp = client.get("/api/v1/computers/default/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["control_owner"] == "agent"
        tok = mint_cap_token(client, vm_id="default")

    ws_vnc_url = f"{env.ws_base_url}{tok['ws_vnc_url']}"
    fb_req = struct.pack("!BBHHHH", 3, 1, 0, 0, 640, 480)
    key_ev = struct.pack("!BBHI", 4, 1, 0, 0x0061)
    ptr_ev = struct.pack("!BBHH", 5, 1, 120, 240)
    cut_text = struct.pack("!B3xI", 6, 5) + b"hello"

    async with (
        websockets.connect(ws_vnc_url, subprotocols=[Subprotocol("binary")]) as ws,
        _vnc_safe_browser_page(strict_browser_page) as page,
    ):
        reader = await _complete_client_rfb_none_handshake(ws)
        await ws.send(fb_req + key_ev + ptr_ev + cut_text)
        assert await reader.read_exact(4) == b"\x00\x00\x00\x00"
        await asyncio.sleep(0.15)
        assert mock_rfb.wait_for_messages(min_count=1, timeout=2.0) == [0x03]
        assert mock_rfb.received_message_types == [0x03]

        await page.goto(env.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")
        await page.locator('button[title="Open Bot Computer"]').click()
        await page.locator("canvas").first.wait_for(state="visible", timeout=10000)
        await page.get_by_text("Starting display").wait_for(state="hidden", timeout=10000)
        assert mock_rfb.handshakes_completed >= 1

        await page.get_by_role("button", name="Take control").click()
        dlg = page.locator('[role="dialog"][aria-label="Full-screen computer view"]')
        await dlg.wait_for(state="visible")
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
            assert (
                client.post(
                    "/api/v1/computers/default/actions",
                    json={"type": "start", "url": env.url("/health"), "actor": "agent"},
                ).status_code
                == 409
            )

        mock_rfb.reset_records()
        await ws.send(key_ev + ptr_ev + cut_text)
        deadline_rfb = time.monotonic() + 3.0
        while time.monotonic() < deadline_rfb:
            gated_msgs = [m for m in mock_rfb.received_messages if m[0] in {0x04, 0x05, 0x06}]
            if len(gated_msgs) >= 3:
                break
            await asyncio.sleep(0.05)
        assert [m for m in mock_rfb.received_messages if m[0] in {0x04, 0x05, 0x06}] == [
            (0x04, key_ev),
            (0x05, ptr_ev),
            (0x06, cut_text),
        ]

        await dlg.get_by_role("button", name="I'm done").click()
        await dlg.wait_for(state="hidden")
        await page.get_by_text("Control returned to your Bot").wait_for(state="visible")

        with env.client() as client:
            assert (
                client.post(
                    "/api/v1/computers/default/actions",
                    json={"type": "start", "url": env.url("/health"), "actor": "agent"},
                ).status_code
                == 200
            )
            assert (
                client.post(
                    "/api/v1/computers/default/actions",
                    json={"type": "stop", "actor": "agent"},
                ).status_code
                == 200
            )

        mock_rfb.reset_records()
        await ws.send(fb_req + key_ev + ptr_ev + cut_text)
        assert await reader.read_exact(4) == b"\x00\x00\x00\x00"
        await asyncio.sleep(0.15)
        assert [m for m in mock_rfb.received_message_types if m != 0x03] == []
        assert 0x03 in mock_rfb.received_message_types

        # Terminal PTY command
        await page.get_by_role("button", name="Terminal", exact=True).click()
        await page.locator('span[title="connected"]').wait_for(state="visible", timeout=10000)
        await page.locator(".xterm-helper-textarea").focus()
        await page.keyboard.type("echo QA_T4_PTY_OK")
        await page.keyboard.press("Enter")
        await page.wait_for_function(
            "() => (document.querySelector('.xterm-rows')?.innerText || '')"
            ".includes('QA_T4_PTY_OK')",
            timeout=10000,
        )

        # Files tab create/delete + API ../ traversal 403
        await page.get_by_role("button", name="Files", exact=True).click()
        await page.get_by_role("button", name="New file", exact=True).click()
        await page.locator('input[placeholder="notes.md"]').fill("t4_note.txt")
        await page.locator('textarea[placeholder="File content…"]').fill("t4_workspace_ok")
        await page.get_by_role("button", name="Create file").click()
        await page.get_by_role("button", name="t4_note.txt", exact=True).wait_for(state="visible")
        file_row = page.locator("div.group").filter(has_text="t4_note.txt").first
        await file_row.hover()
        await page.locator('button[aria-label="Delete t4_note.txt"]').click()
        await file_row.wait_for(state="hidden")

    with env.client() as client:
        assert (
            client.get(
                "/api/v1/computers/default/file", params={"path": "../../etc/passwd"}
            ).status_code
            == 403
        )

    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# Scenario 8 (qa_existing): CB-07 approvals, effect_sim & HMAC webhook draft
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s08_cb07_effect_sim_approval_deny_allow_replay_and_hmac_draft(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Scenario 8 (Feature #19): Deny=0, Allow=1, 409 conflict, fail_after_apply & HMAC."""
    received: list[dict[str, Any]] = []
    wh_app = FastAPI()

    @wh_app.post("/hook")
    async def receive_hook(request: Request) -> JSONResponse:
        raw_body = await request.body()
        received.append(
            {
                "signature": request.headers.get("x-controlbot-signature", ""),
                "raw": raw_body,
                "json": json.loads(raw_body.decode("utf-8")),
            }
        )
        return JSONResponse({"ok": True})

    env = qa_env_factory(
        with_lab=True,
        mock_agy_script=_T4_MOCK_AGY_SCRIPT,
        extra_env={"GROKBOT_ALLOW_LOOPBACK_WEBHOOKS": "1"},
        name="t4_s08_cb07",
    )
    assert env.lab_stack is not None
    effect_url = env.lab_stack.effect_sim_url

    async with _run_loopback_app(wh_app) as wh_origin:
        page = strict_browser_page.page
        await page.goto(env.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")
        composer = page.locator('textarea[aria-label="Message composer"]')

        # 1. Deny -> 0 effects
        await composer.fill("/approval Flush bypass valve")
        await composer.press("Enter")
        deny_card = page.locator("div.my-2\\.5").filter(has_text="Flush bypass valve").first
        await deny_card.get_by_text("Needs approval").wait_for(state="visible")
        await deny_card.get_by_role("button", name="Deny").click()
        await deny_card.get_by_text("Denied").wait_for(state="visible")

        with httpx.Client(timeout=10.0) as lab_client:
            assert lab_client.get(f"{effect_url}/api/effects/state").json()["total_applied"] == 0

        # 2. Allow ask_first -> resumed reply
        await composer.fill("Please delete files in temp workspace")
        await composer.press("Enter")
        ask_card = page.locator("div.my-2\\.5").filter(
            has_text="Ask before deleting files"
        ).first
        await ask_card.get_by_text("Needs approval").wait_for(state="visible")
        await ask_card.get_by_role("button", name="Allow", exact=True).click()
        await ask_card.get_by_text("Allowed once").wait_for(state="visible")
        await page.get_by_text("Resumed mock agy reply after approval.").wait_for(
            state="visible", timeout=10000
        )

        # 3. EffectSim idempotency, replay, 409 conflict & fail_after_apply recovery
        async with env.async_client(timeout=35.0) as aclient:
            r1 = await aclient.post(
                "/api/tasks",
                json={
                    "query": "Apply effect operation_key=t4-op-1 reset_latch on bomba-34-a1",
                    "facility_id": "facility-a",
                    "allowed_areas": ["area-1"],
                    "allowed_tools": ["effect.apply", "effect.inspect_state"],
                    "read_only": False,
                },
            )
            assert r1.status_code == 201
            snap1 = await _poll_task_terminal(aclient, str(r1.json()["run_id"]))
            assert snap1["run"]["status"] == "succeeded"

            st1 = (await aclient.get(f"{effect_url}/api/effects/state")).json()
            assert st1["total_applied"] == 1
            eff0 = st1["effects"][0]
            idem_key = str(eff0["idempotency_key"])

            rep = await aclient.post(
                f"{effect_url}/api/effects/apply",
                json={
                    "idempotency_key": idem_key,
                    "asset_id": eff0["asset_id"],
                    "action": eff0["action"],
                    "params": eff0["params"],
                },
            )
            assert rep.status_code == 200
            assert rep.json()["deduplicated"] is True

            conflict = await aclient.post(
                f"{effect_url}/api/effects/apply",
                json={
                    "idempotency_key": idem_key,
                    "asset_id": eff0["asset_id"],
                    "action": "trip_breaker",
                    "params": {"mode": "unsafe"},
                },
            )
            assert conflict.status_code == 409
            assert (await aclient.get(f"{effect_url}/api/effects/state")).json()[
                "total_applied"
            ] == 1

            r2 = await aclient.post(
                "/api/tasks",
                json={
                    "query": (
                        "Apply effect operation_key=t4-op-2 "
                        "fail_after_apply=true reset_latch on bomba-34-a1"
                    ),
                    "facility_id": "facility-a",
                    "allowed_areas": ["area-1"],
                    "allowed_tools": ["effect.apply", "effect.inspect_state"],
                    "read_only": False,
                },
            )
            assert r2.status_code == 201
            await _poll_task_terminal(aclient, str(r2.json()["run_id"]))
            assert (await aclient.get(f"{effect_url}/api/effects/state")).json()[
                "total_applied"
            ] == 2

            # 4. Signed HMAC webhook draft edited & delivered via UI
            draft_resp = await aclient.post(
                "/api/v1/drafts",
                json={
                    "bot_id": "bot_chief",
                    "thread_id": "thr_bot_chief",
                    "channel_type": "webhook",
                    "fields": {
                        "webhook_url": f"{wh_origin}/hook",
                        "webhook_secret": "t4-hmac-secret",
                        "subject": "T4 Valve Alert",
                        "body": "Initial body",
                    },
                },
            )
            assert draft_resp.status_code == 201
            draft_id = str(draft_resp.json()["id"])

        draft_card = page.locator("div.my-2\\.5").filter(
            has_text=re.compile(r"webhook draft", re.I)
        ).first
        await draft_card.get_by_text("Needs approval").wait_for(state="visible", timeout=10000)
        await draft_card.get_by_label("Body").fill("Verified T4 HMAC payload")
        await draft_card.get_by_role("button", name="Send").click()
        await draft_card.get_by_text("Sent").wait_for(state="visible", timeout=10000)

        assert len(received) == 1
        expected_sig = (
            "sha256="
            + hmac.new(b"t4-hmac-secret", received[0]["raw"], hashlib.sha256).hexdigest()
        )
        assert received[0]["signature"] == expected_sig
        assert received[0]["json"]["draft_id"] == draft_id
        assert received[0]["json"]["fields"]["body"] == "Verified T4 HMAC payload"
        assert_no_secret_leak(received[0]["json"], secrets=("t4-hmac-secret",))

    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# Scenario 9 (qa_existing): CB-08 settings, 5-scope memory & scheduled routine
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s09_cb08_enterprise_governance_settings_5scope_memory_and_routine(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Scenario 9 (Feature #20): Settings reload, 5-scope memory, redaction, 409 UI & routine."""
    env = qa_env_factory(mock_agy_script=_T4_MOCK_AGY_SCRIPT, name="t4_s09_gov")
    canary_secret = "sk-qa-t4-cb08-secret-445566"
    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    sidebar = page.locator("aside")

    # 1. Settings reload persistence
    await sidebar.get_by_role("button", name="Settings").click()
    dlg = page.get_by_role("dialog")
    await dlg.get_by_role("button", name="Dark", exact=True).click()
    await dlg.get_by_label("Display name").fill("T4 Governance Lead")
    await dlg.get_by_label("Default thinking level").select_option("high")
    await page.keyboard.press("Escape")
    await dlg.wait_for(state="hidden")

    await page.reload(wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    assert await page.evaluate("document.documentElement.getAttribute('data-theme')") == "dark"
    await sidebar.get_by_role("button", name="Settings").click()
    dlg = page.get_by_role("dialog")
    assert await dlg.get_by_label("Display name").input_value() == "T4 Governance Lead"
    assert await dlg.get_by_label("Default thinking level").input_value() == "high"
    await dlg.get_by_role("button", name="Light", exact=True).click()
    await page.keyboard.press("Escape")
    await dlg.wait_for(state="hidden")

    # 2. 5-scope memory isolation, Manager-only approved_procedure, redaction & FTS purge
    with env.client() as client:
        r_user = client.post(
            "/api/v1/memory",
            headers={"X-User-Id": "t4_user_a"},
            json={
                "scope": "user",
                "scope_id": "t4_user_a",
                "kind": "preference",
                "title": "T4 User Secret",
                "content": f"Token: {canary_secret}",
            },
        )
        assert r_user.status_code == 201
        user_mem_id = str(r_user.json()["id"])

        assert (
            client.post(
                "/api/v1/memory",
                headers={"X-Agent-Role": "t4_role_a"},
                json={
                    "scope": "agent_role",
                    "scope_id": "t4_role_a",
                    "kind": "preference",
                    "title": "Role Note",
                    "content": "Check gauges",
                },
            ).status_code
            == 201
        )
        assert (
            client.post(
                "/api/v1/memory",
                headers={"X-Thread-Id": "thr_t4_a"},
                json={
                    "scope": "thread",
                    "scope_id": "thr_t4_a",
                    "kind": "dated_observation",
                    "title": "Thread Note",
                    "content": "Observed pressure drop",
                    "observed_at": "2026-11-27T00:00:00Z",
                    "valid_until": "2026-12-31T23:59:59Z",
                },
            ).status_code
            == 201
        )
        assert (
            client.post(
                "/api/v1/memory",
                headers={"X-Project-Area": "area_t4_a"},
                json={
                    "scope": "project_area",
                    "scope_id": "area_t4_a",
                    "kind": "source_reference",
                    "title": "Area Rule",
                    "content": "Max 3600 RPM",
                },
            ).status_code
            == 201
        )

        # Operator cannot create approved_procedure (403); Manager succeeds (201)
        assert (
            client.post(
                "/api/v1/memory",
                headers={"X-Actor-Role": "Operator"},
                json={
                    "scope": "org_approved",
                    "scope_id": "org",
                    "kind": "approved_procedure",
                    "title": "Blocked SOP",
                    "content": "Denied",
                },
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/v1/memory",
                headers={"X-Actor-Role": "Manager"},
                json={
                    "scope": "org_approved",
                    "scope_id": "org",
                    "kind": "approved_procedure",
                    "title": "Approved Lockout",
                    "content": "Isolate breakers",
                },
            ).status_code
            == 201
        )

        # Cross-header isolation
        assert all(
            it["id"] != user_mem_id
            for it in client.get(
                "/api/v1/memory", params={"scope": "user"}, headers={"X-User-Id": "t4_user_b"}
            ).json()["items"]
        )
        assert (
            client.patch(
                f"/api/v1/memory/{user_mem_id}",
                headers={"X-User-Id": "t4_user_b"},
                json={"revision": 1, "content": "hijack"},
            ).status_code
            == 403
        )

        # Redacted export + FTS delete purge
        exp_json = client.get(
            "/api/v1/memory/export", params={"format": "json"}, headers={"X-User-Id": "t4_user_a"}
        )
        assert exp_json.status_code == 200
        assert_no_secret_leak(exp_json.json(), secrets=(canary_secret,))
        exp_md = client.get(
            "/api/v1/memory/export", params={"format": "md"}, headers={"X-User-Id": "t4_user_a"}
        )
        assert exp_md.status_code == 200
        assert_no_secret_leak(exp_md.text, secrets=(canary_secret,))

        assert (
            client.delete(
                f"/api/v1/memory/{user_mem_id}", headers={"X-User-Id": "t4_user_a"}
            ).status_code
            == 200
        )
        assert all(
            it["id"] != user_mem_id
            for it in client.get(
                "/api/v1/memory", params={"q": "T4 User Secret"}, headers={"X-User-Id": "t4_user_a"}
            ).json()["items"]
        )

    # UI MemoryModal stale revision 409 conflict
    await sidebar.get_by_role("button", name=re.compile(r"Memory", re.I)).click()
    mem_dlg = page.get_by_role("dialog")
    await mem_dlg.get_by_role("button", name="New memory").click()
    await mem_dlg.get_by_label("Title").fill("T4 Revision Race")
    await mem_dlg.get_by_label("Content").fill("v1")
    await mem_dlg.get_by_role("button", name="Save memory").click()
    await mem_dlg.get_by_text("T4 Revision Race").wait_for(state="visible")
    await mem_dlg.get_by_role("button", name="Edit T4 Revision Race").click()
    await mem_dlg.get_by_role("button", name="Save changes").wait_for(state="visible")

    with env.client() as client:
        target = next(
            it
            for it in client.get("/api/v1/memory").json()["items"]
            if it["title"] == "T4 Revision Race"
        )
        assert (
            client.patch(
                f"/api/v1/memory/{target['id']}",
                json={"revision": target["revision"], "content": "v2 server"},
            ).status_code
            == 200
        )

    await mem_dlg.get_by_label("Content").fill("v2 stale browser")
    await mem_dlg.get_by_role("button", name="Save changes").click()
    await mem_dlg.locator('[role="alert"]').get_by_text(
        re.compile(r"409|conflict|revision", re.I)
    ).wait_for(state="visible")
    await page.keyboard.press("Escape")
    await mem_dlg.wait_for(state="hidden")

    # 3. Routine test + webhook firing & RoutineRun history + UI inspector
    with env.client() as client:
        r_create = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "T4 Valve Sweep",
                "instruction": "Check valve telemetry",
                "schedule_type": "manual",
                "enabled": True,
            },
        )
        assert r_create.status_code == 201
        rid = str(r_create.json()["id"])
        wkey = str(r_create.json()["webhook_key"])

        assert client.post(f"/api/v1/routines/{rid}/test").status_code == 202
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{rid}",
                headers={"Authorization": "Bearer wrong-key"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                f"/api/v1/webhooks/routines/{rid}",
                headers={"Authorization": f"Bearer {wkey}"},
                json={"event": "t4_routine"},
            ).status_code
            == 202
        )

        deadline = asyncio.get_running_loop().time() + 10.0
        runs: list[dict[str, Any]] = []
        while asyncio.get_running_loop().time() < deadline:
            runs = client.get(f"/api/v1/routines/{rid}/runs").json()["runs"]
            if len(runs) >= 2 and all(r.get("status") != "running" for r in runs):
                break
            await asyncio.sleep(0.15)
        assert {"manual", "webhook"}.issubset({str(r.get("trigger")) for r in runs})

    await page.reload(wait_until="networkidle")
    await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
    await page.get_by_text("T4 Valve Sweep", exact=True).wait_for(state="visible")

    strict_browser_page.assert_clean(
        allow_http_statuses=[409],
        allow_console_substrings=["409 (Conflict)"],
    )


# ---------------------------------------------------------------------------
# Scenario 10 (qa_existing): CB-09 CSV -> JSON + independent edge evaluator
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s10_cb09_autonomous_csv_to_json_and_independent_evaluator(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
    tmp_path: Path,
) -> None:
    """Scenario 10 (Feature #21): CSV->JSON passes 4 adversarial samples & rejects naive."""
    env = qa_env_factory(mock_agy_script=_T4_MOCK_AGY_SCRIPT, name="t4_s10_cb09")
    with env.client() as client:
        assert (
            client.patch("/api/v1/bots/bot_chief", json={"project_name": "Grokbotclon"}).status_code
            == 200
        )

    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    composer = page.locator('textarea[aria-label="Message composer"]')
    await composer.fill("CB09_CSV_PROJECT Create a CSV to JSON converter and unit tests")
    await composer.press("Enter")
    await page.get_by_text("with csv_to_json.py and test_csv_to_json.py.").wait_for(
        state="visible", timeout=15000
    )
    strict_browser_page.assert_clean()

    proj_dir = env.projects_root / "Grokbotclon" / "cb09_proj"
    converter_path = proj_dir / "csv_to_json.py"
    test_path = proj_dir / "test_csv_to_json.py"
    assert converter_path.is_file() and test_path.is_file()

    report = evaluate_csv_to_json_converter(
        [sys.executable, str(converter_path)],
        work_dir=tmp_path / "t4_cb09_eval",
        test_cmd=[sys.executable, "-m", "pytest", "-q", str(test_path)],
    )
    assert report.passed is True
    assert report.project_tests_passed is True
    assert len(report.sample_results) == 4
    assert all(r.passed for r in report.sample_results)

    # Anti-cheat verification: naive split(",") converter fails evaluator
    naive_path = tmp_path / "naive_split.py"
    naive_path.write_text(
        "import json, sys\n"
        "lines = [line for line in open(sys.argv[1], encoding='utf-8').read().splitlines() "
        "if line.strip()]\n"
        "hdr = lines[0].split(',')\n"
        "out = [dict(zip(hdr, line.split(','))) for line in lines[1:]]\n"
        "open(sys.argv[2], 'w', encoding='utf-8').write(json.dumps(out))\n",
        encoding="utf-8",
    )
    naive_report = evaluate_csv_to_json_converter(
        [sys.executable, str(naive_path)],
        work_dir=tmp_path / "t4_cb09_naive",
    )
    assert naive_report.passed is False


# ---------------------------------------------------------------------------
# Scenario 11 (qa_existing): CB-10 two-agent 3-deliverable handoff & build
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s11_cb10_two_agent_3deliverable_handoff_reopen_and_build(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Scenario 11 (Feature #22): 3-deliverable 2-agent spec, handoff attribution & build."""
    spec = build_cb10_three_deliverables_spec()
    env = qa_env_factory(mock_agy_script=_T4_MOCK_AGY_SCRIPT, name="t4_s11_cb10")

    async with env.async_client(timeout=35.0) as aclient:
        b1 = await aclient.post(
            "/api/v1/bots",
            json={"name": "agent_alpha", "engine_id": "agy", "project_name": "Grokbotclon"},
        )
        b2 = await aclient.post(
            "/api/v1/bots",
            json={"name": "agent_beta", "engine_id": "agy", "project_name": "Grokbotclon"},
        )
        assert b1.status_code == 201 and b2.status_code == 201
        alpha_id = str(b1.json()["id"])
        beta_id = str(b2.json()["id"])

        ch_resp = await aclient.post(
            "/api/v1/channels",
            json={"name": "T4 CB10 Collab", "bot_ids": [alpha_id, beta_id]},
        )
        assert ch_resp.status_code == 201
        thread_id = str(ch_resp.json()["thread_id"])

        collab_body = (
            "CB10_COLLAB AGENT_ALPHA build D1 calc.py, "
            "then agent_beta integrate D2 cli.py and D3 tests/test_calc_cli.py"
        )
        t1 = await trigger_and_wait_turn(
            aclient, thread_id, f"@agent_alpha {collab_body}", timeout=25.0
        )
        assert t1.assistant_message is not None
        assert t1.assistant_message["sender_bot_id"] == alpha_id
        assert not any((f.event_type or f.event) == "handoff.dispatched" for f in t1.events)

        proj_root = env.projects_root / "Grokbotclon" / spec.project_name
        d1, d2, d3 = spec.deliverables
        assert (proj_root / d1.rel_path).is_file()
        assert not (proj_root / d2.rel_path).exists()
        assert not (proj_root / d3.rel_path).exists()

        frames: list[SseFrame] = []
        sse_conn = asyncio.Event()
        turn2_ready = asyncio.Event()
        turn2_holder: dict[str, str] = {}

        async def _listen() -> None:
            done_bots: set[str] = set()
            async for frame in iter_sse_events(aclient, timeout=30.0, on_connected=sse_conn):
                frames.append(frame)
                if not turn2_ready.is_set():
                    await turn2_ready.wait()
                ev = frame.event_type or frame.event
                if (
                    ev == "message.completed"
                    and isinstance(frame.data, dict)
                    and frame.data.get("thread_id") == thread_id
                    and frame.data.get("turn_id") == turn2_holder["id"]
                ):
                    msg = frame.data.get("payload", {}).get("message", {})
                    if msg.get("sender_bot_id"):
                        done_bots.add(str(msg["sender_bot_id"]))
                    if {alpha_id, beta_id}.issubset(done_bots):
                        return

        task = asyncio.create_task(_listen())
        try:
            await asyncio.wait_for(sse_conn.wait(), timeout=5.0)
            p2 = await aclient.post(
                f"/api/v1/threads/{thread_id}/messages",
                json={"content": f"@all {collab_body}"},
            )
            assert p2.status_code == 202
            turn2_id = str(p2.json()["turn_id"])
            turn2_holder["id"] = turn2_id
            turn2_ready.set()
            await asyncio.wait_for(task, timeout=30.0)
        finally:
            if not task.done():
                task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

        handoffs = [
            f
            for f in frames
            if (f.event_type or f.event) == "handoff.dispatched"
            and isinstance(f.data, dict)
            and f.data.get("thread_id") == thread_id
            and f.data.get("turn_id") == turn2_id
        ]
        assert len(handoffs) == 1
        assert isinstance(handoffs[0].data, dict)
        h_payload = handoffs[0].data.get("payload") or {}
        assert h_payload.get("from_bot_id") == alpha_id
        assert h_payload.get("to_bot_id") == beta_id

    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    await page.locator("aside").get_by_text("T4 CB10 Collab").click()
    d1_msg = "D1 delivered: src_pkg/calc.py implements compute_summary."
    await page.get_by_text(d1_msg).first.wait_for(state="visible", timeout=10000)
    await page.get_by_text(
        "D2 and D3 delivered: src_pkg/cli.py and tests/test_calc_cli.py integrated."
    ).first.wait_for(state="visible", timeout=10000)
    await page.reload(wait_until="networkidle")
    await page.locator("aside").get_by_text("T4 CB10 Collab").click()
    await page.get_by_text(d1_msg).first.wait_for(state="visible", timeout=10000)
    strict_browser_page.assert_clean()

    for deliverable in spec.deliverables:
        target = proj_root / deliverable.rel_path
        assert target.is_file()
        text = target.read_text(encoding="utf-8")
        for sym in deliverable.required_symbols:
            assert sym in text

    assert (
        subprocess.run(
            list(spec.build_command), cwd=str(proj_root), capture_output=True, check=False
        ).returncode
        == 0
    )
    assert (
        subprocess.run(
            list(spec.test_command), cwd=str(proj_root), capture_output=True, check=False
        ).returncode
        == 0
    )


# ---------------------------------------------------------------------------
# Scenario 12 (qa_existing): CB-11 industrial read-only SCADA/CMMS parity
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s12_cb11_industrial_readonly_scada_cmms_facility_a_b_ambig_contradict(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    qa_lab_env: IsolatedQAEnv,
) -> None:
    """Scenario 12 (Feature #23): facility_a, facility_b Spanish, ambiguity, contradiction."""
    assert qa_lab_env.lab_stack is not None
    async with qa_lab_env.async_client(timeout=35.0) as aclient:
        assert (
            await aclient.patch("/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"})
        ).status_code == 200
        turn_a = await trigger_and_wait_turn(
            aclient,
            "thr_bot_ops",
            "Check bomba 34 alarms and readings in SCADA and maintenance",
            timeout=35.0,
        )
        assert turn_a.assistant_message is not None
        content_a = str(turn_a.assistant_message["content"])
        assert "ALM-3401" in content_a and "WO-3408" in content_a
        assert (turn_a.assistant_message.get("metadata") or {}).get("verdict") == "verified"
        assert (
            await aclient.get(f"{qa_lab_env.lab_stack.effect_sim_url}/api/effects/state")
        ).json()["total_applied"] == 0

        for method in ("POST", "PUT", "PATCH", "DELETE"):
            assert (
                await aclient.request(
                    method, f"{qa_lab_env.lab_stack.scada_url}/api/alarms", json={}
                )
            ).status_code == 405
            assert (
                await aclient.request(
                    method, f"{qa_lab_env.lab_stack.maintenance_url}/api/work_orders", json={}
                )
            ).status_code == 405

    lab_b = LabStack(fixture_mode="facility_b").start()
    try:
        env_b = qa_env_factory(
            extra_env={
                **lab_b.env_vars(),
                "GROKBOT_INSTALLATION_CONFIG": str(
                    _REPO_ROOT / "lab" / "configs" / "facility_b.json"
                ),
            },
            name="t4_s12_fac_b",
        )
        async with env_b.async_client(timeout=35.0) as bclient:
            sub_b = await bclient.post(
                "/api/tasks",
                json={
                    "query": "Check P-77B alarms and latest work order",
                    "facility_id": "facility-b",
                    "allowed_areas": ["area-2"],
                    "read_only": True,
                },
            )
            assert sub_b.status_code == 201
            snap_b = await _poll_task_terminal(bclient, str(sub_b.json()["run_id"]))
            assert snap_b["run"]["status"] == "succeeded"
            assert "ALM-7701" in str(snap_b["result"]["answer"])
            assert "WO-7705" in str(snap_b["result"]["answer"])
            obs = snap_b["result"]["verified_observations"]
            assert any(
                o["asset_id"] == "SC-77" and (o.get("observed_at") or o.get("source_time"))
                for o in obs
            )
            assert any(
                o["asset_id"] == "CMMS-77" and (o.get("observed_at") or o.get("source_time"))
                for o in obs
            )
    finally:
        lab_b.stop()

    lab_amb = LabStack(fixture_mode="ambiguity").start()
    try:
        env_amb = qa_env_factory(extra_env=lab_amb.env_vars(), name="t4_s12_amb")
        async with env_amb.async_client(timeout=35.0) as amb_client:
            sub_amb = await amb_client.post(
                "/api/tasks",
                json={
                    "query": "Check alarms and work orders for bomba 34",
                    "facility_id": "facility-a",
                    "read_only": True,
                },
            )
            run_amb = str(sub_amb.json()["run_id"])
            snap_wait = await _poll_task_terminal(amb_client, run_amb)
            assert snap_wait["run"]["status"] == "waiting_for_input"
            assert (
                await amb_client.post(
                    f"/api/tasks/{run_amb}/resume", json={"human_input": {"choice": "area-1"}}
                )
            ).status_code == 200
            snap_done = await _poll_task_terminal(amb_client, run_amb)
            assert snap_done["run"]["status"] == "succeeded"
            assert "ALM-3401" in str(snap_done["result"]["answer"])
    finally:
        lab_amb.stop()

    lab_con = LabStack(fixture_mode="contradictory").start()
    try:
        env_con = qa_env_factory(extra_env=lab_con.env_vars(), name="t4_s12_con")
        async with env_con.async_client(timeout=35.0) as con_client:
            sub_c = await con_client.post(
                "/api/tasks",
                json={
                    "query": "Check bomba 34 alarms and work orders",
                    "facility_id": "facility-a",
                    "allowed_areas": ["area-1"],
                    "read_only": True,
                },
            )
            snap_c = await _poll_task_terminal(con_client, str(sub_c.json()["run_id"]))
            assert snap_c["run"]["status"] == "partial"
            assert len((snap_c.get("result") or {}).get("contradictions", [])) >= 1
            assert (
                await con_client.get(f"{lab_con.effect_sim_url}/api/effects/state")
            ).json()["total_applied"] == 0
    finally:
        lab_con.stop()


# ---------------------------------------------------------------------------
# Scenario 13 (qa_existing): CB-12 operational resilience variants
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_t4_s13_cb12_operational_resilience_stale_503_sigterm_401_oversize_concurrent(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """Scenario 13 (Feature #24): Stale, 503, 401 pause/resume, SIGTERM WAL/SSE, 413, concurrent."""
    # 1. Stale data
    lab_stale = LabStack(fixture_mode="stale").start()
    try:
        env_s = qa_env_factory(extra_env=lab_stale.env_vars(), name="t4_s13_stale")
        async with env_s.async_client(timeout=35.0) as client:
            await client.patch("/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"})
            turn_s = await trigger_and_wait_turn(
                client,
                "thr_bot_ops",
                "Check bomba 34 alarms and readings in SCADA and maintenance",
                timeout=35.0,
            )
            assert turn_s.assistant_message is not None
            partial_str = json.dumps(
                (turn_s.assistant_message.get("metadata") or {}).get("partial_evidence", [])
            )
            assert "RDG-STALE-01" in partial_str and "RDG-BAD-01" in partial_str
    finally:
        lab_stale.stop()

    # 2. Transient 503 down
    lab_down = LabStack(fixture_mode="down").start()
    try:
        env_d = qa_env_factory(extra_env=lab_down.env_vars(), name="t4_s13_down")
        async with env_d.async_client(timeout=35.0) as client:
            await client.patch("/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"})
            turn_d = await trigger_and_wait_turn(
                client,
                "thr_bot_ops",
                "Check bomba 34 alarms and readings in SCADA and maintenance",
                timeout=35.0,
            )
            assert turn_d.assistant_message is not None
            assert (turn_d.assistant_message.get("metadata") or {}).get("verdict") != "verified"
    finally:
        lab_down.stop()

    # 3. 401 auth_expired pause -> switch to default -> resolve approval -> resume
    lab_auth = _ControllableLabStack(scada_fixture_mode="auth_expired").start()
    try:
        env_a = qa_env_factory(extra_env=lab_auth.env_vars(), name="t4_s13_auth")
        async with env_a.async_client(timeout=40.0) as client:
            await client.patch("/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"})
            pause_turn = await trigger_and_wait_turn(
                client,
                "thr_bot_ops",
                "Check bomba 34 alarms and readings in SCADA and maintenance",
                terminal_events=("hitl.approval.requested",),
                timeout=35.0,
            )
            assert isinstance(pause_turn.terminal_event.data, dict)
            appr = pause_turn.terminal_event.data["payload"]["approval"]
            appr_id = str(appr["id"])
            run_id = str(appr["arguments"]["run_id"])
            lab_auth.scada_state.set_mode("default")

            sse_conn = asyncio.Event()
            resumed_frames: list[SseFrame] = []
            turn_holder: dict[str, str] = {}

            async def _listen_resumed() -> None:
                resumed_tid: str | None = None
                async for frame in iter_sse_events(client, timeout=35.0, on_connected=sse_conn):
                    resumed_frames.append(frame)
                    if not isinstance(frame.data, dict):
                        continue
                    ev = frame.event_type or frame.event
                    if ev == "turn.started" and frame.data.get("thread_id") == "thr_bot_ops":
                        resumed_tid = str(frame.data.get("turn_id"))
                        turn_holder["id"] = resumed_tid
                    if (
                        resumed_tid is not None
                        and ev == "message.completed"
                        and frame.data.get("turn_id") == resumed_tid
                    ):
                        return

            task = asyncio.create_task(_listen_resumed())
            try:
                await asyncio.wait_for(sse_conn.wait(), timeout=5.0)
                assert (
                    await client.post(
                        f"/api/v1/approvals/{appr_id}/resolve",
                        json={"decision": "allow_once"},
                    )
                ).status_code == 200
                await asyncio.wait_for(task, timeout=35.0)
            finally:
                if not task.done():
                    task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

            snap = (await client.get(f"/api/tasks/{run_id}")).json()
            assert snap["run"]["status"] == "succeeded"
            assert (
                await client.get(f"{lab_auth.effect_sim_url}/api/effects/state")
            ).json()["total_applied"] == 0
    finally:
        lab_auth.stop()

    # 4. SIGTERM restart WAL/SSE preservation, 5. >25 MiB 413, 6. 2 concurrent runs
    env_main = qa_env_factory(mock_agy_script=_T4_MOCK_AGY_SCRIPT, name="t4_s13_main")
    async with env_main.async_client(timeout=35.0) as client:
        bot_resp = await client.post(
            "/api/v1/bots", json={"name": "T4 Restart Survivor", "engine_id": "agy"}
        )
        assert bot_resp.status_code == 201
        created_bot_id = str(bot_resp.json()["id"])

        turn_seed = await trigger_and_wait_turn(client, "thr_bot_chief", "/approval Restart seed")
        msg_id = str(turn_seed.user_message["id"])

        pre_frames: list[SseFrame] = []
        connected = asyncio.Event()

        async def _collect_pre() -> None:
            async for frame in iter_sse_events(client, timeout=10.0, on_connected=connected):
                if frame.event_type == "message.reaction":
                    pre_frames.append(frame)
                    return

        task_pre = asyncio.create_task(_collect_pre())
        try:
            await asyncio.wait_for(connected.wait(), timeout=5.0)
            await client.post(
                f"/api/v1/messages/{msg_id}/reactions", json={"emoji": "1️⃣", "action": "add"}
            )
            await asyncio.wait_for(task_pre, timeout=10.0)
        finally:
            if not task_pre.done():
                task_pre.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task_pre

        anchor_id = str(pre_frames[0].id)
        epoch_before = anchor_id.split("_", 2)[2]
        await client.post(
            f"/api/v1/messages/{msg_id}/reactions", json={"emoji": "2️⃣", "action": "add"}
        )

    env_main.restart(keep_port=False)

    async with env_main.async_client(timeout=35.0) as client:
        assert any(
            b["id"] == created_bot_id
            for b in (await client.get("/api/v1/bots")).json()["bots"]
        )
        replayed: list[SseFrame] = []
        async for frame in iter_sse_events(
            client, headers={"Last-Event-ID": anchor_id}, timeout=4.0
        ):
            replayed.append(frame)
            if (
                frame.event_type == "message.reaction"
                and isinstance(frame.data, dict)
                and frame.data.get("payload", {}).get("emoji") == "2️⃣"
            ):
                break
        assert all(f.event_type != "stream.resync" for f in replayed)
        assert any(
            f.id and f.id.startswith("evt_") and f.id.split("_", 2)[2] == epoch_before
            for f in replayed
        )

        # >25 MiB invalid attachment -> 413 with 0 residue
        uploads_dir = env_main.tmp_dir / "uploads"
        before_uploads = set(uploads_dir.iterdir()) if uploads_dir.is_dir() else set()
        with env_main.client(timeout=30.0) as sync_client:
            oversize = sync_client.post(
                "/api/v1/attachments",
                params={"filename": "too_big.bin"},
                headers={"Content-Type": "application/octet-stream"},
                content=_iter_fixed_bytes(_MAX_ATTACHMENT_BYTES + 1),
            )
        assert oversize.status_code == 413
        after_uploads = set(uploads_dir.iterdir()) if uploads_dir.is_dir() else set()
        assert after_uploads == before_uploads

        # 2 concurrent runs -> 0 cross-bleed
        ta, tb = await asyncio.gather(
            trigger_and_wait_turn(
                client, "thr_bot_chief", "Run CONCURRENT_TAG=T4_ALPHA_01", timeout=25.0
            ),
            trigger_and_wait_turn(
                client, "thr_bot_ops", "Run CONCURRENT_TAG=T4_BETA_02", timeout=25.0
            ),
        )
        assert ta.assistant_message is not None and tb.assistant_message is not None
        assert "T4_ALPHA_01" in str(ta.assistant_message["content"])
        assert "T4_BETA_02" not in str(ta.assistant_message["content"])
        assert "T4_BETA_02" in str(tb.assistant_message["content"])
        assert "T4_ALPHA_01" not in str(tb.assistant_message["content"])


# ---------------------------------------------------------------------------
# Scenario 14 (qa_existing): CB-13 Linux zero-egress N3 honest verification
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
def test_t4_s14_cb13_linux_zero_egress_n3_honest_verification(
    qa_cli_runner: QACliRunner,
) -> None:
    """Scenario 14 (Features #25,#37): n3_probe --strict & verify_n3_linux.sh honest status."""
    probe_res = qa_cli_runner.run_module("src.n3_probe", ["--json"])
    assert probe_res.returncode in {0, 2}
    payload = probe_res.json_stdout()
    overall = str(payload["overall_status"])
    assert overall in {"READY", "PENDING_N3_LINUX_ENV", "PENDING_LOCAL_LLM"}

    bad_origin = qa_cli_runner.run_module(
        "src.n3_probe", ["--strict", "--json", "--llm-origin", "http://example.com"]
    )
    assert bad_origin.returncode == 2

    strict_res = qa_cli_runner.run_module("src.n3_probe", ["--strict", "--json"])
    script_res = qa_cli_runner.run_command(["bash", "scripts/verify_n3_linux.sh"])
    if overall == "READY":
        assert strict_res.returncode == 0
        assert script_res.returncode == 0
    else:
        assert strict_res.returncode != 0
        assert script_res.returncode in {1, 2}


# ---------------------------------------------------------------------------
# Scenario 15 (qa_megaplan): E2E telemetry correlation, rotation & dedup
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
async def test_t4_s15_e2e_telemetry_correlation_rotation_ingestion_and_dedup(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    strict_browser_page: StrictBrowserPage,
    tmp_path: Path,
) -> None:
    """Scenario 15 (Features #27,#28): UI client-error -> X-Request-Id -> .1 rotation -> dedup."""
    failures_path = qa_env.logs_dir / "failures.jsonl"
    rotated_path = qa_env.logs_dir / "failures.jsonl.1"
    seeded_bytes = _seed_jsonl_to_size(failures_path, _TEN_MIB - 400)
    assert seeded_bytes < _TEN_MIB
    pre_stat = failures_path.stat()
    pre_identity = (pre_stat.st_dev, pre_stat.st_ino)

    canary_fe = "CANARY_T4_FE_SECRET_1122"
    canary_be = "CANARY_T4_BE_SECRET_3344"

    page = strict_browser_page.page
    await page.goto(qa_env.url("/app"), wait_until="domcontentloaded")
    await page.locator('textarea[aria-label="Message composer"]').wait_for(
        state="visible", timeout=15000
    )
    fe_res: dict[str, Any] = await page.evaluate(
        """async (secret) => {
            const infoRes = await fetch('/api/system/info');
            const reqId = infoRes.headers.get('x-request-id') || '';
            const postRes = await fetch('/api/v1/diagnostics/client-error', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    kind: 'qa_t4_probe',
                    message: 'T4 correlated frontend error probe',
                    url: `/app?token=${secret}`,
                    method: 'GET',
                    status_code: 500,
                    request_id: reqId,
                    extra: {api_key: secret, panel: 't4'}
                })
            });
            return {reqId, status: postRes.status, body: await postRes.json()};
        }""",
        canary_fe,
    )
    assert fe_res["status"] == 202
    assert str(fe_res["reqId"]).startswith("req_")
    strict_browser_page.assert_clean()

    with qa_env.client() as client:
        for _ in range(3):
            miss = client.get(f"/api/v1/threads/t4_dedup_missing/messages?token={canary_be}")
            assert miss.status_code == 404
            if rotated_path.is_file():
                break

    assert rotated_path.is_file(), "Expected failures.jsonl.1 after crossing 10 MiB threshold"
    rot_stat = rotated_path.stat()
    assert (rot_stat.st_dev, rot_stat.st_ino) == pre_identity
    new_stat = failures_path.stat()
    assert (new_stat.st_dev, new_stat.st_ino) != pre_identity

    camp_dir = tmp_path / "t4_s15_camp"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )

    scan1 = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--ingest-logs"]
    )
    _assert_no_cli_false_pass(scan1)
    assert scan1.returncode == 0, f"scan 1 failed: {scan1.stderr}\n{scan1.stdout}"

    with qa_env.client() as client:
        miss2 = client.get(f"/api/v1/threads/t4_dedup_missing/messages?token={canary_be}")
        assert miss2.status_code == 404
        be_req_2 = miss2.headers.get("X-Request-Id", "")
        assert be_req_2.startswith("req_")

    scan2 = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--ingest-logs"]
    )
    _assert_no_cli_false_pass(scan2)
    assert scan2.returncode == 0, f"scan 2 failed: {scan2.stderr}\n{scan2.stdout}"

    qa_items = _query_sqlite_tables(camp_dir, "qa_items")
    run_records = _query_sqlite_tables(camp_dir, "qa_run_records")
    backlog_rows = _query_sqlite_tables(camp_dir, "factory_backlog")
    assert qa_items and run_records

    deduped = [it for it in qa_items if int(it.get("occurrence_count", 0)) >= 2]
    assert deduped, f"Expected deduplicated qa_item with occurrence_count >= 2: {qa_items!r}"
    assert any(
        b.get("item_id") == deduped[0].get("factory_item_id") for b in backlog_rows
    ), "Expected qa_items linked to factory_backlog"

    all_req_ids = [
        rid
        for rec in run_records
        for rid in (rec.get("request_ids") or [])
        if isinstance(rid, str) and rid.startswith("req_")
    ]
    all_corr_ids = [
        cid
        for item in qa_items
        for cid in (item.get("correlation_ids") or [])
        if isinstance(cid, str) and cid.startswith("req_")
    ]
    assert be_req_2 in all_req_ids
    assert str(fe_res["reqId"]) in all_req_ids
    assert be_req_2 in all_corr_ids
    assert str(fe_res["reqId"]) in all_corr_ids

    assert_no_secret_leak(qa_items, secrets=(canary_fe, canary_be, qa_env.cap_secret))
    assert_no_secret_leak(run_records, secrets=(canary_fe, canary_be, qa_env.cap_secret))
    assert_no_secret_leak(
        json.loads((camp_dir / "baseline.json").read_text(encoding="utf-8")),
        secrets=(canary_fe, canary_be, qa_env.cap_secret),
    )


# ---------------------------------------------------------------------------
# Scenario 16 (qa_megaplan): Flaky vs stable P1 triage & 7-step repair
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_t4_s16_flaky_vs_stable_p1_triage_and_seven_step_repair(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Scenario 16 (Features #28,#30,#31,#35): Flaky stays flaky; deterministic P1 fixed first."""
    counter_file = tmp_path / "t4_flaky_counter.txt"
    counter_file.write_text("0", encoding="utf-8")
    repo_dir = tmp_path / "t4_s16_repo"
    base_sha = _init_isolated_git_repo(
        repo_dir,
        files={
            "mod_p1.py": "def val() -> int:\n    return 0\n",
            "mod_p2.py": "def val() -> int:\n    return 0\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "flaky_suite/test_flaky.py": (
                "from pathlib import Path\n\n"
                "def test_alt() -> None:\n"
                f"    p = Path({str(counter_file)!r})\n"
                "    n = int(p.read_text(encoding='utf-8').strip()) + 1\n"
                "    p.write_text(str(n), encoding='utf-8')\n"
                "    assert n % 2 == 0\n"
            ),
            "test_p1.py": "from mod_p1 import val\ndef test_p1() -> None:\n    assert val() == 1\n",
            "test_p2.py": "from mod_p2 import val\ndef test_p2() -> None:\n    assert val() == 2\n",
        },
        with_qa_branch=True,
    )

    camp_dir = tmp_path / "t4_s16_camp"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    seeded = [
        {
            "item_id": "item-flaky",
            "dedup_key": "CB-03:sse:flaky_alt",
            "case_id": "CB-03",
            "subsystem": "sse",
            "normalized_signature": "flaky_alt",
            "severity": "P2",
            "state": "observed",
            "summary": "Alternating flaky test",
            "first_seen_sha": base_sha,
            "last_seen_sha": base_sha,
            "environment_lane": "local_deterministic",
            "repro_command": f"{sys.executable} -m pytest -q flaky_suite/test_flaky.py",
        },
        {
            "item_id": "item-p2",
            "dedup_key": "CB-01:mod_p2:val_bug",
            "case_id": "CB-01",
            "subsystem": "mod_p2",
            "normalized_signature": "val_bug_p2",
            "severity": "P2",
            "state": "reproduced",
            "summary": "Deterministic P2 bug",
            "first_seen_sha": base_sha,
            "last_seen_sha": base_sha,
            "environment_lane": "local_deterministic",
            "repro_command": f"{sys.executable} -m pytest -q test_p2.py",
        },
        {
            "item_id": "item-p1",
            "dedup_key": "CB-00:mod_p1:val_bug",
            "case_id": "CB-00",
            "subsystem": "mod_p1",
            "normalized_signature": "val_bug_p1",
            "severity": "P1",
            "state": "reproduced",
            "summary": "Deterministic P1 bug",
            "first_seen_sha": base_sha,
            "last_seen_sha": base_sha,
            "environment_lane": "local_deterministic",
            "repro_command": f"{sys.executable} -m pytest -q test_p1.py",
        },
    ]
    (camp_dir / "failures.jsonl").write_text(
        "\n".join(json.dumps(row) for row in seeded) + "\n", encoding="utf-8"
    )

    for _ in range(3):
        re_res = qa_cli_runner.run(
            [
                "reevaluate",
                "--campaign-dir",
                str(camp_dir),
                "--item",
                "item-flaky",
                "--repo-root",
                str(repo_dir),
            ],
            cwd=repo_dir,
        )
        _assert_no_cli_false_pass(re_res)
        assert re_res.returncode == 0

    with _mock_repairer_server(
        patch_map={
            "mod_p1": ("mod_p1.py", "def val() -> int:\n    return 1\n"),
            "mod_p2": ("mod_p2.py", "def val() -> int:\n    return 2\n"),
        },
        model_id="hydrogen",
    ) as repairer_env:
        rep_res = qa_cli_runner.run(
            [
                "repair",
                "--campaign-dir",
                str(camp_dir),
                "--max-parallel",
                "1",
                "--max-attempts",
                "1",
                "--author-model",
                "hydrogen",
                "--auditor-model",
                "pro",
                "--repo-root",
                str(repo_dir),
            ],
            env_overrides=repairer_env,
            cwd=repo_dir,
        )
    _assert_no_cli_false_pass(rep_res)
    assert rep_res.returncode == 0, f"repair failed: {rep_res.stderr}\n{rep_res.stdout}"

    items = _query_sqlite_tables(camp_dir, "qa_items")
    by_id = {it["item_id"]: it for it in items}
    assert by_id["item-flaky"]["state"] == "flaky"
    assert by_id["item-p1"]["state"] == "accepted_qa"

    manifests = [
        json.loads(cf.read_text(encoding="utf-8"))
        for cf in sorted((camp_dir / "candidates").glob("*.json"))
    ]
    assert not any(m["item_id"] == "item-flaky" for m in manifests)
    manifests.sort(key=lambda m: str(m.get("created_at") or ""))
    assert manifests[0]["item_id"] == "item-p1"
    p1_man = manifests[0]
    assert p1_man["baseline_passed"] is False
    assert p1_man["candidate_passed"] is True
    assert p1_man["audit_passed"] is True
    assert p1_man["status"] == "accepted_qa"

    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )
    assert (
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "test_p1.py"],
            cwd=str(repo_dir),
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


# ---------------------------------------------------------------------------
# Scenario 17 (qa_megaplan): M7 PolicyGuard enforcement blocks protected paths
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_t4_s17_m7_policy_guard_enforcement_blocks_protected_path(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Scenario 17 (Features #5,#30,#35): PolicyGuard blocks policy.py & tests/e2e/ edits."""
    repo_dir = tmp_path / "t4_s17_repo"
    base_sha = _init_isolated_git_repo(
        repo_dir,
        files={
            "src/factory/policy.py": "# protected policy module\n",
            "tests/e2e/test_core.py": "def test_core() -> None:\n    assert True\n",
            "app_mod.py": "def ok() -> bool:\n    return False\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_bug.py": "from app_mod import ok\ndef test_bug() -> None:\n    assert ok()\n",
            "test_bug2.py": "from app_mod import ok\ndef test_bug2() -> None:\n    assert ok()\n",
        },
        with_qa_branch=True,
    )

    camp_dir = tmp_path / "t4_s17_camp"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    (camp_dir / "failures.jsonl").write_text(
        json.dumps(
            {
                "item_id": "item-pol-breach",
                "dedup_key": "CB-00:app_mod:pol_breach",
                "case_id": "CB-00",
                "subsystem": "app_mod",
                "normalized_signature": "pol_breach",
                "severity": "P1",
                "state": "reproduced",
                "summary": "Bug whose repairer illegally targets policy.py",
                "first_seen_sha": base_sha,
                "last_seen_sha": base_sha,
                "environment_lane": "local_deterministic",
                "repro_command": f"{sys.executable} -m pytest -q test_bug.py",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with _mock_repairer_server(
        patch_map={
            "item-pol-breach": ("src/factory/policy.py", "# tampered policy\n"),
        },
        model_id="hydrogen",
    ) as breach_env:
        rep_res = qa_cli_runner.run(
            [
                "repair",
                "--campaign-dir",
                str(camp_dir),
                "--max-parallel",
                "1",
                "--max-attempts",
                "1",
                "--author-model",
                "hydrogen",
                "--auditor-model",
                "pro",
                "--repo-root",
                str(repo_dir),
                "--json",
            ],
            env_overrides=breach_env,
            cwd=repo_dir,
        )
    _assert_no_cli_false_pass(rep_res)
    assert rep_res.returncode == 0, f"repair failed: {rep_res.stderr}\n{rep_res.stdout}"
    rep_json = rep_res.json_stdout()
    assert rep_json["worker_results"][0]["outcome"] == "blocked_policy"

    qa_items = _query_sqlite_tables(camp_dir, "qa_items")
    pol_item = next(it for it in qa_items if it["item_id"] == "item-pol-breach")
    assert pol_item["state"] == "blocked"
    assert "core_maintenance_review_required" in str(pol_item.get("blocked_reason") or "")
    assert _git_head_sha(repo_dir) == base_sha

    # Step 2: Seed a separate 'reproduced' QA item so `accept` passes the item-state
    # guard and genuinely exercises PolicyGuard on tests/e2e/test_core.py.
    existing_failures = (camp_dir / "failures.jsonl").read_text(encoding="utf-8")
    tamper_item = {
        "item_id": "item-pol-tamper-2",
        "dedup_key": "CB-00:e2e_core:tamper_check",
        "case_id": "CB-00",
        "subsystem": "e2e_core",
        "normalized_signature": "tamper_check",
        "severity": "P1",
        "state": "reproduced",
        "summary": "Pre-staged candidate tampering with tests/e2e/test_core.py",
        "first_seen_sha": base_sha,
        "last_seen_sha": base_sha,
        "environment_lane": "local_deterministic",
        "repro_command": f"{sys.executable} -m pytest -q test_bug2.py",
        "repro_test_path": "test_bug2.py",
    }
    (camp_dir / "failures.jsonl").write_text(
        existing_failures + json.dumps(tamper_item) + "\n",
        encoding="utf-8",
    )

    tamper_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-e2e-tamper",
        files={
            "tests/e2e/test_core.py": (
                "def test_core() -> None:\n    # tampered protected test\n    assert True\n"
            )
        },
        base_ref=base_sha,
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    (camp_dir / "candidates" / "cand-e2e-tamper.json").write_text(
        json.dumps(
            {
                "candidate_id": "cand-e2e-tamper",
                "item_id": "item-pol-tamper-2",
                "campaign_id": state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": tamper_sha,
                "branch_name": "qa/cand-e2e-tamper",
                "files_modified": ["tests/e2e/test_core.py"],
                "repro_test_path": "test_bug2.py",
                "rerun_command": f"{sys.executable} -m pytest -q test_smoke.py",
                "baseline_passed": False,
                "candidate_passed": True,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "pro",
                "status": "candidate_verified",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    acc_res = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            "cand-e2e-tamper",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    acc_combined = _assert_no_cli_false_pass(acc_res)
    assert acc_res.returncode != 0
    assert (
        "policyimmutabilityerror" in acc_combined
        or "policy_immutability_violation" in acc_combined
    ), (
        "Expected PolicyImmutabilityError from PolicyGuard, got:\n"
        f"{acc_res.stdout}\n{acc_res.stderr}"
    )
    assert any(
        tok in acc_combined for tok in ("policy", "immutab", "tests/e2e", "protected")
    )
    qa_items_after = _query_sqlite_tables(camp_dir, "qa_items")
    tamper_row = next(it for it in qa_items_after if it["item_id"] == "item-pol-tamper-2")
    assert tamper_row["state"] != "accepted_qa"
    qa_branch_sha = subprocess.run(
        ["git", "rev-parse", "qa/autopilot"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert qa_branch_sha == base_sha
    assert _git_head_sha(repo_dir) == base_sha


# ---------------------------------------------------------------------------
# Scenario 18 (qa_megaplan): QA-4 parallel 2-repairer + integrator + rollback
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_t4_s18_qa4_parallel_two_repairers_integrator_cross_audit_and_rollback(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Scenario 18 (Features #5,#30,#36,#41): Max-2 parallel + integrator + audit + rollback."""
    repo_dir = tmp_path / "t4_s18_repo"
    base_sha = _init_isolated_git_repo(
        repo_dir,
        files={
            "mod_a.py": "def fn_a() -> str:\n    return 'broken_a'\n",
            "mod_b.py": "def fn_b() -> str:\n    return 'broken_b'\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_a.py": (
                "from mod_a import fn_a\ndef test_a() -> None:\n    assert fn_a() == 'ok_a'\n"
            ),
            "test_b.py": (
                "from mod_b import fn_b\ndef test_b() -> None:\n    assert fn_b() == 'ok_b'\n"
            ),
        },
        with_qa_branch=True,
    )

    camp_dir = tmp_path / "t4_s18_camp"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    # 1. Verify --max-parallel 3 rejected & self-audit / hydrogen-auditor rejected
    over_res = qa_cli_runner.run(
        [
            "repair",
            "--campaign-dir",
            str(camp_dir),
            "--max-parallel",
            "3",
            "--repo-root",
            str(repo_dir),
        ]
    )
    _assert_no_cli_false_pass(over_res)
    assert over_res.returncode != 0

    chk_sha = _create_candidate_branch(
        repo_dir, "qa/cand-bad-audit", files={"dummy_chk.txt": "chk\n"}, base_ref=base_sha
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    bad_cand_path = camp_dir / "candidates" / "cand-bad-audit.json"
    for author_m, auditor_m in (("hydrogen", "hydrogen"), ("sonnet", "hydrogen")):
        bad_cand_path.write_text(
            json.dumps(
                {
                    "candidate_id": "cand-bad-audit",
                    "item_id": "item-bad-audit",
                    "campaign_id": state["campaign_id"],
                    "base_sha": base_sha,
                    "candidate_sha": chk_sha,
                    "branch_name": "qa/cand-bad-audit",
                    "rerun_command": f"{sys.executable} -m pytest -q test_smoke.py",
                    "baseline_passed": False,
                    "candidate_passed": True,
                    "audit_passed": True,
                    "author_model": author_m,
                    "auditor_model": auditor_m,
                    "status": "candidate_verified",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        bad_acc = qa_cli_runner.run(
            [
                "accept",
                "--campaign-dir",
                str(camp_dir),
                "--candidate",
                "cand-bad-audit",
                "--repo-root",
                str(repo_dir),
            ],
            cwd=repo_dir,
        )
        _assert_no_cli_false_pass(bad_acc)
        assert bad_acc.returncode != 0
    bad_cand_path.unlink()

    # 2. Seed two disjoint items & run parallel max-2 repair + single integrator
    (camp_dir / "failures.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "item_id": "item-a",
                        "dedup_key": "CB-05:mod_a:broken_a",
                        "case_id": "CB-05",
                        "subsystem": "mod_a",
                        "normalized_signature": "broken_a",
                        "severity": "P1",
                        "state": "reproduced",
                        "summary": "mod_a returns broken_a",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "repro_command": f"{sys.executable} -m pytest -q test_a.py",
                    }
                ),
                json.dumps(
                    {
                        "item_id": "item-b",
                        "dedup_key": "CB-06:mod_b:broken_b",
                        "case_id": "CB-06",
                        "subsystem": "mod_b",
                        "normalized_signature": "broken_b",
                        "severity": "P1",
                        "state": "reproduced",
                        "summary": "mod_b returns broken_b",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "repro_command": f"{sys.executable} -m pytest -q test_b.py",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with _mock_repairer_server(
        patch_map={
            "mod_a": ("mod_a.py", "def fn_a() -> str:\n    return 'ok_a'\n"),
            "mod_b": ("mod_b.py", "def fn_b() -> str:\n    return 'ok_b'\n"),
        },
        model_id="hydrogen",
    ) as rep_env:
        rep_res = qa_cli_runner.run(
            [
                "repair",
                "--campaign-dir",
                str(camp_dir),
                "--max-parallel",
                "2",
                "--max-attempts",
                "2",
                "--author-model",
                "hydrogen",
                "--auditor-model",
                "pro",
                "--repo-root",
                str(repo_dir),
            ],
            env_overrides=rep_env,
            cwd=repo_dir,
        )
    _assert_no_cli_false_pass(rep_res)
    assert rep_res.returncode == 0, f"repair failed: {rep_res.stderr}\n{rep_res.stdout}"

    state_after = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert int(state_after["max_parallel_repairers"]) <= 2
    assert state_after["last_accepted_sha"] and state_after["last_accepted_sha"] != base_sha

    accepted = sorted(
        (
            json.loads(cf.read_text(encoding="utf-8"))
            for cf in (camp_dir / "candidates").glob("*.json")
        ),
        key=lambda m: str(m.get("created_at") or ""),
    )
    accepted = [m for m in accepted if m.get("status") == "accepted_qa"]
    assert len(accepted) == 2
    assert {m["item_id"] for m in accepted} == {"item-a", "item-b"}
    assert set(accepted[0]["files_modified"]).isdisjoint(set(accepted[1]["files_modified"]))
    for m in accepted:
        assert m["author_model"] and m["auditor_model"]
        assert m["author_model"] != m["auditor_model"]
        assert m["auditor_model"] == "pro"

    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )
    assert (
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=str(repo_dir),
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )

    # 3. Rollback last accepted candidate
    cand_b_id = str(accepted[-1]["candidate_id"])
    rb_res = qa_cli_runner.run(
        [
            "rollback",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            cand_b_id,
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    _assert_no_cli_false_pass(rb_res)
    assert rb_res.returncode == 0, f"rollback failed: {rb_res.stderr}\n{rb_res.stdout}"
    rb_manifest = json.loads(
        (camp_dir / "candidates" / f"{cand_b_id}.json").read_text(encoding="utf-8")
    )
    assert rb_manifest["status"] == "rolled_back"
    rb_record_path = camp_dir / "rollbacks" / f"qa_rollback_{cand_b_id}.json"
    assert rb_record_path.is_file()
    rb_record = json.loads(rb_record_path.read_text(encoding="utf-8"))
    assert _git_head_sha(repo_dir) == rb_record["previous_accepted_sha"]


# ---------------------------------------------------------------------------
# Scenario 19 (qa_megaplan): Crash-safe campaign resume
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_t4_s19_crash_safe_campaign_resume_preserves_offsets_leases_attempts(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Scenario 19 (Features #27,#29): Resume reconciles dead PID, preserves offsets & attempts."""
    with qa_env.client() as client:
        assert client.get("/api/v1/bots/t4_pre_rot/library").status_code == 404

    camp_dir = tmp_path / "t4_s19_camp"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )

    scan1 = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--ingest-logs"]
    )
    _assert_no_cli_false_pass(scan1)
    assert scan1.returncode == 0

    # Simulate .1 rotation with unread tail + new active entry
    failures_log = qa_env.logs_dir / "failures.jsonl"
    rotated_log = qa_env.logs_dir / "failures.jsonl.1"
    with failures_log.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "id": "fail_t4_tail",
                    "ts": "2026-11-27T07:00:00Z",
                    "source": "pages",
                    "kind": "page_tail_error",
                    "message": "POST /api/v1/pages/t4_tail_2 -> HTTP 404",
                    "path": "/api/v1/pages/t4_tail_2",
                    "method": "POST",
                    "status_code": 404,
                    "request_id": "req_t4_tail_2",
                }
            )
            + "\n"
        )
    os.replace(failures_log, rotated_log)
    failures_log.write_text(
        json.dumps(
            {
                "id": "fail_t4_active",
                "ts": "2026-11-27T07:00:01Z",
                "source": "routines",
                "kind": "routine_active_error",
                "message": "GET /api/v1/routines/t4_active_3 -> HTTP 500",
                "path": "/api/v1/routines/t4_active_3",
                "method": "GET",
                "status_code": 500,
                "request_id": "req_t4_active_3",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    # Seed FactoryStore lease on dead PID worker + synthetic non-dead lease
    state = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    store = FactoryStore(camp_dir / "factory.sqlite3")
    store.init_db()
    store.add_backlog_item(
        BacklogItem(
            item_id="fb-item-crash-1",
            title="Crashed worker item",
            priority=1,
            hypothesis="Reconcile dead worker lease",
            target_metric="failures",
            baseline_repro_cmd=f"{sys.executable} -c 'assert True'",
        )
    )
    dead_lease = store.acquire_lease("fb-item-crash-1", "dead-worker", ttl_s=300.0)

    existing_failures = (camp_dir / "failures.jsonl").read_text(encoding="utf-8")
    crash_item = {
        "item_id": "item-crash-1",
        "dedup_key": "CB-00:worker:crashed_1",
        "case_id": "CB-00",
        "subsystem": "worker",
        "normalized_signature": "crashed_1",
        "severity": "P1",
        "state": "in_repair",
        "summary": "Interrupted repair worker",
        "first_seen_sha": state["base_sha"],
        "last_seen_sha": state["base_sha"],
        "environment_lane": "local_deterministic",
        "factory_item_id": "fb-item-crash-1",
        "attempts": 1,
        "repro_command": f"{sys.executable} -c 'assert True'",
    }
    (camp_dir / "failures.jsonl").write_text(
        existing_failures + json.dumps(crash_item) + "\n", encoding="utf-8"
    )

    state["attempts"] = {"item-crash-1": 1, "item-synth-live": 2}
    state["active_leases"] = {
        "item-crash-1": dead_lease.lease_id,
        "item-synth-live": "lease-synth-preserve",
    }
    state["active_worker_pids"] = {"item-crash-1": 999999}
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    cursors_before = _query_sqlite_tables(camp_dir, "qa_log_cursors")
    failures_cursor_before = next(
        (c for c in cursors_before if c.get("file_name") == "failures.jsonl"),
        None,
    )
    assert failures_cursor_before is not None, (
        f"Missing failures.jsonl cursor before resume: {cursors_before!r}"
    )
    offset_before = int(failures_cursor_before.get("byte_offset", 0))
    assert offset_before > 0

    res_resume = qa_cli_runner.run(["resume", "--campaign-dir", str(camp_dir), "--json"])
    _assert_no_cli_false_pass(res_resume)
    assert res_resume.returncode == 0, f"resume failed: {res_resume.stderr}\n{res_resume.stdout}"

    state_after = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert state_after["attempts"]["item-crash-1"] >= 1
    assert state_after["attempts"]["item-synth-live"] == 2
    assert "item-crash-1" not in state_after["active_leases"]
    assert state_after["active_leases"].get("item-synth-live") == "lease-synth-preserve"
    assert "item-crash-1" not in state_after.get("active_worker_pids", {})

    qa_items = _query_sqlite_tables(camp_dir, "qa_items")
    reconciled = next(it for it in qa_items if it["item_id"] == "item-crash-1")
    assert reconciled["state"] == "reproduced"
    assert int(reconciled["attempts"]) >= 1

    all_blob = json.dumps(qa_items)
    assert "req_t4_tail_2" in all_blob or "t4_tail_2" in all_blob
    assert "req_t4_active_3" in all_blob or "t4_active_3" in all_blob
    pre_items = [it for it in qa_items if "t4_pre_rot" in json.dumps(it)]
    assert len(pre_items) == 1 and int(pre_items[0]["occurrence_count"]) == 1

    cursors_after = _query_sqlite_tables(camp_dir, "qa_log_cursors")
    failures_cursor_after = next(
        (c for c in cursors_after if c.get("file_name") == "failures.jsonl"),
        None,
    )
    assert failures_cursor_after is not None, (
        f"Missing failures.jsonl cursor after resume: {cursors_after!r}"
    )
    assert int(failures_cursor_after.get("byte_offset", 0)) == len(failures_log.read_bytes())
    assert int(failures_cursor_after.get("inode_ino") or 0) == failures_log.stat().st_ino


# ---------------------------------------------------------------------------
# Scenario 20 (qa_megaplan): QA-6 closeout certification & DoD reports
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_t4_s20_qa6_closeout_certification_same_sha_passes_and_reports(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Scenario 20 (Features #38,#39,#40): reevaluate -> accept -> 2x same-SHA -> reports."""
    repo_dir = tmp_path / "t4_s20_repo"
    base_sha = _init_isolated_git_repo(
        repo_dir,
        files={
            "calc.py": "def triple(n: int) -> int:\n    return n\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_repro.py": (
                "from calc import triple\ndef test_triple() -> None:\n    assert triple(3) == 9\n"
            ),
        },
        with_qa_branch=True,
    )
    cand_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-closeout",
        files={"calc.py": "def triple(n: int) -> int:\n    return n * 3\n"},
        base_ref=base_sha,
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )

    camp_dir = tmp_path / "t4_s20_camp"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    repro_cmd = f"{sys.executable} -m pytest -q test_repro.py"
    (camp_dir / "failures.jsonl").write_text(
        json.dumps(
            {
                "item_id": "item-closeout",
                "dedup_key": "CB-00:calc:triple_bug",
                "case_id": "CB-00",
                "subsystem": "calc",
                "normalized_signature": "triple_bug",
                "severity": "P1",
                "state": "reproduced",
                "summary": "triple(3) returns 3 instead of 9",
                "first_seen_sha": base_sha,
                "last_seen_sha": base_sha,
                "environment_lane": "local_deterministic",
                "repro_command": repro_cmd,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    cand_path = camp_dir / "candidates" / "cand-closeout.json"
    cand_path.write_text(
        json.dumps(
            {
                "candidate_id": "cand-closeout",
                "item_id": "item-closeout",
                "campaign_id": state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": cand_sha,
                "branch_name": "qa/cand-closeout",
                "files_modified": ["calc.py"],
                "repro_test_path": "test_repro.py",
                "rerun_command": repro_cmd,
                "baseline_passed": False,
                "candidate_passed": False,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "pro",
                "status": "pending",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    reeval = qa_cli_runner.run(
        [
            "reevaluate",
            "--campaign-dir",
            str(camp_dir),
            "--item",
            "item-closeout",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    _assert_no_cli_false_pass(reeval)
    assert reeval.returncode == 0, f"reevaluate failed: {reeval.stderr}\n{reeval.stdout}"

    accept = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            "cand-closeout",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    _assert_no_cli_false_pass(accept)
    assert accept.returncode == 0, f"accept failed: {accept.stderr}\n{accept.stdout}"

    assert json.loads(cand_path.read_text(encoding="utf-8"))["status"] == "accepted_qa"
    state_after = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert state_after["last_accepted_sha"] == cand_sha

    for _ in range(3):
        scan_res = qa_cli_runner.run(["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00"])
        _assert_no_cli_false_pass(scan_res)
        assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    rep_res = qa_cli_runner.run(["report", "--campaign-dir", str(camp_dir), "--json"])
    _assert_no_cli_false_pass(rep_res)
    assert rep_res.returncode == 0, f"report failed: {rep_res.stderr}\n{rep_res.stdout}"
    rep_json = rep_res.json_stdout()
    stats = rep_json["stats"]
    assert stats["open_p0"] == 0
    assert stats["open_p1"] == 0
    assert stats["same_sha_passes"] >= 2
    assert stats["runs"] >= 3
    assert isinstance(stats["median_ms"], (int, float)) and stats["median_ms"] >= 0.0
    assert isinstance(stats["variance_ms"], (int, float)) and stats["variance_ms"] >= 0.0
    assert isinstance(stats["p95_ms"], (int, float)) and stats["p95_ms"] >= 0.0

    handoff_path = camp_dir / "HANDOFF.md"
    daily_path = camp_dir / "daily_report.md"
    assert handoff_path.is_file() and daily_path.is_file()
    handoff_text = handoff_path.read_text(encoding="utf-8")
    daily_text = daily_path.read_text(encoding="utf-8")
    assert "Open P0" in daily_text and "Open P1" in daily_text
    assert "Same-SHA Passes" in daily_text
    assert_no_secret_leak(rep_json, secrets=(qa_env.cap_secret,))
    assert_no_secret_leak(handoff_text, secrets=(qa_env.cap_secret,))
    assert_no_secret_leak(daily_text, secrets=(qa_env.cap_secret,))
