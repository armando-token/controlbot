"""Tier 2 boundary, negative, security, and corner-case E2E tests for CB-00..CB-13."""

from __future__ import annotations

import asyncio
import contextlib
import http.server
import json
import re
import socket
import sqlite3
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
import websockets
from lab.effect_sim import create_effect_sim_app
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import ScadaState, create_scada_app
from tests.e2e._helpers import LabStack, alloc_free_port
from tests.e2e_qa.conftest import StrictBrowserPage
from tests.e2e_qa.fixtures import (
    ValveCatalogFixture,
    build_cb10_three_deliverables_spec,
    build_cb_valve_104_catalog,
    evaluate_csv_to_json_converter,
)
from tests.e2e_qa.helpers import (
    CliResult,
    IsolatedQAEnv,
    QACliRunner,
    SseFrame,
    alloc_qa_free_port,
    assert_no_secret_leak,
    iter_sse_events,
    trigger_and_wait_turn,
)
from websockets.exceptions import ConnectionClosed, InvalidStatus
from websockets.typing import Subprotocol

pytestmark = pytest.mark.qa_tier2

_MIB = 1024 * 1024
_MAX_ATTACHMENT_BYTES = 25 * _MIB
_CONV_ID = "33333333-4444-5555-6666-777777777777"

_BOUNDARY_MOCK_AGY_SCRIPT = f"""#!/usr/bin/env python3
import json
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

Path.home().joinpath("captured_prompts.jsonl").open("a", encoding="utf-8").write(
    json.dumps({{"prompt": prompt}}) + "\\n"
)

cid = "{_CONV_ID}"
reply = "Boundary mock reply."

url_match = re.search(r"CATALOG_BASE=(http://127\\.0\\.0\\.1:\\d+)", prompt)
if url_match:
    base = url_match.group(1)
    with urllib.request.urlopen(base + "/index.json", timeout=5) as resp:
        records = json.loads(resp.read().decode("utf-8"))
    if "AMBIGUOUS_QUERY" in prompt:
        ambig = [r for r in records if r.get("sku", "").startswith("CB-VALVE-104-")]
        opts = ", ".join(
            f"{{r['sku']}} ({{r['currency']}} {{r['price']}})" for r in ambig
        )
        reply = f"Clarification required: multiple matches found ({{opts}})."
    elif "MISSING_SKU=" in prompt:
        m_sku = re.search(r"MISSING_SKU=([A-Za-z0-9_-]+)", prompt)
        missing = m_sku.group(1) if m_sku else "UNKNOWN"
        hits = [r for r in records if r.get("sku") == missing]
        if not hits:
            reply = f"Not found in catalog: {{missing}} does not exist."
elif "CANCEL_DELAYED_WRITE" in prompt:
    marker_m = re.search(r"MARKER=([^\\s]+)", prompt)
    marker_path = Path(marker_m.group(1)) if marker_m else Path("delayed_marker.txt")
    if "--output-format" in args and "stream-json" in args:
        print(json.dumps({{
            "event": "init",
            "conversation_id": cid,
            "init": {{"model": "gemini-4-carbon-low"}},
        }}), flush=True)
        print(json.dumps({{
            "event": "step_update",
            "step_update": {{"step_type": "agent_response", "text_delta": "Working... "}},
        }}), flush=True)
        time.sleep(3.5)
        marker_path.write_text("UNWANTED_POST_CANCEL_WRITE\\n", encoding="utf-8")
    sys.exit(0)
elif "ISOLATION_PROBE" in prompt:
    reply = "Isolated thread response."

if "--output-format" in args and "stream-json" in args:
    print(json.dumps({{
        "event": "init",
        "conversation_id": cid,
        "init": {{"model": "gemini-4-carbon-low"}},
    }}), flush=True)
    print(json.dumps({{
        "event": "step_update",
        "step_update": {{"step_type": "agent_response", "text_delta": reply}},
    }}), flush=True)
    print(json.dumps({{
        "event": "result",
        "result": {{"status": "SUCCESS", "conversation_id": cid, "response": reply}},
    }}), flush=True)
    sys.exit(0)

print(json.dumps({{"status": "SUCCESS", "conversation_id": cid, "response": reply}}))
"""


class _NoSignalUvicorn(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        return None


class _ControllableLabStack:
    """Loopback synthetic SCADA/Maint/EffectSim stack with mutable ScadaState."""

    def __init__(self, *, scada_fixture_mode: str = "auth_expired") -> None:
        self.scada_state = ScadaState(fixture_mode=scada_fixture_mode)
        self.scada_port: int = 0
        self.maintenance_port: int = 0
        self.effect_sim_port: int = 0
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._servers: list[_NoSignalUvicorn] = []
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
            target=self._run_thread, daemon=True, name="qa-t2-controllable-lab"
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
                srv = _NoSignalUvicorn(
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


@contextlib.contextmanager
def _serve_catalog_once(fixture: ValveCatalogFixture) -> Iterator[str]:
    records_bytes = json.dumps(fixture.to_json_records()).encode("utf-8")
    pages = fixture.render_html_pages()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/index.json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(records_bytes)))
                self.end_headers()
                self.wfile.write(records_bytes)
                return
            if self.path in pages:
                body = pages[self.path].encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
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
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3.0)


def _iter_fixed_bytes(total_bytes: int, chunk_size: int = _MIB) -> Iterator[bytes]:
    full = b"X" * chunk_size
    rem = total_bytes
    while rem >= chunk_size:
        yield full
        rem -= chunk_size
    if rem > 0:
        yield b"X" * rem


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


def _assert_clean_scan_cli(res: CliResult) -> str:
    combined = (res.stdout + "\n" + res.stderr).lower()
    assert "unrecognized arguments" not in combined, f"CLI rejected valid args:\n{res.stderr}"
    assert "notimplementederror" not in combined, f"Scan hit NotImplementedError:\n{res.stderr}"
    assert "validationerror" not in combined, f"Unexpected ValidationError:\n{res.stderr}"
    assert "traceback (most recent call last)" not in combined, (
        f"Unhandled traceback in scan:\n{res.stdout}\n{res.stderr}"
    )
    for crash_tok in ("keyerror", "attributeerror", "typeerror", "nameerror"):
        assert crash_tok not in combined, (
            f"Unexpected {crash_tok} crash in scan:\n{res.stdout}\n{res.stderr}"
        )
    assert res.returncode in {0, 1, 2, 3}, (
        f"Unexpected exit code {res.returncode}: {res.stderr}"
    )
    if res.stdout.strip().startswith("{"):
        parsed = res.json_stdout()
        assert isinstance(parsed, dict)
    return combined


def _assert_negative_run_record(camp_dir: Path, case_id: str) -> dict[str, Any]:
    records = _load_megaplan_run_records(camp_dir)
    case_recs = [r for r in records if r.get("case_id") == case_id]
    assert case_recs, f"Expected {case_id} RunRecord in {camp_dir}, got {records!r}"
    latest = case_recs[-1]
    assert latest["passed"] is False, f"{case_id} falsely passed negative boundary: {latest!r}"
    assertions = latest.get("assertions")
    assert isinstance(assertions, dict) and assertions, (
        f"Expected non-empty assertions dict in {case_id} RunRecord: {latest!r}"
    )
    assert any(v is False for v in assertions.values()), (
        f"Expected at least one False assertion in {case_id}: {assertions!r}"
    )
    detail = str(latest.get("error_summary") or latest.get("blocked_reason") or "").strip()
    assert detail, f"Expected non-empty error_summary/blocked_reason in {case_id}: {latest!r}"
    assert not any(
        tok in detail.lower()
        for tok in ("notimplementederror", "keyerror", "attributeerror", "typeerror", "nameerror")
    ), f"Negative RunRecord recorded internal crash instead of domain failure: {detail!r}"
    return latest


# ---------------------------------------------------------------------------
# CB-00..04 Boundaries
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
def test_t2_cb00_asset_path_traversal_and_missing_bundle_404(qa_env: IsolatedQAEnv) -> None:
    """CB-00: Path traversal and nonexistent /assets paths return 404."""
    with qa_env.client() as client:
        assert client.get("/assets/..%2F..%2Fetc%2Fpasswd").status_code == 404
        assert client.get("/assets/nonexistent-cb00-bundle.js").status_code == 404


@pytest.mark.qa_existing
def test_t2_cb01_auth_missing_and_dual_token_mismatch_401(
    qa_auth_env: IsolatedQAEnv,
) -> None:
    """CB-01: Missing token and mismatched query/Bearer dual tokens return 401."""
    token = qa_auth_env.web_token
    assert token is not None
    with httpx.Client(base_url=qa_auth_env.base_url, timeout=10.0) as anon:
        assert anon.get("/api/v1/bots").status_code == 401
        assert anon.get("/api/v1/threads/thr_bot_chief/messages").status_code == 401
        assert anon.get("/api/v1/events/stream").status_code == 401
        mismatch = anon.get(
            "/api/v1/bots?token=wrong-token-value",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert mismatch.status_code == 401


@pytest.mark.qa_existing
async def test_t2_cb02_nonexistent_sku_and_two_match_ambiguity_abstention(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """CB-02: Nonexistent SKU abstains & 2-match ambiguity surfaces both dynamic candidates."""
    fixture = build_cb_valve_104_catalog()
    assert len(fixture.ambiguous_matches) == 2
    match_a, match_b = fixture.ambiguous_matches

    with _serve_catalog_once(fixture) as catalog_origin:
        env = qa_env_factory(mock_agy_script=_BOUNDARY_MOCK_AGY_SCRIPT, name="cb02_bound")
        async with env.async_client(timeout=25.0) as client:
            t_missing = await trigger_and_wait_turn(
                client,
                "thr_bot_chief",
                f"CATALOG_BASE={catalog_origin} MISSING_SKU={fixture.nonexistent_sku}",
                timeout=20.0,
            )
            assert t_missing.assistant_message is not None
            missing_body = str(t_missing.assistant_message["content"])
            assert fixture.nonexistent_sku in missing_body
            assert str(fixture.active_record.price) not in missing_body
            assert str(fixture.prior_record.price) not in missing_body
            assert (
                re.search(
                    r"(?:(?:USD|EUR|GBP|MXN)\s*\d+(?:\.\d+)?|\$\s*\d+(?:\.\d+)?|\b\d+\.\d{2}\b)",
                    missing_body,
                    re.IGNORECASE,
                )
                is None
            ), f"Unexpected fabricated price in nonexistent-SKU reply: {missing_body!r}"
            assert (
                re.search(
                    r"(not found|does not exist|no current|not in catalog|unavailable)",
                    missing_body,
                    re.IGNORECASE,
                )
                is not None
            ), f"Missing abstention phrasing in reply: {missing_body!r}"

            t_ambig = await trigger_and_wait_turn(
                client,
                "thr_bot_chief",
                f"CATALOG_BASE={catalog_origin} AMBIGUOUS_QUERY={fixture.ambiguous_query}",
                timeout=20.0,
            )
            assert t_ambig.assistant_message is not None
            ambig_body = str(t_ambig.assistant_message["content"])
            assert match_a.sku in ambig_body
            assert match_b.sku in ambig_body
            assert str(match_a.price) in ambig_body
            assert str(match_b.price) in ambig_body
            assert (
                re.search(r"(clarification|multiple|ambig)", ambig_body, re.IGNORECASE)
                is not None
            ), f"Missing clarification phrasing in ambiguous reply: {ambig_body!r}"


@pytest.mark.qa_megaplan
def test_t2_megaplan_cb02_rejects_stale_prior_price_as_current(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """CB-02 Megaplan: Scenario evaluator rejects superseded prior_record.price as current."""
    fixture = build_cb_valve_104_catalog()
    assert fixture.prior_record.price != fixture.active_record.price
    stale_reply = (
        f"{fixture.sku}: {fixture.prior_record.currency} {fixture.prior_record.price} "
        f"(effective {fixture.prior_record.effective_date}, "
        f"source {fixture.prior_record.source_url})"
    )
    stale_agy = f"""#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

cid = "{_CONV_ID}"
reply = {stale_reply!r}
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({{
        "event": "init",
        "conversation_id": cid,
        "init": {{"model": "gemini-4-carbon-low"}},
    }}), flush=True)
    print(json.dumps({{
        "event": "step_update",
        "step_update": {{"step_type": "agent_response", "text_delta": reply}},
    }}), flush=True)
    print(json.dumps({{
        "event": "result",
        "result": {{"status": "SUCCESS", "conversation_id": cid, "response": reply}},
    }}), flush=True)
    sys.exit(0)

print(json.dumps({{"status": "SUCCESS", "conversation_id": cid, "response": reply}}))
"""
    env = qa_env_factory(mock_agy_script=stale_agy, name="t2_megaplan_cb02_stale")
    camp_dir = tmp_path / "camp_t2_cb02"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"

    (camp_dir / "fixtures").mkdir(parents=True, exist_ok=True)
    (camp_dir / "fixtures" / "cb_valve_104.json").write_text(
        json.dumps(
            {
                "fixture_version": fixture.fixture_version,
                "sku": fixture.sku,
                "active_price": str(fixture.active_record.price),
                "prior_price": str(fixture.prior_record.price),
                "currency": fixture.active_record.currency,
                "source_url": fixture.active_record.source_url,
                "records": fixture.to_json_records(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    scan_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-02", "--json"]
    )
    _assert_clean_scan_cli(scan_res)
    latest = _assert_negative_run_record(camp_dir, "CB-02")
    assert latest.get("fixture_version") == fixture.fixture_version


@pytest.mark.qa_existing
async def test_t2_cb03_sse_epoch_mismatch_and_invalid_cursor_emit_stream_resync(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-03: Epoch mismatch, invalid cursor & sequence_ahead emit stream.resync."""
    async with qa_env.async_client() as client:
        turn = await trigger_and_wait_turn(client, "thr_bot_chief", "/approval CB-03 resync seed")
        msg_id = str(turn.user_message["id"])
        await client.post(
            f"/api/v1/messages/{msg_id}/reactions",
            json={"emoji": "🍎", "action": "add"},
        )

        for bad_cursor, expected_reason in (
            ("evt_000001_oldepoch", "epoch_mismatch"),
            ("oldepoch:1", "epoch_mismatch"),
            ("not_a_valid_cursor_at_all", "invalid_cursor"),
            ("evt_999999_1", None),
        ):
            seen: list[SseFrame] = []
            async for frame in iter_sse_events(
                client,
                headers={"Last-Event-ID": bad_cursor},
                timeout=3.0,
            ):
                seen.append(frame)
                if frame.event_type == "stream.resync":
                    break
            assert seen and seen[0].event_type == "stream.resync", (
                f"Expected stream.resync for {bad_cursor!r}, got {seen}"
            )
            if expected_reason is not None and isinstance(seen[0].data, dict):
                assert seen[0].data["payload"]["reason"] == expected_reason


@pytest.mark.qa_existing
async def test_t2_cb03_post_cancel_side_effect_prevented_and_unknown_thread_404(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """CB-03: Unknown thread interrupt returns 404, empty msg 422, cancel stops delayed write."""
    env = qa_env_factory(mock_agy_script=_BOUNDARY_MOCK_AGY_SCRIPT, name="cb03_bound")
    marker = env.projects_root / "Grokbotclon" / "delayed_marker.txt"

    async with env.async_client(timeout=20.0) as client:
        assert (await client.post("/api/v1/threads/nonexistent_thr/interrupt")).status_code == 404
        assert (
            await client.post("/api/v1/threads/thr_bot_chief/messages", json={"content": "   "})
        ).status_code == 422

        started = asyncio.Event()

        async def _wait_working() -> None:
            async for frame in iter_sse_events(client, timeout=10.0, on_connected=started):
                if (frame.event_type or frame.event) == "message.delta":
                    return

        listen_task = asyncio.create_task(_wait_working())
        try:
            await asyncio.wait_for(started.wait(), timeout=5.0)
            post = await client.post(
                "/api/v1/threads/thr_bot_chief/messages",
                json={"content": f"CANCEL_DELAYED_WRITE MARKER={marker}"},
            )
            assert post.status_code == 202
            await asyncio.wait_for(listen_task, timeout=10.0)
        finally:
            if not listen_task.done():
                listen_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await listen_task

        intr = await client.post("/api/v1/threads/thr_bot_chief/interrupt")
        assert intr.status_code == 200
        await asyncio.sleep(4.0)
        assert not marker.exists()


@pytest.mark.qa_existing
def test_t2_cb04_channel_over_6_under_2_empty_name_and_empty_channel_409(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-04: Channels reject <2, >6, duplicate bots, empty names (422) & empty send (409)."""
    with qa_env.client() as client:
        extra_bots: list[str] = []
        for idx in range(5):
            r = client.post(
                "/api/v1/bots",
                json={"name": f"OverflowBot {idx}", "engine_id": "agy"},
            )
            assert r.status_code == 201
            extra_bots.append(str(r.json()["id"]))

        seven_bots = ["bot_chief", "bot_ops", *extra_bots]
        assert len(seven_bots) == 7
        assert client.post(
            "/api/v1/channels", json={"name": "TooMany", "bot_ids": seven_bots}
        ).status_code == 422
        assert client.post(
            "/api/v1/channels", json={"name": "TooFew", "bot_ids": ["bot_chief"]}
        ).status_code == 422
        assert client.post(
            "/api/v1/channels", json={"name": "DupBots", "bot_ids": ["bot_chief", "bot_chief"]}
        ).status_code == 422
        assert client.post(
            "/api/v1/channels", json={"name": "   ", "bot_ids": ["bot_chief", "bot_ops"]}
        ).status_code == 422
        assert client.post("/api/v1/bots", json={"name": "   "}).status_code == 422

        # Channel whose member bots are deleted -> 409 on send
        b_tmp_1 = str(client.post("/api/v1/bots", json={"name": "TmpA"}).json()["id"])
        b_tmp_2 = str(client.post("/api/v1/bots", json={"name": "TmpB"}).json()["id"])
        ch = client.post(
            "/api/v1/channels", json={"name": "GhostChannel", "bot_ids": [b_tmp_1, b_tmp_2]}
        ).json()
        assert client.delete(f"/api/v1/bots/{b_tmp_1}").status_code == 200
        assert client.delete(f"/api/v1/bots/{b_tmp_2}").status_code == 200
        send_empty = client.post(
            f"/api/v1/threads/{ch['thread_id']}/messages",
            json={"content": "hello"},
        )
        assert send_empty.status_code == 409


@pytest.mark.qa_existing
async def test_t2_cb04_cross_thread_context_leak_prevented(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """CB-04: Distinct threads never leak prompt context or message history across bots."""
    env = qa_env_factory(mock_agy_script=_BOUNDARY_MOCK_AGY_SCRIPT, name="cb04_iso")
    secret_marker = "UNIQUE_CHIEF_CONTEXT_TOKEN_918273"

    async with env.async_client(timeout=25.0) as client:
        await trigger_and_wait_turn(
            client,
            "thr_bot_chief",
            f"ISOLATION_PROBE {secret_marker}",
            timeout=20.0,
        )
        await trigger_and_wait_turn(
            client,
            "thr_bot_ops",
            "ISOLATION_PROBE ops check",
            timeout=20.0,
        )

        ops_msgs = (await client.get("/api/v1/threads/thr_bot_ops/messages")).json()["messages"]
        assert secret_marker not in json.dumps(ops_msgs)

    captured = [
        json.loads(line)["prompt"]
        for line in (env.fake_home / "captured_prompts.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    ops_prompts = [p for p in captured if "ops check" in p]
    assert ops_prompts
    assert all(secret_marker not in p for p in ops_prompts)


# ---------------------------------------------------------------------------
# CB-05..08 Boundaries
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
def test_t2_cb05_cross_thread_artifact_isolation_and_invalid_page_targets(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-05: Pages are isolated per bot library and reject missing targets (422)."""
    with qa_env.client() as client:
        created = client.post(
            "/api/v1/pages",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "title": "Chief Private Blueprint",
                "content_md": "Confidential chief spec",
            },
        )
        assert created.status_code == 201
        art_id = str(created.json()["id"])

        ops_lib = client.get("/api/v1/bots/bot_ops/library").json()["items"]
        assert all(item["id"] != art_id for item in ops_lib)

        ops_msgs = client.get("/api/v1/threads/thr_bot_ops/messages").json()["messages"]
        assert all(art_id not in json.dumps(m) for m in ops_msgs)

        assert client.post(
            "/api/v1/pages",
            json={"title": "Orphan Page", "content_md": "Missing target"},
        ).status_code == 422


@pytest.mark.qa_existing
def test_t2_cb05_active_mime_html_svg_js_forced_attachment_and_nosniff(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-05: Active-MIME uploads (.html/.svg/.js) force nosniff, sandbox CSP & attachment."""
    samples: list[tuple[str, str, bytes]] = [
        ("xss.html", "text/html", b"<html><script>alert(1)</script></html>"),
        ("vec.svg", "image/svg+xml", b"<svg onload='alert(1)'></svg>"),
        ("evil.js", "application/javascript", b"alert('xss');"),
    ]
    with qa_env.client() as client:
        for fname, mime, payload in samples:
            up = client.post(
                "/api/v1/attachments",
                params={"filename": fname},
                headers={"Content-Type": mime},
                content=payload,
            )
            assert up.status_code == 201
            dl = client.get(f"/api/v1/attachments/{up.json()['id']}")
            assert dl.status_code == 200
            assert dl.headers.get("X-Content-Type-Options") == "nosniff"
            assert dl.headers.get("Content-Security-Policy") == "sandbox; default-src 'none'"
            disp = dl.headers.get("Content-Disposition", "")
            assert disp.startswith("attachment;"), f"Expected attachment disposition, got {disp!r}"


@pytest.mark.qa_existing
async def test_t2_cb06_agent_409_during_takeover_duplicate_key_ws_4401_and_path_escape_403(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """CB-06: Agent action 409 during takeover, dup key 409, WS 4401, path escape 403."""
    env = qa_env_factory(with_mock_rfb=True, name="cb06_bound")
    with env.client() as client:
        tk1 = client.post(
            "/api/v1/computers/default/takeover",
            headers={"Idempotency-Key": "cb06-dup-key"},
            json={"owner": "qa-op"},
        )
        assert tk1.status_code == 200

        tk_dup = client.post(
            "/api/v1/computers/default/takeover",
            headers={"Idempotency-Key": "cb06-dup-key"},
            json={"owner": "qa-op"},
        )
        assert tk_dup.status_code == 409

        agent_act = client.post(
            "/api/v1/computers/default/actions",
            json={"type": "status", "actor": "agent"},
        )
        assert agent_act.status_code == 409

        assert client.post("/api/v1/computers/default/handback", json={}).status_code == 200

        # Workspace file traversal -> 403, missing -> 404, bad ttl -> 422
        assert (
            client.get(
                "/api/v1/computers/default/file", params={"path": "../../etc/passwd"}
            ).status_code
            == 403
        )
        assert (
            client.delete(
                "/api/v1/computers/default/files", params={"path": "../../etc/passwd"}
            ).status_code
            == 403
        )
        assert (
            client.get(
                "/api/v1/computers/default/file", params={"path": "nonexistent.txt"}
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/api/v1/computers/default/vnc-token", json={"ttl_seconds": "bad"}
            ).status_code
            == 422
        )

    # Unauthenticated WS closes with 4401 / 403
    for ws_path in (
        "/ws/v1/computers/default/vnc",
        "/ws/v1/computers/default/control",
        "/ws/v1/computers/default/pty/default",
    ):
        rejected = False
        try:
            async with websockets.connect(
                f"{env.ws_base_url}{ws_path}",
                subprotocols=[Subprotocol("binary")] if ws_path.endswith("/vnc") else None,
            ) as ws:
                await asyncio.wait_for(ws.recv(), timeout=3.0)
        except InvalidStatus as exc:
            assert exc.response.status_code == 403
            rejected = True
        except ConnectionClosed as exc:
            code = exc.rcvd.code if exc.rcvd is not None else (exc.sent.code if exc.sent else None)
            assert code == 4401
            rejected = True
        assert rejected, f"Expected WS rejection on {ws_path}"


@pytest.mark.qa_existing
def test_t2_cb07_duplicate_approval_resolve_409_and_effect_sim_conflict_409(
    qa_lab_env: IsolatedQAEnv,
) -> None:
    """CB-07: Duplicate approval resolve returns 409 and effect_sim conflict preserves count 1."""
    assert qa_lab_env.lab_stack is not None
    with qa_lab_env.client() as client:
        # 1. Approval resolve conflict & disallowed always_allow
        appr = client.post(
            "/api/v1/approvals",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "title": "test_action",
                "allow_always_allowed": False,
            },
        )
        assert appr.status_code == 201
        appr_id = str(appr.json()["id"])

        bad_always = client.post(
            f"/api/v1/approvals/{appr_id}/resolve",
            json={"decision": "always_allow"},
        )
        assert bad_always.status_code == 409

        ok = client.post(
            f"/api/v1/approvals/{appr_id}/resolve",
            json={"decision": "allow_once"},
        )
        assert ok.status_code == 200

        dup = client.post(
            f"/api/v1/approvals/{appr_id}/resolve",
            json={"decision": "deny"},
        )
        assert dup.status_code == 409

        # 2. Direct effect_sim conflict check: total_applied stays 1
        eff_url = qa_lab_env.lab_stack.effect_sim_url
        e1 = client.post(
            f"{eff_url}/api/effects/apply",
            json={
                "idempotency_key": "cb07-conflict-key",
                "asset_id": "bomba-34-a1",
                "action": "reset_latch",
                "params": {"mode": "safe"},
            },
        )
        assert e1.status_code == 200
        e_conflict = client.post(
            f"{eff_url}/api/effects/apply",
            json={
                "idempotency_key": "cb07-conflict-key",
                "asset_id": "bomba-34-a1",
                "action": "trip_breaker",
                "params": {"mode": "unsafe"},
            },
        )
        assert e_conflict.status_code == 409
        state = client.get(f"{eff_url}/api/effects/state").json()
        assert state["total_applied"] == 1


@pytest.mark.qa_existing
async def test_t2_cb08_memory_non_manager_403_and_stale_revision_409_api_and_ui(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """CB-08: Non-Manager / untrusted approved_procedure -> 403 and stale revision -> 409."""
    with qa_env.client() as client:
        non_mgr = client.post(
            "/api/v1/memory",
            headers={"X-Actor-Role": "Operator"},
            json={
                "scope": "org_approved",
                "scope_id": "org",
                "kind": "approved_procedure",
                "title": "Blocked SOP",
                "content": "Should fail",
                "actor_role": "Manager",
            },
        )
        assert non_mgr.status_code == 403

        untrusted = client.post(
            "/api/v1/memory",
            headers={"X-Actor-Role": "Manager"},
            json={
                "scope": "org_approved",
                "scope_id": "org",
                "kind": "approved_procedure",
                "provenance": "untrusted",
                "title": "Untrusted SOP",
                "content": "Should fail",
            },
        )
        assert untrusted.status_code == 403

    # Verify UI MemoryModal stale revision 409 alert cleanly with explicit allow_http_statuses
    page = strict_browser_page.page
    await page.goto(qa_env.base_url + "/app", wait_until="networkidle")
    await page.locator("aside").get_by_role("button", name=re.compile(r"Memory", re.I)).click()
    mem_dlg = page.get_by_role("dialog")
    await mem_dlg.get_by_role("button", name="New memory").click()
    await mem_dlg.get_by_label("Title").fill("Revision Race Item")
    await mem_dlg.get_by_label("Content").fill("v1 content")
    await mem_dlg.get_by_role("button", name="Save memory").click()
    await mem_dlg.get_by_text("Revision Race Item").wait_for(state="visible")

    await mem_dlg.get_by_role("button", name="Edit Revision Race Item").click()
    await mem_dlg.get_by_role("button", name="Save changes").wait_for(state="visible")

    with qa_env.client() as client:
        items = client.get("/api/v1/memory").json()["items"]
        target = next(it for it in items if it["title"] == "Revision Race Item")
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

    strict_browser_page.assert_clean(
        allow_http_statuses=[409],
        allow_console_substrings=["409 (Conflict)"],
    )


@pytest.mark.qa_existing
def test_t2_cb08_memory_export_secret_redaction_and_cross_scope_access_blocked(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-08: Memory export redacts secrets & cross-scope patch/delete returns 403."""
    canary = "sk-qa-t2-export-secret-55667788"
    with qa_env.client() as client:
        created = client.post(
            "/api/v1/memory",
            headers={"X-User-Id": "user_one"},
            json={
                "scope": "user",
                "scope_id": "user_one",
                "kind": "preference",
                "title": "Secret Note",
                "content": f"api_token={canary}",
            },
        )
        assert created.status_code == 201
        item_id = str(created.json()["id"])

        exp = client.get(
            "/api/v1/memory/export",
            params={"format": "json"},
            headers={"X-User-Id": "user_one"},
        )
        assert exp.status_code == 200
        assert_no_secret_leak(exp.json(), secrets=(canary,))

        cross_patch = client.patch(
            f"/api/v1/memory/{item_id}",
            headers={"X-User-Id": "user_two"},
            json={"revision": 1, "content": "tampered"},
        )
        assert cross_patch.status_code == 403

        cross_del = client.delete(
            f"/api/v1/memory/{item_id}",
            headers={"X-User-Id": "user_two"},
        )
        assert cross_del.status_code == 403


@pytest.mark.qa_existing
def test_t2_cb08_routine_webhook_401_404_409_and_auto_review_422(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-08: Routine webhook rejects bad token/missing/disabled; auto-review >20 rules 422."""
    with qa_env.client() as client:
        routine_resp = client.post(
            "/api/v1/bots/bot_chief/routines",
            json={
                "name": "Disabled Routine",
                "instruction": "Check",
                "schedule_type": "manual",
                "enabled": False,
            },
        )
        assert routine_resp.status_code == 201, routine_resp.text
        routine = routine_resp.json()
        rid = str(routine["id"])
        wkey = str(routine["webhook_key"])

        assert client.post(f"/api/v1/webhooks/routines/{rid}").status_code == 401
        assert client.post(
            f"/api/v1/webhooks/routines/{rid}",
            headers={"Authorization": "Bearer wrong-key"},
        ).status_code == 401
        assert client.post(
            "/api/v1/webhooks/routines/unknown_routine_id",
            headers={"Authorization": f"Bearer {wkey}"},
        ).status_code == 404
        assert client.post(
            f"/api/v1/webhooks/routines/{rid}",
            headers={"Authorization": f"Bearer {wkey}"},
        ).status_code == 409

        # Auto-review > 20 rules -> 422 preserving prior rules
        prior = client.get("/api/v1/settings/auto-review").json()["rules"]
        too_many = [{"instruction": f"Rule {i}"} for i in range(21)]
        assert (
            client.put("/api/v1/settings/auto-review", json={"rules": too_many}).status_code
            == 422
        )
        assert client.put(
            "/api/v1/settings/auto-review", json={"rules": [{"instruction": "   "}]}
        ).status_code == 422
        assert client.get("/api/v1/settings/auto-review").json()["rules"] == prior


# ---------------------------------------------------------------------------
# CB-09..13 Boundaries
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
def test_t2_cb09_evaluator_rejects_naive_split_or_exit0_on_malformed_csv(
    tmp_path: Path,
) -> None:
    """CB-09: Independent evaluator catches naive comma-split and exit-0 on malformed CSV."""
    naive = tmp_path / "naive_csv.py"
    naive.write_text(
        "import json, sys\n"
        "raw = open(sys.argv[1], encoding='utf-8').read().splitlines()\n"
        "lines = [line for line in raw if line.strip()]\n"
        "hdr = lines[0].split(',')\n"
        "out = [dict(zip(hdr, line.split(','))) for line in lines[1:]]\n"
        "open(sys.argv[2], 'w', encoding='utf-8').write(json.dumps(out))\n",
        encoding="utf-8",
    )
    report = evaluate_csv_to_json_converter(
        [sys.executable, str(naive)],
        work_dir=tmp_path / "cb09_naive_eval",
    )
    assert report.passed is False
    by_name = {r.name: r for r in report.sample_results}
    assert by_name["quoted_fields"].passed is False
    assert by_name["invalid_malformed"].passed is False


@pytest.mark.qa_megaplan
def test_t2_megaplan_cb09_rejects_prose_without_runnable_code(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """CB-09 Megaplan: Scenario rejects prose-only claims without runnable converter code."""
    prose_reply = (
        "Done! I created csv_to_json.py and test_csv_to_json.py "
        "and all 4 CSV edge-case tests passed."
    )
    prose_agy = f"""#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

cid = "{_CONV_ID}"
reply = {prose_reply!r}
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({{
        "event": "init",
        "conversation_id": cid,
        "init": {{"model": "gemini-4-carbon-low"}},
    }}), flush=True)
    print(json.dumps({{
        "event": "step_update",
        "step_update": {{"step_type": "agent_response", "text_delta": reply}},
    }}), flush=True)
    print(json.dumps({{
        "event": "result",
        "result": {{"status": "SUCCESS", "conversation_id": cid, "response": reply}},
    }}), flush=True)
    sys.exit(0)

print(json.dumps({{"status": "SUCCESS", "conversation_id": cid, "response": reply}}))
"""
    env = qa_env_factory(mock_agy_script=prose_agy, name="t2_megaplan_cb09_prose")
    camp_dir = tmp_path / "camp_t2_cb09"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"
    res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-09", "--json"]
    )
    _assert_clean_scan_cli(res)
    _assert_negative_run_record(camp_dir, "CB-09")
    assert not (env.projects_root / "Grokbotclon" / "cb09_proj" / "csv_to_json.py").exists()


@pytest.mark.qa_existing
def test_t2_cb10_missing_deliverable_or_broken_build_fails_verification(
    tmp_path: Path,
) -> None:
    """CB-10: Missing D3 test deliverable or syntax error in D1 fails build/test checks."""
    spec = build_cb10_three_deliverables_spec()
    proj = tmp_path / spec.project_name
    (proj / "src_pkg").mkdir(parents=True)
    (proj / "tests").mkdir(parents=True)
    (proj / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "src_pkg" / "calc.py").write_text(
        "def compute_summary(vals):\n    return sum(vals\n",  # intentional SyntaxError
        encoding="utf-8",
    )
    (proj / "src_pkg" / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")

    # Missing D3
    assert not (proj / spec.deliverables[2].rel_path).exists()

    # Broken build on D1
    build_proc = subprocess.run(
        list(spec.build_command),
        cwd=str(proj),
        capture_output=True,
        text=True,
        timeout=20.0,
        check=False,
    )
    assert build_proc.returncode != 0


@pytest.mark.qa_megaplan
def test_t2_megaplan_cb10_rejects_missing_deliverable_or_broken_build(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """CB-10 Megaplan: Scenario rejects incomplete deliverable or failing build/tests."""
    broken_cb10_agy = f"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

projects_root = os.environ.get("CONTROLBOT_PROJECTS_ROOT", "").strip()
if projects_root:
    proj = Path(projects_root) / "Grokbotclon" / "cb10_summary_pkg"
    (proj / "src_pkg").mkdir(parents=True, exist_ok=True)
    (proj / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "src_pkg" / "calc.py").write_text(
        "def compute_summary(vals):\\n    return sum(vals\\n",
        encoding="utf-8",
    )

cid = "{_CONV_ID}"
reply = "D1, D2, and D3 delivered and pytest passed."
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({{
        "event": "init",
        "conversation_id": cid,
        "init": {{"model": "gemini-4-carbon-low"}},
    }}), flush=True)
    print(json.dumps({{
        "event": "step_update",
        "step_update": {{"step_type": "agent_response", "text_delta": reply}},
    }}), flush=True)
    print(json.dumps({{
        "event": "result",
        "result": {{"status": "SUCCESS", "conversation_id": cid, "response": reply}},
    }}), flush=True)
    sys.exit(0)

print(json.dumps({{"status": "SUCCESS", "conversation_id": cid, "response": reply}}))
"""
    env = qa_env_factory(mock_agy_script=broken_cb10_agy, name="t2_megaplan_cb10_broken")
    camp_dir = tmp_path / "camp_t2_cb10"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"
    res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-10", "--json"]
    )
    _assert_clean_scan_cli(res)
    _assert_negative_run_record(camp_dir, "CB-10")


@pytest.mark.qa_existing
async def test_t2_cb11_ambiguity_mode_pauses_and_contradictory_mode_preserved(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """CB-11: Ambiguity pauses in waiting_for_input & contradictory preserves contradictions."""
    lab_amb = LabStack(fixture_mode="ambiguity").start()
    try:
        env_amb = qa_env_factory(extra_env=lab_amb.env_vars(), name="cb11_amb")
        async with env_amb.async_client(timeout=35.0) as aclient:
            sub = await aclient.post(
                "/api/tasks",
                json={
                    "query": "Check alarms and work orders for bomba 34",
                    "facility_id": "facility-a",
                    "read_only": True,
                },
            )
            assert sub.status_code == 201
            run_id = str(sub.json()["run_id"])
            snap_wait = await _poll_task_terminal(aclient, run_id)
            assert snap_wait["run"]["status"] == "waiting_for_input"
            assert "Ambiguous asset bomba 34" in str(snap_wait["run"]["required_action"])

            res = await aclient.post(
                f"/api/tasks/{run_id}/resume",
                json={"human_input": {"choice": "area-1"}},
            )
            assert res.status_code == 200
            snap_done = await _poll_task_terminal(aclient, run_id)
            assert snap_done["run"]["status"] == "succeeded"
            assert "ALM-3401" in str(snap_done["result"]["answer"])
    finally:
        lab_amb.stop()

    lab_con = LabStack(fixture_mode="contradictory").start()
    try:
        env_con = qa_env_factory(extra_env=lab_con.env_vars(), name="cb11_con")
        async with env_con.async_client(timeout=35.0) as aclient:
            sub_c = await aclient.post(
                "/api/tasks",
                json={
                    "query": "Check bomba 34 alarms and work orders",
                    "facility_id": "facility-a",
                    "allowed_areas": ["area-1"],
                    "read_only": True,
                },
            )
            assert sub_c.status_code == 201
            snap_c = await _poll_task_terminal(aclient, str(sub_c.json()["run_id"]))
            assert snap_c["run"]["status"] == "partial"
            result = snap_c.get("result") or {}
            assert len(result.get("contradictions", [])) >= 1
            eff = (await aclient.get(f"{lab_con.effect_sim_url}/api/effects/state")).json()
            assert eff["total_applied"] == 0
    finally:
        lab_con.stop()


@pytest.mark.qa_existing
def test_t2_cb11_strictly_zero_write_operations_on_scada_and_maintenance(
    qa_lab_env: IsolatedQAEnv,
) -> None:
    """CB-11: Lab SCADA & Maintenance apps reject all mutating HTTP verbs (405) & 0 effects."""
    assert qa_lab_env.lab_stack is not None
    with httpx.Client(timeout=10.0) as client:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            r_scada = client.request(
                method, f"{qa_lab_env.lab_stack.scada_url}/api/alarms", json={}
            )
            assert r_scada.status_code == 405
            r_maint = client.request(
                method, f"{qa_lab_env.lab_stack.maintenance_url}/api/work_orders", json={}
            )
            assert r_maint.status_code == 405

        eff = client.get(f"{qa_lab_env.lab_stack.effect_sim_url}/api/effects/state").json()
        assert eff["total_applied"] == 0


@pytest.mark.qa_existing
async def test_t2_cb12_stale_data_and_transient_503_down_degraded_handling(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """CB-12: Stale telemetry rejects stale/bad records & 503 down SCADA degrades cleanly."""
    lab_stale = LabStack(fixture_mode="stale").start()
    try:
        env_s = qa_env_factory(extra_env=lab_stale.env_vars(), name="cb12_stale")
        async with env_s.async_client(timeout=35.0) as aclient:
            await aclient.patch("/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"})
            turn_s = await trigger_and_wait_turn(
                aclient,
                "thr_bot_ops",
                "Check bomba 34 alarms and readings in SCADA and maintenance",
                timeout=35.0,
            )
            assert turn_s.assistant_message is not None
            meta_s = turn_s.assistant_message.get("metadata") or {}
            partial_str = json.dumps(meta_s.get("partial_evidence", []))
            assert "RDG-STALE-01" in partial_str
            assert "RDG-BAD-01" in partial_str
    finally:
        lab_stale.stop()

    lab_down = LabStack(fixture_mode="down").start()
    try:
        env_d = qa_env_factory(extra_env=lab_down.env_vars(), name="cb12_down")
        async with env_d.async_client(timeout=35.0) as aclient:
            await aclient.patch("/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"})
            turn_d = await trigger_and_wait_turn(
                aclient,
                "thr_bot_ops",
                "Check bomba 34 alarms and readings in SCADA and maintenance",
                timeout=35.0,
            )
            assert turn_d.assistant_message is not None
            meta_d = turn_d.assistant_message.get("metadata") or {}
            assert meta_d.get("verdict") != "verified", (
                f"Mode 'down' falsely returned verified: {turn_d.assistant_message}"
            )
    finally:
        lab_down.stop()


@pytest.mark.qa_existing
async def test_t2_cb12_auth_expired_401_pause_and_resume_without_duplicating_effect_sim(
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """CB-12: 401 auth_expired pauses with ApprovalCard and resumes cleanly with 0 extra effects."""
    lab = _ControllableLabStack(scada_fixture_mode="auth_expired").start()
    try:
        env = qa_env_factory(extra_env=lab.env_vars(), name="cb12_auth_exp")
        async with env.async_client(timeout=40.0) as aclient:
            await aclient.patch("/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"})

            pause_turn = await trigger_and_wait_turn(
                aclient,
                "thr_bot_ops",
                "Check bomba 34 alarms and readings in SCADA and maintenance",
                terminal_events=("hitl.approval.requested",),
                timeout=35.0,
            )
            assert isinstance(pause_turn.terminal_event.data, dict)
            appr_payload = pause_turn.terminal_event.data["payload"]["approval"]
            appr_id = str(appr_payload["id"])
            run_id = str(appr_payload["arguments"]["run_id"])

            lab.scada_state.set_mode("default")
            resumed_frames: list[SseFrame] = []
            resumed_turn_holder: dict[str, str] = {}
            sse_conn = asyncio.Event()

            async def _listen_resumed() -> None:
                resumed_turn_id: str | None = None
                async for frame in iter_sse_events(aclient, timeout=35.0, on_connected=sse_conn):
                    resumed_frames.append(frame)
                    if not isinstance(frame.data, dict):
                        continue
                    ev = frame.event_type or frame.event
                    if ev == "turn.started" and frame.data.get("thread_id") == "thr_bot_ops":
                        resumed_turn_id = str(frame.data.get("turn_id"))
                        resumed_turn_holder["id"] = resumed_turn_id
                    if (
                        resumed_turn_id is not None
                        and ev == "message.completed"
                        and frame.data.get("turn_id") == resumed_turn_id
                    ):
                        return

            task = asyncio.create_task(_listen_resumed())
            try:
                await asyncio.wait_for(sse_conn.wait(), timeout=5.0)
                res_resp = await aclient.post(
                    f"/api/v1/approvals/{appr_id}/resolve",
                    json={"decision": "allow_once"},
                )
                assert res_resp.status_code == 200
                await asyncio.wait_for(task, timeout=35.0)
            finally:
                if not task.done():
                    task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

            resumed_tid = resumed_turn_holder.get("id")
            assert resumed_tid, f"Missing resumed turn_id in SSE frames: {resumed_frames!r}"
            completed_frame = next(
                f
                for f in reversed(resumed_frames)
                if (f.event_type or f.event) == "message.completed"
                and isinstance(f.data, dict)
                and f.data.get("thread_id") == "thr_bot_ops"
                and f.data.get("turn_id") == resumed_tid
            )
            assert isinstance(completed_frame.data, dict)
            resumed_msg = completed_frame.data["payload"]["message"]
            assert resumed_msg["status"] == "done"
            assert resumed_msg["sender_bot_id"] == "bot_ops"
            assert "ALM-3401" in str(resumed_msg["content"])
            assert "WO-3408" in str(resumed_msg["content"])
            resumed_meta = resumed_msg.get("metadata") or {}
            assert resumed_meta.get("verdict") == "verified"
            assert resumed_meta.get("lane") == "industrial"

            bots_after = (await aclient.get("/api/v1/bots")).json()["bots"]
            bot_ops_after = next(b for b in bots_after if b["id"] == "bot_ops")
            assert bot_ops_after["status_state"] == "idle"

            task_snap = (await aclient.get(f"/api/tasks/{run_id}")).json()
            assert task_snap["run"]["status"] == "succeeded"

            eff = (await aclient.get(f"{lab.effect_sim_url}/api/effects/state")).json()
            assert eff["total_applied"] == 0
    finally:
        lab.stop()


@pytest.mark.qa_existing
def test_t2_cb12_oversize_attachment_413_leaves_zero_disk_or_db_artifacts(
    qa_env: IsolatedQAEnv,
) -> None:
    """CB-12: Attachment >25 MiB returns 413 and leaves 0 files on disk or DB rows."""
    uploads_dir = qa_env.tmp_dir / "uploads"
    before_files = set(uploads_dir.iterdir()) if uploads_dir.is_dir() else set()
    with qa_env.client(timeout=30.0) as client:
        before_lib = len(client.get("/api/v1/bots/bot_chief/library").json()["items"])
        oversize = client.post(
            "/api/v1/attachments",
            params={"filename": "too_big.bin"},
            headers={"Content-Type": "application/octet-stream"},
            content=_iter_fixed_bytes(_MAX_ATTACHMENT_BYTES + 1),
        )
        assert oversize.status_code == 413
        assert str(_MAX_ATTACHMENT_BYTES) in oversize.text

        after_lib = len(client.get("/api/v1/bots/bot_chief/library").json()["items"])
        assert after_lib == before_lib

    after_files = set(uploads_dir.iterdir()) if uploads_dir.is_dir() else set()
    assert after_files == before_files


@pytest.mark.qa_existing
def test_t2_cb13_verify_n3_linux_exit_2_and_disallowed_llm_origin_exit_2(
    qa_cli_runner: QACliRunner,
) -> None:
    """CB-13: Disallowed non-local LLM origin & active egress fail with exit 2; PENDING != pass."""
    bad_llm = qa_cli_runner.run_module(
        "src.n3_probe",
        ["--strict", "--json", "--llm-origin", "http://example.com"],
    )
    assert bad_llm.returncode == 2
    bad_json = bad_llm.json_stdout()
    assert any(c.get("status") == "fail" for c in bad_json.get("checks", []))

    probe = qa_cli_runner.run_module("src.n3_probe", ["--json"]).json_stdout()
    if probe["overall_status"] != "READY":
        strict_probe = qa_cli_runner.run_module("src.n3_probe", ["--strict", "--json"])
        assert strict_probe.returncode != 0

        script_res = qa_cli_runner.run_command(["bash", "scripts/verify_n3_linux.sh"])
        assert script_res.returncode in {1, 2}
        if script_res.returncode == 2:
            assert "outbound network block is not active" in (
                script_res.stdout + script_res.stderr
            ).lower()


@pytest.mark.qa_megaplan
def test_t2_megaplan_cb13_pending_n3_never_treated_as_pass(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """CB-13 Megaplan: PENDING_N3_LINUX_ENV / PENDING_LOCAL_LLM never passes CB-13 linux_real."""
    camp_dir = tmp_path / "camp_t2_cb13"
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
    res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-13", "--json"]
    )
    _assert_clean_scan_cli(res)

    n3_probe = qa_cli_runner.run_module("src.n3_probe", ["--json"]).json_stdout()
    if n3_probe["overall_status"] != "READY":
        latest = _assert_negative_run_record(camp_dir, "CB-13")
        assert bool(str(latest.get("blocked_reason") or "").strip()), (
            f"Expected non-empty blocked_reason for CB-13 when PENDING: {latest!r}"
        )
    else:
        assert res.returncode == 0
        records = _load_megaplan_run_records(camp_dir)
        cb13 = [r for r in records if r.get("case_id") == "CB-13"]
        assert cb13 and cb13[-1]["passed"] is True
