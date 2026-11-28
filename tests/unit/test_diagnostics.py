"""Unit & API tests for backend/frontend failure diagnostics and telemetry."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from src.web.app import create_app
from src.web.diagnostics import scrub_query_string, scrub_url


def test_scrub_query_string_and_url_redacts_tokens() -> None:
    qs = scrub_query_string("token=mut_secret123&bot_id=bot_chief&cap_token=abc999")
    assert "mut_secret123" not in qs
    assert "abc999" not in qs
    assert "bot_id=bot_chief" in qs

    clean = scrub_url("https://example.com/app?token=mut_topsecret&tab=chat#top")
    assert "mut_topsecret" not in clean
    assert "tab=chat" in clean


def test_diagnostics_captures_http_4xx_client_error_and_sse_error(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "diag.sqlite3")
    with TestClient(app) as client:
        # 1. Successful request receives X-Request-Id and is not counted as failure
        ok_resp = client.get("/health")
        assert ok_resp.status_code == 200
        assert ok_resp.headers.get("x-request-id", "").startswith("req_")

        # 2. HTTP 404 is recorded in failures with scrubbed query string
        missing_resp = client.get(
            "/api/v1/threads/nonexistent_thread/messages?token=mut_should_not_leak"
        )
        assert missing_resp.status_code == 404
        req_id = missing_resp.headers.get("x-request-id")
        assert req_id

        # 3. Frontend client error beacon accepted and redacted
        beacon = client.post(
            "/api/v1/diagnostics/client-error",
            json={
                "kind": "api_http_error",
                "message": "Bot not found (Bearer sk-secret999999)",
                "url": "/api/v1/bots/nonexistent_bot?token=mut_should_not_leak",
                "method": "GET",
                "status_code": 404,
                "request_id": req_id,
            },
        )
        assert beacon.status_code == 202
        assert beacon.json()["accepted"] is True

        # 4. EventBus error event automatically recorded
        app.state.event_bus.publish(
            "bot.presence",
            {"state": "error", "subtext": "Simulated runner failure"},
            bot_id="bot_chief",
        )

        # 5. Summary & failures endpoints return correlated records without leaking tokens
        summary = client.get("/api/v1/diagnostics/summary")
        assert summary.status_code == 200
        body = summary.json()
        assert body["total_failures"] >= 3
        assert body["failures_by_source"]["backend_http"] >= 1
        assert body["failures_by_source"]["frontend"] >= 1
        assert body["failures_by_source"]["sse_event"] >= 1

        correlated = client.get(f"/api/v1/diagnostics/failures?request_id={req_id}")
        assert correlated.status_code == 200
        items = correlated.json()["failures"]
        assert len(items) == 2
        sources = {item["source"] for item in items}
        assert sources == {"backend_http", "frontend"}

        # 6. Verify JSONL files on disk never contain leaked token or secret
        failures_file = tmp_path / "logs" / "failures.jsonl"
        requests_file = tmp_path / "logs" / "requests.jsonl"
        assert failures_file.exists()
        assert requests_file.exists()
        raw_failures = failures_file.read_text(encoding="utf-8")
        raw_requests = requests_file.read_text(encoding="utf-8")
        assert "mut_should_not_leak" not in raw_failures
        assert "mut_should_not_leak" not in raw_requests
        assert "sk-secret999999" not in raw_failures
        # Every line is valid JSON
        for line in raw_failures.splitlines():
            json.loads(line)


def test_diagnostics_endpoints_respect_web_token_auth(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "diag_auth.sqlite3", web_token="super-secret-web-tok")
    with TestClient(app) as client:
        assert client.get("/api/v1/diagnostics/summary").status_code == 401
        assert (
            client.post("/api/v1/diagnostics/client-error", json={"kind": "test", "message": "x"})
            .status_code
            == 401
        )
        authed = client.get(
            "/api/v1/diagnostics/summary",
            headers={"Authorization": "Bearer super-secret-web-tok"},
        )
        assert authed.status_code == 200


def test_rfb_input_gate_handles_extended_clipboard_negative_length() -> None:
    import struct

    from src.web.v1.rfb_gate import RfbInputGate

    gate = RfbInputGate()
    # Extended Clipboard caps announcement: msg 0x06, 3 pad bytes, signed length -8, 8-byte payload
    caps_payload = struct.pack("!II", 0x01000001, 0)  # caps + text format
    ext_clip_caps = b"\x06\x00\x00\x00" + struct.pack("!i", -len(caps_payload)) + caps_payload
    pointer_event = struct.pack("!BBHH", 0x05, 1, 100, 200)
    key_event = struct.pack("!BBHI", 0x04, 1, 0, 0x0061)

    # Read-only mode: caps passes through without wedging; pointer & key are dropped cleanly
    out_ro = gate.feed(ext_clip_caps + pointer_event + key_event, allow_input=False)
    assert out_ro == ext_clip_caps
    assert gate.buffered_bytes == 0
    assert gate.dropped_input_events == 2

    # Takeover mode: subsequent pointer & key events flow immediately
    out_rw = gate.feed(pointer_event + key_event, allow_input=True)
    assert out_rw == pointer_event + key_event
    assert gate.buffered_bytes == 0


def test_long_quoted_curl_command_not_blocked_by_120_char_summary_truncation(
    tmp_path: Path,
) -> None:
    from src.contracts.envelope import Lane
    from src.web.live_browser import LiveBrowserController
    from src.web.stub import InMemoryCoordinatorStub
    from src.web.v1.events import EventBus
    from src.web.v1.runner import AgentTurnRunner
    from src.web.v1.store import WorkspaceStore
    from src.web.workspace import parse_agy_stream_event

    long_cmd = (
        'curl -s -X POST http://127.0.0.1:8000/api/browser/action '
        '-H "Content-Type: application/json" '
        "-d '{\"type\":\"navigate\",\"url\":\"https://controlnautas.com/producto/tzone-tht02\"}'"
    )
    assert len(long_cmd) > 120
    ev = parse_agy_stream_event(
        json.dumps(
            {
                "event": "step_update",
                "step_update": {
                    "step_index": 5,
                    "state": "ACTIVE",
                    "step_type": "tool",
                    "tool_name": "run_command",
                    "tool_info": {"parameters": {"CommandLine": json.dumps(long_cmd)}},
                },
            }
        )
    )
    assert ev is not None
    assert ev["command"] == long_cmd
    assert len(ev["summary"]) <= 120

    store = WorkspaceStore(db_path=tmp_path / "runner.sqlite3")
    bus = EventBus(store=store)
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    try:
        allowed, reason = runner._gate_mid_turn_tool(
            bot_id="bot_browser",
            turn_id="trn_test_long",
            lane=Lane.GENERAL,
            tool_name="run_command",
            category="terminal",
            summary=ev["summary"],
            command=ev["command"],
        )
        assert allowed is True, f"Expected allowed, got: {reason}"
        assert reason is None
    finally:
        bus.close()
        store.close()
