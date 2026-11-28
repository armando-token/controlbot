"""Tier-5 unit hardening tests for Runtime, Web, Engine, Redaction, SSE & Watchdog."""

from __future__ import annotations

import asyncio
import base64
import json
import time as std_time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from src.adapters.config import FacilityConfig
from src.contracts.envelope import Lane, VerdictState
from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.engine.policy_gateway import (
    PolicyGateway,
    PolicyRequest,
    default_studio_policy_set,
    safety_floor,
)
from src.storage.redaction import (
    contains_unredacted_secret_strict,
    redact_payload_strict,
    redact_string_strict,
)
from src.web.diagnostics import (
    ClientErrorPayload,
    DiagnosticsRecorder,
    scrub_query_string,
    scrub_url,
)
from src.web.live_browser import LiveBrowserController
from src.web.stub import InMemoryCoordinatorStub
from src.web.v1.events import EventBus, parse_event_seq, scrub_v1_payload
from src.web.v1.runner import AgentTurnRunner
from src.web.v1.schemas import MessageCreateRequest, contains_sensitive_scope_secret
from src.web.v1.store import WorkspaceStore
from src.web.workspace import _scrub_text, parse_agy_stream_event

pytestmark = [pytest.mark.n1, pytest.mark.tier5]

_ALL_SECRET_SAMPLES: tuple[tuple[str, str, str], ...] = (
    ("openai_sk", "sk-proj-LEAKED999999999999", "sk-proj-LEAKED999999999999"),
    ("underscore_sk", "area_sk-1234567890abcdef", "sk-1234567890abcdef"),
    ("ghp", "ghp_1234567890abcdef", "ghp_1234567890abcdef"),
    ("ghs", "ghs_1234567890abcdef", "ghs_1234567890abcdef"),
    ("github_pat", "github_pat_1234567890abcdef1234", "github_pat_1234567890abcdef1234"),
    ("google_api", "AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123", "AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123"),
    ("aws_akia", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("slack", "xoxb-123456789-987654321-abcdef12", "xoxb-123456789-987654321-abcdef12"),
    (
        "jwt",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig12345678",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig12345678",
    ),
    ("auth_qs", "https://example.com/ws?auth=querySecretVal&tab=chat", "querySecretVal"),
    ("url_userinfo", "https://alice:hunter2@example.com/ws", "hunter2"),
)


@pytest.mark.parametrize(("name", "raw_input", "leak_needle"), _ALL_SECRET_SAMPLES)
def test_multi_provider_secret_redaction_across_unit_surfaces(
    tmp_path: Path,
    name: str,
    raw_input: str,
    leak_needle: str,
) -> None:
    assert contains_unredacted_secret_strict(raw_input) is True, name

    redacted_str = redact_string_strict(raw_input)
    assert leak_needle not in redacted_str, name
    assert "alice" not in redacted_str, name
    assert REDACTED_PLACEHOLDER in redacted_str
    assert contains_unredacted_secret_strict(redacted_str) is False, name

    redacted_obj = redact_payload_strict({"msg": raw_input, "nested": [raw_input]})
    dumped_obj = json.dumps(redacted_obj)
    assert leak_needle not in dumped_obj, name
    assert contains_unredacted_secret_strict(redacted_obj) is False, name

    v1_scrubbed = scrub_v1_payload(
        {
            "msg": raw_input,
            "fields": [{"name": "pw", "label": "Password", "secret": True}],
        }
    )
    assert leak_needle not in json.dumps(v1_scrubbed), name
    assert v1_scrubbed["fields"][0]["secret"] is True

    ws_scrubbed = _scrub_text(raw_input)
    assert leak_needle not in ws_scrubbed, name

    rec = DiagnosticsRecorder(logs_dir=tmp_path / f"logs_{name}")
    rec.record_failure(
        source="backend_http",
        kind="http_5xx",
        message=f"Failed with {raw_input}",
        path=f"/ws?auth={leak_needle}",
        query=f"auth={leak_needle}&ok=1",
        detail={"raw": raw_input},
    )
    rec.record_client_error(
        payload=ClientErrorPayload(
            kind="ui_error",
            message=f"UI error {raw_input}",
            url=(
                raw_input
                if raw_input.startswith("http")
                else f"https://example.com/?auth={leak_needle}"
            ),
            page_url=f"https://alice:hunter2@example.com/app?auth={leak_needle}",
            stack=raw_input,
        )
    )
    failures_txt = rec.failures_log_path.read_text(encoding="utf-8")
    frontend_txt = rec.frontend_log_path.read_text(encoding="utf-8")
    assert leak_needle not in failures_txt, name
    assert leak_needle not in frontend_txt, name
    assert "hunter2" not in failures_txt, name
    assert "alice:" not in failures_txt, name


def test_scrub_url_and_query_string_redact_userinfo_and_auth() -> None:
    cleaned = scrub_url(
        "https://alice:hunter2@example.com/ws?auth=jwt_secret_123&token=tok_abc&q=sk-proj-INLINE1234567890"
    )
    assert "alice" not in cleaned
    assert "hunter2" not in cleaned
    assert "jwt_secret_123" not in cleaned
    assert "tok_abc" not in cleaned
    assert "sk-proj-INLINE1234567890" not in cleaned
    assert "example.com/ws" in cleaned

    qs = scrub_query_string("auth=secret_auth_val&q=AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123&tab=chat")
    assert "secret_auth_val" not in qs
    assert "AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123" not in qs
    assert "tab=chat" in qs


@pytest.mark.parametrize(
    "secret_token",
    [
        "sk-1234567890abcdef",
        "area_sk-1234567890abcdef",
        "fac_sk-1234567890abcdef",
        "my_sk-proj-1234567890abcdef",
        "ghp_1234567890abcdef",
        "ghs_1234567890abcdef",
        "github_pat_1234567890abcdef1234",
        "AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123",
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-123456789-987654321-abcdef12",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig12345678",
    ],
)
def test_scope_secret_detection_rejects_underscore_and_provider_tokens(
    tmp_path: Path,
    secret_token: str,
) -> None:
    assert contains_sensitive_scope_secret(secret_token) is True

    with pytest.raises(ValidationError):
        MessageCreateRequest(content="Check pump 34", facility_id=secret_token)
    with pytest.raises(ValidationError):
        MessageCreateRequest(content="Check pump 34", allowed_areas=[secret_token])

    store = WorkspaceStore(tmp_path / "scope_ws.sqlite3")
    bus = EventBus(db_path=store.db_path)
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    try:
        with pytest.raises(ValueError, match="sensitive credentials"):
            runner._resolve_runtime_scope(facility_id=secret_token)
        with pytest.raises(ValueError, match="sensitive credentials"):
            runner._resolve_runtime_scope(allowed_areas=[secret_token])
    finally:
        bus.close()
        store.close()


@pytest.mark.parametrize("safe_id", ["task-1", "disk-1", "area-1", "facility-b", "flask-app-1"])
def test_scope_secret_detection_accepts_normal_ids(safe_id: str) -> None:
    assert contains_sensitive_scope_secret(safe_id) is False
    req = MessageCreateRequest(content="Check", facility_id=safe_id, allowed_areas=[safe_id])
    assert req.facility_id == safe_id
    assert req.allowed_areas == [safe_id]


async def test_runner_thread_turn_uses_allowed_areas_for_homonymous_routing(
    tmp_path: Path,
) -> None:
    fac_cfg = FacilityConfig.model_validate(
        {
            "facility_id": "facility-homonym",
            "facility_name": "Dual Area Plant",
            "areas": {
                "area-1": {"display_name": "Area 1"},
                "area-2": {"display_name": "Area 2"},
            },
            "apps": {
                "scada": {
                    "app_id": "scada",
                    "origin": "http://127.0.0.1:8101",
                    "read_only": True,
                    "adapter_type": "scada",
                }
            },
            "assets": [
                {
                    "asset_id": "bomba-34-a1",
                    "canonical_label": "Bomba 34",
                    "area": "area-1",
                    "aliases": ["pump 34", "bomba 34"],
                    "source_ids": {"scada": "P-34-A1"},
                },
                {
                    "asset_id": "bomba-34-a2",
                    "canonical_label": "Bomba 34",
                    "area": "area-2",
                    "aliases": ["pump 34", "bomba 34"],
                    "source_ids": {"scada": "P-34-A2"},
                },
            ],
        }
    )

    store = WorkspaceStore(tmp_path / "homonym.sqlite3")
    bus = EventBus(db_path=store.db_path)
    coord = InMemoryCoordinatorStub()
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=coord,
        uploads_dir=tmp_path / "uploads",
        facility_config=fac_cfg,
    )
    try:
        store.update_bot("bot_ops", {"engine_id": "controlbot_runtime"})

        # 1. Explicitly area-scoped turn routes directly without NEEDS_CLARIFICATION
        msg_scoped = store.create_message(
            thread_id="thr_bot_ops",
            sender_type="user",
            sender_bot_id=None,
            sender_name="Operator",
            content="Check Pump 34 alarms",
            metadata={"facility_id": "facility-homonym", "allowed_areas": ["area-1"]},
        )
        await runner._run_thread_turn(
            thread_id="thr_bot_ops",
            turn_id="trn_scoped_1",
            user_message=msg_scoped,
            include_browser_context=None,
            model_id=None,
            thinking_level=None,
            skill_ids=[],
            skip_auto_review=True,
            facility_id="facility-homonym",
            allowed_areas=["area-1"],
        )
        msgs, _ = store.list_thread_messages("thr_bot_ops")
        bot_msgs = [m for m in msgs if m["sender_type"] == "bot"]
        assert bot_msgs
        latest_meta = bot_msgs[-1].get("metadata") or {}
        assert latest_meta.get("verdict") != VerdictState.NEEDS_CLARIFICATION.value
        assert latest_meta.get("lane") == Lane.INDUSTRIAL.value
        snaps = coord.list_task_snapshots()
        assert len(snaps) == 1
        assert snaps[0].task.scope.allowed_areas == ("area-1",)

        # 2. Unscoped turn on homonymous Pump 34 still asks for clarification
        msg_unscoped = store.create_message(
            thread_id="thr_bot_ops",
            sender_type="user",
            sender_bot_id=None,
            sender_name="Operator",
            content="Check Pump 34 alarms",
        )
        await runner._run_thread_turn(
            thread_id="thr_bot_ops",
            turn_id="trn_unscoped_2",
            user_message=msg_unscoped,
            include_browser_context=None,
            model_id=None,
            thinking_level=None,
            skill_ids=[],
            skip_auto_review=True,
        )
        msgs2, _ = store.list_thread_messages("thr_bot_ops")
        bot_msgs2 = [m for m in msgs2 if m["sender_type"] == "bot"]
        latest_meta2 = bot_msgs2[-1].get("metadata") or {}
        assert latest_meta2.get("verdict") == VerdictState.NEEDS_CLARIFICATION.value
    finally:
        bus.close()
        store.close()


async def test_event_bus_overflow_monotonic_ids_and_close_guard(tmp_path: Path) -> None:
    bus = EventBus(subscriber_queue_size=2)
    frames: list[str] = []

    async def _consume() -> None:
        async for frame in bus.stream_sse(keepalive_seconds=5.0):
            frames.append(frame)
            if len(frames) >= 5:
                break

    consumer_task = asyncio.create_task(_consume())
    await asyncio.sleep(0.02)
    for i in range(5):
        bus.publish("test.ev", {"n": i + 1})
    await asyncio.sleep(0.02)
    # Publish a post-resync event so stream has >=5 frames without re-emitting seq < latest_seq
    bus.publish("test.ev", {"n": 6})
    await asyncio.wait_for(consumer_task, timeout=2.0)

    # First two frames are ': connected' and 'retry: 2000'
    assert frames[0] == ": connected\n\n"
    assert frames[1] == "retry: 2000\n\n"

    # Extract id: lines across all SSE frames -> must be strictly monotonic and never regress
    emitted_seqs: list[int] = []
    saw_resync = False
    resync_latest_seq: int | None = None
    for frame in frames[2:]:
        if '"stream.resync"' in frame:
            saw_resync = True
            assert not frame.startswith("id:"), (
                f"stream.resync must not emit backwards id: {frame!r}"
            )
            data_line = next(ln for ln in frame.splitlines() if ln.startswith("data:"))
            resync_obj = json.loads(data_line[5:].strip())
            resync_latest_seq = int(resync_obj["payload"]["latest_seq"])
        for line in frame.splitlines():
            if line.startswith("id:"):
                raw_id = line.split(":", 1)[1].strip()
                seq = parse_event_seq(raw_id)
                assert seq is not None
                if resync_latest_seq is not None:
                    assert seq >= resync_latest_seq, (
                        f"Emitted stale seq {seq} < resync latest_seq {resync_latest_seq}"
                    )
                emitted_seqs.append(seq)
    assert saw_resync is True
    assert resync_latest_seq == 5
    assert 4 not in emitted_seqs
    assert emitted_seqs == sorted(emitted_seqs)
    assert len(emitted_seqs) == len(set(emitted_seqs))

    # publish() after bus.close() must not mutate seq or fail
    seq_before = bus._seq
    bus.close()
    closed_ev = bus.publish("test.after_close", {"ok": True})
    assert closed_ev.get("dropped_closed") is True
    assert bus._seq == seq_before

    # publish() after store.close() even if bus.close() wasn't called must not crash
    store = WorkspaceStore(tmp_path / "closed_store.sqlite3")
    bus_st = EventBus(store=store)
    store.close()
    ev_after_store_close = bus_st.publish("test.after_store_close", {"ok": True})
    assert ev_after_store_close.get("dropped_closed") is True
    bus_st.close()


@pytest.mark.parametrize(
    "cmd",
    [
        "shred -u /etc/passwd",
        "shred -fz /dev/sda",
        "truncate -s 0 /etc/passwd",
        "truncate -s0 /var/log/syslog",
        "truncate --size=0 ./important.db",
        "mkfs.ext4 /dev/sda1",
        "wipefs -a /dev/sda",
        "chmod -R 000 /",
        "chmod --recursive 000 /etc",
        "chmod -R a-rwx /var",
    ],
)
def test_safety_floor_blocks_destructive_non_rm_commands_even_with_general_writes(
    cmd: str,
) -> None:
    violation = safety_floor("run_command", {"command": cmd})
    assert violation is not None, f"Expected safety_floor violation for {cmd!r}"

    gw = PolicyGateway(default_studio_policy_set(allow_general_writes=True))
    dec = gw.decide(
        PolicyRequest(
            actor_id="bot_browser",
            actor_role="bot",
            lane=Lane.GENERAL,
            tool_id="run_command",
            action_kind="write",
            arguments={"command": cmd},
        )
    )
    assert dec.allowed is False
    assert dec.safety_violation is not None


def test_watchdog_handles_empty_or_invalid_vnc_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import watchdog as wd

    assert wd._parse_vnc_port(None) == 5901
    assert wd._parse_vnc_port("") == 5901
    assert wd._parse_vnc_port("   ") == 5901
    assert wd._parse_vnc_port("not-a-port") == 5901
    assert wd._parse_vnc_port("99999") == 5901
    assert wd._parse_vnc_port("5902") == 5902

    # Run one loop iteration of main() in isolated logs dir without touching live logs
    monkeypatch.setattr(wd, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setattr(wd, "WATCHDOG_LOG", tmp_path / "logs" / "watchdog.jsonl")
    monkeypatch.setattr(wd, "FAILURES_LOG", tmp_path / "logs" / "failures.jsonl")
    monkeypatch.setattr(wd, "_probe_http", lambda url, timeout=4.0: (True, 200, 1.0, None))
    monkeypatch.setattr(wd, "_probe_tcp", lambda host, port, timeout=2.0: (True, None))
    monkeypatch.setattr(wd, "_STOP", False)

    def _stop_after_sleep(_sec: float) -> None:
        wd._STOP = True

    monkeypatch.setattr(std_time, "sleep", _stop_after_sleep)
    monkeypatch.setenv("GROKBOT_VNC_PORT", "")
    rc = wd.main()
    assert rc == 0
    first_line = (tmp_path / "logs" / "watchdog.jsonl").read_text(encoding="utf-8").splitlines()[0]
    snap = json.loads(first_line)
    assert snap["bot_vnc_port"] == 5901


# ---------------------------------------------------------------------------
# Wave 2 Adversarial Regression Tests (Findings 1–5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_name",
    [
        "sh",
        "zsh",
        "dash",
        "cmd",
        "run_cmd",
        "spawn_process",
        "subprocess",
        "python",
        "python3",
        "eval_tool",
        "script",
        "read_workspace_info",
    ],
)
def test_non_terminal_tool_names_with_command_enforce_pty_write_and_safety_floor(
    tmp_path: Path,
    tool_name: str,
) -> None:
    store = WorkspaceStore(tmp_path / "w2_cmd_gate.sqlite3")
    bus = EventBus(db_path=store.db_path)
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    try:
        # 1. With app_pty=False, any tool with a command (or shell/interpreter name) is blocked
        store.update_connected_app("app_pty", {"enabled": False})
        pending: dict[str, dict[str, object]] = {}
        state_by_call: dict[str, dict[str, object]] = {}
        unnamed: dict[str, str] = {}
        allowed_off, reason_off, meta_off = runner.gate_agy_stream_tool_event(
            ev={
                "type": "tool",
                "step_index": 1,
                "state": "COMPLETED",
                "tool_name": tool_name,
                "summary": "checking workspace status",
                "command": "echo safe",
            },
            bot_id="bot_chief",
            turn_id="trn_pty_off",
            lane=Lane.GENERAL,
            pending_syntax_tools=pending,
            tool_state_by_call=state_by_call,
            active_unnamed_calls_by_tool=unnamed,
        )
        assert allowed_off is False
        assert reason_off is not None and "Terminal (PTY)" in reason_off
        assert meta_off["category"] == "terminal"

        # 2. With app_pty=True, destructive command is passed in policy_args and blocked as write
        store.update_connected_app("app_pty", {"enabled": True})
        allowed_rm, reason_rm, meta_rm = runner.gate_agy_stream_tool_event(
            ev={
                "type": "tool",
                "step_index": 2,
                "state": "COMPLETED",
                "tool_name": tool_name,
                "summary": "checking workspace status",
                "command": "rm -rf /",
            },
            bot_id="bot_chief",
            turn_id="trn_pty_rm",
            lane=Lane.GENERAL,
            pending_syntax_tools={},
            tool_state_by_call={},
            active_unnamed_calls_by_tool={},
        )
        assert allowed_rm is False
        assert reason_rm is not None and "PolicyGateway" in reason_rm
        assert meta_rm["category"] == "terminal"
        audit = runner.policy_audit_log[-1]
        assert audit["tool_id"] == tool_name
        assert audit["effective_action_kind"] == "write"
        assert audit["decision"] == "deny"
        assert "command" in audit["arguments"]
    finally:
        bus.close()
        store.close()


_HYPHEN_SECRET_SAMPLES: tuple[tuple[str, str, str], ...] = (
    ("hyphen_sk_proj", "bad-sk-proj-LEAK422SECRET123456", "sk-proj-LEAK422SECRET123456"),
    ("hyphen_sk_bare", "fac-sk-1234567890abcdef", "sk-1234567890abcdef"),
    ("hyphen_ghp", "bot-ghp_1234567890abcdef", "ghp_1234567890abcdef"),
    ("hyphen_github_pat", "pat-github_pat_1234567890abcdef1234", "github_pat_1234567890abcdef1234"),
    (
        "hyphen_google",
        "key-AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123",
        "AIzaSyDaBcdEfGhIjKlMnOpQrStUvWxYz123",
    ),
    ("hyphen_aws", "aws-AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("hyphen_slack", "slk-xoxb-123456789-987654321-abcdef12", "xoxb-123456789-987654321-abcdef12"),
    (
        "hyphen_jwt",
        "tok-eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig12345678",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig12345678",
    ),
)


@pytest.mark.parametrize(("name", "raw_input", "leak_needle"), _HYPHEN_SECRET_SAMPLES)
def test_hyphen_prefixed_secrets_redacted_and_rejected_everywhere(
    name: str,
    raw_input: str,
    leak_needle: str,
) -> None:
    from src.web.live_browser import _scrub_browser_str

    assert contains_unredacted_secret_strict(raw_input) is True, name
    assert contains_sensitive_scope_secret(raw_input) is True, name
    assert leak_needle not in redact_string_strict(raw_input), name
    assert leak_needle not in json.dumps(scrub_v1_payload({"msg": raw_input})), name
    assert leak_needle not in _scrub_text(raw_input), name
    with pytest.raises(ValidationError):
        MessageCreateRequest(content="Check", facility_id=raw_input)
    with pytest.raises(ValidationError):
        MessageCreateRequest(content="Check", allowed_areas=[raw_input])

    if raw_input.startswith(("bad-sk", "fac-sk", "bot-ghp")):
        assert leak_needle not in _scrub_browser_str(raw_input), name


def test_live_browser_scrubs_short_underscore_and_hyphen_tokens_without_false_positives() -> None:
    from src.web.live_browser import _scrub_browser_str

    assert "sk-12345678" not in _scrub_browser_str("area_sk-12345678")
    assert "sk-12345678" not in _scrub_browser_str("fac-sk-12345678")
    assert "ghp_12345678" not in _scrub_browser_str("bot-ghp_12345678")

    safe_ids = (
        "task-1",
        "disk-1",
        "area-1",
        "facility-b",
        "flask-app-1",
        "ask-me-anything-now",
    )
    for safe_id in safe_ids:
        assert contains_unredacted_secret_strict(safe_id) is False
        assert contains_sensitive_scope_secret(safe_id) is False
        assert _scrub_browser_str(safe_id) == safe_id
        assert _scrub_text(safe_id) == safe_id


@pytest.mark.parametrize(
    "cmd",
    [
        "python3 -c 'import os; os.remove(\"/etc/passwd\")'",
        "python3 -c 'import os; os.unlink(\"/etc/passwd\")'",
        "python3 -c 'import os; os.rmdir(\"/etc\")'",
        "python3 -c 'from pathlib import Path; Path(\"/etc/passwd\").unlink()'",
        "python3 -c 'import pathlib; pathlib.Path.unlink(pathlib.Path(\"/etc/passwd\"))'",
        "dd if=/dev/zero of=/etc/passwd",
        ": > /etc/passwd",
        "echo '' > /etc/passwd",
        "cat /tmp/foo >| /etc/hosts",
        "cp /dev/null /etc/passwd",
        "mv /etc/passwd /tmp/stolen",
        "chmod 000 /etc/passwd",
        "chmod a-rwx /etc/shadow",
        "shred ./secret.txt",
    ],
)
def test_safety_floor_wave2_blocks_python_unlink_and_critical_overwrites_under_general_writes(
    cmd: str,
) -> None:
    violation = safety_floor("run_command", {"command": cmd})
    assert violation is not None, f"Expected safety_floor block for {cmd!r}"

    gw = PolicyGateway(default_studio_policy_set(allow_general_writes=True))
    dec = gw.decide(
        PolicyRequest(
            actor_id="bot_browser",
            actor_role="bot",
            lane=Lane.GENERAL,
            tool_id="run_command",
            action_kind="write",
            arguments={"command": cmd},
        )
    )
    assert dec.allowed is False
    assert dec.safety_violation is not None


@pytest.mark.parametrize(
    "safe_cmd",
    [
        "echo ok >/dev/null 2>&1",
        "echo ok &>/dev/null",
        "echo ok >/dev/null#notcomment",
        "echo ok > /tmp/safe_out.txt",
        "dd if=/dev/zero of=/dev/null bs=1M count=1",
        "dd if=/dev/zero of=/tmp/work/out.img",
        "cp /etc/hosts /tmp/hosts.bak",
        "mv /tmp/a.txt /tmp/b.txt",
        "chmod 644 /tmp/file",
        "python3 -c 'import os; os.remove(\"/tmp/safe_temp.txt\")'",
        "python3 -c 'from pathlib import Path; Path(\"/tmp/safe_temp.txt\").unlink()'",
    ],
)
def test_safety_floor_wave2_preserves_benign_commands(safe_cmd: str) -> None:
    assert safety_floor("run_command", {"command": safe_cmd}) is None, safe_cmd


async def test_multi_area_allowed_areas_scoping_excludes_out_of_scope_assets(
    tmp_path: Path,
) -> None:
    from src.engine.router import LaneRouter

    fac_cfg = FacilityConfig.model_validate(
        {
            "facility_id": "facility-three-areas",
            "facility_name": "Three Area Plant",
            "areas": {
                "area-1": {"display_name": "Area 1"},
                "area-2": {"display_name": "Area 2"},
                "area-3": {"display_name": "Area 3"},
            },
            "apps": {
                "scada": {
                    "app_id": "scada",
                    "origin": "http://127.0.0.1:8101",
                    "read_only": True,
                    "adapter_type": "scada",
                }
            },
            "assets": [
                {
                    "asset_id": "bomba-34-a1",
                    "canonical_label": "Bomba 34",
                    "area": "area-1",
                    "aliases": ["pump 34", "bomba 34"],
                    "source_ids": {"scada": "P-34-A1"},
                },
                {
                    "asset_id": "bomba-34-a3",
                    "canonical_label": "Bomba 34",
                    "area": "area-3",
                    "aliases": ["pump 34", "bomba 34"],
                    "source_ids": {"scada": "P-34-A3"},
                },
            ],
        }
    )

    router = LaneRouter()
    dec = await router.route(
        "Check Pump 34 alarms",
        facility_config=fac_cfg,
        allowed_areas=["area-1", "area-2"],
    )
    assert dec.needs_clarification is False
    assert dec.lane == Lane.INDUSTRIAL

    store = WorkspaceStore(tmp_path / "multi_area.sqlite3")
    bus = EventBus(db_path=store.db_path)
    coord = InMemoryCoordinatorStub()
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=coord,
        uploads_dir=tmp_path / "uploads",
        facility_config=fac_cfg,
    )
    try:
        store.update_bot("bot_ops", {"engine_id": "controlbot_runtime"})
        msg = store.create_message(
            thread_id="thr_bot_ops",
            sender_type="user",
            sender_bot_id=None,
            sender_name="Operator",
            content="Check Pump 34 alarms",
            metadata={
                "facility_id": "facility-three-areas",
                "allowed_areas": ["area-1", "area-2"],
            },
        )
        await runner._run_thread_turn(
            thread_id="thr_bot_ops",
            turn_id="trn_multi_area_1",
            user_message=msg,
            include_browser_context=None,
            model_id=None,
            thinking_level=None,
            skill_ids=[],
            skip_auto_review=True,
            facility_id="facility-three-areas",
            allowed_areas=["area-1", "area-2"],
        )
        msgs, _ = store.list_thread_messages("thr_bot_ops")
        bot_msgs = [m for m in msgs if m["sender_type"] == "bot"]
        assert bot_msgs
        latest_meta = bot_msgs[-1].get("metadata") or {}
        assert latest_meta.get("verdict") != VerdictState.NEEDS_CLARIFICATION.value
        assert latest_meta.get("lane") == Lane.INDUSTRIAL.value
        snaps = coord.list_task_snapshots()
        assert len(snaps) == 1
        assert snaps[0].task.scope.allowed_areas == ("area-1", "area-2")
    finally:
        bus.close()
        store.close()


def test_watchdog_float_env_and_diag_report_deep_filter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import sys

    from scripts import diag_report as dr
    from scripts import watchdog as wd

    assert wd._parse_float_env(None, 15.0) == 15.0
    assert wd._parse_float_env("", 15.0) == 15.0
    assert wd._parse_float_env("   ", 15.0) == 15.0
    assert wd._parse_float_env("not-a-float", 15.0) == 15.0
    assert wd._parse_float_env("nan", 15.0) == 15.0
    assert wd._parse_float_env("inf", 15.0) == 15.0
    assert wd._parse_float_env("-5", 15.0) == 15.0
    assert wd._parse_float_env("0", 15.0) == 15.0
    assert wd._parse_float_env("2.5", 15.0) == 2.5

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    failures_path = logs_dir / "failures.jsonl"
    rows = [
        {
            "ts": "2026-11-27T00:00:00Z",
            "source": "watchdog",
            "kind": "service_down",
            "request_id": "req_old_wd",
            "message": "OLD_WATCHDOG_ALERT",
        }
    ]
    rows.extend(
        {
            "ts": f"2026-11-27T00:01:{i % 60:02d}Z",
            "source": "backend_http",
            "kind": "http_5xx",
            "request_id": f"req_{i}",
            "message": f"noise_{i}",
        }
        for i in range(250)
    )
    failures_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    monkeypatch.setattr(dr, "LOGS_DIR", logs_dir)
    monkeypatch.setattr(dr, "SERVER_LOG", tmp_path / "missing_server.log")
    monkeypatch.setattr(dr, "_probe_http", lambda url, timeout=2.5: "HTTP 200")
    monkeypatch.setattr(dr, "_probe_tcp", lambda host, port, timeout=1.5: "OPEN")
    monkeypatch.setattr(
        sys,
        "argv",
        ["diag_report.py", "--source", "watchdog", "--limit", "5"],
    )
    rc = dr.main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "OLD_WATCHDOG_ALERT" in out

    monkeypatch.setattr(
        sys,
        "argv",
        ["diag_report.py", "--request-id", "req_old_wd", "--limit", "5"],
    )
    rc2 = dr.main()
    assert rc2 == 0
    out2 = capsys.readouterr().out
    assert "OLD_WATCHDOG_ALERT" in out2


# ---------------------------------------------------------------------------
# Wave 3 Adversarial Regression Tests (Findings 1–4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("alt_key", "shadow_val"),
    [
        ("cmd", ""),
        ("cmd", "   "),
        ("command_line", ""),
        ("cmdline", "  \t "),
        ("CommandLine", ""),
        ("script", "   "),
    ],
)
def test_empty_command_does_not_shadow_fallback_command_keys(
    tmp_path: Path,
    alt_key: str,
    shadow_val: str,
) -> None:
    store = WorkspaceStore(tmp_path / "w3_shadow_cmd.sqlite3")
    bus = EventBus(db_path=store.db_path)
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    try:
        store.update_connected_app("app_pty", {"enabled": False})
        allowed_off, reason_off, meta_off = runner.gate_agy_stream_tool_event(
            ev={
                "type": "tool",
                "step_index": 1,
                "state": "COMPLETED",
                "tool_name": "custom_helper",
                "summary": "checking",
                "command": shadow_val,
                alt_key: "rm -rf /",
            },
            bot_id="bot_chief",
            turn_id="trn_w3_off",
            lane=Lane.GENERAL,
            pending_syntax_tools={},
            tool_state_by_call={},
            active_unnamed_calls_by_tool={},
        )
        assert allowed_off is False
        assert reason_off is not None and "Terminal (PTY)" in reason_off
        assert meta_off["category"] == "terminal"

        store.update_connected_app("app_pty", {"enabled": True})
        allowed_rm, reason_rm, meta_rm = runner.gate_agy_stream_tool_event(
            ev={
                "type": "tool",
                "step_index": 2,
                "state": "COMPLETED",
                "tool_name": "custom_helper",
                "summary": "checking",
                "command": shadow_val,
                alt_key: "rm -rf /",
            },
            bot_id="bot_chief",
            turn_id="trn_w3_rm",
            lane=Lane.GENERAL,
            pending_syntax_tools={},
            tool_state_by_call={},
            active_unnamed_calls_by_tool={},
        )
        assert allowed_rm is False
        assert reason_rm is not None and "PolicyGateway" in reason_rm
        assert meta_rm["category"] == "terminal"
        audit = runner.policy_audit_log[-1]
        assert audit["tool_id"] == "custom_helper"
        assert audit["effective_action_kind"] == "write"
        assert audit["decision"] == "deny"
        assert audit["arguments"].get("command") == "rm -rf /"
    finally:
        bus.close()
        store.close()


@pytest.mark.parametrize(
    "cmd",
    [
        'python3 -c \'import os; os.removedirs("/etc/passwd")\'',
        'python3 -c \'import os; os.truncate("/etc/passwd", 0)\'',
        'python3 -c \'from os import truncate; truncate("/etc/passwd", 0)\'',
        'python3 -c \'import os; os.chmod("/etc/passwd", 0)\'',
        'python3 -c \'import os; os.rename("/etc/passwd", "/tmp/x")\'',
        'python3 -c \'import os; os.replace("/etc/passwd", "/tmp/x")\'',
        'python3 -c \'import os; getattr(os, "rename")("/tmp/x", "/etc/passwd")\'',
        'python3 -c \'import shutil; shutil.move("/etc/passwd", "/tmp/x")\'',
        'python3 -c \'from pathlib import Path; Path("/etc/passwd").write_text("")\'',
        'python3 -c \'from pathlib import Path; Path("/etc/passwd").write_bytes(b"")\'',
        'python3 -c \'from pathlib import Path; Path("/etc/passwd").open("w").write("")\'',
        'python3 -c \'open("/etc/passwd", "w").write("")\'',
        'python3 -c \'open("/etc/passwd", "wb").write(b"")\'',
        'python3 -c \'open("/etc/passwd", "w+").write("")\'',
        "chmod 0 /etc/passwd",
        "chmod 00 /etc/passwd",
        "chmod a= /etc/passwd",
        "chmod ugo= /etc/passwd",
        "chmod u-rwx,g-rwx,o-rwx /etc/passwd",
        "chmod a-r /etc/passwd",
        'echo "" | tee /etc/passwd',
        "install /dev/null /etc/passwd",
        "install -t /etc /tmp/x",
        'echo "" >& /etc/passwd',
        'echo "$X" >& /etc/passwd',
        "ln -sf /dev/null /etc/passwd",
    ],
)
def test_safety_floor_wave3_blocks_sibling_python_and_shell_destructive_ops(
    cmd: str,
) -> None:
    violation = safety_floor("run_command", {"command": cmd})
    assert violation is not None, f"Expected safety_floor block for {cmd!r}"

    gw = PolicyGateway(default_studio_policy_set(allow_general_writes=True))
    dec = gw.decide(
        PolicyRequest(
            actor_id="bot_browser",
            actor_role="bot",
            lane=Lane.GENERAL,
            tool_id="run_command",
            action_kind="write",
            arguments={"command": cmd},
        )
    )
    assert dec.allowed is False
    assert dec.safety_violation is not None


@pytest.mark.parametrize(
    "safe_cmd",
    [
        "echo ok 2>&1",
        "echo ok >/dev/null 2>&1",
        "echo ok &>/dev/null",
        "echo ok >& /dev/null",
        "echo ok >& /tmp/ok.txt",
        "echo ok | tee /tmp/ok.txt",
        "echo ok | tee /dev/null",
        "install /etc/hosts /tmp/hosts.bak",
        "ln -sf /etc/hosts /tmp/hosts.link",
        "chmod 644 /tmp/ok.txt",
        'python3 -c \'open("/etc/passwd", "r").read()\'',
        'python3 -c \'open("/tmp/ok.txt", "w").write("hi")\'',
        'python3 -c \'from pathlib import Path; Path("/tmp/ok.txt").write_text("hi")\'',
        'python3 -c \'import os; os.rename("/tmp/a", "/tmp/b")\'',
        'python3 -c \'import os; os.chmod("/tmp/a", 0o644)\'',
    ],
)
def test_safety_floor_wave3_preserves_benign_commands(safe_cmd: str) -> None:
    assert safety_floor("run_command", {"command": safe_cmd}) is None, safe_cmd


async def test_live_browser_status_and_capture_frame_scrub_url_and_title(tmp_path: Path) -> None:
    class _FakePage:
        url = "http://127.0.0.1:45333/login?token=sk-proj-REALURLSECRET123456&k=area_sk-12345678"

        def is_closed(self) -> bool:
            return False

        async def title(self) -> str:
            return "Portal sk-proj-REALBROWSERSECRET12 area-sk-12345678"

        async def screenshot(self, *, type: str = "jpeg", quality: int = 72) -> bytes:
            del type, quality
            return b"\xff\xd8\xff\xe0fakejpeg"

    ctrl = LiveBrowserController(profile_root=tmp_path / "browser")
    ctrl._context = object()  # type: ignore[assignment]
    ctrl._page = _FakePage()  # type: ignore[assignment]

    st = await ctrl._unlocked_status()
    assert "sk-proj-REALURLSECRET123456" not in st["url"]
    assert "sk-12345678" not in st["url"]
    assert "sk-proj-REALBROWSERSECRET12" not in st["title"]
    assert "sk-12345678" not in st["title"]
    assert "[REDACTED]" in st["url"]
    assert "[REDACTED]" in st["title"]

    frame = await ctrl.capture_frame()
    assert frame is not None
    assert "sk-proj-REALURLSECRET123456" not in frame["url"]
    assert "sk-12345678" not in frame["url"]
    assert "sk-proj-REALBROWSERSECRET12" not in frame["title"]
    assert "sk-12345678" not in frame["title"]
    assert base64.b64decode(frame["data"]) == b"\xff\xd8\xff\xe0fakejpeg"


@pytest.mark.parametrize(
    ("token", "needle"),
    [
        ("area_sk-12345678", "sk-12345678"),
        ("area-sk-12345678", "sk-12345678"),
        ("sk-1234567890", "sk-1234567890"),
        ("sk-ant-12345678", "sk-ant-12345678"),
    ],
)
def test_short_8_to_11_char_sk_tokens_caught_across_redaction_schemas_and_diagnostics(
    tmp_path: Path,
    token: str,
    needle: str,
) -> None:
    assert contains_unredacted_secret_strict(token) is True
    assert contains_sensitive_scope_secret(token) is True
    redacted = redact_string_strict(token)
    assert needle not in redacted
    assert contains_unredacted_secret_strict(redacted) is False

    with pytest.raises(ValidationError):
        MessageCreateRequest(content="Check", facility_id=token)
    with pytest.raises(ValidationError):
        MessageCreateRequest(content="Check", allowed_areas=[token])

    rec = DiagnosticsRecorder(logs_dir=tmp_path / "logs_w3")
    rec.record_failure(
        source="backend_http",
        kind="http_422",
        message=f"Rejected {token}",
        detail={"raw": token},
    )
    assert needle not in rec.failures_log_path.read_text(encoding="utf-8")

    for safe_id in ("task-1", "ask-me-anything-now"):
        assert contains_unredacted_secret_strict(safe_id) is False
        assert contains_sensitive_scope_secret(safe_id) is False
        assert redact_string_strict(safe_id) == safe_id


# ---------------------------------------------------------------------------
# Wave 4 Adversarial Regression Tests (Findings 1–4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"command": ["rm", "-rf", "/"]},
        {"command": ("rm", "-rf", "/")},
        {"COMMAND": "rm -rf /"},
        {"command": "", "COMMAND": "rm -rf /"},
        {"args": {"command": ["rm", "-rf", "/"]}},
        {"arguments": {"cmd": "rm -rf /"}},
        {"input": {"CMD": ["rm", "-rf", "/"]}},
        {"tool_info": {"parameters": {"command": ["rm", "-rf", "/"]}}},
    ],
)
def test_wave4_structured_list_case_and_nested_command_extraction_and_gating(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    line = json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "step_type": "tool",
                "step_index": 1,
                "state": "COMPLETED",
                "tool_name": "custom_helper",
                "tool_info": {"name": "custom_helper", "parameters": payload},
            },
        }
    )
    parsed_ev = parse_agy_stream_event(line)
    assert parsed_ev is not None
    assert parsed_ev.get("command") == "rm -rf /"

    store = WorkspaceStore(tmp_path / "w4_cmd_extract.sqlite3")
    bus = EventBus(db_path=store.db_path)
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    try:
        raw_ev: dict[str, object] = {
            "type": "tool",
            "step_index": 1,
            "state": "COMPLETED",
            "tool_name": "custom_helper",
            "summary": "checking",
            **payload,
        }
        for app_pty in (False, True):
            store.update_connected_app("app_pty", {"enabled": app_pty})
            for candidate_ev in (parsed_ev, raw_ev):
                allowed, reason, meta = runner.gate_agy_stream_tool_event(
                    ev=candidate_ev,
                    bot_id="bot_chief",
                    turn_id=f"trn_w4_{app_pty}",
                    lane=Lane.GENERAL,
                    pending_syntax_tools={},
                    tool_state_by_call={},
                    active_unnamed_calls_by_tool={},
                )
                assert allowed is False, (app_pty, payload, reason)
                assert meta["category"] == "terminal"
                if app_pty:
                    assert reason is not None and "PolicyGateway" in reason
                    assert runner.policy_audit_log[-1]["arguments"].get("command") == "rm -rf /"
                else:
                    assert reason is not None and "Terminal (PTY)" in reason

        # Benign argv list still succeeds when app_pty=True
        store.update_connected_app("app_pty", {"enabled": True})
        ok_allowed, ok_reason, ok_meta = runner.gate_agy_stream_tool_event(
            ev={
                "type": "tool",
                "step_index": 2,
                "state": "COMPLETED",
                "tool_name": "custom_helper",
                "command": ["echo", "hello world"],
            },
            bot_id="bot_chief",
            turn_id="trn_w4_ok",
            lane=Lane.GENERAL,
            pending_syntax_tools={},
            tool_state_by_call={},
            active_unnamed_calls_by_tool={},
        )
        assert ok_allowed is True, ok_reason
        assert ok_meta["category"] == "terminal"
    finally:
        bus.close()
        store.close()


def test_wave4_xargs_pipe_3000_safe_completes_under_budget() -> None:
    cmd = ("(" * 3000) + "echo ok" + (") | xargs rm -rf" * 3000)
    t0 = std_time.monotonic()
    res_b = safety_floor("bash.exec", {"command": cmd})
    res_p = safety_floor("turn.prompt", {"prompt": cmd})
    elapsed = std_time.monotonic() - t0
    assert res_b is None
    assert res_p is None
    assert elapsed < 0.8, f"xargs_pipe_3000_safe took {elapsed:.3f}s >= 0.8s"


@pytest.mark.parametrize(
    "cmd",
    [
        'python3 -c \'from pathlib import Path; Path("/etc/passwd").chmod(0)\'',
        'python3 -c \'from pathlib import Path; Path("/etc/passwd").rename("/tmp/x")\'',
        'python3 -c \'from pathlib import Path; Path("/etc/passwd").replace("/tmp/x")\'',
        'python3 -c \'from pathlib import Path; Path("/etc/passwd").symlink_to("/dev/null")\'',
        'python3 -c \'from pathlib import Path; Path("/etc/passwd").hardlink_to("/dev/null")\'',
        'python3 -c \'import os; os.open("/etc/passwd", os.O_WRONLY | os.O_TRUNC)\'',
        'python3 -c \'import os; os.open("/etc/passwd", os.O_CREAT | os.O_RDWR)\'',
        'python3 -c \'import os; os.symlink("/dev/null", "/etc/passwd")\'',
        'python3 -c \'import os; os.link("/dev/null", "/etc/passwd")\'',
        'python3 -c \'import shutil; shutil.copyfile("/dev/null", "/etc/passwd")\'',
        'python3 -c \'import shutil; shutil.copy("/dev/null", "/etc/passwd")\'',
        'python3 -c \'import shutil; shutil.copy2("/dev/null", "/etc/passwd")\'',
        'python3 -c \'import io; io.FileIO("/etc/passwd", "w").write(b"")\'',
        'python3 -c \'import codecs; codecs.open("/etc/passwd", "w").write("")\'',
        "chmod a=x /etc/passwd",
        "chmod =x /etc/passwd",
        "chmod 111 /etc/passwd",
        "chmod --reference=/dev/null /etc/passwd",
        "unlink /etc/passwd",
        "rmdir /etc",
        "find /etc -maxdepth 1 -exec unlink {} +",
        "echo /etc/passwd | xargs tee",
        "echo /etc/passwd | xargs install /dev/null",
        "echo /etc/passwd | xargs ln -sf /dev/null",
        "echo /etc/passwd | xargs unlink",
        "sed -i 'd' /etc/passwd",
        "curl -s http://example.com -o /etc/passwd",
        "wget -q http://example.com -O /etc/passwd",
        "rsync -a --delete /tmp/empty/ /etc/",
    ],
)
def test_safety_floor_wave4_blocks_sibling_python_ast_and_shell_ops(cmd: str) -> None:
    violation = safety_floor("run_command", {"command": cmd})
    assert violation is not None, f"Expected safety_floor block for {cmd!r}"

    gw = PolicyGateway(default_studio_policy_set(allow_general_writes=True))
    dec = gw.decide(
        PolicyRequest(
            actor_id="bot_browser",
            actor_role="bot",
            lane=Lane.GENERAL,
            tool_id="run_command",
            action_kind="write",
            arguments={"command": cmd},
        )
    )
    assert dec.allowed is False
    assert dec.safety_violation is not None


@pytest.mark.parametrize(
    "safe_cmd",
    [
        'python3 -c \'import os; os.open("/etc/passwd", os.O_RDONLY)\'',
        'python3 -c \'import os; os.open("/tmp/ok.txt", os.O_WRONLY | os.O_TRUNC)\'',
        'python3 -c \'import shutil; shutil.copy("/etc/hosts", "/tmp/hosts.bak")\'',
        'python3 -c \'import io; io.FileIO("/etc/passwd", "r").read()\'',
        'python3 -c \'import codecs; codecs.open("/etc/passwd", "r").read()\'',
        'python3 -c \'from pathlib import Path; Path("/tmp/a").rename("/tmp/b")\'',
        'python3 -c \'from pathlib import Path; Path("/tmp/a").chmod(0o644)\'',
        "chmod -R 755 /",
        "chmod a=rx /etc/passwd",
        "chmod --reference=/tmp/a /tmp/b",
        "unlink /tmp/safe.txt",
        "rmdir /tmp/safe_dir",
        "sed 's/a/b/' /etc/passwd",
        "sed -i 'd' /tmp/safe.txt",
        "curl -s http://example.com -o /tmp/out.html",
        "wget -q http://example.com -O -",
        "rsync -a --delete /tmp/a/ /tmp/b/",
        "rsync -a /etc/ /tmp/backup/",
    ],
)
def test_safety_floor_wave4_preserves_benign_commands(safe_cmd: str) -> None:
    assert safety_floor("run_command", {"command": safe_cmd}) is None, safe_cmd


# ---------------------------------------------------------------------------
# Wave 5 Adversarial Regression Tests (Findings 1–4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        'python3 -c \'import os; os.execvp("rm", ["rm", "-rf", "/"])\'',
        'python3 -c \'import os; os.execv("/bin/rm", ["rm", "-rf", "/etc"])\'',
        'python3 -c \'import os; os.execlp("rm", "rm", "-rf", "/")\'',
        'python3 -c \'import os; os.execle("/bin/rm", "rm", "-rf", "/", {})\'',
        'python3 -c \'import os; os.execve("/bin/rm", ["spoof", "-rf", "/etc"], {})\'',
        'python3 -c \'import os; os.spawnvp(os.P_WAIT, "rm", ["rm", "-rf", "/"])\'',
        'python3 -c \'import os; os.spawnlp(os.P_WAIT, "rm", "rm", "-rf", "/")\'',
        'python3 -c \'import os; os.spawnle(os.P_WAIT, "/bin/rm", "rm", "-rf", "/", {})\'',
        'python3 -c \'import os; os.posix_spawn("/bin/rm", ["rm", "-rf", "/"], {})\'',
        'python3 -c \'import os; os.posix_spawnp("rm", ["rm", "-rf", "/"], {})\'',
        'python3 -c \'import pty; pty.spawn(["rm", "-rf", "/"])\'',
        'python3 -c \'from pty import spawn as ps; ps(["sh", "-c", "rm -rf /"])\'',
        'python3 -c \'import os; os.execvp("find", ["find", "/", "-delete"])\'',
        'python3 -c \'import os; os.execvp("shred", ["shred", "/etc/passwd"])\'',
        'python3 -c \'import fileinput; list(fileinput.input("/etc/passwd", inplace=True))\'',
        (
            "python3 -c 'from fileinput import FileInput as FI; "
            'list(FI(files=["/tmp/a", "/etc/shadow"], inplace=True))\''
        ),
        'python3 -c \'import os as o; getattr(o, "exec" + "vp")("rm", ["rm", "-rf", "/"])\'',
        'python3 -c \'import fileinput as fi; getattr(fi, "input")("/etc/passwd", inplace=True)\'',
        "chmod -r /etc/passwd",
        "chmod -rwx /etc/passwd",
        "chmod -R -r /etc/passwd",
        "chmod -R =rwx /",
        "chmod -R =w /",
        "chmod -Rf +w /etc",
        "echo /etc/passwd | xargs truncate --size 1",
        "echo /etc/passwd | xargs -I{} truncate -s 1 {}",
        "truncate --size 1 /etc/passwd",
        "find /etc -maxdepth 1 -exec truncate --size 1 {} +",
    ],
)
def test_safety_floor_wave5_blocks_exec_spawn_fileinput_chmod_and_truncate(cmd: str) -> None:
    violation = safety_floor("run_command", {"command": cmd})
    assert violation is not None, f"Expected safety_floor block for {cmd!r}"

    gw = PolicyGateway(default_studio_policy_set(allow_general_writes=True))
    dec = gw.decide(
        PolicyRequest(
            actor_id="bot_browser",
            actor_role="bot",
            lane=Lane.GENERAL,
            tool_id="run_command",
            action_kind="write",
            arguments={"command": cmd},
        )
    )
    assert dec.allowed is False
    assert dec.safety_violation is not None


@pytest.mark.parametrize(
    "safe_cmd",
    [
        'python3 -c \'import os; os.execvp("rm", ["rm", "-rf", "/tmp/safe"])\'',
        'python3 -c \'import os; os.posix_spawn("/bin/echo", ["echo", "hi"], {})\'',
        'python3 -c \'import pty; pty.spawn(["/bin/echo", "hi"])\'',
        'python3 -c \'import fileinput; list(fileinput.input("/etc/passwd"))\'',
        'python3 -c \'import fileinput; list(fileinput.input("/tmp/safe.txt", inplace=True))\'',
        "chmod -r /tmp/safe.txt",
        "chmod -R =rwx /tmp/safe",
        "chmod -R =rx /",
        "echo /tmp/safe.txt | xargs truncate --size 1",
        "truncate --size 1 /tmp/safe.txt",
        "truncate -r /tmp/ref.txt /tmp/safe.txt",
    ],
)
def test_safety_floor_wave5_preserves_benign_exec_spawn_fileinput_chmod_and_truncate(
    safe_cmd: str,
) -> None:
    assert safety_floor("run_command", {"command": safe_cmd}) is None, safe_cmd


@pytest.mark.parametrize(
    ("payload", "expected_cmd"),
    [
        ({"args": ["rm", "-rf", "/"]}, "rm -rf /"),
        ({"argv": ["rm", "-rf", "/"]}, "rm -rf /"),
        ({"arguments": ["rm", "-rf", "/"]}, "rm -rf /"),
        ({"input": ["rm", "-rf", "/"]}, "rm -rf /"),
        ({"payload": ["rm", "-rf", "/"]}, "rm -rf /"),
        ({"data": ["rm", "-rf", "/"]}, "rm -rf /"),
        (
            {"toolSummary": "Check", "code": "import shutil; shutil.rmtree('/')"},
            "import shutil; shutil.rmtree('/')",
        ),
        ({"toolSummary": "Check", "shell": "rm -rf /"}, "rm -rf /"),
        ({"toolSummary": "Check", "bash": "rm -rf /"}, "rm -rf /"),
        ({"toolSummary": "Check", "args": ["rm", "-rf", "/"]}, "rm -rf /"),
    ],
)
def test_wave5_agy_list_containers_and_code_shell_bash_argv_keys_gated(
    tmp_path: Path,
    payload: dict[str, object],
    expected_cmd: str,
) -> None:
    line = json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "step_type": "tool",
                "step_index": 1,
                "state": "COMPLETED",
                "tool_name": "run_command",
                "tool_info": {"name": "run_command", "parameters": payload},
            },
        }
    )
    parsed_ev = parse_agy_stream_event(line)
    assert parsed_ev is not None
    assert parsed_ev.get("command") == expected_cmd

    store = WorkspaceStore(tmp_path / "w5_cmd_extract.sqlite3")
    bus = EventBus(db_path=store.db_path)
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    try:
        raw_ev: dict[str, object] = {
            "type": "tool",
            "step_index": 1,
            "state": "COMPLETED",
            "tool_name": "run_command",
            "summary": "Check",
            **payload,
        }
        store.update_connected_app("app_pty", {"enabled": True})
        for candidate_ev in (parsed_ev, raw_ev):
            allowed, reason, meta = runner.gate_agy_stream_tool_event(
                ev=candidate_ev,
                bot_id="bot_chief",
                turn_id="trn_w5",
                lane=Lane.GENERAL,
                pending_syntax_tools={},
                tool_state_by_call={},
                active_unnamed_calls_by_tool={},
            )
            assert allowed is False, (payload, candidate_ev, reason)
            assert reason is not None and "PolicyGateway" in reason
            assert meta["category"] == "terminal"

        # Benign payloads remain allowed
        for benign_payload in (
            {"toolSummary": "Check", "code": "print('hello')"},
            {"toolSummary": "Check", "shell": "echo ok"},
            {"toolSummary": "Check", "bash": "ls /tmp"},
            {"toolSummary": "Check", "args": ["echo", "ok"]},
            {"toolSummary": "Check", "data": ["echo", "safe"]},
        ):
            benign_line = json.dumps(
                {
                    "event": "step_update",
                    "step_update": {
                        "step_type": "tool",
                        "step_index": 2,
                        "state": "COMPLETED",
                        "tool_name": "run_command",
                        "tool_info": {"name": "run_command", "parameters": benign_payload},
                    },
                }
            )
            benign_parsed = parse_agy_stream_event(benign_line)
            assert benign_parsed is not None
            ok_allowed, ok_reason, _ = runner.gate_agy_stream_tool_event(
                ev=benign_parsed,
                bot_id="bot_chief",
                turn_id="trn_w5_ok",
                lane=Lane.GENERAL,
                pending_syntax_tools={},
                tool_state_by_call={},
                active_unnamed_calls_by_tool={},
            )
            assert ok_allowed is True, (benign_payload, ok_reason)
    finally:
        bus.close()
        store.close()


# ---------------------------------------------------------------------------
# Wave 6 Adversarial Regression Tests (Findings 1–3)
# ---------------------------------------------------------------------------


def test_wave6_agy_extract_tool_command_does_not_truncate_past_16384_chars(
    tmp_path: Path,
) -> None:
    padding = "a" * 16384
    bad_cmd = f"echo {padding}; rm -rf /"
    bad_line = json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "step_type": "tool",
                "step_index": 1,
                "state": "ACTIVE",
                "tool_name": "run_command",
                "tool_info": {"name": "run_command", "parameters": {"command": bad_cmd}},
            },
        }
    )
    parsed_bad = parse_agy_stream_event(bad_line)
    assert parsed_bad is not None
    assert parsed_bad["command"] == bad_cmd
    assert len(parsed_bad["command"]) > 16384
    assert len(parsed_bad["summary"]) <= 120

    safe_cmd = f"echo {padding}; ls /tmp"
    safe_line = json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "step_type": "tool",
                "step_index": 2,
                "state": "COMPLETED",
                "tool_name": "run_command",
                "tool_info": {"name": "run_command", "parameters": {"command": safe_cmd}},
            },
        }
    )
    parsed_safe = parse_agy_stream_event(safe_line)
    assert parsed_safe is not None
    assert parsed_safe["command"] == safe_cmd
    assert len(parsed_safe["command"]) > 16384

    store = WorkspaceStore(tmp_path / "w6_long_cmd.sqlite3")
    bus = EventBus(db_path=store.db_path)
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    try:
        store.update_connected_app("app_pty", {"enabled": True})
        allowed_bad, reason_bad, _ = runner.gate_agy_stream_tool_event(
            ev=parsed_bad,
            bot_id="bot_chief",
            turn_id="trn_w6_bad",
            lane=Lane.GENERAL,
            pending_syntax_tools={},
            tool_state_by_call={},
            active_unnamed_calls_by_tool={},
        )
        assert allowed_bad is False
        assert reason_bad is not None
        assert "safety_floor:destructive_rm_root_or_glob" in reason_bad

        allowed_safe, reason_safe, _ = runner.gate_agy_stream_tool_event(
            ev=parsed_safe,
            bot_id="bot_chief",
            turn_id="trn_w6_safe",
            lane=Lane.GENERAL,
            pending_syntax_tools={},
            tool_state_by_call={},
            active_unnamed_calls_by_tool={},
        )
        assert allowed_safe is True, reason_safe
    finally:
        bus.close()
        store.close()


@pytest.mark.parametrize(
    "cmd",
    [
        'python3 -c \'import importlib; importlib.import_module("os").unlink("/etc/passwd")\'',
        'python3 -c \'import importlib; importlib.import_module("os").remove("/etc/shadow")\'',
        (
            "python3 -c 'import importlib; "
            'importlib.import_module("os").truncate("/etc/passwd", 0)\''
        ),
        'python3 -c \'import importlib; importlib.import_module("os").chmod("/", 0)\'',
        (
            "python3 -c 'import importlib; "
            'importlib.import_module("os").replace("/dev/null", "/etc/passwd")\''
        ),
        (
            "python3 -c 'from importlib import import_module; "
            'import_module("os").unlink("/etc/passwd")\''
        ),
        (
            "python3 -c 'from importlib import import_module as im; "
            'im("o"+"s").unlink("/etc/passwd")\''
        ),
        (
            "python3 -c 'import importlib as imp; "
            'imp.import_module("os").remove("/etc/shadow")\''
        ),
        (
            "python3 -c 'import importlib; "
            'getattr(importlib, "import_module")("o"+"s").unlink("/etc/passwd")\''
        ),
        (
            "python3 -c 'import importlib; im = getattr(importlib, \"import_module\"); "
            'im("shu"+"til").rmtree("/")\''
        ),
        'python3 -c \'__import__("shu"+"til").rmtree("/")\'',
        'python3 -c \'m="shu"+"til"; __import__(m).rmtree("/")\'',
        'python3 -c \'m="o"+"s"; __import__(m).unlink("/etc/passwd")\'',
        'python3 -c \'__import__("o"+"s").truncate("/etc/passwd", 0)\'',
        'python3 -c \'import importlib; importlib.import_module("shu"+"til").rmtree("/")\'',
        'python3 -c \'import importlib; importlib.import_module("os").system("r"+"m -rf /")\'',
        (
            "python3 -c 'import importlib; "
            'importlib.import_module("subprocess").run(["r"+"m", "-rf", "/"])\''
        ),
        'python3 -c \'import base64, os; os.system(base64.b64decode("cm0gLXJmIC8=").decode())\'',
        (
            "python3 -c 'import base64, os; "
            'd = base64.b64decode("cm0gLXJmIC8=").decode(); os.system(d)\''
        ),
        (
            "python3 -c 'import base64; "
            'exec(base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oInJtIC1yZiAvIik="))\''
        ),
        'python3 -c \'import base64; eval(base64.b64decode("ZWNobyBoaQ==").decode())\'',
        'python3 -c \'import importlib; m = input(); importlib.import_module(m).unlink("/tmp/x")\'',
        'python3 -c \'import importlib; getattr(importlib.import_module(input()), input())("/")\'',
        'python3 -c \'import os; os.system(input())\'',
        'python3 -c \'import subprocess; subprocess.run(input())\'',
        'python3 -c \'import os; os.execvp("sh", ["-c", input()])\'',
        'python3 -c \'import pty; pty.spawn(input())\'',
        'python3 -c \'eval(input())\'',
        'python3 -c \'exec(input())\'',
    ],
)
def test_safety_floor_wave6_blocks_importlib_concat_dunder_and_decoded_exec(cmd: str) -> None:
    violation = safety_floor("run_command", {"command": cmd})
    assert violation is not None, f"Expected safety_floor block for {cmd!r}"

    gw = PolicyGateway(default_studio_policy_set(allow_general_writes=True))
    dec = gw.decide(
        PolicyRequest(
            actor_id="bot_browser",
            actor_role="bot",
            lane=Lane.GENERAL,
            tool_id="run_command",
            action_kind="write",
            arguments={"command": cmd},
        )
    )
    assert dec.allowed is False
    assert dec.safety_violation is not None


@pytest.mark.parametrize(
    "safe_cmd",
    [
        'python3 -c \'import importlib; importlib.import_module("os").unlink("/tmp/safe.txt")\'',
        'python3 -c \'import importlib; importlib.import_module("shu"+"til").rmtree("/tmp/work")\'',
        'python3 -c \'from importlib import import_module as im; im("os").system("echo ok")\'',
        (
            "python3 -c 'import importlib; "
            'getattr(importlib, "import_module")("subprocess").run(["echo", "ok"])\''
        ),
        'python3 -c \'import importlib; importlib.import_module("json").loads("{}")\'',
        'python3 -c \'import importlib; m = input(); print(importlib.import_module(m).__name__)\'',
        'python3 -c \'import base64; print(base64.b64decode("aGVsbG8=").decode())\'',
        'python3 -c \'x = eval("1 + 2"); print(x)\'',
        'python3 -c \'import builtins; builtins.exec("x = 1; print(x)")\'',
    ],
)
def test_safety_floor_wave6_preserves_benign_importlib_decode_and_eval(safe_cmd: str) -> None:
    assert safety_floor("run_command", {"command": safe_cmd}) is None, safe_cmd


@pytest.mark.parametrize("bad_field", ["from", "to", "cc", "bcc", "subject"])
async def test_wave6_deliver_draft_handles_crlf_email_headers_without_raising(
    tmp_path: Path,
    bad_field: str,
) -> None:
    store = WorkspaceStore(tmp_path / f"w6_draft_{bad_field}.sqlite3")
    bus = EventBus(db_path=store.db_path)
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=LiveBrowserController(profile_root=tmp_path / "browser"),
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    try:
        store.update_settings({"smtp": {"host": "127.0.0.1", "port": 2525}})
        fields: dict[str, object] = {
            "from": "sender@example.com",
            "to": "recipient@example.com",
            "cc": "cc@example.com",
            "bcc": "bcc@example.com",
            "subject": "Normal Subject",
            "body": "Hello",
        }
        fields[bad_field] = f"{fields[bad_field]}\r\nX-Injected: evil"
        draft = store.create_draft(
            bot_id="bot_chief",
            thread_id="thr_bot_chief",
            channel_type="email",
            fields=fields,
        )
        res = await runner.deliver_draft(draft)
        assert res["delivered"] is False
        assert res["transport"] == "smtp"
        assert "Invalid CR/LF" in str(res.get("error", ""))
    finally:
        bus.close()
        store.close()


# =============================================================================
# Wave 7 Regression Tests (Python Reflection/Dynamic Paths, xargs Here-String/
# Heredoc Stdin, and AGY Multi-Key Command Shadowing)
# =============================================================================


@pytest.mark.parametrize(
    "blocked_cmd",
    [
        'python3 -c \'import os; os.__dict__["sys"+"tem"]("rm -rf /")\'',
        'python3 -c \'import os; vars(os)["sys"+"tem"]("rm -rf /")\'',
        'python3 -c \'import sys, os; sys.modules["os"].__dict__["system"]("rm -rf /")\'',
        'python3 -c \'import operator, os; operator.attrgetter("sys"+"tem")(os)("rm -rf /")\'',
        'python3 -c \'__builtins__.__dict__["ex"+"ec"]("import os; os.system(\x27rm -rf /\x27)")\'',
        (
            'python3 -c \'import os; os.system("".join(chr(c) '
            'for c in [114,109,32,45,114,102,32,47]))\''
        ),
        'python3 -c \'import shutil; shutil.rmtree(bytes([47]).decode())\'',
        'python3 -c \'import shutil; shutil.rmtree(bytearray([47]).decode())\'',
        'python3 -c \'import shutil; [shutil.rmtree(p) for p in ["/"]]\'',
        'python3 -c \'import shutil; (lambda p: shutil.rmtree(p))("/")\'',
        'python3 -c \'import shutil\ndef f(p): shutil.rmtree(p)\nf("/")\'',
        'python3 -c \'import shutil; shutil.rmtree("".join(chr(ord(c)) for c in "/"))\'',
        (
            'python3 -c \'import os; '
            'os.unlink(bytes([47, 101, 116, 99, 47, 112, 97, 115, 115, 119, 100]).decode())\''
        ),
    ],
)
def test_safety_floor_wave7_blocks_python_reflection_and_dynamic_paths(blocked_cmd: str) -> None:
    reason = safety_floor("run_command", {"command": blocked_cmd})
    assert reason is not None, f"Expected block for: {blocked_cmd}"


@pytest.mark.parametrize(
    "safe_cmd",
    [
        'python3 -c \'print(1 + 2)\'',
        'python3 -c \'import shutil; shutil.rmtree("/tmp/safe_test_dir")\'',
        'python3 -c \'import os; print(os.__dict__.get("name"))\'',
        'python3 -c \'print([i * 2 for i in range(5)])\'',
        'python3 -c \'import shutil; shutil.rmtree(bytes(b"/tmp/safe_test_dir").decode())\'',
        'python3 -c \'import shutil; [shutil.rmtree(p) for p in ["/tmp/safe_test_dir"]]\'',
        'python3 -c \'import shutil; (lambda p: shutil.rmtree(p))("/tmp/safe_test_dir")\'',
        'python3 -c \'import shutil\ndef f(p): shutil.rmtree(p)\nf("/tmp/safe_test_dir")\'',
    ],
)
def test_safety_floor_wave7_preserves_benign_python_reflection_and_comprehensions(
    safe_cmd: str,
) -> None:
    assert safety_floor("run_command", {"command": safe_cmd}) is None, safe_cmd


@pytest.mark.parametrize(
    "blocked_cmd",
    [
        "xargs rm -rf <<< /etc",
        "xargs -I{} rm -rf {} <<< /etc",
        "xargs rm -rf <<EOF\n/etc\nEOF",
        "xargs -I{} rm -rf {} <<EOF\n/etc\nEOF",
        "xargs rm -rf <<'EOF'\n/etc\nEOF",
        "xargs rm -rf <<-EOF\n\t/etc\n\tEOF",
        "cat <<< /etc | xargs rm -rf",
        "xargs unlink <<< /etc/passwd",
        "xargs sh -c 'rm -rf \"$1\"' _ <<< /etc",
        "xargs python3 -c 'import os, sys; os.unlink(sys.argv[1])' <<< /etc/passwd",
        'xargs rm -rf <<< "$TARGET"',
        "xargs rm -rf <<EOF\n$TARGET\nEOF",
    ],
)
def test_safety_floor_wave7_blocks_xargs_herestring_and_heredoc(blocked_cmd: str) -> None:
    reason = safety_floor("run_command", {"command": blocked_cmd})
    assert reason is not None, f"Expected block for: {blocked_cmd}"


@pytest.mark.parametrize(
    "safe_cmd",
    [
        "xargs echo <<< hello",
        "echo /tmp/work | xargs rm -rf",
        "xargs rm -rf <<< /tmp/work",
        "xargs rm -rf <<EOF\n/tmp/work\nEOF",
    ],
)
def test_safety_floor_wave7_preserves_benign_xargs_herestring_and_heredoc(safe_cmd: str) -> None:
    assert safety_floor("run_command", {"command": safe_cmd}) is None, safe_cmd


def test_safety_floor_wave7_xargs_pipe_3000_safe_latency() -> None:
    import time

    cmd = ("(" * 3000) + "echo ok" + (") | xargs rm -rf" * 3000)
    t0 = time.perf_counter()
    res = safety_floor("run_command", {"command": cmd})
    elapsed = time.perf_counter() - t0
    assert res is None
    assert elapsed < 0.8, f"xargs_pipe_3000_safe took {elapsed:.4f}s (>= 0.8s)"


@pytest.mark.parametrize(
    "tool_params",
    [
        {"command": "echo safe", "script": "rm -rf /"},
        {"command": "echo safe", "code": "rm -rf /"},
        {"cmd": "echo safe", "bash": "rm -rf /"},
    ],
)
@pytest.mark.parametrize("tool_name", ["run_command", "app_pty"])
def test_wave7_parse_and_gate_agy_stream_multi_key_command_shadowing(
    tmp_path: Path,
    tool_params: dict[str, str],
    tool_name: str,
) -> None:
    raw_line = json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "step_type": "tool",
                "step_index": 1,
                "state": "WAITING",
                "tool_name": tool_name,
                "tool_info": {"name": tool_name, "parameters": tool_params},
            },
        }
    )
    ev = parse_agy_stream_event(raw_line)
    assert ev is not None
    assert ev["command"] == "echo safe"
    assert isinstance(ev.get("commands"), list)
    assert "echo safe" in ev["commands"]
    assert "rm -rf /" in ev["commands"]

    store = WorkspaceStore(tmp_path / f"w7_shadow_{tool_name}.sqlite3")
    bus = EventBus()
    audit_log: list[dict[str, Any]] = []
    try:
        runner = AgentTurnRunner(
            store=store,
            event_bus=bus,
            live_browser=LiveBrowserController(profile_root=tmp_path / f"browser_{tool_name}"),
            coordinator=InMemoryCoordinatorStub(),
            uploads_dir=tmp_path / f"uploads_{tool_name}",
            policy_gateway=PolicyGateway(
                default_studio_policy_set(allow_general_writes=True),
                audit_sink=audit_log.append,
            ),
        )
        pending: dict[str, dict[str, Any]] = {}
        state_by_call: dict[str, dict[str, Any]] = {}
        active_unnamed: dict[str, str] = {}
        allowed, reason, meta = runner.gate_agy_stream_tool_event(
            ev=ev,
            bot_id="bot_chief",
            turn_id="turn_w7_shadow",
            lane=Lane.GENERAL,
            pending_syntax_tools=pending,
            tool_state_by_call=state_by_call,
            active_unnamed_calls_by_tool=active_unnamed,
        )
        assert allowed is False
        assert reason is not None and "safety_floor:" in reason
        assert meta["tool_name"] == tool_name

        # Complete destructive secondary command must be blocked immediately even while ACTIVE
        ev_active_complete = dict(ev)
        ev_active_complete["state"] = "ACTIVE"
        ev_active_complete["step_index"] = 2
        allowed_act, reason_act, _ = runner.gate_agy_stream_tool_event(
            ev=ev_active_complete,
            bot_id="bot_chief",
            turn_id="turn_w7_shadow_2a",
            lane=Lane.GENERAL,
            pending_syntax_tools={},
            tool_state_by_call={},
            active_unnamed_calls_by_tool={},
        )
        assert allowed_act is False
        assert reason_act is not None and "safety_floor:" in reason_act

        # Incomplete-syntax secondary command deferred during ACTIVE -> blocked on finalize
        ev_active_partial = {
            "type": "tool",
            "step_index": 3,
            "state": "ACTIVE",
            "tool_name": tool_name,
            "command": "echo safe",
            "commands": ["echo safe", "python3 -c '"],
        }
        pending2: dict[str, dict[str, Any]] = {}
        state2: dict[str, dict[str, Any]] = {}
        unnamed2: dict[str, str] = {}
        allowed2, reason2, _ = runner.gate_agy_stream_tool_event(
            ev=ev_active_partial,
            bot_id="bot_chief",
            turn_id="turn_w7_shadow_2",
            lane=Lane.GENERAL,
            pending_syntax_tools=pending2,
            tool_state_by_call=state2,
            active_unnamed_calls_by_tool=unnamed2,
        )
        assert allowed2 is True
        assert reason2 is None
        fin_allowed, fin_reason, _ = runner.finalize_agy_stream_pending_tools(
            bot_id="bot_chief",
            turn_id="turn_w7_shadow_2",
            lane=Lane.GENERAL,
            pending_syntax_tools=pending2,
        )
        assert fin_allowed is False
        assert fin_reason is not None and "safety_floor:" in fin_reason
    finally:
        bus.close()
        store.close()


def test_wave7_gate_agy_stream_multi_key_benign_control(tmp_path: Path) -> None:
    raw_line = json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "step_type": "tool",
                "step_index": 1,
                "state": "WAITING",
                "tool_name": "run_command",
                "tool_info": {
                    "name": "run_command",
                    "parameters": {"command": "echo safe", "script": "ls /tmp"},
                },
            },
        }
    )
    ev = parse_agy_stream_event(raw_line)
    assert ev is not None
    assert ev["commands"] == ["echo safe", "ls /tmp"]

    store = WorkspaceStore(tmp_path / "w7_safe_multi.sqlite3")
    bus = EventBus()
    audit_log: list[dict[str, Any]] = []
    try:
        runner = AgentTurnRunner(
            store=store,
            event_bus=bus,
            live_browser=LiveBrowserController(profile_root=tmp_path / "browser_safe"),
            coordinator=InMemoryCoordinatorStub(),
            uploads_dir=tmp_path / "uploads_safe",
            policy_gateway=PolicyGateway(
                default_studio_policy_set(allow_general_writes=True),
                audit_sink=audit_log.append,
            ),
        )
        allowed, reason, meta = runner.gate_agy_stream_tool_event(
            ev=ev,
            bot_id="bot_chief",
            turn_id="turn_w7_safe",
            lane=Lane.GENERAL,
            pending_syntax_tools={},
            tool_state_by_call={},
            active_unnamed_calls_by_tool={},
        )
        assert allowed is True
        assert reason is None
        assert meta["tool_name"] == "run_command"
    finally:
        bus.close()
        store.close()

