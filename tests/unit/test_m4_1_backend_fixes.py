"""N1 unit regression tests for Milestone M4-1 backend live and routing fixes."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from src.adapters.config import load_facility_config
from src.contracts.budgets import BudgetConfig, BudgetUsage
from src.contracts.common import utc_now
from src.contracts.enums import BackendMode, TaskStatus
from src.contracts.envelope import Lane, VerdictState
from src.contracts.models import Result, Run, TaskScope, TaskSpec
from src.engine.router import LaneRouter
from src.model import BudgetRemaining, ModelDecision, PromptContext
from src.qa.ux_metrics import evaluate_error_actionability
from src.runtime import make_industrial_turn_factory
from src.web.live_browser import LiveBrowserController
from src.web.protocols import TaskSnapshot
from src.web.stub import InMemoryCoordinatorStub
from src.web.v1.events import EventBus
from src.web.v1.runner import AgentTurnRunner, _format_runtime_error_message
from src.web.v1.store import WorkspaceStore
from src.web.workspace import parse_agy_stream_event

_FACILITY_A_PATH = Path("lab/configs/facility_a.json")


def _make_unit_runner(tmp_path: Path) -> tuple[WorkspaceStore, EventBus, AgentTurnRunner]:
    store = WorkspaceStore(tmp_path / "ws.sqlite3")
    bus = EventBus()
    browser = LiveBrowserController(profile_root=tmp_path / "browser")
    runner = AgentTurnRunner(
        store=store,
        event_bus=bus,
        live_browser=browser,
        coordinator=InMemoryCoordinatorStub(),
        uploads_dir=tmp_path / "uploads",
    )
    return store, bus, runner


@pytest.mark.n1
def test_parse_agy_stream_event_command_key_variants_and_json_params() -> None:
    long_cmd = (
        "curl -s -X POST http://127.0.0.1:8000/api/browser/action "
        '-H "Content-Type: application/json" '
        "-d '{\"type\":\"navigate\",\"url\":\"https://example.com/"
        + ("a" * 180)
        + "\"}'"
    )

    for key in ("CommandLine", "commandLine", "command_line", "cmd", "cmdline", "script"):
        line = json.dumps(
            {
                "event": "step_update",
                "step_update": {
                    "step_index": 2,
                    "state": "ACTIVE",
                    "step_type": "tool",
                    "tool_name": "run_command",
                    "tool_info": {
                        "name": "run_command",
                        "parameters": {key: long_cmd},
                    },
                },
            }
        )
        ev = parse_agy_stream_event(line)
        assert ev is not None
        assert ev["type"] == "tool"
        assert ev["command"] == long_cmd
        assert len(ev["summary"]) <= 120

    # JSON-stringified tool_info.parameters and double-JSON-encoded command value
    stringified_line = json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "step_index": 3,
                "state": "ACTIVE",
                "step_type": "tool",
                "tool_name": "run_command",
                "tool_info": {
                    "name": "run_command",
                    "parameters": json.dumps({"commandLine": json.dumps(long_cmd)}),
                },
            },
        }
    )
    ev_str = parse_agy_stream_event(stringified_line)
    assert ev_str is not None
    assert ev_str["command"] == long_cmd
    assert len(ev_str["summary"]) <= 120


@pytest.mark.n1
def test_gate_mid_turn_tool_backwards_compat_and_syntax_deferral(tmp_path: Path) -> None:
    store, bus, runner = _make_unit_runner(tmp_path)
    try:
        partial_cmd = (
            "curl -s --max-time 20 -X POST http://127.0.0.1:8000/api/browser/action "
            '-H "Content-Type: application/json" -d \'{"type":"'
        )
        # Strict default (allow_incomplete_syntax=False) must still reject unparseable syntax
        allowed_strict, reason_strict = runner._gate_mid_turn_tool(
            bot_id="bot_browser",
            turn_id="trn_strict_1",
            lane=Lane.GENERAL,
            tool_name="run_command",
            category="terminal",
            summary=partial_cmd[:120],
            command=partial_cmd,
        )
        assert allowed_strict is False
        assert reason_strict is not None
        assert "unparseable_shell_syntax" in reason_strict

        # Streaming ACTIVE deferral (allow_incomplete_syntax=True) defers ONLY syntax error
        allowed_def, reason_def, deferred = runner._gate_mid_turn_tool_with_status(
            bot_id="bot_browser",
            turn_id="trn_def_1",
            lane=Lane.GENERAL,
            tool_name="run_command",
            category="terminal",
            summary=partial_cmd[:120],
            command=partial_cmd,
            allow_incomplete_syntax=True,
        )
        assert allowed_def is True
        assert reason_def is None
        assert deferred is True

        # Truncated summary when command=None must also defer cleanly on ACTIVE
        allowed_none, reason_none, deferred_none = runner._gate_mid_turn_tool_with_status(
            bot_id="bot_browser",
            turn_id="trn_def_2",
            lane=Lane.GENERAL,
            tool_name="run_command",
            category="terminal",
            summary=partial_cmd[:120],
            command=None,
            allow_incomplete_syntax=True,
        )
        assert allowed_none is True
        assert reason_none is None
        assert deferred_none is True

        # Non-syntax safety violations MUST still block immediately even when deferred
        allowed_rm, reason_rm, deferred_rm = runner._gate_mid_turn_tool_with_status(
            bot_id="bot_browser",
            turn_id="trn_rm_1",
            lane=Lane.GENERAL,
            tool_name="run_command",
            category="terminal",
            summary="rm -rf /",
            command='rm -rf / && echo "unclosed',
            allow_incomplete_syntax=True,
        )
        assert allowed_rm is False
        assert reason_rm is not None
        assert deferred_rm is False

        allowed_proc, reason_proc, _ = runner._gate_mid_turn_tool_with_status(
            bot_id="bot_browser",
            turn_id="trn_proc_1",
            lane=Lane.GENERAL,
            tool_name="run_command",
            category="terminal",
            summary="cat <(echo hi)",
            command="cat <(echo hi)",
            allow_incomplete_syntax=True,
        )
        assert allowed_proc is False
        assert reason_proc is not None
        assert "shell_process_substitution" in reason_proc

        # Lane.INDUSTRIAL still blocks terminal writes on ACTIVE
        allowed_ind, reason_ind, _ = runner._gate_mid_turn_tool_with_status(
            bot_id="bot_ops",
            turn_id="trn_ind_1",
            lane=Lane.INDUSTRIAL,
            tool_name="run_command",
            category="terminal",
            summary=partial_cmd[:120],
            command=partial_cmd,
            allow_incomplete_syntax=True,
        )
        assert allowed_ind is False
        assert reason_ind is not None
        assert "industrial_read_only_lane" in reason_ind
    finally:
        bus.close()
        store.close()


@pytest.mark.n1
async def test_lane_router_cb_valve_104_and_regression_matrix() -> None:
    cfg = load_facility_config(_FACILITY_A_PATH)
    router = LaneRouter()

    # CB-VALVE-104 & generic equipment price/web queries -> Lane.GENERAL (not MIXED/INDUSTRIAL)
    d_cb = await router.route(
        "Busca el precio vigente de CB-VALVE-104 y dime en qué página lo encontraste",
        facility_config=cfg,
    )
    assert d_cb.lane == Lane.GENERAL
    assert d_cb.domain_profile == "web_research"
    assert "web_citation" in d_cb.required_verifiers
    assert d_cb.needs_clarification is False

    d_upd = await router.route("Re-check CB-VALVE-104 price update", facility_config=cfg)
    assert d_upd.lane == Lane.GENERAL
    assert d_upd.domain_profile == "web_research"
    assert d_upd.needs_clarification is False

    d_eng_valve = await router.route(
        "What is the current price of valve CB-VALVE-104?",
        facility_config=cfg,
    )
    assert d_eng_valve.lane == Lane.GENERAL
    assert d_eng_valve.domain_profile == "web_research"

    d_es_valve = await router.route("Precio de una válvula", facility_config=cfg)
    assert d_es_valve.lane == Lane.GENERAL
    assert d_es_valve.domain_profile == "web_research"

    d_about = await router.route("Tell me about CB-VALVE-104", facility_config=cfg)
    assert d_about.lane == Lane.GENERAL
    assert d_about.domain_profile == "general_office"

    d_explain = await router.route("Explain what a ball valve is", facility_config=cfg)
    assert d_explain.lane == Lane.GENERAL
    assert d_explain.domain_profile == "general_office"

    # Existing MIXED / INDUSTRIAL / CLARIFICATION contracts must remain intact
    d_mix1 = await router.route(
        "Verificar TT-402B en SCADA y buscar reemplazo web datasheet OEM",
        facility_config=cfg,
    )
    assert d_mix1.lane == Lane.MIXED

    d_mix2 = await router.route(
        "Find replacement datasheet on web for PT-3401",
        facility_config=cfg,
    )
    assert d_mix2.lane == Lane.MIXED

    d_mix3 = await router.route(
        "Verify Bomba 34 telemetry, find OEM replacement datasheet on web, and export Excel",
        facility_config=cfg,
        area="area-1",
    )
    assert d_mix3.lane == Lane.MIXED

    d_ind = await router.route(
        "Check bomba 34 alarms and readings in SCADA and maintenance",
        facility_config=cfg,
    )
    assert d_ind.lane == Lane.INDUSTRIAL

    d_bare = await router.route("revisa el 34", facility_config=cfg)
    assert d_bare.needs_clarification is True
    assert d_bare.verdict_override == VerdictState.NEEDS_CLARIFICATION

    d_ui_mix = await router.route(
        "Tell me about CB-VALVE-104",
        ui_lane=Lane.MIXED,
        facility_config=cfg,
    )
    assert d_ui_mix.lane == Lane.MIXED


@pytest.mark.n1
def test_format_runtime_error_message_and_build_runtime_meta() -> None:
    raw = (
        "All requested industrial sources failed or returned no authorized evidence: "
        "maintenance (SCADA Playwright error for 'http://127.0.0.1:8102': "
        "Page.goto: net::ERR_CONNECTION_REFUSED), "
        "scada (Playwright error: [Errno 111] Connection refused)"
    )
    partial_info: dict[str, Any] = {
        "available_sources": [],
        "missing_sources": ["maintenance", "scada"],
        "source_errors": {
            "maintenance": "net::ERR_CONNECTION_REFUSED at http://127.0.0.1:8102",
            "scada": "Traceback (most recent call last)\nConnectionError: boom",
        },
    }
    formatted = _format_runtime_error_message(raw, partial_info)
    ok, reason = evaluate_error_actionability(formatted)
    assert ok is True, reason
    assert "net::ERR_" not in formatted
    assert "Traceback" not in formatted
    assert "[Errno" not in formatted
    assert "available_sources" not in formatted
    assert "SCADA" in formatted and "Maintenance" in formatted

    now = utc_now()
    task = TaskSpec(
        task_id="task-meta-1",
        user_id="operator",
        profile_id="default",
        scope=TaskScope(facility_id="facility-a", read_only=True),
        query="Reply with OK",
        backend_mode=BackendMode.LOCAL_HTTP,
    )
    run = Run(
        run_id="run-meta-1",
        task_id=task.task_id,
        status=TaskStatus.SUCCEEDED,
        deadline_at=now + timedelta(minutes=5),
        created_at=now,
        updated_at=now,
    )
    snap_gen = TaskSnapshot(
        run=run,
        task=task,
        budget_config=BudgetConfig(),
        budget_usage=BudgetUsage(),
        transitions=(),
        result=Result(
            task_id=task.task_id,
            run_id=run.run_id,
            status=TaskStatus.SUCCEEDED,
            answer="OK",
        ),
        receipts=(),
    )
    meta_gen = AgentTurnRunner._build_runtime_meta(snap_gen, lane=Lane.GENERAL)
    assert meta_gen["domain_profile"] == "general_office"

    # CB-12 stale/bad rejected_record_ids MUST be preserved without raw JSON dumps
    snap_stale = TaskSnapshot(
        run=run.model_copy(update={"status": TaskStatus.PARTIAL}),
        task=task,
        budget_config=BudgetConfig(),
        budget_usage=BudgetUsage(),
        transitions=(),
        result=Result(
            task_id=task.task_id,
            run_id=run.run_id,
            status=TaskStatus.PARTIAL,
            answer="Excluded non-authorized records.",
            partial_info={
                "available_sources": ["scada", "maintenance"],
                "missing_sources": [],
                "source_errors": {},
                "rejected_record_ids": ["RDG-STALE-01", "RDG-BAD-01"],
                "min_sources": 2,
            },
        ),
        receipts=(),
    )
    meta_stale = AgentTurnRunner._build_runtime_meta(snap_stale, lane=Lane.INDUSTRIAL)
    partial_joined = json.dumps(meta_stale["partial_evidence"])
    assert "RDG-STALE-01" in partial_joined
    assert "RDG-BAD-01" in partial_joined
    assert '"available_sources": [' not in partial_joined
    assert '"missing_sources": [' not in partial_joined


@pytest.mark.n1
def test_industrial_turn_factory_empty_tool_map_returns_clean_message() -> None:
    cfg = load_facility_config(_FACILITY_A_PATH)
    turn_factory = make_industrial_turn_factory(cfg)
    prompt_ctx = PromptContext(
        task_id="task-empty-1",
        run_id="run-empty-1",
        depth=0,
        query="Reply with OK",
        facility_id="facility-a",
    )
    budget = BudgetRemaining(
        active_children_remaining=1,
        depth_remaining=1,
        tool_calls_remaining=8,
        model_calls_remaining=4,
        wall_seconds_remaining=60.0,
        tokens_remaining=8000,
    )
    turn = turn_factory(prompt_ctx, (), budget)
    assert isinstance(turn.decision, ModelDecision)
    assert turn.decision.decision_type == "final"
    assert turn.decision.final_answer is not None
    assert "bomba 34" not in turn.decision.final_answer.lower()
    assert "Collected 0 observation" not in turn.decision.final_answer


@pytest.mark.n1
def test_parse_agy_stream_event_handles_null_and_invalid_step_index() -> None:
    for raw_idx, expected in (
        (None, None),
        ("not-an-int", None),
        (True, None),
        ("7", 7),
        (0, 0),
    ):
        line = json.dumps(
            {
                "event": "step_update",
                "step_update": {
                    "step_index": raw_idx,
                    "state": "ACTIVE",
                    "step_type": "tool",
                    "tool_name": "run_command",
                    "tool_info": {
                        "name": "run_command",
                        "parameters": {"CommandLine": "echo ok"},
                    },
                },
            }
        )
        ev = parse_agy_stream_event(line)
        assert ev is not None
        assert ev["type"] == "tool"
        assert ev["step_index"] == expected
        assert ev["command"] == "echo ok"

    omitted_line = json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "state": "ACTIVE",
                "step_type": "tool",
                "tool_name": "run_command",
                "tool_info": {"name": "run_command", "parameters": {"CommandLine": "echo ok"}},
            },
        }
    )
    ev_omitted = parse_agy_stream_event(omitted_line)
    assert ev_omitted is not None
    assert ev_omitted["step_index"] is None


@pytest.mark.n1
def test_gate_mid_turn_tool_blocks_wrapper_quoted_destructive_active_commands(
    tmp_path: Path,
) -> None:
    store, bus, runner = _make_unit_runner(tmp_path)
    try:
        destructive_cases: list[tuple[str | None, str]] = [
            ('bash -c "rm -rf /', 'bash -c "rm -rf /'),
            ("sh -c 'rm -rf /", "sh -c 'rm -rf /"),
            (
                'python3 -c "import os; os.system(\'rm -rf /\')',
                'python3 -c "import os; os.system(\'rm -rf /\')',
            ),
            (
                'python3 -c "import os; os.system(\'rm -rf /',
                'python3 -c "import os; os.system(\'rm -rf /',
            ),
            (None, 'bash -c "rm -rf /'),
        ]
        for idx, (cmd, summary) in enumerate(destructive_cases):
            allowed, reason, deferred = runner._gate_mid_turn_tool_with_status(
                bot_id="bot_browser",
                turn_id=f"trn_wrap_{idx}",
                lane=Lane.GENERAL,
                tool_name="run_command",
                category="terminal",
                summary=summary,
                command=cmd,
                allow_incomplete_syntax=True,
            )
            assert allowed is False, f"Expected immediate block for {cmd!r} / {summary!r}"
            assert reason is not None
            assert deferred is False

        benign_partial = (
            "curl -s -X POST http://127.0.0.1:8000/api/browser/action "
            '-H "Content-Type: application/json" -d \'{"type":"'
        )
        allowed_b, reason_b, deferred_b = runner._gate_mid_turn_tool_with_status(
            bot_id="bot_browser",
            turn_id="trn_wrap_benign",
            lane=Lane.GENERAL,
            tool_name="run_command",
            category="terminal",
            summary=benign_partial[:120],
            command=benign_partial,
            allow_incomplete_syntax=True,
        )
        assert allowed_b is True
        assert reason_b is None
        assert deferred_b is True
    finally:
        bus.close()
        store.close()


@pytest.mark.n1
async def test_lane_router_spanish_conceptual_and_cost_queries() -> None:
    cfg = load_facility_config(_FACILITY_A_PATH)
    router = LaneRouter()

    for query in (
        "Explica qué es una válvula de bola",
        "Qué es una válvula de bola?",
        "¿Qué es una válvula de bola?",
        "Cómo funciona una válvula de bola?",
    ):
        decision = await router.route(query, facility_config=cfg)
        assert decision.lane == Lane.GENERAL, f"Misrouted {query!r} -> {decision.lane}"

    for query in (
        "How much does a ball valve cost?",
        "¿Cuánto cuesta una válvula de bola?",
    ):
        decision = await router.route(query, facility_config=cfg)
        assert decision.lane == Lane.GENERAL, f"Misrouted {query!r} -> {decision.lane}"
        assert decision.domain_profile == "web_research"

    assert (
        await router.route("What is the price of pump P-34?", facility_config=cfg)
    ).lane == Lane.MIXED
    assert (
        await router.route(
            "Verificar alarma SCADA de válvula PT-3401 y buscar precio web",
            facility_config=cfg,
        )
    ).lane == Lane.MIXED
    assert (
        await router.route("Check valve status in SCADA", facility_config=cfg)
    ).lane == Lane.INDUSTRIAL
    assert (
        await router.route("Revisar alarmas de Bomba 34", facility_config=cfg)
    ).lane == Lane.INDUSTRIAL


@pytest.mark.n1
def test_parse_agy_stream_event_hydrates_500_char_ellipsis_truncated_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.engine.policy_gateway import safety_floor
    from src.web.workspace import _lookup_untruncated_agy_command, parse_agy_stream_event

    conv_id = "11111111-2222-3333-4444-555555555555"
    logs_dir = tmp_path / conv_id / ".system_generated" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CONTROLBOT_AGY_BRAIN_ROOT", str(tmp_path))

    benign_full_cmd = (
        'for u in \\\n  "https://example.com/' + ("a" * 520) + '"; do\n  echo "$u"\ndone'
    )
    malicious_full_cmd = 'echo "' + ("b" * 520) + '" && rm -rf /'
    (logs_dir / "transcript_full.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "step_index": 34,
                        "type": "PLANNER_RESPONSE",
                        "tool_calls": [
                            {"name": "run_command", "args": {"CommandLine": benign_full_cmd}}
                        ],
                    }
                ),
                json.dumps(
                    {
                        "step_index": 36,
                        "type": "PLANNER_RESPONSE",
                        "tool_calls": [
                            {"name": "run_command", "args": {"CommandLine": malicious_full_cmd}}
                        ],
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    benign_truncated = benign_full_cmd[:499] + "\u2026"
    assert safety_floor("run_command", {"command": benign_truncated}) is not None
    ev_benign = parse_agy_stream_event(
        json.dumps(
            {
                "event": "step_update",
                "step_update": {
                    "conversation_id": conv_id,
                    "step_index": 35,
                    "state": "DONE",
                    "step_type": "tool",
                    "tool_name": "run_command",
                    "tool_info": {
                        "name": "run_command",
                        "parameters": {"CommandLine": benign_truncated},
                    },
                },
            }
        )
    )
    assert ev_benign is not None
    assert ev_benign["command"] == benign_full_cmd
    assert safety_floor("run_command", {"command": ev_benign["command"]}) is None

    malicious_truncated = malicious_full_cmd[:499] + "\u2026"
    ev_mal = parse_agy_stream_event(
        json.dumps(
            {
                "event": "step_update",
                "step_update": {
                    "conversation_id": conv_id,
                    "step_index": 37,
                    "state": "DONE",
                    "step_type": "tool",
                    "tool_name": "run_command",
                    "tool_info": {
                        "name": "run_command",
                        "parameters": {"CommandLine": malicious_truncated},
                    },
                },
            }
        )
    )
    assert ev_mal is not None
    assert ev_mal["command"] == malicious_full_cmd
    assert safety_floor("run_command", {"command": ev_mal["command"]}) is not None

    # Path traversal conversation IDs must fail closed
    assert (
        _lookup_untruncated_agy_command("../../etc/passwd", benign_truncated, brain_root=tmp_path)
        is None
    )


@pytest.mark.n1
def test_build_prompt_includes_shell_policy_and_live_browser_hint(tmp_path: Path) -> None:
    store, bus, runner = _make_unit_runner(tmp_path)
    try:
        bot = store.list_bots()[0]
        prompt = runner._build_bot_prompt(
            bot=bot,
            thread_id=str(bot["thread_id"]),
            user_message={"content": "Find the price of Tzone THT02"},
            skill_ids=[],
            thinking_level="medium",
        )
        assert "[EXECUTION & SHELL POLICY]" in prompt
        assert "$(...)" in prompt
        assert "/api/browser/action" in prompt
        assert prompt.index("[EXECUTION & SHELL POLICY]") < prompt.index("[USER MESSAGE]")
    finally:
        bus.close()
        store.close()



