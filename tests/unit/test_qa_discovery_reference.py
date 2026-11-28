"""Unit tests for M3 UI control discovery, UX telemetry, and Grok Bot reference cards."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest
from src.factory.errors import IsolationBoundaryError
from src.qa.discovery import StaticControlSpec, discover_static_controls
from src.qa.models import ControlInventoryItem, CoverageReport, ReferenceBehaviorCard
from src.qa.reference_cards import (
    FIVE_DIMENSIONS,
    build_m3_observed_reference_cards,
    build_ref_unavailable_card,
    build_reference_card,
    compare_against_fixture_truth,
    load_reference_cards,
    observe_grokbot_readonly,
    save_reference_card,
    validate_reference_card,
)
from src.qa.ux_metrics import (
    PNG_MAGIC,
    ScreenshotCheckpoint,
    UxFlowMetrics,
    contains_unredacted_secret_m3,
    evaluate_error_actionability,
    measure_ux_action,
    save_ux_metrics,
    validate_png_file,
)
from src.storage.redaction import contains_unredacted_secret_strict

pytestmark = pytest.mark.n1

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_discover_static_controls_covers_all_modules_and_flags_a11y_gaps() -> None:
    frontend_src = _REPO_ROOT / "frontend" / "src"
    specs = discover_static_controls(frontend_src)
    assert len(specs) > 50
    assert all(isinstance(s, StaticControlSpec) for s in specs)

    modules = {s.module for s in specs}
    for expected in (
        "shell",
        "roster",
        "chat",
        "computer",
        "artifacts",
        "settings",
        "memory",
        "routines",
        "hitl",
    ):
        assert expected in modules, f"Missing module {expected!r} in static discovery"

    takeover_dialogs = [
        s
        for s in specs
        if "FullScreenTakeoverModal.tsx" in s.source_file and s.role == "dialog"
    ]
    assert takeover_dialogs, "Expected dialog spec in FullScreenTakeoverModal.tsx"
    assert all("missing_modal_focus_trap" not in s.a11y_gaps for s in takeover_dialogs)

    labeled_gaps = [s for s in specs if "missing_accessible_label" in s.a11y_gaps]
    assert labeled_gaps == [], (
        f"Expected 0 static missing_accessible_label gaps, got: {labeled_gaps}"
    )


def test_discover_static_controls_flags_synthetic_missing_modal_focus_trap(
    tmp_path: Path,
) -> None:
    tsx_dir = tmp_path / "features" / "computer"
    tsx_dir.mkdir(parents=True)
    (tsx_dir / "NoTrapModal.tsx").write_text(
        """
export function NoTrapModal() {
  return (
    <div role="dialog" aria-modal="true" aria-label="No trap">
      <button type="button">Close</button>
    </div>
  );
}
""",
        encoding="utf-8",
    )
    specs = discover_static_controls(tmp_path)
    dialogs = [s for s in specs if s.role == "dialog"]
    assert len(dialogs) == 1
    assert "missing_modal_focus_trap" in dialogs[0].a11y_gaps


def test_discover_static_controls_handles_arrow_functions_in_jsx(tmp_path: Path) -> None:
    tsx_dir = tmp_path / "features" / "chat"
    tsx_dir.mkdir(parents=True)
    (tsx_dir / "SampleWidget.tsx").write_text(
        """
export function SampleWidget() {
  return (
    <div>
      <button type="button" onClick={() => setCount((c) => c + 1)} aria-label="Increment">
        Plus
      </button>
      <input type="text" />
    </div>
  );
}
""",
        encoding="utf-8",
    )
    specs = discover_static_controls(tmp_path)
    buttons = [s for s in specs if s.role == "button"]
    inputs = [s for s in specs if s.role == "textbox"]
    assert len(buttons) == 1
    assert buttons[0].accessible_name == "Increment"
    assert buttons[0].module == "chat"
    assert len(inputs) == 1
    assert "missing_accessible_label" in inputs[0].a11y_gaps


def test_coverage_report_arithmetic_and_non_covered_reason_invariant() -> None:
    items = [
        ControlInventoryItem(
            control_id="ctrl-1",
            module="chat",
            route="/app",
            role="button",
            accessible_name="Send",
            selector='button[aria-label="Send"]',
            initial_state="enabled",
            post_state="message_sent",
            coverage_status="covered",
        ),
        ControlInventoryItem(
            control_id="ctrl-2",
            module="chat",
            route="/app",
            role="button",
            accessible_name="Deploy",
            selector="#silent-noop-btn",
            initial_state="enabled",
            post_state="silent_noop",
            coverage_status="blocked",
            blocked_reason="Silent no-op control: click had no effect",
        ),
        ControlInventoryItem(
            control_id="ctrl-3",
            module="hitl",
            route="/app#hitl",
            role="button",
            accessible_name="Allow once",
            selector='button:has-text("Allow once")',
            initial_state="static_declared",
            coverage_status="pending",
            blocked_reason="Requires pending HITL ApprovalCard",
        ),
    ]
    report = CoverageReport(
        campaign_id="unit-cov",
        repo_sha="abc1234",
        total_controls=3,
        covered_count=1,
        blocked_count=1,
        pending_count=1,
        out_of_scope_count=0,
        by_module={
            "chat": {"total": 2, "covered": 1, "blocked": 1, "pending": 0, "out_of_scope": 0},
            "hitl": {"total": 1, "covered": 0, "blocked": 0, "pending": 1, "out_of_scope": 0},
        },
        items=items,
    )
    assert (
        report.covered_count
        + report.blocked_count
        + report.pending_count
        + report.out_of_scope_count
        == report.total_controls
    )
    for item in report.items:
        if item.coverage_status != "covered":
            assert item.blocked_reason


def test_reference_cards_enforce_main_test_only_and_reject_forbidden_bots() -> None:
    for bad_bot in ("work", "prod", "admin", "custom", "", "main ", "Test"):
        with pytest.raises(IsolationBoundaryError):
            build_reference_card(
                card_id="ref-bad",
                case_id="CB-01",
                source="grok_bot_app",
                status="observed",
                bot_used=bad_bot,
                discoverability="d",
                state_transition="s",
                independent_verification="v",
                missing_data_or_permission="m",
                efficiency_notes="e",
                expected_controlbot_contract="c",
            )
        with pytest.raises(IsolationBoundaryError):
            observe_grokbot_readonly(case_id="CB-01", bot_name=bad_bot)

    with pytest.raises(ValueError, match="missing required non-empty dimensions"):
        build_reference_card(
            card_id="ref-missing-dim",
            case_id="CB-01",
            source="grok_bot_app",
            status="observed",
            bot_used="test",
            discoverability="ok",
            state_transition="",
            independent_verification="ok",
            missing_data_or_permission="ok",
            efficiency_notes="ok",
            expected_controlbot_contract="ok",
        )


def test_reference_cards_ref_unavailable_secret_redaction_and_persistence(tmp_path: Path) -> None:
    unavail = observe_grokbot_readonly(case_id="CB-02", bot_name="test", display="")
    assert unavail.status == "REF_UNAVAILABLE"
    assert unavail.source == "ref_unavailable"
    assert unavail.bot_used == "test"
    assert unavail.unavailable_reason
    assert validate_reference_card(unavail) == []

    card_with_secret_in_conditions = build_reference_card(
        card_id="ref-cb01-redacted",
        case_id="CB-01",
        source="grok_bot_app",
        status="observed",
        bot_used="main",
        conditions={
            "accessToken": "tok-raw-secret-123",
            "note": "Bearer raw-bearer-secret-456",
        },
        discoverability="Composer visible in 1 click",
        state_transition="Pending -> Done",
        independent_verification="Exact output",
        missing_data_or_permission="Explicit refusal",
        efficiency_notes="1 action",
        expected_controlbot_contract="Match parity",
    )
    assert validate_reference_card(card_with_secret_in_conditions) == []
    assert not contains_unredacted_secret_strict(
        json.loads(card_with_secret_in_conditions.model_dump_json())
    )

    cards_dir = tmp_path / "reference_cards"
    saved_path = save_reference_card(
        card_with_secret_in_conditions, cards_dir, repo_root=_REPO_ROOT
    )
    assert saved_path.is_file()
    loaded = load_reference_cards(cards_dir)
    assert len(loaded) == 1
    assert loaded[0].card_id == "ref-cb01-redacted"

    # Manually built unredacted card must fail validation and save_reference_card.
    leaky = ReferenceBehaviorCard(
        card_id="ref-leaky",
        case_id="CB-01",
        source="grok_bot_app",
        status="observed",
        bot_used="test",
        conditions={"timing_comparability": "ok", "privacy_scope": "ok"},
        discoverability="Bearer secret_leak_xyz",
        state_transition="s",
        independent_verification="v",
        missing_data_or_permission="m",
        efficiency_notes="e",
        expected_controlbot_contract="c",
    )
    assert "unredacted_secret_detected" in validate_reference_card(leaky)
    with pytest.raises(ValueError, match="unredacted_secret_detected"):
        save_reference_card(leaky, cards_dir, repo_root=_REPO_ROOT)

    forbidden_dir = Path.home() / ".config" / "Grok Bot" / "cards"
    with pytest.raises(IsolationBoundaryError):
        save_reference_card(unavail, forbidden_dir, repo_root=_REPO_ROOT)


def test_compare_against_fixture_truth_synthetic_beats_stale_reference() -> None:
    stale_card = build_reference_card(
        card_id="ref-cb02-stale",
        case_id="CB-02",
        source="grok_bot_app",
        status="observed",
        bot_used="main",
        discoverability="Single prompt",
        state_transition="Returns price",
        independent_verification="Stale external claim USD 154.00",
        missing_data_or_permission="None",
        efficiency_notes="1 turn",
        expected_controlbot_contract="Return active fixture price USD 129.50",
    )
    override_res = compare_against_fixture_truth(
        card=stale_card,
        fixture_passed=True,
        fixture_detail="ControlBot returned active USD 129.50",
        reference_matches_fixture=False,
    )
    assert override_res["truth_source"] == "synthetic_fixture"
    assert override_res["authoritative_passed"] is True
    assert override_res["reference_discrepancy"] is True
    assert override_res["verdict"] == "pass_fixture_overrides_reference"

    fail_res = compare_against_fixture_truth(
        card=stale_card,
        fixture_passed=False,
        fixture_detail="ControlBot returned prior USD 154.00",
        reference_matches_fixture=True,
    )
    assert fail_res["authoritative_passed"] is False
    assert fail_res["verdict"] == "fail_controlbot_issue_opened"
    assert fail_res["action"] == "open_qa_failure_item"

    unavail_card = build_ref_unavailable_card(case_id="CB-11", reason="Local SCADA offline")
    local_res = compare_against_fixture_truth(
        card=unavail_card,
        fixture_passed=True,
        fixture_detail="Pump 34 provenance verified",
    )
    assert local_res["authoritative_passed"] is True
    assert local_res["verdict"] == "pass_local_fixture"


def test_m3_observed_reference_cards_all_9_valid() -> None:
    cards = build_m3_observed_reference_cards()
    assert len(cards) == 9
    observed = [c for c in cards if c.status != "REF_UNAVAILABLE"]
    unavail = [c for c in cards if c.status == "REF_UNAVAILABLE"]
    assert len(observed) == 7
    assert len(unavail) == 2

    for card in cards:
        assert validate_reference_card(card) == []
        assert "timing_comparability" in card.conditions
        assert "privacy_scope" in card.conditions
        if card.status != "REF_UNAVAILABLE":
            assert card.bot_used in {"main", "test"}
            for dim in FIVE_DIMENSIONS:
                assert getattr(card, dim).strip()


def test_ux_metrics_actionability_png_validation_and_redaction(tmp_path: Path) -> None:
    ok, _ = evaluate_error_actionability(
        "Antigravity CLI is not installed. Switch engine to ControlBot Runtime or install agy."
    )
    assert ok is True

    bad_empty, _ = evaluate_error_actionability("   ")
    assert bad_empty is False

    bad_trace, _ = evaluate_error_actionability(
        "Traceback (most recent call last):\n  File 'runner.py', line 10"
    )
    assert bad_trace is False

    bad_net, _ = evaluate_error_actionability("net::ERR_CONNECTION_REFUSED at 127.0.0.1:8101")
    assert bad_net is False

    bad_secret, _ = evaluate_error_actionability("Retry failed with Bearer my_secret_token_999")
    assert bad_secret is False

    bad_png = tmp_path / "bad.png"
    bad_png.write_bytes(b"not-a-png")
    with pytest.raises(ValueError, match="Invalid PNG"):
        validate_png_file(bad_png)

    good_png = tmp_path / "good.png"
    good_png.write_bytes(PNG_MAGIC + b"\x00" * 64)
    size, digest = validate_png_file(good_png)
    assert size == len(PNG_MAGIC) + 64
    assert len(digest) == 64

    flow = UxFlowMetrics(
        case_id="CB-01",
        run_id="run-1",
        actions_to_reach=1,
        ttfp_ms=120.5,
        completion_ms=450.0,
        cancel_available=True,
        result_clarity_notes="Bearer secret_should_be_redacted",
        screenshots=[
            ScreenshotCheckpoint(
                checkpoint_id="shot-1",
                case_id="CB-01",
                label="initial",
                path=str(good_png),
                byte_size=size,
                sha256=digest,
            )
        ],
    )
    out_file = save_ux_metrics([flow], tmp_path / "ux_metrics.json", repo_root=_REPO_ROOT)
    saved_text = out_file.read_text(encoding="utf-8")
    assert "secret_should_be_redacted" not in saved_text
    assert not contains_unredacted_secret_strict(json.loads(saved_text))


def test_discover_static_controls_handles_comments_conditionals_comparisons_and_svg(
    tmp_path: Path,
) -> None:
    tsx_dir = tmp_path / "features" / "chat"
    tsx_dir.mkdir(parents=True)
    long_path = "M0 0 " + " ".join(f"L{i} {i}" for i in range(120))
    (tsx_dir / "ComplexWidget.tsx").write_text(
        f"""
export function ComplexWidget({{ open, a, b, c, d }}: {{
  open: boolean; a: number; b: number; c: number; d: number;
}}) {{
  if (a < b && c > d) {{
    return <button type="button">FallbackBtn</button>;
  }}
  return (
    <div>
      <button
        type="button"
        onClick={{() => {{
          // don't break quote tracking on apostrophes!
          /* also don't break on block comments ' ` " */
          console.log('ok');
        }}}}
      >
        FirstBtn
      </button>
      <button type="button">SecondBtn</button>
      <button type="button">ThirdBtn</button>
      {{open && <button type="button">CondBtn</button>}}
      {{open ? (
        <button type="button">TernaryYes</button>
      ) : (
        <button type="button">TernaryNo</button>
      )}}
      <button type="button">
        <svg viewBox="0 0 24 24"><path d="{long_path}" /></svg>
        IconLabel
      </button>
      <button type="button">
        Outer <button type="button">Nested</button> Label
      </button>
    </div>
  );
}}
""",
        encoding="utf-8",
    )
    specs = discover_static_controls(tmp_path)
    names = [s.accessible_name for s in specs]
    for expected in (
        "FallbackBtn",
        "FirstBtn",
        "SecondBtn",
        "ThirdBtn",
        "CondBtn",
        "TernaryYes",
        "TernaryNo",
        "IconLabel",
    ):
        assert expected in names, f"Missing {expected!r} in {names}"
    for name in names:
        for bad_tok in (");", "<path", "=>", "return ", "}"):
            assert bad_tok not in name, f"Leaked JSX/TS token {bad_tok!r} in {name!r}"


def test_m3_api_token_redaction_and_load_validation(tmp_path: Path) -> None:
    tokens = (
        "sk-proj-1234567890abcdef1234567890abcdef",
        "sk-live-secret1234567890abcdef",
        "ghp_1234567890abcdef1234567890abcdef1234",
        "xoxb-1234567890-abcdef123456",
        "AIzaSyD1234567890abcdef1234567890",
    )
    card = build_reference_card(
        card_id="ref-token-scrub",
        case_id="CB-01",
        source="grok_bot_app",
        status="observed",
        bot_used="test",
        conditions={"note": f"Used {tokens[0]} and {tokens[2]}"},
        discoverability=f"Found with {tokens[1]}",
        state_transition=f"State {tokens[3]}",
        independent_verification=f"Verified {tokens[4]}",
        missing_data_or_permission="Safe text with task-description-panel",
        efficiency_notes="1 action",
        expected_controlbot_contract=f"Contract {tokens[0]}",
    )
    assert validate_reference_card(card) == []
    dumped = card.model_dump_json()
    for tok in tokens:
        assert tok not in dumped
    assert "task-description-panel" in dumped
    assert not contains_unredacted_secret_m3(json.loads(dumped))

    unavail = build_ref_unavailable_card(
        case_id="CB-02",
        reason=f"Offline key {tokens[0]}",
        expected_controlbot_contract=f"Contract {tokens[1]}",
    )
    assert tokens[0] not in (unavail.unavailable_reason or "")
    assert tokens[1] not in unavail.expected_controlbot_contract

    cards_dir = tmp_path / "cards"
    leaky_card = ReferenceBehaviorCard(
        card_id="ref-leaky-sk",
        case_id="CB-01",
        source="grok_bot_app",
        status="observed",
        bot_used="test",
        conditions={"timing_comparability": "ok", "privacy_scope": "ok"},
        discoverability="ok",
        state_transition="ok",
        independent_verification="ok",
        missing_data_or_permission="ok",
        efficiency_notes=f"Used {tokens[0]}",
        expected_controlbot_contract="ok",
    )
    assert "unredacted_secret_detected" in validate_reference_card(leaky_card)
    with pytest.raises(ValueError, match="unredacted_secret_detected"):
        save_reference_card(leaky_card, cards_dir, repo_root=_REPO_ROOT)

    # Corrupt/invalid persisted card on disk must fail strict load_reference_cards().
    cards_dir.mkdir(parents=True, exist_ok=True)
    (cards_dir / "bad.json").write_text(leaky_card.model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid ReferenceBehaviorCard"):
        load_reference_cards(cards_dir)
    assert len(load_reference_cards(cards_dir, strict=False)) == 1

    ok_sk, _ = evaluate_error_actionability(f"Retry with {tokens[0]}")
    assert ok_sk is False

    flow = UxFlowMetrics(
        case_id="CB-01",
        run_id="run-sk",
        actions_to_reach=1,
        ttfp_ms=10.0,
        completion_ms=20.0,
        result_clarity_notes=f"Saw {tokens[0]} and {tokens[1]}",
    )
    ux_path = save_ux_metrics([flow], tmp_path / "ux_sk.json", repo_root=_REPO_ROOT)
    ux_text = ux_path.read_text(encoding="utf-8")
    assert tokens[0] not in ux_text
    assert tokens[1] not in ux_text


def test_evaluate_error_actionability_rejects_raw_os_runtime_errors_and_false_verbs() -> None:
    bad_messages = (
        "OSError: [Errno 24] Too many open files in /var/run/app.sock",
        "RuntimeError: database is locked",
        "ValueError: invalid configuration payload",
        "TypeError: cannot read properties of undefined",
        "Too many open files",
        "Healthcheck failed on port 8101",
        "Startup failed unexpectedly",
    )
    for msg in bad_messages:
        ok, _ = evaluate_error_actionability(msg)
        assert ok is False, f"Expected non-actionable for {msg!r}"

    good_messages = (
        "Antigravity CLI is not installed. Switch engine to ControlBot Runtime or install agy.",
        "Connection lost. Open Settings to verify your network configuration and retry.",
        "Server unreachable. Check your connection and try again.",
    )
    for msg in good_messages:
        ok, _ = evaluate_error_actionability(msg)
        assert ok is True, f"Expected actionable for {msg!r}"


def test_measure_ux_action_nonblocking_poller_and_exception_safety() -> None:
    async def _run() -> None:
        async def _fast_action() -> str:
            await asyncio.sleep(0.01)
            return "done"

        async def _never_ready() -> bool:
            return False

        t0 = time.monotonic()
        res, timing = await measure_ux_action(
            _fast_action,
            ttfp_probe=_never_ready,
            poll_interval_s=1.0,
        )
        elapsed = time.monotonic() - t0
        assert res == "done"
        assert elapsed < 0.25
        assert timing.completion_ms < 250.0

        # Cancellation must unwind immediately without waiting on poll_interval_s.
        async def _slow_action() -> str:
            await asyncio.sleep(2.0)
            return "never"

        t1 = time.monotonic()
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(
                measure_ux_action(
                    _slow_action,
                    ttfp_probe=_never_ready,
                    poll_interval_s=1.5,
                ),
                timeout=0.05,
            )
        assert (time.monotonic() - t1) < 0.3

        # Probe exceptions must never mask action() result or exception.
        async def _failing_probe() -> bool:
            raise RuntimeError("page closed")

        res2, _ = await measure_ux_action(_fast_action, ttfp_probe=_failing_probe)
        assert res2 == "done"

        async def _failing_action() -> str:
            raise ValueError("action_boom")

        with pytest.raises(ValueError, match="action_boom"):
            await measure_ux_action(_failing_action, ttfp_probe=_failing_probe)

    asyncio.run(_run())
