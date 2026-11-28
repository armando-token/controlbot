"""Permanent Tier-5 adversarial regression tests covering Findings #1..#8."""

from __future__ import annotations

import asyncio
import json
import subprocess
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from src.doctor import CheckResult, CheckStatus, EvidenceLevel
from src.n3_probe import N3ProbeReport
from src.qa.fixtures.cb_10_multiagent import (
    build_cb10_three_deliverables_spec,
    evaluate_cb10_project,
)
from src.qa.fixtures.cb_valve_104 import (
    evaluate_valve_104_reply,
    load_or_build_cb_valve_104_catalog,
    serve_valve_catalog,
)
from src.qa.models import CampaignState
from src.qa.scenarios import run_scenario
from src.qa.scenarios._common import TargetCapabilities, TurnOutcome
from src.qa.scenarios.cb_01 import _normalize_markdown_for_match, _verify_cb01_ui_state
from src.qa.scenarios.cb_13 import _run_pytest_n3

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _make_state(
    camp_dir: Path,
    *,
    target_url: str = "http://127.0.0.1:19999",
) -> CampaignState:
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-t5-unit",
        base_sha="deadbeef1234",
        lane="local_deterministic",
        target_url=target_url,
        output_dir=str(camp_dir),
    )
    (camp_dir / "campaign.json").write_text(state.model_dump_json(indent=2), encoding="utf-8")
    return state


def _caps(
    *,
    backend_mode: str = "emulated",
    agy_available: bool = False,
    effect_sim_url: str | None = None,
    effect_sim_reachable: bool = False,
    system_info: dict[str, Any] | None = None,
) -> TargetCapabilities:
    return TargetCapabilities(
        health_ok=True,
        backend_mode=backend_mode,
        runtime_mode="live_runtime",
        model_id="local-llm" if backend_mode == "local_http" else "emulated",
        agy_available=agy_available,
        projects_root=None,
        effect_sim_url=effect_sim_url,
        effect_sim_reachable=effect_sim_reachable,
        request_ids=(),
        system_info=system_info if system_info is not None else {"backend_mode": backend_mode},
    )


# ---------------------------------------------------------------------------
# Finding #1: CB-01 Markdown normalization & non-agy UI error + ApprovalCard
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_cb01_markdown_normalization_and_ui_verification() -> None:
    md_reply = "**CB-01 Status**: Verified `OK` — response persisted cleanly."
    normalized = _normalize_markdown_for_match(md_reply)
    assert normalized == "CB-01 Status: Verified OK — response persisted c"
    assert "**" not in normalized
    assert "`" not in normalized

    md_heading = "### Summary\n- [Item One](https://example.local)"
    assert _normalize_markdown_for_match(md_heading) == "Summary"
    assert _normalize_markdown_for_match("```\n```\n> *Quoted* text") == "Quoted text"

    class _FakeTextLocator:
        def __init__(self, should_timeout: bool) -> None:
            self._should_timeout = should_timeout
            self.first = self

        async def wait_for(self, *, state: str = "visible", timeout: int = 10000) -> None:
            del state, timeout
            if self._should_timeout:
                raise PlaywrightTimeoutError("Timed out waiting for locator")

    class _FakeCardLocator:
        def __init__(self, card_missing: bool) -> None:
            self._card_missing = card_missing
            self.first = self

        def filter(self, *, has_text: str = "") -> _FakeCardLocator:
            del has_text
            return self

        def get_by_text(self, text: str) -> _FakeTextLocator:
            del text
            return _FakeTextLocator(self._card_missing)

    class _FakePage:
        def __init__(self, *, bubble_missing: bool, card_missing: bool) -> None:
            self._bubble_missing = bubble_missing
            self._card_missing = card_missing

        def locator(self, selector: str) -> Any:
            if selector == ".gb-markdown":
                return _FakeCardLocator(self._bubble_missing)
            return _FakeCardLocator(self._card_missing)

    async def _run_checks() -> None:
        # Live agy Markdown bubble visible -> passes
        ok_msg, ok_card, err = await _verify_cb01_ui_state(
            _FakePage(bubble_missing=False, card_missing=True),  # type: ignore[arg-type]
            is_live_agent=True,
            expected_assistant_text=normalized,
            expected_approval_title="",
        )
        assert (ok_msg, ok_card, err) == (True, True, None)

        # Non-agy with missing UI error bubble -> fails
        ok_msg2, ok_card2, err2 = await _verify_cb01_ui_state(
            _FakePage(bubble_missing=True, card_missing=False),  # type: ignore[arg-type]
            is_live_agent=False,
            expected_assistant_text="General chat cannot run",
            expected_approval_title="CB-01 simple chat turn abc",
        )
        assert ok_msg2 is False
        assert ok_card2 is False
        assert err2 and "assistant error message" in err2

        # Non-agy with error bubble visible but ApprovalCard missing -> fails
        ok_msg3, ok_card3, err3 = await _verify_cb01_ui_state(
            _FakePage(bubble_missing=False, card_missing=True),  # type: ignore[arg-type]
            is_live_agent=False,
            expected_assistant_text="General chat cannot run",
            expected_approval_title="CB-01 simple chat turn abc",
        )
        assert ok_msg3 is True
        assert ok_card3 is False
        assert err3 and "ApprovalCard" in err3

        # Non-agy with both error bubble and ApprovalCard visible -> passes
        ok_msg4, ok_card4, err4 = await _verify_cb01_ui_state(
            _FakePage(bubble_missing=False, card_missing=False),  # type: ignore[arg-type]
            is_live_agent=False,
            expected_assistant_text="General chat cannot run",
            expected_approval_title="CB-01 simple chat turn abc",
        )
        assert (ok_msg4, ok_card4, err4) == (True, True, None)

    asyncio.run(_run_checks())


# ---------------------------------------------------------------------------
# Finding #2: CB-07 empty effects guard, real error actionability, deny=0
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_cb07_failed_task_no_index_error_and_real_409_actionability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StubCard:
        def __init__(self, card_missing: bool = False) -> None:
            self._card_missing = card_missing
            self.first = self

        def filter(self, *, has_text: str = "") -> _StubCard:
            del has_text
            return self

        def get_by_text(self, text: str) -> _StubCard:
            del text
            return self

        def get_by_role(self, role: str, *, name: str = "") -> _StubCard:
            del role, name
            return self

        async def wait_for(self, *, state: str = "visible", timeout: int = 10000) -> None:
            del state, timeout
            if self._card_missing:
                raise PlaywrightTimeoutError("missing")

        async def click(self) -> None:
            return None

    class _StubPage:
        async def goto(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def wait_for_selector(self, *args: Any, **kwargs: Any) -> None:
            return None

        def locator(self, selector: str) -> _StubCard:
            del selector
            return _StubCard()

    class _StubPwSession:
        def __init__(self) -> None:
            self.page = _StubPage()
            self.console_errors: list[str] = []
            self.page_errors: list[str] = []
            self.external_requests: list[str] = []

        async def __aenter__(self) -> _StubPwSession:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    async def _fake_shot(self: Any, *args: Any, **kwargs: Any) -> Any:
        from src.qa.ux_metrics import ScreenshotCheckpoint

        return ScreenshotCheckpoint(
            checkpoint_id="shot-cb07",
            case_id="CB-07",
            label="cb07_approvals",
            path=str(tmp_path / "shot.png"),
            byte_size=64,
            sha256="0" * 64,
            is_error_state=bool(kwargs.get("is_error_state", False)),
        )

    async def _fake_turn(*args: Any, **kwargs: Any) -> TurnOutcome:
        return TurnOutcome(
            turn_id="trn_cb07",
            user_message={"id": "msg_u1"},
            assistant_messages=[],
            events=[],
            presence_states=["waiting_human"],
            handoffs=[],
            approvals=[{"id": "apr_ui"}],
        )

    monkeypatch.setattr(
        "src.qa.scenarios.cb_07.open_browser_session", lambda **_kw: _StubPwSession()
    )
    monkeypatch.setattr("src.qa.scenarios._common.ScenarioContext.capture_shot", _fake_shot)
    monkeypatch.setattr("src.qa.scenarios.cb_07.trigger_and_wait_turn", _fake_turn)
    monkeypatch.setattr(
        "src.qa.scenarios.registry.probe_target_capabilities",
        lambda *_a, **_kw: _caps(
            effect_sim_url="http://127.0.0.1:19991",
            effect_sim_reachable=True,
        ),
    )

    state_holder: dict[str, Any] = {
        "total_applied": 0,
        "effects": [],
        "task_status": "failed",
        "conflict_detail": "Conflicting payload for idempotency_key='k1'.",
    }
    approvals_db: dict[str, dict[str, Any]] = {}
    drafts_db: dict[str, str] = {}

    def _studio_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/approvals" and request.method == "POST":
            body = json.loads(request.content.decode("utf-8"))
            aid = f"apr_{len(approvals_db) + 1}"
            approvals_db[aid] = {
                "id": aid,
                "status": "pending",
                "allow_always_allowed": body.get("allow_always_allowed", True),
            }
            return httpx.Response(201, json=approvals_db[aid])
        if path.startswith("/api/v1/approvals/") and path.endswith("/resolve"):
            aid = path.split("/")[4]
            body = json.loads(request.content.decode("utf-8"))
            dec = body["decision"]
            rec = approvals_db[aid]
            if rec["status"] != "pending":
                return httpx.Response(
                    409,
                    json={
                        "detail": (
                            f"Approval {aid} already resolved with status '{rec['status']}'."
                        )
                    },
                )
            if dec == "always_allow" and not rec["allow_always_allowed"]:
                return httpx.Response(
                    409, json={"detail": f"Approval {aid} does not allow 'always_allow'."}
                )
            rec["status"] = "allowed_once" if dec == "allow_once" else "denied"
            return httpx.Response(200, json=rec)
        if path == "/api/v1/drafts" and request.method == "POST":
            did = f"drf_{len(drafts_db) + 1}"
            drafts_db[did] = "pending"
            return httpx.Response(201, json={"id": did, "status": "pending"})
        if path.startswith("/api/v1/drafts/") and path.endswith("/resolve"):
            did = path.split("/")[4]
            if drafts_db[did] != "pending":
                return httpx.Response(409, json={"detail": f"Draft {did} already resolved."})
            drafts_db[did] = "discarded"
            return httpx.Response(200, json={"id": did, "status": "discarded"})
        if path == "/api/tasks" and request.method == "POST":
            if state_holder["task_status"] == "succeeded":
                eff = {
                    "idempotency_key": "cb07-qa-1",
                    "asset_id": "bomba-34-a1",
                    "action": "reset_latch",
                    "params": {},
                }
                state_holder["total_applied"] += 1
                state_holder["effects"].append(eff)
            return httpx.Response(201, json={"run_id": "run_cb07_1"})
        if path == "/api/tasks/run_cb07_1":
            return httpx.Response(200, json={"run": {"status": state_holder["task_status"]}})
        return httpx.Response(404, json={})

    def _ef_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/effects/state":
            return httpx.Response(
                200,
                json={
                    "total_applied": state_holder["total_applied"],
                    "effects": state_holder["effects"],
                },
            )
        if path == "/api/effects/apply":
            body = json.loads(request.content.decode("utf-8"))
            if body.get("action") == "different_action":
                return httpx.Response(
                    409,
                    json={
                        "detail": state_holder["conflict_detail"],
                        "code": "IDEMPOTENCY_CONFLICT",
                    },
                )
            return httpx.Response(200, json={"deduplicated": True})
        return httpx.Response(404, json={})

    def _async_client_factory(self: Any, **_kw: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.target_url,
            transport=httpx.MockTransport(_studio_handler),
        )

    orig_async_client = httpx.AsyncClient

    def _httpx_client_router(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        if "transport" in kwargs:
            return orig_async_client(*args, **kwargs)
        return orig_async_client(transport=httpx.MockTransport(_ef_handler))

    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.async_client", _async_client_factory
    )
    monkeypatch.setattr("src.qa.scenarios.cb_07.httpx.AsyncClient", _httpx_client_router)

    # Probe A: Failed /api/tasks (empty effects) -> no IndexError, UI evaluated, actionable=False
    camp_fail = tmp_path / "camp_cb07_fail"
    res_fail = run_scenario(
        case_id="CB-07",
        campaign_dir=camp_fail,
        state=_make_state(camp_fail),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res_fail is not None
    rec_fail, _ = res_fail
    assert rec_fail.passed is False
    assert rec_fail.assertions["effect_sim_task_succeeded"] is False
    assert rec_fail.assertions["effect_sim_single_apply"] is False
    assert rec_fail.assertions["ui_approval_card_deny"] is True
    assert rec_fail.assertions["api_deny_zero_effects"] is True
    ux_fail = json.loads((camp_fail / "ux_metrics.json").read_text(encoding="utf-8"))
    assert ux_fail["flows"][-1]["error_actionable"] is False

    # Probe B: Succeeded /api/tasks with non-actionable 409 -> passed=True, error_actionable=False
    state_holder["task_status"] = "succeeded"
    state_holder["total_applied"] = 0
    state_holder["effects"] = []
    camp_nonact = tmp_path / "camp_cb07_nonact"
    res_nonact = run_scenario(
        case_id="CB-07",
        campaign_dir=camp_nonact,
        state=_make_state(camp_nonact),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res_nonact is not None
    rec_nonact, _ = res_nonact
    assert rec_nonact.passed is True
    assert rec_nonact.assertions["api_deny_zero_effects"] is True
    assert rec_nonact.assertions["effect_approval_allow_once"] is True
    assert rec_nonact.assertions["effect_sim_single_apply"] is True
    assert rec_nonact.assertions["ui_deny_zero_effects"] is True
    ux_nonact = json.loads((camp_nonact / "ux_metrics.json").read_text(encoding="utf-8"))
    assert ux_nonact["flows"][-1]["error_actionable"] is False

    # Probe C: Actionable 409 error text from effect_sim -> error_actionable=True
    state_holder["total_applied"] = 0
    state_holder["effects"] = []
    state_holder["conflict_detail"] = "Conflict for idempotency_key; retry with a new key."
    camp_act = tmp_path / "camp_cb07_act"
    res_act = run_scenario(
        case_id="CB-07",
        campaign_dir=camp_act,
        state=_make_state(camp_act),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res_act is not None
    ux_act = json.loads((camp_act / "ux_metrics.json").read_text(encoding="utf-8"))
    assert ux_act["flows"][-1]["error_actionable"] is True


# ---------------------------------------------------------------------------
# Finding #3: CB-04 & CB-10 @mention multi-bot leakage rejection
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_cb04_and_cb10_reject_multibot_mention_leakage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "src.qa.scenarios.registry.probe_target_capabilities",
        lambda *_a, **_kw: _caps(agy_available=True),
    )

    class _NoopPage:
        async def goto(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def wait_for_function(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def reload(self, *args: Any, **kwargs: Any) -> None:
            return None

        def locator(self, *_args: Any, **_kwargs: Any) -> _NoopPage:
            return self

        def get_by_text(self, *_args: Any, **_kwargs: Any) -> _NoopPage:
            return self

        @property
        def first(self) -> _NoopPage:
            return self

        async def wait_for(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def click(self) -> None:
            return None

    class _NoopPw:
        def __init__(self) -> None:
            self.page = _NoopPage()
            self.console_errors: list[str] = []
            self.page_errors: list[str] = []
            self.external_requests: list[str] = []

        async def __aenter__(self) -> _NoopPw:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    async def _fake_shot(self: Any, *args: Any, **kwargs: Any) -> Any:
        from src.qa.ux_metrics import ScreenshotCheckpoint

        return ScreenshotCheckpoint(
            checkpoint_id="shot-leak",
            case_id="CB-04",
            label="cb04_roster",
            path=str(tmp_path / "shot.png"),
            byte_size=64,
            sha256="0" * 64,
            is_error_state=False,
        )

    monkeypatch.setattr("src.qa.scenarios.cb_04.open_browser_session", lambda **_kw: _NoopPw())
    monkeypatch.setattr("src.qa.scenarios._common.ScenarioContext.capture_shot", _fake_shot)

    # CB-04 negative probe: both bot_b and bot_a reply on @bot_a turn (bot_a is [-1])
    dm_content = ""
    ch_content = ""

    def _cb04_handler(request: httpx.Request) -> httpx.Response:
        nonlocal dm_content, ch_content
        path = request.url.path
        if path == "/api/v1/sections" and request.method == "POST":
            return httpx.Response(201, json={"id": "sec_1"})
        if path == "/api/v1/sections/sec_1" and request.method == "PATCH":
            return httpx.Response(200, json={"id": "sec_1"})
        if path == "/api/v1/bots" and request.method == "POST":
            body = json.loads(request.content.decode("utf-8"))
            if "Alpha" in body["name"]:
                return httpx.Response(201, json={"id": "bot_a", "thread_id": "thr_a"})
            return httpx.Response(201, json={"id": "bot_b", "thread_id": "thr_b"})
        if path == "/api/v1/bots/bot_a" and request.method == "PATCH":
            body = json.loads(request.content.decode("utf-8"))
            return httpx.Response(200, json={"id": "bot_a", "hidden": body.get("hidden", False)})
        if path == "/api/v1/channels" and request.method == "POST":
            return httpx.Response(201, json={"id": "ch_1", "thread_id": "thr_ch"})
        if path == "/api/v1/threads/thr_a/messages":
            return httpx.Response(200, json={"messages": [{"content": dm_content}]})
        if path == "/api/v1/threads/thr_b/messages":
            return httpx.Response(200, json={"messages": []})
        if path == "/api/v1/threads/thr_ch/messages":
            return httpx.Response(200, json={"messages": [{"content": ch_content}]})
        return httpx.Response(200, json={})

    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.async_client",
        lambda self, **_kw: httpx.AsyncClient(
            base_url=self.target_url,
            transport=httpx.MockTransport(_cb04_handler),
        ),
    )

    async def _cb04_leak_turn(_cl: Any, thr: str, content: str, **_kw: Any) -> TurnOutcome:
        nonlocal dm_content, ch_content
        if thr == "thr_a":
            dm_content = content
            return TurnOutcome("t1", {"id": "u1"}, [{"sender_bot_id": "bot_a"}], [], [], [], [])
        ch_content = content
        # Leakage: bot_b replied first, bot_a replied last!
        return TurnOutcome(
            "t2",
            {"id": "u2"},
            [{"sender_bot_id": "bot_b"}, {"sender_bot_id": "bot_a"}],
            [],
            [],
            [],
            [],
        )

    monkeypatch.setattr("src.qa.scenarios.cb_04.trigger_and_wait_turn", _cb04_leak_turn)

    camp_04 = tmp_path / "camp_cb04_leak"
    res_04 = run_scenario(
        case_id="CB-04",
        campaign_dir=camp_04,
        state=_make_state(camp_04),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res_04 is not None
    rec_04, _ = res_04
    assert rec_04.passed is False
    assert rec_04.assertions["mention_routes_targeted_bot"] is False

    # CB-10 negative probe: both beta_id and alpha_id reply to @agent_alpha (alpha_id is [-1])
    def _cb10_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/bots" and request.method == "POST":
            body = json.loads(request.content.decode("utf-8"))
            if body["name"] == "agent_alpha":
                return httpx.Response(201, json={"id": "alpha_1"})
            return httpx.Response(201, json={"id": "beta_1"})
        if path == "/api/v1/channels" and request.method == "POST":
            return httpx.Response(201, json={"id": "ch_10", "thread_id": "thr_10"})
        return httpx.Response(200, json={})

    async def _noop_cleanup(*_a: Any, **_kw: Any) -> list[str]:
        return []

    async def _fake_fetch_tree(*_a: Any, dest_dir: Path, **_kw: Any) -> list[str]:
        (dest_dir / "src_pkg").mkdir(parents=True, exist_ok=True)
        (dest_dir / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
        (dest_dir / "src_pkg" / "calc.py").write_text(
            "def compute_summary(vals):\n    return {'sum': sum(vals)}\n",
            encoding="utf-8",
        )
        if not str(dest_dir).endswith("_turn1"):
            (dest_dir / "src_pkg" / "cli.py").write_text(
                "import json, sys\nfrom src_pkg.calc import compute_summary\n"
                "def main(argv=None):\n    raw = argv if argv is not None else sys.argv[1:]\n"
                "    print(json.dumps(compute_summary([float(x) for x in raw])))\n    return 0\n"
                "if __name__ == '__main__':\n    raise SystemExit(main())\n",
                encoding="utf-8",
            )
            (dest_dir / "tests").mkdir(parents=True, exist_ok=True)
            (dest_dir / "tests" / "test_calc_cli.py").write_text(
                "from src_pkg.cli import main\ndef test_summary_cli_roundtrip():\n"
                "    assert main(['2', '4', '6']) == 0\n",
                encoding="utf-8",
            )
        return ["src_pkg/calc.py"]

    async def _cb10_leak_turn(_cl: Any, _thr: str, content: str, **_kw: Any) -> TurnOutcome:
        if "@agent_alpha" in content:
            return TurnOutcome(
                "t1",
                {"id": "u1"},
                [{"sender_bot_id": "beta_1"}, {"sender_bot_id": "alpha_1"}],
                [],
                [],
                [],
                [],
            )
        return TurnOutcome(
            "t2",
            {"id": "u2"},
            [{"sender_bot_id": "alpha_1"}, {"sender_bot_id": "beta_1"}],
            [],
            [],
            [{"from_bot_id": "alpha_1", "to_bot_id": "beta_1"}],
            [],
        )

    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.async_client",
        lambda self, **_kw: httpx.AsyncClient(
            base_url=self.target_url,
            transport=httpx.MockTransport(_cb10_handler),
        ),
    )
    monkeypatch.setattr("src.qa.scenarios.cb_10.cleanup_project_subpath_http", _noop_cleanup)
    monkeypatch.setattr("src.qa.scenarios.cb_10.fetch_project_tree_http", _fake_fetch_tree)
    monkeypatch.setattr("src.qa.scenarios.cb_10.trigger_and_wait_turn", _cb10_leak_turn)

    camp_10 = tmp_path / "camp_cb10_leak"
    res_10 = run_scenario(
        case_id="CB-10",
        campaign_dir=camp_10,
        state=_make_state(camp_10),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res_10 is not None
    rec_10, _ = res_10
    assert rec_10.passed is False
    assert rec_10.assertions["turn1_alpha_only_sender"] is False


# ---------------------------------------------------------------------------
# Finding #4: CB-13 READY rejects emulated backend + enforces GROKBOT_N3_STRICT=1
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_cb13_ready_rejects_emulated_and_sets_strict_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_envs: list[dict[str, str]] = []

    def _fake_subproc_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        del args
        captured_envs.append(dict(kwargs.get("env") or {}))
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="2 passed", stderr="")

    monkeypatch.delenv("GROKBOT_N3_STRICT", raising=False)
    monkeypatch.setattr("src.qa.scenarios.cb_13.subprocess.run", _fake_subproc_run)

    rc_non, _, _ = _run_pytest_n3(_REPO_ROOT, strict=False)
    assert rc_non == 0
    assert "GROKBOT_N3_STRICT" not in captured_envs[-1]

    rc_strict, _, _ = _run_pytest_n3(_REPO_ROOT, strict=True)
    assert rc_strict == 0
    assert captured_envs[-1].get("GROKBOT_N3_STRICT") == "1"

    # Probe CB-13 with N3=READY against an emulated backend -> MUST fail local_llm_backend_active
    rep_ready = N3ProbeReport(
        timestamp_utc="2026-11-27T00:00:00Z",
        host_os="Linux",
        host_release="6.1.0",
        arch="x86_64",
        overall_status="READY",
        linux_os_ready=True,
        network_isolation_ready=True,
        desktop_ready=True,
        local_llm_ready=True,
        checks=[
            CheckResult(
                name="network_isolation_a11",
                status=CheckStatus.PASS,
                required_for=EvidenceLevel.N3,
                summary="Mocked PASS",
            )
        ],
        evidence_notes=["Mocked READY"],
    )
    monkeypatch.setattr("src.qa.scenarios.cb_13._run_verify_n3_script", lambda _r: (0, "ok", ""))
    monkeypatch.setattr(
        "src.qa.scenarios.cb_13._run_pytest_n3", lambda _r, *, strict=False: (0, "2 passed", "")
    )
    monkeypatch.setattr(
        "src.qa.scenarios.registry.probe_target_capabilities",
        lambda *_a, **_kw: _caps(
            backend_mode="emulated",
            system_info={"backend_mode": "emulated", "emulated": True},
        ),
    )

    def _emulated_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/system/info":
            return httpx.Response(200, json={"backend_mode": "emulated", "emulated": True})
        if request.url.path == "/api/v1/bots":
            return httpx.Response(200, json={"bots": []})
        return httpx.Response(404, json={})

    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.async_client",
        lambda self, **_kw: httpx.AsyncClient(
            base_url=self.target_url,
            transport=httpx.MockTransport(_emulated_handler),
        ),
    )

    async def _fail_chat(*_a: Any, **_kw: Any) -> TurnOutcome:
        raise RuntimeError("No local LLM available on emulated backend")

    async def _ok_ind(*_a: Any, **_kw: Any) -> tuple[bool, dict[str, Any]]:
        return True, {"mode": "mock"}

    class _NoopPage:
        async def goto(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def wait_for_selector(self, *args: Any, **kwargs: Any) -> None:
            return None

    class _NoopPw:
        def __init__(self) -> None:
            self.page = _NoopPage()
            self.console_errors: list[str] = []
            self.page_errors: list[str] = []
            self.external_requests: list[str] = []

        async def __aenter__(self) -> _NoopPw:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    async def _ok_loc(_p: Any) -> tuple[bool, str]:
        return True, "top_header"

    async def _ok_comp(_p: Any) -> tuple[bool, str]:
        return True, "ok"

    async def _fake_shot(self: Any, *args: Any, **kwargs: Any) -> Any:
        from src.qa.ux_metrics import ScreenshotCheckpoint

        return ScreenshotCheckpoint(
            checkpoint_id="shot-cb13-emu",
            case_id="CB-13",
            label="cb13_n3_local",
            path=str(tmp_path / "shot13.png"),
            byte_size=64,
            sha256="0" * 64,
            is_error_state=True,
        )

    monkeypatch.setattr("src.qa.scenarios.cb_13.trigger_and_wait_turn", _fail_chat)
    monkeypatch.setattr("src.qa.scenarios.cb_13._run_readonly_industrial_check", _ok_ind)
    monkeypatch.setattr("src.qa.scenarios.cb_13.open_browser_session", lambda **_kw: _NoopPw())
    monkeypatch.setattr("src.qa.scenarios.cb_13.check_local_remote_indicator", _ok_loc)
    monkeypatch.setattr("src.qa.scenarios.cb_13.check_composer_single_row", _ok_comp)
    monkeypatch.setattr("src.qa.scenarios._common.ScenarioContext.capture_shot", _fake_shot)

    camp_emu = tmp_path / "camp_cb13_emu"
    res = run_scenario(
        case_id="CB-13",
        campaign_dir=camp_emu,
        state=_make_state(camp_emu),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
        n3_report=rep_ready,
    )
    assert res is not None
    rec, _ = res
    assert rec.passed is False
    assert rec.emulated is True
    assert rec.assertions["local_llm_backend_active"] is False


# ---------------------------------------------------------------------------
# Finding #5: CB-10 evaluator rejects comment-only AST & broken CLI + assert True
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_cb10_evaluator_rejects_comments_and_broken_cli_with_trivial_pytest(
    tmp_path: Path,
) -> None:
    spec = build_cb10_three_deliverables_spec()

    # Probe A: Comment-only symbols + broken cli + trivial `assert True` test
    proj_comment = tmp_path / "proj_comment"
    (proj_comment / "src_pkg").mkdir(parents=True)
    (proj_comment / "tests").mkdir(parents=True)
    (proj_comment / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    (proj_comment / "src_pkg" / "calc.py").write_text(
        "# def compute_summary fake\n", encoding="utf-8"
    )
    (proj_comment / "src_pkg" / "cli.py").write_text(
        "# def main compute_summary fake\nraise RuntimeError('broken cli')\n",
        encoding="utf-8",
    )
    (proj_comment / "tests" / "test_calc_cli.py").write_text(
        "def test_summary_cli_roundtrip():\n    assert True\n", encoding="utf-8"
    )
    ok_a, assertions_a, _ = evaluate_cb10_project(proj_comment, spec)
    assert ok_a is False
    assert assertions_a["d1_symbols"] is False
    assert assertions_a["d2_symbols"] is False
    assert assertions_a["independent_cli_passed"] is False

    # Probe B: Valid AST stubs returning wrong result + trivial `assert True` test
    proj_stub = tmp_path / "proj_stub"
    (proj_stub / "src_pkg").mkdir(parents=True)
    (proj_stub / "tests").mkdir(parents=True)
    (proj_stub / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    (proj_stub / "src_pkg" / "calc.py").write_text(
        "def compute_summary(vals):\n    return {'sum': 0.0}\n", encoding="utf-8"
    )
    (proj_stub / "src_pkg" / "cli.py").write_text(
        "from src_pkg.calc import compute_summary\n"
        "def main(argv=None):\n    return compute_summary([1.0])\n",
        encoding="utf-8",
    )
    (proj_stub / "tests" / "test_calc_cli.py").write_text(
        "def test_summary_cli_roundtrip():\n    assert True\n", encoding="utf-8"
    )
    ok_b, assertions_b, _ = evaluate_cb10_project(proj_stub, spec)
    assert ok_b is False
    assert assertions_b["d1_symbols"] is True
    assert assertions_b["d2_symbols"] is True
    assert assertions_b["d3_symbols"] is True
    assert assertions_b["independent_cli_passed"] is False

    # Probe C: Genuine working implementation passes AST + compileall + pytest + independent CLI
    proj_ok = tmp_path / "proj_ok"
    (proj_ok / "src_pkg").mkdir(parents=True)
    (proj_ok / "tests").mkdir(parents=True)
    (proj_ok / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    (proj_ok / "src_pkg" / "calc.py").write_text(
        "def compute_summary(values):\n"
        "    t = float(sum(values))\n"
        "    return {'count': float(len(values)), 'sum': t, 'mean': t / len(values)}\n",
        encoding="utf-8",
    )
    (proj_ok / "src_pkg" / "cli.py").write_text(
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print(json.dumps(compute_summary([float(x) for x in raw])))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n"
        "    raise SystemExit(main())\n",
        encoding="utf-8",
    )
    (proj_ok / "tests" / "test_calc_cli.py").write_text(
        "from src_pkg.cli import main\n"
        "def test_summary_cli_roundtrip():\n"
        "    assert main(['2', '4', '6']) == 0\n",
        encoding="utf-8",
    )
    ok_c, assertions_c, _ = evaluate_cb10_project(proj_ok, spec)
    assert ok_c is True
    assert all(assertions_c.values())


# ---------------------------------------------------------------------------
# Finding #6 & #7: CB-VALVE-104 _price_in_text boundaries & superseded record
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_cb_valve_104_price_boundaries_and_synthesized_superseded_record(
    tmp_path: Path,
) -> None:
    camp_partial = tmp_path / "camp_partial_json"
    (camp_partial / "fixtures").mkdir(parents=True)
    (camp_partial / "fixtures" / "cb_valve_104.json").write_text(
        json.dumps(
            {
                "fixture_version": "cb-valve-104-partial",
                "sku": "CB-VALVE-104",
                "active_price": "129.50",
                "prior_price": "154.00",
                "records": [
                    {
                        "record_id": "rec-cur-only",
                        "sku": "CB-VALVE-104",
                        "title": "Valve 104",
                        "price": "129.50",
                        "currency": "USD",
                        "status": "current",
                        "effective_date": "2026-11-01",
                        "source_url": "/catalog/valves/cb-valve-104",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    fx = load_or_build_cb_valve_104_catalog(camp_partial)
    assert fx.active_record.price == Decimal("129.50")
    assert fx.prior_record.price == Decimal("154.00")
    assert {r.status for r in fx.records} == {"current", "superseded"}

    with (
        serve_valve_catalog(fx) as (origin, _state),
        httpx.Client(base_url=origin, timeout=5.0) as client,
    ):
        idx = client.get("/index.json").json()
        assert any(r["sku"] == "CB-VALVE-104" and r["status"] == "superseded" for r in idx)
        prior_resp = client.get(fx.prior_record.source_url)
        assert prior_resp.status_code == 200
        assert "data-status='superseded'" in prior_resp.text
        assert "data-price='154.00'" in prior_resp.text

    # Finding #6: reject 1,129.50, 129.50.1, 129.501; accept 129.50 and trailing sentence period
    for bad_reply in (
        "CB-VALVE-104: USD 1,129.50 at /catalog/valves/cb-valve-104",
        "CB-VALVE-104: USD 129.50.1 at /catalog/valves/cb-valve-104",
        "CB-VALVE-104: USD 129.501 at /catalog/valves/cb-valve-104",
    ):
        ok_bad, a_bad, _ = evaluate_valve_104_reply(bad_reply, fx, mode="current")
        assert ok_bad is False
        assert a_bad["active_price_exact"] is False

    for good_reply in (
        "CB-VALVE-104: USD 129.50 at /catalog/valves/cb-valve-104",
        "CB-VALVE-104 costs USD 129.50. Source: /catalog/valves/cb-valve-104",
    ):
        ok_good, a_good, _ = evaluate_valve_104_reply(good_reply, fx, mode="current")
        assert ok_good is True
        assert a_good["active_price_exact"] is True


# ---------------------------------------------------------------------------
# Finding #8: CB-09 restores bot_chief.project_name even when originally None
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_cb09_restores_project_name_when_originally_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "src.qa.scenarios.registry.probe_target_capabilities",
        lambda *_a, **_kw: _caps(agy_available=True),
    )

    chief_state: dict[str, Any] = {"id": "bot_chief", "project_name": None}
    patch_history: list[Any] = []

    def _cb09_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/bots" and request.method == "GET":
            return httpx.Response(200, json={"bots": [dict(chief_state)]})
        if path == "/api/v1/bots/bot_chief" and request.method == "PATCH":
            body = json.loads(request.content.decode("utf-8"))
            patch_history.append(body.get("project_name"))
            chief_state["project_name"] = body.get("project_name")
            return httpx.Response(200, json=dict(chief_state))
        return httpx.Response(200, json={})

    class _SyncClientStub:
        def __enter__(self) -> _SyncClientStub:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def patch(self, path: str, *, json: dict[str, Any]) -> httpx.Response:
            if path == "/api/v1/bots/bot_chief":
                patch_history.append(json.get("project_name"))
                chief_state["project_name"] = json.get("project_name")
            return httpx.Response(200, json=dict(chief_state))

    async def _noop_cleanup(*_a: Any, **_kw: Any) -> list[str]:
        return []

    async def _fake_turn(*_a: Any, **_kw: Any) -> TurnOutcome:
        return TurnOutcome(
            "t09", {"id": "u09"}, [{"status": "done", "content": "ok"}], [], [], [], []
        )

    async def _fake_fetch(*_a: Any, dest_dir: Path, **_kw: Any) -> list[str]:
        from src.qa.scenarios.cb_09 import _REFERENCE_CSV_TESTS, _REFERENCE_CSV_TO_JSON

        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / "csv_to_json.py").write_text(_REFERENCE_CSV_TO_JSON, encoding="utf-8")
        (dest_dir / "test_csv_to_json.py").write_text(_REFERENCE_CSV_TESTS, encoding="utf-8")
        return ["csv_to_json.py", "test_csv_to_json.py"]

    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.async_client",
        lambda self, **_kw: httpx.AsyncClient(
            base_url=self.target_url,
            transport=httpx.MockTransport(_cb09_handler),
        ),
    )
    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.sync_client",
        lambda self, **_kw: _SyncClientStub(),
    )
    monkeypatch.setattr("src.qa.scenarios.cb_09.cleanup_project_subpath_http", _noop_cleanup)
    monkeypatch.setattr("src.qa.scenarios.cb_09.trigger_and_wait_turn", _fake_turn)
    monkeypatch.setattr("src.qa.scenarios.cb_09.fetch_project_tree_http", _fake_fetch)

    camp_09 = tmp_path / "camp_cb09_none"
    res = run_scenario(
        case_id="CB-09",
        campaign_dir=camp_09,
        state=_make_state(camp_09),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res is not None
    rec, _ = res
    assert rec.passed is True
    assert patch_history == ["Grokbotclon", None]
    assert chief_state["project_name"] is None


# ---------------------------------------------------------------------------
# Wave 2 Regressions (Findings #1..#5)
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_w2_cb01_markdown_skips_hr_table_sep_images_and_strips_task_checkbox() -> None:
    from src.qa.scenarios.cb_01 import _extract_markdown_match_fragments

    # Tables: skip separator row and extract cell fragments without literal pipes
    table_md = "| Check | Status |\n| --- | --- |\n| CB-01 | OK |"
    assert _normalize_markdown_for_match(table_md) == "Check"
    assert _extract_markdown_match_fragments(table_md) == ["Check", "Status", "CB-01", "OK"]

    # Horizontal rules (---, ***, ___, spaced) skipped
    assert _normalize_markdown_for_match("---\n**CB-01 Status**: Verified OK") == (
        "CB-01 Status: Verified OK"
    )
    assert _normalize_markdown_for_match("***\n___\n- - -\nActual text") == "Actual text"

    # GFM task list checkboxes stripped
    assert _normalize_markdown_for_match("- [x] CB-01 Verified OK") == "CB-01 Verified OK"
    assert _normalize_markdown_for_match("* [ ] Pending check") == "Pending check"
    assert _normalize_markdown_for_match("1. [X] Ordered task") == "Ordered task"

    # Pure image lines (and linked image badges) skipped, inline image alt not matched as text
    assert _normalize_markdown_for_match("![badge](https://example.local/x.png)\nCB-01 OK") == (
        "CB-01 OK"
    )
    assert (
        _normalize_markdown_for_match(
            "[![badge](https://example.local/img.png)](https://example.local)\nCB-01 Link OK"
        )
        == "CB-01 Link OK"
    )
    assert _normalize_markdown_for_match("![only-image](https://example.local/only.png)") == ""


@pytest.mark.n1
def test_t5_w2_cb10_evaluator_rejects_ref_only_wrong_dict_hardcoded_12_and_empty_cli(
    tmp_path: Path,
) -> None:
    spec = build_cb10_three_deliverables_spec()

    def _write_proj(name: str, calc_src: str, cli_src: str, test_src: str) -> Path:
        p = tmp_path / name
        (p / "src_pkg").mkdir(parents=True)
        (p / "tests").mkdir(parents=True)
        (p / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
        (p / "src_pkg" / "calc.py").write_text(calc_src, encoding="utf-8")
        (p / "src_pkg" / "cli.py").write_text(cli_src, encoding="utf-8")
        (p / "tests" / "test_calc_cli.py").write_text(test_src, encoding="utf-8")
        return p

    # 1. _ref = compute_summary + main(argv=None) returning {'sum': 999.0} + assert True
    p_wrong = _write_proj(
        "p_wrong_dict",
        "def compute_summary(vals):\n    return {'sum': float(sum(vals))}\n",
        "from src_pkg.calc import compute_summary\n"
        "_ref = compute_summary\n"
        "def main(argv=None):\n    return {'sum': 999.0}\n",
        "def test_summary_cli_roundtrip():\n    assert True\n",
    )
    ok_1, ass_1, _ = evaluate_cb10_project(p_wrong, spec)
    assert ok_1 is False
    assert ass_1["d2_symbols"] is False
    assert ass_1["independent_cli_passed"] is False

    # 2. Hardcoded 12.0 in calc.py + calling compute_summary in cli.py -> fails [3.0, 5.0] check
    p_hard12 = _write_proj(
        "p_hard12",
        "def compute_summary(vals):\n    return {'sum': 12.0, 'count': 3.0}\n",
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print(json.dumps(compute_summary([float(x) for x in raw])))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        "def test_summary_cli_roundtrip():\n    assert True\n",
    )
    ok_2, ass_2, _ = evaluate_cb10_project(p_hard12, spec)
    assert ok_2 is False
    assert ass_2["independent_cli_passed"] is False

    # 3. cli.py bypasses compute_summary at runtime (prints JSON directly, dummy call)
    p_bypass = _write_proj(
        "p_bypass",
        "def compute_summary(vals):\n    return {'sum': float(sum(vals))}\n",
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def _never_called():\n    return compute_summary([1.0])\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print(json.dumps({'sum': sum(float(x) for x in raw)}))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        "def test_summary_cli_roundtrip():\n    assert True\n",
    )
    ok_3, ass_3, _ = evaluate_cb10_project(p_bypass, spec)
    assert ok_3 is False
    assert ass_3["independent_cli_passed"] is False

    # 4. cli.py with __main__ guard printing empty stdout -> rejected
    p_empty_cli = _write_proj(
        "p_empty_cli",
        "def compute_summary(vals):\n    return {'sum': float(sum(vals))}\n",
        "from src_pkg.calc import compute_summary\n"
        "def main(argv=None):\n"
        "    return compute_summary([float(x) for x in (argv or ['2', '4', '6'])])\n"
        "if __name__ == '__main__':\n    main()\n",
        "def test_summary_cli_roundtrip():\n    assert True\n",
    )
    ok_4, ass_4, _ = evaluate_cb10_project(p_empty_cli, spec)
    assert ok_4 is False
    assert ass_4["independent_cli_passed"] is False


@pytest.mark.n1
def test_t5_w2_cb07_guards_stale_effects_on_fail_and_non_tautological_no_ef_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from lab.effect_sim import create_effect_sim_app
    from src.qa.ux_metrics import ScreenshotCheckpoint, evaluate_error_actionability

    class _StubCard:
        def __init__(self) -> None:
            self.first = self

        def filter(self, *, has_text: str = "") -> _StubCard:
            del has_text
            return self

        def get_by_text(self, text: str) -> _StubCard:
            del text
            return self

        def get_by_role(self, role: str, *, name: str = "") -> _StubCard:
            del role, name
            return self

        async def wait_for(self, *, state: str = "visible", timeout: int = 10000) -> None:
            del state, timeout

        async def click(self) -> None:
            return None

    class _StubPage:
        async def goto(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def wait_for_selector(self, *args: Any, **kwargs: Any) -> None:
            return None

        def locator(self, selector: str) -> _StubCard:
            del selector
            return _StubCard()

    class _StubPw:
        def __init__(self) -> None:
            self.page = _StubPage()
            self.console_errors: list[str] = []
            self.page_errors: list[str] = []
            self.external_requests: list[str] = []

        async def __aenter__(self) -> _StubPw:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    async def _fake_shot(self: Any, *args: Any, **kwargs: Any) -> ScreenshotCheckpoint:
        return ScreenshotCheckpoint(
            checkpoint_id="shot-cb07-w2",
            case_id="CB-07",
            label="cb07_approvals",
            path=str(tmp_path / "shot.png"),
            byte_size=64,
            sha256="0" * 64,
            is_error_state=bool(kwargs.get("is_error_state", False)),
        )

    async def _fake_turn(*_a: Any, **_kw: Any) -> TurnOutcome:
        return TurnOutcome(
            "trn_cb07_w2",
            {"id": "msg_u1"},
            [],
            [],
            ["waiting_human"],
            [],
            [{"id": "apr_ui", "title": "CB07 UI Card"}],
        )

    monkeypatch.setattr("src.qa.scenarios.cb_07.open_browser_session", lambda **_kw: _StubPw())
    monkeypatch.setattr("src.qa.scenarios._common.ScenarioContext.capture_shot", _fake_shot)
    monkeypatch.setattr("src.qa.scenarios.cb_07.trigger_and_wait_turn", _fake_turn)

    # Part A: lab/effect_sim IDEMPOTENCY_CONFLICT 409 detail is naturally actionable
    ef_app = create_effect_sim_app()

    async def _probe_real_effect_sim() -> None:
        transport = httpx.ASGITransport(app=ef_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://ef") as cl:
            r1 = await cl.post(
                "/api/effects/apply",
                json={"idempotency_key": "k-w2", "asset_id": "bomba-34-a1", "action": "ack"},
            )
            assert r1.status_code == 200
            r_conf = await cl.post(
                "/api/effects/apply",
                json={"idempotency_key": "k-w2", "asset_id": "bomba-34-a1", "action": "other"},
            )
            assert r_conf.status_code == 409
            detail = r_conf.json()["detail"]
            ok_act, reason = evaluate_error_actionability(detail)
            assert ok_act is True, reason

    asyncio.run(_probe_real_effect_sim())

    # Part B: ef_url reachable with base_applied >= 1 and failing task -> replay/conflict False
    monkeypatch.setattr(
        "src.qa.scenarios.registry.probe_target_capabilities",
        lambda *_a, **_kw: _caps(
            effect_sim_url="http://127.0.0.1:19991",
            effect_sim_reachable=True,
        ),
    )
    approvals_db: dict[str, dict[str, Any]] = {}
    drafts_db: dict[str, str] = {}
    pre_existing = {
        "idempotency_key": "pre-existing-key",
        "asset_id": "bomba-34-a1",
        "action": "ack_alarm",
        "params": {},
    }

    def _studio_ef(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/approvals" and request.method == "POST":
            body = json.loads(request.content.decode("utf-8"))
            aid = f"apr_{len(approvals_db) + 1}"
            approvals_db[aid] = {
                "id": aid,
                "status": "pending",
                "title": body.get("title", ""),
                "allow_always_allowed": body.get("allow_always_allowed", True),
            }
            return httpx.Response(201, json=approvals_db[aid])
        if path.startswith("/api/v1/approvals/") and path.endswith("/resolve"):
            aid = path.split("/")[4]
            dec = json.loads(request.content.decode("utf-8"))["decision"]
            rec = approvals_db[aid]
            if rec["status"] != "pending":
                return httpx.Response(409, json={"detail": f"Approval {aid} already resolved."})
            if dec == "always_allow" and not rec["allow_always_allowed"]:
                return httpx.Response(409, json={"detail": "always_allow disallowed"})
            rec["status"] = "allowed_once" if dec == "allow_once" else "denied"
            return httpx.Response(200, json=rec)
        if path == "/api/v1/drafts" and request.method == "POST":
            did = f"drf_{len(drafts_db) + 1}"
            drafts_db[did] = "pending"
            return httpx.Response(201, json={"id": did, "status": "pending"})
        if path.startswith("/api/v1/drafts/") and path.endswith("/resolve"):
            did = path.split("/")[4]
            if drafts_db[did] != "pending":
                return httpx.Response(409, json={"detail": "already resolved"})
            drafts_db[did] = "discarded"
            return httpx.Response(200, json={"id": did, "status": "discarded"})
        if path == "/api/tasks" and request.method == "POST":
            return httpx.Response(201, json={"run_id": "run_fail_stale"})
        if path == "/api/tasks/run_fail_stale":
            return httpx.Response(200, json={"run": {"status": "failed"}})
        return httpx.Response(404, json={})

    def _ef_stale(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/effects/state":
            return httpx.Response(200, json={"total_applied": 1, "effects": [pre_existing]})
        if request.url.path == "/api/effects/apply":
            body = json.loads(request.content.decode("utf-8"))
            if body.get("action") == "different_action":
                return httpx.Response(409, json={"detail": "Conflict; retry with new key."})
            return httpx.Response(200, json={"deduplicated": True})
        return httpx.Response(404, json={})

    orig_async_client = httpx.AsyncClient
    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.async_client",
        lambda self, **_kw: orig_async_client(
            base_url=self.target_url, transport=httpx.MockTransport(_studio_ef)
        ),
    )
    monkeypatch.setattr(
        "src.qa.scenarios.cb_07.httpx.AsyncClient",
        lambda *a, **kw: (
            orig_async_client(*a, **kw)
            if "transport" in kw
            else orig_async_client(transport=httpx.MockTransport(_ef_stale))
        ),
    )

    camp_stale = tmp_path / "camp_cb07_stale"
    res_stale = run_scenario(
        case_id="CB-07",
        campaign_dir=camp_stale,
        state=_make_state(camp_stale),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res_stale is not None
    rec_stale, _ = res_stale
    assert rec_stale.passed is False
    assert rec_stale.assertions["effect_sim_task_succeeded"] is False
    assert rec_stale.assertions["effect_sim_single_apply"] is False
    assert rec_stale.assertions["effect_sim_replay_dedup"] is False
    assert rec_stale.assertions["effect_sim_conflict_409"] is False

    # Part C: ef_url=None mode is non-tautological: deny returning 'allowed_once' fails
    monkeypatch.setattr(
        "src.qa.scenarios.registry.probe_target_capabilities",
        lambda *_a, **_kw: _caps(effect_sim_url=None, effect_sim_reachable=False),
    )
    monkeypatch.setattr("src.qa.scenarios.cb_07.httpx.AsyncClient", orig_async_client)

    approvals_bad: dict[str, dict[str, Any]] = {}
    drafts_bad: dict[str, str] = {}
    deny_bug = {"force_allow_on_deny": True}

    def _studio_noef(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/approvals" and request.method == "POST":
            body = json.loads(request.content.decode("utf-8"))
            aid = f"apr_{len(approvals_bad) + 1}"
            approvals_bad[aid] = {
                "id": aid,
                "status": "pending",
                "title": body.get("title", ""),
                "allow_always_allowed": body.get("allow_always_allowed", True),
            }
            return httpx.Response(201, json=approvals_bad[aid])
        if path.startswith("/api/v1/approvals/") and path.endswith("/resolve"):
            aid = path.split("/")[4]
            dec = json.loads(request.content.decode("utf-8"))["decision"]
            rec = approvals_bad[aid]
            if rec["status"] != "pending":
                return httpx.Response(409, json={"detail": f"Approval {aid} already resolved."})
            if dec == "always_allow" and not rec["allow_always_allowed"]:
                return httpx.Response(409, json={"detail": "always_allow disallowed"})
            if dec == "deny" and deny_bug["force_allow_on_deny"]:
                rec["status"] = "allowed_once"
            else:
                rec["status"] = "allowed_once" if dec == "allow_once" else "denied"
            return httpx.Response(200, json=rec)
        if path == "/api/v1/threads/thr_bot_chief/messages":
            apprs = list(approvals_bad.values())
            apprs.append({"id": "apr_ui", "title": "CB07 UI Card", "status": "denied"})
            return httpx.Response(200, json={"messages": [], "approvals": apprs})
        if path == "/api/v1/drafts" and request.method == "POST":
            did = f"drf_{len(drafts_bad) + 1}"
            drafts_bad[did] = "pending"
            return httpx.Response(201, json={"id": did, "status": "pending"})
        if path.startswith("/api/v1/drafts/") and path.endswith("/resolve"):
            did = path.split("/")[4]
            if drafts_bad[did] != "pending":
                return httpx.Response(409, json={"detail": "already resolved"})
            drafts_bad[did] = "discarded"
            return httpx.Response(200, json={"id": did, "status": "discarded"})
        return httpx.Response(404, json={})

    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.async_client",
        lambda self, **_kw: orig_async_client(
            base_url=self.target_url, transport=httpx.MockTransport(_studio_noef)
        ),
    )

    camp_bad_deny = tmp_path / "camp_cb07_bad_deny"
    res_bad_deny = run_scenario(
        case_id="CB-07",
        campaign_dir=camp_bad_deny,
        state=_make_state(camp_bad_deny),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res_bad_deny is not None
    rec_bad_deny, _ = res_bad_deny
    assert rec_bad_deny.passed is False
    assert rec_bad_deny.assertions["api_deny_zero_effects"] is False

    # Part D: Genuine Studio deny/allow_once in ef_url=None mode -> passes with actionable=True
    approvals_bad.clear()
    drafts_bad.clear()
    deny_bug["force_allow_on_deny"] = False
    camp_good_noef = tmp_path / "camp_cb07_good_noef"
    res_good_noef = run_scenario(
        case_id="CB-07",
        campaign_dir=camp_good_noef,
        state=_make_state(camp_good_noef),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res_good_noef is not None
    rec_good_noef, _ = res_good_noef
    assert rec_good_noef.passed is True, rec_good_noef.error_summary
    assert rec_good_noef.assertions["api_deny_zero_effects"] is True
    assert rec_good_noef.assertions["effect_approval_allow_once"] is True
    assert rec_good_noef.assertions["ui_deny_zero_effects"] is True
    ux_good = json.loads((camp_good_noef / "ux_metrics.json").read_text(encoding="utf-8"))
    assert ux_good["flows"][-1]["error_actionable"] is True


@pytest.mark.n1
def test_t5_w2_cb_valve_104_rejects_european_decimal_and_wrong_url_prefix() -> None:
    fx = load_or_build_cb_valve_104_catalog(Path("/nonexistent/cb_valve_w2"))

    for bad_price_reply in (
        "CB-VALVE-104: USD 129.50,00 at /catalog/valves/cb-valve-104",
        "CB-VALVE-104: USD 129.50,000 at /catalog/valves/cb-valve-104",
    ):
        ok, ass, _ = evaluate_valve_104_reply(bad_price_reply, fx, mode="current")
        assert ok is False
        assert ass["active_price_exact"] is False

    for bad_url_reply in (
        "CB-VALVE-104: USD 129.50 at /wrong/catalog/valves/cb-valve-104",
        "CB-VALVE-104: USD 129.50 at http://127.0.0.1:45123/wrong/catalog/valves/cb-valve-104",
        "CB-VALVE-104: USD 129.50 at //catalog/valves/cb-valve-104",
    ):
        ok, ass, _ = evaluate_valve_104_reply(bad_url_reply, fx, mode="current")
        assert ok is False
        assert ass["active_source_url_exact"] is False

    for good_reply in (
        "CB-VALVE-104: USD 129.50, source /catalog/valves/cb-valve-104",
        "CB-VALVE-104: USD 129.50 at http://127.0.0.1:45123/catalog/valves/cb-valve-104",
        "CB-VALVE-104: USD 129.50 at https://example.com/catalog/valves/cb-valve-104.",
    ):
        ok, ass, _ = evaluate_valve_104_reply(good_reply, fx, mode="current")
        assert ok is True
        assert ass["active_price_exact"] is True
        assert ass["active_source_url_exact"] is True


# ---------------------------------------------------------------------------
# Wave 3 Regressions (Findings #1..#4)
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_w3_cb01_markdown_inline_code_fenced_reflink_escaped_and_autolink() -> None:
    from src.qa.scenarios.cb_01 import _extract_markdown_match_fragments

    # 1. Inline code spans protect enclosed emphasis/markdown tokens
    assert _normalize_markdown_for_match("Result: `*CB-01* *OK*`") == "Result: *CB-01* *OK*"
    assert _normalize_markdown_for_match("Code: ``**bold** `inner` ``") == "Code: **bold** `inner`"

    # 2. Fenced code blocks track open/close state and preserve literal Markdown syntax
    assert _normalize_markdown_for_match("```markdown\n**CB-01** **OK**\n```") == (
        "**CB-01** **OK**"
    )
    assert _normalize_markdown_for_match("~~~\n# NotHeading\n*NotItalic*\n~~~") == "# NotHeading"
    assert _extract_markdown_match_fragments("````\n```\n**Inner**\n```\n````") == [
        "```",
        "**Inner**",
        "```",
    ]

    # 3. Reference-link definitions are skipped as non-rendered lines
    assert _normalize_markdown_for_match("[ref]: https://example.local\nCB-01 OK") == "CB-01 OK"

    # 4. Backslash-escaped Markdown punctuation unescapes without triggering emphasis
    assert _normalize_markdown_for_match(r"\*CB-01\* \*OK\*") == "*CB-01* *OK*"
    assert _normalize_markdown_for_match(r"\\*CB-01*") == r"\CB-01"

    # 5. Autolinks unwrap <https://...> / <http://...>
    assert _extract_markdown_match_fragments("<https://example.local>\nCB-01 OK") == [
        "https://example.local",
        "CB-01 OK",
    ]
    assert _normalize_markdown_for_match("<http://127.0.0.1:8080/health>") == (
        "http://127.0.0.1:8080/health"
    )


@pytest.mark.n1
def test_t5_w3_cb10_evaluator_rejects_zero_arg_kwonly_dummy_call_and_vacuous_d3(
    tmp_path: Path,
) -> None:
    spec = build_cb10_three_deliverables_spec()

    def _write_proj(name: str, calc_src: str, cli_src: str, test_src: str) -> Path:
        p = tmp_path / name
        (p / "src_pkg").mkdir(parents=True)
        (p / "tests").mkdir(parents=True)
        (p / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
        (p / "src_pkg" / "calc.py").write_text(calc_src, encoding="utf-8")
        (p / "src_pkg" / "cli.py").write_text(cli_src, encoding="utf-8")
        (p / "tests" / "test_calc_cli.py").write_text(test_src, encoding="utf-8")
        return p

    good_calc = (
        "def compute_summary(vals):\n"
        "    t = float(sum(vals))\n"
        "    return {'count': float(len(vals)), 'sum': t, 'mean': t / len(vals)}\n"
    )
    good_cli = (
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print(json.dumps(compute_summary([float(x) for x in raw])))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n"
    )
    good_test = (
        "import json, subprocess, sys\n"
        "def test_summary_cli_roundtrip():\n"
        "    p = subprocess.run([sys.executable, '-m', 'src_pkg.cli', '2', '4', '6'], "
        "capture_output=True, text=True, check=False)\n"
        "    assert p.returncode == 0\n"
        "    assert json.loads(p.stdout)['sum'] == 12.0\n"
    )

    # 2A: 0-arg main() calling compute_summary([1.0]) and returning wrong dict {'sum': 999.0}
    p_2a = _write_proj(
        "p_2a",
        good_calc,
        "from src_pkg.calc import compute_summary\n"
        "def main():\n    compute_summary([1.0])\n    return {'sum': 999.0}\n",
        good_test,
    )
    ok_2a, ass_2a, _ = evaluate_cb10_project(p_2a, spec)
    assert ok_2a is False
    assert ass_2a["independent_cli_passed"] is False

    # 2B: kw-only main(*, argv=None) calling compute_summary([1.0]) and returning {'sum': 999.0}
    p_2b = _write_proj(
        "p_2b",
        good_calc,
        "from src_pkg.calc import compute_summary\n"
        "def main(*, argv=None):\n    compute_summary([1.0])\n    return {'sum': 999.0}\n",
        good_test,
    )
    ok_2b, ass_2b, _ = evaluate_cb10_project(p_2b, spec)
    assert ok_2b is False
    assert ass_2b["independent_cli_passed"] is False

    # 2C: 0-arg main() with __main__ guard printing {'sum': 999.0}
    p_2c = _write_proj(
        "p_2c",
        good_calc,
        "import json\nfrom src_pkg.calc import compute_summary\n"
        "def main():\n    compute_summary([1.0])\n"
        "    print(json.dumps({'sum': 999.0}))\n    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        good_test,
    )
    ok_2c, ass_2c, _ = evaluate_cb10_project(p_2c, spec)
    assert ok_2c is False
    assert ass_2c["independent_cli_passed"] is False

    # 2D: Vacuous D3 tests (assert True and import+callable-only) with genuine D1+D2 -> rejected
    for idx, vac_test in enumerate(
        (
            "def test_summary_cli_roundtrip():\n    assert True\n",
            "from src_pkg.calc import compute_summary\n"
            "def test_summary_cli_roundtrip():\n    assert callable(compute_summary)\n",
        )
    ):
        p_2d = _write_proj(f"p_2d_{idx}", good_calc, good_cli, vac_test)
        ok_2d, ass_2d, _ = evaluate_cb10_project(p_2d, spec)
        assert ok_2d is False
        assert ass_2d["d3_non_vacuous"] is False

    # 2E: Dummy compute_summary([1.0]) + direct sum(vals) inside cli.py -> rejected
    p_2e = _write_proj(
        "p_2e",
        good_calc,
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    _ = compute_summary([1.0])\n"
        "    print(json.dumps({'sum': sum(float(x) for x in raw)}))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        good_test,
    )
    ok_2e, ass_2e, _ = evaluate_cb10_project(p_2e, spec)
    assert ok_2e is False
    assert ass_2e["independent_cli_passed"] is False

    # Positive controls: genuine kw-only main(*, argv=None) & 0-arg sys.argv main() pass
    p_kw_ok = _write_proj(
        "p_kw_ok",
        good_calc,
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main(*, argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print(json.dumps(compute_summary([float(x) for x in raw])))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        good_test,
    )
    ok_kw, ass_kw, _ = evaluate_cb10_project(p_kw_ok, spec)
    assert ok_kw is True
    assert all(ass_kw.values())


@pytest.mark.n1
def test_t5_w3_cb13_readonly_industrial_check_fails_closed_when_effect_sim_crashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.qa.scenarios._common import ScenarioContext
    from src.qa.scenarios.cb_13 import _run_readonly_industrial_check

    camp_dir = tmp_path / "camp_cb13_ef"
    state = _make_state(camp_dir)
    sys_info_with_ef: dict[str, Any] = {
        "backend_mode": "local_http",
        "emulated": False,
        "facility": {
            "facility_id": "facility-a",
            "apps": [
                {"app_id": "scada", "origin": "http://127.0.0.1:19991"},
                {"app_id": "maintenance", "origin": "http://127.0.0.1:19992"},
                {"app_id": "effect_sim", "origin": "http://127.0.0.1:19993"},
            ],
        },
    }
    ctx = ScenarioContext.create(
        case_id="CB-13",
        campaign_dir=camp_dir,
        state=state,
        target_url="http://127.0.0.1:19999",
        token=None,
        repo_root=_REPO_ROOT,
        caps=_caps(backend_mode="local_http", system_info=sys_info_with_ef),
    )

    async def _reach_true(_origins: dict[str, str]) -> bool:
        return True

    async def _poll_ok(*_a: Any, **_kw: Any) -> dict[str, Any]:
        return {
            "run": {"status": "succeeded"},
            "result": {"answer": "ALM-3401 and WO-3408 read-only OK."},
        }

    ef_counts: list[int | None] = [0, None]

    async def _seq_counts(_url: str) -> int | None:
        return ef_counts.pop(0)

    def _studio_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tasks" and request.method == "POST":
            return httpx.Response(201, json={"run_id": "run_ef_crash"})
        return httpx.Response(404, json={})

    monkeypatch.setattr("src.qa.scenarios.cb_13._are_industrial_origins_reachable", _reach_true)
    monkeypatch.setattr("src.qa.scenarios.cb_13.poll_task_terminal", _poll_ok)
    monkeypatch.setattr("src.qa.scenarios.cb_13._get_effect_applied_count", _seq_counts)

    async def _run_probes() -> None:
        async with httpx.AsyncClient(
            base_url="http://127.0.0.1:19999",
            transport=httpx.MockTransport(_studio_handler),
        ) as cl:
            # Post-task effect_sim crash (before=0, after=None) -> fails closed
            ok_after_none, det_after = await _run_readonly_industrial_check(
                ctx, cl, sys_info_with_ef
            )
            assert ok_after_none is False
            assert det_after["zero_effects"] is False

            # Pre-task effect_sim crash (before=None, after=0) -> fails closed
            ef_counts[:] = [None, 0]
            ok_before_none, det_before = await _run_readonly_industrial_check(
                ctx, cl, sys_info_with_ef
            )
            assert ok_before_none is False
            assert det_before["zero_effects"] is False

            # No effect_sim configured -> exempt (zero_effects=True)
            sys_no_ef = {
                "backend_mode": "local_http",
                "facility": {
                    "facility_id": "facility-a",
                    "apps": [
                        {"app_id": "scada", "origin": "http://127.0.0.1:19991"},
                        {"app_id": "maintenance", "origin": "http://127.0.0.1:19992"},
                    ],
                },
            }
            ok_no_ef, det_no_ef = await _run_readonly_industrial_check(ctx, cl, sys_no_ef)
            assert ok_no_ef is True
            assert det_no_ef["zero_effects"] is True

    asyncio.run(_run_probes())


# ---------------------------------------------------------------------------
# Wave 4 Regressions (Findings #1..#3)
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_w4_cb01_markdown_parens_single_tilde_shortcut_reflink_and_escaped_backticks() -> None:
    # 1. Balanced parens in inline link/image URLs
    assert _normalize_markdown_for_match(
        "[CB-01 Valve](https://example.local/Valve_(104)) OK"
    ) == "CB-01 Valve OK"
    assert _normalize_markdown_for_match(
        "[![img](https://example.local/a_(1).png)](https://example.local/Valve_(104))\nCB-01 OK"
    ) == "CB-01 OK"

    # 2. GFM single-tilde strikethrough (and preserving spaced tildes / 3-tilde / escaped)
    assert _normalize_markdown_for_match("~old~ CB-01 OK") == "old CB-01 OK"
    assert _normalize_markdown_for_match("~~old~~ CB-01 OK") == "old CB-01 OK"
    assert _normalize_markdown_for_match("a ~ b ~ c") == "a ~ b ~ c"
    assert _normalize_markdown_for_match("text ~~~keep~~~") == "text ~~~keep~~~"
    assert _normalize_markdown_for_match(r"\~old\~ CB-01 OK") == "~old~ CB-01 OK"

    # 3. Bare shortcut reference links when matching [ref]: url definition exists
    assert _normalize_markdown_for_match(
        "[CB-01] OK\n\n[CB-01]: https://example.local"
    ) == "CB-01 OK"
    assert _normalize_markdown_for_match(
        "[cb-01] OK\n\n[CB-01]: https://example.local"
    ) == "cb-01 OK"
    assert _normalize_markdown_for_match("[CB-01] OK") == "[CB-01] OK"

    # 4. Escaped backticks around emphasis vs genuine inline code spans
    assert _normalize_markdown_for_match(r"\`*CB-01*\` OK") == "`CB-01` OK"
    assert _normalize_markdown_for_match(r"\\`*CB-01*`") == r"\*CB-01*"


@pytest.mark.n1
def test_t5_w4_cb10_rejects_main_guard_bypass_and_d3_skipping_cli(
    tmp_path: Path,
) -> None:
    spec = build_cb10_three_deliverables_spec()

    def _write_proj(name: str, calc_src: str, cli_src: str, test_src: str) -> Path:
        p = tmp_path / name
        (p / "src_pkg").mkdir(parents=True)
        (p / "tests").mkdir(parents=True)
        (p / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
        (p / "src_pkg" / "calc.py").write_text(calc_src, encoding="utf-8")
        (p / "src_pkg" / "cli.py").write_text(cli_src, encoding="utf-8")
        (p / "tests" / "test_calc_cli.py").write_text(test_src, encoding="utf-8")
        return p

    good_calc = (
        "def compute_summary(vals):\n"
        "    t = float(sum(vals))\n"
        "    return {'count': float(len(vals)), 'sum': t, 'mean': t / len(vals)}\n"
    )
    good_cli = (
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main():\n"
        "    raw = sys.argv[1:]\n"
        "    print(json.dumps(compute_summary([float(x) for x in raw])))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n"
    )
    good_test = (
        "import json, subprocess, sys\n"
        "def test_summary_cli_roundtrip():\n"
        "    p = subprocess.run([sys.executable, '-m', 'src_pkg.cli', '2', '4', '6'], "
        "capture_output=True, text=True, check=False)\n"
        "    assert p.returncode == 0\n"
        "    assert json.loads(p.stdout)['sum'] == 12.0\n"
    )

    # Probe 2A: __main__ bypasses compute_summary while 0-arg main() returns compute_summary([1, 2])
    p_bypass = _write_proj(
        "p_w4_main_guard_bypass",
        good_calc,
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main():\n    return compute_summary([1, 2])\n"
        "if __name__ == '__main__':\n"
        "    print(json.dumps({'sum': sum(float(x) for x in sys.argv[1:])}))\n",
        good_test,
    )
    ok_2a, ass_2a, _ = evaluate_cb10_project(p_bypass, spec)
    assert ok_2a is False
    assert ass_2a["independent_cli_passed"] is False

    # Probe 2F: D3 test_summary_cli_roundtrip skips src_pkg.cli (only tests calc.compute_summary)
    p_skip_cli = _write_proj(
        "p_w4_d3_skips_cli",
        good_calc,
        good_cli,
        "from src_pkg.calc import compute_summary\n"
        "def test_summary_cli_roundtrip():\n"
        "    assert compute_summary([2.0, 4.0])['sum'] == 6.0\n",
    )
    ok_2f, ass_2f, _ = evaluate_cb10_project(p_skip_cli, spec)
    assert ok_2f is False
    assert ass_2f["d3_non_vacuous"] is False

    # Positive control: genuine 0-arg main() reading sys.argv + __main__ + CLI test passes
    p_ok = _write_proj("p_w4_zero_arg_ok", good_calc, good_cli, good_test)
    ok_pos, ass_pos, _ = evaluate_cb10_project(p_ok, spec)
    assert ok_pos is True
    assert all(ass_pos.values())


@pytest.mark.n1
def test_t5_w4_cb07_effect_sim_500_and_transport_error_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.qa.scenarios.cb_07 import _get_effect_sim_state, _get_effect_sim_total_applied
    from src.qa.ux_metrics import ScreenshotCheckpoint

    orig_async_client = httpx.AsyncClient

    # Part A: Direct _get_effect_sim_state / _get_effect_sim_total_applied return None on 500/error
    def _ef_500_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "internal error"})

    def _ef_err_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(
        "src.qa.scenarios.cb_07.httpx.AsyncClient",
        lambda *a, **kw: (
            orig_async_client(*a, **kw)
            if "transport" in kw
            else orig_async_client(transport=httpx.MockTransport(_ef_500_handler))
        ),
    )
    assert asyncio.run(_get_effect_sim_state("http://127.0.0.1:19991")) is None
    assert asyncio.run(_get_effect_sim_total_applied("http://127.0.0.1:19991")) is None

    monkeypatch.setattr(
        "src.qa.scenarios.cb_07.httpx.AsyncClient",
        lambda *a, **kw: (
            orig_async_client(*a, **kw)
            if "transport" in kw
            else orig_async_client(transport=httpx.MockTransport(_ef_err_handler))
        ),
    )
    assert asyncio.run(_get_effect_sim_state("http://127.0.0.1:19991")) is None
    assert asyncio.run(_get_effect_sim_total_applied("http://127.0.0.1:19991")) is None

    # Part B: Full CB-07 run against effect_sim returning HTTP 500 fails closed on deny checks
    class _StubCard:
        def __init__(self) -> None:
            self.first = self

        def filter(self, *, has_text: str = "") -> _StubCard:
            del has_text
            return self

        def get_by_text(self, text: str) -> _StubCard:
            del text
            return self

        def get_by_role(self, role: str, *, name: str = "") -> _StubCard:
            del role, name
            return self

        async def wait_for(self, *, state: str = "visible", timeout: int = 10000) -> None:
            del state, timeout

        async def click(self) -> None:
            return None

    class _StubPage:
        async def goto(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def wait_for_selector(self, *args: Any, **kwargs: Any) -> None:
            return None

        def locator(self, selector: str) -> _StubCard:
            del selector
            return _StubCard()

    class _StubPw:
        def __init__(self) -> None:
            self.page = _StubPage()
            self.console_errors: list[str] = []
            self.page_errors: list[str] = []
            self.external_requests: list[str] = []

        async def __aenter__(self) -> _StubPw:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    async def _fake_shot(self: Any, *args: Any, **kwargs: Any) -> ScreenshotCheckpoint:
        return ScreenshotCheckpoint(
            checkpoint_id="shot-cb07-w4",
            case_id="CB-07",
            label="cb07_approvals",
            path=str(tmp_path / "shot.png"),
            byte_size=64,
            sha256="0" * 64,
            is_error_state=bool(kwargs.get("is_error_state", False)),
        )

    async def _fake_turn(*_a: Any, **_kw: Any) -> TurnOutcome:
        return TurnOutcome(
            "trn_cb07_w4",
            {"id": "msg_u1"},
            [],
            [],
            ["waiting_human"],
            [],
            [{"id": "apr_ui", "title": "CB07 UI Card"}],
        )

    approvals_db: dict[str, dict[str, Any]] = {}
    drafts_db: dict[str, str] = {}

    def _studio_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/approvals" and request.method == "POST":
            body = json.loads(request.content.decode("utf-8"))
            aid = f"apr_{len(approvals_db) + 1}"
            approvals_db[aid] = {
                "id": aid,
                "status": "pending",
                "allow_always_allowed": body.get("allow_always_allowed", True),
            }
            return httpx.Response(201, json=approvals_db[aid])
        if path.startswith("/api/v1/approvals/") and path.endswith("/resolve"):
            aid = path.split("/")[4]
            dec = json.loads(request.content.decode("utf-8"))["decision"]
            rec = approvals_db[aid]
            if rec["status"] != "pending":
                return httpx.Response(409, json={"detail": "already resolved"})
            if dec == "always_allow" and not rec["allow_always_allowed"]:
                return httpx.Response(409, json={"detail": "always_allow disallowed"})
            rec["status"] = "allowed_once" if dec == "allow_once" else "denied"
            return httpx.Response(200, json=rec)
        if path == "/api/v1/drafts" and request.method == "POST":
            did = f"drf_{len(drafts_db) + 1}"
            drafts_db[did] = "pending"
            return httpx.Response(201, json={"id": did, "status": "pending"})
        if path.startswith("/api/v1/drafts/") and path.endswith("/resolve"):
            did = path.split("/")[4]
            if drafts_db[did] != "pending":
                return httpx.Response(409, json={"detail": "already resolved"})
            drafts_db[did] = "discarded"
            return httpx.Response(200, json={"id": did, "status": "discarded"})
        return httpx.Response(404, json={})

    monkeypatch.setattr("src.qa.scenarios.cb_07.open_browser_session", lambda **_kw: _StubPw())
    monkeypatch.setattr("src.qa.scenarios._common.ScenarioContext.capture_shot", _fake_shot)
    monkeypatch.setattr("src.qa.scenarios.cb_07.trigger_and_wait_turn", _fake_turn)
    monkeypatch.setattr(
        "src.qa.scenarios.registry.probe_target_capabilities",
        lambda *_a, **_kw: _caps(
            effect_sim_url="http://127.0.0.1:19991",
            effect_sim_reachable=True,
        ),
    )
    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.async_client",
        lambda self, **_kw: orig_async_client(
            base_url=self.target_url,
            transport=httpx.MockTransport(_studio_handler),
        ),
    )
    monkeypatch.setattr(
        "src.qa.scenarios.cb_07.httpx.AsyncClient",
        lambda *a, **kw: (
            orig_async_client(*a, **kw)
            if "transport" in kw
            else orig_async_client(transport=httpx.MockTransport(_ef_500_handler))
        ),
    )

    camp_500 = tmp_path / "camp_cb07_ef500"
    res_500 = run_scenario(
        case_id="CB-07",
        campaign_dir=camp_500,
        state=_make_state(camp_500),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res_500 is not None
    rec_500, _ = res_500
    assert rec_500.passed is False
    assert rec_500.assertions["api_deny_zero_effects"] is False
    assert rec_500.assertions["ui_deny_zero_effects"] is False
    assert rec_500.assertions["effect_sim_single_apply"] is False


# ---------------------------------------------------------------------------
# Wave 5 Regressions (Findings #1..#4)
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_w5_cb11_and_cb13_effect_sim_non_json_and_missing_key_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.qa.scenarios._common import ScenarioContext
    from src.qa.scenarios.cb_11 import _get_total_applied, _verify_facility_a_pump34
    from src.qa.scenarios.cb_13 import (
        _get_effect_applied_count,
        _run_readonly_industrial_check,
    )

    orig_async_client = httpx.AsyncClient

    for payload_label, resp_factory in (
        ("empty_json_200", lambda: httpx.Response(200, json={})),
        ("html_200", lambda: httpx.Response(200, text="<html>not json</html>")),
        ("bool_200", lambda: httpx.Response(200, json={"total_applied": False})),
        ("err_500", lambda: httpx.Response(500, json={"total_applied": 0})),
    ):
        def _mk_ef_client(
            *a: Any,
            _factory: Any = resp_factory,
            **kw: Any,
        ) -> httpx.AsyncClient:
            if "transport" in kw:
                return orig_async_client(*a, **kw)
            return orig_async_client(transport=httpx.MockTransport(lambda _req: _factory()))

        monkeypatch.setattr("src.qa.scenarios.cb_11.httpx.AsyncClient", _mk_ef_client)
        monkeypatch.setattr("src.qa.scenarios.cb_13.httpx.AsyncClient", _mk_ef_client)
        assert asyncio.run(_get_total_applied("http://127.0.0.1:19993")) is None, payload_label
        assert asyncio.run(_get_effect_applied_count("http://127.0.0.1:19993")) is None, (
            payload_label
        )

    # End-to-end helper checks for CB-11 and CB-13 on HTTP 200 {} and 200 <html>
    async def _reach_true(*_a: Any, **_kw: Any) -> bool:
        return True

    async def _poll_ok(*_a: Any, **_kw: Any) -> dict[str, Any]:
        return {
            "run": {"status": "succeeded"},
            "result": {"answer": "ALM-3401 and WO-3408 read-only OK."},
        }

    async def _cb11_turn(*_a: Any, **_kw: Any) -> TurnOutcome:
        return TurnOutcome(
            "trn_w5",
            {"id": "msg_u_w5"},
            [
                {
                    "status": "done",
                    "content": "ALM-3401 and WO-3408 verified.",
                    "metadata": {"verdict": "verified"},
                }
            ],
            [],
            ["idle"],
            [],
            [],
        )

    monkeypatch.setattr("src.qa.scenarios.cb_11._verify_read_only_http_405", _reach_true)
    monkeypatch.setattr("src.qa.scenarios.cb_11.trigger_and_wait_turn", _cb11_turn)
    monkeypatch.setattr("src.qa.scenarios.cb_13._are_industrial_origins_reachable", _reach_true)
    monkeypatch.setattr("src.qa.scenarios.cb_13.poll_task_terminal", _poll_ok)

    def _studio_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/bots":
            return httpx.Response(200, json={"bots": [{"id": "bot_ops", "engine_id": "e"}]})
        if path == "/api/v1/bots/bot_ops" and request.method == "PATCH":
            return httpx.Response(200, json={"id": "bot_ops"})
        if path == "/api/tasks" and request.method == "POST":
            return httpx.Response(201, json={"run_id": "run_w5_ro"})
        return httpx.Response(404, json={})

    sys_info_ef: dict[str, Any] = {
        "backend_mode": "local_http",
        "emulated": False,
        "facility": {
            "facility_id": "facility-a",
            "apps": [
                {"app_id": "scada", "origin": "http://127.0.0.1:19991"},
                {"app_id": "maintenance", "origin": "http://127.0.0.1:19992"},
                {"app_id": "effect_sim", "origin": "http://127.0.0.1:19993"},
            ],
        },
    }

    for mode, resp_factory in (
        ("empty_json_200", lambda: httpx.Response(200, json={})),
        ("html_200", lambda: httpx.Response(200, text="<html>not json</html>")),
    ):
        def _ef_client_factory(
            *a: Any,
            _factory: Any = resp_factory,
            **kw: Any,
        ) -> httpx.AsyncClient:
            if "transport" in kw:
                return orig_async_client(*a, **kw)
            return orig_async_client(transport=httpx.MockTransport(lambda _req: _factory()))

        monkeypatch.setattr("src.qa.scenarios.cb_11.httpx.AsyncClient", _ef_client_factory)
        monkeypatch.setattr("src.qa.scenarios.cb_13.httpx.AsyncClient", _ef_client_factory)

        camp_11 = tmp_path / f"camp_cb11_{mode}"
        ctx_11 = ScenarioContext.create(
            case_id="CB-11",
            campaign_dir=camp_11,
            state=_make_state(camp_11),
            target_url="http://127.0.0.1:19999",
            token=None,
            repo_root=_REPO_ROOT,
            caps=_caps(),
        )
        camp_13 = tmp_path / f"camp_cb13_{mode}"
        ctx_13 = ScenarioContext.create(
            case_id="CB-13",
            campaign_dir=camp_13,
            state=_make_state(camp_13),
            target_url="http://127.0.0.1:19999",
            token=None,
            repo_root=_REPO_ROOT,
            caps=_caps(backend_mode="local_http", system_info=sys_info_ef),
        )

        async def _verify_both(
            c11: ScenarioContext = ctx_11,
            c13: ScenarioContext = ctx_13,
        ) -> None:
            async with orig_async_client(
                base_url="http://127.0.0.1:19999",
                transport=httpx.MockTransport(_studio_handler),
            ) as cl:
                await _verify_facility_a_pump34(
                    c11,
                    cl,
                    scada_url="http://127.0.0.1:19991",
                    maintenance_url="http://127.0.0.1:19992",
                    effect_sim_url="http://127.0.0.1:19993",
                    record_timing=False,
                )
                assert c11.assertions["facility_a_zero_effects"] is False

                ok_13, detail_13 = await _run_readonly_industrial_check(
                    c13, cl, sys_info_ef
                )
                assert ok_13 is False
                assert detail_13["zero_effects"] is False

        asyncio.run(_verify_both())


@pytest.mark.n1
def test_t5_w5_cb01_markdown_five_commonmark_gfm_constructs() -> None:
    from src.qa.scenarios.cb_01 import _extract_markdown_match_fragments

    # 1. ATX headings with optional closing hashes
    assert _normalize_markdown_for_match("## CB-01 Status ##\nBody OK") == "CB-01 Status"
    assert _normalize_markdown_for_match("## C# ##") == "C#"
    assert _normalize_markdown_for_match("## C#") == "C#"
    assert _normalize_markdown_for_match("## ###\nBody OK") == "Body OK"

    # 2. Headings inside list items (including task lists & nested lists)
    assert _normalize_markdown_for_match("- ### CB-01 Heading\nBody OK") == "CB-01 Heading"
    assert _normalize_markdown_for_match("1. ## Ordered Heading ##") == "Ordered Heading"
    assert _normalize_markdown_for_match("- [x] ### Task Heading") == "Task Heading"

    # 3. HTML character references outside code spans / escapes
    assert _normalize_markdown_for_match("CB-01 &amp; OK") == "CB-01 & OK"
    assert _normalize_markdown_for_match("**CB-01 &lt;v1&gt;**") == "CB-01 <v1>"
    assert _normalize_markdown_for_match("`CB-01 &amp; OK`") == "CB-01 &amp; OK"
    assert _normalize_markdown_for_match(r"\&amp; OK") == "&amp; OK"

    # 4. Blockquote-prefixed fenced code blocks (and top-level fences preserving `>`)
    assert _extract_markdown_match_fragments("> ```\n> **CB-01**\n> ```") == ["**CB-01**"]
    assert _extract_markdown_match_fragments("> > ```\n> > # Lit\n> > ```") == ["# Lit"]
    assert _extract_markdown_match_fragments("```\n> **CB-01**\n```") == ["> **CB-01**"]

    # 5. Intraword double-underscore preserved; boundary __bold__ & intraword **bold** stripped
    assert _normalize_markdown_for_match("foo__bar__baz CB-01") == "foo__bar__baz CB-01"
    assert _normalize_markdown_for_match("__CB-01__ OK") == "CB-01 OK"
    assert _normalize_markdown_for_match("foo**bar**baz") == "foobarbaz"


@pytest.mark.n1
def test_t5_w5_cb10_supports_values_kwarg_and_aliased_src_pkg_calc_import(
    tmp_path: Path,
) -> None:
    from src.qa.fixtures.cb_10_multiagent import deliverable_has_ast_symbols

    spec = build_cb10_three_deliverables_spec()

    def _write_proj(name: str, calc_src: str, cli_src: str, test_src: str) -> Path:
        p = tmp_path / name
        (p / "src_pkg").mkdir(parents=True)
        (p / "tests").mkdir(parents=True)
        (p / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
        (p / "src_pkg" / "calc.py").write_text(calc_src, encoding="utf-8")
        (p / "src_pkg" / "cli.py").write_text(cli_src, encoding="utf-8")
        (p / "tests" / "test_calc_cli.py").write_text(test_src, encoding="utf-8")
        return p

    calc_values_sig = (
        "def compute_summary(values):\n"
        "    vals = list(values)\n"
        "    t = float(sum(vals))\n"
        "    return {'count': float(len(vals)), 'sum': t, 'mean': t / len(vals)}\n"
    )
    good_test = (
        "import json, subprocess, sys\n"
        "def test_summary_cli_roundtrip():\n"
        "    p = subprocess.run([sys.executable, '-m', 'src_pkg.cli', '2', '4', '6'], "
        "capture_output=True, text=True, check=False)\n"
        "    assert p.returncode == 0\n"
        "    assert json.loads(p.stdout)['sum'] == 12.0\n"
    )

    # 1. Keyword call `compute_summary(values=...)` + generator input
    p_kw = _write_proj(
        "p_kw_values",
        calc_values_sig,
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print(json.dumps(compute_summary(values=(float(x) for x in raw))))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        good_test,
    )
    ok_kw, ass_kw, det_kw = evaluate_cb10_project(p_kw, spec)
    assert ok_kw is True, det_kw
    assert all(ass_kw.values())

    # 2. Aliased import `import src_pkg.calc as c` + `c.compute_summary(values=...)`
    p_alias = _write_proj(
        "p_alias_calc",
        calc_values_sig,
        "import json, sys\n"
        "import src_pkg.calc as c\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print(json.dumps(c.compute_summary(values=[float(x) for x in raw])))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        good_test,
    )
    ok_al, ass_al, det_al = evaluate_cb10_project(p_alias, spec)
    assert ok_al is True, det_al
    assert all(ass_al.values())

    # 3. `from src_pkg import calc as c; c.compute_summary(...)` passes D2 AST check
    ok_from_al, miss_from_al = deliverable_has_ast_symbols(
        "from src_pkg import calc as c\ndef main():\n    return c.compute_summary([1.0])\n",
        ("main", "compute_summary"),
        deliverable_id="D2",
    )
    assert ok_from_al is True, miss_from_al

    # 4. Negative controls: unrelated aliased module & uncalled aliased import remain rejected
    ok_unrel, miss_unrel = deliverable_has_ast_symbols(
        "import math as c\ndef main():\n    return c.compute_summary([1.0])\n",
        ("main", "compute_summary"),
        deliverable_id="D2",
    )
    assert ok_unrel is False and miss_unrel == ["compute_summary"]
    ok_nocall, miss_nocall = deliverable_has_ast_symbols(
        "import src_pkg.calc as c\ndef main():\n    _ref = c.compute_summary\n    return 0\n",
        ("main", "compute_summary"),
        deliverable_id="D2",
    )
    assert ok_nocall is False and miss_nocall == ["compute_summary"]


@pytest.mark.n1
def test_t5_w5_cb02_reference_card_alignment_uses_repo_root_fallback(tmp_path: Path) -> None:
    from src.qa.models import ReferenceBehaviorCard
    from src.qa.scenarios._common import ScenarioContext, finalize_scenario
    from src.qa.scenarios.cb_02 import _check_reference_card_alignment

    fake_repo = tmp_path / "fake_repo"
    repo_cards_dir = fake_repo / "var" / "qa_campaigns" / "reference_cards"
    repo_cards_dir.mkdir(parents=True)

    # 1. Conflicting CB-02 card only under repo_root/var/qa_campaigns/reference_cards
    stale_card = ReferenceBehaviorCard(
        card_id="ref-cb02-stale",
        case_id="CB-02",
        source="grok_bot_app",
        status="observed",
        bot_used="test",
        independent_verification="Observed USD 999.99 at /wrong/url",
        expected_controlbot_contract="USD 129.50 at /catalog/valves/cb-valve-104",
    )
    (repo_cards_dir / "cb02.json").write_text(
        stale_card.model_dump_json(indent=2), encoding="utf-8"
    )

    camp_conflict = tmp_path / "camp_cb02_conflict"
    fx = load_or_build_cb_valve_104_catalog(camp_conflict)
    ctx_conflict = ScenarioContext.create(
        case_id="CB-02",
        campaign_dir=camp_conflict,
        state=_make_state(camp_conflict),
        target_url="http://127.0.0.1:19999",
        token=None,
        repo_root=fake_repo,
        caps=_caps(),
    )
    ctx_conflict.assertions["catalog_checked"] = True
    _check_reference_card_alignment(ctx_conflict, fx)
    assert ctx_conflict.reference_matches_fixture is False

    rec_conflict, _ = finalize_scenario(ctx_conflict)
    ev_conflict = json.loads(
        Path(next(p for p in rec_conflict.artifact_paths if p.endswith(".json"))).read_text(
            encoding="utf-8"
        )
    )
    comps = ev_conflict["reference_comparisons"]
    assert len(comps) == 1
    assert comps[0]["reference_discrepancy"] is True
    assert comps[0]["verdict"] == "pass_fixture_overrides_reference"

    # 2. Aligned CB-02 card under repo_root/var/qa_campaigns/reference_cards
    aligned_card = ReferenceBehaviorCard(
        card_id="ref-cb02-ok",
        case_id="CB-02",
        source="grok_bot_app",
        status="observed",
        bot_used="test",
        independent_verification=(
            f"Observed USD {fx.active_record.price} at {fx.active_record.source_url}"
        ),
        expected_controlbot_contract=(
            f"USD {fx.active_record.price} at {fx.active_record.source_url}"
        ),
    )
    (repo_cards_dir / "cb02.json").write_text(
        aligned_card.model_dump_json(indent=2), encoding="utf-8"
    )
    camp_ok = tmp_path / "camp_cb02_ok"
    ctx_ok = ScenarioContext.create(
        case_id="CB-02",
        campaign_dir=camp_ok,
        state=_make_state(camp_ok),
        target_url="http://127.0.0.1:19999",
        token=None,
        repo_root=fake_repo,
        caps=_caps(),
    )
    ctx_ok.assertions["catalog_checked"] = True
    _check_reference_card_alignment(ctx_ok, fx)
    assert ctx_ok.reference_matches_fixture is True
    rec_ok, _ = finalize_scenario(ctx_ok)
    ev_ok = json.loads(
        Path(next(p for p in rec_ok.artifact_paths if p.endswith(".json"))).read_text(
            encoding="utf-8"
        )
    )
    assert ev_ok["reference_comparisons"][0]["reference_discrepancy"] is False
    assert ev_ok["reference_comparisons"][0]["verdict"] == "pass_parity_aligned"


# ---------------------------------------------------------------------------
# Wave 6 Regressions (Gaps #1..#2 + CB-07 bool parity)
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_w6_cb01_intraword_asterisk_and_defined_reflink_gating() -> None:
    # 1. Intraword single-asterisk emphasis stripped (matching CommonMark §6.2),
    #    while intraword `_` and `__`, spaced `*`, and spaced `**` stay literal.
    assert _normalize_markdown_for_match("foo*bar*baz CB-01") == "foobarbaz CB-01"
    assert _normalize_markdown_for_match("foo**bar**baz CB-01") == "foobarbaz CB-01"
    assert _normalize_markdown_for_match("***CB-01*** OK") == "CB-01 OK"
    assert _normalize_markdown_for_match("foo_bar_baz CB-01") == "foo_bar_baz CB-01"
    assert _normalize_markdown_for_match("foo__bar__baz CB-01") == "foo__bar__baz CB-01"
    assert _normalize_markdown_for_match("2 * 3 * 4") == "2 * 3 * 4"
    assert _normalize_markdown_for_match("** a **") == "** a **"

    # 2. Undefined [text][ref] / [text][] and ![alt][ref] / ![alt][] remain literal;
    #    defined reference links/images strip according to defined_refs.
    assert _normalize_markdown_for_match("[CB-01][] OK") == "[CB-01][] OK"
    assert _normalize_markdown_for_match("[CB-01][missing] OK") == "[CB-01][missing] OK"
    assert (
        _normalize_markdown_for_match("[CB-01][missing] OK\n\n[CB-01]: https://example.local")
        == "[CB-01][missing] OK"
    )
    assert _normalize_markdown_for_match("![alt][missing] OK") == "![alt][missing] OK"
    assert _normalize_markdown_for_match("![alt][] OK") == "![alt][] OK"

    assert (
        _normalize_markdown_for_match("[CB-01][] OK\n\n[CB-01]: https://example.local")
        == "CB-01 OK"
    )
    assert (
        _normalize_markdown_for_match("[Link][ref] OK\n\n[REF]: https://example.local")
        == "Link OK"
    )
    assert (
        _normalize_markdown_for_match("![alt][img]\nCB-01 OK\n\n[img]: https://example.local/a.png")
        == "CB-01 OK"
    )
    assert (
        _normalize_markdown_for_match("![alt][]\nCB-01 OK\n\n[ALT]: https://example.local/a.png")
        == "CB-01 OK"
    )


@pytest.mark.n1
def test_t5_w6_cb10_rejects_nested_d3_exit5_and_accepts_relative_aliased_calc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.qa.fixtures.cb_10_multiagent import (
        _check_d3_non_vacuous,
        deliverable_has_ast_symbols,
    )

    spec = build_cb10_three_deliverables_spec()

    def _write_proj(name: str, calc_src: str, cli_src: str, test_src: str) -> Path:
        p = tmp_path / name
        (p / "src_pkg").mkdir(parents=True)
        (p / "tests").mkdir(parents=True)
        (p / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
        (p / "src_pkg" / "calc.py").write_text(calc_src, encoding="utf-8")
        (p / "src_pkg" / "cli.py").write_text(cli_src, encoding="utf-8")
        (p / "tests" / "test_calc_cli.py").write_text(test_src, encoding="utf-8")
        return p

    good_calc = (
        "def compute_summary(vals):\n"
        "    t = float(sum(vals))\n"
        "    return {'count': float(len(vals)), 'sum': t, 'mean': t / len(vals)}\n"
    )
    good_cli = (
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print(json.dumps(compute_summary([float(x) for x in raw])))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n"
    )
    good_test = (
        "import json, subprocess, sys\n"
        "def test_summary_cli_roundtrip():\n"
        "    p = subprocess.run([sys.executable, '-m', 'src_pkg.cli', '2', '4', '6'], "
        "capture_output=True, text=True, check=False)\n"
        "    assert p.returncode == 0\n"
        "    assert json.loads(p.stdout)['sum'] == 12.0\n"
    )

    # 1. Nested test_summary_cli_roundtrip inside helper() + dummy top-level test -> rejected
    p_nested = _write_proj(
        "p_w6_nested_d3",
        good_calc,
        good_cli,
        "def test_other():\n    assert True\n\n"
        "def helper():\n"
        "    def test_summary_cli_roundtrip():\n"
        "        pass\n",
    )
    ok_nest, ass_nest, _ = evaluate_cb10_project(p_nested, spec)
    assert ok_nest is False
    assert ass_nest["d3_symbols"] is False
    assert ass_nest["d3_non_vacuous"] is False

    # 2. Non-Test* class method test_summary_cli_roundtrip -> rejected
    p_non_test_cls = _write_proj(
        "p_w6_non_test_cls",
        good_calc,
        good_cli,
        "def test_other():\n    assert True\n\n"
        "class Helper:\n"
        "    def test_summary_cli_roundtrip(self):\n"
        "        pass\n",
    )
    ok_cls, ass_cls, _ = evaluate_cb10_project(p_non_test_cls, spec)
    assert ok_cls is False
    assert ass_cls["d3_symbols"] is False
    assert ass_cls["d3_non_vacuous"] is False

    # 3. Direct _check_d3_non_vacuous rejects pytest exit 5 and exit 2
    assert _check_d3_non_vacuous(p_nested)[0] is False

    monkeypatch.setattr(
        "src.qa.fixtures.cb_10_multiagent.subprocess.run",
        lambda *_a, **_kw: subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr=""),
    )
    ok_rc2, msg_rc2 = _check_d3_non_vacuous(p_nested)
    assert ok_rc2 is False
    assert "rc=2" in msg_rc2
    monkeypatch.undo()

    # 4. Positive control: method on top-level Test* class passes
    p_test_cls = _write_proj(
        "p_w6_test_cls_ok",
        good_calc,
        good_cli,
        "import json, subprocess, sys\n"
        "class TestCLI:\n"
        "    def test_summary_cli_roundtrip(self):\n"
        "        p = subprocess.run([sys.executable, '-m', 'src_pkg.cli', '2', '4', '6'], "
        "capture_output=True, text=True, check=False)\n"
        "        assert p.returncode == 0\n"
        "        assert json.loads(p.stdout)['sum'] == 12.0\n",
    )
    ok_tcls, ass_tcls, det_tcls = evaluate_cb10_project(p_test_cls, spec)
    assert ok_tcls is True, det_tcls
    assert all(ass_tcls.values())

    # 5. Relative aliased import `from . import calc as c` passes D2 & full evaluation
    p_rel = _write_proj(
        "p_w6_rel_alias_ok",
        good_calc,
        "import json, sys\n"
        "from . import calc as c\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print(json.dumps(c.compute_summary([float(x) for x in raw])))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        good_test,
    )
    ok_rel, ass_rel, det_rel = evaluate_cb10_project(p_rel, spec)
    assert ok_rel is True, det_rel
    assert all(ass_rel.values())

    # 6. Negative AST controls for relative/unrelated/uncalled imports
    ok_rel_math, miss_rel_math = deliverable_has_ast_symbols(
        "from . import math as c\ndef main():\n    return c.compute_summary([1.0])\n",
        ("main", "compute_summary"),
        deliverable_id="D2",
    )
    assert ok_rel_math is False and miss_rel_math == ["compute_summary"]
    ok_rel_uncalled, miss_rel_uncalled = deliverable_has_ast_symbols(
        "from . import calc as c\ndef main():\n    _ref = c.compute_summary\n    return 0\n",
        ("main", "compute_summary"),
        deliverable_id="D2",
    )
    assert ok_rel_uncalled is False and miss_rel_uncalled == ["compute_summary"]


@pytest.mark.n1
def test_t5_w6_cb07_rejects_bool_total_applied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.qa.scenarios.cb_07 import _get_effect_sim_state, _get_effect_sim_total_applied
    from src.qa.ux_metrics import ScreenshotCheckpoint

    orig_async_client = httpx.AsyncClient

    for bool_val in (False, True):
        monkeypatch.setattr(
            "src.qa.scenarios.cb_07.httpx.AsyncClient",
            lambda *a, _bv=bool_val, **kw: (
                orig_async_client(*a, **kw)
                if "transport" in kw
                else orig_async_client(
                    transport=httpx.MockTransport(
                        lambda _req: httpx.Response(200, json={"total_applied": _bv, "effects": []})
                    )
                )
            ),
        )
        assert asyncio.run(_get_effect_sim_state("http://127.0.0.1:19991")) is None
        assert asyncio.run(_get_effect_sim_total_applied("http://127.0.0.1:19991")) is None

    # Post-task /api/effects/state returning boolean `total_applied: True` fails closed
    class _StubCard:
        def __init__(self) -> None:
            self.first = self

        def filter(self, *, has_text: str = "") -> _StubCard:
            del has_text
            return self

        def get_by_text(self, text: str) -> _StubCard:
            del text
            return self

        def get_by_role(self, role: str, *, name: str = "") -> _StubCard:
            del role, name
            return self

        async def wait_for(self, *, state: str = "visible", timeout: int = 10000) -> None:
            del state, timeout

        async def click(self) -> None:
            return None

    class _StubPage:
        async def goto(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def wait_for_selector(self, *args: Any, **kwargs: Any) -> None:
            return None

        def locator(self, selector: str) -> _StubCard:
            del selector
            return _StubCard()

    class _StubPw:
        def __init__(self) -> None:
            self.page = _StubPage()
            self.console_errors: list[str] = []
            self.page_errors: list[str] = []
            self.external_requests: list[str] = []

        async def __aenter__(self) -> _StubPw:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    async def _fake_shot(self: Any, *args: Any, **kwargs: Any) -> ScreenshotCheckpoint:
        return ScreenshotCheckpoint(
            checkpoint_id="shot-cb07-w6",
            case_id="CB-07",
            label="cb07_approvals",
            path=str(tmp_path / "shot.png"),
            byte_size=64,
            sha256="0" * 64,
            is_error_state=bool(kwargs.get("is_error_state", False)),
        )

    async def _fake_turn(*_a: Any, **_kw: Any) -> TurnOutcome:
        return TurnOutcome(
            "trn_cb07_w6",
            {"id": "msg_u1"},
            [],
            [],
            ["waiting_human"],
            [],
            [{"id": "apr_ui", "title": "CB07 UI Card"}],
        )

    approvals_db: dict[str, dict[str, Any]] = {}
    drafts_db: dict[str, str] = {}
    ef_calls = {"state": 0}

    def _studio_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/approvals" and request.method == "POST":
            body = json.loads(request.content.decode("utf-8"))
            aid = f"apr_{len(approvals_db) + 1}"
            approvals_db[aid] = {
                "id": aid,
                "status": "pending",
                "allow_always_allowed": body.get("allow_always_allowed", True),
            }
            return httpx.Response(201, json=approvals_db[aid])
        if path.startswith("/api/v1/approvals/") and path.endswith("/resolve"):
            aid = path.split("/")[4]
            dec = json.loads(request.content.decode("utf-8"))["decision"]
            rec = approvals_db[aid]
            if rec["status"] != "pending":
                return httpx.Response(409, json={"detail": "already resolved"})
            if dec == "always_allow" and not rec["allow_always_allowed"]:
                return httpx.Response(409, json={"detail": "always_allow disallowed"})
            rec["status"] = "allowed_once" if dec == "allow_once" else "denied"
            return httpx.Response(200, json=rec)
        if path == "/api/v1/drafts" and request.method == "POST":
            did = f"drf_{len(drafts_db) + 1}"
            drafts_db[did] = "pending"
            return httpx.Response(201, json={"id": did, "status": "pending"})
        if path.startswith("/api/v1/drafts/") and path.endswith("/resolve"):
            did = path.split("/")[4]
            if drafts_db[did] != "pending":
                return httpx.Response(409, json={"detail": "already resolved"})
            drafts_db[did] = "discarded"
            return httpx.Response(200, json={"id": did, "status": "discarded"})
        if path == "/api/tasks" and request.method == "POST":
            return httpx.Response(201, json={"run_id": "run_cb07_w6"})
        if path == "/api/tasks/run_cb07_w6":
            return httpx.Response(200, json={"run": {"status": "succeeded"}})
        return httpx.Response(404, json={})

    def _ef_bool_post_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/effects/state":
            ef_calls["state"] += 1
            if ef_calls["state"] <= 3:
                return httpx.Response(200, json={"total_applied": 0, "effects": []})
            return httpx.Response(200, json={"total_applied": True, "effects": []})
        return httpx.Response(404, json={})

    monkeypatch.setattr("src.qa.scenarios.cb_07.open_browser_session", lambda **_kw: _StubPw())
    monkeypatch.setattr("src.qa.scenarios._common.ScenarioContext.capture_shot", _fake_shot)
    monkeypatch.setattr("src.qa.scenarios.cb_07.trigger_and_wait_turn", _fake_turn)
    monkeypatch.setattr(
        "src.qa.scenarios.registry.probe_target_capabilities",
        lambda *_a, **_kw: _caps(
            effect_sim_url="http://127.0.0.1:19991",
            effect_sim_reachable=True,
        ),
    )
    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.async_client",
        lambda self, **_kw: orig_async_client(
            base_url=self.target_url,
            transport=httpx.MockTransport(_studio_handler),
        ),
    )
    monkeypatch.setattr(
        "src.qa.scenarios.cb_07.httpx.AsyncClient",
        lambda *a, **kw: (
            orig_async_client(*a, **kw)
            if "transport" in kw
            else orig_async_client(transport=httpx.MockTransport(_ef_bool_post_handler))
        ),
    )

    camp_bool = tmp_path / "camp_cb07_bool"
    res_bool = run_scenario(
        case_id="CB-07",
        campaign_dir=camp_bool,
        state=_make_state(camp_bool),
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
    )
    assert res_bool is not None
    rec_bool, _ = res_bool
    assert rec_bool.passed is False
    assert rec_bool.assertions["effect_sim_single_apply"] is False
    assert rec_bool.assertions["effect_sim_replay_dedup"] is False
    assert rec_bool.assertions["effect_sim_conflict_409"] is False


# ---------------------------------------------------------------------------
# Wave 7 Regressions (Challenger Findings 1..4)
# ---------------------------------------------------------------------------


@pytest.mark.n1
def test_t5_w7_cb01_gfm_footnotes_table_pipes_and_list_blockquotes() -> None:
    from src.qa.scenarios.cb_01 import _extract_markdown_match_fragments

    # 1. GFM footnote definitions stay distinct from reference links; defined footnotes number 1..N
    assert _normalize_markdown_for_match("CB-01 OK[^1]\n\n[^1]: note") == "CB-01 OK1"
    assert _normalize_markdown_for_match("CB-01 OK[^alpha]\n\n[^alpha]: note") == "CB-01 OK1"
    assert (
        _normalize_markdown_for_match(
            "Second[^beta] then First[^alpha]\n\n[^alpha]: a\n[^beta]: b"
        )
        == "Second1 then First2"
    )
    assert _normalize_markdown_for_match("CB-01 OK[^undef]") == "CB-01 OK[^undef]"
    assert (
        _normalize_markdown_for_match("[^1]: note\n\nCB-01 OK[^1]")
        == "CB-01 OK1"
    )
    assert (
        _normalize_markdown_for_match("```\n[^1]: fenced\n```\nCB-01 OK[^1]")
        == "[^1]: fenced"
    )

    # 2. Table rows protect inline code spans and escaped pipes before splitting on `|`
    assert _extract_markdown_match_fragments(
        "| `a | b` | C |\n| --- | --- |\n| 1 | 2 |"
    ) == ["a | b", "C", "1", "2"]
    assert _extract_markdown_match_fragments(
        r"| A \| B | C |" + "\n| --- | --- |\n| 1 | 2 |"
    ) == ["A | B", "C", "1", "2"]

    # 3. Interleaved blockquote + list-marker stripping
    assert _normalize_markdown_for_match("- > CB-01 OK") == "CB-01 OK"
    assert _normalize_markdown_for_match("- [x] > CB-01 OK") == "CB-01 OK"
    assert _normalize_markdown_for_match("- > - > **CB-01** OK") == "CB-01 OK"
    assert _normalize_markdown_for_match("- > ## CB-01 Heading ##") == "CB-01 Heading"


@pytest.mark.n1
def test_t5_w7_cb10_pretty_json_and_reject_d2_local_compute_summary(tmp_path: Path) -> None:
    from src.qa.fixtures.cb_10_multiagent import deliverable_has_ast_symbols

    spec = build_cb10_three_deliverables_spec()
    proj = tmp_path / "p_w7_pretty"
    (proj / "src_pkg").mkdir(parents=True)
    (proj / "tests").mkdir(parents=True)
    (proj / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "src_pkg" / "calc.py").write_text(
        "def compute_summary(vals):\n"
        "    t = float(sum(vals))\n"
        "    return {'count': float(len(vals)), 'sum': t, 'mean': t / len(vals)}\n",
        encoding="utf-8",
    )
    (proj / "src_pkg" / "cli.py").write_text(
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print(json.dumps(compute_summary([float(x) for x in raw]), indent=2))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        encoding="utf-8",
    )
    (proj / "tests" / "test_calc_cli.py").write_text(
        "import json, subprocess, sys\n"
        "def test_summary_cli_roundtrip():\n"
        "    p = subprocess.run([sys.executable, '-m', 'src_pkg.cli', '2', '4', '6'], "
        "capture_output=True, text=True, check=False)\n"
        "    assert p.returncode == 0\n"
        "    assert json.loads(p.stdout)['sum'] == 12.0\n",
        encoding="utf-8",
    )

    ok_pretty, ass_pretty, det_pretty = evaluate_cb10_project(proj, spec)
    assert ok_pretty is True, det_pretty
    assert ass_pretty["independent_cli_passed"] is True

    # Log-prefixed stdout ending with single-line JSON still works via fallback
    (proj / "src_pkg" / "cli.py").write_text(
        "import json, sys\n"
        "from src_pkg.calc import compute_summary\n"
        "def main(argv=None):\n"
        "    raw = argv if argv is not None else sys.argv[1:]\n"
        "    print('debug: running summary')\n"
        "    print(json.dumps(compute_summary([float(x) for x in raw])))\n"
        "    return 0\n"
        "if __name__ == '__main__':\n    raise SystemExit(main())\n",
        encoding="utf-8",
    )
    (proj / "tests" / "test_calc_cli.py").write_text(
        "import json, subprocess, sys\n"
        "def test_summary_cli_roundtrip():\n"
        "    p = subprocess.run([sys.executable, '-m', 'src_pkg.cli', '2', '4', '6'], "
        "capture_output=True, text=True, check=False)\n"
        "    assert p.returncode == 0\n"
        "    assert json.loads(p.stdout.strip().splitlines()[-1])['sum'] == 12.0\n",
        encoding="utf-8",
    )
    ok_log, ass_log, det_log = evaluate_cb10_project(proj, spec)
    assert ok_log is True, det_log
    assert ass_log["independent_cli_passed"] is True

    # D2 AST check rejects local def compute_summary without src_pkg.calc import
    ok_local, miss_local = deliverable_has_ast_symbols(
        "def compute_summary(vals):\n"
        "    return {'sum': sum(vals)}\n"
        "def main():\n"
        "    return compute_summary([2.0, 4.0])\n",
        ("main", "compute_summary"),
        deliverable_id="D2",
    )
    assert ok_local is False
    assert miss_local == ["compute_summary"]

    # D2 AST check rejects unrelated module aliased to compute_summary
    ok_fake_imp, miss_fake_imp = deliverable_has_ast_symbols(
        "from math import sin as compute_summary\n"
        "def main():\n"
        "    return compute_summary(1.0)\n",
        ("main", "compute_summary"),
        deliverable_id="D2",
    )
    assert ok_fake_imp is False
    assert miss_fake_imp == ["compute_summary"]


@pytest.mark.n1
def test_t5_w7_cb12_same_epoch_requires_non_empty_valid_event_ids() -> None:
    from src.qa.scenarios._common import SseEventFrame
    from src.qa.scenarios.cb_12 import _evaluate_sigterm_sse_replay

    def _rx_frame(event_id: str | None, emoji: str) -> SseEventFrame:
        return SseEventFrame(
            event_id=event_id,
            event="message.reaction",
            event_type="message.reaction",
            data={"payload": {"emoji": emoji}},
        )

    # Empty replayed list -> fails
    ok_empty, ev_empty = _evaluate_sigterm_sse_replay(
        [], epoch_before="ep1", bot_survived=True
    )
    assert ok_empty is False
    assert ev_empty["same_epoch"] is False

    # Missing or malformed event_id on message.reaction frames -> fails
    ok_none, ev_none = _evaluate_sigterm_sse_replay(
        [_rx_frame(None, "2️⃣"), _rx_frame("malformed", "3️⃣")],
        epoch_before="ep1",
        bot_survived=True,
    )
    assert ok_none is False
    assert ev_none["same_epoch"] is False

    # Mixed valid + missing event_id -> fails
    ok_mixed, ev_mixed = _evaluate_sigterm_sse_replay(
        [_rx_frame("evt_000002_ep1", "2️⃣"), _rx_frame(None, "3️⃣")],
        epoch_before="ep1",
        bot_survived=True,
    )
    assert ok_mixed is False
    assert ev_mixed["same_epoch"] is False

    # Wrong epoch or non-numeric seq -> fails
    ok_wrong_ep, ev_wrong_ep = _evaluate_sigterm_sse_replay(
        [_rx_frame("evt_000002_ep1", "2️⃣"), _rx_frame("evt_000003_ep2", "3️⃣")],
        epoch_before="ep1",
        bot_survived=True,
    )
    assert ok_wrong_ep is False
    assert ev_wrong_ep["same_epoch"] is False

    ok_bad_seq, ev_bad_seq = _evaluate_sigterm_sse_replay(
        [_rx_frame("evt_abc_ep1", "2️⃣"), _rx_frame("evt_000003_ep1", "3️⃣")],
        epoch_before="ep1",
        bot_survived=True,
    )
    assert ok_bad_seq is False
    assert ev_bad_seq["same_epoch"] is False

    # Valid evt_<seq>_<epoch> on all frames -> passes
    ok_good, ev_good = _evaluate_sigterm_sse_replay(
        [_rx_frame("evt_000002_ep1", "2️⃣"), _rx_frame("evt_000003_ep1", "3️⃣")],
        epoch_before="ep1",
        bot_survived=True,
    )
    assert ok_good is True
    assert ev_good["same_epoch"] is True


@pytest.mark.n1
def test_t5_w7_fetch_project_tree_http_enforces_path_confinement(tmp_path: Path) -> None:
    from src.factory.errors import IsolationBoundaryError
    from src.qa.scenarios._common import fetch_project_tree_http

    root = tmp_path / "sandbox"
    dest = root / "dest"
    dest.mkdir(parents=True)

    for unsafe_name in ("../escaped.txt", "..", ".", "sub/evil.txt", r"sub\evil.txt", "a\x00b"):
        def _evil_handler(request: httpx.Request, _name: str = unsafe_name) -> httpx.Response:
            if request.url.path.endswith("/files"):
                return httpx.Response(
                    200,
                    json={
                        "entries": [
                            {"rel_path": "cb09_proj/evil", "name": _name, "is_dir": False}
                        ]
                    },
                )
            return httpx.Response(200, json={"content": "pwned"})

        async def _run_evil(handler: Any = _evil_handler) -> list[str]:
            async with httpx.AsyncClient(
                base_url="http://127.0.0.1:19999",
                transport=httpx.MockTransport(handler),
            ) as cl:
                return await fetch_project_tree_http(
                    cl, project_rel_root="cb09_proj", dest_dir=dest
                )

        with pytest.raises(IsolationBoundaryError):
            asyncio.run(_run_evil())
        assert not (root / "escaped.txt").exists()

    # Valid nested tree writes strictly inside dest
    def _safe_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/files"):
            rel = request.url.params.get("path", "")
            if rel == "cb09_proj":
                return httpx.Response(
                    200,
                    json={
                        "entries": [
                            {"rel_path": "cb09_proj/src_pkg", "name": "src_pkg", "is_dir": True}
                        ]
                    },
                )
            return httpx.Response(
                200,
                json={
                    "entries": [
                        {
                            "rel_path": "cb09_proj/src_pkg/calc.py",
                            "name": "calc.py",
                            "is_dir": False,
                        }
                    ]
                },
            )
        return httpx.Response(200, json={"content": "def ok():\n    return 1\n"})

    async def _run_safe() -> list[str]:
        async with httpx.AsyncClient(
            base_url="http://127.0.0.1:19999",
            transport=httpx.MockTransport(_safe_handler),
        ) as cl:
            return await fetch_project_tree_http(
                cl, project_rel_root="cb09_proj", dest_dir=dest
            )

    downloaded = asyncio.run(_run_safe())
    assert downloaded == ["src_pkg/calc.py"]
    assert (dest / "src_pkg" / "calc.py").read_text(encoding="utf-8") == "def ok():\n    return 1\n"
