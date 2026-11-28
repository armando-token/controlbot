"""Unit tests for M5 CB-11..CB-13 scenarios, facility_id scoping & QA-6 N3 blocker docs."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import src.qa as qa_pkg
import src.qa.scenarios as scenarios_pkg
import src.qa.scenarios.registry as registry_mod
from pydantic import ValidationError
from src.adapters.config import FacilityConfig
from src.doctor import CheckResult, CheckStatus, EvidenceLevel
from src.n3_probe import N3ProbeReport, N3Status
from src.qa.cli import _compute_run_stats, _render_campaign_handoff, _render_daily_report, main
from src.qa.models import BaselineReport, CampaignState
from src.qa.queue import open_campaign_store
from src.qa.scenarios import IMPLEMENTED_CASES, SCENARIO_RUNNERS, run_scenario
from src.qa.scenarios._common import TargetCapabilities
from src.qa.scenarios.cb_13 import run_n3_honest_probe
from src.qa.ux_metrics import contains_unredacted_secret_m3
from src.web.app import create_app
from src.web.live_browser import LiveBrowserController
from src.web.v1.events import EventBus
from src.web.v1.runner import AgentTurnRunner
from src.web.v1.schemas import MessageCreateRequest
from src.web.v1.store import WorkspaceStore

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _make_state(
    camp_dir: Path,
    base_sha: str = "sha_m5_unit",
    *,
    target_url: str | None = None,
) -> CampaignState:
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id=f"qa-m5-{uuid.uuid4().hex[:6]}",
        base_sha=base_sha,
        lane="local_deterministic",
        target_url=target_url,
        output_dir=str(camp_dir),
    )
    (camp_dir / "campaign.json").write_text(state.model_dump_json(indent=2), encoding="utf-8")
    return state


def _make_n3_report(
    status: N3Status,
    *,
    has_fail: bool = False,
) -> N3ProbeReport:
    is_ready = status == "READY"
    chk_status = (
        CheckStatus.FAIL
        if has_fail
        else (CheckStatus.PASS if is_ready else CheckStatus.PENDING_N3_LINUX_ENV)
    )
    return N3ProbeReport(
        timestamp_utc="2026-11-27T00:00:00Z",
        host_os="Linux",
        host_release="6.1.0",
        arch="x86_64",
        overall_status=status,
        linux_os_ready=True,
        network_isolation_ready=is_ready,
        desktop_ready=is_ready,
        local_llm_ready=status != "PENDING_LOCAL_LLM" and is_ready,
        checks=[
            CheckResult(
                name="network_isolation_a11",
                status=chk_status,
                required_for=EvidenceLevel.N3,
                summary="Mocked N3 network check",
            )
        ],
        evidence_notes=[f"Mocked status={status}"],
    )


@pytest.mark.n1
def test_m5_registry_completeness_and_no_deferred_m5_cases() -> None:
    expected = {f"CB-{i:02d}" for i in range(14)}
    assert expected == IMPLEMENTED_CASES
    assert set(SCENARIO_RUNNERS) == expected
    assert not hasattr(registry_mod, "DEFERRED_M5_CASES")
    assert not hasattr(scenarios_pkg, "DEFERRED_M5_CASES")
    assert not hasattr(qa_pkg, "DEFERRED_M5_CASES")


@pytest.mark.n1
def test_cb13_pending_fail_and_ready_behaviors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "src.qa.scenarios.cb_13._run_verify_n3_script", lambda _r: (2, "", "egress")
    )
    monkeypatch.setattr("src.qa.scenarios.cb_13._run_pytest_n3", lambda _r: (0, "2 skipped", ""))

    pending_statuses: tuple[N3Status, ...] = ("PENDING_N3_LINUX_ENV", "PENDING_LOCAL_LLM")
    for pending_status in pending_statuses:
        camp_dir = tmp_path / f"camp_{pending_status.lower()}"
        state = _make_state(camp_dir)
        rep = _make_n3_report(pending_status, has_fail=False)
        rec, findings = run_n3_honest_probe(
            campaign_dir=camp_dir,
            state=state,
            repo_root=_REPO_ROOT,
            n3_report=rep,
        )
        assert rec.passed is False
        assert rec.assertions["n3_ready"] is False
        assert rec.blocked_reason and pending_status in rec.blocked_reason
        assert "verify_n3_linux.sh" in rec.blocked_reason
        assert findings == [], "Environmental PENDING state must keep open_p1 == 0"

    # Real CheckStatus.FAIL emits a P1 finding
    camp_fail = tmp_path / "camp_fail"
    state_fail = _make_state(camp_fail)
    rep_fail = _make_n3_report("PENDING_N3_LINUX_ENV", has_fail=True)
    rec_fail, findings_fail = run_n3_honest_probe(
        campaign_dir=camp_fail,
        state=state_fail,
        repo_root=_REPO_ROOT,
        n3_report=rep_fail,
    )
    assert rec_fail.passed is False
    assert len(findings_fail) == 1 and findings_fail[0]["severity"] == "P1"

    # READY with target_url passes when N3, local_http, chat, industrial & UI pass
    camp_ready = tmp_path / "camp_ready"
    state_ready = _make_state(camp_ready, target_url="http://127.0.0.1:19999")
    rep_ready = _make_n3_report("READY", has_fail=False)
    strict_calls: list[bool] = []

    def _fake_pytest_n3(_r: Path, *, strict: bool = False) -> tuple[int, str, str]:
        strict_calls.append(strict)
        return (0, "2 passed", "")

    monkeypatch.setattr("src.qa.scenarios.cb_13._run_verify_n3_script", lambda _r: (0, "ok", ""))
    monkeypatch.setattr("src.qa.scenarios.cb_13._run_pytest_n3", _fake_pytest_n3)
    fake_sys_info: dict[str, Any] = {
        "backend_mode": "local_http",
        "emulated": False,
        "facility": {
            "facility_id": "facility-a",
            "apps": [
                {"app_id": "scada", "origin": "http://127.0.0.1:19991"},
                {"app_id": "maintenance", "origin": "http://127.0.0.1:19992"},
            ],
        },
    }
    monkeypatch.setattr(
        "src.qa.scenarios.registry.probe_target_capabilities",
        lambda *_a, **_kw: TargetCapabilities(
            health_ok=True,
            backend_mode="local_http",
            runtime_mode="live_runtime",
            model_id="local-llm",
            agy_available=False,
            projects_root=None,
            effect_sim_url=None,
            effect_sim_reachable=False,
            request_ids=(),
            system_info=fake_sys_info,
        ),
    )

    async def _fake_ind_reachable(_origins: dict[str, str]) -> bool:
        return True

    monkeypatch.setattr(
        "src.qa.scenarios.cb_13._are_industrial_origins_reachable",
        _fake_ind_reachable,
    )

    class _FakeResp:
        def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
            self.status_code = status_code
            self._payload = payload
            self.headers: dict[str, str] = {"X-Request-Id": "req_cb13_ok"}

        def json(self) -> dict[str, Any]:
            return self._payload

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

    class _FakeSseStream:
        def __init__(self, client: _FakeAsyncClient) -> None:
            self._client = client
            self.status_code = 200

        async def __aenter__(self) -> _FakeSseStream:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        def raise_for_status(self) -> None:
            return None

        async def aiter_lines(self) -> Any:
            import asyncio

            for _ in range(50):
                if self._client._turn_id:
                    break
                await asyncio.sleep(0.01)
            tid = self._client._turn_id or "trn_cb13"
            ev_done = json.dumps(
                {
                    "type": "message.completed",
                    "thread_id": "thr_bot_chief",
                    "turn_id": tid,
                    "payload": {
                        "message": {
                            "id": "msg_bot_cb13",
                            "sender_type": "bot",
                            "sender_bot_id": "bot_chief",
                            "status": "done",
                            "content": "Local LLM response verified.",
                        }
                    },
                }
            )
            ev_idle = json.dumps(
                {
                    "type": "bot.presence",
                    "thread_id": "thr_bot_chief",
                    "turn_id": tid,
                    "payload": {"state": "idle"},
                }
            )
            for line in (
                "id: evt_1",
                "event: message.completed",
                f"data: {ev_done}",
                "",
                "id: evt_2",
                "event: bot.presence",
                f"data: {ev_idle}",
                "",
            ):
                yield line

    class _FakeAsyncClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._turn_id: str | None = None
            self._last_prompt: str = ""

        async def __aenter__(self) -> _FakeAsyncClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        def stream(self, method: str, path: str, **kwargs: Any) -> _FakeSseStream:
            del method, path, kwargs
            return _FakeSseStream(self)

        async def post(self, path: str, **kwargs: Any) -> _FakeResp:
            if path == "/api/v1/threads/thr_bot_chief/messages":
                self._turn_id = "trn_cb13_ok"
                self._last_prompt = str((kwargs.get("json") or {}).get("content") or "")
                return _FakeResp(
                    202,
                    {
                        "turn_id": self._turn_id,
                        "user_message": {
                            "id": "msg_usr_cb13",
                            "sender_type": "user",
                            "content": self._last_prompt,
                        },
                    },
                )
            if path == "/api/tasks":
                return _FakeResp(201, {"run_id": "run_cb13_ind", "status": "queued"})
            return _FakeResp(404, {})

        async def patch(self, path: str, **kwargs: Any) -> _FakeResp:
            del path, kwargs
            return _FakeResp(200, {"id": "bot_chief", "engine_id": "controlbot_runtime"})

        async def get(self, path: str) -> _FakeResp:
            if path == "/health":
                return _FakeResp(200, {"status": "ok"})
            if path == "/api/v1/bots":
                return _FakeResp(
                    200, {"bots": [{"id": "bot_chief", "engine_id": "controlbot_runtime"}]}
                )
            if path == "/api/v1/threads/thr_bot_chief/messages":
                return _FakeResp(
                    200,
                    {
                        "messages": [
                            {
                                "id": "msg_usr_cb13",
                                "sender_type": "user",
                                "content": self._last_prompt,
                            },
                            {
                                "id": "msg_bot_cb13",
                                "sender_type": "bot",
                                "sender_bot_id": "bot_chief",
                                "status": "done",
                                "content": "Local LLM response verified.",
                            },
                        ]
                    },
                )
            if path == "/api/tasks/run_cb13_ind":
                return _FakeResp(
                    200,
                    {
                        "run": {"run_id": "run_cb13_ind", "status": "succeeded"},
                        "result": {"answer": "ALM-3401 and WO-3408 read-only OK."},
                    },
                )
            return _FakeResp(200, fake_sys_info)

    class _FakePage:
        async def goto(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def wait_for_selector(self, *args: Any, **kwargs: Any) -> None:
            return None

    class _FakePwSession:
        def __init__(self) -> None:
            self.page = _FakePage()
            self.console_errors: list[str] = []
            self.page_errors: list[str] = []
            self.external_requests: list[str] = []

        async def __aenter__(self) -> _FakePwSession:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    async def _fake_loc(_page: Any) -> tuple[bool, str]:
        return True, "top_header"

    async def _fake_comp(_page: Any) -> tuple[bool, dict[str, Any]]:
        return True, {}

    async def _fake_shot(*args: Any, **kwargs: Any) -> Any:
        from src.qa.ux_metrics import ScreenshotCheckpoint

        return ScreenshotCheckpoint(
            checkpoint_id="shot-cb13-ready",
            case_id="CB-13",
            label="cb13_n3_local",
            path=str(camp_ready / "screenshots" / "cb13.png"),
            byte_size=128,
            sha256="0" * 64,
            is_error_state=False,
        )

    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.async_client",
        lambda self, **_kw: _FakeAsyncClient(),
    )
    monkeypatch.setattr(
        "src.qa.scenarios.cb_13.open_browser_session",
        lambda **_kw: _FakePwSession(),
    )
    monkeypatch.setattr("src.qa.scenarios.cb_13.check_local_remote_indicator", _fake_loc)
    monkeypatch.setattr("src.qa.scenarios.cb_13.check_composer_single_row", _fake_comp)
    monkeypatch.setattr(
        "src.qa.scenarios._common.ScenarioContext.capture_shot",
        _fake_shot,
    )

    res_ready = run_scenario(
        case_id="CB-13",
        campaign_dir=camp_ready,
        state=state_ready,
        target_url="http://127.0.0.1:19999",
        repo_root=_REPO_ROOT,
        n3_report=rep_ready,
    )
    assert res_ready is not None
    rec_ready, findings_ready = res_ready
    assert rec_ready.passed is True
    assert rec_ready.assertions["n3_ready"] is True
    assert rec_ready.assertions["verify_n3_linux_passed"] is True
    assert rec_ready.assertions["test_n3_passed"] is True
    assert rec_ready.assertions["local_llm_backend_active"] is True
    assert rec_ready.assertions["local_chat_turn_completed"] is True
    assert rec_ready.assertions["read_only_industrial_check_passed"] is True
    assert strict_calls == [True]
    assert findings_ready == []


@pytest.mark.n1
async def test_runner_facility_id_resolution_schemas_routes_and_read_only(tmp_path: Path) -> None:
    # 1. MessageCreateRequest validation (whitespace & secret rejection, incl. bare sk-...)
    with pytest.raises(ValidationError):
        MessageCreateRequest(content="hi", facility_id="   ")
    with pytest.raises(ValidationError):
        MessageCreateRequest(content="hi", facility_id="fac token=secretkey123456")
    with pytest.raises(ValidationError):
        MessageCreateRequest(content="hi", facility_id="sk-1234567890abcdefghijklmnop")
    with pytest.raises(ValidationError):
        MessageCreateRequest(content="hi", allowed_areas=["area-1", "   "])
    with pytest.raises(ValidationError):
        MessageCreateRequest(content="hi", allowed_areas=["sk-1234567890abcdefghijklmnop"])

    req = MessageCreateRequest(
        content="Check P-77B",
        facility_id="  facility-b  ",
        allowed_areas=[" area-2 ", "area-2", "area-3"],
    )
    assert req.facility_id == "facility-b"
    assert req.allowed_areas == ["area-2", "area-3"]

    # 2. create_app wires coord._facility_config into v1_runner._facility_config
    fac_b = FacilityConfig.model_validate_json(
        (_REPO_ROOT / "lab" / "configs" / "facility_b.json").read_text(encoding="utf-8")
    )

    class _FakeCoord:
        def __init__(self, cfg: FacilityConfig) -> None:
            self._facility_config = cfg

    app = create_app(db_path=tmp_path / "fac_wire.sqlite3", coordinator=_FakeCoord(fac_b))  # type: ignore[arg-type]
    try:
        assert app.state.v1_runner._resolve_facility_config() is fac_b

        captured_turn: dict[str, Any] = {}

        def _fake_start_turn(**kwargs: Any) -> str:
            captured_turn.update(kwargs)
            return "trn_fac_b_route"

        with patch.object(app.state.v1_runner, "start_turn", side_effect=_fake_start_turn):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/threads/thr_bot_ops/messages",
                    json={
                        "content": "Check P-77B alarms",
                        "facility_id": "facility-b",
                        "allowed_areas": ["area-2"],
                    },
                )
        assert resp.status_code == 202
        user_msg = resp.json()["user_message"]
        assert user_msg["metadata"]["facility_id"] == "facility-b"
        assert user_msg["metadata"]["allowed_areas"] == ["area-2"]
        assert captured_turn["facility_id"] == "facility-b"
        assert captured_turn["allowed_areas"] == ["area-2"]
    finally:
        app.state.memory_store.close()
        app.state.event_bus.close()
        app.state.workspace_store.close()

    # 3. _resolve_runtime_scope precedence & ALWAYS read_only=True & allowed_areas=() default
    store = WorkspaceStore(tmp_path / "scope_ws.sqlite3")
    bus = EventBus(db_path=store.db_path)
    browser = LiveBrowserController(profile_root=tmp_path / "prof")
    try:
        runner = AgentTurnRunner(
            store=store,
            event_bus=bus,
            live_browser=browser,
            coordinator=_FakeCoord(fac_b),  # type: ignore[arg-type]
            uploads_dir=tmp_path / "uploads",
            facility_config=fac_b,
        )
        # Default from facility_config, allowed_areas stays () for ambiguity preservation
        s_cfg = runner._resolve_runtime_scope()
        assert s_cfg.facility_id == "facility-b"
        assert s_cfg.allowed_areas == ()
        assert s_cfg.read_only is True

        # Metadata overrides config; explicit arg overrides metadata
        s_meta = runner._resolve_runtime_scope(
            user_message={"metadata": {"facility_id": "facility-c", "allowed_areas": ["area-9"]}}
        )
        assert s_meta.facility_id == "facility-c"
        assert s_meta.allowed_areas == ("area-9",)
        assert s_meta.read_only is True

        s_exp = runner._resolve_runtime_scope(
            facility_id="facility-x",
            allowed_areas=("area-7",),
            user_message={"metadata": {"facility_id": "facility-c"}},
        )
        assert s_exp.facility_id == "facility-x"
        assert s_exp.allowed_areas == ("area-7",)
        assert s_exp.read_only is True

        with pytest.raises(ValueError, match="sensitive credentials"):
            runner._resolve_runtime_scope(facility_id="sk-1234567890abcdefghijklmnop")
        with pytest.raises(ValueError, match="sensitive credentials"):
            runner._resolve_runtime_scope(allowed_areas=["sk-1234567890abcdefghijklmnop"])

        # 4. ask_first pending_context -> on_approval_resolved preserves facility_id & allowed_areas
        store.add_auto_review_rule("ask_first", "Ask before 'p-77b' alarms")
        ask_msg = store.create_message(
            thread_id="thr_bot_ops",
            sender_type="user",
            sender_bot_id=None,
            sender_name="Operator",
            content="Check P-77B alarms",
            metadata={"facility_id": "facility-b", "allowed_areas": ["area-2"]},
        )
        await runner._run_thread_turn(
            thread_id="thr_bot_ops",
            turn_id="trn_ask_first_m5",
            user_message=ask_msg,
            include_browser_context=None,
            model_id=None,
            thinking_level=None,
            skill_ids=[],
            skip_auto_review=False,
            facility_id="facility-b",
            allowed_areas=["area-2"],
        )
        ask_apprs = [
            a
            for a in store.list_thread_approvals("thr_bot_ops")
            if a.get("kind") == "ask_first" and a.get("status") == "pending"
        ]
        assert len(ask_apprs) == 1
        ask_appr = ask_apprs[0]
        pending_ctx = store.get_approval_pending_context(str(ask_appr["id"]))
        assert pending_ctx is not None
        assert pending_ctx["facility_id"] == "facility-b"
        assert pending_ctx["allowed_areas"] == ["area-2"]

        resumed_kwargs: dict[str, Any] = {}

        def _capture_resumed_turn(**kwargs: Any) -> str:
            resumed_kwargs.update(kwargs)
            return "trn_ask_resumed_m5"

        with patch.object(runner, "start_turn", side_effect=_capture_resumed_turn):
            await runner.on_approval_resolved(ask_appr, decision="allow_once")

        assert resumed_kwargs["facility_id"] == "facility-b"
        assert resumed_kwargs["allowed_areas"] == ["area-2"]
        assert resumed_kwargs["skip_auto_review"] is True
        resumed_scope = runner._resolve_runtime_scope(
            facility_id=resumed_kwargs["facility_id"],
            allowed_areas=resumed_kwargs["allowed_areas"],
            user_message=resumed_kwargs["user_message"],
        )
        assert resumed_scope.facility_id == "facility-b"
        assert resumed_scope.allowed_areas == ("area-2",)
        assert resumed_scope.read_only is True
    finally:
        bus.close()
        store.close()


@pytest.mark.n1
def test_cb11_cb12_fail_closed_and_secret_redaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_tok = "sk-m5secretcanary99887766"
    monkeypatch.setattr(
        "src.qa.scenarios.registry.probe_target_capabilities",
        lambda *_a, **_kw: TargetCapabilities(
            health_ok=True,
            backend_mode="emulated",
            runtime_mode="live_runtime",
            model_id="emulated",
            agy_available=False,
            projects_root=None,
            effect_sim_url=None,
            effect_sim_reachable=False,
            request_ids=(),
            system_info={"backend_mode": "emulated"},
        ),
    )

    def _boom(_ctx: Any) -> Any:
        raise RuntimeError(f"upstream failed bearer token={secret_tok}")

    monkeypatch.setitem(SCENARIO_RUNNERS, "CB-11", _boom)
    camp_dir = tmp_path / "camp_red"
    state = _make_state(camp_dir, target_url="http://127.0.0.1:19888")
    res = run_scenario(
        case_id="CB-11",
        campaign_dir=camp_dir,
        state=state,
        target_url="http://127.0.0.1:19888",
        repo_root=_REPO_ROOT,
    )
    assert res is not None
    rec, findings = res
    assert rec.passed is False
    assert rec.assertions.get("scenario_execution_completed") is False
    assert findings
    ev_files = [Path(p) for p in rec.artifact_paths if p.endswith(".json") and "artifacts" in p]
    assert ev_files
    ev_data = json.loads(ev_files[0].read_text(encoding="utf-8"))
    assert not contains_unredacted_secret_m3(ev_data)
    assert secret_tok not in json.dumps(ev_data)


@pytest.mark.n1
def test_qa6_report_renders_n3_blocker_section_preserving_zero_p0_p1(tmp_path: Path) -> None:
    camp_dir = tmp_path / "camp_qa6_doc"
    state = _make_state(camp_dir, base_sha="sha_doc_1")
    open_campaign_store(camp_dir, state, repo_root=_REPO_ROOT)
    baseline = BaselineReport(
        campaign_id=state.campaign_id,
        repo_sha="sha_doc_1",
        deployed_sha="sha_doc_1",
        surface_verified=True,
        served_surface="react",
        backend_mode="emulated",
        runtime_mode="live_runtime",
        n3_status="PENDING_N3_LINUX_ENV",
        skipped_checks=["n3_probe:PENDING_N3_LINUX_ENV"],
        overall_passed=True,
        exit_code=0,
    )
    (camp_dir / "baseline.json").write_text(baseline.model_dump_json(indent=2), encoding="utf-8")

    rep_cb13 = _make_n3_report("PENDING_N3_LINUX_ENV")
    rec_13, _ = run_n3_honest_probe(
        campaign_dir=camp_dir,
        state=state,
        repo_root=_REPO_ROOT,
        n3_report=rep_cb13,
    )
    stats = _compute_run_stats(state, [rec_13], [], [])
    assert stats["open_p0"] == 0
    assert stats["open_p1"] == 0

    daily = _render_daily_report(state, baseline, stats, runs=[rec_13])
    handoff = _render_campaign_handoff(state, baseline, stats, runs=[rec_13])
    combined = f"{daily}\n{handoff}"
    assert "## N3 & Environmental Blockers" in daily
    assert "## N3 & Environmental Blockers" in handoff
    assert "bash scripts/verify_n3_linux.sh" in combined
    assert "make test-n3" in combined
    assert re.search(r"(?i)open p0[^\n0-9]*0", daily)
    assert re.search(r"(?i)open p1[^\n0-9]*0", daily)
    assert main(["report", "--campaign-dir", str(camp_dir), "--repo-root", str(_REPO_ROOT)]) == 0
    assert (camp_dir / "HANDOFF.md").is_file()
    assert (camp_dir / "daily_report.md").is_file()
