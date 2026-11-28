"""Shared isolated target probing, SSE/Playwright & artifact builders for CB-00..CB-10."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import hashlib
import json
import shutil
import socket
import tempfile
import threading
import time
import uuid
from collections.abc import AsyncIterator, Coroutine, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
import uvicorn
from lab.effect_sim import create_effect_sim_app
from lab.maintenance_app import MaintenanceState, create_maintenance_app
from lab.scada_app import ScadaState, create_scada_app
from playwright.async_api import (
    BrowserContext,
    ConsoleMessage,
    Page,
    Response,
    Route,
    WebSocket,
    async_playwright,
)

from src.contracts.common import utc_now
from src.factory.errors import IsolationBoundaryError
from src.qa.isolation import (
    _HOST_HOME,
    StrictPlaywrightSession,
    _is_allowed_browser_url,
    _is_under,
    _scrub_url_strict,
    alloc_ephemeral_port,
    assert_not_live_target,
    assert_safe_mutation_path,
)
from src.qa.isolation import (
    _REPO_ROOT as _ISOLATION_REPO_ROOT,
)
from src.qa.models import BaselineReport, CampaignState, ReferenceBehaviorCard, RunRecord
from src.qa.queue import assert_strictly_redacted
from src.qa.reference_cards import compare_against_fixture_truth, load_reference_cards
from src.qa.ux_metrics import (
    ScreenshotCheckpoint,
    UxFlowMetrics,
    UxMetricReport,
    capture_screenshot_checkpoint,
    contains_unredacted_secret_m3,
    redact_payload_m3,
    save_ux_metrics,
)

_REPO_ROOT: Path = _ISOLATION_REPO_ROOT


def run_coro_sync[T](coro: Coroutine[Any, Any, T]) -> T:
    """Run an async coroutine safely from synchronous CLI/scenario entrypoints."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def build_auth_headers(token: str | None) -> dict[str, str]:
    """Return Bearer header dict when an auth token is configured."""
    return {"Authorization": f"Bearer {token}"} if token else {}


def target_app_url(base_url: str, path: str = "/app", token: str | None = None) -> str:
    """Build a target URL for ControlBot Studio, appending `?token=` if configured."""
    clean_base = base_url.rstrip("/")
    clean_path = path if path.startswith("/") else f"/{path}"
    full = f"{clean_base}{clean_path}"
    if not token:
        return full
    parsed = urlparse(full)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["token"] = token
    return urlunparse(parsed._replace(query=urlencode(query)))


def ws_base_url(base_url: str) -> str:
    """Convert http(s):// base URL to ws(s)://."""
    parsed = urlparse(base_url.rstrip("/"))
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return urlunparse(parsed._replace(scheme=scheme, path="", params="", query="", fragment=""))


def safe_response_json(resp: httpx.Response, *, default: Any = None) -> Any:
    """Parse JSON from an `httpx.Response` without raising `JSONDecodeError`."""
    try:
        return resp.json()
    except (ValueError, json.JSONDecodeError):
        return {} if default is None else default


def safe_response_dict(resp: httpx.Response) -> dict[str, Any]:
    """Parse a JSON object from an `httpx.Response`, returning `{}` on non-JSON/error."""
    parsed = safe_response_json(resp, default={})
    return dict(parsed) if isinstance(parsed, dict) else {}


@dataclass(frozen=True)
class TargetCapabilities:
    """Live capability probe results for an isolated ControlBot Studio target."""

    health_ok: bool
    backend_mode: str
    runtime_mode: str
    model_id: str | None
    agy_available: bool
    projects_root: str | None
    effect_sim_url: str | None
    effect_sim_reachable: bool
    request_ids: tuple[str, ...]
    system_info: dict[str, Any] = field(default_factory=dict)

    @property
    def is_live_agent_target(self) -> bool:
        return self.agy_available or self.backend_mode == "local_http"


def probe_target_capabilities(
    target_url: str,
    *,
    token: str | None = None,
    timeout_s: float = 8.0,
) -> TargetCapabilities:
    """Probe /health, /api/system/info, /api/agy/models, /api/projects, and effect_sim."""
    headers = build_auth_headers(token)
    request_ids: list[str] = []
    health_ok = False
    backend_mode = "emulated"
    runtime_mode = "live_runtime"
    model_id: str | None = "emulated"
    agy_available = False
    projects_root: str | None = None
    effect_sim_url: str | None = None
    effect_sim_reachable = False
    sys_info: dict[str, Any] = {}

    with httpx.Client(
        base_url=target_url.rstrip("/"),
        headers=headers,
        timeout=timeout_s,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        with contextlib.suppress(httpx.HTTPError):
            r_health = client.get("/health")
            health_ok = r_health.status_code == 200
            if req_id := r_health.headers.get("X-Request-Id"):
                request_ids.append(req_id)

        with contextlib.suppress(httpx.HTTPError, ValueError):
            r_info = client.get("/api/system/info")
            if req_id := r_info.headers.get("X-Request-Id"):
                request_ids.append(req_id)
            if r_info.status_code == 200:
                payload = r_info.json()
                if isinstance(payload, dict):
                    sys_info = payload
                    backend_mode = str(payload.get("backend_mode") or backend_mode)
                    runtime_mode = str(payload.get("runtime_mode") or runtime_mode)
                    if payload.get("llm_model_id"):
                        model_id = str(payload["llm_model_id"])
                    facility = payload.get("facility")
                    if isinstance(facility, dict):
                        apps = facility.get("apps")
                        if isinstance(apps, list):
                            for app in apps:
                                if (
                                    isinstance(app, dict)
                                    and app.get("app_id") == "effect_sim"
                                    and isinstance(app.get("origin"), str)
                                ):
                                    effect_sim_url = str(app["origin"]).rstrip("/")
                                    break

        with contextlib.suppress(httpx.HTTPError, ValueError):
            r_agy = client.get("/api/agy/models")
            if req_id := r_agy.headers.get("X-Request-Id"):
                request_ids.append(req_id)
            if r_agy.status_code == 200:
                agy_json = r_agy.json()
                if isinstance(agy_json, dict):
                    agy_available = bool(agy_json.get("available", False))
                    if agy_available and agy_json.get("default_model"):
                        model_id = str(agy_json["default_model"])

        with contextlib.suppress(httpx.HTTPError, ValueError):
            r_proj = client.get("/api/projects")
            if req_id := r_proj.headers.get("X-Request-Id"):
                request_ids.append(req_id)
            if r_proj.status_code == 200:
                proj_json = r_proj.json()
                if isinstance(proj_json, dict) and isinstance(proj_json.get("projects_root"), str):
                    projects_root = str(proj_json["projects_root"])

    if effect_sim_url:
        with (
            contextlib.suppress(httpx.HTTPError),
            httpx.Client(timeout=3.0, trust_env=False) as ef_client,
        ):
            ef_health = ef_client.get(f"{effect_sim_url}/health")
            effect_sim_reachable = ef_health.status_code == 200

    return TargetCapabilities(
        health_ok=health_ok,
        backend_mode=backend_mode,
        runtime_mode=runtime_mode,
        model_id=model_id,
        agy_available=agy_available,
        projects_root=projects_root,
        effect_sim_url=effect_sim_url,
        effect_sim_reachable=effect_sim_reachable,
        request_ids=tuple(dict.fromkeys(request_ids)),
        system_info=sys_info,
    )


@dataclass(frozen=True)
class SseEventFrame:
    """Parsed Server-Sent Event frame from `/api/v1/events/stream`."""

    event_id: str | None
    event: str | None
    event_type: str | None
    data: Any


async def iter_sse_events(
    aclient: httpx.AsyncClient,
    *,
    last_event_id: str | None = None,
    query_last_event_id: str | None = None,
    timeout: float = 20.0,
    on_connected: asyncio.Event | None = None,
) -> AsyncIterator[SseEventFrame]:
    """Stream and parse SSE frames from `/api/v1/events/stream`."""
    headers: dict[str, str] = {}
    params: dict[str, str] = {}
    if last_event_id is not None:
        headers["Last-Event-ID"] = last_event_id
    if query_last_event_id is not None:
        params["last_event_id"] = query_last_event_id

    deadline = asyncio.get_running_loop().time() + timeout
    async with aclient.stream(
        "GET",
        "/api/v1/events/stream",
        headers=headers,
        params=params,
        timeout=httpx.Timeout(timeout, read=timeout),
    ) as resp:
        resp.raise_for_status()
        if on_connected is not None:
            on_connected.set()

        ev_id: str | None = None
        ev_name: str | None = None
        data_lines: list[str] = []

        async for raw_line in resp.aiter_lines():
            if asyncio.get_running_loop().time() > deadline:
                break
            line = raw_line.rstrip("\r")
            if line == "":
                if data_lines or ev_name or ev_id:
                    raw_payload = "\n".join(data_lines)
                    parsed: Any = raw_payload
                    if raw_payload:
                        with contextlib.suppress(json.JSONDecodeError):
                            parsed = json.loads(raw_payload)
                    ev_type = parsed.get("type") if isinstance(parsed, dict) else ev_name
                    yield SseEventFrame(
                        event_id=ev_id,
                        event=ev_name,
                        event_type=str(ev_type) if ev_type is not None else ev_name,
                        data=parsed,
                    )
                ev_id = None
                ev_name = None
                data_lines = []
                continue
            if line.startswith(":"):
                continue
            if line.startswith("id:"):
                ev_id = line[3:].strip()
            elif line.startswith("event:"):
                ev_name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())


@dataclass
class TurnOutcome:
    """Result of posting a thread message and awaiting SSE turn completion."""

    turn_id: str
    user_message: dict[str, Any]
    assistant_messages: list[dict[str, Any]]
    events: list[SseEventFrame]
    presence_states: list[str]
    handoffs: list[dict[str, Any]]
    approvals: list[dict[str, Any]]

    @property
    def assistant_message(self) -> dict[str, Any] | None:
        return self.assistant_messages[-1] if self.assistant_messages else None

    @property
    def reply_text(self) -> str:
        if not self.assistant_messages:
            return ""
        return str(self.assistant_messages[-1].get("content") or "")


async def trigger_and_wait_turn(
    aclient: httpx.AsyncClient,
    thread_id: str,
    content: str,
    *,
    timeout: float = 30.0,
    expected_bots: int = 1,
    idle_drain_timeout: float = 1.0,
) -> TurnOutcome:
    """Send a chat turn and await terminal SSE events (briefly draining trailing idle)."""
    frames: list[SseEventFrame] = []
    connected = asyncio.Event()
    turn_ready = asyncio.Event()
    completed_ev = asyncio.Event()
    idle_ev = asyncio.Event()
    turn_holder: dict[str, str] = {}
    completed_bots: set[str] = set()
    approvals: list[dict[str, Any]] = []
    handoffs: list[dict[str, Any]] = []
    presence_states: list[str] = []
    saw_completed = False

    async def _listen() -> None:
        nonlocal saw_completed
        async for frame in iter_sse_events(aclient, timeout=timeout, on_connected=connected):
            frames.append(frame)
            if not turn_ready.is_set():
                await turn_ready.wait()
            t_id = turn_holder["turn_id"]
            data = frame.data if isinstance(frame.data, dict) else {}
            if data.get("thread_id") != thread_id:
                continue
            ev = frame.event_type or frame.event
            if data.get("turn_id") not in (None, t_id):
                continue
            if ev == "bot.presence":
                st = data.get("payload", {}).get("state")
                if isinstance(st, str):
                    presence_states.append(st)
                    if saw_completed and st == "idle":
                        idle_ev.set()
                        return
            elif ev == "handoff.dispatched":
                payload = data.get("payload")
                if isinstance(payload, dict):
                    handoffs.append(payload)
            elif ev == "hitl.approval.requested":
                appr = data.get("payload", {}).get("approval")
                if isinstance(appr, dict):
                    approvals.append(appr)
                completed_ev.set()
                return
            elif ev == "message.completed" and data.get("turn_id") == t_id:
                msg = data.get("payload", {}).get("message", {})
                bot_id = str(msg.get("sender_bot_id") or f"anon_{len(completed_bots)}")
                completed_bots.add(bot_id)
                if len(completed_bots) >= expected_bots:
                    saw_completed = True
                    completed_ev.set()
                    if "idle" in presence_states or idle_drain_timeout <= 0:
                        idle_ev.set()
                        return

    listen_task = asyncio.create_task(_listen())
    try:
        await asyncio.wait_for(connected.wait(), timeout=8.0)
        resp = await aclient.post(
            f"/api/v1/threads/{thread_id}/messages",
            json={"content": content},
        )
        resp.raise_for_status()
        body = safe_response_dict(resp)
        turn_id = str(body["turn_id"])
        user_msg = dict(body["user_message"])
        turn_holder["turn_id"] = turn_id
        turn_ready.set()
        await asyncio.wait_for(completed_ev.wait(), timeout=timeout)
        if not approvals and not idle_ev.is_set() and idle_drain_timeout > 0:
            with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
                await asyncio.wait_for(idle_ev.wait(), timeout=idle_drain_timeout)
    finally:
        turn_ready.set()
        if not listen_task.done():
            listen_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await listen_task

    msgs_resp = await aclient.get(f"/api/v1/threads/{thread_id}/messages")
    msgs_resp.raise_for_status()
    all_msgs = safe_response_dict(msgs_resp).get("messages", [])
    user_id = str(user_msg.get("id") or "")
    after_user = False
    assistant_msgs: list[dict[str, Any]] = []
    for msg in all_msgs:
        if str(msg.get("id")) == user_id:
            after_user = True
            continue
        if after_user and msg.get("sender_type") == "bot":
            assistant_msgs.append(dict(msg))

    return TurnOutcome(
        turn_id=turn_id,
        user_message=user_msg,
        assistant_messages=assistant_msgs,
        events=frames,
        presence_states=presence_states,
        handoffs=handoffs,
        approvals=approvals,
    )


class VncSafePlaywrightSession:
    """Playwright Chromium session with HTTP route guard + WS observer (no route_web_socket)."""

    def __init__(self, *, headless: bool = True, viewport: dict[str, int] | None = None) -> None:
        self.headless = headless
        self.viewport = viewport or {"width": 1280, "height": 800}
        self.console_errors: list[str] = []
        self.page_errors: list[str] = []
        self.http_errors: list[tuple[int, str]] = []
        self.external_requests: list[str] = []
        self._pw_cm: Any = None
        self._pw: Any = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._temp_dir: Path | None = None

    @property
    def page(self) -> Page:
        if self._page is None:
            raise RuntimeError("VncSafePlaywrightSession not entered.")
        return self._page

    async def __aenter__(self) -> VncSafePlaywrightSession:
        self._temp_dir = Path(tempfile.mkdtemp(prefix="cb_qa_vnc_pw_"))
        self._pw_cm = async_playwright()
        self._pw = await self._pw_cm.__aenter__()
        self._context = await self._pw.chromium.launch_persistent_context(
            user_data_dir=str(self._temp_dir),
            headless=self.headless,
            viewport={"width": self.viewport["width"], "height": self.viewport["height"]},
        )

        async def _route_handler(route: Route) -> None:
            req_url = route.request.url
            if _is_allowed_browser_url(req_url):
                await route.continue_()
            else:
                self.external_requests.append(_scrub_url_strict(req_url))
                await route.abort()

        await self._context.route("**/*", _route_handler)
        existing_pages = self._context.pages
        self._page = existing_pages[0] if existing_pages else await self._context.new_page()

        def _on_console(msg: ConsoleMessage) -> None:
            if msg.type == "error":
                self.console_errors.append(msg.text)

        def _on_pageerror(exc: Exception) -> None:
            self.page_errors.append(repr(exc))

        def _on_response(resp: Response) -> None:
            if resp.status >= 400:
                self.http_errors.append((resp.status, _scrub_url_strict(resp.url)))

        def _on_ws(ws: WebSocket) -> None:
            if not _is_allowed_browser_url(ws.url):
                self.external_requests.append(_scrub_url_strict(ws.url))

        self._page.on("console", _on_console)
        self._page.on("pageerror", _on_pageerror)
        self._page.on("response", _on_response)
        self._page.on("websocket", _on_ws)
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._context is not None:
            with contextlib.suppress(Exception):
                await self._context.unroute_all(behavior="ignoreErrors")
        if self._page is not None:
            with contextlib.suppress(Exception):
                await self._page.close()
            self._page = None
        if self._context is not None:
            with contextlib.suppress(Exception):
                await self._context.close()
            self._context = None
        if self._pw_cm is not None:
            with contextlib.suppress(Exception):
                await self._pw_cm.__aexit__(None, None, None)
            self._pw_cm = None
            self._pw = None
        if self._temp_dir is not None:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None


@contextlib.asynccontextmanager
async def open_browser_session(
    *,
    vnc_safe: bool = False,
) -> AsyncIterator[StrictPlaywrightSession | VncSafePlaywrightSession]:
    """Open an isolated Chromium Playwright session (strict or VNC-safe)."""
    if vnc_safe:
        async with VncSafePlaywrightSession() as session:
            yield session
    else:
        async with StrictPlaywrightSession() as session:
            yield session


def compute_build_hash(campaign_dir: Path, state: CampaignState) -> str:
    """Compute build hash matching `cli.py` baseline asset hash semantics."""
    baseline_path = campaign_dir / "baseline.json"
    if baseline_path.is_file():
        with contextlib.suppress(Exception):
            baseline = BaselineReport.model_validate_json(
                baseline_path.read_text(encoding="utf-8")
            )
            if baseline.asset_hashes:
                return hashlib.sha256(
                    json.dumps(baseline.asset_hashes, sort_keys=True).encode("utf-8")
                ).hexdigest()[:16]
    return state.base_sha[:12]


def _load_matching_reference_cards(
    *,
    case_id: str,
    campaign_dir: Path,
    repo_root: Path | None,
    provided_cards: Sequence[ReferenceBehaviorCard],
) -> list[ReferenceBehaviorCard]:
    cards = list(provided_cards)
    if not cards:
        camp_ref = campaign_dir / "reference_cards"
        if camp_ref.is_dir():
            with contextlib.suppress(Exception):
                cards.extend(load_reference_cards(camp_ref, strict=False))
        if not cards and repo_root is not None:
            repo_ref = repo_root / "var" / "qa_campaigns" / "reference_cards"
            if repo_ref.is_dir():
                with contextlib.suppress(Exception):
                    cards.extend(load_reference_cards(repo_ref, strict=False))
    return [c for c in cards if c.case_id == case_id]


def append_ux_metrics(
    *,
    campaign_dir: Path,
    campaign_id: str,
    flow: UxFlowMetrics,
    repo_root: Path | None = None,
) -> Path:
    """Merge a `UxFlowMetrics` entry into `campaign_dir/ux_metrics.json` atomically."""
    ux_path = assert_safe_mutation_path(campaign_dir / "ux_metrics.json", repo_root=repo_root)
    existing_flows: list[UxFlowMetrics] = []
    if ux_path.is_file():
        with contextlib.suppress(Exception):
            prev = UxMetricReport.model_validate_json(ux_path.read_text(encoding="utf-8"))
            existing_flows = [f for f in prev.flows if f.run_id != flow.run_id]
    existing_flows.append(flow)
    return save_ux_metrics(
        existing_flows,
        ux_path,
        campaign_id=campaign_id,
        repo_root=repo_root,
    )


def build_blocked_run_record(
    *,
    case_id: str,
    campaign_dir: Path,
    state: CampaignState,
    blocked_reason: str,
    repo_root: Path | None = None,
    fixture_version: str = "1.0",
    assertions: dict[str, bool] | None = None,
    extra_artifacts: Sequence[str] = (),
    subsystem: str = "scenario",
) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Build a failed/blocked RunRecord (never stub-passing) when prerequisites are absent."""
    now = utc_now()
    run_id = f"run-{case_id.lower()}-{uuid.uuid4().hex[:8]}"
    resolved_assertions = dict(assertions or {"target_url_configured": False})
    resolved_assertions.setdefault("scenario_runner_available", True)
    build_hash = compute_build_hash(campaign_dir, state)
    artifacts = list(dict.fromkeys([str(p) for p in extra_artifacts if str(p).strip()]))

    rec = RunRecord(
        campaign_id=state.campaign_id,
        case_id=case_id,
        run_id=run_id,
        base_sha=state.base_sha,
        candidate_sha=state.last_accepted_sha,
        build_hash=build_hash,
        lane=state.lane,
        profile="default",
        ui_variant="react_dist",
        backend_mode="emulated",
        runtime_mode="live_runtime",
        model_id="emulated",
        emulated=True,
        real_services=[],
        simulated_services=["emulated_runtime"],
        fixture_version=fixture_version,
        browser="none",
        started_at=now,
        finished_at=now,
        duration_ms=0.05,
        request_ids=[],
        passed=False,
        assertions=resolved_assertions,
        artifact_paths=artifacts,
        error_summary=blocked_reason,
        blocked_reason=blocked_reason,
    )
    findings = [
        {
            "subsystem": subsystem,
            "raw_signature": f"{case_id}_blocked",
            "severity": "P1",
            "summary": blocked_reason,
        }
    ]
    return rec, findings


@dataclass
class ScenarioContext:
    """Execution context passed to each CB-00..CB-10 scenario runner."""

    case_id: str
    campaign_dir: Path
    state: CampaignState
    target_url: str
    token: str | None
    repo_root: Path | None
    caps: TargetCapabilities
    extra_artifacts: tuple[str, ...]
    reference_cards: tuple[ReferenceBehaviorCard, ...]
    run_id: str
    started_at: datetime
    t0: float
    build_hash: str
    assertions: dict[str, bool] = field(default_factory=dict)
    request_ids: list[str] = field(default_factory=list)
    screenshots: list[ScreenshotCheckpoint] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    simulated_services: list[str] = field(default_factory=list)
    real_services: list[str] = field(default_factory=lambda: ["controlbot_studio"])
    thread_id: str | None = None
    message_id: str | None = None
    action_id: str | None = None
    browser_name: str = "http_and_playwright"
    fixture_version: str = "1.0"
    subsystem: str = "e2e"
    error_notes: list[str] = field(default_factory=list)
    actions_to_reach: int = 1
    ttfp_ms: float | None = None
    completion_ms: float | None = None
    cancel_available: bool = False
    focus_predictable: bool = True
    local_remote_visible: bool = True
    local_remote_location: str = "top_header"
    composer_intact: bool = True
    response_persisted: bool | None = None
    error_actionable: bool | None = None
    clarity_notes: str = ""
    reference_matches_fixture: bool | None = None

    @classmethod
    def create(
        cls,
        *,
        case_id: str,
        campaign_dir: Path,
        state: CampaignState,
        target_url: str,
        token: str | None,
        repo_root: Path | None,
        caps: TargetCapabilities,
        extra_artifacts: Sequence[str] = (),
        reference_cards: Sequence[ReferenceBehaviorCard] = (),
        subsystem: str = "e2e",
    ) -> ScenarioContext:
        assert_not_live_target(target_url, allow_readonly=False)
        run_id = f"run-{case_id.lower()}-{uuid.uuid4().hex[:8]}"
        started_at = utc_now()
        t0 = time.monotonic()
        sim: list[str] = []
        if caps.backend_mode in {"emulated", "stub"}:
            sim.append("emulated_runtime")
        if not caps.is_live_agent_target:
            sim.append("deterministic_fixture_harness")
        real = ["controlbot_studio"]
        if caps.agy_available:
            real.append("agy_cli")
        if caps.effect_sim_reachable:
            real.append("effect_sim")
        return cls(
            case_id=case_id,
            campaign_dir=campaign_dir,
            state=state,
            target_url=target_url.rstrip("/"),
            token=token,
            repo_root=repo_root,
            caps=caps,
            extra_artifacts=tuple(extra_artifacts),
            reference_cards=tuple(reference_cards),
            run_id=run_id,
            started_at=started_at,
            t0=t0,
            build_hash=compute_build_hash(campaign_dir, state),
            request_ids=list(caps.request_ids),
            simulated_services=sim,
            real_services=real,
            subsystem=subsystem,
        )

    def add_request_id(self, resp: httpx.Response | None) -> None:
        if resp is None:
            return
        req_id = resp.headers.get("X-Request-Id")
        if req_id and req_id not in self.request_ids:
            self.request_ids.append(req_id)

    def sync_client(self, *, timeout: float = 15.0) -> httpx.Client:
        return httpx.Client(
            base_url=self.target_url,
            headers=build_auth_headers(self.token),
            timeout=timeout,
            trust_env=False,
            follow_redirects=False,
        )

    def async_client(self, *, timeout: float = 20.0) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.target_url,
            headers=build_auth_headers(self.token),
            timeout=timeout,
            trust_env=False,
            follow_redirects=False,
        )

    def app_url(self, path: str = "/app") -> str:
        return target_app_url(self.target_url, path=path, token=self.token)

    def isolated_work_dir(self) -> Path:
        safe_camp = assert_safe_mutation_path(self.campaign_dir, repo_root=self.repo_root)
        work_dir = safe_camp / "work" / f"{self.case_id.lower()}_{self.run_id}"
        work_dir.mkdir(parents=True, exist_ok=True)
        return work_dir

    async def capture_shot(
        self,
        page: Page,
        label: str,
        *,
        is_error_state: bool = False,
    ) -> ScreenshotCheckpoint:
        shot = await capture_screenshot_checkpoint(
            page,
            output_dir=self.campaign_dir,
            case_id=self.case_id,
            label=label,
            is_error_state=is_error_state,
            repo_root=self.repo_root,
        )
        self.screenshots.append(shot)
        return shot


def finalize_scenario(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Compare against reference cards, save UX metrics & redacted evidence, and build RunRecord."""
    finished_at = utc_now()
    duration_ms = round(max(0.01, (time.monotonic() - ctx.t0) * 1000.0), 3)
    passed = bool(ctx.assertions) and all(ctx.assertions.values()) and not ctx.error_notes
    failed_keys = [k for k, v in ctx.assertions.items() if not v]

    error_summary: str | None = None
    if not passed:
        parts: list[str] = []
        if failed_keys:
            parts.append(f"Failed assertions: {', '.join(failed_keys)}")
        parts.extend(ctx.error_notes)
        error_summary = "; ".join(parts) or f"{ctx.case_id} scenario failed."

    matching_cards = _load_matching_reference_cards(
        case_id=ctx.case_id,
        campaign_dir=ctx.campaign_dir,
        repo_root=ctx.repo_root,
        provided_cards=ctx.reference_cards,
    )
    comparisons = [
        compare_against_fixture_truth(
            card=card,
            fixture_passed=passed,
            fixture_detail=error_summary or ctx.clarity_notes or f"{ctx.case_id} passed",
            reference_matches_fixture=ctx.reference_matches_fixture,
        )
        for card in matching_cards
    ]

    ux_flow = UxFlowMetrics(
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        actions_to_reach=ctx.actions_to_reach,
        error_actionable=ctx.error_actionable,
        ttfp_ms=ctx.ttfp_ms if ctx.ttfp_ms is not None else duration_ms,
        completion_ms=ctx.completion_ms if ctx.completion_ms is not None else duration_ms,
        focus_predictable=ctx.focus_predictable,
        cancel_available=ctx.cancel_available,
        local_remote_indicator_visible=ctx.local_remote_visible,
        local_remote_location=ctx.local_remote_location,
        response_persisted_on_reload=ctx.response_persisted,
        result_clarity_notes=ctx.clarity_notes or (error_summary or f"{ctx.case_id} verified"),
        composer_layout_intact=ctx.composer_intact,
        screenshots=ctx.screenshots,
    )
    ux_path = append_ux_metrics(
        campaign_dir=ctx.campaign_dir,
        campaign_id=ctx.state.campaign_id,
        flow=ux_flow,
        repo_root=ctx.repo_root,
    )

    safe_camp = assert_safe_mutation_path(ctx.campaign_dir, repo_root=ctx.repo_root)
    artifacts_dir = safe_camp / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = artifacts_dir / f"{ctx.run_id}.json"
    raw_evidence = {
        "campaign_id": ctx.state.campaign_id,
        "case_id": ctx.case_id,
        "run_id": ctx.run_id,
        "passed": passed,
        "assertions": ctx.assertions,
        "fixture_version": ctx.fixture_version,
        "reference_comparisons": comparisons,
        "evidence": ctx.evidence,
        "ux_metrics_path": str(ux_path),
    }
    redacted_evidence = redact_payload_m3(raw_evidence)
    assert_strictly_redacted(redacted_evidence)
    if contains_unredacted_secret_m3(redacted_evidence):
        raise ValueError(f"Unredacted secret detected in {ctx.case_id} evidence payload.")
    evidence_path.write_text(
        json.dumps(redacted_evidence, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    artifact_paths: list[str] = list(
        dict.fromkeys(
            [
                *[str(p) for p in ctx.extra_artifacts if str(p).strip()],
                *[s.path for s in ctx.screenshots],
                str(evidence_path),
                str(ux_path),
            ]
        )
    )

    emulated = ctx.caps.backend_mode in {"emulated", "stub"} or (
        not ctx.caps.is_live_agent_target
    )
    rec = RunRecord(
        campaign_id=ctx.state.campaign_id,
        case_id=ctx.case_id,
        run_id=ctx.run_id,
        base_sha=ctx.state.base_sha,
        candidate_sha=ctx.state.last_accepted_sha,
        build_hash=ctx.build_hash,
        lane=ctx.state.lane,
        profile="default",
        ui_variant="react_dist",
        backend_mode=ctx.caps.backend_mode,
        runtime_mode=ctx.caps.runtime_mode,
        model_id=ctx.caps.model_id,
        emulated=emulated,
        real_services=list(dict.fromkeys(ctx.real_services)),
        simulated_services=list(dict.fromkeys(ctx.simulated_services)),
        fixture_version=ctx.fixture_version,
        browser=ctx.browser_name,
        started_at=ctx.started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
        thread_id=ctx.thread_id,
        message_id=ctx.message_id,
        action_id=ctx.action_id,
        request_ids=list(dict.fromkeys(ctx.request_ids)),
        passed=passed,
        assertions=ctx.assertions,
        artifact_paths=artifact_paths,
        error_summary=error_summary,
        blocked_reason=None if passed else error_summary,
    )

    findings: list[dict[str, Any]] = []
    if not passed:
        if failed_keys:
            for key in failed_keys:
                findings.append(
                    {
                        "subsystem": ctx.subsystem,
                        "raw_signature": f"{ctx.case_id}_{key}",
                        "severity": "P1",
                        "summary": error_summary or f"{ctx.case_id} assertion {key!r} failed.",
                    }
                )
        else:
            findings.append(
                {
                    "subsystem": ctx.subsystem,
                    "raw_signature": f"{ctx.case_id}_failure",
                    "severity": "P1",
                    "summary": error_summary or f"{ctx.case_id} scenario failed.",
                }
            )
    return rec, findings


async def fetch_project_tree_http(
    aclient: httpx.AsyncClient,
    *,
    project_rel_root: str,
    dest_dir: Path,
    project_name: str = "Grokbotclon",
    vm_id: str = "default",
) -> list[str]:
    """Recursively download files from Studio `/api/v1/computers/{vm_id}/files` into `dest_dir`."""
    downloaded: list[str] = []
    resolved_dest = dest_dir.resolve()

    async def _walk(rel_dir: str, rel_out_prefix: str) -> None:
        resp = await aclient.get(
            f"/api/v1/computers/{vm_id}/files",
            params={"path": rel_dir, "project": project_name},
        )
        if resp.status_code != 200:
            return
        entries = safe_response_dict(resp).get("entries", [])
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            entry_rel = str(entry.get("rel_path") or "")
            name = str(entry.get("name") or "")
            if not entry_rel or not name:
                continue
            if name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
                raise IsolationBoundaryError(
                    f"Refusing fetch_project_tree_http for unsafe entry name: {name!r}"
                )
            sub_out = f"{rel_out_prefix}/{name}" if rel_out_prefix else name
            sub_parts = Path(sub_out).parts
            if (
                not sub_parts
                or "." in sub_parts
                or ".." in sub_parts
                or "\\" in sub_out
                or "\x00" in sub_out
                or Path(sub_out).is_absolute()
            ):
                raise IsolationBoundaryError(
                    f"Refusing fetch_project_tree_http for unsafe relative path: {sub_out!r}"
                )
            target = (dest_dir / sub_out).resolve()
            if target == resolved_dest or not target.is_relative_to(resolved_dest):
                raise IsolationBoundaryError(
                    f"Refusing fetch_project_tree_http path escape outside {resolved_dest}: "
                    f"{target}"
                )
            if entry.get("is_dir"):
                await _walk(entry_rel, sub_out)
            else:
                file_resp = await aclient.get(
                    f"/api/v1/computers/{vm_id}/file",
                    params={"path": entry_rel, "project": project_name},
                )
                if file_resp.status_code == 200:
                    content = safe_response_dict(file_resp).get("content")
                    if isinstance(content, str):
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(content, encoding="utf-8")
                        downloaded.append(sub_out)

    await _walk(project_rel_root.strip("/"), "")
    return downloaded


_ALLOWED_SCENARIO_SUBPATHS: frozenset[str] = frozenset({"cb09_proj", "cb10_summary_pkg"})


class ProjectsRootUnavailableError(IsolationBoundaryError):
    """Raised when GET /api/projects cannot supply a valid projects_root."""


async def cleanup_project_subpath_http(
    aclient: httpx.AsyncClient,
    *,
    project_rel_root: str,
    project_name: str = "Grokbotclon",
    vm_id: str = "default",
    repo_root: Path | None = None,
) -> list[str]:
    """Recursively delete files and dirs under a dedicated scenario subpath via Studio API."""
    if not isinstance(project_rel_root, str):
        raise ValueError(
            f"Refusing HTTP cleanup for non-scenario subpath: {project_rel_root!r}"
        )
    cleaned_root = project_rel_root.strip().strip("/")
    if cleaned_root not in _ALLOWED_SCENARIO_SUBPATHS:
        raise ValueError(
            f"Refusing HTTP cleanup for non-scenario subpath: {project_rel_root!r}"
        )

    if not isinstance(project_name, str):
        raise ValueError(f"Refusing HTTP cleanup for unsafe project_name: {project_name!r}")
    cleaned_project = project_name.strip()
    if (
        not cleaned_project
        or cleaned_project in {".", ".."}
        or cleaned_project.startswith(".")
        or "/" in cleaned_project
        or "\\" in cleaned_project
        or "\x00" in cleaned_project
    ):
        raise ValueError(f"Refusing HTTP cleanup for unsafe project_name: {project_name!r}")

    base_url_str = str(aclient.base_url).strip()
    if base_url_str:
        assert_not_live_target(base_url_str, allow_readonly=False)

    try:
        proj_resp = await aclient.get("/api/projects")
    except httpx.HTTPError as exc:
        raise ProjectsRootUnavailableError(
            f"Refusing HTTP cleanup: GET /api/projects failed ({type(exc).__name__}: {exc})."
        ) from exc
    if proj_resp.status_code != 200:
        raise ProjectsRootUnavailableError(
            f"Refusing HTTP cleanup: GET /api/projects returned HTTP {proj_resp.status_code}."
        )
    try:
        proj_payload = proj_resp.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise ProjectsRootUnavailableError(
            f"Refusing HTTP cleanup: GET /api/projects returned invalid JSON: {exc}"
        ) from exc
    if not isinstance(proj_payload, dict):
        raise ProjectsRootUnavailableError(
            "Refusing HTTP cleanup: GET /api/projects did not return a JSON object."
        )
    projects_root_raw = proj_payload.get("projects_root")
    if not isinstance(projects_root_raw, str) or not projects_root_raw.strip():
        raise ProjectsRootUnavailableError(
            "Refusing HTTP cleanup: GET /api/projects missing non-empty 'projects_root'."
        )

    raw_root_path = Path(projects_root_raw.strip()).expanduser()
    if not raw_root_path.is_absolute():
        raise IsolationBoundaryError(
            f"Refusing HTTP cleanup: non-absolute projects_root {projects_root_raw!r}"
        )

    projects_root_path = raw_root_path.resolve()
    project_dir = (projects_root_path / cleaned_project).resolve()
    if project_dir == projects_root_path or not project_dir.is_relative_to(projects_root_path):
        raise IsolationBoundaryError(
            f"Refusing HTTP cleanup: project directory {project_dir} escapes {projects_root_path}"
        )

    real_repo = _REPO_ROOT.resolve()
    if (
        _is_under(projects_root_path, real_repo)
        or _is_under(project_dir, real_repo)
        or _is_under(real_repo, project_dir)
    ):
        raise IsolationBoundaryError(
            f"Refusing HTTP cleanup inside real source repository: {project_dir}"
        )

    protected_host_roots = (_HOST_HOME, (_HOST_HOME / "Projects").resolve(), Path("/"))
    if projects_root_path in protected_host_roots or project_dir in protected_host_roots:
        raise IsolationBoundaryError(
            f"Refusing HTTP cleanup inside protected host directory: {project_dir}"
        )

    if repo_root is not None:
        resolved_caller_repo = repo_root.resolve()
        is_git_repo = (resolved_caller_repo / ".git").exists()
        if (
            projects_root_path == resolved_caller_repo
            or project_dir == resolved_caller_repo
            or _is_under(resolved_caller_repo, project_dir)
            or (
                is_git_repo
                and (
                    _is_under(projects_root_path, resolved_caller_repo)
                    or _is_under(project_dir, resolved_caller_repo)
                )
            )
        ):
            raise IsolationBoundaryError(
                f"Refusing HTTP cleanup inside repository root {resolved_caller_repo}: "
                f"{project_dir}"
            )

    target_subpath = (project_dir / cleaned_root).resolve()
    if target_subpath == project_dir or not target_subpath.is_relative_to(project_dir):
        raise IsolationBoundaryError(
            f"Refusing HTTP cleanup: target subpath {target_subpath} escapes {project_dir}"
        )
    assert_safe_mutation_path(target_subpath, repo_root=repo_root)

    files_to_delete: list[str] = []
    dirs_to_delete: list[str] = []

    async def _collect(rel_dir: str) -> None:
        resp = await aclient.get(
            f"/api/v1/computers/{vm_id}/files",
            params={"path": rel_dir, "project": cleaned_project},
        )
        if resp.status_code != 200:
            return
        entries = safe_response_dict(resp).get("entries", [])
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            entry_rel = str(entry.get("rel_path") or "").strip("/")
            if not entry_rel:
                continue
            if "\\" in entry_rel or "\x00" in entry_rel or ".." in Path(entry_rel).parts:
                continue
            if entry_rel != cleaned_root and not entry_rel.startswith(f"{cleaned_root}/"):
                continue
            if entry.get("is_dir"):
                await _collect(entry_rel)
                dirs_to_delete.append(entry_rel)
            else:
                files_to_delete.append(entry_rel)

    await _collect(cleaned_root)
    deleted: list[str] = []
    for rel_path in [*files_to_delete, *dirs_to_delete, cleaned_root]:
        del_resp = await aclient.delete(
            f"/api/v1/computers/{vm_id}/files",
            params={"path": rel_path, "project": cleaned_project},
        )
        if del_resp.status_code in {200, 204}:
            deleted.append(rel_path)
        elif del_resp.status_code == 404:
            continue
    return deleted


def is_valid_png_screenshot(path: Path) -> bool:
    return path.is_file() and path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")


def repo_root_fallback(repo_root: Path | None) -> Path:
    return (repo_root or _REPO_ROOT).resolve()


class _NoSignalUvicornServer(uvicorn.Server):
    """Uvicorn server subclass for background-thread ephemeral lab servers."""

    def install_signal_handlers(self) -> None:
        return None


class _EphemeralLabStack:
    """Self-contained synthetic SCADA, Maintenance & EffectSim stack on ephemeral ports."""

    def __init__(
        self,
        *,
        fixture_mode: str = "default",
        scada_fixture_mode: str | None = None,
        maintenance_fixture_mode: str | None = None,
        host: str = "127.0.0.1",
    ) -> None:
        self.fixture_mode = fixture_mode
        self.scada_fixture_mode = scada_fixture_mode or fixture_mode
        self.maintenance_fixture_mode = maintenance_fixture_mode or fixture_mode
        self.host = host
        self.scada_port: int = 0
        self.maintenance_port: int = 0
        self.effect_sim_port: int = 0
        self.scada_state: ScadaState | None = None
        self.maintenance_state: MaintenanceState | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._servers: list[_NoSignalUvicornServer] = []
        self._ready = threading.Event()
        self._error: BaseException | None = None

    @property
    def scada_url(self) -> str:
        return f"http://{self.host}:{self.scada_port}"

    @property
    def maintenance_url(self) -> str:
        return f"http://{self.host}:{self.maintenance_port}"

    @property
    def effect_sim_url(self) -> str:
        return f"http://{self.host}:{self.effect_sim_port}"

    def env_vars(self) -> dict[str, str]:
        return {
            "GROKBOT_SCADA_URL": self.scada_url,
            "GROKBOT_MAINTENANCE_URL": self.maintenance_url,
            "GROKBOT_EFFECT_SIM_URL": self.effect_sim_url,
        }

    def start(self, timeout: float = 10.0) -> _EphemeralLabStack:
        if self._thread is not None and self._thread.is_alive():
            return self
        self._ready.clear()
        self._error = None
        self._thread = threading.Thread(
            target=self._run_thread,
            daemon=True,
            name="qa-ephemeral-lab-stack",
        )
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            self.stop()
            raise TimeoutError("Timed out starting ephemeral lab stack.")
        if self._error is not None:
            err = self._error
            self.stop()
            raise RuntimeError(f"Ephemeral lab stack failed to start: {err!r}") from err
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
        now_ref = utc_now()
        scada_app = create_scada_app(fixture_mode=self.scada_fixture_mode)
        maint_app = create_maintenance_app(fixture_mode=self.maintenance_fixture_mode)
        effect_app = create_effect_sim_app()
        scada_app.state.scada_state.set_reference_time(now_ref)
        maint_app.state.maintenance_state.set_reference_time(now_ref)
        self.scada_state = scada_app.state.scada_state
        self.maintenance_state = maint_app.state.maintenance_state

        sockets: list[socket.socket] = []
        used_ports: set[int] = set()
        tasks: list[asyncio.Task[None]] = []
        try:
            for app in (scada_app, maint_app, effect_app):
                port = alloc_ephemeral_port(self.host, exclude=used_ports)
                used_ports.add(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, port))
                sock.listen(128)
                sock.setblocking(False)
                sockets.append(sock)
                srv = _NoSignalUvicornServer(
                    uvicorn.Config(
                        app,
                        host=self.host,
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
                        exc = task.exception()
                        raise RuntimeError(f"Ephemeral lab server exited early: {exc!r}")
                    if asyncio.get_running_loop().time() >= deadline:
                        raise TimeoutError("Timed out waiting for ephemeral lab uvicorn server.")
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

    def __enter__(self) -> _EphemeralLabStack:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()


async def poll_task_terminal(
    aclient: httpx.AsyncClient, run_id: str, *, timeout: float = 25.0
) -> dict[str, Any]:
    """Poll `/api/tasks/{run_id}` until a terminal or waiting_for_input status."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        resp = await aclient.get(f"/api/tasks/{run_id}")
        resp.raise_for_status()
        snap = resp.json()
        if snap["run"]["status"] in {
            "succeeded",
            "partial",
            "failed",
            "cancelled",
            "waiting_for_input",
        }:
            return dict(snap)
        await asyncio.sleep(0.15)
    raise TimeoutError(f"Task {run_id} did not settle within {timeout}s")
