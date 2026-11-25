"""Unified M4 runtime wiring connecting Engine, Storage, Model, Adapters, and Web UI."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from src.adapters._common import (
    AdapterPermissionError,
    CredentialProvider,
    SourceUnavailableError,
)
from src.adapters.config import FacilityConfig
from src.adapters.effects import EffectSimAdapter, get_effect_tool_specs
from src.adapters.maintenance import MaintenanceAdapter, get_maintenance_tool_specs
from src.adapters.scada import ScadaAdapter, get_scada_tool_specs
from src.adapters.sessions import (
    AuthExpiredError,
    OriginNotAllowedError,
    SessionBusyError,
    SessionManager,
    SessionOwnershipError,
    SessionTakenOverError,
    make_session_id,
    validate_session_segment,
)
from src.adapters.verifier import Verifier
from src.contracts.common import InvalidStateTransitionError, PlanValidationError, utc_now
from src.contracts.enums import BackendMode, is_terminal_status
from src.contracts.models import Observation, Result, Run, TaskSpec, ToolSpec
from src.engine.coordinator import Coordinator, CoordinatorConfig, ResultVerifier
from src.engine.tool_registry import (
    AuthToolError,
    PermissionToolError,
    SemanticToolError,
    ToolExecutionContext,
    ToolRegistry,
    TransientToolError,
)
from src.model.emulator import EmulatedModelClient, EmulatedTurn
from src.model.http_client import LocalHttpModelClient, LocalModelConfig, build_model_client
from src.model.protocol import (
    BudgetRemaining,
    ModelClient,
    ModelDecision,
    ModelProtocolError,
    ModelToolCall,
    ModelUsage,
    PromptContext,
)
from src.storage.errors import NotFoundError
from src.storage.redaction import contains_unredacted_secret_strict, redact_payload_strict
from src.storage.repo import StorageRepo
from src.web.app import create_app
from src.web.protocols import TaskSnapshot, TransitionRecord


def _infer_asset_query(query: str, config: FacilityConfig) -> str:
    lower_q = query.lower()
    candidates: list[str] = []
    for asset in config.assets:
        candidates.append(asset.asset_id)
        candidates.append(asset.canonical_label)
        candidates.extend(asset.aliases)
        candidates.extend(asset.source_ids.values())
    for cand in sorted(set(candidates), key=len, reverse=True):
        if cand.lower() in lower_q:
            return cand
    if config.assets:
        return config.assets[0].canonical_label
    return query


def _session_id_for_tool(task_spec: TaskSpec, tool_id: str) -> str | None:
    if tool_id.startswith("scada."):
        return make_session_id(task_spec.user_id, task_spec.profile_id, "scada")
    if tool_id.startswith("maint."):
        return make_session_id(task_spec.user_id, task_spec.profile_id, "maintenance")
    return None


def _build_task_from_ctx(
    ctx: ToolExecutionContext,
    task_lookup: Callable[[str], TaskSpec] | None,
) -> TaskSpec:
    if task_lookup is not None:
        base_task = task_lookup(ctx.task_id)
        return base_task.model_copy(update={"scope": ctx.scope})
    user_id = "operator"
    profile_id = "default"
    if ctx.session_id and "__" in ctx.session_id:
        parts = ctx.session_id.split("__")
        if len(parts) >= 2:
            user_id, profile_id = parts[0], parts[1]
    return TaskSpec(
        task_id=ctx.task_id,
        user_id=user_id,
        profile_id=profile_id,
        scope=ctx.scope,
        query=f"Execute tool step {ctx.step_id}",
    )


def register_industrial_tools(
    registry: ToolRegistry,
    *,
    config: FacilityConfig,
    session_manager: SessionManager,
    credential_provider: CredentialProvider | None = None,
    effect_adapter: EffectSimAdapter | None = None,
    task_lookup: Callable[[str], TaskSpec] | None = None,
    replace: bool = False,
) -> None:
    """Register async SCADA, Maintenance, and optional EffectSim handlers on ToolRegistry."""
    scada_adapter = ScadaAdapter(session_manager, credential_provider)
    maint_adapter = MaintenanceAdapter(session_manager, credential_provider)

    if "scada" in config.apps:
        scada_origin = config.apps["scada"].origin
        scada_specs = get_scada_tool_specs((scada_origin,))

        async def _handle_scada_alarms(
            args: dict[str, Any],
            ctx: ToolExecutionContext,
        ) -> dict[str, Any]:
            task = _build_task_from_ctx(ctx, task_lookup)
            try:
                observations, receipt = await scada_adapter.read_alarms(
                    task=task,
                    config=config,
                    run_id=ctx.run_id,
                    step_id=ctx.step_id,
                    attempt=ctx.attempt,
                    operation_key=ctx.operation_key,
                    asset_query=args.get("asset"),
                    asset_id=args.get("asset_id"),
                    area=args.get("area"),
                )
            except AuthExpiredError as exc:
                raise AuthToolError(str(exc)) from exc
            except (
                AdapterPermissionError,
                OriginNotAllowedError,
                SessionTakenOverError,
                SessionOwnershipError,
            ) as exc:
                raise PermissionToolError(str(exc)) from exc
            except (SourceUnavailableError, SessionBusyError) as exc:
                raise TransientToolError(str(exc)) from exc

            return {
                "output": {
                    "source": "scada",
                    "count": len(observations),
                    "records": [o.model_dump(mode="json") for o in observations],
                },
                "observations": list(observations),
                "observed_before": receipt.observed_before,
                "observed_after": receipt.observed_after,
                "evidence_refs": list(receipt.evidence_refs),
            }

        async def _handle_scada_readings(
            args: dict[str, Any],
            ctx: ToolExecutionContext,
        ) -> dict[str, Any]:
            task = _build_task_from_ctx(ctx, task_lookup)
            try:
                observations, receipt = await scada_adapter.read_readings(
                    task=task,
                    config=config,
                    run_id=ctx.run_id,
                    step_id=ctx.step_id,
                    attempt=ctx.attempt,
                    operation_key=ctx.operation_key,
                    asset_query=args.get("asset"),
                    asset_id=args.get("asset_id"),
                    area=args.get("area"),
                )
            except AuthExpiredError as exc:
                raise AuthToolError(str(exc)) from exc
            except (
                AdapterPermissionError,
                OriginNotAllowedError,
                SessionTakenOverError,
                SessionOwnershipError,
            ) as exc:
                raise PermissionToolError(str(exc)) from exc
            except (SourceUnavailableError, SessionBusyError) as exc:
                raise TransientToolError(str(exc)) from exc

            return {
                "output": {
                    "source": "scada",
                    "count": len(observations),
                    "records": [o.model_dump(mode="json") for o in observations],
                },
                "observations": list(observations),
                "observed_before": receipt.observed_before,
                "observed_after": receipt.observed_after,
                "evidence_refs": list(receipt.evidence_refs),
            }

        registry.register(scada_specs["scada.read_alarms"], _handle_scada_alarms, replace=replace)
        registry.register(
            scada_specs["scada.read_readings"],
            _handle_scada_readings,
            replace=replace,
        )

    if "maintenance" in config.apps:
        maint_origin = config.apps["maintenance"].origin
        maint_specs = get_maintenance_tool_specs((maint_origin,))

        async def _handle_maint_work_orders(
            args: dict[str, Any],
            ctx: ToolExecutionContext,
        ) -> dict[str, Any]:
            task = _build_task_from_ctx(ctx, task_lookup)
            try:
                observations, receipt = await maint_adapter.read_work_orders(
                    task=task,
                    config=config,
                    run_id=ctx.run_id,
                    step_id=ctx.step_id,
                    attempt=ctx.attempt,
                    operation_key=ctx.operation_key,
                    asset_query=args.get("asset"),
                    asset_id=args.get("asset_id"),
                    area=args.get("area"),
                )
            except AuthExpiredError as exc:
                raise AuthToolError(str(exc)) from exc
            except (
                AdapterPermissionError,
                OriginNotAllowedError,
                SessionTakenOverError,
                SessionOwnershipError,
            ) as exc:
                raise PermissionToolError(str(exc)) from exc
            except (SourceUnavailableError, SessionBusyError) as exc:
                raise TransientToolError(str(exc)) from exc

            return {
                "output": {
                    "source": "maintenance",
                    "count": len(observations),
                    "records": [o.model_dump(mode="json") for o in observations],
                },
                "observations": list(observations),
                "observed_before": receipt.observed_before,
                "observed_after": receipt.observed_after,
                "evidence_refs": list(receipt.evidence_refs),
            }

        registry.register(
            maint_specs["maint.read_work_orders"],
            _handle_maint_work_orders,
            replace=replace,
        )

    if "effect_sim" in config.apps and effect_adapter is not None:
        effect_origin = config.apps["effect_sim"].origin
        effect_specs = get_effect_tool_specs((effect_origin,))

        async def _handle_effect_inspect(
            args: dict[str, Any],
            ctx: ToolExecutionContext,
        ) -> dict[str, Any]:
            task = _build_task_from_ctx(ctx, task_lookup)
            origin = ctx.target_origin or effect_origin
            try:
                state = await effect_adapter.inspect_state(
                    task=task,
                    origin=origin,
                    operation_key=args.get("operation_key"),
                )
            except OriginNotAllowedError as exc:
                raise PermissionToolError(str(exc)) from exc
            return {"output": state}

        async def _handle_effect_apply(
            args: dict[str, Any],
            ctx: ToolExecutionContext,
        ) -> dict[str, Any]:
            task = _build_task_from_ctx(ctx, task_lookup)
            origin = ctx.target_origin or effect_origin
            try:
                payload, receipt = await effect_adapter.apply_effect(
                    task=task,
                    origin=origin,
                    run_id=ctx.run_id,
                    step_id=ctx.step_id,
                    attempt=ctx.attempt,
                    operation_key=str(
                        ctx.idempotency_key or args.get("operation_key") or ctx.operation_key
                    ),
                    asset_id=str(args["asset_id"]),
                    action=str(args["action"]),
                    params=args.get("params") if isinstance(args.get("params"), dict) else None,
                    fail_after_apply=args.get("fail_after_apply", False),
                )
            except (AdapterPermissionError, OriginNotAllowedError) as exc:
                raise PermissionToolError(str(exc)) from exc

            if receipt.outcome.value == "unknown_needs_reconciliation":
                raise TimeoutError(receipt.error_detail or "effect_unknown_needs_reconciliation")
            if receipt.outcome.value == "failed_semantic":
                raise SemanticToolError(receipt.error_detail or "effect_apply_conflict")
            return {
                "output": payload or {},
                "observed_before": receipt.observed_before,
                "observed_after": receipt.observed_after,
                "evidence_refs": list(receipt.evidence_refs),
            }

        async def _effect_reconciler(
            op_key: str,
            idem_key: str,
            ctx: ToolExecutionContext,
        ) -> tuple[bool, dict[str, Any] | None]:
            task = _build_task_from_ctx(ctx, task_lookup)
            origin = ctx.target_origin or effect_origin
            state = await effect_adapter.inspect_state(
                task=task,
                origin=origin,
                operation_key=idem_key or op_key,
            )
            existing = state.get("effect")
            if isinstance(existing, dict):
                return True, existing
            return False, {"confirmed_unapplied": True}

        registry.register(
            effect_specs["effect.inspect_state"],
            _handle_effect_inspect,
            replace=replace,
        )
        registry.register(
            effect_specs["effect.apply"],
            _handle_effect_apply,
            reconciler=_effect_reconciler,
            supports_idempotency=True,
            replace=replace,
        )


def build_industrial_result_verifier(
    config: FacilityConfig,
    *,
    verifier: Verifier | None = None,
    reference_time_fn: Callable[[], datetime] | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> ResultVerifier:
    """Create a Coordinator result_verifier delegating synthesis to Verifier."""
    active_verifier = verifier or Verifier()

    def _verify(
        task_spec: TaskSpec,
        run_id: str,
        observations: tuple[Observation, ...],
        history: Sequence[dict[str, Any]],
        candidate: Result,
        last_human_input: dict[str, Any] | None,
    ) -> Result:
        industrial_tools_ran = any(
            isinstance(item, dict)
            and str(item.get("tool_id", "")).startswith(("scada.", "maint."))
            for item in history
        )
        if not observations and not industrial_tools_ran:
            return candidate

        source_errors: dict[str, str] = {}
        ok_sources = {obs.source for obs in observations}
        for item in history:
            if not isinstance(item, dict):
                continue
            tid = str(item.get("tool_id", ""))
            outcome = str(item.get("outcome", ""))
            if outcome in ("failed_transient", "failed_semantic", "failed_permission"):
                err_text = str(item.get("error") or outcome)
                if tid.startswith("scada.") and "scada" not in ok_sources:
                    source_errors["scada"] = err_text
                elif tid.startswith("maint.") and "maintenance" not in ok_sources:
                    source_errors["maintenance"] = err_text

        target_area: str | None = None
        if len(task_spec.scope.allowed_areas) == 1:
            target_area = task_spec.scope.allowed_areas[0]
        elif last_human_input:
            raw_area = last_human_input.get("area") or last_human_input.get("choice")
            if isinstance(raw_area, str) and raw_area.strip():
                target_area = raw_area.strip()

        filtered_obs = (
            tuple(obs for obs in observations if obs.area == target_area)
            if target_area is not None
            else observations
        )
        target_asset_query = _infer_asset_query(task_spec.query, config)
        ref_time = reference_time_fn() if reference_time_fn is not None else utc_now()

        return active_verifier.verify_and_synthesize(
            task=task_spec,
            config=config,
            observations=filtered_obs,
            source_errors=source_errors,
            run_id=run_id,
            target_asset_query=target_asset_query,
            target_area=target_area,
            window_start=window_start,
            window_end=window_end,
            reference_time=ref_time,
            metrics=candidate.execution_metrics,
        )

    return _verify


def make_industrial_turn_factory(
    config: FacilityConfig,
) -> Callable[[PromptContext, Sequence[ToolSpec], BudgetRemaining], EmulatedTurn]:
    """Deterministic multi-source Pump-34 turn factory for EmulatedModelClient."""

    def _turn_factory(
        prompt_ctx: PromptContext,
        tools: Sequence[ToolSpec],
        budget_remaining: BudgetRemaining,
    ) -> EmulatedTurn:
        del budget_remaining
        usage = ModelUsage(
            prompt_tokens=48,
            completion_tokens=24,
            total_tokens=72,
            usage_mode="actual",
        )
        tool_map = {t.tool_id: t for t in tools}
        called_tools = [
            str(item.get("tool_id"))
            for item in prompt_ctx.history
            if isinstance(item, dict) and item.get("tool_id")
        ]

        chosen_area: str | None = None
        if len(prompt_ctx.allowed_areas) == 1:
            chosen_area = prompt_ctx.allowed_areas[0]
        elif prompt_ctx.human_input:
            raw_area = prompt_ctx.human_input.get("area") or prompt_ctx.human_input.get("choice")
            if isinstance(raw_area, str) and raw_area.strip():
                chosen_area = raw_area.strip()

        asset_query = _infer_asset_query(prompt_ctx.query, config)
        plan_order = ("scada.read_alarms", "scada.read_readings", "maint.read_work_orders")
        for tool_id in plan_order:
            if tool_id in tool_map and tool_id not in called_tools:
                spec = tool_map[tool_id]
                args: dict[str, Any] = {"asset": asset_query}
                if chosen_area is not None:
                    args["area"] = chosen_area
                return EmulatedTurn(
                    decision=ModelDecision(
                        decision_type="tool_call",
                        tool_call=ModelToolCall(
                            tool_id=tool_id,
                            args=args,
                            target_origin=(
                                spec.allowed_origins[0] if spec.allowed_origins else None
                            ),
                            completion_verifier=spec.verifier_name,
                            rationale=f"Query {tool_id} for {asset_query}.",
                        ),
                        usage=usage,
                    )
                )

        return EmulatedTurn(
            decision=ModelDecision(
                decision_type="final",
                final_answer=(
                    f"Collected {len(prompt_ctx.observations)} observation(s) "
                    f"for {asset_query}."
                ),
                usage=usage,
            )
        )

    return _turn_factory


class RuntimeCoordinatorAdapter:
    """Adapter implementing web.protocols.CoordinatorProtocol over real Coordinator/Repo."""

    def __init__(
        self,
        *,
        repo: StorageRepo,
        coordinator: Coordinator,
        facility_config: FacilityConfig | None = None,
        auto_run: bool = True,
    ) -> None:
        self._repo = repo
        self._coordinator = coordinator
        self._facility_config = facility_config
        self._auto_run = auto_run
        self._bg_tasks: dict[str, asyncio.Task[Result]] = {}

    @property
    def coordinator(self) -> Coordinator:
        return self._coordinator

    def _emit_trace_if_enabled(self, run_id: str) -> None:
        if os.environ.get("GROKBOT_TRACING_ENABLED", "").strip().lower() not in {
            "1",
            "true",
            "yes",
            "on",
        }:
            return
        raw_dir = os.environ.get("GROKBOT_TRACE_DIR", "").strip()
        if not raw_dir:
            return
        snap = self.get_task_snapshot(run_id)
        if snap is None:
            return
        trace_dir = Path(raw_dir)
        trace_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "run_id": run_id,
            "tracing_enabled": True,
            "deploy_config": os.environ.get("GROKBOT_DEPLOY_CONFIG", "").strip() or None,
            "status": snap.run.status.value,
            "run": snap.run.model_dump(mode="json"),
            "task": snap.task.model_dump(mode="json"),
            "transitions": [
                {
                    "from_status": t.from_status.value if t.from_status is not None else None,
                    "to_status": t.to_status.value,
                    "reason": t.reason,
                    "timestamp": t.timestamp.isoformat(),
                }
                for t in snap.transitions
            ],
            "receipts": [r.model_dump(mode="json") for r in snap.receipts],
            "result": snap.result.model_dump(mode="json") if snap.result is not None else None,
        }
        scrubbed = redact_payload_strict(payload)
        if contains_unredacted_secret_strict(scrubbed):
            raise ValueError("Trace serialization failed redaction check.")

        def _pad_auth(val: Any) -> Any:
            if isinstance(val, dict):
                return {k: _pad_auth(v) for k, v in val.items()}
            if isinstance(val, list):
                return [_pad_auth(item) for item in val]
            if isinstance(val, str):
                return re.sub(
                    r"(?i)\b(Bearer|Basic)\s+\[REDACTED\](?=$|[^ \t\r\n])",
                    r"\1 [REDACTED] ",
                    val,
                )
            return val

        padded = _pad_auth(scrubbed)
        json_text = json.dumps(padded, indent=2) + "\n"
        if contains_unredacted_secret_strict(json_text):
            raise ValueError("Serialized trace failed redaction check.")
        trace_path = trace_dir / f"trace_{run_id}.json"
        tmp_path = trace_dir / f".tmp_trace_{run_id}.json"
        tmp_path.write_text(json_text, encoding="utf-8")
        os.replace(tmp_path, trace_path)

    def _schedule_run(self, run_id: str) -> None:
        if not self._auto_run:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        async def _run_and_trace() -> Result:
            result = await self._coordinator.run_until_settled(run_id)
            with contextlib.suppress(Exception):
                self._emit_trace_if_enabled(run_id)
            return result

        task = loop.create_task(_run_and_trace())
        self._bg_tasks[run_id] = task

        def _cleanup(done_task: asyncio.Task[Result]) -> None:
            if self._bg_tasks.get(run_id) is done_task:
                self._bg_tasks.pop(run_id, None)

        task.add_done_callback(_cleanup)

    def submit_task(self, task_spec: TaskSpec) -> Run:
        effective_spec = task_spec
        if not task_spec.scope.allowed_origins and self._facility_config is not None:
            default_origins = tuple(
                sorted(
                    {
                        app.origin
                        for app in self._facility_config.apps.values()
                        if not task_spec.scope.read_only or app.read_only
                    }
                )
            )
            effective_spec = task_spec.model_copy(
                update={
                    "scope": task_spec.scope.model_copy(
                        update={"allowed_origins": default_origins}
                    )
                }
            )
        try:
            validate_session_segment("user_id", effective_spec.user_id)
            validate_session_segment("profile_id", effective_spec.profile_id)
        except ValueError as exc:
            raise PlanValidationError(str(exc)) from exc
        self._coordinator.validate_backend_mode(effective_spec)
        run = self._coordinator.submit_task(effective_spec)
        self._schedule_run(run.run_id)
        return run

    def get_task_snapshot(self, run_id: str) -> TaskSnapshot | None:
        try:
            snap = self._repo.get_run_snapshot(run_id)
        except NotFoundError:
            return None
        transitions = tuple(
            TransitionRecord(
                from_status=ev.from_status,
                to_status=ev.to_status,
                reason=ev.reason or ev.event_type,
                timestamp=ev.created_at,
            )
            for ev in snap.events
            if ev.to_status is not None
            and ev.event_type in ("task_created", "run_transition", "human_input_received")
        )
        return TaskSnapshot(
            run=snap.run,
            task=snap.task_spec,
            budget_config=snap.task_spec.budget,
            budget_usage=snap.budget_usage,
            transitions=transitions,
            result=snap.result,
            receipts=snap.receipts,
        )

    def list_task_snapshots(self) -> list[TaskSnapshot]:
        runs = self._repo.list_runs(limit=100, root_only=False)
        snapshots: list[TaskSnapshot] = []
        for run in runs:
            snap = self.get_task_snapshot(run.run_id)
            if snap is not None:
                snapshots.append(snap)
        return snapshots

    def cancel_task(self, run_id: str, reason: str = "cancelled_by_user") -> Run:
        current = self._repo.get_run(run_id)
        if is_terminal_status(current.status):
            raise InvalidStateTransitionError(
                f"Run {run_id!r} is already terminal ({current.status.value})."
            )
        return self._coordinator.cancel_task(run_id, reason=reason)

    def resume_task(self, run_id: str, human_input: dict[str, Any]) -> Run:
        updated = self._coordinator.resume_task(run_id, human_input)
        self._schedule_run(run_id)
        return updated

    async def wait_for_run(self, run_id: str, timeout: float = 30.0) -> Result | None:
        bg = self._bg_tasks.get(run_id)
        if bg is None:
            return None
        return await asyncio.wait_for(bg, timeout=timeout)

    async def shutdown(self) -> None:
        pending = [t for t in self._bg_tasks.values() if not t.done()]
        for t in pending:
            t.cancel()
        for t in pending:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        self._bg_tasks.clear()


class GrokbotRuntime:
    """Full wired runtime holding StorageRepo, SessionManager, ToolRegistry, Coordinator, Web."""

    def __init__(
        self,
        *,
        db_path: Path,
        repo: StorageRepo,
        session_manager: SessionManager,
        tool_registry: ToolRegistry,
        model_client: ModelClient,
        coordinator: Coordinator,
        web_coordinator: RuntimeCoordinatorAdapter,
        facility_config: FacilityConfig,
        app: FastAPI,
    ) -> None:
        self.db_path = db_path
        self.repo = repo
        self.session_manager = session_manager
        self.tool_registry = tool_registry
        self.model_client = model_client
        self.coordinator = coordinator
        self.web_coordinator = web_coordinator
        self.facility_config = facility_config
        self.app = app

    async def __aenter__(self) -> GrokbotRuntime:
        await self.session_manager.start()
        await self.coordinator.recover_inflight_runs()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.web_coordinator.shutdown()
        await self.session_manager.close_all()


def build_runtime(
    *,
    db_path: Path | str,
    profile_root: Path | str,
    facility_config: FacilityConfig,
    credential_provider: CredentialProvider | None = None,
    backend_mode: BackendMode = BackendMode.EMULATED,
    local_http_config: LocalModelConfig | None = None,
    model_client: ModelClient | None = None,
    effect_adapter: EffectSimAdapter | None = None,
    coordinator_config: CoordinatorConfig | None = None,
    reference_time_fn: Callable[[], datetime] | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    auto_run: bool = True,
    headless: bool = True,
    strict_tool_allowlist: bool = False,
) -> GrokbotRuntime:
    """Construct a complete, wired GrokbotRuntime with real WAL DB, Playwright, and Web API."""
    resolved_db = Path(db_path)
    resolved_profiles = Path(profile_root)
    repo = StorageRepo(resolved_db)
    repo.init_db()

    session_manager = SessionManager(resolved_profiles, headless=headless)
    tool_registry = ToolRegistry(
        strict_tool_allowlist=strict_tool_allowlist,
        takeover_checker=session_manager.is_takeover_active,
    )
    register_industrial_tools(
        tool_registry,
        config=facility_config,
        session_manager=session_manager,
        credential_provider=credential_provider,
        effect_adapter=effect_adapter,
        task_lookup=repo.get_task_spec,
    )

    if model_client is not None:
        active_model: ModelClient = model_client
    elif backend_mode == BackendMode.LOCAL_HTTP:
        active_model = build_model_client(
            BackendMode.LOCAL_HTTP,
            local_http_config=local_http_config,
        )
    else:
        active_model = EmulatedModelClient(
            mode="custom",
            turn_factory=make_industrial_turn_factory(facility_config),
        )

    if backend_mode == BackendMode.LOCAL_HTTP and not isinstance(
        active_model, LocalHttpModelClient
    ):
        raise ModelProtocolError(
            "backend_mode='local_http' requires LocalHttpModelClient; "
            "silent fallback to EmulatedModelClient is forbidden."
        )

    granted_perms = tuple(
        sorted(
            {
                perm
                for app in facility_config.apps.values()
                for perm in app.permissions
            }
        )
    )
    eff_coord_config = (
        coordinator_config
        if coordinator_config is not None
        else CoordinatorConfig(default_granted_permissions=granted_perms)
    )

    def _permission_revalidator(
        task_spec: TaskSpec,
        human_input: dict[str, Any],
    ) -> tuple[bool, str]:
        del human_input
        for app_id in ("scada", "maintenance"):
            sid = make_session_id(task_spec.user_id, task_spec.profile_id, app_id)
            if session_manager.is_takeover_active(sid):
                return (
                    False,
                    f"Session {sid!r} is still under human takeover; release before resuming.",
                )
        return True, "ok"

    result_verifier = build_industrial_result_verifier(
        facility_config,
        reference_time_fn=reference_time_fn,
        window_start=window_start,
        window_end=window_end,
    )

    coordinator = Coordinator(
        repo,
        active_model,
        tool_registry,
        config=eff_coord_config,
        session_id_resolver=_session_id_for_tool,
        result_verifier=result_verifier,
        permission_revalidator=_permission_revalidator,
    )
    web_coordinator = RuntimeCoordinatorAdapter(
        repo=repo,
        coordinator=coordinator,
        facility_config=facility_config,
        auto_run=auto_run,
    )
    app = create_app(
        db_path=resolved_db,
        coordinator=web_coordinator,
        session_manager=session_manager,
    )

    return GrokbotRuntime(
        db_path=resolved_db,
        repo=repo,
        session_manager=session_manager,
        tool_registry=tool_registry,
        model_client=active_model,
        coordinator=coordinator,
        web_coordinator=web_coordinator,
        facility_config=facility_config,
        app=app,
    )
