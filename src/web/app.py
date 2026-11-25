"""FastAPI local operator API and minimal observability UI."""

from __future__ import annotations

import json
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, quote_plus, urlparse

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from pydantic import ValidationError

from src.adapters.sessions import (
    OriginNotAllowedError,
    SessionBusyError,
    SessionLockState,
    SessionManager,
    SessionNotFoundError,
    TakeoverStateError,
)
from src.contracts.common import (
    InvalidStateTransitionError,
    PlanValidationError,
    validate_http_origin,
)
from src.contracts.models import ActionReceipt, Run, TaskSpec
from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.storage.errors import ConflictError, NotFoundError
from src.storage.redaction import (
    contains_unredacted_secret_strict,
    is_sensitive_key_strict,
    redact_payload_strict,
)
from src.web.protocols import CoordinatorProtocol, SessionManagerProtocol, TaskSnapshot, maybe_await
from src.web.schemas import (
    CancelRequest,
    ReleaseRequest,
    ResumeRequest,
    TakeoverRequest,
    TaskSubmitRequest,
)
from src.web.stub import InMemoryCoordinatorStub

if TYPE_CHECKING:
    from src.runtime import GrokbotRuntime

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_RUNTIME_ENV_KEYS: tuple[str, ...] = (
    "GROKBOT_DB_PATH",
    "GROKBOT_ALLOWED_ORIGINS",
    "GROKBOT_SCADA_URL",
    "GROKBOT_MAINTENANCE_URL",
    "GROKBOT_EFFECT_SIM_URL",
    "GROKBOT_LLM_BASE_URL",
    "GROKBOT_INSTALLATION_CONFIG",
    "GROKBOT_PROFILE_ROOT",
    "GROKBOT_PROFILES_DIR",
)


def _has_runtime_env() -> bool:
    return any(bool(os.environ.get(key, "").strip()) for key in _RUNTIME_ENV_KEYS)


def _env_origin_overrides() -> dict[str, str]:
    overrides: dict[str, str] = {}
    scada_url = os.environ.get("GROKBOT_SCADA_URL", "").strip()
    maint_url = os.environ.get("GROKBOT_MAINTENANCE_URL", "").strip()
    effect_url = os.environ.get("GROKBOT_EFFECT_SIM_URL", "").strip()
    if scada_url:
        overrides["scada"] = validate_http_origin(scada_url)
    if maint_url:
        overrides["maintenance"] = validate_http_origin(maint_url)
    if effect_url:
        overrides["effect_sim"] = validate_http_origin(effect_url)
    return overrides


def _build_default_credentials() -> dict[tuple[str, str, str], tuple[str, str]]:
    creds: dict[tuple[str, str, str], tuple[str, str]] = {
        ("operator_a", "*", "scada"): ("operator_a", "scada-pass-a"),
        ("operator_a", "*", "maintenance"): ("maint_a", "maint-pass-a"),
        ("operator_a1", "*", "scada"): ("operator_a1", "scada-pass-a1"),
        ("operator_a1", "*", "maintenance"): ("maint_a1", "maint-pass-a1"),
        ("operator_b", "*", "scada"): ("operator_b", "scada-pass-b"),
        ("operator_b", "*", "maintenance"): ("maint_b", "maint-pass-b"),
        ("operator_a2", "*", "scada"): ("operator_a2", "scada-pass-a2"),
        ("operator_a2", "*", "maintenance"): ("maint_a2", "maint-pass-a2"),
        ("operator_ro", "*", "scada"): ("operator_ro", "scada-pass-ro"),
        ("operator_ro", "*", "maintenance"): ("maint_ro", "maint-pass-ro"),
        ("*", "*", "scada"): ("operator_ro", "scada-pass-ro"),
        ("*", "*", "maintenance"): ("maint_ro", "maint-pass-ro"),
    }
    raw_extra = os.environ.get("GROKBOT_CREDENTIALS_JSON", "").strip()
    if raw_extra:
        try:
            parsed = json.loads(raw_extra)
        except ValueError as exc:
            raise ValueError(
                f"Invalid GROKBOT_CREDENTIALS_JSON: {getattr(exc, 'msg', str(exc))}"
            ) from exc
        if isinstance(parsed, dict):
            for key_str, val in parsed.items():
                parts = [p.strip() for p in str(key_str).split(":")]
                if len(parts) == 3 and isinstance(val, (list, tuple)) and len(val) == 2:
                    creds[(parts[0], parts[1], parts[2])] = (str(val[0]), str(val[1]))
        elif isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    if not all(k in item for k in ("app_id", "username", "password")):
                        raise ValueError(
                            "Invalid GROKBOT_CREDENTIALS_JSON entry: missing required key."
                        )
                    creds[
                        (
                            str(item.get("user_id", "*")),
                            str(item.get("profile_id", "*")),
                            str(item["app_id"]),
                        )
                    ] = (str(item["username"]), str(item["password"]))
        else:
            raise ValueError("Invalid GROKBOT_CREDENTIALS_JSON: expected JSON object or array.")
    return creds


def _load_configured_origins_from_path(
    raw_path: str,
    *,
    origin_overrides: dict[str, str],
) -> set[str]:
    from deploy.config import DeployConfigError, load_deploy_config

    from src.adapters.config import load_facility_config

    path = Path(raw_path)
    if not path.is_absolute() and not path.exists():
        repo_candidate = _REPO_ROOT / path
        if repo_candidate.exists():
            path = repo_candidate
    if not path.exists():
        raise FileNotFoundError(
            f"Invalid installation_config_path {raw_path!r}: config file not found."
        )

    is_deploy_cfg = path.suffix.lower() in {".yaml", ".yml"}
    if not is_deploy_cfg and path.suffix.lower() == ".json":
        try:
            raw_obj = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Malformed JSON in installation_config_path {raw_path!r}: {exc.msg}"
            ) from exc
        if isinstance(raw_obj, dict) and "apps" not in raw_obj and "allowed_origins" in raw_obj:
            is_deploy_cfg = True

    try:
        if is_deploy_cfg:
            deploy_cfg = load_deploy_config(path, verify_facility=True, repo_root=_REPO_ROOT)
            origins = set(deploy_cfg.allowed_origins)
            origins.update(origin_overrides.values())
            return origins

        facility_cfg = load_facility_config(path, origin_overrides=origin_overrides or None)
    except ValidationError as exc:
        fields = [
            ".".join(str(part) for part in err.get("loc", ())) or "root"
            for err in exc.errors()
        ]
        raise ValueError(
            f"Invalid installation_config_path {raw_path!r}: "
            f"malformed config fields ({', '.join(fields)})."
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Malformed JSON in installation_config_path {raw_path!r}: {exc.msg}"
        ) from exc
    except DeployConfigError as exc:
        raise ValueError(
            f"Invalid installation_config_path {raw_path!r}: malformed deployment config."
        ) from exc

    if not facility_cfg.apps:
        raise ValueError(
            f"Invalid installation_config_path {raw_path!r}: "
            "defines zero configured app origins."
        )
    return {app_cfg.origin for app_cfg in facility_cfg.apps.values()}


def _validate_task_origins(
    task_spec: TaskSpec,
    active_runtime: GrokbotRuntime | None,
) -> None:
    overrides = _env_origin_overrides()
    raw_inst_env = os.environ.get("GROKBOT_INSTALLATION_CONFIG", "").strip()
    raw_allowed = os.environ.get("GROKBOT_ALLOWED_ORIGINS", "").strip()
    configured_origins: set[str] = set()
    strict_configured_check = False

    if task_spec.installation_config_path is not None:
        strict_configured_check = True
        configured_origins = _load_configured_origins_from_path(
            task_spec.installation_config_path,
            origin_overrides=overrides,
        )
    elif raw_inst_env:
        strict_configured_check = True
        configured_origins = _load_configured_origins_from_path(
            raw_inst_env,
            origin_overrides=overrides,
        )
    elif raw_allowed:
        strict_configured_check = True
        for raw_origin in raw_allowed.split(","):
            if raw_origin.strip():
                configured_origins.add(validate_http_origin(raw_origin.strip()))
        if overrides:
            configured_origins.update(overrides.values())
    else:
        if active_runtime is not None:
            configured_origins.update(
                app_cfg.origin for app_cfg in active_runtime.facility_config.apps.values()
            )
        if configured_origins and overrides:
            configured_origins.update(overrides.values())

    if task_spec.scope.allowed_origins:
        if strict_configured_check:
            if configured_origins:
                disallowed = [
                    origin
                    for origin in task_spec.scope.allowed_origins
                    if origin not in configured_origins
                ]
                if disallowed:
                    raise ValueError(
                        f"Unconfigured or disallowed allowed_origins: {disallowed}"
                    )
        else:
            all_apps_overridden = active_runtime is not None and all(
                app_id in overrides
                for app_id in active_runtime.facility_config.apps
            )
            for origin in task_spec.scope.allowed_origins:
                parsed_origin = urlparse(origin)
                hostname = (parsed_origin.hostname or "").lower()
                is_loopback = hostname in {"127.0.0.1", "localhost", "::1"}
                if not is_loopback:
                    raise ValueError(
                        "Non-loopback allowed_origin requires "
                        f"installation_config_path: {origin}"
                    )
                if (
                    all_apps_overridden
                    and configured_origins
                    and origin not in configured_origins
                ):
                    raise ValueError(
                        f"Unconfigured or disallowed allowed_origins: {[origin]}"
                    )


def _scrub_and_verify(payload: Any, *, label: str = "payload") -> Any:
    scrubbed = redact_payload_strict(payload)
    if contains_unredacted_secret_strict(scrubbed):
        raise ValueError(f"{label} serialization failed redaction check.")
    return scrubbed


def _is_truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _pad_redacted_auth_markers(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _pad_redacted_auth_markers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_pad_redacted_auth_markers(item) for item in value]
    if isinstance(value, str):
        return re.sub(
            r"(?i)\b(Bearer|Basic)\s+\[REDACTED\](?=$|[^ \t\r\n])",
            r"\1 [REDACTED] ",
            value,
        )
    return value


def _maybe_write_trace_from_payload(run_id: str, payload: dict[str, Any]) -> None:
    if not _is_truthy_env("GROKBOT_TRACING_ENABLED"):
        return
    raw_dir = os.environ.get("GROKBOT_TRACE_DIR", "").strip()
    if not raw_dir:
        return
    trace_dir = Path(raw_dir)
    trace_dir.mkdir(parents=True, exist_ok=True)
    deploy_cfg = os.environ.get("GROKBOT_DEPLOY_CONFIG", "").strip() or None
    trace_doc = _pad_redacted_auth_markers(
        _scrub_and_verify(
            {
                "run_id": run_id,
                "tracing_enabled": True,
                "deploy_config": deploy_cfg,
                **payload,
            },
            label="Trace",
        )
    )
    json_text = json.dumps(trace_doc, indent=2) + "\n"
    if contains_unredacted_secret_strict(json_text):
        raise ValueError("Serialized trace failed redaction check.")
    trace_path = trace_dir / f"trace_{run_id}.json"
    tmp_path = trace_dir / f".tmp_trace_{run_id}.json"
    tmp_path.write_text(json_text, encoding="utf-8")
    os.replace(tmp_path, trace_path)


def _serialize_redacted_receipt(receipt: ActionReceipt) -> dict[str, Any]:
    raw = receipt.model_dump(mode="json")
    scrubbed: dict[str, Any] = _scrub_and_verify(raw, label="Receipt")
    return scrubbed


def _serialize_run(run: Run) -> dict[str, Any]:
    scrubbed: dict[str, Any] = _scrub_and_verify(run.model_dump(mode="json"), label="Run")
    return scrubbed


def _serialize_session(sess: SessionLockState) -> dict[str, Any]:
    scrubbed: dict[str, Any] = _scrub_and_verify(
        sess.model_dump(mode="json"),
        label="SessionLockState",
    )
    return scrubbed


def _serialize_snapshot(snapshot: TaskSnapshot) -> dict[str, Any]:
    transitions_json = [
        _scrub_and_verify(t.model_dump(mode="json"), label="TransitionRecord")
        for t in snapshot.transitions
    ]
    last_transition = transitions_json[-1] if transitions_json else None
    receipts_json = [_serialize_redacted_receipt(r) for r in snapshot.receipts]
    result_json: dict[str, Any] | None = None
    if snapshot.result is not None:
        result_json = _scrub_and_verify(
            snapshot.result.model_dump(mode="json"),
            label="Result",
        )

    payload: dict[str, Any] = {
        "run": _serialize_run(snapshot.run),
        "task": _scrub_and_verify(snapshot.task.model_dump(mode="json"), label="TaskSpec"),
        "status": snapshot.run.status.value,
        "last_transition": last_transition,
        "transition_reason": _scrub_and_verify(
            snapshot.run.transition_reason,
            label="transition_reason",
        ),
        "required_action": (
            _scrub_and_verify(snapshot.run.required_action, label="required_action")
            if snapshot.run.required_action is not None
            else None
        ),
        "budget": {
            "config": _scrub_and_verify(
                snapshot.budget_config.model_dump(mode="json"),
                label="BudgetConfig",
            ),
            "usage": _scrub_and_verify(
                snapshot.budget_usage.model_dump(mode="json"),
                label="BudgetUsage",
            ),
            "usage_estimated": snapshot.budget_usage.usage_estimated,
        },
        "transitions": transitions_json,
        "receipts": receipts_json,
        "result": result_json,
    }
    serialized: dict[str, Any] = _scrub_and_verify(payload, label="TaskSnapshot")
    return serialized


def _serialize_ui_snapshot(snapshot: TaskSnapshot) -> dict[str, Any]:
    usage_dict = snapshot.budget_usage.model_dump(mode="json")
    usage_dict["total_tokens_used"] = snapshot.budget_usage.total_tokens_used
    payload: dict[str, Any] = {
        "run": _serialize_run(snapshot.run),
        "task": _scrub_and_verify(snapshot.task.model_dump(mode="json"), label="TaskSpec"),
        "budget_config": _scrub_and_verify(
            snapshot.budget_config.model_dump(mode="json"),
            label="BudgetConfig",
        ),
        "budget_usage": _scrub_and_verify(usage_dict, label="BudgetUsage"),
        "transitions": [
            _scrub_and_verify(t.model_dump(mode="json"), label="TransitionRecord")
            for t in snapshot.transitions
        ],
        "result": (
            _scrub_and_verify(snapshot.result.model_dump(mode="json"), label="Result")
            if snapshot.result is not None
            else None
        ),
        "receipts": [_serialize_redacted_receipt(r) for r in snapshot.receipts],
    }
    serialized: dict[str, Any] = _scrub_and_verify(payload, label="UISnapshot")
    return serialized


def create_app(
    db_path: Path | str | None = None,
    coordinator: CoordinatorProtocol | None = None,
    session_manager: SessionManagerProtocol | None = None,
) -> FastAPI:
    """Create the FastAPI local operator API & HTML observability UI."""
    resolved_db = Path(db_path) if db_path is not None else None
    active_runtime: GrokbotRuntime | None = None
    owns_session_manager = session_manager is None
    internal_sm: SessionManager | None = None

    if coordinator is not None:
        coord: CoordinatorProtocol = coordinator
        if session_manager is None:
            profile_root = (
                resolved_db.parent / "browser_profiles"
                if resolved_db is not None
                else Path.cwd() / ".grokbot_profiles"
            )
            internal_sm = SessionManager(profile_root=profile_root, headless=True)
            sess_mgr: SessionManagerProtocol = internal_sm
        else:
            sess_mgr = session_manager
    elif _has_runtime_env():
        from deploy.config import load_deploy_config

        from src.adapters._common import MappingCredentialProvider
        from src.adapters.config import load_facility_config
        from src.adapters.effects import EffectSimAdapter
        from src.contracts.enums import BackendMode
        from src.model.http_client import LocalModelConfig
        from src.runtime import build_runtime

        env_db = os.environ.get("GROKBOT_DB_PATH", "").strip()
        if resolved_db is None:
            resolved_db = Path(env_db) if env_db else (Path.cwd() / "grokbot.sqlite3")

        env_profiles = (
            os.environ.get("GROKBOT_PROFILE_ROOT", "").strip()
            or os.environ.get("GROKBOT_PROFILES_DIR", "").strip()
        )
        profile_root = (
            Path(env_profiles) if env_profiles else (resolved_db.parent / "browser_profiles")
        )

        overrides = _env_origin_overrides()
        raw_inst_cfg = os.environ.get("GROKBOT_INSTALLATION_CONFIG", "").strip()
        if raw_inst_cfg:
            inst_path = Path(raw_inst_cfg)
            is_deploy_file = inst_path.suffix.lower() in {".yaml", ".yml"}
            if not is_deploy_file and inst_path.suffix.lower() == ".json" and inst_path.exists():
                raw_inst_obj = json.loads(inst_path.read_text(encoding="utf-8"))
                if (
                    isinstance(raw_inst_obj, dict)
                    and "apps" not in raw_inst_obj
                    and "facility_config_path" in raw_inst_obj
                ):
                    is_deploy_file = True
            if is_deploy_file:
                deploy_cfg = load_deploy_config(
                    inst_path, verify_facility=False, repo_root=_REPO_ROOT
                )
                fac_path = Path(deploy_cfg.facility_config_path)
                if not fac_path.is_absolute():
                    fac_path = _REPO_ROOT / fac_path
                facility_config = load_facility_config(
                    fac_path, origin_overrides=overrides or None
                )
            else:
                facility_config = load_facility_config(
                    inst_path, origin_overrides=overrides or None
                )
        else:
            default_fac = _REPO_ROOT / "lab" / "configs" / "facility_a.json"
            facility_config = load_facility_config(
                default_fac, origin_overrides=overrides or None
            )

        llm_base_url = os.environ.get("GROKBOT_LLM_BASE_URL", "").strip()
        local_http_config: LocalModelConfig | None = None
        backend_mode = BackendMode.EMULATED
        if llm_base_url:
            parsed_llm = urlparse(llm_base_url)
            llm_origin = f"{parsed_llm.scheme}://{parsed_llm.netloc}"
            llm_path = parsed_llm.path.rstrip("/")
            endpoint_path = (
                "/v1/chat/completions"
                if llm_path in {"", "/v1"}
                else f"{llm_path}/chat/completions"
            )
            allow_private_lan = os.environ.get("GROKBOT_ALLOW_PRIVATE_LAN", "").strip().lower() in {
                "1",
                "true",
                "yes",
            }
            local_http_config = LocalModelConfig(
                origin=llm_origin,
                endpoint_path=endpoint_path,
                model_id=os.environ.get("GROKBOT_LLM_MODEL_ID", "").strip()
                or "mock-local-qwen2.5",
                allow_private_lan=allow_private_lan,
            )
            backend_mode = BackendMode.LOCAL_HTTP

        effect_adapter = EffectSimAdapter() if "effect_sim" in facility_config.apps else None
        active_runtime = build_runtime(
            db_path=resolved_db,
            profile_root=profile_root,
            facility_config=facility_config,
            credential_provider=MappingCredentialProvider(_build_default_credentials()),
            backend_mode=backend_mode,
            local_http_config=local_http_config,
            effect_adapter=effect_adapter,
            auto_run=True,
            headless=True,
        )
        coord = active_runtime.web_coordinator
        sess_mgr = (
            session_manager if session_manager is not None else active_runtime.session_manager
        )
        owns_session_manager = False
    else:
        coord = InMemoryCoordinatorStub()
        if session_manager is None:
            profile_root = (
                resolved_db.parent / "browser_profiles"
                if resolved_db is not None
                else Path.cwd() / ".grokbot_profiles"
            )
            internal_sm = SessionManager(profile_root=profile_root, headless=True)
            sess_mgr = internal_sm
        else:
            sess_mgr = session_manager

    jinja_env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
    )
    templates = Jinja2Templates(env=jinja_env)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if active_runtime is not None:
            async with active_runtime:
                yield
            return
        try:
            yield
        finally:
            if owns_session_manager and internal_sm is not None:
                await internal_sm.close_all()

    app = FastAPI(title="Grokbotclon Local Operator Console", version="1.0.0", lifespan=lifespan)
    app.state.db_path = str(resolved_db) if resolved_db is not None else None
    app.state.coordinator = coord
    app.state.session_manager = sess_mgr
    app.state.runtime = active_runtime

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        del request
        encoded = jsonable_encoder(exc.errors())
        if isinstance(encoded, list):
            for err in encoded:
                if isinstance(err, dict):
                    loc = err.get("loc")
                    if (
                        isinstance(loc, list)
                        and loc
                        and is_sensitive_key_strict(str(loc[-1]))
                        and err.get("input") is not None
                    ):
                        err["input"] = REDACTED_PLACEHOLDER
        scrubbed = _scrub_and_verify(encoded, label="validation_error")
        return JSONResponse(status_code=422, content={"detail": scrubbed})

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "ok",
                "service": "grokbot-web",
                "db_path": str(resolved_db) if resolved_db is not None else None,
            },
        )

    @app.post("/api/tasks", status_code=status.HTTP_201_CREATED)
    async def api_submit_task(payload: TaskSubmitRequest) -> JSONResponse:
        task_spec = payload.to_task_spec()
        try:
            _validate_task_origins(task_spec, active_runtime)
        except (OSError, ValueError, ValidationError, OriginNotAllowedError) as exc:
            raise HTTPException(
                status_code=422,
                detail=str(_scrub_and_verify(str(exc), label="error")),
            ) from exc

        try:
            run = await maybe_await(coord.submit_task(task_spec))
        except (InvalidStateTransitionError, ConflictError, PlanValidationError) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(_scrub_and_verify(str(exc), label="error")),
            ) from exc
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=_serialize_run(run),
        )

    @app.get("/api/tasks")
    async def api_list_tasks() -> JSONResponse:
        snapshots = await maybe_await(coord.list_task_snapshots())
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"tasks": [_serialize_snapshot(snap) for snap in snapshots]},
        )

    @app.get("/api/tasks/{run_id}")
    async def api_get_task(run_id: str) -> JSONResponse:
        snapshot = await maybe_await(coord.get_task_snapshot(run_id))
        if snapshot is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(_scrub_and_verify(f"Unknown run_id: {run_id}", label="error")),
            )
        serialized = _serialize_snapshot(snapshot)
        _maybe_write_trace_from_payload(run_id, serialized)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=serialized,
        )

    @app.post("/api/tasks/{run_id}/cancel")
    async def api_cancel_task(
        run_id: str,
        payload: CancelRequest | None = None,
    ) -> JSONResponse:
        reason = payload.reason if payload is not None else "cancelled_by_user"
        try:
            updated = await maybe_await(coord.cancel_task(run_id, reason=reason))
        except (KeyError, NotFoundError) as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(_scrub_and_verify(f"Unknown run_id: {run_id}", label="error")),
            ) from exc
        except (InvalidStateTransitionError, ConflictError, PlanValidationError) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(_scrub_and_verify(str(exc), label="error")),
            ) from exc
        return JSONResponse(status_code=status.HTTP_200_OK, content=_serialize_run(updated))

    @app.post("/api/tasks/{run_id}/resume")
    async def api_resume_task(run_id: str, payload: ResumeRequest) -> JSONResponse:
        try:
            updated = await maybe_await(coord.resume_task(run_id, payload.human_input))
        except (KeyError, NotFoundError) as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(_scrub_and_verify(f"Unknown run_id: {run_id}", label="error")),
            ) from exc
        except (InvalidStateTransitionError, ConflictError, PlanValidationError) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(_scrub_and_verify(str(exc), label="error")),
            ) from exc
        return JSONResponse(status_code=status.HTTP_200_OK, content=_serialize_run(updated))

    @app.get("/api/sessions")
    async def api_list_sessions() -> JSONResponse:
        sessions = await maybe_await(sess_mgr.list_sessions())
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"sessions": [_serialize_session(s) for s in sessions]},
        )

    @app.post("/api/sessions/{session_id}/takeover")
    async def api_session_takeover(
        session_id: str,
        payload: TakeoverRequest | None = None,
    ) -> JSONResponse:
        req = payload if payload is not None else TakeoverRequest()
        try:
            state = await maybe_await(
                sess_mgr.request_takeover(session_id, owner=req.owner, reason=req.reason)
            )
        except (KeyError, SessionNotFoundError) as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(_scrub_and_verify(f"Unknown session_id: {session_id}", label="error")),
            ) from exc
        except (SessionBusyError, TakeoverStateError) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(_scrub_and_verify(str(exc), label="error")),
            ) from exc
        return JSONResponse(status_code=status.HTTP_200_OK, content=_serialize_session(state))

    @app.post("/api/sessions/{session_id}/release")
    async def api_session_release(
        session_id: str,
        payload: ReleaseRequest | None = None,
    ) -> JSONResponse:
        owner = payload.owner if payload is not None else None
        try:
            state = await maybe_await(sess_mgr.release_takeover(session_id, owner=owner))
        except (KeyError, SessionNotFoundError) as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(_scrub_and_verify(f"Unknown session_id: {session_id}", label="error")),
            ) from exc
        except TakeoverStateError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(_scrub_and_verify(str(exc), label="error")),
            ) from exc
        return JSONResponse(status_code=status.HTTP_200_OK, content=_serialize_session(state))

    @app.get("/", response_class=HTMLResponse)
    async def ui_index(request: Request, error: str | None = None) -> Response:
        snapshots = await maybe_await(coord.list_task_snapshots())
        sessions = await maybe_await(sess_mgr.list_sessions())
        safe_error = _scrub_and_verify(error, label="error") if error is not None else None
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "snapshots": [_serialize_ui_snapshot(s) for s in snapshots],
                "sessions": [_serialize_session(s) for s in sessions],
                "error_message": safe_error,
            },
        )

    @app.get("/tasks/{run_id}", response_class=HTMLResponse)
    async def ui_task_detail(
        request: Request,
        run_id: str,
        error: str | None = None,
    ) -> Response:
        snapshot = await maybe_await(coord.get_task_snapshot(run_id))
        if snapshot is None:
            snapshots = await maybe_await(coord.list_task_snapshots())
            sessions = await maybe_await(sess_mgr.list_sessions())
            safe_not_found = _scrub_and_verify(f"Unknown run_id: {run_id}", label="error")
            return templates.TemplateResponse(
                request,
                "index.html",
                {
                    "snapshots": [_serialize_ui_snapshot(s) for s in snapshots],
                    "sessions": [_serialize_session(s) for s in sessions],
                    "error_message": safe_not_found,
                },
                status_code=status.HTTP_404_NOT_FOUND,
            )
        ui_snapshot = _serialize_ui_snapshot(snapshot)
        safe_error = _scrub_and_verify(error, label="error") if error is not None else None
        return templates.TemplateResponse(
            request,
            "task_detail.html",
            {
                "snapshot": ui_snapshot,
                "redacted_receipts": ui_snapshot["receipts"],
                "error_message": safe_error,
            },
        )

    async def _read_form(request: Request) -> dict[str, str]:
        body_bytes = await request.body()
        try:
            raw = body_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid UTF-8 form body.",
            ) from exc
        parsed = parse_qs(raw, keep_blank_values=True)
        return {k: vals[0] for k, vals in parsed.items() if vals}

    @app.post("/ui/tasks")
    async def ui_submit_task(request: Request) -> RedirectResponse:
        form = await _read_form(request)
        query = form.get("query", "")
        facility_id = form.get("facility_id", "facility-a") or "facility-a"
        user_id = form.get("user_id", "operator") or "operator"
        profile_id = form.get("profile_id", "default") or "default"
        allowed_areas = form.get("allowed_areas", "")
        areas_tuple = tuple(a.strip() for a in allowed_areas.split(",") if a.strip())
        allowed_origins = form.get("allowed_origins", "")
        origins_tuple = tuple(o.strip() for o in allowed_origins.split(",") if o.strip())
        try:
            req = TaskSubmitRequest(
                query=query,
                facility_id=facility_id,
                user_id=user_id,
                profile_id=profile_id,
                allowed_origins=origins_tuple,
                allowed_areas=areas_tuple,
            )
            task_spec = req.to_task_spec()
            _validate_task_origins(task_spec, active_runtime)
            run = await maybe_await(coord.submit_task(task_spec))
        except (
            ValidationError,
            ConflictError,
            PlanValidationError,
            OriginNotAllowedError,
            InvalidStateTransitionError,
            ValueError,
            OSError,
        ) as exc:
            safe_err = str(_scrub_and_verify(str(exc), label="error"))
            return RedirectResponse(
                url=f"/?error={quote_plus(safe_err)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        return RedirectResponse(
            url=f"/tasks/{quote_plus(run.run_id)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/ui/tasks/{run_id}/cancel")
    async def ui_cancel_task(run_id: str, request: Request) -> RedirectResponse:
        form = await _read_form(request)
        reason = form.get("reason", "cancelled_by_operator") or "cancelled_by_operator"
        try:
            await maybe_await(coord.cancel_task(run_id, reason=reason))
        except (
            KeyError,
            NotFoundError,
            InvalidStateTransitionError,
            ConflictError,
            PlanValidationError,
        ) as exc:
            safe_err = str(_scrub_and_verify(str(exc), label="error"))
            safe_run_id = quote_plus(str(_scrub_and_verify(run_id, label="run_id")))
            return RedirectResponse(
                url=f"/tasks/{safe_run_id}?error={quote_plus(safe_err)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        safe_run_id = quote_plus(str(_scrub_and_verify(run_id, label="run_id")))
        return RedirectResponse(
            url=f"/tasks/{safe_run_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/ui/tasks/{run_id}/resume")
    async def ui_resume_task(run_id: str, request: Request) -> RedirectResponse:
        form = await _read_form(request)
        choice = form.get("choice", "")
        try:
            await maybe_await(coord.resume_task(run_id, {"choice": choice}))
        except (
            KeyError,
            NotFoundError,
            InvalidStateTransitionError,
            ConflictError,
            PlanValidationError,
        ) as exc:
            safe_err = str(_scrub_and_verify(str(exc), label="error"))
            safe_run_id = quote_plus(str(_scrub_and_verify(run_id, label="run_id")))
            return RedirectResponse(
                url=f"/tasks/{safe_run_id}?error={quote_plus(safe_err)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        safe_run_id = quote_plus(str(_scrub_and_verify(run_id, label="run_id")))
        return RedirectResponse(
            url=f"/tasks/{safe_run_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/ui/sessions/{session_id}/takeover")
    async def ui_session_takeover(session_id: str, request: Request) -> RedirectResponse:
        form = await _read_form(request)
        owner = form.get("owner", "operator") or "operator"
        reason = form.get("reason", "manual_intervention") or "manual_intervention"
        try:
            await maybe_await(sess_mgr.request_takeover(session_id, owner=owner, reason=reason))
        except (KeyError, SessionNotFoundError, SessionBusyError, TakeoverStateError) as exc:
            safe_err = str(_scrub_and_verify(str(exc), label="error"))
            return RedirectResponse(
                url=f"/?error={quote_plus(safe_err)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/ui/sessions/{session_id}/release")
    async def ui_session_release(session_id: str, request: Request) -> RedirectResponse:
        form = await _read_form(request)
        owner = form.get("owner", "operator") or "operator"
        try:
            await maybe_await(sess_mgr.release_takeover(session_id, owner=owner))
        except (KeyError, SessionNotFoundError, TakeoverStateError) as exc:
            safe_err = str(_scrub_and_verify(str(exc), label="error"))
            return RedirectResponse(
                url=f"/?error={quote_plus(safe_err)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    return app
