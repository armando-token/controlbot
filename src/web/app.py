"""FastAPI local operator API and minimal observability UI."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote_plus

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from pydantic import ValidationError

from src.adapters.sessions import (
    SessionBusyError,
    SessionLockState,
    SessionManager,
    SessionNotFoundError,
    TakeoverStateError,
)
from src.contracts.common import InvalidStateTransitionError, PlanValidationError
from src.contracts.models import ActionReceipt, Run
from src.storage.errors import ConflictError, NotFoundError
from src.storage.redaction import (
    contains_unredacted_secret_strict,
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

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _scrub_and_verify(payload: Any, *, label: str = "payload") -> Any:
    scrubbed = redact_payload_strict(payload)
    if contains_unredacted_secret_strict(scrubbed):
        raise ValueError(f"{label} serialization failed redaction check.")
    return scrubbed


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
    coord: CoordinatorProtocol = (
        coordinator if coordinator is not None else InMemoryCoordinatorStub()
    )
    owns_session_manager = session_manager is None
    internal_sm: SessionManager | None = None
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

    jinja_env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
    )
    templates = Jinja2Templates(env=jinja_env)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owns_session_manager and internal_sm is not None:
                await internal_sm.close_all()

    app = FastAPI(title="Grokbotclon Local Operator Console", version="1.0.0", lifespan=lifespan)
    app.state.db_path = str(resolved_db) if resolved_db is not None else None
    app.state.coordinator = coord
    app.state.session_manager = sess_mgr

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
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=_serialize_snapshot(snapshot),
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
        raw = (await request.body()).decode("utf-8")
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
            run = await maybe_await(coord.submit_task(req.to_task_spec()))
        except (ValidationError, ConflictError, PlanValidationError) as exc:
            safe_err = str(_scrub_and_verify(str(exc), label="error"))
            return RedirectResponse(
                url=f"/?error={quote_plus(safe_err)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        return RedirectResponse(
            url=f"/tasks/{run.run_id}",
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
        return RedirectResponse(
            url=f"/tasks/{run_id}",
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
        return RedirectResponse(
            url=f"/tasks/{run_id}",
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
