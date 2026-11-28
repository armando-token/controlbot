"""FastAPI APIRouter for compartmentalized `/api/v1/memory/*` endpoints (CB-07)."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Header, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse

from src.storage.memory import (
    MemoryAccessContext,
    MemoryConflictError,
    MemoryNotFoundError,
    MemoryPermissionError,
    MemoryStore,
    MemoryValidationError,
    normalize_scope,
)
from src.storage.redaction import contains_unredacted_secret_strict, redact_string_strict
from src.web.v1.schemas import MemoryCreateRequest, MemoryPatchRequest


def _raise_memory_http(status_code: int, detail: str | Exception, *, exc: Exception) -> None:
    scrubbed = redact_string_strict(str(detail))
    if contains_unredacted_secret_strict(scrubbed):
        scrubbed = "[REDACTED]"
    raise HTTPException(status_code=status_code, detail=scrubbed) from exc


def _clean_identity(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _build_access_ctx(
    *,
    user_id: str | None,
    agent_role: str | None,
    thread_id: str | None,
    project_area: str | None,
    actor_role: str,
) -> MemoryAccessContext:
    resolved_user = _clean_identity(user_id)
    resolved_agent = _clean_identity(agent_role)
    resolved_thread = _clean_identity(thread_id)
    resolved_project = _clean_identity(project_area)

    if not any([resolved_user, resolved_agent, resolved_thread, resolved_project]):
        resolved_user = "operator"

    return MemoryAccessContext(
        user_id=resolved_user,
        agent_role=resolved_agent,
        thread_id=resolved_thread,
        project_area=resolved_project,
        include_org_approved=True,
        actor_role=actor_role,
    )


def create_memory_router(memory_store: MemoryStore) -> APIRouter:
    """Create `/api/v1/memory/*` FastAPI APIRouter backed by MemoryStore."""
    router = APIRouter(prefix="/api/v1", tags=["v1", "memory"])

    @router.get("/memory")
    async def list_memories(
        scope: str | None = None,
        scope_id: str | None = None,
        kind: str | None = None,
        q: str = "",
        include_expired: bool = False,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        user_id: str | None = None,
        agent_role: str | None = None,
        thread_id: str | None = None,
        project_area: str | None = None,
        actor_role: str | None = None,
        x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
        x_agent_role: Annotated[str | None, Header(alias="X-Agent-Role")] = None,
        x_thread_id: Annotated[str | None, Header(alias="X-Thread-Id")] = None,
        x_project_area: Annotated[str | None, Header(alias="X-Project-Area")] = None,
        x_actor_role: Annotated[str | None, Header(alias="X-Actor-Role")] = None,
    ) -> JSONResponse:
        effective_role = (
            _clean_identity(x_actor_role) or _clean_identity(actor_role) or "Operator"
        )
        try:
            ctx = _build_access_ctx(
                user_id=_clean_identity(x_user_id) or _clean_identity(user_id),
                agent_role=_clean_identity(x_agent_role) or _clean_identity(agent_role),
                thread_id=_clean_identity(x_thread_id) or _clean_identity(thread_id),
                project_area=_clean_identity(x_project_area) or _clean_identity(project_area),
                actor_role=effective_role,
            )
            items = memory_store.list_memories(
                ctx,
                scope=scope,
                scope_id=scope_id,
                kind=kind,
                query=q,
                include_expired=include_expired,
                limit=limit,
            )
        except MemoryValidationError as exc:
            _raise_memory_http(422, exc, exc=exc)
        return JSONResponse(content={"items": items}, status_code=status.HTTP_200_OK)

    @router.get("/memory/export", response_model=None)
    async def export_memories(
        export_format: Annotated[Literal["json", "md"], Query(alias="format")] = "md",
        scope: str | None = None,
        scope_id: str | None = None,
        kind: str | None = None,
        include_expired: bool = False,
        user_id: str | None = None,
        agent_role: str | None = None,
        thread_id: str | None = None,
        project_area: str | None = None,
        actor_role: str | None = None,
        x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
        x_agent_role: Annotated[str | None, Header(alias="X-Agent-Role")] = None,
        x_thread_id: Annotated[str | None, Header(alias="X-Thread-Id")] = None,
        x_project_area: Annotated[str | None, Header(alias="X-Project-Area")] = None,
        x_actor_role: Annotated[str | None, Header(alias="X-Actor-Role")] = None,
    ) -> JSONResponse | Response:
        effective_role = (
            _clean_identity(x_actor_role) or _clean_identity(actor_role) or "Operator"
        )
        try:
            ctx = _build_access_ctx(
                user_id=_clean_identity(x_user_id) or _clean_identity(user_id),
                agent_role=_clean_identity(x_agent_role) or _clean_identity(agent_role),
                thread_id=_clean_identity(x_thread_id) or _clean_identity(thread_id),
                project_area=_clean_identity(x_project_area) or _clean_identity(project_area),
                actor_role=effective_role,
            )
            rendered = memory_store.export_memories(
                ctx,
                fmt=export_format,
                scope=scope,
                scope_id=scope_id,
                kind=kind,
                include_expired=include_expired,
            )
        except MemoryValidationError as exc:
            _raise_memory_http(422, exc, exc=exc)

        if export_format == "json":
            parsed: Any = json.loads(rendered)
            return JSONResponse(content=parsed, status_code=status.HTTP_200_OK)

        return Response(
            content=rendered,
            status_code=status.HTTP_200_OK,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="memory_export.md"'},
        )

    @router.post("/memory", status_code=status.HTTP_201_CREATED)
    async def create_memory(
        payload: MemoryCreateRequest,
        user_id: str | None = None,
        agent_role: str | None = None,
        thread_id: str | None = None,
        project_area: str | None = None,
        actor_role: str | None = None,
        x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
        x_agent_role: Annotated[str | None, Header(alias="X-Agent-Role")] = None,
        x_thread_id: Annotated[str | None, Header(alias="X-Thread-Id")] = None,
        x_project_area: Annotated[str | None, Header(alias="X-Project-Area")] = None,
        x_actor_role: Annotated[str | None, Header(alias="X-Actor-Role")] = None,
    ) -> JSONResponse:
        explicit_user = _clean_identity(x_user_id) or _clean_identity(user_id)
        explicit_agent = _clean_identity(x_agent_role) or _clean_identity(agent_role)
        explicit_thread = _clean_identity(x_thread_id) or _clean_identity(thread_id)
        explicit_project = _clean_identity(x_project_area) or _clean_identity(project_area)
        effective_role = (
            _clean_identity(x_actor_role)
            or _clean_identity(actor_role)
            or "Operator"
        )
        if (
            "actor_role" in payload.model_fields_set
            and (payload.actor_role or "").strip().lower() == "manager"
            and effective_role.strip().lower() != "manager"
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot elevate actor_role to Manager via request body.",
            )
        try:
            norm_scope = normalize_scope(payload.scope)
        except MemoryValidationError as exc:
            _raise_memory_http(422, exc, exc=exc)

        cleaned_scope_id = payload.scope_id.strip()
        has_any_identity = any(
            v is not None
            for v in (explicit_user, explicit_agent, explicit_thread, explicit_project)
        )
        if norm_scope == "user":
            caller_user = explicit_user if has_any_identity else "operator"
            if caller_user is None or cleaned_scope_id != caller_user:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot create user-scoped memory for another user.",
                )
        elif norm_scope == "agent_role":
            if explicit_agent is None or cleaned_scope_id != explicit_agent:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot create agent_role-scoped memory for another role.",
                )
        elif norm_scope == "thread":
            if explicit_thread is None or cleaned_scope_id != explicit_thread:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot create thread-scoped memory for another thread.",
                )
        elif norm_scope == "project_area":
            if explicit_project is None or cleaned_scope_id != explicit_project:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot create project_area-scoped memory for another project area.",
                )
        elif norm_scope == "org_approved" and effective_role.strip().lower() != "manager":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only Manager role can create org_approved memories.",
            )

        try:
            created = memory_store.create_memory(
                scope=norm_scope,
                scope_id=payload.scope_id,
                kind=payload.kind,
                title=payload.title,
                content=payload.content,
                tags=payload.tags,
                observed_at=payload.observed_at,
                valid_until=payload.valid_until,
                provenance=payload.provenance,
                actor_role=effective_role,
                created_by=explicit_user or payload.created_by,
            )
        except MemoryPermissionError as exc:
            _raise_memory_http(status.HTTP_403_FORBIDDEN, exc, exc=exc)
        except MemoryValidationError as exc:
            _raise_memory_http(422, exc, exc=exc)
        return JSONResponse(content=created, status_code=status.HTTP_201_CREATED)

    @router.patch("/memory/{item_id}")
    async def patch_memory(
        item_id: str,
        payload: MemoryPatchRequest,
        user_id: str | None = None,
        agent_role: str | None = None,
        thread_id: str | None = None,
        project_area: str | None = None,
        actor_role: str | None = None,
        x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
        x_agent_role: Annotated[str | None, Header(alias="X-Agent-Role")] = None,
        x_thread_id: Annotated[str | None, Header(alias="X-Thread-Id")] = None,
        x_project_area: Annotated[str | None, Header(alias="X-Project-Area")] = None,
        x_actor_role: Annotated[str | None, Header(alias="X-Actor-Role")] = None,
    ) -> JSONResponse:
        effective_role = (
            _clean_identity(x_actor_role)
            or _clean_identity(actor_role)
            or "Operator"
        )
        if (
            "actor_role" in payload.model_fields_set
            and (payload.actor_role or "").strip().lower() == "manager"
            and effective_role.strip().lower() != "manager"
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot elevate actor_role to Manager via request body.",
            )
        ctx = _build_access_ctx(
            user_id=_clean_identity(x_user_id) or _clean_identity(user_id),
            agent_role=_clean_identity(x_agent_role) or _clean_identity(agent_role),
            thread_id=_clean_identity(x_thread_id) or _clean_identity(thread_id),
            project_area=_clean_identity(x_project_area) or _clean_identity(project_area),
            actor_role=effective_role,
        )

        try:
            updated = memory_store.update_memory(
                item_id,
                expected_revision=payload.revision,
                access_ctx=ctx,
                title=payload.title,
                content=payload.content,
                tags=payload.tags,
                observed_at=payload.observed_at,
                valid_until=payload.valid_until,
                provenance=payload.provenance,
                actor_role=effective_role,
            )
        except MemoryPermissionError as exc:
            _raise_memory_http(status.HTTP_403_FORBIDDEN, exc, exc=exc)
        except MemoryNotFoundError as exc:
            _raise_memory_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        except MemoryConflictError as exc:
            _raise_memory_http(status.HTTP_409_CONFLICT, exc, exc=exc)
        except MemoryValidationError as exc:
            _raise_memory_http(422, exc, exc=exc)
        return JSONResponse(content=updated, status_code=status.HTTP_200_OK)

    @router.delete("/memory/{item_id}")
    async def delete_memory(
        item_id: str,
        user_id: str | None = None,
        agent_role: str | None = None,
        thread_id: str | None = None,
        project_area: str | None = None,
        actor_role: str | None = None,
        x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None,
        x_agent_role: Annotated[str | None, Header(alias="X-Agent-Role")] = None,
        x_thread_id: Annotated[str | None, Header(alias="X-Thread-Id")] = None,
        x_project_area: Annotated[str | None, Header(alias="X-Project-Area")] = None,
        x_actor_role: Annotated[str | None, Header(alias="X-Actor-Role")] = None,
    ) -> JSONResponse:
        effective_role = (
            _clean_identity(x_actor_role) or _clean_identity(actor_role) or "Operator"
        )
        ctx = _build_access_ctx(
            user_id=_clean_identity(x_user_id) or _clean_identity(user_id),
            agent_role=_clean_identity(x_agent_role) or _clean_identity(agent_role),
            thread_id=_clean_identity(x_thread_id) or _clean_identity(thread_id),
            project_area=_clean_identity(x_project_area) or _clean_identity(project_area),
            actor_role=effective_role,
        )

        try:
            memory_store.delete_memory(item_id, access_ctx=ctx, actor_role=effective_role)
        except MemoryPermissionError as exc:
            _raise_memory_http(status.HTTP_403_FORBIDDEN, exc, exc=exc)
        except MemoryNotFoundError as exc:
            _raise_memory_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        return JSONResponse(
            content={"deleted": True, "id": item_id},
            status_code=status.HTTP_200_OK,
        )

    return router
