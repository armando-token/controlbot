"""FastAPI `/api/v1` REST and SSE router for Grok Bot UX/UI workspace."""

from __future__ import annotations

import contextlib
import email.parser
import email.policy
import hmac
import mimetypes
import re
import uuid
from pathlib import Path
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import ValidationError

from src.web.live_browser import (
    LiveBrowserController,
    domain_matches_url,
    domains_compatible,
)
from src.web.live_browser import (
    _candidate_selectors as _candidate_selectors,
)
from src.web.protocols import CoordinatorProtocol
from src.web.v1.events import EventBus, scrub_v1_payload
from src.web.v1.runner import AgentTurnRunner
from src.web.v1.schemas import (
    ApprovalCreateRequest,
    ApprovalResolveRequest,
    ArtifactPinRequest,
    AutoReviewPutRequest,
    BotCreateRequest,
    BotPatchRequest,
    ChannelCreateRequest,
    ChannelPatchRequest,
    ConnectedAppPatchRequest,
    DraftCreateRequest,
    DraftResolveRequest,
    MessageCreateRequest,
    MessageToPageRequest,
    PageCreateRequest,
    PagePatchRequest,
    ReactionRequest,
    RoutineCreateRequest,
    RoutinePatchRequest,
    SectionCreateRequest,
    SectionPatchRequest,
    SecureFillRequest,
    SecureFormCreateRequest,
    SettingsPatchRequest,
    SkillCreateRequest,
    VaultSecretCreateRequest,
)
from src.web.v1.store import (
    StoreConflictError,
    StoreNotFoundError,
    StoreValidationError,
    WorkspaceStore,
)

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_HEADING_RE = re.compile(r"^\s*#{1,3}\s+(.+)$", re.MULTILINE)
_ACTIVE_ATTACHMENT_MIMES: frozenset[str] = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "image/svg+xml",
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
        "application/x-ecmascript",
        "application/xml",
        "text/xml",
        "text/xsl",
        "application/xslt+xml",
    }
)
_ACTIVE_ATTACHMENT_EXTS: frozenset[str] = frozenset(
    {".html", ".htm", ".xhtml", ".svg", ".js", ".mjs", ".xml", ".xsl", ".xslt"}
)


def _json_response(payload: Any, *, status_code: int = status.HTTP_200_OK) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=scrub_v1_payload(payload))


def _raise_http(status_code: int, detail: Any, *, exc: Exception | None = None) -> NoReturn:
    safe_detail = str(scrub_v1_payload(str(detail)))
    if exc is not None:
        raise HTTPException(status_code=status_code, detail=safe_detail) from exc
    raise HTTPException(status_code=status_code, detail=safe_detail)


def _sanitize_filename(raw_name: str | None) -> str:
    base = Path((raw_name or "").strip()).name
    cleaned = _SAFE_FILENAME_RE.sub("_", base).strip("._")
    if not cleaned:
        return "upload.bin"
    return cleaned[:160]


def _parse_multipart_upload(
    content_type: str,
    raw_body: bytes,
) -> tuple[bytes, str | None, str | None, str | None]:
    """Parse multipart/form-data using stdlib email.parser without requiring python-multipart."""
    header_bytes = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode(
        "latin-1", errors="ignore"
    )
    parsed = email.parser.BytesParser(policy=email.policy.default).parsebytes(
        header_bytes + raw_body
    )
    if not parsed.is_multipart():
        return raw_body, None, None, None

    file_bytes: bytes | None = None
    part_filename: str | None = None
    part_mime: str | None = None
    form_thread_id: str | None = None

    for part in parsed.iter_parts():
        field_name = part.get_param("name", header="content-disposition")
        fname = part.get_filename()
        if field_name == "thread_id" and fname is None:
            raw_val = part.get_payload(decode=True)
            if isinstance(raw_val, bytes):
                form_thread_id = raw_val.decode("utf-8", errors="replace").strip() or None
            continue
        if field_name == "file" or (file_bytes is None and fname is not None):
            payload = part.get_payload(decode=True)
            file_bytes = payload if isinstance(payload, bytes) else b""
            part_filename = fname
            part_mime = part.get_content_type()

    return file_bytes if file_bytes is not None else b"", part_filename, part_mime, form_thread_id


def create_v1_router(
    store: WorkspaceStore,
    event_bus: EventBus,
    runner: AgentTurnRunner,
    live_browser: LiveBrowserController,
    uploads_dir: Path,
    coordinator: CoordinatorProtocol,
) -> APIRouter:
    """Create the FastAPI `/api/v1` router implementing REST and SSE workspace endpoints."""
    del coordinator  # Handled via runner for controlbot_runtime turns
    uploads_dir.mkdir(parents=True, exist_ok=True)
    router = APIRouter(prefix="/api/v1", tags=["v1"])

    # ------------------------------------------------------------------
    # Roster, Bots, Sections, Channels
    # ------------------------------------------------------------------

    @router.get("/bots")
    async def list_bots_roster() -> JSONResponse:
        return _json_response(store.list_roster())

    @router.post("/bots", status_code=status.HTTP_201_CREATED)
    async def create_bot(payload: BotCreateRequest) -> JSONResponse:
        try:
            bot = store.create_bot(payload.model_dump())
        except StoreValidationError as exc:
            _raise_http(422, exc, exc=exc)
        return _json_response(bot, status_code=status.HTTP_201_CREATED)

    @router.patch("/bots/{bot_id}")
    async def patch_bot(bot_id: str, payload: BotPatchRequest) -> JSONResponse:
        updates = payload.model_dump(exclude_unset=True)
        try:
            bot = store.update_bot(bot_id, updates)
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        except StoreValidationError as exc:
            _raise_http(422, exc, exc=exc)
        return _json_response(bot)

    @router.delete("/bots/{bot_id}")
    async def delete_bot(bot_id: str) -> JSONResponse:
        existing = store.get_bot(bot_id)
        if existing is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Bot not found: {bot_id}")
        await runner.interrupt(str(existing["thread_id"]))
        store.delete_bot(bot_id)
        return _json_response({"deleted": True, "bot_id": bot_id})

    @router.post("/bots/{bot_id}/clone-template", status_code=status.HTTP_201_CREATED)
    async def clone_bot_template(bot_id: str) -> JSONResponse:
        bot = store.get_bot(bot_id)
        if bot is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Bot not found: {bot_id}")
        skills = store.list_skills(bot_id)
        routines = store.list_routines(bot_id)
        lines = [
            f"# Bot Template: {bot['name']}",
            "",
            "## Profile",
            f"- **Avatar**: `{bot['avatar_shape']}` ({bot['avatar_color']})",
            f"- **Engine**: `{bot['engine_id']}`",
            f"- **Model**: `{bot['model_id']}`",
            f"- **Thinking Level**: `{bot['thinking_level']}`",
            f"- **Project**: `{bot.get('project_name') or 'None'}`",
            f"- **Timezone**: `{bot['timezone']}`",
            "",
            "## Role Instructions",
            bot["role_prompt"] or "_No custom instructions configured._",
        ]
        if skills:
            lines.extend(["", "## Skills"])
            for skl in skills:
                lines.append(f"- **@{skl['slug']}**: {skl['description'] or skl['name']}")
        if routines:
            lines.extend(["", "## Routines"])
            for rtn in routines:
                sched = (
                    rtn["cron_expr"]
                    if rtn["schedule_type"] == "cron"
                    else rtn["schedule_type"]
                )
                lines.append(f"- **{rtn['name']}** (`{sched}`): {rtn['instruction']}")

        template_md = "\n".join(lines)
        title = f"{bot['name']} — Bot Template"
        thread_id = str(bot["thread_id"])

        msg = store.create_message(
            thread_id=thread_id,
            sender_type="bot",
            sender_bot_id=bot_id,
            sender_name=str(bot["name"]),
            content=f"Generated a reusable template page for **{bot['name']}**.",
            status="done",
        )
        artifact, supersedes_msg_id = store.create_or_version_page(
            bot_id=bot_id,
            title=title,
            content_md=template_md,
            thread_id=thread_id,
            message_id=str(msg["id"]),
            share_scope="team",
        )
        updated_msg = store.update_message(
            str(msg["id"]),
            {
                "artifacts": [
                    {
                        "id": artifact["id"],
                        "type": artifact["type"],
                        "title": artifact["title"],
                        "version": artifact["version"],
                        "superseded_by_id": artifact["superseded_by_id"],
                    }
                ]
            },
        )
        event_bus.publish(
            "artifact.page.updated",
            {"artifact": artifact, "supersedes_message_id": supersedes_msg_id},
            bot_id=bot_id,
            thread_id=thread_id,
        )
        event_bus.publish(
            "message.completed",
            {"message_id": updated_msg["id"], "message": updated_msg},
            bot_id=bot_id,
            thread_id=thread_id,
        )
        return _json_response(
            {"artifact": artifact, "message": updated_msg},
            status_code=status.HTTP_201_CREATED,
        )

    @router.post("/sections", status_code=status.HTTP_201_CREATED)
    async def create_section(payload: SectionCreateRequest) -> JSONResponse:
        sec = store.create_section(name=payload.name, sort_order=payload.sort_order)
        return _json_response(sec, status_code=status.HTTP_201_CREATED)

    @router.patch("/sections/{section_id}")
    async def patch_section(section_id: str, payload: SectionPatchRequest) -> JSONResponse:
        try:
            sec = store.update_section(section_id, payload.model_dump(exclude_unset=True))
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        return _json_response(sec)

    @router.delete("/sections/{section_id}")
    async def delete_section(section_id: str) -> JSONResponse:
        deleted = store.delete_section(section_id)
        if not deleted:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Section not found: {section_id}")
        return _json_response({"deleted": True})

    @router.post("/channels", status_code=status.HTTP_201_CREATED)
    async def create_channel(payload: ChannelCreateRequest) -> JSONResponse:
        try:
            channel = store.create_channel(payload.model_dump())
        except StoreValidationError as exc:
            _raise_http(422, exc, exc=exc)
        return _json_response(channel, status_code=status.HTTP_201_CREATED)

    @router.patch("/channels/{channel_id}")
    async def patch_channel(channel_id: str, payload: ChannelPatchRequest) -> JSONResponse:
        try:
            channel = store.update_channel(channel_id, payload.model_dump(exclude_unset=True))
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        except StoreValidationError as exc:
            _raise_http(422, exc, exc=exc)
        return _json_response(channel)

    @router.delete("/channels/{channel_id}")
    async def delete_channel(channel_id: str) -> JSONResponse:
        existing = store.get_channel(channel_id)
        if existing is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Channel not found: {channel_id}")
        await runner.interrupt(str(existing["thread_id"]))
        store.delete_channel(channel_id)
        return _json_response({"deleted": True})

    # ------------------------------------------------------------------
    # Threads & Messages
    # ------------------------------------------------------------------

    @router.get("/threads/{thread_id}/messages")
    async def get_thread_messages(
        thread_id: str,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        before_id: str | None = None,
    ) -> JSONResponse:
        if not store.thread_exists(thread_id):
            _raise_http(status.HTTP_404_NOT_FOUND, f"Thread not found: {thread_id}")
        messages, has_more = store.list_thread_messages(
            thread_id, limit=limit, before_id=before_id
        )
        approvals = store.list_thread_approvals(thread_id)
        drafts = store.list_thread_drafts(thread_id)
        secure_forms = store.list_thread_secure_forms(thread_id)
        return _json_response(
            {
                "thread_id": thread_id,
                "messages": messages,
                "approvals": approvals,
                "drafts": drafts,
                "secure_forms": secure_forms,
                "has_more": has_more,
            }
        )

    @router.post("/threads/{thread_id}/messages", status_code=status.HTTP_202_ACCEPTED)
    async def post_thread_message(
        thread_id: str,
        payload: MessageCreateRequest,
    ) -> JSONResponse:
        if not store.thread_exists(thread_id):
            _raise_http(status.HTTP_404_NOT_FOUND, f"Thread not found: {thread_id}")
        settings = store.get_settings()
        sender_name = str(settings.get("display_name") or "You")
        attachments = store.get_attachments_summary(payload.attachment_ids)
        user_msg = store.create_message(
            thread_id=thread_id,
            sender_type="user",
            sender_bot_id=None,
            sender_name=sender_name,
            content=payload.content,
            reply_to_id=payload.reply_to_id,
            mentions=payload.mentions,
            attachments=attachments,
            status="done",
        )
        turn_id = runner.start_turn(
            thread_id=thread_id,
            user_message=user_msg,
            include_browser_context=payload.include_browser_context,
            model_id=payload.model_id,
            thinking_level=payload.thinking_level,
            skill_ids=payload.skill_ids,
        )
        return _json_response(
            {
                "user_message": user_msg,
                "turn_id": turn_id,
                "status": "accepted",
            },
            status_code=status.HTTP_202_ACCEPTED,
        )

    @router.post("/threads/{thread_id}/interrupt")
    async def interrupt_thread(thread_id: str) -> JSONResponse:
        if not store.thread_exists(thread_id):
            _raise_http(status.HTTP_404_NOT_FOUND, f"Thread not found: {thread_id}")
        interrupted = await runner.interrupt(thread_id)
        return _json_response({"interrupted": interrupted, "thread_id": thread_id})

    @router.post("/messages/{message_id}/reactions")
    async def react_to_message(message_id: str, payload: ReactionRequest) -> JSONResponse:
        try:
            updated = store.apply_reaction(message_id, payload.emoji, action=payload.action)
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        event_bus.publish(
            "message.reaction",
            {
                "message_id": str(updated["id"]),
                "reactions": updated.get("reactions", {}),
                "emoji": payload.emoji,
                "action": payload.action,
                "message": updated,
            },
            bot_id=updated.get("sender_bot_id"),
            thread_id=str(updated["thread_id"]),
        )
        return _json_response(updated)

    @router.post("/messages/{message_id}/to-page", status_code=status.HTTP_201_CREATED)
    async def message_to_page(
        message_id: str,
        payload: MessageToPageRequest | None = None,
    ) -> JSONResponse:
        msg = store.get_message(message_id)
        if msg is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Message not found: {message_id}")
        req = payload or MessageToPageRequest()
        thread_id = str(msg["thread_id"])
        bot_id = msg.get("sender_bot_id")
        if not bot_id:
            bot = store.get_bot_by_thread(thread_id)
            if bot is not None:
                bot_id = bot["id"]
            else:
                chn = store.get_channel_by_thread(thread_id)
                bot_id = chn["bot_ids"][0] if (chn and chn["bot_ids"]) else "bot_chief"

        content = str(msg.get("content") or "")
        title = (req.title or "").strip()
        if not title:
            heading = _HEADING_RE.search(content)
            if heading is not None:
                title = heading.group(1).strip()[:120]
            else:
                first_line = next((ln.strip() for ln in content.splitlines() if ln.strip()), "")
                title = (first_line[:60] or "Saved Page").strip("#*` ")

        page, supersedes_msg_id = store.create_or_version_page(
            bot_id=str(bot_id),
            title=title,
            content_md=content,
            thread_id=thread_id,
            message_id=message_id,
            share_scope=req.share_scope,
        )
        existing_arts = list(msg.get("artifacts") or [])
        existing_arts.append(
            {
                "id": page["id"],
                "type": page["type"],
                "title": page["title"],
                "version": page["version"],
                "superseded_by_id": page["superseded_by_id"],
            }
        )
        updated_msg = store.update_message(message_id, {"artifacts": existing_arts})
        event_bus.publish(
            "artifact.page.updated",
            {"artifact": page, "supersedes_message_id": supersedes_msg_id},
            bot_id=str(bot_id),
            thread_id=thread_id,
        )
        event_bus.publish(
            "message.completed",
            {"message_id": updated_msg["id"], "message": updated_msg},
            bot_id=str(bot_id),
            thread_id=thread_id,
        )
        return _json_response(
            {"page": page, "message": updated_msg},
            status_code=status.HTTP_201_CREATED,
        )

    # ------------------------------------------------------------------
    # Attachments, Library, Pages
    # ------------------------------------------------------------------

    @router.post("/attachments", status_code=status.HTTP_201_CREATED)
    async def upload_attachment(
        request: Request,
        filename: str | None = None,
        thread_id: str | None = None,
    ) -> JSONResponse:
        raw_content_len = request.headers.get("content-length")
        if raw_content_len is not None:
            with contextlib.suppress(ValueError):
                if int(raw_content_len) > _MAX_UPLOAD_BYTES:
                    _raise_http(
                        status.HTTP_413_CONTENT_TOO_LARGE,
                        f"Attachment exceeds maximum size of {_MAX_UPLOAD_BYTES} bytes.",
                    )

        buf = bytearray()
        async for chunk in request.stream():
            if not chunk:
                continue
            if len(buf) + len(chunk) > _MAX_UPLOAD_BYTES:
                _raise_http(
                    status.HTTP_413_CONTENT_TOO_LARGE,
                    f"Attachment exceeds maximum size of {_MAX_UPLOAD_BYTES} bytes.",
                )
            buf.extend(chunk)
        raw_body = bytes(buf)

        content_type = request.headers.get("content-type", "")
        if content_type.lower().startswith("multipart/form-data"):
            file_bytes, part_filename, part_mime, form_thread_id = _parse_multipart_upload(
                content_type, raw_body
            )
            resolved_name = _sanitize_filename(filename or part_filename)
            resolved_thread = thread_id or form_thread_id
            guessed = mimetypes.guess_type(resolved_name)[0]
            resolved_mime = (
                part_mime
                if part_mime and part_mime != "application/octet-stream"
                else (guessed or part_mime or "application/octet-stream")
            )
        else:
            file_bytes = raw_body
            resolved_name = _sanitize_filename(filename)
            resolved_thread = thread_id
            base_ct = content_type.split(";", 1)[0].strip()
            guessed = mimetypes.guess_type(resolved_name)[0]
            resolved_mime = (
                base_ct
                if base_ct and base_ct != "application/octet-stream"
                else (guessed or "application/octet-stream")
            )

        att_id = f"att_{uuid.uuid4().hex[:12]}"
        dest_path = (uploads_dir / f"{att_id}_{resolved_name}").resolve()
        if not dest_path.is_relative_to(uploads_dir.resolve()):
            _raise_http(status.HTTP_400_BAD_REQUEST, "Invalid attachment filename.")
        dest_path.write_bytes(file_bytes)

        bot_id: str | None = None
        if resolved_thread:
            bot = store.get_bot_by_thread(resolved_thread)
            if bot is not None:
                bot_id = str(bot["id"])

        try:
            record = store.create_attachment(
                att_id,
                thread_id=resolved_thread,
                bot_id=bot_id,
                filename=resolved_name,
                mime_type=resolved_mime,
                size_bytes=len(file_bytes),
                storage_path=str(dest_path),
            )

            if bot_id is not None:
                art_type = (
                    "media"
                    if resolved_mime.startswith(("image/", "video/", "audio/"))
                    else "file"
                )
                store.create_artifact(
                    bot_id=bot_id,
                    artifact_type=art_type,
                    title=resolved_name,
                    thread_id=resolved_thread,
                    url=f"/api/v1/attachments/{att_id}",
                    file_path=resolved_name,
                    mime_type=resolved_mime,
                    size_bytes=len(file_bytes),
                )
        except Exception:
            with contextlib.suppress(OSError):
                dest_path.unlink(missing_ok=True)
            raise

        return _json_response(record, status_code=status.HTTP_201_CREATED)

    @router.get("/attachments/{attachment_id}")
    async def download_attachment(attachment_id: str) -> Response:
        record = store.get_attachment_record(attachment_id)
        if record is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Attachment not found: {attachment_id}")
        file_path = Path(str(record["storage_path"])).resolve()
        if not file_path.is_relative_to(uploads_dir.resolve()) or not file_path.is_file():
            _raise_http(status.HTTP_404_NOT_FOUND, f"Attachment file missing: {attachment_id}")
        safe_disp = _sanitize_filename(str(record["filename"]))
        base_mime = str(record["mime_type"]).split(";", 1)[0].strip().lower()
        is_active = (
            base_mime in _ACTIVE_ATTACHMENT_MIMES
            or Path(safe_disp).suffix.lower() in _ACTIVE_ATTACHMENT_EXTS
        )
        disposition = "attachment" if is_active else "inline"
        return Response(
            content=file_path.read_bytes(),
            media_type=str(record["mime_type"]),
            headers={
                "Content-Disposition": f'{disposition}; filename="{safe_disp}"',
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "sandbox; default-src 'none'",
            },
        )

    @router.get("/bots/{bot_id}/library")
    async def get_bot_library(
        bot_id: str,
        artifact_type: Annotated[str, Query(alias="type")] = "all",
        pinned: bool = False,
        q: str = "",
    ) -> JSONResponse:
        if store.get_bot(bot_id) is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Bot not found: {bot_id}")
        library = store.list_bot_library(
            bot_id,
            artifact_type=artifact_type,
            pinned_only=pinned,
            query=q,
        )
        return _json_response(library)

    @router.post("/pages", status_code=status.HTTP_201_CREATED)
    async def create_page(request: Request) -> JSONResponse:
        try:
            raw_json = await request.json()
        except (ValueError, UnicodeDecodeError) as exc:
            _raise_http(status.HTTP_400_BAD_REQUEST, "Invalid JSON body.", exc=exc)
        if not isinstance(raw_json, dict):
            _raise_http(422, "Page payload must be a JSON object.")

        raw_body: dict[str, Any] = dict(raw_json)
        raw_bot_id = str(raw_body.get("bot_id") or "").strip()
        raw_channel_id = str(raw_body.get("channel_id") or "").strip() or None
        raw_thread_id = str(raw_body.get("thread_id") or "").strip() or None

        if not raw_bot_id:
            if raw_channel_id:
                chn = store.get_channel(raw_channel_id)
                if chn is None:
                    _raise_http(status.HTTP_404_NOT_FOUND, f"Channel not found: {raw_channel_id}")
                bot_ids = list(chn.get("bot_ids") or [])
                if not bot_ids:
                    _raise_http(422, f"Channel {raw_channel_id} has no bots.")
                raw_body["bot_id"] = str(bot_ids[0])
                if not raw_thread_id:
                    raw_body["thread_id"] = str(chn["thread_id"])
            elif raw_thread_id:
                chn = store.get_channel_by_thread(raw_thread_id)
                if chn is not None and chn.get("bot_ids"):
                    raw_body["bot_id"] = str(chn["bot_ids"][0])
                else:
                    bot_by_thr = store.get_bot_by_thread(raw_thread_id)
                    if bot_by_thr is not None:
                        raw_body["bot_id"] = str(bot_by_thr["id"])

        try:
            payload = PageCreateRequest.model_validate(raw_body)
        except ValidationError as exc:
            raise RequestValidationError(exc.errors()) from exc

        resolved_bot_id = str(
            getattr(payload, "bot_id", None) or raw_body.get("bot_id") or ""
        ).strip()
        if not resolved_bot_id:
            _raise_http(422, "bot_id or channel_id is required to create a page.")
        bot = store.get_bot(resolved_bot_id)
        if bot is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Bot not found: {resolved_bot_id}")
        thread_id = payload.thread_id or raw_thread_id or str(bot["thread_id"])
        page, supersedes_msg_id = store.create_or_version_page(
            bot_id=resolved_bot_id,
            title=payload.title,
            content_md=payload.content_md,
            thread_id=thread_id,
            message_id=payload.message_id,
            pinned=payload.pinned,
            share_scope=payload.share_scope,
        )
        event_bus.publish(
            "artifact.page.updated",
            {"artifact": page, "supersedes_message_id": supersedes_msg_id},
            bot_id=resolved_bot_id,
            thread_id=thread_id,
        )
        return _json_response(page, status_code=status.HTTP_201_CREATED)

    @router.get("/pages/{page_id}")
    async def get_page(page_id: str) -> JSONResponse:
        page = store.get_artifact(page_id)
        if page is None or page["type"] != "page":
            _raise_http(status.HTTP_404_NOT_FOUND, f"Page not found: {page_id}")
        return _json_response(page)

    @router.patch("/pages/{page_id}")
    async def patch_page(page_id: str, payload: PagePatchRequest) -> JSONResponse:
        try:
            page = store.update_page(page_id, payload.model_dump(exclude_unset=True))
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        event_bus.publish(
            "artifact.page.updated",
            {"artifact": page},
            bot_id=str(page["bot_id"]),
            thread_id=page.get("thread_id"),
        )
        return _json_response(page)

    @router.patch("/artifacts/{artifact_id}/pin")
    async def pin_artifact(artifact_id: str, payload: ArtifactPinRequest) -> JSONResponse:
        try:
            artifact = store.pin_artifact(artifact_id, payload.pinned)
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        return _json_response(artifact)

    @router.delete("/artifacts/{artifact_id}")
    async def delete_artifact(artifact_id: str) -> JSONResponse:
        existing = store.get_artifact(artifact_id)
        if existing is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Artifact not found: {artifact_id}")
        deleted: Any = store.delete_artifact(artifact_id)
        if not deleted:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Artifact not found: {artifact_id}")

        uploads_root = uploads_dir.resolve()
        if isinstance(deleted, dict) and deleted.get("attachment_path"):
            candidate = Path(str(deleted["attachment_path"])).resolve()
            if candidate.is_relative_to(uploads_root) and candidate.is_file():
                with contextlib.suppress(OSError):
                    candidate.unlink(missing_ok=True)
        else:
            att_url = str(existing.get("url") or "")
            if att_url.startswith("/api/v1/attachments/"):
                att_id = att_url.removeprefix("/api/v1/attachments/").split("?", 1)[0].strip()
                if att_id:
                    att_rec = store.get_attachment_record(att_id)
                    if att_rec is not None:
                        bot_id_str = str(existing["bot_id"])
                        still_in_lib = any(
                            str(item.get("url") or "") == att_url
                            for item in store.list_bot_library(bot_id_str).get("items", [])
                        )
                        still_in_thread = False
                        thr_id = existing.get("thread_id")
                        if thr_id:
                            msgs, _ = store.list_thread_messages(str(thr_id), limit=200)
                            still_in_thread = any(
                                any(
                                    str(a.get("id") or "") == att_id
                                    for a in m.get("attachments", [])
                                )
                                for m in msgs
                            )
                        if not still_in_lib and not still_in_thread:
                            candidate = Path(str(att_rec["storage_path"])).resolve()
                            if candidate.is_relative_to(uploads_root) and candidate.is_file():
                                with contextlib.suppress(OSError):
                                    candidate.unlink(missing_ok=True)

        event_bus.publish(
            "artifact.deleted",
            {
                "artifact_id": artifact_id,
                "bot_id": str(existing["bot_id"]),
                "thread_id": existing.get("thread_id"),
                "type": existing.get("type"),
            },
            bot_id=str(existing["bot_id"]),
            thread_id=existing.get("thread_id"),
        )
        return _json_response({"deleted": True})

    # ------------------------------------------------------------------
    # HITL: Approvals, Drafts, Secure Forms, Vault, Auto-Review
    # ------------------------------------------------------------------

    @router.post("/approvals", status_code=status.HTTP_201_CREATED)
    async def create_approval(payload: ApprovalCreateRequest) -> JSONResponse:
        appr = store.create_approval(
            bot_id=payload.bot_id,
            thread_id=payload.thread_id,
            kind=payload.kind,
            title=payload.title,
            target=payload.target,
            risk_banner=payload.risk_banner,
            arguments=payload.arguments,
            allow_always_allowed=payload.allow_always_allowed,
            waiting_for_user=payload.waiting_for_user,
            expires_in_minutes=payload.expires_in_minutes,
        )
        with contextlib.suppress(StoreNotFoundError):
            store.update_bot(
                payload.bot_id,
                {
                    "status_state": "waiting_human",
                    "needs_attention": True,
                    "status_subtext": f"Waiting: {payload.title[:80]}",
                },
            )
        event_bus.publish(
            "hitl.approval.requested",
            {"approval": appr},
            bot_id=payload.bot_id,
            thread_id=payload.thread_id,
        )
        event_bus.publish(
            "bot.presence",
            {
                "state": "waiting_human",
                "subtext": f"Waiting: {payload.title[:80]}",
                "computer_active": False,
            },
            bot_id=payload.bot_id,
            thread_id=payload.thread_id,
        )
        return _json_response(appr, status_code=status.HTTP_201_CREATED)

    @router.post("/approvals/{approval_id}/resolve")
    async def resolve_approval(
        approval_id: str,
        payload: ApprovalResolveRequest,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        try:
            resolved = store.resolve_approval(
                approval_id,
                payload.decision,
                decision_by=payload.decision_by,
                idempotency_key=idempotency_key,
            )
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        except StoreConflictError as exc:
            _raise_http(status.HTTP_409_CONFLICT, exc, exc=exc)
        except StoreValidationError as exc:
            _raise_http(422, exc, exc=exc)

        event_bus.publish(
            "hitl.approval.resolved",
            {"approval": resolved},
            bot_id=str(resolved["bot_id"]),
            thread_id=str(resolved["thread_id"]),
        )
        await runner.on_approval_resolved(
            resolved,
            decision=payload.decision,
            rule_text=payload.rule_text,
        )
        return _json_response(resolved)

    @router.post("/drafts", status_code=status.HTTP_201_CREATED)
    async def create_draft(payload: DraftCreateRequest) -> JSONResponse:
        draft = store.create_draft(
            bot_id=payload.bot_id,
            thread_id=payload.thread_id,
            channel_type=payload.channel_type,
            fields=payload.fields,
        )
        event_bus.publish(
            "hitl.draft.created",
            {"draft": draft},
            bot_id=payload.bot_id,
            thread_id=payload.thread_id,
        )
        return _json_response(draft, status_code=status.HTTP_201_CREATED)

    @router.post("/drafts/{draft_id}/resolve")
    async def resolve_draft(
        draft_id: str,
        payload: DraftResolveRequest,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        action = payload.action or "send"
        try:
            updated = store.resolve_draft(
                draft_id,
                action,
                fields=payload.fields,
                idempotency_key=idempotency_key,
            )
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        except StoreConflictError as exc:
            _raise_http(status.HTTP_409_CONFLICT, exc, exc=exc)
        except StoreValidationError as exc:
            _raise_http(422, exc, exc=exc)

        event_bus.publish(
            "hitl.draft.updated",
            {"draft": updated},
            bot_id=str(updated["bot_id"]),
            thread_id=str(updated["thread_id"]),
        )
        return _json_response(updated)

    @router.post("/secure-forms", status_code=status.HTTP_201_CREATED)
    async def create_secure_form(payload: SecureFormCreateRequest) -> JSONResponse:
        form = store.create_secure_form(
            bot_id=payload.bot_id,
            thread_id=payload.thread_id,
            kind=payload.kind,
            domain=payload.domain,
            title=payload.title,
            fields=[f.model_dump() for f in payload.fields],
            allow_vault_save=payload.allow_vault_save,
        )
        event_bus.publish(
            "hitl.secure_form.requested",
            {"form": form},
            bot_id=payload.bot_id,
            thread_id=payload.thread_id,
        )
        return _json_response(form, status_code=status.HTTP_201_CREATED)

    @router.post("/vault/secure-fill")
    async def vault_secure_fill(request: Request, payload: SecureFillRequest) -> JSONResponse:
        # Secrets are NEVER written to logs, chat messages, transcripts, or SSE events.
        form = store.get_secure_form(payload.form_id) if payload.form_id else None
        if payload.form_id and form is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Secure form not found: {payload.form_id}")

        action: Any = getattr(payload, "action", None)
        if action is None:
            with contextlib.suppress(Exception):
                raw_json = await request.json()
                if isinstance(raw_json, dict):
                    action = raw_json.get("action")
        action_norm = str(action or "submit").strip().lower()

        if action_norm == "cancel":
            if form is None:
                _raise_http(
                    status.HTTP_400_BAD_REQUEST,
                    "form_id is required to cancel a secure form.",
                )
            if payload.bot_id and str(payload.bot_id) != str(form["bot_id"]):
                _raise_http(status.HTTP_403_FORBIDDEN, "bot_id does not match secure form.")
            if form["status"] != "pending":
                _raise_http(
                    status.HTTP_409_CONFLICT,
                    f"Secure form {form['id']} already resolved with status '{form['status']}'.",
                )
            updated_form = store.resolve_secure_form(str(form["id"]), status="cancelled")
            event_bus.publish(
                "hitl.secure_form.resolved",
                {"form": updated_form},
                bot_id=str(updated_form["bot_id"]),
                thread_id=str(updated_form["thread_id"]),
            )
            return _json_response(
                {
                    "filled": False,
                    "saved_secret_id": None,
                    "status": "cancelled",
                    "message": "Secure form cancelled.",
                }
            )

        form_domain = str(form.get("domain") or "").strip() if form is not None else ""
        payload_domain = payload.domain.strip()
        if form is not None:
            if form["status"] != "pending":
                _raise_http(
                    status.HTTP_409_CONFLICT,
                    f"Secure form {form['id']} already resolved with status '{form['status']}'.",
                )
            if payload.bot_id and str(payload.bot_id) != str(form["bot_id"]):
                _raise_http(status.HTTP_403_FORBIDDEN, "bot_id does not match secure form.")
            if (
                payload_domain
                and form_domain
                and not domains_compatible(payload_domain, form_domain)
            ):
                _raise_http(
                    status.HTTP_409_CONFLICT,
                    "domain does not match secure form domain.",
                )

        effective_bot_id = (payload.bot_id or "").strip() or (
            str(form["bot_id"]) if form else None
        )
        expected_domain = form_domain if form_domain else payload_domain
        secret_domain = ""

        fill_values: dict[str, str] = {
            str(k): str(v) for k, v in payload.values.items() if str(k).strip()
        }
        used_vault_secret = False
        if not fill_values and payload.secret_id:
            getter = getattr(store, "get_vault_secret", None)
            secret_meta: dict[str, Any] | None
            if callable(getter):
                secret_meta = getter(payload.secret_id)
            else:
                secret_meta = next(
                    (s for s in store.list_vault_secrets() if s["id"] == payload.secret_id),
                    None,
                )
            if secret_meta is None:
                _raise_http(
                    status.HTTP_404_NOT_FOUND,
                    f"Vault secret not found: {payload.secret_id}",
                )
            secret_bot_id = secret_meta.get("bot_id")
            if secret_bot_id is not None and (
                not effective_bot_id or str(secret_bot_id) != str(effective_bot_id)
            ):
                _raise_http(
                    status.HTTP_403_FORBIDDEN,
                    "Vault secret does not belong to this bot.",
                )
            secret_domain = str(secret_meta.get("domain") or "").strip()
            if secret_domain:
                for target_dom in (form_domain, payload_domain):
                    if target_dom and not domains_compatible(secret_domain, target_dom):
                        _raise_http(
                            status.HTTP_403_FORBIDDEN,
                            "Vault secret domain does not match target domain.",
                        )
            if not expected_domain:
                expected_domain = secret_domain

            decrypted = store.decrypt_vault_secret(payload.secret_id)
            if decrypted is None:
                _raise_http(
                    status.HTTP_404_NOT_FOUND,
                    f"Vault secret not found: {payload.secret_id}",
                )
            used_vault_secret = True
            fill_values = decrypted

        required_domains: list[str] = []
        for dom in (form_domain, payload_domain, secret_domain):
            if dom and dom not in required_domains:
                required_domains.append(dom)

        is_secret_only_form = form is not None and form.get("kind") == "secret"
        filled = False
        browser_running = live_browser.running
        if not is_secret_only_form:
            strict_fill = form is not None or not payload.save_to_vault
            if strict_fill:
                if not browser_running:
                    _raise_http(
                        status.HTTP_409_CONFLICT,
                        "Live browser is not running; "
                        "open the target page before filling credentials.",
                    )
                if not required_domains:
                    _raise_http(
                        status.HTTP_409_CONFLICT,
                        "Target domain is required for secure browser fill.",
                    )
                fill_res = await live_browser.fill_credentials(
                    fill_values,
                    expected_domain=required_domains,
                )
                if not fill_res["filled"]:
                    reason = str(fill_res.get("reason") or "fill_failed")
                    if reason == "origin_mismatch":
                        _raise_http(
                            status.HTTP_409_CONFLICT,
                            "Active browser URL does not match target domain.",
                        )
                    _raise_http(
                        status.HTTP_409_CONFLICT,
                        f"Could not fill credentials into active page ({reason}).",
                    )
                filled = True
            elif browser_running:
                if not required_domains:
                    if used_vault_secret:
                        _raise_http(
                            status.HTTP_409_CONFLICT,
                            "Target domain is required to fill a Vault secret.",
                        )
                else:
                    active_url = live_browser.current_url() or ""
                    if not all(
                        domain_matches_url(dom, active_url) for dom in required_domains
                    ):
                        _raise_http(
                            status.HTTP_409_CONFLICT,
                            "Active browser URL does not match target domain.",
                        )
                    if fill_values:
                        fill_res = await live_browser.fill_credentials(
                            fill_values,
                            expected_domain=required_domains,
                        )
                        if not fill_res["filled"] and fill_res.get("reason") in {
                            "origin_mismatch",
                            "domain_required",
                        }:
                            _raise_http(
                                status.HTTP_409_CONFLICT,
                                "Active browser URL does not match target domain.",
                            )
                        filled = bool(fill_res["filled"])

        saved_secret_id: str | None = None
        allow_save = True if form is None else bool(form.get("allow_vault_save", True))
        if payload.save_to_vault and fill_values and allow_save:
            username_hint = ""
            for key, val in fill_values.items():
                low = key.lower()
                if any(tok in low for tok in ("user", "email", "login")) and "pass" not in low:
                    username_hint = val[:120]
                    break
            vault_name = (
                (payload.vault_name or "").strip()
                or (f"{expected_domain} credentials" if expected_domain else "Saved credentials")
            )
            meta = store.create_vault_secret(
                bot_id=effective_bot_id,
                name=vault_name,
                domain=expected_domain,
                username_hint=username_hint,
                fields=fill_values,
            )
            saved_secret_id = str(meta["id"])

        if form is not None and (filled or is_secret_only_form):
            updated_form = store.resolve_secure_form(str(form["id"]), status="submitted")
            event_bus.publish(
                "hitl.secure_form.resolved",
                {"form": updated_form},
                bot_id=str(updated_form["bot_id"]),
                thread_id=str(updated_form["thread_id"]),
            )

        if filled:
            msg_text = "Filled into the page. Secret values were never shown to your Bot."
        elif is_secret_only_form:
            msg_text = "Secret saved. Secret values were never shown to your Bot."
        elif browser_running and not required_domains:
            msg_text = (
                "Saved to Vault (no target domain specified; browser not filled; "
                "secret values were never shown to your Bot)."
            )
        elif browser_running:
            msg_text = (
                "Saved to Vault (no matching inputs filled on active page; "
                "secret values were never shown to your Bot)."
            )
        else:
            msg_text = (
                "Saved to Vault (live browser not running; "
                "secret values were never shown to your Bot)."
            )

        return _json_response(
            {
                "filled": filled,
                "saved_secret_id": saved_secret_id,
                "message": msg_text,
            }
        )

    @router.get("/vault/secrets")
    async def list_vault_secrets(bot_id: str | None = None) -> JSONResponse:
        return _json_response({"secrets": store.list_vault_secrets(bot_id=bot_id)})

    @router.post("/vault/secrets", status_code=status.HTTP_201_CREATED)
    async def create_vault_secret(payload: VaultSecretCreateRequest) -> JSONResponse:
        fields = dict(payload.fields)
        if payload.username and "username" not in fields:
            fields["username"] = payload.username
        if payload.secret_value and "password" not in fields:
            fields["password"] = payload.secret_value
        username_hint = payload.username or fields.get("username") or fields.get("email") or ""
        meta = store.create_vault_secret(
            bot_id=payload.bot_id,
            name=payload.name,
            domain=payload.domain,
            username_hint=username_hint[:120],
            fields=fields,
        )
        return _json_response(meta, status_code=status.HTTP_201_CREATED)

    @router.delete("/vault/secrets/{secret_id}")
    async def delete_vault_secret(secret_id: str) -> JSONResponse:
        deleted = store.delete_vault_secret(secret_id)
        if not deleted:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Vault secret not found: {secret_id}")
        return _json_response({"deleted": True})

    @router.get("/settings/auto-review")
    async def get_auto_review_rules() -> JSONResponse:
        return _json_response({"rules": store.list_auto_review_rules()})

    @router.put("/settings/auto-review")
    async def put_auto_review_rules(payload: AutoReviewPutRequest) -> JSONResponse:
        try:
            rules = store.replace_auto_review_rules([r.model_dump() for r in payload.rules])
        except StoreValidationError as exc:
            _raise_http(422, exc, exc=exc)
        return _json_response({"rules": rules})

    # ------------------------------------------------------------------
    # Routines & Skills
    # ------------------------------------------------------------------

    @router.get("/bots/{bot_id}/routines")
    async def list_bot_routines(bot_id: str) -> JSONResponse:
        if store.get_bot(bot_id) is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Bot not found: {bot_id}")
        return _json_response({"routines": store.list_routines(bot_id=bot_id)})

    @router.post("/bots/{bot_id}/routines", status_code=status.HTTP_201_CREATED)
    async def create_bot_routine(
        bot_id: str,
        payload: RoutineCreateRequest,
    ) -> JSONResponse:
        try:
            routine = store.create_routine(bot_id, payload.model_dump())
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        except StoreValidationError as exc:
            _raise_http(422, exc, exc=exc)
        return _json_response(routine, status_code=status.HTTP_201_CREATED)

    @router.patch("/routines/{routine_id}")
    async def patch_routine(routine_id: str, payload: RoutinePatchRequest) -> JSONResponse:
        try:
            routine = store.update_routine(routine_id, payload.model_dump(exclude_unset=True))
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        return _json_response(routine)

    @router.delete("/routines/{routine_id}")
    async def delete_routine(routine_id: str) -> JSONResponse:
        deleted = store.delete_routine(routine_id)
        if not deleted:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Routine not found: {routine_id}")
        return _json_response({"deleted": True})

    @router.post("/routines/{routine_id}/test", status_code=status.HTTP_202_ACCEPTED)
    async def test_routine(routine_id: str) -> JSONResponse:
        try:
            run = await runner.execute_routine(routine_id, trigger="manual")
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        return _json_response(run, status_code=status.HTTP_202_ACCEPTED)

    @router.post("/webhooks/routines/{routine_id}", status_code=status.HTTP_202_ACCEPTED)
    async def webhook_trigger_routine(
        routine_id: str,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> JSONResponse:
        routine = store.get_routine(routine_id)
        if routine is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Routine not found: {routine_id}")
        if not authorization or not authorization.lower().startswith("bearer "):
            _raise_http(status.HTTP_401_UNAUTHORIZED, "Missing Bearer webhook key.")
        provided = authorization[7:].strip()
        if not provided or not hmac.compare_digest(provided, str(routine["webhook_key"])):
            _raise_http(status.HTTP_401_UNAUTHORIZED, "Invalid routine webhook key.")
        if not routine["enabled"]:
            _raise_http(status.HTTP_409_CONFLICT, "Routine is currently disabled.")
        run = await runner.execute_routine(routine_id, trigger="webhook")
        return _json_response(run, status_code=status.HTTP_202_ACCEPTED)

    @router.get("/routines/{routine_id}/runs")
    async def list_routine_runs(routine_id: str) -> JSONResponse:
        if store.get_routine(routine_id) is None:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Routine not found: {routine_id}")
        return _json_response({"runs": store.list_routine_runs(routine_id)})

    @router.get("/skills")
    async def list_skills(bot_id: str | None = None) -> JSONResponse:
        return _json_response({"skills": store.list_skills(bot_id=bot_id)})

    @router.post("/skills", status_code=status.HTTP_201_CREATED)
    async def create_skill(payload: SkillCreateRequest) -> JSONResponse:
        skill = store.create_skill(payload.model_dump())
        return _json_response(skill, status_code=status.HTTP_201_CREATED)

    @router.delete("/skills/{skill_id}")
    async def delete_skill(skill_id: str) -> JSONResponse:
        deleted = store.delete_skill(skill_id)
        if not deleted:
            _raise_http(status.HTTP_404_NOT_FOUND, f"Skill not found: {skill_id}")
        return _json_response({"deleted": True})

    # ------------------------------------------------------------------
    # Settings, Connected Apps, Usage, Search
    # ------------------------------------------------------------------

    @router.get("/settings")
    async def get_settings() -> JSONResponse:
        return _json_response(store.get_settings())

    @router.patch("/settings")
    async def patch_settings(payload: SettingsPatchRequest) -> JSONResponse:
        updated = store.update_settings(payload.model_dump(exclude_unset=True))
        return _json_response(updated)

    @router.get("/apps")
    async def list_connected_apps() -> JSONResponse:
        return _json_response({"apps": store.list_connected_apps()})

    @router.patch("/apps/{app_id}")
    async def patch_connected_app(
        app_id: str,
        payload: ConnectedAppPatchRequest,
    ) -> JSONResponse:
        try:
            updated = store.update_connected_app(app_id, payload.model_dump(exclude_unset=True))
        except StoreNotFoundError as exc:
            _raise_http(status.HTTP_404_NOT_FOUND, exc, exc=exc)
        return _json_response(updated)

    @router.get("/usage")
    async def get_usage() -> JSONResponse:
        return _json_response(store.get_usage(active_turns=runner.active_turns_count))

    @router.get("/search")
    async def search_workspace(q: str = "") -> JSONResponse:
        return _json_response(store.search(q))

    # ------------------------------------------------------------------
    # SSE Event Stream
    # ------------------------------------------------------------------

    @router.get("/events/stream")
    async def stream_events(
        request: Request,
        last_event_id: str | None = None,
    ) -> StreamingResponse:
        effective_last_id = last_event_id or request.headers.get("last-event-id")
        return StreamingResponse(
            event_bus.stream_sse(effective_last_id, keepalive_seconds=15.0),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return router
