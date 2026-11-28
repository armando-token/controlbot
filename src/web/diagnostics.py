"""Structured failure detection, request/WS telemetry, and diagnostics API.

Captures backend HTTP 4xx/5xx responses, unhandled exceptions with tracebacks,
WebSocket abnormal closes/errors, Python WARNING/ERROR log records, SSE error
events, and frontend browser errors into secret-redacted JSONL logs under
``<state_dir>/logs/``.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import traceback
import uuid
from collections import Counter, deque
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode

from fastapi import APIRouter, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.storage.redaction import redact_payload_strict, redact_string_strict

_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "token",
        "cap_token",
        "access_token",
        "auth",
        "key",
        "api_key",
        "secret",
        "password",
        "webhook_key",
    }
)
_VAULT_PATHS = ("/api/v1/vault", "/api/v1/secure-forms")
_MAX_BODY_CAPTURE_BYTES = 2048
_MAX_LOG_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB per file before .1 rotation
_NORMAL_WS_CLOSE_CODES = frozenset({1000, 1001, 1005})


def _utc_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def scrub_query_string(raw_qs: bytes | bytearray | str) -> str:
    """Redact sensitive query parameters such as `?token=` and `?cap_token=`."""
    qs = (
        raw_qs.decode("latin-1", errors="replace")
        if isinstance(raw_qs, (bytes, bytearray))
        else str(raw_qs)
    )
    if not qs:
        return ""
    pairs = parse_qsl(qs, keep_blank_values=True)
    if not pairs:
        return ""
    scrubbed: list[tuple[str, str]] = []
    for k, v in pairs:
        k_low = k.lower()
        if k_low in _SENSITIVE_QUERY_KEYS or any(
            marker in k_low for marker in ("token", "secret", "password", "key", "auth")
        ):
            scrubbed.append((k, REDACTED_PLACEHOLDER))
        else:
            scrubbed.append((k, redact_string_strict(v)[:200]))
    return urlencode(scrubbed)


def scrub_url(url: str) -> str:
    """Scrub URL userinfo, inline secrets, and sensitive query parameters."""
    if "?" not in url:
        return redact_string_strict(url)[:500]
    base, qs = url.split("?", 1)
    fragment = ""
    if "#" in qs:
        qs, fragment = qs.split("#", 1)
    clean_base = redact_string_strict(base)
    clean_qs = scrub_query_string(qs)
    rebuilt = f"{clean_base}?{clean_qs}" if clean_qs else clean_base
    if fragment:
        rebuilt = f"{rebuilt}#{redact_string_strict(fragment)[:100]}"
    return rebuilt[:600]


def _truncate_str(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[:limit] + f"... [truncated {len(value) - limit} chars]"


def _safe_json_line(payload: Mapping[str, Any]) -> str:
    import json

    scrubbed = redact_payload_strict(dict(payload))
    return json.dumps(scrubbed, ensure_ascii=False, default=str)


class ClientErrorPayload(BaseModel):
    """Frontend error report sent by browser telemetry."""

    model_config = ConfigDict(extra="ignore")

    kind: str = Field(default="unknown", max_length=64)
    message: str = Field(default="", max_length=2000)
    stack: str | None = Field(default=None, max_length=8000)
    component_stack: str | None = Field(default=None, max_length=4000)
    url: str | None = Field(default=None, max_length=1000)
    page_url: str | None = Field(default=None, max_length=1000)
    method: str | None = Field(default=None, max_length=16)
    status_code: int | None = Field(default=None, ge=0, le=999)
    request_id: str | None = Field(default=None, max_length=128)
    extra: dict[str, Any] = Field(default_factory=dict)


class _DiagnosticsLogHandler(logging.Handler):
    """Forwards WARNING/ERROR/CRITICAL Python log records into DiagnosticsRecorder."""

    def __init__(self, recorder: DiagnosticsRecorder) -> None:
        super().__init__(level=logging.WARNING)
        self._recorder = recorder
        self._local = threading.local()

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(self._local, "active", False):
            return
        self._local.active = True
        try:
            tb_text: str | None = None
            if record.exc_info and record.exc_info[0] is not None:
                tb_text = "".join(traceback.format_exception(*record.exc_info))
            msg = record.getMessage()
            self._recorder.record_failure(
                source="python_log",
                kind=record.levelname.lower(),
                message=msg,
                detail={
                    "logger": record.name,
                    "pathname": record.pathname,
                    "lineno": record.lineno,
                    "funcName": record.funcName,
                },
                traceback_text=tb_text,
            )
        except Exception:
            pass
        finally:
            self._local.active = False


class DiagnosticsRecorder:
    """Thread-safe JSONL + ring-buffer recorder for requests and failures."""

    def __init__(
        self,
        logs_dir: Path,
        *,
        ring_size: int = 500,
        max_file_bytes: int = _MAX_LOG_FILE_BYTES,
    ) -> None:
        self.logs_dir = logs_dir
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.requests_log_path = self.logs_dir / "requests.jsonl"
        self.failures_log_path = self.logs_dir / "failures.jsonl"
        self.frontend_log_path = self.logs_dir / "frontend_errors.jsonl"
        self._max_file_bytes = max(65536, int(max_file_bytes))
        self._lock = threading.Lock()
        self._failures: deque[dict[str, Any]] = deque(maxlen=max(50, ring_size))
        self._requests: deque[dict[str, Any]] = deque(maxlen=max(50, ring_size))
        self._total_requests = 0
        self._total_failures = 0
        self._by_source: Counter[str] = Counter()
        self._by_status: Counter[str] = Counter()
        self._started_at = _utc_iso()
        self._started_mono = time.monotonic()
        self._log_handler: _DiagnosticsLogHandler | None = None
        self._attached_loggers: list[logging.Logger] = []

    def _append_jsonl(self, path: Path, payload: Mapping[str, Any]) -> None:
        line = _safe_json_line(payload) + "\n"
        try:
            if path.exists() and path.stat().st_size >= self._max_file_bytes:
                rotated = path.with_suffix(path.suffix + ".1")
                os.replace(path, rotated)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            # Never break application requests if disk logging fails.
            pass

    def record_request(
        self,
        *,
        request_id: str,
        protocol: str,
        method: str,
        path: str,
        query: str,
        status_code: int | None,
        duration_ms: float,
        client_ip: str | None = None,
        error_preview: str | None = None,
        ws_close_code: int | None = None,
        ws_close_reason: str | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "ts": _utc_iso(),
            "request_id": request_id,
            "protocol": protocol,
            "method": method,
            "path": scrub_url(path),
            "query": scrub_query_string(query) if query else "",
            "status_code": status_code,
            "duration_ms": round(duration_ms, 2),
            "client_ip": client_ip,
        }
        if error_preview:
            entry["error_preview"] = _truncate_str(
                redact_string_strict(error_preview), _MAX_BODY_CAPTURE_BYTES
            )
        if ws_close_code is not None:
            entry["ws_close_code"] = ws_close_code
        if ws_close_reason:
            entry["ws_close_reason"] = _truncate_str(
                redact_string_strict(ws_close_reason), 500
            )

        scrubbed = redact_payload_strict(entry)
        with self._lock:
            self._total_requests += 1
            if status_code is not None:
                self._by_status[str(status_code)] += 1
            self._requests.append(scrubbed)
            self._append_jsonl(self.requests_log_path, scrubbed)

    def record_failure(
        self,
        *,
        source: str,
        kind: str,
        message: str,
        request_id: str | None = None,
        method: str | None = None,
        path: str | None = None,
        query: str | None = None,
        status_code: int | None = None,
        duration_ms: float | None = None,
        traceback_text: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "id": f"fail_{uuid.uuid4().hex[:12]}",
            "ts": _utc_iso(),
            "source": source,
            "kind": kind,
            "message": _truncate_str(redact_string_strict(message), 2000) or "",
        }
        if request_id:
            entry["request_id"] = request_id
        if method:
            entry["method"] = method
        if path:
            entry["path"] = scrub_url(path)
        if query:
            entry["query"] = scrub_query_string(query)
        if status_code is not None:
            entry["status_code"] = status_code
        if duration_ms is not None:
            entry["duration_ms"] = round(duration_ms, 2)
        if traceback_text:
            entry["traceback"] = _truncate_str(redact_string_strict(traceback_text), 8000)
        if detail:
            entry["detail"] = dict(detail)

        scrubbed: dict[str, Any] = redact_payload_strict(entry)
        with self._lock:
            self._total_failures += 1
            self._by_source[source] += 1
            self._failures.append(scrubbed)
            self._append_jsonl(self.failures_log_path, scrubbed)
            if source == "frontend":
                self._append_jsonl(self.frontend_log_path, scrubbed)
        return scrubbed

    def record_client_error(self, payload: ClientErrorPayload) -> dict[str, Any]:
        detail: dict[str, Any] = {}
        if payload.page_url:
            detail["page_url"] = scrub_url(payload.page_url)
        if payload.component_stack:
            detail["component_stack"] = _truncate_str(
                redact_string_strict(payload.component_stack), 4000
            )
        if payload.extra:
            detail["extra"] = payload.extra
        return self.record_failure(
            source="frontend",
            kind=payload.kind,
            message=payload.message or payload.kind,
            request_id=payload.request_id,
            method=payload.method,
            path=scrub_url(payload.url) if payload.url else None,
            status_code=payload.status_code,
            traceback_text=payload.stack,
            detail=detail or None,
        )

    def observe_sse_event(self, event: Mapping[str, Any]) -> None:
        """Record error/failed/resync events emitted on the internal EventBus."""
        event_type = str(event.get("type", ""))
        payload = event.get("payload")
        payload_map: Mapping[str, Any] = payload if isinstance(payload, Mapping) else {}
        is_failure = (
            event_type.endswith(".error")
            or event_type.endswith(".failed")
            or event_type == "stream.resync"
            or (event_type == "bot.presence" and payload_map.get("state") == "error")
            or (
                event_type in {"routine.run.status", "tool.call.updated", "message.completed"}
                and str(payload_map.get("status", "")).lower() in {"error", "failed"}
            )
        )
        if not is_failure:
            return
        raw_msg = (
            payload_map.get("error")
            or payload_map.get("subtext")
            or payload_map.get("reason")
            or ""
        )
        msg = str(raw_msg) or f"SSE event {event_type}"
        self.record_failure(
            source="sse_event",
            kind=event_type,
            message=msg,
            detail={
                "event_id": event.get("id"),
                "bot_id": event.get("bot_id"),
                "thread_id": event.get("thread_id"),
                "turn_id": event.get("turn_id"),
                "payload": dict(payload_map),
            },
        )

    def install_logging_handler(self) -> None:
        """Attach WARNING+ handler to app & uvicorn error loggers."""
        with self._lock:
            if self._log_handler is not None:
                return
            handler = _DiagnosticsLogHandler(self)
            self._log_handler = handler
            for logger_name in ("src", "uvicorn.error", "fastapi"):
                logger = logging.getLogger(logger_name)
                logger.addHandler(handler)
                self._attached_loggers.append(logger)

    def uninstall_logging_handler(self) -> None:
        with self._lock:
            handler = self._log_handler
            if handler is None:
                return
            for logger in self._attached_loggers:
                logger.removeHandler(handler)
            self._attached_loggers.clear()
            self._log_handler = None

    def get_failures(
        self,
        *,
        limit: int = 50,
        source: str | None = None,
        request_id: str | None = None,
    ) -> list[dict[str, Any]]:
        capped = max(1, min(int(limit), 500))
        with self._lock:
            items = list(self._failures)
        if source:
            items = [item for item in items if item.get("source") == source]
        if request_id:
            items = [item for item in items if item.get("request_id") == request_id]
        return list(reversed(items[-capped:]))

    def get_recent_requests(self, *, limit: int = 50) -> list[dict[str, Any]]:
        capped = max(1, min(int(limit), 500))
        with self._lock:
            items = list(self._requests)
        return list(reversed(items[-capped:]))

    def summary(self) -> dict[str, Any]:
        with self._lock:
            recent = list(reversed(list(self._failures)[-25:]))
            by_source = dict(self._by_source)
            by_status = dict(self._by_status)
            total_req = self._total_requests
            total_fail = self._total_failures
        return {
            "started_at": self._started_at,
            "uptime_seconds": round(time.monotonic() - self._started_mono, 1),
            "pid": os.getpid(),
            "logs_dir": str(self.logs_dir),
            "files": {
                "failures": str(self.failures_log_path),
                "requests": str(self.requests_log_path),
                "frontend_errors": str(self.frontend_log_path),
            },
            "total_requests": total_req,
            "total_failures": total_fail,
            "failures_by_source": by_source,
            "responses_by_status": by_status,
            "recent_failures": recent,
        }


class DiagnosticsMiddleware:
    """Pure raw ASGI middleware (non-buffering for SSE/WS) capturing all failures."""

    def __init__(self, app: ASGIApp, *, recorder: DiagnosticsRecorder) -> None:
        self._app = app
        self._recorder = recorder

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type not in {"http", "websocket"}:
            await self._app(scope, receive, send)
            return

        req_id = f"req_{uuid.uuid4().hex[:12]}"
        path = str(scope.get("path", ""))
        raw_qs = scope.get("query_string", b"")
        query = scrub_query_string(raw_qs if isinstance(raw_qs, (bytes, bytearray, str)) else b"")
        client = scope.get("client")
        client_ip = str(client[0]) if isinstance(client, (tuple, list)) and client else None
        is_vault = any(path == p or path.startswith(p + "/") for p in _VAULT_PATHS)
        start = time.monotonic()

        if scope_type == "http":
            method = str(scope.get("method", "GET")).upper()
            status_code: int | None = None
            err_chunks: list[bytes] = []
            err_captured = 0

            async def send_wrapper(message: Message) -> None:
                nonlocal status_code, err_captured
                msg_type = message.get("type")
                if msg_type == "http.response.start":
                    raw_status = message.get("status")
                    status_code = int(raw_status) if isinstance(raw_status, int) else None
                    raw_headers: Sequence[tuple[bytes, bytes]] = message.get("headers", ())
                    headers = list(raw_headers)
                    if not any(k.lower() == b"x-request-id" for k, _ in headers):
                        headers.append((b"x-request-id", req_id.encode("ascii")))
                    message = {**message, "headers": headers}
                elif (
                    msg_type == "http.response.body"
                    and status_code is not None
                    and status_code >= 400
                    and not is_vault
                    and err_captured < _MAX_BODY_CAPTURE_BYTES
                ):
                    body_bytes = message.get("body", b"")
                    if isinstance(body_bytes, (bytes, bytearray)) and body_bytes:
                        remaining = _MAX_BODY_CAPTURE_BYTES - err_captured
                        chunk = bytes(body_bytes[:remaining])
                        err_chunks.append(chunk)
                        err_captured += len(chunk)
                await send(message)

            try:
                await self._app(scope, receive, send_wrapper)
            except Exception as exc:
                duration_ms = (time.monotonic() - start) * 1000.0
                tb_text = traceback.format_exc()
                self._recorder.record_request(
                    request_id=req_id,
                    protocol="http",
                    method=method,
                    path=path,
                    query=query,
                    status_code=500,
                    duration_ms=duration_ms,
                    client_ip=client_ip,
                    error_preview=f"{type(exc).__name__}: {exc}",
                )
                self._recorder.record_failure(
                    source="backend_http",
                    kind="unhandled_exception",
                    message=f"{type(exc).__name__}: {exc}",
                    request_id=req_id,
                    method=method,
                    path=path,
                    query=query,
                    status_code=500,
                    duration_ms=duration_ms,
                    traceback_text=tb_text,
                )
                raise

            duration_ms = (time.monotonic() - start) * 1000.0
            preview: str | None = None
            if status_code is not None and status_code >= 400:
                if is_vault:
                    preview = "[vault response body omitted]"
                elif err_chunks:
                    preview = b"".join(err_chunks).decode("utf-8", errors="replace")

            # Avoid recording noisy recursive diagnostics requests unless they fail.
            if not path.startswith("/api/v1/diagnostics/") or (
                status_code is not None and status_code >= 400
            ):
                self._recorder.record_request(
                    request_id=req_id,
                    protocol="http",
                    method=method,
                    path=path,
                    query=query,
                    status_code=status_code,
                    duration_ms=duration_ms,
                    client_ip=client_ip,
                    error_preview=preview,
                )
            if status_code is not None and status_code >= 400:
                self._recorder.record_failure(
                    source="backend_http",
                    kind="http_5xx" if status_code >= 500 else "http_4xx",
                    message=f"{method} {path} -> HTTP {status_code}",
                    request_id=req_id,
                    method=method,
                    path=path,
                    query=query,
                    status_code=status_code,
                    duration_ms=duration_ms,
                    detail={"response_preview": preview} if preview else None,
                )
            return

        # WebSocket lifecycle tracking
        ws_close_code: int | None = None
        ws_close_reason: str | None = None

        async def ws_send_wrapper(message: Message) -> None:
            nonlocal ws_close_code, ws_close_reason
            if message.get("type") == "websocket.close":
                raw_code = message.get("code")
                ws_close_code = int(raw_code) if isinstance(raw_code, int) else 1000
                raw_reason = message.get("reason")
                ws_close_reason = str(raw_reason) if raw_reason else None
            await send(message)

        try:
            await self._app(scope, receive, ws_send_wrapper)
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000.0
            tb_text = traceback.format_exc()
            self._recorder.record_request(
                request_id=req_id,
                protocol="websocket",
                method="WS",
                path=path,
                query=query,
                status_code=None,
                duration_ms=duration_ms,
                client_ip=client_ip,
                error_preview=f"{type(exc).__name__}: {exc}",
            )
            self._recorder.record_failure(
                source="websocket",
                kind="unhandled_exception",
                message=f"WS {path} crashed: {type(exc).__name__}: {exc}",
                request_id=req_id,
                method="WS",
                path=path,
                query=query,
                duration_ms=duration_ms,
                traceback_text=tb_text,
            )
            raise

        duration_ms = (time.monotonic() - start) * 1000.0
        self._recorder.record_request(
            request_id=req_id,
            protocol="websocket",
            method="WS",
            path=path,
            query=query,
            status_code=None,
            duration_ms=duration_ms,
            client_ip=client_ip,
            ws_close_code=ws_close_code,
            ws_close_reason=ws_close_reason,
        )
        if ws_close_code is not None and ws_close_code not in _NORMAL_WS_CLOSE_CODES:
            self._recorder.record_failure(
                source="websocket",
                kind="abnormal_close",
                message=f"WS {path} closed with code {ws_close_code}",
                request_id=req_id,
                method="WS",
                path=path,
                query=query,
                duration_ms=duration_ms,
                detail={"close_code": ws_close_code, "close_reason": ws_close_reason},
            )


def create_diagnostics_router(recorder: DiagnosticsRecorder) -> APIRouter:
    """Mount `/api/v1/diagnostics/*` endpoints for live failure inspection & client beacons."""
    router = APIRouter(prefix="/api/v1/diagnostics", tags=["diagnostics"])

    @router.post("/client-error", status_code=status.HTTP_202_ACCEPTED)
    async def ingest_client_error(payload: ClientErrorPayload, request: Request) -> dict[str, Any]:
        del request
        recorded = recorder.record_client_error(payload)
        return {"accepted": True, "id": recorded["id"]}

    @router.get("/summary")
    async def diagnostics_summary() -> dict[str, Any]:
        return recorder.summary()

    @router.get("/failures")
    async def diagnostics_failures(
        limit: int = Query(default=50, ge=1, le=500),
        source: str | None = Query(default=None),
        request_id: str | None = Query(default=None),
    ) -> dict[str, Any]:
        items = recorder.get_failures(limit=limit, source=source, request_id=request_id)
        return {"count": len(items), "failures": items}

    @router.get("/requests")
    async def diagnostics_requests(
        limit: int = Query(default=50, ge=1, le=500),
    ) -> dict[str, Any]:
        items = recorder.get_recent_requests(limit=limit)
        return {"count": len(items), "requests": items}

    return router
