"""Authentication, CORS, and sliding-window rate limiting for ControlBot web endpoints."""

from __future__ import annotations

import hmac
import json
import math
import os
import re
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs

from fastapi import WebSocket
from starlette.types import ASGIApp, Receive, Scope, Send

DEFAULT_RATE_LIMITS: dict[str, tuple[int, float]] = {
    "vnc_token": (30, 60.0),
    "attachments": (60, 60.0),
    "webhooks": (30, 60.0),
    "secure_fill": (20, 60.0),
    "messages": (60, 60.0),
}

_DEFAULT_LOOPBACK_ORIGIN_REGEX = r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$"
_WEBHOOK_ROUTINE_RE = re.compile(r"^/api/v1/webhooks/routines/([^/]+)$")
_VNC_TOKEN_RE = re.compile(r"^/api/v1/computers/[^/]+/vnc-token$")
_ATTACHMENTS_RE = re.compile(r"^/api/v1/attachments$")
_SECURE_FILL_RE = re.compile(r"^/api/v1/vault/secure-fill$")
_MESSAGES_RE = re.compile(r"^/api/v1/threads/[^/]+/messages$")


@dataclass(frozen=True)
class CorsConfig:
    """Resolved CORSMiddleware settings."""

    allow_origins: list[str]
    allow_origin_regex: str | None
    allow_credentials: bool
    allow_methods: list[str]
    allow_headers: list[str]
    expose_headers: list[str]


def resolve_web_token(explicit_token: str | None = None) -> str | None:
    """Resolve optional web authentication token from argument or environment."""
    if explicit_token is not None:
        cleaned = explicit_token.strip()
        return cleaned or None
    for env_key in ("GROKBOT_WEB_TOKEN", "CONTROLBOT_WEB_TOKEN"):
        val = os.environ.get(env_key, "").strip()
        if val:
            return val
    return None


def constant_time_token_match(candidate: str | None, expected: str) -> bool:
    """Compare candidate token against expected token in constant time."""
    if not candidate or not expected:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def extract_bearer_token(
    headers: Mapping[str, str] | Sequence[tuple[bytes, bytes]],
) -> str | None:
    """Extract Authorization: Bearer token from ASGI headers or mapping."""
    auth_val: str | None = None
    if isinstance(headers, Mapping):
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth_val = v
                break
    else:
        for raw_k, raw_v in headers:
            if raw_k.decode("latin-1").lower() == "authorization":
                auth_val = raw_v.decode("latin-1")
                break
    if auth_val is None:
        return None
    if auth_val.lower().startswith("bearer "):
        return auth_val[7:].strip()
    return None


def extract_query_token(query_string: bytes | str) -> str | None:
    """Extract `?token=` query parameter from ASGI query_string."""
    qs = (
        query_string.decode("latin-1")
        if isinstance(query_string, (bytes, bytearray))
        else str(query_string)
    )
    if not qs:
        return None
    parsed = parse_qs(qs, keep_blank_values=True)
    vals = parsed.get("token")
    if not vals:
        return None
    return vals[0].strip()


def verify_request_token(
    expected_token: str,
    *,
    headers: Mapping[str, str] | Sequence[tuple[bytes, bytes]],
    query_string: bytes | str,
) -> bool:
    """Verify Bearer header and/or `?token=` query param against expected_token.

    If both are supplied, both must match so a wrong Bearer token cannot be
    masked by a valid query parameter (and vice versa).
    """
    bearer = extract_bearer_token(headers)
    qtok = extract_query_token(query_string)
    if bearer is not None and qtok is not None:
        return constant_time_token_match(bearer, expected_token) and constant_time_token_match(
            qtok, expected_token
        )
    if bearer is not None:
        return constant_time_token_match(bearer, expected_token)
    if qtok is not None:
        return constant_time_token_match(qtok, expected_token)
    return False


def verify_websocket_token(websocket: WebSocket, expected_token: str | None) -> bool:
    """Verify WebSocket connection token when expected_token is configured."""
    if expected_token is None:
        return True
    raw_qs = websocket.scope.get("query_string", b"")
    qs: bytes | str = raw_qs if isinstance(raw_qs, (bytes, str)) else b""
    return verify_request_token(
        expected_token,
        headers=websocket.headers,
        query_string=qs,
    )


def resolve_cors_config(explicit_origins: Sequence[str] | None = None) -> CorsConfig:
    """Resolve CORS allowlist configuration with safe loopback defaults."""
    origins: list[str] = []
    if explicit_origins is not None:
        origins = [item.strip() for item in explicit_origins if item and item.strip()]
    else:
        raw_env = (
            os.environ.get("GROKBOT_CORS_ORIGINS", "").strip()
            or os.environ.get("CONTROLBOT_CORS_ORIGINS", "").strip()
        )
        if raw_env:
            origins = [part.strip() for part in raw_env.split(",") if part.strip()]

    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type", "Idempotency-Key", "Last-Event-ID"]
    expose_headers = ["Content-Disposition", "Retry-After", "X-Request-Id"]

    if origins:
        if "*" in origins:
            return CorsConfig(
                allow_origins=["*"],
                allow_origin_regex=None,
                allow_credentials=False,
                allow_methods=methods,
                allow_headers=allow_headers,
                expose_headers=expose_headers,
            )
        return CorsConfig(
            allow_origins=origins,
            allow_origin_regex=None,
            allow_credentials=True,
            allow_methods=methods,
            allow_headers=allow_headers,
            expose_headers=expose_headers,
        )

    return CorsConfig(
        allow_origins=[],
        allow_origin_regex=_DEFAULT_LOOPBACK_ORIGIN_REGEX,
        allow_credentials=True,
        allow_methods=methods,
        allow_headers=allow_headers,
        expose_headers=expose_headers,
    )


class SlidingWindowRateLimiter:
    """Thread-safe bounded in-memory sliding-window rate limiter."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 4096,
    ) -> None:
        self._clock = clock
        self._max_keys = max(16, int(max_keys))
        self._lock = threading.Lock()
        self._windows: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()

    def check(
        self,
        bucket: str,
        client_key: str,
        *,
        limit: int,
        window_seconds: float,
    ) -> tuple[bool, int]:
        """Record a hit if under limit; returns (allowed, retry_after_seconds)."""
        if limit <= 0:
            return False, max(1, math.ceil(max(1.0, window_seconds)))
        if window_seconds <= 0:
            return True, 0

        now = self._clock()
        cutoff = now - window_seconds
        key = (bucket, client_key)

        with self._lock:
            dq = self._windows.get(key)
            if dq is None:
                dq = deque()
                self._windows[key] = dq
            else:
                self._windows.move_to_end(key)

            while dq and dq[0] <= cutoff:
                dq.popleft()

            if len(dq) >= limit:
                retry_after = max(1, math.ceil(window_seconds - (now - dq[0])))
                return False, retry_after

            dq.append(now)
            while len(self._windows) > self._max_keys:
                self._windows.popitem(last=False)
            return True, 0


async def _send_json_error(
    send: Send,
    *,
    status_code: int,
    detail: str,
    extra_headers: Sequence[tuple[bytes, bytes]] = (),
) -> None:
    body = json.dumps({"detail": detail}).encode("utf-8")
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        *extra_headers,
    ]
    await send({"type": "http.response.start", "status": status_code, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _is_http_path_protected(path: str) -> bool:
    if path == "/health":
        return False
    if path.startswith("/assets/"):
        return False
    if path == "/app" or path.startswith("/app/"):
        return False
    if _WEBHOOK_ROUTINE_RE.fullmatch(path):
        return False
    return (
        path in {"/", "/studio-legacy", "/api", "/ui", "/tasks"}
        or path.startswith("/api/")
        or path.startswith("/ui/")
        or path.startswith("/tasks/")
    )


class TokenAuthMiddleware:
    """Pure ASGI token authentication middleware (non-buffering for SSE & streaming uploads)."""

    def __init__(self, app: ASGIApp, *, expected_token: str | None) -> None:
        self._app = app
        self._expected_token = expected_token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._expected_token is None:
            await self._app(scope, receive, send)
            return

        scope_type = scope.get("type")
        path = str(scope.get("path", ""))

        if scope_type == "http":
            if str(scope.get("method", "")).upper() == "OPTIONS":
                await self._app(scope, receive, send)
                return
            if not _is_http_path_protected(path):
                await self._app(scope, receive, send)
                return
            headers: Sequence[tuple[bytes, bytes]] = scope.get("headers", ())
            raw_qs = scope.get("query_string", b"")
            qs: bytes | str = raw_qs if isinstance(raw_qs, (bytes, str)) else b""
            if not verify_request_token(self._expected_token, headers=headers, query_string=qs):
                await _send_json_error(
                    send,
                    status_code=401,
                    detail="Unauthorized: invalid or missing authentication token.",
                    extra_headers=((b"www-authenticate", b"Bearer"),),
                )
                return
            await self._app(scope, receive, send)
            return

        if scope_type == "websocket":
            # `/ws/v1/computers/{vm_id}/*` delegates to computer.py's dual-token validator
            # (`cap_token` OR valid web token).
            if path.startswith("/ws/v1/computers/"):
                await self._app(scope, receive, send)
                return
            ws_headers: Sequence[tuple[bytes, bytes]] = scope.get("headers", ())
            ws_raw_qs = scope.get("query_string", b"")
            ws_qs: bytes | str = ws_raw_qs if isinstance(ws_raw_qs, (bytes, str)) else b""
            if not verify_request_token(
                self._expected_token, headers=ws_headers, query_string=ws_qs
            ):
                await send({"type": "websocket.close", "code": 4401})
                return
            await self._app(scope, receive, send)
            return

        await self._app(scope, receive, send)


def _match_rate_limit_bucket(path: str, client_ip: str) -> tuple[str, str] | None:
    if _VNC_TOKEN_RE.fullmatch(path):
        return "vnc_token", client_ip
    if _ATTACHMENTS_RE.fullmatch(path):
        return "attachments", client_ip
    wh_match = _WEBHOOK_ROUTINE_RE.fullmatch(path)
    if wh_match is not None:
        return "webhooks", f"{client_ip}:{wh_match.group(1)}"
    if _SECURE_FILL_RE.fullmatch(path):
        return "secure_fill", client_ip
    if _MESSAGES_RE.fullmatch(path):
        return "messages", client_ip
    return None


def _extract_client_ip(scope: Scope) -> str:
    client: Any = scope.get("client")
    if isinstance(client, (tuple, list)) and client:
        return str(client[0] or "unknown")
    return "unknown"


class RateLimitMiddleware:
    """Pure ASGI sliding-window rate limiter for sensitive POST endpoints."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        limiter: SlidingWindowRateLimiter,
        limits: Mapping[str, tuple[int, float]],
    ) -> None:
        self._app = app
        self._limiter = limiter
        self._limits = dict(limits)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "http" and str(scope.get("method", "")).upper() == "POST":
            path = str(scope.get("path", ""))
            matched = _match_rate_limit_bucket(path, _extract_client_ip(scope))
            if matched is not None:
                bucket, client_key = matched
                cfg = self._limits.get(bucket)
                if cfg is not None:
                    limit, window_seconds = cfg
                    allowed, retry_after = self._limiter.check(
                        bucket,
                        client_key,
                        limit=limit,
                        window_seconds=window_seconds,
                    )
                    if not allowed:
                        await _send_json_error(
                            send,
                            status_code=429,
                            detail="Rate limit exceeded. Try again shortly.",
                            extra_headers=((b"retry-after", str(retry_after).encode("ascii")),),
                        )
                        return
        await self._app(scope, receive, send)
