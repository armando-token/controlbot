"""Isolated Playwright persistent BrowserContext manager with origin and takeover guards."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import BrowserContext, Page, Playwright, Route, async_playwright
from playwright.async_api import Error as PlaywrightError

from src.adapters._common import SourceUnavailableError
from src.contracts.common import (
    FrozenModel,
    HttpOrigin,
    NonEmptyStr,
    UtcDatetime,
    utc_now,
    validate_http_origin,
)

_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class SessionError(RuntimeError):
    """Base error for Playwright session isolation and locking."""


class SessionNotFoundError(SessionError):
    """Raised when referencing an unknown session_id."""


class SessionOwnershipError(SessionError):
    """Raised when a persistent browser profile belongs to another identity or origin."""


class OriginNotAllowedError(SessionError):
    """Raised when a URL or subresource targets an origin outside the allowlist."""


OriginBlockedError = OriginNotAllowedError


class SessionBusyError(SessionError):
    """Raised when human takeover is requested while an automated lease is active."""


TakeoverConflictError = SessionBusyError


class SessionTakenOverError(SessionError):
    """Raised when automation attempts to run while human takeover is active."""


class TakeoverStateError(SessionError):
    """Raised on invalid takeover release or conflicting takeover ownership."""


class AuthExpiredError(SessionError):
    """Raised when an application session expires or redirects to login unexpectedly."""


class SessionLockState(FrozenModel):
    """Immutable snapshot of a browser session's identity, isolation, and lock state."""

    session_id: NonEmptyStr
    user_id: NonEmptyStr
    profile_id: NonEmptyStr
    app_id: NonEmptyStr
    allowed_origins: tuple[HttpOrigin, ...]
    profile_dir: str
    active_lease: bool = False
    takeover_active: bool = False
    takeover_owner: str | None = None
    takeover_reason: str | None = None
    blocked_origins: tuple[str, ...] = ()
    created_at: UtcDatetime
    updated_at: UtcDatetime


def _validate_segment(label: str, value: str) -> str:
    stripped = value.strip()
    if (
        not stripped
        or stripped in {".", ".."}
        or ".." in stripped
        or "/" in stripped
        or "\\" in stripped
        or not _SAFE_SEGMENT_RE.match(stripped)
    ):
        raise ValueError(f"Invalid {label} segment for profile path: {value!r}")
    return stripped


def make_session_id(user_id: str, profile_id: str, app_id: str) -> str:
    """Build deterministic safe session_id for (user_id, profile_id, app_id)."""
    u = _validate_segment("user_id", user_id)
    p = _validate_segment("profile_id", profile_id)
    a = _validate_segment("app_id", app_id)
    return f"{u}__{p}__{a}"


def _extract_url_origin(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"URL lacks scheme/netloc: {url!r}")
    return validate_http_origin(f"{parts.scheme}://{parts.netloc}")


@dataclass
class _MutableSessionRecord:
    session_id: str
    user_id: str
    profile_id: str
    app_id: str
    allowed_origins: tuple[str, ...]
    profile_dir: Path
    context: BrowserContext
    page: Page
    created_at: datetime
    updated_at: datetime
    active_lease: bool = False
    takeover_active: bool = False
    takeover_owner: str | None = None
    takeover_reason: str | None = None
    blocked_origins: list[str] = field(default_factory=list)

    def to_lock_state(self) -> SessionLockState:
        return SessionLockState(
            session_id=self.session_id,
            user_id=self.user_id,
            profile_id=self.profile_id,
            app_id=self.app_id,
            allowed_origins=self.allowed_origins,
            profile_dir=str(self.profile_dir),
            active_lease=self.active_lease,
            takeover_active=self.takeover_active,
            takeover_owner=self.takeover_owner,
            takeover_reason=self.takeover_reason,
            blocked_origins=tuple(self.blocked_origins),
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


@dataclass(frozen=True)
class ManagedSession:
    """Handle passed to adapters holding an active Playwright Page and session metadata."""

    session_id: str
    user_id: str
    profile_id: str
    app_id: str
    allowed_origins: tuple[str, ...]
    profile_dir: Path
    context: BrowserContext
    page: Page


class SessionManager:
    """Manages isolated Playwright persistent BrowserContexts with origin & takeover locks."""

    def __init__(self, profile_root: Path | str, *, headless: bool = True) -> None:
        self._profile_root = Path(profile_root)
        self._headless = headless
        self._lock = asyncio.Lock()
        self._playwright: Playwright | None = None
        self._sessions: dict[str, _MutableSessionRecord] = {}
        self._closed = False

    async def __aenter__(self) -> SessionManager:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close_all()

    async def start(self) -> None:
        async with self._lock:
            if self._playwright is None:
                self._profile_root.mkdir(parents=True, exist_ok=True)
                os.chmod(self._profile_root, 0o700)
                self._playwright = await async_playwright().start()
                self._closed = False

    async def _ensure_playwright(self) -> Playwright:
        if self._playwright is None:
            await self.start()
        assert self._playwright is not None
        return self._playwright

    async def open_session(
        self,
        user_id: str,
        profile_id: str,
        app_id: str,
        allowed_origins: Sequence[str],
        *,
        headless: bool | None = None,
    ) -> ManagedSession:
        """Open or reuse an isolated persistent BrowserContext for (user_id, profile_id, app_id)."""
        u = _validate_segment("user_id", user_id)
        p = _validate_segment("profile_id", profile_id)
        a = _validate_segment("app_id", app_id)
        normalized_origins = tuple(sorted({validate_http_origin(o) for o in allowed_origins}))
        if not normalized_origins:
            raise OriginNotAllowedError("allowed_origins must contain at least one origin.")

        session_id = make_session_id(u, p, a)
        pw = await self._ensure_playwright()

        async with self._lock:
            user_dir = self._profile_root / u
            profile_parent = user_dir / p
            profile_dir = profile_parent / a
            meta_path = profile_dir / "session_meta.json"

            existing = self._sessions.get(session_id)
            if existing is not None:
                if (
                    existing.user_id != u
                    or existing.profile_id != p
                    or existing.app_id != a
                    or tuple(sorted(existing.allowed_origins)) != normalized_origins
                ):
                    raise SessionOwnershipError(
                        f"Session {session_id!r} ownership/origin mismatch."
                    )
                if meta_path.exists():
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    if (
                        meta.get("user_id") != u
                        or meta.get("profile_id") != p
                        or meta.get("app_id") != a
                        or sorted(meta.get("allowed_origins", [])) != list(normalized_origins)
                    ):
                        raise SessionOwnershipError(
                            f"Profile directory {profile_dir} ownership mismatch: "
                            f"expected ({u}, {p}, {a}, {list(normalized_origins)})."
                        )
                elif profile_dir.exists() and any(profile_dir.iterdir()):
                    raise SessionOwnershipError(
                        f"Profile directory {profile_dir} is non-empty but missing "
                        "session_meta.json; refusing to adopt unverified profile."
                    )
                return ManagedSession(
                    session_id=existing.session_id,
                    user_id=existing.user_id,
                    profile_id=existing.profile_id,
                    app_id=existing.app_id,
                    allowed_origins=existing.allowed_origins,
                    profile_dir=existing.profile_dir,
                    context=existing.context,
                    page=existing.page,
                )

            for d in (self._profile_root, user_dir, profile_parent, profile_dir):
                d.mkdir(parents=True, exist_ok=True)
                os.chmod(d, 0o700)

            now = utc_now()
            if meta_path.exists():
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                if (
                    meta.get("user_id") != u
                    or meta.get("profile_id") != p
                    or meta.get("app_id") != a
                    or sorted(meta.get("allowed_origins", [])) != list(normalized_origins)
                ):
                    raise SessionOwnershipError(
                        f"Profile directory {profile_dir} ownership mismatch: "
                        f"expected ({u}, {p}, {a}, {list(normalized_origins)})."
                    )
            else:
                if any(profile_dir.iterdir()):
                    raise SessionOwnershipError(
                        f"Profile directory {profile_dir} is non-empty but missing "
                        "session_meta.json; refusing to adopt unverified profile."
                    )
                meta_payload = {
                    "user_id": u,
                    "profile_id": p,
                    "app_id": a,
                    "allowed_origins": list(normalized_origins),
                    "created_at": now.isoformat(),
                }
                meta_path.write_text(json.dumps(meta_payload, indent=2), encoding="utf-8")
                os.chmod(meta_path, 0o600)

            use_headless = self._headless if headless is None else headless
            context = await pw.chromium.launch_persistent_context(
                user_data_dir=str(profile_dir),
                headless=use_headless,
            )
            page = context.pages[0] if context.pages else await context.new_page()

            record = _MutableSessionRecord(
                session_id=session_id,
                user_id=u,
                profile_id=p,
                app_id=a,
                allowed_origins=normalized_origins,
                profile_dir=profile_dir,
                context=context,
                page=page,
                created_at=now,
                updated_at=now,
            )

            allowed_set = set(normalized_origins)

            async def _route_guard(route: Route) -> None:
                req_url = route.request.url
                if req_url == "about:blank" or req_url.startswith(("about:", "data:", "blob:")):
                    await route.continue_()
                    return
                try:
                    req_origin = _extract_url_origin(req_url)
                except ValueError:
                    record.blocked_origins.append(req_url)
                    await route.abort("blockedbyclient")
                    return
                if req_origin not in allowed_set:
                    record.blocked_origins.append(req_origin)
                    await route.abort("blockedbyclient")
                    return
                await route.continue_()

            await context.route("**/*", _route_guard)
            self._sessions[session_id] = record
            return ManagedSession(
                session_id=record.session_id,
                user_id=record.user_id,
                profile_id=record.profile_id,
                app_id=record.app_id,
                allowed_origins=record.allowed_origins,
                profile_dir=record.profile_dir,
                context=record.context,
                page=record.page,
            )

    def assert_origin_allowed(
        self,
        session_id: str,
        url: str,
        *,
        task_origins: Sequence[str] = (),
    ) -> str:
        """Validate URL origin against session allowlist and optional task scope allowlist."""
        record = self._sessions.get(session_id)
        if record is None:
            raise SessionNotFoundError(f"Unknown session_id: {session_id!r}")
        try:
            origin = _extract_url_origin(url)
        except ValueError as exc:
            raise OriginNotAllowedError(f"Invalid target URL origin: {url!r}") from exc
        if origin not in record.allowed_origins:
            record.blocked_origins.append(origin)
            raise OriginNotAllowedError(
                f"Origin {origin!r} not in session allowlist {record.allowed_origins}."
            )
        if task_origins:
            normalized_task = {validate_http_origin(o) for o in task_origins}
            if origin not in normalized_task:
                record.blocked_origins.append(origin)
                raise OriginNotAllowedError(
                    f"Origin {origin!r} not in task scope allowlist {sorted(normalized_task)}."
                )
        return origin

    async def navigate(
        self,
        session_id: str,
        url: str,
        *,
        task_origins: Sequence[str] = (),
    ) -> int | None:
        """Navigate session page after enforcing origin allowlists and checking redirects."""
        self.assert_origin_allowed(session_id, url, task_origins=task_origins)
        record = self._sessions[session_id]
        before_blocked = len(record.blocked_origins)
        try:
            response = await record.page.goto(url, wait_until="domcontentloaded")
        except PlaywrightError as exc:
            if len(record.blocked_origins) > before_blocked or "ERR_BLOCKED_BY_CLIENT" in str(exc):
                raise OriginNotAllowedError(
                    f"Navigation blocked by origin allowlist: {url!r}"
                ) from exc
            raise SourceUnavailableError(f"Navigation failed for {url!r}: {exc}") from exc
        if len(record.blocked_origins) > before_blocked:
            blocked_list = record.blocked_origins[before_blocked:]
            raise OriginNotAllowedError(
                f"Disallowed origin request aborted during navigation: {blocked_list!r}"
            )
        final_url = record.page.url
        if final_url and not final_url.startswith("about:"):
            self.assert_origin_allowed(session_id, final_url, task_origins=task_origins)
        return response.status if response is not None else None

    @asynccontextmanager
    async def acquire_lease(self, session_id: str) -> AsyncIterator[ManagedSession]:
        """Acquire exclusive automation lease for a session, blocking if human takeover active."""
        async with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                raise SessionNotFoundError(f"Unknown session_id: {session_id!r}")
            if record.takeover_active:
                raise SessionTakenOverError(
                    f"Session {session_id!r} is locked by human takeover "
                    f"(owner={record.takeover_owner!r})."
                )
            if record.active_lease:
                raise SessionBusyError(f"Session {session_id!r} already has an active lease.")
            record.active_lease = True
            record.updated_at = utc_now()
            managed = ManagedSession(
                session_id=record.session_id,
                user_id=record.user_id,
                profile_id=record.profile_id,
                app_id=record.app_id,
                allowed_origins=record.allowed_origins,
                profile_dir=record.profile_dir,
                context=record.context,
                page=record.page,
            )
        try:
            yield managed
        finally:
            async with self._lock:
                if session_id in self._sessions:
                    self._sessions[session_id].active_lease = False
                    self._sessions[session_id].updated_at = utc_now()

    async def set_takeover(
        self,
        session_id: str,
        locked: bool,
        *,
        owner: str = "operator",
        reason: str = "manual_intervention",
    ) -> SessionLockState:
        """Set or clear human takeover lock on a session."""
        if locked:
            return await self.request_takeover(session_id, owner=owner, reason=reason)
        return await self.release_takeover(session_id, owner=owner)

    async def request_takeover(
        self,
        session_id: str,
        owner: str = "operator",
        reason: str = "manual_intervention",
    ) -> SessionLockState:
        """Acquire human takeover lock unless an automation lease is active."""
        async with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                raise SessionNotFoundError(f"Unknown session_id: {session_id!r}")
            if record.active_lease:
                raise SessionBusyError(
                    f"Cannot take over session {session_id!r} while automation lease is active."
                )
            if record.takeover_active and record.takeover_owner != owner:
                raise TakeoverStateError(
                    f"Session {session_id!r} is already taken over by {record.takeover_owner!r}."
                )
            record.takeover_active = True
            record.takeover_owner = owner
            record.takeover_reason = reason
            record.updated_at = utc_now()
            return record.to_lock_state()

    async def release_takeover(
        self,
        session_id: str,
        owner: str | None = None,
    ) -> SessionLockState:
        """Release human takeover lock, validating current holder."""
        async with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                raise SessionNotFoundError(f"Unknown session_id: {session_id!r}")
            if not record.takeover_active:
                raise TakeoverStateError(
                    f"Session {session_id!r} is not currently under human takeover."
                )
            if record.takeover_owner is not None and (
                owner is None or record.takeover_owner != owner
            ):
                raise TakeoverStateError(
                    f"Cannot release takeover owned by {record.takeover_owner!r} as {owner!r}."
                )
            record.takeover_active = False
            record.takeover_owner = None
            record.takeover_reason = None
            record.updated_at = utc_now()
            return record.to_lock_state()

    async def get_session_state(self, session_id: str) -> SessionLockState | None:
        async with self._lock:
            record = self._sessions.get(session_id)
            return record.to_lock_state() if record is not None else None

    async def list_sessions(self) -> list[SessionLockState]:
        async with self._lock:
            return [record.to_lock_state() for record in self._sessions.values()]

    def is_takeover_active(self, session_id: str) -> bool:
        """Synchronous check for ToolRegistry.takeover_checker."""
        record = self._sessions.get(session_id)
        return bool(record.takeover_active) if record is not None else False

    async def close_session(self, session_id: str) -> None:
        async with self._lock:
            record = self._sessions.pop(session_id, None)
        if record is not None:
            with contextlib.suppress(PlaywrightError):
                await record.context.close()

    async def close_all(self) -> None:
        async with self._lock:
            records = list(self._sessions.values())
            self._sessions.clear()
            pw = self._playwright
            self._playwright = None
            self._closed = True
        for record in records:
            with contextlib.suppress(PlaywrightError):
                await record.context.close()
        if pw is not None:
            with contextlib.suppress(PlaywrightError):
                await pw.stop()
