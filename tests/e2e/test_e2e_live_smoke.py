"""Tier 4 Live Smoke E2E tests (Scenario 6 — strictly read-only & cleanup-safe)."""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlsplit, urlunsplit

import httpx
import pytest
from playwright.async_api import (
    ConsoleMessage,
    Response,
    Route,
    WebSocketRoute,
    async_playwright,
)

pytestmark = [pytest.mark.e2e, pytest.mark.e2e_live]

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


@dataclass(frozen=True)
class _ParsedLiveTarget:
    origin: str
    prefix: str
    hostname: str
    token: str | None

    @property
    def api_base(self) -> str:
        return f"{self.origin}{self.prefix}"

    @property
    def app_url(self) -> str:
        base = f"{self.origin}{self.prefix}/app"
        if self.token:
            return f"{base}?{urlencode({'token': self.token})}"
        return base

    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}


def _parse_live_target(raw_url: str) -> _ParsedLiveTarget:
    parts = urlsplit(raw_url.strip())
    if not parts.scheme or not parts.netloc or not parts.hostname:
        raise ValueError(f"Invalid E2E_TARGET_URL: {raw_url!r}")
    origin = f"{parts.scheme}://{parts.netloc}"
    raw_path = parts.path.rstrip("/")
    prefix = raw_path[:-4] if raw_path.endswith("/app") else raw_path
    qs_token = parse_qs(parts.query).get("token", [])
    env_token = os.environ.get("E2E_TARGET_TOKEN", "").strip()
    token = qs_token[0] if qs_token else (env_token or None)
    return _ParsedLiveTarget(
        origin=origin,
        prefix=prefix,
        hostname=parts.hostname.lower(),
        token=token,
    )


async def test_live_smoke_read_only_api_and_studio_browser(
    live_target_url: str,
) -> None:
    target = _parse_live_target(live_target_url)

    # 1. Read-only REST API smoke checks
    async with httpx.AsyncClient(
        base_url=target.api_base,
        headers=target.auth_headers(),
        timeout=15.0,
        follow_redirects=True,
    ) as client:
        health = await client.get("/health")
        assert health.status_code == 200
        assert health.json().get("status") == "ok"

        sys_info = await client.get("/api/system/info")
        assert sys_info.status_code == 200
        assert "backend_mode" in sys_info.json()

        bots = await client.get("/api/v1/bots")
        assert bots.status_code == 200
        assert isinstance(bots.json().get("bots"), list)
        assert len(bots.json()["bots"]) >= 1

        comp_status = await client.get("/api/v1/computers/default/status")
        assert comp_status.status_code == 200
        assert "control_owner" in comp_status.json()

        usage = await client.get("/api/v1/usage")
        assert usage.status_code == 200
        assert isinstance(usage.json(), dict)

    # 2. Read-only real Chromium /app check with target-host + loopback route guard
    allowed_hosts = _LOOPBACK_HOSTS | {target.hostname}

    def _is_allowed(url: str) -> bool:
        if url.startswith(("data:", "blob:", "about:")):
            return True
        parsed = urlparse(url)
        if parsed.scheme in {"http", "https", "ws", "wss"}:
            return (parsed.hostname or "").lower() in allowed_hosts
        return False

    console_errors: list[str] = []
    page_errors: list[str] = []
    http_errors: list[tuple[int, str]] = []
    external_requests: list[str] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1280, "height": 800})

        async def _route_guard(route: Route) -> None:
            req_url = route.request.url
            if _is_allowed(req_url):
                await route.continue_()
            else:
                external_requests.append(req_url)
                await route.abort()

        async def _ws_guard(ws_route: WebSocketRoute) -> None:
            ws_url = ws_route.url
            if _is_allowed(ws_url):
                ws_route.connect_to_server()
            else:
                external_requests.append(ws_url)
                await ws_route.close(code=1008, reason="Blocked external WebSocket")

        await context.route("**/*", _route_guard)
        await context.route_web_socket("**/*", _ws_guard)

        page = await context.new_page()

        def _on_console(msg: ConsoleMessage) -> None:
            if msg.type == "error":
                console_errors.append(msg.text)

        def _on_pageerror(exc: Exception) -> None:
            page_errors.append(repr(exc))

        def _on_response(resp: Response) -> None:
            if resp.status >= 400:
                http_errors.append((resp.status, resp.url))

        page.on("console", _on_console)
        page.on("pageerror", _on_pageerror)
        page.on("response", _on_response)

        try:
            await page.goto(target.app_url, wait_until="networkidle")
            await page.wait_for_selector("text=Grok Bot")

            title = await page.title()
            theme = await page.evaluate(
                "document.documentElement.getAttribute('data-theme')"
            )
            assert title == "Grok Bot — ControlBot Studio"
            assert theme == "light"
            assert console_errors == [], f"Unexpected console errors: {console_errors}"
            assert page_errors == [], f"Unexpected page errors: {page_errors}"
            assert http_errors == [], f"Unexpected HTTP >= 400 responses: {http_errors}"
            assert external_requests == [], f"Blocked external requests: {external_requests}"
        finally:
            with contextlib.suppress(Exception):
                await context.unroute_all(behavior="ignoreErrors")
            with contextlib.suppress(Exception):
                await page.close()
            with contextlib.suppress(Exception):
                await context.close()
            with contextlib.suppress(Exception):
                await browser.close()


def _normalize_novnc_probe_url(raw_url: str) -> str:
    parts = urlsplit(raw_url.strip())
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"Invalid E2E_NOVNC_URL: {raw_url!r}")
    path = parts.path if parts.path and parts.path != "/" else "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


async def test_live_smoke_optional_novnc_http_check(
    live_target_url: str,
    live_novnc_url: str,
) -> None:
    del live_target_url
    probe_url = _normalize_novnc_probe_url(live_novnc_url)
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        resp = await client.get(probe_url)
        assert resp.status_code == 200
        assert "vnc" in resp.text.lower() or "novnc" in resp.text.lower()
