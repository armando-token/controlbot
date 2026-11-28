"""Pytest configuration, QA tier/lane markers, StrictBrowserPage, and isolated fixtures."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest
from playwright.async_api import (
    Browser,
    BrowserContext,
    ConsoleMessage,
    Page,
    Response,
    Route,
    WebSocketRoute,
    async_playwright,
)
from tests.e2e._helpers import MockRfbServer
from tests.e2e_qa.helpers import IsolatedQAEnv, QACliRunner

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


def pytest_configure(config: pytest.Config) -> None:
    """Register E2E QA tier and capability markers."""
    config.addinivalue_line(
        "markers",
        "qa_tier1: Tier 1 isolated happy-path E2E QA tests.",
    )
    config.addinivalue_line(
        "markers",
        "qa_tier2: Tier 2 boundary, negative, and corner-case E2E QA tests.",
    )
    config.addinivalue_line(
        "markers",
        "qa_tier3: Tier 3 pairwise cross-feature combination E2E QA tests.",
    )
    config.addinivalue_line(
        "markers",
        "qa_tier4: Tier 4 realistic end-to-end operator/industrial/differential QA scenarios.",
    )
    config.addinivalue_line(
        "markers",
        "qa_existing: Tests verifiable immediately against existing repository capabilities.",
    )
    config.addinivalue_line(
        "markers",
        "qa_megaplan: Tests targeting new Megaplan QA/self-repair contracts.",
    )


def _is_allowed_browser_url(url: str) -> bool:
    if url.startswith(("data:", "blob:", "about:")):
        return True
    parsed = urlparse(url)
    if parsed.scheme in {"http", "https", "ws", "wss"}:
        hostname = (parsed.hostname or "").lower()
        return hostname in _LOOPBACK_HOSTS
    return False


@dataclass
class StrictBrowserPage:
    """Playwright async Page wrapper enforcing zero console/page/HTTP>=400/external errors."""

    page: Page
    context: BrowserContext
    browser: Browser
    console_errors: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    http_errors: list[tuple[int, str]] = field(default_factory=list)
    external_requests: list[str] = field(default_factory=list)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.page, name)

    @property
    def errors(self) -> list[str]:
        items: list[str] = []
        items.extend(f"console.error: {msg}" for msg in self.console_errors)
        items.extend(f"pageerror: {err}" for err in self.page_errors)
        items.extend(f"http {status}: {url}" for status, url in self.http_errors)
        items.extend(f"external request blocked: {url}" for url in self.external_requests)
        return items

    def reset_errors(self) -> None:
        self.console_errors.clear()
        self.page_errors.clear()
        self.http_errors.clear()
        self.external_requests.clear()

    def assert_clean(
        self,
        *,
        allow_http_statuses: Sequence[int] = (),
        allow_console_substrings: Sequence[str] = (),
    ) -> None:
        allowed_statuses = set(allow_http_statuses)
        unexpected_http = [
            (status, url) for status, url in self.http_errors if status not in allowed_statuses
        ]
        unexpected_console = [
            msg
            for msg in self.console_errors
            if not any(sub in msg for sub in allow_console_substrings)
        ]

        problems: list[str] = []
        if unexpected_console:
            problems.append(f"console_errors={unexpected_console}")
        if self.page_errors:
            problems.append(f"page_errors={self.page_errors}")
        if unexpected_http:
            problems.append(f"http_errors={unexpected_http}")
        if self.external_requests:
            problems.append(f"external_requests={self.external_requests}")

        if problems:
            raise AssertionError(
                "StrictBrowserPage detected browser errors: " + "; ".join(problems)
            )


@pytest.fixture
def mock_rfb_server(tmp_path: Path) -> Iterator[MockRfbServer]:
    """Start an ephemeral loopback RFB 3.8 server with DES VNC Auth."""
    rfb = MockRfbServer(passwd_path=tmp_path / "vnc_passwd")
    rfb.start()
    try:
        yield rfb
    finally:
        rfb.stop()


@pytest.fixture
def qa_env_factory(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Callable[..., IsolatedQAEnv]]:
    """Factory fixture producing IsolatedQAEnv instances, automatically stopped on teardown."""
    created: list[IsolatedQAEnv] = []
    counter = 0

    def _create(
        *,
        web_token: str | None = None,
        cap_secret: str = "qa-e2e-cap-secret-0123456789abcdef",
        with_mock_rfb: bool = False,
        with_lab: bool = False,
        mock_agy_script: str | None = None,
        extra_env: dict[str, str] | None = None,
        name: str = "qa_srv",
        auto_start: bool = True,
    ) -> IsolatedQAEnv:
        nonlocal counter
        counter += 1
        tmp_dir = tmp_path_factory.mktemp(f"{name}_{counter}")
        env_obj = IsolatedQAEnv(
            tmp_dir=tmp_dir,
            web_token=web_token,
            cap_secret=cap_secret,
            with_mock_rfb=with_mock_rfb,
            with_lab=with_lab,
            mock_agy_script=mock_agy_script,
            extra_env=dict(extra_env or {}),
        )
        created.append(env_obj)
        if auto_start:
            env_obj.start()
        return env_obj

    try:
        yield _create
    finally:
        for env_obj in reversed(created):
            with contextlib.suppress(Exception):
                env_obj.stop()


@pytest.fixture
def qa_env(qa_env_factory: Callable[..., IsolatedQAEnv]) -> IsolatedQAEnv:
    """Isolated ephemeral ControlBot server without GROKBOT_WEB_TOKEN."""
    return qa_env_factory(web_token=None, name="qa_env")


@pytest.fixture
def qa_auth_env(qa_env_factory: Callable[..., IsolatedQAEnv]) -> IsolatedQAEnv:
    """Isolated ephemeral ControlBot server with GROKBOT_WEB_TOKEN configured."""
    return qa_env_factory(web_token="qa-e2e-web-token-9876", name="qa_auth_env")


@pytest.fixture
def qa_lab_env(qa_env_factory: Callable[..., IsolatedQAEnv]) -> IsolatedQAEnv:
    """Isolated ephemeral ControlBot server with synthetic LabStack enabled."""
    return qa_env_factory(with_lab=True, name="qa_lab_env")


@pytest.fixture
def qa_cli_runner(tmp_path: Path) -> QACliRunner:
    """Sanitized CLI runner with an isolated fake HOME inside tmp_path."""
    return QACliRunner(fake_home=tmp_path / "cli_home")


@pytest.fixture
async def strict_browser_page() -> AsyncIterator[StrictBrowserPage]:
    """Headless Chromium Playwright page enforcing loopback-only & error-free execution."""
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1280, "height": 800})
        external_requests: list[str] = []

        async def _route_guard(route: Route) -> None:
            req_url = route.request.url
            if _is_allowed_browser_url(req_url):
                await route.continue_()
            else:
                external_requests.append(req_url)
                await route.abort()

        async def _ws_guard(ws_route: WebSocketRoute) -> None:
            ws_url = ws_route.url
            if _is_allowed_browser_url(ws_url):
                ws_route.connect_to_server()
            else:
                external_requests.append(ws_url)
                await ws_route.close(code=1008, reason="Blocked external WebSocket")

        await context.route("**/*", _route_guard)
        await context.route_web_socket("**/*", _ws_guard)

        page = await context.new_page()
        wrapper = StrictBrowserPage(
            page=page,
            context=context,
            browser=browser,
            external_requests=external_requests,
        )

        def _on_console(msg: ConsoleMessage) -> None:
            if msg.type == "error":
                wrapper.console_errors.append(msg.text)

        def _on_pageerror(exc: Exception) -> None:
            wrapper.page_errors.append(repr(exc))

        def _on_response(resp: Response) -> None:
            if resp.status >= 400:
                wrapper.http_errors.append((resp.status, resp.url))

        page.on("console", _on_console)
        page.on("pageerror", _on_pageerror)
        page.on("response", _on_response)

        try:
            yield wrapper
        finally:
            with contextlib.suppress(Exception):
                await context.unroute_all(behavior="ignoreErrors")
            with contextlib.suppress(Exception):
                await page.close()
            with contextlib.suppress(Exception):
                await context.close()
            with contextlib.suppress(Exception):
                await browser.close()
