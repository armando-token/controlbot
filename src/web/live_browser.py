"""Lazy interactive Playwright browser controller for Live Computer Workspace."""

from __future__ import annotations

import asyncio
import base64
import contextlib
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Page, Playwright, async_playwright

_VIEWPORT_WIDTH = 1280
_VIEWPORT_HEIGHT = 800
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]", "10.", "192.168.")
_WELCOME_HTML = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<style>body{font-family:-apple-system,system-ui,sans-serif;background:#f8fafc;color:#0f172a;"
    "margin:0;padding:48px;}h1{font-size:24px;margin:0 0 8px;}p{color:#475569;max-width:600px;}"
    "code{background:#e2e8f0;padding:2px 6px;border-radius:4px;}</style></head><body>"
    "<h1>Navegador Vivo de ControlBot</h1>"
    "<p>Escribe una URL en la barra superior (por ejemplo <code>127.0.0.1:8000</code> o cualquier "
    "sitio web) para navegar, hacer clic, escribir y simular inicios de sesi&oacute;n en vivo.</p>"
    "</body></html>"
)


def normalize_browser_url(raw_url: str) -> str:
    """Validate and normalize an interactive browser URL (HTTP/HTTPS only)."""
    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("URL must not be empty.")
    if "://" not in cleaned:
        low = cleaned.lower()
        scheme = "http" if any(low.startswith(prefix) for prefix in _LOCAL_HOSTS) else "https"
        cleaned = f"{scheme}://{cleaned}"
    parsed = urlparse(cleaned)
    scheme_low = parsed.scheme.lower()
    if scheme_low not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Unsupported or invalid browser URL: {raw_url!r}")
    return cleaned


class LiveBrowserController:
    """Lazy persistent Playwright Chromium session controlled over HTTP/WebSocket."""

    def __init__(self, *, profile_root: Path) -> None:
        self._profile_root = profile_root
        self._lock = asyncio.Lock()
        self._playwright: Playwright | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None

    @property
    def running(self) -> bool:
        return self._context is not None and self._page is not None and not self._page.is_closed()

    async def status(self) -> dict[str, Any]:
        """Return current browser running status, URL, and page title."""
        async with self._lock:
            return await self._unlocked_status()

    async def _unlocked_status(self) -> dict[str, Any]:
        if not self.running or self._page is None:
            return {
                "running": False,
                "url": "",
                "title": "",
                "viewport": {"width": _VIEWPORT_WIDTH, "height": _VIEWPORT_HEIGHT},
            }
        title = ""
        with contextlib.suppress(Exception):
            title = await self._page.title()
        return {
            "running": True,
            "url": self._page.url,
            "title": title,
            "viewport": {"width": _VIEWPORT_WIDTH, "height": _VIEWPORT_HEIGHT},
        }

    async def start(self, initial_url: str | None = None) -> dict[str, Any]:
        """Lazily start persistent Chromium browser if not already running."""
        async with self._lock:
            if not self.running:
                self._profile_root.mkdir(parents=True, exist_ok=True)
                self._playwright = await async_playwright().start()
                self._context = await self._playwright.chromium.launch_persistent_context(
                    user_data_dir=str(self._profile_root),
                    headless=True,
                    viewport={"width": _VIEWPORT_WIDTH, "height": _VIEWPORT_HEIGHT},
                )
                self._context.set_default_timeout(12000)
                pages = self._context.pages
                self._page = pages[0] if pages else await self._context.new_page()
                if initial_url and initial_url.strip():
                    target = normalize_browser_url(initial_url)
                    await self._page.goto(target, wait_until="domcontentloaded")
                else:
                    await self._page.set_content(_WELCOME_HTML, wait_until="domcontentloaded")
            elif initial_url and initial_url.strip() and self._page is not None:
                target = normalize_browser_url(initial_url)
                await self._page.goto(target, wait_until="domcontentloaded")
            return await self._unlocked_status()

    async def stop(self) -> dict[str, Any]:
        """Close Chromium context and Playwright instance to reclaim all browser RAM."""
        async with self._lock:
            if self._context is not None:
                with contextlib.suppress(Exception):
                    await self._context.close()
                self._context = None
            self._page = None
            if self._playwright is not None:
                with contextlib.suppress(Exception):
                    await self._playwright.stop()
                self._playwright = None
            return await self._unlocked_status()

    async def navigate(self, raw_url: str) -> dict[str, Any]:
        """Navigate active page (starting Chromium lazily if stopped)."""
        target = normalize_browser_url(raw_url)
        async with self._lock:
            if not self.running:
                self._profile_root.mkdir(parents=True, exist_ok=True)
                self._playwright = await async_playwright().start()
                self._context = await self._playwright.chromium.launch_persistent_context(
                    user_data_dir=str(self._profile_root),
                    headless=True,
                    viewport={"width": _VIEWPORT_WIDTH, "height": _VIEWPORT_HEIGHT},
                )
                self._context.set_default_timeout(12000)
                pages = self._context.pages
                self._page = pages[0] if pages else await self._context.new_page()
            assert self._page is not None
            await self._page.goto(target, wait_until="domcontentloaded")
            return await self._unlocked_status()

    async def go_back(self) -> dict[str, Any]:
        async with self._lock:
            if self.running and self._page is not None:
                with contextlib.suppress(Exception):
                    await self._page.go_back(wait_until="domcontentloaded")
            return await self._unlocked_status()

    async def go_forward(self) -> dict[str, Any]:
        async with self._lock:
            if self.running and self._page is not None:
                with contextlib.suppress(Exception):
                    await self._page.go_forward(wait_until="domcontentloaded")
            return await self._unlocked_status()

    async def reload(self) -> dict[str, Any]:
        async with self._lock:
            if self.running and self._page is not None:
                with contextlib.suppress(Exception):
                    await self._page.reload(wait_until="domcontentloaded")
            return await self._unlocked_status()

    async def handle_input(self, event: dict[str, Any]) -> None:
        """Apply mouse/keyboard interaction event onto the active page."""
        async with self._lock:
            if not self.running or self._page is None:
                return
            ev_type = str(event.get("type", "")).strip().lower()
            if ev_type == "click":
                x = max(0.0, min(float(_VIEWPORT_WIDTH), float(event.get("x", 0.0))))
                y = max(0.0, min(float(_VIEWPORT_HEIGHT), float(event.get("y", 0.0))))
                raw_btn = str(event.get("button", "left")).lower()
                btn: Literal["left", "middle", "right"] = (
                    "right"
                    if raw_btn == "right"
                    else ("middle" if raw_btn == "middle" else "left")
                )
                await self._page.mouse.click(x, y, button=btn)
            elif ev_type == "dblclick":
                x = max(0.0, min(float(_VIEWPORT_WIDTH), float(event.get("x", 0.0))))
                y = max(0.0, min(float(_VIEWPORT_HEIGHT), float(event.get("y", 0.0))))
                await self._page.mouse.dblclick(x, y)
            elif ev_type == "wheel":
                dx = float(event.get("dx", 0.0))
                dy = float(event.get("dy", 0.0))
                await self._page.mouse.wheel(dx, dy)
            elif ev_type == "type":
                text = str(event.get("text", ""))
                if text:
                    await self._page.keyboard.type(text)
            elif ev_type == "key":
                key = str(event.get("key", ""))
                if key:
                    await self._page.keyboard.press(key)

    async def capture_frame(self, quality: int = 72) -> dict[str, Any] | None:
        """Capture a compressed JPEG screenshot frame if the browser is running."""
        async with self._lock:
            if not self.running or self._page is None:
                return None
            with contextlib.suppress(Exception):
                raw_bytes = await self._page.screenshot(type="jpeg", quality=quality)
                title = ""
                with contextlib.suppress(Exception):
                    title = await self._page.title()
                return {
                    "type": "frame",
                    "data": base64.b64encode(raw_bytes).decode("ascii"),
                    "url": self._page.url,
                    "title": title,
                    "width": _VIEWPORT_WIDTH,
                    "height": _VIEWPORT_HEIGHT,
                }
            return None
