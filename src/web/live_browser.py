"""Lazy interactive Playwright browser controller for Live Computer Workspace."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Page, Playwright, async_playwright

from src.storage.redaction import redact_payload_strict

_VIEWPORT_WIDTH = 1280
_VIEWPORT_HEIGHT = 800
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]", "10.", "192.168.")
_INLINE_TOKEN_RE = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pou]_[A-Za-z0-9_]{8,})\b")
_EXTRACT_JS = r"""(maxElements) => {
  const collectText = (doc) => {
    if (!doc || !doc.body) return "";
    let out = doc.body.innerText || "";
    const frames = doc.querySelectorAll ? doc.querySelectorAll("iframe") : [];
    for (const fr of frames) {
      try {
        if (fr.contentDocument && fr.contentDocument.body) {
          const sub = fr.contentDocument.body.innerText || "";
          if (sub.trim()) out += "\n" + sub;
        }
      } catch (_) {}
    }
    return out;
  };
  const rawText = collectText(document);
  const selector = 'a, button, input:not([type="password"]), select, textarea, [role="button"]';
  const els = [];
  const nodes = document.querySelectorAll(selector);
  for (const el of nodes) {
    if (els.length >= maxElements) break;
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0 || rect.bottom < 0 || rect.top > 800) continue;
    const tag = (el.tagName || "").toLowerCase();
    const typeAttr = (el.getAttribute && (el.getAttribute("type") || "").toLowerCase()) || "";
    if (tag === "input" && typeAttr === "password") continue;
    const text = (el.innerText || el.getAttribute("aria-label") || el.getAttribute("title") || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 120);
    const placeholder = (el.getAttribute("placeholder") || "").trim().slice(0, 80);
    const href = tag === "a" ? (el.getAttribute("href") || "").trim().slice(0, 160) : "";
    els.push({
      tag,
      text,
      placeholder,
      href,
      x: Math.round(rect.left + rect.width / 2),
      y: Math.round(rect.top + rect.height / 2)
    });
  }
  return { visible_text: rawText, elements: els };
}"""


def _scrub_browser_str(value: str) -> str:
    scrubbed = str(redact_payload_strict(value))
    return _INLINE_TOKEN_RE.sub("[REDACTED]", scrubbed)
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

    def _on_new_page(self, page: Page) -> None:
        self._page = page

    def _active_page(self) -> Page | None:
        if self._context is None:
            self._page = None
            return None
        if self._page is not None and not self._page.is_closed():
            return self._page
        open_pages = [p for p in self._context.pages if not p.is_closed()]
        self._page = open_pages[-1] if open_pages else None
        return self._page

    @property
    def running(self) -> bool:
        return self._active_page() is not None

    async def status(self) -> dict[str, Any]:
        """Return current browser running status, URL, and page title."""
        async with self._lock:
            return await self._unlocked_status()

    async def _unlocked_status(self) -> dict[str, Any]:
        page = self._active_page()
        if page is None:
            return {
                "running": False,
                "url": "",
                "title": "",
                "viewport": {"width": _VIEWPORT_WIDTH, "height": _VIEWPORT_HEIGHT},
            }
        title = ""
        with contextlib.suppress(Exception):
            title = await page.title()
        return {
            "running": True,
            "url": page.url,
            "title": title,
            "viewport": {"width": _VIEWPORT_WIDTH, "height": _VIEWPORT_HEIGHT},
        }

    async def _ensure_context_unlocked(self) -> Page:
        existing = self._active_page()
        if existing is not None:
            return existing
        self._profile_root.mkdir(parents=True, exist_ok=True)
        self._playwright = await async_playwright().start()
        self._context = await self._playwright.chromium.launch_persistent_context(
            user_data_dir=str(self._profile_root),
            headless=True,
            viewport={"width": _VIEWPORT_WIDTH, "height": _VIEWPORT_HEIGHT},
        )
        self._context.set_default_timeout(12000)
        self._context.on("page", self._on_new_page)
        pages = self._context.pages
        self._page = pages[0] if pages else await self._context.new_page()
        return self._page

    async def start(self, initial_url: str | None = None) -> dict[str, Any]:
        """Lazily start persistent Chromium browser if not already running."""
        async with self._lock:
            was_running = self._active_page() is not None
            page = await self._ensure_context_unlocked()
            if initial_url and initial_url.strip():
                target = normalize_browser_url(initial_url)
                await page.goto(target, wait_until="domcontentloaded")
            elif not was_running:
                await page.set_content(_WELCOME_HTML, wait_until="domcontentloaded")
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
            page = await self._ensure_context_unlocked()
            await page.goto(target, wait_until="domcontentloaded")
            return await self._unlocked_status()

    async def go_back(self) -> dict[str, Any]:
        async with self._lock:
            page = self._active_page()
            if page is not None:
                with contextlib.suppress(Exception):
                    await page.go_back(wait_until="domcontentloaded")
            return await self._unlocked_status()

    async def go_forward(self) -> dict[str, Any]:
        async with self._lock:
            page = self._active_page()
            if page is not None:
                with contextlib.suppress(Exception):
                    await page.go_forward(wait_until="domcontentloaded")
            return await self._unlocked_status()

    async def reload(self) -> dict[str, Any]:
        async with self._lock:
            page = self._active_page()
            if page is not None:
                with contextlib.suppress(Exception):
                    await page.reload(wait_until="domcontentloaded")
            return await self._unlocked_status()

    async def _apply_input_unlocked(self, page: Page, event: dict[str, Any]) -> None:
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
            await page.mouse.click(x, y, button=btn)
        elif ev_type == "dblclick":
            x = max(0.0, min(float(_VIEWPORT_WIDTH), float(event.get("x", 0.0))))
            y = max(0.0, min(float(_VIEWPORT_HEIGHT), float(event.get("y", 0.0))))
            await page.mouse.dblclick(x, y)
        elif ev_type == "wheel":
            dx = float(event.get("dx", 0.0))
            dy = float(event.get("dy", 0.0))
            await page.mouse.wheel(dx, dy)
        elif ev_type == "type":
            text = str(event.get("text", ""))
            if text:
                await page.keyboard.type(text)
        elif ev_type == "key":
            key = str(event.get("key", ""))
            if key:
                await page.keyboard.press(key)

    async def handle_input(self, event: dict[str, Any]) -> None:
        """Apply mouse/keyboard interaction event onto the active page."""
        async with self._lock:
            page = self._active_page()
            if page is None:
                return
            await self._apply_input_unlocked(page, event)

    async def capture_frame(self, quality: int = 72) -> dict[str, Any] | None:
        """Capture a compressed JPEG screenshot frame if the browser is running."""
        async with self._lock:
            page = self._active_page()
            if page is None:
                return None
            with contextlib.suppress(Exception):
                raw_bytes = await page.screenshot(type="jpeg", quality=quality)
                title = ""
                with contextlib.suppress(Exception):
                    title = await page.title()
                return {
                    "type": "frame",
                    "data": base64.b64encode(raw_bytes).decode("ascii"),
                    "url": page.url,
                    "title": title,
                    "width": _VIEWPORT_WIDTH,
                    "height": _VIEWPORT_HEIGHT,
                }
            return None

    async def extract_page_context(
        self,
        *,
        max_text_chars: int = 16000,
        max_elements: int = 40,
        screenshot_path: Path | None = None,
    ) -> dict[str, Any] | None:
        """Extract visible DOM text, interactive element coords, and optional JPEG snapshot."""
        async with self._lock:
            page = self._active_page()
            if page is None:
                return None
            title = ""
            with contextlib.suppress(Exception):
                title = await page.title()

            raw_eval: dict[str, Any] = {"visible_text": "", "elements": []}
            with contextlib.suppress(Exception):
                evaluated = await page.evaluate(_EXTRACT_JS, max_elements)
                if isinstance(evaluated, dict):
                    raw_eval = evaluated

            raw_text = re.sub(r"\n{3,}", "\n\n", str(raw_eval.get("visible_text", ""))).strip()
            text_truncated = len(raw_text) > max_text_chars
            visible_text = _scrub_browser_str(raw_text[:max_text_chars])

            elements: list[dict[str, Any]] = []
            raw_els = raw_eval.get("elements")
            if isinstance(raw_els, list):
                for item in raw_els[:max_elements]:
                    if not isinstance(item, dict):
                        continue
                    elements.append(
                        {
                            "tag": str(item.get("tag", ""))[:24],
                            "text": _scrub_browser_str(str(item.get("text", "")))[:120],
                            "placeholder": _scrub_browser_str(
                                str(item.get("placeholder", ""))
                            )[:80],
                            "href": _scrub_browser_str(str(item.get("href", "")))[:160],
                            "x": int(item.get("x", 0)),
                            "y": int(item.get("y", 0)),
                        }
                    )

            resolved_screenshot: str | None = None
            if screenshot_path is not None:
                with contextlib.suppress(Exception):
                    screenshot_path.parent.mkdir(parents=True, exist_ok=True)
                    await page.screenshot(path=str(screenshot_path), type="jpeg", quality=75)
                    if screenshot_path.is_file():
                        resolved_screenshot = str(screenshot_path.resolve())

            payload: dict[str, Any] = {
                "running": True,
                "url": _scrub_browser_str(page.url),
                "title": _scrub_browser_str(title),
                "visible_text": visible_text,
                "text_truncated": text_truncated,
                "elements": elements,
                "screenshot_path": resolved_screenshot,
            }
            scrubbed: dict[str, Any] = redact_payload_strict(payload)
            return scrubbed

    async def perform_action(
        self,
        event: dict[str, Any],
        *,
        screenshot_path: Path | None = None,
    ) -> dict[str, Any]:
        """Execute a high-level browser action and return updated status + page context."""
        ev_type = str(event.get("type", "")).strip().lower()
        if ev_type == "start":
            raw_url = event.get("url")
            st = await self.start(initial_url=str(raw_url) if isinstance(raw_url, str) else None)
        elif ev_type == "stop":
            st = await self.stop()
            return {"status": st, "context": None}
        elif ev_type == "navigate":
            raw_url = str(event.get("url", "")).strip()
            if not raw_url:
                raise ValueError("navigate action requires a non-empty 'url'.")
            st = await self.navigate(raw_url)
        elif ev_type == "back":
            st = await self.go_back()
        elif ev_type == "forward":
            st = await self.go_forward()
        elif ev_type == "reload":
            st = await self.reload()
        elif ev_type in {"click", "dblclick", "wheel", "type", "key"}:
            if not self.running:
                raise ValueError("Live browser is not running; start or navigate first.")
            await self.handle_input(event)
            await asyncio.sleep(0.25)
            st = await self.status()
        else:
            raise ValueError(f"Unsupported browser action: {ev_type or '<empty>'}")

        ctx = await self.extract_page_context(screenshot_path=screenshot_path)
        return {"status": st, "context": ctx}
