"""Lazy interactive Playwright browser controller for Live Computer Workspace."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Page, Playwright, async_playwright

from src.storage.redaction import redact_payload_strict

_VIEWPORT_WIDTH = 1280
_VIEWPORT_HEIGHT = 800
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]", "10.", "192.168.")
_INLINE_TOKEN_RE = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pou]_[A-Za-z0-9_]{8,})\b")
_SELECTOR_SAFE_RE = re.compile(r'["\\\x00-\x1f\x7f]')
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
    if (!text && !placeholder && !href) continue;
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


def _has_unsafe_authority_chars(value: str) -> bool:
    return any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def _extract_raw_authority(url_clean: str) -> str:
    if "://" not in url_clean:
        return ""
    after_scheme = url_clean.split("://", 1)[1]
    end = len(after_scheme)
    for sep in ("/", "?", "#"):
        idx = after_scheme.find(sep)
        if idx != -1 and idx < end:
            end = idx
    return after_scheme[:end]


def _parse_domain_spec(raw_spec: str) -> tuple[str | None, str, int | None] | None:
    """Parse a domain or URL spec into (explicit_scheme, host, explicit_port)."""
    exp = raw_spec.strip()
    if not exp or _has_unsafe_authority_chars(exp) or "@" in exp or "\\" in exp:
        return None
    has_scheme = "://" in exp
    if not has_scheme and ("/" in exp or "?" in exp or "#" in exp):
        return None
    candidate = exp if has_scheme else f"https://{exp}"
    try:
        parsed = urlparse(candidate)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or "\\" in parsed.netloc
        or _has_unsafe_authority_chars(parsed.netloc)
    ):
        return None
    scheme_low = parsed.scheme.lower()
    if has_scheme and scheme_low not in {"http", "https"}:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return None
    return (scheme_low if has_scheme else None), host, port


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def domain_matches_url(expected_domain: str, active_url: str) -> bool:
    """Return True iff `active_url` is an http(s) URL matching `expected_domain`."""
    exp_spec = _parse_domain_spec(expected_domain)
    if exp_spec is None:
        return False
    exp_scheme, exp_host, exp_port = exp_spec

    url_clean = active_url.strip()
    if not url_clean:
        return False
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url_clean):
        return False
    raw_authority = _extract_raw_authority(url_clean)
    if (
        not raw_authority
        or "@" in raw_authority
        or "\\" in raw_authority
        or _has_unsafe_authority_chars(raw_authority)
    ):
        return False
    try:
        parsed_url = urlparse(url_clean)
        actual_port = parsed_url.port
    except ValueError:
        return False
    if (
        parsed_url.username is not None
        or parsed_url.password is not None
        or "@" in parsed_url.netloc
        or "\\" in parsed_url.netloc
        or _has_unsafe_authority_chars(parsed_url.netloc)
    ):
        return False

    actual_scheme = parsed_url.scheme.lower()
    if actual_scheme not in {"http", "https"}:
        return False
    actual_host = (parsed_url.hostname or "").lower().rstrip(".")
    if not actual_host:
        return False

    if exp_scheme is not None and actual_scheme != exp_scheme:
        return False

    if exp_port is not None:
        effective_actual_port = (
            actual_port if actual_port is not None else (443 if actual_scheme == "https" else 80)
        )
        if effective_actual_port != exp_port:
            return False

    if _is_ip_literal(exp_host) or _is_ip_literal(actual_host):
        return actual_host == exp_host
    return actual_host == exp_host or actual_host.endswith(f".{exp_host}")


def domains_compatible(domain_a: str, domain_b: str) -> bool:
    """Return True iff two domain/URL specs denote the same or parent/subdomain origin."""
    spec_a = _parse_domain_spec(domain_a)
    spec_b = _parse_domain_spec(domain_b)
    if spec_a is None or spec_b is None:
        return False
    scheme_a, host_a, port_a = spec_a
    scheme_b, host_b, port_b = spec_b
    if scheme_a is not None and scheme_b is not None and scheme_a != scheme_b:
        return False
    if port_a is not None and port_b is not None and port_a != port_b:
        return False
    if _is_ip_literal(host_a) or _is_ip_literal(host_b):
        return host_a == host_b
    return (
        host_a == host_b
        or host_a.endswith(f".{host_b}")
        or host_b.endswith(f".{host_a}")
    )


def _candidate_selectors(field_name: str) -> list[str]:
    esc = _SELECTOR_SAFE_RE.sub("", field_name).strip()
    low = esc.lower()
    selectors: list[str] = []
    if esc:
        selectors.append(f'input[name="{esc}"]')
    if "pass" in low or low in {"pwd", "secret", "pin", "passcode"}:
        selectors.append('input[type="password"]')
        if esc:
            selectors.append(f'input[id*="{esc}"]')
    elif "email" in low or "user" in low or "login" in low:
        selectors.extend(
            [
                'input[type="email"]',
                'input[name*="user"]',
                'input[name*="email"]',
                'input[name*="login"]',
            ]
        )
        if esc:
            selectors.append(f'input[id*="{esc}"]')
        selectors.append('input[type="text"]')
    elif esc:
        selectors.extend(
            [
                f'textarea[name="{esc}"]',
                f'input[id="{esc}"]',
                f'[name*="{esc}"]',
            ]
        )
    return selectors


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

    def current_url(self) -> str | None:
        """Return the active page URL if the browser is running, else None."""
        page = self._active_page()
        return page.url if page is not None else None

    async def fill_credentials(
        self,
        fields: dict[str, str],
        *,
        expected_domain: str | Sequence[str] | None = None,
        submit_selector: str | None = None,
    ) -> dict[str, Any]:
        """Fill credential fields on the active page after fail-closed origin verification."""
        async with self._lock:
            page = self._active_page()
            if page is None:
                return {"filled": False, "reason": "browser_not_running", "url": None}
            active_url = page.url
            required_domains: list[str]
            if expected_domain is None:
                required_domains = []
            elif isinstance(expected_domain, str):
                cleaned_dom = expected_domain.strip()
                required_domains = [cleaned_dom] if cleaned_dom else []
            else:
                required_domains = [
                    str(dom).strip() for dom in expected_domain if str(dom).strip()
                ]
            if not required_domains:
                return {"filled": False, "reason": "domain_required", "url": active_url}
            for dom in required_domains:
                if not domain_matches_url(dom, active_url):
                    return {"filled": False, "reason": "origin_mismatch", "url": active_url}
            if not fields:
                return {"filled": False, "reason": "no_fields", "url": active_url}

            filled_fields: list[str] = []
            for field_name, field_value in fields.items():
                for selector in _candidate_selectors(field_name):
                    with contextlib.suppress(Exception):
                        loc = page.locator(selector)
                        if await loc.count() > 0:
                            await loc.first.fill(field_value, timeout=2000)
                            filled_fields.append(field_name)
                            break

            if filled_fields and submit_selector:
                with contextlib.suppress(Exception):
                    btn = page.locator(submit_selector)
                    if await btn.count() > 0:
                        await btn.first.click(timeout=2000)

            return {
                "filled": bool(filled_fields),
                "reason": "ok" if filled_fields else "no_matching_inputs",
                "url": active_url,
            }

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
