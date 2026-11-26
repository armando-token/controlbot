"""Cited web search adapter with SSRF egress guard, HTTP extractor, & Playwright bridge (CB-08)."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
import socket
from collections.abc import Sequence
from html.parser import HTMLParser
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

import httpx
from pydantic import Field

from src.contracts.common import FrozenModel, NonEmptyStr, UtcDatetime, utc_now


class EgressBlockedError(PermissionError):
    """Raised when a web fetch violates SSRF, scheme, redirect, or domain allowlist policy."""


class WebSearchResultItem(FrozenModel):
    """Structured search hit tagged with explicit untrusted provenance."""

    title: NonEmptyStr
    url: NonEmptyStr
    snippet: str = ""
    published_at: UtcDatetime | None = None
    is_primary_oem: bool = False
    manufacturer: str | None = None
    model: str | None = None
    provenance: Literal["untrusted"] = "untrusted"


class WebPageExtract(FrozenModel):
    """Extracted web page text/tables/specs tagged as untrusted external evidence."""

    url: NonEmptyStr
    final_url: NonEmptyStr
    status_code: int = Field(ge=100, le=599)
    title: str = ""
    text_excerpt: str = ""
    extracted_specs: dict[str, str] = Field(default_factory=dict)
    fetched_at: UtcDatetime = Field(default_factory=utc_now)
    is_primary_oem: bool = False
    provenance: Literal["untrusted"] = "untrusted"


class SearchBackend(Protocol):
    """Protocol for pluggable web search providers (deterministic fakes or live search)."""

    async def search(
        self,
        query: str,
        *,
        max_results: int = 5,
    ) -> Sequence[WebSearchResultItem]:
        """Return search candidates for query."""
        ...


class EgressGuard:
    """Validates outbound HTTP/HTTPS URLs against SSRF and optional domain allowlists."""

    def __init__(
        self,
        *,
        allowed_domains: Sequence[str] = (),
        allow_loopback_for_tests: bool = False,
    ) -> None:
        self._allowed_domains = tuple(
            d.strip().lower().lstrip(".") for d in allowed_domains if d.strip()
        )
        self._allow_loopback_for_tests = allow_loopback_for_tests

    def validate_url(self, url: str) -> str:
        clean = url.strip()
        parsed = urlparse(clean)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise EgressBlockedError(f"Blocked URL scheme {scheme!r}; only http/https allowed.")
        host = (parsed.hostname or "").strip().lower()
        if not host:
            raise EgressBlockedError(f"Blocked URL without hostname: {url!r}")

        if self._allowed_domains and not any(
            host == dom or host.endswith(f".{dom}") for dom in self._allowed_domains
        ):
            raise EgressBlockedError(
                f"Host {host!r} is outside allowed_domains {self._allowed_domains}."
            )

        if self._is_forbidden_host(host):
            raise EgressBlockedError(f"SSRF egress blocked for private/internal host {host!r}.")
        return clean

    def _is_forbidden_host(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
            return self._is_forbidden_ip(ip)
        except ValueError:
            pass

        if host in {"localhost", "localhost.localdomain"} or host.endswith(
            (".local", ".lan", ".internal", ".intranet")
        ):
            return not self._allow_loopback_for_tests

        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except OSError:
            return False
        for info in infos:
            addr = str(info[4][0])
            try:
                resolved_ip = ipaddress.ip_address(addr.split("%", 1)[0])
            except ValueError:
                continue
            if self._is_forbidden_ip(resolved_ip):
                return True
        return False

    def _is_forbidden_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if self._allow_loopback_for_tests and ip.is_loopback:
            return False
        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        )


class _SimpleHtmlSpecParser(HTMLParser):
    """Stdlib HTML parser extracting title, visible text, and key-value table/dl specs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._in_title = False
        self._in_cell = False
        self._cell_parts: list[str] = []
        self._current_row: list[str] = []
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.specs: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        low = tag.lower()
        if low in {"script", "style", "noscript"}:
            self._skip_depth += 1
        elif low == "title":
            self._in_title = True
        elif low == "tr":
            self._current_row = []
        elif low in {"td", "th", "dt", "dd"}:
            self._in_cell = True
            self._cell_parts = []

    def handle_endtag(self, tag: str) -> None:
        low = tag.lower()
        if low in {"script", "style", "noscript"} and self._skip_depth > 0:
            self._skip_depth -= 1
        elif low == "title":
            self._in_title = False
        elif low in {"td", "th", "dt", "dd"}:
            self._in_cell = False
            cell_txt = re.sub(r"\s+", " ", "".join(self._cell_parts)).strip()
            if cell_txt:
                self._current_row.append(cell_txt)
            if low == "dd" and len(self._current_row) >= 2:
                k = self._current_row[0].strip(": ").lower()
                v = self._current_row[1].strip()
                if k and v:
                    self.specs[k] = v
                self._current_row = []
        elif low == "tr":
            if len(self._current_row) >= 2:
                k = self._current_row[0].strip(": ").lower()
                v = self._current_row[1].strip()
                if k and v:
                    self.specs[k] = v
            self._current_row = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        if self._in_title:
            self.title_parts.append(data)
        if self._in_cell:
            self._cell_parts.append(data)
        cleaned = data.strip()
        if cleaned:
            self.text_parts.append(cleaned)


def parse_html_specs(html_text: str) -> tuple[str, str, dict[str, str]]:
    """Parse HTML into (title, normalized_text, key_value_specs) using stdlib HTMLParser."""
    parser = _SimpleHtmlSpecParser()
    parser.feed(html_text)
    parser.close()
    title = re.sub(r"\s+", " ", "".join(parser.title_parts)).strip()
    body = re.sub(r"\s+", " ", " ".join(parser.text_parts)).strip()
    return title, body, parser.specs


class HttpWebFetcher:
    """Async HTTP fetcher enforcing EgressGuard, trust_env=False, and follow_redirects=False."""

    def __init__(
        self,
        *,
        egress_guard: EgressGuard | None = None,
        timeout_s: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        oem_domains: Sequence[str] = (),
    ) -> None:
        self._guard = egress_guard or EgressGuard()
        self._timeout_s = timeout_s
        self._transport = transport
        self._oem_domains = tuple(d.strip().lower().lstrip(".") for d in oem_domains if d.strip())

    def _is_oem_url(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").strip().lower()
        return any(host == d or host.endswith(f".{d}") for d in self._oem_domains)

    async def fetch(self, url: str, *, is_primary_oem: bool | None = None) -> WebPageExtract:
        validated_url = self._guard.validate_url(url)
        client_kwargs: dict[str, Any] = {
            "trust_env": False,
            "follow_redirects": False,
            "timeout": self._timeout_s,
        }
        if self._transport is not None:
            client_kwargs["transport"] = self._transport

        async with httpx.AsyncClient(**client_kwargs) as client:
            resp = await client.get(validated_url)

        if 300 <= resp.status_code < 400:
            loc = resp.headers.get("location", "")
            raise EgressBlockedError(
                f"HTTP redirect blocked by EgressGuard ({resp.status_code} -> {loc!r})."
            )

        title, text_body, specs = parse_html_specs(resp.text)
        oem_flag = is_primary_oem if is_primary_oem is not None else self._is_oem_url(validated_url)
        return WebPageExtract(
            url=validated_url,
            final_url=str(resp.url),
            status_code=resp.status_code,
            title=title,
            text_excerpt=text_body[:4000],
            extracted_specs=specs,
            fetched_at=utc_now(),
            is_primary_oem=oem_flag,
            provenance="untrusted",
        )


class PlaywrightMcpBridge:
    """Optional Playwright accessibility/content extractor guarded by EgressGuard."""

    def __init__(self, *, egress_guard: EgressGuard | None = None) -> None:
        self._guard = egress_guard or EgressGuard()

    async def fetch_rendered(
        self,
        url: str,
        *,
        timeout_ms: int = 15000,
        is_primary_oem: bool = False,
    ) -> WebPageExtract:
        validated_url = self._guard.validate_url(url)
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-proxy-server"],
            )
            context = await browser.new_context(service_workers="block")
            nav_blocked: list[str] = []

            async def _handle_route(route: Any) -> None:
                req_url = route.request.url
                is_nav = route.request.is_navigation_request()
                try:
                    self._guard.validate_url(req_url)
                except EgressBlockedError as exc:
                    if is_nav:
                        nav_blocked.append(str(exc))
                    with contextlib.suppress(Exception):
                        await route.abort("blockedbyclient")
                    return
                try:
                    resp = await route.fetch(max_redirects=0)
                except Exception as exc:  # noqa: BLE001
                    if is_nav:
                        nav_blocked.append(f"Egress fetch error for {req_url!r}: {exc}")
                    with contextlib.suppress(Exception):
                        await route.abort("failed")
                    return
                if 300 <= resp.status < 400:
                    loc = resp.headers.get("location", "")
                    if is_nav:
                        nav_blocked.append(
                            f"HTTP redirect blocked by EgressGuard ({resp.status} -> {loc!r})."
                        )
                    with contextlib.suppress(Exception):
                        await route.abort("blockedbyclient")
                    return
                with contextlib.suppress(Exception):
                    await route.fulfill(response=resp)

            try:
                await context.route("**/*", _handle_route)
                page = await context.new_page()
                try:
                    resp = await page.goto(
                        validated_url, timeout=timeout_ms, wait_until="domcontentloaded"
                    )
                except Exception as exc:
                    if nav_blocked:
                        raise EgressBlockedError(nav_blocked[0]) from exc
                    raise
                if nav_blocked:
                    raise EgressBlockedError(nav_blocked[0])
                try:
                    final_url = page.url
                    self._guard.validate_url(final_url)
                    title = await page.title()
                    html = await page.content()
                except EgressBlockedError:
                    raise
                except Exception as exc:
                    if not nav_blocked:
                        await asyncio.sleep(0.05)
                    if nav_blocked:
                        raise EgressBlockedError(nav_blocked[0]) from exc
                    raise
                if nav_blocked:
                    raise EgressBlockedError(nav_blocked[0])
                _, body_text, specs = parse_html_specs(html)
                return WebPageExtract(
                    url=validated_url,
                    final_url=final_url,
                    status_code=resp.status if resp is not None else 200,
                    title=title,
                    text_excerpt=body_text[:4000],
                    extracted_specs=specs,
                    fetched_at=utc_now(),
                    is_primary_oem=is_primary_oem,
                    provenance="untrusted",
                )
            finally:
                with contextlib.suppress(Exception):
                    await context.close()
                await browser.close()


__all__ = [
    "EgressBlockedError",
    "EgressGuard",
    "HttpWebFetcher",
    "PlaywrightMcpBridge",
    "SearchBackend",
    "WebPageExtract",
    "WebSearchResultItem",
    "parse_html_specs",
]
