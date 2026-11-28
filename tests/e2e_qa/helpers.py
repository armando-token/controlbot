"""Shared isolated E2E QA harness helpers, surface checks, CLI runner, and leak guards."""

from __future__ import annotations

import asyncio
import atexit
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx
from playwright.async_api import Page
from tests.e2e._helpers import (
    IsolatedServer,
    LabStack,
    MockRfbServer,
)
from tests.e2e._helpers import (
    SseFrame as SseFrame,
)
from tests.e2e._helpers import (
    TurnResult as TurnResult,
)
from tests.e2e._helpers import (
    iter_sse_events as iter_sse_events,
)
from tests.e2e._helpers import (
    mint_cap_token as mint_cap_token,
)
from tests.e2e._helpers import (
    trigger_and_wait_turn as trigger_and_wait_turn,
)
from tests.e2e._helpers import (
    wait_for_sse_event as wait_for_sse_event,
)

FORBIDDEN_PORTS: frozenset[int] = frozenset({8000, 6080, 5900, 5901})

_HOST_HOME: Path = Path.home().resolve()
_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_SAFE_FALLBACK_PATH: tuple[str, ...] = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)
_ASSET_PATH_RE = re.compile(r"/assets/[A-Za-z0-9_.-]+\.(?:js|css)")
_BEARER_LEAK_RE = re.compile(
    r"(?i)\b(Bearer)\s+(?!\[REDACTED\](?:$|[\s,;)'\"\]\}]))(\S+)"
)
_BASIC_LEAK_RE = re.compile(
    r"(?i)\b(Basic)\s+(?!\[REDACTED\](?:$|[\s,;)'\"\]\}]))(\S+)"
)
_QUERY_SECRET_RE = re.compile(
    r"(?i)(?:[?&]|^)(?:token|cap_token|access_token|api_key|secret|password)="
    r"(?!(?:\[REDACTED\]|%5BREDACTED%5D)(?:$|[&\s\"',;)\]}]))([^&\s\"']+)"
)
_SENSITIVE_KEY_EXACT: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "secret_key",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "auth_token",
        "session_token",
        "csrf_token",
        "cap_token",
        "authorization",
        "cookie",
        "cookies",
        "set_cookie",
        "private_key",
        "client_secret",
        "credential",
        "credentials",
    }
)
_SENSITIVE_KEY_SUFFIXES: tuple[str, ...] = (
    "_password",
    "_passwd",
    "_secret",
    "_secret_key",
    "_api_key",
    "_apikey",
    "_token",
    "_access_token",
    "_refresh_token",
    "_auth_token",
    "_cookie",
    "_cookies",
    "_set_cookie",
    "_private_key",
    "_client_secret",
    "_credential",
    "_credentials",
)
_SAFE_KEY_TOKENS: frozenset[str] = frozenset(
    {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "max_total_tokens",
        "tokens_reserved",
        "prompt_tokens_used",
        "completion_tokens_used",
        "session_id",
        "task_id",
        "run_id",
        "step_id",
        "operation_key",
    }
)


class StrictPageProtocol(Protocol):
    """Structural protocol satisfied by StrictBrowserPage."""

    @property
    def page(self) -> Page: ...

    def assert_clean(
        self,
        *,
        allow_http_statuses: Sequence[int] = (),
        allow_console_substrings: Sequence[str] = (),
    ) -> None: ...


def alloc_qa_free_port(
    host: str = "127.0.0.1",
    *,
    exclude: set[int] | frozenset[int] = frozenset(),
) -> int:
    """Bind an ephemeral loopback port, strictly excluding all FORBIDDEN_PORTS."""
    blocked = FORBIDDEN_PORTS | set(exclude)
    for _ in range(64):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, 0))
            port = int(sock.getsockname()[1])
        if port not in blocked:
            return port
    raise RuntimeError(f"Failed to allocate a free port outside {sorted(blocked)}.")


def _sanitize_path_env(
    raw_path: str,
    *,
    allowed_root: Path | None = None,
    prepend_bin: Path | None = None,
) -> str:
    """Strip host agy / user-local / gemini bin directories from PATH."""
    resolved_allowed = allowed_root.resolve() if allowed_root is not None else None
    host_blocked_roots = (
        _HOST_HOME / ".local",
        _HOST_HOME / ".gemini",
    )
    cleaned: list[str] = []
    seen: set[str] = set()

    def _is_blocked(entry: str) -> bool:
        stripped = entry.strip()
        if not stripped or stripped == ".":
            return True
        try:
            resolved = Path(stripped).expanduser().resolve()
        except OSError:
            resolved = Path(stripped)
        if resolved_allowed is not None and resolved.is_relative_to(resolved_allowed):
            return False
        if any(resolved.is_relative_to(root) for root in host_blocked_roots):
            return True
        return bool(
            (Path(stripped) / "agy").exists()
            or (resolved / "agy").exists()
            or shutil.which("agy", path=stripped) is not None
        )

    for segment in raw_path.split(os.pathsep):
        if _is_blocked(segment):
            continue
        if segment not in seen:
            seen.add(segment)
            cleaned.append(segment)

    if not cleaned:
        for fallback in _SAFE_FALLBACK_PATH:
            if not _is_blocked(fallback) and fallback not in seen:
                seen.add(fallback)
                cleaned.append(fallback)

    if prepend_bin is not None:
        bin_str = str(prepend_bin)
        cleaned = [bin_str, *[p for p in cleaned if p != bin_str]]

    return os.pathsep.join(cleaned)


def _server_allocated_ports(server: IsolatedServer) -> set[int]:
    ports = {server.port, server.vnc_port}
    if server.lab_stack is not None:
        ports.update(
            {
                server.lab_stack.scada_port,
                server.lab_stack.maintenance_port,
                server.lab_stack.effect_sim_port,
            }
        )
    return ports


@dataclass
class IsolatedQAEnv:
    """Composition wrapper around IsolatedServer enforcing full live-port isolation."""

    tmp_dir: Path
    web_token: str | None = None
    cap_secret: str = "qa-e2e-cap-secret-0123456789abcdef"
    with_mock_rfb: bool = False
    with_lab: bool = False
    mock_agy_script: str | None = None
    extra_env: dict[str, str] = field(default_factory=dict)

    _server: IsolatedServer = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.tmp_dir = Path(self.tmp_dir)
        last_collision: set[int] = set()
        for attempt in range(5):
            attempt_dir = self.tmp_dir if attempt == 0 else self.tmp_dir / f"retry_{attempt}"
            srv = IsolatedServer(
                tmp_dir=attempt_dir,
                web_token=self.web_token,
                cap_secret=self.cap_secret,
                with_mock_rfb=self.with_mock_rfb,
                with_lab=self.with_lab,
                mock_agy_script=self.mock_agy_script,
                extra_env=dict(self.extra_env),
            )
            allocated = _server_allocated_ports(srv)
            collision = allocated & FORBIDDEN_PORTS
            if not collision:
                self._server = srv
                return
            last_collision = collision
            srv.stop()
        raise RuntimeError(
            f"IsolatedServer repeatedly collided with forbidden ports: {sorted(last_collision)}"
        )

    @property
    def port(self) -> int:
        return self._server.port

    @property
    def vnc_port(self) -> int:
        return self._server.vnc_port

    @property
    def base_url(self) -> str:
        return self._server.base_url

    @property
    def ws_base_url(self) -> str:
        return self._server.ws_base_url

    @property
    def db_path(self) -> Path:
        return self._server.db_path

    @property
    def workspace_db_path(self) -> Path:
        return self._server.workspace_db_path

    @property
    def logs_dir(self) -> Path:
        return self._server.workspace_db_path.parent / "logs"

    @property
    def projects_root(self) -> Path:
        return self._server.projects_root

    @property
    def fake_home(self) -> Path:
        return self._server.fake_home

    @property
    def brain_root(self) -> Path:
        return self._server.brain_root

    @property
    def profile_root(self) -> Path:
        return self._server.profile_root

    @property
    def vnc_passwd_path(self) -> Path:
        return self._server.vnc_passwd_path

    @property
    def env(self) -> dict[str, str]:
        return self._server.env

    @property
    def mock_rfb(self) -> MockRfbServer | None:
        return self._server.mock_rfb

    @property
    def lab_stack(self) -> LabStack | None:
        return self._server.lab_stack

    def start(self, *, timeout: float = 15.0) -> IsolatedQAEnv:
        self._server.start(timeout=timeout)
        self.assert_isolated_from_live()
        return self

    def stop(self) -> None:
        self._server.stop()

    def restart(
        self,
        *,
        keep_port: bool = False,
        extra_env: dict[str, str] | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._server.restart(keep_port=keep_port, extra_env=extra_env, timeout=timeout)
        for _ in range(4):
            if not (_server_allocated_ports(self._server) & FORBIDDEN_PORTS):
                break
            self._server.restart(keep_port=False, extra_env=extra_env, timeout=timeout)
        self.assert_isolated_from_live()

    def __enter__(self) -> IsolatedQAEnv:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    def url(self, path: str, *, include_token: bool = True) -> str:
        return self._server.url(path, include_token=include_token)

    def ws_url(self, path: str, *, include_token: bool = True) -> str:
        return self._server.ws_url(path, include_token=include_token)

    def auth_headers(self) -> dict[str, str]:
        return self._server.auth_headers()

    def client(self, timeout: float = 20.0) -> httpx.Client:
        return self._server.client(timeout=timeout)

    def async_client(self, timeout: float = 20.0) -> httpx.AsyncClient:
        return self._server.async_client(timeout=timeout)

    def assert_isolated_from_live(self) -> None:
        allocated = _server_allocated_ports(self._server)
        overlap = allocated & FORBIDDEN_PORTS
        assert not overlap, f"IsolatedQAEnv collided with forbidden live ports: {sorted(overlap)}"

        tmp_root = self._server.tmp_dir.resolve()
        live_var = (_REPO_ROOT / "var").resolve()

        assert self.fake_home.resolve() != _HOST_HOME
        assert self.fake_home.resolve().is_relative_to(tmp_root)
        assert self.db_path.resolve().is_relative_to(tmp_root)
        assert self.workspace_db_path.resolve().is_relative_to(tmp_root)
        assert self.profile_root.resolve().is_relative_to(tmp_root)
        assert not self.db_path.resolve().is_relative_to(live_var)
        assert not self.workspace_db_path.resolve().is_relative_to(live_var)

        assert self.env.get("GROKBOT_X11_DISPLAY") == ""
        assert "DISPLAY" not in self.env
        assert "WAYLAND_DISPLAY" not in self.env

        resolved_agy = shutil.which("agy", path=self.env.get("PATH", ""))
        if self.mock_agy_script is None:
            assert resolved_agy is None, f"Host agy leaked into sanitized PATH: {resolved_agy}"
        else:
            assert resolved_agy is not None
            assert Path(resolved_agy).resolve().is_relative_to(self.fake_home.resolve())


@dataclass(frozen=True)
class CliResult:
    """Captured subprocess outcome for opaque-box CLI invocations."""

    returncode: int
    stdout: str
    stderr: str
    command: list[str]
    duration_ms: float

    def json_stdout(self) -> dict[str, Any]:
        parsed = json.loads(self.stdout)
        if not isinstance(parsed, dict):
            raise AssertionError(f"Expected JSON object on stdout, got {type(parsed).__name__}")
        return parsed


@dataclass
class QACliRunner:
    """Runs opaque-box `python -m src.qa` and external commands in a sanitized environment."""

    cwd: Path | None = None
    fake_home: Path | None = None
    extra_env: Mapping[str, str] | None = None
    timeout: float = 60.0
    _ephemeral_bin_dir: Path | None = field(default=None, init=False, repr=False)

    def cleanup(self) -> None:
        """Remove any lazily created ephemeral uv-only bin directory."""
        if self._ephemeral_bin_dir is not None:
            shutil.rmtree(self._ephemeral_bin_dir, ignore_errors=True)
            self._ephemeral_bin_dir = None

    def _ensure_clean_uv_bin(self, uv_src: str) -> Path:
        if self.fake_home is not None:
            fake_bin = self.fake_home / ".local" / "bin"
        else:
            if self._ephemeral_bin_dir is None or not self._ephemeral_bin_dir.is_dir():
                created = Path(tempfile.mkdtemp(prefix="qa_cli_uv_"))
                self._ephemeral_bin_dir = created
                atexit.register(shutil.rmtree, str(created), ignore_errors=True)
            fake_bin = self._ephemeral_bin_dir
        fake_bin.mkdir(parents=True, exist_ok=True)
        fake_uv = fake_bin / "uv"
        if not fake_uv.exists():
            fake_uv.symlink_to(Path(uv_src).resolve())
        return fake_bin

    def build_env(self, env_overrides: Mapping[str, str] | None = None) -> dict[str, str]:
        env = os.environ.copy()
        for key in list(env):
            if (
                key.startswith(("GROKBOT_", "CONTROLBOT_"))
                or key in {"PORT", "DISPLAY", "WAYLAND_DISPLAY"}
            ):
                env.pop(key, None)

        home_dir = self.fake_home or (self.cwd or _REPO_ROOT)
        if self.fake_home is not None:
            self.fake_home.mkdir(parents=True, exist_ok=True)
            env["HOME"] = str(self.fake_home)
            default_pw = _HOST_HOME / ".cache" / "ms-playwright"
            fake_pw = self.fake_home / ".cache" / "ms-playwright"
            if default_pw.is_dir() and not fake_pw.exists():
                fake_pw.parent.mkdir(parents=True, exist_ok=True)
                fake_pw.symlink_to(default_pw)
        env["PYTHONUNBUFFERED"] = "1"

        if "PLAYWRIGHT_BROWSERS_PATH" not in env:
            default_pw = _HOST_HOME / ".cache" / "ms-playwright"
            if default_pw.is_dir():
                env["PLAYWRIGHT_BROWSERS_PATH"] = str(default_pw)

        if self.extra_env:
            env.update(self.extra_env)
        if env_overrides:
            env.update(env_overrides)

        allowed_root = self.fake_home if self.fake_home is not None else home_dir
        raw_path = env.get("PATH", "")
        sanitized_base = _sanitize_path_env(raw_path, allowed_root=allowed_root)

        prepend_bin: Path | None = None
        uv_src = shutil.which("uv", path=raw_path)
        if uv_src is not None and (
            self.fake_home is not None or shutil.which("uv", path=sanitized_base) is None
        ):
            prepend_bin = self._ensure_clean_uv_bin(uv_src)
            if self.fake_home is None:
                allowed_root = prepend_bin

        env["PATH"] = _sanitize_path_env(
            raw_path,
            allowed_root=allowed_root,
            prepend_bin=prepend_bin,
        )
        return env

    def run_command(
        self,
        cmd: Sequence[str],
        *,
        env_overrides: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        timeout: float | None = None,
    ) -> CliResult:
        cmd_list = [str(part) for part in cmd]
        effective_cwd = cwd or self.cwd or _REPO_ROOT
        effective_timeout = self.timeout if timeout is None else timeout
        env = self.build_env(env_overrides)
        started = time.monotonic()
        completed = subprocess.run(
            cmd_list,
            cwd=str(effective_cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            check=False,
        )
        elapsed_ms = (time.monotonic() - started) * 1000.0
        return CliResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            command=cmd_list,
            duration_ms=elapsed_ms,
        )

    def run_module(
        self,
        module: str,
        args: Sequence[str] = (),
        *,
        env_overrides: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        timeout: float | None = None,
    ) -> CliResult:
        return self.run_command(
            [sys.executable, "-m", module, *args],
            env_overrides=env_overrides,
            cwd=cwd,
            timeout=timeout,
        )

    def run(
        self,
        args: Sequence[str],
        *,
        env_overrides: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        timeout: float | None = None,
    ) -> CliResult:
        return self.run_module(
            "src.qa",
            args,
            env_overrides=env_overrides,
            cwd=cwd,
            timeout=timeout,
        )


def _extract_dist_assets(dist_dir: Path) -> tuple[set[str], set[str]]:
    index_path = dist_dir / "index.html"
    if not index_path.is_file():
        return set(), set()
    html_text = index_path.read_text(encoding="utf-8")
    assets = set(_ASSET_PATH_RE.findall(html_text))
    js_assets = {path for path in assets if path.endswith(".js")}
    css_assets = {path for path in assets if path.endswith(".css")}
    return js_assets, css_assets


async def assert_react_app_surface(
    base_url: str,
    page: Page | StrictPageProtocol,
    *,
    dist_dir: Path | None = None,
    web_token: str | None = None,
) -> dict[str, Any]:
    """Verify `/app` serves compiled React assets (not legacy studio.html) and renders cleanly."""
    clean_base = base_url.rstrip("/")
    effective_dist = dist_dir if dist_dir is not None else (_REPO_ROOT / "frontend" / "dist")
    expected_js, expected_css = _extract_dist_assets(effective_dist)

    token_qs = f"?{urlencode({'token': web_token})}" if web_token else ""
    app_url = f"{clean_base}/app{token_qs}"

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(app_url)
        assert resp.status_code == 200, f"GET /app returned {resp.status_code}"
        request_id = resp.headers.get("X-Request-Id", "")
        assert request_id.startswith("req_"), f"Missing X-Request-Id header: {resp.headers!r}"

        html = resp.text
        assert "<title>Grok Bot — ControlBot Studio</title>" in html, (
            "GET /app did not serve React title (<title>Grok Bot — ControlBot Studio</title>)."
        )
        assert "<title>ControlBot Studio</title>" not in html, (
            "GET /app fell back to legacy studio.html template!"
        )
        assert "controlbot.showPlantModule" not in html
        assert "Computador en Vivo" not in html

        served_assets = sorted(set(_ASSET_PATH_RE.findall(html)))
        served_js = {path for path in served_assets if path.endswith(".js")}
        served_css = {path for path in served_assets if path.endswith(".css")}
        assert served_js, f"No compiled /assets/*.js found in GET /app HTML: {html[:500]}"
        assert served_css, f"No compiled /assets/*.css found in GET /app HTML: {html[:500]}"

        if expected_js:
            assert served_js == expected_js, (
                f"Served JS assets {served_js} != built dist {expected_js}"
            )
        if expected_css:
            assert served_css == expected_css, (
                f"Served CSS assets {served_css} != built dist {expected_css}"
            )

        for asset_path in served_assets:
            asset_resp = await client.get(f"{clean_base}{asset_path}{token_qs}")
            assert asset_resp.status_code == 200, (
                f"Asset {asset_path} returned {asset_resp.status_code}"
            )
            assert len(asset_resp.content) > 0, f"Asset {asset_path} is empty"
            cache_hdr = asset_resp.headers.get("Cache-Control", "")
            assert "immutable" in cache_hdr, f"Missing immutable cache header on {asset_path}"

    raw_page: Page = page if isinstance(page, Page) else page.page
    await raw_page.goto(app_url, wait_until="domcontentloaded")
    composer = raw_page.locator('textarea[aria-label="Message composer"]')
    await composer.wait_for(state="visible", timeout=15000)

    rendered_title = await raw_page.title()
    assert rendered_title == "Grok Bot — ControlBot Studio", f"Unexpected title: {rendered_title!r}"
    data_theme = await raw_page.evaluate("document.documentElement.getAttribute('data-theme')")
    assert data_theme == "light", f"Expected data-theme='light', got {data_theme!r}"

    inspector_btn = raw_page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]')
    new_btn = raw_page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]')
    assert await inspector_btn.is_visible()
    assert await new_btn.is_visible()

    assert_clean_fn = getattr(page, "assert_clean", None)
    if callable(assert_clean_fn):
        assert_clean_fn()

    return {
        "title": rendered_title,
        "data_theme": data_theme,
        "assets": served_assets,
        "request_id": request_id,
    }


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    if normalized in _SAFE_KEY_TOKENS:
        return False
    if normalized in _SENSITIVE_KEY_EXACT:
        return True
    return normalized.endswith(_SENSITIVE_KEY_SUFFIXES)


def _is_redacted_or_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value in {"", "[REDACTED]", "%5BREDACTED%5D"}
    if isinstance(value, (list, tuple, dict, set, frozenset)):
        return len(value) == 0
    return False


def assert_no_secret_leak(obj: Any, secrets: Sequence[str] = ()) -> None:
    """Assert recursively that no canary secrets, unredacted keys, or auth strings leak."""
    canary_list = [s for s in secrets if s]

    def _scan(node: Any, path: str) -> None:
        if isinstance(node, Mapping):
            for k, v in node.items():
                key_str = str(k)
                child_path = f"{path}.{key_str}" if path else key_str
                if _is_sensitive_key(key_str) and not _is_redacted_or_empty(v):
                    raise AssertionError(
                        f"Unredacted sensitive key at {child_path!r}: {v!r}"
                    )
                _scan(v, child_path)
            return

        if isinstance(node, (list, tuple, set, frozenset)):
            for idx, item in enumerate(node):
                _scan(item, f"{path}[{idx}]")
            return

        if isinstance(node, str):
            for canary in canary_list:
                if canary in node:
                    raise AssertionError(f"Canary secret leaked at {path or '<root>'}")
            if _BEARER_LEAK_RE.search(node):
                raise AssertionError(f"Unredacted Bearer token leaked at {path or '<root>'}")
            if _BASIC_LEAK_RE.search(node):
                raise AssertionError(f"Unredacted Basic credentials leaked at {path or '<root>'}")
            if _QUERY_SECRET_RE.search(node):
                raise AssertionError(f"Unredacted query secret leaked at {path or '<root>'}")
            stripped = node.lstrip()
            if stripped.startswith(("{", "[")):
                try:
                    parsed_json = json.loads(stripped)
                except json.JSONDecodeError:
                    parsed_json = None
                if isinstance(parsed_json, (Mapping, list)):
                    _scan(parsed_json, f"{path}<json>")

    _scan(obj, "")


@dataclass(frozen=True)
class UxTimingResult:
    """UX interaction timing and affordance metrics."""

    actions_to_reach: int
    ttfp_ms: float | None
    completion_ms: float
    cancel_available: bool


async def measure_ttfp_and_completion[T](
    action: Callable[[], Awaitable[T]],
    *,
    actions_to_reach: int = 1,
    ttfp_probe: Callable[[], Awaitable[bool]] | None = None,
    cancel_available: bool = False,
    poll_interval_s: float = 0.02,
) -> tuple[T, UxTimingResult]:
    """Measure time-to-first-progress (TTFP) and completion latency of an async UX action."""
    started = time.monotonic()
    ttfp_ms: float | None = None
    stop_polling = asyncio.Event()

    async def _poll_progress() -> None:
        nonlocal ttfp_ms
        if ttfp_probe is None:
            return
        while not stop_polling.is_set():
            if await ttfp_probe():
                ttfp_ms = (time.monotonic() - started) * 1000.0
                return
            await asyncio.sleep(poll_interval_s)

    poller = asyncio.create_task(_poll_progress()) if ttfp_probe is not None else None
    try:
        result = await action()
    finally:
        stop_polling.set()
        if poller is not None:
            await poller

    completion_ms = (time.monotonic() - started) * 1000.0
    if ttfp_probe is None:
        ttfp_ms = completion_ms

    return result, UxTimingResult(
        actions_to_reach=actions_to_reach,
        ttfp_ms=ttfp_ms,
        completion_ms=completion_ms,
        cancel_available=cancel_available,
    )
