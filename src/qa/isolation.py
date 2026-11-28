"""Lab-vs-live isolation boundaries, lab servers, Playwright session, and safe log reader."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlparse

import httpx
from playwright.async_api import (
    Browser,
    BrowserContext,
    ConsoleMessage,
    Page,
    Playwright,
    Response,
    Route,
    WebSocketRoute,
    async_playwright,
)

from src.contracts.redaction import REDACTED_PLACEHOLDER
from src.factory.errors import IsolationBoundaryError
from src.storage.redaction import (
    contains_unredacted_secret_strict,
    is_sensitive_key_strict,
    redact_payload_strict,
    redact_string_strict,
)
from src.web.diagnostics import _SENSITIVE_QUERY_KEYS, scrub_url
from src.web.v1.rfb_gate import _VNC_PASSWD_FIXED_KEY, des_encrypt_block

LIVE_FORBIDDEN_PORTS: frozenset[int] = frozenset({8000, 6080, 5900, 5901})
ALLOWED_GROKBOT_BOTS: frozenset[str] = frozenset({"main", "test"})
FORBIDDEN_GROKBOT_CONFIG_DIR: Path = Path.home().resolve() / ".config" / "Grok Bot"

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_HOST_HOME: Path = Path.home().resolve()
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_SAFE_FALLBACK_PATH: tuple[str, ...] = ("/usr/local/bin", "/usr/bin", "/bin")
_DB_PATH_ENV_KEY: str = "GROKBOT_" + "DB_PATH"
_LEGACY_PROFILES_DIR_NAME: str = "." + "grokbot_profiles"
_VNC_LAB_KEY: bytes = b"qalabvnc"
_LOG_FILES: tuple[str, ...] = (
    "failures.jsonl",
    "frontend_errors.jsonl",
    "requests.jsonl",
    "watchdog.jsonl",
)


def _write_lab_vnc_passwd(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    padded = _VNC_LAB_KEY[:8].ljust(8, b"\x00")
    encrypted = des_encrypt_block(_VNC_PASSWD_FIXED_KEY, padded)
    path.write_bytes(encrypted)
    path.chmod(0o600)


def _extract_port_from_target(target: str | int) -> int | None:
    if isinstance(target, int):
        return target
    raw = target.strip()
    if not raw:
        return None
    if raw.isdigit():
        return int(raw)
    candidate = raw if "://" in raw else f"http://{raw}"
    parsed = urlparse(candidate)
    try:
        return parsed.port
    except ValueError:
        return None


def assert_not_live_target(target: str | int, *, allow_readonly: bool = False) -> None:
    """Reject mutating operations targeting live ControlBot/noVNC/VNC ports."""
    if allow_readonly:
        return
    port = _extract_port_from_target(target)
    if port is not None and port in LIVE_FORBIDDEN_PORTS:
        raise IsolationBoundaryError(
            f"Mutating target {target!r} on live port {port} is forbidden (blocked)."
        )


def assert_allowed_grokbot_target(bot_name: str) -> str:
    """Permit interaction ONLY with the installed Grok Bot 'main' and 'test' bots."""
    normalized = bot_name.strip()
    if normalized not in ALLOWED_GROKBOT_BOTS:
        raise IsolationBoundaryError(
            f"Grok Bot target {bot_name!r} is forbidden; "
            "only 'main' and 'test' are allowed (blocked)."
        )
    return normalized


def _is_under(path: Path, parent: Path) -> bool:
    return path == parent or path.is_relative_to(parent)


def assert_safe_mutation_path(path: Path | str, *, repo_root: Path | None = None) -> Path:
    """Verify a writable path does not touch live DBs, profiles, logs, or Grok Bot host state."""
    raw_path = Path(path).expanduser()
    resolved = raw_path.resolve()
    effective_repo = (repo_root or _REPO_ROOT).resolve()

    forbidden_roots: list[Path] = [
        FORBIDDEN_GROKBOT_CONFIG_DIR,
        Path("/home/user/.config/Grok Bot").resolve(),
        _HOST_HOME / ".gemini",
        _HOST_HOME / ".local" / "bin" / "agy",
        effective_repo / "var" / "logs",
        effective_repo / "var" / "browser_profiles",
        effective_repo / "browser_profiles",
    ]
    for root in forbidden_roots:
        if _is_under(resolved, root.resolve()):
            raise IsolationBoundaryError(
                f"Writable path {str(resolved)!r} targets protected directory "
                f"{str(root)!r} (blocked)."
            )

    env_db = os.environ.get(_DB_PATH_ENV_KEY, "").strip()
    if env_db:
        env_db_path = Path(env_db).expanduser().resolve()
        protected_db_paths = (
            env_db_path,
            Path(f"{env_db_path}-wal"),
            Path(f"{env_db_path}-shm"),
            Path(f"{env_db_path}-journal"),
        )
        for protected_db in protected_db_paths:
            if resolved == protected_db or _is_under(protected_db, resolved):
                raise IsolationBoundaryError(
                    f"Writable path {str(resolved)!r} conflicts with active "
                    f"{_DB_PATH_ENV_KEY} (blocked)."
                )

    var_root = (effective_repo / "var").resolve()
    if resolved == var_root:
        raise IsolationBoundaryError(
            f"Writable path {str(resolved)!r} targets protected var/ root directory (blocked)."
        )

    for part in resolved.parts:
        if part in {_LEGACY_PROFILES_DIR_NAME, "browser_profiles"}:
            raise IsolationBoundaryError(
                f"Writable path {str(resolved)!r} contains forbidden profile marker "
                f"{part!r} (blocked)."
            )

    parts_lower = [part.lower() for part in resolved.parts]
    name_lower = resolved.name.lower()
    if (
        name_lower.startswith(("controlbot", "grokbot"))
        and ".sqlite3" in name_lower
        and "var" in parts_lower
    ):
        raise IsolationBoundaryError(
            f"Writable path {str(resolved)!r} targets live var/ runtime SQLite database (blocked)."
        )
    if (
        "var" in parts_lower
        and "logs" in parts_lower
        and parts_lower.index("logs") == parts_lower.index("var") + 1
    ):
        raise IsolationBoundaryError(
            f"Writable path {str(resolved)!r} targets live var/logs directory (blocked)."
        )

    return resolved


def alloc_ephemeral_port(host: str = "127.0.0.1", *, exclude: Collection[int] = ()) -> int:
    """Bind and release an ephemeral TCP port excluding live forbidden ports."""
    blocked = set(LIVE_FORBIDDEN_PORTS) | set(exclude)
    for _ in range(64):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, 0))
            port = int(sock.getsockname()[1])
        if port not in blocked:
            return port
    raise RuntimeError("Unable to allocate an ephemeral port outside forbidden live ports.")


@dataclass(frozen=True)
class LabWorkspacePaths:
    """Filesystem paths for an isolated ephemeral QA lab run."""

    root_dir: Path
    fake_home: Path
    projects_root: Path
    brain_root: Path
    profile_root: Path
    playwright_user_data_dir: Path
    db_path: Path
    workspace_db_path: Path
    logs_dir: Path
    vnc_passwd_path: Path


def allocate_lab_workspace(
    base_dir: Path | None = None,
    *,
    prefix: str = "cb_qa_lab_",
    repo_root: Path | None = None,
) -> LabWorkspacePaths:
    """Allocate a clean, isolated temporary workspace for lab server and browser checks."""
    if base_dir is not None:
        base_resolved = assert_safe_mutation_path(base_dir, repo_root=repo_root)
        base_resolved.mkdir(parents=True, exist_ok=True)
        root_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=str(base_resolved)))
    else:
        root_dir = Path(tempfile.mkdtemp(prefix=prefix))

    root_resolved = assert_safe_mutation_path(root_dir, repo_root=repo_root)
    fake_home = root_resolved / "fake_home"
    projects_root = root_resolved / "Projects"
    demo_project = projects_root / "Grokbotclon"
    brain_root = root_resolved / "brain"
    profile_root = root_resolved / "lab_profiles"
    playwright_user_data_dir = root_resolved / "playwright_profile"
    logs_dir = root_resolved / "logs"

    for directory in (
        fake_home,
        demo_project,
        brain_root,
        profile_root,
        playwright_user_data_dir,
        logs_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    readme = demo_project / "README.md"
    if not readme.exists():
        readme.write_text("# Grokbotclon QA Lab Workspace\n", encoding="utf-8")

    vnc_passwd_path = root_resolved / "vnc_passwd"
    _write_lab_vnc_passwd(vnc_passwd_path)

    return LabWorkspacePaths(
        root_dir=root_resolved,
        fake_home=fake_home,
        projects_root=projects_root,
        brain_root=brain_root,
        profile_root=profile_root,
        playwright_user_data_dir=playwright_user_data_dir,
        db_path=root_resolved / "controlbot.sqlite3",
        workspace_db_path=root_resolved / "controlbot_workspace.sqlite3",
        logs_dir=logs_dir,
        vnc_passwd_path=vnc_passwd_path,
    )


_WORKTREE_LOCKS_GUARD = threading.Lock()
_WORKTREE_LOCKS: dict[str, threading.Lock] = {}


def _resolve_git_common_dir(repo_root: Path) -> Path | None:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    common = Path(proc.stdout.strip())
    return (repo_root / common).resolve() if not common.is_absolute() else common.resolve()


@contextlib.contextmanager
def _git_worktree_metadata_lock(repo_root: Path) -> Iterator[None]:
    """Serialize git worktree metadata mutations per repository (thread + process)."""
    common_git_dir = _resolve_git_common_dir(repo_root)
    lock_key = str(common_git_dir if common_git_dir is not None else repo_root)
    with _WORKTREE_LOCKS_GUARD:
        thread_lock = _WORKTREE_LOCKS.get(lock_key)
        if thread_lock is None:
            thread_lock = threading.Lock()
            _WORKTREE_LOCKS[lock_key] = thread_lock

    with thread_lock:
        lock_fd: int | None = None
        if common_git_dir is not None and common_git_dir.is_dir():
            lock_path = common_git_dir / "cb_qa_worktree.lock"
            try:
                lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except OSError:
                if lock_fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(lock_fd)
                    lock_fd = None
        try:
            yield
        finally:
            if lock_fd is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                with contextlib.suppress(OSError):
                    os.close(lock_fd)


@contextlib.contextmanager
def ephemeral_git_worktree(
    repo_root: Path,
    ref: str = "HEAD",
    dest_dir: Path | None = None,
) -> Iterator[Path]:
    """Create a detached ephemeral git worktree and clean it up on exit."""
    resolved_repo = repo_root.resolve()
    owned_tmp: Path | None = None
    if dest_dir is None:
        owned_tmp = Path(tempfile.mkdtemp(prefix="cb_qa_wt_"))
        worktree_dir = owned_tmp / f"wt_{uuid.uuid4().hex[:12]}"
    else:
        worktree_dir = assert_safe_mutation_path(dest_dir, repo_root=resolved_repo)

    with _git_worktree_metadata_lock(resolved_repo):
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(resolved_repo),
                "worktree",
                "add",
                "--detach",
                str(worktree_dir),
                ref,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            if owned_tmp is not None:
                shutil.rmtree(owned_tmp, ignore_errors=True)
            subprocess.run(
                ["git", "-C", str(resolved_repo), "worktree", "prune"],
                capture_output=True,
                text=True,
                check=False,
            )
    if proc.returncode != 0:
        raise RuntimeError(f"git worktree add failed: {proc.stderr.strip()}")
    try:
        yield worktree_dir
    finally:
        with _git_worktree_metadata_lock(resolved_repo):
            rm_proc = subprocess.run(
                [
                    "git",
                    "-C",
                    str(resolved_repo),
                    "worktree",
                    "remove",
                    "--force",
                    str(worktree_dir),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if owned_tmp is not None:
                shutil.rmtree(owned_tmp, ignore_errors=True)
            if rm_proc.returncode != 0:
                subprocess.run(
                    ["git", "-C", str(resolved_repo), "worktree", "prune"],
                    capture_output=True,
                    text=True,
                    check=False,
                )


class IsolatedLabServer:
    """Manages an isolated ephemeral ControlBot Studio uvicorn subprocess."""

    def __init__(
        self,
        *,
        repo_root: Path | None = None,
        base_dir: Path | None = None,
        web_token: str | None = None,
        cap_secret: str = "qa-lab-cap-secret-0123456789abcdef",
        extra_env: Mapping[str, str] | None = None,
    ) -> None:
        self.repo_root: Path = (repo_root or _REPO_ROOT).resolve()
        self.workspace: LabWorkspacePaths = allocate_lab_workspace(
            base_dir=base_dir,
            repo_root=self.repo_root,
        )
        self.web_token = web_token
        self.cap_secret = cap_secret
        self.extra_env: dict[str, str] = dict(extra_env or {})
        self.vnc_port: int = alloc_ephemeral_port()
        self.port: int = alloc_ephemeral_port(exclude={self.vnc_port})
        assert_not_live_target(self.port)
        self.base_url: str = f"http://127.0.0.1:{self.port}"
        self.ws_base_url: str = f"ws://127.0.0.1:{self.port}"
        self.env: dict[str, str] = self._build_env()
        self._proc: subprocess.Popen[bytes] | None = None
        self._stdout_file: Any = None
        self._stderr_file: Any = None
        self._cleanup_root_on_exit: bool = base_dir is None

    def _sanitize_path(self, raw_path: str) -> str:
        tmp_root = self.workspace.root_dir.resolve()
        host_blocked_roots = (_HOST_HOME / ".local", _HOST_HOME / ".gemini")
        cleaned: list[str] = []
        seen: set[str] = set()

        def _is_host_agy_dir(entry: str) -> bool:
            stripped = entry.strip()
            if not stripped or stripped == ".":
                return True
            try:
                resolved = Path(stripped).expanduser().resolve()
            except OSError:
                resolved = Path(stripped)
            if resolved.is_relative_to(tmp_root):
                return False
            if any(resolved.is_relative_to(root) for root in host_blocked_roots):
                return True
            return bool(
                (Path(stripped) / "agy").exists()
                or (resolved / "agy").exists()
                or shutil.which("agy", path=stripped) is not None
            )

        for segment in raw_path.split(os.pathsep):
            if _is_host_agy_dir(segment):
                continue
            if segment not in seen:
                seen.add(segment)
                cleaned.append(segment)

        if not cleaned:
            for fallback in _SAFE_FALLBACK_PATH:
                if not _is_host_agy_dir(fallback) and fallback not in seen:
                    seen.add(fallback)
                    cleaned.append(fallback)
        return os.pathsep.join(cleaned)

    def _build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        for key in list(env):
            if (
                key.startswith(("GROKBOT_", "CONTROLBOT_"))
                or key in {"PORT", "DISPLAY", "WAYLAND_DISPLAY"}
            ):
                env.pop(key, None)

        env.update(
            {
                "HOME": str(self.workspace.fake_home),
                _DB_PATH_ENV_KEY: str(self.workspace.db_path),
                "GROKBOT_PROFILE_ROOT": str(self.workspace.profile_root),
                "CONTROLBOT_PROJECTS_ROOT": str(self.workspace.projects_root),
                "CONTROLBOT_AGY_BRAIN_ROOT": str(self.workspace.brain_root),
                "CONTROLBOT_BASE_URL": self.base_url,
                "GROKBOT_BASE_URL": self.base_url,
                "CONTROLBOT_PORT": str(self.port),
                "PORT": str(self.port),
                "GROKBOT_CAP_SECRET": self.cap_secret,
                "GROKBOT_VNC_HOST": "127.0.0.1",
                "GROKBOT_VNC_PORT": str(self.vnc_port),
                "GROKBOT_VNC_PASSWD_PATH": str(self.workspace.vnc_passwd_path),
                "GROKBOT_X11_DISPLAY": "",
                "PYTHONUNBUFFERED": "1",
            }
        )
        if self.web_token is not None:
            env["GROKBOT_WEB_TOKEN"] = self.web_token
            env["CONTROLBOT_WEB_TOKEN"] = self.web_token
        if self.extra_env:
            env.update(self.extra_env)

        env["PATH"] = self._sanitize_path(env.get("PATH", ""))

        if "PLAYWRIGHT_BROWSERS_PATH" not in self.extra_env:
            host_pw = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
            if host_pw:
                env["PLAYWRIGHT_BROWSERS_PATH"] = host_pw
            else:
                default_pw = _HOST_HOME / ".cache" / "ms-playwright"
                if default_pw.is_dir():
                    env["PLAYWRIGHT_BROWSERS_PATH"] = str(default_pw)

        if "GROKBOT_LLM_BASE_URL" not in self.extra_env:
            env.pop("GROKBOT_LLM_BASE_URL", None)
        return env

    def start(self, *, timeout: float = 15.0) -> IsolatedLabServer:
        if self._proc is not None and self._proc.poll() is None:
            return self

        stdout_path = self.workspace.root_dir / "uvicorn.stdout.log"
        stderr_path = self.workspace.root_dir / "uvicorn.stderr.log"
        self._stdout_file = stdout_path.open("wb")
        self._stderr_file = stderr_path.open("wb")

        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "src.web.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--log-level",
            "warning",
        ]
        try:
            self._proc = subprocess.Popen(
                cmd,
                cwd=str(self.repo_root),
                env=self.env,
                stdout=self._stdout_file,
                stderr=self._stderr_file,
            )
            self._wait_healthy(timeout=timeout, stdout_path=stdout_path, stderr_path=stderr_path)
        except Exception:
            self.stop()
            raise
        return self

    def _wait_healthy(self, *, timeout: float, stdout_path: Path, stderr_path: Path) -> None:
        deadline = time.monotonic() + timeout
        last_exc: Exception | None = None
        with httpx.Client(timeout=2.0, trust_env=False) as client:
            while time.monotonic() < deadline:
                if self._proc is not None and self._proc.poll() is not None:
                    stdout_txt = stdout_path.read_text(encoding="utf-8", errors="replace")
                    stderr_txt = stderr_path.read_text(encoding="utf-8", errors="replace")
                    raise RuntimeError(
                        f"Isolated lab uvicorn exited prematurely ({self._proc.returncode}).\n"
                        f"STDOUT:\n{stdout_txt[-1500:]}\nSTDERR:\n{stderr_txt[-1500:]}"
                    )
                try:
                    resp = client.get(f"{self.base_url}/health")
                    if resp.status_code == 200:
                        return
                except httpx.HTTPError as exc:
                    last_exc = exc
                time.sleep(0.05)

        stderr_txt = stderr_path.read_text(encoding="utf-8", errors="replace")
        raise TimeoutError(
            f"Timed out waiting for isolated lab server {self.base_url}/health "
            f"(last_exc={last_exc!r}). STDERR:\n{stderr_txt[-1500:]}"
        )

    def stop(self) -> None:
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait(timeout=5.0)
            self._proc = None
        for attr in ("_stdout_file", "_stderr_file"):
            handle = getattr(self, attr)
            if handle is not None:
                with contextlib.suppress(Exception):
                    handle.close()
                setattr(self, attr, None)
        if self._cleanup_root_on_exit:
            shutil.rmtree(self.workspace.root_dir, ignore_errors=True)

    def __enter__(self) -> IsolatedLabServer:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()


def _is_allowed_browser_url(url: str) -> bool:
    if url.startswith(("data:", "blob:", "about:")):
        return True
    parsed = urlparse(url)
    if parsed.scheme in {"http", "https", "ws", "wss"}:
        hostname = (parsed.hostname or "").lower()
        if hostname not in _LOOPBACK_HOSTS:
            return False
        try:
            port = parsed.port
        except ValueError:
            return False
        return port is None or port not in LIVE_FORBIDDEN_PORTS
    return False


@dataclass
class StrictPlaywrightSession:
    """Async Playwright Chromium session with isolated profile dir and loopback route guard."""

    user_data_dir: Path | None = None
    headless: bool = True
    viewport: dict[str, int] = field(default_factory=lambda: {"width": 1280, "height": 800})
    console_errors: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    http_errors: list[tuple[int, str]] = field(default_factory=list)
    external_requests: list[str] = field(default_factory=list)

    _pw_cm: Any = field(default=None, init=False, repr=False)
    _pw: Playwright | None = field(default=None, init=False, repr=False)
    _browser: Browser | None = field(default=None, init=False, repr=False)
    _context: BrowserContext | None = field(default=None, init=False, repr=False)
    _page: Page | None = field(default=None, init=False, repr=False)
    _owned_temp_dir: Path | None = field(default=None, init=False, repr=False)

    @property
    def page(self) -> Page:
        if self._page is None:
            raise RuntimeError("StrictPlaywrightSession has not been entered.")
        return self._page

    async def __aenter__(self) -> StrictPlaywrightSession:
        if self.user_data_dir is not None:
            profile_dir = assert_safe_mutation_path(self.user_data_dir)
            profile_dir.mkdir(parents=True, exist_ok=True)
        else:
            self._owned_temp_dir = Path(tempfile.mkdtemp(prefix="cb_qa_pw_"))
            profile_dir = self._owned_temp_dir

        self._pw_cm = async_playwright()
        self._pw = await self._pw_cm.__aenter__()
        assert self._pw is not None
        self._context = await self._pw.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            headless=self.headless,
            viewport={"width": self.viewport["width"], "height": self.viewport["height"]},
        )

        async def _route_handler(route: Route) -> None:
            req_url = route.request.url
            if _is_allowed_browser_url(req_url):
                await route.continue_()
            else:
                self.external_requests.append(_scrub_url_strict(req_url))
                await route.abort()

        async def _ws_handler(ws_route: WebSocketRoute) -> None:
            ws_url = ws_route.url
            if _is_allowed_browser_url(ws_url):
                ws_route.connect_to_server()
            else:
                self.external_requests.append(_scrub_url_strict(ws_url))
                await ws_route.close(code=1008, reason="Blocked external WebSocket")

        await self._context.route("**/*", _route_handler)
        await self._context.route_web_socket("**/*", _ws_handler)

        existing_pages = self._context.pages
        self._page = existing_pages[0] if existing_pages else await self._context.new_page()

        def _on_console(msg: ConsoleMessage) -> None:
            if msg.type == "error":
                self.console_errors.append(msg.text)

        def _on_pageerror(exc: Exception) -> None:
            self.page_errors.append(repr(exc))

        def _on_response(resp: Response) -> None:
            if resp.status >= 400:
                self.http_errors.append((resp.status, _scrub_url_strict(resp.url)))

        self._page.on("console", _on_console)
        self._page.on("pageerror", _on_pageerror)
        self._page.on("response", _on_response)
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._context is not None:
            with contextlib.suppress(Exception):
                await self._context.unroute_all(behavior="ignoreErrors")
        if self._page is not None:
            with contextlib.suppress(Exception):
                await self._page.close()
            self._page = None
        if self._context is not None:
            with contextlib.suppress(Exception):
                await self._context.close()
            self._context = None
        if self._browser is not None:
            with contextlib.suppress(Exception):
                await self._browser.close()
            self._browser = None
        if self._pw_cm is not None:
            with contextlib.suppress(Exception):
                await self._pw_cm.__aexit__(None, None, None)
            self._pw_cm = None
            self._pw = None
        if self._owned_temp_dir is not None:
            shutil.rmtree(self._owned_temp_dir, ignore_errors=True)
            self._owned_temp_dir = None


@dataclass(frozen=True)
class LogCursor:
    """Read-only cursor for incremental, rotation-aware JSONL log reading."""

    file_name: str
    inode: tuple[int, int] | None = None
    byte_offset: int = 0


_URL_FIELD_KEYS: frozenset[str] = frozenset(
    {"url", "page_url", "path", "target_url", "referer", "href", "src"}
)


def _looks_like_single_url(value: str) -> bool:
    if "\n" in value or "\r" in value or len(value) > 1000:
        return False
    return ("?" in value or "#" in value) and (
        value.startswith(("http://", "https://", "ws://", "wss://", "/"))
    )


_ENCODED_AUTH_SPACE_RE = re.compile(
    r"(?i)(?:(?<=%[0-9A-Fa-f]{2})|\b)(Bearer|Basic)(?:%20|%09|\s)+"
    r"(?!(?:\[REDACTED\]|%5BREDACTED%5D)(?:[\s&;,'\"#\)\]\}]|$))([^\s&;,'\"#]+)"
)
_ENCODED_AUTH_PLUS_RE = re.compile(
    r"(?i)(?:(?<=%[0-9A-Fa-f]{2})|\b)(Bearer|Basic)(?:\+|%2B)+"
    r"(?!(?:\[REDACTED\]|%5BREDACTED%5D)(?:[\s&;,'\"#\)\]\}]|$))([^\s&;,'\"#]+)"
)
_EMBEDDED_URL_RE = re.compile(
    r"(?:(?:https?|wss?)://[^\s'\"<>]+"
    r"|(?<![A-Za-z0-9_/])(?<!:/)(?!//)"
    r"(?:/|[A-Za-z0-9_.:@%+,~();=$!*\[\]{}-])"
    r"[A-Za-z0-9_./:@%+,~();=$!*\[\]{}-]*"
    r"(?:\?[^\s'\"<>#]*(?:#[^\s'\"<>]+)?|#[^\s'\"<>]+))"
)


def _redact_encoded_auth(text: str) -> str:
    scrubbed = _ENCODED_AUTH_SPACE_RE.sub(rf"\1 {REDACTED_PLACEHOLDER}", text)
    return _ENCODED_AUTH_PLUS_RE.sub(rf"\1 {REDACTED_PLACEHOLDER}", scrubbed)


def contains_encoded_auth(text: str) -> bool:
    """Return True if text contains unredacted space/percent/plus-encoded Bearer or Basic auth."""
    return bool(_ENCODED_AUTH_SPACE_RE.search(text) or _ENCODED_AUTH_PLUS_RE.search(text))


def _is_sensitive_param_key(key: str) -> bool:
    k_low = key.lower()
    return (
        k_low in _SENSITIVE_QUERY_KEYS
        or any(marker in k_low for marker in ("token", "secret", "password", "key", "auth"))
        or is_sensitive_key_strict(key)
    )


def _scrub_kv_segment(segment: str, *, _depth: int = 0) -> str:
    pairs = parse_qsl(segment, keep_blank_values=True)
    cleaned_pairs: list[tuple[str, str]] = []
    for k, v in pairs:
        if _is_sensitive_param_key(k) or v == REDACTED_PLACEHOLDER:
            cleaned_pairs.append((k, REDACTED_PLACEHOLDER))
        else:
            decoded_v = unquote(v[:200])
            if _depth < 3 and "%" in decoded_v:
                next_decoded = unquote(decoded_v)
                if next_decoded != decoded_v and any(
                    ch in next_decoded for ch in ("?", "#", "://", "=")
                ):
                    decoded_v = next_decoded
            redacted_v = _redact_encoded_auth(redact_string_strict(decoded_v))
            if _depth < 3:
                if _looks_like_single_url(redacted_v):
                    redacted_v = _scrub_url_strict(redacted_v, _depth=_depth + 1)
                elif "://" in redacted_v or "?" in redacted_v or "#" in redacted_v:
                    redacted_v = _EMBEDDED_URL_RE.sub(
                        lambda match: _scrub_url_strict(match.group(0), _depth=_depth + 1),
                        redacted_v,
                    )
            cleaned_pairs.append((k, redacted_v))
    return urlencode(cleaned_pairs).replace("%5BREDACTED%5D", REDACTED_PLACEHOLDER)


def _scrub_fragment_strict(fragment: str, *, _depth: int = 0) -> str:
    if not fragment:
        return ""
    if "?" in fragment:
        frag_head, frag_qs = fragment.split("?", 1)
        clean_head = _redact_encoded_auth(redact_string_strict(unquote(frag_head[:100])))
        clean_qs = _scrub_kv_segment(frag_qs, _depth=_depth)
        return f"{clean_head}?{clean_qs}" if clean_qs else clean_head
    if "=" in fragment:
        pairs = parse_qsl(fragment, keep_blank_values=True)
        if pairs:
            return _scrub_kv_segment(fragment, _depth=_depth)
    return _redact_encoded_auth(redact_string_strict(unquote(fragment[:100])))


def _has_sensitive_kv(segment: str, *, _depth: int = 0) -> bool:
    if not segment or "=" not in segment:
        return False
    for k, v in parse_qsl(segment, keep_blank_values=True):
        if _is_sensitive_param_key(k) and v not in {"", REDACTED_PLACEHOLDER, "%5BREDACTED%5D"}:
            return True
        if v in {"", REDACTED_PLACEHOLDER, "%5BREDACTED%5D"}:
            continue
        candidates_v: list[str] = [v]
        cur = v
        for _ in range(2):
            nxt = unquote(cur)
            if nxt == cur:
                break
            candidates_v.append(nxt)
            cur = nxt
        for cand in candidates_v:
            if contains_encoded_auth(cand) or contains_unredacted_secret_strict(cand):
                return True
            if (
                _depth < 3
                and ("?" in cand or "#" in cand or "://" in cand)
                and contains_unredacted_url_secret(cand, _depth=_depth + 1)
            ):
                return True
    return False


def contains_unredacted_url_secret(text: str, *, _depth: int = 0) -> bool:
    """Return True if any URL (or embedded URL) contains unredacted query/fragment secrets."""
    if _depth > 3:
        return False
    candidates: list[str] = []
    if _looks_like_single_url(text):
        candidates.append(text)
    candidates.extend(m.group(0) for m in _EMBEDDED_URL_RE.finditer(text))
    for url in candidates:
        url_no_frag, frag = url.split("#", 1) if "#" in url else (url, "")
        _, qs = url_no_frag.split("?", 1) if "?" in url_no_frag else (url_no_frag, "")
        if _has_sensitive_kv(qs, _depth=_depth):
            return True
        if frag:
            frag_qs = frag.split("?", 1)[1] if "?" in frag else frag
            if _has_sensitive_kv(frag_qs, _depth=_depth):
                return True
    return False


def _scrub_url_strict(url: str, *, _depth: int = 0) -> str:
    pre_redacted = _redact_encoded_auth(url)
    base_scrubbed = scrub_url(pre_redacted).replace("%5BREDACTED%5D", REDACTED_PLACEHOLDER)
    url_no_frag, fragment = (
        base_scrubbed.split("#", 1) if "#" in base_scrubbed else (base_scrubbed, "")
    )
    if "?" in url_no_frag:
        base, qs = url_no_frag.split("?", 1)
        clean_qs = _scrub_kv_segment(qs, _depth=_depth)
    else:
        base = url_no_frag
        clean_qs = ""

    clean_base = _redact_encoded_auth(redact_string_strict(base))
    rebuilt = f"{clean_base}?{clean_qs}" if clean_qs else clean_base
    if fragment:
        clean_frag = _scrub_fragment_strict(fragment, _depth=_depth)
        if clean_frag:
            rebuilt = f"{rebuilt}#{clean_frag}"
    return rebuilt[:600]


def _scrub_embedded_urls_strict(text: str) -> str:
    if _looks_like_single_url(text):
        return _scrub_url_strict(text)
    if "://" not in text and "?" not in text and "#" not in text:
        return text
    return _EMBEDDED_URL_RE.sub(lambda match: _scrub_url_strict(match.group(0)), text)


def _has_unredacted_secret_any(value: Any) -> bool:
    """Return True if value (or any nested key/item) has strict, encoded-auth, or URL secrets."""
    if contains_unredacted_secret_strict(value):
        return True
    if isinstance(value, Mapping):
        return any(
            _has_unredacted_secret_any(k) or _has_unredacted_secret_any(v)
            for k, v in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_has_unredacted_secret_any(item) for item in value)
    if isinstance(value, str):
        return contains_encoded_auth(value) or contains_unredacted_url_secret(value)
    if value is not None:
        raw = str(value)
        return contains_encoded_auth(raw) or contains_unredacted_url_secret(raw)
    return False


def _sanitize_key(key: Any) -> Any:
    if isinstance(key, str):
        scrubbed = _scrub_embedded_urls_strict(key)
        return redact_string_strict(_redact_encoded_auth(scrubbed))
    if isinstance(key, tuple):
        return tuple(_sanitize_key(item) for item in key)
    if isinstance(key, frozenset):
        return frozenset(_sanitize_key(item) for item in key)
    if isinstance(key, (int, float, bool, type(None))):
        return key
    raw = str(key)
    if _has_unredacted_secret_any(raw):
        scrubbed = _scrub_embedded_urls_strict(raw)
        return redact_string_strict(_redact_encoded_auth(scrubbed))
    return key


def _sanitize_record(value: Any) -> Any:
    if isinstance(value, Mapping):
        cleaned: dict[Any, Any] = {}
        for k, v in value.items():
            safe_k = _sanitize_key(k)
            k_str = str(safe_k)
            if isinstance(v, str) and (
                k_str.lower() in _URL_FIELD_KEYS or _looks_like_single_url(v)
            ):
                cleaned[safe_k] = _scrub_url_strict(v)
            else:
                cleaned[safe_k] = _sanitize_record(v)
        return redact_payload_strict(cleaned)
    if isinstance(value, list):
        return [_sanitize_record(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_record(item) for item in value)
    if isinstance(value, set):
        return {_sanitize_record(item) for item in value}
    if isinstance(value, frozenset):
        return frozenset(_sanitize_record(item) for item in value)
    if isinstance(value, str):
        scrubbed = _scrub_embedded_urls_strict(value)
        return redact_payload_strict(_redact_encoded_auth(scrubbed))
    return redact_payload_strict(value)


def _read_jsonl_slice(
    path: Path,
    start_offset: int,
    max_entries: int,
) -> tuple[list[dict[str, Any]], int]:
    entries: list[dict[str, Any]] = []
    if not path.is_file():
        return entries, 0
    with path.open("rb") as handle:
        handle.seek(max(0, start_offset))
        end_offset = handle.tell()
        while len(entries) < max_entries:
            line_start = handle.tell()
            raw_line = handle.readline()
            if not raw_line:
                end_offset = line_start
                break
            if not raw_line.endswith(b"\n"):
                end_offset = line_start
                break
            end_offset = handle.tell()
            if not raw_line.strip():
                continue
            try:
                parsed = json.loads(raw_line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                sanitized = _sanitize_record(parsed)
                if isinstance(sanitized, dict):
                    entries.append(sanitized)
    return entries, end_offset


def read_sanitized_logs(
    logs_dir: Path,
    *,
    cursors: Mapping[str, LogCursor] | None = None,
    max_entries_per_file: int = 5000,
    files: Collection[str] = _LOG_FILES,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, LogCursor]]:
    """Read and redact JSONL logs read-only, handling `.1` log rotation."""
    results: dict[str, list[dict[str, Any]]] = {}
    next_cursors: dict[str, LogCursor] = {}

    for fname in files:
        active_path = logs_dir / fname
        prev = cursors.get(fname) if cursors is not None else None
        if not active_path.is_file():
            results[fname] = []
            next_cursors[fname] = prev or LogCursor(file_name=fname)
            continue

        stat_res = active_path.stat()
        cur_inode = (stat_res.st_dev, stat_res.st_ino)
        entries: list[dict[str, Any]] = []

        if prev is not None and prev.inode is not None and prev.inode != cur_inode:
            rotated_path = active_path.with_suffix(active_path.suffix + ".1")
            rot_drained = True
            if rotated_path.is_file():
                rot_stat = rotated_path.stat()
                if (
                    (rot_stat.st_dev, rot_stat.st_ino) == prev.inode
                    and prev.byte_offset < rot_stat.st_size
                ):
                    rot_entries, rot_end_offset = _read_jsonl_slice(
                        rotated_path,
                        prev.byte_offset,
                        max_entries_per_file,
                    )
                    entries.extend(rot_entries)
                    if (
                        len(rot_entries) >= max_entries_per_file
                        and rot_end_offset < rot_stat.st_size
                    ):
                        rot_drained = False
                        results[fname] = entries
                        next_cursors[fname] = LogCursor(
                            file_name=fname,
                            inode=prev.inode,
                            byte_offset=rot_end_offset,
                        )
            if not rot_drained:
                continue
            remaining = max(0, max_entries_per_file - len(entries))
            act_entries, end_offset = _read_jsonl_slice(active_path, 0, remaining)
            entries.extend(act_entries)
        else:
            start_offset = 0
            if (
                prev is not None
                and prev.inode == cur_inode
                and prev.byte_offset <= stat_res.st_size
            ):
                start_offset = prev.byte_offset
            act_entries, end_offset = _read_jsonl_slice(
                active_path,
                start_offset,
                max_entries_per_file,
            )
            entries.extend(act_entries)

        results[fname] = entries
        next_cursors[fname] = LogCursor(file_name=fname, inode=cur_inode, byte_offset=end_offset)

    return results, next_cursors


def summarize_active_logs(logs_dir: Path, *, recent_limit: int = 20) -> dict[str, Any]:
    """Summarize active diagnostics logs read-only with strict secret redaction."""
    if not logs_dir.is_dir():
        return {
            "logs_dir": str(logs_dir),
            "exists": False,
            "counts_by_file": {},
            "failures_by_source": {},
            "failures_by_kind": {},
            "recent_failures": [],
            "last_watchdog": None,
        }

    records, _ = read_sanitized_logs(logs_dir)
    counts_by_file = {fname: len(items) for fname, items in records.items()}
    failures = records.get("failures.jsonl", [])
    failures_by_source: dict[str, int] = {}
    failures_by_kind: dict[str, int] = {}
    for item in failures:
        src = str(item.get("source") or "unknown")
        kind = str(item.get("kind") or "unknown")
        failures_by_source[src] = failures_by_source.get(src, 0) + 1
        failures_by_kind[kind] = failures_by_kind.get(kind, 0) + 1

    watchdog_items = records.get("watchdog.jsonl", [])
    last_watchdog = watchdog_items[-1] if watchdog_items else None

    summary: dict[str, Any] = {
        "logs_dir": str(logs_dir),
        "exists": True,
        "counts_by_file": counts_by_file,
        "failures_by_source": failures_by_source,
        "failures_by_kind": failures_by_kind,
        "recent_failures": failures[-recent_limit:],
        "last_watchdog": last_watchdog,
    }
    redacted = _sanitize_record(summary)
    assert isinstance(redacted, dict)
    return redacted


def _probe_tcp_listen_passive(port: int) -> bool:
    """Passively inspect /proc/net/tcp* for LISTEN (0A) without touching VNC sockets."""
    port_hex = f":{port:04X}"
    for proc_path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        if not proc_path.is_file():
            continue
        try:
            lines = proc_path.read_text(encoding="ascii", errors="ignore").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) >= 4 and parts[3] == "0A" and parts[1].upper().endswith(port_hex):
                return True
    return False


def probe_live_readonly(
    target_url: str = "http://127.0.0.1:8000",
    *,
    token: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Strictly read-only probe of live ControlBot, noVNC :6080, and passive VNC :5900/:5901."""
    clean_base = target_url.strip().rstrip("/")
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    snapshot: dict[str, Any] = {
        "target_url": _scrub_url_strict(clean_base),
        "health_ok": False,
        "health_status": None,
        "health_payload": None,
        "system_info_status": None,
        "system_info": None,
        "app_status": None,
        "app_html_excerpt": None,
        "diagnostics_summary_status": None,
        "diagnostics_summary": None,
        "diagnostics_failures_status": None,
        "diagnostics_failures": None,
        "novnc_6080_status": None,
        "vnc_5900_listening": _probe_tcp_listen_passive(5900),
        "vnc_5901_listening": _probe_tcp_listen_passive(5901),
        "errors": [],
    }
    errors: list[str] = []

    with httpx.Client(
        base_url=clean_base,
        headers=headers,
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        try:
            r_health = client.get("/health")
            snapshot["health_status"] = r_health.status_code
            if r_health.status_code == 200:
                payload = r_health.json()
                snapshot["health_payload"] = _sanitize_record(payload)
                snapshot["health_ok"] = isinstance(payload, dict) and payload.get("status") == "ok"
        except Exception as exc:
            errors.append(f"health:{type(exc).__name__}:{exc}")

        try:
            r_info = client.get("/api/system/info")
            snapshot["system_info_status"] = r_info.status_code
            if r_info.status_code == 200:
                snapshot["system_info"] = _sanitize_record(r_info.json())
        except Exception as exc:
            errors.append(f"system_info:{type(exc).__name__}:{exc}")

        try:
            app_params = {"token": token} if token else None
            r_app = client.get("/app", params=app_params)
            snapshot["app_status"] = r_app.status_code
            if r_app.status_code == 200:
                snapshot["app_html_excerpt"] = r_app.text[:4000]
        except Exception as exc:
            errors.append(f"app:{type(exc).__name__}:{exc}")

        try:
            r_diag_sum = client.get("/api/v1/diagnostics/summary")
            snapshot["diagnostics_summary_status"] = r_diag_sum.status_code
            if r_diag_sum.status_code == 200:
                snapshot["diagnostics_summary"] = _sanitize_record(r_diag_sum.json())
        except Exception as exc:
            errors.append(f"diag_summary:{type(exc).__name__}:{exc}")

        try:
            r_diag_fail = client.get("/api/v1/diagnostics/failures", params={"limit": 25})
            snapshot["diagnostics_failures_status"] = r_diag_fail.status_code
            if r_diag_fail.status_code == 200:
                snapshot["diagnostics_failures"] = _sanitize_record(r_diag_fail.json())
        except Exception as exc:
            errors.append(f"diag_failures:{type(exc).__name__}:{exc}")

    with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False) as novnc_client:
        try:
            r_novnc = novnc_client.get("http://127.0.0.1:6080/")
            snapshot["novnc_6080_status"] = r_novnc.status_code
        except Exception as exc:
            errors.append(f"novnc_6080:{type(exc).__name__}:{exc}")

    snapshot["errors"] = errors
    redacted = _sanitize_record(snapshot)
    assert isinstance(redacted, dict)
    return redacted


__all__ = [
    "ALLOWED_GROKBOT_BOTS",
    "FORBIDDEN_GROKBOT_CONFIG_DIR",
    "IsolatedLabServer",
    "IsolationBoundaryError",
    "LIVE_FORBIDDEN_PORTS",
    "LabWorkspacePaths",
    "LogCursor",
    "StrictPlaywrightSession",
    "alloc_ephemeral_port",
    "allocate_lab_workspace",
    "assert_allowed_grokbot_target",
    "assert_not_live_target",
    "assert_safe_mutation_path",
    "ephemeral_git_worktree",
    "probe_live_readonly",
    "read_sanitized_logs",
    "summarize_active_logs",
]
