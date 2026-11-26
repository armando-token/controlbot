"""Shared isolated E2E test harness helpers: IsolatedServer, MockRfbServer, LabStack & SSE/WS."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, overload
from urllib.parse import urlencode

import httpx
import uvicorn
from lab.effect_sim import create_effect_sim_app
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import create_scada_app
from src.contracts.common import utc_now
from src.web.v1.rfb_gate import des_encrypt_block, solve_vnc_challenge

FORBIDDEN_PORTS: frozenset[int] = frozenset({8000, 6080, 5900})
_VNC_PASSWD_FIXED_KEY: bytes = bytes([0xE8, 0x4A, 0xD6, 0x60, 0xC4, 0x72, 0x1A, 0xE0])
_HOST_HOME: Path = Path.home().resolve()
_SAFE_FALLBACK_PATH: tuple[str, ...] = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)


def alloc_free_port(
    host: str = "127.0.0.1",
    *,
    exclude: set[int] | frozenset[int] = frozenset(),
) -> int:
    """Bind an ephemeral TCP port on loopback and return it, never returning live ports."""
    blocked = FORBIDDEN_PORTS | set(exclude)
    for _ in range(32):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, 0))
            port = int(sock.getsockname()[1])
        if port not in blocked:
            return port
    raise RuntimeError("Failed to allocate an ephemeral loopback port outside forbidden ports.")


def write_vnc_passwd_file(path: Path, password: bytes = b"e2evncpw") -> Path:
    """Write a valid 8-byte DES-encrypted vncpasswd file compatible with rfb_gate.py."""
    padded = password[:8].ljust(8, b"\x00")
    encrypted = des_encrypt_block(_VNC_PASSWD_FIXED_KEY, padded)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encrypted)
    path.chmod(0o600)
    return path


class _NoSignalUvicornServer(uvicorn.Server):
    """Uvicorn server subclass for background-thread lab servers."""

    def install_signal_handlers(self) -> None:
        return None


class LabStack:
    """Runs synthetic SCADA, Maintenance, and EffectSim FastAPI apps on free ports."""

    def __init__(self, *, fixture_mode: str = "default", host: str = "127.0.0.1") -> None:
        self.fixture_mode = fixture_mode
        self.host = host
        self.scada_port: int = 0
        self.maintenance_port: int = 0
        self.effect_sim_port: int = 0
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._servers: list[_NoSignalUvicornServer] = []
        self._ready = threading.Event()
        self._error: BaseException | None = None

    @property
    def scada_url(self) -> str:
        return f"http://{self.host}:{self.scada_port}"

    @property
    def maintenance_url(self) -> str:
        return f"http://{self.host}:{self.maintenance_port}"

    @property
    def effect_sim_url(self) -> str:
        return f"http://{self.host}:{self.effect_sim_port}"

    def env_vars(self) -> dict[str, str]:
        return {
            "GROKBOT_SCADA_URL": self.scada_url,
            "GROKBOT_MAINTENANCE_URL": self.maintenance_url,
            "GROKBOT_EFFECT_SIM_URL": self.effect_sim_url,
        }

    def start(self, timeout: float = 10.0) -> LabStack:
        if self._thread is not None and self._thread.is_alive():
            return self
        self._ready.clear()
        self._error = None
        self._thread = threading.Thread(target=self._run_thread, daemon=True, name="e2e-lab-stack")
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            self.stop()
            raise TimeoutError("Timed out starting synthetic lab stack.")
        if self._error is not None:
            err = self._error
            self.stop()
            raise RuntimeError(f"Synthetic lab stack failed to start: {err!r}") from err
        return self

    def _run_thread(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._serve_all())
        except BaseException as exc:  # noqa: BLE001
            self._error = exc
            self._ready.set()
        finally:
            loop.close()

    async def _serve_all(self) -> None:
        now_ref = utc_now()
        scada_app = create_scada_app(fixture_mode=self.fixture_mode)
        maint_app = create_maintenance_app(fixture_mode=self.fixture_mode)
        effect_app = create_effect_sim_app()
        scada_app.state.scada_state.set_reference_time(now_ref)
        maint_app.state.maintenance_state.set_reference_time(now_ref)

        sockets: list[socket.socket] = []
        used_ports: set[int] = set()
        tasks: list[asyncio.Task[None]] = []
        try:
            for app in (scada_app, maint_app, effect_app):
                port = alloc_free_port(self.host, exclude=used_ports)
                used_ports.add(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, port))
                sock.listen(128)
                sock.setblocking(False)
                sockets.append(sock)
                srv = _NoSignalUvicornServer(
                    uvicorn.Config(
                        app,
                        host=self.host,
                        port=port,
                        log_level="warning",
                        access_log=False,
                        lifespan="on",
                    )
                )
                self._servers.append(srv)
                tasks.append(asyncio.create_task(srv.serve(sockets=[sock])))

            for srv, task in zip(self._servers, tasks, strict=True):
                deadline = asyncio.get_running_loop().time() + 10.0
                while not srv.started:
                    if task.done():
                        exc = task.exception()
                        raise RuntimeError(f"Lab server exited early: {exc!r}")
                    if asyncio.get_running_loop().time() >= deadline:
                        raise TimeoutError("Timed out waiting for lab uvicorn server.")
                    await asyncio.sleep(0.01)

            self.scada_port = int(sockets[0].getsockname()[1])
            self.maintenance_port = int(sockets[1].getsockname()[1])
            self.effect_sim_port = int(sockets[2].getsockname()[1])
            self._ready.set()

            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for srv in reversed(self._servers):
                srv.should_exit = True
            for task in tasks:
                if not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
            for sock in sockets:
                with contextlib.suppress(OSError):
                    sock.close()

    def stop(self) -> None:
        loop = self._loop
        if loop is not None and not loop.is_closed():
            for srv in reversed(self._servers):
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(setattr, srv, "should_exit", True)
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self._thread = None
        self._servers.clear()


class MockRfbServer:
    """Lightweight loopback RFB 3.8 TCP server for testing VNC auth and RfbInputGate.

    Supports both SecurityType VNC Auth (2) with DES challenge/response and SecurityType None (1),
    writes a matching DES-encrypted `vnc_passwd` file, emits ServerInit (640x480), and records
    every received RFB client-to-server message type byte and raw frame.

    Supports tuple unpacking `(host, port, passwd_path) = mock_rfb_server` as well as rich
    attribute inspection (`received_message_types`, `received_messages`, `handshakes_completed`).
    """

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        passwd_path: Path | None = None,
        password: bytes = b"e2evncpw",
        security_types: tuple[int, ...] = (2,),
        desktop_name: bytes = b"MockRFB",
    ) -> None:
        self.host = host
        self._requested_port = port
        self.port = port
        self.password = password[:8]
        self._owned_passwd_dir: Path | None = None
        if passwd_path is not None:
            self.passwd_path = passwd_path
        else:
            self._owned_passwd_dir = Path(tempfile.mkdtemp(prefix="e2e_mock_rfb_"))
            self.passwd_path = self._owned_passwd_dir / "vnc_passwd"
        self.security_types = security_types
        self.desktop_name = desktop_name

        self._lock = threading.Lock()
        self.received_message_types: list[int] = []
        self.received_messages: list[tuple[int, bytes]] = []
        self.handshakes_completed: int = 0
        self.auth_failures: int = 0
        self.client_inits: list[int] = []

        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.Server | None = None
        self._stop_event: asyncio.Event | None = None
        self._ready = threading.Event()
        self._msg_event = threading.Event()
        self._error: BaseException | None = None

    def __iter__(self) -> Iterator[Any]:
        yield self.host
        yield self.port
        yield self.passwd_path

    def reset_records(self) -> None:
        with self._lock:
            self.received_message_types.clear()
            self.received_messages.clear()
            self.client_inits.clear()
            self._msg_event.clear()

    def wait_for_messages(self, min_count: int = 1, timeout: float = 5.0) -> list[int]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self.received_message_types) >= min_count:
                    return list(self.received_message_types)
                self._msg_event.clear()
            self._msg_event.wait(timeout=max(0.01, min(0.1, deadline - time.monotonic())))
        with self._lock:
            return list(self.received_message_types)

    def start(self, timeout: float = 5.0) -> MockRfbServer:
        if self._thread is not None and self._thread.is_alive():
            return self
        if self._owned_passwd_dir is not None and not self._owned_passwd_dir.exists():
            self._owned_passwd_dir = Path(tempfile.mkdtemp(prefix="e2e_mock_rfb_"))
            self.passwd_path = self._owned_passwd_dir / "vnc_passwd"
        write_vnc_passwd_file(self.passwd_path, self.password)
        self._ready.clear()
        self._error = None
        self._thread = threading.Thread(target=self._run_thread, daemon=True, name="e2e-mock-rfb")
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            self.stop()
            raise TimeoutError("Timed out starting MockRfbServer.")
        if self._error is not None:
            err = self._error
            self.stop()
            raise RuntimeError(f"MockRfbServer failed to start: {err!r}") from err
        return self

    def stop(self) -> None:
        try:
            loop = self._loop
            stop_event = self._stop_event
            if loop is not None and stop_event is not None and not loop.is_closed():
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(stop_event.set)
            if self._thread is not None and self._thread.is_alive():
                self._thread.join(timeout=5.0)
            self._thread = None
        finally:
            if self._owned_passwd_dir is not None:
                shutil.rmtree(self._owned_passwd_dir, ignore_errors=True)

    def __enter__(self) -> MockRfbServer:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    def _run_thread(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._serve())
        except BaseException as exc:  # noqa: BLE001
            self._error = exc
            self._ready.set()
        finally:
            loop.close()

    async def _serve(self) -> None:
        stop_event = asyncio.Event()
        self._stop_event = stop_event
        bind_port = (
            self._requested_port
            if self._requested_port > 0
            else alloc_free_port(self.host)
        )
        server = await asyncio.start_server(self._handle_client, self.host, bind_port)
        self._server = server
        assert server.sockets
        actual_port = int(server.sockets[0].getsockname()[1])
        if actual_port in FORBIDDEN_PORTS:
            server.close()
            await server.wait_closed()
            raise RuntimeError(f"MockRfbServer bound forbidden port {actual_port}")
        self.port = actual_port
        self._ready.set()
        try:
            await stop_event.wait()
        finally:
            server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), timeout=3.0)

    def _build_server_init(self) -> bytes:
        # 640x480, 32bpp, depth 24, little-endian, true-color, RGB max 255, shifts 16/8/0
        return (
            struct.pack(
                "!HHBBBBHHHBBB3xI",
                640,
                480,
                32,
                24,
                0,
                1,
                255,
                255,
                255,
                16,
                8,
                0,
                len(self.desktop_name),
            )
            + self.desktop_name
        )

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            client_ver = await reader.readexactly(12)
            if not client_ver.startswith(b"RFB "):
                return

            sec_list = bytes(self.security_types)
            writer.write(struct.pack("!B", len(sec_list)) + sec_list)
            await writer.drain()

            chosen_raw = await reader.readexactly(1)
            chosen = chosen_raw[0]
            if chosen not in self.security_types:
                msg = b"Unsupported security type"
                writer.write(struct.pack("!II", 1, len(msg)) + msg)
                await writer.drain()
                return

            if chosen == 2:
                challenge = secrets.token_bytes(16)
                writer.write(challenge)
                await writer.drain()
                response = await reader.readexactly(16)
                expected = solve_vnc_challenge(self.password, challenge)
                if not hmac.compare_digest(response, expected):
                    with self._lock:
                        self.auth_failures += 1
                    msg = b"Authentication failed"
                    writer.write(struct.pack("!II", 1, len(msg)) + msg)
                    await writer.drain()
                    return

            # SecurityResult OK (0)
            writer.write(b"\x00\x00\x00\x00")
            await writer.drain()

            # ClientInit (1 byte)
            shared_raw = await reader.readexactly(1)
            with self._lock:
                self.client_inits.append(shared_raw[0])
                self.handshakes_completed += 1

            # ServerInit (640x480)
            writer.write(self._build_server_init())
            await writer.drain()

            # Client-to-server message loop
            while True:
                head = await reader.read(1)
                if not head:
                    break
                msg_type = head[0]
                if msg_type == 0x00:  # SetPixelFormat: 20 bytes
                    rest = await reader.readexactly(19)
                elif msg_type == 0x02:  # SetEncodings: 4 + 4*n bytes
                    hdr = await reader.readexactly(3)
                    (num_enc,) = struct.unpack("!H", hdr[1:3])
                    rest = hdr + await reader.readexactly(4 * int(num_enc))
                elif msg_type == 0x03:  # FramebufferUpdateRequest: 10 bytes
                    rest = await reader.readexactly(9)
                    # Reply with valid empty FramebufferUpdate (4 bytes)
                    writer.write(b"\x00\x00\x00\x00")
                    await writer.drain()
                elif msg_type == 0x04:  # KeyEvent: 8 bytes
                    rest = await reader.readexactly(7)
                elif msg_type == 0x05:  # PointerEvent: 6 bytes
                    rest = await reader.readexactly(5)
                elif msg_type == 0x06:  # ClientCutText: 8 + len bytes
                    hdr = await reader.readexactly(7)
                    (text_len,) = struct.unpack("!I", hdr[3:7])
                    rest = hdr + await reader.readexactly(int(text_len))
                elif msg_type == 0x96:  # EnableContinuousUpdates: 10 bytes
                    rest = await reader.readexactly(9)
                elif msg_type == 0xF8:  # Fence: 9 + payload_len bytes
                    hdr = await reader.readexactly(8)
                    payload_len = int(hdr[7])
                    rest = hdr + await reader.readexactly(payload_len)
                elif msg_type == 0xFB:  # SetDesktopSize: 8 + 16*n bytes
                    hdr = await reader.readexactly(7)
                    num_screens = int(hdr[5])
                    rest = hdr + await reader.readexactly(16 * num_screens)
                elif msg_type == 0xFF:  # QEMU extended
                    sub = await reader.readexactly(1)
                    rest = sub + await reader.readexactly(11) if sub[0] == 0x00 else sub
                else:
                    rest = b""

                frame = head + rest
                with self._lock:
                    self.received_message_types.append(msg_type)
                    self.received_messages.append((msg_type, frame))
                    self._msg_event.set()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


@dataclass
class IsolatedServer:
    """Manages an isolated ephemeral uvicorn subprocess for opaque-box E2E tests."""

    tmp_dir: Path
    web_token: str | None = None
    cap_secret: str = "e2e-test-cap-secret-0123456789abcdef"
    with_mock_rfb: bool = False
    with_lab: bool = False
    mock_agy_script: str | None = None
    extra_env: dict[str, str] = field(default_factory=dict)

    port: int = field(init=False)
    base_url: str = field(init=False)
    ws_base_url: str = field(init=False)
    db_path: Path = field(init=False)
    workspace_db_path: Path = field(init=False)
    projects_root: Path = field(init=False)
    fake_home: Path = field(init=False)
    brain_root: Path = field(init=False)
    profile_root: Path = field(init=False)
    vnc_passwd_path: Path = field(init=False)
    vnc_port: int = field(init=False)
    env: dict[str, str] = field(init=False)

    mock_rfb: MockRfbServer | None = field(default=None, init=False)
    lab_stack: LabStack | None = field(default=None, init=False)
    _proc: subprocess.Popen[bytes] | None = field(default=None, init=False, repr=False)
    _stdout_file: Any = field(default=None, init=False, repr=False)
    _stderr_file: Any = field(default=None, init=False, repr=False)
    _restart_count: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        self.tmp_dir = Path(self.tmp_dir)
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.fake_home = self.tmp_dir / "fake_home"
        self.fake_home.mkdir(parents=True, exist_ok=True)
        self.projects_root = self.tmp_dir / "Projects"
        demo_project = self.projects_root / "Grokbotclon"
        demo_project.mkdir(parents=True, exist_ok=True)
        readme = demo_project / "README.md"
        if not readme.exists():
            readme.write_text("# Grokbotclon E2E Workspace\n", encoding="utf-8")

        self.brain_root = self.tmp_dir / "brain"
        self.brain_root.mkdir(parents=True, exist_ok=True)
        self.profile_root = self.tmp_dir / "browser_profiles"
        self.profile_root.mkdir(parents=True, exist_ok=True)

        self.db_path = self.tmp_dir / "controlbot.sqlite3"
        self.workspace_db_path = self.tmp_dir / "controlbot_workspace.sqlite3"
        self.vnc_passwd_path = self.tmp_dir / "vnc_passwd"
        write_vnc_passwd_file(self.vnc_passwd_path)

        if self.mock_agy_script is not None:
            agy_path = self.fake_home / ".local" / "bin" / "agy"
            agy_path.parent.mkdir(parents=True, exist_ok=True)
            agy_path.write_text(self.mock_agy_script, encoding="utf-8")
            agy_path.chmod(0o755)

        try:
            if self.with_mock_rfb:
                self.mock_rfb = MockRfbServer(passwd_path=self.vnc_passwd_path)
                self.mock_rfb.start()
                self.vnc_port = self.mock_rfb.port
            else:
                self.vnc_port = alloc_free_port()

            if self.with_lab:
                self.lab_stack = LabStack().start()

            self.port = alloc_free_port(exclude={self.vnc_port})
            self._sync_urls()
            self.env = self._build_env()
        except Exception:
            self.stop()
            raise

    def _sync_urls(self) -> None:
        if self.port in FORBIDDEN_PORTS:
            raise RuntimeError(f"Refusing to bind forbidden port {self.port}")
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.ws_base_url = f"ws://127.0.0.1:{self.port}"

    def _sanitize_path(self, raw_path: str) -> str:
        """Strip host agy/user-bin dirs outside tmp_dir; prepend fake_home/.local/bin if mocked."""
        tmp_root = self.tmp_dir.resolve()
        host_blocked_roots = (
            _HOST_HOME / ".local",
            _HOST_HOME / ".gemini",
        )
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

        if self.mock_agy_script is not None:
            fake_bin = str(self.fake_home / ".local" / "bin")
            cleaned = [fake_bin, *[p for p in cleaned if p != fake_bin]]

        return os.pathsep.join(cleaned)

    def _build_env(self, extra_overrides: dict[str, str] | None = None) -> dict[str, str]:
        env = os.environ.copy()
        for key in list(env):
            if (
                key.startswith(("GROKBOT_", "CONTROLBOT_"))
                or key in {"PORT", "DISPLAY", "WAYLAND_DISPLAY"}
            ):
                env.pop(key, None)

        env.update(
            {
                "HOME": str(self.fake_home),
                "GROKBOT_DB_PATH": str(self.db_path),
                "GROKBOT_PROFILE_ROOT": str(self.profile_root),
                "CONTROLBOT_PROJECTS_ROOT": str(self.projects_root),
                "CONTROLBOT_AGY_BRAIN_ROOT": str(self.brain_root),
                "CONTROLBOT_BASE_URL": self.base_url,
                "GROKBOT_BASE_URL": self.base_url,
                "CONTROLBOT_PORT": str(self.port),
                "PORT": str(self.port),
                "GROKBOT_CAP_SECRET": self.cap_secret,
                "GROKBOT_VNC_HOST": "127.0.0.1",
                "GROKBOT_VNC_PORT": str(self.vnc_port),
                "GROKBOT_VNC_PASSWD_PATH": str(self.vnc_passwd_path),
                "GROKBOT_X11_DISPLAY": "",
                "PYTHONUNBUFFERED": "1",
            }
        )
        if self.web_token is not None:
            env["GROKBOT_WEB_TOKEN"] = self.web_token
            env["CONTROLBOT_WEB_TOKEN"] = self.web_token
        if self.lab_stack is not None:
            env.update(self.lab_stack.env_vars())
        if self.extra_env:
            env.update(self.extra_env)
        if extra_overrides:
            env.update(extra_overrides)

        # Sanitize PATH AFTER extra_env/extra_overrides so host agy dirs can never re-leak.
        env["PATH"] = self._sanitize_path(env.get("PATH", ""))

        # Forward Playwright browser cache when HOME is isolated unless explicitly overridden.
        if (
            "PLAYWRIGHT_BROWSERS_PATH" not in self.extra_env
            and (not extra_overrides or "PLAYWRIGHT_BROWSERS_PATH" not in extra_overrides)
        ):
            host_pw = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
            if host_pw:
                env["PLAYWRIGHT_BROWSERS_PATH"] = host_pw
            else:
                default_pw = _HOST_HOME / ".cache" / "ms-playwright"
                if default_pw.is_dir():
                    env["PLAYWRIGHT_BROWSERS_PATH"] = str(default_pw)

        # Re-assert LLM URL stays unset unless explicitly passed via extra_env/extra_overrides
        if "GROKBOT_LLM_BASE_URL" not in self.extra_env and (
            not extra_overrides or "GROKBOT_LLM_BASE_URL" not in extra_overrides
        ):
            env.pop("GROKBOT_LLM_BASE_URL", None)
        return env

    def start(self, *, timeout: float = 15.0) -> IsolatedServer:
        if self._proc is not None and self._proc.poll() is None:
            return self
        try:
            self._launch_process(timeout=timeout)
        except Exception:
            self.stop()
            raise
        return self

    def __enter__(self) -> IsolatedServer:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    def _close_log_files(self) -> None:
        for handle_attr in ("_stdout_file", "_stderr_file"):
            handle = getattr(self, handle_attr)
            if handle is not None:
                with contextlib.suppress(Exception):
                    handle.close()
                setattr(self, handle_attr, None)

    def _launch_process(self, *, timeout: float = 15.0) -> None:
        self._close_log_files()
        idx = self._restart_count
        stdout_path = self.tmp_dir / f"uvicorn_{idx}.stdout.log"
        stderr_path = self.tmp_dir / f"uvicorn_{idx}.stderr.log"
        self._stdout_file = stdout_path.open("wb")
        self._stderr_file = stderr_path.open("wb")

        repo_root = Path(__file__).resolve().parents[2]
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
        self._proc = subprocess.Popen(
            cmd,
            cwd=str(repo_root),
            env=self.env,
            stdout=self._stdout_file,
            stderr=self._stderr_file,
        )
        self._wait_healthy(timeout=timeout, stdout_path=stdout_path, stderr_path=stderr_path)

    def _wait_healthy(self, *, timeout: float, stdout_path: Path, stderr_path: Path) -> None:
        deadline = time.monotonic() + timeout
        last_exc: Exception | None = None
        with httpx.Client(timeout=2.0) as client:
            while time.monotonic() < deadline:
                if self._proc is not None and self._proc.poll() is not None:
                    stdout_txt = stdout_path.read_text(encoding="utf-8", errors="replace")
                    stderr_txt = stderr_path.read_text(encoding="utf-8", errors="replace")
                    raise RuntimeError(
                        f"uvicorn exited prematurely with code {self._proc.returncode}.\n"
                        f"STDOUT:\n{stdout_txt[-2000:]}\nSTDERR:\n{stderr_txt[-2000:]}"
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
            f"Timed out waiting for {self.base_url}/health (last error: {last_exc!r}).\n"
            f"STDERR:\n{stderr_txt[-2000:]}"
        )

    def _terminate_process(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)
        self._close_log_files()

    def restart(
        self,
        *,
        keep_port: bool = False,
        extra_env: dict[str, str] | None = None,
        timeout: float = 15.0,
    ) -> None:
        """Stop uvicorn cleanly via SIGTERM (kill fallback) and relaunch on the same DBs."""
        self._terminate_process()
        self._restart_count += 1
        if not keep_port:
            self.port = alloc_free_port(exclude={self.vnc_port, self.port})
            self._sync_urls()
        self.env = self._build_env(extra_overrides=extra_env)
        try:
            self._launch_process(timeout=timeout)
        except Exception:
            self._terminate_process()
            raise

    def stop(self) -> None:
        try:
            self._terminate_process()
        finally:
            if self.mock_rfb is not None:
                with contextlib.suppress(Exception):
                    self.mock_rfb.stop()
            if self.lab_stack is not None:
                with contextlib.suppress(Exception):
                    self.lab_stack.stop()

    def url(self, path: str, *, include_token: bool = True) -> str:
        rel = path if path.startswith("/") else f"/{path}"
        full = f"{self.base_url}{rel}"
        if include_token and self.web_token:
            sep = "&" if "?" in full else "?"
            return f"{full}{sep}{urlencode({'token': self.web_token})}"
        return full

    def ws_url(self, path: str, *, include_token: bool = True) -> str:
        rel = path if path.startswith("/") else f"/{path}"
        full = f"{self.ws_base_url}{rel}"
        if include_token and self.web_token:
            sep = "&" if "?" in full else "?"
            return f"{full}{sep}{urlencode({'token': self.web_token})}"
        return full

    def auth_headers(self) -> dict[str, str]:
        if not self.web_token:
            return {}
        return {"Authorization": f"Bearer {self.web_token}"}

    def client(self, timeout: float = 20.0) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            headers=self.auth_headers(),
            timeout=timeout,
        )

    def async_client(self, timeout: float = 20.0) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.auth_headers(),
            timeout=timeout,
        )


@dataclass(frozen=True)
class SseFrame:
    """Parsed Server-Sent Event frame."""

    id: str | None
    event: str | None
    data: dict[str, Any] | str
    raw: str

    @property
    def event_type(self) -> str | None:
        if isinstance(self.data, dict) and isinstance(self.data.get("type"), str):
            return str(self.data["type"])
        return self.event


def _parse_sse_frame(raw_lines: list[str]) -> SseFrame | None:
    frame_id: str | None = None
    event_name: str | None = None
    data_lines: list[str] = []
    for line in raw_lines:
        if line.startswith(":"):
            continue
        if ":" in line:
            field_name, raw_val = line.split(":", 1)
            val = raw_val[1:] if raw_val.startswith(" ") else raw_val
        else:
            field_name, val = line, ""
        if field_name == "id":
            frame_id = val
        elif field_name == "event":
            event_name = val
        elif field_name == "data":
            data_lines.append(val)

    if not data_lines and frame_id is None and event_name is None:
        return None
    if not data_lines:
        return None

    joined = "\n".join(data_lines)
    parsed: dict[str, Any] | str = joined
    stripped = joined.lstrip()
    if stripped.startswith(("{", "[")):
        with contextlib.suppress(json.JSONDecodeError):
            obj = json.loads(joined)
            if isinstance(obj, dict):
                parsed = obj

    resolved_event = event_name
    if resolved_event is None and isinstance(parsed, dict) and isinstance(parsed.get("type"), str):
        resolved_event = str(parsed["type"])

    return SseFrame(
        id=frame_id,
        event=resolved_event,
        data=parsed,
        raw="\n".join(raw_lines),
    )


async def iter_sse_events(
    client_or_url: httpx.AsyncClient | str,
    last_event_id: str | None = None,
    timeout: float = 10.0,
    *,
    url: str = "/api/v1/events/stream",
    headers: dict[str, str] | None = None,
    on_connected: asyncio.Event | None = None,
    on_first_line: asyncio.Event | None = None,
) -> AsyncIterator[SseFrame]:
    """Stream and parse SSE frames from a full URL or an existing httpx.AsyncClient."""
    req_headers = dict(headers or {})
    if last_event_id is not None:
        req_headers["Last-Event-ID"] = last_event_id

    httpx_timeout = httpx.Timeout(connect=5.0, read=timeout, write=5.0, pool=5.0)
    if isinstance(client_or_url, str):
        owns_client = True
        client: httpx.AsyncClient = httpx.AsyncClient(timeout=httpx_timeout)
        target = client_or_url
    else:
        owns_client = False
        client = client_or_url
        target = url

    try:
        async with asyncio.timeout(timeout), client.stream(
            "GET",
            target,
            headers=req_headers,
            timeout=httpx_timeout,
        ) as resp:
            resp.raise_for_status()
            if on_connected is not None:
                on_connected.set()
            buf: list[str] = []
            async for line in resp.aiter_lines():
                if on_first_line is not None and not on_first_line.is_set():
                    on_first_line.set()
                if line == "":
                    if buf:
                        frame = _parse_sse_frame(buf)
                        buf.clear()
                        if frame is not None:
                            yield frame
                else:
                    buf.append(line)
            if buf:
                frame = _parse_sse_frame(buf)
                if frame is not None:
                    yield frame
    finally:
        if on_connected is not None and not on_connected.is_set():
            on_connected.set()
        if on_first_line is not None and not on_first_line.is_set():
            on_first_line.set()
        if owns_client:
            await client.aclose()


async def wait_for_sse_event(
    url_or_client: str | httpx.AsyncClient,
    predicate: Callable[[SseFrame], bool],
    *,
    headers: dict[str, str] | None = None,
    last_event_id: str | None = None,
    timeout: float = 10.0,
    url: str = "/api/v1/events/stream",
) -> SseFrame:
    """Wait for the first SSE frame matching `predicate`, raising TimeoutError on expiry."""
    seen: list[str] = []
    try:
        async for frame in iter_sse_events(
            url_or_client,
            last_event_id=last_event_id,
            timeout=timeout,
            url=url,
            headers=headers,
        ):
            seen.append(str(frame.event_type or frame.event))
            if predicate(frame):
                return frame
    except TimeoutError as exc:
        raise TimeoutError(
            f"Timed out after {timeout}s waiting for matching SSE event. Seen: {seen}"
        ) from exc
    raise TimeoutError(
        f"SSE stream ended before matching event arrived. Seen: {seen}"
    )


@overload
def mint_cap_token(
    client: httpx.Client,
    vm_id: str = "default",
    *,
    ttl_seconds: int | None = None,
    session_id: str | None = None,
) -> dict[str, Any]: ...


@overload
def mint_cap_token(
    client: httpx.AsyncClient,
    vm_id: str = "default",
    *,
    ttl_seconds: int | None = None,
    session_id: str | None = None,
) -> Any: ...


def mint_cap_token(
    client: httpx.Client | httpx.AsyncClient,
    vm_id: str = "default",
    *,
    ttl_seconds: int | None = None,
    session_id: str | None = None,
) -> Any:
    """Mint a short-lived capability token via POST /api/v1/computers/{vm_id}/vnc-token."""
    body: dict[str, Any] = {}
    if ttl_seconds is not None:
        body["ttl_seconds"] = ttl_seconds
    if session_id is not None:
        body["session_id"] = session_id
    endpoint = f"/api/v1/computers/{vm_id}/vnc-token"

    if isinstance(client, httpx.AsyncClient):
        async def _mint_async() -> dict[str, Any]:
            resp = await client.post(endpoint, json=body or None)
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return data

        return _mint_async()

    resp = client.post(endpoint, json=body or None)
    resp.raise_for_status()
    data: dict[str, Any] = resp.json()
    return data


@dataclass
class TurnResult:
    """Captured REST + SSE outcome for a triggered agent turn."""

    turn_id: str
    user_message: dict[str, Any]
    events: list[SseFrame]
    terminal_event: SseFrame
    assistant_message: dict[str, Any] | None = None


async def trigger_and_wait_turn(
    client: httpx.AsyncClient,
    thread_id: str,
    content: str,
    *,
    sse_url: str = "/api/v1/events/stream",
    timeout: float = 15.0,
    terminal_events: tuple[str, ...] = (
        "message.completed",
        "hitl.approval.requested",
        "hitl.draft.created",
        "hitl.secure_form.requested",
    ),
    **message_kwargs: Any,
) -> TurnResult:
    """Open SSE before posting a thread message and wait until its turn completes."""
    payload: dict[str, Any] = {"content": content, **message_kwargs}
    collected: list[SseFrame] = []
    sse_connected = asyncio.Event()
    sse_first_line = asyncio.Event()
    turn_id_ready = asyncio.Event()
    target_turn_id: dict[str, str] = {}
    terminal_holder: dict[str, SseFrame] = {}

    async def _listen() -> None:
        async for frame in iter_sse_events(
            client,
            timeout=timeout,
            url=sse_url,
            on_connected=sse_connected,
            on_first_line=sse_first_line,
        ):
            collected.append(frame)
            if not turn_id_ready.is_set():
                await turn_id_ready.wait()
            tid = target_turn_id["id"]
            if not isinstance(frame.data, dict):
                continue
            if frame.data.get("turn_id") != tid:
                continue
            ev_name = frame.event_type or frame.event
            if ev_name in terminal_events:
                terminal_holder["frame"] = frame
                return

    listen_task = asyncio.create_task(_listen())
    try:
        # Wait for HTTP 200 on SSE stream, then wait for initial `: connected` line
        # (guaranteed to follow EventBus.stream_sse subscriber registration) with a short
        # fallback only if a test stub omits the SSE comment preamble.
        await asyncio.wait_for(sse_connected.wait(), timeout=min(5.0, timeout))
        if listen_task.done() and not listen_task.cancelled():
            exc = listen_task.exception()
            if exc is not None:
                raise exc
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(sse_first_line.wait(), timeout=min(0.25, timeout))

        resp = await client.post(f"/api/v1/threads/{thread_id}/messages", json=payload)
        resp.raise_for_status()
        post_data = resp.json()
        turn_id = str(post_data["turn_id"])
        target_turn_id["id"] = turn_id
        turn_id_ready.set()

        # Check already-collected events in case the turn completed right as POST returned
        for frame in collected:
            if (
                isinstance(frame.data, dict)
                and frame.data.get("turn_id") == turn_id
                and (frame.event_type or frame.event) in terminal_events
            ):
                terminal_holder["frame"] = frame
                listen_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await listen_task
                break
        else:
            await asyncio.wait_for(listen_task, timeout=timeout)
    finally:
        if not listen_task.done():
            listen_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await listen_task

    if "frame" not in terminal_holder:
        seen_events = [str(f.event_type or f.event) for f in collected]
        raise TimeoutError(
            "SSE stream closed before terminal event arrived for turn "
            f"{target_turn_id.get('id')!r} "
            f"(expected={terminal_events}, seen={seen_events})."
        )

    term = terminal_holder["frame"]
    turn_events = [
        f
        for f in collected
        if isinstance(f.data, dict) and f.data.get("turn_id") == target_turn_id["id"]
    ]
    assistant_msg: dict[str, Any] | None = None
    if isinstance(term.data, dict):
        ev_payload = term.data.get("payload")
        if isinstance(ev_payload, dict) and isinstance(ev_payload.get("message"), dict):
            assistant_msg = dict(ev_payload["message"])

    return TurnResult(
        turn_id=target_turn_id["id"],
        user_message=dict(post_data["user_message"]),
        events=turn_events,
        terminal_event=term,
        assistant_message=assistant_msg,
    )
