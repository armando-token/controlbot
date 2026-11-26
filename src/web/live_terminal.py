"""Lazy interactive PTY terminal session for Live Computer Workspace."""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import pty
import shutil
import signal
import struct
import subprocess
import termios
from pathlib import Path


def _default_shell() -> str:
    zsh_path = Path("/bin/zsh")
    if zsh_path.is_file() and os.access(zsh_path, os.X_OK):
        return str(zsh_path)
    return shutil.which("zsh") or shutil.which("bash") or "/bin/sh"


class LiveTerminalSession:
    """Manages an interactive pseudo-terminal child shell bound to an asyncio loop."""

    def __init__(self, *, cwd: Path) -> None:
        self.cwd = cwd
        self.output_queue: asyncio.Queue[str | None] = asyncio.Queue()
        self._loop = asyncio.get_running_loop()
        self._closed = False

        master_fd, slave_fd = pty.openpty()
        self._master_fd: int | None = master_fd
        self._set_winsize(master_fd, cols=100, rows=28)

        env = os.environ.copy()
        extra_path = f"{Path.home() / '.local' / 'bin'}:/opt/homebrew/bin:/usr/local/bin"
        env["PATH"] = f"{extra_path}:{env.get('PATH', '/usr/bin:/bin')}"
        env["TERM"] = "xterm-256color"
        env["LANG"] = env.get("LANG", "en_US.UTF-8")

        shell = _default_shell()
        try:
            self._proc: subprocess.Popen[bytes] | None = subprocess.Popen(
                [shell, "-i"],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=str(cwd),
                env=env,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            os.close(slave_fd)

        os.set_blocking(master_fd, False)
        self._loop.add_reader(master_fd, self._on_readable)

    @staticmethod
    def _set_winsize(fd: int, *, cols: int, rows: int) -> None:
        bounded_cols = max(20, min(300, int(cols)))
        bounded_rows = max(5, min(120, int(rows)))
        winsz = struct.pack("HHHH", bounded_rows, bounded_cols, 0, 0)
        with contextlib.suppress(OSError):
            fcntl.ioctl(fd, termios.TIOCSWINSZ, winsz)

    def _on_readable(self) -> None:
        fd = self._master_fd
        if fd is None or self._closed:
            return
        chunks: list[bytes] = []
        eof = False
        while True:
            try:
                data = os.read(fd, 4096)
            except BlockingIOError:
                break
            except OSError:
                eof = True
                break
            if not data:
                eof = True
                break
            chunks.append(data)

        if chunks:
            text = b"".join(chunks).decode("utf-8", errors="replace")
            self.output_queue.put_nowait(text)
        if eof:
            self._detach_reader()
            self.output_queue.put_nowait(None)

    def _detach_reader(self) -> None:
        fd = self._master_fd
        if fd is not None:
            with contextlib.suppress(Exception):
                self._loop.remove_reader(fd)

    def write(self, data: str) -> None:
        """Send UTF-8 input bytes to the PTY child shell."""
        if self._closed or self._master_fd is None or not data:
            return
        raw = data.encode("utf-8", errors="replace")
        view = memoryview(raw)
        while view:
            try:
                written = os.write(self._master_fd, view)
                view = view[written:]
            except BlockingIOError:
                break
            except OSError:
                break

    def resize(self, *, cols: int, rows: int) -> None:
        """Update PTY terminal dimensions."""
        if self._closed or self._master_fd is None:
            return
        self._set_winsize(self._master_fd, cols=cols, rows=rows)

    def close(self) -> None:
        """Terminate PTY child process group and close descriptors."""
        if self._closed:
            return
        self._closed = True
        self._detach_reader()
        if self._master_fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._master_fd)
            self._master_fd = None

        proc = self._proc
        self._proc = None
        if proc is not None and proc.poll() is None:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.killpg(proc.pid, signal.SIGTERM)
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                proc.wait(timeout=0.5)
            if proc.poll() is None:
                with contextlib.suppress(ProcessLookupError, OSError):
                    os.killpg(proc.pid, signal.SIGKILL)
                with contextlib.suppress(Exception):
                    proc.wait(timeout=0.5)
        self.output_queue.put_nowait(None)
