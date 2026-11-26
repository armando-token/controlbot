"""Lazy interactive PTY terminal session for Live Computer Workspace."""

from __future__ import annotations

import asyncio
import codecs
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
        self._master_fd: int | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._reader_attached = False
        self._writer_attached = False
        self._write_buffer = bytearray()
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

        master_fd, slave_fd = pty.openpty()
        self._master_fd = master_fd
        try:
            self._set_winsize(master_fd, cols=100, rows=28)

            env = os.environ.copy()
            extra_path = f"{Path.home() / '.local' / 'bin'}:/opt/homebrew/bin:/usr/local/bin"
            env["PATH"] = f"{extra_path}:{env.get('PATH', '/usr/bin:/bin')}"
            env["TERM"] = "xterm-256color"
            env["LANG"] = env.get("LANG", "en_US.UTF-8")

            shell = _default_shell()
            try:
                self._proc = subprocess.Popen(
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
                with contextlib.suppress(OSError):
                    os.close(slave_fd)

            os.set_blocking(master_fd, False)
            self._loop.add_reader(master_fd, self._on_readable)
            self._reader_attached = True
        except Exception:
            self.close()
            raise

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
            text = self._decoder.decode(b"".join(chunks), final=False)
            if text:
                self.output_queue.put_nowait(text)
        if eof:
            tail = self._decoder.decode(b"", final=True)
            if tail:
                self.output_queue.put_nowait(tail)
            self._detach_reader()
            self.output_queue.put_nowait(None)

    def _detach_reader(self) -> None:
        fd = self._master_fd
        if self._reader_attached and fd is not None:
            with contextlib.suppress(Exception):
                self._loop.remove_reader(fd)
            self._reader_attached = False

    def _ensure_writer(self) -> None:
        fd = self._master_fd
        if not self._writer_attached and fd is not None and not self._closed:
            self._loop.add_writer(fd, self._on_writable)
            self._writer_attached = True

    def _detach_writer(self) -> None:
        fd = self._master_fd
        if self._writer_attached and fd is not None:
            with contextlib.suppress(Exception):
                self._loop.remove_writer(fd)
            self._writer_attached = False

    def _on_writable(self) -> None:
        fd = self._master_fd
        if self._closed or fd is None:
            self._detach_writer()
            return
        while self._write_buffer:
            try:
                written = os.write(fd, self._write_buffer)
            except BlockingIOError:
                return
            except OSError:
                self._write_buffer.clear()
                self._detach_writer()
                return
            if written == 0:
                return
            del self._write_buffer[:written]
        self._detach_writer()

    def write(self, data: str) -> None:
        """Send UTF-8 input bytes to the PTY child shell without dropping on EAGAIN."""
        if self._closed or self._master_fd is None or not data:
            return
        raw = data.encode("utf-8", errors="replace")
        if self._write_buffer:
            self._write_buffer.extend(raw)
            self._ensure_writer()
            return

        view = memoryview(raw)
        while view:
            try:
                written = os.write(self._master_fd, view)
                if written == 0:
                    self._write_buffer.extend(view)
                    self._ensure_writer()
                    break
                view = view[written:]
            except BlockingIOError:
                self._write_buffer.extend(view)
                self._ensure_writer()
                break
            except OSError:
                break

    def send_signal(self, sig: int) -> bool:
        """Deliver a POSIX signal to the PTY child process group."""
        if self._closed or sig <= 0:
            return False
        delivered = False
        proc = self._proc
        master_fd = self._master_fd

        fg_pgrp: int | None = None
        if master_fd is not None:
            with contextlib.suppress(OSError):
                candidate = os.tcgetpgrp(master_fd)
                if candidate > 0:
                    fg_pgrp = candidate

        if proc is not None and proc.poll() is None:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.killpg(proc.pid, sig)
                delivered = True
            if fg_pgrp is not None and fg_pgrp != proc.pid:
                with contextlib.suppress(ProcessLookupError, OSError):
                    os.killpg(fg_pgrp, sig)
                    delivered = True
        elif fg_pgrp is not None:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.killpg(fg_pgrp, sig)
                delivered = True

        if not delivered and sig == int(signal.SIGINT):
            self.write("\x03")
            delivered = True
        return delivered

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
        self._detach_writer()
        self._write_buffer.clear()
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
