"""Ephemeral ASGI/uvicorn loopback server helpers for N2 integration tests."""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import uvicorn


class _NoSignalUvicornServer(uvicorn.Server):
    """Uvicorn server subclass that skips OS signal handler installation in async tests."""

    def install_signal_handlers(self) -> None:
        return


@asynccontextmanager
async def run_asgi_server(app: Any, host: str = "127.0.0.1") -> AsyncIterator[str]:
    """Bind an ephemeral TCP port on loopback, serve an ASGI app, and yield its origin URL."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, 0))
    sock.listen(128)
    sock.setblocking(False)
    port = int(sock.getsockname()[1])
    origin = f"http://{host}:{port}"

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
        lifespan="on",
    )
    server = _NoSignalUvicornServer(config)
    serve_task = asyncio.create_task(server.serve(sockets=[sock]))

    try:
        deadline = asyncio.get_running_loop().time() + 10.0
        while not server.started:
            if serve_task.done():
                exc = serve_task.exception()
                raise RuntimeError(f"Ephemeral uvicorn server exited prematurely: {exc!r}")
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError(f"Timed out waiting for uvicorn server on {origin}")
            await asyncio.sleep(0.01)
        yield origin
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(serve_task, timeout=5.0)
        except TimeoutError:
            serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await serve_task
        with contextlib.suppress(OSError):
            sock.close()
