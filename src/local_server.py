"""Unified local server launcher (synthetic lab portals + ControlBot API & Studio UX)."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import uvicorn
from lab.effect_sim import create_effect_sim_app
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import create_scada_app

from src.adapters import MappingCredentialProvider, load_facility_config
from src.adapters.effects import EffectSimAdapter
from src.contracts.common import utc_now
from src.contracts.enums import BackendMode
from src.model.http_client import LocalModelConfig
from src.runtime import GrokbotRuntime, build_runtime
from src.web.app import _build_default_credentials

_DEFAULT_FACILITY_PATH = (
    Path(__file__).resolve().parent.parent / "lab" / "configs" / "facility_a.json"
)


class _ManagedUvicornServer(uvicorn.Server):
    """Uvicorn server that lets the outer asyncio supervisor handle SIGINT/SIGTERM."""

    def install_signal_handlers(self) -> None:
        return None


@dataclass(frozen=True)
class LocalServerStackInfo:
    """Live endpoints and configuration metadata for the unified local server."""

    web_origin: str
    studio_url: str
    classic_url: str
    scada_origin: str | None
    maintenance_origin: str | None
    effect_origin: str | None
    backend_mode: str
    db_path: Path
    profile_root: Path


def _parse_llm_config(
    llm_url: str | None,
    llm_model: str,
) -> tuple[BackendMode, LocalModelConfig | None]:
    cleaned = (llm_url or "").strip()
    if not cleaned:
        return BackendMode.EMULATED, None
    parsed = urlparse(cleaned)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    raw_path = parsed.path.rstrip("/")
    endpoint_path = (
        "/v1/chat/completions" if raw_path in {"", "/v1"} else f"{raw_path}/chat/completions"
    )
    return (
        BackendMode.LOCAL_HTTP,
        LocalModelConfig(
            origin=origin,
            endpoint_path=endpoint_path,
            model_id=llm_model.strip() or "qwen2.5:3b",
            allow_private_lan=False,
        ),
    )


@contextlib.asynccontextmanager
async def running_local_stack(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    scada_port: int = 8101,
    maintenance_port: int = 8102,
    effect_port: int = 8103,
    facility_path: Path = _DEFAULT_FACILITY_PATH,
    fixture_mode: str = "default",
    db_path: Path = Path("var/controlbot.sqlite3"),
    profile_root: Path = Path(".browser_profiles/desktop"),
    llm_url: str | None = None,
    llm_model: str = "qwen2.5:3b",
    start_lab: bool = True,
) -> AsyncIterator[tuple[LocalServerStackInfo, GrokbotRuntime, list[_ManagedUvicornServer]]]:
    """Start lab portals (optional) + ControlBot runtime & FastAPI server in one event loop."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    profile_root.mkdir(parents=True, exist_ok=True)

    servers: list[_ManagedUvicornServer] = []
    tasks: list[asyncio.Task[None]] = []
    overrides: dict[str, str] = {}
    scada_origin: str | None = None
    maint_origin: str | None = None
    effect_origin: str | None = None

    async def _launch_server(server: _ManagedUvicornServer) -> None:
        task = asyncio.create_task(server.serve())
        tasks.append(task)
        for _ in range(150):
            if server.started:
                return
            if task.done():
                exc = task.exception()
                if exc is not None:
                    raise exc
                raise RuntimeError("Uvicorn server exited before starting.")
            await asyncio.sleep(0.05)
        raise TimeoutError("Timed out waiting for local server startup.")

    try:
        if start_lab:
            now_ref = utc_now()
            scada_app = create_scada_app(fixture_mode=fixture_mode)
            maint_app = create_maintenance_app(fixture_mode=fixture_mode)
            effect_app = create_effect_sim_app()
            scada_app.state.scada_state.set_reference_time(now_ref)
            maint_app.state.maintenance_state.set_reference_time(now_ref)

            scada_srv = _ManagedUvicornServer(
                uvicorn.Config(scada_app, host=host, port=scada_port, log_level="warning")
            )
            maint_srv = _ManagedUvicornServer(
                uvicorn.Config(maint_app, host=host, port=maintenance_port, log_level="warning")
            )
            effect_srv = _ManagedUvicornServer(
                uvicorn.Config(effect_app, host=host, port=effect_port, log_level="warning")
            )
            for srv in (scada_srv, maint_srv, effect_srv):
                servers.append(srv)
                await _launch_server(srv)

            scada_port_actual = scada_srv.servers[0].sockets[0].getsockname()[1]
            maint_port_actual = maint_srv.servers[0].sockets[0].getsockname()[1]
            effect_port_actual = effect_srv.servers[0].sockets[0].getsockname()[1]
            scada_origin = f"http://{host}:{scada_port_actual}"
            maint_origin = f"http://{host}:{maint_port_actual}"
            effect_origin = f"http://{host}:{effect_port_actual}"
            overrides = {
                "scada": scada_origin,
                "maintenance": maint_origin,
                "effect_sim": effect_origin,
            }

        facility_cfg = load_facility_config(
            facility_path,
            origin_overrides=overrides or None,
        )
        backend_mode, local_http_cfg = _parse_llm_config(llm_url, llm_model)
        effect_adapter = EffectSimAdapter() if "effect_sim" in facility_cfg.apps else None

        runtime = build_runtime(
            db_path=db_path,
            profile_root=profile_root,
            facility_config=facility_cfg,
            credential_provider=MappingCredentialProvider(_build_default_credentials()),
            backend_mode=backend_mode,
            local_http_config=local_http_cfg,
            effect_adapter=effect_adapter,
            reference_time_fn=utc_now,
            auto_run=True,
            headless=True,
        )
        async with runtime:
            web_srv = _ManagedUvicornServer(
                uvicorn.Config(runtime.app, host=host, port=port, log_level="info")
            )
            servers.append(web_srv)
            await _launch_server(web_srv)
            web_port_actual = web_srv.servers[0].sockets[0].getsockname()[1]
            web_origin = f"http://{host}:{web_port_actual}"
            info = LocalServerStackInfo(
                web_origin=web_origin,
                studio_url=f"{web_origin}/app",
                classic_url=f"{web_origin}/",
                scada_origin=scada_origin,
                maintenance_origin=maint_origin,
                effect_origin=effect_origin,
                backend_mode=backend_mode.value,
                db_path=db_path,
                profile_root=profile_root,
            )
            yield info, runtime, servers
    finally:
        for srv in reversed(servers):
            srv.should_exit = True
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(task, timeout=5.0)


async def serve_local_stack(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    scada_port: int = 8101,
    maintenance_port: int = 8102,
    effect_port: int = 8103,
    facility_path: Path = _DEFAULT_FACILITY_PATH,
    fixture_mode: str = "default",
    db_path: Path = Path("var/controlbot.sqlite3"),
    profile_root: Path = Path(".browser_profiles/desktop"),
    llm_url: str | None = None,
    llm_model: str = "qwen2.5:3b",
    start_lab: bool = True,
) -> int:
    """Run the unified ControlBot local server until SIGINT/SIGTERM."""
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop_event.set)

    async with running_local_stack(
        host=host,
        port=port,
        scada_port=scada_port,
        maintenance_port=maintenance_port,
        effect_port=effect_port,
        facility_path=facility_path,
        fixture_mode=fixture_mode,
        db_path=db_path,
        profile_root=profile_root,
        llm_url=llm_url,
        llm_model=llm_model,
        start_lab=start_lab,
    ) as (info, _, _):
        print(f"ControlBot Studio  : {info.studio_url}", flush=True)
        print(f"ControlBot Classic : {info.classic_url}", flush=True)
        if info.scada_origin:
            print(f"Lab SCADA          : {info.scada_origin}", flush=True)
        if info.maintenance_origin:
            print(f"Lab Maintenance    : {info.maintenance_origin}", flush=True)
        if info.effect_origin:
            print(f"Lab EffectSim      : {info.effect_origin}", flush=True)
        print(f"Backend Mode       : {info.backend_mode}", flush=True)
        print(f"SQLite WAL DB      : {info.db_path}", flush=True)
        await stop_event.wait()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for unified local ControlBot stack."""
    parser = argparse.ArgumentParser(
        description="Launch ControlBot local server (Studio UI + API + synthetic lab apps)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="ControlBot Web port (default 8000)")
    parser.add_argument(
        "--scada-port",
        type=int,
        default=8101,
        help="Lab SCADA port (default 8101)",
    )
    parser.add_argument(
        "--maintenance-port",
        type=int,
        default=8102,
        help="Lab Maintenance port (default 8102)",
    )
    parser.add_argument(
        "--effect-port", type=int, default=8103, help="Lab EffectSim port (default 8103)"
    )
    parser.add_argument(
        "--facility",
        type=Path,
        default=_DEFAULT_FACILITY_PATH,
        help="Facility JSON config path",
    )
    parser.add_argument("--fixture-mode", default="default", help="Lab fixture mode")
    parser.add_argument(
        "--db-path",
        type=Path,
        default=Path("var/controlbot.sqlite3"),
        help="SQLite WAL database path",
    )
    parser.add_argument(
        "--profile-root",
        type=Path,
        default=Path(".browser_profiles/desktop"),
        help="Isolated Playwright profile root",
    )
    parser.add_argument(
        "--llm-url",
        default=None,
        help="Optional local OpenAI/llama.cpp/Ollama base URL (e.g. http://127.0.0.1:11434/v1)",
    )
    parser.add_argument("--llm-model", default="qwen2.5:3b", help="Local LLM model id")
    parser.add_argument(
        "--no-lab",
        action="store_true",
        help="Do not boot synthetic lab apps (use origins from facility config as-is)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    return asyncio.run(
        serve_local_stack(
            host=args.host,
            port=args.port,
            scada_port=args.scada_port,
            maintenance_port=args.maintenance_port,
            effect_port=args.effect_port,
            facility_path=args.facility,
            fixture_mode=args.fixture_mode,
            db_path=args.db_path,
            profile_root=args.profile_root,
            llm_url=args.llm_url,
            llm_model=args.llm_model,
            start_lab=not args.no_lab,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
