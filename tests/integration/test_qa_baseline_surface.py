"""Integration tests for M1 QA baseline CLI, React /app surface, and Makefile target."""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from src.qa.isolation import LIVE_FORBIDDEN_PORTS, IsolatedLabServer, alloc_ephemeral_port
from src.web.app import _render_studio_app_html

_REPO_ROOT = Path(__file__).resolve().parents[2]


class _NoSignalServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        return None


@contextlib.contextmanager
def _run_custom_uvicorn(app: FastAPI) -> Iterator[str]:
    port = alloc_ephemeral_port()
    assert port not in LIVE_FORBIDDEN_PORTS
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = _NoSignalServer(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 10.0
    with httpx.Client(timeout=1.0, trust_env=False) as client:
        while time.monotonic() < deadline:
            try:
                if client.get(f"{base_url}/health").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


@pytest.mark.n2
def test_baseline_cli_subprocess_against_isolated_react_server_and_browser(tmp_path: Path) -> None:
    dist_dir = _REPO_ROOT / "frontend" / "dist"
    assert (dist_dir / "index.html").is_file(), "Compiled frontend/dist/index.html is required"

    out_dir = tmp_path / "qa_camp_green"
    with IsolatedLabServer(repo_root=_REPO_ROOT, base_dir=tmp_path / "lab") as srv:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "src.qa",
                "baseline",
                "--target-url",
                srv.base_url,
                "--output-dir",
                str(out_dir),
                "--no-build-frontend",
                "--json",
            ],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        assert "RuntimeWarning" not in proc.stderr

    baseline_data = json.loads((out_dir / "baseline.json").read_text(encoding="utf-8"))
    assert baseline_data["surface_verified"] is True
    assert baseline_data["served_surface"] == "react"
    assert baseline_data["boot_errors"] == []
    assert baseline_data["functional_errors"] == []
    assert len(baseline_data["asset_hashes"]) >= 2
    assert len(baseline_data["react_controls_verified"]) >= 3
    assert (out_dir / "BASELINE.md").is_file()
    assert (out_dir / "campaign.json").is_file()

    rep_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.qa",
            "report",
            "--campaign-dir",
            str(out_dir),
            "--json",
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert rep_proc.returncode == 0, f"STDERR:\n{rep_proc.stderr}"
    assert (out_dir / "daily_report.md").is_file()
    assert (out_dir / "HANDOFF.md").is_file()


@pytest.mark.n2
def test_baseline_cli_fails_distinguishing_legacy_fallback_in_isolated_server(
    tmp_path: Path,
) -> None:
    legacy_html = (_REPO_ROOT / "src" / "web" / "templates" / "studio.html").read_text(
        encoding="utf-8"
    )
    app = FastAPI()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "grokbot-web"}

    @app.get("/api/system/info")
    def sys_info() -> dict[str, str]:
        return {"service": "controlbot", "backend_mode": "emulated", "runtime_mode": "live_runtime"}

    @app.get("/api/v1/bots")
    def bots() -> dict[str, list[object]]:
        return {"bots": []}

    @app.get("/app")
    @app.get("/app/{subpath:path}")
    def legacy_app(subpath: str = "") -> HTMLResponse:
        del subpath
        return HTMLResponse(legacy_html)

    out_dir = tmp_path / "qa_camp_legacy"
    with _run_custom_uvicorn(app) as base_url:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "src.qa",
                "baseline",
                "--target-url",
                str(base_url),
                "--output-dir",
                str(out_dir),
                "--no-build-frontend",
                "--json",
            ],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 2, f"Expected boot failure 2, got {proc.returncode}"

    baseline_data = json.loads((out_dir / "baseline.json").read_text(encoding="utf-8"))
    assert baseline_data["surface_verified"] is False
    assert baseline_data["served_surface"] == "legacy_fallback"
    assert baseline_data["boot_errors"]
    assert baseline_data["functional_errors"] == []


@pytest.mark.n2
def test_baseline_cli_distinguishes_functional_error_from_boot_error(tmp_path: Path) -> None:
    dist_dir = _REPO_ROOT / "frontend" / "dist"
    rendered_html = _render_studio_app_html(
        (dist_dir / "index.html").read_text(encoding="utf-8"),
        dist_dir / "assets",
    )
    app = FastAPI()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "grokbot-web"}

    @app.get("/api/system/info")
    def sys_info() -> dict[str, str]:
        return {"service": "controlbot", "backend_mode": "emulated", "runtime_mode": "live_runtime"}

    @app.get("/api/v1/bots")
    def bots_fail() -> JSONResponse:
        return JSONResponse({"detail": "injected failure"}, status_code=500)

    @app.get("/app")
    @app.get("/app/{subpath:path}")
    def react_app(subpath: str = "") -> HTMLResponse:
        del subpath
        return HTMLResponse(rendered_html)

    @app.get("/assets/{file_path:path}")
    def react_assets(file_path: str) -> PlainTextResponse:
        target = (dist_dir / "assets" / file_path).resolve()
        media = "application/javascript" if file_path.endswith(".js") else "text/css"
        return PlainTextResponse(target.read_text(encoding="utf-8"), media_type=media)

    out_dir = tmp_path / "qa_camp_func_fail"
    with _run_custom_uvicorn(app) as base_url:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "src.qa",
                "baseline",
                "--target-url",
                str(base_url),
                "--output-dir",
                str(out_dir),
                "--no-build-frontend",
                "--json",
            ],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 3, f"Expected functional failure 3, got {proc.returncode}"

    baseline_data = json.loads((out_dir / "baseline.json").read_text(encoding="utf-8"))
    assert baseline_data["surface_verified"] is True
    assert baseline_data["served_surface"] == "react"
    assert baseline_data["boot_errors"] == []
    assert baseline_data["functional_errors"]


@pytest.mark.n2
def test_make_qa_baseline_target_dry_or_isolated_execution() -> None:
    dry_proc = subprocess.run(
        ["make", "-n", "qa-baseline"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert dry_proc.returncode == 0, f"STDERR:\n{dry_proc.stderr}"
    assert "src.qa baseline" in dry_proc.stdout
    assert "frontend" in dry_proc.stdout
    assert "test_qa_baseline_surface.py" in dry_proc.stdout

    check_proc = subprocess.run(
        ["make", "-n", "check"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert check_proc.returncode == 0
    assert "doctor" in check_proc.stdout
    assert "lint" in check_proc.stdout
    assert "typecheck" in check_proc.stdout
    assert "test" in check_proc.stdout


@pytest.mark.n2
def test_baseline_cli_unreachable_target_records_boot_errors_only(tmp_path: Path) -> None:
    dead_port = alloc_ephemeral_port()
    out_dir = tmp_path / "qa_camp_unreachable"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.qa",
            "baseline",
            "--target-url",
            f"http://127.0.0.1:{dead_port}",
            "--output-dir",
            str(out_dir),
            "--no-build-frontend",
            "--json",
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    data = json.loads((out_dir / "baseline.json").read_text(encoding="utf-8"))
    assert data["served_surface"] == "unreachable"
    assert data["surface_verified"] is False
    assert data["overall_passed"] is False
    assert data["boot_errors"]
    assert data["functional_errors"] == []


@pytest.mark.n2
def test_baseline_cli_linux_real_and_agy_real_reject_incomplete_env_or_emulated_engine(
    tmp_path: Path,
) -> None:
    with IsolatedLabServer(repo_root=_REPO_ROOT, base_dir=tmp_path / "lab") as srv:
        linux_out = tmp_path / "qa_camp_linux_real"
        linux_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "src.qa",
                "baseline",
                "--target-url",
                srv.base_url,
                "--output-dir",
                str(linux_out),
                "--lane",
                "linux_real",
                "--no-build-frontend",
                "--json",
            ],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        linux_data = json.loads((linux_out / "baseline.json").read_text(encoding="utf-8"))
        if linux_data["n3_status"] != "READY":
            assert linux_proc.returncode != 0
            assert linux_data["overall_passed"] is False
            assert linux_data["functional_errors"]

        agy_out = tmp_path / "qa_camp_agy_real"
        agy_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "src.qa",
                "baseline",
                "--target-url",
                srv.base_url,
                "--output-dir",
                str(agy_out),
                "--lane",
                "agy_real",
                "--no-build-frontend",
                "--json",
            ],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert agy_proc.returncode != 0
        agy_data = json.loads((agy_out / "baseline.json").read_text(encoding="utf-8"))
        assert agy_data["overall_passed"] is False
        assert agy_data["functional_errors"]
