"""Environment diagnostics for N1, N2, and N3 readiness."""

from __future__ import annotations

import argparse
import importlib.util
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class CheckStatus(StrEnum):
    """Status of a single diagnostic check."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    PENDING_N3_LINUX_ENV = "pending_n3_linux_env"


class EvidenceLevel(StrEnum):
    """Evidence tier required by a diagnostic check."""

    N1 = "N1"
    N2 = "N2"
    N3 = "N3"


class CheckResult(BaseModel):
    """Result of an individual environment check."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    status: CheckStatus
    required_for: EvidenceLevel
    summary: str
    detail: dict[str, Any] = Field(default_factory=dict)


class DoctorReport(BaseModel):
    """Aggregated host and environment readiness report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp_utc: str
    host_os: str
    host_release: str
    arch: str
    n1_ready: bool
    n2_ready: bool
    n3_status: Literal["PENDING_N3_LINUX_ENV", "READY"]
    checks: list[CheckResult]


def check_python_version(version_info: tuple[int, int, int] | None = None) -> CheckResult:
    """Verify that Python 3.12.x is active."""
    ver = version_info if version_info is not None else (
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
    )
    ver_str = f"{ver[0]}.{ver[1]}.{ver[2]}"
    if ver[0] == 3 and ver[1] == 12:
        return CheckResult(
            name="python_version",
            status=CheckStatus.PASS,
            required_for=EvidenceLevel.N1,
            summary=f"Python {ver_str} matches required 3.12.x.",
            detail={"version": ver_str, "executable": sys.executable},
        )
    return CheckResult(
        name="python_version",
        status=CheckStatus.FAIL,
        required_for=EvidenceLevel.N1,
        summary=f"Python {ver_str} does not match required >=3.12,<3.13.",
        detail={"version": ver_str, "executable": sys.executable},
    )


def check_sqlite_wal(db_dir: Path | None = None) -> CheckResult:
    """Verify SQLite WAL mode, foreign keys, and busy_timeout using separate PRAGMA calls."""
    temp_ctx: tempfile.TemporaryDirectory[str] | None = None
    try:
        if db_dir is None:
            temp_ctx = tempfile.TemporaryDirectory(prefix="grokbot_wal_probe_")
            target_dir = Path(temp_ctx.name)
        else:
            target_dir = db_dir
            target_dir.mkdir(parents=True, exist_ok=True)

        db_path = target_dir / "wal_probe.db"
        conn = sqlite3.connect(db_path)
        try:
            # Python sqlite3 execute() supports one statement per call.
            journal_row = conn.execute("PRAGMA journal_mode=WAL;").fetchone()
            conn.execute("PRAGMA foreign_keys=ON;")
            fk_row = conn.execute("PRAGMA foreign_keys;").fetchone()
            conn.execute("PRAGMA busy_timeout=5000;")
            timeout_row = conn.execute("PRAGMA busy_timeout;").fetchone()

            conn.execute(
                "CREATE TABLE IF NOT EXISTS probe (id INTEGER PRIMARY KEY, val TEXT NOT NULL);"
            )
            conn.execute("INSERT INTO probe (val) VALUES ('ok');")
            conn.commit()
            read_row = conn.execute("SELECT val FROM probe ORDER BY id DESC LIMIT 1;").fetchone()
        finally:
            conn.close()

        journal_mode = str(journal_row[0]).lower() if journal_row else ""
        fk_enabled = int(fk_row[0]) if fk_row else 0
        busy_timeout = int(timeout_row[0]) if timeout_row else 0
        read_val = str(read_row[0]) if read_row else ""

        ok = (
            journal_mode == "wal"
            and fk_enabled == 1
            and busy_timeout == 5000
            and read_val == "ok"
        )
        detail = {
            "sqlite_version": sqlite3.sqlite_version,
            "journal_mode": journal_mode,
            "foreign_keys": fk_enabled,
            "busy_timeout": busy_timeout,
            "read_back": read_val,
        }
        if ok:
            return CheckResult(
                name="sqlite_wal",
                status=CheckStatus.PASS,
                required_for=EvidenceLevel.N1,
                summary=(
                    f"SQLite {sqlite3.sqlite_version} WAL verified "
                    "(journal_mode=wal, foreign_keys=1, busy_timeout=5000)."
                ),
                detail=detail,
            )
        return CheckResult(
            name="sqlite_wal",
            status=CheckStatus.FAIL,
            required_for=EvidenceLevel.N1,
            summary="SQLite WAL probe did not satisfy required PRAGMA settings.",
            detail=detail,
        )
    except Exception as exc:
        return CheckResult(
            name="sqlite_wal",
            status=CheckStatus.FAIL,
            required_for=EvidenceLevel.N1,
            summary=f"SQLite WAL probe failed: {exc}",
            detail={"error": str(exc)},
        )
    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()


def _run_git_cmd(repo_dir: Path, args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout.strip()


def check_git(
    repo_dir: Path | None = None,
    which_fn: Callable[[str], str | None] = shutil.which,
) -> CheckResult:
    """Verify git binary, repository initialization, and local user config."""
    git_bin = which_fn("git")
    if git_bin is None:
        return CheckResult(
            name="git",
            status=CheckStatus.FAIL,
            required_for=EvidenceLevel.N1,
            summary="git executable not found on PATH.",
            detail={},
        )

    target_repo = repo_dir if repo_dir is not None else Path.cwd()
    git_version_proc = subprocess.run(
        [git_bin, "--version"], capture_output=True, text=True, check=False
    )
    git_version = git_version_proc.stdout.strip()
    has_git_dir = (target_repo / ".git").exists()
    name_rc, user_name = _run_git_cmd(target_repo, ["config", "user.name"])
    email_rc, user_email = _run_git_cmd(target_repo, ["config", "user.email"])

    detail: dict[str, Any] = {
        "git_path": git_bin,
        "git_version": git_version,
        "repo_dir": str(target_repo),
        "has_git_dir": has_git_dir,
        "user_name_set": name_rc == 0 and bool(user_name),
        "user_email_set": email_rc == 0 and bool(user_email),
    }

    if not has_git_dir:
        return CheckResult(
            name="git",
            status=CheckStatus.WARN,
            required_for=EvidenceLevel.N1,
            summary=f"{git_version} available, but .git directory not found in {target_repo}.",
            detail=detail,
        )
    if not (detail["user_name_set"] and detail["user_email_set"]):
        return CheckResult(
            name="git",
            status=CheckStatus.WARN,
            required_for=EvidenceLevel.N1,
            summary=f"{git_version} repo initialized, but git user.name/user.email is unset.",
            detail=detail,
        )
    return CheckResult(
        name="git",
        status=CheckStatus.PASS,
        required_for=EvidenceLevel.N1,
        summary=f"{git_version} ready with repo-local git identity.",
        detail=detail,
    )


def check_tooling(which_fn: Callable[[str], str | None] = shutil.which) -> CheckResult:
    """Verify uv and make availability and versions."""
    uv_bin = which_fn("uv")
    make_bin = which_fn("make")

    versions: dict[str, str] = {}
    if uv_bin:
        uv_proc = subprocess.run([uv_bin, "--version"], capture_output=True, text=True, check=False)
        versions["uv"] = uv_proc.stdout.strip()
    if make_bin:
        make_proc = subprocess.run(
            [make_bin, "--version"], capture_output=True, text=True, check=False
        )
        first_line = make_proc.stdout.splitlines()[0].strip() if make_proc.stdout else ""
        versions["make"] = first_line

    detail = {
        "uv_path": uv_bin,
        "make_path": make_bin,
        "versions": versions,
    }
    if uv_bin and make_bin:
        return CheckResult(
            name="tooling",
            status=CheckStatus.PASS,
            required_for=EvidenceLevel.N1,
            summary=f"Tooling ready ({versions.get('uv', 'uv')}, {versions.get('make', 'make')}).",
            detail=detail,
        )
    missing = [name for name, path in (("uv", uv_bin), ("make", make_bin)) if not path]
    return CheckResult(
        name="tooling",
        status=CheckStatus.FAIL,
        required_for=EvidenceLevel.N1,
        summary=f"Missing required build tooling: {', '.join(missing)}.",
        detail=detail,
    )


def check_playwright_env(
    cache_dir: Path | None = None,
    chrome_app_path: Path | None = None,
    has_playwright_pkg: bool | None = None,
) -> CheckResult:
    """Verify Playwright Python package and cached Chromium binaries for N2 tests."""
    system_name = platform.system()
    resolved_cache = cache_dir
    if resolved_cache is None:
        if system_name == "Darwin":
            resolved_cache = Path.home() / "Library" / "Caches" / "ms-playwright"
        else:
            resolved_cache = Path.home() / ".cache" / "ms-playwright"

    resolved_chrome = chrome_app_path
    if resolved_chrome is None and system_name == "Darwin":
        resolved_chrome = Path("/Applications/Google Chrome.app")

    pkg_available = (
        has_playwright_pkg
        if has_playwright_pkg is not None
        else importlib.util.find_spec("playwright") is not None
    )

    chromium_dirs: list[str] = []
    headless_dirs: list[str] = []
    if resolved_cache.exists():
        chromium_dirs = sorted(
            p.name
            for p in resolved_cache.iterdir()
            if p.is_dir() and p.name.startswith("chromium-") and any(p.iterdir())
        )
        headless_dirs = sorted(
            p.name
            for p in resolved_cache.iterdir()
            if p.is_dir() and p.name.startswith("chromium_headless_shell-")
        )

    chrome_exists = bool(resolved_chrome and resolved_chrome.exists())
    detail: dict[str, Any] = {
        "playwright_package_installed": pkg_available,
        "cache_dir": str(resolved_cache),
        "cache_exists": resolved_cache.exists(),
        "chromium_dirs": chromium_dirs,
        "headless_shell_dirs": headless_dirs,
        "chrome_app_path": str(resolved_chrome) if resolved_chrome else None,
        "chrome_app_exists": chrome_exists,
    }

    if not pkg_available:
        return CheckResult(
            name="playwright_env",
            status=CheckStatus.FAIL,
            required_for=EvidenceLevel.N2,
            summary="Playwright Python package is not installed in active environment.",
            detail=detail,
        )
    if not chromium_dirs:
        return CheckResult(
            name="playwright_env",
            status=CheckStatus.FAIL,
            required_for=EvidenceLevel.N2,
            summary=f"No cached Playwright chromium-* binary found in {resolved_cache}.",
            detail=detail,
        )
    if not headless_dirs:
        return CheckResult(
            name="playwright_env",
            status=CheckStatus.WARN,
            required_for=EvidenceLevel.N2,
            summary=(
                f"Playwright chromium ({', '.join(chromium_dirs)}) found, "
                "but chromium_headless_shell-* is missing."
            ),
            detail=detail,
        )
    return CheckResult(
        name="playwright_env",
        status=CheckStatus.PASS,
        required_for=EvidenceLevel.N2,
        summary=(
            f"Playwright ready with {', '.join(chromium_dirs)} and "
            f"{', '.join(headless_dirs)}."
        ),
        detail=detail,
    )


def check_n3_linux_env(
    system_name: str | None = None,
    which_fn: Callable[[str], str | None] = shutil.which,
) -> CheckResult:
    """Assess Linux OS, container/netns isolation, and local LLM runtime for N3."""
    os_name = system_name if system_name is not None else platform.system()
    container_tools = ("docker", "lima", "qemu-system-aarch64", "qemu-system-x86_64", "podman")
    llm_tools = ("ollama", "llama-server", "vllm")

    found_containers = {tool: which_fn(tool) for tool in container_tools if which_fn(tool)}
    found_llms = {tool: which_fn(tool) for tool in llm_tools if which_fn(tool)}

    is_linux = os_name == "Linux"
    detail: dict[str, Any] = {
        "system_name": os_name,
        "is_linux": is_linux,
        "container_or_vm_runtimes": found_containers,
        "local_llm_runtimes": found_llms,
    }

    if is_linux and found_llms:
        return CheckResult(
            name="n3_linux_env",
            status=CheckStatus.PASS,
            required_for=EvidenceLevel.N3,
            summary=(
                "Linux host and local LLM runtime detected "
                f"({', '.join(sorted(found_llms))})."
            ),
            detail=detail,
        )

    reasons: list[str] = []
    if not is_linux:
        reasons.append(f"host OS is {os_name} (Linux required for N3)")
    if not found_containers and not is_linux:
        reasons.append("no Linux VM/container runtime (docker/lima/qemu) found")
    if not found_llms:
        reasons.append("no local LLM runtime (ollama/llama-server/vllm) found")

    return CheckResult(
        name="n3_linux_env",
        status=CheckStatus.PENDING_N3_LINUX_ENV,
        required_for=EvidenceLevel.N3,
        summary=f"PENDING_N3_LINUX_ENV: {'; '.join(reasons)}.",
        detail=detail,
    )


def run_doctor(checks: Sequence[CheckResult] | None = None) -> DoctorReport:
    """Run all environment checks and build an aggregated DoctorReport."""
    resolved_checks = (
        list(checks)
        if checks is not None
        else [
            check_python_version(),
            check_sqlite_wal(),
            check_git(),
            check_tooling(),
            check_playwright_env(),
            check_n3_linux_env(),
        ]
    )

    n1_checks = [c for c in resolved_checks if c.required_for == EvidenceLevel.N1]
    n2_checks = [c for c in resolved_checks if c.required_for == EvidenceLevel.N2]
    n3_checks = [c for c in resolved_checks if c.required_for == EvidenceLevel.N3]

    n1_ready = bool(n1_checks) and all(c.status != CheckStatus.FAIL for c in n1_checks)
    n2_ready = (
        n1_ready
        and bool(n2_checks)
        and all(c.status != CheckStatus.FAIL for c in n2_checks)
    )
    n3_status: Literal["PENDING_N3_LINUX_ENV", "READY"] = (
        "READY"
        if n3_checks and all(c.status == CheckStatus.PASS for c in n3_checks)
        else "PENDING_N3_LINUX_ENV"
    )

    return DoctorReport(
        timestamp_utc=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        host_os=platform.system(),
        host_release=platform.release(),
        arch=platform.machine(),
        n1_ready=n1_ready,
        n2_ready=n2_ready,
        n3_status=n3_status,
        checks=resolved_checks,
    )


def _format_human_report(report: DoctorReport) -> str:
    lines = [
        f"Grokbot-clon Doctor ({report.timestamp_utc})",
        f"Host: {report.host_os} {report.host_release} ({report.arch})",
        (
            f"Readiness: n1_ready={report.n1_ready} | "
            f"n2_ready={report.n2_ready} | n3_status={report.n3_status}"
        ),
        "",
    ]
    for check in report.checks:
        lines.append(
            f"- [{check.status.value.upper()}] ({check.required_for.value}) "
            f"{check.name}: {check.summary}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for Grokbot-clon environment diagnostics."""
    parser = argparse.ArgumentParser(description="Grokbot-clon environment diagnostics")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    args = parser.parse_args(argv)

    report = run_doctor()
    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(_format_human_report(report))

    return 0 if (report.n1_ready and report.n2_ready) else 1


if __name__ == "__main__":
    raise SystemExit(main())
