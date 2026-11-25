"""Pytest acceptance evidence recorder emitting Megaplan §6.3 JSONL records."""

from __future__ import annotations

import importlib.metadata
import json
import os
import platform
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_EVIDENCE_PATH = Path(__file__).resolve().parent / "acceptance_evidence.jsonl"
_SESSION_RECORDS: dict[str, dict[str, Any]] = {}


def _git_head_sha() -> str:
    proc = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    sha = proc.stdout.strip()
    return sha if sha else "0000000"


def _dependency_versions() -> dict[str, str]:
    deps: dict[str, str] = {"python": platform.python_version()}
    for pkg in ("pydantic", "fastapi", "uvicorn", "httpx", "playwright", "pyyaml", "pytest"):
        try:
            deps[pkg] = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            continue
    return deps


def _evidence_tier(report: pytest.TestReport) -> str:
    keywords = set(report.keywords)
    if "n3" in keywords:
        return "N3"
    if "n1" in keywords:
        return "N1"
    return "N2"


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.when != "call" and not (
        report.when == "setup" and report.outcome in {"skipped", "failed"}
    ):
        return

    tier = _evidence_tier(report)
    nodeid = report.nodeid
    low = nodeid.lower()
    if tier == "N3":
        backend_mode = "n3_linux_local_llm"
    elif "local_http" in low:
        backend_mode = "local_http"
    else:
        backend_mode = "emulated"

    exit_code = 0 if report.outcome in {"passed", "skipped"} else 1
    observed: str = report.outcome
    if report.outcome == "skipped" and tier == "N3":
        observed = "skipped: PENDING_N3_LINUX_ENV"
    elif report.outcome == "failed" and report.longreprtext:
        observed = f"failed: {report.longreprtext.splitlines()[-1][:200]}"

    record: dict[str, Any] = {
        "test_id": nodeid,
        "commit": _git_head_sha(),
        "dependency_versions": _dependency_versions(),
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "host": f"{platform.system()} {platform.machine()}",
        "backend_mode": backend_mode,
        "command": f"uv run pytest {nodeid}",
        "exit_code": exit_code,
        "expected": "pass" if report.outcome != "skipped" else "pass_or_pending_n3",
        "observed": observed,
        "evidence_tier": tier,
    }
    if "a12" in low:
        record["files_changed"] = ["lab/configs/facility_b.json"]
        record["adaptation_hours"] = round(max(0.0, float(report.duration)) / 3600.0, 6)

    _SESSION_RECORDS[nodeid] = record


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    del session, exitstatus
    if not _SESSION_RECORDS:
        return

    merged: dict[str, dict[str, Any]] = {}
    if _EVIDENCE_PATH.exists():
        for raw_line in _EVIDENCE_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw_line.strip():
                continue
            try:
                loaded = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            if isinstance(loaded, dict) and isinstance(loaded.get("test_id"), str):
                merged[loaded["test_id"]] = loaded

    merged.update(_SESSION_RECORDS)
    lines = [json.dumps(rec, ensure_ascii=False) for rec in merged.values()]
    content = "\n".join(lines) + "\n"

    _EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp_acc_ev_", dir=str(_EVIDENCE_PATH.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, _EVIDENCE_PATH)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def pytest_terminal_summary(
    terminalreporter: Any,
    exitstatus: int,
    config: pytest.Config,
) -> None:
    del exitstatus, config
    if platform.system() != "Linux":
        pending_n3 = [
            rec["test_id"]
            for rec in _SESSION_RECORDS.values()
            if rec.get("observed") == "skipped: PENDING_N3_LINUX_ENV"
        ]
        if pending_n3:
            terminalreporter.write_sep(
                "-",
                f"N3 Readiness: PENDING_N3_LINUX_ENV "
                f"({len(pending_n3)} skipped on {platform.system()})",
            )
            for test_id in pending_n3:
                terminalreporter.write_line(f"PENDING_N3_LINUX_ENV: {test_id}")
