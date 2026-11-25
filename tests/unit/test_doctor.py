"""N1 unit tests for src/doctor.py environment diagnostics."""

from __future__ import annotations

from pathlib import Path

import pytest
from src import doctor
from src.doctor import (
    CheckResult,
    CheckStatus,
    DoctorReport,
    EvidenceLevel,
    check_n3_linux_env,
    check_playwright_env,
    check_python_version,
    check_sqlite_wal,
    main,
    run_doctor,
)


@pytest.mark.n1
def test_check_python_version() -> None:
    ok = check_python_version((3, 12, 15))
    assert ok.status == CheckStatus.PASS
    assert ok.required_for == EvidenceLevel.N1

    too_old = check_python_version((3, 11, 9))
    assert too_old.status == CheckStatus.FAIL

    too_new = check_python_version((3, 13, 0))
    assert too_new.status == CheckStatus.FAIL


@pytest.mark.n1
def test_check_sqlite_wal(tmp_path: Path) -> None:
    result = check_sqlite_wal(db_dir=tmp_path)
    assert result.status == CheckStatus.PASS
    assert result.required_for == EvidenceLevel.N1
    assert result.detail["journal_mode"] == "wal"
    assert result.detail["foreign_keys"] == 1
    assert result.detail["busy_timeout"] == 5000
    assert result.detail["read_back"] == "ok"


@pytest.mark.n1
def test_check_playwright_env(tmp_path: Path) -> None:
    cache_dir = tmp_path / "ms-playwright"
    (cache_dir / "chromium-1248").mkdir(parents=True)
    (cache_dir / "chromium-1248" / "chrome-bin").write_text("stub", encoding="utf-8")
    (cache_dir / "chromium_headless_shell-1248").mkdir(parents=True)

    passed = check_playwright_env(
        cache_dir=cache_dir,
        chrome_app_path=tmp_path / "MissingChrome.app",
        has_playwright_pkg=True,
    )
    assert passed.status == CheckStatus.PASS
    assert passed.required_for == EvidenceLevel.N2
    assert passed.detail["chromium_dirs"] == ["chromium-1248"]

    # Missing headless shell -> WARN
    cache_warn = tmp_path / "ms-playwright-warn"
    (cache_warn / "chromium-1248").mkdir(parents=True)
    (cache_warn / "chromium-1248" / "chrome-bin").write_text("stub", encoding="utf-8")
    warned = check_playwright_env(
        cache_dir=cache_warn,
        chrome_app_path=tmp_path / "MissingChrome.app",
        has_playwright_pkg=True,
    )
    assert warned.status == CheckStatus.WARN

    # Empty chromium-* directory -> FAIL
    empty_chromium_cache = tmp_path / "ms-playwright-empty-chromium"
    (empty_chromium_cache / "chromium-1248").mkdir(parents=True)
    (empty_chromium_cache / "chromium_headless_shell-1248").mkdir(parents=True)
    failed_empty_chromium = check_playwright_env(
        cache_dir=empty_chromium_cache,
        chrome_app_path=tmp_path / "MissingChrome.app",
        has_playwright_pkg=True,
    )
    assert failed_empty_chromium.status == CheckStatus.FAIL

    # Missing chromium binary -> FAIL
    empty_cache = tmp_path / "ms-playwright-empty"
    empty_cache.mkdir()
    failed_bin = check_playwright_env(
        cache_dir=empty_cache,
        chrome_app_path=tmp_path / "MissingChrome.app",
        has_playwright_pkg=True,
    )
    assert failed_bin.status == CheckStatus.FAIL

    # Missing playwright package -> FAIL
    failed_pkg = check_playwright_env(
        cache_dir=cache_dir,
        chrome_app_path=tmp_path / "MissingChrome.app",
        has_playwright_pkg=False,
    )
    assert failed_pkg.status == CheckStatus.FAIL


@pytest.mark.n1
def test_check_n3_linux_env_reports_pending_never_fail() -> None:
    darwin_result = check_n3_linux_env(system_name="Darwin", which_fn=lambda _: None)
    assert darwin_result.status == CheckStatus.PENDING_N3_LINUX_ENV
    assert darwin_result.required_for == EvidenceLevel.N3

    linux_no_llm = check_n3_linux_env(system_name="Linux", which_fn=lambda _: None)
    assert linux_no_llm.status == CheckStatus.PENDING_N3_LINUX_ENV

    linux_with_llm = check_n3_linux_env(
        system_name="Linux",
        which_fn=lambda cmd: "/usr/bin/llama-server" if cmd == "llama-server" else None,
    )
    assert linux_with_llm.status == CheckStatus.PASS


@pytest.mark.n1
def test_run_doctor_and_main_json_exit_codes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    passing_checks = [
        CheckResult(
            name="python_version",
            status=CheckStatus.PASS,
            required_for=EvidenceLevel.N1,
            summary="ok",
        ),
        CheckResult(
            name="playwright_env",
            status=CheckStatus.PASS,
            required_for=EvidenceLevel.N2,
            summary="ok",
        ),
        CheckResult(
            name="n3_linux_env",
            status=CheckStatus.PENDING_N3_LINUX_ENV,
            required_for=EvidenceLevel.N3,
            summary="pending",
        ),
    ]
    report = run_doctor(checks=passing_checks)
    assert report.n1_ready is True
    assert report.n2_ready is True
    assert report.n3_status == "PENDING_N3_LINUX_ENV"

    monkeypatch.setattr(doctor, "run_doctor", lambda: report)
    rc_ok = main(["--json"])
    assert rc_ok == 0
    captured = capsys.readouterr().out
    parsed = DoctorReport.model_validate_json(captured)
    assert parsed.n1_ready is True
    assert parsed.n2_ready is True
    assert parsed.n3_status == "PENDING_N3_LINUX_ENV"

    # Failure in N2 returns exit code 1
    failing_report = run_doctor(
        checks=[
            passing_checks[0],
            CheckResult(
                name="playwright_env",
                status=CheckStatus.FAIL,
                required_for=EvidenceLevel.N2,
                summary="missing",
            ),
            passing_checks[2],
        ]
    )
    monkeypatch.setattr(doctor, "run_doctor", lambda: failing_report)
    rc_fail = main(["--json"])
    assert rc_fail == 1


@pytest.mark.n1
def test_check_git_and_check_tooling_edge_cases(tmp_path: Path) -> None:
    missing_git = doctor.check_git(repo_dir=tmp_path, which_fn=lambda _: None)
    assert missing_git.status == CheckStatus.FAIL

    no_git_dir = doctor.check_git(repo_dir=tmp_path)
    assert no_git_dir.status == CheckStatus.WARN

    missing_tools = doctor.check_tooling(which_fn=lambda _: None)
    assert missing_tools.status == CheckStatus.FAIL
    assert "uv" in missing_tools.summary and "make" in missing_tools.summary


@pytest.mark.n1
def test_run_doctor_empty_checks_not_ready() -> None:
    empty_report = run_doctor(checks=[])
    assert empty_report.n1_ready is False
    assert empty_report.n2_ready is False
    assert empty_report.n3_status == "PENDING_N3_LINUX_ENV"


