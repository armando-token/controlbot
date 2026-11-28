"""Tier 2 boundary, negative, and corner-case E2E tests for Gates, Isolation & CLI."""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from src.factory.db import FactoryStore
from src.factory.errors import FactoryLeaseError, IsolationBoundaryError, PolicyImmutabilityError
from src.factory.models import BacklogItem
from src.factory.policy import IsolationGuard, PolicyGuard
from tests.e2e_qa.conftest import StrictBrowserPage
from tests.e2e_qa.fixtures import build_grok_bot_reference_card, evaluate_csv_to_json_converter
from tests.e2e_qa.helpers import (
    IsolatedQAEnv,
    QACliRunner,
    alloc_qa_free_port,
    assert_no_secret_leak,
    assert_react_app_surface,
)

pytestmark = pytest.mark.qa_tier2

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _git_head_sha(repo_dir: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _init_git_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "qa-e2e@example.local"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "QA E2E"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    (repo_dir / "README.md").write_text("# Isolated Repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return _git_head_sha(repo_dir)


def _create_candidate_branch(
    repo_dir: Path,
    branch_name: str,
    *,
    filename: str = "feature.txt",
    content: str = "candidate change\n",
) -> str:
    subprocess.run(
        ["git", "checkout", "-b", branch_name],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    (repo_dir / filename).write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", filename], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", f"candidate {branch_name}"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return _git_head_sha(repo_dir)


@pytest.mark.qa_existing
async def test_existing_missing_dist_app_silent_fallback_trap(
    tmp_path: Path,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Patchless repro: missing frontend/dist causes GET /app to silently return 200 legacy HTML."""
    iso_repo = tmp_path / "iso_repo"
    iso_repo.mkdir(parents=True, exist_ok=True)
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
    for subdir in ("src", "lab", "deploy"):
        shutil.copytree(_REPO_ROOT / subdir, iso_repo / subdir, ignore=ignore)
    assert not (iso_repo / "frontend" / "dist").exists()

    port = alloc_qa_free_port()
    base_url = f"http://127.0.0.1:{port}"
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for key in list(env):
        if (
            key.startswith(("GROKBOT_", "CONTROLBOT_"))
            or key in {"PORT", "DISPLAY", "WAYLAND_DISPLAY"}
        ):
            env.pop(key, None)
    env.update(
        {
            "HOME": str(fake_home),
            "PYTHONPATH": str(iso_repo),
            "GROKBOT_DB_PATH": str(tmp_path / "controlbot.sqlite3"),
            "GROKBOT_PROFILE_ROOT": str(tmp_path / "profiles"),
            "CONTROLBOT_PROJECTS_ROOT": str(tmp_path / "projects"),
            "GROKBOT_X11_DISPLAY": "",
            "PYTHONUNBUFFERED": "1",
        }
    )

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.web.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(iso_repo),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 15.0
        with httpx.Client(timeout=2.0) as client:
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    out, err = proc.communicate(timeout=2.0)
                    raise RuntimeError(
                        f"Isolated uvicorn exited ({proc.returncode}): "
                        f"{err.decode()}\n{out.decode()}"
                    )
                try:
                    if client.get(f"{base_url}/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.05)
            else:
                raise TimeoutError("Timed out waiting for isolated missing-dist uvicorn /health")

            resp = client.get(f"{base_url}/app")
            assert resp.status_code == 200
            assert "<title>ControlBot Studio</title>" in resp.text
            assert "controlbot.showPlantModule" in resp.text
            assert "<title>Grok Bot — ControlBot Studio</title>" not in resp.text

        with pytest.raises(AssertionError):
            await assert_react_app_surface(
                base_url,
                strict_browser_page,
                dist_dir=iso_repo / "frontend" / "dist",
            )
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)


@pytest.mark.qa_existing
def test_existing_auth_dual_token_asset_traversal_and_401_request_id(
    qa_auth_env: IsolatedQAEnv,
) -> None:
    """Verify auth exemption, dual-token mismatch 401, X-Request-Id correlation & /assets 404."""
    token = qa_auth_env.web_token
    assert token is not None

    with httpx.Client(base_url=qa_auth_env.base_url, timeout=10.0) as anon_client:
        assert anon_client.get("/health").status_code == 200
        assert anon_client.get("/app").status_code == 200
        assert anon_client.get("/studio-legacy").status_code == 401
        assert anon_client.get("/api/v1/diagnostics/summary").status_code == 401

        unauth_info = anon_client.get("/api/system/info")
        assert unauth_info.status_code == 401
        req_id = unauth_info.headers.get("X-Request-Id", "")
        assert req_id.startswith("req_")

        mismatch_resp = anon_client.get(
            "/api/system/info?token=wrong-token-value",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert mismatch_resp.status_code == 401

        trav_resp = anon_client.get("/assets/..%2F..%2Fetc%2Fpasswd")
        assert trav_resp.status_code == 404
        missing_asset = anon_client.get("/assets/nonexistent-qa-asset.js")
        assert missing_asset.status_code == 404

    with qa_auth_env.client() as auth_client:
        diag_resp = auth_client.get(f"/api/v1/diagnostics/failures?request_id={req_id}")
        assert diag_resp.status_code == 200
        diag_data = diag_resp.json()
        assert diag_data["count"] >= 1
        matching = [
            f for f in diag_data["failures"]
            if f.get("request_id") == req_id and f.get("status_code") == 401
        ]
        assert matching, f"Missing correlated 401 failure for {req_id}: {diag_data}"
        assert matching[0]["source"] == "backend_http"
        assert_no_secret_leak(diag_data, secrets=(token, qa_auth_env.cap_secret))


@pytest.mark.qa_existing
async def test_existing_strict_browser_page_blocks_external_and_detects_errors(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Verify StrictBrowserPage blocks external HTTP/WS, records console/404, & leak scanner."""
    await strict_browser_page.page.goto(f"{qa_env.base_url}/app", wait_until="domcontentloaded")
    await strict_browser_page.page.locator('textarea[aria-label="Message composer"]').wait_for(
        state="visible",
        timeout=15000,
    )
    await strict_browser_page.page.evaluate(
        """async () => {
            console.error("qa-synthetic-console-error");
            await fetch("/assets/missing-qa-bundle-404.js");
            try {
                await fetch("https://example.com/blocked.json");
            } catch (_err) {}
            try {
                const ws = new WebSocket("wss://example.com/ws");
                ws.close();
            } catch (_err) {}
        }"""
    )
    await strict_browser_page.page.wait_for_timeout(300)

    assert any("example.com" in u for u in strict_browser_page.external_requests)
    assert any("qa-synthetic-console-error" in m for m in strict_browser_page.console_errors)
    assert any(status == 404 for status, _url in strict_browser_page.http_errors)
    with pytest.raises(AssertionError):
        strict_browser_page.assert_clean()

    strict_browser_page.external_requests.clear()
    strict_browser_page.assert_clean(
        allow_http_statuses=(404,),
        allow_console_substrings=("qa-synthetic-console-error", "Failed to load resource"),
    )

    with contextlib.suppress(Exception):
        await strict_browser_page.page.goto("https://example.com/", timeout=5000)
    assert any("example.com" in u for u in strict_browser_page.external_requests)

    canary = "CANARY_SECRET_XYZ_987"
    with pytest.raises(AssertionError):
        assert_no_secret_leak({"msg": f"leaked {canary}"}, secrets=(canary,))
    with pytest.raises(AssertionError):
        assert_no_secret_leak({"api_token": "raw-secret-value"})
    with pytest.raises(AssertionError):
        assert_no_secret_leak({"header": "Authorization: Bearer raw-jwt-token"})
    with pytest.raises(AssertionError):
        assert_no_secret_leak({"url": "http://127.0.0.1:8000/app?token=raw-qs-token"})
    with pytest.raises(AssertionError):
        assert_no_secret_leak({"raw_log": '{"api_key": "raw-json-secret"}'})

    assert_no_secret_leak(
        {
            "api_token": "[REDACTED]",
            "header": "Bearer [REDACTED]",
            "header_punct": "Authorization: Bearer [REDACTED], retry=1",
            "basic_punct": "Authorization: Basic [REDACTED]; scope=read",
            "url": "http://127.0.0.1:8000/app?token=[REDACTED], ok=1",
            "raw_log": '{"api_key": "[REDACTED]"}',
            "total_tokens": 42,
        },
        secrets=(canary,),
    )


@pytest.mark.qa_existing
def test_existing_policy_guard_rejects_e2e_factory_policy_and_contracts() -> None:
    """Verify PolicyGuard raises PolicyImmutabilityError for tests/e2e, policy.py & contracts."""
    guard = PolicyGuard()
    for protected_path in (
        "tests/e2e/test_e2e_harness_smoke.py",
        "src/factory/policy.py",
        "src/contracts/common.py",
    ):
        with pytest.raises(PolicyImmutabilityError) as exc_info:
            guard.check_candidate_paths([protected_path])
        assert "POLICY_IMMUTABILITY_VIOLATION" in str(exc_info.value)
        assert protected_path in exc_info.value.offending_paths


@pytest.mark.qa_existing
def test_existing_policy_guard_rejects_p1_prefixes_and_bypass_lines() -> None:
    """Verify PolicyGuard catches git -p1 `a/` prefixes and inline bypass assignments."""
    guard = PolicyGuard()
    with pytest.raises(PolicyImmutabilityError):
        guard.check_candidate_paths(["a/tests/e2e/smoke.py"])

    with pytest.raises(PolicyImmutabilityError):
        guard.check_added_lines(
            ["PolicyGuard = None"],
            touched_paths=["src/web/app.py"],
        )


@pytest.mark.qa_existing
def test_existing_isolation_guard_blocks_runtime_db_creds_and_profile_dirs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify IsolationGuard & FactoryStore reject live DBs, creds, and browser profile dirs."""
    repo_dir = tmp_path / "iso_repo"
    _init_git_repo(repo_dir)

    live_db = tmp_path / "live_controlbot.sqlite3"
    with pytest.raises(IsolationBoundaryError):
        IsolationGuard.validate_paths(live_db, repo_dir, forbidden_db_paths=(live_db,))

    with pytest.raises(IsolationBoundaryError):
        FactoryStore(live_db, forbidden_db_paths=(live_db,))

    monkeypatch.setenv("GROKBOT_DB_PATH", str(live_db))
    with pytest.raises(IsolationBoundaryError):
        IsolationGuard.validate_paths(live_db, repo_dir)
    monkeypatch.delenv("GROKBOT_DB_PATH", raising=False)

    cred_dir = tmp_path / "creds"
    cred_dir.mkdir()
    with pytest.raises(IsolationBoundaryError):
        IsolationGuard.validate_paths(
            cred_dir / "factory.sqlite3",
            repo_dir,
            forbidden_credential_paths=(cred_dir,),
        )

    profile_db = tmp_path / ".grokbot_profiles" / "factory.sqlite3"
    with pytest.raises(IsolationBoundaryError):
        IsolationGuard.validate_paths(profile_db, repo_dir)


@pytest.mark.qa_existing
def test_existing_factory_lease_contention_and_stale_generation_rejected(
    tmp_path: Path,
) -> None:
    """Verify FactoryStore rejects double lease acquisition and stale generation release."""
    store = FactoryStore(tmp_path / "lease_test.sqlite3")
    store.init_db()
    store.add_backlog_item(
        BacklogItem(
            item_id="lease-item-1",
            title="Lease contention test",
            priority=1,
            hypothesis="Verify exclusive lease fencing",
            target_metric="lease_pass",
            baseline_repro_cmd="pytest tests/unit -q",
        )
    )
    lease = store.acquire_lease("lease-item-1", "worker-a", ttl_s=60.0)
    with pytest.raises(FactoryLeaseError):
        store.acquire_lease("lease-item-1", "worker-b", ttl_s=60.0)

    with pytest.raises(FactoryLeaseError):
        store.release_lease(lease.lease_id, lease.generation + 999)

    store.release_lease(lease.lease_id, lease.generation)


@pytest.mark.qa_existing
def test_existing_fixtures_reject_forbidden_grok_bots_and_malformed_csv(
    tmp_path: Path,
) -> None:
    """Verify Grok Bot card factory rejects non-{main,test} bots & CSV evaluator catches exit 0."""
    for forbidden_bot in ("work", "other", "", "Main", "TEST", "personal"):
        with pytest.raises(ValueError):
            build_grok_bot_reference_card(bot_name=forbidden_bot, case_id="CB-01")

    broken_converter = tmp_path / "broken_csv.py"
    broken_converter.write_text(
        "import json, sys\n"
        "open(sys.argv[2], 'w', encoding='utf-8').write('[]')\n",
        encoding="utf-8",
    )
    report = evaluate_csv_to_json_converter(
        [sys.executable, str(broken_converter)],
        work_dir=tmp_path / "broken_eval",
    )
    assert report.passed is False
    assert any(not r.passed for r in report.sample_results)


@pytest.mark.qa_megaplan
def test_megaplan_qa1_distinguishes_boot_error_from_functional_error(
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #2, #32, #33: Unreachable target records boot_errors distinctly from functional."""
    unused_port = alloc_qa_free_port()
    out_dir = tmp_path / "boot_err_out"
    res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            f"http://127.0.0.1:{unused_port}",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert res.returncode != 0
    data = json.loads((out_dir / "baseline.json").read_text(encoding="utf-8"))
    assert data["served_surface"] == "unreachable"
    assert data["surface_verified"] is False
    assert data["boot_errors"]
    assert data["functional_errors"] == []


@pytest.mark.qa_megaplan
def test_megaplan_app_legacy_fallback_200_fails_react_surface_gate(
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #3, #33: HTTP 200 legacy fallback on /app fails the React surface gate."""
    legacy_html = (
        "<!doctype html><html lang='es'><head><title>ControlBot Studio</title></head>"
        "<body><script>window.controlbot={showPlantModule:true};</script></body></html>"
    )

    class _LegacyHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.startswith("/health"):
                body = b'{"status":"ok","service":"grokbot-web","db_path":null}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.startswith("/app"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(legacy_html.encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    port = alloc_qa_free_port()
    httpd = socketserver.TCPServer(("127.0.0.1", port), _LegacyHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        out_dir = tmp_path / "legacy_fallback_out"
        res = qa_cli_runner.run(
            [
                "baseline",
                "--target-url",
                f"http://127.0.0.1:{port}",
                "--output-dir",
                str(out_dir),
            ]
        )
        assert res.returncode != 0
        data = json.loads((out_dir / "baseline.json").read_text(encoding="utf-8"))
        assert data["surface_verified"] is False
        assert data["served_surface"] == "legacy_fallback"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.qa_megaplan
def test_megaplan_skip_or_pending_n3_marker_never_counts_as_pass(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #6, #9, #33: Pending N3 / skipped checks never yield overall_passed=True."""
    out_dir = tmp_path / "n3_pending_out"
    res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(out_dir),
            "--lane",
            "linux_real",
        ]
    )
    data = json.loads((out_dir / "baseline.json").read_text(encoding="utf-8"))
    if (
        data.get("n3_status") == "PENDING_N3_LINUX_ENV"
        or data.get("n3_status") != "READY"
        or data.get("skipped_checks")
    ):
        assert res.returncode != 0
        assert data["overall_passed"] is False
    else:
        assert res.returncode == 0
        assert data["overall_passed"] is True


@pytest.mark.qa_megaplan
def test_megaplan_mismatched_engine_or_invalid_lane_rejected(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #4, #6, #9: Invalid lane or mismatched engine selection fails loudly."""
    out_dir = tmp_path / "bad_lane"
    bad_lane = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(out_dir),
            "--lane",
            "invalid_lane_xyz",
        ]
    )
    assert bad_lane.returncode != 0

    mismatch = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(tmp_path / "bad_engine"),
            "--lane",
            "agy_real",
        ]
    )
    assert mismatch.returncode != 0


@pytest.mark.qa_megaplan
def test_megaplan_mutating_campaign_commands_refuse_live_port_8000(
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #10: Mutating campaign commands refuse live :8000 target and live DB paths."""
    base_sha = _init_git_repo(tmp_path / "iso_guard_repo")

    camp_dir = tmp_path / "refuse_live_8000"
    camp_dir.mkdir(parents=True, exist_ok=True)
    (camp_dir / "campaign.json").write_text(
        json.dumps(
            {
                "campaign_id": "qa-live-refuse-8000",
                "base_sha": base_sha,
                "lane": "local_deterministic",
                "target_url": "http://127.0.0.1:8000",
                "status": "active",
                "output_dir": str(camp_dir),
            }
        ),
        encoding="utf-8",
    )

    for subcmd in (
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00"],
        ["repair", "--campaign-dir", str(camp_dir), "--max-parallel", "1"],
    ):
        res = qa_cli_runner.run(subcmd)
        combined = (res.stdout + "\n" + res.stderr).lower()
        assert res.returncode != 0
        assert "unrecognized arguments" not in combined, (
            f"CLI rejected valid arguments on {subcmd}: {res.stderr}"
        )
        assert "notimplementederror" not in combined, (
            f"{subcmd[0]} hit NotImplementedError instead of refusing live :8000: {res.stderr}"
        )
        assert any(
            tok in combined for tok in ("forbidden", "live", "isolation", "refus", "port")
        ), f"Expected live-port isolation error for {subcmd}, got:\n{res.stdout}\n{res.stderr}"

    camp_db_dir = tmp_path / "refuse_live_db"
    camp_db_dir.mkdir(parents=True, exist_ok=True)
    safe_unused_port = alloc_qa_free_port()
    (camp_db_dir / "campaign.json").write_text(
        json.dumps(
            {
                "campaign_id": "qa-live-refuse-db",
                "base_sha": base_sha,
                "lane": "local_deterministic",
                "target_url": f"http://127.0.0.1:{safe_unused_port}",
                "status": "active",
                "output_dir": str(camp_db_dir),
            }
        ),
        encoding="utf-8",
    )
    live_db_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_db_dir), "--cases", "CB-00"],
        env_overrides={"GROKBOT_DB_PATH": str(_REPO_ROOT / "var" / "controlbot.sqlite3")},
    )
    live_db_combined = (live_db_res.stdout + "\n" + live_db_res.stderr).lower()
    assert live_db_res.returncode != 0
    assert "unrecognized arguments" not in live_db_combined
    assert "notimplementederror" not in live_db_combined
    assert "connection refused" not in live_db_combined
    assert any(
        tok in live_db_combined
        for tok in (
            "isolation",
            "forbidden",
            "live",
            "var/controlbot",
            "controlbot.sqlite3",
            "boundary",
        )
    ), (
        f"Expected live-DB isolation error, got:\n{live_db_res.stdout}\n{live_db_res.stderr}"
    )


@pytest.mark.qa_megaplan
def test_megaplan_resume_preserves_attempt_counters_leases_and_cursors(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #29, #39: `resume` preserves non-zero attempts, leases, and log offsets."""
    camp_dir = tmp_path / "resume_preserve"
    assert qa_cli_runner.run(
        ["baseline", "--target-url", qa_env.base_url, "--output-dir", str(camp_dir)]
    ).returncode == 0

    camp_json = camp_dir / "campaign.json"
    if camp_json.is_file():
        state = json.loads(camp_json.read_text(encoding="utf-8"))
    else:
        base_data = json.loads((camp_dir / "baseline.json").read_text(encoding="utf-8"))
        state = {
            "campaign_id": base_data["campaign_id"],
            "base_sha": base_data["repo_sha"],
            "output_dir": str(camp_dir),
            "attempts": {"item-preserve-1": 1},
            "active_leases": {"item-preserve-1": "lease-gen-3"},
        }
    state["attempts"] = {"item-preserve-1": 1}
    state["active_leases"] = {"item-preserve-1": "lease-gen-3"}
    camp_json.write_text(json.dumps(state), encoding="utf-8")

    cursors_path = camp_dir / "log_cursors.json"
    cursors_path.write_text(json.dumps({"failures.jsonl": {"offset": 512}}), encoding="utf-8")

    res = qa_cli_runner.run(["resume", "--campaign-dir", str(camp_dir)])
    assert res.returncode == 0, f"resume failed: {res.stderr}\n{res.stdout}"
    after = json.loads(camp_json.read_text(encoding="utf-8"))
    assert after["attempts"]["item-preserve-1"] >= 1
    assert json.loads(cursors_path.read_text(encoding="utf-8"))["failures.jsonl"]["offset"] >= 512


@pytest.mark.qa_megaplan
def test_megaplan_rollback_restores_last_accepted_sha(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #38, #39: `rollback` restores last_accepted_sha and marks candidate rolled_back."""
    rb_repo = tmp_path / "rb_repo"
    base_sha = _init_git_repo(rb_repo)
    subprocess.run(
        ["git", "branch", "qa/autopilot"],
        cwd=str(rb_repo),
        check=True,
        capture_output=True,
    )
    candidate_sha = _create_candidate_branch(
        rb_repo,
        "qa/rb",
        filename="feature.txt",
        content="candidate change\n",
    )
    assert candidate_sha != base_sha
    subprocess.run(
        ["git", "checkout", "-B", "qa/autopilot", candidate_sha],
        cwd=str(rb_repo),
        check=True,
        capture_output=True,
    )
    assert _git_head_sha(rb_repo) == candidate_sha

    camp_dir = tmp_path / "rb_camp"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"

    camp_json_path = camp_dir / "campaign.json"
    camp_state = json.loads(camp_json_path.read_text(encoding="utf-8"))
    camp_state["base_sha"] = base_sha
    camp_state["last_accepted_sha"] = base_sha
    camp_state["qa_branch"] = "qa/autopilot"
    camp_json_path.write_text(json.dumps(camp_state, indent=2), encoding="utf-8")

    cand_id = "cand-rb-001"
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    cand_path = camp_dir / "candidates" / f"{cand_id}.json"
    cand_path.write_text(
        json.dumps(
            {
                "candidate_id": cand_id,
                "item_id": "item-rb-001",
                "campaign_id": camp_state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": candidate_sha,
                "branch_name": "qa/rb",
                "rerun_command": f"{sys.executable} -c 'assert True'",
                "baseline_passed": False,
                "candidate_passed": True,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "pro",
                "status": "accepted_qa",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    res = qa_cli_runner.run(
        [
            "rollback",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            cand_id,
            "--repo-root",
            str(rb_repo),
        ],
        cwd=rb_repo,
    )
    combined = (res.stdout + "\n" + res.stderr).lower()
    assert "notimplementederror" not in combined
    assert res.returncode == 0, f"rollback failed: {res.stderr}\n{res.stdout}"
    manifest = json.loads(cand_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "rolled_back"
    state_after = json.loads(camp_json_path.read_text(encoding="utf-8"))
    assert state_after["last_accepted_sha"] == base_sha
    assert _git_head_sha(rb_repo) == base_sha


@pytest.mark.qa_megaplan
def test_megaplan_repair_rejects_more_than_two_parallel_repairers(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #36, #41: `repair --max-parallel 3` is rejected (max 2 parallel repairers)."""
    camp_dir = tmp_path / "max_parallel_camp"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"
    res = qa_cli_runner.run(
        ["repair", "--campaign-dir", str(camp_dir), "--max-parallel", "3"]
    )
    combined = (res.stdout + "\n" + res.stderr).lower()
    assert res.returncode != 0
    assert "notimplementederror" not in combined
    assert "unrecognized arguments" not in combined
    assert "validationerror" not in combined
    assert "extra inputs are not permitted" not in combined
    assert "extra_forbidden" not in combined
    assert any(
        tok in combined
        for tok in ("parallel", "max_parallel", "max-parallel", "<= 2", "at most 2", "exceed")
    ), f"Expected parallel repairer limit error, got:\n{res.stdout}\n{res.stderr}"


@pytest.mark.qa_megaplan
def test_megaplan_accept_rejects_self_audit_same_author_and_auditor_model(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #40, #41: `accept` rejects candidate where auditor_model == author_model."""
    sa_repo = tmp_path / "self_audit_repo"
    base_sha = _init_git_repo(sa_repo)
    subprocess.run(
        ["git", "branch", "qa/autopilot"],
        cwd=str(sa_repo),
        check=True,
        capture_output=True,
    )
    candidate_sha = _create_candidate_branch(
        sa_repo,
        "qa/self-audit",
        filename="self_audit_fix.txt",
        content="self audit candidate\n",
    )
    assert candidate_sha != base_sha
    subprocess.run(
        ["git", "checkout", "qa/autopilot"],
        cwd=str(sa_repo),
        check=True,
        capture_output=True,
    )

    camp_dir = tmp_path / "self_audit_camp"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"

    camp_json_path = camp_dir / "campaign.json"
    camp_state = json.loads(camp_json_path.read_text(encoding="utf-8"))
    camp_state["base_sha"] = base_sha
    camp_state["last_accepted_sha"] = base_sha
    camp_state["qa_branch"] = "qa/autopilot"
    camp_json_path.write_text(json.dumps(camp_state, indent=2), encoding="utf-8")

    cand_id = "cand-self-audit"
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    (camp_dir / "candidates" / f"{cand_id}.json").write_text(
        json.dumps(
            {
                "candidate_id": cand_id,
                "item_id": "item-self-audit",
                "campaign_id": camp_state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": candidate_sha,
                "branch_name": "qa/self-audit",
                "rerun_command": f"{sys.executable} -c 'assert True'",
                "baseline_passed": False,
                "candidate_passed": True,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "hydrogen",
                "status": "candidate_verified",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    res = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            cand_id,
            "--repo-root",
            str(sa_repo),
        ],
        cwd=sa_repo,
    )
    combined = (res.stdout + "\n" + res.stderr).lower()
    assert res.returncode != 0
    assert "notimplementederror" not in combined
    assert "unrecognized arguments" not in combined
    assert "validationerror" not in combined
    assert "extra inputs are not permitted" not in combined
    assert "extra_forbidden" not in combined
    assert any(
        tok in combined
        for tok in (
            "self-audit",
            "self_audit",
            "self audit",
            "distinct",
            "author_model",
            "auditor_model",
            "same model",
            "auditor",
        )
    ), f"Expected self-audit rejection message, got:\n{res.stdout}\n{res.stderr}"
