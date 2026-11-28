"""Tier 1 happy-path E2E tests for Discovery, UX Telemetry, QA Queue & 7-Step Self-Repair."""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import socketserver
import sqlite3
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from src.factory.db import FactoryStore
from src.factory.engine import EvalResult, FactoryEngine, rollback_from_manifest
from src.factory.models import (
    BacklogItem,
    CandidatePatch,
    CycleBudget,
    FactoryStatus,
    compute_proposal_hash,
)
from src.factory.policy import IsolationGuard, PolicyGuard
from tests.e2e_qa.conftest import StrictBrowserPage
from tests.e2e_qa.fixtures import build_cb_valve_104_catalog
from tests.e2e_qa.helpers import (
    FORBIDDEN_PORTS,
    IsolatedQAEnv,
    QACliRunner,
    UxTimingResult,
    alloc_qa_free_port,
    assert_no_secret_leak,
    measure_ttfp_and_completion,
)

pytestmark = pytest.mark.qa_tier1

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TEN_MIB = 10 * 1024 * 1024
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_ALLOWED_QA_STATES = frozenset(
    {
        "observed",
        "reproduced",
        "flaky",
        "in_repair",
        "candidate_verified",
        "accepted_qa",
        "blocked",
        "parked",
    }
)
_MOCK_UX_AGY_SCRIPT = """#!/usr/bin/env python3
import json
import sys
import time

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

cid = "33333333-4444-5555-6666-777777777777"
reply = "Mock UX ack: response ready"
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({
        "event": "init",
        "conversation_id": cid,
        "init": {"model": "gemini-4-carbon-low"},
    }), flush=True)
    time.sleep(0.35)
    print(json.dumps({
        "event": "step_update",
        "step_update": {
            "step_type": "agent_response",
            "text_delta": reply,
        },
    }), flush=True)
    print(json.dumps({
        "event": "result",
        "result": {
            "status": "SUCCESS",
            "conversation_id": cid,
            "response": reply,
        },
    }), flush=True)
    sys.exit(0)

print(json.dumps({"status": "SUCCESS", "conversation_id": cid, "response": reply}))
"""


def _git_head_sha(repo_dir: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _init_isolated_repo(
    repo_dir: Path,
    *,
    files: dict[str, str] | None = None,
    with_qa_branch: bool = False,
) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True
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
    seed_files = files or {
        "app_mod.py": "def add(a: int, b: int) -> int:\n    return a - b\n",
        "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
    }
    for rel_path, content in seed_files.items():
        target = repo_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial isolated repo"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    if with_qa_branch:
        subprocess.run(
            ["git", "branch", "qa/autopilot"],
            cwd=str(repo_dir),
            check=True,
            capture_output=True,
        )
    return _git_head_sha(repo_dir)


def _create_candidate_branch(
    repo_dir: Path,
    branch_name: str,
    *,
    files: dict[str, str],
    base_ref: str = "main",
) -> str:
    subprocess.run(
        ["git", "checkout", "-B", branch_name, base_ref],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    for rel_path, content in files.items():
        target = repo_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", f"candidate {branch_name}"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return _git_head_sha(repo_dir)


_MOCK_REPAIRER_AGY_BODY = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
if args and args[0] == "models":
    print("mock-repairer-model  Mock Repairer")
    sys.exit(0)

prompt = " ".join(args)
cwd = Path.cwd()
replacements = {
    "mod_p1.py": "def val() -> int:\\n    return 1\\n",
    "mod_p2.py": "def val() -> int:\\n    return 2\\n",
    "mod_p3.py": "def val() -> int:\\n    return 3\\n",
    "mod_a.py": "def fn_a() -> str:\\n    return 'ok_a'\\n",
    "mod_b.py": "def fn_b() -> str:\\n    return 'ok_b'\\n",
}
patched = []
for fname, content in replacements.items():
    target = cwd / fname
    if target.is_file() and (
        fname in prompt
        or fname.replace(".py", "") in prompt
        or (fname == "mod_p1.py" and "test_p1" in prompt)
        or (fname == "mod_p2.py" and "test_p2" in prompt)
        or (fname == "mod_p3.py" and "test_p3" in prompt)
        or (fname == "mod_a.py" and "test_a" in prompt)
        or (fname == "mod_b.py" and "test_b" in prompt)
    ):
        target.write_text(content, encoding="utf-8")
        patched.append(fname)

reply = json.dumps({"patched_files": patched, "status": "ok"})
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({"event": "init", "conversation_id": "mock-repair-cid"}), flush=True)
    print(
        json.dumps(
            {
                "event": "result",
                "result": {
                    "status": "SUCCESS",
                    "conversation_id": "mock-repair-cid",
                    "response": reply,
                },
            }
        ),
        flush=True,
    )
else:
    print(
        json.dumps(
            {
                "status": "SUCCESS",
                "conversation_id": "mock-repair-cid",
                "response": reply,
            }
        )
    )
"""


@contextlib.contextmanager
def _mock_repairer_env(fake_home: Path | None) -> Iterator[dict[str, str]]:
    """Provide a test-scoped mock OpenAI-compatible HTTP server & mock `agy` CLI."""
    assert fake_home is not None
    bin_dir = fake_home / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    agy_path = bin_dir / "agy"
    agy_path.write_text(_MOCK_REPAIRER_AGY_BODY, encoding="utf-8")
    os.chmod(agy_path, 0o755)

    port = alloc_qa_free_port()

    class _MockLlmHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            payload = json.dumps({"data": [{"id": "mock-repairer-model"}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
            patch_map = {
                "mod_p1": ("mod_p1.py", "def val() -> int:\n    return 1\n"),
                "mod_p2": ("mod_p2.py", "def val() -> int:\n    return 2\n"),
                "mod_p3": ("mod_p3.py", "def val() -> int:\n    return 3\n"),
                "mod_a": ("mod_a.py", "def fn_a() -> str:\n    return 'ok_a'\n"),
                "mod_b": ("mod_b.py", "def fn_b() -> str:\n    return 'ok_b'\n"),
            }
            files_out: dict[str, str] = {}
            for key, (fname, content) in patch_map.items():
                if key in raw_body or fname in raw_body:
                    files_out[fname] = content
            resp_obj = {
                "id": "chatcmpl-mock-qa",
                "object": "chat.completion",
                "model": "mock-repairer-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps({"files": files_out}),
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
            payload = json.dumps(resp_obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    httpd = _ThreadingServer(("127.0.0.1", port), _MockLlmHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "GROKBOT_LLM_BASE_URL": f"http://127.0.0.1:{port}",
            "GROKBOT_LLM_API_KEY": "mock-qa-api-key",
            "GROKBOT_LLM_MODEL_ID": "mock-repairer-model",
        }
    finally:
        httpd.shutdown()
        httpd.server_close()
        with contextlib.suppress(OSError):
            agy_path.unlink()


def _seed_jsonl_to_size(path: Path, min_bytes: int) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    pad = "x" * 900
    lines: list[str] = []
    written = 0
    idx = 0
    while written < min_bytes:
        idx += 1
        line = json.dumps({"id": f"seed_{idx}", "source": "seed", "pad": pad}) + "\n"
        lines.append(line)
        written += len(line.encode("utf-8"))
    path.write_text("".join(lines), encoding="utf-8")
    return path.stat().st_size


def _query_sqlite_tables(camp_dir: Path, table_name: str) -> list[dict[str, Any]]:
    rows_out: list[dict[str, Any]] = []
    for db_file in sorted(camp_dir.glob("**/*.sqlite3")):
        with sqlite3.connect(db_file) as conn:
            conn.row_factory = sqlite3.Row
            tables = {
                str(r[0])
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if table_name not in tables:
                continue
            for raw_row in conn.execute(f"SELECT * FROM {table_name}").fetchall():
                row_dict = dict(raw_row)
                payload_raw = row_dict.get("payload_json")
                if isinstance(payload_raw, str) and payload_raw.strip():
                    parsed_payload = json.loads(payload_raw)
                    if isinstance(parsed_payload, dict):
                        row_dict = {**row_dict, **parsed_payload}
                for key, val in list(row_dict.items()):
                    if isinstance(val, str) and val.startswith(("[", "{")):
                        with contextlib.suppress(json.JSONDecodeError):
                            row_dict[key] = json.loads(val)
                rows_out.append(row_dict)
    return rows_out


def _run_baseline_to_dir(
    qa_cli_runner: QACliRunner,
    qa_env: IsolatedQAEnv,
    camp_dir: Path,
    *,
    lane: str = "local_deterministic",
    log_dir: Path | None = None,
    skip_browser: bool = True,
) -> dict[str, Any]:
    cmd = [
        "baseline",
        "--target-url",
        qa_env.base_url,
        "--output-dir",
        str(camp_dir),
        "--lane",
        lane,
        "--no-build-frontend",
    ]
    if skip_browser:
        cmd.append("--skip-browser")
    if log_dir is not None:
        cmd.extend(["--log-dir", str(log_dir)])
    res = qa_cli_runner.run(cmd)
    assert res.returncode == 0, f"baseline failed: {res.stderr}\n{res.stdout}"
    return dict(json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# qa_existing Tier 1 tests (MUST ALL PASS immediately)
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
async def test_existing_diagnostics_middleware_correlation_and_client_error_api(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Feature #27: X-Request-Id correlates browser client-error, backend 404 & JSONL logs."""
    page = strict_browser_page.page
    await page.goto(qa_env.url("/app"), wait_until="domcontentloaded")
    await page.locator('textarea[aria-label="Message composer"]').wait_for(
        state="visible", timeout=15000
    )

    canary_fe = "CANARY_FE_TOKEN_7711"
    beacon_result: dict[str, Any] = await page.evaluate(
        """async (secret) => {
            const infoRes = await fetch('/api/system/info');
            const reqId = infoRes.headers.get('x-request-id') || '';
            const postRes = await fetch('/api/v1/diagnostics/client-error', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    kind: 'qa_ui_probe',
                    message: 'Correlated UI probe failure',
                    url: `/app?token=${secret}`,
                    page_url: `/app?cap_token=${secret}`,
                    method: 'GET',
                    status_code: 500,
                    request_id: reqId,
                    extra: {source_panel: 'settings'}
                })
            });
            const body = await postRes.json();
            return {reqId, status: postRes.status, body};
        }""",
        canary_fe,
    )
    assert beacon_result["status"] == 202
    assert beacon_result["body"]["accepted"] is True
    assert str(beacon_result["body"]["id"]).startswith("fail_")
    fe_req_id = str(beacon_result["reqId"])
    assert fe_req_id.startswith("req_")

    strict_browser_page.assert_clean()

    canary_be = "CANARY_BE_TOKEN_8822"
    with qa_env.client() as client:
        miss = client.get(f"/api/v1/threads/nonexistent_qa_corr_thread/messages?token={canary_be}")
        assert miss.status_code == 404
        be_req_id = miss.headers.get("X-Request-Id", "")
        assert be_req_id.startswith("req_")

        summary_resp = client.get("/api/v1/diagnostics/summary")
        assert summary_resp.status_code == 200
        summary = summary_resp.json()
        assert summary["total_failures"] >= 2
        assert summary["failures_by_source"].get("frontend", 0) >= 1
        assert summary["failures_by_source"].get("backend_http", 0) >= 1

        fe_corr = client.get(f"/api/v1/diagnostics/failures?request_id={fe_req_id}")
        assert fe_corr.status_code == 200
        fe_items = fe_corr.json()["failures"]
        assert any(
            item["source"] == "frontend" and item["request_id"] == fe_req_id
            for item in fe_items
        )

        be_corr = client.get(f"/api/v1/diagnostics/failures?request_id={be_req_id}")
        assert be_corr.status_code == 200
        be_items = be_corr.json()["failures"]
        assert any(
            item["source"] == "backend_http" and item["request_id"] == be_req_id
            for item in be_items
        )

        reqs_resp = client.get("/api/v1/diagnostics/requests?limit=50")
        assert reqs_resp.status_code == 200
        reqs_data = reqs_resp.json()
        assert any(r.get("request_id") == be_req_id for r in reqs_data["requests"])

        assert_no_secret_leak(summary, secrets=(qa_env.cap_secret, canary_fe, canary_be))
        assert_no_secret_leak(fe_corr.json(), secrets=(qa_env.cap_secret, canary_fe, canary_be))
        assert_no_secret_leak(be_corr.json(), secrets=(qa_env.cap_secret, canary_fe, canary_be))
        assert_no_secret_leak(reqs_data, secrets=(qa_env.cap_secret, canary_fe, canary_be))

    for fname in ("failures.jsonl", "requests.jsonl", "frontend_errors.jsonl"):
        fpath = qa_env.logs_dir / fname
        assert fpath.is_file(), f"Missing diagnostics log file: {fpath}"
        parsed_lines = [
            json.loads(line) for line in fpath.read_text(encoding="utf-8").splitlines() if line
        ]
        assert parsed_lines
        assert_no_secret_leak(parsed_lines, secrets=(qa_env.cap_secret, canary_fe, canary_be))


@pytest.mark.qa_existing
def test_existing_diagnostics_redaction_and_10mib_rotation_identity(
    qa_env: IsolatedQAEnv,
) -> None:
    """Feature #27: 10 MiB failures.jsonl rotates to .1 preserving inode, with strict redaction."""
    failures_path = qa_env.logs_dir / "failures.jsonl"
    rotated_path = qa_env.logs_dir / "failures.jsonl.1"
    seeded_bytes = _seed_jsonl_to_size(failures_path, _TEN_MIB)
    assert seeded_bytes >= _TEN_MIB
    assert not rotated_path.exists()

    old_stat = failures_path.stat()
    old_identity = (old_stat.st_dev, old_stat.st_ino)

    canary_bearer = "CANARY_BEARER_9090"
    canary_cookie = "CANARY_COOKIE_9191"
    canary_qs = "CANARY_QS_9292"
    canary_cap = "CANARY_CAP_9393"
    canary_clip = "CANARY_CLIPBOARD_SECRET_9494"

    with qa_env.client() as client:
        resp = client.post(
            "/api/v1/diagnostics/client-error",
            headers={
                "Authorization": f"Bearer {canary_bearer}",
                "Cookie": f"session_id={canary_cookie}",
            },
            json={
                "kind": "rotation_probe",
                "message": f"Probe with Authorization: Bearer {canary_bearer}",
                "url": f"/app?token={canary_qs}&cap_token={canary_cap}",
                "request_id": "req_rotate10mib",
                "extra": {
                    "Authorization": f"Bearer {canary_bearer}",
                    "Cookie": f"session={canary_cookie}",
                    "credential": canary_clip,
                },
            },
        )
        assert resp.status_code == 202
        fail_id = resp.json()["id"]

        diag_resp = client.get("/api/v1/diagnostics/failures?request_id=req_rotate10mib")
        assert diag_resp.status_code == 200
        assert_no_secret_leak(
            diag_resp.json(),
            secrets=(canary_bearer, canary_cookie, canary_qs, canary_cap, canary_clip),
        )

    assert rotated_path.is_file(), "Expected failures.jsonl.1 after crossing 10 MiB threshold"
    rot_stat = rotated_path.stat()
    assert (rot_stat.st_dev, rot_stat.st_ino) == old_identity

    assert failures_path.is_file()
    new_stat = failures_path.stat()
    new_identity = (new_stat.st_dev, new_stat.st_ino)
    assert new_identity != old_identity, "Active failures.jsonl must rotate to a new inode"
    assert new_stat.st_size < _TEN_MIB

    active_records = [
        json.loads(line)
        for line in failures_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        rec.get("id") == fail_id and rec.get("request_id") == "req_rotate10mib"
        for rec in active_records
    )
    assert_no_secret_leak(
        active_records,
        secrets=(canary_bearer, canary_cookie, canary_qs, canary_cap, canary_clip),
    )


@pytest.mark.qa_existing
async def test_existing_live_app_ux_modal_focus_escape_restore_and_origin_display(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Feature #26: Modal focus trap, Escape focus restore, and System & Tasks origin display."""
    page = strict_browser_page.page
    await page.goto(qa_env.url("/app"), wait_until="domcontentloaded")
    await page.locator('textarea[aria-label="Message composer"]').wait_for(
        state="visible", timeout=15000
    )

    settings_btn = page.locator('aside button[aria-label="Settings"]')
    await settings_btn.focus()
    await settings_btn.click()

    dialog = page.locator('[role="dialog"][aria-modal="true"]')
    await dialog.wait_for(state="visible", timeout=10000)
    await page.wait_for_function(
        """() => {
            const d = document.querySelector('[role="dialog"][aria-modal="true"]');
            return Boolean(d && d.contains(document.activeElement));
        }"""
    )

    await dialog.get_by_role("button", name="System & Tasks").click()
    await dialog.get_by_text("runtime_mode", exact=True).wait_for(state="visible")
    await dialog.get_by_text("live_runtime", exact=True).wait_for(state="visible")
    await dialog.get_by_text("backend_mode", exact=True).wait_for(state="visible")
    await dialog.get_by_text("emulated", exact=True).wait_for(state="visible")

    await page.keyboard.press("Escape")
    await dialog.wait_for(state="hidden")
    await page.wait_for_function(
        """() => {
            const btn = document.querySelector('aside button[aria-label="Settings"]');
            return Boolean(btn && document.activeElement === btn);
        }"""
    )

    shortcuts_btn = page.locator('aside button[aria-label="Keyboard shortcuts"]')
    await shortcuts_btn.focus()
    await shortcuts_btn.click()
    await dialog.wait_for(state="visible", timeout=10000)
    await page.wait_for_function(
        """() => {
            const d = document.querySelector('[role="dialog"][aria-modal="true"]');
            return Boolean(d && d.contains(document.activeElement));
        }"""
    )
    await page.keyboard.press("Escape")
    await dialog.wait_for(state="hidden")
    await page.wait_for_function(
        """() => {
            const btn = document.querySelector('aside button[aria-label="Keyboard shortcuts"]');
            return Boolean(btn && document.activeElement === btn);
        }"""
    )

    # Close active SSE connection cleanly before restarting server
    await page.goto("about:blank")
    qa_env.restart(
        extra_env={
            "GROKBOT_LLM_BASE_URL": "http://127.0.0.1:11434",
            "GROKBOT_LLM_MODEL_ID": "qwen2.5-lab",
        }
    )
    await page.goto(qa_env.url("/app"), wait_until="domcontentloaded")
    await page.locator('textarea[aria-label="Message composer"]').wait_for(
        state="visible", timeout=15000
    )
    await page.locator('aside button[aria-label="Settings"]').click()
    await dialog.wait_for(state="visible", timeout=10000)
    await dialog.get_by_role("button", name="System & Tasks").click()
    await dialog.get_by_text("backend_mode", exact=True).wait_for(state="visible")
    await dialog.get_by_text("local_http", exact=True).wait_for(state="visible")
    await dialog.get_by_text("llm_origin", exact=True).wait_for(state="visible")
    await dialog.get_by_text("http://127.0.0.1:11434", exact=True).wait_for(state="visible")
    await dialog.get_by_text("qwen2.5-lab", exact=True).wait_for(state="visible")
    await page.keyboard.press("Escape")
    await dialog.wait_for(state="hidden")

    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
async def test_existing_live_app_ttfp_progress_stop_button_and_png_checkpoint(
    qa_env_factory: Callable[..., IsolatedQAEnv],
    strict_browser_page: StrictBrowserPage,
    tmp_path: Path,
) -> None:
    """Feature #26: Measure TTFP, visible Working/Stop affordances, and save PNG checkpoint."""
    env = qa_env_factory(mock_agy_script=_MOCK_UX_AGY_SCRIPT, name="ux_ttfp")
    page = strict_browser_page.page
    await page.goto(env.url("/app"), wait_until="networkidle")
    composer = page.locator('textarea[aria-label="Message composer"]')
    await composer.wait_for(state="visible", timeout=15000)

    stop_seen = False

    async def _send_and_wait() -> bool:
        await composer.fill("Measure TTFP UX check")
        await composer.press("Enter")
        await page.get_by_text("Mock UX ack: response ready").wait_for(
            state="visible", timeout=15000
        )
        return True

    async def _probe_progress() -> bool:
        nonlocal stop_seen
        stop_btn = page.locator('button[aria-label="Stop current generation"]')
        stop_visible = await stop_btn.is_visible()
        if stop_visible:
            stop_seen = True
        working_visible = await page.get_by_text("Working…").is_visible()
        return stop_visible or working_visible

    done, timing = await measure_ttfp_and_completion(
        _send_and_wait,
        actions_to_reach=2,
        ttfp_probe=_probe_progress,
        cancel_available=True,
        poll_interval_s=0.02,
    )
    assert done is True
    assert isinstance(timing, UxTimingResult)
    assert timing.actions_to_reach == 2
    assert timing.ttfp_ms is not None
    assert 0.0 <= timing.ttfp_ms < timing.completion_ms
    assert stop_seen is True

    shot_path = tmp_path / "ux_checkpoint.png"
    await page.screenshot(path=str(shot_path), full_page=True)
    assert shot_path.is_file()
    raw_png = shot_path.read_bytes()
    assert raw_png[:8] == _PNG_MAGIC
    assert len(raw_png) > 1024

    strict_browser_page.assert_clean()


@pytest.mark.qa_existing
def test_existing_factory_store_engine_lifecycle_and_rollback_manifest(
    tmp_path: Path,
) -> None:
    """Features #29, #30: FactoryStore/Engine promotes isolated fix and rollback restores HEAD."""
    repo_dir = tmp_path / "factory_repo"
    base_sha = _init_isolated_repo(repo_dir)

    store_db = tmp_path / "factory_state" / "factory.sqlite3"
    store = FactoryStore(
        store_db,
        forbidden_db_paths=[_REPO_ROOT / "var" / "controlbot.sqlite3"],
    )
    IsolationGuard.validate_paths(store.db_path, repo_dir)
    policy_guard = PolicyGuard()
    budget = CycleBudget(budget_id="qa-t1", max_cycles=2, max_attempts=2)
    engine = FactoryEngine(
        repo_dir,
        store,
        policy_guard=policy_guard,
        budget=budget,
        owner="qa-t1-worker",
        base_branch="main",
        artifacts_dir=tmp_path / "artifacts",
    )

    store.add_backlog_item(
        BacklogItem(
            item_id="item-add-bug",
            title="Fix add() subtraction bug",
            priority=1,
            hypothesis="Replace subtraction with addition in app_mod.add.",
            target_metric="failing_assertions",
            baseline_repro_cmd="pytest -q",
            max_attempts=2,
        )
    )

    files_to_modify = {
        "app_mod.py": "def add(a: int, b: int) -> int:\n    return a + b\n",
    }
    repro_path = "test_repro_add.py"
    repro_content = (
        "from app_mod import add\n\n"
        "def test_add_sums_numbers() -> None:\n"
        "    assert add(2, 3) == 5\n"
    )
    proposal_hash = compute_proposal_hash(
        item_id="item-add-bug",
        target_metric="failing_assertions",
        files_to_modify=files_to_modify,
        repro_test_path=repro_path,
        repro_test_content=repro_content,
    )
    candidate = CandidatePatch(
        candidate_id="cand-add-001",
        item_id="item-add-bug",
        branch_name="qa/cand-add-001",
        hypothesis="Fix subtraction typo in app_mod.add",
        target_metric="failing_assertions",
        proposal_hash=proposal_hash,
        files_to_modify=files_to_modify,
        repro_test_path=repro_path,
        repro_test_content=repro_content,
    )

    def _eval_add(path: Path) -> EvalResult:
        proc = subprocess.run(
            [sys.executable, "-B", "-c", "from app_mod import add; assert add(2, 3) == 5"],
            cwd=str(path),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            return EvalResult(passed=True, metric=0.0, detail="add(2, 3) == 5")
        return EvalResult(passed=False, metric=1.0, detail="add(2, 3) failed")

    result = engine.run_candidate_cycle(candidate, evaluator=_eval_add)
    assert result.status == FactoryStatus.PROMOTED
    assert result.base_commit == base_sha
    assert result.candidate_commit is not None and result.candidate_commit != base_sha
    assert _git_head_sha(repo_dir) == result.candidate_commit
    assert result.manifest_path is not None

    manifest_path = Path(result.manifest_path)
    assert manifest_path.is_file()
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    for key in (
        "previous_commit",
        "new_commit",
        "uv_lock_hash",
        "config_hash",
        "restore_command",
    ):
        assert manifest_data.get(key), f"Missing RollbackManifest key {key!r}"
    assert manifest_data["previous_commit"] == base_sha
    assert manifest_data["new_commit"] == result.candidate_commit

    rb_out = rollback_from_manifest(manifest_path, repo_path=repo_dir, store=store)
    assert rb_out["ok"] is True
    assert rb_out["status"] == "rolled_back"
    assert _git_head_sha(repo_dir) == base_sha


# ---------------------------------------------------------------------------
# qa_megaplan Tier 1 tests (opaque-box M2/M3 contracts)
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_megaplan_qa2_discover_controls_coverage_json_and_single_fire(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #11, #34: `scan --discover-controls` emits valid coverage.json and fires once."""
    camp_dir = tmp_path / "camp_discover"
    _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=False)

    with qa_env.client() as client:
        bots_before = len(client.get("/api/v1/bots").json()["bots"])

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-00",
            "--discover-controls",
        ]
    )
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    cov_path = camp_dir / "coverage.json"
    assert cov_path.is_file(), f"Missing {cov_path}"
    cov = json.loads(cov_path.read_text(encoding="utf-8"))
    for key in (
        "campaign_id",
        "generated_at",
        "repo_sha",
        "total_controls",
        "covered_count",
        "blocked_count",
        "pending_count",
        "out_of_scope_count",
        "by_module",
        "items",
    ):
        assert key in cov, f"Missing CoverageReport key {key!r}"

    assert cov["total_controls"] > 0
    assert cov["covered_count"] > 0
    assert (
        cov["covered_count"]
        + cov["blocked_count"]
        + cov["pending_count"]
        + cov["out_of_scope_count"]
        == cov["total_controls"]
    )

    items = cov["items"]
    assert isinstance(items, list) and len(items) == cov["total_controls"]
    for item in items:
        for field_name in (
            "control_id",
            "module",
            "route",
            "role",
            "accessible_name",
            "selector",
            "initial_state",
            "post_state",
            "precondition",
            "observable_effect",
            "keyboard_accessible",
            "repeatable",
            "test_case_id",
            "coverage_status",
            "blocked_reason",
        ):
            assert field_name in item, f"Missing ControlInventoryItem field {field_name!r}"

    with qa_env.client() as client:
        bots_after = len(client.get("/api/v1/bots").json()["bots"])
    assert bots_after - bots_before <= 1, (
        f"Mutable discovery created duplicate resources: before={bots_before}, after={bots_after}"
    )


@pytest.mark.qa_megaplan
def test_megaplan_differential_grok_bot_card_five_dimensions_main_test_only(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #7, #34: Differential behavior cards strictly use main/test & 5 dimensions."""
    camp_dir = tmp_path / "camp_ref_cards"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, lane="external_reference", skip_browser=True
    )

    scan_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-01"]
    )
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    card_files = sorted(
        [*camp_dir.glob("reference_cards/*.json"), *camp_dir.glob("**/ref_*.json")]
    )
    assert card_files, f"Expected ReferenceBehaviorCard JSON artifact(s) under {camp_dir}"

    for cf in card_files:
        card = json.loads(cf.read_text(encoding="utf-8"))
        assert card.get("status") in {"observed", "documented", "REF_UNAVAILABLE"}
        if card.get("source") == "grok_bot_app" and card["status"] != "REF_UNAVAILABLE":
            assert card.get("bot_used") in {"main", "test"}
        else:
            assert card.get("bot_used") in {"main", "test", None}
        assert card.get("expected_controlbot_contract")
        if card["status"] != "REF_UNAVAILABLE":
            for dim in (
                "discoverability",
                "state_transition",
                "independent_verification",
                "missing_data_or_permission",
                "efficiency_notes",
            ):
                assert str(card.get(dim, "")).strip(), f"Empty dimension {dim!r} in {cf}"


@pytest.mark.qa_megaplan
def test_megaplan_truth_source_dynamic_valve_fixture_beats_wrong_reference(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #8: ControlBot synthetic fixture truth overrides an inaccurate external reference."""
    catalog = build_cb_valve_104_catalog()
    assert catalog.active_record.price != catalog.prior_record.price

    camp_dir = tmp_path / "camp_truth_source"
    _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)

    (camp_dir / "fixtures").mkdir(parents=True, exist_ok=True)
    (camp_dir / "fixtures" / "cb_valve_104.json").write_text(
        json.dumps(
            {
                "fixture_version": catalog.fixture_version,
                "sku": catalog.sku,
                "active_price": str(catalog.active_record.price),
                "prior_price": str(catalog.prior_record.price),
                "currency": catalog.active_record.currency,
                "source_url": catalog.active_record.source_url,
                "records": catalog.to_json_records(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (camp_dir / "reference_cards").mkdir(parents=True, exist_ok=True)
    (camp_dir / "reference_cards" / "ref-cb02-main.json").write_text(
        json.dumps(
            {
                "card_id": "ref-cb02-main",
                "case_id": "CB-02",
                "source": "grok_bot_app",
                "status": "observed",
                "bot_used": "main",
                "discoverability": "Single query prompt",
                "state_transition": "Returns answer",
                "independent_verification": f"Stale ref claimed {catalog.prior_record.price}",
                "missing_data_or_permission": "None",
                "efficiency_notes": "1 turn",
                "expected_controlbot_contract": (
                    f"Must match synthetic fixture {catalog.active_record.currency} "
                    f"{catalog.active_record.price} at {catalog.active_record.source_url}"
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    scan_res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-02"]
    )
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    runs = _query_sqlite_tables(camp_dir, "qa_run_records")
    if not runs:
        run_files = sorted([*camp_dir.glob("**/run_*.json"), *camp_dir.glob("**/runs.jsonl")])
        assert run_files, f"No RunRecord persisted under {camp_dir}"
        raw = run_files[0].read_text(encoding="utf-8")
        runs = [json.loads(line) for line in raw.splitlines() if line.strip()]

    cb02_runs = [r for r in runs if r.get("case_id") == "CB-02"]
    assert cb02_runs, f"Missing CB-02 RunRecord in {runs!r}"
    latest = cb02_runs[-1]
    assert latest["passed"] is True
    assert latest.get("fixture_version") == catalog.fixture_version, (
        f"Expected dynamic fixture_version {catalog.fixture_version!r}, "
        f"got {latest.get('fixture_version')!r}"
    )
    assertions_map = latest.get("assertions") or {}
    assert isinstance(assertions_map, dict) and assertions_map, (
        f"Expected non-empty assertions in CB-02 RunRecord: {latest!r}"
    )
    assert all(bool(v) for v in assertions_map.values()), (
        f"Expected all CB-02 assertions True: {assertions_map!r}"
    )
    evidence_parts: list[str] = [json.dumps(latest)]
    for apath_raw in latest.get("artifact_paths", []):
        apath = Path(str(apath_raw))
        if not apath.is_absolute():
            apath = camp_dir / apath
        if apath.is_file():
            evidence_parts.append(apath.read_text(encoding="utf-8", errors="replace"))
    evidence_blob = "\n".join(evidence_parts)
    assert (
        str(catalog.active_record.price) in evidence_blob
        or catalog.active_record.source_url in evidence_blob
    ), "CB-02 RunRecord/artifacts must validate dynamic active_record price or source_url"
    assert not latest.get("error_summary")
    assert_no_secret_leak(cb02_runs, secrets=(qa_env.cap_secret,))


@pytest.mark.qa_megaplan
def test_megaplan_unified_run_record_schema_and_run_id_correlation(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #27, #34: Unified RunRecord persists §5.1 fields and links run_id/request_ids."""
    camp_dir = tmp_path / "camp_run_record"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-00",
            "--ingest-logs",
        ]
    )
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    records = _query_sqlite_tables(camp_dir, "qa_run_records")
    if not records:
        run_files = sorted([*camp_dir.glob("**/run_*.json"), *camp_dir.glob("**/runs.jsonl")])
        assert run_files, f"No qa_run_records or runs.jsonl found in {camp_dir}"
        raw = run_files[0].read_text(encoding="utf-8")
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]

    assert records
    rec = records[-1]
    for field_name in (
        "campaign_id",
        "case_id",
        "run_id",
        "base_sha",
        "candidate_sha",
        "build_hash",
        "profile",
        "backend_mode",
        "runtime_mode",
        "model_id",
        "fixture_version",
        "browser",
        "duration_ms",
        "assertions",
        "artifact_paths",
        "request_ids",
    ):
        assert field_name in rec, f"Missing RunRecord field {field_name!r}"
    assert str(rec["run_id"]).strip()
    assert isinstance(rec["duration_ms"], (int, float)) and rec["duration_ms"] >= 0.0
    assert isinstance(rec["assertions"], dict)
    assert isinstance(rec["artifact_paths"], list)


@pytest.mark.qa_megaplan
def test_megaplan_ux_telemetry_ttfp_affordances_and_screenshots(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #26: Control discovery & UX telemetry emit valid PNG checkpoint screenshots."""
    camp_dir = tmp_path / "camp_ux_shots"
    _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=False)

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-00",
            "--discover-controls",
        ]
    )
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    png_files = sorted(camp_dir.glob("**/*.png"))
    assert png_files, f"Expected UX checkpoint PNG screenshot(s) under {camp_dir}"
    for png in png_files:
        data = png.read_bytes()
        assert data[:8] == _PNG_MAGIC, f"Invalid PNG header in {png}"
        assert len(data) > 512


@pytest.mark.qa_megaplan
def test_megaplan_qa_queue_dedup_key_and_factory_store_link(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #28: Repeated failures deduplicate into 1 qa_items row linked to FactoryStore."""
    camp_dir = tmp_path / "camp_dedup"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )

    with qa_env.client() as client:
        r1 = client.get("/api/v1/threads/missing_dedup_target/messages")
        assert r1.status_code == 404

    scan1 = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--ingest-logs"]
    )
    assert scan1.returncode == 0, f"scan 1 failed: {scan1.stderr}\n{scan1.stdout}"

    with qa_env.client() as client:
        r2 = client.get("/api/v1/threads/missing_dedup_target/messages")
        assert r2.status_code == 404

    scan2 = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--ingest-logs"]
    )
    assert scan2.returncode == 0, f"scan 2 failed: {scan2.stderr}\n{scan2.stdout}"

    qa_items = _query_sqlite_tables(camp_dir, "qa_items")
    assert qa_items, f"Expected rows in qa_items SQLite table under {camp_dir}"
    matching = [
        item
        for item in qa_items
        if "missing_dedup_target" in str(item.get("dedup_key", ""))
        or "missing_dedup_target" in str(item.get("normalized_signature", ""))
        or "404" in str(item.get("normalized_signature", ""))
    ]
    assert len(matching) == 1, f"Expected exactly 1 deduplicated item, got {matching!r}"
    item = matching[0]
    assert item["dedup_key"] == (
        f"{item['case_id']}:{item['subsystem']}:{item['normalized_signature']}"
    )
    assert int(item["occurrence_count"]) >= 2
    assert len(item["run_ids"]) >= 2
    assert item["first_seen_sha"]
    assert item["last_seen_sha"]
    assert item.get("factory_item_id"), (
        "Expected factory_item_id linking qa_items -> factory_backlog"
    )

    backlog_rows = _query_sqlite_tables(camp_dir, "factory_backlog")
    assert any(b.get("item_id") == item["factory_item_id"] for b in backlog_rows)


@pytest.mark.qa_megaplan
def test_megaplan_eight_state_lifecycle_and_p0_to_p3_triage_order(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #28, #31: 8-state lifecycle supported and P1 prioritized before P2/P3."""
    repo_dir = tmp_path / "prio_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "mod_p1.py": "def val() -> int:\n    return 0\n",
            "mod_p2.py": "def val() -> int:\n    return 0\n",
            "mod_p3.py": "def val() -> int:\n    return 0\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_p1.py": "from mod_p1 import val\ndef test_p1() -> None:\n    assert val() == 1\n",
            "test_p2.py": "from mod_p2 import val\ndef test_p2() -> None:\n    assert val() == 2\n",
            "test_p3.py": "from mod_p3 import val\ndef test_p3() -> None:\n    assert val() == 3\n",
        },
        with_qa_branch=True,
    )

    camp_dir = tmp_path / "camp_prio"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    seeded = [
        {
            "item_id": "item-p3",
            "dedup_key": "CB-00:ui:p3_cosmetic",
            "case_id": "CB-00",
            "subsystem": "ui",
            "normalized_signature": "p3_cosmetic",
            "severity": "P3",
            "state": "reproduced",
            "summary": "Low priority P3 issue",
            "first_seen_sha": base_sha,
            "last_seen_sha": base_sha,
            "environment_lane": "local_deterministic",
            "repro_command": f"{sys.executable} -m pytest -q test_p3.py",
        },
        {
            "item_id": "item-p2",
            "dedup_key": "CB-00:api:p2_degraded",
            "case_id": "CB-00",
            "subsystem": "api",
            "normalized_signature": "p2_degraded",
            "severity": "P2",
            "state": "reproduced",
            "summary": "Medium priority P2 issue",
            "first_seen_sha": base_sha,
            "last_seen_sha": base_sha,
            "environment_lane": "local_deterministic",
            "repro_command": f"{sys.executable} -m pytest -q test_p2.py",
        },
        {
            "item_id": "item-p1",
            "dedup_key": "CB-00:core:p1_blocker",
            "case_id": "CB-00",
            "subsystem": "core",
            "normalized_signature": "p1_blocker",
            "severity": "P1",
            "state": "reproduced",
            "summary": "High priority P1 blocker",
            "first_seen_sha": base_sha,
            "last_seen_sha": base_sha,
            "environment_lane": "local_deterministic",
            "repro_command": f"{sys.executable} -m pytest -q test_p1.py",
        },
    ]
    (camp_dir / "failures.jsonl").write_text(
        "\n".join(json.dumps(x) for x in seeded) + "\n", encoding="utf-8"
    )

    with _mock_repairer_env(qa_cli_runner.fake_home) as repairer_env:
        rep_res = qa_cli_runner.run(
            [
                "repair",
                "--campaign-dir",
                str(camp_dir),
                "--max-parallel",
                "1",
                "--max-attempts",
                "1",
                "--repo-root",
                str(repo_dir),
            ],
            env_overrides=repairer_env,
            cwd=repo_dir,
        )
    assert rep_res.returncode == 0, f"repair failed: {rep_res.stderr}\n{rep_res.stdout}"

    items_after = _query_sqlite_tables(camp_dir, "qa_items")
    if not items_after:
        items_after = [
            json.loads(line)
            for line in (camp_dir / "failures.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    by_id = {it["item_id"]: it for it in items_after}
    for it in items_after:
        assert it["state"] in _ALLOWED_QA_STATES
    assert by_id["item-p1"]["attempts"] >= 1 or by_id["item-p1"]["state"] != "reproduced"

    cand_files = list((camp_dir / "candidates").glob("*.json"))
    if cand_files:
        manifests = [json.loads(cf.read_text(encoding="utf-8")) for cf in cand_files]
        manifests.sort(key=lambda m: str(m.get("created_at") or ""))
        assert manifests[0]["item_id"] == "item-p1", (
            f"Expected P1 item prioritized first by created_at, got {manifests[0]['item_id']!r}"
        )
    else:
        factory_cands = _query_sqlite_tables(camp_dir, "factory_candidates")
        assert factory_cands, "Expected CandidateManifest JSON or factory_candidates rows"
        factory_cands.sort(key=lambda c: str(c.get("created_at") or ""))
        assert "p1" in str(factory_cands[0].get("item_id", "")), (
            f"Expected P1 item prioritized first, got {factory_cands[0]!r}"
        )


@pytest.mark.qa_megaplan
def test_megaplan_seven_step_repair_and_compiled_react_evaluator(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #30, #35: 7-step evaluation verifies candidate on isolated checkout/DB + React."""
    repo_dir = tmp_path / "repair_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "calc.py": "def double(n: int) -> int:\n    return n\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_repro_double.py": (
                "from calc import double\n\n"
                "def test_double() -> None:\n"
                "    assert double(4) == 8\n"
            ),
            "frontend/dist/index.html": (
                "<!doctype html><html><head><title>Grok Bot — ControlBot Studio</title>"
                "<script src='/assets/app.js'></script>"
                "<link rel='stylesheet' href='/assets/app.css'/></head><body></body></html>\n"
            ),
            "frontend/dist/assets/app.js": "console.log('react');\n",
            "frontend/dist/assets/app.css": "body{}\n",
        },
        with_qa_branch=True,
    )
    cand_id = "cand-double-01"
    cand_branch = f"qa/{cand_id}"
    cand_sha = _create_candidate_branch(
        repo_dir,
        cand_branch,
        files={"calc.py": "def double(n: int) -> int:\n    return n * 2\n"},
        base_ref=base_sha,
    )
    assert cand_sha != base_sha
    subprocess.run(
        ["git", "checkout", "qa/autopilot"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )

    camp_dir = tmp_path / "camp_7step"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    repro_cmd = f"{sys.executable} -m pytest -q test_repro_double.py"
    (camp_dir / "failures.jsonl").write_text(
        json.dumps(
            {
                "item_id": "item-double-01",
                "dedup_key": "CB-00:calc:double_bug",
                "case_id": "CB-00",
                "subsystem": "calc",
                "normalized_signature": "double_bug",
                "severity": "P1",
                "state": "reproduced",
                "summary": "calc.double returns n instead of n*2",
                "first_seen_sha": base_sha,
                "last_seen_sha": base_sha,
                "environment_lane": "local_deterministic",
                "repro_command": repro_cmd,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    cand_path = camp_dir / "candidates" / f"{cand_id}.json"
    cand_path.write_text(
        json.dumps(
            {
                "candidate_id": cand_id,
                "item_id": "item-double-01",
                "campaign_id": state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": cand_sha,
                "branch_name": cand_branch,
                "files_modified": ["calc.py"],
                "repro_test_path": "test_repro_double.py",
                "rerun_command": repro_cmd,
                "baseline_passed": False,
                "candidate_passed": False,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "pro",
                "status": "pending",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    reeval_res = qa_cli_runner.run(
        [
            "reevaluate",
            "--campaign-dir",
            str(camp_dir),
            "--item",
            "item-double-01",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    assert reeval_res.returncode == 0, (
        f"reevaluate failed: {reeval_res.stderr}\n{reeval_res.stdout}"
    )

    accept_res = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            cand_id,
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    assert accept_res.returncode == 0, f"accept failed: {accept_res.stderr}\n{accept_res.stdout}"

    cand = json.loads(cand_path.read_text(encoding="utf-8"))
    assert cand["baseline_passed"] is False
    assert cand["candidate_passed"] is True
    assert cand["audit_passed"] is True
    assert cand.get("author_model") and cand.get("auditor_model")
    assert cand["author_model"] != cand["auditor_model"]
    assert cand["status"] == "accepted_qa"
    assert cand.get("build_hash"), "Expected compiled-React / build_hash verification"

    state_after = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert state_after.get("last_accepted_sha") == cand_sha

    # Live repo & :8000 untouched
    assert not (camp_dir / "target_url_8000").exists()
    for port in FORBIDDEN_PORTS:
        assert f":{port}" not in str(state.get("target_url") or "")


@pytest.mark.qa_megaplan
def test_megaplan_qa3_candidate_manifest_emits_diff_repro_and_rerun_cmd(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #35: QA-3 CandidateManifest includes diff_stat, files_modified & rerun_command."""
    repo_dir = tmp_path / "qa3_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "calc.py": "def mul(a: int, b: int) -> int:\n    return a + b\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_repro_mul.py": (
                "from calc import mul\n\n"
                "def test_mul() -> None:\n"
                "    assert mul(3, 4) == 12\n"
            ),
        },
        with_qa_branch=True,
    )
    cand_id = "cand-qa3-mul"
    cand_branch = f"qa/{cand_id}"
    cand_sha = _create_candidate_branch(
        repo_dir,
        cand_branch,
        files={"calc.py": "def mul(a: int, b: int) -> int:\n    return a * b\n"},
        base_ref=base_sha,
    )
    assert cand_sha != base_sha
    subprocess.run(
        ["git", "checkout", "qa/autopilot"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )

    camp_dir = tmp_path / "camp_qa3"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    repro_cmd = f"{sys.executable} -m pytest -q test_repro_mul.py"
    (camp_dir / "failures.jsonl").write_text(
        json.dumps(
            {
                "item_id": "item-qa3-mul",
                "dedup_key": "CB-00:calc:mul_bug",
                "case_id": "CB-00",
                "subsystem": "calc",
                "normalized_signature": "mul_bug",
                "severity": "P1",
                "state": "reproduced",
                "summary": "calc.mul performs addition",
                "first_seen_sha": base_sha,
                "last_seen_sha": base_sha,
                "environment_lane": "local_deterministic",
                "repro_command": repro_cmd,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    cand_path = camp_dir / "candidates" / f"{cand_id}.json"
    cand_path.write_text(
        json.dumps(
            {
                "candidate_id": cand_id,
                "item_id": "item-qa3-mul",
                "campaign_id": state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": cand_sha,
                "branch_name": cand_branch,
                "repro_test_path": "test_repro_mul.py",
                "rerun_command": repro_cmd,
                "baseline_passed": False,
                "candidate_passed": False,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "pro",
                "status": "pending",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # Confirm baseline fails before evaluation/promotion
    base_check = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "test_repro_mul.py"],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    assert base_check.returncode != 0

    reeval_res = qa_cli_runner.run(
        [
            "reevaluate",
            "--campaign-dir",
            str(camp_dir),
            "--item",
            "item-qa3-mul",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    assert reeval_res.returncode == 0, (
        f"reevaluate failed: {reeval_res.stderr}\n{reeval_res.stdout}"
    )

    accept_res = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            cand_id,
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    assert accept_res.returncode == 0, f"accept failed: {accept_res.stderr}\n{accept_res.stdout}"

    cand = json.loads(cand_path.read_text(encoding="utf-8"))
    assert str(cand.get("diff_stat", "")).strip()
    assert cand.get("files_modified") == ["calc.py"]
    assert cand.get("repro_test_path") == "test_repro_mul.py"
    assert str(cand.get("rerun_command", "")).strip()
    assert cand.get("rollback_manifest_path")
    assert Path(str(cand["rollback_manifest_path"])).is_file()
    assert cand["baseline_passed"] is False
    assert cand["candidate_passed"] is True
    assert cand["audit_passed"] is True
    assert cand["status"] == "accepted_qa"

    # Promoted qa/autopilot passes repro_command
    subprocess.run(
        ["git", "checkout", "qa/autopilot"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    promoted_check = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "test_repro_mul.py"],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    assert promoted_check.returncode == 0, promoted_check.stdout + promoted_check.stderr


@pytest.mark.qa_megaplan
def test_megaplan_qa4_max_two_disjoint_parallel_repairers_and_integrator(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #36, #41: Max-2 disjoint parallel repairers + single serialized QA integrator."""
    repo_dir = tmp_path / "qa4_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "mod_a.py": "def fn_a() -> str:\n    return 'broken_a'\n",
            "mod_b.py": "def fn_b() -> str:\n    return 'broken_b'\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_a.py": (
                "from mod_a import fn_a\ndef test_a() -> None:\n    assert fn_a() == 'ok_a'\n"
            ),
            "test_b.py": (
                "from mod_b import fn_b\ndef test_b() -> None:\n    assert fn_b() == 'ok_b'\n"
            ),
        },
        with_qa_branch=True,
    )
    cand_a_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-qa4-a",
        files={"mod_a.py": "def fn_a() -> str:\n    return 'ok_a'\n"},
        base_ref=base_sha,
    )
    cand_b_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-qa4-b",
        files={"mod_b.py": "def fn_b() -> str:\n    return 'ok_b'\n"},
        base_ref=base_sha,
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )

    camp_dir = tmp_path / "camp_qa4"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    (camp_dir / "failures.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "item_id": "item-qa4-a",
                        "dedup_key": "CB-05:mod_a:broken_a",
                        "case_id": "CB-05",
                        "subsystem": "mod_a",
                        "normalized_signature": "broken_a",
                        "severity": "P1",
                        "state": "reproduced",
                        "summary": "mod_a returns broken_a",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "repro_command": f"{sys.executable} -m pytest -q test_a.py",
                    }
                ),
                json.dumps(
                    {
                        "item_id": "item-qa4-b",
                        "dedup_key": "CB-06:mod_b:broken_b",
                        "case_id": "CB-06",
                        "subsystem": "mod_b",
                        "normalized_signature": "broken_b",
                        "severity": "P1",
                        "state": "reproduced",
                        "summary": "mod_b returns broken_b",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "repro_command": f"{sys.executable} -m pytest -q test_b.py",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    for cid, iid, branch, csha, fmod, rtest in (
        ("cand-qa4-a", "item-qa4-a", "qa/cand-qa4-a", cand_a_sha, ["mod_a.py"], "test_a.py"),
        ("cand-qa4-b", "item-qa4-b", "qa/cand-qa4-b", cand_b_sha, ["mod_b.py"], "test_b.py"),
    ):
        (camp_dir / "candidates" / f"{cid}.json").write_text(
            json.dumps(
                {
                    "candidate_id": cid,
                    "item_id": iid,
                    "campaign_id": state["campaign_id"],
                    "base_sha": base_sha,
                    "candidate_sha": csha,
                    "branch_name": branch,
                    "files_modified": fmod,
                    "repro_test_path": rtest,
                    "rerun_command": f"{sys.executable} -m pytest -q {rtest}",
                    "baseline_passed": False,
                    "candidate_passed": False,
                    "audit_passed": True,
                    "author_model": "hydrogen",
                    "auditor_model": "pro",
                    "status": "pending",
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    with _mock_repairer_env(qa_cli_runner.fake_home) as repairer_env:
        rep_res = qa_cli_runner.run(
            [
                "repair",
                "--campaign-dir",
                str(camp_dir),
                "--max-parallel",
                "2",
                "--max-attempts",
                "2",
                "--repo-root",
                str(repo_dir),
            ],
            env_overrides=repairer_env,
            cwd=repo_dir,
        )
    assert rep_res.returncode == 0, f"repair failed: {rep_res.stderr}\n{rep_res.stdout}"

    # Serialize any candidate_verified manifests onto qa/autopilot via single integrator accept
    for cf in sorted((camp_dir / "candidates").glob("*.json")):
        manifest = json.loads(cf.read_text(encoding="utf-8"))
        if manifest.get("status") == "candidate_verified":
            acc_res = qa_cli_runner.run(
                [
                    "accept",
                    "--campaign-dir",
                    str(camp_dir),
                    "--candidate",
                    manifest["candidate_id"],
                    "--repo-root",
                    str(repo_dir),
                ],
                cwd=repo_dir,
            )
            assert acc_res.returncode == 0, f"accept failed: {acc_res.stderr}\n{acc_res.stdout}"

    state_after = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert int(state_after["max_parallel_repairers"]) <= 2
    assert state_after.get("last_accepted_sha") and state_after["last_accepted_sha"] != base_sha

    accepted_manifests = [
        json.loads(cf.read_text(encoding="utf-8"))
        for cf in sorted((camp_dir / "candidates").glob("*.json"))
        if json.loads(cf.read_text(encoding="utf-8")).get("status") == "accepted_qa"
    ]
    assert len(accepted_manifests) >= 2, (
        f"Expected >= 2 accepted_qa manifests, got {accepted_manifests!r}"
    )
    accepted_items = {m["item_id"] for m in accepted_manifests}
    assert {"item-qa4-a", "item-qa4-b"}.issubset(accepted_items)
    branches = {m["branch_name"] for m in accepted_manifests}
    assert len(branches) >= 2
    file_sets = [set(m.get("files_modified", [])) for m in accepted_manifests[:2]]
    assert file_sets[0].isdisjoint(file_sets[1]), (
        f"Parallel repairers must touch disjoint files: {file_sets}"
    )

    # Combined QA branch passes full pytest gate
    subprocess.run(
        ["git", "checkout", state_after["qa_branch"]],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    combined_pytest = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    assert combined_pytest.returncode == 0, combined_pytest.stdout + combined_pytest.stderr


@pytest.mark.qa_megaplan
def test_megaplan_crash_safe_resume_preserves_cursors_attempts_and_leases(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #29: Crash-safe resume preserves non-zero log cursors, attempt counts, and leases."""
    camp_dir = tmp_path / "camp_resume"
    state = _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )
    state["attempts"] = {"item-resume-1": 1}
    state["active_leases"] = {"item-resume-1": "lease-gen-2"}
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    cursors_path = camp_dir / "log_cursors.json"
    cursors_path.write_text(
        json.dumps({"failures.jsonl": {"offset": 256, "inode": [1, 100]}}, indent=2),
        encoding="utf-8",
    )

    res = qa_cli_runner.run(["resume", "--campaign-dir", str(camp_dir)])
    assert res.returncode == 0, f"resume failed: {res.stderr}\n{res.stdout}"

    after = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert after["attempts"]["item-resume-1"] >= 1
    assert after["active_leases"].get("item-resume-1")
    cursor_rows = _query_sqlite_tables(camp_dir, "qa_log_cursors")
    if cursor_rows:
        assert any(int(r.get("byte_offset", 0)) >= 256 for r in cursor_rows)
    else:
        after_cursors = json.loads(cursors_path.read_text(encoding="utf-8"))
        assert after_cursors["failures.jsonl"]["offset"] >= 256


@pytest.mark.qa_megaplan
def test_megaplan_log_ingestion_correlates_run_and_request_ids(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #27, #34: Single scan run_id correlates RunRecord, request_ids & ingested logs."""
    with qa_env.client() as client:
        resp = client.get("/api/v1/threads/missing_corr_scan_item/messages?token=CANARY_LOG_INGEST")
        assert resp.status_code == 404
        req_id = resp.headers.get("X-Request-Id", "")
        assert req_id.startswith("req_")

    camp_dir = tmp_path / "camp_corr_ingest"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-00",
            "--ingest-logs",
        ]
    )
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    runs = _query_sqlite_tables(camp_dir, "qa_run_records")
    qa_items = _query_sqlite_tables(camp_dir, "qa_items")
    assert runs or qa_items, f"Expected ingested RunRecord or QAFailureItem under {camp_dir}"

    if runs:
        run_ids = {r["run_id"] for r in runs}
        assert any(req_id in r.get("request_ids", []) for r in runs)
        if qa_items:
            assert any(set(it.get("run_ids", [])) & run_ids for it in qa_items)

    assert_no_secret_leak(runs, secrets=("CANARY_LOG_INGEST", qa_env.cap_secret))
    assert_no_secret_leak(qa_items, secrets=("CANARY_LOG_INGEST", qa_env.cap_secret))
