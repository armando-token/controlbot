"""Tier 2 boundary, negative, and corner-case E2E tests for Discovery, Queue & Self-Repair."""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import re
import socketserver
import sqlite3
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from src.factory.db import FactoryStore
from src.factory.errors import FactoryLeaseError, PolicyImmutabilityError
from src.factory.models import (
    BacklogItem,
    CandidatePatch,
    CandidateRunRecord,
    CycleBudget,
    LessonRecord,
    compute_proposal_hash,
)
from src.factory.policy import PolicyGuard
from tests.e2e_qa.conftest import StrictBrowserPage
from tests.e2e_qa.fixtures import (
    build_cb_valve_104_catalog,
    build_grok_bot_reference_card,
)
from tests.e2e_qa.helpers import (
    CliResult,
    IsolatedQAEnv,
    QACliRunner,
    alloc_qa_free_port,
    assert_no_secret_leak,
)

pytestmark = pytest.mark.qa_tier2

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TEN_MIB = 10 * 1024 * 1024


def _assert_no_cli_false_pass(res: CliResult) -> str:
    """Ensure CLI failure is a genuine domain rejection, never stub/argparse/schema noise."""
    combined = (res.stdout + "\n" + res.stderr).lower()
    assert "notimplementederror" not in combined, (
        f"Hit unimplemented M2+ stub instead of domain validation:\n{res.stdout}\n{res.stderr}"
    )
    assert "unrecognized arguments" not in combined, (
        f"CLI rejected valid arguments:\n{res.stdout}\n{res.stderr}"
    )
    assert "validationerror" not in combined, (
        f"Unexpected Pydantic ValidationError:\n{res.stdout}\n{res.stderr}"
    )
    assert "extra inputs are not permitted" not in combined, (
        f"Unexpected extra_forbidden schema error:\n{res.stdout}\n{res.stderr}"
    )
    assert "extra_forbidden" not in combined, (
        f"Unexpected extra_forbidden schema error:\n{res.stdout}\n{res.stderr}"
    )
    return combined


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
        "app_mod.py": "def fn() -> int:\n    return 1\n",
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


def _seed_jsonl_to_size(path: Path, target_bytes: int) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    written = 0
    idx = 0
    while written < target_bytes:
        idx += 1
        base_obj = {"id": f"seed_{idx}", "source": "seed", "pad": ""}
        base_len = len((json.dumps(base_obj) + "\n").encode("utf-8"))
        remaining = target_bytes - written
        pad_len = min(900, max(0, remaining - base_len))
        obj = {"id": f"seed_{idx}", "source": "seed", "pad": "x" * pad_len}
        line = json.dumps(obj) + "\n"
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
# qa_existing Tier 2 boundary tests (MUST ALL PASS immediately)
# ---------------------------------------------------------------------------


@pytest.mark.qa_existing
def test_existing_diagnostics_secret_redaction_boundary_across_channels_and_vault(
    qa_env: IsolatedQAEnv,
) -> None:
    """Feature #27: Secrets across query/headers/camelCase/vault never leak into logs or API."""
    canaries = (
        "CANARY_QS_TOKEN_101",
        "CANARY_QS_CAP_102",
        "CANARY_QS_APIKEY_103",
        "CANARY_HEADER_BEARER_104",
        "CANARY_HEADER_COOKIE_105",
        "CANARY_HEADER_XAPIKEY_106",
        "CANARY_CAMEL_ACCESS_107",
        "CANARY_CAMEL_CLIENT_108",
        "CANARY_VAULT_SECRET_109",
    )
    (
        c_qs_tok,
        c_qs_cap,
        c_qs_key,
        c_bearer,
        c_cookie,
        c_xapi,
        c_camel_acc,
        c_camel_sec,
        c_vault,
    ) = canaries

    with qa_env.client() as client:
        r_miss = client.get(
            f"/api/v1/threads/missing_secret_boundary/messages"
            f"?token={c_qs_tok}&cap_token={c_qs_cap}&api_key={c_qs_key}",
            headers={
                "Authorization": f"Bearer {c_bearer}",
                "Cookie": f"sid={c_cookie}",
                "x-api-key": c_xapi,
            },
        )
        assert r_miss.status_code == 404

        r_fe = client.post(
            "/api/v1/diagnostics/client-error",
            json={
                "kind": "secret_boundary",
                "message": f"Err Bearer {c_bearer} ?token={c_qs_tok}",
                "url": f"/app?token={c_qs_tok}&cap_token={c_qs_cap}&api_key={c_qs_key}",
                "page_url": f"/app?api_key={c_qs_key}",
                "request_id": "req_secboundary",
                "extra": {
                    "accessToken": c_camel_acc,
                    "clientSecret": c_camel_sec,
                    "x-api-key": c_xapi,
                    "Cookie": c_cookie,
                },
            },
        )
        assert r_fe.status_code == 202

        r_vault = client.post(
            "/api/v1/vault/secure-fill",
            json={"secret_value": c_vault},
        )
        assert r_vault.status_code >= 400
        vault_req_id = r_vault.headers.get("X-Request-Id", "")
        assert vault_req_id.startswith("req_")

        for endpoint in (
            "/api/v1/diagnostics/summary",
            "/api/v1/diagnostics/failures?limit=100",
            "/api/v1/diagnostics/requests?limit=100",
        ):
            api_data = client.get(endpoint).json()
            assert_no_secret_leak(api_data, secrets=(*canaries, qa_env.cap_secret))

        vault_failures = client.get(
            f"/api/v1/diagnostics/failures?request_id={vault_req_id}"
        ).json()["failures"]
        assert vault_failures
        assert vault_failures[0]["detail"]["response_preview"] == "[vault response body omitted]"

    for fname in ("failures.jsonl", "requests.jsonl", "frontend_errors.jsonl"):
        fpath = qa_env.logs_dir / fname
        assert fpath.is_file()
        raw_text = fpath.read_text(encoding="utf-8")
        for secret in canaries:
            assert secret not in raw_text, f"Secret {secret} leaked in {fname}"
        rows = [json.loads(line) for line in raw_text.splitlines() if line.strip()]
        assert_no_secret_leak(rows, secrets=(*canaries, qa_env.cap_secret))


@pytest.mark.qa_existing
def test_existing_diagnostics_10mib_rotation_below_and_crossing_threshold(
    qa_env: IsolatedQAEnv,
) -> None:
    """Feature #27: <10 MiB appends in-place; >=10 MiB rotates via .1 preserving inode."""
    failures_path = qa_env.logs_dir / "failures.jsonl"
    rotated_path = qa_env.logs_dir / "failures.jsonl.1"

    below_size = _seed_jsonl_to_size(failures_path, _TEN_MIB - 1500)
    assert below_size < _TEN_MIB
    assert not rotated_path.exists()

    stat_below = failures_path.stat()
    id_below = (stat_below.st_dev, stat_below.st_ino)

    with qa_env.client() as client:
        r1 = client.get("/api/v1/threads/below_threshold_probe/messages")
        assert r1.status_code == 404
        req_below = r1.headers.get("X-Request-Id", "")
        below_diag = client.get(f"/api/v1/diagnostics/failures?request_id={req_below}").json()
        assert below_diag["count"] >= 1

    assert not rotated_path.exists(), "Must NOT rotate before 10 MiB threshold"
    stat_after_below = failures_path.stat()
    assert (stat_after_below.st_dev, stat_after_below.st_ino) == id_below
    assert stat_after_below.st_size > below_size

    # Cross the 10 MiB threshold
    crossed_size = _seed_jsonl_to_size(failures_path, _TEN_MIB)
    assert crossed_size >= _TEN_MIB
    stat_at_thresh = failures_path.stat()
    id_at_thresh = (stat_at_thresh.st_dev, stat_at_thresh.st_ino)

    with qa_env.client() as client:
        r2 = client.get("/api/v1/threads/cross_threshold_probe/messages")
        assert r2.status_code == 404
        req_cross = r2.headers.get("X-Request-Id", "")
        cross_diag = client.get(f"/api/v1/diagnostics/failures?request_id={req_cross}").json()
        assert cross_diag["count"] >= 1

    assert rotated_path.is_file(), "Expected .1 file after crossing 10 MiB threshold"
    rot_stat = rotated_path.stat()
    assert (rot_stat.st_dev, rot_stat.st_ino) == id_at_thresh

    active_stat = failures_path.stat()
    assert (active_stat.st_dev, active_stat.st_ino) != id_at_thresh
    active_lines = [
        json.loads(line)
        for line in failures_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(item.get("request_id") == req_cross for item in active_lines)
    assert req_below  # appended cleanly pre-rotation
    # Last line of rotated file is valid JSON
    rot_tail = rotated_path.read_text(encoding="utf-8").splitlines()[-1]
    assert isinstance(json.loads(rot_tail), dict)


@pytest.mark.qa_existing
def test_existing_policy_guard_blocks_protected_paths_symlinks_and_bypass(
    tmp_path: Path,
) -> None:
    """Feature #30: PolicyGuard rejects all protected prefixes, symlinks, and bypass patches."""
    guard = PolicyGuard()
    protected_samples = (
        "tests/e2e/test_protected.py",
        "tests/acceptance/test_core.py",
        "src/contracts/common.py",
        "src/factory/policy.py",
        "src/factory/errors.py",
        "src/engine/tool_registry.py",
        "src/engine/budget.py",
        "src/engine/loop_detector.py",
        "src/engine/coordinator.py",
        "src/custom_guard_helper.py",
        "src/oracle_override.py",
    )
    for bad_path in protected_samples:
        with pytest.raises(PolicyImmutabilityError) as exc_info:
            guard.check_candidate_paths([bad_path])
        assert "POLICY_IMMUTABILITY_VIOLATION" in str(exc_info.value)

    repo_dir = tmp_path / "policy_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "src/factory/policy.py": "# protected placeholder\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
        },
    )
    from src.factory.engine import FactoryEngine

    store = FactoryStore(tmp_path / "policy_factory.sqlite3")
    engine = FactoryEngine(
        repo_dir,
        store,
        policy_guard=guard,
        budget=CycleBudget(budget_id="pol-test", max_cycles=2, max_attempts=2),
        owner="qa-policy-worker",
        base_branch="main",
    )
    store.add_backlog_item(
        BacklogItem(
            item_id="item-pol-tamper",
            title="Attempt protected policy edit",
            priority=1,
            hypothesis="Illegal tamper test",
            target_metric="failures",
            baseline_repro_cmd="pytest -q",
        )
    )
    files_to_modify = {"src/factory/policy.py": "# tampered!\n"}
    patch = CandidatePatch(
        candidate_id="cand-pol-tamper",
        item_id="item-pol-tamper",
        branch_name="qa/cand-pol-tamper",
        hypothesis="Illegal edit of policy.py",
        target_metric="failures",
        proposal_hash=compute_proposal_hash(
            item_id="item-pol-tamper",
            target_metric="failures",
            files_to_modify=files_to_modify,
        ),
        files_to_modify=files_to_modify,
    )
    with pytest.raises(PolicyImmutabilityError) as engine_exc:
        engine.run_candidate_cycle(patch)
    assert "POLICY_IMMUTABILITY_VIOLATION" in str(engine_exc.value)
    assert _git_head_sha(repo_dir) == base_sha

    # Symlink escape check via PolicyGuard.check_repo_symlinks & inspect_git_diff
    outside_target = tmp_path / "outside_secret_target.py"
    outside_target.write_text("SECRET = 1\n", encoding="utf-8")
    escape_link = repo_dir / "escape_link.py"
    escape_link.symlink_to(outside_target)
    with pytest.raises(PolicyImmutabilityError) as sym_exc:
        guard.check_repo_symlinks(repo_dir, ["escape_link.py"])
    assert "POLICY_IMMUTABILITY_VIOLATION" in str(sym_exc.value)

    subprocess.run(
        ["git", "checkout", "-B", "qa/cand-symlink", "main"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "add", "escape_link.py"], cwd=str(repo_dir), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "commit", "-m", "add symlink escape"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    with pytest.raises(PolicyImmutabilityError) as sym_diff_exc:
        guard.inspect_git_diff(repo_dir, "main", "qa/cand-symlink")
    assert "POLICY_IMMUTABILITY_VIOLATION" in str(sym_diff_exc.value)

    subprocess.run(["git", "checkout", "main"], cwd=str(repo_dir), check=True, capture_output=True)

    # Policy bypass pattern check via PolicyGuard.inspect_git_diff & FactoryEngine
    bypass_files = {"app_mod.py": "PolicyGuard = None\ndef ok() -> bool:\n    return True\n"}
    _create_candidate_branch(repo_dir, "qa/cand-bypass", files=bypass_files, base_ref="main")
    subprocess.run(["git", "checkout", "main"], cwd=str(repo_dir), check=True, capture_output=True)
    with pytest.raises(PolicyImmutabilityError) as bypass_diff_exc:
        guard.inspect_git_diff(repo_dir, "main", "qa/cand-bypass")
    assert "POLICY_IMMUTABILITY_VIOLATION" in str(bypass_diff_exc.value)

    bypass_patch = CandidatePatch(
        candidate_id="cand-pol-bypass",
        item_id="item-pol-tamper",
        branch_name="qa/cand-pol-bypass",
        hypothesis="Attempt PolicyGuard bypass in app_mod.py",
        target_metric="failures",
        proposal_hash=compute_proposal_hash(
            item_id="item-pol-tamper",
            target_metric="failures",
            files_to_modify=bypass_files,
        ),
        files_to_modify=bypass_files,
    )
    with pytest.raises(PolicyImmutabilityError) as bypass_eng_exc:
        engine.run_candidate_cycle(bypass_patch)
    assert "POLICY_IMMUTABILITY_VIOLATION" in str(bypass_eng_exc.value)
    assert _git_head_sha(repo_dir) == base_sha


@pytest.mark.qa_existing
def test_existing_factory_store_stale_lease_generation_fencing(tmp_path: Path) -> None:
    """Feature #29: FactoryStore rejects stale lease generation on renew, release, and commit."""
    store = FactoryStore(tmp_path / "lease_fence.sqlite3")
    store.init_db()
    store.ensure_budget(CycleBudget(budget_id="default", max_cycles=3, max_attempts=3))
    store.add_backlog_item(
        BacklogItem(
            item_id="item-lease-1",
            title="Lease fencing item",
            priority=1,
            hypothesis="Verify generation fencing",
            target_metric="failures",
            baseline_repro_cmd="pytest -q",
        )
    )
    lease_gen1 = store.acquire_lease("item-lease-1", "worker-1", ttl_s=60.0)
    assert lease_gen1.generation == 1
    store.release_lease(lease_gen1.lease_id, lease_gen1.generation)

    lease_gen2 = store.acquire_lease("item-lease-1", "worker-2", ttl_s=60.0)
    assert lease_gen2.generation == 2

    with pytest.raises(FactoryLeaseError):
        store.renew_lease(lease_gen1.lease_id, "worker-1", lease_gen1.generation)
    with pytest.raises(FactoryLeaseError):
        store.release_lease(lease_gen1.lease_id, lease_gen1.generation)

    now = datetime.now(UTC)
    rec = CandidateRunRecord(
        run_id="frun-stale",
        candidate_id="cand-stale",
        item_id="item-lease-1",
        branch_name="qa/cand-stale",
        base_commit="abc1234",
        candidate_commit="def5678",
        proposal_hash="h" * 64,
        baseline_passed=False,
        regression_passed=True,
        identity_gate_passed=True,
        policy_passed=True,
        status="PROMOTED",
        reason="stale attempt",
        created_at=now,
    )
    lesson = LessonRecord(
        lesson_id="fles-stale",
        item_id="item-lease-1",
        candidate_id="cand-stale",
        proposal_hash="h" * 64,
        outcome="PROMOTED",
        reason="stale attempt",
        created_at=now,
    )
    with pytest.raises(FactoryLeaseError):
        store.commit_candidate_attempt(lease=lease_gen1, record=rec, lesson=lesson)

    loaded = store.get_backlog_item("item-lease-1")
    assert loaded is not None
    assert loaded.attempts_used == 0


@pytest.mark.qa_existing
def test_existing_grok_bot_scope_rejects_unauthorized_bots_and_allows_ref_unavailable() -> None:
    """Features #7, #8: Grok Bot cards forbid non-main/test bots; REF_UNAVAILABLE never blocks."""
    for forbidden_bot in ("work", "prod", "admin", "custom", "", "main ", "Test"):
        with pytest.raises(ValueError):
            build_grok_bot_reference_card(bot_name=forbidden_bot, case_id="CB-01")

    unavail = build_grok_bot_reference_card(
        bot_name="test",
        case_id="CB-02",
        available=False,
        unavailable_reason="Grok Bot auth session absent in headless lab",
    )
    assert unavail.status == "REF_UNAVAILABLE"
    assert unavail.bot_used == "test"
    assert unavail.unavailable_reason == "Grok Bot auth session absent in headless lab"
    assert "REF_UNAVAILABLE" in unavail.expected_controlbot_contract

    catalog = build_cb_valve_104_catalog()
    assert catalog.active_record.price != catalog.prior_record.price


@pytest.mark.qa_existing
async def test_existing_ux_disabled_controls_state_and_clean_browser(
    qa_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Features #11, #26: Disabled composer & modal submit buttons expose disabled state cleanly."""
    page = strict_browser_page.page
    await page.goto(qa_env.url("/app"), wait_until="domcontentloaded")
    composer = page.locator('textarea[aria-label="Message composer"]')
    await composer.wait_for(state="visible", timeout=15000)

    send_btn = page.locator('button[aria-label="Send message"]')
    assert await send_btn.is_disabled()

    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.locator("button").filter(has_text=re.compile(r"^New bot")).click()
    dialog = page.locator('[role="dialog"][aria-modal="true"]')
    await dialog.wait_for(state="visible")
    create_bot_btn = dialog.get_by_role("button", name="Create bot")
    assert await create_bot_btn.is_disabled()
    await page.keyboard.press("Escape")
    await dialog.wait_for(state="hidden")

    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New group chat").click()
    await dialog.wait_for(state="visible")
    create_group_btn = dialog.get_by_role("button", name="Create group chat")
    assert await create_group_btn.is_disabled()
    await page.keyboard.press("Escape")
    await dialog.wait_for(state="hidden")

    strict_browser_page.assert_clean()


# ---------------------------------------------------------------------------
# qa_megaplan Tier 2 boundary/negative tests (anti-false-pass guarded!)
# ---------------------------------------------------------------------------


@pytest.mark.qa_megaplan
def test_megaplan_coverage_non_covered_states_never_counted_or_pass(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #11, #34: blocked/pending/out_of_scope never increment covered_count or pass."""
    camp_dir = tmp_path / "camp_cov_boundary"
    _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=False)

    res = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--discover-controls"]
    )
    _assert_no_cli_false_pass(res)
    assert res.returncode == 0, f"scan failed: {res.stderr}\n{res.stdout}"

    cov = json.loads((camp_dir / "coverage.json").read_text(encoding="utf-8"))
    items = cov["items"]
    covered = [it for it in items if it["coverage_status"] == "covered"]
    blocked = [it for it in items if it["coverage_status"] == "blocked"]
    pending = [it for it in items if it["coverage_status"] == "pending"]
    oos = [it for it in items if it["coverage_status"] == "out_of_scope"]

    assert cov["covered_count"] == len(covered)
    assert cov["blocked_count"] == len(blocked)
    assert cov["pending_count"] == len(pending)
    assert cov["out_of_scope_count"] == len(oos)
    assert (
        cov["covered_count"]
        + cov["blocked_count"]
        + cov["pending_count"]
        + cov["out_of_scope_count"]
        == cov["total_controls"]
    )
    for non_cov in (*blocked, *pending, *oos):
        assert str(non_cov.get("blocked_reason") or "").strip(), (
            f"Non-covered item {non_cov['control_id']} must explain reason"
        )


@pytest.mark.qa_megaplan
def test_megaplan_silent_disabled_control_without_explanation_fails_discovery(
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #11, #26: Silent no-op button lacking disabled/aria-disabled fails discovery."""
    port = alloc_qa_free_port()
    html_body = (
        "<!doctype html><html lang='en' data-theme='light'><head>"
        "<title>Grok Bot — ControlBot Studio</title>"
        "<link rel='stylesheet' href='/assets/app.css'/>"
        "<script src='/assets/app.js'></script>"
        "</head>"
        "<body><div id='root'>"
        "<textarea aria-label='Message composer'></textarea>"
        "<button id='silent-noop-btn'>Deploy</button>"
        "</div></body></html>"
    )

    class _NoopHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path_only = self.path.split("?", 1)[0]
            if path_only == "/health":
                payload = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path_only == "/api/system/info":
                payload = json.dumps(
                    {
                        "service": "controlbot",
                        "runtime_mode": "live_runtime",
                        "backend_mode": "emulated",
                        "llm_origin": None,
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path_only == "/assets/app.js":
                payload = b"console.log('mock react bundle');\n"
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Cache-Control", "public, max-age=31536000, immutable")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path_only == "/assets/app.css":
                payload = b"body{}\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/css")
                self.send_header("Cache-Control", "public, max-age=31536000, immutable")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            payload = html_body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", port), _NoopHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        camp_dir = tmp_path / "camp_silent_noop"
        camp_dir.mkdir(parents=True, exist_ok=True)
        base_sha = _init_isolated_repo(tmp_path / "silent_noop_repo")
        (camp_dir / "campaign.json").write_text(
            json.dumps(
                {
                    "campaign_id": "qa-silent-noop",
                    "base_sha": base_sha,
                    "lane": "local_deterministic",
                    "target_url": f"http://127.0.0.1:{port}",
                    "status": "active",
                    "output_dir": str(camp_dir),
                }
            ),
            encoding="utf-8",
        )
        res = qa_cli_runner.run(
            ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--discover-controls"]
        )
        combined = _assert_no_cli_false_pass(res)
        cov_path = camp_dir / "coverage.json"
        if cov_path.is_file():
            cov = json.loads(cov_path.read_text(encoding="utf-8"))
            noop_items = [
                it for it in cov.get("items", []) if "Deploy" in str(it.get("accessible_name", ""))
            ]
            assert noop_items, f"Expected 'Deploy' control in coverage.json: {cov!r}"
            assert all(it.get("coverage_status") != "covered" for it in noop_items)
        else:
            assert res.returncode != 0
            assert any(
                tok in combined for tok in ("silent", "noop", "no-op", "disabled", "discover")
            )
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.qa_megaplan
def test_megaplan_ref_unavailable_does_not_block_local_scan(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #7, #8, #34: REF_UNAVAILABLE external reference does not block local scan."""
    camp_dir = tmp_path / "camp_ref_unavail"
    _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    (camp_dir / "reference_cards").mkdir(parents=True, exist_ok=True)
    unavail = build_grok_bot_reference_card(
        bot_name="main",
        case_id="CB-00",
        available=False,
        unavailable_reason="Quota exhausted on reference session",
    )
    (camp_dir / "reference_cards" / "ref-cb00-main.json").write_text(
        json.dumps(unavail.to_dict(), indent=2), encoding="utf-8"
    )

    res = qa_cli_runner.run(["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00"])
    _assert_no_cli_false_pass(res)
    assert res.returncode == 0, f"scan should continue despite REF_UNAVAILABLE: {res.stderr}"

    card_after = json.loads(
        (camp_dir / "reference_cards" / "ref-cb00-main.json").read_text(encoding="utf-8")
    )
    assert card_after["status"] == "REF_UNAVAILABLE"
    assert card_after["unavailable_reason"]


@pytest.mark.qa_megaplan
def test_megaplan_flaky_alternating_pass_fail_stays_flaky_never_in_repair(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #28: Alternating pass/fail stays `flaky` and is never promoted to `in_repair`."""
    repo_dir = tmp_path / "flaky_repo"
    counter_file = tmp_path / "flaky_counter.txt"
    counter_file.write_text("0", encoding="utf-8")
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_flaky.py": (
                "from pathlib import Path\n\n"
                "def test_alternating() -> None:\n"
                f"    p = Path({str(counter_file)!r})\n"
                "    n = int(p.read_text(encoding='utf-8').strip()) + 1\n"
                "    p.write_text(str(n), encoding='utf-8')\n"
                "    assert n % 2 == 0\n"
            ),
        },
        with_qa_branch=True,
    )

    camp_dir = tmp_path / "camp_flaky"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    (camp_dir / "failures.jsonl").write_text(
        json.dumps(
            {
                "item_id": "item-flaky-1",
                "dedup_key": "CB-03:sse:alternating_reconnect",
                "case_id": "CB-03",
                "subsystem": "sse",
                "normalized_signature": "alternating_reconnect",
                "severity": "P2",
                "state": "observed",
                "summary": "Alternating pass/fail SSE reconnect probe",
                "first_seen_sha": base_sha,
                "last_seen_sha": base_sha,
                "environment_lane": "local_deterministic",
                "repro_command": f"{sys.executable} -m pytest -q test_flaky.py",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    for _ in range(3):
        re_res = qa_cli_runner.run(
            [
                "reevaluate",
                "--campaign-dir",
                str(camp_dir),
                "--item",
                "item-flaky-1",
                "--repo-root",
                str(repo_dir),
            ],
            cwd=repo_dir,
        )
        _assert_no_cli_false_pass(re_res)

    rep_res = qa_cli_runner.run(
        [
            "repair",
            "--campaign-dir",
            str(camp_dir),
            "--max-parallel",
            "1",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    _assert_no_cli_false_pass(rep_res)

    items = _query_sqlite_tables(camp_dir, "qa_items")
    if not items:
        items = [
            json.loads(line)
            for line in (camp_dir / "failures.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    flaky_item = next(it for it in items if it["item_id"] == "item-flaky-1")
    assert flaky_item["state"] == "flaky"
    assert flaky_item["state"] != "in_repair"
    assert not list((camp_dir / "candidates").glob("*.json"))


@pytest.mark.qa_megaplan
def test_megaplan_p0_incident_halts_lane_and_preserves_evidence(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #31: P0 incident halts affected lane (`halted_p0`), blocks P2, preserves evidence."""
    repo_dir = tmp_path / "p0_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "mod_p2.py": "def val() -> int:\n    return 0\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_p2.py": "from mod_p2 import val\ndef test_p2() -> None:\n    assert val() == 2\n",
        },
        with_qa_branch=True,
    )
    camp_dir = tmp_path / "camp_p0_halt"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    ev_path = camp_dir / "evidence_p0.json"
    ev_path.write_text(
        json.dumps({"detail": "Attempted write near live var/controlbot.sqlite3"}), encoding="utf-8"
    )
    (camp_dir / "failures.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "item_id": "item-p0-leak",
                        "dedup_key": "CB-06:isolation:live_db_leak_risk",
                        "case_id": "CB-06",
                        "subsystem": "isolation",
                        "normalized_signature": "live_db_leak_risk",
                        "severity": "P0",
                        "state": "reproduced",
                        "summary": "P0 data-loss / live-target breach",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "evidence_paths": [str(ev_path)],
                        "repro_command": f"{sys.executable} -c 'raise SystemExit(1)'",
                    }
                ),
                json.dumps(
                    {
                        "item_id": "item-p2-other",
                        "dedup_key": "CB-01:ui:minor_p2",
                        "case_id": "CB-01",
                        "subsystem": "ui",
                        "normalized_signature": "minor_p2",
                        "severity": "P2",
                        "state": "reproduced",
                        "summary": "Lower priority P2 issue",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "repro_command": f"{sys.executable} -m pytest -q test_p2.py",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    rep_res = qa_cli_runner.run(
        [
            "repair",
            "--campaign-dir",
            str(camp_dir),
            "--max-parallel",
            "1",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    combined = _assert_no_cli_false_pass(rep_res)
    assert rep_res.returncode != 0
    assert any(tok in combined for tok in ("p0", "halt", "halted_p0", "data-loss", "live"))

    state_after = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert state_after["status"] == "halted_p0"
    assert ev_path.is_file()
    p2_cands = [
        json.loads(cf.read_text(encoding="utf-8"))
        for cf in (camp_dir / "candidates").glob("*.json")
        if json.loads(cf.read_text(encoding="utf-8")).get("item_id") == "item-p2-other"
    ]
    assert not p2_cands, "P2 repair must not run when lane is halted by P0"


@pytest.mark.qa_megaplan
def test_megaplan_budget_exhaustion_parks_item_with_next_diagnostic(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #28, #31: Exhausting max_attempts parks item with next_diagnostic and advances."""
    repo_dir = tmp_path / "park_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "mod_unfixable.py": "def impossible() -> bool:\n    return False\n",
            "mod_ok.py": "def fixable() -> bool:\n    return False\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_unfixable.py": (
                "import os\ndef test_impossible() -> None:\n"
                "    assert os.environ.get('NONEXISTENT_EXTERNAL_DEP') == '1'\n"
            ),
            "test_fixable.py": (
                "from mod_ok import fixable\ndef test_fixable() -> None:\n    assert fixable()\n"
            ),
        },
        with_qa_branch=True,
    )
    camp_dir = tmp_path / "camp_park"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    state["max_attempts_per_item"] = 2
    state["attempts"] = {"item-exhaust-a": 2}
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    (camp_dir / "failures.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "item_id": "item-exhaust-a",
                        "dedup_key": "CB-13:env:missing_dep_a",
                        "case_id": "CB-13",
                        "subsystem": "env",
                        "normalized_signature": "missing_dep_a",
                        "severity": "P1",
                        "state": "reproduced",
                        "summary": "Unfixable without external dep",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "attempts": 2,
                        "repro_command": f"{sys.executable} -m pytest -q test_unfixable.py",
                    }
                ),
                json.dumps(
                    {
                        "item_id": "item-next-b",
                        "dedup_key": "CB-01:mod_ok:fixable",
                        "case_id": "CB-01",
                        "subsystem": "mod_ok",
                        "normalized_signature": "fixable",
                        "severity": "P2",
                        "state": "reproduced",
                        "summary": "Independent fixable item B",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "attempts": 0,
                        "repro_command": f"{sys.executable} -m pytest -q test_fixable.py",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    rep_res = qa_cli_runner.run(
        [
            "repair",
            "--campaign-dir",
            str(camp_dir),
            "--max-parallel",
            "1",
            "--max-attempts",
            "2",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    _assert_no_cli_false_pass(rep_res)

    items = _query_sqlite_tables(camp_dir, "qa_items")
    if not items:
        items = [
            json.loads(line)
            for line in (camp_dir / "failures.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    item_a = next(it for it in items if it["item_id"] == "item-exhaust-a")
    item_b = next(it for it in items if it["item_id"] == "item-next-b")
    assert item_a["state"] == "parked"
    assert str(item_a.get("next_diagnostic") or "").strip(), (
        "Parked item must record hypothesis / next_diagnostic"
    )
    assert item_b["state"] != "reproduced" or item_b.get("attempts", 0) >= 1


@pytest.mark.qa_megaplan
def test_megaplan_resume_across_dot1_rotation_no_missed_or_duplicate_lines(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #27, #29: Resume ingests unread tail of .1 + new active file without duplicates."""
    camp_dir = tmp_path / "camp_rotate_resume"
    _run_baseline_to_dir(
        qa_cli_runner, qa_env, camp_dir, log_dir=qa_env.logs_dir, skip_browser=True
    )

    with qa_env.client() as client:
        assert client.get("/api/v1/bots/rot_before_1/library").status_code == 404

    scan1 = qa_cli_runner.run(
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--ingest-logs"]
    )
    _assert_no_cli_false_pass(scan1)
    assert scan1.returncode == 0

    failures_file = qa_env.logs_dir / "failures.jsonl"
    rotated_file = qa_env.logs_dir / "failures.jsonl.1"
    # Distinct routes & subsystems so path-ID normalization cannot collapse them
    tail_entry = json.dumps(
        {
            "id": "fail_rot_tail_01",
            "ts": "2026-11-27T06:00:00Z",
            "source": "pages",
            "kind": "page_render_error",
            "message": "POST /api/v1/pages/rot_tail_2 -> HTTP 404",
            "path": "/api/v1/pages/rot_tail_2",
            "method": "POST",
            "status_code": 404,
            "request_id": "req_rot_tail_01",
        }
    )
    with failures_file.open("a", encoding="utf-8") as fh:
        fh.write(tail_entry + "\n")
    os.replace(failures_file, rotated_file)

    active_entry = json.dumps(
        {
            "id": "fail_rot_new_02",
            "ts": "2026-11-27T06:00:01Z",
            "source": "routines",
            "kind": "routine_dispatch_error",
            "message": "GET /api/v1/routines/rot_new_3 -> HTTP 500",
            "path": "/api/v1/routines/rot_new_3",
            "method": "GET",
            "status_code": 500,
            "request_id": "req_rot_new_02",
        }
    )
    failures_file.write_text(active_entry + "\n", encoding="utf-8")

    res = qa_cli_runner.run(["resume", "--campaign-dir", str(camp_dir)])
    _assert_no_cli_false_pass(res)
    assert res.returncode == 0

    qa_items = _query_sqlite_tables(camp_dir, "qa_items")
    assert len(qa_items) >= 3, f"Expected 3 distinct qa_items across rotation, got {qa_items!r}"
    all_text = json.dumps(qa_items)
    assert any(
        tok in all_text for tok in ("rot_tail_2", "pages", "page_render_error", "req_rot_tail_01")
    ), "Missed unread tail from failures.jsonl.1"
    assert any(
        tok in all_text
        for tok in ("rot_new_3", "routines", "routine_dispatch_error", "req_rot_new_02")
    ), "Missed new entry from rotated failures.jsonl"
    before_items = [
        it
        for it in qa_items
        if "rot_before_1" in json.dumps(it) or "/api/v1/bots/" in json.dumps(it)
    ]
    assert len(before_items) == 1
    assert int(before_items[0]["occurrence_count"]) == 1, "Pre-rotation entry was double-counted"


@pytest.mark.qa_megaplan
def test_megaplan_stale_lease_generation_fencing_rejected(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #29: Accept rejects a candidate whose item lease generation is stale/superseded."""
    repo_dir = tmp_path / "stale_lease_repo"
    base_sha = _init_isolated_repo(repo_dir, with_qa_branch=True)
    stale_cand_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-stale",
        files={"feature_stale.py": "def ok() -> bool:\n    return True\n"},
        base_ref=base_sha,
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )

    camp_dir = tmp_path / "camp_stale_lease"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"

    # Seed FactoryStore with generation=1 released and generation=2 active on another owner
    store = FactoryStore(camp_dir / "factory.sqlite3")
    store.init_db()
    store.ensure_budget(CycleBudget(budget_id="default", max_cycles=4, max_attempts=4))
    store.add_backlog_item(
        BacklogItem(
            item_id="item-stale-lease",
            title="Stale lease fencing test",
            priority=1,
            hypothesis="Verify stale lease generation is rejected",
            target_metric="failures",
            baseline_repro_cmd="pytest -q test_smoke.py",
        )
    )
    lease_gen1 = store.acquire_lease("item-stale-lease", "worker-1", ttl_s=60.0)
    assert lease_gen1.generation == 1
    store.release_lease(lease_gen1.lease_id, lease_gen1.generation)
    lease_gen2 = store.acquire_lease("item-stale-lease", "worker-2", ttl_s=60.0)
    assert lease_gen2.generation == 2

    state["active_leases"] = {"item-stale-lease": lease_gen1.lease_id}
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    cand_path = camp_dir / "candidates" / "cand-stale.json"
    cand_path.write_text(
        json.dumps(
            {
                "candidate_id": "cand-stale",
                "item_id": "item-stale-lease",
                "campaign_id": state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": stale_cand_sha,
                "branch_name": "qa/cand-stale",
                "files_modified": ["feature_stale.py"],
                "rerun_command": f"{sys.executable} -m pytest -q test_smoke.py",
                "baseline_passed": False,
                "candidate_passed": True,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "pro",
                "status": "candidate_verified",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    acc_res = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            "cand-stale",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    combined = _assert_no_cli_false_pass(acc_res)
    assert acc_res.returncode != 0, (
        f"Expected stale lease fencing rejection, got 0:\n{acc_res.stdout}\n{acc_res.stderr}"
    )
    assert any(tok in combined for tok in ("stale", "lease", "generation", "fenced", "owner"))
    state_after = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert state_after["last_accepted_sha"] == base_sha
    assert _git_head_sha(repo_dir) == base_sha
    assert json.loads(cand_path.read_text(encoding="utf-8"))["status"] != "accepted_qa"


@pytest.mark.qa_megaplan
def test_megaplan_base_sha_advance_forces_rebase_on_accept(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #29: Advancing qa/autopilot base SHA forces rebase onto advanced_sha on accept."""
    repo_dir = tmp_path / "rebase_repo"
    base_sha = _init_isolated_repo(repo_dir, with_qa_branch=True)
    cand_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-rebase",
        files={
            "feature_a.py": "def feat_a() -> bool:\n    return True\n",
            "test_feature_a.py": (
                "from feature_a import feat_a\ndef test_feat_a() -> None:\n    assert feat_a()\n"
            ),
        },
        base_ref=base_sha,
    )
    # Advance qa/autopilot externally with an unrelated change & test
    advanced_sha = _create_candidate_branch(
        repo_dir,
        "qa/autopilot",
        files={
            "unrelated_qa.py": "def qa_tip() -> bool:\n    return True\n",
            "test_qa_tip.py": (
                "from unrelated_qa import qa_tip\n"
                "def test_qa_tip() -> None:\n    assert qa_tip()\n"
            ),
        },
        base_ref=base_sha,
    )
    assert advanced_sha != base_sha

    camp_dir = tmp_path / "camp_rebase"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = advanced_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    cand_path = camp_dir / "candidates" / "cand-rebase.json"
    cand_path.write_text(
        json.dumps(
            {
                "candidate_id": "cand-rebase",
                "item_id": "item-rb",
                "campaign_id": state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": cand_sha,
                "branch_name": "qa/cand-rebase",
                "files_modified": ["feature_a.py", "test_feature_a.py"],
                "rerun_command": f"{sys.executable} -m pytest -q test_feature_a.py",
                "baseline_passed": False,
                "candidate_passed": True,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "pro",
                "status": "candidate_verified",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    acc_res = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            "cand-rebase",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    _assert_no_cli_false_pass(acc_res)
    assert acc_res.returncode == 0, f"accept rebase failed: {acc_res.stderr}\n{acc_res.stdout}"

    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )
    new_head = _git_head_sha(repo_dir)
    assert new_head != advanced_sha, "Expected new rebased commit on qa/autopilot"
    anc = subprocess.run(
        ["git", "merge-base", "--is-ancestor", advanced_sha, new_head],
        cwd=str(repo_dir),
        check=False,
    )
    assert anc.returncode == 0, "Candidate overwrote advanced QA SHA without rebasing!"
    assert json.loads(cand_path.read_text(encoding="utf-8"))["status"] == "accepted_qa"

    combined_pytest = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    assert combined_pytest.returncode == 0, combined_pytest.stdout + combined_pytest.stderr


@pytest.mark.qa_megaplan
def test_megaplan_repair_rejects_self_audit_and_hydrogen_auditor(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #30, #41: Rejects both author==auditor self-audit and auditor_model=='hydrogen'."""
    repo_dir = tmp_path / "audit_repo"
    base_sha = _init_isolated_repo(repo_dir, with_qa_branch=True)
    cand_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-bad-audit",
        files={"fix.txt": "fix\n"},
        base_ref=base_sha,
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )

    for idx, (author, auditor) in enumerate(
        [("hydrogen", "hydrogen"), ("sonnet", "hydrogen")], start=1
    ):
        camp_dir = tmp_path / f"camp_bad_audit_{idx}"
        state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
        state["base_sha"] = base_sha
        state["last_accepted_sha"] = base_sha
        state["qa_branch"] = "qa/autopilot"
        (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
        (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
        cand_path = camp_dir / "candidates" / "cand-bad-audit.json"
        cand_path.write_text(
            json.dumps(
                {
                    "candidate_id": "cand-bad-audit",
                    "item_id": "item-bad-audit",
                    "campaign_id": state["campaign_id"],
                    "base_sha": base_sha,
                    "candidate_sha": cand_sha,
                    "branch_name": "qa/cand-bad-audit",
                    "rerun_command": f"{sys.executable} -m pytest -q test_smoke.py",
                    "baseline_passed": False,
                    "candidate_passed": True,
                    "audit_passed": True,
                    "author_model": author,
                    "auditor_model": auditor,
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
                "cand-bad-audit",
                "--repo-root",
                str(repo_dir),
            ],
            cwd=repo_dir,
        )
        combined = _assert_no_cli_false_pass(res)
        assert res.returncode != 0
        assert any(
            tok in combined
            for tok in ("hydrogen", "self-audit", "self_audit", "auditor", "distinct", "same")
        )
        assert json.loads(cand_path.read_text(encoding="utf-8"))["status"] != "accepted_qa"
        assert _git_head_sha(repo_dir) == base_sha


@pytest.mark.qa_megaplan
def test_megaplan_repair_rejects_locked_test_or_fixture_tampering(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #30: Candidate modifying locked repro test or PolicyGuard path is rejected."""
    repo_dir = tmp_path / "tamper_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "app_mod.py": "def val() -> int:\n    return 0\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_locked_repro.py": (
                "from app_mod import val\ndef test_val() -> None:\n    assert val() == 1\n"
            ),
        },
        with_qa_branch=True,
    )
    tamper_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-tamper",
        files={
            # Tamper with locked test instead of fixing app_mod.py!
            "test_locked_repro.py": "def test_val() -> None:\n    assert True\n",
        },
        base_ref=base_sha,
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )

    camp_dir = tmp_path / "camp_tamper"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    cand_path = camp_dir / "candidates" / "cand-tamper.json"
    cand_path.write_text(
        json.dumps(
            {
                "candidate_id": "cand-tamper",
                "item_id": "item-tamper",
                "campaign_id": state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": tamper_sha,
                "branch_name": "qa/cand-tamper",
                "files_modified": ["test_locked_repro.py"],
                "repro_test_path": "test_locked_repro.py",
                "rerun_command": f"{sys.executable} -m pytest -q test_locked_repro.py",
                "baseline_passed": False,
                "candidate_passed": True,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "pro",
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
            "cand-tamper",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    combined = _assert_no_cli_false_pass(res)
    assert res.returncode != 0
    assert any(
        tok in combined
        for tok in ("tamper", "locked", "repro_test", "policy", "immutable", "fixture")
    )
    assert json.loads(cand_path.read_text(encoding="utf-8"))["status"] != "accepted_qa"
    assert _git_head_sha(repo_dir) == base_sha


@pytest.mark.qa_megaplan
def test_megaplan_integration_regression_triggers_automatic_rollback(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #30, #35: Combined QA gate regression rolls back to last_accepted_sha."""
    repo_dir = tmp_path / "regress_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "shared.py": "def ok() -> bool:\n    return True\n",
            "test_smoke.py": "from shared import ok\ndef test_smoke() -> None:\n    assert ok()\n",
            "test_feature.py": "def test_feature() -> None:\n    assert True\n",
        },
        with_qa_branch=True,
    )
    bad_cand_sha = _create_candidate_branch(
        repo_dir,
        "qa/cand-regress",
        files={"shared.py": "def ok() -> bool:\n    return False\n"},
        base_ref=base_sha,
    )
    subprocess.run(
        ["git", "checkout", "qa/autopilot"], cwd=str(repo_dir), check=True, capture_output=True
    )

    camp_dir = tmp_path / "camp_regress"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (camp_dir / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    cand_path = camp_dir / "candidates" / "cand-regress.json"
    cand_path.write_text(
        json.dumps(
            {
                "candidate_id": "cand-regress",
                "item_id": "item-regress",
                "campaign_id": state["campaign_id"],
                "base_sha": base_sha,
                "candidate_sha": bad_cand_sha,
                "branch_name": "qa/cand-regress",
                "files_modified": ["shared.py"],
                "rerun_command": f"{sys.executable} -m pytest -q test_feature.py",
                "baseline_passed": False,
                "candidate_passed": True,
                "audit_passed": True,
                "author_model": "hydrogen",
                "auditor_model": "pro",
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
            "cand-regress",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    combined = _assert_no_cli_false_pass(res)
    assert res.returncode != 0
    assert any(tok in combined for tok in ("regress", "rollback", "rolled_back", "failed", "gate"))
    assert _git_head_sha(repo_dir) == base_sha
    state_after = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert state_after["last_accepted_sha"] == base_sha
    cand_after = json.loads(cand_path.read_text(encoding="utf-8"))
    assert cand_after["status"] in {"rolled_back", "rejected"}


@pytest.mark.qa_megaplan
def test_megaplan_parallel_over_two_or_overlapping_write_areas_rejected(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #36, #41: >2 parallel repairers rejected & overlapping write areas serialized."""
    camp_dir = tmp_path / "camp_over_parallel"
    _run_baseline_to_dir(qa_cli_runner, qa_env, camp_dir, skip_browser=True)

    over_res = qa_cli_runner.run(
        ["repair", "--campaign-dir", str(camp_dir), "--max-parallel", "3"]
    )
    combined = _assert_no_cli_false_pass(over_res)
    assert over_res.returncode != 0
    assert any(
        tok in combined for tok in ("parallel", "max_parallel", "<= 2", "at most 2", "exceed")
    )

    repo_dir = tmp_path / "overlap_repo"
    base_sha = _init_isolated_repo(
        repo_dir,
        files={
            "shared_target.py": "def a() -> int:\n    return 0\ndef b() -> int:\n    return 0\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_a.py": (
                "from shared_target import a\ndef test_a() -> None:\n    assert a() == 1\n"
            ),
            "test_b.py": (
                "from shared_target import b\ndef test_b() -> None:\n    assert b() == 2\n"
            ),
        },
        with_qa_branch=True,
    )
    overlap_camp = tmp_path / "camp_overlap"
    state = _run_baseline_to_dir(qa_cli_runner, qa_env, overlap_camp, skip_browser=True)
    state["base_sha"] = base_sha
    state["last_accepted_sha"] = base_sha
    state["qa_branch"] = "qa/autopilot"
    (overlap_camp / "campaign.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    (overlap_camp / "failures.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "item_id": "item-ov-1",
                        "dedup_key": "CB-05:shared_target:a",
                        "case_id": "CB-05",
                        "subsystem": "shared_target",
                        "normalized_signature": "a",
                        "severity": "P1",
                        "state": "reproduced",
                        "summary": "Overlap bug A in shared_target.py",
                        "first_seen_sha": base_sha,
                        "last_seen_sha": base_sha,
                        "environment_lane": "local_deterministic",
                        "repro_command": f"{sys.executable} -m pytest -q test_a.py",
                    }
                ),
                json.dumps(
                    {
                        "item_id": "item-ov-2",
                        "dedup_key": "CB-05:shared_target:b",
                        "case_id": "CB-05",
                        "subsystem": "shared_target",
                        "normalized_signature": "b",
                        "severity": "P1",
                        "state": "reproduced",
                        "summary": "Overlap bug B in shared_target.py",
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

    ov_res = qa_cli_runner.run(
        [
            "repair",
            "--campaign-dir",
            str(overlap_camp),
            "--max-parallel",
            "2",
            "--repo-root",
            str(repo_dir),
        ],
        cwd=repo_dir,
    )
    _assert_no_cli_false_pass(ov_res)
    # Serialized cleanly (returncode == 0) or rejected conflict cleanly
    if ov_res.returncode == 0:
        cand_files = sorted((overlap_camp / "candidates").glob("*.json"))
        assert cand_files
        assert int(
            json.loads((overlap_camp / "campaign.json").read_text(encoding="utf-8"))[
                "max_parallel_repairers"
            ]
        ) <= 2
    else:
        ov_combined = (ov_res.stdout + "\n" + ov_res.stderr).lower()
        assert any(
            tok in ov_combined for tok in ("overlap", "conflict", "serial", "write_area", "lease")
        )
