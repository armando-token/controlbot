"""Permanent Tier-5 adversarial hardening regression tests for src/qa/*."""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from src.contracts.common import utc_now
from src.factory.engine import _ephemeral_worktree
from src.factory.errors import IsolationBoundaryError, PolicyImmutabilityError
from src.qa.baseline import run_baseline
from src.qa.cli import build_parser
from src.qa.cli import dispatch_command as cli_dispatch_command
from src.qa.cli import main as cli_main
from src.qa.isolation import (
    LIVE_FORBIDDEN_PORTS,
    LogCursor,
    StrictPlaywrightSession,
    _is_allowed_browser_url,
    _sanitize_record,
    _scrub_embedded_urls_strict,
    _scrub_url_strict,
    contains_encoded_auth,
    contains_unredacted_url_secret,
    ephemeral_git_worktree,
    read_sanitized_logs,
    summarize_active_logs,
)
from src.qa.models import (
    CampaignState,
    CandidateManifest,
    QAFailureItem,
    ReferenceBehaviorCard,
    RunRecord,
)
from src.qa.queue import (
    get_qa_item,
    import_failures_jsonl_into_store,
    ingest_sanitized_logs,
    list_qa_items,
    open_campaign_store,
    persist_run_record,
    record_failure_observation,
    resume_campaign,
    save_campaign_state,
    sync_failures_jsonl_from_store,
    upsert_qa_item,
)
from src.qa.reference_cards import (
    build_ref_unavailable_card,
    build_reference_card,
    save_reference_card,
    validate_reference_card,
)
from src.qa.repair_loop import (
    QARepairLoop,
    _extract_test_file_from_command,
    _extract_test_files_from_command,
    _load_candidate_manifest,
    _run_shell_or_cmd,
    accept_candidate_to_qa,
    audit_candidate_forensic,
    build_qa_product_evaluator,
    reevaluate_qa_item,
    rollback_candidate_from_qa,
)
from src.qa.ux_metrics import (
    UxFlowMetrics,
    contains_unredacted_secret_m3,
    redact_payload_m3,
    save_ux_metrics,
)

pytestmark = pytest.mark.n1


def _init_git_repo(repo_dir: Path, files: dict[str, str]) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "qa-tier5@example.local"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "QA Tier5"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    for rel, content in files.items():
        target = repo_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit_branch(
    repo_dir: Path,
    branch: str,
    files: dict[str, str],
    *,
    base_ref: str = "main",
) -> str:
    subprocess.run(
        ["git", "checkout", "-B", branch, base_ref],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    for rel, content in files.items():
        target = repo_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", f"commit {branch}"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "checkout", "main"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return sha


def _make_state(
    camp_dir: Path, base_sha: str, *, campaign_id: str = "qa-tier5-camp"
) -> CampaignState:
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id=campaign_id,
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        qa_branch="qa/autopilot",
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)
    return state


# ---------------------------------------------------------------------------
# Finding 1 (P0): Nodeid & unittest module extraction + reevaluate fallback
# ---------------------------------------------------------------------------


def test_extract_test_file_handles_pytest_nodeids_k_flag_and_unittest_modules(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / "tests" / "unit").mkdir(parents=True)
    test_file = repo / "tests" / "unit" / "test_app_logic.py"
    test_file.write_text("def test_compute(): assert True\n", encoding="utf-8")

    assert (
        _extract_test_file_from_command(
            "python -m pytest -q tests/unit/test_app_logic.py::test_compute", repo
        )
        == "tests/unit/test_app_logic.py"
    )
    assert (
        _extract_test_file_from_command(
            "pytest tests/unit/test_app_logic.py::TestCls::test_m[a.py]", repo
        )
        == "tests/unit/test_app_logic.py"
    )
    assert (
        _extract_test_file_from_command(
            "pytest -k test_other.py tests/unit/test_app_logic.py::test_compute", repo
        )
        == "tests/unit/test_app_logic.py"
    )
    assert (
        _extract_test_file_from_command(
            "python -m unittest tests.unit.test_app_logic.TestCls.test_compute", repo
        )
        == "tests/unit/test_app_logic.py"
    )
    assert _extract_test_file_from_command("pytest ../escape.py::test_x", repo) is None


def test_repair_loop_and_reevaluate_block_nodeid_repro_test_tampering(tmp_path: Path) -> None:
    repo = tmp_path / "nodeid_repo"
    base_sha = _init_git_repo(
        repo,
        {
            "app_logic.py": "def compute() -> int:\n    return 1\n",
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 2\n"
            ),
        },
    )
    camp_dir = tmp_path / "camp_nodeid"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)

    repro_cmd = f"{sys.executable} -m pytest -q tests/unit/test_app_logic.py::test_compute"
    item = QAFailureItem(
        item_id="qa-nodeid-1",
        dedup_key="CB-01:app:nodeid",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="nodeid",
        severity="P1",
        state="reproduced",
        summary="compute returns 1 instead of 2",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=repro_cmd,
        repro_test_path=None,
    )
    upsert_qa_item(store, state.campaign_id, item)

    def _cheating_repairer(wt: Path, it: QAFailureItem) -> dict[str, str]:
        del wt, it
        return {
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 1\n"
            )
        }

    loop = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo,
        max_parallel=1,
        auto_accept=True,
        repairer_fn=_cheating_repairer,
    )
    res = loop.run()
    assert res["accepted_candidates"] == []
    assert res["worker_results"][0]["outcome"] == "blocked_policy"
    blocked_item = get_qa_item(store, state.campaign_id, "qa-nodeid-1")
    assert blocked_item is not None and blocked_item.state == "blocked"

    # Also verify reevaluate_qa_item catches nodeid test tampering when repro_test_path is None
    tamper_sha = _commit_branch(
        repo,
        "qa/cand-nodeid-reeval",
        {
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 1\n"
            )
        },
        base_ref=base_sha,
    )
    item_reeval = item.model_copy(
        update={"item_id": "qa-nodeid-2", "dedup_key": "CB-01:app:nodeid2", "state": "reproduced"}
    )
    upsert_qa_item(store, state.campaign_id, item_reeval)
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    cand_path = camp_dir / "candidates" / "cand-nodeid-reeval.json"
    cand_path.write_text(
        CandidateManifest(
            candidate_id="cand-nodeid-reeval",
            item_id="qa-nodeid-2",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=tamper_sha,
            branch_name="qa/cand-nodeid-reeval",
            repro_test_path=None,
            rerun_command=repro_cmd,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="pending",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    reeval_res = reevaluate_qa_item(camp_dir, item_id="qa-nodeid-2", repo_root=repo)
    assert reeval_res["evaluated_candidates"][0]["status"] == "rejected"
    assert reeval_res["evaluated_candidates"][0]["audit_passed"] is False
    saved_cand = CandidateManifest.model_validate_json(cand_path.read_text(encoding="utf-8"))
    assert "locked repro test" in str(saved_cand.audit_notes)


# ---------------------------------------------------------------------------
# Finding 2 (P0): Locked criterion & rerun_command immutability
# ---------------------------------------------------------------------------


def test_accept_and_reevaluate_enforce_locked_repro_command_and_criterion_hash(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "crit_repo"
    repro_body = (
        "from app_logic import compute\n"
        "def test_compute() -> None:\n"
        "    assert compute() == 2\n"
    )
    base_sha = _init_git_repo(
        repo,
        {
            "app_logic.py": "def compute() -> int:\n    return 1\n",
            "tests/unit/test_app_logic.py": repro_body,
            "README.md": "# initial\n",
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )
    broken_cand_sha = _commit_branch(
        repo,
        "qa/cand-cheat",
        {"README.md": "# unchanged bug\n"},
        base_ref=base_sha,
    )

    camp_dir = tmp_path / "camp_crit"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)

    repro_cmd = f"{sys.executable} -m pytest -q tests/unit/test_app_logic.py"
    real_test_hash = hashlib.sha256(repro_body.encode("utf-8")).hexdigest()[:16]
    item = QAFailureItem(
        item_id="qa-crit-1",
        dedup_key="CB-01:app:crit",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="crit",
        severity="P1",
        state="candidate_verified",
        summary="compute broken",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=repro_cmd,
        repro_test_path="tests/unit/test_app_logic.py",
        repro_test_hash=real_test_hash,
        locked_criterion_hash="cafebabe12345678",
    )
    upsert_qa_item(store, state.campaign_id, item)
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)

    # Case A: altered rerun_command with matching locked_criterion_hash
    (camp_dir / "candidates" / "cand-bad-cmd.json").write_text(
        CandidateManifest(
            candidate_id="cand-bad-cmd",
            item_id="qa-crit-1",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=broken_cand_sha,
            branch_name="qa/cand-cheat",
            repro_test_path="tests/unit/test_app_logic.py",
            repro_test_hash=real_test_hash,
            locked_criterion_hash="cafebabe12345678",
            rerun_command=f"{sys.executable} -c 'pass'",
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises(PolicyImmutabilityError, match="rerun_command"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-bad-cmd", repo_root=repo)

    # Case B: altered locked_criterion_hash with matching rerun_command
    (camp_dir / "candidates" / "cand-bad-hash.json").write_text(
        CandidateManifest(
            candidate_id="cand-bad-hash",
            item_id="qa-crit-1",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=broken_cand_sha,
            branch_name="qa/cand-cheat",
            repro_test_path="tests/unit/test_app_logic.py",
            repro_test_hash=real_test_hash,
            locked_criterion_hash="0000000000000000",
            rerun_command=repro_cmd,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises(PolicyImmutabilityError, match="locked_criterion_hash"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-bad-hash", repo_root=repo)

    # Case C: missing locked_criterion_hash on candidate when qa_item has one
    (camp_dir / "candidates" / "cand-none-hash.json").write_text(
        CandidateManifest(
            candidate_id="cand-none-hash",
            item_id="qa-crit-1",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=broken_cand_sha,
            branch_name="qa/cand-cheat",
            repro_test_path="tests/unit/test_app_logic.py",
            repro_test_hash=real_test_hash,
            locked_criterion_hash=None,
            rerun_command=repro_cmd,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises(PolicyImmutabilityError, match="locked_criterion_hash"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-none-hash", repo_root=repo)

    # Verify qa/autopilot was never mutated
    tip = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "qa/autopilot"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert tip == base_sha

    # Verify reevaluate_qa_item executes authoritative item.repro_command & rejects all 3 cheats
    reeval = reevaluate_qa_item(camp_dir, item_id="qa-crit-1", repo_root=repo)
    assert len(reeval["evaluated_candidates"]) == 3
    for entry in reeval["evaluated_candidates"]:
        assert entry["status"] == "rejected"
        assert entry["audit_passed"] is False


# ---------------------------------------------------------------------------
# Finding 3 (P1): resume_campaign preserves halted_p0
# ---------------------------------------------------------------------------


def test_resume_campaign_preserves_halted_p0_on_secret_leak_ingestion(tmp_path: Path) -> None:
    camp_dir = tmp_path / "camp_resume_p0"
    logs_dir = tmp_path / "logs_resume_p0"
    logs_dir.mkdir(parents=True, exist_ok=True)
    _make_state(camp_dir, "sha_resume_p0")

    secret = "super_secret_xyz_999"
    (logs_dir / "failures.jsonl").write_text(
        json.dumps(
            {
                "id": "fail-p0-resume",
                "source": "backend_http",
                "kind": "http_error",
                "message": f"Authorization: Bearer {secret}",
                "status_code": 500,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    resumed_state, info = resume_campaign(camp_dir, logs_dir=logs_dir)
    assert info["ingested_from_logs"] == 1
    assert info["halted_p0"] is True
    assert resumed_state.status == "halted_p0"
    assert resumed_state.p0_halt_reason

    persisted = CampaignState.model_validate_json(
        (camp_dir / "campaign.json").read_text(encoding="utf-8")
    )
    assert persisted.status == "halted_p0"
    assert persisted.p0_halt_reason
    assert secret not in (camp_dir / "campaign.json").read_text(encoding="utf-8")
    assert secret not in (camp_dir / "failures.jsonl").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Finding 4 (P1): record_failure_observation sanitizes before dedup & hash
# ---------------------------------------------------------------------------


def test_record_failure_observation_sanitizes_before_dedup_no_integrity_error(
    tmp_path: Path,
) -> None:
    camp_dir = tmp_path / "camp_dedup_sec"
    state = _make_state(camp_dir, "sha_dedup")
    store = open_campaign_store(camp_dir, state)

    it1 = record_failure_observation(
        store,
        state,
        case_id="CB-01",
        subsystem="web",
        raw_signature="auth failed Bearer tok_one_111",
        severity="P1",
        summary="auth failed Bearer tok_one_111",
        run_id="run-1",
    )
    it2 = record_failure_observation(
        store,
        state,
        case_id="CB-01",
        subsystem="web",
        raw_signature="auth failed Bearer tok_two_222",
        severity="P1",
        summary="auth failed Bearer tok_two_222",
        run_id="run-2",
    )
    it3 = record_failure_observation(
        store,
        state,
        case_id="CB-01",
        subsystem="web",
        raw_signature="auth failed Bearer tok_three_333",
        severity="P1",
        summary="auth failed Bearer tok_three_333",
        run_id="run-3",
    )

    assert it1.item_id == it2.item_id == it3.item_id
    assert it3.occurrence_count == 3
    assert it3.run_ids == ["run-1", "run-2", "run-3"]
    assert "[redacted]" in it3.dedup_key.lower()
    for secret in ("tok_one_111", "tok_two_222", "tok_three_333"):
        assert secret not in it3.dedup_key
        assert secret not in it3.summary

    # Also verify URL query/fragment secrets in raw_signature deduplicate cleanly
    u1 = record_failure_observation(
        store,
        state,
        case_id="CB-02",
        subsystem="web",
        raw_signature="GET http://127.0.0.1:9000/app?token=qsec_1#auth=fsec_1",
        severity="P1",
        summary="URL secret 1",
        run_id="run-u1",
    )
    u2 = record_failure_observation(
        store,
        state,
        case_id="CB-02",
        subsystem="web",
        raw_signature="GET http://127.0.0.1:9000/app?token=qsec_2#auth=fsec_2",
        severity="P1",
        summary="URL secret 2",
        run_id="run-u2",
    )
    assert u1.item_id == u2.item_id
    assert u2.occurrence_count == 2
    assert len(list_qa_items(store, state.campaign_id)) == 2


# ---------------------------------------------------------------------------
# Finding 5 (P1): Empty repro_command never passes or marks item flaky
# ---------------------------------------------------------------------------


def test_empty_repro_command_never_passes_or_marks_log_failures_flaky(tmp_path: Path) -> None:
    ok, msg = _run_shell_or_cmd("   ", cwd=tmp_path)
    assert ok is False
    assert "missing_repro_command" in msg

    repo = tmp_path / "empty_repro_repo"
    base_sha = _init_git_repo(repo, {"README.md": "# empty repro test\n"})
    camp_dir = tmp_path / "camp_empty_repro"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)

    eval_fn = build_qa_product_evaluator(
        repro_command="",
        campaign_dir=camp_dir,
        case_id="CB-00",
        build_frontend=False,
        skip_browser=True,
    )
    eval_res = eval_fn(repo)
    assert eval_res.passed is False
    assert "missing_repro_command" in eval_res.detail

    item = record_failure_observation(
        store,
        state,
        case_id="CB-00",
        subsystem="backend_http",
        raw_signature="POST /api/v1/runs -> HTTP 500",
        severity="P1",
        summary="Backend 500 from logs",
        source="log",
        repro_command="",
        repro_test_path=None,
        initial_state="observed",
    )

    reeval_res = reevaluate_qa_item(camp_dir, item_id=item.item_id, repo_root=repo)
    assert reeval_res["ok"] is False
    assert reeval_res["baseline_passed"] is False
    assert reeval_res["state"] == "blocked"

    # Reset to observed and verify QARepairLoop also blocks cleanly without marking flaky
    store_item = get_qa_item(store, state.campaign_id, item.item_id)
    assert store_item is not None and store_item.state == "blocked"
    assert "needs_repro" in str(store_item.blocked_reason)

    item2 = record_failure_observation(
        store,
        state,
        case_id="CB-01",
        subsystem="ux",
        raw_signature="composer_wrapped",
        severity="P1",
        summary="UX failure without repro",
        source="ux",
        repro_command="",
        repro_test_path=None,
        initial_state="observed",
    )
    loop = QARepairLoop(campaign_dir=camp_dir, repo_root=repo, max_parallel=1, auto_accept=False)
    loop_res = loop.run()
    assert loop_res["worker_results"] == [
        {"item_id": item2.item_id, "outcome": "needs_repro", "state": "blocked"}
    ]
    after2 = get_qa_item(store, state.campaign_id, item2.item_id)
    assert after2 is not None
    assert after2.state != "flaky"
    assert after2.state == "blocked"


# ---------------------------------------------------------------------------
# Finding 6 (P1): Rotated .1 log tail > 5000 entries is drained completely
# ---------------------------------------------------------------------------


def test_rotated_log_tail_over_5000_drains_completely_without_data_loss(tmp_path: Path) -> None:
    # First test small batch boundary directly in read_sanitized_logs
    small_logs = tmp_path / "small_logs"
    small_logs.mkdir(parents=True)
    small_active = small_logs / "failures.jsonl"
    small_rot = small_logs / "failures.jsonl.1"
    small_rot.write_text(
        "".join(
            json.dumps({"id": f"r-{i}", "source": "web", "kind": "err", "message": f"rot {i}"})
            + "\n"
            for i in range(12)
        ),
        encoding="utf-8",
    )
    small_active.write_text(
        "".join(
            json.dumps({"id": f"a-{i}", "source": "web", "kind": "err", "message": f"act {i}"})
            + "\n"
            for i in range(2)
        ),
        encoding="utf-8",
    )
    rot_st = small_rot.stat()
    cur = {
        "failures.jsonl": LogCursor(
            file_name="failures.jsonl", inode=(rot_st.st_dev, rot_st.st_ino), byte_offset=0
        )
    }
    collected_ids: list[str] = []
    for _ in range(4):
        recs, cur = read_sanitized_logs(
            small_logs, cursors=cur, max_entries_per_file=5, files=("failures.jsonl",)
        )
        collected_ids.extend(r["id"] for r in recs["failures.jsonl"])
    assert collected_ids == [*(f"r-{i}" for i in range(12)), "a-0", "a-1"]

    # Now test full >5000 rotation drain via ingest_sanitized_logs
    camp_dir = tmp_path / "camp_rot_5010"
    logs_dir = tmp_path / "logs_rot_5010"
    logs_dir.mkdir(parents=True)
    state = _make_state(camp_dir, "sha_rot_5010")
    store = open_campaign_store(camp_dir, state)

    failures_log = logs_dir / "failures.jsonl"
    rotated_log = logs_dir / "failures.jsonl.1"
    failures_log.write_text(
        json.dumps({"id": "seed-0", "source": "web", "kind": "err", "message": "seed 0"}) + "\n",
        encoding="utf-8",
    )
    r0 = ingest_sanitized_logs(store, state, logs_dir=logs_dir, campaign_dir=camp_dir)
    assert r0["ingested_count"] == 1

    with failures_log.open("a", encoding="utf-8") as fh:
        for i in range(5010):
            fh.write(
                json.dumps(
                    {
                        "id": f"rot-{i}",
                        "source": "web",
                        "kind": f"err_{i % 7}",
                        "message": f"rotated failure {i}",
                    }
                )
                + "\n"
            )
    os.replace(failures_log, rotated_log)
    failures_log.write_text(
        json.dumps({"id": "act-0", "source": "web", "kind": "err_act", "message": "active 0"})
        + "\n",
        encoding="utf-8",
    )

    r1 = ingest_sanitized_logs(store, state, logs_dir=logs_dir, campaign_dir=camp_dir)
    assert r1["ingested_count"] == 5011


# ---------------------------------------------------------------------------
# Finding 7 (P1): URL fragment & encoded auth redaction across isolation/ux/ref
# ---------------------------------------------------------------------------


def test_secret_redaction_url_fragments_and_encoded_auth_across_m3_modules(
    tmp_path: Path,
) -> None:
    s1 = _scrub_url_strict("http://127.0.0.1:8000/app#auth=secret_val_123")
    assert "secret_val_123" not in s1
    assert "auth=[REDACTED]" in s1

    s2 = _scrub_url_strict("http://127.0.0.1:8000/app?x=1#auth=secret_val_123&key=api_secret_456")
    assert "secret_val_123" not in s2
    assert "api_secret_456" not in s2
    assert "x=1" in s2

    encoded_inputs = (
        "http://127.0.0.1:9999/app?h=Bearer%20my_secret_tok&a=1",
        "Basic%20dXNlcjpwYXNz",
        "Bearer+plus_secret_tok_999",
        "http://127.0.0.1:9999/app#auth=frag_secret_999",
        "http://127.0.0.1:9999/app#key=frag_key_888",
    )
    for raw in encoded_inputs:
        assert contains_unredacted_secret_m3(raw) is True, f"Should detect {raw!r}"
        red = redact_payload_m3({"notes": raw})
        assert contains_unredacted_secret_m3(red) is False, f"Residual secret in {red!r}"

    flow = UxFlowMetrics(
        case_id="CB-01",
        run_id="run-enc",
        actions_to_reach=1,
        completion_ms=10.0,
        result_clarity_notes="http://127.0.0.1:9999/app?h=Bearer%20my_secret_tok#auth=frag_tok",
    )
    ux_path = save_ux_metrics([flow], tmp_path / "ux_enc.json")
    ux_txt = ux_path.read_text(encoding="utf-8")
    assert "my_secret_tok" not in ux_txt
    assert "frag_tok" not in ux_txt
    assert not contains_unredacted_secret_m3(json.loads(ux_txt))

    card = build_reference_card(
        card_id="ref-enc-card",
        case_id="CB-01",
        source="grok_bot_app",
        status="observed",
        bot_used="test",
        conditions={"url": "http://127.0.0.1:9999/app#auth=card_frag_secret"},
        discoverability="Header Bearer%20card_encoded_secret",
        state_transition="s",
        independent_verification="v",
        missing_data_or_permission="m",
        efficiency_notes="e",
        expected_controlbot_contract="c",
    )
    dumped = card.model_dump_json()
    assert "card_frag_secret" not in dumped
    assert "card_encoded_secret" not in dumped
    assert validate_reference_card(card) == []

    leaky_card = ReferenceBehaviorCard(
        card_id="ref-leaky-enc",
        case_id="CB-01",
        source="grok_bot_app",
        status="observed",
        bot_used="test",
        conditions={"timing_comparability": "ok", "privacy_scope": "ok"},
        discoverability="Bearer%20unredacted_tok",
        state_transition="s",
        independent_verification="v",
        missing_data_or_permission="m",
        efficiency_notes="e",
        expected_controlbot_contract="c",
    )
    assert "unredacted_secret_detected" in validate_reference_card(leaky_card)
    with pytest.raises(ValueError, match="unredacted_secret_detected"):
        save_reference_card(leaky_card, tmp_path / "cards")


# ---------------------------------------------------------------------------
# Finding 8 (P1): StrictPlaywrightSession blocks live forbidden ports
# ---------------------------------------------------------------------------


def test_strict_playwright_url_guard_rejects_live_forbidden_ports(tmp_path: Path) -> None:
    for port in sorted(LIVE_FORBIDDEN_PORTS):
        assert _is_allowed_browser_url(f"http://127.0.0.1:{port}/api/v1/bots") is False
        assert _is_allowed_browser_url(f"http://localhost:{port}/app") is False
        assert _is_allowed_browser_url(f"ws://127.0.0.1:{port}/websockify") is False
        assert _is_allowed_browser_url(f"http://[::1]:{port}/health") is False

    assert _is_allowed_browser_url("http://127.0.0.1:18123/app") is True
    assert _is_allowed_browser_url("ws://localhost:18123/ws") is True
    assert _is_allowed_browser_url("https://example.com/") is False
    assert _is_allowed_browser_url("data:text/plain,ok") is True

    async def _exercise_session() -> list[str]:
        async with StrictPlaywrightSession(user_data_dir=tmp_path / "pw_guard") as session:
            await session.page.set_content(
                """
                <script>
                  window.__done = Promise.all([
                    fetch('http://127.0.0.1:8000/health').catch(() => 'blocked'),
                    fetch('http://localhost:6080/').catch(() => 'blocked'),
                  ]);
                </script>
                """
            )
            await session.page.evaluate("() => window.__done")
            return list(session.external_requests)

    blocked_reqs = asyncio.run(_exercise_session())
    assert any(":8000" in req for req in blocked_reqs)
    assert any(":6080" in req for req in blocked_reqs)


# ---------------------------------------------------------------------------
# Finding 9 (P2): Path traversal rejection in card_id & candidate_id
# ---------------------------------------------------------------------------


def test_path_traversal_rejected_in_save_reference_card_and_candidate_manifest(
    tmp_path: Path,
) -> None:
    cards_dir = tmp_path / "cards"
    for bad_id in ("../escaped", "sub/card", "sub\\card", "..", "."):
        card = build_ref_unavailable_card(
            case_id="CB-01",
            reason="offline",
            card_id=bad_id,
        )
        with pytest.raises(ValueError, match="Invalid card_id"):
            save_reference_card(card, cards_dir)
    assert not (tmp_path / "escaped.json").exists()

    camp_dir = tmp_path / "camp_trav"
    (camp_dir / "candidates").mkdir(parents=True)
    escaped_file = camp_dir / "escaped.json"
    escaped_file.write_text("{}", encoding="utf-8")
    for bad_cand in ("../escaped", "sub/cand", "sub\\cand", "..", "."):
        with pytest.raises(ValueError, match="Invalid candidate_id"):
            _load_candidate_manifest(camp_dir, bad_cand)


# ---------------------------------------------------------------------------
# Finding 10 (P2): rollback_candidate_from_qa rejects unaccepted candidates
# ---------------------------------------------------------------------------


def test_rollback_candidate_rejects_unaccepted_statuses_without_touching_qa_branch(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "rb_guard_repo"
    base_sha = _init_git_repo(repo, {"app.py": "x = 0\n"})
    accepted_sha = _commit_branch(repo, "qa/autopilot", {"app.py": "x = 1\n"}, base_ref=base_sha)
    bad_sha = _commit_branch(repo, "qa/cand-rejected", {"app.py": "x = 99\n"}, base_ref=base_sha)

    camp_dir = tmp_path / "camp_rb_guard"
    state = _make_state(camp_dir, base_sha).model_copy(update={"last_accepted_sha": accepted_sha})
    save_campaign_state(camp_dir, state)
    open_campaign_store(camp_dir, state, repo_root=repo)

    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    for bad_status in ("rejected", "pending", "candidate_verified", "rolled_back"):
        cid = f"cand-{bad_status}"
        (camp_dir / "candidates" / f"{cid}.json").write_text(
            CandidateManifest(
                candidate_id=cid,
                item_id="item-rb",
                campaign_id=state.campaign_id,
                base_sha=base_sha,
                candidate_sha=bad_sha,
                branch_name="qa/cand-rejected",
                rerun_command=f"{sys.executable} -c 'pass'",
                baseline_passed=False,
                candidate_passed=False,
                audit_passed=False,
                author_model="hydrogen",
                auditor_model="pro",
                status=bad_status,
            ).model_dump_json(indent=2),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="must be 'accepted_qa'"):
            rollback_candidate_from_qa(camp_dir, candidate_id=cid, repo_root=repo)

    tip = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "qa/autopilot"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert tip == accepted_sha


# ---------------------------------------------------------------------------
# Finding 11 (P2): CLI --no-skip-browser support
# ---------------------------------------------------------------------------


def test_cli_skip_browser_supports_boolean_optional_action(tmp_path: Path) -> None:
    parser = build_parser()
    camp_arg = str(tmp_path / "camp")
    cases: list[tuple[list[str], bool]] = [
        (["repair", "--campaign-dir", camp_arg], True),
        (["repair", "--campaign-dir", camp_arg, "--skip-browser"], True),
        (["repair", "--campaign-dir", camp_arg, "--no-skip-browser"], False),
        (["reevaluate", "--campaign-dir", camp_arg, "--item", "i1"], True),
        (["reevaluate", "--campaign-dir", camp_arg, "--item", "i1", "--skip-browser"], True),
        (["reevaluate", "--campaign-dir", camp_arg, "--item", "i1", "--no-skip-browser"], False),
        (["accept", "--campaign-dir", camp_arg, "--candidate", "c1"], True),
        (["accept", "--campaign-dir", camp_arg, "--candidate", "c1", "--skip-browser"], True),
        (["accept", "--campaign-dir", camp_arg, "--candidate", "c1", "--no-skip-browser"], False),
    ]
    for argv, expected in cases:
        ns = parser.parse_args(argv)
        assert ns.skip_browser is expected, f"Failed for argv={argv!r}"


# ---------------------------------------------------------------------------
# Wave 2 Finding 1 (P0): pytest -s, unittest discover -s/-p, & multi-file repro
# ---------------------------------------------------------------------------


def test_extract_test_files_handles_pytest_s_unittest_discover_env_and_multifile(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w2_f1"
    (repo / "tests" / "unit").mkdir(parents=True)
    (repo / "tests" / "unit" / "test_a.py").write_text("def test_a(): pass\n", encoding="utf-8")
    (repo / "tests" / "unit" / "test_b.py").write_text("def test_b(): pass\n", encoding="utf-8")

    assert (
        _extract_test_file_from_command("pytest -s tests/unit/test_a.py::test_1", repo)
        == "tests/unit/test_a.py"
    )
    assert (
        _extract_test_file_from_command("python -m pytest -s tests/unit/test_a.py", repo)
        == "tests/unit/test_a.py"
    )
    assert (
        _extract_test_file_from_command(
            "python -m unittest discover -s tests/unit -p test_a.py", repo
        )
        == "tests/unit/test_a.py"
    )
    assert _extract_test_files_from_command(
        "python -m unittest discover -s tests/unit -p test_a.py", repo
    ) == ["tests/unit/test_a.py"]
    assert _extract_test_files_from_command(
        "python -m pytest -q tests/unit/test_a.py tests/unit/test_b.py::test_b", repo
    ) == ["tests/unit/test_a.py", "tests/unit/test_b.py"]
    assert _extract_test_files_from_command(
        "FOO=bar.py env BAZ=1 python -m pytest -s tests/unit/test_a.py", repo
    ) == ["tests/unit/test_a.py"]


def test_repair_loop_reeval_and_accept_block_pytest_s_and_multifile_tampering(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w2_tamper"
    base_sha = _init_git_repo(
        repo,
        {
            "app_logic.py": "def compute() -> int:\n    return 1\n",
            "tests/unit/test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 2\n"
            ),
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )
    camp_dir = tmp_path / "camp_w2_tamper"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)

    # 1. pytest -s <file> tampering blocked in QARepairLoop
    item_s = QAFailureItem(
        item_id="qa-w2-sflag",
        dedup_key="CB-01:app:sflag",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="sflag",
        severity="P1",
        state="reproduced",
        summary="pytest -s tampering check",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=f"{sys.executable} -m pytest -s tests/unit/test_app_logic.py::test_compute",
        repro_test_path=None,
    )
    upsert_qa_item(store, state.campaign_id, item_s)

    def _cheat_second_test(wt: Path, it: QAFailureItem) -> dict[str, str]:
        del wt, it
        return {
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 1\n"
            )
        }

    res_s = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo,
        max_parallel=1,
        auto_accept=True,
        repairer_fn=_cheat_second_test,
    ).run()
    assert res_s["accepted_candidates"] == []
    assert res_s["worker_results"][0]["outcome"] == "blocked_policy"

    # 2. Multi-file repro_command tampering on second file blocked in QARepairLoop, reevaluate,
    #    audit_candidate_forensic, and accept_candidate_to_qa
    multi_cmd = (
        f"{sys.executable} -m pytest -q tests/unit/test_smoke.py tests/unit/test_app_logic.py"
    )
    item_multi = QAFailureItem(
        item_id="qa-w2-multi",
        dedup_key="CB-01:app:multi",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="multi",
        severity="P1",
        state="reproduced",
        summary="multi-file tampering check",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=multi_cmd,
        repro_test_path=None,
    )
    upsert_qa_item(store, state.campaign_id, item_multi)
    res_multi = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo,
        max_parallel=1,
        auto_accept=True,
        repairer_fn=_cheat_second_test,
    ).run()
    assert res_multi["accepted_candidates"] == []
    assert res_multi["worker_results"][0]["outcome"] == "blocked_policy"

    tamper_sha = _commit_branch(
        repo,
        "qa/cand-multi-tamper",
        {
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 1\n"
            )
        },
        base_ref=base_sha,
    )
    cand_multi = CandidateManifest(
        candidate_id="cand-multi-tamper",
        item_id="qa-w2-multi",
        campaign_id=state.campaign_id,
        base_sha=base_sha,
        candidate_sha=tamper_sha,
        branch_name="qa/cand-multi-tamper",
        repro_test_path=None,
        rerun_command=multi_cmd,
        baseline_passed=False,
        candidate_passed=True,
        audit_passed=True,
        author_model="hydrogen",
        auditor_model="pro",
        status="candidate_verified",
    )
    with pytest.raises(PolicyImmutabilityError, match="locked repro test"):
        audit_candidate_forensic(
            repo,
            manifest=cand_multi,
            base_sha=base_sha,
            candidate_sha=tamper_sha,
        )

    item_multi_accept = QAFailureItem(
        item_id="qa-w2-multi-accept",
        dedup_key="CB-01:app:multi_accept",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="multi_accept",
        severity="P1",
        state="candidate_verified",
        summary="multi-file accept tampering check",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=multi_cmd,
        repro_test_path=None,
    )
    upsert_qa_item(store, state.campaign_id, item_multi_accept)
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    (camp_dir / "candidates" / "cand-multi-tamper.json").write_text(
        cand_multi.model_copy(update={"item_id": "qa-w2-multi-accept"}).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises(PolicyImmutabilityError, match="locked repro test"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-multi-tamper", repo_root=repo)

    (camp_dir / "candidates" / "cand-multi-tamper.json").write_text(
        cand_multi.model_dump_json(indent=2),
        encoding="utf-8",
    )
    reeval = reevaluate_qa_item(camp_dir, item_id="qa-w2-multi", repo_root=repo)
    assert reeval["evaluated_candidates"][0]["status"] == "rejected"
    assert reeval["evaluated_candidates"][0]["audit_passed"] is False


# ---------------------------------------------------------------------------
# Wave 2 Finding 2 (P0): accept_candidate_to_qa empty repro_command & status
# ---------------------------------------------------------------------------


def test_accept_candidate_enforces_repro_test_path_fallback_and_rejects_terminal_statuses(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w2_f2"
    base_sha = _init_git_repo(
        repo,
        {
            "app_logic.py": "def compute() -> int:\n    return 1\n",
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 2\n"
            ),
            "README.md": "# base\n",
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )
    noop_sha = _commit_branch(
        repo, "qa/cand-noop", {"README.md": "# untouched bug\n"}, base_ref=base_sha
    )
    good_sha = _commit_branch(
        repo,
        "qa/cand-good",
        {"app_logic.py": "def compute() -> int:\n    return 2\n"},
        base_ref=base_sha,
    )

    camp_dir = tmp_path / "camp_w2_f2"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)

    item = QAFailureItem(
        item_id="qa-w2-empty-cmd",
        dedup_key="CB-01:app:emptycmd",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="emptycmd",
        severity="P1",
        state="candidate_verified",
        summary="empty repro_command with repro_test_path set",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command="",
        repro_test_path="tests/unit/test_app_logic.py",
        locked_criterion_hash=None,
    )
    upsert_qa_item(store, state.campaign_id, item)
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)

    # Case 2A: broken candidate with rerun_command="python -c 'pass'" must be rejected
    (camp_dir / "candidates" / "cand-2a.json").write_text(
        CandidateManifest(
            candidate_id="cand-2a",
            item_id=item.item_id,
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=noop_sha,
            branch_name="qa/cand-noop",
            repro_test_path="tests/unit/test_app_logic.py",
            rerun_command=f"{sys.executable} -c 'pass'",
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises(PolicyImmutabilityError, match="rerun_command"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-2a", repo_root=repo)

    # Case 2B: already-rejected candidate must be rejected by accept_candidate_to_qa
    expected_repro = f"{sys.executable} -m pytest -q tests/unit/test_app_logic.py"
    (camp_dir / "candidates" / "cand-2b-rej.json").write_text(
        CandidateManifest(
            candidate_id="cand-2b-rej",
            item_id=item.item_id,
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=good_sha,
            branch_name="qa/cand-good",
            repro_test_path="tests/unit/test_app_logic.py",
            rerun_command=expected_repro,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=False,
            author_model="hydrogen",
            auditor_model="pro",
            status="rejected",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not eligible"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-2b-rej", repo_root=repo)

    # Case 2C: accept valid candidate, roll back, and verify re-accepting rolled_back/accepted fails
    (camp_dir / "candidates" / "cand-good.json").write_text(
        CandidateManifest(
            candidate_id="cand-good",
            item_id=item.item_id,
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=good_sha,
            branch_name="qa/cand-good",
            repro_test_path="tests/unit/test_app_logic.py",
            rerun_command=expected_repro,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    acc = accept_candidate_to_qa(camp_dir, candidate_id="cand-good", repo_root=repo)
    assert acc["status"] == "accepted_qa"
    with pytest.raises(ValueError, match="not eligible"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-good", repo_root=repo)

    rb = rollback_candidate_from_qa(camp_dir, candidate_id="cand-good", repo_root=repo)
    assert rb["status"] == "rolled_back"
    with pytest.raises(ValueError, match="not eligible"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-good", repo_root=repo)


# ---------------------------------------------------------------------------
# Wave 2 Finding 3 (P1): _EMBEDDED_URL_RE relative URL with ?query#fragment
# ---------------------------------------------------------------------------


def test_embedded_relative_url_with_query_and_fragment_is_detected_and_scrubbed() -> None:
    samples = (
        ("GET /app?x=1#mykey=topsecret123", "topsecret123"),
        ("error: GET /app?x=1#secret_id=frag_secret_123", "frag_secret_123"),
        ("POST /cb?foo=bar#token=rel_tok_999&a=1", "rel_tok_999"),
    )
    for raw, secret in samples:
        assert contains_unredacted_url_secret(raw) is True
        assert contains_unredacted_secret_m3(raw) is True

        scrubbed = _scrub_embedded_urls_strict(raw)
        assert secret not in scrubbed
        assert "[REDACTED]" in scrubbed
        assert contains_unredacted_url_secret(scrubbed) is False

        sanitized = _sanitize_record({"message": raw})
        assert secret not in sanitized["message"]
        assert contains_unredacted_secret_m3(sanitized) is False

        red_m3 = redact_payload_m3({"notes": raw})
        assert secret not in red_m3["notes"]
        assert contains_unredacted_secret_m3(red_m3) is False


# ---------------------------------------------------------------------------
# Wave 2 Finding 4 (P1): Encoded auth & URL-fragment secrets trigger P0 halt
# ---------------------------------------------------------------------------


def test_encoded_auth_and_url_fragment_secrets_trigger_p0_halt_in_ingest_and_resume(
    tmp_path: Path,
) -> None:
    # 1. resume_campaign halts with halted_p0 on Bearer%20 in failures.jsonl
    camp_f = tmp_path / "camp_w2_f4_failures"
    logs_f = tmp_path / "logs_w2_f4_failures"
    logs_f.mkdir(parents=True)
    _make_state(camp_f, "sha_w2_f4")
    (logs_f / "failures.jsonl").write_text(
        json.dumps(
            {
                "id": "f-enc",
                "source": "web",
                "kind": "err",
                "message": "GET /cb?h=Bearer%20secret_xyz_999",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    resumed_state, info = resume_campaign(camp_f, logs_dir=logs_f)
    assert info["halted_p0"] is True
    assert info["ingested_from_logs"] == 1
    assert resumed_state.status == "halted_p0"
    assert "secret_xyz_999" not in (camp_f / "campaign.json").read_text(encoding="utf-8")
    assert "secret_xyz_999" not in (camp_f / "failures.jsonl").read_text(encoding="utf-8")

    # 2. HTTP < 500 requests.jsonl with Bearer%20 and relative ?query#fragment triggers P0 halt
    camp_r = tmp_path / "camp_w2_f4_requests"
    logs_r = tmp_path / "logs_w2_f4_requests"
    logs_r.mkdir(parents=True)
    state_r = _make_state(camp_r, "sha_w2_f4_req")
    store_r = open_campaign_store(camp_r, state_r)
    (logs_r / "requests.jsonl").write_text(
        "".join(
            [
                json.dumps(
                    {
                        "id": "req-enc-200",
                        "method": "GET",
                        "path": "/cb?h=Bearer%20req_secret_111",
                        "status_code": 200,
                    }
                )
                + "\n",
                json.dumps(
                    {
                        "id": "req-frag-200",
                        "method": "GET",
                        "path": "/app?x=1#mykey=frag_secret_222",
                        "status_code": 200,
                    }
                )
                + "\n",
            ]
        ),
        encoding="utf-8",
    )
    ing = ingest_sanitized_logs(store_r, state_r, logs_dir=logs_r, campaign_dir=camp_r)
    assert ing["halted_p0"] is True
    assert ing["ingested_count"] == 2
    assert len(ing["p0_items"]) == 2
    failures_txt = (camp_r / "failures.jsonl").read_text(encoding="utf-8")
    assert "req_secret_111" not in failures_txt
    assert "frag_secret_222" not in failures_txt


# ---------------------------------------------------------------------------
# Wave 2 Finding 5 (P2): _run_shell_or_cmd VAR=val-prefixed repro_command
# ---------------------------------------------------------------------------


def test_run_shell_or_cmd_executes_env_var_prefixed_commands(tmp_path: Path) -> None:
    # Non-shell branch: parses leading NAME=VAL into env and maps python -> sys.executable
    ok, out = _run_shell_or_cmd(
        "FOO=bar_val BAR='two words' python -c "
        "\"print(__import__('os').environ['FOO'] + ':' + __import__('os').environ['BAR'])\"",
        cwd=tmp_path,
    )
    assert ok is True, out
    assert "bar_val:two words" in out

    # Shell branch (contains ';') with explicit sys.executable
    ok_sh, out_sh = _run_shell_or_cmd(
        f"FOO=shell_val {sys.executable} -c \"import os; print(os.environ['FOO'])\"",
        cwd=tmp_path,
    )
    assert ok_sh is True, out_sh
    assert "shell_val" in out_sh

    only_env_ok, only_env_out = _run_shell_or_cmd("FOO=bar", cwd=tmp_path)
    assert only_env_ok is False
    assert "missing_repro_command" in only_env_out


# ---------------------------------------------------------------------------
# Wave 3 Finding 1 (P0): Directory pytest & positional unittest discover
# ---------------------------------------------------------------------------


def test_extract_test_files_handles_directory_pytest_and_positional_unittest_discover(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w3_f1"
    (repo / "tests" / "unit" / "sub").mkdir(parents=True)
    (repo / "tests" / "integration").mkdir(parents=True)
    (repo / "tests" / "unit" / "test_app_logic.py").write_text(
        "def test_ok(): assert True\n", encoding="utf-8"
    )
    (repo / "tests" / "unit" / "sub" / "helper_test.py").write_text(
        "def test_helper(): assert True\n", encoding="utf-8"
    )
    (repo / "tests" / "unit" / "custom_spec.py").write_text(
        "import unittest\n", encoding="utf-8"
    )
    (repo / "tests" / "unit" / "notes.py").write_text("X = 1\n", encoding="utf-8")
    (repo / "tests" / "integration" / "test_int.py").write_text(
        "def test_int(): assert True\n", encoding="utf-8"
    )

    assert _extract_test_files_from_command("python -m pytest -q tests/unit", repo) == [
        "tests/unit/test_app_logic.py",
        "tests/unit/sub/helper_test.py",
    ]
    assert _extract_test_files_from_command(
        "pytest tests/unit tests/unit/test_app_logic.py", repo
    ) == [
        "tests/unit/test_app_logic.py",
        "tests/unit/sub/helper_test.py",
    ]
    assert _extract_test_files_from_command("pytest -q .", repo) == [
        "tests/integration/test_int.py",
        "tests/unit/test_app_logic.py",
        "tests/unit/sub/helper_test.py",
    ]
    assert _extract_test_files_from_command(
        "python -m unittest discover tests/unit 'custom_*.py'", repo
    ) == ["tests/unit/custom_spec.py"]
    assert _extract_test_files_from_command(
        "python -m unittest discover tests/unit 'custom_*.py' .", repo
    ) == ["tests/unit/custom_spec.py"]
    assert _extract_test_files_from_command("python -m unittest discover tests/unit", repo) == [
        "tests/unit/test_app_logic.py"
    ]
    assert _extract_test_files_from_command("pytest -q ../outside", repo) == []


def test_repair_loop_and_accept_block_directory_pytest_and_positional_unittest_tampering(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w3_tamper"
    base_sha = _init_git_repo(
        repo,
        {
            "app_logic.py": "def compute() -> int:\n    return 1\n",
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 2\n"
            ),
            "tests/unit/custom_spec.py": (
                "import unittest\n"
                "from app_logic import compute\n"
                "class SpecTest(unittest.TestCase):\n"
                "    def test_compute(self) -> None:\n"
                "        self.assertEqual(compute(), 2)\n"
            ),
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )
    camp_dir = tmp_path / "camp_w3_tamper"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)

    # 1. Directory-targeted pytest repro_command
    dir_cmd = f"{sys.executable} -m pytest -q tests/unit"
    item_dir = QAFailureItem(
        item_id="qa-w3-dir",
        dedup_key="CB-01:app:dir_pytest",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="dir_pytest",
        severity="P1",
        state="reproduced",
        summary="dir pytest tamper check",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=dir_cmd,
        repro_test_path=None,
    )
    upsert_qa_item(store, state.campaign_id, item_dir)

    def _cheat_pytest_file(wt: Path, it: QAFailureItem) -> dict[str, str]:
        del wt, it
        return {
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 1\n"
            )
        }

    res_dir = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo,
        max_parallel=1,
        auto_accept=True,
        repairer_fn=_cheat_pytest_file,
    ).run()
    assert res_dir["accepted_candidates"] == []
    assert res_dir["worker_results"][0]["outcome"] == "blocked_policy"

    tamper_dir_sha = _commit_branch(
        repo,
        "qa/cand-w3-dir-tamper",
        {
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 1\n"
            )
        },
        base_ref=base_sha,
    )
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    item_dir_accept = item_dir.model_copy(
        update={
            "item_id": "qa-w3-dir-accept",
            "dedup_key": "CB-01:app:dir_pytest_accept",
            "state": "candidate_verified",
        }
    )
    upsert_qa_item(store, state.campaign_id, item_dir_accept)
    (camp_dir / "candidates" / "cand-w3-dir-tamper.json").write_text(
        CandidateManifest(
            candidate_id="cand-w3-dir-tamper",
            item_id="qa-w3-dir-accept",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=tamper_dir_sha,
            branch_name="qa/cand-w3-dir-tamper",
            repro_test_path=None,
            rerun_command=dir_cmd,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises(PolicyImmutabilityError, match="locked repro test"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-w3-dir-tamper", repo_root=repo)

    # 2. Positional unittest discover repro_command
    pos_cmd = f"{sys.executable} -m unittest discover tests/unit 'custom_*.py'"
    item_pos = QAFailureItem(
        item_id="qa-w3-pos",
        dedup_key="CB-01:app:pos_unittest",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="pos_unittest",
        severity="P1",
        state="reproduced",
        summary="positional unittest discover tamper check",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=pos_cmd,
        repro_test_path=None,
    )
    upsert_qa_item(store, state.campaign_id, item_pos)

    def _cheat_custom_spec(wt: Path, it: QAFailureItem) -> dict[str, str]:
        del wt, it
        return {
            "tests/unit/custom_spec.py": (
                "import unittest\n"
                "from app_logic import compute\n"
                "class SpecTest(unittest.TestCase):\n"
                "    def test_compute(self) -> None:\n"
                "        self.assertEqual(compute(), 1)\n"
            )
        }

    res_pos = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo,
        max_parallel=1,
        auto_accept=True,
        repairer_fn=_cheat_custom_spec,
    ).run()
    assert res_pos["accepted_candidates"] == []
    assert res_pos["worker_results"][0]["outcome"] == "blocked_policy"

    tamper_pos_sha = _commit_branch(
        repo,
        "qa/cand-w3-pos-tamper",
        {
            "tests/unit/custom_spec.py": (
                "import unittest\n"
                "from app_logic import compute\n"
                "class SpecTest(unittest.TestCase):\n"
                "    def test_compute(self) -> None:\n"
                "        self.assertEqual(compute(), 1)\n"
            )
        },
        base_ref=base_sha,
    )
    item_pos_accept = item_pos.model_copy(
        update={
            "item_id": "qa-w3-pos-accept",
            "dedup_key": "CB-01:app:pos_unittest_accept",
            "state": "candidate_verified",
        }
    )
    upsert_qa_item(store, state.campaign_id, item_pos_accept)
    (camp_dir / "candidates" / "cand-w3-pos-tamper.json").write_text(
        CandidateManifest(
            candidate_id="cand-w3-pos-tamper",
            item_id="qa-w3-pos-accept",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=tamper_pos_sha,
            branch_name="qa/cand-w3-pos-tamper",
            repro_test_path=None,
            rerun_command=pos_cmd,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises(PolicyImmutabilityError, match="locked repro test"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-w3-pos-tamper", repo_root=repo)


# ---------------------------------------------------------------------------
# Wave 3 Finding 2 (P1): RFC 3986 path chars & %XX-prefixed encoded auth
# ---------------------------------------------------------------------------


def test_rfc3986_relative_url_paths_and_pct_prefixed_encoded_auth_trigger_p0_halt(
    tmp_path: Path,
) -> None:
    samples = (
        ("GET /api/v1/users/@me?mykey=sec_at_123", "sec_at_123"),
        ("GET /api/v1/items:batch?secret_id=sec_colon_123", "sec_colon_123"),
        ("GET /files/a%20b?auth_val=sec_pct_123", "sec_pct_123"),
        ("GET /v1/a+b,c~d?my_token=sec_tilde_123", "sec_tilde_123"),
        ("Authorization%3ABearer%20sec_header_pct3a", "sec_header_pct3a"),
        ("h=foo%3DBearer%20sec_header_pct3d", "sec_header_pct3d"),
        ("Authorization%3ABasic%2Bsec_basic_pct3a", "sec_basic_pct3a"),
    )
    for raw, secret in samples:
        assert contains_unredacted_secret_m3(raw) is True, f"Missed raw={raw!r}"
        sanitized = _sanitize_record({"message": raw})
        assert secret not in sanitized["message"], f"Leaked in _sanitize_record: {sanitized!r}"
        assert contains_unredacted_secret_m3(sanitized) is False

        red_m3 = redact_payload_m3({"notes": raw})
        assert secret not in red_m3["notes"], f"Leaked in redact_payload_m3: {red_m3!r}"
        assert contains_unredacted_secret_m3(red_m3) is False

    assert contains_unredacted_url_secret("GET /api/v1/users/@me?mykey=sec_at_123") is True
    assert contains_encoded_auth("Authorization%3ABearer%20sec_header_pct3a") is True
    assert contains_encoded_auth("subBearer%20not_a_header") is False

    for idx, (raw, secret) in enumerate(samples):
        camp_dir = tmp_path / f"camp_w3_f2_{idx}"
        logs_dir = tmp_path / f"logs_w3_f2_{idx}"
        logs_dir.mkdir(parents=True)
        _make_state(camp_dir, f"sha_w3_f2_{idx}")
        (logs_dir / "failures.jsonl").write_text(
            json.dumps(
                {
                    "id": f"f-w3-{idx}",
                    "source": "web",
                    "kind": "err",
                    "message": raw,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        resumed_state, info = resume_campaign(camp_dir, logs_dir=logs_dir)
        assert info["halted_p0"] is True, f"Expected halted_p0 for {raw!r}"
        assert resumed_state.status == "halted_p0"
        assert secret not in (camp_dir / "campaign.json").read_text(encoding="utf-8")
        assert secret not in (camp_dir / "failures.jsonl").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Wave 3 Finding 3 (P1): accept_candidate_to_qa rejects empty repro_command + None path
# ---------------------------------------------------------------------------


def test_accept_candidate_rejects_qa_item_with_empty_repro_command_and_no_repro_test_path(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w3_f3"
    base_sha = _init_git_repo(repo, {"app_logic.py": "x = 1\n", "README.md": "# base\n"})
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )
    cand_sha = _commit_branch(
        repo, "qa/cand-norepro", {"README.md": "# forged\n"}, base_ref=base_sha
    )

    camp_dir = tmp_path / "camp_w3_f3"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    upsert_qa_item(
        store,
        state.campaign_id,
        QAFailureItem(
            item_id="qa-w3-norepro",
            dedup_key="CB-01:app:norepro",
            case_id="CB-01",
            subsystem="app",
            normalized_signature="norepro",
            severity="P1",
            state="candidate_verified",
            summary="Item missing both repro_command and repro_test_path",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command="",
            repro_test_path=None,
        ),
    )
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    (camp_dir / "candidates" / "cand-norepro.json").write_text(
        CandidateManifest(
            candidate_id="cand-norepro",
            item_id="qa-w3-norepro",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=cand_sha,
            branch_name="qa/cand-norepro",
            repro_test_path=None,
            rerun_command=f"{sys.executable} -c 'pass'",
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises((ValueError, PolicyImmutabilityError), match="no locked repro_command"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-norepro", repo_root=repo)

    tip = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "qa/autopilot"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert tip == base_sha


# ---------------------------------------------------------------------------
# Wave 3 Finding 4 (P2): _run_shell_or_cmd quoted ';' & bare pytest
# ---------------------------------------------------------------------------


def test_run_shell_or_cmd_handles_quoted_semicolons_and_bare_pytest_without_venv_on_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "/usr/bin:/bin")

    ok_dq, out_dq = _run_shell_or_cmd(
        "FOO=bar_dq python -c \"import os; print(os.environ['FOO'])\"",
        cwd=tmp_path,
    )
    assert ok_dq is True, out_dq
    assert "bar_dq" in out_dq

    ok_sq, out_sq = _run_shell_or_cmd(
        "FOO=bar_sq python -c 'import os; print(os.environ[\"FOO\"])'",
        cwd=tmp_path,
    )
    assert ok_sq is True, out_sq
    assert "bar_sq" in out_sq

    ok_pt, out_pt = _run_shell_or_cmd("FOO=bar_pytest pytest --version", cwd=tmp_path)
    assert ok_pt is True, out_pt
    assert "pytest" in out_pt.lower()

    ok_and, out_and = _run_shell_or_cmd(
        f"{sys.executable} -c \"print('step1')\" && {sys.executable} -c \"print('step2')\"",
        cwd=tmp_path,
    )
    assert ok_and is True, out_and
    assert "step1" in out_and and "step2" in out_and


# ---------------------------------------------------------------------------
# Wave 3 Finding 5 (Critical): Parallel ephemeral_git_worktree race stress test
# ---------------------------------------------------------------------------


def test_ephemeral_git_worktree_concurrent_threads_no_race_or_leaked_worktrees(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_wt_race"
    base_sha = _init_git_repo(repo, {"app.py": "VALUE = 42\n", "README.md": "# race test\n"})

    num_threads = 4
    rounds = 5
    start_barrier = threading.Barrier(num_threads)
    active_basenames: list[str] = []
    basenames_lock = threading.Lock()

    def _worker(tid: int) -> list[str]:
        seen: list[str] = []
        start_barrier.wait(timeout=10.0)
        for round_idx in range(rounds):
            with ephemeral_git_worktree(repo, ref=base_sha) as wt:
                assert (wt / "app.py").read_text(encoding="utf-8") == "VALUE = 42\n"
                (wt / f"scratch_{tid}_{round_idx}.txt").write_text("ok\n", encoding="utf-8")
                with basenames_lock:
                    active_basenames.append(wt.name)
                seen.append(wt.name)
        return seen

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
        futures = [pool.submit(_worker, tid) for tid in range(num_threads)]
        per_thread = [fut.result(timeout=60.0) for fut in futures]

    all_basenames = [name for names in per_thread for name in names]
    assert len(all_basenames) == num_threads * rounds
    assert len(set(all_basenames)) == num_threads * rounds
    assert all(name.startswith("wt_") and name != "repo" for name in all_basenames)

    # Also verify explicit dest_dir with colliding basename ("repo") serializes cleanly
    dest_barrier = threading.Barrier(num_threads)

    def _dest_worker(tid: int) -> Path:
        dest = tmp_path / f"dest_slot_{tid}" / "repo"
        dest_barrier.wait(timeout=10.0)
        with ephemeral_git_worktree(repo, ref=base_sha, dest_dir=dest) as wt:
            assert wt == dest.resolve()
            assert (wt / "README.md").is_file()
            return wt

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
        dest_futures = [pool.submit(_dest_worker, tid) for tid in range(num_threads)]
        dest_paths = [fut.result(timeout=60.0) for fut in dest_futures]
    assert len(set(dest_paths)) == num_threads

    wt_list_proc = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    )
    worktree_lines = [
        line for line in wt_list_proc.stdout.splitlines() if line.startswith("worktree ")
    ]
    assert len(worktree_lines) == 1, f"Leaked git worktrees: {wt_list_proc.stdout!r}"
    git_worktrees_dir = repo / ".git" / "worktrees"
    if git_worktrees_dir.exists():
        assert list(git_worktrees_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# Wave 4 Finding 1 (P0): Bare pytest, conftest.py, globs & attached -s/-p
# ---------------------------------------------------------------------------


def test_extract_test_files_handles_bare_pytest_conftest_globs_and_attached_unittest_flags(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w4_f1"
    (repo / "tests" / "unit" / "sub").mkdir(parents=True)
    (repo / "conftest.py").write_text("# root conftest\n", encoding="utf-8")
    (repo / "tests" / "conftest.py").write_text("# tests conftest\n", encoding="utf-8")
    (repo / "tests" / "unit" / "conftest.py").write_text("# unit conftest\n", encoding="utf-8")
    (repo / "tests" / "unit" / "test_app_logic.py").write_text(
        "def test_ok(): assert True\n", encoding="utf-8"
    )
    (repo / "tests" / "unit" / "sub" / "helper_test.py").write_text(
        "def test_helper(): assert True\n", encoding="utf-8"
    )
    (repo / "tests" / "unit" / "custom_spec.py").write_text(
        "import unittest\n", encoding="utf-8"
    )

    expected_all = {
        "tests/unit/test_app_logic.py",
        "tests/unit/sub/helper_test.py",
        "tests/unit/conftest.py",
        "tests/conftest.py",
        "conftest.py",
    }
    assert set(_extract_test_files_from_command("python -m pytest -q", repo)) == expected_all
    assert set(_extract_test_files_from_command("pytest -q", repo)) == expected_all
    assert (
        set(_extract_test_files_from_command("python -m pytest -q -k test_ok", repo))
        == expected_all
    )
    assert (
        set(_extract_test_files_from_command("python -m pytest -q --rootdir tests/unit", repo))
        == expected_all
    )

    single_files = _extract_test_files_from_command(
        "python -m pytest -q tests/unit/test_app_logic.py", repo
    )
    assert single_files[0] == "tests/unit/test_app_logic.py"
    assert _extract_test_file_from_command(
        "python -m pytest -q tests/unit/test_app_logic.py", repo
    ) == "tests/unit/test_app_logic.py"
    assert {
        "tests/unit/test_app_logic.py",
        "tests/unit/conftest.py",
        "tests/conftest.py",
        "conftest.py",
    }.issubset(set(single_files))

    glob_expected = {
        "tests/unit/test_app_logic.py",
        "tests/unit/conftest.py",
        "tests/conftest.py",
        "conftest.py",
    }
    assert (
        set(
            _extract_test_files_from_command(
                "true && python -m pytest -q tests/unit/test_*.py", repo
            )
        )
        == glob_expected
    )
    assert (
        set(
            _extract_test_files_from_command(
                "true&&python -m pytest -q tests/unit/test_*.py", repo
            )
        )
        == glob_expected
    )

    assert _extract_test_files_from_command(
        "python -m unittest discover -stests/unit -pcustom_*.py", repo
    ) == ["tests/unit/custom_spec.py"]
    assert _extract_test_files_from_command(
        "python -m unittest discover -vs tests/unit -pcustom_*.py", repo
    ) == ["tests/unit/custom_spec.py"]
    assert _extract_test_files_from_command("pytest -q ../outside", repo) == []


def test_repair_loop_and_accept_block_bare_pytest_conftest_and_glob_tampering(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w4_tamper"
    base_sha = _init_git_repo(
        repo,
        {
            "app_logic.py": "def compute() -> int:\n    return 1\n",
            "tests/unit/conftest.py": "# legitimate fixtures\n",
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 2\n"
            ),
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )
    camp_dir = tmp_path / "camp_w4_tamper"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)

    cheat_test_edit = {
        "tests/unit/test_app_logic.py": (
            "from app_logic import compute\n"
            "def test_compute() -> None:\n"
            "    assert compute() == 1\n"
        )
    }
    cheat_conftest_edit = {
        "tests/unit/conftest.py": (
            "import pytest\n"
            "@pytest.hookimpl(hookwrapper=True)\n"
            "def pytest_runtest_makereport(item, call):\n"
            "    outcome = yield\n"
            "    rep = outcome.get_result()\n"
            "    if rep.when == 'call' and rep.failed:\n"
            "        rep.outcome = 'passed'\n"
            "        rep.longrepr = None\n"
        )
    }

    cases = [
        ("bare", f"{sys.executable} -m pytest -q", cheat_test_edit),
        ("conf", f"{sys.executable} -m pytest -q tests/unit", cheat_conftest_edit),
        ("glob", f"true && {sys.executable} -m pytest -q tests/unit/test_*.py", cheat_test_edit),
    ]
    for tag, repro_cmd, tamper_files in cases:
        item = QAFailureItem(
            item_id=f"qa-w4-{tag}",
            dedup_key=f"CB-01:app:{tag}",
            case_id="CB-01",
            subsystem="app",
            normalized_signature=tag,
            severity="P1",
            state="reproduced",
            summary=f"tamper check {tag}",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command=repro_cmd,
            repro_test_path=None,
        )
        upsert_qa_item(store, state.campaign_id, item)

        def _make_cheater(edits: dict[str, str]):  # type: ignore[no-untyped-def]
            def _cheater(wt: Path, it: QAFailureItem) -> dict[str, str]:
                del wt, it
                return edits

            return _cheater

        loop_res = QARepairLoop(
            campaign_dir=camp_dir,
            repo_root=repo,
            max_parallel=1,
            auto_accept=True,
            repairer_fn=_make_cheater(tamper_files),
        ).run()
        assert loop_res["accepted_candidates"] == []
        assert loop_res["worker_results"][0]["outcome"] == "blocked_policy"

        tamper_sha = _commit_branch(
            repo, f"qa/cand-w4-{tag}", tamper_files, base_ref=base_sha
        )
        acc_item = item.model_copy(
            update={
                "item_id": f"qa-w4-{tag}-acc",
                "dedup_key": f"CB-01:app:{tag}_acc",
                "state": "candidate_verified",
            }
        )
        upsert_qa_item(store, state.campaign_id, acc_item)
        (camp_dir / "candidates" / f"cand-w4-{tag}.json").write_text(
            CandidateManifest(
                candidate_id=f"cand-w4-{tag}",
                item_id=acc_item.item_id,
                campaign_id=state.campaign_id,
                base_sha=base_sha,
                candidate_sha=tamper_sha,
                branch_name=f"qa/cand-w4-{tag}",
                repro_test_path=None,
                rerun_command=repro_cmd,
                baseline_passed=False,
                candidate_passed=True,
                audit_passed=True,
                author_model="hydrogen",
                auditor_model="pro",
                status="candidate_verified",
            ).model_dump_json(indent=2),
            encoding="utf-8",
        )
        with pytest.raises(PolicyImmutabilityError, match="locked repro test"):
            accept_candidate_to_qa(
                camp_dir, candidate_id=f"cand-w4-{tag}", repo_root=repo
            )


# ---------------------------------------------------------------------------
# Wave 4 Finding 2 (P1): Colon-prefixed URLs, sub-delims & nested encoded URLs
# ---------------------------------------------------------------------------


def test_colon_prefix_subdelims_and_nested_encoded_urls_scrubbed_and_trigger_p0_halt(
    tmp_path: Path,
) -> None:
    samples = (
        ("endpoint:/api/v1/users/@me?mykey=sec_colon_prefix", "sec_colon_prefix"),
        ("url=/api/v1/items(1);v=2?mykey=sec_subdelim", "sec_subdelim"),
        ("GET /api/v1/items$1!/*?token=sec_subdelim_more", "sec_subdelim_more"),
        ("GET /app?next=https%3A%2F%2Fevil.com%3Fmykey%3Dsec_nested", "sec_nested"),
        (
            "GET /app?next=https%253A%252F%252Fevil.com%253Fmykey%253Dsec_double_nested",
            "sec_double_nested",
        ),
        ("GET /app#next=https%3A%2F%2Fevil.com%3Fmykey%3Dsec_frag_nested", "sec_frag_nested"),
    )
    for raw, secret in samples:
        assert contains_unredacted_url_secret(raw) is True, f"Missed URL secret: {raw!r}"
        assert contains_unredacted_secret_m3(raw) is True, f"Missed M3 secret: {raw!r}"

        scrubbed = _scrub_embedded_urls_strict(raw)
        assert secret not in scrubbed, f"Leaked in _scrub_embedded_urls_strict: {scrubbed!r}"
        assert contains_unredacted_url_secret(scrubbed) is False

        sanitized = _sanitize_record({"message": raw})
        assert secret not in sanitized["message"], f"Leaked in _sanitize_record: {sanitized!r}"
        assert contains_unredacted_secret_m3(sanitized) is False

        red_m3 = redact_payload_m3({"notes": raw})
        assert secret not in red_m3["notes"], f"Leaked in redact_payload_m3: {red_m3!r}"
        assert contains_unredacted_secret_m3(red_m3) is False

    for idx, (raw, secret) in enumerate(samples):
        camp_dir = tmp_path / f"camp_w4_f2_{idx}"
        logs_dir = tmp_path / f"logs_w4_f2_{idx}"
        logs_dir.mkdir(parents=True)
        _make_state(camp_dir, f"sha_w4_f2_{idx}")
        (logs_dir / "failures.jsonl").write_text(
            json.dumps(
                {
                    "id": f"f-w4-{idx}",
                    "source": "web",
                    "kind": "err",
                    "message": raw,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        resumed_state, info = resume_campaign(camp_dir, logs_dir=logs_dir)
        assert info["halted_p0"] is True, f"Expected halted_p0 for {raw!r}"
        assert resumed_state.status == "halted_p0"
        assert secret not in (camp_dir / "campaign.json").read_text(encoding="utf-8")
        assert secret not in (camp_dir / "failures.jsonl").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Wave 4 Finding 3 (P1): FactoryEngine._ephemeral_worktree concurrent stress
# ---------------------------------------------------------------------------


def test_factory_engine_ephemeral_worktree_concurrent_threads_no_race_or_leaked_worktrees(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_factory_wt_race"
    base_sha = _init_git_repo(repo, {"app.py": "VALUE = 7\n", "README.md": "# factory race\n"})

    num_threads = 8
    rounds = 15
    start_barrier = threading.Barrier(num_threads)

    def _worker(tid: int) -> list[str]:
        seen: list[str] = []
        start_barrier.wait(timeout=15.0)
        for round_idx in range(rounds):
            with _ephemeral_worktree(repo, ref=base_sha) as wt:
                assert (wt / "app.py").read_text(encoding="utf-8") == "VALUE = 7\n"
                (wt / f"scratch_{tid}_{round_idx}.txt").write_text("ok\n", encoding="utf-8")
                seen.append(wt.name)
        return seen

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
        futures = [pool.submit(_worker, tid) for tid in range(num_threads)]
        per_thread = [fut.result(timeout=120.0) for fut in futures]

    all_basenames = [name for names in per_thread for name in names]
    assert len(all_basenames) == num_threads * rounds
    assert len(set(all_basenames)) == num_threads * rounds
    assert all(name.startswith("wt_") and name != "repo" for name in all_basenames)

    # Also interleave FactoryEngine._ephemeral_worktree and ephemeral_git_worktree concurrently
    mix_barrier = threading.Barrier(8)

    def _mixed_worker(tid: int) -> list[str]:
        seen: list[str] = []
        mix_barrier.wait(timeout=15.0)
        cm_fn = _ephemeral_worktree if tid % 2 == 0 else ephemeral_git_worktree
        for _ in range(5):
            with cm_fn(repo, ref=base_sha) as wt:
                assert (wt / "README.md").is_file()
                seen.append(wt.name)
        return seen

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        mix_futures = [pool.submit(_mixed_worker, tid) for tid in range(8)]
        mix_names = [name for fut in mix_futures for name in fut.result(timeout=120.0)]
    assert len(mix_names) == 40
    assert len(set(mix_names)) == 40

    wt_list_proc = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    )
    worktree_lines = [
        line for line in wt_list_proc.stdout.splitlines() if line.startswith("worktree ")
    ]
    assert len(worktree_lines) == 1, f"Leaked git worktrees: {wt_list_proc.stdout!r}"
    git_worktrees_dir = repo / ".git" / "worktrees"
    if git_worktrees_dir.exists():
        assert list(git_worktrees_dir.iterdir()) == []


# ---------------------------------------------------------------------------
# Wave 4 Finding 4 (P2): Compound shell=True & env ... python PATH resolution
# ---------------------------------------------------------------------------


def test_run_shell_or_cmd_compound_shell_and_env_wrapper_without_venv_on_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "/usr/bin:/bin")

    ok_cmp, out_cmp = _run_shell_or_cmd(
        "FOO=bar_cmp python -c \"import os; print(os.environ['FOO'])\" "
        "&& python -c \"print('step2_ok')\"",
        cwd=tmp_path,
    )
    assert ok_cmp is True, out_cmp
    assert "bar_cmp" in out_cmp
    assert "step2_ok" in out_cmp

    ok_env, out_env = _run_shell_or_cmd(
        "FOO=bar_env env BAZ=qux_env python -c "
        "\"import os; print(os.environ['FOO'], os.environ['BAZ'])\"",
        cwd=tmp_path,
    )
    assert ok_env is True, out_env
    assert "bar_env qux_env" in out_env

    ok_pt, out_pt = _run_shell_or_cmd("true && pytest --version", cwd=tmp_path)
    assert ok_pt is True, out_pt
    assert "pytest" in out_pt.lower()


# ---------------------------------------------------------------------------
# Wave 5 Finding 1 (P0): Block new conftest.py, sitecustomize, & runner configs
# ---------------------------------------------------------------------------


def test_repair_loop_accept_and_forensic_block_new_conftest_sitecustomize_and_pytest_configs(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w5_f1"
    base_sha = _init_git_repo(
        repo,
        {
            "app_logic.py": "def compute() -> int:\n    return 1\n",
            "pyproject.toml": (
                '[project]\nname = "demo"\n[tool.ruff]\nline-length = 100\n'
                '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
            ),
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 2\n"
            ),
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )
    camp_dir = tmp_path / "camp_w5_f1"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)

    repro_cmd = f"{sys.executable} -m pytest -q tests/unit/test_app_logic.py"
    hijack_variants: list[tuple[str, dict[str, str]]] = [
        (
            "new_conftest",
            {
                "tests/unit/conftest.py": (
                    "import pytest\n"
                    "@pytest.hookimpl(hookwrapper=True)\n"
                    "def pytest_runtest_makereport(item, call):\n"
                    "    outcome = yield\n"
                    "    rep = outcome.get_result()\n"
                    "    if rep.when == 'call' and rep.failed:\n"
                    "        rep.outcome = 'passed'\n"
                    "        rep.longrepr = None\n"
                )
            },
        ),
        (
            "sitecustomize",
            {
                "sitecustomize.py": (
                    "import app_logic\n"
                    "app_logic.compute = lambda: 2\n"
                )
            },
        ),
        (
            "usercustomize",
            {
                "usercustomize.py": (
                    "import app_logic\n"
                    "app_logic.compute = lambda: 2\n"
                )
            },
        ),
        ("pytest_ini", {"pytest.ini": "[pytest]\naddopts = -k nonexistent\n"}),
        ("tox_ini", {"tox.ini": "[pytest]\naddopts = -k nonexistent\n"}),
        ("setup_cfg", {"setup.cfg": "[tool:pytest]\naddopts = -k nonexistent\n"}),
        (
            "pyproject_pytest_edit",
            {
                "pyproject.toml": (
                    '[project]\nname = "demo"\n[tool.ruff]\nline-length = 100\n'
                    '[tool.pytest.ini_options]\ntestpaths = ["tests"]\naddopts = "-k nope"\n'
                )
            },
        ),
        (
            "pyproject_pytest_delete",
            {
                "pyproject.toml": (
                    '[project]\nname = "demo"\n[tool.ruff]\nline-length = 100\n'
                )
            },
        ),
    ]

    for tag, edits in hijack_variants:
        item = QAFailureItem(
            item_id=f"qa-w5-{tag}",
            dedup_key=f"CB-01:app:{tag}",
            case_id="CB-01",
            subsystem="app",
            normalized_signature=tag,
            severity="P1",
            state="reproduced",
            summary=f"hijack variant {tag}",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command=repro_cmd,
            repro_test_path="tests/unit/test_app_logic.py",
        )
        upsert_qa_item(store, state.campaign_id, item)

        def _make_hijacker(files: dict[str, str]):  # type: ignore[no-untyped-def]
            def _hijacker(wt: Path, it: QAFailureItem) -> dict[str, str]:
                del wt, it
                return files

            return _hijacker

        loop_res = QARepairLoop(
            campaign_dir=camp_dir,
            repo_root=repo,
            max_parallel=1,
            auto_accept=True,
            repairer_fn=_make_hijacker(edits),
        ).run()
        assert loop_res["accepted_candidates"] == [], f"{tag} should not be accepted"
        assert loop_res["worker_results"][0]["outcome"] == "blocked_policy", f"{tag}: {loop_res}"
        blocked_item = get_qa_item(store, state.campaign_id, item.item_id)
        assert blocked_item is not None and blocked_item.state == "blocked"

        # Also verify audit_candidate_forensic & accept_candidate_to_qa reject committed hijacks
        cand_sha = _commit_branch(repo, f"qa/cand-w5-{tag}", edits, base_ref=base_sha)
        acc_item = item.model_copy(
            update={
                "item_id": f"qa-w5-{tag}-acc",
                "dedup_key": f"CB-01:app:{tag}_acc",
                "state": "candidate_verified",
            }
        )
        upsert_qa_item(store, state.campaign_id, acc_item)
        cand_manifest = CandidateManifest(
            candidate_id=f"cand-w5-{tag}",
            item_id=acc_item.item_id,
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=cand_sha,
            branch_name=f"qa/cand-w5-{tag}",
            repro_test_path="tests/unit/test_app_logic.py",
            rerun_command=repro_cmd,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        )
        (camp_dir / "candidates" / f"cand-w5-{tag}.json").write_text(
            cand_manifest.model_dump_json(indent=2), encoding="utf-8"
        )
        with pytest.raises(PolicyImmutabilityError):
            audit_candidate_forensic(
                repo,
                manifest=cand_manifest,
                base_sha=base_sha,
                candidate_sha=cand_sha,
                repro_test_path="tests/unit/test_app_logic.py",
                repro_command=repro_cmd,
            )
        with pytest.raises(PolicyImmutabilityError):
            accept_candidate_to_qa(
                camp_dir, candidate_id=f"cand-w5-{tag}", repo_root=repo
            )

    # Non-pytest edit to pyproject.toml (only [tool.ruff]) alongside real fix must be permitted
    legit_sha = _commit_branch(
        repo,
        "qa/cand-w5-ruff-only",
        {
            "app_logic.py": "def compute() -> int:\n    return 2\n",
            "pyproject.toml": (
                '[project]\nname = "demo"\n[tool.ruff]\nline-length = 120\n'
                '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
            ),
        },
        base_ref=base_sha,
    )
    legit_manifest = CandidateManifest(
        candidate_id="cand-w5-ruff-only",
        item_id="qa-w5-legit",
        campaign_id=state.campaign_id,
        base_sha=base_sha,
        candidate_sha=legit_sha,
        branch_name="qa/cand-w5-ruff-only",
        repro_test_path="tests/unit/test_app_logic.py",
        rerun_command=repro_cmd,
        baseline_passed=False,
        candidate_passed=True,
        audit_passed=False,
        author_model="hydrogen",
        auditor_model="pro",
        status="pending",
    )
    verdict = audit_candidate_forensic(
        repo,
        manifest=legit_manifest,
        base_sha=base_sha,
        candidate_sha=legit_sha,
        repro_test_path="tests/unit/test_app_logic.py",
        repro_command=repro_cmd,
    )
    assert verdict.passed is True

    tip = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "qa/autopilot"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert tip == base_sha


# ---------------------------------------------------------------------------
# Wave 5 Finding 2 (P1): Root-path & bracket/brace-path embedded URL redaction
# ---------------------------------------------------------------------------


def test_embedded_root_and_bracket_brace_urls_scrubbed_and_trigger_p0_halt(
    tmp_path: Path,
) -> None:
    samples = (
        ("GET /?mykey=sec_root_qs_123", "sec_root_qs_123"),
        ("GET /#mykey=sec_root_frag_123", "sec_root_frag_123"),
        ("GET /?authkey=sec_authkey_123", "sec_authkey_123"),
        ("GET /api/v1/items[0]?mykey=sec_bracket_123", "sec_bracket_123"),
        ("GET /api/v1/items/{id}?mykey=sec_brace_123", "sec_brace_123"),
        ('err={"url": "/?mykey=sec_in_json"}', "sec_in_json"),
    )
    for raw, secret in samples:
        assert contains_unredacted_url_secret(raw) is True, f"Missed URL secret: {raw!r}"
        assert contains_unredacted_secret_m3(raw) is True, f"Missed M3 secret: {raw!r}"

        scrubbed = _scrub_embedded_urls_strict(raw)
        assert secret not in scrubbed, f"Leaked in _scrub_embedded_urls_strict: {scrubbed!r}"
        assert contains_unredacted_url_secret(scrubbed) is False

        sanitized = _sanitize_record({"message": raw})
        assert secret not in sanitized["message"], f"Leaked in _sanitize_record: {sanitized!r}"
        assert contains_unredacted_secret_m3(sanitized) is False

        red_m3 = redact_payload_m3({"notes": raw})
        assert secret not in red_m3["notes"], f"Leaked in redact_payload_m3: {red_m3!r}"
        assert contains_unredacted_secret_m3(red_m3) is False

    # Preserve non-`//` safety and clean non-secret strings
    assert contains_unredacted_url_secret("//example.com/?x=1") is False
    assert _scrub_embedded_urls_strict("//comment?foo=bar") == "//comment?foo=bar"

    for idx, (raw, secret) in enumerate(samples):
        camp_dir = tmp_path / f"camp_w5_f2_{idx}"
        logs_dir = tmp_path / f"logs_w5_f2_{idx}"
        logs_dir.mkdir(parents=True)
        _make_state(camp_dir, f"sha_w5_f2_{idx}")
        (logs_dir / "failures.jsonl").write_text(
            json.dumps(
                {
                    "id": f"f-w5-{idx}",
                    "source": "web",
                    "kind": "err",
                    "message": raw,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        resumed_state, info = resume_campaign(camp_dir, logs_dir=logs_dir)
        assert info["halted_p0"] is True, f"Expected halted_p0 for {raw!r}"
        assert resumed_state.status == "halted_p0"
        assert secret not in (camp_dir / "campaign.json").read_text(encoding="utf-8")
        assert secret not in (camp_dir / "failures.jsonl").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Wave 5 Finding 3 (P1): accept_candidate_to_qa atomic state validation/stepping
# ---------------------------------------------------------------------------


def test_accept_candidate_to_qa_handles_observed_atomically_and_rejects_ineligible_before_commit(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w5_f3"
    repro_body = (
        "from app_logic import compute\n"
        "def test_compute() -> None:\n"
        "    assert compute() == 2\n"
    )
    base_sha = _init_git_repo(
        repo,
        {
            "app_logic.py": "def compute() -> int:\n    return 1\n",
            "tests/unit/test_app_logic.py": repro_body,
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )
    cand_sha = _commit_branch(
        repo,
        "qa/cand-obs",
        {"app_logic.py": "def compute() -> int:\n    return 2\n"},
        base_ref=base_sha,
    )

    camp_dir = tmp_path / "camp_w5_f3"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    repro_cmd = f"{sys.executable} -m pytest -q tests/unit/test_app_logic.py"

    # 1. Ineligible item state ("blocked") must fail BEFORE promoting qa/autopilot
    blocked_item = QAFailureItem(
        item_id="qa-blk-1",
        dedup_key="CB-01:app:blk",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="blk",
        severity="P1",
        state="blocked",
        summary="blocked item",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=repro_cmd,
        repro_test_path="tests/unit/test_app_logic.py",
    )
    upsert_qa_item(store, state.campaign_id, blocked_item)
    blk_cand_path = camp_dir / "candidates" / "cand-blk.json"
    blk_cand_path.write_text(
        CandidateManifest(
            candidate_id="cand-blk",
            item_id="qa-blk-1",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=cand_sha,
            branch_name="qa/cand-obs",
            repro_test_path="tests/unit/test_app_logic.py",
            rerun_command=repro_cmd,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="blocked"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-blk", repo_root=repo)
    assert (
        subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "qa/autopilot"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        == base_sha
    )
    assert (
        CandidateManifest.model_validate_json(
            blk_cand_path.read_text(encoding="utf-8")
        ).status
        == "candidate_verified"
    )

    # 2. Item in state="observed" steps observed -> reproduced -> in_repair -> ... -> accepted_qa
    obs_item = QAFailureItem(
        item_id="qa-obs-1",
        dedup_key="CB-01:app:obs",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="obs",
        severity="P1",
        state="observed",
        summary="observed item",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=repro_cmd,
        repro_test_path="tests/unit/test_app_logic.py",
    )
    upsert_qa_item(store, state.campaign_id, obs_item)
    obs_cand_path = camp_dir / "candidates" / "cand-obs.json"
    obs_cand_path.write_text(
        CandidateManifest(
            candidate_id="cand-obs",
            item_id="qa-obs-1",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=cand_sha,
            branch_name="qa/cand-obs",
            repro_test_path="tests/unit/test_app_logic.py",
            rerun_command=repro_cmd,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    acc = accept_candidate_to_qa(camp_dir, candidate_id="cand-obs", repo_root=repo)
    assert acc["ok"] is True
    assert acc["status"] == "accepted_qa"

    final_item = get_qa_item(store, state.campaign_id, "qa-obs-1")
    assert final_item is not None and final_item.state == "accepted_qa"
    final_state = CampaignState.model_validate_json(
        (camp_dir / "campaign.json").read_text(encoding="utf-8")
    )
    assert final_state.last_accepted_sha == acc["accepted_sha"]
    assert final_state.last_accepted_sha != base_sha
    assert "accepted_qa" in (camp_dir / "failures.jsonl").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Wave 5 Finding 4 (P1): Preserve drifted existing_manifest.base_sha
# ---------------------------------------------------------------------------


def test_repair_loop_preserves_drifted_existing_manifest_base_sha(tmp_path: Path) -> None:
    for mode, repro_suffix in (("bare", ""), ("targeted", " test_b.py")):
        repo = tmp_path / f"repo_w5_f4_{mode}"
        c0_sha = _init_git_repo(
            repo,
            {
                "mod_a.py": "A = 1\n",
                "mod_b.py": "B = 1\n",
                "test_a.py": "from mod_a import A\ndef test_a(): assert A == 1\n",
                "test_b.py": "from mod_b import B\ndef test_b(): assert B == 2\n",
            },
        )
        c1_sha = _commit_branch(
            repo,
            "qa/autopilot",
            {
                "mod_a.py": "A = 10\n",
                "test_a.py": "from mod_a import A\ndef test_a(): assert A == 10\n",
                "test_extra.py": "def test_extra(): assert True\n",
            },
            base_ref=c0_sha,
        )
        cand_b_sha = _commit_branch(
            repo,
            "qa/cand-b",
            {"mod_b.py": "B = 2\n"},
            base_ref=c0_sha,
        )

        camp_dir = tmp_path / f"camp_w5_f4_{mode}"
        state = _make_state(camp_dir, c0_sha)
        save_campaign_state(
            camp_dir, state.model_copy(update={"last_accepted_sha": c1_sha})
        )
        store = open_campaign_store(camp_dir, state, repo_root=repo)
        repro_cmd = f"{sys.executable} -m pytest -q{repro_suffix}"
        item_b = QAFailureItem(
            item_id="qa-b",
            dedup_key=f"CB-01:b:{mode}",
            case_id="CB-01",
            subsystem="mod_b",
            normalized_signature=f"b_{mode}",
            severity="P1",
            state="reproduced",
            summary="mod_b returns 1 instead of 2",
            first_seen_sha=c0_sha,
            last_seen_sha=c0_sha,
            environment_lane="local_deterministic",
            repro_command=repro_cmd,
            repro_test_path="test_b.py" if repro_suffix else None,
        )
        upsert_qa_item(store, state.campaign_id, item_b)
        (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
        cand_path = camp_dir / "candidates" / "cand-b.json"
        cand_path.write_text(
            CandidateManifest(
                candidate_id="cand-b",
                item_id="qa-b",
                campaign_id=state.campaign_id,
                base_sha=c0_sha,
                candidate_sha=cand_b_sha,
                branch_name="qa/cand-b",
                repro_test_path="test_b.py" if repro_suffix else None,
                rerun_command=repro_cmd,
                baseline_passed=False,
                candidate_passed=False,
                audit_passed=False,
                author_model="hydrogen",
                auditor_model="pro",
                status="pending",
            ).model_dump_json(indent=2),
            encoding="utf-8",
        )

        res = QARepairLoop(
            campaign_dir=camp_dir,
            repo_root=repo,
            max_parallel=1,
            auto_accept=True,
        ).run()
        assert res["accepted_candidates"] == ["cand-b"], f"{mode}: {res}"
        saved = CandidateManifest.model_validate_json(cand_path.read_text(encoding="utf-8"))
        assert saved.base_sha == c0_sha
        assert saved.files_modified == ["mod_b.py"]
        assert saved.status == "accepted_qa"
        final_item = get_qa_item(store, state.campaign_id, "qa-b")
        assert final_item is not None and final_item.state == "accepted_qa"


# ---------------------------------------------------------------------------
# Wave 5 Finding 5 (P2): Pytest space-separated value flags in test extractor
# ---------------------------------------------------------------------------


def test_extract_test_files_handles_pytest_space_separated_value_flags(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w5_f5"
    (repo / "tests" / "unit").mkdir(parents=True)
    (repo / "tests" / "unit" / "test_a.py").write_text(
        "def test_a(): assert True\n", encoding="utf-8"
    )

    cmds = (
        "pytest -q --durations 5",
        "pytest -q -r a",
        "pytest -q --color yes",
        "pytest -q --verbosity 1",
        "pytest -q --capture no",
        "pytest -q --show-capture no",
        "pytest -q --code-highlight no",
        "pytest -q --import-mode importlib",
        "pytest -q --junit-xml report.xml",
        "pytest -q --log-cli-level INFO",
        "pytest -q --log-file run.log",
        "pytest -q --log-file-level DEBUG",
        "pytest -q --log-format '%(message)s'",
        "pytest -q --log-date-format '%H:%M:%S'",
        "pytest -q --pastebin all",
    )
    for cmd in cmds:
        assert _extract_test_files_from_command(cmd, repo) == [
            "tests/unit/test_a.py"
        ], f"Failed bare pytest extraction for: {cmd!r}"


# ---------------------------------------------------------------------------
# Wave 5 Finding 6 (P2): Cross-model self-audit & cli scan forbidden bot_used
# ---------------------------------------------------------------------------


def test_cross_model_self_audit_not_masked_and_cli_scan_rejects_forbidden_bot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo_w5_f6"
    base_sha = _init_git_repo(
        repo,
        {
            "app_logic.py": "def compute() -> int:\n    return 1\n",
            "tests/unit/test_app_logic.py": (
                "from app_logic import compute\n"
                "def test_compute() -> None:\n"
                "    assert compute() == 2\n"
            ),
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )

    class _MockLLMHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            payload = {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "files": {
                                        "app_logic.py": "def compute() -> int:\n    return 2\n"
                                    }
                                }
                            )
                        }
                    }
                ]
            }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockLLMHandler)
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    try:
        camp_llm = tmp_path / "camp_w5_f6_llm"
        state_llm = _make_state(camp_llm, base_sha)
        store_llm = open_campaign_store(camp_llm, state_llm, repo_root=repo)
        upsert_qa_item(
            store_llm,
            state_llm.campaign_id,
            QAFailureItem(
                item_id="qa-self-audit",
                dedup_key="CB-01:app:self_audit",
                case_id="CB-01",
                subsystem="app",
                normalized_signature="self_audit",
                severity="P1",
                state="reproduced",
                summary="compute returns 1",
                first_seen_sha=base_sha,
                last_seen_sha=base_sha,
                environment_lane="local_deterministic",
                repro_command=f"{sys.executable} -m pytest -q tests/unit/test_app_logic.py",
                repro_test_path="tests/unit/test_app_logic.py",
            ),
        )
        monkeypatch.setenv("GROKBOT_LLM_BASE_URL", f"http://127.0.0.1:{server.server_address[1]}")
        monkeypatch.setenv("GROKBOT_LLM_MODEL_ID", "pro")

        with pytest.raises(ValueError, match="self-audit rejected"):
            QARepairLoop(
                campaign_dir=camp_llm,
                repo_root=repo,
                max_parallel=1,
                author_model="hydrogen",
                auditor_model="pro",
                auto_accept=True,
            ).run()

        assert (
            subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "qa/autopilot"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            == base_sha
        )
    finally:
        server.shutdown()
        server.server_close()
        srv_thread.join(timeout=5.0)

    # Part 6b: cli scan fails closed on reference card with forbidden bot_used
    camp_scan = tmp_path / "camp_w5_f6_scan"
    _make_state(camp_scan, base_sha)
    ref_dir = camp_scan / "reference_cards"
    ref_dir.mkdir(parents=True, exist_ok=True)
    (ref_dir / "bad_bot_card.json").write_text(
        json.dumps(
            {
                "card_id": "ref-bad-bot",
                "case_id": "CB-00",
                "source": "grok_bot_app",
                "status": "observed",
                "bot_used": "forbidden_bot_xyz",
                "discoverability": "d",
                "state_transition": "s",
                "independent_verification": "v",
                "missing_data_or_permission": "m",
                "efficiency_notes": "e",
                "expected_controlbot_contract": "c",
            }
        ),
        encoding="utf-8",
    )
    parser = build_parser()
    args = parser.parse_args(
        [
            "scan",
            "--campaign-dir",
            str(camp_scan),
            "--cases",
            "CB-00",
            "--repo-root",
            str(repo),
        ]
    )
    with pytest.raises(IsolationBoundaryError, match="forbidden"):
        cli_dispatch_command(args)

    rc = cli_main(
        [
            "scan",
            "--campaign-dir",
            str(camp_scan),
            "--cases",
            "CB-00",
            "--repo-root",
            str(repo),
        ]
    )
    assert rc != 0


# ---------------------------------------------------------------------------
# Wave 6 Finding 1 (P0): Test-runner/plugin/stdlib shadowing & test __init__.py
# ---------------------------------------------------------------------------


def test_runner_shadowing_and_test_init_mutations_blocked_while_src_init_allowed(
    tmp_path: Path,
) -> None:
    shadow_payloads: dict[str, dict[str, str]] = {
        "pytest_py": {"pytest.py": "import sys\nsys.exit(0)\n"},
        "pytest_pkg": {"pytest/__init__.py": "import sys\nsys.exit(0)\n"},
        "_pytest_pkg": {"_pytest/__init__.py": "import sys\nsys.exit(0)\n"},
        "pluggy_py": {"pluggy.py": "import sys\nsys.exit(0)\n"},
        "unittest_py": {"unittest.py": "import sys\nsys.exit(0)\n"},
        "py_py": {"py.py": "import sys\nsys.exit(0)\n"},
        "iniconfig_py": {"iniconfig.py": "import sys\nsys.exit(0)\n"},
        "tests_root_init": {"tests/__init__.py": "import src.pkg as p\np.VAL = 2\n"},
        "tests_unit_init": {"tests/unit/__init__.py": "import src.pkg as p\np.VAL = 2\n"},
    }

    repro_variants = (
        ("py_m_pytest", f"{sys.executable} -m pytest -q tests/unit/test_app_logic.py"),
        ("bare_pytest", "pytest -q tests/unit/test_app_logic.py"),
        ("py_m_unittest", f"{sys.executable} -m unittest tests.unit.test_app_logic"),
    )

    for cmd_label, repro_cmd in repro_variants:
        repo = tmp_path / f"repo_w6_f1_{cmd_label}"
        repro_body = (
            "import unittest\n"
            "from src.pkg import compute\n"
            "class TestCompute(unittest.TestCase):\n"
            "    def test_compute(self) -> None:\n"
            "        self.assertEqual(compute(), 2)\n"
        )
        base_sha = _init_git_repo(
            repo,
            {
                "src/__init__.py": "",
                "src/pkg/__init__.py": "def compute() -> int:\n    return 1\n",
                "tests/unit/__init__.py": "",
                "tests/unit/test_app_logic.py": repro_body,
            },
        )
        subprocess.run(
            ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
        )
        repro_hash = hashlib.sha256(repro_body.encode("utf-8")).hexdigest()[:16]

        for idx, (variant_name, hijack_files) in enumerate(shadow_payloads.items()):
            camp_dir = tmp_path / f"camp_w6_f1_{cmd_label}_{variant_name}"
            state = _make_state(camp_dir, base_sha)
            store = open_campaign_store(camp_dir, state, repo_root=repo)
            item_id = f"qa-w6-{cmd_label}-{idx}"
            item = QAFailureItem(
                item_id=item_id,
                dedup_key=f"CB-01:shadow:{cmd_label}:{variant_name}",
                case_id="CB-01",
                subsystem="app",
                normalized_signature=f"shadow_{variant_name}",
                severity="P1",
                state="reproduced",
                summary="compute returns 1 instead of 2",
                first_seen_sha=base_sha,
                last_seen_sha=base_sha,
                environment_lane="local_deterministic",
                repro_command=repro_cmd,
                repro_test_path="tests/unit/test_app_logic.py",
                repro_test_hash=repro_hash,
            )
            upsert_qa_item(store, state.campaign_id, item)

            def _hijack_repairer(
                wt: Path, it: QAFailureItem, files: dict[str, str] = hijack_files
            ) -> dict[str, str]:
                del wt, it
                return dict(files)

            res = QARepairLoop(
                campaign_dir=camp_dir,
                repo_root=repo,
                max_parallel=1,
                auto_accept=True,
                repairer_fn=_hijack_repairer,
            ).run()
            assert res["accepted_candidates"] == [], f"{cmd_label}/{variant_name}: {res}"
            assert res["worker_results"][0]["outcome"] == "blocked_policy", (
                f"{cmd_label}/{variant_name}: {res}"
            )
            blocked_item = get_qa_item(store, state.campaign_id, item_id)
            assert blocked_item is not None and blocked_item.state == "blocked"

            # Direct audit_candidate_forensic, reevaluate_qa_item, and accept_candidate_to_qa
            # must also reject forged manifests pointing to the same shadow commit.
            cand_branch = f"qa/forged-{cmd_label}-{variant_name}"
            hijack_sha = _commit_branch(repo, cand_branch, hijack_files, base_ref=base_sha)
            forged_manifest = CandidateManifest(
                candidate_id=f"cand-forged-{cmd_label}-{variant_name}",
                item_id=f"{item_id}-direct",
                campaign_id=state.campaign_id,
                base_sha=base_sha,
                candidate_sha=hijack_sha,
                branch_name=cand_branch,
                repro_test_path="tests/unit/test_app_logic.py",
                repro_test_hash=repro_hash,
                rerun_command=repro_cmd,
                baseline_passed=False,
                candidate_passed=True,
                audit_passed=True,
                author_model="hydrogen",
                auditor_model="pro",
                status="candidate_verified",
            )
            with pytest.raises(PolicyImmutabilityError):
                audit_candidate_forensic(
                    repo,
                    manifest=forged_manifest,
                    base_sha=base_sha,
                    candidate_sha=hijack_sha,
                    repro_test_path="tests/unit/test_app_logic.py",
                    repro_command=repro_cmd,
                    expected_repro_test_hash=repro_hash,
                )

            direct_item = item.model_copy(
                update={
                    "item_id": f"{item_id}-direct",
                    "dedup_key": f"CB-01:shadow:{cmd_label}:{variant_name}:direct",
                    "state": "candidate_verified",
                }
            )
            upsert_qa_item(store, state.campaign_id, direct_item)
            (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
            forged_path = camp_dir / "candidates" / f"{forged_manifest.candidate_id}.json"
            forged_path.write_text(forged_manifest.model_dump_json(indent=2), encoding="utf-8")
            with pytest.raises(PolicyImmutabilityError):
                accept_candidate_to_qa(
                    camp_dir, candidate_id=forged_manifest.candidate_id, repo_root=repo
                )
            reeval = reevaluate_qa_item(camp_dir, item_id=direct_item.item_id, repo_root=repo)
            assert reeval["evaluated_candidates"][0]["status"] == "rejected"
            assert reeval["evaluated_candidates"][0]["audit_passed"] is False

        # Verify ancestor __init__.py of a non-tests/ locked test path is also blocked.
        custom_repo = tmp_path / f"repo_w6_custom_anc_{cmd_label}"
        custom_repro_cmd = f"{sys.executable} -m pytest -q custom_tests/sub/test_custom.py"
        custom_base = _init_git_repo(
            custom_repo,
            {
                "src/pkg/__init__.py": "def compute() -> int:\n    return 1\n",
                "custom_tests/sub/test_custom.py": (
                    "from src.pkg import compute\n"
                    "def test_c() -> None:\n    assert compute() == 2\n"
                ),
            },
        )
        custom_hijack_sha = _commit_branch(
            custom_repo,
            "qa/custom-anc-hijack",
            {"custom_tests/sub/__init__.py": "import src.pkg\nsrc.pkg.compute = lambda: 2\n"},
            base_ref=custom_base,
        )
        with pytest.raises(PolicyImmutabilityError):
            audit_candidate_forensic(
                custom_repo,
                manifest=CandidateManifest(
                    candidate_id="cand-custom-anc",
                    item_id="qa-custom-anc",
                    campaign_id="camp-custom-anc",
                    base_sha=custom_base,
                    candidate_sha=custom_hijack_sha,
                    branch_name="qa/custom-anc-hijack",
                    repro_test_path=None,
                    rerun_command=custom_repro_cmd,
                    baseline_passed=False,
                    candidate_passed=True,
                    audit_passed=True,
                    author_model="hydrogen",
                    auditor_model="pro",
                    status="candidate_verified",
                ),
                base_sha=custom_base,
                candidate_sha=custom_hijack_sha,
                repro_command=custom_repro_cmd,
            )

        # Positive control: legitimate src/pkg/__init__.py edit succeeds end-to-end.
        camp_ok = tmp_path / f"camp_w6_f1_ok_{cmd_label}"
        state_ok = _make_state(camp_ok, base_sha)
        store_ok = open_campaign_store(camp_ok, state_ok, repo_root=repo)
        ok_item = QAFailureItem(
            item_id="qa-w6-src-init-ok",
            dedup_key=f"CB-01:src_init:{cmd_label}",
            case_id="CB-01",
            subsystem="app",
            normalized_signature="src_init_ok",
            severity="P1",
            state="reproduced",
            summary="compute returns 1 instead of 2",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command=repro_cmd,
            repro_test_path="tests/unit/test_app_logic.py",
            repro_test_hash=repro_hash,
        )
        upsert_qa_item(store_ok, state_ok.campaign_id, ok_item)
        res_ok = QARepairLoop(
            campaign_dir=camp_ok,
            repo_root=repo,
            max_parallel=1,
            auto_accept=True,
            repairer_fn=lambda wt, it: {
                "src/pkg/__init__.py": "def compute() -> int:\n    return 2\n"
            },
        ).run()
        assert len(res_ok["accepted_candidates"]) == 1, f"{cmd_label}: {res_ok}"
        accepted_item = get_qa_item(store_ok, state_ok.campaign_id, "qa-w6-src-init-ok")
        assert accepted_item is not None and accepted_item.state == "accepted_qa"


# ---------------------------------------------------------------------------
# Wave 6 Finding 2 (P1): agy adapter preserves tracked & nested paths
# ---------------------------------------------------------------------------


def test_agy_adapter_preserves_tracked_and_nested_paths_without_truncation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo_w6_agy"
    base_sha = _init_git_repo(
        repo,
        {
            "src_mod.py": "def value() -> int:\n    return 1\n",
            "tests/unit/test_src_mod.py": (
                "from src_mod import value\n"
                "from pkg.nested_mod import bonus\n"
                "def test_value_and_bonus() -> None:\n"
                "    assert value() + bonus() == 5\n"
            ),
            "pkg/__init__.py": "",
            "pkg/nested_mod.py": "def bonus() -> int:\n    return 0\n",
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )

    bin_dir = tmp_path / "mock_bin"
    bin_dir.mkdir(parents=True)
    agy_script = bin_dir / "agy"
    agy_script.write_text(
        f"#!{sys.executable}\n"
        "from pathlib import Path\n"
        "Path('src_mod.py').write_text('def value() -> int:\\n    return 2\\n', encoding='utf-8')\n"
        "Path('pkg/nested_mod.py').write_text("
        "'def bonus() -> int:\\n    return 3\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )
    agy_script.chmod(0o755)

    monkeypatch.delenv("GROKBOT_LLM_BASE_URL", raising=False)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    camp_dir = tmp_path / "camp_w6_agy"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    item = QAFailureItem(
        item_id="qa-w6-agy-1",
        dedup_key="CB-01:agy:tracked_nested",
        case_id="CB-01",
        subsystem="src_mod",
        normalized_signature="tracked_nested",
        severity="P1",
        state="reproduced",
        summary="value() + bonus() != 5",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=f"{sys.executable} -m pytest -q tests/unit/test_src_mod.py",
        repro_test_path="tests/unit/test_src_mod.py",
    )
    upsert_qa_item(store, state.campaign_id, item)

    res = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo,
        max_parallel=1,
        auto_accept=True,
    ).run()
    assert len(res["accepted_candidates"]) == 1, res
    cand_id = res["accepted_candidates"][0]
    _, manifest = _load_candidate_manifest(camp_dir, cand_id)
    assert manifest.author_model == "agy-repairer"
    assert sorted(manifest.files_modified) == ["pkg/nested_mod.py", "src_mod.py"]
    assert manifest.status == "accepted_qa"
    accepted_item = get_qa_item(store, state.campaign_id, "qa-w6-agy-1")
    assert accepted_item is not None and accepted_item.state == "accepted_qa"


# ---------------------------------------------------------------------------
# Wave 6 Finding 3 (P1): Mapping key sanitization across baseline, logs, queue
# ---------------------------------------------------------------------------


def test_mapping_key_url_and_encoded_auth_redaction_across_baseline_logs_and_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_sanitize = "sec_key_sanitize_111"
    secret_auth = "tok_key_auth_222"
    secret_tuple = "sec_tuple_333"
    secret_frozenset = "sec_fset_444"
    sanitized_obj = _sanitize_record(
        {
            f"GET /?mykey={secret_sanitize}": "ok",
            f"Authorization: Bearer%20{secret_auth}": "ok",
            ("prefix", f"https://example.local/cb?api_key={secret_tuple}"): "tuple_val",
            frozenset({f"GET /x?token={secret_frozenset}"}): "fset_val",
        }
    )
    dumped_sanitized = repr(sanitized_obj)
    for sec in (secret_sanitize, secret_auth, secret_tuple, secret_frozenset):
        assert sec not in dumped_sanitized, (
            f"Secret {sec!r} leaked in _sanitize_record: {dumped_sanitized}"
        )
    assert contains_unredacted_secret_m3(sanitized_obj) is False

    # summarize_active_logs scrubs URL/encoded-auth secrets in extra dict keys
    logs_dir = tmp_path / "logs_w6_f3"
    logs_dir.mkdir(parents=True)
    log_secret_key = "sec_leak_summary_555"
    log_secret_auth = "sec_leak_auth_666"
    (logs_dir / "failures.jsonl").write_text(
        json.dumps(
            {
                "id": "f-w6-1",
                "source": "web",
                "kind": f"GET /?mykey={log_secret_key}",
                "message": "bad req",
                "extra": {
                    f"GET /?mykey={log_secret_key}": "val",
                    f"Bearer%20{log_secret_auth}": "val2",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    summary = summarize_active_logs(logs_dir)
    summary_json = json.dumps(summary)
    assert log_secret_key not in summary_json
    assert log_secret_auth not in summary_json
    assert contains_unredacted_url_secret(summary_json) is False
    assert contains_encoded_auth(summary_json) is False

    # run_baseline never leaks URL/encoded-auth dict-key secrets into baseline.json or BASELINE.md
    import src.qa.baseline as baseline_mod

    repo_root = Path(__file__).resolve().parents[2]
    monkeypatch.setattr(
        baseline_mod,
        "verify_app_surface_http",
        lambda *a, **kw: baseline_mod.SurfaceHttpCheckResult(
            served_surface="unreachable",
            ui_variant="unknown",
            surface_verified=False,
            boot_errors=["unreachable"],
        ),
    )
    bl_out = tmp_path / "camp_w6_bl"
    report = run_baseline(
        repo_root=repo_root,
        output_dir=bl_out,
        target_url="http://127.0.0.1:65432",
        build_frontend=False,
        skip_browser=True,
        use_isolated_lab=False,
        log_dir=logs_dir,
    )
    assert report.exit_code == 2
    bl_json_text = (bl_out / "baseline.json").read_text(encoding="utf-8")
    bl_md_text = (bl_out / "BASELINE.md").read_text(encoding="utf-8")
    for sec in (log_secret_key, log_secret_auth):
        assert sec not in bl_json_text
        assert sec not in bl_md_text

    # Also verify run_baseline's final check catches unredacted URL/encoded-auth secrets if injected
    monkeypatch.setattr(
        baseline_mod,
        "summarize_active_logs",
        lambda *a, **kw: {
            "exists": True,
            "recent_failures": [{"extra": {"GET /?mykey=bypass_777": "x"}}],
        },
    )
    with pytest.raises(RuntimeError, match="strict secret redaction"):
        run_baseline(
            repo_root=repo_root,
            output_dir=tmp_path / "camp_w6_bl_failclosed",
            target_url="http://127.0.0.1:65432",
            build_frontend=False,
            skip_browser=True,
            use_isolated_lab=False,
            log_dir=logs_dir,
        )

    # persist_run_record handles URL/encoded-auth secrets in dict keys cleanly without crashing
    camp_rec = tmp_path / "camp_w6_rec"
    state_rec = _make_state(camp_rec, "sha_w6_rec")
    store_rec = open_campaign_store(camp_rec, state_rec, repo_root=repo_root)
    now = utc_now()
    rec_secret_url = "sec_assert_888"
    rec_secret_auth = "sec_assert_auth_999"
    runs_jsonl = persist_run_record(
        store_rec,
        camp_rec,
        RunRecord(
            campaign_id=state_rec.campaign_id,
            case_id="CB-01",
            run_id="r-w6-1",
            base_sha="sha_w6_rec",
            lane="local_deterministic",
            backend_mode="emulated",
            started_at=now,
            finished_at=now,
            duration_ms=10.0,
            passed=False,
            assertions={
                f"GET /?mykey={rec_secret_url}": False,
                f"Bearer%20{rec_secret_auth}": True,
            },
        ),
    )
    runs_text = runs_jsonl.read_text(encoding="utf-8")
    assert rec_secret_url not in runs_text
    assert rec_secret_auth not in runs_text
    assert "[REDACTED]" in runs_text

    # ingest_sanitized_logs on both JSONL and /api/v1/diagnostics/failures with dict-key secrets
    api_secret = "sec_api_key_000"

    class _MockDiagHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = json.dumps(
                {
                    "failures": [
                        {
                            "id": "diag-w6-1",
                            "source": "web",
                            "kind": "http_500",
                            "message": "request failed",
                            "extra": {f"GET /?mykey={api_secret}": "v"},
                        }
                    ]
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            del format, args

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockDiagHandler)
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()
    try:
        camp_ing = tmp_path / "camp_w6_ingest"
        state_ing = _make_state(camp_ing, "sha_w6_ing")
        store_ing = open_campaign_store(camp_ing, state_ing, repo_root=repo_root)
        ing_res = ingest_sanitized_logs(
            store_ing,
            state_ing,
            campaign_dir=camp_ing,
            logs_dir=logs_dir,
            target_url=f"http://127.0.0.1:{srv.server_address[1]}",
        )
        assert ing_res["ingested_count"] >= 2
        assert ing_res["halted_p0"] is True
        all_items = list_qa_items(store_ing, state_ing.campaign_id)
        assert any(it.severity == "P0" for it in all_items)
        failures_text = (camp_ing / "failures.jsonl").read_text(encoding="utf-8")
        for sec in (log_secret_key, log_secret_auth, api_secret):
            assert sec not in failures_text
    finally:
        srv.shutdown()
        srv.server_close()
        srv_thread.join(timeout=5.0)


# ---------------------------------------------------------------------------
# Wave 7 Finding 1 (P0): Stdlib / site-packages / tests-root module shadowing
# ---------------------------------------------------------------------------


def test_stdlib_installed_package_and_tests_root_shadowing_blocked_while_src_allowed(
    tmp_path: Path,
) -> None:
    repro_body = (
        "from src.pkg import compute\n"
        "def test_compute() -> None:\n"
        "    assert compute() == 2\n"
    )
    repro_hash = hashlib.sha256(repro_body.encode("utf-8")).hexdigest()[:16]
    repro_cmd = f"{sys.executable} -m pytest -q tests/unit/test_app_logic.py"

    shadow_variants: dict[str, dict[str, str]] = {
        "typing_py": {"typing.py": "import sys\nsys.exit(0)\n"},
        "re_py": {"re.py": "import sys\nsys.exit(0)\n"},
        "anyio_py": {"anyio.py": "import sys\nsys.exit(0)\n"},
        "typing_pkg": {"typing/__init__.py": "import sys\nsys.exit(0)\n"},
        "anyio_pkg": {"anyio/__init__.py": "import sys\nsys.exit(0)\n"},
        "tests_typing_py": {"tests/typing.py": "import sys\nsys.exit(0)\n"},
        "tests_anyio_py": {"tests/anyio.py": "import sys\nsys.exit(0)\n"},
        "tests_src_path_hijack": {
            "tests/src.py": (
                "import pathlib\n"
                '__path__ = [str(pathlib.Path(__file__).with_name("_fake_src"))]\n'
            ),
            "tests/_fake_src/pkg.py": "def compute() -> int:\n    return 2\n",
        },
        "tests_unit_helper": {"tests/unit/helper.py": "VAL = 2\n"},
    }

    repo = tmp_path / "repo_w7_f1"
    base_sha = _init_git_repo(
        repo,
        {
            "src/__init__.py": "",
            "src/pkg/__init__.py": "def compute() -> int:\n    return 1\n",
            "tests/unit/__init__.py": "",
            "tests/unit/test_app_logic.py": repro_body,
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )

    for idx, (tag, hijack_files) in enumerate(shadow_variants.items()):
        camp_dir = tmp_path / f"camp_w7_f1_{tag}"
        state = _make_state(camp_dir, base_sha, campaign_id=f"qa-w7-f1-{idx}")
        store = open_campaign_store(camp_dir, state, repo_root=repo)
        item_id = f"qa-w7-{tag}"
        item = QAFailureItem(
            item_id=item_id,
            dedup_key=f"CB-01:w7:{tag}",
            case_id="CB-01",
            subsystem="app",
            normalized_signature=f"w7_{tag}",
            severity="P1",
            state="reproduced",
            summary="compute returns 1 instead of 2",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command=repro_cmd,
            repro_test_path="tests/unit/test_app_logic.py",
            repro_test_hash=repro_hash,
        )
        upsert_qa_item(store, state.campaign_id, item)

        def _make_hijacker(files: dict[str, str]):  # type: ignore[no-untyped-def]
            def _hijack(wt: Path, it: QAFailureItem) -> dict[str, str]:
                del wt, it
                return dict(files)

            return _hijack

        res = QARepairLoop(
            campaign_dir=camp_dir,
            repo_root=repo,
            max_parallel=1,
            auto_accept=True,
            repairer_fn=_make_hijacker(hijack_files),
        ).run()
        assert res["accepted_candidates"] == [], f"{tag}: {res}"
        assert res["worker_results"][0]["outcome"] == "blocked_policy", f"{tag}: {res}"
        blocked_item = get_qa_item(store, state.campaign_id, item_id)
        assert blocked_item is not None and blocked_item.state == "blocked"

        cand_branch = f"qa/forged-w7-{tag}"
        hijack_sha = _commit_branch(repo, cand_branch, hijack_files, base_ref=base_sha)
        forged_manifest = CandidateManifest(
            candidate_id=f"cand-forged-w7-{tag}",
            item_id=f"{item_id}-direct",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=hijack_sha,
            branch_name=cand_branch,
            repro_test_path="tests/unit/test_app_logic.py",
            repro_test_hash=repro_hash,
            rerun_command=repro_cmd,
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        )
        with pytest.raises(PolicyImmutabilityError):
            audit_candidate_forensic(
                repo,
                manifest=forged_manifest,
                base_sha=base_sha,
                candidate_sha=hijack_sha,
                repro_test_path="tests/unit/test_app_logic.py",
                repro_command=repro_cmd,
                expected_repro_test_hash=repro_hash,
            )

        direct_item = item.model_copy(
            update={
                "item_id": f"{item_id}-direct",
                "dedup_key": f"CB-01:w7:{tag}:direct",
                "state": "candidate_verified",
            }
        )
        upsert_qa_item(store, state.campaign_id, direct_item)
        (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
        (camp_dir / "candidates" / f"{forged_manifest.candidate_id}.json").write_text(
            forged_manifest.model_dump_json(indent=2), encoding="utf-8"
        )
        with pytest.raises(PolicyImmutabilityError):
            accept_candidate_to_qa(
                camp_dir, candidate_id=forged_manifest.candidate_id, repo_root=repo
            )
        reeval = reevaluate_qa_item(camp_dir, item_id=direct_item.item_id, repo_root=repo)
        assert reeval["evaluated_candidates"][0]["status"] == "rejected"
        assert reeval["evaluated_candidates"][0]["audit_passed"] is False

    # Verify non-tests/ locked-test ancestor shadow module (custom_tests/sub/src.py) & deletion
    custom_repo = tmp_path / "repo_w7_custom_anc"
    custom_repro = f"{sys.executable} -m pytest -q custom_tests/sub/test_custom.py"
    custom_base = _init_git_repo(
        custom_repo,
        {
            "src/__init__.py": "",
            "src/pkg/__init__.py": "def compute() -> int:\n    return 1\n",
            "custom_tests/sub/test_custom.py": (
                "from src.pkg import compute\ndef test_c() -> None:\n    assert compute() == 2\n"
            ),
            "custom_tests/sub/existing_helper.py": "HELPER = 1\n",
        },
    )
    custom_src_hijack_sha = _commit_branch(
        custom_repo,
        "qa/custom-src-hijack",
        {
            "custom_tests/sub/src.py": (
                "import pathlib\n"
                '__path__ = [str(pathlib.Path(__file__).with_name("_fake"))]\n'
            ),
            "custom_tests/sub/_fake/pkg.py": "def compute() -> int:\n    return 2\n",
        },
        base_ref=custom_base,
    )
    with pytest.raises(PolicyImmutabilityError):
        audit_candidate_forensic(
            custom_repo,
            manifest=CandidateManifest(
                candidate_id="cand-custom-src",
                item_id="qa-custom-src",
                campaign_id="camp-custom-src",
                base_sha=custom_base,
                candidate_sha=custom_src_hijack_sha,
                branch_name="qa/custom-src-hijack",
                rerun_command=custom_repro,
                baseline_passed=False,
                candidate_passed=True,
                audit_passed=True,
                author_model="hydrogen",
                auditor_model="pro",
                status="candidate_verified",
            ),
            base_sha=custom_base,
            candidate_sha=custom_src_hijack_sha,
            repro_command=custom_repro,
        )

    # Deletion of non-test module under locked-test ancestor is also blocked
    subprocess.run(
        ["git", "-C", str(custom_repo), "checkout", "-B", "qa/custom-del", custom_base],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(custom_repo), "rm", "custom_tests/sub/existing_helper.py"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(custom_repo), "commit", "-m", "delete helper"],
        check=True,
        capture_output=True,
    )
    del_sha = subprocess.run(
        ["git", "-C", str(custom_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(custom_repo), "checkout", "main"],
        check=True,
        capture_output=True,
    )
    with pytest.raises(PolicyImmutabilityError):
        audit_candidate_forensic(
            custom_repo,
            manifest=CandidateManifest(
                candidate_id="cand-custom-del",
                item_id="qa-custom-del",
                campaign_id="camp-custom-del",
                base_sha=custom_base,
                candidate_sha=del_sha,
                branch_name="qa/custom-del",
                rerun_command=custom_repro,
                baseline_passed=False,
                candidate_passed=True,
                audit_passed=True,
                author_model="hydrogen",
                auditor_model="pro",
                status="candidate_verified",
            ),
            base_sha=custom_base,
            candidate_sha=del_sha,
            repro_command=custom_repro,
        )

    tip_before_ok = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "qa/autopilot"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert tip_before_ok == base_sha

    # Positive control: legitimate src/ package edit passes QARepairLoop & accept_candidate_to_qa
    camp_ok = tmp_path / "camp_w7_f1_ok"
    state_ok = _make_state(camp_ok, base_sha, campaign_id="qa-w7-f1-ok")
    store_ok = open_campaign_store(camp_ok, state_ok, repo_root=repo)
    ok_item = QAFailureItem(
        item_id="qa-w7-src-ok",
        dedup_key="CB-01:w7:src_ok",
        case_id="CB-01",
        subsystem="app",
        normalized_signature="src_ok",
        severity="P1",
        state="reproduced",
        summary="compute returns 1 instead of 2",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=repro_cmd,
        repro_test_path="tests/unit/test_app_logic.py",
        repro_test_hash=repro_hash,
    )
    upsert_qa_item(store_ok, state_ok.campaign_id, ok_item)
    res_ok = QARepairLoop(
        campaign_dir=camp_ok,
        repo_root=repo,
        max_parallel=1,
        auto_accept=True,
        repairer_fn=lambda wt, it: {
            "src/pkg/__init__.py": "from src.pkg.calc import compute\n__all__ = ['compute']\n",
            "src/pkg/calc.py": "def compute() -> int:\n    return 2\n",
        },
    ).run()
    assert len(res_ok["accepted_candidates"]) == 1, res_ok
    accepted_item = get_qa_item(store_ok, state_ok.campaign_id, "qa-w7-src-ok")
    assert accepted_item is not None and accepted_item.state == "accepted_qa"


# ---------------------------------------------------------------------------
# Wave 7 Finding 2 (P1): import_failures_jsonl_into_store preserves repro_command
# ---------------------------------------------------------------------------


def test_import_failures_jsonl_preserves_sqlite_repro_command_and_last_seen_sha(
    tmp_path: Path,
) -> None:
    camp_dir = tmp_path / "camp_w7_repro_preserve"
    state = _make_state(camp_dir, "sha_old", campaign_id="qa-w7-f2")
    store = open_campaign_store(camp_dir, state)

    t1 = utc_now() - timedelta(minutes=5)
    t2 = utc_now()

    it = record_failure_observation(
        store,
        state,
        case_id="CB-01",
        subsystem="web",
        raw_signature="missing_repro_clobber",
        severity="P1",
        summary="Failure before repro_command attached",
        sha="sha_old",
        repro_command="",
        observed_at=t1,
    )
    sync_failures_jsonl_from_store(store, state.campaign_id, camp_dir)

    # Update SQLite directly without re-syncing failures.jsonl
    upsert_qa_item(
        store,
        state.campaign_id,
        it.model_copy(
            update={
                "repro_command": "pytest -q tests/unit/test_x.py",
                "state": "reproduced",
                "last_seen_sha": "sha_newer",
                "last_seen_at": t2,
            }
        ),
    )

    import_failures_jsonl_into_store(store, state, camp_dir)
    loaded = get_qa_item(store, state.campaign_id, it.item_id)
    assert loaded is not None
    assert loaded.repro_command == "pytest -q tests/unit/test_x.py"
    assert loaded.state == "reproduced"
    assert loaded.last_seen_sha == "sha_newer"

    # Also verify SQLite empty repro_command gets populated when failures.jsonl provides one
    it2 = record_failure_observation(
        store,
        state,
        case_id="CB-02",
        subsystem="web",
        raw_signature="jsonl_provides_repro",
        severity="P1",
        summary="JSONL fills empty repro_command",
        sha="sha_old",
        repro_command="",
        observed_at=t1,
    )
    failures_path = camp_dir / "failures.jsonl"
    rows = [json.loads(line) for line in failures_path.read_text(encoding="utf-8").splitlines()]
    rows.append(
        json.loads(
            it2.model_copy(update={"repro_command": "pytest -q tests/unit/test_y.py"})
            .model_dump_json()
        )
    )
    failures_path.write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
    )
    import_failures_jsonl_into_store(store, state, camp_dir)
    loaded2 = get_qa_item(store, state.campaign_id, it2.item_id)
    assert loaded2 is not None
    assert loaded2.repro_command == "pytest -q tests/unit/test_y.py"


# ---------------------------------------------------------------------------
# Wave 7 Finding 3 (P2): Zero-diff / identical-content edit does not crash
# ---------------------------------------------------------------------------


def test_repair_loop_zero_diff_identical_content_uses_no_patch_produced_without_crashing(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_w7_noop"
    orig_mod = "def val() -> int:\n    return 1\n"
    base_sha = _init_git_repo(
        repo,
        {
            "src/__init__.py": "",
            "src/mod.py": orig_mod,
            "tests/unit/test_mod.py": (
                "from src.mod import val\ndef test_val() -> None:\n    assert val() == 2\n"
            ),
        },
    )
    subprocess.run(
        ["git", "branch", "qa/autopilot"], cwd=str(repo), check=True, capture_output=True
    )

    camp_dir = tmp_path / "camp_w7_noop"
    state = _make_state(camp_dir, base_sha, campaign_id="qa-w7-f3")
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    item = QAFailureItem(
        item_id="qa-w7-noop-1",
        dedup_key="CB-01:mod:noop",
        case_id="CB-01",
        subsystem="mod",
        normalized_signature="noop",
        severity="P1",
        state="reproduced",
        summary="val returns 1 instead of 2",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=f"{sys.executable} -m pytest -q tests/unit/test_mod.py",
        repro_test_path="tests/unit/test_mod.py",
    )
    upsert_qa_item(store, state.campaign_id, item)

    loop = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo,
        max_parallel=1,
        max_attempts=2,
        auto_accept=True,
        repairer_fn=lambda wt, it: {"src/mod.py": orig_mod},
    )

    res1 = loop.run()
    assert res1["accepted_candidates"] == []
    assert res1["worker_results"][0]["outcome"] == "no_patch_produced"
    after1 = get_qa_item(store, state.campaign_id, item.item_id)
    assert after1 is not None
    assert after1.state == "reproduced"
    assert after1.attempts == 1

    res2 = loop.run()
    assert res2["accepted_candidates"] == []
    assert res2["worker_results"][0]["outcome"] == "no_patch_produced"
    after2 = get_qa_item(store, state.campaign_id, item.item_id)
    assert after2 is not None
    assert after2.state == "parked"
    assert after2.attempts == 2





