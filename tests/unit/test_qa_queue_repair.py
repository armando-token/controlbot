"""Deterministic N1 unit tests for M2 QA queue, log ingestion, and 7-step repair governance."""

from __future__ import annotations

import http.server
import json
import os
import sqlite3
import subprocess
import sys
import threading
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from src.contracts.common import utc_now
from src.factory.db import FactoryStore
from src.factory.engine import EvalResult, FactoryEngine
from src.factory.errors import IsolationBoundaryError, PolicyImmutabilityError
from src.factory.models import (
    BacklogItem,
    CandidatePatch,
    CycleBudget,
    FactoryStatus,
    compute_proposal_hash,
)
from src.qa.cli import main
from src.qa.models import (
    CampaignState,
    CandidateManifest,
    QAFailureItem,
    QARollbackManifest,
    RunRecord,
)
from src.qa.queue import (
    compute_same_sha_passes,
    get_qa_item,
    import_failures_jsonl_into_store,
    ingest_sanitized_logs,
    list_qa_items,
    normalize_failure_signature,
    open_campaign_store,
    persist_run_record,
    record_failure_observation,
    record_item_probe_outcome,
    resume_campaign,
    save_campaign_state,
    sync_failures_jsonl_from_store,
    transition_qa_item_state,
    upsert_qa_item,
)
from src.qa.repair_loop import (
    QARepairLoop,
    accept_candidate_to_qa,
    audit_candidate_forensic,
    check_cross_model_governance,
    infer_write_area,
    validate_campaign_isolation,
)
from src.storage.redaction import contains_unredacted_secret_strict


def _init_git_repo(repo_dir: Path, files: dict[str, str] | None = None) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.email", "qa-unit@example.local"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "QA Unit"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    seed = files or {
        "app_mod.py": "def val() -> int:\n    return 0\n",
        "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
        "test_repro.py": (
            "from app_mod import val\ndef test_repro() -> None:\n    assert val() == 1\n"
        ),
    }
    for rel, content in seed.items():
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
    subprocess.run(
        ["git", "branch", "qa/autopilot"],
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
    repo_dir: Path, branch: str, files: dict[str, str], *, base_ref: str = "main"
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
        ["git", "checkout", "qa/autopilot"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return sha


def _make_state(camp_dir: Path, base_sha: str) -> CampaignState:
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-unit-camp",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        qa_branch="qa/autopilot",
        catalog_hash="cat123",
        criteria_hash="crit123",
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)
    return state


@pytest.mark.n1
def test_models_backward_compatibility_and_strict_extra_forbid() -> None:
    cand = CandidateManifest(
        candidate_id="cand-1",
        item_id="item-1",
        campaign_id="camp-1",
        base_sha="abc123",
        branch_name="qa/cand-1",
        rerun_command="pytest -q",
        baseline_passed=False,
        candidate_passed=True,
        author_model="hydrogen",
        auditor_model="pro",
    )
    assert cand.author_model == "hydrogen"
    assert cand.auditor_model == "pro"
    with pytest.raises(ValidationError):
        CandidateManifest.model_validate({**cand.model_dump(), "unknown_extra": 1})

    rb = QARollbackManifest(
        candidate_id="cand-1",
        item_id="item-1",
        campaign_id="camp-1",
        qa_branch="qa/autopilot",
        previous_accepted_sha="abc123",
        rolled_back_sha="def456",
        restore_command="git reset --hard abc123",
    )
    assert rb.previous_accepted_sha == "abc123"


@pytest.mark.n1
def test_factory_store_qa_schema_and_runtime_table_isolation(tmp_path: Path) -> None:
    camp_dir = tmp_path / "camp_db"
    state = _make_state(camp_dir, "abc123")
    store = open_campaign_store(camp_dir, state)
    assert store.db_path == (camp_dir / "factory.sqlite3").resolve()
    assert (store.db_path.stat().st_mode & 0o777) == 0o600

    with store.read_tx() as conn:
        tables = {
            str(r["name"])
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        }
    assert {
        "factory_backlog",
        "factory_leases",
        "factory_budgets",
        "factory_manifests",
        "qa_campaigns",
        "qa_items",
        "qa_run_records",
        "qa_log_cursors",
        "qa_candidates",
    }.issubset(tables)

    # Budget clamp >= used without resetting counters
    store.ensure_budget(
        CycleBudget(
            budget_id="default",
            max_cycles=3,
            cycles_used=2,
            max_attempts=3,
            attempts_used=2,
        )
    )
    updated = store.update_budget_limits("default", max_cycles=1, max_attempts=1)
    assert updated.max_cycles == 2
    assert updated.max_attempts == 2
    assert updated.cycles_used == 2
    assert updated.attempts_used == 2

    # Reject runtime table collision
    runtime_db = tmp_path / "runtime_collision.sqlite3"
    with sqlite3.connect(runtime_db) as rconn:
        rconn.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY);")
    bad_store = FactoryStore(runtime_db)
    with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
        bad_store.init_db()


@pytest.mark.n1
def test_factory_engine_non_promoting_cycle_and_drift_rebase(tmp_path: Path) -> None:
    repo_dir = tmp_path / "engine_repo"
    base_sha = _init_git_repo(repo_dir)
    store = FactoryStore(tmp_path / "factory.sqlite3")
    engine = FactoryEngine(
        repo_dir, store, base_branch="qa/autopilot", artifacts_dir=tmp_path / "rb"
    )
    store.add_backlog_item(
        BacklogItem(
            item_id="item-eng-1",
            title="Fix val()",
            priority=1,
            hypothesis="Return 1",
            target_metric="failing",
            baseline_repro_cmd="pytest -q test_repro.py",
        )
    )
    files = {"app_mod.py": "def val() -> int:\n    return 1\n"}
    patch = CandidatePatch(
        candidate_id="cand-eng-1",
        item_id="item-eng-1",
        branch_name="qa/cand-eng-1",
        hypothesis="Return 1",
        target_metric="failing",
        proposal_hash=compute_proposal_hash(
            item_id="item-eng-1", target_metric="failing", files_to_modify=files
        ),
        files_to_modify=files,
        author_model="hydrogen",
        auditor_model="pro",
    )

    def _eval(path: Path) -> EvalResult:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(path)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        p = subprocess.run(
            [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_repro.py"],
            cwd=str(path),
            env=env,
            capture_output=True,
            check=False,
        )
        return EvalResult(passed=p.returncode == 0, metric=0.0 if p.returncode == 0 else 1.0)

    res = engine.run_candidate_cycle(
        patch, evaluator=_eval, run_full_pytest=False, promote_to_base=False
    )
    assert res.status == FactoryStatus.PROMOTED
    assert res.candidate_commit is not None and res.candidate_commit != base_sha
    assert subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "qa/autopilot"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip() == base_sha

    # Advance qa/autopilot independently before promotion
    adv_sha = _commit_branch(
        repo_dir,
        "qa/autopilot",
        {"other.py": "def other() -> bool:\n    return True\n"},
        base_ref=base_sha,
    )
    promo = engine.promote_candidate_branch(
        patch,
        candidate_commit=res.candidate_commit,
        base_commit=base_sha,
        target_branch="qa/autopilot",
        evaluator=_eval,
        run_full_pytest=False,
    )
    assert promo.status == FactoryStatus.PROMOTED
    assert promo.candidate_commit is not None and promo.candidate_commit != adv_sha
    assert store.get_latest_manifest("cand-eng-1") is not None
    assert len(store.list_manifests()) == 1


@pytest.mark.n1
def test_queue_dedup_correlation_and_eight_state_lifecycle(tmp_path: Path) -> None:
    camp_dir = tmp_path / "camp_queue"
    state = _make_state(camp_dir, "sha001")
    store = open_campaign_store(camp_dir, state)

    sig1 = normalize_failure_signature(
        "GET /api/v1/threads/missing_x/messages req_a1b2c3d4e5f6 2026-11-27T07:00:00Z -> HTTP 404"
    )
    sig2 = normalize_failure_signature(
        "GET /api/v1/threads/missing_x/messages req_999988887777 2026-11-27T07:05:00Z -> HTTP 404"
    )
    assert sig1 == sig2
    assert "missing_x" in sig1

    be_item = record_failure_observation(
        store,
        state,
        case_id="CB-01",
        subsystem="backend_http",
        raw_signature="GET /api/v1/threads/missing_x/messages req_00001111 -> HTTP 500",
        severity="P1",
        summary="Backend 500 on missing_x",
        run_id="run-1",
        correlation_ids=["req_corr_1111"],
    )
    dup_item = record_failure_observation(
        store,
        state,
        case_id="CB-01",
        subsystem="backend_http",
        raw_signature="GET /api/v1/threads/missing_x/messages req_abcd1234 -> HTTP 500",
        severity="P2",
        summary="Duplicate backend 500",
        run_id="run-2",
        correlation_ids=["req_corr_2222"],
    )
    assert dup_item.item_id == be_item.item_id
    assert dup_item.occurrence_count == 2
    assert dup_item.severity == "P1"
    assert dup_item.run_ids == ["run-1", "run-2"]
    assert dup_item.factory_item_id == f"fb-{be_item.item_id}"

    # Verify backlog row linked and lifecycle transitions enforced
    fb = store.get_backlog_item(str(dup_item.factory_item_id))
    assert fb is not None and fb.status == "paused"
    repro_item = transition_qa_item_state(store, state.campaign_id, be_item.item_id, "reproduced")
    assert repro_item.state == "reproduced"
    fb_after = store.get_backlog_item(str(dup_item.factory_item_id))
    assert fb_after is not None and fb_after.status == "pending"

    with pytest.raises(ValueError, match="Illegal QA item state transition"):
        transition_qa_item_state(store, state.campaign_id, be_item.item_id, "accepted_qa")

    # Alternating pass/fail marks flaky and pauses backlog
    record_item_probe_outcome(
        store, state.campaign_id, be_item.item_id, passed=True, run_id="run-3"
    )
    flaky_item = get_qa_item(store, state.campaign_id, be_item.item_id)
    assert flaky_item is not None and flaky_item.state == "flaky"
    assert flaky_item.flaky_reason
    fb_flaky = store.get_backlog_item(str(dup_item.factory_item_id))
    assert fb_flaky is not None and fb_flaky.status == "paused"


@pytest.mark.n1
def test_log_ingestion_secret_redaction_and_rotation_resume(tmp_path: Path) -> None:
    logs_dir = tmp_path / "external_logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    failures_log = logs_dir / "failures.jsonl"
    rotated_log = logs_dir / "failures.jsonl.1"

    secret_token = "tok_live_super_secret_canary_998877"
    entry_1 = {
        "id": "fail_0001",
        "ts": "2026-11-27T07:00:00Z",
        "source": "backend_http",
        "kind": "http_error",
        "message": f"GET /api/v1/bots/b1?token={secret_token} -> HTTP 500",
        "path": f"/api/v1/bots/b1?token={secret_token}",
        "status_code": 500,
        "request_id": "req_1111aaaa",
    }
    failures_log.write_text(json.dumps(entry_1) + "\n", encoding="utf-8")

    camp_dir = tmp_path / "camp_logs"
    state = _make_state(camp_dir, "sha002")
    store = open_campaign_store(camp_dir, state)

    res1 = ingest_sanitized_logs(
        store, state, logs_dir=logs_dir, campaign_dir=camp_dir, case_id="CB-00"
    )
    assert res1["ingested_count"] == 1
    failures_text = (camp_dir / "failures.jsonl").read_text(encoding="utf-8")
    assert secret_token not in failures_text
    assert not contains_unredacted_secret_strict(failures_text)

    # Rotate log with unread tail + new active entry + correlated frontend error
    entry_tail = {
        "id": "fail_0002",
        "ts": "2026-11-27T07:00:02Z",
        "source": "frontend",
        "kind": "sse_error",
        "message": "SSE dropped during /api/v1/bots/b1",
        "request_id": "req_1111aaaa",
    }
    with failures_log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry_tail) + "\n")
    os.replace(failures_log, rotated_log)

    entry_active = {
        "id": "fail_0003",
        "ts": "2026-11-27T07:00:05Z",
        "source": "routines",
        "kind": "routine_dispatch_error",
        "message": "POST /api/v1/routines/r1 -> HTTP 500",
        "status_code": 500,
        "request_id": "req_2222bbbb",
    }
    failures_log.write_text(json.dumps(entry_active) + "\n", encoding="utf-8")

    # Seed an attempt & dead worker PID & synthetic lease to verify crash-safe resume
    state_with_work = state.model_copy(
        update={
            "attempts": {"item-keep": 2},
            "active_leases": {"item-keep": "lease-synth-4"},
        }
    )
    save_campaign_state(camp_dir, state_with_work, store=store)

    resumed_state, info = resume_campaign(camp_dir, logs_dir=logs_dir)
    assert resumed_state.attempts["item-keep"] == 2
    assert resumed_state.active_leases["item-keep"] == "lease-synth-4"
    assert info["ingested_from_logs"] == 2

    items = list_qa_items(store, state.campaign_id)
    assert len(items) == 3
    fe_item = next(it for it in items if it.subsystem == "frontend")
    be_item = next(it for it in items if it.subsystem == "backend_http")
    assert fe_item.parent_item_id == be_item.item_id
    assert be_item.occurrence_count == 1  # No double-count across rotation


@pytest.mark.n1
def test_governance_rejections_and_forensic_audit_boundaries(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="distinct"):
        check_cross_model_governance("sonnet", "sonnet")
    with pytest.raises(ValueError, match="hydrogen"):
        check_cross_model_governance("sonnet", "hydrogen")
    with pytest.raises(ValueError, match="missing"):
        check_cross_model_governance(None, "pro")

    camp_dir = tmp_path / "camp_gov"
    repo_dir = tmp_path / "gov_repo"
    base_sha = _init_git_repo(repo_dir)
    _make_state(camp_dir, base_sha)

    with pytest.raises(ValueError, match="at most 2 parallel"):
        QARepairLoop(campaign_dir=camp_dir, repo_root=repo_dir, max_parallel=3)

    # Locked repro test tampering rejected
    tamper_sha = _commit_branch(
        repo_dir,
        "qa/cand-tamper",
        {"test_repro.py": "def test_repro() -> None:\n    assert True\n"},
        base_ref=base_sha,
    )
    tamper_man = CandidateManifest(
        candidate_id="cand-tamper",
        item_id="item-tamper",
        campaign_id="qa-unit-camp",
        base_sha=base_sha,
        candidate_sha=tamper_sha,
        branch_name="qa/cand-tamper",
        repro_test_path="test_repro.py",
        rerun_command="pytest -q test_repro.py",
        baseline_passed=False,
        candidate_passed=True,
        author_model="hydrogen",
        auditor_model="pro",
    )
    with pytest.raises(PolicyImmutabilityError, match="locked repro test"):
        audit_candidate_forensic(
            repo_dir,
            manifest=tamper_man,
            base_sha=base_sha,
            candidate_sha=tamper_sha,
            repro_test_path="test_repro.py",
        )

    # Immutable PolicyGuard path rejection inside QARepairLoop -> blocked
    item_pol = QAFailureItem(
        item_id="item-pol",
        dedup_key="CB-00:policy:fix",
        case_id="CB-00",
        subsystem="policy",
        normalized_signature="fix",
        severity="P1",
        state="reproduced",
        summary="Fix policy",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=f"{sys.executable} -m pytest -q test_repro.py",
    )
    store = open_campaign_store(camp_dir, _make_state(camp_dir, base_sha))
    from src.qa.queue import upsert_qa_item

    upsert_qa_item(store, "qa-unit-camp", item_pol)

    def _bad_repairer(wt: Path, it: QAFailureItem) -> dict[str, str]:
        del wt, it
        return {"src/factory/policy.py": "# tampered\n"}

    loop = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo_dir,
        max_parallel=1,
        auto_accept=False,
        repairer_fn=_bad_repairer,
    )
    res = loop.run()
    assert res["worker_results"][0]["outcome"] == "blocked_policy"
    blocked = get_qa_item(store, "qa-unit-camp", "item-pol")
    assert blocked is not None and blocked.state == "blocked"
    assert "core_maintenance_review_required" in str(blocked.blocked_reason)


@pytest.mark.n1
def test_p0_halt_and_stale_lease_fencing_and_write_area_inference(tmp_path: Path) -> None:
    repo_dir = tmp_path / "p0_lease_repo"
    base_sha = _init_git_repo(repo_dir)
    cand_sha = _commit_branch(
        repo_dir,
        "qa/cand-lease",
        {"app_mod.py": "def val() -> int:\n    return 1\n"},
        base_ref=base_sha,
    )
    camp_dir = tmp_path / "camp_p0_lease"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state)

    # Infer write_area from test_repro.py import
    item_probe = QAFailureItem(
        item_id="item-wa",
        dedup_key="CB-00:sub:sig",
        case_id="CB-00",
        subsystem="sub",
        normalized_signature="sig",
        severity="P1",
        state="reproduced",
        summary="Import test",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command="pytest -q test_repro.py",
    )
    assert infer_write_area(item_probe, repo_root=repo_dir) == "app_mod"

    # Stale lease fencing on accept
    store.add_backlog_item(
        BacklogItem(
            item_id="fb-item-stale",
            title="Stale",
            priority=1,
            hypothesis="h",
            target_metric="m",
            baseline_repro_cmd="pytest -q",
        )
    )
    l1 = store.acquire_lease("fb-item-stale", "w1")
    store.release_lease(l1.lease_id, l1.generation)
    l2 = store.acquire_lease("fb-item-stale", "w2")
    assert l2.generation == 2

    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    (camp_dir / "candidates" / "cand-stale.json").write_text(
        CandidateManifest(
            candidate_id="cand-stale",
            item_id="item-stale",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=cand_sha,
            branch_name="qa/cand-lease",
            rerun_command="pytest -q test_repro.py",
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            lease_id=l1.lease_id,
            lease_generation=l1.generation,
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Stale lease generation"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-stale", repo_root=repo_dir)

    # P0 incident halts QARepairLoop
    record_failure_observation(
        store,
        state,
        case_id="CB-06",
        subsystem="isolation",
        raw_signature="live_db_leak_risk",
        severity="P0",
        summary="Live DB leak detected",
        initial_state="reproduced",
    )
    loop = QARepairLoop(campaign_dir=camp_dir, repo_root=repo_dir, max_parallel=1)
    with pytest.raises(RuntimeError, match="halted_p0"):
        loop.run()
    reloaded = CampaignState.model_validate_json(
        (camp_dir / "campaign.json").read_text(encoding="utf-8")
    )
    assert reloaded.status == "halted_p0"


@pytest.mark.n1
def test_isolation_pre_network_and_report_dod_stats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_dir = tmp_path / "iso_repo"
    base_sha = _init_git_repo(repo_dir)
    camp_dir = tmp_path / "camp_dod"
    state = _make_state(camp_dir, base_sha)
    store = open_campaign_store(camp_dir, state)

    # Reject live :8000 and live DB path pre-network
    with pytest.raises(IsolationBoundaryError, match="forbidden"):
        validate_campaign_isolation(
            camp_dir, repo_root=repo_dir, target_url="http://127.0.0.1:8000"
        )
    monkeypatch.setenv("GROKBOT_" + "DB_PATH", str(repo_dir / "var" / "controlbot.sqlite3"))
    with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
        validate_campaign_isolation(camp_dir, repo_root=repo_dir)
    monkeypatch.delenv("GROKBOT_" + "DB_PATH", raising=False)

    # Persist 3 passing RunRecords on base_sha and verify DoD report metrics
    runs: list[RunRecord] = []
    for idx, dur in enumerate((10.0, 20.0, 45.0), start=1):
        rec = RunRecord(
            campaign_id=state.campaign_id,
            case_id="CB-00",
            run_id=f"run-dod-{idx}",
            base_sha=base_sha,
            lane="local_deterministic",
            backend_mode="emulated",
            started_at=utc_now(),
            finished_at=utc_now(),
            duration_ms=dur,
            passed=True,
            assertions={"health": True},
        )
        persist_run_record(store, camp_dir, rec)
        runs.append(rec)
    assert compute_same_sha_passes(runs, base_sha) == 3

    assert main(["report", "--campaign-dir", str(camp_dir), "--repo-root", str(repo_dir)]) == 0
    daily = (camp_dir / "daily_report.md").read_text(encoding="utf-8")
    assert "Open P0**: `0`" in daily
    assert "Open P1**: `0`" in daily
    assert "Same-SHA Passes**: `3`" in daily
    assert "Runs**: `3`" in daily
    assert "Median Duration (ms)**: `20.0`" in daily
    assert "P95 Duration (ms)**: `45.0`" in daily


@pytest.mark.n1
def test_unimplemented_scenarios_and_pending_n3_cb13_never_emit_passed_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_dir = tmp_path / "stub_check_repo"
    base_sha = _init_git_repo(repo_dir)
    camp_dir = tmp_path / "camp_no_stub"
    _make_state(camp_dir, base_sha)

    # Ensure CB-01, CB-02 (no fixture), CB-09, CB-10, CB-13 never emit passed=True without runner
    rc = main(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-01,CB-02,CB-09,CB-10,CB-13",
            "--repo-root",
            str(repo_dir),
        ]
    )
    assert rc == 0
    runs = [
        RunRecord.model_validate_json(line)
        for line in (camp_dir / "runs.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    by_case = {r.case_id: r for r in runs}
    assert set(by_case) == {"CB-01", "CB-02", "CB-09", "CB-10", "CB-13"}
    for case_id, rec in by_case.items():
        assert rec.passed is False, f"{case_id} must NOT emit stub passed=True"
        assert rec.blocked_reason and rec.blocked_reason.strip()
        assert any(v is False for v in rec.assertions.values())

    # Specifically verify CB-13 with non-READY n3_probe always sets passed=False + blocked_reason
    from src.n3_probe import run_n3_probe

    mock_n3 = run_n3_probe().model_copy(
        update={
            "overall_status": "PENDING_N3_LINUX_ENV",
            "linux_os_ready": False,
            "network_isolation_ready": False,
            "local_llm_ready": False,
            "evidence_notes": ["Mocked pending N3"],
        }
    )
    monkeypatch.setattr("src.qa.cli.run_n3_probe", lambda: mock_n3)
    camp_cb13 = tmp_path / "camp_cb13_pending"
    _make_state(camp_cb13, base_sha)
    assert (
        main(
            [
                "scan",
                "--campaign-dir",
                str(camp_cb13),
                "--cases",
                "CB-13",
                "--repo-root",
                str(repo_dir),
            ]
        )
        == 0
    )
    cb13_rec = RunRecord.model_validate_json(
        (camp_cb13 / "runs.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert cb13_rec.passed is False
    assert cb13_rec.assertions.get("n3_ready") is False
    assert "PENDING_N3_LINUX_ENV" in str(cb13_rec.blocked_reason)

    # Even with cb_valve_104.json present, CB-02 without src.qa.scenarios must NOT emit passed=True
    camp_cb02 = tmp_path / "camp_cb02_no_runner"
    _make_state(camp_cb02, base_sha)
    (camp_cb02 / "fixtures").mkdir(parents=True, exist_ok=True)
    (camp_cb02 / "fixtures" / "cb_valve_104.json").write_text(
        json.dumps({"fixture_version": "cb-valve-104-v9999", "active_price": "129.50"}),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "scan",
                "--campaign-dir",
                str(camp_cb02),
                "--cases",
                "CB-02",
                "--repo-root",
                str(repo_dir),
            ]
        )
        == 0
    )
    cb02_rec = RunRecord.model_validate_json(
        (camp_cb02 / "runs.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert cb02_rec.passed is False
    assert cb02_rec.fixture_version == "cb-valve-104-v9999"
    assert cb02_rec.blocked_reason and "CB-02" in cb02_rec.blocked_reason


@pytest.mark.n1
def test_raw_secret_canary_in_logs_and_api_triggers_halted_p0_without_leak(
    tmp_path: Path,
) -> None:
    camp_dir = tmp_path / "camp_secret_p0"
    logs_dir = tmp_path / "logs_secret"
    logs_dir.mkdir(parents=True, exist_ok=True)
    state = _make_state(camp_dir, "sha_sec_1")
    store = open_campaign_store(camp_dir, state)

    canaries = (
        "CANARY_SECRET_BEARER_9911",
        "CANARY_QUERY_TOK_8822",
        "CANARY_NESTED_APIKEY_7733",
        "CANARY_ACCESS_TOKEN_6644",
    )
    (logs_dir / "failures.jsonl").write_text(
        json.dumps(
            {
                "id": "fail-sec-1",
                "source": "backend_http",
                "kind": "request_error",
                "message": f"Auth failed: Bearer {canaries[0]}",
                "url": f"http://127.0.0.1:9000/api/run?token={canaries[1]}&foo=bar",
                "meta": {"nested": {"apiKey": canaries[2], "accessToken": canaries[3]}},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    res = ingest_sanitized_logs(store, state, logs_dir=logs_dir, campaign_dir=camp_dir)
    assert res["halted_p0"] is True
    assert len(res["p0_items"]) == 1
    reloaded = CampaignState.model_validate_json(
        (camp_dir / "campaign.json").read_text(encoding="utf-8")
    )
    assert reloaded.status == "halted_p0"
    assert reloaded.p0_halt_reason

    persisted_blob = (camp_dir / "failures.jsonl").read_text(encoding="utf-8") + (
        camp_dir / "campaign.json"
    ).read_text(encoding="utf-8")
    for canary in canaries:
        assert canary not in persisted_blob
    assert "[REDACTED]" in persisted_blob

    # Also test raw secret canary from /api/v1/diagnostics/failures with logs_dir=None
    api_canary = "CANARY_DIAG_API_BEARER_5555"

    class _DiagHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = json.dumps(
                {
                    "failures": [
                        {
                            "id": "diag-api-sec-1",
                            "source": "backend_http",
                            "kind": "http_error",
                            "message": f"Authorization: Bearer {api_canary}",
                            "status_code": 400,
                        }
                    ]
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = http.server.HTTPServer(("127.0.0.1", 0), _DiagHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        camp_api = tmp_path / "camp_api_sec_p0"
        st_api = _make_state(camp_api, "sha_api_sec")
        store_api = open_campaign_store(camp_api, st_api)
        api_res = ingest_sanitized_logs(
            store_api,
            st_api,
            logs_dir=None,
            campaign_dir=camp_api,
            target_url=f"http://127.0.0.1:{server.server_address[1]}",
        )
        assert api_res["halted_p0"] is True
        assert api_canary not in (camp_api / "failures.jsonl").read_text(encoding="utf-8")
        assert (
            CampaignState.model_validate_json(
                (camp_api / "campaign.json").read_text(encoding="utf-8")
            ).status
            == "halted_p0"
        )
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.n1
def test_ingest_truncate_to_zero_resets_offset_and_logs_dir_none_persists_seen_ids(
    tmp_path: Path,
) -> None:
    camp_dir = tmp_path / "camp_trunc"
    logs_dir = tmp_path / "logs_trunc"
    logs_dir.mkdir(parents=True, exist_ok=True)
    state = _make_state(camp_dir, "sha_trunc")
    store = open_campaign_store(camp_dir, state)

    log_path = logs_dir / "failures.jsonl"
    log_path.write_text(
        json.dumps({"id": "e1", "source": "backend", "kind": "err", "message": "first error"})
        + "\n",
        encoding="utf-8",
    )
    r1 = ingest_sanitized_logs(store, state, logs_dir=logs_dir, campaign_dir=camp_dir)
    assert r1["ingested_count"] == 1
    assert r1["cursors"]["failures.jsonl"] > 0

    # Truncate in-place to 0 bytes -> ingest -> write longer line -> must ingest new line
    log_path.write_text("", encoding="utf-8")
    r_empty = ingest_sanitized_logs(store, state, logs_dir=logs_dir, campaign_dir=camp_dir)
    assert r_empty["ingested_count"] == 0
    assert r_empty["cursors"]["failures.jsonl"] == 0

    log_path.write_text(
        json.dumps(
            {
                "id": "e2",
                "source": "backend",
                "kind": "err",
                "message": "much longer post-truncation failure entry exceeding old offset",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    r2 = ingest_sanitized_logs(store, state, logs_dir=logs_dir, campaign_dir=camp_dir)
    assert r2["ingested_count"] == 1

    # Polling diagnostics API twice with logs_dir=None must persist seen_ids in qa_log_cursors
    class _PollHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = json.dumps(
                {
                    "failures": [
                        {
                            "id": "api-only-1",
                            "source": "backend_http",
                            "kind": "http_500",
                            "message": "API boom",
                            "status_code": 500,
                        }
                    ]
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = http.server.HTTPServer(("127.0.0.1", 0), _PollHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        camp_poll = tmp_path / "camp_api_poll"
        st_poll = _make_state(camp_poll, "sha_poll")
        store_poll = open_campaign_store(camp_poll, st_poll)
        url = f"http://127.0.0.1:{server.server_address[1]}"
        p1 = ingest_sanitized_logs(
            store_poll, st_poll, logs_dir=None, campaign_dir=camp_poll, target_url=url
        )
        p2 = ingest_sanitized_logs(
            store_poll, st_poll, logs_dir=None, campaign_dir=camp_poll, target_url=url
        )
        assert p1["ingested_count"] == 1
        assert p2["ingested_count"] == 0
        items = list_qa_items(store_poll, st_poll.campaign_id)
        assert len(items) == 1
        assert items[0].occurrence_count == 1
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.n1
def test_import_failures_jsonl_preserves_sqlite_progression_and_resume_parks_in_repair(
    tmp_path: Path,
) -> None:
    camp_dir = tmp_path / "camp_preserve"
    state = _make_state(camp_dir, "sha_pres")
    store = open_campaign_store(camp_dir, state)

    flaky_item = record_failure_observation(
        store,
        state,
        case_id="CB-01",
        subsystem="chat",
        raw_signature="flaky_sig",
        severity="P1",
        summary="Flaky item",
        initial_state="reproduced",
        repro_test_path="test_flaky.py",
    )
    blocked_item = record_failure_observation(
        store,
        state,
        case_id="CB-02",
        subsystem="policy",
        raw_signature="blocked_sig",
        severity="P1",
        summary="Blocked item",
        initial_state="reproduced",
    )
    crash_item = record_failure_observation(
        store,
        state,
        case_id="CB-03",
        subsystem="runner",
        raw_signature="crash_sig",
        severity="P1",
        summary="Crash item",
        initial_state="reproduced",
    )
    # Write stale failures.jsonl where all items are still "reproduced"
    sync_failures_jsonl_from_store(store, state.campaign_id, camp_dir)

    # Progress SQLite states without syncing failures.jsonl
    record_item_probe_outcome(store, state.campaign_id, flaky_item.item_id, passed=True)
    transition_qa_item_state(
        store,
        state.campaign_id,
        blocked_item.item_id,
        "blocked",
        blocked_reason="core_maintenance_review_required: policy",
    )
    lease = store.acquire_lease(crash_item.factory_item_id or f"fb-{crash_item.item_id}", "w-dead")
    transition_qa_item_state(
        store,
        state.campaign_id,
        crash_item.item_id,
        "in_repair",
        attempts_delta=2,
        repro_test_hash="deadbeef12345678",
        locked_criterion_hash="cafebabe12345678",
    )

    import_failures_jsonl_into_store(store, state, camp_dir)
    flaky_after = get_qa_item(store, state.campaign_id, flaky_item.item_id)
    blocked_after = get_qa_item(store, state.campaign_id, blocked_item.item_id)
    crash_after = get_qa_item(store, state.campaign_id, crash_item.item_id)
    assert flaky_after is not None and flaky_after.state == "flaky"
    assert flaky_after.pass_count == 1
    assert flaky_after.flaky_reason
    assert blocked_after is not None and blocked_after.state == "blocked"
    assert blocked_after.blocked_reason == "core_maintenance_review_required: policy"
    assert crash_after is not None and crash_after.state == "in_repair"
    assert crash_after.repro_test_hash == "deadbeef12345678"
    assert crash_after.locked_criterion_hash == "cafebabe12345678"

    # Simulate dead worker PID + active lease on resume -> exhausted in_repair transitions to parked
    crash_state = state.model_copy(
        update={
            "active_worker_pids": {crash_item.item_id: 999999},
            "active_leases": {crash_item.item_id: lease.lease_id},
        }
    )
    save_campaign_state(camp_dir, crash_state, store=store)
    resumed_state, resume_info = resume_campaign(camp_dir)
    assert lease.lease_id in resume_info["expired_leases"]
    assert crash_item.item_id not in resumed_state.active_worker_pids
    parked = get_qa_item(store, state.campaign_id, crash_item.item_id)
    assert parked is not None and parked.state == "parked"


@pytest.mark.n1
def test_list_qa_items_sorts_occurrence_desc_before_first_seen_asc(tmp_path: Path) -> None:
    camp_dir = tmp_path / "camp_sort"
    state = _make_state(camp_dir, "sha_sort")
    store = open_campaign_store(camp_dir, state)
    t0 = utc_now() - timedelta(minutes=10)
    t1 = utc_now()

    item_old = QAFailureItem(
        item_id="qa-old-1",
        dedup_key="CB-01:web:old",
        case_id="CB-01",
        subsystem="web",
        normalized_signature="old",
        severity="P1",
        state="reproduced",
        summary="Old 1x failure",
        first_seen_sha="sha_sort",
        last_seen_sha="sha_sort",
        environment_lane="local_deterministic",
        occurrence_count=1,
        first_seen_at=t0,
        last_seen_at=t0,
    )
    item_hot = QAFailureItem(
        item_id="qa-hot-5",
        dedup_key="CB-01:web:hot",
        case_id="CB-01",
        subsystem="web",
        normalized_signature="hot",
        severity="P1",
        state="reproduced",
        summary="Hot 5x failure",
        first_seen_sha="sha_sort",
        last_seen_sha="sha_sort",
        environment_lane="local_deterministic",
        occurrence_count=5,
        first_seen_at=t1,
        last_seen_at=t1,
    )
    upsert_qa_item(store, state.campaign_id, item_old)
    upsert_qa_item(store, state.campaign_id, item_hot)

    ordered = list_qa_items(store, state.campaign_id)
    assert [it.item_id for it in ordered] == ["qa-hot-5", "qa-old-1"]


@pytest.mark.n1
def test_ingest_same_batch_cross_file_correlation_and_fail_closed_redaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    camp_dir = tmp_path / "camp_corr_batch"
    logs_dir = tmp_path / "logs_corr_batch"
    logs_dir.mkdir(parents=True, exist_ok=True)
    state = _make_state(camp_dir, "sha_corr")
    store = open_campaign_store(camp_dir, state)

    # frontend_errors.jsonl is read BEFORE requests.jsonl in read_sanitized_logs
    (logs_dir / "frontend_errors.jsonl").write_text(
        json.dumps(
            {
                "id": "fe-batch-1",
                "source": "frontend",
                "kind": "sse_error",
                "message": "SSE dropped",
                "request_id": "req_batch_corr_99",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (logs_dir / "requests.jsonl").write_text(
        json.dumps(
            {
                "id": "be-batch-1",
                "source": "backend_http",
                "kind": "http_response",
                "method": "GET",
                "path": "/api/v1/runs",
                "status_code": 500,
                "message": "Internal error",
                "request_id": "req_batch_corr_99",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    ingest_sanitized_logs(store, state, logs_dir=logs_dir, campaign_dir=camp_dir)
    items = list_qa_items(store, state.campaign_id)
    fe_item = next(it for it in items if it.subsystem == "frontend")
    be_item = next(it for it in items if it.subsystem == "backend_http")
    assert fe_item.parent_item_id == be_item.item_id

    # Fail closed if assert_strictly_redacted raises ValueError on diagnostics API
    class _FailClosedHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = json.dumps({"failures": [{"id": "d1", "message": "x"}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = http.server.HTTPServer(("127.0.0.1", 0), _FailClosedHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        def _boom(*args: object, **kwargs: object) -> object:
            del args, kwargs
            raise ValueError("Refusing to persist unredacted secret in diagnostics_api.")

        monkeypatch.setattr("src.qa.queue.assert_strictly_redacted", _boom)
        with pytest.raises(ValueError, match="unredacted secret"):
            ingest_sanitized_logs(
                store,
                state,
                logs_dir=None,
                campaign_dir=camp_dir,
                target_url=f"http://127.0.0.1:{server.server_address[1]}",
            )
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.n1
def test_compute_run_stats_ignores_stale_same_sha_passes_cache(tmp_path: Path) -> None:
    repo_dir = tmp_path / "stats_repo"
    base_sha = _init_git_repo(repo_dir)
    camp_dir = tmp_path / "camp_stale_stats"
    state = _make_state(camp_dir, base_sha).model_copy(
        update={"same_sha_passes": {base_sha: 2}}
    )
    save_campaign_state(camp_dir, state)
    store = open_campaign_store(camp_dir, state)

    for idx, passed in enumerate((True, True, False), start=1):
        persist_run_record(
            store,
            camp_dir,
            RunRecord(
                campaign_id=state.campaign_id,
                case_id="CB-00",
                run_id=f"run-stale-{idx}",
                base_sha=base_sha,
                lane="local_deterministic",
                backend_mode="emulated",
                started_at=utc_now(),
                finished_at=utc_now(),
                duration_ms=12.0,
                passed=passed,
                assertions={"health": passed},
            ),
        )

    assert main(["report", "--campaign-dir", str(camp_dir), "--repo-root", str(repo_dir)]) == 0
    daily = (camp_dir / "daily_report.md").read_text(encoding="utf-8")
    assert "Same-SHA Passes**: `0`" in daily
