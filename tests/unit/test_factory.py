"""N1 unit tests for the isolated M7 local software factory (F16)."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from src.factory import (
    BacklogItem,
    CandidatePatch,
    CycleBudget,
    DuplicateProposalError,
    EvalResult,
    FactoryEngine,
    FactoryLeaseError,
    FactoryStatus,
    FactoryStore,
    IsolationBoundaryError,
    PolicyGuard,
    PolicyImmutabilityError,
    compute_proposal_hash,
    open_factory_connection,
    rollback_from_manifest,
)
from src.factory.__main__ import main as factory_cli_main
from src.storage import StorageRepo


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def _init_git_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", str(repo_dir)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.name", "Factory Test"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.email", "factory@test.local"],
        check=True,
        capture_output=True,
    )
    (repo_dir / ".gitignore").write_text(
        "__pycache__/\n*.py[cod]\n.pytest_cache/\n",
        encoding="utf-8",
    )
    (repo_dir / "app.py").write_text(
        "def compute_steps() -> int:\n    return 50\n",
        encoding="utf-8",
    )
    tests_dir = repo_dir / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "test_app.py").write_text(
        "import app\n\ndef test_compute_positive() -> None:\n    assert app.compute_steps() > 0\n",
        encoding="utf-8",
    )
    (repo_dir / "uv.lock").write_text("# lock\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-m", "chore: baseline"],
        check=True,
        capture_output=True,
    )
    return subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.mark.n1
def test_factory_sqlite_wal_permissions_and_lease_persistence(tmp_path: Path) -> None:
    clock = FakeClock()
    state_dir = tmp_path / "factory_state"
    db_path = state_dir / "factory.db"
    store = FactoryStore(db_path, clock=clock)
    store.init_db()

    conn: sqlite3.Connection = open_factory_connection(db_path)
    try:
        jm = str(conn.execute("PRAGMA journal_mode;").fetchone()[0]).lower()
        fk = int(conn.execute("PRAGMA foreign_keys;").fetchone()[0])
        bt = int(conn.execute("PRAGMA busy_timeout;").fetchone()[0])
        assert jm == "wal"
        assert fk == 1
        assert bt >= 5000
    finally:
        conn.close()

    if os.name == "posix":
        assert (state_dir.stat().st_mode & 0o777) == 0o700
        assert (db_path.stat().st_mode & 0o777) == 0o600

    store.add_backlog_item(
        BacklogItem(
            item_id="B-1",
            title="Test item",
            priority=1,
            hypothesis="Reduce scan steps",
            target_metric="scan_steps",
            baseline_repro_cmd="pytest -q",
            max_attempts=3,
        )
    )
    store.ensure_budget(CycleBudget(max_cycles=5, max_attempts=5))

    lease1 = store.acquire_lease("B-1", "worker-a", ttl_s=30.0)
    assert lease1.generation == 1

    # Concurrent active lease acquisition must fail
    with pytest.raises(FactoryLeaseError, match="already leased"):
        store.acquire_lease("B-1", "worker-b", ttl_s=30.0)

    # Advance clock past expiry and re-acquire in a fresh FactoryStore instance
    clock.advance(45.0)
    store2 = FactoryStore(db_path, clock=clock)
    lease2 = store2.acquire_lease("B-1", "worker-b", ttl_s=30.0)
    assert lease2.generation == 2

    # Stale lease1 generation cannot release or renew
    with pytest.raises(FactoryLeaseError):
        store2.release_lease(lease1.lease_id, lease1.generation)
    with pytest.raises(FactoryLeaseError):
        store2.renew_lease(lease1.lease_id, "worker-a", lease1.generation)

    # Commit attempt under lease2 and verify counters persist across re-instantiation
    repo_dir = tmp_path / "repo"
    base_sha = _init_git_repo(repo_dir)
    from src.factory.models import CandidateRunRecord, LessonRecord

    rec = CandidateRunRecord(
        run_id="frun-1",
        candidate_id="c-1",
        item_id="B-1",
        branch_name="factory/c-1",
        base_commit=base_sha,
        proposal_hash="abc123",
        baseline_passed=True,
        regression_passed=False,
        identity_gate_passed=True,
        policy_passed=True,
        status="REJECTED",
        reason="failed gate",
        created_at=clock(),
    )
    lesson = LessonRecord(
        lesson_id="fles-1",
        item_id="B-1",
        candidate_id="c-1",
        proposal_hash="abc123",
        outcome="REJECTED",
        reason="failed gate",
        created_at=clock(),
    )
    store2.commit_candidate_attempt(lease=lease2, record=rec, lesson=lesson, wall_seconds_delta=1.5)

    store3 = FactoryStore(db_path, clock=clock)
    reloaded_item = store3.get_backlog_item("B-1")
    reloaded_budget = store3.get_budget()
    assert reloaded_item is not None
    assert reloaded_item.attempts_used == 1
    assert reloaded_budget.cycles_used == 1
    assert reloaded_budget.attempts_used == 1


@pytest.mark.n1
def test_factory_isolation_boundary_rejects_shared_runtime_db_and_profiles(
    tmp_path: Path,
) -> None:
    runtime_db = tmp_path / "runtime.sqlite3"
    repo = StorageRepo(runtime_db)
    repo.init_db()

    # Reject explicit forbidden runtime DB path
    with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
        FactoryStore(runtime_db, forbidden_db_paths=(runtime_db,))

    # Reject opening an existing runtime DB containing tasks/runs tables even without flag
    store_sneaky = FactoryStore(runtime_db)
    with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
        store_sneaky.init_db()

    # Reject factory DB inside browser profile directories
    with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
        FactoryStore(tmp_path / ".grokbot_profiles" / "factory.db")

    # Reject candidate diff referencing runtime credentials/DB
    lab_repo = tmp_path / "lab_repo"
    base_sha = _init_git_repo(lab_repo)
    f_store = FactoryStore(tmp_path / "isolated_factory.db")
    engine = FactoryEngine(lab_repo, f_store)
    f_store.add_backlog_item(
        BacklogItem(
            item_id="B-ISO",
            title="Attempt credential read",
            priority=1,
            hypothesis="Sneaky read",
            target_metric="steps",
            baseline_repro_cmd="pytest -q",
        )
    )
    cand = CandidatePatch(
        candidate_id="cand-iso-breach",
        item_id="B-ISO",
        branch_name="factory/cand-iso",
        hypothesis="Read GROKBOT_DB_PATH",
        target_metric="steps",
        proposal_hash="iso-hash-1",
        files_to_modify={"app.py": "import os\nDB = os.environ.get('GROKBOT_DB_PATH')\n"},
    )
    with pytest.raises(IsolationBoundaryError, match="ISOLATION_BOUNDARY_VIOLATION"):
        engine.run_candidate_cycle(cand)
    head_after = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "main"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head_after == base_sha


@pytest.mark.n1
@pytest.mark.parametrize(
    "immutable_path",
    [
        "tests/acceptance/test_a01_a14.py",
        "tests/e2e/tier1/test_f01.py",
        "src/contracts/models.py",
        "src/factory/policy.py",
        "src/engine/tool_registry.py",
        "src/custom_policy_override.py",
    ],
)
def test_policy_immutability_guard_blocks_candidate_diffs_and_preserves_main(
    tmp_path: Path,
    immutable_path: str,
) -> None:
    guard = PolicyGuard()
    with pytest.raises(PolicyImmutabilityError, match="POLICY_IMMUTABILITY_VIOLATION"):
        guard.check_candidate_paths([immutable_path])

    lab_repo = tmp_path / "lab_repo"
    base_sha = _init_git_repo(lab_repo)
    store = FactoryStore(tmp_path / "factory.db")
    engine = FactoryEngine(lab_repo, store)
    store.add_backlog_item(
        BacklogItem(
            item_id="B-POL",
            title="Touch protected file",
            priority=1,
            hypothesis="Weaken guard",
            target_metric="steps",
            baseline_repro_cmd="pytest -q",
        )
    )
    cand = CandidatePatch(
        candidate_id="cand-policy-viol",
        item_id="B-POL",
        branch_name="factory/cand-pol",
        hypothesis="Mutate protected path",
        target_metric="steps",
        proposal_hash=f"pol-{immutable_path}",
        files_to_modify={immutable_path: "# tampered\n"},
    )
    with pytest.raises(PolicyImmutabilityError, match="POLICY_IMMUTABILITY_VIOLATION"):
        engine.run_candidate_cycle(cand)

    head_after = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "main"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head_after == base_sha
    assert any(les.outcome == "REJECTED" for les in store.list_lessons())


@pytest.mark.n1
def test_repeat_proposal_guard_and_clean_pause_states(tmp_path: Path) -> None:
    lab_repo = tmp_path / "lab_repo"
    _init_git_repo(lab_repo)
    store = FactoryStore(tmp_path / "factory.db")
    engine = FactoryEngine(
        lab_repo,
        store,
        budget=CycleBudget(max_cycles=2, max_attempts=2),
    )

    # Empty backlog pauses cleanly
    empty_pause = engine.check_pause_state()
    assert empty_pause is not None
    assert empty_pause.status == FactoryStatus.PAUSED_EMPTY_BACKLOG

    store.add_backlog_item(
        BacklogItem(
            item_id="B-DUP",
            title="Test duplicate guard",
            priority=1,
            hypothesis="No improvement",
            target_metric="steps",
            baseline_repro_cmd="pytest -q",
            max_attempts=2,
        )
    )
    files = {"app.py": "def compute_steps() -> int:\n    return 0\n"}
    prop_hash = compute_proposal_hash(
        item_id="B-DUP",
        target_metric="steps",
        files_to_modify=files,
    )
    cand = CandidatePatch(
        candidate_id="cand-fail-1",
        item_id="B-DUP",
        branch_name="factory/cand-fail-1",
        hypothesis="Break test",
        target_metric="steps",
        proposal_hash=prop_hash,
        files_to_modify=files,
    )
    res1 = engine.run_candidate_cycle(
        cand, evaluator=lambda _p: EvalResult(passed=False, metric=99.0)
    )
    assert res1.status == FactoryStatus.REJECTED

    # Duplicate proposal without new_evidence=True must be rejected immediately
    with pytest.raises(DuplicateProposalError, match="DUPLICATE_PROPOSAL_REJECTED"):
        engine.run_candidate_cycle(cand)

    # With new_evidence=True it runs and exhausts max_attempts/max_cycles
    cand_retry = cand.model_copy(update={"candidate_id": "cand-fail-2", "new_evidence": True})
    res2 = engine.run_candidate_cycle(
        cand_retry,
        evaluator=lambda _p: EvalResult(passed=False, metric=99.0),
    )
    assert res2.status == FactoryStatus.REJECTED

    paused_budget = engine.run_candidate_cycle(cand_retry)
    assert paused_budget.status == FactoryStatus.PAUSED_BUDGET_EXHAUSTED

    # Max attempts check with fresh higher budget
    store2 = FactoryStore(tmp_path / "factory2.db")
    engine2 = FactoryEngine(lab_repo, store2, budget=CycleBudget(max_cycles=5, max_attempts=5))
    store2.add_backlog_item(
        BacklogItem(
            item_id="B-MAX",
            title="Max attempts item",
            priority=1,
            hypothesis="Check max attempts",
            target_metric="steps",
            baseline_repro_cmd="pytest -q",
            max_attempts=1,
            attempts_used=1,
        )
    )
    paused_max = engine2.check_pause_state("B-MAX")
    assert paused_max is not None
    assert paused_max.status == FactoryStatus.PAUSED_MAX_ATTEMPTS


@pytest.mark.n1
def test_factory_rollback_missing_or_corrupt_manifest_clean_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "does_not_exist.json"
    rc_missing = factory_cli_main(["rollback", "--manifest", str(missing)])
    cap1 = capsys.readouterr()
    assert rc_missing != 0
    assert "Traceback" not in cap1.err
    assert "not found" in cap1.err.lower()

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{bad json", encoding="utf-8")
    rc_corrupt = factory_cli_main(["rollback", "--manifest", str(corrupt)])
    cap2 = capsys.readouterr()
    assert rc_corrupt != 0
    assert "Traceback" not in cap2.err
    assert "corrupt" in cap2.err.lower() or "invalid" in cap2.err.lower()

    # Subprocess verification without traceback
    proc = subprocess.run(
        [sys.executable, "-m", "src.factory", "rollback", "--manifest", str(missing)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert json.dumps({"ok": True}) not in proc.stdout
    assert callable(rollback_from_manifest)


@pytest.mark.n1
def test_factory_migration_resume_and_audit_log_completeness(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy_factory.db"
    # Pre-populate a legacy factory DB without attempt_count / budget_used columns
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(
        """
        CREATE TABLE factory_backlog (
            item_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            priority INTEGER NOT NULL,
            status TEXT NOT NULL,
            hypothesis TEXT NOT NULL,
            target_metric TEXT NOT NULL,
            baseline_repro_cmd TEXT NOT NULL,
            max_attempts INTEGER NOT NULL,
            attempts_used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE factory_budgets (
            budget_id TEXT PRIMARY KEY,
            max_cycles INTEGER NOT NULL,
            cycles_used INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL,
            attempts_used INTEGER NOT NULL DEFAULT 0,
            max_wall_seconds REAL NOT NULL,
            wall_seconds_used REAL NOT NULL DEFAULT 0.0,
            updated_at TEXT NOT NULL
        );
        """
    )
    conn.execute(
        """
        INSERT INTO factory_backlog (
            item_id, title, priority, status, hypothesis, target_metric,
            baseline_repro_cmd, max_attempts, attempts_used, created_at, updated_at
        ) VALUES (
            'B-LEG', 'Legacy', 1, 'pending', 'Speed up', 'steps',
            'pytest -q', 3, 1, '2026-11-25T12:00:00+00:00', '2026-11-25T12:00:00+00:00'
        );
        """
    )
    conn.execute(
        """
        INSERT INTO factory_budgets (
            budget_id, max_cycles, cycles_used, max_attempts, attempts_used,
            max_wall_seconds, wall_seconds_used, updated_at
        ) VALUES ('default', 4, 1, 3, 1, 120.0, 1.0, '2026-11-25T12:00:00+00:00');
        """
    )
    conn.commit()
    conn.close()

    lab_repo = tmp_path / "lab_repo"
    _init_git_repo(lab_repo)
    store = FactoryStore(db_path)
    engine = FactoryEngine(lab_repo, store)

    # Verify migration backfilled attempt_count and budget_used
    migrated = open_factory_connection(db_path)
    try:
        b_row = migrated.execute(
            "SELECT attempts_used, attempt_count FROM factory_backlog WHERE item_id = 'B-LEG';"
        ).fetchone()
        assert int(b_row["attempts_used"]) == 1
        assert int(b_row["attempt_count"]) == 1
        g_row = migrated.execute(
            "SELECT attempts_used, attempt_count, budget_used FROM factory_budgets "
            "WHERE budget_id = 'default';"
        ).fetchone()
        assert int(g_row["attempt_count"]) == 1
        assert int(g_row["budget_used"]) == 1
    finally:
        migrated.close()

    files = {"app.py": "def compute_steps() -> int:\n    return 5\n"}
    cand = CandidatePatch(
        candidate_id="cand-mig-1",
        item_id="B-LEG",
        branch_name="factory/cand-mig-1",
        hypothesis="Return 5 steps instead of 50",
        target_metric="steps",
        proposal_hash=compute_proposal_hash(
            item_id="B-LEG",
            target_metric="steps",
            files_to_modify=files,
        ),
        files_to_modify=files,
    )
    def _eval_repo(repo_dir: Path) -> EvalResult:
        txt = (repo_dir / "app.py").read_text(encoding="utf-8")
        metric = 5.0 if "return 50" not in txt and "return 5" in txt else 50.0
        return EvalResult(passed=True, metric=metric)

    res = engine.run_candidate_cycle(cand, evaluator=_eval_repo)
    assert res.status == FactoryStatus.PROMOTED, res.reason

    audit_conn = open_factory_connection(db_path)
    try:
        audit_row = audit_conn.execute(
            "SELECT detail_json FROM factory_audit_log ORDER BY created_at DESC LIMIT 1;"
        ).fetchone()
        assert audit_row is not None
        detail = json.loads(str(audit_row["detail_json"]))
        assert detail["hypothesis"] == "Return 5 steps instead of 50"
        assert detail["baseline_metric"] is not None
        assert detail["candidate_metric"] == 5.0
        assert "return 5" in detail["diff"]
        assert detail["base_commit"]
        assert detail["candidate_commit"]
        assert detail["auditor_signoff"] == "approved"
    finally:
        audit_conn.close()

    # Resume CLI preserves counters without resetting or crashing
    rc = factory_cli_main(["resume", "--db", str(db_path), "--repo", str(lab_repo), "--json"])
    assert rc == 0
    assert store.get_budget().attempts_used == 2


@pytest.mark.n1
def test_factory_cli_run_empty_backlog_and_force_fail_pause_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab_repo = tmp_path / "lab_repo"
    _init_git_repo(lab_repo)
    base_head = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    empty_backlog = tmp_path / "empty_backlog.json"
    empty_backlog.write_text("[]", encoding="utf-8")
    db1 = tmp_path / "factory_empty.db"
    out1 = tmp_path / "out_empty"
    rc_empty = factory_cli_main(
        [
            "run",
            "--repo",
            str(lab_repo),
            "--db",
            str(db1),
            "--output-dir",
            str(out1),
            "--backlog",
            str(empty_backlog),
            "--json",
        ]
    )
    assert rc_empty == 0
    summary1 = json.loads((out1 / "factory_run_summary.json").read_text(encoding="utf-8"))
    assert summary1["status"] == "paused_empty_backlog"

    db2 = tmp_path / "factory_exhaust.db"
    out2 = tmp_path / "out_exhaust"
    monkeypatch.setenv("GROKBOT_FACTORY_FORCE_FAIL", "1")
    rc_exhaust = factory_cli_main(
        [
            "run",
            "--repo",
            str(lab_repo),
            "--db",
            str(db2),
            "--output-dir",
            str(out2),
            "--max-attempts",
            "2",
            "--json",
        ]
    )
    assert rc_exhaust == 0
    summary2 = json.loads((out2 / "factory_run_summary.json").read_text(encoding="utf-8"))
    assert "paused" in summary2["status"]
    assert FactoryStore(db2).get_budget().attempts_used == 2
    head_after = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head_after == base_head
