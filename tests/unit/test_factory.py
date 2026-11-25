"""N1 unit tests for the isolated M7 local software factory (F16)."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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


@pytest.mark.n1
def test_factory_cli_evaluate_patch_and_run_cycle_exhaustion_and_md_backlog(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lab_repo = tmp_path / "lab_repo"
    _init_git_repo(lab_repo)
    base_head = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    db_path = tmp_path / "factory_cli.db"

    tamper_patch = tmp_path / "tamper.patch"
    tamper_patch.write_text(
        "diff --git a/src/engine/tool_registry.py b/src/engine/tool_registry.py\n"
        "--- a/src/engine/tool_registry.py\n"
        "+++ b/src/engine/tool_registry.py\n"
        "@@ -1 +1 @@\n"
        "-ALLOW = False\n"
        "+ALLOW = True\n",
        encoding="utf-8",
    )
    rc_eval = factory_cli_main(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--factory-db",
            str(db_path),
            "--patch",
            str(tamper_patch),
            "--json",
        ]
    )
    captured_eval = capsys.readouterr()
    assert rc_eval == 1
    assert "POLICY_IMMUTABILITY_VIOLATION" in captured_eval.out
    assert (
        subprocess.run(
            ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        == base_head
    )

    backlog_md = tmp_path / "BACKLOG.md"
    backlog_md.write_text("- [ ] `B-MD-01`: Fix asset confusion in lookup.\n", encoding="utf-8")
    out_dir = tmp_path / "out_cycle"
    rc_rej = factory_cli_main(
        [
            "run-cycle",
            "--repo",
            str(lab_repo),
            "--factory-db",
            str(db_path),
            "--backlog",
            str(backlog_md),
            "--candidate-mode",
            "reject-asset-confusion",
            "--output-dir",
            str(out_dir),
            "--json",
        ]
    )
    captured_rej = capsys.readouterr()
    assert rc_rej == 0
    rej_payload = json.loads(captured_rej.out)
    assert rej_payload["status"] == "REJECTED"
    assert Path(rej_payload["regression_test_path"]).is_file()

    db_ex = tmp_path / "factory_ex.db"
    rc_ex1 = factory_cli_main(
        [
            "run-cycle",
            "--repo",
            str(lab_repo),
            "--factory-db",
            str(db_ex),
            "--max-attempts",
            "2",
            "--simulate-exhaustion",
            "--json",
        ]
    )
    assert rc_ex1 == 0
    ex1 = json.loads(capsys.readouterr().out)
    assert ex1["attempts_used"] == 1

    rc_ex2 = factory_cli_main(
        [
            "run-cycle",
            "--repo",
            str(lab_repo),
            "--factory-db",
            str(db_ex),
            "--max-attempts",
            "2",
            "--simulate-exhaustion",
            "--json",
        ]
    )
    assert rc_ex2 == 0
    ex2 = json.loads(capsys.readouterr().out)
    assert ex2["attempts_used"] == 2
    assert "PAUSED" in ex2["status"]


@pytest.mark.n1
@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        ".",
        "./",
        "/abs/path",
        "/etc/passwd",
        "../outside",
        "foo/../../outside.py",
        "foo/../tests/acceptance/test_a01.py",
        "foo/../app.py",
        "src/./contracts/models.py",
        "./tests/e2e/tier1/test_f01.py",
        "src\\contracts\\models.py",
    ],
)
def test_policy_guard_normalizes_and_rejects_traversal_paths(bad_path: str) -> None:
    guard = PolicyGuard()
    assert guard.is_immutable_path(bad_path) is True
    with pytest.raises(PolicyImmutabilityError, match="POLICY_IMMUTABILITY_VIOLATION"):
        guard.check_candidate_paths([bad_path])


@pytest.mark.n1
def test_evaluate_patch_hardening_noprefix_rename_traversal_symlink_and_short_forbidden(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lab_repo = tmp_path / "lab_repo"
    _init_git_repo(lab_repo)
    (lab_repo / "tests" / "acceptance").mkdir(parents=True, exist_ok=True)
    (lab_repo / "tests" / "acceptance" / "test_a01.py").write_text(
        "def test_a01() -> None:\n    assert False\n", encoding="utf-8"
    )
    (lab_repo / "src" / "contracts").mkdir(parents=True, exist_ok=True)
    (lab_repo / "src" / "contracts" / "models.py").write_text(
        "ALLOW = False\n", encoding="utf-8"
    )
    subprocess.run(["git", "-C", str(lab_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(lab_repo), "commit", "-m", "add acceptance & contracts"],
        check=True,
        capture_output=True,
    )
    base_head = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    db_path = tmp_path / "factory_hardening.db"

    def _run_eval(patch_file: Path) -> tuple[int, dict[str, Any]]:
        rc = factory_cli_main(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(patch_file),
                "--json",
            ]
        )
        out = capsys.readouterr().out
        return rc, json.loads(out)

    # 1. git diff --no-prefix on tests/acceptance/test_a01.py
    (lab_repo / "tests" / "acceptance" / "test_a01.py").write_text(
        "def test_a01() -> None:\n    assert True\n", encoding="utf-8"
    )
    noprefix_diff = subprocess.run(
        ["git", "-C", str(lab_repo), "diff", "--no-prefix"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    subprocess.run(
        ["git", "-C", str(lab_repo), "checkout", "--", "."], check=True, capture_output=True
    )
    p_noprefix = tmp_path / "noprefix.patch"
    p_noprefix.write_text(noprefix_diff, encoding="utf-8")
    rc, payload = _run_eval(p_noprefix)
    assert rc == 1
    assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"
    assert "tests/acceptance/test_a01.py" in payload["touched_paths"]

    # 2. Pure rename without a/ b/
    p_rename = tmp_path / "rename.patch"
    p_rename.write_text(
        "diff --git app.py tests/acceptance/test_a01.py\n"
        "rename from app.py\n"
        "rename to tests/acceptance/test_a01.py\n",
        encoding="utf-8",
    )
    rc, payload = _run_eval(p_rename)
    assert rc == 1
    assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    # 3. Quoted git path + copy to
    p_quoted = tmp_path / "quoted.patch"
    p_quoted.write_text(
        'diff --git "app.py" "tests/acceptance/my test.py"\n'
        'copy from app.py\n'
        'copy to "tests/acceptance/my test.py"\n',
        encoding="utf-8",
    )
    rc, payload = _run_eval(p_quoted)
    assert rc == 1
    assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    # 4. Internal ./ and ../ traversals
    for name, rel in [
        ("dot", "src/./contracts/models.py"),
        ("traversal", "foo/../tests/acceptance/test_a01.py"),
    ]:
        p_trav = tmp_path / f"{name}.patch"
        p_trav.write_text(
            f"diff --git a/{rel} b/{rel}\n"
            f"--- a/{rel}\n"
            f"+++ b/{rel}\n"
            "@@ -1 +1 @@\n"
            "-x = 1\n"
            "+x = 2\n",
            encoding="utf-8",
        )
        rc, payload = _run_eval(p_trav)
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    # 5. Non-empty garbage patch yielding zero touched_paths & unparseable header
    for name, content in [
        ("garbage", "not a unified diff at all\n"),
        ("bad_header", "diff --git only_one_token\n"),
    ]:
        p_bad = tmp_path / f"{name}.patch"
        p_bad.write_text(content, encoding="utf-8")
        rc, payload = _run_eval(p_bad)
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    # 6. Symlink in repo pointing to immutable file or outside repo
    if os.name == "posix":
        immut_link = lab_repo / "sneaky_immut.py"
        immut_link.symlink_to("tests/acceptance/test_a01.py")
        p_sym_immut = tmp_path / "sym_immut.patch"
        p_sym_immut.write_text(
            "diff --git a/sneaky_immut.py b/sneaky_immut.py\n"
            "--- a/sneaky_immut.py\n"
            "+++ b/sneaky_immut.py\n"
            "@@ -1 +1 @@\n"
            "-x = 1\n"
            "+x = 2\n",
            encoding="utf-8",
        )
        rc, payload = _run_eval(p_sym_immut)
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"
        immut_link.unlink()

        outside_target = tmp_path / "outside.py"
        outside_target.write_text("X = 1\n", encoding="utf-8")
        esc_link = lab_repo / "escape_link.py"
        esc_link.symlink_to(outside_target)
        p_sym_esc = tmp_path / "sym_esc.patch"
        p_sym_esc.write_text(
            "diff --git a/escape_link.py b/escape_link.py\n"
            "--- a/escape_link.py\n"
            "+++ b/escape_link.py\n"
            "@@ -1 +1 @@\n"
            "-X = 1\n"
            "+X = 2\n",
            encoding="utf-8",
        )
        rc, payload = _run_eval(p_sym_esc)
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"
        esc_link.unlink()

    # 7. GROKBOT_FORBIDDEN_PATHS short basename (rt.db) & symlink (alias_link.db -> rt.db)
    rt_db = tmp_path / "rt.db"
    rt_db.write_bytes(b"sqlite")
    monkeypatch.setenv("GROKBOT_FORBIDDEN_PATHS", str(rt_db))

    p_short = tmp_path / "short_forb.patch"
    p_short.write_text(
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def compute_steps() -> int:\n"
        "-    return 50\n"
        '+    return len(open("rt.db", "rb").read())\n',
        encoding="utf-8",
    )
    rc, payload = _run_eval(p_short)
    assert rc == 1
    assert payload["violation"] == "ISOLATION_BOUNDARY_VIOLATION"

    if os.name == "posix":
        alias_link = lab_repo / "alias_link.db"
        alias_link.symlink_to(rt_db)
        p_alias = tmp_path / "alias_forb.patch"
        p_alias.write_text(
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def compute_steps() -> int:\n"
            "-    return 50\n"
            '+    return len(open("alias_link.db", "rb").read())\n',
            encoding="utf-8",
        )
        rc, payload = _run_eval(p_alias)
        assert rc == 1
        assert payload["violation"] == "ISOLATION_BOUNDARY_VIOLATION"
        alias_link.unlink()

    # 8. Valid unrelated unprefixed patch (even with "smart.db" string) must remain ALLOWED
    p_valid = tmp_path / "valid_noprefix.patch"
    p_valid.write_text(
        "diff --git app.py app.py\n"
        "--- app.py\n"
        "+++ app.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def compute_steps() -> int:\n"
        "-    return 50\n"
        '+    _label = "smart.db"\n'
        "+    return 25\n",
        encoding="utf-8",
    )
    rc, payload = _run_eval(p_valid)
    assert rc == 0
    assert payload["status"] == "ALLOWED"
    assert payload["policy_passed"] is True

    # Repo HEAD untouched & audit log persisted
    head_after = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head_after == base_head
    conn = open_factory_connection(db_path)
    try:
        rows = conn.execute("SELECT decision FROM factory_audit_log;").fetchall()
        assert len(rows) >= 10
    finally:
        conn.close()


@pytest.mark.n1
def test_evaluate_patch_rejects_parent_multihop_ancestor_120000_and_circular_symlinks(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lab_repo = tmp_path / "lab_repo"
    _init_git_repo(lab_repo)
    (lab_repo / "tests" / "acceptance").mkdir(parents=True, exist_ok=True)
    (lab_repo / "tests" / "acceptance" / "test_a01.py").write_text(
        "assert False\n", encoding="utf-8"
    )
    (lab_repo / "src" / "contracts").mkdir(parents=True, exist_ok=True)
    (lab_repo / "src" / "contracts" / "models.py").write_text(
        "ALLOW = False\n", encoding="utf-8"
    )
    (lab_repo / "lab" / "safe_dir").mkdir(parents=True, exist_ok=True)
    (lab_repo / "lab" / "safe_dir" / "ok.py").write_text("X = 1\n", encoding="utf-8")

    if os.name == "posix":
        (lab_repo / "lab" / "link_to_tests").symlink_to("../tests")
        (lab_repo / "lab" / "link_to_src").symlink_to("../src")
        (lab_repo / "lab" / "hop2_to_tests").symlink_to("link_to_tests")
        (lab_repo / "lab" / "link_to_safe").symlink_to("safe_dir")
        (lab_repo / "lab" / "loop_a").symlink_to("loop_b")
        (lab_repo / "lab" / "loop_b").symlink_to("loop_a")

    subprocess.run(["git", "-C", str(lab_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(lab_repo), "commit", "-m", "add symlink fixtures"],
        check=True,
        capture_output=True,
    )
    base_head = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    db_path = tmp_path / "factory_symlinks.db"

    def _run_eval(patch_file: Path) -> tuple[int, dict[str, Any]]:
        rc = factory_cli_main(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(patch_file),
                "--json",
            ]
        )
        out = capsys.readouterr().out
        return rc, json.loads(out)

    expected_rejections = 0

    if os.name == "posix":
        # 1. Parent-dir symlink: lab/link_to_tests -> ../tests + acceptance target
        p_parent_tests = tmp_path / "parent_tests.patch"
        p_parent_tests.write_text(
            "diff --git a/lab/link_to_tests/acceptance/test_a01.py "
            "b/lab/link_to_tests/acceptance/test_a01.py\n"
            "--- a/lab/link_to_tests/acceptance/test_a01.py\n"
            "+++ b/lab/link_to_tests/acceptance/test_a01.py\n"
            "@@ -1 +1 @@\n"
            "-assert False\n"
            "+assert True  # PWNED\n",
            encoding="utf-8",
        )
        rc, payload = _run_eval(p_parent_tests)
        assert rc == 1
        assert payload["status"] == "REJECTED"
        assert payload["policy_passed"] is False
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"
        expected_rejections += 1

        # 2. Parent-dir symlink: lab/link_to_src -> ../src + contracts target
        p_parent_src = tmp_path / "parent_src.patch"
        p_parent_src.write_text(
            "diff --git a/lab/link_to_src/contracts/models.py "
            "b/lab/link_to_src/contracts/models.py\n"
            "--- a/lab/link_to_src/contracts/models.py\n"
            "+++ b/lab/link_to_src/contracts/models.py\n"
            "@@ -1 +1 @@\n"
            "-ALLOW = False\n"
            "+ALLOW = True\n",
            encoding="utf-8",
        )
        rc, payload = _run_eval(p_parent_src)
        assert rc == 1
        assert payload["status"] == "REJECTED"
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"
        expected_rejections += 1

        # 3. Multi-hop symlink: lab/hop2_to_tests -> link_to_tests -> ../tests
        p_multihop = tmp_path / "multihop_tests.patch"
        p_multihop.write_text(
            "diff --git a/lab/hop2_to_tests/acceptance/test_a01.py "
            "b/lab/hop2_to_tests/acceptance/test_a01.py\n"
            "--- a/lab/hop2_to_tests/acceptance/test_a01.py\n"
            "+++ b/lab/hop2_to_tests/acceptance/test_a01.py\n"
            "@@ -1 +1 @@\n"
            "-assert False\n"
            "+assert True  # PWNED\n",
            encoding="utf-8",
        )
        rc, payload = _run_eval(p_multihop)
        assert rc == 1
        assert payload["status"] == "REJECTED"
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"
        expected_rejections += 1

        # 4. Circular symlink (ELOOP): lab/loop_a -> loop_b -> loop_a fails closed with JSON
        p_eloop = tmp_path / "eloop.patch"
        p_eloop.write_text(
            "diff --git a/lab/loop_a b/lab/loop_a\n"
            "--- a/lab/loop_a\n"
            "+++ b/lab/loop_a\n"
            "@@ -1 +1 @@\n"
            "-loop_b\n"
            "+loop_b\n",
            encoding="utf-8",
        )
        rc, payload = _run_eval(p_eloop)
        assert rc == 1
        assert payload["status"] == "REJECTED"
        assert payload["policy_passed"] is False
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"
        assert "unresolvable symlink" in str(payload["reason"])
        expected_rejections += 1

        # 5. Legitimate symlink inside non-immutable lab/safe_dir remains ALLOWED
        p_safe_link = tmp_path / "safe_link.patch"
        p_safe_link.write_text(
            "diff --git a/lab/link_to_safe/ok.py b/lab/link_to_safe/ok.py\n"
            "--- a/lab/link_to_safe/ok.py\n"
            "+++ b/lab/link_to_safe/ok.py\n"
            "@@ -1 +1 @@\n"
            "-X = 1\n"
            "+X = 2\n",
            encoding="utf-8",
        )
        rc, payload = _run_eval(p_safe_link)
        assert rc == 0
        assert payload["status"] == "ALLOWED"
        assert payload["policy_passed"] is True

    # 6. 2-hunk 120000 ancestor symlink (sym_tests -> tests) + immutable target write
    p_120000_2hunk = tmp_path / "sym_120000_2hunk.patch"
    p_120000_2hunk.write_text(
        "diff --git a/sym_tests b/sym_tests\n"
        "new file mode 120000\n"
        "index 0000000..1234567\n"
        "--- /dev/null\n"
        "+++ b/sym_tests\n"
        "@@ -0,0 +1 @@\n"
        "+tests\n"
        "diff --git a/sym_tests/acceptance/test_a01.py b/sym_tests/acceptance/test_a01.py\n"
        "--- a/sym_tests/acceptance/test_a01.py\n"
        "+++ b/sym_tests/acceptance/test_a01.py\n"
        "@@ -1 +1 @@\n"
        "-assert False\n"
        "+assert True  # PWNED\n",
        encoding="utf-8",
    )
    rc, payload = _run_eval(p_120000_2hunk)
    assert rc == 1
    assert payload["status"] == "REJECTED"
    assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"
    expected_rejections += 1

    # 7. Multi-hop & circular 120000 symlink chains inside patch fail closed with cycle protection
    guard = PolicyGuard()
    if os.name == "posix":
        (lab_repo / "lab" / "safe_dir" / "inner_to_tests").symlink_to("../../tests")
        with pytest.raises(PolicyImmutabilityError, match="POLICY_IMMUTABILITY_VIOLATION"):
            guard.check_added_lines(
                [],
                touched_paths=[
                    "lab/p_hop3",
                    "lab/p_hop2",
                    "lab/p_hop1",
                    "lab/p_hop3/inner_to_tests/acceptance/test_a01.py",
                ],
                repo_path=lab_repo,
                symlink_added_targets=[
                    ("lab/p_hop3", "p_hop2"),
                    ("lab/p_hop2", "p_hop1"),
                    ("lab/p_hop1", "safe_dir"),
                ],
            )
        (lab_repo / "lab" / "safe_dir" / "inner_to_tests").unlink()

    with pytest.raises(PolicyImmutabilityError, match="circular symlink patch"):
        guard.check_added_lines(
            [],
            touched_paths=["lab/cyc_a", "lab/cyc_b", "lab/cyc_a/file.py"],
            repo_path=lab_repo,
            symlink_added_targets=[
                ("lab/cyc_a", "cyc_b"),
                ("lab/cyc_b", "cyc_a"),
            ],
        )

    # Repo HEAD remains untouched & factory_audit_log persisted all rejections
    head_after = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head_after == base_head

    conn = open_factory_connection(db_path)
    try:
        deny_rows = conn.execute(
            "SELECT action, decision, detail_json FROM factory_audit_log WHERE decision = 'deny';"
        ).fetchall()
        assert len(deny_rows) == expected_rejections
        assert all(row[0] == "patch_evaluation_rejected" for row in deny_rows)
    finally:
        conn.close()


@pytest.mark.n1
def test_evaluate_patch_and_audit_branch_reject_case_variants_and_unmerged_120000_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lab_repo = tmp_path / "lab_repo"
    _init_git_repo(lab_repo)
    (lab_repo / "tests" / "acceptance").mkdir(parents=True, exist_ok=True)
    (lab_repo / "tests" / "acceptance" / "test_a01.py").write_text(
        "assert False\n", encoding="utf-8"
    )
    (lab_repo / "src" / "contracts").mkdir(parents=True, exist_ok=True)
    (lab_repo / "src" / "contracts" / "models.py").write_text("X = 1\n", encoding="utf-8")
    (lab_repo / "lab" / "safe_dir").mkdir(parents=True, exist_ok=True)
    (lab_repo / "lab" / "safe_dir" / "ok.py").write_text("OK = 1\n", encoding="utf-8")
    if os.name == "posix":
        (lab_repo / "lab" / "link_upper").symlink_to("../Tests")
        (lab_repo / "lab" / "safe_dir" / "inner_to_tests").symlink_to("../../tests")

    subprocess.run(["git", "-C", str(lab_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(lab_repo), "commit", "-m", "add case fixtures"],
        check=True,
        capture_output=True,
    )
    base_head = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    db_path = tmp_path / "factory_case.db"

    def _run_cli(argv: list[str]) -> tuple[int, dict[str, Any]]:
        rc = factory_cli_main(argv)
        out = capsys.readouterr().out
        return rc, json.loads(out)

    # 1. Case-variant direct paths: Tests/acceptance/test_a01.py & SRC/contracts/models.py
    for name, rel in [
        ("case_tests", "Tests/acceptance/test_a01.py"),
        ("case_src", "SRC/contracts/models.py"),
    ]:
        p_case = tmp_path / f"{name}.patch"
        p_case.write_text(
            f"diff --git a/{rel} b/{rel}\n"
            f"--- a/{rel}\n"
            f"+++ b/{rel}\n"
            "@@ -1 +1 @@\n"
            "-assert False\n"
            "+assert True  # CASE_BYPASS\n",
            encoding="utf-8",
        )
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_case),
                "--json",
            ]
        )
        assert rc == 1
        assert payload["status"] == "REJECTED"
        assert payload["policy_passed"] is False
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    # 2. Case-variant repo symlink: lab/link_upper -> ../Tests
    if os.name == "posix":
        p_sym_upper = tmp_path / "case_sym.patch"
        p_sym_upper.write_text(
            "diff --git a/lab/link_upper/acceptance/test_a01.py "
            "b/lab/link_upper/acceptance/test_a01.py\n"
            "--- a/lab/link_upper/acceptance/test_a01.py\n"
            "+++ b/lab/link_upper/acceptance/test_a01.py\n"
            "@@ -1 +1 @@\n"
            "-assert False\n"
            "+assert True  # SYM_CASE_BYPASS\n",
            encoding="utf-8",
        )
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_sym_upper),
                "--json",
            ]
        )
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    # 3. 2-hunk 120000 case-variant symlink: sym_up -> Tests + case-variant lookup SYM_UP/...
    p_120000_up = tmp_path / "case_120000.patch"
    p_120000_up.write_text(
        "diff --git a/sym_up b/sym_up\n"
        "new file mode 120000\n"
        "index 0000000..1234567\n"
        "--- /dev/null\n"
        "+++ b/sym_up\n"
        "@@ -0,0 +1 @@\n"
        "+Tests\n"
        "diff --git a/sym_up/acceptance/test_a01.py b/sym_up/acceptance/test_a01.py\n"
        "--- a/sym_up/acceptance/test_a01.py\n"
        "+++ b/sym_up/acceptance/test_a01.py\n"
        "@@ -1 +1 @@\n"
        "-assert False\n"
        "+assert True  # CASE_120000_BYPASS\n",
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_120000_up),
            "--json",
        ]
    )
    assert rc == 1
    assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    if os.name == "posix":
        p_120000_case_lookup = tmp_path / "case_lookup_120000.patch"
        p_120000_case_lookup.write_text(
            "diff --git a/lab/sym_safe b/lab/sym_safe\n"
            "new file mode 120000\n"
            "index 0000000..1234567\n"
            "--- /dev/null\n"
            "+++ b/lab/sym_safe\n"
            "@@ -0,0 +1 @@\n"
            "+safe_dir\n"
            "diff --git a/lab/SYM_SAFE/inner_to_tests/acceptance/test_a01.py "
            "b/lab/SYM_SAFE/inner_to_tests/acceptance/test_a01.py\n"
            "--- a/lab/SYM_SAFE/inner_to_tests/acceptance/test_a01.py\n"
            "+++ b/lab/SYM_SAFE/inner_to_tests/acceptance/test_a01.py\n"
            "@@ -1 +1 @@\n"
            "-assert False\n"
            "+assert True\n",
            encoding="utf-8",
        )
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_120000_case_lookup),
                "--json",
            ]
        )
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    # 4. audit-branch committing Tests/acceptance/test_a01.py (core.ignorecase=false)
    subprocess.run(
        ["git", "-C", str(lab_repo), "checkout", "-b", "cand_ci"],
        check=True,
        capture_output=True,
    )
    (lab_repo / "Tests" / "acceptance").mkdir(parents=True, exist_ok=True)
    (lab_repo / "Tests" / "acceptance" / "test_a01.py").write_text(
        "assert True  # CI_BYPASS\n", encoding="utf-8"
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(lab_repo),
            "-c",
            "core.ignorecase=false",
            "add",
            "Tests/acceptance/test_a01.py",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(lab_repo), "commit", "-m", "ci bypass"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(lab_repo), "checkout", "-f", "main"],
        check=True,
        capture_output=True,
    )
    rc, payload = _run_cli(
        [
            "audit-branch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--branch",
            "cand_ci",
            "--base",
            "main",
            "--json",
        ]
    )
    assert rc == 1
    assert payload["ok"] is False
    assert payload["policy_passed"] is False
    assert "POLICY_IMMUTABILITY_VIOLATION" in str(payload["reason"])

    # 5. audit-branch on unmerged branch committing 120000 symlink (lab/link_to_tests -> ../tests)
    if os.name == "posix":
        subprocess.run(
            ["git", "-C", str(lab_repo), "checkout", "-b", "cand_120000"],
            check=True,
            capture_output=True,
        )
        (lab_repo / "lab" / "link_to_tests").symlink_to("../tests")
        subprocess.run(
            ["git", "-C", str(lab_repo), "add", "lab/link_to_tests"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(lab_repo), "commit", "-m", "add unmerged 120000 symlink"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(lab_repo), "checkout", "-f", "main"],
            check=True,
            capture_output=True,
        )
        rc, payload = _run_cli(
            [
                "audit-branch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--branch",
                "cand_120000",
                "--base",
                "main",
                "--json",
            ]
        )
        assert rc == 1
        assert payload["ok"] is False
        assert payload["policy_passed"] is False
        assert "POLICY_IMMUTABILITY_VIOLATION" in str(payload["reason"])

        # Legitimate unmerged 120000 symlink in non-immutable safe_dir stays ALLOWED
        subprocess.run(
            ["git", "-C", str(lab_repo), "checkout", "-b", "cand_safe_120000"],
            check=True,
            capture_output=True,
        )
        (lab_repo / "lab" / "new_safe_link").symlink_to("safe_dir")
        (lab_repo / "lab" / "safe_dir" / "ok.py").write_text("OK = 2\n", encoding="utf-8")
        subprocess.run(
            [
                "git",
                "-C",
                str(lab_repo),
                "add",
                "lab/new_safe_link",
                "lab/safe_dir/ok.py",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(lab_repo), "commit", "-m", "add safe 120000 symlink"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(lab_repo), "checkout", "-f", "main"],
            check=True,
            capture_output=True,
        )
        rc, payload = _run_cli(
            [
                "audit-branch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--branch",
                "cand_safe_120000",
                "--base",
                "main",
                "--json",
            ]
        )
        assert rc == 0
        assert payload["ok"] is True
        assert payload["policy_passed"] is True

    # 6. Case-variant forbidden path (RT.DB rejected, smart.db allowed)
    rt_db = tmp_path / "rt.db"
    rt_db.write_bytes(b"sqlite")
    monkeypatch.setenv("GROKBOT_FORBIDDEN_PATHS", str(rt_db))

    p_rt_upper = tmp_path / "rt_upper.patch"
    p_rt_upper.write_text(
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def compute_steps() -> int:\n"
        "-    return 50\n"
        '+    return len(open("RT.DB", "rb").read())\n',
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_rt_upper),
            "--json",
        ]
    )
    assert rc == 1
    assert payload["violation"] == "ISOLATION_BOUNDARY_VIOLATION"

    p_smart = tmp_path / "smart_ok.patch"
    p_smart.write_text(
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def compute_steps() -> int:\n"
        "-    return 50\n"
        '+    _name = "smart.db"\n'
        "+    return 25\n",
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_smart),
            "--json",
        ]
    )
    assert rc == 0
    assert payload["status"] == "ALLOWED"
    assert payload["policy_passed"] is True

    head_after = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head_after == base_head


@pytest.mark.n1
def test_evaluate_patch_and_audit_branch_reject_custom_p1_prefixes_symlink_renames_and_nfd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lab_repo = tmp_path / "lab_repo"
    _init_git_repo(lab_repo)
    (lab_repo / "tests" / "acceptance").mkdir(parents=True, exist_ok=True)
    (lab_repo / "tests" / "acceptance" / "test_a01.py").write_text(
        "assert False\n", encoding="utf-8"
    )
    (lab_repo / "src" / "contracts").mkdir(parents=True, exist_ok=True)
    (lab_repo / "src" / "contracts" / "models.py").write_text("X = 1\n", encoding="utf-8")
    (lab_repo / "src" / "engine").mkdir(parents=True, exist_ok=True)
    (lab_repo / "src" / "engine" / "coordinator.py").write_text("COORD = 1\n", encoding="utf-8")
    (lab_repo / "MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md").write_text(
        "# Spec\n", encoding="utf-8"
    )
    (lab_repo / "lab" / "inner").mkdir(parents=True, exist_ok=True)
    (lab_repo / "lab" / "ok.py").write_text("OK = 1\n", encoding="utf-8")
    if os.name == "posix":
        (lab_repo / "lab" / "inner" / "safe_sym").symlink_to("tests")
        (lab_repo / "lab" / "link_to_tests").symlink_to("../tests")
        (lab_repo / "lab" / "was_sym").symlink_to("inner")

    subprocess.run(["git", "-C", str(lab_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(lab_repo), "commit", "-m", "add r5 fixtures"],
        check=True,
        capture_output=True,
    )
    base_head = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    db_path = tmp_path / "factory_r5.db"

    def _run_cli(argv: list[str]) -> tuple[int, dict[str, Any]]:
        rc = factory_cli_main(argv)
        out = capsys.readouterr().out
        return rc, json.loads(out)

    # 1. git diff --src-prefix=x/ --dst-prefix=y/ over immutable files -> REJECTED
    subprocess.run(
        ["git", "-C", str(lab_repo), "checkout", "-b", "evil_prefix"],
        check=True,
        capture_output=True,
    )
    (lab_repo / "tests" / "acceptance" / "test_a01.py").write_text(
        "assert True  # PWN_A01\n", encoding="utf-8"
    )
    (lab_repo / "src" / "contracts" / "models.py").write_text(
        "X = 999  # PWN_MODELS\n", encoding="utf-8"
    )
    (lab_repo / "src" / "engine" / "coordinator.py").write_text(
        "COORD = 999  # PWN_COORD\n", encoding="utf-8"
    )
    (lab_repo / "MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md").write_text(
        "# PWN_MEGAPLAN\n", encoding="utf-8"
    )
    subprocess.run(["git", "-C", str(lab_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(lab_repo), "commit", "-m", "evil prefix"],
        check=True,
        capture_output=True,
    )
    custom_diff = subprocess.run(
        [
            "git",
            "-C",
            str(lab_repo),
            "diff",
            "--src-prefix=x/",
            "--dst-prefix=y/",
            "main..evil_prefix",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    subprocess.run(
        ["git", "-C", str(lab_repo), "checkout", "-f", "main"],
        check=True,
        capture_output=True,
    )
    p_custom = tmp_path / "custom_prefix.patch"
    p_custom.write_text(custom_diff, encoding="utf-8")
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_custom),
            "--json",
        ]
    )
    assert rc == 1
    assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    # 2. Plain unified diff --- x/... +++ y/... without diff --git -> REJECTED
    p_plain = tmp_path / "plain_prefix.patch"
    p_plain.write_text(
        "--- x/tests/acceptance/test_a01.py\n"
        "+++ y/tests/acceptance/test_a01.py\n"
        "@@ -1 +1 @@\n"
        "-assert False\n"
        "+assert True  # CUSTOM_PREFIX_PWNED\n",
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_plain),
            "--json",
        ]
    )
    assert rc == 1
    assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    # 3. Header mismatch diff --git x/lab/ok.py y/lab/ok.py + --- x/tests/... -> REJECTED
    p_mismatch = tmp_path / "mismatch.patch"
    p_mismatch.write_text(
        "diff --git x/lab/ok.py y/lab/ok.py\n"
        "--- x/tests/acceptance/test_a01.py\n"
        "+++ y/tests/acceptance/test_a01.py\n"
        "@@ -1 +1 @@\n"
        "-assert False\n"
        "+assert True  # MISMATCH_PWNED\n",
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_mismatch),
            "--json",
        ]
    )
    assert rc == 1
    assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    # 4. Custom -p1 prefix 120000 symlink diff --git x/sym_x y/sym_x -> tests -> REJECTED
    p_sym_x = tmp_path / "sym_x.patch"
    p_sym_x.write_text(
        "diff --git x/sym_x y/sym_x\n"
        "new file mode 120000\n"
        "--- /dev/null\n"
        "+++ y/sym_x\n"
        "@@ -0,0 +1 @@\n"
        "+tests\n",
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_sym_x),
            "--json",
        ]
    )
    assert rc == 1
    assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    if os.name == "posix":
        # Custom -p1 prefix traversing pre-existing repo symlink -> REJECTED
        p_repo_sym_x = tmp_path / "repo_sym_x.patch"
        p_repo_sym_x.write_text(
            "diff --git x/lab/link_to_tests/acceptance/test_a01.py "
            "y/lab/link_to_tests/acceptance/test_a01.py\n"
            "--- x/lab/link_to_tests/acceptance/test_a01.py\n"
            "+++ y/lab/link_to_tests/acceptance/test_a01.py\n"
            "@@ -1 +1 @@\n"
            "-assert False\n"
            "+assert True\n",
            encoding="utf-8",
        )
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_repo_sym_x),
                "--json",
            ]
        )
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

        # 5. git mv symlink re-anchoring to immutable ancestor: audit-branch & evaluate-patch
        subprocess.run(
            ["git", "-C", str(lab_repo), "checkout", "-b", "cand_mv_sym"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(lab_repo), "mv", "lab/inner/safe_sym", "sym_to_tests"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(lab_repo), "commit", "-m", "mv sym"],
            check=True,
            capture_output=True,
        )
        mv_patch_text = subprocess.run(
            ["git", "-C", str(lab_repo), "diff", "-U0", "main..cand_mv_sym"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        subprocess.run(
            ["git", "-C", str(lab_repo), "checkout", "-f", "main"],
            check=True,
            capture_output=True,
        )

        rc, payload = _run_cli(
            [
                "audit-branch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--branch",
                "cand_mv_sym",
                "--base",
                "main",
                "--json",
            ]
        )
        assert rc == 1
        assert payload["ok"] is False
        assert payload["policy_passed"] is False
        assert "POLICY_IMMUTABILITY_VIOLATION" in str(payload["reason"])

        p_mv = tmp_path / "mv_sym.patch"
        p_mv.write_text(mv_patch_text, encoding="utf-8")
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_mv),
                "--json",
            ]
        )
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

        # Legitimate symlink rename inside lab/ stays ALLOWED
        subprocess.run(
            ["git", "-C", str(lab_repo), "checkout", "-b", "cand_mv_safe"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(lab_repo), "mv", "lab/inner/safe_sym", "lab/moved_safe_sym"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(lab_repo), "commit", "-m", "mv safe sym"],
            check=True,
            capture_output=True,
        )
        mv_safe_text = subprocess.run(
            ["git", "-C", str(lab_repo), "diff", "-U0", "main..cand_mv_safe"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        subprocess.run(
            ["git", "-C", str(lab_repo), "checkout", "-f", "main"],
            check=True,
            capture_output=True,
        )
        rc, payload = _run_cli(
            [
                "audit-branch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--branch",
                "cand_mv_safe",
                "--base",
                "main",
                "--json",
            ]
        )
        assert rc == 0
        assert payload["policy_passed"] is True

        p_mv_safe = tmp_path / "mv_safe.patch"
        p_mv_safe.write_text(mv_safe_text, encoding="utf-8")
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_mv_safe),
                "--json",
            ]
        )
        assert rc == 0
        assert payload["status"] == "ALLOWED"

        # old mode 120000 -> new mode 100644 replacing symlink with regular file stays ALLOWED
        p_sym_to_file = tmp_path / "sym_to_file.patch"
        p_sym_to_file.write_text(
            "diff --git a/lab/was_sym b/lab/was_sym\n"
            "old mode 120000\n"
            "new mode 100644\n"
            "index 1111111..2222222\n"
            "--- a/lab/was_sym\n"
            "+++ b/lab/was_sym\n"
            "@@ -1 +1 @@\n"
            "-inner\n"
            '+print("tests")\n',
            encoding="utf-8",
        )
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_sym_to_file),
                "--json",
            ]
        )
        assert rc == 0
        assert payload["status"] == "ALLOWED"

    # 6. Legitimate --src-prefix=x/ --dst-prefix=y/ and --no-prefix lab/ok.py stay ALLOWED
    subprocess.run(
        ["git", "-C", str(lab_repo), "checkout", "-b", "good_prefix"],
        check=True,
        capture_output=True,
    )
    (lab_repo / "lab" / "ok.py").write_text("OK = 2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(lab_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(lab_repo), "commit", "-m", "good prefix"],
        check=True,
        capture_output=True,
    )
    good_custom_diff = subprocess.run(
        [
            "git",
            "-C",
            str(lab_repo),
            "diff",
            "--src-prefix=x/",
            "--dst-prefix=y/",
            "main..good_prefix",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    good_noprefix_diff = subprocess.run(
        ["git", "-C", str(lab_repo), "diff", "--no-prefix", "main..good_prefix"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    subprocess.run(
        ["git", "-C", str(lab_repo), "checkout", "-f", "main"],
        check=True,
        capture_output=True,
    )
    for name, diff_txt in [
        ("good_custom", good_custom_diff),
        ("good_noprefix", good_noprefix_diff),
    ]:
        p_good = tmp_path / f"{name}.patch"
        p_good.write_text(diff_txt, encoding="utf-8")
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_good),
                "--json",
            ]
        )
        assert rc == 0
        assert payload["status"] == "ALLOWED"
        assert payload["policy_passed"] is True

    # 7. Unicode NFC vs NFD forbidden path normalization
    nfc_name = unicodedata.normalize("NFC", "café.db")
    nfd_name = unicodedata.normalize("NFD", "café.db")
    assert nfc_name != nfd_name
    cafe_db = tmp_path / nfc_name
    cafe_db.write_bytes(b"sqlite")
    monkeypatch.setenv("GROKBOT_FORBIDDEN_PATHS", str(cafe_db))

    p_nfd = tmp_path / "nfd_forbidden.patch"
    p_nfd.write_text(
        "diff --git a/lab/ok.py b/lab/ok.py\n"
        "--- a/lab/ok.py\n"
        "+++ b/lab/ok.py\n"
        "@@ -1 +1 @@\n"
        "-OK = 1\n"
        f'+DB = "{nfd_name}"\n',
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_nfd),
            "--json",
        ]
    )
    assert rc == 1
    assert payload["violation"] == "ISOLATION_BOUNDARY_VIOLATION"

    p_nfd_sym = tmp_path / "nfd_sym.patch"
    p_nfd_sym.write_text(
        "diff --git a/lab/alias_nfd b/lab/alias_nfd\n"
        "new file mode 120000\n"
        "--- /dev/null\n"
        "+++ b/lab/alias_nfd\n"
        "@@ -0,0 +1 @@\n"
        f"+{nfd_name}\n",
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_nfd_sym),
            "--json",
        ]
    )
    assert rc == 1
    assert payload["violation"] == "ISOLATION_BOUNDARY_VIOLATION"

    p_smart_ok = tmp_path / "smart_ok_r5.patch"
    p_smart_ok.write_text(
        "diff --git a/lab/ok.py b/lab/ok.py\n"
        "--- a/lab/ok.py\n"
        "+++ b/lab/ok.py\n"
        "@@ -1 +1 @@\n"
        "-OK = 1\n"
        '+DB = "smart.db"\n',
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_smart_ok),
            "--json",
        ]
    )
    assert rc == 0
    assert payload["status"] == "ALLOWED"

    # 8. Binary patches & differ headers targeting immutable paths/symlinks fail closed
    for idx_bin, bin_patch in enumerate(
        [
            (
                "diff --git a/lab/ok.py b/lab/ok.py\n"
                "--- a/lab/ok.py\n"
                "+++ b/lab/ok.py\n"
                "@@ -1 +1 @@\n"
                "-OK = 1\n"
                "+OK = 2\n"
                "Binary files x/tests/acceptance/evil.bin and y/tests/acceptance/evil.bin differ\n"
            ),
            (
                'Binary files "a/tests/acceptance/evil file.bin" '
                'and "b/tests/acceptance/evil file.bin" differ\n'
            ),
            "Files a/src/contracts/data.bin and b/src/contracts/data.bin differ\n",
            (
                "diff --git a/tests/acceptance/evil.bin b/tests/acceptance/evil.bin\n"
                "new file mode 100644\n"
                "index 0000000..1234567\n"
                "GIT binary patch\n"
                "literal 4\n"
                "LcmZQzU|<5P002M$\n"
            ),
            (
                "diff --git a/lab/sym_bin b/lab/sym_bin\n"
                "new file mode 120000\n"
                "index 0000000..1234567\n"
                "GIT binary patch\n"
                "literal 5\n"
                "McmZQzU|<5P002M$\n"
            ),
            "GIT binary patch\nliteral 4\nLcmZQzU|<5P002M$\n",
        ]
    ):
        p_bin = tmp_path / f"evil_bin_{idx_bin}.patch"
        p_bin.write_text(bin_patch, encoding="utf-8")
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_bin),
                "--json",
            ]
        )
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    p_bin_ok = tmp_path / "good_bin.patch"
    p_bin_ok.write_text(
        "diff --git a/lab/fixture.bin b/lab/fixture.bin\n"
        "new file mode 100644\n"
        "index 0000000..1234567\n"
        "GIT binary patch\n"
        "literal 4\n"
        "LcmZQzU|<5P002M$\n",
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_bin_ok),
            "--json",
        ]
    )
    assert rc == 0
    assert payload["status"] == "ALLOWED"

    guard = PolicyGuard()
    with pytest.raises(PolicyImmutabilityError, match="null byte"):
        guard.check_added_lines(
            [],
            touched_paths=["lab/ok_sym"],
            repo_path=lab_repo,
            symlink_added_targets=[("lab/ok_sym", "safe\x00dir")],
        )

    head_after = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head_after == base_head


@pytest.mark.n1
def test_evaluate_patch_closes_binary_leak_cross_section_symlink_space_timestamp_and_short_casefold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lab_repo = tmp_path / "lab_repo_r6"
    _init_git_repo(lab_repo)
    (lab_repo / "tests" / "acceptance").mkdir(parents=True, exist_ok=True)
    (lab_repo / "tests" / "acceptance" / "test_a01.py").write_text(
        "assert False\n", encoding="utf-8"
    )
    (lab_repo / "src" / "contracts").mkdir(parents=True, exist_ok=True)
    (lab_repo / "src" / "contracts" / "models.py").write_text("X = 1\n", encoding="utf-8")
    (lab_repo / "src" / "factory").mkdir(parents=True, exist_ok=True)
    (lab_repo / "src" / "factory" / "policy.py").write_text("POLICY = 1\n", encoding="utf-8")
    (lab_repo / "src" / "factory" / "errors.py").write_text("ERR = 1\n", encoding="utf-8")
    (lab_repo / "src" / "engine").mkdir(parents=True, exist_ok=True)
    (lab_repo / "src" / "engine" / "coordinator.py").write_text("COORD = 1\n", encoding="utf-8")
    (lab_repo / "src" / "engine" / "budget.py").write_text("BUDGET = 1\n", encoding="utf-8")
    (lab_repo / "src" / "engine" / "loop_detector.py").write_text("LOOP = 1\n", encoding="utf-8")
    (lab_repo / "src" / "engine" / "tool_registry.py").write_text("TOOL = 1\n", encoding="utf-8")
    (lab_repo / "MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md").write_text(
        "# Spec\n", encoding="utf-8"
    )
    (lab_repo / "ok.py").write_text("X = 1\n", encoding="utf-8")
    (lab_repo / "lab").mkdir(parents=True, exist_ok=True)
    (lab_repo / "lab" / "ok.py").write_text("OK = 1\n", encoding="utf-8")
    (lab_repo / "lab" / "my file.py").write_text("SPACE = 1\n", encoding="utf-8")
    (lab_repo / "lab" / "fixture.bin").write_bytes(b"\x00\x01\x02\x03")

    subprocess.run(["git", "-C", str(lab_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(lab_repo), "commit", "-m", "add r6 fixtures"],
        check=True,
        capture_output=True,
    )
    base_head = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    db_path = tmp_path / "factory_r6.db"

    def _run_cli(argv: list[str]) -> tuple[int, dict[str, Any]]:
        rc = factory_cli_main(argv)
        out = capsys.readouterr().out
        return rc, json.loads(out)

    # Generate real git binary patch on lab/fixture.bin
    subprocess.run(
        ["git", "-C", str(lab_repo), "checkout", "-b", "bin_gen"],
        check=True,
        capture_output=True,
    )
    (lab_repo / "lab" / "fixture.bin").write_bytes(b"\xff\xfe\xfd\xfc")
    subprocess.run(
        ["git", "-C", str(lab_repo), "add", "lab/fixture.bin"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(lab_repo), "commit", "-m", "bin update"],
        check=True,
        capture_output=True,
    )
    bin_base_patch = subprocess.run(
        ["git", "-C", str(lab_repo), "diff", "--binary", "main..bin_gen"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    subprocess.run(
        ["git", "-C", str(lab_repo), "checkout", "-f", "main"],
        check=True,
        capture_output=True,
    )

    # 1. H1: GIT binary patch followed by plain ---/+++ diff over all 9 immutable targets
    immutable_targets = [
        ("tests/acceptance/test_a01.py", "assert False", "assert True  # H1_PWN"),
        ("src/contracts/models.py", "X = 1", "X = 999"),
        ("src/factory/policy.py", "POLICY = 1", "POLICY = None"),
        ("src/engine/coordinator.py", "COORD = 1", "COORD = 999"),
        ("src/engine/budget.py", "BUDGET = 1", "BUDGET = 999"),
        ("src/engine/loop_detector.py", "LOOP = 1", "LOOP = 999"),
        ("src/engine/tool_registry.py", "TOOL = 1", "TOOL = 999"),
        ("src/factory/errors.py", "ERR = 1", "ERR = 999"),
        ("MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md", "# Spec", "# H1_PWN"),
    ]
    for idx, (target_rel, old_line, new_line) in enumerate(immutable_targets):
        p_h1 = tmp_path / f"h1_{idx}.patch"
        p_h1.write_text(
            f"{bin_base_patch}\n"
            f"--- a/{target_rel}\n"
            f"+++ b/{target_rel}\n"
            "@@ -1 +1 @@\n"
            f"-{old_line}\n"
            f"+{new_line}\n",
            encoding="utf-8",
        )
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_h1),
                "--json",
            ]
        )
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"
        assert target_rel in payload["touched_paths"]

    # H1 variant: GIT binary patch followed by legitimate plain diff -> ALLOWED
    p_h1_ok = tmp_path / "h1_ok.patch"
    p_h1_ok.write_text(
        f"{bin_base_patch}\n"
        "--- a/lab/ok.py\n"
        "+++ b/lab/ok.py\n"
        "@@ -1 +1 @@\n"
        "-OK = 1\n"
        "+OK = 2\n",
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_h1_ok),
            "--json",
        ]
    )
    assert rc == 0
    assert payload["status"] == "ALLOWED"

    # 2. E1: 120000 symlink section followed by plain --- a/ok.py adding +tests -> ALLOWED
    p_e1 = tmp_path / "e1.patch"
    p_e1.write_text(
        "diff --git a/lab/sym_a b/lab/sym_a\n"
        "new file mode 120000\n"
        "--- /dev/null\n"
        "+++ b/lab/sym_a\n"
        "@@ -0,0 +1 @@\n"
        "+ok_target\n"
        "--- a/ok.py\n"
        "+++ b/ok.py\n"
        "@@ -1 +1,2 @@\n"
        " X = 1\n"
        "+tests\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", str(lab_repo), "apply", "--check", str(p_e1)],
        check=True,
        capture_output=True,
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_e1),
            "--json",
        ]
    )
    assert rc == 0
    assert payload["status"] == "ALLOWED"
    assert payload["policy_passed"] is True

    # 3. H5: Space-separated timestamps on ---/+++ headers fail closed; space filenames stay ALLOWED
    h5_patches = [
        (
            "--- x/src/engine/budget.py 2026-11-25 10:00:00\n"
            "+++ y/src/engine/budget.py 2026-11-25 10:00:01\n"
            "@@ -1 +1 @@\n"
            "-BUDGET = 1\n"
            "+BUDGET = 999\n"
        ),
        (
            "--- a/MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md 2026-11-25 10:00:00\n"
            "+++ b/MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md 2026-11-25 10:00:01\n"
            "@@ -1 +1 @@\n"
            "-# Spec\n"
            "+# PWN\n"
        ),
        (
            "--- x/src/engine/coordinator.py Wed Nov 25 10:00:00 2026\n"
            "+++ y/src/engine/coordinator.py Wed Nov 25 10:00:01 2026\n"
            "@@ -1 +1 @@\n"
            "-COORD = 1\n"
            "+COORD = 999\n"
        ),
    ]
    for idx, h5_text in enumerate(h5_patches):
        p_h5 = tmp_path / f"h5_{idx}.patch"
        p_h5.write_text(h5_text, encoding="utf-8")
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_h5),
                "--json",
            ]
        )
        assert rc == 1
        assert payload["violation"] == "POLICY_IMMUTABILITY_VIOLATION"

    p_space_ok = tmp_path / "h5_space_ok.patch"
    p_space_ok.write_text(
        "--- a/lab/my file.py 2026-11-25 10:00:00\n"
        "+++ b/lab/my file.py 2026-11-25 10:00:01\n"
        "@@ -1 +1 @@\n"
        "-SPACE = 1\n"
        "+SPACE = 2\n",
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_space_ok),
            "--json",
        ]
    )
    assert rc == 0
    assert payload["status"] == "ALLOWED"

    # 4. E2: Short (<12) forbidden basenames (ß.db -> SS.DB, straße.db -> STRASSE.DB, smart.db OK)
    monkeypatch.setenv(
        "GROKBOT_FORBIDDEN_PATHS",
        f"{tmp_path / 'ß.db'},{tmp_path / 'straße.db'},{tmp_path / 'art.db'}",
    )
    for idx, forbidden_ref in enumerate(["SS.DB", "STRASSE.DB", "dir/SS.DB", "sub/STRASSE.DB"]):
        p_e2 = tmp_path / f"e2_{idx}.patch"
        p_e2.write_text(
            "diff --git a/lab/ok.py b/lab/ok.py\n"
            "--- a/lab/ok.py\n"
            "+++ b/lab/ok.py\n"
            "@@ -1 +1,2 @@\n"
            " OK = 1\n"
            f'+DB = "{forbidden_ref}"\n',
            encoding="utf-8",
        )
        rc, payload = _run_cli(
            [
                "evaluate-patch",
                "--repo",
                str(lab_repo),
                "--db",
                str(db_path),
                "--patch",
                str(p_e2),
                "--json",
            ]
        )
        assert rc == 1
        assert payload["violation"] == "ISOLATION_BOUNDARY_VIOLATION"

    p_e2_smart = tmp_path / "e2_smart.patch"
    p_e2_smart.write_text(
        "diff --git a/lab/ok.py b/lab/ok.py\n"
        "--- a/lab/ok.py\n"
        "+++ b/lab/ok.py\n"
        "@@ -1 +1,2 @@\n"
        " OK = 1\n"
        '+DB = "smart.db"\n',
        encoding="utf-8",
    )
    rc, payload = _run_cli(
        [
            "evaluate-patch",
            "--repo",
            str(lab_repo),
            "--db",
            str(db_path),
            "--patch",
            str(p_e2_smart),
            "--json",
        ]
    )
    assert rc == 0
    assert payload["status"] == "ALLOWED"

    head_after = subprocess.run(
        ["git", "-C", str(lab_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head_after == base_head
