"""Acceptance tests for Milestone M6: M7 Software Factory (F16) & M8 Offline Packaging (F17)."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from pathlib import Path

import pytest
from deploy.config import load_deploy_config
from src.factory import (
    BacklogItem,
    CandidatePatch,
    CycleBudget,
    FactoryEngine,
    FactoryStore,
    PolicyImmutabilityError,
    run_factory_demo,
)
from src.n3_probe import run_n3_probe
from src.storage import StorageRepo

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.mark.acceptance
@pytest.mark.n2
def test_m6_factory_accepted_and_rejected_asset_confusing_candidates(tmp_path: Path) -> None:
    summary = run_factory_demo(
        workspace_dir=tmp_path / "factory_ws",
        repo_dir=tmp_path / "factory_ws" / "lab_repo",
        db_path=tmp_path / "factory_ws" / "factory.db",
        output_dir=tmp_path / "factory_ws" / "artifacts",
    )
    assert summary["ok"] is True
    assert summary["isolation_verified"] is True
    assert summary["rollback_verified"] is True
    assert summary["candidate_1"]["status"] == "promoted"
    assert summary["candidate_1"]["candidate_metric"] < summary["candidate_1"]["baseline_metric"]
    assert summary["candidate_2"]["status"] == "rejected"
    assert "bomba-34-a2" in summary["candidate_2"]["reason"]
    assert summary["final_main_head"] == summary["promoted_commit"]


@pytest.mark.acceptance
@pytest.mark.n2
def test_m6_factory_policy_immutability_and_lease_recovery(tmp_path: Path) -> None:
    lab_repo = tmp_path / "lab_repo"
    lab_repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(lab_repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(lab_repo), "config", "user.name", "Acc Test"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(lab_repo), "config", "user.email", "acc@test.local"],
        check=True,
        capture_output=True,
    )
    (lab_repo / "tests" / "acceptance").mkdir(parents=True)
    (lab_repo / "tests" / "acceptance" / "test_oracle.py").write_text(
        "def test_ok() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(lab_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(lab_repo), "commit", "-m", "baseline"],
        check=True,
        capture_output=True,
    )

    db_path = tmp_path / "factory.db"
    store1 = FactoryStore(db_path)
    engine1 = FactoryEngine(
        lab_repo,
        store1,
        budget=CycleBudget(max_cycles=3, max_attempts=3),
    )
    store1.add_backlog_item(
        BacklogItem(
            item_id="B-ACC-POL",
            title="Attempt acceptance override",
            priority=1,
            hypothesis="Tamper oracle",
            target_metric="pass_rate",
            baseline_repro_cmd="pytest -q",
            max_attempts=3,
        )
    )
    cand = CandidatePatch(
        candidate_id="cand-tamper",
        item_id="B-ACC-POL",
        branch_name="factory/cand-tamper",
        hypothesis="Tamper acceptance test",
        target_metric="pass_rate",
        proposal_hash="tamper-hash",
        files_to_modify={"tests/acceptance/test_oracle.py": "def test_ok(): assert True\n"},
    )
    with pytest.raises(PolicyImmutabilityError, match="POLICY_IMMUTABILITY_VIOLATION"):
        engine1.run_candidate_cycle(cand)

    # Restart FactoryStore/Engine and confirm persistent attempt/cycle counters were NOT reset
    store2 = FactoryStore(db_path)
    engine2 = FactoryEngine(lab_repo, store2)
    persisted_budget = engine2.store.get_budget()
    persisted_item = engine2.store.get_backlog_item("B-ACC-POL")
    assert persisted_budget.cycles_used == 1
    assert persisted_budget.attempts_used == 1
    assert persisted_item is not None
    assert persisted_item.attempts_used == 1


@pytest.mark.acceptance
@pytest.mark.n2
def test_m6_deploy_package_and_rollback_subprocess_e2e(tmp_path: Path) -> None:
    proj = tmp_path / "bundle_app"
    (proj / "deploy").mkdir(parents=True)
    (proj / "lab" / "configs").mkdir(parents=True)
    (proj / "src").mkdir(parents=True)
    (proj / "pyproject.toml").write_text('[project]\nname="app"\nversion="0.1.0"\n')
    (proj / "uv.lock").write_text("# lock\n")
    (proj / "src" / "hello.py").write_text("MSG = 'ok'\n")
    (proj / "lab" / "configs" / "facility_a.json").write_text(
        (_REPO_ROOT / "lab" / "configs" / "facility_a.json").read_text()
    )

    state_dir = tmp_path / "runtime_state"
    runtime_db = state_dir / "grokbot.sqlite3"
    repo = StorageRepo(runtime_db)
    repo.init_db()
    from src.contracts.models import TaskScope, TaskSpec

    repo.create_task_and_run(
        TaskSpec(
            task_id="task-preserve-1",
            user_id="operator_ro",
            profile_id="p1",
            scope=TaskScope(facility_id="facility-a", read_only=True),
            query="Preserve me across rollback",
        )
    )
    profile_dir = state_dir / "profiles"
    profile_dir.mkdir(parents=True)
    (profile_dir / "marker.txt").write_text("keep-profile", encoding="utf-8")

    cfg_dict = load_deploy_config(
        _REPO_ROOT / "deploy" / "install_config.yaml",
        verify_facility=False,
    ).model_dump(mode="json")
    cfg_dict["storage"]["sqlite_wal_path"] = str(runtime_db)
    cfg_dict["storage"]["profile_root"] = str(profile_dir)
    cfg_path = proj / "deploy" / "install_config.json"
    cfg_path.write_text(json.dumps(cfg_dict, indent=2), encoding="utf-8")

    releases_dir = tmp_path / "releases"
    pkg_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "deploy.package",
            "--config",
            str(cfg_path),
            "--root-dir",
            str(proj),
            "--output",
            str(tmp_path / "rel1.json"),
            "--releases-dir",
            str(releases_dir),
            "--release-id",
            "rel-0.1.0",
            "--version",
            "0.1.0",
            "--json",
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert pkg_proc.returncode == 0, pkg_proc.stderr
    assert "RuntimeWarning" not in pkg_proc.stderr

    rb_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "deploy.rollback",
            "--releases-dir",
            str(releases_dir),
            "--target-release",
            "rel-0.1.0",
            "--root-dir",
            str(proj),
            "--json",
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert rb_proc.returncode == 0, rb_proc.stderr
    rb_data = json.loads(rb_proc.stdout)
    assert rb_data["ok"] is True
    assert rb_data["state_preserved"] is True

    # Confirm SQLite WAL task row & profile marker survived rollback intact
    reloaded = StorageRepo(runtime_db)
    assert reloaded.get_task_spec("task-preserve-1").query == "Preserve me across rollback"
    assert (profile_dir / "marker.txt").read_text(encoding="utf-8") == "keep-profile"

    # Missing manifest subprocess check (no 'usage:' in stdout or stderr)
    err_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "deploy.rollback",
            "--manifest",
            str(tmp_path / "missing_manifest.json"),
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert err_proc.returncode != 0
    assert err_proc.stderr.strip()
    assert "usage:" not in err_proc.stdout.lower()
    assert "usage:" not in err_proc.stderr.lower()


@pytest.mark.acceptance
@pytest.mark.n3
@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="PENDING_N3_LINUX_ENV: Linux host netns/iptables + local LLM required.",
)
def test_m6_n3_linux_offline_gate() -> None:
    cfg = load_deploy_config(
        _REPO_ROOT / "deploy" / "install_config.yaml",
        verify_facility=True,
        repo_root=_REPO_ROOT,
    )
    assert cfg.offline_ops.egress_blocked is True
    report = run_n3_probe()
    assert report.linux_os_ready is True
    assert report.network_isolation_ready is True
    assert report.local_llm_ready is True
    assert report.overall_status == "READY"
