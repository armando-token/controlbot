"""N2 integration tests for 7-step M7 self-repair, rebase/rollback, and parallel repairers."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from src.factory.errors import PolicyImmutabilityError
from src.qa.cli import main
from src.qa.models import CampaignState, CandidateManifest, QAFailureItem
from src.qa.queue import (
    open_campaign_store,
    record_item_probe_outcome,
    save_campaign_state,
    upsert_qa_item,
)
from src.qa.repair_loop import QARepairLoop, accept_candidate_to_qa, rollback_candidate_from_qa


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _init_repo(repo: Path, files: dict[str, str]) -> str:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "qa-int@example.local")
    _git(repo, "config", "user.name", "QA Int")
    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")
    _git(repo, "branch", "qa/autopilot")
    return _git(repo, "rev-parse", "HEAD")


def _commit_on_branch(repo: Path, branch: str, files: dict[str, str], *, base_ref: str) -> str:
    _git(repo, "checkout", "-B", branch, base_ref)
    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", f"branch {branch}")
    sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "qa/autopilot")
    return sha


@pytest.mark.n2
def test_seven_step_self_repair_accept_and_rollback_with_dist_surface(tmp_path: Path) -> None:
    repo = tmp_path / "repair_repo"
    base_sha = _init_repo(
        repo,
        {
            "calc.py": "def double(x: int) -> int:\n    return x\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_repro.py": (
                "from calc import double\ndef test_double() -> None:\n    assert double(5) == 10\n"
            ),
            "frontend/dist/index.html": (
                "<!doctype html><html><head><title>Grok Bot — ControlBot Studio</title>"
                "<script src='/assets/app.js'></script></head><body></body></html>\n"
            ),
            "frontend/dist/assets/app.js": "console.log('ok');\n",
        },
    )

    camp_dir = tmp_path / "camp_7step"
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-int-7step",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        qa_branch="qa/autopilot",
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    repro_cmd = f"{sys.executable} -m pytest -q test_repro.py"
    item = QAFailureItem(
        item_id="item-double",
        dedup_key="CB-00:calc:double_bug",
        case_id="CB-00",
        subsystem="calc",
        normalized_signature="double_bug",
        severity="P1",
        state="reproduced",
        summary="calc.double returns x instead of x*2",
        first_seen_sha=base_sha,
        last_seen_sha=base_sha,
        environment_lane="local_deterministic",
        repro_command=repro_cmd,
        repro_test_path="test_repro.py",
    )
    upsert_qa_item(store, state.campaign_id, item)

    def _repairer(wt: Path, it: QAFailureItem) -> dict[str, str]:
        del wt, it
        return {"calc.py": "def double(x: int) -> int:\n    return x * 2\n"}

    loop = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo,
        max_parallel=1,
        max_attempts=2,
        author_model="hydrogen",
        auditor_model="pro",
        build_frontend=False,
        skip_browser=True,
        auto_accept=True,
        repairer_fn=_repairer,
    )
    res = loop.run()
    assert len(res["accepted_candidates"]) == 1
    cand_id = res["accepted_candidates"][0]

    cand_data = CandidateManifest.model_validate_json(
        (camp_dir / "candidates" / f"{cand_id}.json").read_text(encoding="utf-8")
    )
    assert cand_data.status == "accepted_qa"
    assert cand_data.baseline_passed is False
    assert cand_data.candidate_passed is True
    assert cand_data.audit_passed is True
    assert cand_data.build_hash
    assert cand_data.rollback_manifest_path and Path(cand_data.rollback_manifest_path).is_file()

    state_after = CampaignState.model_validate_json(
        (camp_dir / "campaign.json").read_text(encoding="utf-8")
    )
    assert state_after.last_accepted_sha == cand_data.candidate_sha
    assert _git(repo, "rev-parse", "qa/autopilot") == cand_data.candidate_sha

    # Rollback restores base_sha cleanly
    rb = rollback_candidate_from_qa(camp_dir, candidate_id=cand_id, repo_root=repo)
    assert rb["status"] == "rolled_back"
    assert _git(repo, "rev-parse", "qa/autopilot") == base_sha
    state_rb = CampaignState.model_validate_json(
        (camp_dir / "campaign.json").read_text(encoding="utf-8")
    )
    assert state_rb.last_accepted_sha == base_sha


@pytest.mark.n2
def test_parallel_disjoint_and_serialized_overlapping_repairers(tmp_path: Path) -> None:
    repo = tmp_path / "parallel_repo"
    base_sha = _init_repo(
        repo,
        {
            "mod_a.py": "def fn_a() -> str:\n    return 'bad_a'\n",
            "mod_b.py": "def fn_b() -> str:\n    return 'bad_b'\n",
            "shared.py": "def s1() -> int:\n    return 0\ndef s2() -> int:\n    return 0\n",
            "test_a.py": (
                "from mod_a import fn_a\ndef test_a() -> None:\n    assert fn_a() == 'ok_a'\n"
            ),
            "test_b.py": (
                "from mod_b import fn_b\ndef test_b() -> None:\n    assert fn_b() == 'ok_b'\n"
            ),
            "test_s1.py": "from shared import s1\ndef test_s1() -> None:\n    assert s1() == 1\n",
            "test_s2.py": "from shared import s2\ndef test_s2() -> None:\n    assert s2() == 2\n",
        },
    )

    camp_dir = tmp_path / "camp_parallel"
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-int-parallel",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        qa_branch="qa/autopilot",
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)
    store = open_campaign_store(camp_dir, state, repo_root=repo)

    for iid, case_id, sub, test_file in (
        ("item-a", "CB-05", "mod_a", "test_a.py"),
        ("item-b", "CB-06", "mod_b", "test_b.py"),
        ("item-s1", "CB-07", "shared", "test_s1.py"),
        ("item-s2", "CB-08", "shared", "test_s2.py"),
    ):
        upsert_qa_item(
            store,
            state.campaign_id,
            QAFailureItem(
                item_id=iid,
                dedup_key=f"{case_id}:{sub}:{iid}",
                case_id=case_id,
                subsystem=sub,
                normalized_signature=iid,
                severity="P1",
                state="reproduced",
                summary=f"Fix {iid}",
                first_seen_sha=base_sha,
                last_seen_sha=base_sha,
                environment_lane="local_deterministic",
                repro_command=f"{sys.executable} -m pytest -q {test_file}",
                repro_test_path=test_file,
            ),
        )

    def _repairer(wt: Path, it: QAFailureItem) -> dict[str, str]:
        if it.item_id == "item-a":
            return {"mod_a.py": "def fn_a() -> str:\n    return 'ok_a'\n"}
        if it.item_id == "item-b":
            return {"mod_b.py": "def fn_b() -> str:\n    return 'ok_b'\n"}
        cur = (wt / "shared.py").read_text(encoding="utf-8")
        if it.item_id == "item-s1":
            return {
                "shared.py": cur.replace(
                    "def s1() -> int:\n    return 0",
                    "def s1() -> int:\n    return 1",
                )
            }
        return {
            "shared.py": cur.replace(
                "def s2() -> int:\n    return 0",
                "def s2() -> int:\n    return 2",
            )
        }

    loop = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo,
        max_parallel=2,
        max_attempts=2,
        auto_accept=True,
        repairer_fn=_repairer,
    )
    res = loop.run()
    assert len(res["accepted_candidates"]) == 4

    _git(repo, "checkout", "qa/autopilot")
    full_pytest = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )
    assert full_pytest.returncode == 0, full_pytest.stdout + full_pytest.stderr


@pytest.mark.n2
def test_accept_regression_triggers_automatic_rollback(tmp_path: Path) -> None:
    repo = tmp_path / "regress_repo"
    base_sha = _init_repo(
        repo,
        {
            "shared.py": "def healthy() -> bool:\n    return True\n",
            "test_smoke.py": (
                "from shared import healthy\ndef test_smoke() -> None:\n    assert healthy()\n"
            ),
            "test_feat.py": "def test_feat() -> None:\n    assert True\n",
        },
    )
    bad_sha = _commit_on_branch(
        repo,
        "qa/cand-bad",
        {"shared.py": "def healthy() -> bool:\n    return False\n"},
        base_ref=base_sha,
    )
    camp_dir = tmp_path / "camp_regress"
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-int-regress",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        qa_branch="qa/autopilot",
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    cand_path = camp_dir / "candidates" / "cand-bad.json"
    cand_path.write_text(
        CandidateManifest(
            candidate_id="cand-bad",
            item_id="item-bad",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=bad_sha,
            branch_name="qa/cand-bad",
            rerun_command=f"{sys.executable} -m pytest -q test_feat.py",
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="rolled back"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-bad", repo_root=repo)

    assert _git(repo, "rev-parse", "qa/autopilot") == base_sha
    cand_after = json.loads(cand_path.read_text(encoding="utf-8"))
    assert cand_after["status"] == "rolled_back"


@pytest.mark.n2
def test_cli_lifecycle_against_isolated_lab_and_live_port_refusal(tmp_path: Path) -> None:
    repo = tmp_path / "cli_repo"
    base_sha = _init_repo(repo, {"README.md": "# cli test\n"})
    camp_dir = tmp_path / "camp_cli_n2"
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-int-cli",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        target_url="http://127.0.0.1:8000",
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)

    # Live :8000 refused on scan and repair
    assert main(["scan", "--campaign-dir", str(camp_dir), "--repo-root", str(repo)]) == 1
    assert main(["repair", "--campaign-dir", str(camp_dir), "--repo-root", str(repo)]) == 1

    # Switch to non-live URL and run full lifecycle
    safe_state = state.model_copy(update={"target_url": None})
    save_campaign_state(camp_dir, safe_state)
    for _ in range(3):
        rc = main(
            ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00", "--repo-root", str(repo)]
        )
        assert rc == 0

    # Verify RunRecords persisted in SQLite & runs.jsonl
    assert (camp_dir / "runs.jsonl").is_file()
    assert len((camp_dir / "runs.jsonl").read_text(encoding="utf-8").splitlines()) == 3
    assert main(["repair", "--campaign-dir", str(camp_dir), "--repo-root", str(repo)]) == 0
    assert main(["resume", "--campaign-dir", str(camp_dir), "--repo-root", str(repo)]) == 0
    assert main(["report", "--campaign-dir", str(camp_dir), "--repo-root", str(repo)]) == 0
    assert (camp_dir / "daily_report.md").is_file()
    assert (camp_dir / "HANDOFF.md").is_file()


@pytest.mark.n2
def test_accept_and_rollback_preserve_dirty_repo_root_and_head_branch(tmp_path: Path) -> None:
    repo = tmp_path / "dirty_repo"
    base_sha = _init_repo(
        repo,
        {
            "app_mod.py": "def ok() -> bool:\n    return False\n",
            "diag.py": "# tracked diagnostic baseline\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_repro.py": (
                "from app_mod import ok\ndef test_repro() -> None:\n    assert ok()\n"
            ),
        },
    )
    cand_sha = _commit_on_branch(
        repo,
        "qa/cand-dirty",
        {"app_mod.py": "def ok() -> bool:\n    return True\n"},
        base_ref=base_sha,
    )
    _git(repo, "checkout", "main")
    (repo / "diag.py").write_text("# DIRTY UNCOMMITTED DIAGNOSTIC WORK\n", encoding="utf-8")
    (repo / "untracked_diag.txt").write_text("keep-me\n", encoding="utf-8")

    camp_dir = tmp_path / "camp_dirty"
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-int-dirty",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        qa_branch="qa/autopilot",
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    upsert_qa_item(
        store,
        state.campaign_id,
        QAFailureItem(
            item_id="item-dirty",
            dedup_key="CB-00:app:dirty",
            case_id="CB-00",
            subsystem="app",
            normalized_signature="dirty",
            severity="P1",
            state="candidate_verified",
            summary="Fix ok()",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command=f"{sys.executable} -m pytest -q test_repro.py",
            repro_test_path="test_repro.py",
        ),
    )
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    (camp_dir / "candidates" / "cand-dirty.json").write_text(
        CandidateManifest(
            candidate_id="cand-dirty",
            item_id="item-dirty",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=cand_sha,
            branch_name="qa/cand-dirty",
            repro_test_path="test_repro.py",
            rerun_command=f"{sys.executable} -m pytest -q test_repro.py",
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    acc = accept_candidate_to_qa(camp_dir, candidate_id="cand-dirty", repo_root=repo)
    assert acc["status"] == "accepted_qa"
    assert _git(repo, "rev-parse", "qa/autopilot") == cand_sha
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert (repo / "diag.py").read_text(encoding="utf-8") == "# DIRTY UNCOMMITTED DIAGNOSTIC WORK\n"
    assert (repo / "untracked_diag.txt").read_text(encoding="utf-8") == "keep-me\n"

    rb = rollback_candidate_from_qa(camp_dir, candidate_id="cand-dirty", repo_root=repo)
    assert rb["status"] == "rolled_back"
    assert _git(repo, "rev-parse", "qa/autopilot") == base_sha
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert (repo / "diag.py").read_text(encoding="utf-8") == "# DIRTY UNCOMMITTED DIAGNOSTIC WORK\n"
    assert (repo / "untracked_diag.txt").read_text(encoding="utf-8") == "keep-me\n"


@pytest.mark.n2
def test_accept_rejects_flaky_item_and_enforces_locked_sqlite_repro_test(tmp_path: Path) -> None:
    repo = tmp_path / "lock_repo"
    repro_body = "from app_mod import ok\ndef test_repro() -> None:\n    assert ok()\n"
    repro_hash = hashlib.sha256(repro_body.encode("utf-8")).hexdigest()[:16]
    base_sha = _init_repo(
        repo,
        {
            "app_mod.py": "def ok() -> bool:\n    return False\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_repro.py": repro_body,
        },
    )
    cand_flaky_sha = _commit_on_branch(
        repo,
        "qa/cand-flaky",
        {"app_mod.py": "def ok() -> bool:\n    return True\n"},
        base_ref=base_sha,
    )
    cand_tamper_sha = _commit_on_branch(
        repo,
        "qa/cand-tamper-strip",
        {"test_repro.py": "def test_repro() -> None:\n    assert True\n"},
        base_ref=base_sha,
    )

    camp_dir = tmp_path / "camp_lock_accept"
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-int-lock",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        qa_branch="qa/autopilot",
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)
    store = open_campaign_store(camp_dir, state, repo_root=repo)

    upsert_qa_item(
        store,
        state.campaign_id,
        QAFailureItem(
            item_id="item-flaky",
            dedup_key="CB-01:app:flaky",
            case_id="CB-01",
            subsystem="app",
            normalized_signature="flaky",
            severity="P1",
            state="reproduced",
            summary="Flaky item",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command=f"{sys.executable} -m pytest -q test_repro.py",
            repro_test_path="test_repro.py",
        ),
    )
    record_item_probe_outcome(store, state.campaign_id, "item-flaky", passed=True)

    upsert_qa_item(
        store,
        state.campaign_id,
        QAFailureItem(
            item_id="item-locked",
            dedup_key="CB-02:app:locked",
            case_id="CB-02",
            subsystem="app",
            normalized_signature="locked",
            severity="P1",
            state="candidate_verified",
            summary="Locked repro test item",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command=f"{sys.executable} -m pytest -q test_repro.py",
            repro_test_path="test_repro.py",
            repro_test_hash=repro_hash,
        ),
    )

    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    (camp_dir / "candidates" / "cand-flaky.json").write_text(
        CandidateManifest(
            candidate_id="cand-flaky",
            item_id="item-flaky",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=cand_flaky_sha,
            branch_name="qa/cand-flaky",
            rerun_command=f"{sys.executable} -m pytest -q test_repro.py",
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    # Candidate strips repro_test_path & repro_test_hash while tampering test_repro.py
    (camp_dir / "candidates" / "cand-tamper-strip.json").write_text(
        CandidateManifest(
            candidate_id="cand-tamper-strip",
            item_id="item-locked",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=cand_tamper_sha,
            branch_name="qa/cand-tamper-strip",
            repro_test_path=None,
            repro_test_hash=None,
            rerun_command=f"{sys.executable} -m pytest -q test_repro.py",
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="flaky"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-flaky", repo_root=repo)

    with pytest.raises(PolicyImmutabilityError, match="tampered with locked repro test"):
        accept_candidate_to_qa(camp_dir, candidate_id="cand-tamper-strip", repo_root=repo)


@pytest.mark.n2
def test_accept_discovers_tests_dir_without_tests_unit_and_skips_unrelated_failing_test(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "tests_dir_repo"
    base_sha = _init_repo(
        repo,
        {
            "app_mod.py": "def ok() -> bool:\n    return False\n",
            "tests/test_lib.py": "def test_lib() -> None:\n    assert True\n",
            "tests/test_unrelated_open_repro.py": (
                "def test_open_bug() -> None:\n    assert False\n"
            ),
            "tests/test_repro_ok.py": (
                "from app_mod import ok\ndef test_repro_ok() -> None:\n    assert ok()\n"
            ),
        },
    )
    cand_sha = _commit_on_branch(
        repo,
        "qa/cand-tests-dir",
        {"app_mod.py": "def ok() -> bool:\n    return True\n"},
        base_ref=base_sha,
    )

    camp_dir = tmp_path / "camp_tests_dir"
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-int-tests-dir",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        qa_branch="qa/autopilot",
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    upsert_qa_item(
        store,
        state.campaign_id,
        QAFailureItem(
            item_id="item-tests-dir",
            dedup_key="CB-01:app:tests_dir",
            case_id="CB-01",
            subsystem="app",
            normalized_signature="tests_dir",
            severity="P1",
            state="candidate_verified",
            summary="Fix app_mod.ok",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command=f"{sys.executable} -m pytest -q tests/test_repro_ok.py",
            repro_test_path="tests/test_repro_ok.py",
        ),
    )
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    (camp_dir / "candidates" / "cand-tests-dir.json").write_text(
        CandidateManifest(
            candidate_id="cand-tests-dir",
            item_id="item-tests-dir",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=cand_sha,
            branch_name="qa/cand-tests-dir",
            repro_test_path="tests/test_repro_ok.py",
            rerun_command=f"{sys.executable} -m pytest -q tests/test_repro_ok.py",
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    acc = accept_candidate_to_qa(camp_dir, candidate_id="cand-tests-dir", repo_root=repo)
    assert acc["status"] == "accepted_qa"
    assert _git(repo, "rev-parse", "qa/autopilot") == cand_sha


@pytest.mark.n2
def test_repair_loop_skips_duplicate_evaluated_proposal_and_tracks_worker_pid(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "dup_prop_repo"
    base_sha = _init_repo(
        repo,
        {
            "calc.py": "def mul(a: int, b: int) -> int:\n    return a + b\n",
            "test_repro.py": (
                "from calc import mul\ndef test_mul() -> None:\n    assert mul(3, 4) == 12\n"
            ),
        },
    )
    camp_dir = tmp_path / "camp_dup_prop"
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-int-dup",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        qa_branch="qa/autopilot",
        max_attempts_per_item=3,
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    upsert_qa_item(
        store,
        state.campaign_id,
        QAFailureItem(
            item_id="item-dup",
            dedup_key="CB-09:calc:mul_bug",
            case_id="CB-09",
            subsystem="calc",
            normalized_signature="mul_bug",
            severity="P1",
            state="reproduced",
            summary="mul returns a + b",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command=f"{sys.executable} -m pytest -q test_repro.py",
            repro_test_path="test_repro.py",
        ),
    )

    observed_active_pids: list[dict[str, int]] = []

    def _same_bad_repairer(wt: Path, it: QAFailureItem) -> dict[str, str]:
        del wt
        cur_state = CampaignState.model_validate_json(
            (camp_dir / "campaign.json").read_text(encoding="utf-8")
        )
        observed_active_pids.append(dict(cur_state.active_worker_pids))
        assert cur_state.active_worker_pids.get(it.item_id) == os.getpid()
        assert cur_state.active_leases.get(it.item_id)
        return {"calc.py": "def mul(a: int, b: int) -> int:\n    return a - b\n"}

    loop = QARepairLoop(
        campaign_dir=camp_dir,
        repo_root=repo,
        max_parallel=1,
        max_attempts=3,
        auto_accept=False,
        repairer_fn=_same_bad_repairer,
    )
    res1 = loop.run()
    assert res1["worker_results"][0]["outcome"] == "rejected"
    assert res1["worker_results"][0].get("proposal_hash")
    cand_files_1 = list((camp_dir / "candidates").glob("*.json"))
    assert len(cand_files_1) == 1

    # Second run with identical proposal must skip redundant commit/evaluation
    res2 = loop.run()
    assert res2["worker_results"][0]["outcome"] == "skipped_duplicate_proposal"
    assert "duplicate proposal" in res2["worker_results"][0]["skip_reason"].lower()
    cand_files_2 = list((camp_dir / "candidates").glob("*.json"))
    assert len(cand_files_2) == 1
    assert len(observed_active_pids) == 2

    final_state = CampaignState.model_validate_json(
        (camp_dir / "campaign.json").read_text(encoding="utf-8")
    )
    assert final_state.active_worker_pids == {}
    assert final_state.active_leases == {}


@pytest.mark.n2
def test_accept_and_rollback_update_working_tree_when_clean_on_qa_branch(tmp_path: Path) -> None:
    repo = tmp_path / "clean_qa_branch_repo"
    base_sha = _init_repo(
        repo,
        {
            "app_mod.py": "def mul(a: int, b: int) -> int:\n    return a + b\n",
            "test_smoke.py": "def test_smoke() -> None:\n    assert True\n",
            "test_repro.py": (
                "from app_mod import mul\ndef test_mul() -> None:\n    assert mul(3, 4) == 12\n"
            ),
        },
    )
    cand_sha = _commit_on_branch(
        repo,
        "qa/cand-clean-wt",
        {"app_mod.py": "def mul(a: int, b: int) -> int:\n    return a * b\n"},
        base_ref=base_sha,
    )
    _git(repo, "checkout", "qa/autopilot")
    assert "return a + b" in (repo / "app_mod.py").read_text(encoding="utf-8")

    camp_dir = tmp_path / "camp_clean_wt"
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id="qa-int-clean-wt",
        base_sha=base_sha,
        last_accepted_sha=base_sha,
        qa_branch="qa/autopilot",
        output_dir=str(camp_dir),
    )
    save_campaign_state(camp_dir, state)
    store = open_campaign_store(camp_dir, state, repo_root=repo)
    upsert_qa_item(
        store,
        state.campaign_id,
        QAFailureItem(
            item_id="item-clean-wt",
            dedup_key="CB-09:app:mul",
            case_id="CB-09",
            subsystem="app",
            normalized_signature="mul",
            severity="P1",
            state="candidate_verified",
            summary="Fix mul",
            first_seen_sha=base_sha,
            last_seen_sha=base_sha,
            environment_lane="local_deterministic",
            repro_command=f"{sys.executable} -m pytest -q test_repro.py",
            repro_test_path="test_repro.py",
        ),
    )
    (camp_dir / "candidates").mkdir(parents=True, exist_ok=True)
    (camp_dir / "candidates" / "cand-clean-wt.json").write_text(
        CandidateManifest(
            candidate_id="cand-clean-wt",
            item_id="item-clean-wt",
            campaign_id=state.campaign_id,
            base_sha=base_sha,
            candidate_sha=cand_sha,
            branch_name="qa/cand-clean-wt",
            repro_test_path="test_repro.py",
            rerun_command=f"{sys.executable} -m pytest -q test_repro.py",
            baseline_passed=False,
            candidate_passed=True,
            audit_passed=True,
            author_model="hydrogen",
            auditor_model="pro",
            status="candidate_verified",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    acc = accept_candidate_to_qa(camp_dir, candidate_id="cand-clean-wt", repo_root=repo)
    assert acc["status"] == "accepted_qa"
    assert _git(repo, "rev-parse", "HEAD") == cand_sha
    assert _git(repo, "status", "--porcelain") == ""
    assert "return a * b" in (repo / "app_mod.py").read_text(encoding="utf-8")

    rb = rollback_candidate_from_qa(camp_dir, candidate_id="cand-clean-wt", repo_root=repo)
    assert rb["status"] == "rolled_back"
    assert _git(repo, "rev-parse", "HEAD") == base_sha
    assert _git(repo, "status", "--porcelain") == ""
    assert "return a + b" in (repo / "app_mod.py").read_text(encoding="utf-8")
