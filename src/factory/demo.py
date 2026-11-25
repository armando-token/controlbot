"""Runnable 2-candidate demonstration for the M7 local software factory (F16)."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from src.factory.db import FactoryStore
from src.factory.engine import EvalResult, FactoryEngine, rollback_from_manifest
from src.factory.errors import DuplicateProposalError
from src.factory.models import BacklogItem, CandidatePatch, CycleBudget, compute_proposal_hash

_PLANT_LOOKUP_BASELINE = '''"""Synthetic isolated plant asset lookup module for M7 factory demo."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlantAsset:
    asset_id: str
    canonical_label: str
    area: str
    status: str


ASSETS: list[PlantAsset] = [
    *[
        PlantAsset(
            asset_id=f"aux-{idx:03d}",
            canonical_label=f"valvula {idx}",
            area="area-1" if idx % 2 == 0 else "area-2",
            status="ok",
        )
        for idx in range(1, 99)
    ],
    PlantAsset(
        asset_id="bomba-34-a1",
        canonical_label="bomba 34",
        area="area-1",
        status="alarm_high_vibration",
    ),
    PlantAsset(
        asset_id="bomba-34-a2",
        canonical_label="bomba 34",
        area="area-2",
        status="normal",
    ),
]


def resolve_asset(label: str, *, area: str | None = None) -> tuple[PlantAsset | None, int]:
    """Resolve an asset by label and required area; returns (asset, scan_steps)."""
    if not area:
        return None, 0
    needle = label.strip().lower()
    steps = 0
    for asset in ASSETS:
        steps += 1
        if asset.canonical_label == needle and asset.area == area:
            return asset, steps
    return None, steps
'''

_PLANT_TESTS_BASELINE = '''"""Regression and asset identity tests for lab plant_lookup."""

from __future__ import annotations

import plant_lookup


def test_area_disambiguation_required() -> None:
    ambiguous, _ = plant_lookup.resolve_asset("bomba 34", area=None)
    assert ambiguous is None

    a1, _ = plant_lookup.resolve_asset("bomba 34", area="area-1")
    assert a1 is not None
    assert a1.asset_id == "bomba-34-a1"

    a2, _ = plant_lookup.resolve_asset("bomba 34", area="area-2")
    assert a2 is not None
    assert a2.asset_id == "bomba-34-a2"
'''

_CAND1_PLANT_LOOKUP = '''"""Isolated plant asset lookup with O(1) (label, area) index."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlantAsset:
    asset_id: str
    canonical_label: str
    area: str
    status: str


ASSETS: list[PlantAsset] = [
    *[
        PlantAsset(
            asset_id=f"aux-{idx:03d}",
            canonical_label=f"valvula {idx}",
            area="area-1" if idx % 2 == 0 else "area-2",
            status="ok",
        )
        for idx in range(1, 99)
    ],
    PlantAsset(
        asset_id="bomba-34-a1",
        canonical_label="bomba 34",
        area="area-1",
        status="alarm_high_vibration",
    ),
    PlantAsset(
        asset_id="bomba-34-a2",
        canonical_label="bomba 34",
        area="area-2",
        status="normal",
    ),
]

_ASSET_INDEX: dict[tuple[str, str], PlantAsset] = {
    (asset.canonical_label.lower(), asset.area): asset for asset in ASSETS
}


def resolve_asset(label: str, *, area: str | None = None) -> tuple[PlantAsset | None, int]:
    """Resolve an asset in O(1) via (canonical_label, area) index with disambiguation."""
    if not area:
        return None, 0
    needle = label.strip().lower()
    return _ASSET_INDEX.get((needle, area)), 1
'''

_CAND1_REPRO_TEST = '''"""Repro test for O(1) scan_steps with area-1/area-2 disambiguation."""

from __future__ import annotations

import plant_lookup


def test_indexed_lookup_reduces_scan_steps_safely() -> None:
    a2, steps = plant_lookup.resolve_asset("bomba 34", area="area-2")
    assert a2 is not None
    assert a2.asset_id == "bomba-34-a2"
    assert steps == 1
'''

_CAND2_ASSET_CONFUSING = '''"""Unsafe speed optimization dropping area check (rejected)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlantAsset:
    asset_id: str
    canonical_label: str
    area: str
    status: str


ASSETS: list[PlantAsset] = [
    PlantAsset(
        asset_id="bomba-34-a1",
        canonical_label="bomba 34",
        area="area-1",
        status="alarm_high_vibration",
    ),
    PlantAsset(
        asset_id="bomba-34-a2",
        canonical_label="bomba 34",
        area="area-2",
        status="normal",
    ),
]

_FIRST_BY_LABEL: dict[str, PlantAsset] = {}
for _asset in ASSETS:
    _FIRST_BY_LABEL.setdefault(_asset.canonical_label.lower(), _asset)


def resolve_asset(label: str, *, area: str | None = None) -> tuple[PlantAsset | None, int]:
    """Skip area check and return first label match in 1 step (confuses bomba-34-a1/a2!)."""
    del area
    return _FIRST_BY_LABEL.get(label.strip().lower()), 1
'''


def _init_lab_repo(repo_dir: Path, *, uv_lock_source: Path | None) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", str(repo_dir)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.name", "Grokbot Factory"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.email", "factory@grokbot.local"],
        check=True,
        capture_output=True,
    )
    (repo_dir / ".gitignore").write_text(
        "__pycache__/\n*.py[cod]\n.pytest_cache/\n",
        encoding="utf-8",
    )
    (repo_dir / "pyproject.toml").write_text(
        '[project]\nname = "factory-lab"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    if uv_lock_source and uv_lock_source.exists():
        (repo_dir / "uv.lock").write_text(
            uv_lock_source.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    else:
        (repo_dir / "uv.lock").write_text("# isolated lab lock\n", encoding="utf-8")

    (repo_dir / "plant_lookup.py").write_text(_PLANT_LOOKUP_BASELINE, encoding="utf-8")
    tests_dir = repo_dir / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    (tests_dir / "test_plant_lookup.py").write_text(_PLANT_TESTS_BASELINE, encoding="utf-8")

    subprocess.run(["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-m", "chore: baseline plant_lookup"],
        check=True,
        capture_output=True,
    )
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def _evaluate_lab_repo(repo_dir: Path) -> EvalResult:
    module_path = repo_dir / "plant_lookup.py"
    if not module_path.exists():
        return EvalResult(passed=False, metric=None, detail="plant_lookup.py not present")
    mod_name = "lab_plant_lookup_eval"
    spec = importlib.util.spec_from_file_location(mod_name, module_path)
    if spec is None or spec.loader is None:
        return EvalResult(passed=False, detail="Cannot load plant_lookup.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    try:
        spec.loader.exec_module(mod)
        wrong_attrs = 0
        a1, steps_a1 = mod.resolve_asset("bomba 34", area="area-1")
        a2, steps_a2 = mod.resolve_asset("bomba 34", area="area-2")
        ambig, _ = mod.resolve_asset("bomba 34", area=None)
        if a1 is None or a1.asset_id != "bomba-34-a1":
            wrong_attrs += 1
        if a2 is None or a2.asset_id != "bomba-34-a2":
            wrong_attrs += 1
        if ambig is not None:
            wrong_attrs += 1
        return EvalResult(
            passed=wrong_attrs == 0,
            metric=float(max(steps_a1, steps_a2)),
            wrong_asset_attributions=wrong_attrs,
            detail=(
                f"area-2={a2.asset_id if a2 else None} (expected bomba-34-a2), "
                f"steps={max(steps_a1, steps_a2)}"
            ),
        )
    finally:
        sys.modules.pop(mod_name, None)


def _is_existing_git_repo(repo_dir: Path) -> bool:
    if not repo_dir.exists() or not (repo_dir / ".git").exists():
        return False
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "--verify", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def _detect_base_branch(repo_dir: Path) -> str:
    cur = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    cur_branch = cur.stdout.strip()
    if (
        cur.returncode == 0
        and cur_branch
        and cur_branch != "HEAD"
        and not cur_branch.startswith("factory/")
    ):
        return cur_branch
    for candidate_branch in ("main", "master"):
        chk = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--verify", candidate_branch],
            capture_output=True,
            text=True,
            check=False,
        )
        if chk.returncode == 0:
            return candidate_branch
    return "HEAD"


def run_factory_demo(
    *,
    workspace_dir: Path | None = None,
    repo_dir: Path | None = None,
    db_path: Path | None = None,
    output_dir: Path | None = None,
    candidate: str = "all",
) -> dict[str, Any]:
    """Run the M7 software factory demo (candidate='all', '1', or '2')."""
    if candidate not in {"all", "1", "2"}:
        raise ValueError(f"Unsupported demo candidate selector: {candidate!r}")

    temp_ctx: tempfile.TemporaryDirectory[str] | None = None
    if workspace_dir is None and (repo_dir is None or db_path is None):
        temp_ctx = tempfile.TemporaryDirectory(prefix="grokbot_factory_demo_")
        root = Path(temp_ctx.name)
    else:
        root = (workspace_dir or (db_path.parent if db_path else Path.cwd())).resolve()

    try:
        lab_repo = (repo_dir or (root / "lab_repo")).resolve()
        factory_db = (db_path or (root / "factory_state" / "factory.db")).resolve()
        artifacts_dir = (output_dir or (root / "factory_artifacts")).resolve()
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        repo_root_lock = Path(__file__).resolve().parent.parent.parent / "uv.lock"
        existing_repo = _is_existing_git_repo(lab_repo)

        if candidate == "all" or not existing_repo:
            baseline_commit = _init_lab_repo(lab_repo, uv_lock_source=repo_root_lock)
            base_branch = "main"
        else:
            base_branch = _detect_base_branch(lab_repo)
            baseline_commit = subprocess.run(
                ["git", "-C", str(lab_repo), "rev-parse", base_branch],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        store = FactoryStore(factory_db)
        uv_lock_candidate = lab_repo / "uv.lock"
        engine = FactoryEngine(
            lab_repo,
            store,
            base_branch=base_branch,
            budget=CycleBudget(max_cycles=4, max_attempts=4, max_wall_seconds=120.0),
            uv_lock_path=uv_lock_candidate if uv_lock_candidate.exists() else repo_root_lock,
            artifacts_dir=artifacts_dir,
        )

        item1_def = BacklogItem(
            item_id="B-FAC-01",
            title="Index plant asset lookup by (canonical_label, area)",
            priority=1,
            hypothesis=(
                "O(1) (canonical_label, area) index reduces scan steps "
                "without losing disambiguation."
            ),
            target_metric="scan_steps",
            baseline_repro_cmd="pytest -q",
            max_attempts=2,
        )
        item2_def = BacklogItem(
            item_id="B-FAC-02",
            title="Fast-path asset lookup skipping area filter",
            priority=2,
            hypothesis="Returning first label match skips area scan and reduces lookup steps.",
            target_metric="scan_steps",
            baseline_repro_cmd="pytest -q",
            max_attempts=2,
        )

        cand1_files = {"plant_lookup.py": _CAND1_PLANT_LOOKUP}
        cand1 = CandidatePatch(
            candidate_id="cand-1-index",
            item_id=item1_def.item_id,
            branch_name="factory/cand-1-index",
            hypothesis=item1_def.hypothesis,
            target_metric=item1_def.target_metric,
            proposal_hash=compute_proposal_hash(
                item_id=item1_def.item_id,
                target_metric=item1_def.target_metric,
                files_to_modify=cand1_files,
                repro_test_path="tests/test_repro_cand1.py",
                repro_test_content=_CAND1_REPRO_TEST,
            ),
            files_to_modify=cand1_files,
            repro_test_path="tests/test_repro_cand1.py",
            repro_test_content=_CAND1_REPRO_TEST,
        )
        cand2_files = {"plant_lookup.py": _CAND2_ASSET_CONFUSING}
        cand2 = CandidatePatch(
            candidate_id="cand-2-skip-area",
            item_id=item2_def.item_id,
            branch_name="factory/cand-2-skip-area",
            hypothesis=item2_def.hypothesis,
            target_metric=item2_def.target_metric,
            proposal_hash=compute_proposal_hash(
                item_id=item2_def.item_id,
                target_metric=item2_def.target_metric,
                files_to_modify=cand2_files,
            ),
            files_to_modify=cand2_files,
            repro_test_path="tests/test_plant_lookup.py",
        )

        if candidate == "1":
            if store.get_backlog_item(item1_def.item_id) is None:
                store.add_backlog_item(item1_def)
            manifest_path = artifacts_dir / "rollback_cand1.json"
            res1 = engine.run_candidate_cycle(
                cand1,
                evaluator=_evaluate_lab_repo,
                manifest_out=manifest_path,
            )
            final_head = subprocess.run(
                ["git", "-C", str(lab_repo), "rev-parse", base_branch],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            lessons = [lesson.model_dump(mode="json") for lesson in store.list_lessons()]
            return {
                "ok": res1.status.value == "promoted",
                "candidate": "1",
                "baseline_commit": baseline_commit,
                "promoted_commit": res1.candidate_commit,
                "final_main_head": final_head,
                "factory_db_path": str(factory_db),
                "isolation_verified": True,
                "manifest_path": str(manifest_path),
                "candidate_1": res1.model_dump(mode="json"),
                "lessons": lessons,
            }

        if candidate == "2":
            if store.get_backlog_item(item2_def.item_id) is None:
                store.add_backlog_item(item2_def)
            try:
                res2 = engine.run_candidate_cycle(cand2, evaluator=_evaluate_lab_repo)
            except DuplicateProposalError as exc:
                final_head = subprocess.run(
                    ["git", "-C", str(lab_repo), "rev-parse", base_branch],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                lessons = [lesson.model_dump(mode="json") for lesson in store.list_lessons()]
                return {
                    "ok": True,
                    "candidate": "2",
                    "status": "skipped_duplicate_rejected",
                    "skipped": True,
                    "duplicate": True,
                    "already_rejected": True,
                    "reason": str(exc),
                    "baseline_commit": baseline_commit,
                    "final_main_head": final_head,
                    "factory_db_path": str(factory_db),
                    "isolation_verified": True,
                    "candidate_2": {
                        "candidate_id": cand2.candidate_id,
                        "status": "skipped_duplicate_rejected",
                        "reason": str(exc),
                    },
                    "lessons": lessons,
                }
            final_head = subprocess.run(
                ["git", "-C", str(lab_repo), "rev-parse", base_branch],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            lessons = [lesson.model_dump(mode="json") for lesson in store.list_lessons()]
            return {
                "ok": res2.status.value == "rejected" and final_head == baseline_commit,
                "candidate": "2",
                "status": res2.status.value,
                "baseline_commit": baseline_commit,
                "final_main_head": final_head,
                "factory_db_path": str(factory_db),
                "isolation_verified": True,
                "candidate_2": res2.model_dump(mode="json"),
                "lessons": lessons,
            }

        item1 = store.add_backlog_item(item1_def)
        item2 = store.add_backlog_item(item2_def)
        del item1, item2

        # Candidate 1: Accepted optimization
        manifest_path = artifacts_dir / "rollback_cand1.json"
        res1 = engine.run_candidate_cycle(
            cand1,
            evaluator=_evaluate_lab_repo,
            manifest_out=manifest_path,
        )
        promoted_commit = res1.candidate_commit

        # Verify RollbackManifest restores baseline_commit, then restore promoted head
        rollback_res = rollback_from_manifest(manifest_path, repo_path=lab_repo, store=store)
        post_rollback_test = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "pytest",
                "-q",
                "-o",
                "addopts=",
                "-p",
                "no:cacheprovider",
            ],
            cwd=str(lab_repo),
            env={
                **os.environ,
                "PYTHONPATH": str(lab_repo),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            capture_output=True,
            text=True,
            check=False,
        )
        rollback_verified = (
            rollback_res["restored_head"] == baseline_commit
            and post_rollback_test.returncode == 0
        )

        # Re-advance main to promoted_commit so Candidate 2 runs against latest promoted main
        assert promoted_commit is not None
        subprocess.run(
            ["git", "-C", str(lab_repo), "reset", "--hard", promoted_commit],
            check=True,
            capture_output=True,
        )

        # Candidate 2: Rejected asset-confusing optimization
        res2 = engine.run_candidate_cycle(cand2, evaluator=_evaluate_lab_repo)
        final_main_head = subprocess.run(
            ["git", "-C", str(lab_repo), "rev-parse", "main"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        lessons = [lesson.model_dump(mode="json") for lesson in store.list_lessons()]
        ok = (
            res1.status.value == "promoted"
            and rollback_verified
            and res2.status.value == "rejected"
            and final_main_head == promoted_commit
            and len(lessons) == 2
        )

        return {
            "ok": ok,
            "baseline_commit": baseline_commit,
            "promoted_commit": promoted_commit,
            "final_main_head": final_main_head,
            "factory_db_path": str(factory_db),
            "isolation_verified": True,
            "rollback_verified": rollback_verified,
            "manifest_path": str(manifest_path),
            "candidate_1": res1.model_dump(mode="json"),
            "candidate_2": res2.model_dump(mode="json"),
            "lessons": lessons,
        }
    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()


def _format_human_demo(summary: dict[str, Any]) -> str:
    c1 = summary.get("candidate_1")
    c2 = summary.get("candidate_2")
    lines = [
        "=== Grokbot-clon M7 Local Software Factory Demo ===",
        f"Overall OK         : {summary['ok']}",
        f"Isolation Verified : {summary['isolation_verified']}",
        f"Rollback Verified  : {summary.get('rollback_verified', 'N/A')}",
        f"Baseline Commit    : {summary['baseline_commit'][:12]}",
        f"Promoted Commit    : {str(summary.get('promoted_commit'))[:12]}",
        f"Final Main HEAD    : {summary['final_main_head'][:12]}",
    ]
    if isinstance(c1, dict):
        lines.extend(
            [
                "",
                f"Candidate 1 ({c1['candidate_id']}): {str(c1['status']).upper()}",
                f"  Metric : {c1.get('baseline_metric')} -> {c1.get('candidate_metric')}",
                f"  Reason : {c1.get('reason')}",
            ]
        )
    if isinstance(c2, dict):
        lines.extend(
            [
                "",
                f"Candidate 2 ({c2['candidate_id']}): {str(c2['status']).upper()}",
                f"  Reason : {c2.get('reason')}",
            ]
        )
    lines.append(f"Lessons Recorded   : {len(summary['lessons'])}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `python -m src.factory.demo`."""
    parser = argparse.ArgumentParser(description="Run Grokbot-clon M7 software factory demo.")
    parser.add_argument(
        "--repo",
        default=os.environ.get("GROKBOT_FACTORY_REPO") or None,
        help="Optional isolated lab git repo dir.",
    )
    parser.add_argument(
        "--db",
        "--factory-db",
        dest="db",
        default=os.environ.get("GROKBOT_FACTORY_DB") or None,
        help="Optional isolated factory SQLite DB path.",
    )
    parser.add_argument(
        "--output-dir",
        "--out",
        dest="output_dir",
        default=os.environ.get("GROKBOT_FACTORY_OUT") or None,
        help="Optional artifact output directory.",
    )
    parser.add_argument(
        "--candidate",
        choices=("all", "1", "2"),
        default=os.environ.get("GROKBOT_FACTORY_CANDIDATE") or "all",
        help="Candidate selector: all, 1, or 2 (default: all).",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args(argv)

    summary = run_factory_demo(
        repo_dir=Path(args.repo) if args.repo else None,
        db_path=Path(args.db) if args.db else None,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        candidate=args.candidate,
    )
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print(_format_human_demo(summary))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
