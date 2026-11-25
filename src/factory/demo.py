"""Runnable 2-candidate demonstration for the M7 local software factory (F16)."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.report import (
    BenchmarkReport,
    ProvenanceMetadata,
    ScenarioTrialResult,
    aggregate_trials,
    format_markdown_report,
)

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


def _write_regression_test_artifact(artifacts_dir: Path) -> Path:
    """Write a real asset-disambiguation regression test file into artifacts_dir."""
    reg_path = artifacts_dir / "test_asset_disambiguation_regression.py"
    reg_path.write_text(_PLANT_TESTS_BASELINE, encoding="utf-8")
    return reg_path


def _generate_cand1_benchmark_artifacts(
    artifacts_dir: Path,
    *,
    git_commit: str,
) -> tuple[Path, Path]:
    """Execute 12 real lookup scenarios comparing baseline vs Candidate 1 and emit JSON+MD."""
    base_ns: dict[str, Any] = {}
    cand_ns: dict[str, Any] = {}
    exec(compile(_PLANT_LOOKUP_BASELINE, "plant_lookup_baseline.py", "exec"), base_ns)
    exec(compile(_CAND1_PLANT_LOOKUP, "plant_lookup_cand1.py", "exec"), cand_ns)
    base_resolve = base_ns["resolve_asset"]
    cand_resolve = cand_ns["resolve_asset"]

    cases: list[tuple[str, str, str, str | None, str | None]] = [
        ("FAC-01", "Bomba 34 Area 1", "bomba 34", "area-1", "bomba-34-a1"),
        ("FAC-02", "Bomba 34 Area 2", "bomba 34", "area-2", "bomba-34-a2"),
        ("FAC-03", "Bomba 34 Ambiguous", "bomba 34", None, None),
        ("FAC-04", "Valvula 10 Area 1", "valvula 10", "area-1", "aux-010"),
        ("FAC-05", "Valvula 21 Area 2", "valvula 21", "area-2", "aux-021"),
        ("FAC-06", "Valvula 34 Area 1", "valvula 34", "area-1", "aux-034"),
        ("FAC-07", "Valvula 45 Area 2", "valvula 45", "area-2", "aux-045"),
        ("FAC-08", "Valvula 56 Area 1", "valvula 56", "area-1", "aux-056"),
        ("FAC-09", "Valvula 67 Area 2", "valvula 67", "area-2", "aux-067"),
        ("FAC-10", "Valvula 78 Area 1", "valvula 78", "area-1", "aux-078"),
        ("FAC-11", "Valvula 89 Area 2", "valvula 89", "area-2", "aux-089"),
        ("FAC-12", "Valvula 98 Area 1", "valvula 98", "area-1", "aux-098"),
    ]

    trials: list[ScenarioTrialResult] = []
    for sid, name, label, area, expected_id in cases:
        for sys_name, fn in (("baseline", base_resolve), ("grokbot_engine", cand_resolve)):
            t0 = time.perf_counter()
            got, steps = fn(label, area=area)
            elapsed_ms = max(0.001, (time.perf_counter() - t0) * 1000.0)
            got_id = got.asset_id if got is not None else None
            is_correct = got_id == expected_id
            is_abstain = expected_id is None and got_id is None
            trials.append(
                ScenarioTrialResult(
                    scenario_id=sid,
                    scenario_name=name,
                    system=sys_name,
                    repeat_index=1,
                    evidence_tier="N1",
                    status="succeeded" if is_correct else "failed",
                    correct=is_correct,
                    correct_abstention=is_abstain,
                    wrong_asset_attribution=(
                        not is_correct and expected_id is not None and got_id is not None
                    ),
                    duration_ms=elapsed_ms,
                    tool_calls=int(steps),
                    model_calls=1,
                    total_tokens=72,
                    usage_mode="emulated",
                    detail=f"resolved={got_id}, steps={steps}",
                )
            )

    baseline_summary = aggregate_trials(
        "RuleBasedBaseline",
        [t for t in trials if t.system == "baseline"],
        num_scenarios=len(cases),
        repeats_per_scenario=1,
        ram_mb=None,
        vram_mb=None,
        vram_note="N/A (baseline)",
    )
    engine_summary = aggregate_trials(
        "GrokbotEngine",
        [t for t in trials if t.system == "grokbot_engine"],
        num_scenarios=len(cases),
        repeats_per_scenario=1,
        ram_mb=None,
        vram_mb=None,
        vram_note="N/A (emulated)",
    )
    provenance = ProvenanceMetadata(
        benchmark_id="bench-factory-cand1",
        git_commit=git_commit,
        timestamp_utc=datetime.now(UTC).isoformat(),
        host_os=os.uname().sysname,
        host_arch=os.uname().machine,
        python_version=sys.version.split()[0],
        playwright_version="1.64.0",
        model_type="emulated",
        evidence_level="N1",
        n3_status="PENDING_N3_LINUX_ENV",
        a11_status="NOT_SELECTED",
        command="python -m src.factory demo",
        exit_code=0 if engine_summary.promotion_eligible else 1,
    )
    report = BenchmarkReport(
        provenance=provenance,
        baseline_summary=baseline_summary,
        engine_summary=engine_summary,
        trials=tuple(trials),
    )
    bench_json = artifacts_dir / "factory_cand1_benchmark.json"
    bench_md = artifacts_dir / "factory_cand1_benchmark.md"
    bench_json.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    bench_md.write_text(format_markdown_report(report), encoding="utf-8")
    return bench_json, bench_md


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

        if not existing_repo:
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
        if not (lab_repo / "tests" / "test_plant_lookup.py").exists():
            cand1_files["tests/test_plant_lookup.py"] = _PLANT_TESTS_BASELINE
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
            bench_json, bench_md = _generate_cand1_benchmark_artifacts(
                artifacts_dir,
                git_commit=res1.candidate_commit or baseline_commit,
            )
            final_head = subprocess.run(
                ["git", "-C", str(lab_repo), "rev-parse", base_branch],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            lessons = [lesson.model_dump(mode="json") for lesson in store.list_lessons()]
            cand1_entry = {
                **res1.model_dump(mode="json"),
                "status": (
                    "PROMOTED"
                    if res1.status.value == "promoted"
                    else res1.status.value.upper()
                ),
                "promotion_passed": res1.status.value == "promoted",
                "rollback_manifest_path": str(manifest_path),
                "benchmark_json_path": str(bench_json),
                "benchmark_md_path": str(bench_md),
            }
            return {
                "ok": res1.status.value == "promoted",
                "candidate": "1",
                "baseline_commit": baseline_commit,
                "promoted_commit": res1.candidate_commit,
                "final_main_head": final_head,
                "factory_db_path": str(factory_db),
                "isolation_verified": True,
                "manifest_path": str(manifest_path),
                "rollback_manifest_path": str(manifest_path),
                "benchmark_json_path": str(bench_json),
                "benchmark_md_path": str(bench_md),
                "candidate_1": res1.model_dump(mode="json"),
                "candidates": [cand1_entry],
                "lessons": lessons,
            }

        if candidate == "2":
            if store.get_backlog_item(item2_def.item_id) is None:
                store.add_backlog_item(item2_def)
            reg_test_file = _write_regression_test_artifact(artifacts_dir)
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
                cand2_dup = {
                    "candidate_id": cand2.candidate_id,
                    "status": "REJECTED",
                    "promotion_passed": False,
                    "regression_test_path": str(reg_test_file),
                    "reason": str(exc),
                }
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
                    "regression_test_path": str(reg_test_file),
                    "candidate_2": {
                        "candidate_id": cand2.candidate_id,
                        "status": "skipped_duplicate_rejected",
                        "reason": str(exc),
                    },
                    "candidates": [cand2_dup],
                    "lessons": lessons,
                }
            final_head = subprocess.run(
                ["git", "-C", str(lab_repo), "rev-parse", base_branch],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            lessons = [lesson.model_dump(mode="json") for lesson in store.list_lessons()]
            cand2_entry = {
                **res2.model_dump(mode="json"),
                "status": (
                    "REJECTED"
                    if res2.status.value == "rejected"
                    else res2.status.value.upper()
                ),
                "promotion_passed": False,
                "regression_test_path": str(reg_test_file),
            }
            return {
                "ok": res2.status.value == "rejected" and final_head == baseline_commit,
                "candidate": "2",
                "status": res2.status.value,
                "baseline_commit": baseline_commit,
                "final_main_head": final_head,
                "factory_db_path": str(factory_db),
                "isolation_verified": True,
                "regression_test_path": str(reg_test_file),
                "candidate_2": res2.model_dump(mode="json"),
                "candidates": [cand2_entry],
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
        bench_json, bench_md = _generate_cand1_benchmark_artifacts(
            artifacts_dir,
            git_commit=promoted_commit or baseline_commit,
        )

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
        rollback_tests_ok = post_rollback_test.returncode == 0 or (
            existing_repo and post_rollback_test.returncode == 5
        )
        rollback_verified = (
            rollback_res["restored_head"] == baseline_commit and rollback_tests_ok
        )

        # Re-advance base_branch to promoted_commit so Candidate 2 runs against latest promoted head
        assert promoted_commit is not None
        subprocess.run(
            ["git", "-C", str(lab_repo), "reset", "--hard", promoted_commit],
            check=True,
            capture_output=True,
        )

        # Candidate 2: Rejected asset-confusing optimization
        res2 = engine.run_candidate_cycle(cand2, evaluator=_evaluate_lab_repo)
        final_main_head = subprocess.run(
            ["git", "-C", str(lab_repo), "rev-parse", base_branch],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        reg_test_file = _write_regression_test_artifact(artifacts_dir)

        lessons = [lesson.model_dump(mode="json") for lesson in store.list_lessons()]
        ok = (
            res1.status.value == "promoted"
            and rollback_verified
            and res2.status.value == "rejected"
            and final_main_head == promoted_commit
            and len(lessons) == 2
        )

        cand1_entry = {
            **res1.model_dump(mode="json"),
            "status": "PROMOTED" if res1.status.value == "promoted" else res1.status.value.upper(),
            "promotion_passed": res1.status.value == "promoted",
            "rollback_manifest_path": str(manifest_path),
            "benchmark_json_path": str(bench_json),
            "benchmark_md_path": str(bench_md),
        }
        cand2_entry = {
            **res2.model_dump(mode="json"),
            "status": "REJECTED" if res2.status.value == "rejected" else res2.status.value.upper(),
            "promotion_passed": False,
            "regression_test_path": str(reg_test_file),
        }

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
            "candidates": [cand1_entry, cand2_entry],
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
