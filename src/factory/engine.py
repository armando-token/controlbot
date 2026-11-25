"""Autonomous continuous-improvement factory cycle and rollback engine (F16)."""

from __future__ import annotations

import hashlib
import os
import shlex
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from src.contracts.common import FrozenModel, utc_now
from src.factory.db import FactoryStore
from src.factory.errors import (
    DuplicateProposalError,
    FactoryError,
    IsolationBoundaryError,
    PolicyImmutabilityError,
)
from src.factory.models import (
    CandidatePatch,
    CandidateRunRecord,
    CycleBudget,
    FactoryCycleResult,
    FactoryStatus,
    LessonRecord,
    RollbackManifest,
)
from src.factory.policy import IsolationGuard, PolicyGuard


class EvalResult(FrozenModel):
    """Result from running baseline or candidate metric + asset-identity gate."""

    passed: bool
    metric: float | None = None
    wrong_asset_attributions: int = 0
    detail: str = ""


def _sha256_or_missing(path: Path | None) -> str:
    if path is None or not path.exists() or not path.is_file():
        return hashlib.sha256(b"missing").hexdigest()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_git(repo_path: Path, args: Sequence[str]) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or proc.stdout.strip()
        raise FactoryError(f"git {' '.join(args)} failed in {repo_path}: {err_msg}")
    return proc.stdout.strip()


def _run_pytest_suite(repo_path: Path) -> tuple[bool, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_path)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTEST_ADDOPTS", None)
    proc = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-q", "-o", "addopts=", "-p", "no:cacheprovider"],
        cwd=str(repo_path),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    output = (proc.stdout + "\n" + proc.stderr).strip()
    return proc.returncode == 0, output


class FactoryEngine:
    """Executes isolated hypothesis -> repro -> branch edit -> audit -> promote/reject cycles."""

    def __init__(
        self,
        repo_path: Path | str,
        store: FactoryStore,
        *,
        policy_guard: PolicyGuard | None = None,
        budget: CycleBudget | None = None,
        owner: str = "factory-worker-1",
        base_branch: str = "main",
        uv_lock_path: Path | None = None,
        clock: Callable[[], datetime] = utc_now,
        forbidden_db_paths: Sequence[Path | str] = (),
        forbidden_credential_paths: Sequence[Path | str] = (),
        artifacts_dir: Path | None = None,
    ) -> None:
        self._repo_path = Path(repo_path).resolve()
        self._store = store
        self._policy_guard = policy_guard or PolicyGuard()
        self._owner = owner
        self._base_branch = base_branch
        self._uv_lock_path = uv_lock_path
        self._clock = clock
        self._artifacts_dir = (
            artifacts_dir.resolve()
            if artifacts_dir is not None
            else (self._store.db_path.parent / "factory_manifests")
        )

        IsolationGuard.validate_paths(
            self._store.db_path,
            self._repo_path,
            forbidden_db_paths=forbidden_db_paths,
            forbidden_credential_paths=forbidden_credential_paths,
        )
        self._store.init_db()
        self._budget_id = budget.budget_id if budget is not None else "default"
        self._store.ensure_budget(budget)

    @property
    def store(self) -> FactoryStore:
        return self._store

    @property
    def repo_path(self) -> Path:
        return self._repo_path

    def check_pause_state(self, item_id: str | None = None) -> FactoryCycleResult | None:
        """Check whether empty backlog, budget exhaustion, or max attempts forces a clean pause."""
        budget = self._store.get_budget(self._budget_id)
        if budget.cycles_used >= budget.max_cycles or budget.attempts_used >= budget.max_attempts:
            return FactoryCycleResult(
                status=FactoryStatus.PAUSED_BUDGET_EXHAUSTED,
                item_id=item_id,
                reason=(
                    f"FACTORY_BUDGET_EXHAUSTED: cycles={budget.cycles_used}/{budget.max_cycles}, "
                    f"attempts={budget.attempts_used}/{budget.max_attempts}."
                ),
                budget=budget,
            )

        if item_id is not None:
            item = self._store.get_backlog_item(item_id)
            if item is None:
                return FactoryCycleResult(
                    status=FactoryStatus.PAUSED_EMPTY_BACKLOG,
                    reason=f"Backlog item {item_id!r} not found.",
                    budget=budget,
                )
            if item.attempts_used >= item.max_attempts:
                self._store.set_backlog_status(item_id, "paused")
                return FactoryCycleResult(
                    status=FactoryStatus.PAUSED_MAX_ATTEMPTS,
                    item_id=item_id,
                    reason=(
                        f"Backlog item {item_id!r} exhausted max_attempts "
                        f"({item.attempts_used}/{item.max_attempts})."
                    ),
                    budget=budget,
                )
        else:
            next_item = self._store.get_next_pending_item()
            if next_item is None:
                return FactoryCycleResult(
                    status=FactoryStatus.PAUSED_EMPTY_BACKLOG,
                    reason="No pending or in-progress backlog items remaining.",
                    budget=budget,
                )
            if next_item.attempts_used >= next_item.max_attempts:
                self._store.set_backlog_status(next_item.item_id, "paused")
                return FactoryCycleResult(
                    status=FactoryStatus.PAUSED_MAX_ATTEMPTS,
                    item_id=next_item.item_id,
                    reason=(
                        f"Backlog item {next_item.item_id!r} exhausted max_attempts "
                        f"({next_item.attempts_used}/{next_item.max_attempts})."
                    ),
                    budget=budget,
                )

        return None

    def run_candidate_cycle(
        self,
        candidate: CandidatePatch,
        *,
        evaluator: Callable[[Path], EvalResult] | None = None,
        manifest_out: Path | None = None,
        lease_ttl_s: float = 60.0,
    ) -> FactoryCycleResult:
        """Execute one bounded autonomous improvement cycle in an isolated branch."""
        paused = self.check_pause_state(candidate.item_id)
        if paused is not None:
            return paused

        if (
            self._store.has_rejected_proposal(candidate.proposal_hash)
            and not candidate.new_evidence
        ):
            self._store.append_audit_log(
                actor=self._owner,
                action="duplicate_proposal_rejected",
                decision="deny",
                detail={
                    "candidate_id": candidate.candidate_id,
                    "item_id": candidate.item_id,
                    "proposal_hash": candidate.proposal_hash,
                },
            )
            raise DuplicateProposalError(
                f"DUPLICATE_PROPOSAL_REJECTED: proposal_hash={candidate.proposal_hash} "
                "was already rejected and new_evidence=False."
            )

        if candidate.branch_name == self._base_branch:
            raise FactoryError(
                f"Candidate branch_name {candidate.branch_name!r} must be isolated from "
                f"base_branch {self._base_branch!r}."
            )

        started = time.monotonic()
        lease = self._store.acquire_lease(candidate.item_id, self._owner, ttl_s=lease_ttl_s)
        base_commit = _run_git(self._repo_path, ["rev-parse", self._base_branch])
        _run_git(self._repo_path, ["checkout", self._base_branch])

        baseline_passed, baseline_output = _run_pytest_suite(self._repo_path)
        baseline_eval = (
            evaluator(self._repo_path)
            if evaluator is not None
            else EvalResult(passed=baseline_passed)
        )
        baseline_metric = baseline_eval.metric

        candidate_commit: str | None = None
        try:
            _run_git(self._repo_path, ["checkout", "-B", candidate.branch_name, base_commit])

            for rel_path, content in candidate.files_to_modify.items():
                target = (self._repo_path / rel_path).resolve()
                if not target.is_relative_to(self._repo_path):
                    raise IsolationBoundaryError(
                        f"ISOLATION_BOUNDARY_VIOLATION: blocked file path escaping repo: {rel_path}"
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")

            if candidate.repro_test_path and candidate.repro_test_content is not None:
                test_target = (self._repo_path / candidate.repro_test_path).resolve()
                if not test_target.is_relative_to(self._repo_path):
                    raise IsolationBoundaryError(
                        "ISOLATION_BOUNDARY_VIOLATION: blocked repro_test_path escaping repo: "
                        f"{candidate.repro_test_path}"
                    )
                test_target.parent.mkdir(parents=True, exist_ok=True)
                test_target.write_text(candidate.repro_test_content, encoding="utf-8")

            paths_to_stage = list(candidate.files_to_modify.keys())
            if candidate.repro_test_path and candidate.repro_test_content is not None:
                paths_to_stage.append(candidate.repro_test_path)
            if paths_to_stage:
                _run_git(self._repo_path, ["add", "--", *paths_to_stage])
            status_out = _run_git(self._repo_path, ["status", "--porcelain"])
            if status_out:
                _run_git(
                    self._repo_path,
                    ["commit", "-m", f"factory({candidate.candidate_id}): {candidate.hypothesis}"],
                )
            candidate_commit = _run_git(self._repo_path, ["rev-parse", "HEAD"])
            diff_text = _run_git(
                self._repo_path, ["diff", f"{base_commit}..{candidate_commit}"]
            )[:16384]

            # Independent PolicyGuard audit before any regression or promotion
            try:
                self._policy_guard.inspect_git_diff(
                    self._repo_path, base_commit, candidate_commit
                )
            except (PolicyImmutabilityError, IsolationBoundaryError) as exc:
                _run_git(self._repo_path, ["checkout", "-f", self._base_branch])
                assert _run_git(self._repo_path, ["rev-parse", "HEAD"]) == base_commit
                elapsed = time.monotonic() - started
                now = self._clock()
                rec = CandidateRunRecord(
                    run_id=f"frun-{uuid.uuid4().hex[:12]}",
                    candidate_id=candidate.candidate_id,
                    item_id=candidate.item_id,
                    branch_name=candidate.branch_name,
                    base_commit=base_commit,
                    candidate_commit=candidate_commit,
                    proposal_hash=candidate.proposal_hash,
                    baseline_metric=baseline_metric,
                    candidate_metric=None,
                    baseline_passed=baseline_passed,
                    regression_passed=False,
                    identity_gate_passed=False,
                    policy_passed=False,
                    status="REJECTED",
                    reason=str(exc),
                    created_at=now,
                )
                lesson = LessonRecord(
                    lesson_id=f"fles-{uuid.uuid4().hex[:12]}",
                    item_id=candidate.item_id,
                    candidate_id=candidate.candidate_id,
                    proposal_hash=candidate.proposal_hash,
                    outcome="REJECTED",
                    reason=str(exc),
                    regression_test_path=candidate.repro_test_path,
                    reopen_condition="Remove immutable policy or isolation boundary edits.",
                    created_at=now,
                )
                self._store.commit_candidate_attempt(
                    lease=lease,
                    record=rec,
                    lesson=lesson,
                    wall_seconds_delta=elapsed,
                    budget_id=self._budget_id,
                    hypothesis=candidate.hypothesis,
                    diff=diff_text,
                    auditor_signoff="rejected",
                )
                raise

            regression_passed, reg_output = _run_pytest_suite(self._repo_path)
            cand_eval = (
                evaluator(self._repo_path)
                if evaluator is not None
                else EvalResult(passed=regression_passed)
            )
            candidate_metric = cand_eval.metric
            identity_ok = cand_eval.passed and cand_eval.wrong_asset_attributions == 0
            metric_ok = True
            if baseline_metric is not None and candidate_metric is not None:
                metric_ok = candidate_metric < baseline_metric

            elapsed = time.monotonic() - started
            now = self._clock()

            if regression_passed and identity_ok and metric_ok:
                _run_git(self._repo_path, ["checkout", "-f", self._base_branch])
                _run_git(self._repo_path, ["merge", "--ff-only", candidate_commit])
                new_commit = _run_git(self._repo_path, ["rev-parse", "HEAD"])

                uv_hash = _sha256_or_missing(
                    self._uv_lock_path or (self._repo_path / "uv.lock")
                )
                cfg_candidate = (
                    self._repo_path / "pyproject.toml"
                    if (self._repo_path / "pyproject.toml").exists()
                    else None
                )
                cfg_hash = _sha256_or_missing(cfg_candidate)
                restore_cmd = (
                    f"git -C {shlex.quote(str(self._repo_path))} reset --hard {base_commit}"
                )

                target_manifest_path = (
                    manifest_out.resolve()
                    if manifest_out is not None
                    else (self._artifacts_dir / f"rollback_{candidate.candidate_id}.json")
                )
                target_manifest_path.parent.mkdir(parents=True, exist_ok=True)
                manifest = RollbackManifest(
                    candidate_id=candidate.candidate_id,
                    item_id=candidate.item_id,
                    repo_path=str(self._repo_path),
                    branch_name=candidate.branch_name,
                    previous_commit=base_commit,
                    new_commit=new_commit,
                    uv_lock_hash=uv_hash,
                    config_hash=cfg_hash,
                    restore_command=restore_cmd,
                    promoted_at=now,
                )
                target_manifest_path.write_text(
                    manifest.model_dump_json(indent=2) + "\n",
                    encoding="utf-8",
                )

                reason = (
                    f"Promoted: regression passed, identity gate passed, "
                    f"metric {baseline_metric} -> {candidate_metric}."
                )
                rec = CandidateRunRecord(
                    run_id=f"frun-{uuid.uuid4().hex[:12]}",
                    candidate_id=candidate.candidate_id,
                    item_id=candidate.item_id,
                    branch_name=candidate.branch_name,
                    base_commit=base_commit,
                    candidate_commit=new_commit,
                    proposal_hash=candidate.proposal_hash,
                    baseline_metric=baseline_metric,
                    candidate_metric=candidate_metric,
                    baseline_passed=baseline_passed,
                    regression_passed=True,
                    identity_gate_passed=True,
                    policy_passed=True,
                    status="PROMOTED",
                    reason=reason,
                    manifest_path=str(target_manifest_path),
                    created_at=now,
                )
                lesson = LessonRecord(
                    lesson_id=f"fles-{uuid.uuid4().hex[:12]}",
                    item_id=candidate.item_id,
                    candidate_id=candidate.candidate_id,
                    proposal_hash=candidate.proposal_hash,
                    outcome="PROMOTED",
                    reason=reason,
                    regression_test_path=candidate.repro_test_path,
                    created_at=now,
                )
                self._store.commit_candidate_attempt(
                    lease=lease,
                    record=rec,
                    lesson=lesson,
                    manifest=manifest,
                    wall_seconds_delta=elapsed,
                    budget_id=self._budget_id,
                    hypothesis=candidate.hypothesis,
                    diff=diff_text,
                    auditor_signoff="approved",
                )
                return FactoryCycleResult(
                    status=FactoryStatus.PROMOTED,
                    item_id=candidate.item_id,
                    candidate_id=candidate.candidate_id,
                    branch_name=candidate.branch_name,
                    base_commit=base_commit,
                    candidate_commit=new_commit,
                    baseline_metric=baseline_metric,
                    candidate_metric=candidate_metric,
                    manifest_path=str(target_manifest_path),
                    reason=reason,
                    lesson=lesson,
                    budget=self._store.get_budget(self._budget_id),
                )

            # Rejection path: keep base_branch untouched at base_commit
            _run_git(self._repo_path, ["checkout", "-f", self._base_branch])
            head_after = _run_git(self._repo_path, ["rev-parse", "HEAD"])
            if head_after != base_commit:
                _run_git(self._repo_path, ["reset", "--hard", base_commit])

            fail_reasons: list[str] = []
            if not regression_passed:
                fail_reasons.append(f"regression_failed ({reg_output[-200:]})")
            if not identity_ok:
                fail_reasons.append(
                    "identity_gate_failed "
                    f"(wrong_asset_attributions={cand_eval.wrong_asset_attributions}; "
                    f"{cand_eval.detail})"
                )
            if not metric_ok:
                fail_reasons.append(
                    f"no_metric_improvement ({baseline_metric} -> {candidate_metric})"
                )
            reason = "; ".join(fail_reasons) or f"Rejected (baseline={baseline_output[:80]})."

            rec = CandidateRunRecord(
                run_id=f"frun-{uuid.uuid4().hex[:12]}",
                candidate_id=candidate.candidate_id,
                item_id=candidate.item_id,
                branch_name=candidate.branch_name,
                base_commit=base_commit,
                candidate_commit=candidate_commit,
                proposal_hash=candidate.proposal_hash,
                baseline_metric=baseline_metric,
                candidate_metric=candidate_metric,
                baseline_passed=baseline_passed,
                regression_passed=regression_passed,
                identity_gate_passed=identity_ok,
                policy_passed=True,
                status="REJECTED",
                reason=reason,
                created_at=now,
            )
            lesson = LessonRecord(
                lesson_id=f"fles-{uuid.uuid4().hex[:12]}",
                item_id=candidate.item_id,
                candidate_id=candidate.candidate_id,
                proposal_hash=candidate.proposal_hash,
                outcome="REJECTED",
                reason=reason,
                regression_test_path=candidate.repro_test_path,
                reopen_condition="Provide new evidence fixing asset identity/regression failure.",
                created_at=now,
            )
            self._store.commit_candidate_attempt(
                lease=lease,
                record=rec,
                lesson=lesson,
                wall_seconds_delta=elapsed,
                budget_id=self._budget_id,
                hypothesis=candidate.hypothesis,
                diff=diff_text,
                auditor_signoff="rejected",
            )
            return FactoryCycleResult(
                status=FactoryStatus.REJECTED,
                item_id=candidate.item_id,
                candidate_id=candidate.candidate_id,
                branch_name=candidate.branch_name,
                base_commit=base_commit,
                candidate_commit=candidate_commit,
                baseline_metric=baseline_metric,
                candidate_metric=candidate_metric,
                reason=reason,
                lesson=lesson,
                budget=self._store.get_budget(self._budget_id),
            )
        except Exception:
            cur_branch = _run_git(self._repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])
            if cur_branch != self._base_branch:
                _run_git(self._repo_path, ["checkout", "-f", self._base_branch])
            raise

    def audit_branch(
        self,
        branch_name: str,
        *,
        base_branch: str | None = None,
    ) -> dict[str, object]:
        """Independently audit an existing candidate branch without mutating base_branch."""
        ref_base = base_branch or self._base_branch
        base_commit = _run_git(self._repo_path, ["rev-parse", ref_base])
        cand_commit = _run_git(self._repo_path, ["rev-parse", branch_name])
        self._policy_guard.inspect_git_diff(self._repo_path, base_commit, cand_commit)
        return {
            "ok": True,
            "base_branch": ref_base,
            "base_commit": base_commit,
            "branch_name": branch_name,
            "candidate_commit": cand_commit,
            "policy_passed": True,
        }


def rollback_from_manifest(
    manifest_path: Path | str,
    *,
    repo_path: Path | None = None,
    store: FactoryStore | None = None,
) -> dict[str, object]:
    """Load a RollbackManifest JSON and restore git HEAD to previous_commit."""
    path = Path(manifest_path)
    if not path.exists():
        raise FactoryError(f"Rollback manifest not found: {path}")
    if not path.is_file():
        raise FactoryError(f"Rollback manifest path is not a file: {path}")
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FactoryError(f"Cannot read rollback manifest {path}: {exc}") from exc
    if not raw_text.strip():
        raise FactoryError(f"Rollback manifest is empty: {path}")
    try:
        manifest = RollbackManifest.model_validate_json(raw_text)
    except (ValidationError, ValueError) as exc:
        raise FactoryError(f"Invalid or corrupt rollback manifest {path}: {exc}") from exc

    target_repo = (repo_path or Path(manifest.repo_path)).resolve()
    if not target_repo.exists():
        raise FactoryError(f"Target repository for rollback does not exist: {target_repo}")

    _run_git(target_repo, ["reset", "--hard", manifest.previous_commit])
    restored_head = _run_git(target_repo, ["rev-parse", "HEAD"])
    if restored_head != manifest.previous_commit:
        raise FactoryError(
            f"Rollback verification failed: HEAD={restored_head} != {manifest.previous_commit}."
        )
    if store is not None:
        store.mark_manifest_rolled_back(manifest.candidate_id)

    return {
        "ok": True,
        "status": FactoryStatus.ROLLED_BACK.value,
        "candidate_id": manifest.candidate_id,
        "repo_path": str(target_repo),
        "previous_commit": manifest.previous_commit,
        "restored_head": restored_head,
    }
