"""Autonomous continuous-improvement factory cycle and rollback engine (F16)."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import posixpath
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
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
from src.factory.policy import IsolationGuard, PolicyGuard, _norm_fold


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


def _ensure_no_symlink_components(repo_path: Path, rel_path: str) -> Path:
    if "\x00" in rel_path:
        raise IsolationBoundaryError(
            f"ISOLATION_BOUNDARY_VIOLATION: blocked file path with null byte: {rel_path!r}"
        )
    raw_norm = posixpath.normpath(rel_path.strip().replace("\\", "/"))
    if (
        not raw_norm
        or raw_norm == "."
        or raw_norm.startswith("/")
        or ".." in raw_norm.split("/")
    ):
        raise IsolationBoundaryError(
            f"ISOLATION_BOUNDARY_VIOLATION: blocked file path escaping repo: {rel_path}"
        )
    parts = [part for part in Path(raw_norm).parts if part]
    if any(_norm_fold(part) in {".git", ".gitmodules", ".gitattributes"} for part in parts):
        raise PolicyImmutabilityError(
            f"POLICY_IMMUTABILITY_VIOLATION: blocked git-internal path {rel_path!r}.",
            offending_paths=(rel_path,),
        )
    cur = repo_path
    for part in parts:
        cur = cur / part
        if cur.is_symlink():
            raise PolicyImmutabilityError(
                f"POLICY_IMMUTABILITY_VIOLATION: blocked symlink path component "
                f"{part!r} in {rel_path!r}.",
                offending_paths=(rel_path,),
            )
    resolved = (repo_path / raw_norm).resolve()
    if not resolved.is_relative_to(repo_path):
        raise IsolationBoundaryError(
            f"ISOLATION_BOUNDARY_VIOLATION: blocked file path escaping repo: {rel_path}"
        )
    return resolved


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


def _is_clean_working_tree(repo_path: Path) -> bool:
    """Return True if repo_path has no dirty tracked files or non-cache untracked files."""
    status_out = _run_git(repo_path, ["status", "--porcelain"])
    for line in status_out.splitlines():
        if not line.strip():
            continue
        if line.startswith("?? "):
            rel = line[3:].strip().strip('"').rstrip("/")
            parts = Path(rel).parts
            if ".pytest_cache" in parts or "__pycache__" in parts:
                continue
        return False
    return True


_FACTORY_WORKTREE_LOCKS_GUARD = threading.Lock()
_FACTORY_WORKTREE_LOCKS: dict[str, threading.Lock] = {}


def _resolve_git_common_dir(repo_root: Path) -> Path | None:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    common = Path(proc.stdout.strip())
    return (repo_root / common).resolve() if not common.is_absolute() else common.resolve()


@contextlib.contextmanager
def _git_worktree_metadata_lock(repo_root: Path) -> Iterator[None]:
    """Serialize git worktree metadata mutations per repository (thread + process)."""
    common_git_dir = _resolve_git_common_dir(repo_root)
    lock_key = str(common_git_dir if common_git_dir is not None else repo_root)
    with _FACTORY_WORKTREE_LOCKS_GUARD:
        thread_lock = _FACTORY_WORKTREE_LOCKS.get(lock_key)
        if thread_lock is None:
            thread_lock = threading.Lock()
            _FACTORY_WORKTREE_LOCKS[lock_key] = thread_lock

    with thread_lock:
        lock_fd: int | None = None
        if common_git_dir is not None and common_git_dir.is_dir():
            lock_path = common_git_dir / "cb_qa_worktree.lock"
            try:
                lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except OSError:
                if lock_fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(lock_fd)
                    lock_fd = None
        try:
            yield
        finally:
            if lock_fd is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                with contextlib.suppress(OSError):
                    os.close(lock_fd)


@contextlib.contextmanager
def _ephemeral_worktree(repo_path: Path, *, ref: str) -> Iterator[Path]:
    """Create a detached temporary git worktree without touching repo_path's working tree."""
    resolved_repo = repo_path.resolve()
    tmp_dir = Path(tempfile.mkdtemp(prefix="factory_wt_"))
    wt_dir = tmp_dir / f"wt_{uuid.uuid4().hex[:12]}"
    with _git_worktree_metadata_lock(resolved_repo):
        proc = subprocess.run(
            ["git", "-C", str(resolved_repo), "worktree", "add", "--detach", str(wt_dir), ref],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            subprocess.run(
                ["git", "-C", str(resolved_repo), "worktree", "prune"],
                capture_output=True,
                text=True,
                check=False,
            )
    if proc.returncode != 0:
        raise FactoryError(f"git worktree add failed in {resolved_repo}: {proc.stderr.strip()}")
    try:
        yield wt_dir
    finally:
        with _git_worktree_metadata_lock(resolved_repo):
            rm_proc = subprocess.run(
                ["git", "-C", str(resolved_repo), "worktree", "remove", "--force", str(wt_dir)],
                capture_output=True,
                text=True,
                check=False,
            )
            shutil.rmtree(tmp_dir, ignore_errors=True)
            if rm_proc.returncode != 0:
                subprocess.run(
                    ["git", "-C", str(resolved_repo), "worktree", "prune"],
                    capture_output=True,
                    text=True,
                    check=False,
                )


def _run_pytest_suite(
    repo_path: Path,
    *,
    pytest_args: Sequence[str] = (),
) -> tuple[bool, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_path)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTEST_ADDOPTS", None)
    cmd = [
        sys.executable,
        "-B",
        "-m",
        "pytest",
        "-q",
        "-o",
        "addopts=",
        "-p",
        "no:cacheprovider",
        *pytest_args,
    ]
    proc = subprocess.run(
        cmd,
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
        self._policy_guard = policy_guard or PolicyGuard(
            forbidden_paths=[*forbidden_db_paths, *forbidden_credential_paths]
        )
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
        run_full_pytest: bool = True,
        pytest_args: Sequence[str] = (),
        promote_to_base: bool = True,
        forensic_audit: Callable[[Path, str, str], tuple[bool, str]] | None = None,
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

        if run_full_pytest or pytest_args:
            baseline_passed, baseline_output = _run_pytest_suite(
                self._repo_path, pytest_args=pytest_args
            )
            baseline_eval = (
                evaluator(self._repo_path)
                if evaluator is not None
                else EvalResult(passed=baseline_passed)
            )
        else:
            baseline_eval = (
                evaluator(self._repo_path)
                if evaluator is not None
                else EvalResult(passed=True, detail="pytest skipped")
            )
            baseline_passed = baseline_eval.passed
            baseline_output = baseline_eval.detail
        baseline_metric = baseline_eval.metric

        candidate_commit: str | None = None
        diff_text = ""
        try:
            _run_git(self._repo_path, ["checkout", "-B", candidate.branch_name, base_commit])

            paths_to_stage = list(candidate.files_to_modify.keys())
            if candidate.repro_test_path and candidate.repro_test_content is not None:
                paths_to_stage.append(candidate.repro_test_path)

            try:
                if paths_to_stage:
                    self._policy_guard.check_candidate_paths(paths_to_stage)
                    self._policy_guard.check_repo_symlinks(self._repo_path, paths_to_stage)
                resolved_writes: list[tuple[Path, str]] = []
                for rel_path, content in candidate.files_to_modify.items():
                    target = _ensure_no_symlink_components(self._repo_path, rel_path)
                    resolved_writes.append((target, content))
                if candidate.repro_test_path and candidate.repro_test_content is not None:
                    test_target = _ensure_no_symlink_components(
                        self._repo_path, candidate.repro_test_path
                    )
                    resolved_writes.append((test_target, candidate.repro_test_content))

                for target, content in resolved_writes:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8")

                if paths_to_stage:
                    _run_git(self._repo_path, ["add", "--", *paths_to_stage])
                status_out = _run_git(self._repo_path, ["status", "--porcelain"])
                if status_out:
                    _run_git(
                        self._repo_path,
                        [
                            "commit",
                            "-m",
                            f"factory({candidate.candidate_id}): {candidate.hypothesis}",
                        ],
                    )
                dirty_tracked = _run_git(self._repo_path, ["diff", "--name-only"])
                dirty_staged = (
                    _run_git(
                        self._repo_path, ["status", "--porcelain", "--", *paths_to_stage]
                    )
                    if paths_to_stage
                    else ""
                )
                if dirty_tracked or dirty_staged:
                    raise IsolationBoundaryError(
                        "ISOLATION_BOUNDARY_VIOLATION: dirty worktree remained after "
                        f"candidate commit: {dirty_tracked or dirty_staged}"
                    )
                candidate_commit = _run_git(self._repo_path, ["rev-parse", "HEAD"])
                diff_text = _run_git(
                    self._repo_path, ["diff", f"{base_commit}..{candidate_commit}"]
                )[:16384]

                # Independent PolicyGuard audit before any regression or promotion
                self._policy_guard.inspect_git_diff(
                    self._repo_path, base_commit, candidate_commit
                )
                if forensic_audit is not None:
                    audit_ok, audit_reason = forensic_audit(
                        self._repo_path, base_commit, candidate_commit
                    )
                    if not audit_ok:
                        raise PolicyImmutabilityError(
                            f"FORENSIC_AUDIT_FAILED: {audit_reason}",
                            offending_paths=(),
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
                    candidate_commit=candidate_commit or base_commit,
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
                    author_model=candidate.author_model,
                    auditor_model=candidate.auditor_model,
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

            if run_full_pytest or pytest_args:
                regression_passed, reg_output = _run_pytest_suite(
                    self._repo_path, pytest_args=pytest_args
                )
                cand_eval = (
                    evaluator(self._repo_path)
                    if evaluator is not None
                    else EvalResult(passed=regression_passed)
                )
            else:
                cand_eval = (
                    evaluator(self._repo_path)
                    if evaluator is not None
                    else EvalResult(passed=True, detail="pytest skipped")
                )
                regression_passed = cand_eval.passed
                reg_output = cand_eval.detail
            candidate_metric = cand_eval.metric
            identity_ok = cand_eval.passed and cand_eval.wrong_asset_attributions == 0
            metric_ok = True
            if baseline_metric is not None and candidate_metric is not None:
                metric_ok = candidate_metric < baseline_metric

            elapsed = time.monotonic() - started
            now = self._clock()

            if regression_passed and identity_ok and metric_ok:
                if not promote_to_base:
                    _run_git(self._repo_path, ["checkout", "-f", self._base_branch])
                    assert candidate_commit is not None
                    reason = (
                        "Verified on candidate branch (awaiting serialized integrator promotion): "
                        f"metric {baseline_metric} -> {candidate_metric}."
                    )
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
                        regression_passed=True,
                        identity_gate_passed=True,
                        policy_passed=True,
                        status="PROMOTED",
                        reason=reason,
                        manifest_path=None,
                        created_at=now,
                        author_model=candidate.author_model,
                        auditor_model=candidate.auditor_model,
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
                        manifest=None,
                        wall_seconds_delta=elapsed,
                        budget_id=self._budget_id,
                        hypothesis=candidate.hypothesis,
                        diff=diff_text,
                        auditor_signoff="approved",
                    )
                    self._store.set_backlog_status(candidate.item_id, "pending")
                    return FactoryCycleResult(
                        status=FactoryStatus.PROMOTED,
                        item_id=candidate.item_id,
                        candidate_id=candidate.candidate_id,
                        branch_name=candidate.branch_name,
                        base_commit=base_commit,
                        candidate_commit=candidate_commit,
                        baseline_metric=baseline_metric,
                        candidate_metric=candidate_metric,
                        manifest_path=None,
                        reason=reason,
                        lesson=lesson,
                        budget=self._store.get_budget(self._budget_id),
                    )

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
                    author_model=candidate.author_model,
                    auditor_model=candidate.auditor_model,
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
            with contextlib.suppress(FactoryError):
                _run_git(self._repo_path, ["reset", "--hard", base_commit])
            _run_git(self._repo_path, ["checkout", "-f", self._base_branch])
            raise

    def promote_candidate_branch(
        self,
        candidate: CandidatePatch,
        *,
        candidate_commit: str | None = None,
        base_commit: str | None = None,
        target_branch: str | None = None,
        evaluator: Callable[[Path], EvalResult] | None = None,
        manifest_out: Path | None = None,
        rebase_on_drift: bool = True,
        pytest_args: Sequence[str] = (),
        run_full_pytest: bool = True,
        extra_forbidden_paths: Sequence[Path | str] = (),
    ) -> FactoryCycleResult:
        """Promote a verified candidate branch onto target_branch in an isolated worktree."""
        target = target_branch or self._base_branch
        short_target = target.removeprefix("refs/heads/")
        target_ref = target if target.startswith("refs/") else f"refs/heads/{short_target}"
        current_tip = _run_git(self._repo_path, ["rev-parse", target_ref])
        cand_sha = candidate_commit or _run_git(
            self._repo_path, ["rev-parse", candidate.branch_name]
        )
        orig_base = base_commit or _run_git(
            self._repo_path, ["merge-base", current_tip, cand_sha]
        )

        anc_proc = subprocess.run(
            [
                "git",
                "-C",
                str(self._repo_path),
                "merge-base",
                "--is-ancestor",
                current_tip,
                cand_sha,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if anc_proc.returncode != 0 and not rebase_on_drift:
            return FactoryCycleResult(
                status=FactoryStatus.REJECTED,
                item_id=candidate.item_id,
                candidate_id=candidate.candidate_id,
                branch_name=candidate.branch_name,
                base_commit=current_tip,
                candidate_commit=cand_sha,
                reason=f"Target branch {target!r} drifted and rebase_on_drift=False.",
            )

        wt_start_ref = cand_sha if anc_proc.returncode == 0 else current_tip
        with _ephemeral_worktree(self._repo_path, ref=wt_start_ref) as eval_wt:
            if anc_proc.returncode == 0:
                integrated_sha = cand_sha
            else:
                if orig_base != cand_sha:
                    cp_proc = subprocess.run(
                        [
                            "git",
                            "-C",
                            str(eval_wt),
                            "cherry-pick",
                            f"{orig_base}..{cand_sha}",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if cp_proc.returncode != 0:
                        subprocess.run(
                            ["git", "-C", str(eval_wt), "cherry-pick", "--abort"],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        return FactoryCycleResult(
                            status=FactoryStatus.REJECTED,
                            item_id=candidate.item_id,
                            candidate_id=candidate.candidate_id,
                            branch_name=candidate.branch_name,
                            base_commit=current_tip,
                            candidate_commit=cand_sha,
                            reason=(
                                "Rebase/cherry-pick conflict integrating candidate onto "
                                f"{target!r}: {(cp_proc.stderr or cp_proc.stdout).strip()}"
                            ),
                        )
                integrated_sha = _run_git(eval_wt, ["rev-parse", "HEAD"])

            self._policy_guard.inspect_git_diff(
                self._repo_path,
                current_tip,
                integrated_sha,
                extra_forbidden_paths=extra_forbidden_paths,
            )

            if run_full_pytest or pytest_args:
                reg_ok, reg_out = _run_pytest_suite(eval_wt, pytest_args=pytest_args)
            else:
                reg_ok, reg_out = True, "pytest skipped"

            eval_res = (
                evaluator(eval_wt)
                if evaluator is not None
                else EvalResult(passed=reg_ok)
            )
            if not (reg_ok and eval_res.passed and eval_res.wrong_asset_attributions == 0):
                return FactoryCycleResult(
                    status=FactoryStatus.REJECTED,
                    item_id=candidate.item_id,
                    candidate_id=candidate.candidate_id,
                    branch_name=candidate.branch_name,
                    base_commit=current_tip,
                    candidate_commit=integrated_sha,
                    reason=(
                        "Combined QA gate regression on promotion (rolled back to "
                        f"{current_tip}): pytest_ok={reg_ok}, eval_ok={eval_res.passed}, "
                        f"detail={eval_res.detail or reg_out[-200:]}"
                    ),
                )

            # Capture clean/branch state BEFORE moving target_ref so HEAD doesn't skew git status.
            head_branch_proc = subprocess.run(
                ["git", "-C", str(self._repo_path), "symbolic-ref", "--short", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            head_branch = (
                head_branch_proc.stdout.strip() if head_branch_proc.returncode == 0 else ""
            )
            was_clean_on_target = _is_clean_working_tree(self._repo_path) and (
                head_branch == short_target
            )

            _run_git(
                self._repo_path,
                ["update-ref", target_ref, integrated_sha, current_tip],
            )
            new_commit = integrated_sha

            if was_clean_on_target:
                _run_git(self._repo_path, ["reset", "--hard", new_commit])

            now = self._clock()
            uv_candidate = self._uv_lock_path or (eval_wt / "uv.lock")
            if not uv_candidate.exists():
                uv_candidate = self._repo_path / "uv.lock"
            uv_hash = _sha256_or_missing(uv_candidate)
            cfg_candidate = (
                eval_wt / "pyproject.toml"
                if (eval_wt / "pyproject.toml").exists()
                else (
                    self._repo_path / "pyproject.toml"
                    if (self._repo_path / "pyproject.toml").exists()
                    else None
                )
            )
            cfg_hash = _sha256_or_missing(cfg_candidate)
            restore_cmd = (
                f"git -C {shlex.quote(str(self._repo_path))} update-ref "
                f"{shlex.quote(target_ref)} {current_tip}"
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
                branch_name=short_target,
                previous_commit=current_tip,
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
            self._store.record_promoted_manifest(manifest, mark_item_completed=candidate.item_id)
            return FactoryCycleResult(
                status=FactoryStatus.PROMOTED,
                item_id=candidate.item_id,
                candidate_id=candidate.candidate_id,
                branch_name=short_target,
                base_commit=current_tip,
                candidate_commit=new_commit,
                manifest_path=str(target_manifest_path),
                reason=f"Promoted {candidate.candidate_id} onto {target!r} at {new_commit}.",
                budget=self._store.get_budget(self._budget_id),
            )

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
