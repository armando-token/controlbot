"""7-step M7 self-repair loop, forensic audit, and serialized QA integrator."""

from __future__ import annotations

import concurrent.futures
import contextlib
import fcntl
import glob
import hashlib
import importlib.metadata
import json
import os
import posixpath
import re
import shlex
import shutil
import site
import stat
import subprocess
import sys
import sysconfig
import threading
import tomllib
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.contracts.common import utc_now
from src.factory.db import FactoryStore
from src.factory.engine import EvalResult, FactoryEngine, rollback_from_manifest
from src.factory.errors import (
    FactoryError,
    IsolationBoundaryError,
    PolicyImmutabilityError,
)
from src.factory.models import (
    CandidatePatch,
    CycleBudget,
    FactoryStatus,
    RollbackManifest,
    compute_proposal_hash,
)
from src.factory.policy import PolicyGuard
from src.qa.baseline import (
    _frontend_dist_lock,
    collect_frontend_dist_assets,
    verify_app_surface_browser,
    verify_app_surface_http,
)
from src.qa.isolation import (
    _DB_PATH_ENV_KEY,
    IsolatedLabServer,
    assert_not_live_target,
    assert_safe_mutation_path,
    ephemeral_git_worktree,
)
from src.qa.models import (
    CampaignState,
    CandidateManifest,
    QAFailureItem,
    QARollbackManifest,
)
from src.qa.queue import (
    assert_strictly_redacted,
    get_qa_item,
    import_failures_jsonl_into_store,
    list_qa_items,
    open_campaign_store,
    record_item_probe_outcome,
    save_campaign_state,
    sync_failures_jsonl_from_store,
    transition_qa_item_state,
)
from src.storage.redaction import contains_unredacted_secret_strict

_PROCESS_INTEGRATOR_LOCK = threading.Lock()

_FORBIDDEN_QA_MUTATION_PREFIXES: tuple[str, ...] = (
    "tests/e2e_qa/",
    "src/qa/fixtures/",
    "src/qa/scenarios/",
)
_LOCKFILE_NAMES: frozenset[str] = frozenset(
    {"uv.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
)
_FORBIDDEN_TEST_HARNESS_FILENAMES: frozenset[str] = frozenset(
    {
        "conftest.py",
        "sitecustomize.py",
        "usercustomize.py",
        "pytest.ini",
        "tox.ini",
        "setup.cfg",
        "pytest.py",
        "_pytest.py",
        "pluggy.py",
        "unittest.py",
        "py.py",
        "iniconfig.py",
    }
)
_FORBIDDEN_CUSTOMIZE_PKG_DIRS: frozenset[str] = frozenset(
    {
        "sitecustomize",
        "usercustomize",
        "pytest",
        "_pytest",
        "pluggy",
        "unittest",
        "py",
        "iniconfig",
    }
)
_REPO_TOP_LEVEL_PACKAGES: frozenset[str] = frozenset(
    {"src", "lab", "scripts", "benchmarks", "deploy", "tests"}
)
_MAX_AUDIT_FILE_BYTES: int = 2 * 1024 * 1024
_SCRIPT_EXTENSIONS: frozenset[str] = frozenset({".sh", ".bash"})
_PY_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+([A-Za-z0-9_.]+)", re.MULTILINE)


def _read_git_blob_text(repo_root: Path, ref: str, rel_path: str) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"{ref}:{rel_path}"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="replace")


def _extract_pyproject_pytest_section(
    raw_text: str | None,
) -> tuple[bool, Any]:
    if raw_text is None:
        return False, None
    try:
        parsed = tomllib.loads(raw_text)
    except tomllib.TOMLDecodeError:
        return ("pytest" in raw_text.lower()), "__unparseable__"
    tool_tbl = parsed.get("tool")
    if isinstance(tool_tbl, dict) and "pytest" in tool_tbl:
        return True, tool_tbl["pytest"]
    return False, None


def _py_module_stem(filename: str) -> str | None:
    low = filename.lower()
    if low.endswith((".py", ".pyw", ".pyc", ".pyo")):
        return filename.rsplit(".", 1)[0].lower()
    if low.endswith((".so", ".pyd")):
        return filename.split(".", 1)[0].lower()
    return None


def _is_test_module_filename(fname_low: str) -> bool:
    return fname_low.endswith((".py", ".pyw")) and (
        fname_low.startswith("test_") or fname_low.endswith(("_test.py", "_test.pyw"))
    )


def _collect_shadow_module_names(repo_root: Path) -> frozenset[str]:
    """Collect stdlib, installed distribution, and non-repo sys.path module/package stems."""
    names: set[str] = {n.lower() for n in sys.stdlib_module_names} | {
        n.lower() for n in sys.builtin_module_names
    }
    with contextlib.suppress(Exception):
        for pkg_name in importlib.metadata.packages_distributions():
            if pkg_name:
                names.add(pkg_name.lower())

    candidate_dirs: list[Path] = []
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        raw = sysconfig.get_path(key)
        if raw:
            candidate_dirs.append(Path(raw))
    with contextlib.suppress(Exception):
        for raw in site.getsitepackages():
            if raw:
                candidate_dirs.append(Path(raw))
    with contextlib.suppress(Exception):
        user_site = site.getusersitepackages()
        if user_site:
            candidate_dirs.append(Path(user_site))

    resolved_repo = repo_root.resolve()
    resolved_cwd = Path.cwd().resolve()
    this_repo_root = Path(__file__).resolve().parents[2]
    for raw_entry in sys.path:
        if not raw_entry or raw_entry == ".":
            continue
        try:
            entry_path = Path(raw_entry).expanduser().resolve()
        except OSError:
            continue
        is_pkg_store = any(
            part in {".venv", "site-packages", "dist-packages", "lib-dynload"}
            or part.startswith("python3.")
            for part in entry_path.parts
        )
        if not is_pkg_store and (
            entry_path in (resolved_repo, resolved_cwd, this_repo_root)
            or entry_path.is_relative_to(resolved_repo)
            or entry_path.is_relative_to(this_repo_root)
            or entry_path.name in {"tests", "unit", "integration", "e2e", "e2e_qa", "acceptance"}
        ):
            continue
        candidate_dirs.append(entry_path)

    seen_dirs: set[Path] = set()
    for raw_dir in candidate_dirs:
        try:
            resolved_dir = raw_dir.resolve()
        except OSError:
            continue
        if resolved_dir in seen_dirs or not resolved_dir.is_dir():
            continue
        seen_dirs.add(resolved_dir)
        try:
            for child in resolved_dir.iterdir():
                cname = child.name
                if cname.startswith(".") or cname in {
                    "__pycache__",
                    "site-packages",
                    "dist-packages",
                    "lib-dynload",
                }:
                    continue
                if cname.endswith((".dist-info", ".egg-info", ".pth")):
                    continue
                if child.is_dir():
                    names.add(cname.lower())
                elif child.is_file():
                    stem = _py_module_stem(cname)
                    if stem:
                        names.add(stem)
        except OSError:
            continue

    return frozenset(names)


def _check_forbidden_test_harness_mutations(
    repo_root: Path,
    *,
    base_sha: str,
    rel_paths: Sequence[str],
    candidate_sha: str | None = None,
    cand_worktree: Path | None = None,
    locked_test_paths: Sequence[str] = (),
) -> None:
    """Reject candidate creation/modification/deletion of test-runner or shadow hijack files."""
    forbidden_init_dirs: set[str] = set()
    non_root_test_ancestors: set[str] = {"tests"}
    for lt in locked_test_paths:
        lt_norm = posixpath.normpath(lt.strip().replace("\\", "/").lstrip("/"))
        if not lt_norm or lt_norm == ".":
            continue
        for parent in Path(lt_norm).parents:
            p_str = str(parent).replace("\\", "/")
            forbidden_init_dirs.add(p_str)
            if p_str and p_str != ".":
                non_root_test_ancestors.add(p_str.lower())

    shadow_names = _collect_shadow_module_names(repo_root)

    for rel_path in rel_paths:
        raw_norm = rel_path.replace("\\", "/").lstrip("/")
        if not raw_norm:
            continue
        norm = posixpath.normpath(raw_norm)
        if not norm or norm == ".":
            continue
        if norm == ".." or norm.startswith("../"):
            raise PolicyImmutabilityError(
                f"FORENSIC_AUDIT_FAILED: path traversal in candidate path {rel_path!r}.",
                offending_paths=(rel_path,),
            )
        path_obj = Path(norm)
        parts = path_obj.parts
        parts_low = [part.lower() for part in parts]
        fname_low = parts_low[-1]
        if fname_low in _FORBIDDEN_TEST_HARNESS_FILENAMES:
            raise PolicyImmutabilityError(
                f"FORENSIC_AUDIT_FAILED: forbidden test/execution configuration file {norm!r}.",
                offending_paths=(norm,),
            )
        if any(dir_part in _FORBIDDEN_CUSTOMIZE_PKG_DIRS for dir_part in parts_low[:-1]) or (
            len(parts_low) == 1 and fname_low in _FORBIDDEN_CUSTOMIZE_PKG_DIRS
        ):
            raise PolicyImmutabilityError(
                f"FORENSIC_AUDIT_FAILED: forbidden startup/runner shadowing package {norm!r}.",
                offending_paths=(norm,),
            )
        if fname_low == "__init__.py":
            parent_norm = str(path_obj.parent).replace("\\", "/")
            if parts_low[0] == "tests" or parent_norm in forbidden_init_dirs:
                raise PolicyImmutabilityError(
                    f"FORENSIC_AUDIT_FAILED: forbidden test-package __init__.py mutation {norm!r}.",
                    offending_paths=(norm,),
                )

        file_stem = _py_module_stem(parts[-1])
        # Block top-level (repo root) stdlib / installed-package / repo-package file shadowing
        if len(parts) == 1:
            if file_stem is not None and (
                file_stem in shadow_names or file_stem in _REPO_TOP_LEVEL_PACKAGES
            ):
                raise PolicyImmutabilityError(
                    f"FORENSIC_AUDIT_FAILED: forbidden top-level shadowing module {norm!r} "
                    f"({file_stem!r}).",
                    offending_paths=(norm,),
                )
        elif parts_low[0] in shadow_names:
            raise PolicyImmutabilityError(
                f"FORENSIC_AUDIT_FAILED: forbidden top-level shadowing package directory "
                f"{norm!r} ({parts_low[0]!r}).",
                offending_paths=(norm,),
            )

        # Block shadowing & non-test helper/shadow modules under tests/ or locked-test ancestors
        matched_anc: str | None = None
        matched_depth = 0
        for idx in range(1, len(parts_low)):
            prefix = "/".join(parts_low[:idx])
            if prefix in non_root_test_ancestors:
                matched_anc = prefix
                matched_depth = idx
                break
        if matched_anc is not None:
            sub_parts_low = parts_low[matched_depth:]
            for dir_part in sub_parts_low[:-1]:
                if (
                    dir_part in shadow_names
                    or dir_part in _REPO_TOP_LEVEL_PACKAGES
                    or dir_part in _FORBIDDEN_CUSTOMIZE_PKG_DIRS
                ):
                    raise PolicyImmutabilityError(
                        f"FORENSIC_AUDIT_FAILED: forbidden shadowing directory {dir_part!r} "
                        f"under test directory {matched_anc!r} in {norm!r}.",
                        offending_paths=(norm,),
                    )
            if file_stem is not None:
                if (
                    file_stem in shadow_names
                    or file_stem in _REPO_TOP_LEVEL_PACKAGES
                    or file_stem in _FORBIDDEN_CUSTOMIZE_PKG_DIRS
                ):
                    raise PolicyImmutabilityError(
                        f"FORENSIC_AUDIT_FAILED: forbidden shadowing module {norm!r} "
                        f"under test directory {matched_anc!r}.",
                        offending_paths=(norm,),
                    )
                if not _is_test_module_filename(fname_low):
                    raise PolicyImmutabilityError(
                        f"FORENSIC_AUDIT_FAILED: forbidden non-test module {norm!r} "
                        f"under test directory {matched_anc!r}.",
                        offending_paths=(norm,),
                    )

        if fname_low == "pyproject.toml":
            base_text = _read_git_blob_text(repo_root, base_sha, norm)
            if cand_worktree is not None:
                cand_file = cand_worktree / norm
                cand_text = (
                    cand_file.read_text(encoding="utf-8", errors="replace")
                    if cand_file.is_file()
                    else None
                )
            elif candidate_sha is not None:
                cand_text = _read_git_blob_text(repo_root, candidate_sha, norm)
            else:
                cand_text = None

            base_has_pytest, base_pytest = _extract_pyproject_pytest_section(base_text)
            cand_has_pytest, cand_pytest = _extract_pyproject_pytest_section(cand_text)
            if cand_pytest == "__unparseable__" and (
                base_has_pytest or (cand_text is not None and "pytest" in cand_text.lower())
            ):
                raise PolicyImmutabilityError(
                    "FORENSIC_AUDIT_FAILED: unparseable pyproject.toml touching pytest config "
                    f"in {norm!r}.",
                    offending_paths=(norm,),
                )
            if base_has_pytest != cand_has_pytest or base_pytest != cand_pytest:
                raise PolicyImmutabilityError(
                    f"FORENSIC_AUDIT_FAILED: forbidden [tool.pytest] modification in {norm!r}.",
                    offending_paths=(norm,),
                )


@dataclass(frozen=True)
class QAEvaluationResult:
    """Outcome of running the compiled-React + repro + smoke evaluator."""

    passed: bool
    build_hash: str
    surface_ok: bool
    repro_ok: bool
    smoke_ok: bool
    detail: str
    artifact_paths: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ForensicAuditVerdict:
    """Result of cross-model and diff-based forensic audit on a candidate."""

    passed: bool
    reason: str
    files_modified: list[str]
    diff_stat: str


@dataclass(frozen=True)
class RepairWorkerSlot:
    """Scheduled repair task assigned to a disjoint write area."""

    item: QAFailureItem
    write_area: str
    existing_manifest: CandidateManifest | None = None


def validate_campaign_isolation(
    campaign_dir: Path,
    *,
    repo_root: Path | None = None,
    target_url: str | None = None,
    allow_live_target: bool = False,
) -> Path:
    """Validate campaign dir, runtime DB env isolation, and non-live target URL pre-network."""
    safe_dir = assert_safe_mutation_path(campaign_dir, repo_root=repo_root)
    env_db = os.environ.get(_DB_PATH_ENV_KEY, "").strip()
    if env_db:
        env_path = Path(env_db).expanduser().resolve()
        assert_safe_mutation_path(env_path, repo_root=repo_root)
        if repo_root is not None:
            var_dir = (repo_root.resolve() / "var").resolve()
            if env_path == var_dir or env_path.is_relative_to(var_dir):
                raise IsolationBoundaryError(
                    f"ISOLATION_BOUNDARY_VIOLATION: {_DB_PATH_ENV_KEY}={env_path} "
                    f"targets live var/ directory ({var_dir})."
                )
        if (
            env_path.name.lower().startswith(("controlbot", "grokbot"))
            and ".sqlite3" in env_path.name.lower()
        ):
            raise IsolationBoundaryError(
                f"ISOLATION_BOUNDARY_VIOLATION: {_DB_PATH_ENV_KEY}={env_path} "
                "targets forbidden live runtime SQLite filename."
            )
    if target_url and not allow_live_target:
        assert_not_live_target(target_url, allow_readonly=False)
    return safe_dir


def check_cross_model_governance(
    author_model: str | None,
    auditor_model: str | None,
) -> None:
    """Enforce distinct author/auditor models and forbid hydrogen self-audit."""
    author = (author_model or "").strip()
    auditor = (auditor_model or "").strip()
    if not author:
        raise ValueError(
            "Cross-model governance violation: missing `author_model` on candidate."
        )
    if not auditor:
        raise ValueError(
            "Cross-model governance violation: missing `auditor_model` on candidate."
        )
    if "hydrogen" in auditor.lower():
        raise ValueError(
            f"Cross-model governance violation: auditor_model={auditor!r} is forbidden "
            "(hydrogen cannot audit patches)."
        )
    if author.lower() == auditor.lower():
        raise ValueError(
            f"Cross-model governance violation: self-audit rejected "
            f"(author_model={author!r} == auditor_model={auditor!r}; must be distinct)."
        )


def _run_git(repo_path: Path, args: Sequence[str]) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip()
        raise FactoryError(f"git {' '.join(args)} failed in {repo_path}: {err}")
    return proc.stdout.strip()


def _git_branch_exists(repo_path: Path, branch_name: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "--verify", branch_name],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def _sanitized_subproc_env(worktree: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTEST_ADDOPTS", None)
    env.pop("PYTHONSTARTUP", None)
    env.pop("PYTHONINSPECT", None)
    env["PYTHONPATH"] = str(worktree)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    interp_bin = str(Path(os.path.abspath(sys.executable)).parent)
    if interp_bin:
        existing_parts = [
            part for part in env.get("PATH", "").split(os.pathsep) if part and part != interp_bin
        ]
        env["PATH"] = os.pathsep.join([interp_bin, *existing_parts])
    return env


_PYTEST_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "-k",
        "-o",
        "-p",
        "-c",
        "-W",
        "-n",
        "-r",
        "--tb",
        "--maxfail",
        "--rootdir",
        "--confcutdir",
        "--basetemp",
        "--junitxml",
        "--junit-xml",
        "--junit-prefix",
        "--override-ini",
        "--log-level",
        "--log-cli-level",
        "--log-cli-format",
        "--log-cli-date-format",
        "--log-file",
        "--log-file-level",
        "--log-file-format",
        "--log-file-date-format",
        "--log-format",
        "--log-date-format",
        "--log-auto-indent",
        "--ignore",
        "--ignore-glob",
        "--deselect",
        "--asyncio-mode",
        "--timeout",
        "--cov",
        "--cov-report",
        "--dist",
        "--tx",
        "--durations",
        "--durations-min",
        "--color",
        "--verbosity",
        "--capture",
        "--show-capture",
        "--code-highlight",
        "--import-mode",
        "--pastebin",
        "--lfnf",
        "--last-failed-no-failures",
    }
)
_PYTEST_INFO_FLAGS: frozenset[str] = frozenset(
    {"--version", "-V", "--help", "-h", "--markers", "--fixtures"}
)
_GLOB_META_CHARS: tuple[str, ...] = ("*", "?", "[")
_ENV_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)


def _effective_item_repro_command(item: QAFailureItem) -> str:
    cmd = item.repro_command.strip()
    if not cmd and item.repro_test_path and item.repro_test_path.strip():
        cmd = f"{sys.executable} -m pytest -q {shlex.quote(item.repro_test_path.strip())}"
    return cmd


def _has_unquoted_shell_operator(cmd_str: str) -> bool:
    """Return True if cmd_str contains shell operators outside single/double quotes."""
    in_single = False
    in_double = False
    escaped = False
    idx = 0
    length = len(cmd_str)
    while idx < length:
        ch = cmd_str[idx]
        if escaped:
            escaped = False
            idx += 1
            continue
        if in_single:
            if ch == "'":
                in_single = False
            idx += 1
            continue
        if in_double:
            if ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
            idx += 1
            continue
        if ch == "\\":
            escaped = True
        elif ch == "'":
            in_single = True
        elif ch == '"':
            in_double = True
        elif ch in {"|", ";", ">", "<"} or cmd_str[idx : idx + 2] == "&&":
            return True
        idx += 1
    return False


def _run_shell_or_cmd(
    command: str,
    *,
    cwd: Path,
    timeout: float = 120.0,
) -> tuple[bool, str]:
    cmd_str = command.strip()
    if not cmd_str:
        return False, "missing_repro_command: empty command cannot verify fix"
    env = _sanitized_subproc_env(cwd)
    use_shell = _has_unquoted_shell_operator(cmd_str)
    if use_shell:
        proc = subprocess.run(
            cmd_str,
            cwd=str(cwd),
            env=env,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    else:
        try:
            argv = shlex.split(cmd_str)
        except ValueError as exc:
            return False, f"invalid_repro_command: {exc}"
        while argv:
            env_match = _ENV_ASSIGN_RE.match(argv[0])
            if not env_match:
                break
            env[env_match.group(1)] = env_match.group(2)
            argv.pop(0)
        if not argv:
            return False, "missing_repro_command: command contains only environment assignments"
        if len(argv) >= 2 and Path(argv[0]).name.startswith("python"):
            argv[0] = sys.executable
        elif argv[0] == "pytest":
            which_pytest = shutil.which("pytest", path=env.get("PATH"))
            interp_bin = Path(os.path.abspath(sys.executable)).parent
            if (
                which_pytest is None
                or Path(os.path.abspath(which_pytest)).parent != interp_bin
            ):
                argv = [sys.executable, "-m", "pytest", *argv[1:]]
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    output = (proc.stdout + "\n" + proc.stderr).strip()
    return proc.returncode == 0, output


def _extract_test_files_from_command(repro_command: str, repo_root: Path) -> list[str]:
    if not repro_command.strip():
        return []
    try:
        lex = shlex.shlex(repro_command, posix=True, punctuation_chars=";&|")
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        tokens = repro_command.split()

    resolved_repo = repo_root.resolve()
    found: list[str] = []
    seen: set[str] = set()
    skip_dir_parts = frozenset({".git", ".venv", "node_modules", "__pycache__"})

    def _add_candidate(cand_path: Path) -> bool:
        try:
            cand = cand_path.resolve()
        except OSError:
            return False
        if cand.is_file() and cand.is_relative_to(resolved_repo):
            rel_obj = cand.relative_to(resolved_repo)
            if any(part in skip_dir_parts for part in rel_obj.parts):
                return False
            rel = str(rel_obj).replace("\\", "/")
            if rel not in seen:
                seen.add(rel)
                found.append(rel)
            return True
        return False

    def _add_conftest_ancestors(start_dir: Path) -> None:
        try:
            cur = start_dir.resolve()
        except OSError:
            return
        while cur.is_relative_to(resolved_repo):
            _add_candidate(cur / "conftest.py")
            if cur == resolved_repo:
                break
            cur = cur.parent

    expecting_cmd = True
    in_env_prefix = False
    in_unittest = False
    in_pytest = False
    unittest_discover = False
    unittest_start_dir: str | None = None
    unittest_pattern: str | None = None
    unittest_pos_idx = 0
    unittest_had_target = False
    unittest_info_only = False
    pytest_had_target = False
    pytest_rootdir: str | None = None
    pytest_noconftest = False
    pytest_info_only = False
    pytest_dir_targets: list[Path] = []
    pytest_file_dirs: list[Path] = []
    skip_next_for: str | None = None

    def _collect_pytest_dir(dir_path: Path) -> bool:
        try:
            resolved_dir = dir_path.resolve()
        except OSError:
            return False
        if not (resolved_dir.is_dir() and resolved_dir.is_relative_to(resolved_repo)):
            return False
        for matched in sorted(resolved_dir.rglob("test_*.py")):
            _add_candidate(matched)
        for matched in sorted(resolved_dir.rglob("*_test.py")):
            _add_candidate(matched)
        pytest_dir_targets.append(resolved_dir)
        return True

    def _flush_segment() -> None:
        if in_unittest and not unittest_info_only and (
            unittest_discover
            or unittest_start_dir is not None
            or unittest_pattern is not None
            or not unittest_had_target
        ):
            start_rel = (unittest_start_dir or ".").strip() or "."
            pattern = (unittest_pattern or "test*.py").strip()
            if pattern:
                try:
                    start_path = (resolved_repo / start_rel).resolve()
                except OSError:
                    start_path = None
                if (
                    start_path is not None
                    and not start_path.is_dir()
                    and "." in start_rel
                    and not start_rel.startswith(".")
                    and "/" not in start_rel
                    and "\\" not in start_rel
                ):
                    try:
                        dotted_path = (resolved_repo / start_rel.replace(".", "/")).resolve()
                        if dotted_path.is_dir():
                            start_path = dotted_path
                    except OSError:
                        pass
                if (
                    start_path is not None
                    and start_path.is_dir()
                    and start_path.is_relative_to(resolved_repo)
                ):
                    for matched in sorted(start_path.rglob(pattern)):
                        _add_candidate(matched)

        if in_pytest and not pytest_had_target and not pytest_info_only:
            root_path = resolved_repo
            if pytest_rootdir:
                try:
                    cand_root = (resolved_repo / pytest_rootdir).resolve()
                    if cand_root.is_dir() and cand_root.is_relative_to(resolved_repo):
                        root_path = cand_root
                except OSError:
                    pass
            _collect_pytest_dir(root_path)

        if in_pytest and not pytest_noconftest:
            for dpath in pytest_dir_targets:
                for cf in sorted(dpath.rglob("conftest.py")):
                    _add_candidate(cf)
                _add_conftest_ancestors(dpath)
            for fdir in pytest_file_dirs:
                _add_conftest_ancestors(fdir)

    for tok in tokens:
        if skip_next_for is not None:
            mode = skip_next_for
            skip_next_for = None
            if mode == "module":
                if tok == "unittest":
                    in_unittest = True
                elif tok == "pytest":
                    in_pytest = True
            elif mode == "unittest_s":
                unittest_start_dir = tok
            elif mode == "unittest_p":
                unittest_pattern = tok
            elif mode == "pytest_rootdir":
                pytest_rootdir = tok
            continue

        if tok in {"&&", "||", ";", "|"}:
            _flush_segment()
            expecting_cmd = True
            in_env_prefix = False
            in_unittest = False
            in_pytest = False
            unittest_discover = False
            unittest_start_dir = None
            unittest_pattern = None
            unittest_pos_idx = 0
            unittest_had_target = False
            unittest_info_only = False
            pytest_had_target = False
            pytest_rootdir = None
            pytest_noconftest = False
            pytest_info_only = False
            pytest_dir_targets = []
            pytest_file_dirs = []
            continue

        just_started_cmd = False
        if expecting_cmd:
            if _ENV_ASSIGN_RE.match(tok):
                continue
            if tok == "env" or tok.endswith("/env"):
                in_env_prefix = True
                continue
            if in_env_prefix:
                if tok in {"-u", "-C", "--unset", "--chdir"}:
                    skip_next_for = "skip"
                    continue
                if tok.startswith("-"):
                    continue
                in_env_prefix = False
            expecting_cmd = False
            just_started_cmd = True

        if tok == "-m" and not in_pytest:
            skip_next_for = "module"
            continue

        if in_unittest:
            if tok == "discover" and not unittest_discover:
                unittest_discover = True
                continue
            if tok in {"-s", "--start-directory"}:
                skip_next_for = "unittest_s"
                continue
            if tok.startswith("--start-directory="):
                unittest_start_dir = tok.split("=", 1)[1]
                continue
            if tok in {"-p", "--pattern"}:
                skip_next_for = "unittest_p"
                continue
            if tok.startswith("--pattern="):
                unittest_pattern = tok.split("=", 1)[1]
                continue
            if tok in {"-t", "--top-level-directory", "-k"}:
                skip_next_for = "skip"
                continue
            if tok.startswith(("--top-level-directory=", "-k=")):
                continue
            if tok in {"-h", "--help"}:
                unittest_info_only = True
                continue
            if tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
                pos = 1
                while pos < len(tok):
                    flag_ch = tok[pos]
                    rest = tok[pos + 1 :]
                    if flag_ch == "s":
                        if rest:
                            unittest_start_dir = rest
                        else:
                            skip_next_for = "unittest_s"
                        break
                    if flag_ch == "p":
                        if rest:
                            unittest_pattern = rest
                        else:
                            skip_next_for = "unittest_p"
                        break
                    if flag_ch in {"t", "k"}:
                        if not rest:
                            skip_next_for = "skip"
                        break
                    if flag_ch == "h":
                        unittest_info_only = True
                    pos += 1
                continue
            if tok.startswith("-"):
                continue
            if unittest_discover:
                if unittest_pos_idx == 0 and unittest_start_dir is None:
                    unittest_start_dir = tok
                elif unittest_pos_idx == 1 and unittest_pattern is None:
                    unittest_pattern = tok
                unittest_pos_idx += 1
                unittest_had_target = True
                continue
            unittest_had_target = True
        else:
            if not in_pytest and tok == "-c":
                skip_next_for = "skip"
                continue
            if tok == "--rootdir":
                skip_next_for = "pytest_rootdir"
                continue
            if tok.startswith("--rootdir="):
                pytest_rootdir = tok.split("=", 1)[1]
                continue
            if tok == "--noconftest":
                pytest_noconftest = True
                continue
            if tok in _PYTEST_INFO_FLAGS:
                pytest_info_only = True
                continue
            if tok in _PYTEST_VALUE_FLAGS or tok == "-m":
                skip_next_for = "skip"
                continue
            if tok.startswith("-"):
                continue

        tok_name = Path(tok).name
        if (
            tok in {"unittest", "python3", "python", "pytest", "py.test"}
            or tok.endswith(("/unittest", "/pytest", "/py.test"))
            or (just_started_cmd and tok_name.startswith("python") and not tok_name.endswith(".py"))
        ):
            if tok == "unittest" or tok.endswith("/unittest"):
                in_unittest = True
            elif tok in {"pytest", "py.test"} or tok.endswith(("/pytest", "/py.test")):
                in_pytest = True
            continue

        if in_pytest:
            pytest_had_target = True

        base_tok = tok.split("::", 1)[0]
        if not in_unittest and any(ch in base_tok for ch in _GLOB_META_CHARS):
            try:
                glob_matches = sorted(
                    glob.glob(base_tok, root_dir=str(resolved_repo), recursive=True)
                )
            except OSError:
                glob_matches = []
            for match in glob_matches:
                matched_path = resolved_repo / match
                if matched_path.is_dir():
                    _collect_pytest_dir(matched_path)
                elif _add_candidate(matched_path):
                    pytest_file_dirs.append(matched_path.resolve().parent)
            continue

        if base_tok.endswith(".py"):
            cand_file = resolved_repo / base_tok
            if _add_candidate(cand_file):
                pytest_file_dirs.append(cand_file.resolve().parent)
            continue

        if not in_unittest and _collect_pytest_dir(resolved_repo / base_tok):
            continue

        if in_unittest and not any(ch in base_tok for ch in ("/", "\\", "=", ";", "&", "|")):
            parts = [p for p in base_tok.split(".") if p]
            for cut in range(len(parts), 0, -1):
                if _add_candidate(resolved_repo / ("/".join(parts[:cut]) + ".py")):
                    break

    _flush_segment()
    return found


def _extract_test_file_from_command(repro_command: str, repo_root: Path) -> str | None:
    files = _extract_test_files_from_command(repro_command, repo_root)
    return files[0] if files else None


def infer_write_area(
    item: QAFailureItem,
    candidate: CandidateManifest | None = None,
    *,
    repo_root: Path | None = None,
) -> str:
    """Infer deterministic write_area token for disjoint parallel scheduling."""
    locked_tests: set[str] = set()
    if item.repro_test_path:
        locked_tests.add(item.repro_test_path.strip().replace("\\", "/"))
    if repo_root is not None:
        locked_tests.update(_extract_test_files_from_command(item.repro_command, repo_root))

    if candidate is not None:
        if candidate.write_area and candidate.write_area.strip():
            return candidate.write_area.strip()
        if candidate.files_modified:
            mods = sorted(
                {
                    f.strip().replace("\\", "/")
                    for f in candidate.files_modified
                    if f.strip() and f.strip().replace("\\", "/") not in locked_tests
                }
            )
            if mods:
                return ",".join(mods)

    if repo_root is not None:
        candidate_tests = (
            [item.repro_test_path]
            if item.repro_test_path
            else _extract_test_files_from_command(item.repro_command, repo_root)
        )
        local_mods: list[str] = []
        for test_rel in candidate_tests:
            if not test_rel:
                continue
            test_file = repo_root / test_rel
            if test_file.is_file():
                try:
                    src_text = test_file.read_text(encoding="utf-8", errors="replace")
                    imports = _PY_IMPORT_RE.findall(src_text)
                    local_mods.extend(
                        imp.split(".")[0]
                        for imp in imports
                        if (repo_root / f"{imp.split('.')[0]}.py").is_file()
                        or (repo_root / imp.replace(".", "/")).is_dir()
                        or (repo_root / f"{imp.replace('.', '/')}.py").is_file()
                    )
                except OSError:
                    pass
        if local_mods:
            return ",".join(sorted(set(local_mods)))

    return item.subsystem.strip() or item.case_id.strip() or item.item_id


def _compute_repro_hashes(
    worktree: Path,
    *,
    repro_command: str,
    repro_test_path: str | None,
    smoke_tests: Sequence[str] = (),
) -> tuple[str, str]:
    extracted_files = _extract_test_files_from_command(repro_command, worktree)
    locked_files: list[str] = []
    for cand in ([repro_test_path] if repro_test_path else []) + extracted_files:
        norm = cand.strip().replace("\\", "/").lstrip("./")
        if norm and norm not in locked_files:
            locked_files.append(norm)
    test_rel = repro_test_path or (locked_files[0] if locked_files else None)
    existing_files = [rel for rel in locked_files if (worktree / rel).is_file()]
    if len(existing_files) == 1:
        repro_test_hash = hashlib.sha256((worktree / existing_files[0]).read_bytes()).hexdigest()[
            :16
        ]
    elif len(existing_files) > 1:
        hasher = hashlib.sha256()
        for rel in sorted(existing_files):
            hasher.update(rel.encode("utf-8"))
            hasher.update(b"\0")
            hasher.update((worktree / rel).read_bytes())
        repro_test_hash = hasher.hexdigest()[:16]
    else:
        repro_test_hash = hashlib.sha256(repro_command.encode("utf-8")).hexdigest()[:16]
    crit_payload: dict[str, Any] = {
        "repro_command": repro_command,
        "repro_test_path": test_rel,
        "repro_test_hash": repro_test_hash,
        "smoke_tests": list(smoke_tests),
    }
    if len(existing_files) > 1:
        crit_payload["repro_test_paths"] = sorted(existing_files)
    locked_criterion_hash = hashlib.sha256(
        json.dumps(crit_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return repro_test_hash, locked_criterion_hash


def _resolve_common_repo_root(worktree: Path) -> Path | None:
    proc = subprocess.run(
        ["git", "-C", str(worktree), "rev-parse", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    common = Path(proc.stdout.strip())
    if not common.is_absolute():
        common = (worktree / common).resolve()
    return common.parent


def _compute_dist_build_hash(worktree: Path) -> str:
    dist_dir = worktree / "frontend" / "dist"
    if dist_dir.is_dir():
        asset_hashes, _ = collect_frontend_dist_assets(dist_dir)
        index_html = dist_dir / "index.html"
        combined: dict[str, str] = dict(asset_hashes)
        if index_html.is_file():
            combined["index.html"] = hashlib.sha256(index_html.read_bytes()).hexdigest()
        if combined:
            return hashlib.sha256(
                json.dumps(combined, sort_keys=True).encode("utf-8")
            ).hexdigest()[:16]
    tree_proc = subprocess.run(
        ["git", "-C", str(worktree), "rev-parse", "HEAD^{tree}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if tree_proc.returncode == 0 and tree_proc.stdout.strip():
        return tree_proc.stdout.strip()[:16]
    return "no-tree-hash"


def build_qa_product_evaluator(
    *,
    repro_command: str,
    campaign_dir: Path,
    case_id: str,
    build_frontend: bool = True,
    skip_browser: bool = False,
    smoke_tests: Sequence[str] = (),
    metadata_out: dict[str, Any] | None = None,
) -> Callable[[Path], EvalResult]:
    """Build an M7 EvalResult callback checking compiled React + repro_command + smoke tests."""
    del campaign_dir, case_id

    def _evaluate(worktree: Path) -> EvalResult:
        details: list[str] = []
        surface_ok = True
        symlinked_node_modules: Path | None = None

        pkg_json = worktree / "frontend" / "package.json"
        if pkg_json.is_file() and build_frontend:
            wt_node_modules = worktree / "frontend" / "node_modules"
            if not wt_node_modules.exists():
                common_root = _resolve_common_repo_root(worktree)
                if common_root is not None:
                    src_nm = common_root / "frontend" / "node_modules"
                    if src_nm.is_dir():
                        wt_node_modules.symlink_to(src_nm)
                        symlinked_node_modules = wt_node_modules

            try:
                lock_root = _resolve_common_repo_root(worktree) or worktree
                with _frontend_dist_lock(lock_root, exclusive=True):
                    build_proc = subprocess.run(
                        ["npm", "--prefix", str(worktree / "frontend"), "run", "build"],
                        capture_output=True,
                        text=True,
                        timeout=180,
                        check=False,
                    )
                if build_proc.returncode != 0:
                    surface_ok = False
                    details.append(
                        f"npm build failed (rc={build_proc.returncode}): "
                        f"{(build_proc.stderr or build_proc.stdout)[-300:]}"
                    )
            finally:
                if symlinked_node_modules is not None and symlinked_node_modules.is_symlink():
                    symlinked_node_modules.unlink()

        build_hash = _compute_dist_build_hash(worktree)

        has_web_app = (worktree / "src" / "web" / "app.py").is_file()
        dist_dir = worktree / "frontend" / "dist"
        if has_web_app and not skip_browser and (dist_dir / "index.html").is_file():
            try:
                import httpx

                from src.qa.baseline import _run_coro_sync

                with IsolatedLabServer(repo_root=worktree) as lab:
                    with httpx.Client(
                        base_url=lab.base_url,
                        timeout=10.0,
                        trust_env=False,
                        follow_redirects=False,
                    ) as client:
                        http_res = verify_app_surface_http(client, dist_dir=dist_dir)
                        if not http_res.surface_verified:
                            surface_ok = False
                            details.extend(http_res.boot_errors)
                    if http_res.served_surface == "react":
                        browser_res = _run_coro_sync(
                            verify_app_surface_browser(
                                lab.base_url,
                                user_data_dir=lab.workspace.playwright_user_data_dir,
                            )
                        )
                        if not browser_res.verified:
                            surface_ok = False
                            details.extend(browser_res.boot_errors)
            except Exception as exc:
                surface_ok = False
                details.append(
                    f"IsolatedLabServer surface check failed: {type(exc).__name__}: {exc}"
                )

        repro_ok, repro_out = _run_shell_or_cmd(repro_command, cwd=worktree)
        if not repro_ok:
            details.append(f"repro_command failed: {repro_out[-300:]}")

        smoke_ok = True
        for smoke_cmd in smoke_tests:
            s_ok, s_out = _run_shell_or_cmd(smoke_cmd, cwd=worktree)
            if not s_ok:
                smoke_ok = False
                details.append(f"smoke_test {smoke_cmd!r} failed: {s_out[-250:]}")
                break

        overall = surface_ok and repro_ok and smoke_ok
        summary = "all gates passed" if overall else "; ".join(details)
        if metadata_out is not None:
            metadata_out["build_hash"] = build_hash
            metadata_out["surface_ok"] = surface_ok
            metadata_out["repro_ok"] = repro_ok
            metadata_out["smoke_ok"] = smoke_ok
            metadata_out["detail"] = summary

        return EvalResult(
            passed=overall,
            metric=0.0 if overall else 1.0,
            wrong_asset_attributions=0,
            detail=summary,
        )

    return _evaluate


def _get_git_diff_stats(
    repo_root: Path,
    base_sha: str,
    cand_sha: str,
) -> tuple[list[str], str]:
    names_out = _run_git(
        repo_root,
        ["-c", "core.quotepath=false", "diff", "--name-only", f"{base_sha}..{cand_sha}"],
    )
    files_modified = [line.strip() for line in names_out.splitlines() if line.strip()]
    stat_out = _run_git(repo_root, ["diff", "--stat", f"{base_sha}..{cand_sha}"])
    return files_modified, stat_out


def audit_candidate_forensic(
    repo_root: Path,
    *,
    manifest: CandidateManifest,
    base_sha: str,
    candidate_sha: str,
    repro_test_path: str | None = None,
    repro_test_paths: Sequence[str] = (),
    repro_command: str | None = None,
    expected_repro_test_hash: str | None = None,
    allow_lockfile_edits: bool = False,
) -> ForensicAuditVerdict:
    """Perform cross-model, PolicyGuard, locked-test, permission, size & secret forensic audit."""
    check_cross_model_governance(manifest.author_model, manifest.auditor_model)

    if not manifest.candidate_passed:
        return ForensicAuditVerdict(
            passed=False,
            reason="Candidate did not pass verification (candidate_passed=False).",
            files_modified=list(manifest.files_modified),
            diff_stat=manifest.diff_stat,
        )
    if manifest.baseline_passed:
        return ForensicAuditVerdict(
            passed=False,
            reason=(
                "Baseline already passed (baseline_passed=True); "
                "candidate did not fix a failure."
            ),
            files_modified=list(manifest.files_modified),
            diff_stat=manifest.diff_stat,
        )

    files_modified, diff_stat = _get_git_diff_stats(repo_root, base_sha, candidate_sha)
    if not files_modified:
        return ForensicAuditVerdict(
            passed=False,
            reason="Empty candidate diff (0 modified files).",
            files_modified=[],
            diff_stat="",
        )

    PolicyGuard().inspect_git_diff(repo_root, base_sha, candidate_sha)

    locked_tests: list[str] = []
    locked_seen: set[str] = set()

    def _add_locked(raw_path: str | None) -> None:
        if not raw_path or not raw_path.strip():
            return
        norm_p = raw_path.strip().replace("\\", "/").lstrip("./")
        if norm_p and norm_p not in locked_seen:
            locked_seen.add(norm_p)
            locked_tests.append(norm_p)

    _add_locked(repro_test_path)
    _add_locked(manifest.repro_test_path)
    for extra_path in repro_test_paths:
        _add_locked(extra_path)
    if repro_command:
        for extracted in _extract_test_files_from_command(repro_command, repo_root):
            _add_locked(extracted)
    for extracted in _extract_test_files_from_command(manifest.rerun_command, repo_root):
        _add_locked(extracted)

    for rel_path in files_modified:
        norm = rel_path.replace("\\", "/").lstrip("./")
        if norm in locked_seen:
            raise PolicyImmutabilityError(
                f"FORENSIC_AUDIT_FAILED: candidate tampered with locked repro test {norm!r}.",
                offending_paths=(norm,),
            )
        for prefix in _FORBIDDEN_QA_MUTATION_PREFIXES:
            if norm.startswith(prefix):
                raise PolicyImmutabilityError(
                    f"FORENSIC_AUDIT_FAILED: protected QA fixture/suite modified ({norm!r}).",
                    offending_paths=(norm,),
                )
        if not allow_lockfile_edits and Path(norm).name in _LOCKFILE_NAMES:
            raise PolicyImmutabilityError(
                f"FORENSIC_AUDIT_FAILED: unauthorized lockfile modification {norm!r}.",
                offending_paths=(norm,),
            )
    _check_forbidden_test_harness_mutations(
        repo_root,
        base_sha=base_sha,
        rel_paths=files_modified,
        candidate_sha=candidate_sha,
        locked_test_paths=locked_tests,
    )

    for rel_path in files_modified:
        norm = rel_path.replace("\\", "/").lstrip("./")

        tree_proc = subprocess.run(
            ["git", "-C", str(repo_root), "ls-tree", candidate_sha, "--", norm],
            capture_output=True,
            text=True,
            check=False,
        )
        if tree_proc.returncode == 0 and tree_proc.stdout.strip():
            mode_str = tree_proc.stdout.strip().split()[0]
            mode_int = int(mode_str, 8)
            if mode_int & (stat.S_ISUID | stat.S_ISGID):
                raise PolicyImmutabilityError(
                    f"FORENSIC_AUDIT_FAILED: forbidden setuid/setgid mode {mode_str} on {norm!r}.",
                    offending_paths=(norm,),
                )
            if (mode_int & 0o111) and Path(norm).suffix not in _SCRIPT_EXTENSIONS:
                raise PolicyImmutabilityError(
                    f"FORENSIC_AUDIT_FAILED: unexpected executable bit {mode_str} on {norm!r}.",
                    offending_paths=(norm,),
                )

        size_proc = subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "-s", f"{candidate_sha}:{norm}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if size_proc.returncode == 0 and size_proc.stdout.strip().isdigit():
            file_size = int(size_proc.stdout.strip())
            if file_size > _MAX_AUDIT_FILE_BYTES:
                raise PolicyImmutabilityError(
                    f"FORENSIC_AUDIT_FAILED: file {norm!r} exceeds size limit ({file_size} bytes).",
                    offending_paths=(norm,),
                )

    if expected_repro_test_hash and locked_tests:
        cand_blobs: list[tuple[str, bytes]] = []
        for ltest in locked_tests:
            blob_proc = subprocess.run(
                ["git", "-C", str(repo_root), "show", f"{candidate_sha}:{ltest}"],
                capture_output=True,
                check=False,
            )
            if blob_proc.returncode == 0:
                cand_blobs.append((ltest, blob_proc.stdout))
        if len(cand_blobs) == 1:
            cand_test_hash = hashlib.sha256(cand_blobs[0][1]).hexdigest()[:16]
            if cand_test_hash != expected_repro_test_hash:
                raise PolicyImmutabilityError(
                    "FORENSIC_AUDIT_FAILED: locked repro test hash changed "
                    f"({cand_test_hash} != {expected_repro_test_hash}).",
                    offending_paths=(cand_blobs[0][0],),
                )
        elif len(cand_blobs) > 1:
            hasher = hashlib.sha256()
            for rel, raw_bytes in sorted(cand_blobs, key=lambda pair: pair[0]):
                hasher.update(rel.encode("utf-8"))
                hasher.update(b"\0")
                hasher.update(raw_bytes)
            cand_multi_hash = hasher.hexdigest()[:16]
            primary_norm = (
                (repro_test_path or manifest.repro_test_path or "").replace("\\", "/").lstrip("./")
            )
            primary_hashes_ok = False
            if primary_norm:
                for rel, raw_bytes in cand_blobs:
                    if rel == primary_norm:
                        primary_hashes_ok = (
                            hashlib.sha256(raw_bytes).hexdigest()[:16] == expected_repro_test_hash
                        )
                        break
            if cand_multi_hash != expected_repro_test_hash and not primary_hashes_ok:
                raise PolicyImmutabilityError(
                    "FORENSIC_AUDIT_FAILED: locked repro test hash changed "
                    f"({cand_multi_hash} != {expected_repro_test_hash}).",
                    offending_paths=tuple(rel for rel, _ in cand_blobs),
                )

    patch_diff = _run_git(repo_root, ["diff", f"{base_sha}..{candidate_sha}"])
    if contains_unredacted_secret_strict(patch_diff):
        raise PolicyImmutabilityError(
            "FORENSIC_AUDIT_FAILED: unredacted secret detected in candidate diff.",
            offending_paths=tuple(files_modified),
        )

    return ForensicAuditVerdict(
        passed=True,
        reason=(
            "Forensic audit passed "
            "(PolicyGuard, locked test, permissions, size, secrets, cross-model)."
        ),
        files_modified=files_modified,
        diff_stat=diff_stat,
    )


def _validate_safe_id(value: str, *, label: str = "candidate_id") -> str:
    if (
        not value
        or value != value.strip()
        or "/" in value
        or "\\" in value
        or ".." in value
        or "\x00" in value
        or value in {".", ".."}
    ):
        raise ValueError(
            f"Invalid {label} {value!r}: path traversal or whitespace-padded IDs are forbidden."
        )
    return value


def _enforce_locked_criterion_match(
    qa_item: QAFailureItem,
    manifest: CandidateManifest,
    *,
    candidate_id: str,
) -> None:
    if (
        qa_item.repro_test_path
        and manifest.repro_test_path
        and manifest.repro_test_path.replace("\\", "/").lstrip("./")
        != qa_item.repro_test_path.replace("\\", "/").lstrip("./")
    ):
        raise PolicyImmutabilityError(
            f"FORENSIC_AUDIT_FAILED: candidate {candidate_id!r} repro_test_path="
            f"{manifest.repro_test_path!r} conflicts with locked qa_item "
            f"repro_test_path={qa_item.repro_test_path!r}.",
            offending_paths=(manifest.repro_test_path, qa_item.repro_test_path),
        )
    if (
        qa_item.repro_test_hash
        and manifest.repro_test_hash
        and manifest.repro_test_hash != qa_item.repro_test_hash
    ):
        raise PolicyImmutabilityError(
            f"FORENSIC_AUDIT_FAILED: candidate {candidate_id!r} repro_test_hash="
            f"{manifest.repro_test_hash!r} conflicts with locked qa_item "
            f"repro_test_hash={qa_item.repro_test_hash!r}.",
            offending_paths=((qa_item.repro_test_path or manifest.repro_test_path or ""),),
        )
    if (
        qa_item.locked_criterion_hash
        and manifest.locked_criterion_hash != qa_item.locked_criterion_hash
    ):
        raise PolicyImmutabilityError(
            f"FORENSIC_AUDIT_FAILED: candidate {candidate_id!r} locked_criterion_hash="
            f"{manifest.locked_criterion_hash!r} conflicts with locked qa_item "
            f"locked_criterion_hash={qa_item.locked_criterion_hash!r}.",
            offending_paths=((qa_item.repro_test_path or manifest.repro_test_path or ""),),
        )
    qa_repro_cmd = _effective_item_repro_command(qa_item)
    if not qa_repro_cmd:
        raise PolicyImmutabilityError(
            f"FORENSIC_AUDIT_FAILED: cannot accept candidate {candidate_id!r} onto "
            f"qa branch: qa_item {qa_item.item_id!r} has no locked repro_command or "
            "repro_test_path.",
            offending_paths=((qa_item.repro_test_path or manifest.repro_test_path or ""),),
        )
    if manifest.rerun_command.strip() != qa_repro_cmd:
        raise PolicyImmutabilityError(
            f"FORENSIC_AUDIT_FAILED: candidate {candidate_id!r} rerun_command="
            f"{manifest.rerun_command!r} conflicts with locked qa_item "
            f"repro_command={qa_repro_cmd!r}.",
            offending_paths=((qa_item.repro_test_path or manifest.repro_test_path or ""),),
        )


def _load_candidate_manifest(
    campaign_dir: Path, candidate_id: str
) -> tuple[Path, CandidateManifest]:
    _validate_safe_id(candidate_id, label="candidate_id")
    candidates_dir = (campaign_dir / "candidates").resolve()
    cand_path = (candidates_dir / f"{candidate_id}.json").resolve()
    if cand_path.parent != candidates_dir:
        raise ValueError(
            f"Invalid candidate_id {candidate_id!r}: resolved path escapes candidates directory."
        )
    if not cand_path.is_file():
        raise FileNotFoundError(f"Candidate manifest not found: {cand_path}")
    manifest = CandidateManifest.model_validate_json(cand_path.read_text(encoding="utf-8"))
    return cand_path, manifest


def _save_candidate_manifest(
    cand_path: Path,
    manifest: CandidateManifest,
    *,
    store: FactoryStore | None = None,
) -> None:
    cand_path.parent.mkdir(parents=True, exist_ok=True)
    sanitized = assert_strictly_redacted(
        json.loads(manifest.model_dump_json()), label=f"candidate:{manifest.candidate_id}"
    )
    cand_path.write_text(
        json.dumps(sanitized, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    if store is not None:
        now_iso = utc_now().isoformat()
        with store.write_tx() as conn:
            has_item = conn.execute(
                "SELECT 1 FROM qa_items WHERE item_id = ?;", (manifest.item_id,)
            ).fetchone()
            if has_item is not None:
                conn.execute(
                    """
                    INSERT INTO qa_candidates (
                        candidate_id, campaign_id, item_id, proposal_hash, base_sha,
                        candidate_sha, branch_name, author_model, reviewer_model, auditor_model,
                        status, manifest_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(candidate_id) DO UPDATE SET
                        proposal_hash=COALESCE(excluded.proposal_hash, qa_candidates.proposal_hash),
                        candidate_sha=excluded.candidate_sha,
                        status=excluded.status,
                        manifest_json=excluded.manifest_json,
                        updated_at=excluded.updated_at;
                    """,
                    (
                        manifest.candidate_id,
                        manifest.campaign_id,
                        manifest.item_id,
                        manifest.proposal_hash,
                        manifest.base_sha,
                        manifest.candidate_sha,
                        manifest.branch_name,
                        manifest.author_model,
                        manifest.reviewer_model,
                        manifest.auditor_model,
                        manifest.status,
                        json.dumps(sanitized, sort_keys=True, ensure_ascii=False),
                        manifest.created_at.isoformat(),
                        now_iso,
                    ),
                )


def _check_lease_fencing(
    store: FactoryStore,
    state: CampaignState,
    manifest: CandidateManifest,
) -> None:
    """Reject candidates whose FactoryStore lease generation was superseded or expired."""
    latest = store.get_latest_lease(f"fb-{manifest.item_id}") or store.get_latest_lease(
        manifest.item_id
    )
    if latest is None:
        return

    claimed_lease_id = manifest.lease_id or state.active_leases.get(manifest.item_id)
    if manifest.lease_generation is not None and manifest.lease_generation < latest.generation:
        raise ValueError(
            f"Stale lease generation {manifest.lease_generation} for item {manifest.item_id!r} "
            f"(current generation={latest.generation}, owner={latest.owner!r})."
        )
    if claimed_lease_id is not None and claimed_lease_id != latest.lease_id:
        raise ValueError(
            f"Stale/superseded lease {claimed_lease_id!r} for item {manifest.item_id!r} "
            f"(latest={latest.lease_id!r}, gen={latest.generation}, owner={latest.owner!r})."
        )
    if claimed_lease_id is not None and latest.status == "expired":
        raise ValueError(
            f"Expired lease {claimed_lease_id!r} for item {manifest.item_id!r} "
            f"(generation={latest.generation})."
        )


@contextlib.contextmanager
def _integrator_file_lock(campaign_dir: Path) -> Iterator[None]:
    lock_path = campaign_dir / ".integrator.lock"
    with _PROCESS_INTEGRATOR_LOCK, lock_path.open("a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def reevaluate_qa_item(
    campaign_dir: Path,
    *,
    item_id: str,
    repo_root: Path,
    build_frontend: bool = False,
    skip_browser: bool = True,
) -> dict[str, Any]:
    """Re-run repro_command on baseline and re-evaluate matching candidate manifests."""
    safe_dir = validate_campaign_isolation(campaign_dir, repo_root=repo_root)
    campaign_file = safe_dir / "campaign.json"
    if not campaign_file.is_file():
        raise FileNotFoundError(f"Missing campaign.json in {safe_dir}")
    state = CampaignState.model_validate_json(campaign_file.read_text(encoding="utf-8"))
    validate_campaign_isolation(
        safe_dir,
        repo_root=repo_root,
        target_url=state.target_url,
        allow_live_target=True,
    )

    store = open_campaign_store(safe_dir, state, repo_root=repo_root)
    import_failures_jsonl_into_store(store, state, safe_dir)
    item = get_qa_item(store, state.campaign_id, item_id)
    if item is None:
        raise FileNotFoundError(f"Unknown QA item {item_id!r} in {safe_dir}")

    effective_item_repro = _effective_item_repro_command(item)
    if not effective_item_repro:
        if item.state not in {"candidate_verified", "accepted_qa", "blocked", "parked"}:
            updated_item = transition_qa_item_state(
                store,
                state.campaign_id,
                item.item_id,
                "blocked",
                blocked_reason="needs_repro: missing repro_command and repro_test_path",
                next_diagnostic="Provide repro_command or repro_test_path before reevaluation.",
            )
        else:
            updated_item = item
        sync_failures_jsonl_from_store(store, state.campaign_id, safe_dir)
        updated_state = state.model_copy(
            update={
                "last_requested_command": "reevaluate",
                "updated_at": utc_now(),
            }
        )
        save_campaign_state(safe_dir, updated_state, store=store)
        return {
            "ok": False,
            "item_id": updated_item.item_id,
            "state": updated_item.state,
            "baseline_passed": False,
            "reason": "needs_repro: missing repro_command and repro_test_path",
            "evaluated_candidates": [],
        }

    base_ref = state.qa_branch if _git_branch_exists(repo_root, state.qa_branch) else state.base_sha
    base_sha = _run_git(repo_root, ["rev-parse", base_ref])

    baseline_meta: dict[str, Any] = {}
    baseline_eval_fn = build_qa_product_evaluator(
        repro_command=effective_item_repro,
        campaign_dir=safe_dir,
        case_id=item.case_id,
        build_frontend=build_frontend,
        skip_browser=skip_browser,
        metadata_out=baseline_meta,
    )
    with ephemeral_git_worktree(repo_root, ref=base_sha) as base_wt:
        base_res = baseline_eval_fn(base_wt)
        base_extracted_files = _extract_test_files_from_command(effective_item_repro, base_wt)
        repro_hash, crit_hash = _compute_repro_hashes(
            base_wt,
            repro_command=effective_item_repro,
            repro_test_path=item.repro_test_path,
        )

    if item.state in {"candidate_verified", "accepted_qa"}:
        updated_item = item
    else:
        updated_item = record_item_probe_outcome(
            store,
            state.campaign_id,
            item.item_id,
            passed=base_res.passed,
            run_id=f"reeval-{uuid.uuid4().hex[:8]}",
        )

    evaluated_candidates: list[dict[str, Any]] = []
    candidates_dir = safe_dir / "candidates"
    if candidates_dir.is_dir():
        for cand_path in sorted(candidates_dir.glob("*.json")):
            manifest = CandidateManifest.model_validate_json(
                cand_path.read_text(encoding="utf-8")
            )
            if manifest.item_id != item.item_id:
                continue
            if manifest.status in {"accepted_qa", "rolled_back"}:
                continue

            cand_ref = manifest.candidate_sha or manifest.branch_name
            try:
                cand_sha = _run_git(repo_root, ["rev-parse", cand_ref])
            except FactoryError:
                continue

            authoritative_repro = effective_item_repro or manifest.rerun_command
            extracted_repro_files = list(base_extracted_files)
            for rel_f in _extract_test_files_from_command(authoritative_repro, repo_root):
                if rel_f not in extracted_repro_files:
                    extracted_repro_files.append(rel_f)
            reeval_locked_tests: list[str] = []
            for cand_locked in (
                item.repro_test_path,
                manifest.repro_test_path,
                *extracted_repro_files,
            ):
                if cand_locked and cand_locked not in reeval_locked_tests:
                    reeval_locked_tests.append(cand_locked)
            files_modified, diff_stat = _get_git_diff_stats(
                repo_root, manifest.base_sha, cand_sha
            )
            pre_audit_exc: Exception | None = None
            if files_modified:
                try:
                    PolicyGuard().inspect_git_diff(repo_root, manifest.base_sha, cand_sha)
                    _check_forbidden_test_harness_mutations(
                        repo_root,
                        base_sha=manifest.base_sha,
                        rel_paths=files_modified,
                        candidate_sha=cand_sha,
                        locked_test_paths=reeval_locked_tests,
                    )
                except (PolicyImmutabilityError, IsolationBoundaryError, ValueError) as exc:
                    pre_audit_exc = exc

            cand_meta: dict[str, Any] = {}
            if pre_audit_exc is None:
                cand_eval_fn = build_qa_product_evaluator(
                    repro_command=authoritative_repro,
                    campaign_dir=safe_dir,
                    case_id=item.case_id,
                    build_frontend=build_frontend,
                    skip_browser=skip_browser,
                    metadata_out=cand_meta,
                )
                with ephemeral_git_worktree(repo_root, ref=cand_sha) as cand_wt:
                    cand_res = cand_eval_fn(cand_wt)
                cand_passed = cand_res.passed
                cand_detail = cand_res.detail
            else:
                cand_passed = False
                cand_detail = str(pre_audit_exc)

            preserve_baseline_fail = (
                manifest.status == "candidate_verified" and manifest.baseline_passed is False
            )
            provisional = manifest.model_copy(
                update={
                    "candidate_sha": cand_sha,
                    "build_hash": str(cand_meta.get("build_hash") or ""),
                    "diff_stat": diff_stat,
                    "files_modified": files_modified,
                    "baseline_passed": False if preserve_baseline_fail else base_res.passed,
                    "candidate_passed": cand_passed,
                    "repro_test_hash": manifest.repro_test_hash or repro_hash,
                    "locked_criterion_hash": manifest.locked_criterion_hash or crit_hash,
                    "evaluator_summary": cand_detail,
                }
            )
            effective_repro_test_path = (
                item.repro_test_path
                or manifest.repro_test_path
                or (extracted_repro_files[0] if extracted_repro_files else None)
            )
            audit_ok = False
            audit_notes = ""
            try:
                _enforce_locked_criterion_match(
                    item, manifest, candidate_id=manifest.candidate_id
                )
                verdict = audit_candidate_forensic(
                    repo_root,
                    manifest=provisional,
                    base_sha=manifest.base_sha,
                    candidate_sha=cand_sha,
                    repro_test_path=effective_repro_test_path,
                    repro_test_paths=extracted_repro_files,
                    repro_command=authoritative_repro,
                    expected_repro_test_hash=provisional.repro_test_hash,
                )
                audit_ok = verdict.passed
                audit_notes = verdict.reason
            except (PolicyImmutabilityError, IsolationBoundaryError, ValueError) as exc:
                audit_ok = False
                audit_notes = str(exc)

            new_status: Any = "candidate_verified" if audit_ok else "rejected"
            final_manifest = provisional.model_copy(
                update={
                    "audit_passed": audit_ok,
                    "audit_notes": audit_notes,
                    "status": new_status,
                }
            )
            _save_candidate_manifest(cand_path, final_manifest, store=store)
            if audit_ok and updated_item.state in {"observed", "reproduced", "in_repair"}:
                if updated_item.state == "observed":
                    updated_item = transition_qa_item_state(
                        store, state.campaign_id, updated_item.item_id, "reproduced"
                    )
                if updated_item.state == "reproduced":
                    updated_item = transition_qa_item_state(
                        store, state.campaign_id, updated_item.item_id, "in_repair"
                    )
                updated_item = transition_qa_item_state(
                    store,
                    state.campaign_id,
                    updated_item.item_id,
                    "candidate_verified",
                    candidate_id=final_manifest.candidate_id,
                    repro_test_hash=repro_hash,
                    locked_criterion_hash=crit_hash,
                )
            evaluated_candidates.append(
                {
                    "candidate_id": final_manifest.candidate_id,
                    "status": final_manifest.status,
                    "baseline_passed": final_manifest.baseline_passed,
                    "candidate_passed": final_manifest.candidate_passed,
                    "audit_passed": final_manifest.audit_passed,
                }
            )

    sync_failures_jsonl_from_store(store, state.campaign_id, safe_dir)
    updated_state = state.model_copy(
        update={
            "last_requested_command": "reevaluate",
            "updated_at": utc_now(),
        }
    )
    save_campaign_state(safe_dir, updated_state, store=store)
    return {
        "ok": True,
        "item_id": updated_item.item_id,
        "state": updated_item.state,
        "baseline_passed": base_res.passed,
        "evaluated_candidates": evaluated_candidates,
    }


def _discover_passing_regression_tests(
    repo_root: Path,
    *,
    current_tip: str,
) -> tuple[str, ...]:
    """Discover repo test files (tests/unit -> tests -> root test_*.py) that pass on tip."""
    with ephemeral_git_worktree(repo_root, ref=current_tip) as tip_wt:
        discovered: list[str] = []
        unit_dir = tip_wt / "tests" / "unit"
        tests_dir = tip_wt / "tests"
        if unit_dir.is_dir():
            discovered.extend(
                str(p.relative_to(tip_wt)).replace("\\", "/")
                for p in sorted(unit_dir.rglob("test_*.py"))
            )
        elif tests_dir.is_dir():
            discovered.extend(
                str(p.relative_to(tip_wt)).replace("\\", "/")
                for p in sorted(tests_dir.rglob("test_*.py"))
            )
        for root_test in sorted(tip_wt.glob("test_*.py")):
            rel = str(root_test.relative_to(tip_wt)).replace("\\", "/")
            if rel not in discovered:
                discovered.append(rel)

        if not discovered:
            return ()

        quoted_all = " ".join(shlex.quote(p) for p in discovered)
        all_ok, _ = _run_shell_or_cmd(
            f"{sys.executable} -B -m pytest -q -o addopts= -p no:cacheprovider {quoted_all}",
            cwd=tip_wt,
        )
        if all_ok:
            if unit_dir.is_dir() and not any(tip_wt.glob("test_*.py")) and len(discovered) > 20:
                return ("tests/unit",)
            return tuple(discovered)

        passing: list[str] = []
        for rel in discovered:
            t_ok, _ = _run_shell_or_cmd(
                f"{sys.executable} -B -m pytest -q -o addopts= -p no:cacheprovider "
                f"{shlex.quote(rel)}",
                cwd=tip_wt,
            )
            if t_ok:
                passing.append(rel)
        return tuple(passing)


def accept_candidate_to_qa(
    campaign_dir: Path,
    *,
    candidate_id: str,
    repo_root: Path,
    build_frontend: bool = False,
    skip_browser: bool = True,
) -> dict[str, Any]:
    """Single serialized Integrator: validate audit/lease, rebase, retest, promote/rollback."""
    safe_dir = validate_campaign_isolation(campaign_dir, repo_root=repo_root)
    campaign_file = safe_dir / "campaign.json"
    if not campaign_file.is_file():
        raise FileNotFoundError(f"Missing campaign.json in {safe_dir}")
    state = CampaignState.model_validate_json(campaign_file.read_text(encoding="utf-8"))
    validate_campaign_isolation(
        safe_dir,
        repo_root=repo_root,
        target_url=state.target_url,
        allow_live_target=True,
    )

    with _integrator_file_lock(safe_dir):
        store = open_campaign_store(safe_dir, state, repo_root=repo_root)
        import_failures_jsonl_into_store(store, state, safe_dir)

        cand_path, manifest = _load_candidate_manifest(safe_dir, candidate_id)
        if manifest.status in {"rejected", "rolled_back", "accepted_qa"}:
            raise ValueError(
                f"Cannot accept candidate {candidate_id!r}: "
                f"status={manifest.status!r} is not eligible for acceptance."
            )
        _check_lease_fencing(store, state, manifest)

        qa_item = get_qa_item(store, state.campaign_id, manifest.item_id)
        if qa_item is not None:
            _enforce_locked_criterion_match(qa_item, manifest, candidate_id=candidate_id)
            if qa_item.state not in {"observed", "reproduced", "in_repair", "candidate_verified"}:
                raise ValueError(
                    f"Cannot accept candidate {candidate_id!r} for QA item {manifest.item_id!r} "
                    f"in state {qa_item.state!r}."
                )

        effective_item_repro = (
            _effective_item_repro_command(qa_item) if qa_item is not None else ""
        )
        effective_repro_command = effective_item_repro or manifest.rerun_command
        extracted_repro_files: list[str]
        if manifest.base_sha:
            try:
                _run_git(repo_root, ["rev-parse", "--verify", f"{manifest.base_sha}^{{commit}}"])
                with ephemeral_git_worktree(repo_root, ref=manifest.base_sha) as acc_base_wt:
                    extracted_repro_files = _extract_test_files_from_command(
                        effective_repro_command, acc_base_wt
                    )
            except FactoryError:
                extracted_repro_files = _extract_test_files_from_command(
                    effective_repro_command, repo_root
                )
        else:
            extracted_repro_files = _extract_test_files_from_command(
                effective_repro_command, repo_root
            )
        effective_repro_test_path = (
            (qa_item.repro_test_path if qa_item else None)
            or manifest.repro_test_path
            or (extracted_repro_files[0] if extracted_repro_files else None)
        )
        effective_repro_test_hash = (
            (qa_item.repro_test_hash if qa_item else None) or manifest.repro_test_hash
        )

        cand_ref = manifest.candidate_sha or manifest.branch_name
        cand_sha = _run_git(repo_root, ["rev-parse", cand_ref])
        verdict = audit_candidate_forensic(
            repo_root,
            manifest=manifest,
            base_sha=manifest.base_sha,
            candidate_sha=cand_sha,
            repro_test_path=effective_repro_test_path,
            repro_test_paths=extracted_repro_files,
            repro_command=effective_repro_command,
            expected_repro_test_hash=effective_repro_test_hash,
        )
        if not verdict.passed:
            rejected = manifest.model_copy(
                update={
                    "status": "rejected",
                    "audit_passed": False,
                    "audit_notes": verdict.reason,
                }
            )
            _save_candidate_manifest(cand_path, rejected, store=store)
            raise ValueError(f"Candidate {candidate_id!r} failed forensic audit: {verdict.reason}")

        qa_branch = state.qa_branch
        if not _git_branch_exists(repo_root, qa_branch):
            _run_git(repo_root, ["branch", qa_branch, manifest.base_sha])

        current_tip = _run_git(repo_root, ["rev-parse", qa_branch])
        rb_dir = (safe_dir / "rollbacks").resolve()
        rb_dir.mkdir(parents=True, exist_ok=True)
        factory_manifest_out = (rb_dir / f"rollback_{candidate_id}.json").resolve()
        if factory_manifest_out.parent != rb_dir:
            raise ValueError(f"Invalid candidate_id {candidate_id!r}: rollback path escaped.")

        meta_out: dict[str, Any] = {}
        eval_fn = build_qa_product_evaluator(
            repro_command=effective_repro_command,
            campaign_dir=safe_dir,
            case_id=manifest.item_id,
            build_frontend=build_frontend,
            skip_browser=skip_browser,
            metadata_out=meta_out,
        )

        # Determine regression gate tests that ALREADY pass on current_tip
        pytest_args = _discover_passing_regression_tests(repo_root, current_tip=current_tip)
        run_full_pytest = False

        engine = FactoryEngine(
            repo_root,
            store,
            base_branch=qa_branch,
            owner="qa-integrator",
            artifacts_dir=rb_dir,
        )
        patch = CandidatePatch(
            candidate_id=manifest.candidate_id,
            item_id=f"fb-{manifest.item_id}",
            branch_name=manifest.branch_name,
            hypothesis=f"Accept QA candidate {manifest.candidate_id}",
            target_metric="failing_assertions",
            proposal_hash=manifest.proposal_hash
            or compute_proposal_hash(
                item_id=manifest.item_id,
                target_metric="failing_assertions",
                files_to_modify=dict.fromkeys(verdict.files_modified, "modified"),
                repro_test_path=effective_repro_test_path,
            ),
            files_to_modify={},
            repro_test_path=effective_repro_test_path,
            author_model=manifest.author_model,
            auditor_model=manifest.auditor_model,
            write_area=manifest.write_area,
        )
        result = engine.promote_candidate_branch(
            patch,
            candidate_commit=cand_sha,
            base_commit=manifest.base_sha,
            target_branch=qa_branch,
            evaluator=eval_fn,
            manifest_out=factory_manifest_out,
            rebase_on_drift=True,
            pytest_args=pytest_args,
            run_full_pytest=run_full_pytest,
            extra_forbidden_paths=(),
        )

        if result.status != FactoryStatus.PROMOTED or not result.candidate_commit:
            rolled_back = manifest.model_copy(
                update={
                    "status": "rolled_back",
                    "rollback_sha": current_tip,
                    "audit_notes": result.reason,
                }
            )
            _save_candidate_manifest(cand_path, rolled_back, store=store)
            qa_item = get_qa_item(store, state.campaign_id, manifest.item_id)
            if qa_item is not None and qa_item.state == "candidate_verified":
                transition_qa_item_state(
                    store, state.campaign_id, qa_item.item_id, "reproduced"
                )
            sync_failures_jsonl_from_store(store, state.campaign_id, safe_dir)
            raise RuntimeError(
                f"Combined QA gate regression on accept for {candidate_id!r}; "
                f"rolled back {qa_branch!r} to {current_tip}: {result.reason}"
            )

        accepted_manifest = manifest.model_copy(
            update={
                "candidate_sha": result.candidate_commit,
                "build_hash": str(meta_out.get("build_hash") or manifest.build_hash or ""),
                "diff_stat": verdict.diff_stat,
                "files_modified": verdict.files_modified,
                "audit_passed": True,
                "rollback_manifest_path": str(factory_manifest_out),
                "rollback_sha": current_tip,
                "status": "accepted_qa",
            }
        )
        _save_candidate_manifest(cand_path, accepted_manifest, store=store)

        qa_item = get_qa_item(store, state.campaign_id, manifest.item_id)
        if qa_item is not None:
            if qa_item.state == "observed":
                transition_qa_item_state(
                    store, state.campaign_id, qa_item.item_id, "reproduced"
                )
                qa_item = get_qa_item(store, state.campaign_id, manifest.item_id)
            if qa_item is not None and qa_item.state == "reproduced":
                transition_qa_item_state(
                    store, state.campaign_id, qa_item.item_id, "in_repair"
                )
                qa_item = get_qa_item(store, state.campaign_id, manifest.item_id)
            if qa_item is not None and qa_item.state == "in_repair":
                transition_qa_item_state(
                    store,
                    state.campaign_id,
                    qa_item.item_id,
                    "candidate_verified",
                    candidate_id=candidate_id,
                )
                qa_item = get_qa_item(store, state.campaign_id, manifest.item_id)
            if qa_item is not None and qa_item.state == "candidate_verified":
                transition_qa_item_state(
                    store,
                    state.campaign_id,
                    qa_item.item_id,
                    "accepted_qa",
                    candidate_id=candidate_id,
                )

        updated_artifacts = dict(state.artifacts)
        updated_artifacts[f"rollback_{candidate_id}"] = str(factory_manifest_out)
        updated_state = state.model_copy(
            update={
                "last_accepted_sha": result.candidate_commit,
                "last_green_sha": result.candidate_commit,
                "artifacts": updated_artifacts,
                "last_requested_command": "accept",
                "updated_at": utc_now(),
            }
        )
        save_campaign_state(safe_dir, updated_state, store=store)
        sync_failures_jsonl_from_store(store, updated_state.campaign_id, safe_dir)

        return {
            "ok": True,
            "candidate_id": candidate_id,
            "status": "accepted_qa",
            "qa_branch": qa_branch,
            "accepted_sha": result.candidate_commit,
            "previous_sha": current_tip,
            "rollback_manifest_path": str(factory_manifest_out),
        }


def rollback_candidate_from_qa(
    campaign_dir: Path,
    *,
    candidate_id: str,
    repo_root: Path,
    reason: str = "operator_or_regression_rollback",
) -> dict[str, Any]:
    """Roll back an accepted candidate on qa_branch and restore last_accepted_sha."""
    safe_dir = validate_campaign_isolation(campaign_dir, repo_root=repo_root)
    campaign_file = safe_dir / "campaign.json"
    if not campaign_file.is_file():
        raise FileNotFoundError(f"Missing campaign.json in {safe_dir}")
    state = CampaignState.model_validate_json(campaign_file.read_text(encoding="utf-8"))

    with _integrator_file_lock(safe_dir):
        store = open_campaign_store(safe_dir, state, repo_root=repo_root)
        import_failures_jsonl_into_store(store, state, safe_dir)

        cand_path, manifest = _load_candidate_manifest(safe_dir, candidate_id)
        if manifest.status != "accepted_qa":
            raise ValueError(
                f"Cannot roll back candidate {candidate_id!r}: "
                f"status={manifest.status!r} (must be 'accepted_qa')."
            )
        qa_branch = state.qa_branch
        short_qa_branch = qa_branch.removeprefix("refs/heads/")
        qa_ref = qa_branch if qa_branch.startswith("refs/") else f"refs/heads/{short_qa_branch}"

        target_sha: str | None = None
        rb_manifest_path = (
            Path(manifest.rollback_manifest_path)
            if manifest.rollback_manifest_path
            else None
        )
        f_man: RollbackManifest | None = None
        if rb_manifest_path is not None and rb_manifest_path.is_file():
            try:
                f_man = RollbackManifest.model_validate_json(
                    rb_manifest_path.read_text(encoding="utf-8")
                )
                target_sha = f_man.previous_commit
            except Exception:
                target_sha = None

        if target_sha is None:
            for cand_sha_opt in (
                manifest.rollback_sha,
                manifest.base_sha,
                state.last_accepted_sha,
                state.base_sha,
            ):
                if cand_sha_opt and cand_sha_opt != manifest.candidate_sha:
                    target_sha = cand_sha_opt
                    break

        if not target_sha or (manifest.candidate_sha and target_sha == manifest.candidate_sha):
            raise ValueError(
                f"Cannot roll back candidate {candidate_id!r}: missing valid rollback target SHA."
            )
        try:
            target_sha = _run_git(
                repo_root, ["rev-parse", "--verify", f"{target_sha}^{{commit}}"]
            )
        except FactoryError as exc:
            raise ValueError(
                f"Cannot roll back candidate {candidate_id!r}: invalid rollback SHA {target_sha!r}."
            ) from exc

        head_branch_proc = subprocess.run(
            ["git", "-C", str(repo_root), "symbolic-ref", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        head_branch = head_branch_proc.stdout.strip() if head_branch_proc.returncode == 0 else ""
        status_out = _run_git(repo_root, ["status", "--porcelain"])
        is_clean = True
        for line in status_out.splitlines():
            if not line.strip():
                continue
            if line.startswith("?? "):
                rel = line[3:].strip().strip('"').rstrip("/")
                parts = Path(rel).parts
                if ".pytest_cache" in parts or "__pycache__" in parts:
                    continue
            is_clean = False
            break
        was_clean_on_qa_branch = is_clean and (head_branch == short_qa_branch)

        _run_git(repo_root, ["update-ref", qa_ref, target_sha])
        if was_clean_on_qa_branch:
            if f_man is not None and rb_manifest_path is not None:
                rollback_from_manifest(rb_manifest_path, repo_path=repo_root, store=store)
            else:
                _run_git(repo_root, ["reset", "--hard", target_sha])
        else:
            store.mark_manifest_rolled_back(candidate_id)

        restored_head = _run_git(repo_root, ["rev-parse", qa_ref])
        if restored_head != target_sha:
            raise RuntimeError(
                f"Rollback failed: {qa_ref}={restored_head} != expected {target_sha}"
            )

        rb_dir = safe_dir / "rollbacks"
        rb_dir.mkdir(parents=True, exist_ok=True)
        qa_rb = QARollbackManifest(
            candidate_id=candidate_id,
            item_id=manifest.item_id,
            campaign_id=state.campaign_id,
            qa_branch=qa_branch,
            previous_accepted_sha=target_sha,
            rolled_back_sha=manifest.candidate_sha or state.last_accepted_sha or target_sha,
            restore_command=f"git -C {shlex.quote(str(repo_root))} reset --hard {target_sha}",
            reason=reason,
        )
        qa_rb_path = rb_dir / f"qa_rollback_{candidate_id}.json"
        qa_rb_path.write_text(qa_rb.model_dump_json(indent=2) + "\n", encoding="utf-8")

        updated_manifest = manifest.model_copy(
            update={
                "status": "rolled_back",
                "rollback_sha": target_sha,
            }
        )
        _save_candidate_manifest(cand_path, updated_manifest, store=store)

        qa_item = get_qa_item(store, state.campaign_id, manifest.item_id)
        if qa_item is not None and qa_item.state == "accepted_qa":
            transition_qa_item_state(store, state.campaign_id, qa_item.item_id, "reproduced")

        updated_state = state.model_copy(
            update={
                "last_accepted_sha": target_sha,
                "last_requested_command": "rollback",
                "updated_at": utc_now(),
            }
        )
        save_campaign_state(safe_dir, updated_state, store=store)
        sync_failures_jsonl_from_store(store, updated_state.campaign_id, safe_dir)

        return {
            "ok": True,
            "candidate_id": candidate_id,
            "status": "rolled_back",
            "restored_sha": restored_head,
            "qa_rollback_manifest_path": str(qa_rb_path),
        }


def _invoke_repairer_adapter(
    worktree: Path,
    item: QAFailureItem,
    *,
    repairer_fn: Callable[[Path, QAFailureItem], dict[str, str]] | None = None,
) -> tuple[list[str], str]:
    """Generate minimal candidate changes in `worktree` via injected fn, LLM HTTP, or `agy`."""
    if repairer_fn is not None:
        edits = repairer_fn(worktree, item)
        changed: list[str] = []
        for rel_path, content in edits.items():
            target = (worktree / rel_path).resolve()
            if not target.is_relative_to(worktree.resolve()):
                raise IsolationBoundaryError(f"Repairer escaped worktree: {rel_path}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            changed.append(rel_path)
        return changed, "custom_repairer_fn"

    test_rel = item.repro_test_path or _extract_test_file_from_command(
        item.repro_command, worktree
    )
    test_body = ""
    if test_rel and (worktree / test_rel).is_file():
        test_body = (worktree / test_rel).read_text(encoding="utf-8", errors="replace")[:2000]

    prompt = (
        f"Fix QA failure {item.item_id} ({item.subsystem}): {item.summary}\n"
        f"Repro command: {item.repro_command}\n"
        f"Repro test ({test_rel or 'none'}):\n{test_body}\n"
        "Modify only the minimal source file(s). Never modify tests or PolicyGuard files."
    )

    llm_url = os.environ.get("GROKBOT_LLM_BASE_URL", "").strip()
    if llm_url:
        try:
            endpoint = f"{llm_url.rstrip('/')}/v1/chat/completions"
            req_body = json.dumps(
                {
                    "model": os.environ.get("GROKBOT_LLM_MODEL_ID", "local-model"),
                    "messages": [{"role": "user", "content": prompt}],
                }
            ).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            api_key = os.environ.get("GROKBOT_LLM_API_KEY", "").strip()
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            req = urllib.request.Request(endpoint, data=req_body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=30.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            content_str = (
                data.get("choices", [{}])[0].get("message", {}).get("content", "")
                if isinstance(data, dict)
                else ""
            )
            parsed = json.loads(content_str) if content_str.strip().startswith("{") else {}
            files_map = parsed.get("files") if isinstance(parsed, dict) else None
            if isinstance(files_map, dict) and files_map:
                changed = []
                for rel_path, content in files_map.items():
                    if isinstance(rel_path, str) and isinstance(content, str):
                        target = (worktree / rel_path).resolve()
                        if target.is_relative_to(worktree.resolve()):
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_text(content, encoding="utf-8")
                            changed.append(rel_path)
                if changed:
                    model_used = os.environ.get("GROKBOT_LLM_MODEL_ID", "").strip() or "local-llm"
                    return changed, model_used
        except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError):
            pass

    agy_bin = shutil.which("agy")
    if agy_bin:
        proc = subprocess.run(
            [agy_bin, "--prompt", prompt],
            cwd=str(worktree),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode == 0:
            status_proc = subprocess.run(
                [
                    "git",
                    "-C",
                    str(worktree),
                    "-c",
                    "core.quotepath=false",
                    "status",
                    "--porcelain",
                    "-z",
                    "-uall",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if status_proc.returncode != 0:
                err = status_proc.stderr.strip() or status_proc.stdout.strip()
                raise FactoryError(f"git status --porcelain -z -uall failed in {worktree}: {err}")
            entries = status_proc.stdout.split("\0")
            changed = []
            idx = 0
            while idx < len(entries):
                entry = entries[idx]
                idx += 1
                if not entry or len(entry) < 4:
                    continue
                xy = entry[:2]
                rel_path = entry[3:]
                if rel_path and rel_path not in changed:
                    changed.append(rel_path)
                if ("R" in xy or "C" in xy) and idx < len(entries):
                    orig_path = entries[idx]
                    idx += 1
                    if orig_path and orig_path not in changed:
                        changed.append(orig_path)
            if changed:
                return changed, "agy-repairer"

    return [], "none"


def _areas_overlap(area_a: str, area_b: str) -> bool:
    tokens_a = {t.strip() for t in area_a.split(",") if t.strip()}
    tokens_b = {t.strip() for t in area_b.split(",") if t.strip()}
    return bool(tokens_a & tokens_b)


def _compute_worktree_proposal_hash(
    worktree: Path,
    *,
    item_id: str,
    changed_files: Sequence[str],
    repro_test_path: str | None,
) -> str:
    files_map: dict[str, str] = {}
    for rel in sorted(set(changed_files)):
        target = worktree / rel
        if target.is_file():
            files_map[rel] = target.read_text(encoding="utf-8", errors="replace")
        else:
            files_map[rel] = "__deleted__"
    return compute_proposal_hash(
        item_id=item_id,
        target_metric="failing_assertions",
        files_to_modify=files_map,
        repro_test_path=repro_test_path,
    )


def _find_duplicate_evaluated_candidate(
    store: FactoryStore,
    campaign_dir: Path,
    *,
    item_id: str,
    base_sha: str,
    proposal_hash: str,
) -> tuple[str, str] | None:
    """Return (candidate_id, status) if (item_id, base_sha, proposal_hash) was already evaluated."""
    evaluated_qa_statuses = ("rejected", "rolled_back", "candidate_verified", "accepted_qa")
    with store.read_tx() as conn:
        qa_row = conn.execute(
            """
            SELECT candidate_id, status FROM qa_candidates
            WHERE item_id = ? AND base_sha = ? AND proposal_hash = ?
              AND status IN ('rejected', 'rolled_back', 'candidate_verified', 'accepted_qa')
            LIMIT 1;
            """,
            (item_id, base_sha, proposal_hash),
        ).fetchone()
        if qa_row is not None:
            return str(qa_row["candidate_id"]), str(qa_row["status"])

        fb_row = conn.execute(
            """
            SELECT candidate_id, status FROM factory_candidates
            WHERE item_id IN (?, ?) AND base_commit = ? AND proposal_hash = ?
              AND status IN ('REJECTED', 'PROMOTED')
            LIMIT 1;
            """,
            (item_id, f"fb-{item_id}", base_sha, proposal_hash),
        ).fetchone()
        if fb_row is not None:
            return str(fb_row["candidate_id"]), str(fb_row["status"])

    cand_dir = campaign_dir / "candidates"
    if cand_dir.is_dir():
        for cf in sorted(cand_dir.glob("*.json")):
            try:
                man = CandidateManifest.model_validate_json(cf.read_text(encoding="utf-8"))
            except Exception:
                continue
            if (
                man.item_id == item_id
                and man.base_sha == base_sha
                and man.proposal_hash == proposal_hash
                and man.status in evaluated_qa_statuses
            ):
                return man.candidate_id, man.status
    return None


class QARepairLoop:
    """7-step M7 self-repair orchestrator with max-2 disjoint parallel workers + 1 integrator."""

    def __init__(
        self,
        *,
        campaign_dir: Path,
        repo_root: Path,
        max_parallel: int = 2,
        max_attempts: int = 2,
        author_model: str = "hydrogen",
        auditor_model: str = "pro",
        build_frontend: bool = False,
        skip_browser: bool = True,
        auto_accept: bool = True,
        new_evidence: bool = False,
        repairer_fn: Callable[[Path, QAFailureItem], dict[str, str]] | None = None,
    ) -> None:
        if max_parallel < 1 or max_parallel > 2:
            raise ValueError(
                f"max_parallel={max_parallel} exceeds allowed range [1, 2]; "
                "at most 2 parallel repairers are permitted."
            )
        if max_attempts < 1:
            raise ValueError(f"max_attempts must be >= 1, got {max_attempts}.")
        check_cross_model_governance(author_model, auditor_model)

        self.campaign_dir = validate_campaign_isolation(campaign_dir, repo_root=repo_root)
        self.repo_root = repo_root.resolve()
        self.max_parallel = max_parallel
        self.max_attempts = max_attempts
        self.author_model = author_model
        self.auditor_model = auditor_model
        self.build_frontend = build_frontend
        self.skip_browser = skip_browser
        self.auto_accept = auto_accept
        self.new_evidence = new_evidence
        self.repairer_fn = repairer_fn

    def _update_worker_tracking(
        self,
        store: FactoryStore,
        *,
        item_id: str,
        pid: int | None,
        lease_id: str | None,
        attempts: int | None = None,
        remove: bool = False,
    ) -> None:
        campaign_file = self.campaign_dir / "campaign.json"
        if not campaign_file.is_file():
            return
        with _integrator_file_lock(self.campaign_dir):
            cur_state = CampaignState.model_validate_json(
                campaign_file.read_text(encoding="utf-8")
            )
            pids = dict(cur_state.active_worker_pids)
            leases = dict(cur_state.active_leases)
            att_map = dict(cur_state.attempts)
            if remove:
                if pid is None or pids.get(item_id) == pid:
                    pids.pop(item_id, None)
                if lease_id is None or leases.get(item_id) == lease_id:
                    leases.pop(item_id, None)
            else:
                if pid is not None:
                    pids[item_id] = pid
                if lease_id is not None:
                    leases[item_id] = lease_id
            if attempts is not None:
                att_map[item_id] = max(att_map.get(item_id, 0), attempts)
            next_state = cur_state.model_copy(
                update={
                    "active_worker_pids": pids,
                    "active_leases": leases,
                    "attempts": att_map,
                    "updated_at": utc_now(),
                }
            )
            save_campaign_state(self.campaign_dir, next_state, store=store)

    def _run_single_slot(
        self,
        slot: RepairWorkerSlot,
        *,
        state: CampaignState,
        store: FactoryStore,
        base_sha: str,
    ) -> dict[str, Any]:
        item = slot.item
        worker_id = f"qa-worker-{uuid.uuid4().hex[:6]}"
        cand_id = (
            slot.existing_manifest.candidate_id
            if slot.existing_manifest is not None
            else f"cand-{item.item_id}-{uuid.uuid4().hex[:6]}"
        )
        cand_base_sha = (
            slot.existing_manifest.base_sha
            if slot.existing_manifest is not None and slot.existing_manifest.base_sha
            else base_sha
        )
        cand_branch = (
            slot.existing_manifest.branch_name
            if slot.existing_manifest is not None
            else f"qa/{cand_id}"
        )
        repro_cmd = (
            item.repro_command.strip()
            or (
                slot.existing_manifest.rerun_command.strip()
                if slot.existing_manifest is not None and slot.existing_manifest.rerun_command
                else ""
            )
        )
        extracted_repro_files = _extract_test_files_from_command(repro_cmd, self.repo_root)
        test_rel = (
            item.repro_test_path
            or (slot.existing_manifest.repro_test_path if slot.existing_manifest else None)
            or (extracted_repro_files[0] if extracted_repro_files else None)
        )
        if not repro_cmd and test_rel and test_rel.strip():
            repro_cmd = f"{sys.executable} -m pytest -q {shlex.quote(test_rel.strip())}"
        if not repro_cmd and not (test_rel and test_rel.strip()):
            transition_qa_item_state(
                store,
                state.campaign_id,
                item.item_id,
                "blocked",
                blocked_reason="needs_repro: missing repro_command and repro_test_path",
                next_diagnostic="Provide repro_command or repro_test_path before repair.",
            )
            return {
                "item_id": item.item_id,
                "outcome": "needs_repro",
                "state": "blocked",
            }

        # Step 2 (Reproduce) & Step 3 (Lock Criterion) in isolated base worktree
        base_meta: dict[str, Any] = {}
        eval_fn = build_qa_product_evaluator(
            repro_command=repro_cmd,
            campaign_dir=self.campaign_dir,
            case_id=item.case_id,
            build_frontend=self.build_frontend,
            skip_browser=self.skip_browser,
            metadata_out=base_meta,
        )
        with ephemeral_git_worktree(self.repo_root, ref=base_sha) as base_wt:
            base_res = eval_fn(base_wt)
            if cand_base_sha == base_sha:
                for rel_f in _extract_test_files_from_command(repro_cmd, base_wt):
                    if rel_f not in extracted_repro_files:
                        extracted_repro_files.append(rel_f)
                if not test_rel and extracted_repro_files:
                    test_rel = extracted_repro_files[0]
                repro_hash, crit_hash = _compute_repro_hashes(
                    base_wt,
                    repro_command=repro_cmd,
                    repro_test_path=test_rel,
                )

        if cand_base_sha != base_sha:
            with ephemeral_git_worktree(self.repo_root, ref=cand_base_sha) as cand_base_wt:
                extracted_repro_files = _extract_test_files_from_command(repro_cmd, cand_base_wt)
                if not test_rel and extracted_repro_files:
                    test_rel = extracted_repro_files[0]
                repro_hash, crit_hash = _compute_repro_hashes(
                    cand_base_wt,
                    repro_command=repro_cmd,
                    repro_test_path=test_rel,
                )

        if base_res.passed:
            updated = record_item_probe_outcome(
                store, state.campaign_id, item.item_id, passed=True
            )
            return {
                "item_id": item.item_id,
                "outcome": "flaky_or_passing_baseline",
                "state": updated.state,
            }

        # Step 4: Acquire FactoryStore lease, persist worker PID/lease, and move item -> in_repair
        fb_item_id = item.factory_item_id or f"fb-{item.item_id}"
        lease = store.acquire_lease(fb_item_id, worker_id, ttl_s=300.0)
        worker_pid = os.getpid()
        in_repair_item = transition_qa_item_state(
            store,
            state.campaign_id,
            item.item_id,
            "in_repair",
            attempts_delta=1,
            repro_test_hash=item.repro_test_hash or repro_hash,
            locked_criterion_hash=item.locked_criterion_hash or crit_hash,
        )
        self._update_worker_tracking(
            store,
            item_id=item.item_id,
            pid=worker_pid,
            lease_id=lease.lease_id,
            attempts=in_repair_item.attempts,
            remove=False,
        )

        cand_sha: str | None = None
        proposal_hash: str | None = (
            slot.existing_manifest.proposal_hash if slot.existing_manifest is not None else None
        )
        author_used = (
            slot.existing_manifest.author_model
            if slot.existing_manifest is not None and slot.existing_manifest.author_model
            else self.author_model
        )
        auditor_used = (
            slot.existing_manifest.auditor_model
            if slot.existing_manifest is not None and slot.existing_manifest.auditor_model
            else self.auditor_model
        )

        slot_locked_tests: list[str] = []
        for cand_locked in (
            test_rel,
            item.repro_test_path,
            slot.existing_manifest.repro_test_path if slot.existing_manifest is not None else None,
            *extracted_repro_files,
        ):
            if cand_locked and cand_locked not in slot_locked_tests:
                slot_locked_tests.append(cand_locked)

        try:
            if slot.existing_manifest is not None:
                cand_ref = (
                    slot.existing_manifest.candidate_sha or slot.existing_manifest.branch_name
                )
                cand_sha = _run_git(self.repo_root, ["rev-parse", cand_ref])
                ex_files, _ = _get_git_diff_stats(self.repo_root, cand_base_sha, cand_sha)
                if ex_files:
                    PolicyGuard().inspect_git_diff(self.repo_root, cand_base_sha, cand_sha)
                    _check_forbidden_test_harness_mutations(
                        self.repo_root,
                        base_sha=cand_base_sha,
                        rel_paths=ex_files,
                        candidate_sha=cand_sha,
                        locked_test_paths=slot_locked_tests,
                    )
                if proposal_hash is None and ex_files:
                    with ephemeral_git_worktree(self.repo_root, ref=cand_sha) as ex_wt:
                        proposal_hash = _compute_worktree_proposal_hash(
                            ex_wt,
                            item_id=item.item_id,
                            changed_files=ex_files,
                            repro_test_path=test_rel,
                        )
                if proposal_hash is not None and not self.new_evidence:
                    dup = _find_duplicate_evaluated_candidate(
                        store,
                        self.campaign_dir,
                        item_id=item.item_id,
                        base_sha=cand_base_sha,
                        proposal_hash=proposal_hash,
                    )
                    if dup is not None:
                        dup_cand_id, dup_status = dup
                        skip_reason = (
                            f"Skipped duplicate proposal {proposal_hash[:12]} for "
                            f"({item.item_id}, {cand_base_sha[:12]}) already {dup_status} as "
                            f"{dup_cand_id}."
                        )
                        cur = get_qa_item(store, state.campaign_id, item.item_id)
                        if cur is not None and cur.attempts >= self.max_attempts:
                            transition_qa_item_state(
                                store,
                                state.campaign_id,
                                item.item_id,
                                "parked",
                                next_diagnostic=skip_reason,
                            )
                        else:
                            transition_qa_item_state(
                                store,
                                state.campaign_id,
                                item.item_id,
                                "reproduced",
                                next_diagnostic=skip_reason,
                            )
                        return {
                            "item_id": item.item_id,
                            "candidate_id": dup_cand_id,
                            "proposal_hash": proposal_hash,
                            "outcome": "skipped_duplicate_proposal",
                            "skip_reason": skip_reason,
                        }
            else:
                with ephemeral_git_worktree(self.repo_root, ref=base_sha) as edit_wt:
                    changed_files, adapter_name = _invoke_repairer_adapter(
                        edit_wt, item, repairer_fn=self.repairer_fn
                    )
                    if adapter_name not in {"none", "custom_repairer_fn"}:
                        author_used = adapter_name
                        check_cross_model_governance(author_used, auditor_used)
                    if changed_files:
                        PolicyGuard().check_candidate_paths(changed_files)
                        _check_forbidden_test_harness_mutations(
                            self.repo_root,
                            base_sha=base_sha,
                            rel_paths=changed_files,
                            cand_worktree=edit_wt,
                            locked_test_paths=slot_locked_tests,
                        )
                        proposal_hash = _compute_worktree_proposal_hash(
                            edit_wt,
                            item_id=item.item_id,
                            changed_files=changed_files,
                            repro_test_path=test_rel,
                        )
                        if not self.new_evidence:
                            dup = _find_duplicate_evaluated_candidate(
                                store,
                                self.campaign_dir,
                                item_id=item.item_id,
                                base_sha=base_sha,
                                proposal_hash=proposal_hash,
                            )
                            if dup is not None:
                                dup_cand_id, dup_status = dup
                                skip_reason = (
                                    f"Skipped duplicate proposal {proposal_hash[:12]} for "
                                    f"({item.item_id}, {base_sha[:12]}) already {dup_status} as "
                                    f"{dup_cand_id}."
                                )
                                cur = get_qa_item(store, state.campaign_id, item.item_id)
                                if cur is not None and cur.attempts >= self.max_attempts:
                                    transition_qa_item_state(
                                        store,
                                        state.campaign_id,
                                        item.item_id,
                                        "parked",
                                        next_diagnostic=skip_reason,
                                    )
                                else:
                                    transition_qa_item_state(
                                        store,
                                        state.campaign_id,
                                        item.item_id,
                                        "reproduced",
                                        next_diagnostic=skip_reason,
                                    )
                                return {
                                    "item_id": item.item_id,
                                    "candidate_id": dup_cand_id,
                                    "proposal_hash": proposal_hash,
                                    "outcome": "skipped_duplicate_proposal",
                                    "skip_reason": skip_reason,
                                }
                        _run_git(edit_wt, ["add", "--", *changed_files])
                        if _run_git(edit_wt, ["status", "--porcelain"]):
                            _run_git(
                                edit_wt, ["commit", "-m", f"qa({cand_id}): fix {item.item_id}"]
                            )
                            cand_sha = _run_git(edit_wt, ["rev-parse", "HEAD"])
                            _run_git(edit_wt, ["branch", "-f", cand_branch, cand_sha])
                        else:
                            proposal_hash = None

            if cand_sha is None:
                manifest = CandidateManifest(
                    candidate_id=cand_id,
                    item_id=item.item_id,
                    campaign_id=state.campaign_id,
                    base_sha=cand_base_sha,
                    candidate_sha=None,
                    branch_name=cand_branch,
                    proposal_hash=proposal_hash,
                    rerun_command=repro_cmd or f"python -m src.qa reevaluate --item {item.item_id}",
                    baseline_passed=False,
                    candidate_passed=False,
                    audit_passed=False,
                    author_model=author_used,
                    auditor_model=auditor_used,
                    write_area=slot.write_area,
                    lease_id=lease.lease_id,
                    lease_generation=lease.generation,
                    repro_test_path=test_rel,
                    repro_test_hash=repro_hash,
                    locked_criterion_hash=crit_hash,
                    audit_notes="No repairer produced a candidate diff (write_area serialized).",
                    status="rejected",
                )
                _save_candidate_manifest(
                    self.campaign_dir / "candidates" / f"{cand_id}.json", manifest, store=store
                )
                cur = get_qa_item(store, state.campaign_id, item.item_id)
                if cur is not None and cur.attempts >= self.max_attempts:
                    transition_qa_item_state(
                        store,
                        state.campaign_id,
                        item.item_id,
                        "parked",
                        next_diagnostic=(
                            f"No repairer patch produced after {cur.attempts} attempt(s); "
                            f"check {repro_cmd!r}."
                        ),
                    )
                else:
                    transition_qa_item_state(store, state.campaign_id, item.item_id, "reproduced")
                return {
                    "item_id": item.item_id,
                    "candidate_id": cand_id,
                    "outcome": "no_patch_produced",
                }

            # Step 5: Compare baseline vs candidate on isolated worktree + compiled React
            cand_meta: dict[str, Any] = {}
            cand_eval_fn = build_qa_product_evaluator(
                repro_command=repro_cmd,
                campaign_dir=self.campaign_dir,
                case_id=item.case_id,
                build_frontend=self.build_frontend,
                skip_browser=self.skip_browser,
                metadata_out=cand_meta,
            )
            with ephemeral_git_worktree(self.repo_root, ref=cand_sha) as cand_wt:
                cand_res = cand_eval_fn(cand_wt)

            files_modified, diff_stat = _get_git_diff_stats(
                self.repo_root, cand_base_sha, cand_sha
            )
            cand_repro_hash = (
                slot.existing_manifest.repro_test_hash
                if slot.existing_manifest is not None and slot.existing_manifest.repro_test_hash
                else repro_hash
            )
            cand_crit_hash = (
                slot.existing_manifest.locked_criterion_hash
                if slot.existing_manifest is not None
                and slot.existing_manifest.locked_criterion_hash
                else crit_hash
            )
            provisional = CandidateManifest(
                candidate_id=cand_id,
                item_id=item.item_id,
                campaign_id=state.campaign_id,
                base_sha=cand_base_sha,
                candidate_sha=cand_sha,
                branch_name=cand_branch,
                proposal_hash=proposal_hash,
                build_hash=str(cand_meta.get("build_hash") or ""),
                diff_stat=diff_stat,
                files_modified=files_modified,
                repro_test_path=test_rel,
                rerun_command=repro_cmd or f"python -m src.qa reevaluate --item {item.item_id}",
                baseline_passed=False,
                candidate_passed=cand_res.passed,
                audit_passed=False,
                author_model=author_used,
                auditor_model=auditor_used,
                write_area=slot.write_area,
                lease_id=lease.lease_id,
                lease_generation=lease.generation,
                repro_test_hash=cand_repro_hash,
                locked_criterion_hash=cand_crit_hash,
                evaluator_summary=cand_res.detail,
                status="pending",
            )

            # Step 6: Forensic Audit
            verdict = audit_candidate_forensic(
                self.repo_root,
                manifest=provisional,
                base_sha=cand_base_sha,
                candidate_sha=cand_sha,
                repro_test_path=test_rel,
                repro_test_paths=extracted_repro_files,
                repro_command=repro_cmd,
                expected_repro_test_hash=item.repro_test_hash or repro_hash,
            )
            final_status: Any = "candidate_verified" if verdict.passed else "rejected"
            final_manifest = provisional.model_copy(
                update={
                    "audit_passed": verdict.passed,
                    "audit_notes": verdict.reason,
                    "status": final_status,
                }
            )
            _save_candidate_manifest(
                self.campaign_dir / "candidates" / f"{cand_id}.json",
                final_manifest,
                store=store,
            )
            if verdict.passed:
                transition_qa_item_state(
                    store,
                    state.campaign_id,
                    item.item_id,
                    "candidate_verified",
                    candidate_id=cand_id,
                )
            else:
                transition_qa_item_state(store, state.campaign_id, item.item_id, "reproduced")

            return {
                "item_id": item.item_id,
                "candidate_id": cand_id,
                "proposal_hash": proposal_hash,
                "status": final_status,
                "lease_id": lease.lease_id,
                "outcome": "verified" if verdict.passed else "rejected",
            }

        except (PolicyImmutabilityError, IsolationBoundaryError) as exc:
            transition_qa_item_state(
                store,
                state.campaign_id,
                item.item_id,
                "blocked",
                blocked_reason=f"core_maintenance_review_required: {exc}",
            )
            return {
                "item_id": item.item_id,
                "candidate_id": cand_id,
                "outcome": "blocked_policy",
                "error": str(exc),
            }
        finally:
            with contextlib.suppress(Exception):
                store.release_lease(lease.lease_id, lease.generation)
            with contextlib.suppress(Exception):
                self._update_worker_tracking(
                    store,
                    item_id=item.item_id,
                    pid=worker_pid,
                    lease_id=lease.lease_id,
                    remove=True,
                )

    def run(self) -> dict[str, Any]:
        """Execute the 7-step repair pipeline on prioritized QA items."""
        campaign_file = self.campaign_dir / "campaign.json"
        if not campaign_file.is_file():
            raise FileNotFoundError(f"Missing campaign.json in {self.campaign_dir}")
        state = CampaignState.model_validate_json(campaign_file.read_text(encoding="utf-8"))
        validate_campaign_isolation(
            self.campaign_dir,
            repo_root=self.repo_root,
            target_url=state.target_url,
            allow_live_target=False,
        )

        store = open_campaign_store(self.campaign_dir, state, repo_root=self.repo_root)
        store.ensure_budget(
            CycleBudget(
                budget_id="default",
                max_cycles=16,
                max_attempts=max(4, self.max_attempts * 4),
            )
        )
        import_failures_jsonl_into_store(store, state, self.campaign_dir)

        all_items = list_qa_items(store, state.campaign_id)

        # P0 incident check: halt lane immediately and preserve redacted evidence
        open_p0 = [
            it
            for it in all_items
            if it.severity == "P0" and it.state not in {"accepted_qa", "parked"}
        ]
        if open_p0 or state.status == "halted_p0":
            reason = state.p0_halt_reason or "; ".join(
                f"{it.item_id}: {it.summary}" for it in open_p0
            )
            halted_state = state.model_copy(
                update={
                    "status": "halted_p0",
                    "p0_halt_reason": reason,
                    "max_parallel_repairers": self.max_parallel,
                    "max_attempts_per_item": self.max_attempts,
                    "author_model": self.author_model,
                    "auditor_model": self.auditor_model,
                    "cross_model_audit": True,
                    "last_requested_command": "repair",
                    "updated_at": utc_now(),
                }
            )
            save_campaign_state(self.campaign_dir, halted_state, store=store)
            sync_failures_jsonl_from_store(store, halted_state.campaign_id, self.campaign_dir)
            raise RuntimeError(
                f"P0 incident halted repair lane (status=halted_p0): {reason}"
            )

        # Park items that already exhausted max_attempts
        repaired_candidates: list[str] = []
        parked_items: list[str] = []
        worker_results: list[dict[str, Any]] = []

        # Map existing pending candidates by item_id
        pending_by_item: dict[str, CandidateManifest] = {}
        cand_dir = self.campaign_dir / "candidates"
        if cand_dir.is_dir():
            for cf in sorted(cand_dir.glob("*.json")):
                man = CandidateManifest.model_validate_json(cf.read_text(encoding="utf-8"))
                if man.status in {"pending", "candidate_verified"}:
                    pending_by_item.setdefault(man.item_id, man)

        eligible_slots: list[RepairWorkerSlot] = []
        items_by_id = {it.item_id: it for it in all_items}
        for item in all_items:
            if item.state in {"flaky", "blocked", "parked", "accepted_qa", "candidate_verified"}:
                continue
            if item.parent_item_id:
                parent = items_by_id.get(item.parent_item_id)
                if parent is not None and parent.state not in {"accepted_qa", "parked"}:
                    continue
            eff_attempts = max(item.attempts, state.attempts.get(item.item_id, 0))
            if eff_attempts >= self.max_attempts:
                transition_qa_item_state(
                    store,
                    state.campaign_id,
                    item.item_id,
                    "parked",
                    next_diagnostic=(
                        f"Exhausted max_attempts={self.max_attempts} for {item.dedup_key}; "
                        f"last_seen_sha={item.last_seen_sha}, repro={item.repro_command!r}."
                    ),
                )
                parked_items.append(item.item_id)
                continue
            existing_man = pending_by_item.get(item.item_id)
            eff_repro = item.repro_command.strip() or (
                existing_man.rerun_command.strip()
                if existing_man is not None and existing_man.rerun_command
                else ""
            )
            eff_test = item.repro_test_path or (
                existing_man.repro_test_path if existing_man is not None else None
            )
            if not eff_repro and not (eff_test and eff_test.strip()):
                transition_qa_item_state(
                    store,
                    state.campaign_id,
                    item.item_id,
                    "blocked",
                    blocked_reason="needs_repro: missing repro_command and repro_test_path",
                    next_diagnostic="Provide repro_command or repro_test_path before repair.",
                )
                worker_results.append(
                    {
                        "item_id": item.item_id,
                        "outcome": "needs_repro",
                        "state": "blocked",
                    }
                )
                continue
            if item.state == "observed":
                item = transition_qa_item_state(
                    store, state.campaign_id, item.item_id, "reproduced"
                )
            write_area = infer_write_area(item, existing_man, repo_root=self.repo_root)
            eligible_slots.append(
                RepairWorkerSlot(item=item, write_area=write_area, existing_manifest=existing_man)
            )

        base_ref = (
            state.qa_branch
            if _git_branch_exists(self.repo_root, state.qa_branch)
            else state.base_sha
        )
        base_sha = _run_git(self.repo_root, ["rev-parse", base_ref])

        # Schedule batches of up to `self.max_parallel` strictly disjoint write_areas
        remaining = list(eligible_slots)
        while remaining:
            batch: list[RepairWorkerSlot] = [remaining.pop(0)]
            if self.max_parallel > 1:
                for idx, cand_slot in enumerate(remaining):
                    if all(not _areas_overlap(cand_slot.write_area, b.write_area) for b in batch):
                        batch.append(remaining.pop(idx))
                        if len(batch) >= self.max_parallel:
                            break

            batch_results: list[dict[str, Any]] = []
            if len(batch) == 1:
                batch_results.append(
                    self._run_single_slot(batch[0], state=state, store=store, base_sha=base_sha)
                )
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(batch)) as pool:
                    futures = [
                        pool.submit(
                            self._run_single_slot, slot, state=state, store=store, base_sha=base_sha
                        )
                        for slot in batch
                    ]
                    for fut in futures:
                        batch_results.append(fut.result())
            worker_results.extend(batch_results)

            # Step 7: Single Serialized Integrator after each batch
            if self.auto_accept:
                for res in batch_results:
                    cid = res.get("candidate_id")
                    if res.get("outcome") == "verified" and isinstance(cid, str):
                        try:
                            acc = accept_candidate_to_qa(
                                self.campaign_dir,
                                candidate_id=cid,
                                repo_root=self.repo_root,
                                build_frontend=self.build_frontend,
                                skip_browser=self.skip_browser,
                            )
                            repaired_candidates.append(cid)
                            res["accepted"] = acc
                        except Exception as exc:
                            res["accept_error"] = str(exc)

            # Refresh base_sha after integration so serialized overlapping slots rebase cleanly
            if _git_branch_exists(self.repo_root, state.qa_branch):
                base_sha = _run_git(self.repo_root, ["rev-parse", state.qa_branch])

        # Reload latest campaign state & sync attempts/failures
        latest_state = CampaignState.model_validate_json(campaign_file.read_text(encoding="utf-8"))
        merged_attempts = dict(latest_state.attempts)
        for it in list_qa_items(store, latest_state.campaign_id):
            if it.attempts > 0:
                merged_attempts[it.item_id] = max(merged_attempts.get(it.item_id, 0), it.attempts)

        final_state = latest_state.model_copy(
            update={
                "max_parallel_repairers": self.max_parallel,
                "max_attempts_per_item": self.max_attempts,
                "author_model": self.author_model,
                "auditor_model": self.auditor_model,
                "cross_model_audit": True,
                "attempts": merged_attempts,
                "limits": {
                    **latest_state.limits,
                    "max_parallel_repairers": self.max_parallel,
                    "max_attempts_per_item": self.max_attempts,
                },
                "last_requested_command": "repair",
                "updated_at": utc_now(),
            }
        )
        save_campaign_state(self.campaign_dir, final_state, store=store)
        sync_failures_jsonl_from_store(store, final_state.campaign_id, self.campaign_dir)

        return {
            "ok": True,
            "campaign_id": final_state.campaign_id,
            "max_parallel_repairers": self.max_parallel,
            "author_model": self.author_model,
            "auditor_model": self.auditor_model,
            "parked_items": parked_items,
            "worker_results": worker_results,
            "accepted_candidates": repaired_candidates,
        }


__all__ = [
    "ForensicAuditVerdict",
    "QAEvaluationResult",
    "QARepairLoop",
    "RepairWorkerSlot",
    "accept_candidate_to_qa",
    "audit_candidate_forensic",
    "build_qa_product_evaluator",
    "check_cross_model_governance",
    "infer_write_area",
    "reevaluate_qa_item",
    "rollback_candidate_from_qa",
    "validate_campaign_isolation",
]
