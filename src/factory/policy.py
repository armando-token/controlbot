"""Policy-immutability and runtime-isolation guards for the M7 software factory (F16)."""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path

from src.factory.errors import IsolationBoundaryError, PolicyImmutabilityError

POLICY_IMMUTABILITY_VIOLATION = "POLICY_IMMUTABILITY_VIOLATION"
ISOLATION_BOUNDARY_VIOLATION = "ISOLATION_BOUNDARY_VIOLATION"

IMMUTABLE_PATH_PREFIXES: tuple[str, ...] = (
    "tests/acceptance/",
    "tests/e2e/",
    "src/contracts/",
    "src/factory/policy.py",
    "src/factory/errors.py",
    "src/engine/tool_registry.py",
    "src/engine/budget.py",
    "src/engine/loop_detector.py",
    "src/engine/coordinator.py",
    "MEGAPLAN_IMPLEMENTACION_GROKBOT_LINUX_TEAMWORK.md",
)

_IMMUTABLE_NAME_RE = re.compile(r"(policy|guard|oracle|permission)", re.IGNORECASE)
_POLICY_BYPASS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"PolicyGuard\s*=.*None"),
    re.compile(r"verify_observation\s*=\s*lambda"),
    re.compile(r"detect_ambiguity\s*=\s*lambda"),
    re.compile(r"detect_contradictions\s*=\s*lambda"),
    re.compile(r"POLICY_IMMUTABILITY_VIOLATION.*disable", re.IGNORECASE),
)
_ISOLATION_BREACH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"scada-pass"),
    re.compile(r"maint-pass"),
    re.compile(r"MappingCredentialProvider"),
    re.compile(r"\.grokbot_profiles"),
    re.compile(r"GROKBOT_DB_PATH"),
)


class PolicyGuard:
    """Enforces unconditional immutability of acceptance criteria, policy, and safety guards."""

    def __init__(
        self,
        *,
        extra_immutable_prefixes: Sequence[str] = (),
        forbidden_paths: Sequence[Path | str] = (),
    ) -> None:
        self._immutable_prefixes = (*IMMUTABLE_PATH_PREFIXES, *extra_immutable_prefixes)
        self._forbidden_paths: tuple[str, ...] = self._normalize_forbidden_paths(forbidden_paths)

    @staticmethod
    def _normalize_forbidden_paths(forbidden_paths: Sequence[Path | str]) -> tuple[str, ...]:
        raw_items: list[str] = [str(p).strip() for p in forbidden_paths if str(p).strip()]
        env_raw = os.environ.get("GROKBOT_FORBIDDEN_PATHS", "").strip()
        if env_raw:
            raw_items.extend(part.strip() for part in env_raw.split(",") if part.strip())
        tokens: list[str] = []
        seen: set[str] = set()
        for item in raw_items:
            candidates = [item]
            with contextlib.suppress(OSError):
                candidates.append(str(Path(item).resolve()))
            name = Path(item).name
            if len(name) >= 12:
                candidates.append(name)
            for cand in candidates:
                if cand and cand not in seen:
                    seen.add(cand)
                    tokens.append(cand)
        return tuple(tokens)

    def is_immutable_path(self, rel_path: str) -> bool:
        normalized = rel_path.replace("\\", "/").lstrip("./")
        for prefix in self._immutable_prefixes:
            clean_prefix = prefix.replace("\\", "/").lstrip("./")
            if clean_prefix.endswith("/"):
                if normalized.startswith(clean_prefix):
                    return True
            elif normalized == clean_prefix or normalized.startswith(f"{clean_prefix}/"):
                return True
        filename = Path(normalized).name
        if _IMMUTABLE_NAME_RE.search(filename):
            return True
        return bool(_IMMUTABLE_NAME_RE.search(normalized))

    def check_candidate_paths(self, paths: Sequence[str]) -> None:
        offending = tuple(sorted({p for p in paths if self.is_immutable_path(p)}))
        if offending:
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: candidate patch attempted to modify "
                "immutable policy, guardrail, contract, or acceptance files.",
                offending_paths=offending,
            )

    def inspect_git_diff(
        self,
        repo_path: Path,
        base_ref: str,
        candidate_ref: str,
        *,
        extra_forbidden_paths: Sequence[Path | str] = (),
    ) -> None:
        """Inspect git diff between base_ref and candidate_ref; fail closed on any violation."""
        forbidden_tokens = self._forbidden_paths + self._normalize_forbidden_paths(
            extra_forbidden_paths
        )
        names_proc = subprocess.run(
            ["git", "-C", str(repo_path), "diff", "--name-only", f"{base_ref}..{candidate_ref}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if names_proc.returncode != 0:
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unable to inspect git diff "
                f"({names_proc.stderr.strip()})."
            )
        changed_paths = [line.strip() for line in names_proc.stdout.splitlines() if line.strip()]
        self.check_candidate_paths(changed_paths)

        patch_proc = subprocess.run(
            ["git", "-C", str(repo_path), "diff", "-U0", f"{base_ref}..{candidate_ref}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if patch_proc.returncode != 0:
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unable to read patch diff "
                f"({patch_proc.stderr.strip()})."
            )

        for line in patch_proc.stdout.splitlines():
            if not line.startswith("+") or line.startswith("+++"):
                continue
            added = line[1:]
            for pat in _POLICY_BYPASS_PATTERNS:
                if pat.search(added):
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: candidate diff attempted to "
                        f"weaken or disable verification/policy guard ({pat.pattern}).",
                        offending_paths=tuple(changed_paths),
                    )
            for pat in _ISOLATION_BREACH_PATTERNS:
                if pat.search(added):
                    raise IsolationBoundaryError(
                        f"{ISOLATION_BOUNDARY_VIOLATION}: blocked candidate diff referencing "
                        f"forbidden runtime DB or credential boundary ({pat.pattern})."
                    )
            for forbidden in forbidden_tokens:
                if forbidden in added:
                    raise IsolationBoundaryError(
                        f"{ISOLATION_BOUNDARY_VIOLATION}: blocked candidate diff referencing "
                        f"forbidden runtime DB or credential path ({forbidden})."
                    )


class IsolationGuard:
    """Verifies factory DB, credentials, and lab git workspace remain strictly isolated."""

    @staticmethod
    def validate_paths(
        factory_db_path: Path,
        repo_path: Path,
        *,
        forbidden_db_paths: Sequence[Path | str] = (),
        forbidden_credential_paths: Sequence[Path | str] = (),
    ) -> None:
        resolved_db = factory_db_path.resolve()
        resolved_repo = repo_path.resolve()

        forbidden_dbs = {Path(p).resolve() for p in forbidden_db_paths}
        env_db = os.environ.get("GROKBOT_DB_PATH", "").strip()
        if env_db:
            forbidden_dbs.add(Path(env_db).resolve())

        if resolved_db in forbidden_dbs:
            raise IsolationBoundaryError(
                f"{ISOLATION_BOUNDARY_VIOLATION}: blocked factory DB {resolved_db} "
                "colliding with industrial runtime DB."
            )

        for cred_raw in forbidden_credential_paths:
            cred = Path(cred_raw).resolve()
            if (
                resolved_db == cred
                or resolved_db.is_relative_to(cred)
                or resolved_repo == cred
                or resolved_repo.is_relative_to(cred)
            ):
                raise IsolationBoundaryError(
                    f"{ISOLATION_BOUNDARY_VIOLATION}: blocked factory access to forbidden "
                    f"credential/profile path {cred}."
                )

        if not resolved_repo.exists():
            raise IsolationBoundaryError(
                f"{ISOLATION_BOUNDARY_VIOLATION}: blocked missing factory git repo {resolved_repo}."
            )
        git_check = subprocess.run(
            ["git", "-C", str(resolved_repo), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=False,
        )
        if git_check.returncode != 0 or git_check.stdout.strip() != "true":
            raise IsolationBoundaryError(
                f"{ISOLATION_BOUNDARY_VIOLATION}: blocked non-git workspace {resolved_repo}."
            )
