"""Policy-immutability and runtime-isolation guards for the M7 software factory (F16)."""

from __future__ import annotations

import contextlib
import os
import posixpath
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


_SKIP_WALK_DIRS: frozenset[str] = frozenset(
    {".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules"}
)


def _extract_path_candidates_from_line(line: str) -> list[str]:
    """Extract quoted strings and path-like tokens from an added source line."""
    candidates: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"""(["'])([^"'\n\x00]{1,512})\1""", line):
        val = m.group(2).strip()
        if val and val not in seen:
            seen.add(val)
            candidates.append(val)
    for m in re.finditer(r"""[A-Za-z0-9_./~-]{2,512}""", line):
        val = m.group(0).strip()
        if ("/" in val or "." in val) and val not in seen:
            seen.add(val)
            candidates.append(val)
    return candidates


class PolicyGuard:
    """Enforces unconditional immutability of acceptance criteria, policy, and safety guards."""

    def __init__(
        self,
        *,
        extra_immutable_prefixes: Sequence[str] = (),
        forbidden_paths: Sequence[Path | str] = (),
    ) -> None:
        self._immutable_prefixes = (*IMMUTABLE_PATH_PREFIXES, *extra_immutable_prefixes)
        self._raw_forbidden_paths: tuple[str, ...] = self._collect_raw_forbidden_paths(
            forbidden_paths
        )
        self._forbidden_paths: tuple[str, ...] = self._normalize_forbidden_paths(forbidden_paths)

    @staticmethod
    def _collect_raw_forbidden_paths(forbidden_paths: Sequence[Path | str]) -> tuple[str, ...]:
        raw_items: list[str] = [str(p).strip() for p in forbidden_paths if str(p).strip()]
        env_raw = os.environ.get("GROKBOT_FORBIDDEN_PATHS", "").strip()
        if env_raw:
            raw_items.extend(part.strip() for part in env_raw.split(",") if part.strip())
        deduped: list[str] = []
        seen: set[str] = set()
        for item in raw_items:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return tuple(deduped)

    @staticmethod
    def _is_explicit_forbidden_basename(raw_item: str, name: str) -> bool:
        if not name or name in {".", ".."}:
            return False
        if len(name) >= 12 or name.startswith("."):
            return True
        is_dir = False
        with contextlib.suppress(OSError):
            is_dir = Path(raw_item).is_dir()
        if is_dir:
            return False
        return "." in name or len(name) >= 4 or ("/" not in raw_item and "\\" not in raw_item)

    @classmethod
    def _normalize_forbidden_paths(cls, forbidden_paths: Sequence[Path | str]) -> tuple[str, ...]:
        raw_items = cls._collect_raw_forbidden_paths(forbidden_paths)
        tokens: list[str] = []
        seen: set[str] = set()
        for item in raw_items:
            candidates = [item]
            with contextlib.suppress(OSError):
                candidates.append(str(Path(item).resolve()))
            name = Path(item).name
            if cls._is_explicit_forbidden_basename(item, name):
                candidates.append(name)
            for cand in candidates:
                if cand and cand not in seen:
                    seen.add(cand)
                    tokens.append(cand)
        return tuple(tokens)

    @classmethod
    def _build_forbidden_matchers(
        cls,
        raw_forbidden_paths: Sequence[Path | str],
    ) -> tuple[
        tuple[str, ...],
        tuple[tuple[str, re.Pattern[str]], ...],
        set[Path],
        set[str],
    ]:
        raw_items = cls._collect_raw_forbidden_paths(raw_forbidden_paths)
        exact_tokens: list[str] = []
        seen_exact: set[str] = set()
        basename_patterns: list[tuple[str, re.Pattern[str]]] = []
        seen_names: set[str] = set()
        resolved_set: set[Path] = set()

        for item in raw_items:
            for cand in (item, os.path.abspath(item)):
                if ("/" in cand or "\\" in cand or len(cand) >= 12) and cand not in seen_exact:
                    seen_exact.add(cand)
                    exact_tokens.append(cand)
            with contextlib.suppress(OSError):
                res = Path(item).resolve()
                resolved_set.add(res)
                res_str = str(res)
                if ("/" in res_str or "\\" in res_str or len(res_str) >= 12) and (
                    res_str not in seen_exact
                ):
                    seen_exact.add(res_str)
                    exact_tokens.append(res_str)

            name = Path(item).name
            if cls._is_explicit_forbidden_basename(item, name) and name not in seen_names:
                seen_names.add(name)
                pat = re.compile(
                    rf"(?<![A-Za-z0-9_.-]){re.escape(name)}(?![A-Za-z0-9_.])"
                )
                basename_patterns.append((name, pat))

        return tuple(exact_tokens), tuple(basename_patterns), resolved_set, seen_names

    def is_immutable_path(self, rel_path: str) -> bool:
        raw = rel_path.strip().replace("\\", "/")
        if not raw or "\x00" in raw:
            return True
        if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw):
            return True
        if ".." in raw.split("/"):
            return True
        normalized = posixpath.normpath(raw)
        if normalized in ("", ".") or normalized.startswith("/") or ".." in normalized.split("/"):
            return True
        for prefix in self._immutable_prefixes:
            raw_prefix = prefix.replace("\\", "/")
            clean_prefix = posixpath.normpath(raw_prefix)
            if clean_prefix in ("", "."):
                continue
            if normalized == clean_prefix or normalized.startswith(f"{clean_prefix}/"):
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

    def _matches_forbidden_target(
        self,
        resolved_target: Path,
        raw_target: str | None,
        forbidden_resolved: set[Path],
        forbidden_names: set[str],
    ) -> str | None:
        if resolved_target in forbidden_resolved:
            return str(resolved_target)
        for forb_res in forbidden_resolved:
            with contextlib.suppress(OSError, ValueError):
                if resolved_target.is_relative_to(forb_res):
                    return str(forb_res)
        if resolved_target.name in forbidden_names:
            return resolved_target.name
        if raw_target:
            raw_name = Path(raw_target).name
            if raw_name in forbidden_names:
                return raw_name
        return None

    def check_repo_symlinks(
        self,
        repo_path: Path,
        touched_paths: Sequence[str],
        *,
        extra_forbidden_paths: Sequence[Path | str] = (),
    ) -> tuple[
        tuple[str, ...],
        tuple[tuple[str, re.Pattern[str]], ...],
        set[Path],
        set[str],
    ]:
        """Inspect symlinks in repo_path for touched paths and forbidden targets."""
        resolved_repo = repo_path.resolve()
        exact_tokens, basename_patterns, forbidden_resolved, forbidden_names = (
            self._build_forbidden_matchers([*self._raw_forbidden_paths, *extra_forbidden_paths])
        )

        # 1. Inspect touched paths and all parent directory components in repo_path
        for rel_p in touched_paths:
            norm_p = posixpath.normpath(rel_p.strip().replace("\\", "/"))
            cur = resolved_repo
            for part in Path(norm_p).parts:
                cur = cur / part
                if cur.is_symlink():
                    raw_target: str | None = None
                    with contextlib.suppress(OSError):
                        raw_target = os.readlink(cur)
                    resolved_target = cur.resolve()
                    forb_hit = self._matches_forbidden_target(
                        resolved_target, raw_target, forbidden_resolved, forbidden_names
                    )
                    if forb_hit is not None:
                        raise IsolationBoundaryError(
                            f"{ISOLATION_BOUNDARY_VIOLATION}: blocked symlink {rel_p!r} "
                            f"pointing to forbidden path ({forb_hit})."
                        )
                    if not resolved_target.is_relative_to(resolved_repo):
                        raise PolicyImmutabilityError(
                            f"{POLICY_IMMUTABILITY_VIOLATION}: symlink {rel_p!r} escapes "
                            f"repository to {resolved_target}.",
                            offending_paths=(rel_p,),
                        )
                    target_rel = resolved_target.relative_to(resolved_repo).as_posix()
                    if self.is_immutable_path(target_rel):
                        raise PolicyImmutabilityError(
                            f"{POLICY_IMMUTABILITY_VIOLATION}: symlink {rel_p!r} resolves "
                            f"to immutable path {target_rel!r}.",
                            offending_paths=(rel_p,),
                        )
                elif not cur.exists():
                    break

        # 2. Discover symlinks inside repo_path pointing to forbidden targets
        extra_exact: list[str] = list(exact_tokens)
        extra_patterns: list[tuple[str, re.Pattern[str]]] = list(basename_patterns)
        seen_exact = set(exact_tokens)
        seen_names = set(forbidden_names)
        if forbidden_resolved or forbidden_names:
            for root_str, dirnames, filenames in os.walk(resolved_repo, followlinks=False):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_WALK_DIRS]
                root_path = Path(root_str)
                for entry_name in (*dirnames, *filenames):
                    entry = root_path / entry_name
                    if not entry.is_symlink():
                        continue
                    raw_target = None
                    with contextlib.suppress(OSError):
                        raw_target = os.readlink(entry)
                    with contextlib.suppress(OSError):
                        resolved_target = entry.resolve()
                        if (
                            self._matches_forbidden_target(
                                resolved_target,
                                raw_target,
                                forbidden_resolved,
                                forbidden_names,
                            )
                            is not None
                        ):
                            rel_str = entry.relative_to(resolved_repo).as_posix()
                            for tok in (str(entry), rel_str):
                                if tok not in seen_exact:
                                    seen_exact.add(tok)
                                    extra_exact.append(tok)
                            if entry.name and entry.name not in seen_names:
                                seen_names.add(entry.name)
                                extra_patterns.append(
                                    (
                                        entry.name,
                                        re.compile(
                                            rf"(?<![A-Za-z0-9_.-]){re.escape(entry.name)}"
                                            r"(?![A-Za-z0-9_.])"
                                        ),
                                    )
                                )

        return tuple(extra_exact), tuple(extra_patterns), forbidden_resolved, forbidden_names

    def check_added_lines(
        self,
        added_lines: Sequence[str],
        *,
        touched_paths: Sequence[str] = (),
        repo_path: Path | None = None,
        extra_search_dirs: Sequence[Path] = (),
        exact_tokens: Sequence[str] = (),
        basename_patterns: Sequence[tuple[str, re.Pattern[str]]] = (),
        forbidden_resolved: set[Path] | None = None,
        forbidden_names: set[str] | None = None,
        symlink_added_targets: Sequence[tuple[str, str]] = (),
    ) -> None:
        """Inspect added diff lines for policy bypasses, isolation breaches, or symlinks."""
        resolved_repo = repo_path.resolve() if repo_path is not None else None
        forb_res = forbidden_resolved or set()
        forb_names = forbidden_names or set()

        for link_rel, target_str in symlink_added_targets:
            cleaned_target = target_str.strip()
            if not cleaned_target:
                continue
            if cleaned_target.startswith("/") or ".." in cleaned_target.replace("\\", "/").split(
                "/"
            ):
                with contextlib.suppress(OSError):
                    t_res = (
                        (resolved_repo / Path(link_rel).parent / cleaned_target).resolve()
                        if resolved_repo is not None and not cleaned_target.startswith("/")
                        else Path(cleaned_target).resolve()
                    )
                    forb_hit = self._matches_forbidden_target(
                        t_res, cleaned_target, forb_res, forb_names
                    )
                    if forb_hit is not None:
                        raise IsolationBoundaryError(
                            f"{ISOLATION_BOUNDARY_VIOLATION}: blocked symlink patch "
                            f"{link_rel!r} pointing to forbidden path ({forb_hit})."
                        )
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: patch creates escaping symlink "
                    f"{link_rel!r} -> {cleaned_target!r}.",
                    offending_paths=tuple(touched_paths) or (link_rel,),
                )
            if resolved_repo is not None:
                link_parent = (resolved_repo / link_rel).parent
                resolved_target = (link_parent / cleaned_target).resolve()
                forb_hit = self._matches_forbidden_target(
                    resolved_target, cleaned_target, forb_res, forb_names
                )
                if forb_hit is not None:
                    raise IsolationBoundaryError(
                        f"{ISOLATION_BOUNDARY_VIOLATION}: blocked symlink patch "
                        f"{link_rel!r} pointing to forbidden path ({forb_hit})."
                    )
                if not resolved_target.is_relative_to(resolved_repo):
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: patch symlink {link_rel!r} "
                        f"escapes repository.",
                        offending_paths=tuple(touched_paths) or (link_rel,),
                    )
                target_rel = resolved_target.relative_to(resolved_repo).as_posix()
                if self.is_immutable_path(target_rel):
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: patch symlink {link_rel!r} "
                        f"targets immutable path {target_rel!r}.",
                        offending_paths=tuple(touched_paths) or (link_rel,),
                    )

        search_bases: list[Path] = []
        if resolved_repo is not None:
            search_bases.append(resolved_repo)
        for base in extra_search_dirs:
            with contextlib.suppress(OSError):
                search_bases.append(base.resolve())

        for added in added_lines:
            for pat in _POLICY_BYPASS_PATTERNS:
                if pat.search(added):
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: candidate diff attempted to "
                        f"weaken or disable verification/policy guard ({pat.pattern}).",
                        offending_paths=tuple(touched_paths),
                    )
            for pat in _ISOLATION_BREACH_PATTERNS:
                if pat.search(added):
                    raise IsolationBoundaryError(
                        f"{ISOLATION_BOUNDARY_VIOLATION}: blocked candidate diff referencing "
                        f"forbidden runtime DB or credential boundary ({pat.pattern})."
                    )
            for tok in exact_tokens:
                if tok in added:
                    raise IsolationBoundaryError(
                        f"{ISOLATION_BOUNDARY_VIOLATION}: blocked candidate diff referencing "
                        f"forbidden runtime DB or credential path ({tok})."
                    )
            for name, pat in basename_patterns:
                if pat.search(added):
                    raise IsolationBoundaryError(
                        f"{ISOLATION_BOUNDARY_VIOLATION}: blocked candidate diff referencing "
                        f"forbidden filename ({name})."
                    )
            if search_bases and (forb_res or forb_names):
                for cand_tok in _extract_path_candidates_from_line(added):
                    cand_paths = [Path(cand_tok)] if cand_tok.startswith("/") else [
                        base / cand_tok for base in search_bases
                    ]
                    for cand_path in cand_paths:
                        is_sym = False
                        with contextlib.suppress(OSError):
                            is_sym = cand_path.is_symlink()
                        if not is_sym:
                            continue
                        raw_target = None
                        with contextlib.suppress(OSError):
                            raw_target = os.readlink(cand_path)
                        with contextlib.suppress(OSError):
                            res_target = cand_path.resolve()
                            forb_hit = self._matches_forbidden_target(
                                res_target, raw_target, forb_res, forb_names
                            )
                            if forb_hit is not None:
                                raise IsolationBoundaryError(
                                    f"{ISOLATION_BOUNDARY_VIOLATION}: blocked candidate diff "
                                    f"referencing symlink {cand_tok!r} -> {forb_hit}."
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
        exact_tokens, basename_patterns, forbidden_resolved, forbidden_names = (
            self.check_repo_symlinks(
                repo_path, changed_paths, extra_forbidden_paths=extra_forbidden_paths
            )
        )

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

        added_lines = [
            line[1:]
            for line in patch_proc.stdout.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        self.check_added_lines(
            added_lines,
            touched_paths=changed_paths,
            repo_path=repo_path,
            exact_tokens=exact_tokens,
            basename_patterns=basename_patterns,
            forbidden_resolved=forbidden_resolved,
            forbidden_names=forbidden_names,
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
