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


_C_ESCAPE_MAP: dict[str, int] = {
    "\\": ord("\\"),
    '"': ord('"'),
    "a": 7,
    "b": 8,
    "f": 12,
    "n": 10,
    "r": 13,
    "t": 9,
    "v": 11,
}
_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _consume_quoted_git_token(text: str, start: int = 0) -> tuple[str, int]:
    """Parse a C-quoted git diff path token starting at `start`."""
    if start >= len(text) or text[start] != '"':
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: expected quoted git diff path in {text!r}."
        )
    buf = bytearray()
    idx = start + 1
    while idx < len(text):
        ch = text[idx]
        if ch == '"':
            try:
                return buf.decode("utf-8"), idx + 1
            except UnicodeDecodeError as exc:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: invalid UTF-8 in quoted diff path."
                ) from exc
        if ch == "\\":
            idx += 1
            if idx >= len(text):
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: truncated escape in diff path {text!r}."
                )
            esc = text[idx]
            if esc in _C_ESCAPE_MAP:
                buf.append(_C_ESCAPE_MAP[esc])
                idx += 1
            elif esc in "01234567":
                oct_digits = esc
                idx += 1
                for _ in range(2):
                    if idx < len(text) and text[idx] in "01234567":
                        oct_digits += text[idx]
                        idx += 1
                    else:
                        break
                buf.append(int(oct_digits, 8) & 0xFF)
            else:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: invalid escape \\{esc} in diff path."
                )
        else:
            buf.extend(ch.encode("utf-8"))
            idx += 1
    raise PolicyImmutabilityError(
        f"{POLICY_IMMUTABILITY_VIOLATION}: unterminated quoted diff path in {text!r}."
    )


def _unquote_git_path(token: str) -> str:
    stripped = token.strip()
    if stripped.startswith('"'):
        decoded, end_idx = _consume_quoted_git_token(stripped, 0)
        if stripped[end_idx:].strip():
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: trailing garbage after quoted path {token!r}."
            )
        return decoded
    return stripped


def _parse_diff_git_line(line: str) -> tuple[str, str]:
    rest = line[len("diff --git ") :]
    if not rest.strip():
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable empty diff --git header."
        )

    left_raw: str
    right_raw: str
    if '"' in rest:
        idx = 0
        while idx < len(rest) and rest[idx] == " ":
            idx += 1
        if idx >= len(rest):
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff --git header {line!r}."
            )
        if rest[idx] == '"':
            left_raw, idx = _consume_quoted_git_token(rest, idx)
        else:
            next_sp = rest.find(" ", idx)
            if next_sp == -1:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff --git header {line!r}."
                )
            left_raw = rest[idx:next_sp]
            idx = next_sp
        if idx >= len(rest) or rest[idx] != " ":
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff --git header {line!r}."
            )
        while idx < len(rest) and rest[idx] == " ":
            idx += 1
        if idx >= len(rest):
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff --git header {line!r}."
            )
        if rest[idx] == '"':
            right_raw, end_idx = _consume_quoted_git_token(rest, idx)
            if rest[end_idx:].strip():
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff --git header {line!r}."
                )
        else:
            right_raw = rest[idx:].rstrip()
    else:
        trimmed = rest.strip()
        parts = trimmed.split(" ")
        if len(parts) == 2 and parts[0] and parts[1]:
            left_raw, right_raw = parts[0], parts[1]
        else:
            m = re.match(r"^a/(.+?) b/(.+)$", trimmed)
            if m:
                left_raw, right_raw = f"a/{m.group(1)}", f"b/{m.group(2)}"
            elif len(trimmed) % 2 == 1:
                mid = len(trimmed) // 2
                if trimmed[mid] == " " and trimmed[:mid] == trimmed[mid + 1 :]:
                    left_raw = right_raw = trimmed[:mid]
                else:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff --git header {line!r}."
                    )
            else:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff --git header {line!r}."
                )

    if left_raw.startswith("a/") and right_raw.startswith("b/"):
        left, right = left_raw[2:], right_raw[2:]
    else:
        left = (
            left_raw[2:]
            if left_raw.startswith("a/") and not right_raw.startswith("a/")
            else left_raw
        )
        right = (
            right_raw[2:]
            if right_raw.startswith("b/") and not left_raw.startswith("b/")
            else right_raw
        )

    if not left or not right:
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: empty path in diff --git header {line!r}."
        )
    return left, right


def _parse_minus_plus_header(line: str, header_prefix: str, git_prefix: str) -> str | None:
    rest = line[len(header_prefix) :]
    if rest.startswith('"'):
        raw, end_idx = _consume_quoted_git_token(rest, 0)
        trailing = rest[end_idx:]
        if trailing and not trailing.startswith("\t") and trailing.strip():
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff header {line!r}."
            )
    else:
        raw = rest.split("\t", 1)[0].strip()

    if raw == "/dev/null":
        return None
    if not raw:
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: empty path in diff header {line!r}."
        )
    if raw.startswith(git_prefix):
        raw = raw[len(git_prefix) :]
    if not raw:
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: empty path after prefix in diff header {line!r}."
        )
    return raw


def parse_unified_patch(
    patch_text: str,
) -> tuple[list[str], list[str], list[tuple[str, str]]]:
    """Parse git/unified diff path headers, added lines, and 120000 symlink targets."""
    touched: list[str] = []
    added_lines: list[str] = []
    symlink_added_targets: list[tuple[str, str]] = []

    def _add_touched(path_str: str) -> None:
        if path_str != "/dev/null" and path_str not in touched:
            touched.append(path_str)

    in_hunk = False
    old_rem = 0
    new_rem = 0
    current_is_symlink = False
    current_section_paths: list[str] = []

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
            old_rem = 0
            new_rem = 0
            current_is_symlink = False
            current_section_paths = []
            left, right = _parse_diff_git_line(line)
            _add_touched(left)
            _add_touched(right)
            current_section_paths.extend([left, right])
            continue

        if line.startswith("@@"):
            m = _HUNK_HEADER_RE.match(line)
            if m is None:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff hunk header {line!r}."
                )
            old_rem = int(m.group(2)) if m.group(2) is not None else 1
            new_rem = int(m.group(4)) if m.group(4) is not None else 1
            in_hunk = old_rem > 0 or new_rem > 0
            continue

        if in_hunk:
            if line.startswith("+"):
                added = line[1:]
                added_lines.append(added)
                if current_is_symlink:
                    link_rel = current_section_paths[-1] if current_section_paths else ""
                    symlink_added_targets.append((link_rel, added))
                new_rem -= 1
            elif line.startswith("-"):
                old_rem -= 1
            elif line.startswith(" ") or line == "":
                old_rem -= 1
                new_rem -= 1
            elif line.startswith("\\"):
                pass
            else:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: malformed diff hunk body line {line!r}."
                )
            if old_rem <= 0 and new_rem <= 0:
                in_hunk = False
            continue

        if line.startswith(
            (
                "new file mode 120000",
                "deleted file mode 120000",
                "old mode 120000",
                "new mode 120000",
            )
        ):
            current_is_symlink = True
            continue
        if line.startswith("index ") and line.rstrip().endswith(" 120000"):
            current_is_symlink = True
            continue

        if line.startswith("--- "):
            p = _parse_minus_plus_header(line, "--- ", "a/")
            if p is not None:
                _add_touched(p)
                current_section_paths.append(p)
            continue

        if line.startswith("+++ "):
            p = _parse_minus_plus_header(line, "+++ ", "b/")
            if p is not None:
                _add_touched(p)
                current_section_paths.append(p)
            continue

        matched_meta = False
        for meta_hdr in ("rename from ", "rename to ", "copy from ", "copy to "):
            if line.startswith(meta_hdr):
                raw_meta = line[len(meta_hdr) :].strip()
                if not raw_meta:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: empty path in {meta_hdr.strip()} header."
                    )
                unquoted = _unquote_git_path(raw_meta)
                if not unquoted:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: empty path in {meta_hdr.strip()} header."
                    )
                _add_touched(unquoted)
                current_section_paths.append(unquoted)
                matched_meta = True
                break
        if matched_meta:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])

    if patch_text.strip() and not touched:
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: non-empty patch yielded zero touched paths."
        )

    return touched, added_lines, symlink_added_targets


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
            name_folded = name.casefold()
            if cls._is_explicit_forbidden_basename(item, name) and name_folded not in {
                existing.casefold() for existing in seen_names
            }:
                seen_names.add(name)
                pat = re.compile(
                    rf"(?<![A-Za-z0-9_.-]){re.escape(name)}(?![A-Za-z0-9_.])",
                    re.IGNORECASE,
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
        norm_folded = normalized.casefold()
        for prefix in self._immutable_prefixes:
            raw_prefix = prefix.replace("\\", "/")
            clean_prefix = posixpath.normpath(raw_prefix)
            if clean_prefix in ("", "."):
                continue
            prefix_folded = clean_prefix.casefold()
            if norm_folded == prefix_folded or norm_folded.startswith(f"{prefix_folded}/"):
                return True
        filename = Path(normalized).name
        if _IMMUTABLE_NAME_RE.search(filename) or _IMMUTABLE_NAME_RE.search(filename.casefold()):
            return True
        return bool(_IMMUTABLE_NAME_RE.search(normalized) or _IMMUTABLE_NAME_RE.search(norm_folded))

    def _is_immutable_ancestor(self, rel_path: str) -> bool:
        norm = posixpath.normpath(rel_path.strip().replace("\\", "/"))
        if norm in ("", ".") or norm.startswith("/") or ".." in norm.split("/"):
            return True
        norm_folded = norm.casefold()
        for prefix in self._immutable_prefixes:
            clean_prefix = posixpath.normpath(prefix.replace("\\", "/"))
            if clean_prefix in ("", "."):
                continue
            prefix_folded = clean_prefix.casefold()
            if prefix_folded == norm_folded or prefix_folded.startswith(f"{norm_folded}/"):
                return True
        return False

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
        resolved_folded = str(resolved_target).casefold()
        for forb_res in forbidden_resolved:
            forb_folded = str(forb_res).casefold()
            if resolved_folded == forb_folded:
                return str(resolved_target)
            with contextlib.suppress(OSError, ValueError):
                if resolved_target.is_relative_to(forb_res):
                    return str(forb_res)
            forb_prefix = forb_folded.rstrip("/")
            if forb_prefix and resolved_folded.startswith(f"{forb_prefix}/"):
                return str(forb_res)
        forbidden_names_folded = {n.casefold() for n in forbidden_names}
        if (
            resolved_target.name in forbidden_names
            or resolved_target.name.casefold() in forbidden_names_folded
        ):
            return resolved_target.name
        if raw_target:
            raw_name = Path(raw_target).name
            if raw_name in forbidden_names or raw_name.casefold() in forbidden_names_folded:
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
        try:
            resolved_repo = repo_path.resolve()
        except (OSError, RuntimeError) as exc:
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unresolvable repository path "
                f"{repo_path!r} ({exc}).",
                offending_paths=tuple(touched_paths),
            ) from exc
        exact_tokens, basename_patterns, forbidden_resolved, forbidden_names = (
            self._build_forbidden_matchers([*self._raw_forbidden_paths, *extra_forbidden_paths])
        )

        # 1. Inspect touched paths, all parent directory components, and full resolved targets
        for rel_p in touched_paths:
            norm_p = posixpath.normpath(rel_p.strip().replace("\\", "/"))
            cur = resolved_repo
            for part in Path(norm_p).parts:
                cur = cur / part
                try:
                    is_sym = cur.is_symlink()
                except OSError as exc:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: unresolvable symlink "
                        f"{rel_p!r} ({exc}).",
                        offending_paths=(rel_p,),
                    ) from exc
                if is_sym:
                    raw_target: str | None = None
                    with contextlib.suppress(OSError):
                        raw_target = os.readlink(cur)
                    try:
                        resolved_target = cur.resolve()
                    except (OSError, RuntimeError) as exc:
                        raise PolicyImmutabilityError(
                            f"{POLICY_IMMUTABILITY_VIOLATION}: unresolvable symlink "
                            f"{rel_p!r} ({exc}).",
                            offending_paths=(rel_p,),
                        ) from exc
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
                    if self.is_immutable_path(target_rel) or self._is_immutable_ancestor(
                        target_rel
                    ):
                        raise PolicyImmutabilityError(
                            f"{POLICY_IMMUTABILITY_VIOLATION}: symlink {rel_p!r} resolves "
                            f"to immutable path or ancestor {target_rel!r}.",
                            offending_paths=(rel_p,),
                        )
                elif not cur.exists():
                    break

            try:
                full_resolved = (resolved_repo / norm_p).resolve()
            except (OSError, RuntimeError) as exc:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: unresolvable symlink {rel_p!r} ({exc}).",
                    offending_paths=(rel_p,),
                ) from exc
            full_forb_hit = self._matches_forbidden_target(
                full_resolved, None, forbidden_resolved, forbidden_names
            )
            if full_forb_hit is not None:
                raise IsolationBoundaryError(
                    f"{ISOLATION_BOUNDARY_VIOLATION}: blocked symlink {rel_p!r} "
                    f"pointing to forbidden path ({full_forb_hit})."
                )
            if not full_resolved.is_relative_to(resolved_repo):
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: symlink {rel_p!r} escapes "
                    f"repository to {full_resolved}.",
                    offending_paths=(rel_p,),
                )
            full_rel = full_resolved.relative_to(resolved_repo).as_posix()
            if self.is_immutable_path(full_rel):
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: path {rel_p!r} resolves "
                    f"to immutable path {full_rel!r}.",
                    offending_paths=(rel_p,),
                )

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
                    is_sym = False
                    with contextlib.suppress(OSError):
                        is_sym = entry.is_symlink()
                    if not is_sym:
                        continue
                    raw_target = None
                    with contextlib.suppress(OSError):
                        raw_target = os.readlink(entry)
                    with contextlib.suppress(OSError, RuntimeError):
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
                            if entry.name and entry.name.casefold() not in {
                                n.casefold() for n in seen_names
                            }:
                                seen_names.add(entry.name)
                                extra_patterns.append(
                                    (
                                        entry.name,
                                        re.compile(
                                            rf"(?<![A-Za-z0-9_.-]){re.escape(entry.name)}"
                                            r"(?![A-Za-z0-9_.])",
                                            re.IGNORECASE,
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
        resolved_repo: Path | None = None
        if repo_path is not None:
            try:
                resolved_repo = repo_path.resolve()
            except (OSError, RuntimeError) as exc:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: unresolvable repository path "
                    f"{repo_path!r} ({exc}).",
                    offending_paths=tuple(touched_paths),
                ) from exc
        forb_res = forbidden_resolved or set()
        forb_names = forbidden_names or set()

        added_symlinks_exact: dict[str, str] = {}
        added_symlinks_folded: dict[str, str] = {}
        for link_rel, target_str in symlink_added_targets:
            norm_link = posixpath.normpath(link_rel.strip().replace("\\", "/"))
            if (
                not norm_link
                or norm_link == "."
                or norm_link.startswith("/")
                or ".." in norm_link.split("/")
            ):
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: invalid symlink path {link_rel!r}.",
                    offending_paths=tuple(touched_paths) or (link_rel,),
                )
            cleaned_target = target_str.strip().replace("\\", "/")
            if not cleaned_target:
                continue
            if cleaned_target.startswith("/") or ".." in cleaned_target.split("/"):
                with contextlib.suppress(OSError, RuntimeError):
                    t_res = (
                        (resolved_repo / Path(norm_link).parent / cleaned_target).resolve()
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

            link_parent_rel = posixpath.dirname(norm_link)
            lexical_target_rel = posixpath.normpath(
                posixpath.join(link_parent_rel, cleaned_target)
                if link_parent_rel
                else cleaned_target
            )
            if lexical_target_rel.startswith("/") or ".." in lexical_target_rel.split("/"):
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: patch creates escaping symlink "
                    f"{link_rel!r} -> {cleaned_target!r}.",
                    offending_paths=tuple(touched_paths) or (link_rel,),
                )
            forb_lex_hit = self._matches_forbidden_target(
                Path(lexical_target_rel), cleaned_target, forb_res, forb_names
            )
            if forb_lex_hit is not None:
                raise IsolationBoundaryError(
                    f"{ISOLATION_BOUNDARY_VIOLATION}: blocked symlink patch "
                    f"{link_rel!r} pointing to forbidden path ({forb_lex_hit})."
                )
            if self.is_immutable_path(lexical_target_rel) or self._is_immutable_ancestor(
                lexical_target_rel
            ):
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: patch symlink {link_rel!r} "
                    f"targets immutable path or ancestor {lexical_target_rel!r}.",
                    offending_paths=tuple(touched_paths) or (link_rel,),
                )

            if resolved_repo is not None:
                link_parent = (resolved_repo / norm_link).parent
                try:
                    resolved_target = (link_parent / cleaned_target).resolve()
                except (OSError, RuntimeError) as exc:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: unresolvable symlink patch "
                        f"{link_rel!r} ({exc}).",
                        offending_paths=tuple(touched_paths) or (link_rel,),
                    ) from exc
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
                if self.is_immutable_path(target_rel) or self._is_immutable_ancestor(target_rel):
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: patch symlink {link_rel!r} "
                        f"targets immutable path or ancestor {target_rel!r}.",
                        offending_paths=tuple(touched_paths) or (link_rel,),
                    )

            added_symlinks_exact[norm_link] = lexical_target_rel
            added_symlinks_folded[norm_link.casefold()] = lexical_target_rel

        if added_symlinks_exact and touched_paths:
            resolved_touched: list[str] = []
            max_hops = max(16, len(added_symlinks_exact) * 2 + 4)
            for orig_path in touched_paths:
                cur_path = posixpath.normpath(orig_path.strip().replace("\\", "/"))
                seen_paths: set[str] = {cur_path.casefold()}
                completed = False
                for _ in range(max_hops):
                    parts = cur_path.split("/")
                    replaced = False
                    for idx in range(1, len(parts) + 1):
                        prefix = "/".join(parts[:idx])
                        target_base = added_symlinks_exact.get(prefix)
                        if target_base is None:
                            target_base = added_symlinks_folded.get(prefix.casefold())
                        if target_base is not None:
                            remainder = "/".join(parts[idx:])
                            next_path = posixpath.normpath(
                                f"{target_base}/{remainder}" if remainder else target_base
                            )
                            next_folded = next_path.casefold()
                            if next_folded in seen_paths:
                                raise PolicyImmutabilityError(
                                    f"{POLICY_IMMUTABILITY_VIOLATION}: circular symlink patch "
                                    f"involving {orig_path!r}.",
                                    offending_paths=tuple(touched_paths),
                                )
                            seen_paths.add(next_folded)
                            cur_path = next_path
                            replaced = True
                            break
                    if not replaced:
                        completed = True
                        break
                if not completed:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: excessive symlink indirection "
                        f"in patch for {orig_path!r}.",
                        offending_paths=tuple(touched_paths),
                    )
                resolved_touched.append(cur_path)

            self.check_candidate_paths(resolved_touched)
            for res_p in resolved_touched:
                if self._is_immutable_ancestor(res_p):
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: patch path {res_p!r} "
                        "resolves to immutable ancestor directory.",
                        offending_paths=tuple(touched_paths),
                    )
                forb_res_hit = self._matches_forbidden_target(
                    Path(res_p), res_p, forb_res, forb_names
                )
                if forb_res_hit is not None:
                    raise IsolationBoundaryError(
                        f"{ISOLATION_BOUNDARY_VIOLATION}: blocked patch path {res_p!r} "
                        f"referencing forbidden path ({forb_res_hit})."
                    )
            if resolved_repo is not None:
                self.check_repo_symlinks(resolved_repo, resolved_touched)

        search_bases: list[Path] = []
        if resolved_repo is not None:
            search_bases.append(resolved_repo)
        for base in extra_search_dirs:
            with contextlib.suppress(OSError, RuntimeError):
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
            added_folded = added.casefold()
            for tok in exact_tokens:
                if tok in added or tok.casefold() in added_folded:
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
                        with contextlib.suppress(OSError, RuntimeError):
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

        parsed_touched, added_lines, symlink_added_targets = parse_unified_patch(
            patch_proc.stdout
        )
        touched_paths = list(dict.fromkeys([*changed_paths, *parsed_touched]))
        self.check_candidate_paths(touched_paths)
        self.check_added_lines(
            added_lines,
            touched_paths=touched_paths,
            repo_path=repo_path,
            exact_tokens=exact_tokens,
            basename_patterns=basename_patterns,
            forbidden_resolved=forbidden_resolved,
            forbidden_names=forbidden_names,
            symlink_added_targets=symlink_added_targets,
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
