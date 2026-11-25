"""Policy-immutability and runtime-isolation guards for the M7 software factory (F16)."""

from __future__ import annotations

import contextlib
import os
import posixpath
import re
import stat
import subprocess
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
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


def _norm_fold(value: str) -> str:
    """Normalize Unicode (NFC + casefold) for case/normalization-insensitive matching."""
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", value).casefold())


def _p1_candidates(path_str: str) -> tuple[str, ...]:
    """Return raw, slash-normalized, and -p1-stripped path candidates (`git apply`/`patch`)."""
    cleaned = path_str.strip().replace("\\", "/")
    if not cleaned:
        return (path_str,)
    norm = posixpath.normpath(cleaned)
    candidates: list[str] = [path_str]
    for cand in (cleaned, norm):
        if cand not in candidates:
            candidates.append(cand)
        if "/" in cand:
            stripped = cand.split("/", 1)[1]
            if stripped and stripped not in candidates:
                candidates.append(stripped)
    return tuple(candidates)


@dataclass(frozen=True)
class ParsedPatch:
    """Structured extraction from a unified/git diff patch."""

    touched_paths: list[str]
    added_lines: list[str]
    symlink_added_targets: list[tuple[str, str]]
    renamed_pairs: list[tuple[str, str]]


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


def _parse_diff_git_line_details(line: str) -> tuple[str, str, bool, str | None]:
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
            else:
                m_custom = re.match(r"^([^/\s]+/)(.+?) ([^/\s]+/)\2$", trimmed)
                if m_custom:
                    left_raw = f"{m_custom.group(1)}{m_custom.group(2)}"
                    right_raw = f"{m_custom.group(3)}{m_custom.group(2)}"
                elif len(trimmed) % 2 == 1:
                    mid = len(trimmed) // 2
                    if trimmed[mid] == " " and trimmed[:mid] == trimmed[mid + 1 :]:
                        left_raw = right_raw = trimmed[:mid]
                    else:
                        raise PolicyImmutabilityError(
                            f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff --git "
                            f"header {line!r}."
                        )
                else:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable diff --git header {line!r}."
                    )

    had_standard_ab = left_raw.startswith("a/") and right_raw.startswith("b/")
    right_prefix = f"{right_raw.split('/', 1)[0]}/" if "/" in right_raw else None
    if had_standard_ab:
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
    return left, right, had_standard_ab, right_prefix


def _parse_diff_git_line(line: str) -> tuple[str, str]:
    left, right, _, _ = _parse_diff_git_line_details(line)
    return left, right


def _parse_minus_plus_header_details(
    line: str, header_prefix: str, git_prefix: str
) -> tuple[str | None, bool]:
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
        return None, False
    if not raw:
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: empty path in diff header {line!r}."
        )
    had_git_prefix = raw.startswith(git_prefix)
    if had_git_prefix:
        raw = raw[len(git_prefix) :]
    if not raw:
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: empty path after prefix in diff header {line!r}."
        )
    return raw, had_git_prefix


def _parse_minus_plus_header(line: str, header_prefix: str, git_prefix: str) -> str | None:
    parsed, _ = _parse_minus_plus_header_details(line, header_prefix, git_prefix)
    return parsed


def _parse_binary_differ_line(line: str) -> tuple[str | None, str | None]:
    """Parse `Binary files <left> and <right> differ` or `Files <left> and <right> differ`."""
    prefix = "Binary files " if line.startswith("Binary files ") else "Files "
    if not line.endswith(" differ"):
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable binary diff header {line!r}."
        )
    body = line[len(prefix) : -len(" differ")].strip()
    if not body:
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: empty binary diff header {line!r}."
        )

    left_raw: str
    right_raw: str
    if '"' in body:
        idx = 0
        if body[idx] == '"':
            left_raw, idx = _consume_quoted_git_token(body, idx)
        else:
            sep_idx = body.find(" and ")
            if sep_idx == -1:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable binary diff header {line!r}."
                )
            left_raw = body[:sep_idx].strip()
            idx = sep_idx
        if not body[idx:].startswith(" and "):
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable binary diff header {line!r}."
            )
        idx += len(" and ")
        rest = body[idx:].lstrip()
        if rest.startswith('"'):
            right_raw, end_idx = _consume_quoted_git_token(rest, 0)
            if rest[end_idx:].strip():
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable binary diff header {line!r}."
                )
        else:
            right_raw = rest
    else:
        parts = body.split(" and ")
        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
            left_raw, right_raw = parts[0].strip(), parts[1].strip()
        else:
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unparseable binary diff header {line!r}."
            )

    if left_raw.startswith("a/") and right_raw.startswith("b/"):
        left: str | None = left_raw[2:]
        right: str | None = right_raw[2:]
    elif left_raw == "/dev/null" and right_raw.startswith("b/"):
        left, right = None, right_raw[2:]
    elif right_raw == "/dev/null" and left_raw.startswith("a/"):
        left, right = left_raw[2:], None
    else:
        left = None if left_raw == "/dev/null" else left_raw
        right = None if right_raw == "/dev/null" else right_raw

    if (left is not None and not left) or (right is not None and not right):
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: empty path in binary diff header {line!r}."
        )
    return left, right


def parse_unified_patch_details(patch_text: str) -> ParsedPatch:
    """Parse git/unified diff path headers, added lines, 120000 targets, and renames."""
    touched: list[str] = []
    added_lines: list[str] = []
    symlink_added_targets: list[tuple[str, str]] = []
    renamed_pairs: list[tuple[str, str]] = []

    def _add_touched(path_str: str) -> None:
        if path_str != "/dev/null" and path_str not in touched:
            touched.append(path_str)

    in_hunk = False
    in_binary_patch = False
    old_rem = 0
    new_rem = 0
    current_is_symlink = False
    current_non_symlink_mode = False
    current_symlink_target_added = False
    current_section_paths: list[str] = []
    current_rename_from: str | None = None
    current_rename_to: str | None = None
    current_has_diff_git = False
    current_had_standard_ab = False
    current_right_prefix: str | None = None
    current_plus_had_b_prefix: bool | None = None

    def _flush_section() -> None:
        if (
            current_rename_from is not None
            and current_rename_to is not None
            and not current_symlink_target_added
            and not current_non_symlink_mode
        ):
            pair = (current_rename_from, current_rename_to)
            if pair not in renamed_pairs:
                renamed_pairs.append(pair)
            if "/" in current_rename_to and (
                not current_has_diff_git
                or (
                    not current_had_standard_ab
                    and current_right_prefix is not None
                    and current_rename_to.startswith(current_right_prefix)
                )
            ):
                stripped_dst = current_rename_to.split("/", 1)[1]
                if stripped_dst:
                    stripped_pair = (current_rename_from, stripped_dst)
                    if stripped_pair not in renamed_pairs:
                        renamed_pairs.append(stripped_pair)

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            _flush_section()
            in_hunk = False
            in_binary_patch = False
            old_rem = 0
            new_rem = 0
            current_is_symlink = False
            current_non_symlink_mode = False
            current_symlink_target_added = False
            current_section_paths = []
            current_rename_from = None
            current_rename_to = None
            current_plus_had_b_prefix = None
            left, right, current_had_standard_ab, current_right_prefix = (
                _parse_diff_git_line_details(line)
            )
            current_has_diff_git = True
            _add_touched(left)
            _add_touched(right)
            current_section_paths.extend([left, right])
            continue

        if line.startswith("@@"):
            in_binary_patch = False
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
                    already_b_stripped = (
                        current_plus_had_b_prefix
                        if current_plus_had_b_prefix is not None
                        else current_had_standard_ab
                    )
                    if not already_b_stripped and "/" in link_rel:
                        stripped_link = link_rel.split("/", 1)[1]
                        if stripped_link:
                            symlink_added_targets.append((stripped_link, added))
                    current_symlink_target_added = True
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

        if (line.startswith("Binary files ") or line.startswith("Files ")) and line.endswith(
            " differ"
        ):
            in_binary_patch = False
            bin_left, bin_right = _parse_binary_differ_line(line)
            if bin_left is not None:
                _add_touched(bin_left)
                current_section_paths.append(bin_left)
            if bin_right is not None:
                _add_touched(bin_right)
                current_section_paths.append(bin_right)
            continue

        if line.strip() == "GIT binary patch":
            if not current_section_paths:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: GIT binary patch missing target path header."
                )
            if current_is_symlink:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: binary patch targeting 120000 symlink "
                    f"{current_section_paths[-1]!r} is not permitted."
                )
            in_binary_patch = True
            continue

        if in_binary_patch:
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
            current_non_symlink_mode = False
            continue
        if line.startswith(("new mode ", "new file mode ")):
            current_is_symlink = False
            current_non_symlink_mode = True
            continue
        if line.startswith("index ") and line.rstrip().endswith(" 120000"):
            current_is_symlink = True
            current_non_symlink_mode = False
            continue

        if line.startswith("--- "):
            p = _parse_minus_plus_header(line, "--- ", "a/")
            if p is not None:
                _add_touched(p)
                current_section_paths.append(p)
            continue

        if line.startswith("+++ "):
            p, had_b = _parse_minus_plus_header_details(line, "+++ ", "b/")
            if p is not None:
                _add_touched(p)
                current_section_paths.append(p)
                current_plus_had_b_prefix = had_b
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
                if meta_hdr in ("rename from ", "copy from "):
                    current_rename_from = unquoted
                else:
                    current_rename_to = unquoted
                matched_meta = True
                break
        if matched_meta:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])

    _flush_section()

    if patch_text.strip() and not touched:
        raise PolicyImmutabilityError(
            f"{POLICY_IMMUTABILITY_VIOLATION}: non-empty patch yielded zero touched paths."
        )

    return ParsedPatch(
        touched_paths=touched,
        added_lines=added_lines,
        symlink_added_targets=symlink_added_targets,
        renamed_pairs=renamed_pairs,
    )


def parse_unified_patch(
    patch_text: str,
) -> tuple[list[str], list[str], list[tuple[str, str]]]:
    """Parse git/unified diff path headers, added lines, and 120000 symlink targets."""
    parsed = parse_unified_patch_details(patch_text)
    return parsed.touched_paths, parsed.added_lines, parsed.symlink_added_targets


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
            name_nfc = unicodedata.normalize("NFC", name)
            name_folded = _norm_fold(name)
            if cls._is_explicit_forbidden_basename(item, name) and name_folded not in {
                _norm_fold(existing) for existing in seen_names
            }:
                seen_names.add(name)
                pat = re.compile(
                    rf"(?<![A-Za-z0-9_.-]){re.escape(name_nfc)}(?![A-Za-z0-9_.])",
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
        norm_folded = _norm_fold(normalized)
        for prefix in self._immutable_prefixes:
            raw_prefix = prefix.replace("\\", "/")
            clean_prefix = posixpath.normpath(raw_prefix)
            if clean_prefix in ("", "."):
                continue
            prefix_folded = _norm_fold(clean_prefix)
            if norm_folded == prefix_folded or norm_folded.startswith(f"{prefix_folded}/"):
                return True
        filename = Path(normalized).name
        if _IMMUTABLE_NAME_RE.search(filename) or _IMMUTABLE_NAME_RE.search(_norm_fold(filename)):
            return True
        return bool(_IMMUTABLE_NAME_RE.search(normalized) or _IMMUTABLE_NAME_RE.search(norm_folded))

    def _is_immutable_ancestor(self, rel_path: str) -> bool:
        norm = posixpath.normpath(rel_path.strip().replace("\\", "/"))
        if norm in ("", ".") or norm.startswith("/") or ".." in norm.split("/"):
            return True
        norm_folded = _norm_fold(norm)
        for prefix in self._immutable_prefixes:
            clean_prefix = posixpath.normpath(prefix.replace("\\", "/"))
            if clean_prefix in ("", "."):
                continue
            prefix_folded = _norm_fold(clean_prefix)
            if prefix_folded == norm_folded or prefix_folded.startswith(f"{norm_folded}/"):
                return True
        return False

    def check_candidate_paths(self, paths: Sequence[str]) -> None:
        offending = tuple(
            sorted(
                {
                    p
                    for p in paths
                    if any(self.is_immutable_path(cand) for cand in _p1_candidates(p))
                }
            )
        )
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
        resolved_folded = _norm_fold(str(resolved_target))
        for forb_res in forbidden_resolved:
            forb_folded = _norm_fold(str(forb_res))
            if resolved_folded == forb_folded:
                return str(resolved_target)
            with contextlib.suppress(OSError, ValueError):
                if resolved_target.is_relative_to(forb_res):
                    return str(forb_res)
            forb_prefix = forb_folded.rstrip("/")
            if forb_prefix and resolved_folded.startswith(f"{forb_prefix}/"):
                return str(forb_res)
        forbidden_names_folded = {_norm_fold(n) for n in forbidden_names}
        if (
            resolved_target.name in forbidden_names
            or _norm_fold(resolved_target.name) in forbidden_names_folded
        ):
            return resolved_target.name
        if raw_target:
            raw_name = Path(raw_target).name
            if raw_name in forbidden_names or _norm_fold(raw_name) in forbidden_names_folded:
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

        # 1. Inspect touched paths, -p1-stripped candidates, parent components, and resolved targets
        expanded_touched: list[str] = []
        seen_touched: set[str] = set()
        for raw_p in touched_paths:
            for cand in _p1_candidates(raw_p):
                if cand not in seen_touched:
                    seen_touched.add(cand)
                    expanded_touched.append(cand)
        for rel_p in expanded_touched:
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
                            if entry.name and _norm_fold(entry.name) not in {
                                _norm_fold(n) for n in seen_names
                            }:
                                seen_names.add(entry.name)
                                entry_nfc = unicodedata.normalize("NFC", entry.name)
                                extra_patterns.append(
                                    (
                                        entry.name,
                                        re.compile(
                                            rf"(?<![A-Za-z0-9_.-]){re.escape(entry_nfc)}"
                                            r"(?![A-Za-z0-9_.])",
                                            re.IGNORECASE,
                                        ),
                                    )
                                )

        return tuple(extra_exact), tuple(extra_patterns), forbidden_resolved, forbidden_names

    def collect_renamed_symlink_targets(
        self,
        repo_path: Path,
        renamed_pairs: Sequence[tuple[str, str]],
        *,
        touched_paths: Sequence[str] = (),
    ) -> list[tuple[str, str]]:
        """Read symlink targets from repo_path for rename/copy pairs lacking explicit hunks."""
        if not renamed_pairs:
            return []
        try:
            resolved_repo = repo_path.resolve()
        except (OSError, RuntimeError) as exc:
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unresolvable repository path "
                f"{repo_path!r} ({exc}).",
                offending_paths=tuple(touched_paths),
            ) from exc

        discovered: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for src_rel, dst_rel in renamed_pairs:
            for src_cand in _p1_candidates(src_rel):
                norm_src = posixpath.normpath(src_cand.strip().replace("\\", "/"))
                if (
                    not norm_src
                    or norm_src == "."
                    or norm_src.startswith("/")
                    or ".." in norm_src.split("/")
                ):
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: invalid rename source path {src_rel!r}.",
                        offending_paths=tuple(touched_paths) or (src_rel, dst_rel),
                    )
                src_path = resolved_repo / norm_src
                try:
                    parent_res = src_path.parent.resolve()
                except (OSError, RuntimeError) as exc:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: unresolvable rename source "
                        f"{src_rel!r} ({exc}).",
                        offending_paths=tuple(touched_paths) or (src_rel, dst_rel),
                    ) from exc
                if not parent_res.is_relative_to(resolved_repo):
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: rename source {src_rel!r} "
                        "escapes repository.",
                        offending_paths=tuple(touched_paths) or (src_rel, dst_rel),
                    )
                try:
                    st = os.lstat(src_path)
                except (FileNotFoundError, NotADirectoryError):
                    continue
                except OSError as exc:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: unreadable rename source "
                        f"{src_rel!r} ({exc}).",
                        offending_paths=tuple(touched_paths) or (src_rel, dst_rel),
                    ) from exc
                if not stat.S_ISLNK(st.st_mode):
                    continue
                try:
                    target_str = os.readlink(src_path)
                except (OSError, RuntimeError) as exc:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: unreadable symlink rename source "
                        f"{src_rel!r} ({exc}).",
                        offending_paths=tuple(touched_paths) or (src_rel, dst_rel),
                    ) from exc
                if not target_str.strip():
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: empty symlink target on rename "
                        f"source {src_rel!r}.",
                        offending_paths=tuple(touched_paths) or (src_rel, dst_rel),
                    )
                pair = (dst_rel, target_str)
                if pair not in seen:
                    seen.add(pair)
                    discovered.append(pair)
        return discovered

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
        strip_p1_symlink_links: bool = True,
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
            if "\x00" in link_rel or "\x00" in target_str:
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: null byte in symlink patch entry.",
                    offending_paths=tuple(touched_paths) or (link_rel,),
                )
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

            link_candidates: list[str] = [norm_link]
            if strip_p1_symlink_links and "/" in norm_link:
                stripped_link = norm_link.split("/", 1)[1]
                if stripped_link and stripped_link not in link_candidates:
                    link_candidates.append(stripped_link)

            for cand_link in link_candidates:
                if (
                    not cand_link
                    or cand_link == "."
                    or cand_link.startswith("/")
                    or ".." in cand_link.split("/")
                ):
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: invalid symlink path {link_rel!r}.",
                        offending_paths=tuple(touched_paths) or (link_rel,),
                    )
                if cleaned_target.startswith("/") or ".." in cleaned_target.split("/"):
                    with contextlib.suppress(OSError, RuntimeError):
                        t_res = (
                            (resolved_repo / Path(cand_link).parent / cleaned_target).resolve()
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

                link_parent_rel = posixpath.dirname(cand_link)
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
                    link_parent = (resolved_repo / cand_link).parent
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
                    if self.is_immutable_path(target_rel) or self._is_immutable_ancestor(
                        target_rel
                    ):
                        raise PolicyImmutabilityError(
                            f"{POLICY_IMMUTABILITY_VIOLATION}: patch symlink {link_rel!r} "
                            f"targets immutable path or ancestor {target_rel!r}.",
                            offending_paths=tuple(touched_paths) or (link_rel,),
                        )

                added_symlinks_exact[cand_link] = lexical_target_rel
                added_symlinks_folded[_norm_fold(cand_link)] = lexical_target_rel

        if added_symlinks_exact and touched_paths:
            expanded_touched: list[str] = []
            seen_cand: set[str] = set()
            for orig_path in touched_paths:
                for cand in _p1_candidates(orig_path):
                    if cand not in seen_cand:
                        seen_cand.add(cand)
                        expanded_touched.append(cand)
            resolved_touched: list[str] = []
            max_hops = max(16, len(added_symlinks_exact) * 2 + 4)
            for orig_path in expanded_touched:
                cur_path = posixpath.normpath(orig_path.strip().replace("\\", "/"))
                seen_paths: set[str] = {_norm_fold(cur_path)}
                completed = False
                for _ in range(max_hops):
                    parts = cur_path.split("/")
                    replaced = False
                    for idx in range(1, len(parts) + 1):
                        prefix = "/".join(parts[:idx])
                        target_base = added_symlinks_exact.get(prefix)
                        if target_base is None:
                            target_base = added_symlinks_folded.get(_norm_fold(prefix))
                        if target_base is not None:
                            remainder = "/".join(parts[idx:])
                            next_path = posixpath.normpath(
                                f"{target_base}/{remainder}" if remainder else target_base
                            )
                            next_folded = _norm_fold(next_path)
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
            added_folded = _norm_fold(added)
            added_nfc = unicodedata.normalize("NFC", added)
            added_nfd = unicodedata.normalize("NFD", added)
            for tok in exact_tokens:
                if tok in added or _norm_fold(tok) in added_folded:
                    raise IsolationBoundaryError(
                        f"{ISOLATION_BOUNDARY_VIOLATION}: blocked candidate diff referencing "
                        f"forbidden runtime DB or credential path ({tok})."
                    )
            for name, pat in basename_patterns:
                if pat.search(added) or pat.search(added_nfc) or pat.search(added_nfd):
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

    def _collect_git_tree_symlink_targets(
        self,
        repo_path: Path,
        candidate_ref: str,
        touched_paths: Sequence[str],
    ) -> list[tuple[str, str]]:
        """Inspect candidate_ref git tree for 120000 symlink entries among touched_paths."""
        unique_paths = list(dict.fromkeys(p for p in touched_paths if p and p != "/dev/null"))
        if not unique_paths:
            return []

        discovered: list[tuple[str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()
        chunk_size = 200
        for offset in range(0, len(unique_paths), chunk_size):
            batch = unique_paths[offset : offset + chunk_size]
            tree_proc = subprocess.run(
                ["git", "-C", str(repo_path), "ls-tree", "-z", candidate_ref, "--", *batch],
                capture_output=True,
                check=False,
            )
            if tree_proc.returncode != 0:
                err_msg = tree_proc.stderr.decode("utf-8", errors="replace").strip()
                raise PolicyImmutabilityError(
                    f"{POLICY_IMMUTABILITY_VIOLATION}: unable to inspect git tree "
                    f"on {candidate_ref!r} ({err_msg}).",
                    offending_paths=tuple(touched_paths),
                )
            for raw_entry in tree_proc.stdout.split(b"\x00"):
                if not raw_entry:
                    continue
                if b"\t" not in raw_entry:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: malformed git ls-tree entry.",
                        offending_paths=tuple(touched_paths),
                    )
                meta_bytes, path_bytes = raw_entry.split(b"\t", 1)
                meta_parts = meta_bytes.decode("ascii", errors="strict").split()
                if len(meta_parts) != 3:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: malformed git ls-tree metadata.",
                        offending_paths=tuple(touched_paths),
                    )
                mode, obj_type, oid = meta_parts
                if mode != "120000" or obj_type != "blob":
                    continue
                try:
                    entry_path = path_bytes.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: non-UTF-8 symlink path in git tree.",
                        offending_paths=tuple(touched_paths),
                    ) from exc
                blob_proc = subprocess.run(
                    ["git", "-C", str(repo_path), "cat-file", "blob", oid],
                    capture_output=True,
                    check=False,
                )
                if blob_proc.returncode != 0:
                    err_msg = blob_proc.stderr.decode("utf-8", errors="replace").strip()
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: unable to read symlink blob "
                        f"for {entry_path!r} ({err_msg}).",
                        offending_paths=tuple(touched_paths),
                    )
                try:
                    target_str = blob_proc.stdout.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: non-UTF-8 symlink target "
                        f"for {entry_path!r}.",
                        offending_paths=tuple(touched_paths),
                    ) from exc
                if not target_str.strip():
                    raise PolicyImmutabilityError(
                        f"{POLICY_IMMUTABILITY_VIOLATION}: empty symlink target "
                        f"for {entry_path!r}.",
                        offending_paths=tuple(touched_paths),
                    )
                pair = (entry_path, target_str)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    discovered.append(pair)
        return discovered

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
            [
                "git",
                "-C",
                str(repo_path),
                "-c",
                "core.quotepath=false",
                "diff",
                "--name-only",
                f"{base_ref}..{candidate_ref}",
            ],
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
            [
                "git",
                "-C",
                str(repo_path),
                "-c",
                "diff.mnemonicPrefix=false",
                "diff",
                "--src-prefix=a/",
                "--dst-prefix=b/",
                "-U0",
                f"{base_ref}..{candidate_ref}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if patch_proc.returncode != 0:
            raise PolicyImmutabilityError(
                f"{POLICY_IMMUTABILITY_VIOLATION}: unable to read patch diff "
                f"({patch_proc.stderr.strip()})."
            )

        parsed = parse_unified_patch_details(patch_proc.stdout)
        touched_paths = list(dict.fromkeys([*changed_paths, *parsed.touched_paths]))
        self.check_candidate_paths(touched_paths)
        tree_symlinks = self._collect_git_tree_symlink_targets(
            repo_path, candidate_ref, touched_paths
        )
        all_symlinks = list(dict.fromkeys([*parsed.symlink_added_targets, *tree_symlinks]))
        self.check_added_lines(
            parsed.added_lines,
            touched_paths=touched_paths,
            repo_path=repo_path,
            exact_tokens=exact_tokens,
            basename_patterns=basename_patterns,
            forbidden_resolved=forbidden_resolved,
            forbidden_names=forbidden_names,
            symlink_added_targets=all_symlinks,
            strip_p1_symlink_links=False,
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
