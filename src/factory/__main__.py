"""CLI entrypoint for `python -m src.factory` (M7 local software factory)."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from src.factory.db import FactoryStore
from src.factory.demo import run_factory_demo
from src.factory.engine import EvalResult, FactoryEngine, rollback_from_manifest
from src.factory.errors import FactoryError, IsolationBoundaryError, PolicyImmutabilityError
from src.factory.models import BacklogItem, CandidatePatch, CycleBudget, compute_proposal_hash
from src.factory.policy import (
    ISOLATION_BOUNDARY_VIOLATION,
    POLICY_IMMUTABILITY_VIOLATION,
    IsolationGuard,
    PolicyGuard,
)


def _parse_forbidden_paths(
    runtime_dbs: list[str] | None = None,
    credentials_files: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    env_forbidden = [
        part.strip()
        for part in os.environ.get("GROKBOT_FORBIDDEN_PATHS", "").split(",")
        if part.strip()
    ]
    dbs = [*(runtime_dbs or []), *env_forbidden]
    creds = [*(credentials_files or []), *env_forbidden]
    return dbs, creds


def _resolve_base_branch(repo_path: Path, requested_base: str | None) -> str:
    if requested_base and requested_base.strip():
        return requested_base.strip()
    cur = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    cur_branch = cur.stdout.strip()
    if cur.returncode == 0 and cur_branch and cur_branch != "HEAD":
        return cur_branch
    for candidate in ("main", "master"):
        chk = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "--verify", candidate],
            capture_output=True,
            text=True,
            check=False,
        )
        if chk.returncode == 0:
            return candidate
    return "HEAD"


def _add_audit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repo",
        default=os.environ.get("GROKBOT_FACTORY_REPO") or None,
        help="Path to isolated lab git repo.",
    )
    parser.add_argument(
        "--db",
        "--factory-db",
        dest="db",
        default=os.environ.get("GROKBOT_FACTORY_DB") or None,
        help="Path to isolated factory SQLite DB.",
    )
    parser.add_argument(
        "--branch",
        default=os.environ.get("GROKBOT_FACTORY_CANDIDATE_BRANCH") or None,
        help="Candidate branch name to audit.",
    )
    parser.add_argument("--base", default=None, help="Base branch name (auto-detected if omitted).")
    parser.add_argument(
        "--runtime-db", action="append", default=[], help="Forbidden runtime DB path."
    )
    parser.add_argument(
        "--credentials-file",
        action="append",
        default=[],
        help="Forbidden runtime credentials path.",
    )
    parser.add_argument(
        "--output-dir",
        "--out",
        dest="output_dir",
        default=os.environ.get("GROKBOT_FACTORY_OUT") or None,
        help="Optional artifact output directory.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.factory",
        description="Grokbot-clon M7 autonomous local software factory CLI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_demo = sub.add_parser("demo", help="Run the 2-candidate isolated factory demonstration.")
    p_demo.add_argument(
        "--repo",
        default=os.environ.get("GROKBOT_FACTORY_REPO") or None,
        help="Optional isolated lab git repo path.",
    )
    p_demo.add_argument(
        "--db",
        "--factory-db",
        dest="db",
        default=os.environ.get("GROKBOT_FACTORY_DB") or None,
        help="Optional isolated factory DB path.",
    )
    p_demo.add_argument(
        "--output-dir",
        "--out",
        dest="output_dir",
        default=os.environ.get("GROKBOT_FACTORY_OUT") or None,
        help="Optional artifact directory.",
    )
    p_demo.add_argument(
        "--candidate",
        choices=("all", "1", "2"),
        default=os.environ.get("GROKBOT_FACTORY_CANDIDATE") or "all",
        help="Candidate selector: all, 1, or 2 (default: all).",
    )
    p_demo.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_run = sub.add_parser("run", help="Execute bounded factory cycles against a backlog.")
    p_run.add_argument(
        "--repo",
        default=os.environ.get("GROKBOT_FACTORY_REPO") or None,
        help="Path to isolated lab git repo.",
    )
    p_run.add_argument(
        "--db",
        "--factory-db",
        dest="db",
        default=os.environ.get("GROKBOT_FACTORY_DB") or None,
        help="Path to isolated factory SQLite DB.",
    )
    p_run.add_argument(
        "--output-dir",
        "--out",
        dest="output_dir",
        default=os.environ.get("GROKBOT_FACTORY_OUT") or None,
        help="Optional artifact directory.",
    )
    p_run.add_argument(
        "--backlog",
        default=os.environ.get("GROKBOT_FACTORY_BACKLOG") or None,
        help="Path to JSON backlog list file.",
    )
    p_run.add_argument(
        "--max-attempts",
        type=int,
        default=int(os.environ.get("GROKBOT_FACTORY_MAX_ATTEMPTS") or "2"),
        help="Maximum bounded attempts per run.",
    )
    p_run.add_argument(
        "--branch",
        default=os.environ.get("GROKBOT_FACTORY_CANDIDATE_BRANCH") or None,
        help="Optional candidate branch to audit.",
    )
    p_run.add_argument("--base", default=None, help="Base branch name (auto-detected if omitted).")
    p_run.add_argument(
        "--runtime-db", action="append", default=[], help="Forbidden runtime DB path."
    )
    p_run.add_argument(
        "--credentials-file",
        action="append",
        default=[],
        help="Forbidden runtime credentials path.",
    )
    p_run.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_cycle = sub.add_parser("cycle", help="Run one candidate cycle on an isolated branch.")
    p_cycle.add_argument(
        "--repo",
        default=os.environ.get("GROKBOT_FACTORY_REPO") or None,
        required=not bool(os.environ.get("GROKBOT_FACTORY_REPO")),
        help="Path to isolated lab git repo.",
    )
    p_cycle.add_argument(
        "--db",
        "--factory-db",
        dest="db",
        default=os.environ.get("GROKBOT_FACTORY_DB") or None,
        required=not bool(os.environ.get("GROKBOT_FACTORY_DB")),
        help="Path to isolated factory SQLite DB.",
    )
    p_cycle.add_argument("--item-id", default="B-FAC-CLI", help="Backlog item ID.")
    p_cycle.add_argument("--candidate-id", default="cand-cli-1", help="Candidate ID.")
    p_cycle.add_argument(
        "--branch",
        default=os.environ.get("GROKBOT_FACTORY_CANDIDATE_BRANCH", "factory/candidate-1"),
        help="Isolated candidate branch name.",
    )
    p_cycle.add_argument(
        "--base", default=None, help="Base branch name (auto-detected if omitted)."
    )
    p_cycle.add_argument(
        "--runtime-db", action="append", default=[], help="Forbidden runtime DB path."
    )
    p_cycle.add_argument(
        "--credentials-file",
        action="append",
        default=[],
        help="Forbidden runtime credentials path.",
    )
    p_cycle.add_argument(
        "--output-dir",
        "--out",
        dest="output_dir",
        default=os.environ.get("GROKBOT_FACTORY_OUT") or None,
        help="Optional artifact directory.",
    )
    p_cycle.add_argument("--manifest-out", default=None, help="Optional rollback manifest output.")
    p_cycle.add_argument("--max-attempts", type=int, default=2, help="Max attempts for item.")
    p_cycle.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_audit = sub.add_parser("audit", help="Audit an existing candidate branch diff.")
    _add_audit_arguments(p_audit)

    p_audit_branch = sub.add_parser(
        "audit-branch", help="Audit an existing candidate branch diff."
    )
    _add_audit_arguments(p_audit_branch)

    p_rb = sub.add_parser("rollback", help="Restore lab repository from a RollbackManifest JSON.")
    p_rb.add_argument("--manifest", required=True, help="Path to rollback manifest JSON.")
    p_rb.add_argument("--repo", default=None, help="Optional repository path override.")
    p_rb.add_argument("--db", "--factory-db", dest="db", default=None, help="Optional factory DB.")
    p_rb.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_status = sub.add_parser("status", help="Inspect factory backlog, budgets, and lessons.")
    p_status.add_argument(
        "--db",
        "--factory-db",
        dest="db",
        default=os.environ.get("GROKBOT_FACTORY_DB") or None,
        required=not bool(os.environ.get("GROKBOT_FACTORY_DB")),
        help="Path to isolated factory SQLite DB.",
    )
    p_status.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_resume = sub.add_parser(
        "resume",
        help="Resume or inspect persisted factory state without resetting counters.",
    )
    p_resume.add_argument(
        "--db",
        "--factory-db",
        dest="db",
        default=os.environ.get("GROKBOT_FACTORY_DB") or None,
        required=not bool(os.environ.get("GROKBOT_FACTORY_DB")),
        help="Path to isolated factory SQLite DB.",
    )
    p_resume.add_argument(
        "--repo",
        default=os.environ.get("GROKBOT_FACTORY_REPO") or None,
        help="Optional isolated lab git repo path.",
    )
    p_resume.add_argument(
        "--output-dir",
        "--out",
        dest="output_dir",
        default=os.environ.get("GROKBOT_FACTORY_OUT") or None,
        help="Optional artifact directory.",
    )
    p_resume.add_argument("--max-steps", type=int, default=None, help="Optional max step limit.")
    p_resume.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_eval = sub.add_parser(
        "evaluate-patch",
        help="Evaluate a candidate unified diff patch against policy & isolation guards.",
    )
    p_eval.add_argument(
        "--repo",
        default=os.environ.get("GROKBOT_FACTORY_REPO") or None,
        help="Path to isolated lab git repo.",
    )
    p_eval.add_argument(
        "--db",
        "--factory-db",
        dest="db",
        default=os.environ.get("GROKBOT_FACTORY_DB") or None,
        help="Path to isolated factory SQLite DB.",
    )
    p_eval.add_argument("--patch", required=True, help="Path to unified diff patch file.")
    p_eval.add_argument(
        "--runtime-db", action="append", default=[], help="Forbidden runtime DB path."
    )
    p_eval.add_argument(
        "--credentials-file",
        action="append",
        default=[],
        help="Forbidden runtime credentials path.",
    )
    p_eval.add_argument("--json", action="store_true", help="Emit JSON output.")

    for cmd_name in ("run-cycle", "run-candidate"):
        p_rc = sub.add_parser(
            cmd_name,
            help="Execute a bounded factory cycle or candidate mode on an isolated repo.",
        )
        p_rc.add_argument(
            "--repo",
            default=os.environ.get("GROKBOT_FACTORY_REPO") or None,
            help="Path to isolated lab git repo.",
        )
        p_rc.add_argument(
            "--db",
            "--factory-db",
            dest="db",
            default=os.environ.get("GROKBOT_FACTORY_DB") or None,
            help="Path to isolated factory SQLite DB.",
        )
        p_rc.add_argument(
            "--backlog",
            default=os.environ.get("GROKBOT_FACTORY_BACKLOG") or None,
            help="Path to JSON or Markdown backlog file.",
        )
        p_rc.add_argument(
            "--max-attempts",
            type=int,
            default=int(os.environ.get("GROKBOT_FACTORY_MAX_ATTEMPTS") or "2"),
            help="Maximum bounded attempts.",
        )
        p_rc.add_argument(
            "--simulate-exhaustion",
            action="store_true",
            help="Simulate failing candidate attempts until budget/attempts exhaust.",
        )
        p_rc.add_argument(
            "--candidate-mode",
            choices=("valid-optimization", "reject-asset-confusion"),
            default=None,
            help="Optional deterministic candidate mode.",
        )
        p_rc.add_argument(
            "--output-dir",
            "--out",
            dest="output_dir",
            default=os.environ.get("GROKBOT_FACTORY_OUT") or None,
            help="Optional artifact output directory.",
        )
        p_rc.add_argument("--base", default=None, help="Base branch name.")
        p_rc.add_argument(
            "--runtime-db", action="append", default=[], help="Forbidden runtime DB path."
        )
        p_rc.add_argument(
            "--credentials-file",
            action="append",
            default=[],
            help="Forbidden runtime credentials path.",
        )
        p_rc.add_argument("--json", action="store_true", help="Emit JSON output.")

    return parser


def _handle_audit(args: argparse.Namespace) -> int:
    if not args.repo:
        raise FactoryError("Missing --repo / GROKBOT_FACTORY_REPO for audit.")
    if not args.db:
        raise FactoryError("Missing --db / GROKBOT_FACTORY_DB for audit.")
    if not args.branch:
        raise FactoryError("Missing --branch / GROKBOT_FACTORY_CANDIDATE_BRANCH for audit.")

    repo_path = Path(args.repo).resolve()
    forbidden_dbs, forbidden_creds = _parse_forbidden_paths(
        args.runtime_db, args.credentials_file
    )
    store = FactoryStore(
        args.db,
        forbidden_db_paths=forbidden_dbs,
        forbidden_credential_paths=forbidden_creds,
    )
    store.init_db()
    base_branch = _resolve_base_branch(repo_path, args.base)
    engine = FactoryEngine(
        repo_path,
        store,
        base_branch=base_branch,
        forbidden_db_paths=forbidden_dbs,
        forbidden_credential_paths=forbidden_creds,
        artifacts_dir=Path(args.output_dir) if getattr(args, "output_dir", None) else None,
    )
    try:
        audit_res = engine.audit_branch(args.branch, base_branch=base_branch)
    except (PolicyImmutabilityError, IsolationBoundaryError) as exc:
        store.append_audit_log(
            actor="factory-auditor",
            action="branch_audit_rejected",
            decision="deny",
            detail={"branch": args.branch, "base": base_branch, "reason": str(exc)},
        )
        payload = {
            "ok": False,
            "status": "rejected",
            "branch_name": args.branch,
            "base_branch": base_branch,
            "policy_passed": False,
            "reason": str(exc),
        }
        print(json.dumps(payload, indent=2, default=str))
        print(f"Factory audit rejected: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(audit_res, indent=2, default=str))
    return 0


def _load_backlog_items(backlog_path: Path, *, max_attempts: int) -> list[BacklogItem]:
    if not backlog_path.is_file():
        raise FactoryError(f"Backlog file not found: {backlog_path}")
    text = backlog_path.read_text(encoding="utf-8")
    if backlog_path.suffix.lower() == ".json":
        raw_backlog = json.loads(text)
        if not isinstance(raw_backlog, list):
            raise FactoryError("Backlog JSON must decode to a list of items.")
        return [
            BacklogItem.model_validate(entry)
            for entry in raw_backlog
            if isinstance(entry, dict)
        ]

    # Parse Markdown backlog (e.g. ops/BACKLOG.md)
    unchecked: list[BacklogItem] = []
    checked: list[BacklogItem] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        m = re.match(
            r"^\s*[-*]\s+\[([ xX])\]\s+`?([A-Za-z0-9_.-]+)`?\s*:\s*(.+)$",
            line,
        )
        if not m:
            continue
        mark, item_id, desc = m.group(1), m.group(2), m.group(3).strip()
        item = BacklogItem(
            item_id=item_id,
            title=desc[:120] or item_id,
            priority=idx,
            hypothesis=desc or f"Address {item_id}",
            target_metric="tests",
            baseline_repro_cmd="pytest -q",
            max_attempts=max_attempts,
        )
        if mark == " ":
            unchecked.append(item)
        else:
            checked.append(item)
    return unchecked or checked


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


def _parse_unified_patch(
    patch_text: str,
) -> tuple[list[str], list[str], list[tuple[str, str]]]:
    """Parse git/unified diff path headers and added lines; fail closed on invalid headers."""
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


def _handle_evaluate_patch(args: argparse.Namespace) -> int:
    if not args.repo:
        raise FactoryError("Missing --repo / GROKBOT_FACTORY_REPO for evaluate-patch.")
    if not args.db:
        raise FactoryError("Missing --db / GROKBOT_FACTORY_DB for evaluate-patch.")
    patch_path = Path(args.patch)
    if not patch_path.is_file():
        raise FactoryError(f"Patch file not found: {patch_path}")

    repo_path = Path(args.repo).resolve()
    forbidden_dbs, forbidden_creds = _parse_forbidden_paths(
        args.runtime_db, args.credentials_file
    )
    store = FactoryStore(
        args.db,
        forbidden_db_paths=forbidden_dbs,
        forbidden_credential_paths=forbidden_creds,
    )
    store.init_db()
    IsolationGuard.validate_paths(
        store.db_path,
        repo_path,
        forbidden_db_paths=forbidden_dbs,
        forbidden_credential_paths=forbidden_creds,
    )

    patch_text = patch_path.read_text(encoding="utf-8")
    touched: list[str] = []
    guard = PolicyGuard(forbidden_paths=[*forbidden_dbs, *forbidden_creds])
    try:
        touched, added_lines, symlink_added_targets = _parse_unified_patch(patch_text)
        guard.check_candidate_paths(touched)
        exact_tokens, basename_patterns, forbidden_resolved, forbidden_names = (
            guard.check_repo_symlinks(repo_path, touched)
        )
        guard.check_added_lines(
            added_lines,
            touched_paths=touched,
            repo_path=repo_path,
            extra_search_dirs=[patch_path.resolve().parent, Path.cwd()],
            exact_tokens=exact_tokens,
            basename_patterns=basename_patterns,
            forbidden_resolved=forbidden_resolved,
            forbidden_names=forbidden_names,
            symlink_added_targets=symlink_added_targets,
        )
    except (PolicyImmutabilityError, IsolationBoundaryError) as exc:
        violation_code = (
            POLICY_IMMUTABILITY_VIOLATION
            if isinstance(exc, PolicyImmutabilityError)
            else ISOLATION_BOUNDARY_VIOLATION
        )
        store.append_audit_log(
            actor="factory-auditor",
            action="patch_evaluation_rejected",
            decision="deny",
            detail={"patch": str(patch_path), "violation": violation_code, "reason": str(exc)},
        )
        payload = {
            "ok": False,
            "status": "REJECTED",
            "policy_passed": False,
            "violation": violation_code,
            "reason": str(exc),
            "touched_paths": touched,
        }
        print(json.dumps(payload, indent=2, default=str))
        print(f"Factory patch rejected: {exc}", file=sys.stderr)
        return 1

    store.append_audit_log(
        actor="factory-auditor",
        action="patch_evaluation_allowed",
        decision="allow",
        detail={"patch": str(patch_path), "touched_paths": touched},
    )
    print(
        json.dumps(
            {
                "ok": True,
                "status": "ALLOWED",
                "policy_passed": True,
                "touched_paths": touched,
            },
            indent=2,
            default=str,
        )
    )
    return 0


def _handle_run_cycle(args: argparse.Namespace) -> int:
    if not args.repo:
        raise FactoryError("Missing --repo / GROKBOT_FACTORY_REPO for run-cycle.")
    if not args.db:
        raise FactoryError("Missing --db / GROKBOT_FACTORY_DB for run-cycle.")

    repo_path = Path(args.repo).resolve()
    db_path = Path(args.db).resolve()
    out_dir = (
        Path(args.output_dir).resolve()
        if args.output_dir
        else (db_path.parent / "factory_artifacts")
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    forbidden_dbs, forbidden_creds = _parse_forbidden_paths(
        args.runtime_db, args.credentials_file
    )
    store = FactoryStore(
        db_path,
        forbidden_db_paths=forbidden_dbs,
        forbidden_credential_paths=forbidden_creds,
    )
    store.init_db()
    max_attempts = max(1, int(args.max_attempts))

    if args.backlog:
        items = _load_backlog_items(Path(args.backlog), max_attempts=max_attempts)
        for item in items:
            if store.get_backlog_item(item.item_id) is None:
                store.add_backlog_item(item)

    if args.candidate_mode == "valid-optimization":
        summary = run_factory_demo(
            repo_dir=repo_path,
            db_path=db_path,
            output_dir=out_dir,
            candidate="1",
        )
        budget_after = store.get_budget()
        payload: dict[str, Any] = {
            "ok": bool(summary.get("ok")),
            "status": "PROMOTED" if summary.get("ok") else "REJECTED",
            "attempts_used": budget_after.attempts_used,
            "cycles_used": budget_after.cycles_used,
            "rollback_manifest_path": summary.get("manifest_path"),
            "benchmark_json_path": summary.get("benchmark_json_path"),
            "benchmark_md_path": summary.get("benchmark_md_path"),
            "candidate_1": summary.get("candidate_1"),
            "budget": budget_after.model_dump(mode="json"),
        }
        print(json.dumps(payload, indent=2, default=str))
        return 0 if summary.get("ok") else 1

    if args.candidate_mode == "reject-asset-confusion":
        summary = run_factory_demo(
            repo_dir=repo_path,
            db_path=db_path,
            output_dir=out_dir,
            candidate="2",
        )
        budget_after = store.get_budget()
        reg_path = summary.get("regression_test_path")
        payload = {
            "ok": True,
            "status": "REJECTED",
            "attempts_used": budget_after.attempts_used,
            "cycles_used": budget_after.cycles_used,
            "regression_test_path": reg_path,
            "candidate_2": summary.get("candidate_2"),
            "lessons": summary.get("lessons", []),
            "budget": budget_after.model_dump(mode="json"),
        }
        print(json.dumps(payload, indent=2, default=str))
        return 0

    base_branch = _resolve_base_branch(repo_path, args.base)
    engine = FactoryEngine(
        repo_path,
        store,
        budget=CycleBudget(max_cycles=max_attempts, max_attempts=max_attempts),
        base_branch=base_branch,
        forbidden_db_paths=forbidden_dbs,
        forbidden_credential_paths=forbidden_creds,
        artifacts_dir=out_dir,
    )

    if args.simulate_exhaustion:
        if not store.list_backlog_items():
            store.add_backlog_item(
                BacklogItem(
                    item_id="B-FAC-EXHAUST",
                    title="Bounded exhaustion probe item",
                    priority=1,
                    hypothesis="Test bounded attempt and cycle exhaustion pause.",
                    target_metric="tests",
                    baseline_repro_cmd="pytest -q",
                    max_attempts=max_attempts,
                )
            )
        pause = engine.check_pause_state()
        cycle_res_dict: dict[str, Any] | None = None
        if pause is None:
            next_item = store.get_next_pending_item()
            if next_item is not None:
                attempt_num = store.get_budget().attempts_used + 1
                files = {"_factory_exhaust_probe.txt": f"attempt={attempt_num}\n"}
                cand = CandidatePatch(
                    candidate_id=f"cand-exhaust-{attempt_num}",
                    item_id=next_item.item_id,
                    branch_name=f"factory/exhaust-{attempt_num}",
                    hypothesis=next_item.hypothesis,
                    target_metric=next_item.target_metric,
                    proposal_hash=compute_proposal_hash(
                        item_id=next_item.item_id,
                        target_metric=next_item.target_metric,
                        files_to_modify=files,
                    ),
                    new_evidence=True,
                    files_to_modify=files,
                )
                cycle_res = engine.run_candidate_cycle(
                    cand,
                    evaluator=lambda _p: EvalResult(
                        passed=False, metric=999.0, detail="simulated_exhaustion_failure"
                    ),
                )
                cycle_res_dict = cycle_res.model_dump(mode="json")

        post_pause = engine.check_pause_state()
        budget_after = store.get_budget()
        if post_pause is not None:
            status_str = post_pause.status.value.upper()
            reason_str = post_pause.reason
        elif cycle_res_dict is not None:
            status_str = str(cycle_res_dict["status"]).upper()
            reason_str = str(cycle_res_dict.get("reason", ""))
        else:
            status_str = "PAUSED_BUDGET_EXHAUSTED"
            reason_str = "Factory attempt budget exhausted."

        payload = {
            "ok": True,
            "status": status_str,
            "reason": reason_str,
            "attempts_used": budget_after.attempts_used,
            "cycles_used": budget_after.cycles_used,
            "cycle_result": cycle_res_dict,
            "budget": budget_after.model_dump(mode="json"),
        }
        print(json.dumps(payload, indent=2, default=str))
        return 0

    pause = engine.check_pause_state()
    budget_now = store.get_budget()
    payload = {
        "ok": True,
        "status": pause.status.value.upper() if pause is not None else "READY",
        "reason": pause.reason if pause is not None else "ready",
        "attempts_used": budget_now.attempts_used,
        "cycles_used": budget_now.cycles_used,
        "budget": budget_now.model_dump(mode="json"),
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0


def _handle_run(args: argparse.Namespace) -> int:
    if args.branch:
        return _handle_audit(args)
    if not args.repo:
        raise FactoryError("Missing --repo / GROKBOT_FACTORY_REPO for run.")
    if not args.db:
        raise FactoryError("Missing --db / GROKBOT_FACTORY_DB for run.")

    repo_path = Path(args.repo).resolve()
    out_dir = Path(args.output_dir).resolve() if args.output_dir else None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

    forbidden_dbs, forbidden_creds = _parse_forbidden_paths(
        args.runtime_db, args.credentials_file
    )
    store = FactoryStore(
        args.db,
        forbidden_db_paths=forbidden_dbs,
        forbidden_credential_paths=forbidden_creds,
    )
    store.init_db()

    base_branch = _resolve_base_branch(repo_path, args.base)
    max_attempts = max(1, int(args.max_attempts))
    engine = FactoryEngine(
        repo_path,
        store,
        budget=CycleBudget(max_cycles=max_attempts, max_attempts=max_attempts),
        base_branch=base_branch,
        forbidden_db_paths=forbidden_dbs,
        forbidden_credential_paths=forbidden_creds,
        artifacts_dir=out_dir,
    )

    if args.backlog:
        backlog_path = Path(args.backlog)
        if not backlog_path.is_file():
            raise FactoryError(f"Backlog file not found: {backlog_path}")
        raw_backlog = json.loads(backlog_path.read_text(encoding="utf-8"))
        if not isinstance(raw_backlog, list):
            raise FactoryError("Backlog JSON must decode to a list of items.")
        for entry in raw_backlog:
            if isinstance(entry, dict):
                store.add_backlog_item(BacklogItem.model_validate(entry))
        if not raw_backlog:
            pause = engine.check_pause_state()
            assert pause is not None
            store.append_audit_log(
                actor="factory-runner",
                action="factory_paused",
                decision="allow",
                detail={"status": pause.status.value, "reason": pause.reason},
            )
            payload: dict[str, Any] = {
                "ok": True,
                "status": pause.status.value,
                "reason": pause.reason,
                "budget": store.get_budget().model_dump(mode="json"),
                "backlog": [],
            }
            if out_dir is not None:
                (out_dir / "factory_run_summary.json").write_text(
                    json.dumps(payload, indent=2, default=str),
                    encoding="utf-8",
                )
            print(json.dumps(payload, indent=2, default=str))
            return 0

    force_fail = os.environ.get("GROKBOT_FACTORY_FORCE_FAIL", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    if force_fail:
        if not store.list_backlog_items():
            store.add_backlog_item(
                BacklogItem(
                    item_id="B-FAC-RUN",
                    title="Bounded factory run",
                    priority=1,
                    hypothesis="Evaluate bounded candidate attempts",
                    target_metric="tests",
                    baseline_repro_cmd="pytest -q",
                    max_attempts=max_attempts,
                )
            )
        results: list[dict[str, Any]] = []
        for idx in range(1, max_attempts + 1):
            pause = engine.check_pause_state()
            if pause is not None:
                break
            next_item = store.get_next_pending_item()
            if next_item is None:
                break
            files = {"_factory_attempt_probe.txt": f"attempt={idx}\n"}
            cand = CandidatePatch(
                candidate_id=f"cand-run-{idx}",
                item_id=next_item.item_id,
                branch_name=f"factory/run-attempt-{idx}",
                hypothesis=next_item.hypothesis,
                target_metric=next_item.target_metric,
                proposal_hash=compute_proposal_hash(
                    item_id=next_item.item_id,
                    target_metric=next_item.target_metric,
                    files_to_modify=files,
                ),
                new_evidence=True,
                files_to_modify=files,
            )
            cycle_res = engine.run_candidate_cycle(
                cand,
                evaluator=lambda _p: EvalResult(
                    passed=False, metric=999.0, detail="forced_failure"
                ),
            )
            results.append(cycle_res.model_dump(mode="json"))

        final_pause = engine.check_pause_state()
        status_val = (
            final_pause.status.value
            if final_pause is not None
            else "paused_budget_exhausted"
        )
        reason_val = (
            final_pause.reason
            if final_pause is not None
            else "Attempt/budget limit exhausted."
        )
        store.append_audit_log(
            actor="factory-runner",
            action="factory_paused",
            decision="allow",
            detail={"status": status_val, "reason": reason_val},
        )
        payload = {
            "ok": True,
            "status": status_val,
            "reason": reason_val,
            "attempts": results,
            "budget": store.get_budget().model_dump(mode="json"),
        }
        if out_dir is not None:
            (out_dir / "factory_run_summary.json").write_text(
                json.dumps(payload, indent=2, default=str),
                encoding="utf-8",
            )
        print(json.dumps(payload, indent=2, default=str))
        return 0

    pause = engine.check_pause_state()
    if pause is not None:
        payload = {
            "ok": True,
            "status": pause.status.value,
            "reason": pause.reason,
            "budget": store.get_budget().model_dump(mode="json"),
        }
        print(json.dumps(payload, indent=2, default=str))
        return 0

    payload = {
        "ok": True,
        "status": "ready",
        "budget": store.get_budget().model_dump(mode="json"),
        "backlog": [item.model_dump(mode="json") for item in store.list_backlog_items()],
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "demo":
            summary = run_factory_demo(
                repo_dir=Path(args.repo) if args.repo else None,
                db_path=Path(args.db) if args.db else None,
                output_dir=Path(args.output_dir) if args.output_dir else None,
                candidate=args.candidate,
            )
            print(json.dumps(summary, indent=2, default=str))
            return 0 if summary["ok"] else 1

        if args.command == "run":
            return _handle_run(args)

        if args.command == "evaluate-patch":
            return _handle_evaluate_patch(args)

        if args.command in {"run-cycle", "run-candidate"}:
            return _handle_run_cycle(args)

        if args.command in {"audit", "audit-branch"}:
            return _handle_audit(args)

        if args.command == "rollback":
            store = FactoryStore(args.db) if args.db else None
            if store is not None:
                store.init_db()
            res = rollback_from_manifest(
                args.manifest,
                repo_path=Path(args.repo) if args.repo else None,
                store=store,
            )
            print(json.dumps(res, indent=2, default=str))
            return 0

        if args.command == "status":
            store = FactoryStore(args.db)
            store.init_db()
            payload = {
                "budget": store.get_budget().model_dump(mode="json"),
                "backlog": [item.model_dump(mode="json") for item in store.list_backlog_items()],
                "lessons": [lesson.model_dump(mode="json") for lesson in store.list_lessons()],
            }
            print(json.dumps(payload, indent=2, default=str))
            return 0

        if args.command == "resume":
            store = FactoryStore(args.db)
            store.init_db()
            budget = store.get_budget()
            backlog = store.list_backlog_items()
            lessons = store.list_lessons()
            exhausted = (
                budget.cycles_used >= budget.max_cycles
                or budget.attempts_used >= budget.max_attempts
            )
            resume_payload: dict[str, Any] = {
                "ok": True,
                "status": "paused_budget_exhausted" if exhausted else "resumed",
                "repo": str(args.repo) if args.repo else None,
                "output_dir": str(args.output_dir) if args.output_dir else None,
                "max_steps": args.max_steps,
                "budget": budget.model_dump(mode="json"),
                "backlog": [item.model_dump(mode="json") for item in backlog],
                "lessons": [lesson.model_dump(mode="json") for lesson in lessons],
            }
            print(json.dumps(resume_payload, indent=2, default=str))
            return 0

        if args.command == "cycle":
            forbidden_dbs, forbidden_creds = _parse_forbidden_paths(
                args.runtime_db, args.credentials_file
            )
            base_branch = _resolve_base_branch(Path(args.repo), args.base)
            store = FactoryStore(
                args.db,
                forbidden_db_paths=forbidden_dbs,
                forbidden_credential_paths=forbidden_creds,
            )
            engine = FactoryEngine(
                args.repo,
                store,
                base_branch=base_branch,
                forbidden_db_paths=forbidden_dbs,
                forbidden_credential_paths=forbidden_creds,
                artifacts_dir=Path(args.output_dir) if args.output_dir else None,
            )
            if store.get_backlog_item(args.item_id) is None:
                store.add_backlog_item(
                    BacklogItem(
                        item_id=args.item_id,
                        title=f"CLI backlog item {args.item_id}",
                        priority=1,
                        hypothesis="Evaluate candidate patch",
                        target_metric="tests",
                        baseline_repro_cmd="pytest -q",
                        max_attempts=args.max_attempts,
                    )
                )
            cand = CandidatePatch(
                candidate_id=args.candidate_id,
                item_id=args.item_id,
                branch_name=args.branch,
                hypothesis="CLI candidate evaluation",
                target_metric="tests",
                proposal_hash=compute_proposal_hash(
                    item_id=args.item_id,
                    target_metric="tests",
                    files_to_modify={},
                ),
            )
            cycle_res = engine.run_candidate_cycle(
                cand,
                manifest_out=Path(args.manifest_out) if args.manifest_out else None,
            )
            print(cycle_res.model_dump_json(indent=2))
            return 0

    except (FactoryError, OSError, ValueError) as exc:
        print(f"Factory error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
