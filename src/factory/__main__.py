"""CLI entrypoint for `python -m src.factory` (M7 local software factory)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from src.factory.db import FactoryStore
from src.factory.demo import run_factory_demo
from src.factory.engine import FactoryEngine, rollback_from_manifest
from src.factory.errors import FactoryError
from src.factory.models import BacklogItem, CandidatePatch, compute_proposal_hash


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.factory",
        description="Grokbot-clon M7 autonomous local software factory CLI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_demo = sub.add_parser("demo", help="Run the 2-candidate isolated factory demonstration.")
    p_demo.add_argument("--repo", default=None, help="Optional isolated lab git repo path.")
    p_demo.add_argument("--db", default=None, help="Optional isolated factory DB path.")
    p_demo.add_argument("--output-dir", default=None, help="Optional artifact directory.")
    p_demo.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_cycle = sub.add_parser("cycle", help="Run one candidate cycle on an isolated branch.")
    p_cycle.add_argument("--repo", required=True, help="Path to isolated lab git repo.")
    p_cycle.add_argument("--db", required=True, help="Path to isolated factory SQLite DB.")
    p_cycle.add_argument("--item-id", default="B-FAC-CLI", help="Backlog item ID.")
    p_cycle.add_argument("--candidate-id", default="cand-cli-1", help="Candidate ID.")
    p_cycle.add_argument(
        "--branch",
        default=os.environ.get("GROKBOT_FACTORY_CANDIDATE_BRANCH", "factory/candidate-1"),
        help="Isolated candidate branch name.",
    )
    p_cycle.add_argument("--base", default="main", help="Base branch name (default: main).")
    p_cycle.add_argument(
        "--runtime-db", action="append", default=[], help="Forbidden runtime DB path."
    )
    p_cycle.add_argument(
        "--credentials-file",
        action="append",
        default=[],
        help="Forbidden runtime credentials path.",
    )
    p_cycle.add_argument("--output-dir", default=None, help="Optional artifact directory.")
    p_cycle.add_argument("--manifest-out", default=None, help="Optional rollback manifest output.")
    p_cycle.add_argument("--max-attempts", type=int, default=2, help="Max attempts for item.")
    p_cycle.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_audit = sub.add_parser("audit-branch", help="Audit an existing candidate branch diff.")
    p_audit.add_argument("--repo", required=True, help="Path to isolated lab git repo.")
    p_audit.add_argument("--db", required=True, help="Path to isolated factory SQLite DB.")
    p_audit.add_argument(
        "--branch",
        default=os.environ.get("GROKBOT_FACTORY_CANDIDATE_BRANCH", ""),
        required=not bool(os.environ.get("GROKBOT_FACTORY_CANDIDATE_BRANCH")),
        help="Candidate branch name to audit.",
    )
    p_audit.add_argument("--base", default="main", help="Base branch name (default: main).")
    p_audit.add_argument(
        "--runtime-db", action="append", default=[], help="Forbidden runtime DB path."
    )
    p_audit.add_argument(
        "--credentials-file",
        action="append",
        default=[],
        help="Forbidden runtime credentials path.",
    )
    p_audit.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_rb = sub.add_parser("rollback", help="Restore lab repository from a RollbackManifest JSON.")
    p_rb.add_argument("--manifest", required=True, help="Path to rollback manifest JSON.")
    p_rb.add_argument("--repo", default=None, help="Optional repository path override.")
    p_rb.add_argument("--db", default=None, help="Optional factory DB path.")
    p_rb.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_status = sub.add_parser("status", help="Inspect factory backlog, budgets, and lessons.")
    p_status.add_argument("--db", required=True, help="Path to isolated factory SQLite DB.")
    p_status.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_resume = sub.add_parser(
        "resume",
        help="Resume or inspect persisted factory state without resetting counters.",
    )
    p_resume.add_argument("--db", required=True, help="Path to isolated factory SQLite DB.")
    p_resume.add_argument("--repo", default=None, help="Optional isolated lab git repo path.")
    p_resume.add_argument("--output-dir", default=None, help="Optional artifact directory.")
    p_resume.add_argument("--max-steps", type=int, default=None, help="Optional max step limit.")
    p_resume.add_argument("--json", action="store_true", help="Emit JSON output.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "demo":
            summary = run_factory_demo(
                repo_dir=Path(args.repo) if args.repo else None,
                db_path=Path(args.db) if args.db else None,
                output_dir=Path(args.output_dir) if args.output_dir else None,
            )
            print(json.dumps(summary, indent=2, default=str))
            return 0 if summary["ok"] else 1

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

        if args.command == "audit-branch":
            store = FactoryStore(
                args.db,
                forbidden_db_paths=args.runtime_db,
                forbidden_credential_paths=args.credentials_file,
            )
            engine = FactoryEngine(
                args.repo,
                store,
                base_branch=args.base,
                forbidden_db_paths=args.runtime_db,
                forbidden_credential_paths=args.credentials_file,
            )
            audit_res = engine.audit_branch(args.branch, base_branch=args.base)
            print(json.dumps(audit_res, indent=2, default=str))
            return 0

        if args.command == "cycle":
            store = FactoryStore(
                args.db,
                forbidden_db_paths=args.runtime_db,
                forbidden_credential_paths=args.credentials_file,
            )
            engine = FactoryEngine(
                args.repo,
                store,
                base_branch=args.base,
                forbidden_db_paths=args.runtime_db,
                forbidden_credential_paths=args.credentials_file,
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
