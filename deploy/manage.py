"""Deployment lifecycle management CLI (`python -m deploy.manage`) (M8 / F17)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from deploy.config import DeployConfigError, load_deploy_config
from deploy.package import (
    ManifestError,
    create_release_manifest,
    write_release_manifest,
)
from deploy.rollback import RollbackError, execute_rollback

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m deploy.manage",
        description="Manage staged offline Grokbot-clon release upgrades and rollbacks.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ur = sub.add_parser(
        "upgrade-and-rollback",
        help="Stage an upgrade manifest in --work-dir and verify state-preserving rollback.",
    )
    p_ur.add_argument(
        "--config",
        required=True,
        help="Path to declarative deployment configuration (YAML/JSON).",
    )
    p_ur.add_argument(
        "--db-path",
        required=True,
        help="Path to runtime SQLite WAL DB to preserve untouched across upgrade/rollback.",
    )
    p_ur.add_argument(
        "--work-dir",
        required=True,
        help="Staging directory for release manifests and rollback pointers.",
    )
    p_ur.add_argument(
        "--root-dir",
        default=None,
        help="Optional project root directory (defaults to repository root).",
    )
    p_ur.add_argument("--json", action="store_true", help="Emit JSON summary.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `python -m deploy.manage`."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "upgrade-and-rollback":
        try:
            root_dir = Path(args.root_dir).resolve() if args.root_dir else _REPO_ROOT
            config_path = Path(args.config).resolve()
            db_path = Path(args.db_path).resolve()
            work_dir = Path(args.work_dir).resolve()
            work_dir.mkdir(parents=True, exist_ok=True)
            releases_dir = work_dir / "releases"

            load_deploy_config(config_path, verify_facility=True, repo_root=root_dir)

            base_manifest = create_release_manifest(
                root_dir=root_dir,
                install_config_path=config_path,
                version="0.1.0",
                release_id="rel-0.1.0-base",
                verify_facility=True,
            )
            preserve_paths = tuple(
                dict.fromkeys((*base_manifest.state_preserve_paths, str(db_path)))
            )
            base_manifest = base_manifest.model_copy(
                update={"state_preserve_paths": preserve_paths}
            )
            base_ptr = write_release_manifest(
                base_manifest,
                work_dir / "base_manifest.json",
                releases_dir=releases_dir,
            )

            upgrade_manifest = create_release_manifest(
                root_dir=root_dir,
                install_config_path=config_path,
                version="0.2.0",
                release_id="rel-0.2.0-upgrade",
                previous_manifest_path=base_ptr,
                verify_facility=True,
            ).model_copy(update={"state_preserve_paths": preserve_paths})
            write_release_manifest(
                upgrade_manifest,
                work_dir / "upgrade_manifest.json",
                releases_dir=releases_dir,
            )

            rb_result = execute_rollback(
                releases_dir=releases_dir,
                root_dir=root_dir,
                state_dir=work_dir,
                verify_checksums=True,
            )
        except (DeployConfigError, ManifestError, RollbackError, OSError, ValueError) as exc:
            print(f"Deploy manage error: {exc}", file=sys.stderr)
            return 1

        payload = {
            "ok": rb_result.ok,
            "staged_upgrade_release_id": upgrade_manifest.release_id,
            "rolled_back_to_release_id": rb_result.rolled_back_to_release_id,
            "verified_artifacts_count": rb_result.verified_artifacts_count,
            "preserved_state_paths": list(rb_result.preserved_state_paths),
            "state_preserved": rb_result.state_preserved,
            "work_dir": str(work_dir),
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(
                f"Upgrade & rollback ok: {upgrade_manifest.release_id} -> "
                f"{rb_result.rolled_back_to_release_id} "
                f"(verified={rb_result.verified_artifacts_count}, "
                f"state_preserved={rb_result.state_preserved})"
            )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
