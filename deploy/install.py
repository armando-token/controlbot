"""State-preserving offline install/upgrade entrypoint for Grokbot-clon (M8 / F17)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from deploy.config import DeployConfigError
from deploy.package import (
    ManifestError,
    create_release_manifest,
    write_release_manifest,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install or upgrade Grokbot-clon release manifest without touching WAL state."
    )
    parser.add_argument(
        "--config",
        default="deploy/install_config.yaml",
        help="Path to declarative install config (default: deploy/install_config.yaml).",
    )
    parser.add_argument(
        "--db",
        default=os.environ.get("GROKBOT_DB_PATH", ""),
        help="Optional SQLite WAL database path to preserve untouched.",
    )
    parser.add_argument(
        "--target",
        default=os.environ.get("GROKBOT_DEPLOY_TARGET", ""),
        help="Target deployment staging directory.",
    )
    parser.add_argument(
        "--manifest-dir",
        default=os.environ.get("GROKBOT_MANIFEST_DIR", ""),
        help="Directory to write release_manifest.json and current_release.json.",
    )
    parser.add_argument(
        "--root-dir",
        default=str(_REPO_ROOT),
        help="Repository root directory.",
    )
    parser.add_argument("--version", default="0.1.0", help="Semantic release version.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `python -m deploy.install`."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    root_dir = Path(args.root_dir).resolve()
    raw_cfg = Path(args.config)
    cfg_path = raw_cfg if raw_cfg.is_absolute() else (root_dir / raw_cfg)

    manifest_dir_str = (
        str(args.manifest_dir).strip()
        or str(args.target).strip()
        or str(_REPO_ROOT / "deploy")
    )
    manifest_dir = Path(manifest_dir_str).resolve()
    manifest_out = manifest_dir / "release_manifest.json"
    releases_dir = Path(str(args.target).strip()).resolve() if str(args.target).strip() else None

    try:
        manifest = create_release_manifest(
            root_dir=root_dir,
            install_config_path=cfg_path,
            version=args.version,
            previous_manifest_path=manifest_out if manifest_out.exists() else None,
            verify_facility=True,
        )
        db_str = str(args.db).strip()
        if db_str:
            merged_preserve = tuple(dict.fromkeys((*manifest.state_preserve_paths, db_str)))
            manifest = manifest.model_copy(update={"state_preserve_paths": merged_preserve})

        written = write_release_manifest(
            manifest,
            manifest_out,
            releases_dir=releases_dir,
        )
    except (DeployConfigError, ManifestError, OSError, ValueError) as exc:
        print(f"Install failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(manifest.model_dump_json(indent=2))
    else:
        print(
            f"Installed release {manifest.release_id} "
            f"(preserved={len(manifest.state_preserve_paths)}, "
            f"n3_status={manifest.n3_status}) -> {written}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
