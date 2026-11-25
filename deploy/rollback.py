"""State-preserving release rollback for Grokbot-clon (M8 / F17)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from pydantic import Field
from src.contracts.common import FrozenModel, NonEmptyStr, UtcDatetime, utc_now

from deploy.config import DeployConfigError
from deploy.package import ManifestError, compute_sha256, load_release_manifest


class RollbackError(RuntimeError):
    """Raised when rollback verification or pointer restoration fails."""


class RollbackResult(FrozenModel):
    """Structured result of a state-preserving release rollback."""

    ok: bool
    rolled_back_to_release_id: NonEmptyStr
    manifest_path: NonEmptyStr
    previous_active_release_id: str | None = None
    verified_artifacts_count: int = Field(ge=0)
    preserved_state_paths: tuple[str, ...]
    state_preserved: bool
    dry_run: bool
    rolled_back_at: UtcDatetime


def _atomic_write_text(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp_rollback_", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def _resolve_manifest_target(
    *,
    manifest_path: Path | None,
    releases_dir: Path | None,
    target_release_id: str | None,
) -> tuple[Path, str | None]:
    prev_active_id: str | None = None
    if releases_dir is not None:
        current_ptr = releases_dir / "current_release.json"
        if current_ptr.exists():
            try:
                raw_ptr = json.loads(current_ptr.read_text(encoding="utf-8"))
                if isinstance(raw_ptr, dict):
                    raw_active = raw_ptr.get("release_id")
                    if isinstance(raw_active, str) and raw_active.strip():
                        prev_active_id = raw_active.strip()
                    if manifest_path is None and target_release_id is None:
                        prev_manifest = raw_ptr.get("previous_manifest_path")
                        prev_rel_id = raw_ptr.get("previous_release_id")
                        if isinstance(prev_manifest, str) and prev_manifest.strip():
                            return Path(prev_manifest), prev_active_id
                        if isinstance(prev_rel_id, str) and prev_rel_id.strip():
                            return releases_dir / prev_rel_id / "manifest.json", prev_active_id
                        raise RollbackError(
                            f"Current release {prev_active_id or 'unknown'} "
                            "has no previous release."
                        )
            except ValueError as exc:
                raise RollbackError(
                    f"Corrupt current_release.json in {releases_dir}: {exc}"
                ) from exc

    if manifest_path is not None:
        return manifest_path, prev_active_id
    if releases_dir is not None and target_release_id is not None:
        return releases_dir / target_release_id / "manifest.json", prev_active_id
    raise RollbackError("Either --manifest or --releases-dir must be provided.")


def _collect_existing_state_paths(state_preserve_paths: tuple[str, ...]) -> tuple[str, ...]:
    preserved: list[str] = []
    for raw_path in state_preserve_paths:
        candidate = Path(raw_path)
        candidates = [candidate]
        # Include SQLite WAL sidecars if present alongside SQLite DB path.
        if candidate.suffix in {".db", ".sqlite", ".sqlite3"} or "sqlite" in candidate.name:
            candidates.append(Path(f"{candidate}-wal"))
            candidates.append(Path(f"{candidate}-shm"))
        for item in candidates:
            if item.exists():
                preserved.append(str(item))
    return tuple(preserved)


def execute_rollback(
    *,
    manifest_path: Path | None = None,
    releases_dir: Path | None = None,
    target_release_id: str | None = None,
    root_dir: Path | None = None,
    state_dir: Path | None = None,
    verify_checksums: bool = True,
    dry_run: bool = False,
) -> RollbackResult:
    """Verify target release manifest and switch active pointer without touching WAL/profiles."""
    resolved_manifest_path, prev_active_id = _resolve_manifest_target(
        manifest_path=manifest_path,
        releases_dir=releases_dir,
        target_release_id=target_release_id,
    )
    manifest = load_release_manifest(resolved_manifest_path)

    verified_count = 0
    if verify_checksums:
        base_dir = (root_dir or Path.cwd()).resolve()
        for item in manifest.artifacts:
            target_file = (base_dir / item.relative_path).resolve()
            if not target_file.is_relative_to(base_dir):
                raise RollbackError(
                    f"Artifact path escapes root_dir: {item.relative_path}"
                )
            if not target_file.exists():
                raise RollbackError(
                    f"Missing packaged artifact during rollback verification: {item.relative_path}"
                )
            actual_sha = compute_sha256(target_file)
            if actual_sha != item.sha256:
                raise RollbackError(
                    f"Checksum mismatch for {item.relative_path}: "
                    f"expected {item.sha256}, got {actual_sha}"
                )
            verified_count += 1

    preserved_paths = _collect_existing_state_paths(manifest.state_preserve_paths)
    now = utc_now()

    if not dry_run:
        ptr_dir = state_dir or releases_dir or resolved_manifest_path.parent
        current_ptr = ptr_dir / "current_release.json"
        ptr_payload = json.dumps(
            {
                "release_id": manifest.release_id,
                "version": manifest.version,
                "manifest_path": str(resolved_manifest_path.resolve()),
                "previous_release_id": manifest.previous_release_id,
                "previous_manifest_path": manifest.previous_manifest_path,
                "rolled_back_from_release_id": prev_active_id,
                "updated_at": now.isoformat(),
            },
            indent=2,
        )
        _atomic_write_text(current_ptr, ptr_payload + "\n")

        history_path = ptr_dir / "rollback_history.jsonl"
        history_entry = json.dumps(
            {
                "rolled_back_to_release_id": manifest.release_id,
                "previous_active_release_id": prev_active_id,
                "manifest_path": str(resolved_manifest_path.resolve()),
                "preserved_state_paths": list(preserved_paths),
                "rolled_back_at": now.isoformat(),
            }
        )
        history_path.parent.mkdir(parents=True, exist_ok=True)
        with history_path.open("a", encoding="utf-8") as handle:
            handle.write(history_entry + "\n")

    return RollbackResult(
        ok=True,
        rolled_back_to_release_id=manifest.release_id,
        manifest_path=str(resolved_manifest_path.resolve()),
        previous_active_release_id=prev_active_id,
        verified_artifacts_count=verified_count,
        preserved_state_paths=preserved_paths,
        state_preserved=True,
        dry_run=dry_run,
        rolled_back_at=now,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute state-preserving rollback for Grokbot-clon release manifest."
    )
    parser.add_argument("--manifest", default=None, help="Path to target release manifest JSON.")
    parser.add_argument(
        "--releases-dir",
        default=None,
        help="Directory holding versioned releases and current_release.json.",
    )
    parser.add_argument(
        "--target-release",
        default=None,
        help="Target release_id inside --releases-dir.",
    )
    parser.add_argument(
        "--root-dir",
        default=None,
        help="Root directory to verify packaged artifact checksums against.",
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help="Directory where current_release.json and rollback_history.jsonl are recorded.",
    )
    parser.add_argument(
        "--no-verify-checksums",
        action="store_true",
        help="Skip SHA-256 verification of packaged artifacts.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate manifest and checksums without modifying release pointers.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `python -m deploy.rollback`."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        # Never use parser.error() for runtime failures (avoids emitting 'usage:').
        result = execute_rollback(
            manifest_path=Path(args.manifest) if args.manifest else None,
            releases_dir=Path(args.releases_dir) if args.releases_dir else None,
            target_release_id=args.target_release,
            root_dir=Path(args.root_dir) if args.root_dir else None,
            state_dir=Path(args.state_dir) if args.state_dir else None,
            verify_checksums=not args.no_verify_checksums,
            dry_run=args.dry_run,
        )
    except (
        ManifestError,
        RollbackError,
        DeployConfigError,
        FileNotFoundError,
        OSError,
        ValueError,
    ) as exc:
        print(f"Rollback failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print(
            f"Rollback ok -> {result.rolled_back_to_release_id} "
            f"(verified={result.verified_artifacts_count}, "
            f"state_preserved={result.state_preserved}, dry_run={result.dry_run})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
