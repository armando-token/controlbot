"""Deterministic SHA-256 release packaging and manifest management (M8 / F17)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError
from src.contracts.common import FrozenModel, NonEmptyStr, UtcDatetime, utc_now
from src.n3_probe import run_n3_probe

from deploy.config import DeployConfigError, _resolve_facility_path, load_deploy_config

_DEFAULT_ARTIFACT_ROOTS: tuple[str, ...] = (
    "pyproject.toml",
    "uv.lock",
    "deploy",
    "lab/configs",
    "src",
)


class ManifestError(ValueError):
    """Raised when a release manifest cannot be read, parsed, or validated."""


class ArtifactChecksum(FrozenModel):
    """SHA-256 digest and byte size for a single packaged file."""

    relative_path: NonEmptyStr
    sha256: NonEmptyStr
    size_bytes: int = Field(ge=0)


class ReleaseManifest(FrozenModel):
    """Versioned, chain-linked release manifest with preserved runtime state paths."""

    schema_version: NonEmptyStr = "1.0.0"
    release_id: NonEmptyStr
    version: NonEmptyStr
    git_commit: NonEmptyStr
    created_at: UtcDatetime
    install_config_path: NonEmptyStr
    install_config_sha256: NonEmptyStr
    facility_config_path: NonEmptyStr
    facility_config_sha256: NonEmptyStr
    previous_release_id: str | None = None
    previous_manifest_path: str | None = None
    state_preserve_paths: tuple[NonEmptyStr, ...]
    artifacts: tuple[ArtifactChecksum, ...]
    n3_status: Literal["PENDING_N3_LINUX_ENV", "PENDING_LOCAL_LLM", "READY"]


def compute_sha256(file_path: Path) -> str:
    """Compute lowercase hexadecimal SHA-256 digest for a file."""
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_head_sha(root_dir: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(root_dir), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return "uncommitted"


def _collect_artifact_files(
    root_dir: Path,
    artifact_globs: Sequence[str] | None,
) -> list[Path]:
    targets = list(artifact_globs) if artifact_globs is not None else list(_DEFAULT_ARTIFACT_ROOTS)
    collected: set[Path] = set()
    for entry in targets:
        candidate = root_dir / entry
        if any(ch in entry for ch in "*?[]"):
            for match in root_dir.glob(entry):
                if match.is_file():
                    collected.add(match.resolve())
            continue
        if candidate.is_file():
            collected.add(candidate.resolve())
        elif candidate.is_dir():
            for child in candidate.rglob("*"):
                if not child.is_file():
                    continue
                if "__pycache__" in child.parts or child.suffix == ".pyc":
                    continue
                collected.add(child.resolve())

    resolved_root = root_dir.resolve()
    rel_sorted = sorted(
        (p for p in collected if p.is_relative_to(resolved_root)),
        key=lambda p: p.relative_to(resolved_root).as_posix(),
    )
    return rel_sorted


def load_release_manifest(manifest_path: Path | str) -> ReleaseManifest:
    """Load and validate a ReleaseManifest JSON file; raises ManifestError on failure."""
    path = Path(manifest_path)
    if not path.exists():
        raise ManifestError(f"Release manifest not found: {path}")
    if not path.is_file():
        raise ManifestError(f"Release manifest path is not a file: {path}")
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"Cannot read release manifest {path}: {exc}") from exc
    if not raw_text.strip():
        raise ManifestError(f"Release manifest is empty: {path}")
    try:
        parsed = json.loads(raw_text)
    except ValueError as exc:
        raise ManifestError(f"Corrupt JSON in release manifest {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ManifestError(f"Release manifest {path} must be a JSON object.")
    try:
        return ReleaseManifest.model_validate(parsed)
    except ValidationError as exc:
        raise ManifestError(f"Invalid release manifest schema in {path}: {exc}") from exc


def create_release_manifest(
    *,
    root_dir: Path,
    install_config_path: Path,
    version: str = "0.1.0",
    release_id: str | None = None,
    artifact_globs: Sequence[str] | None = None,
    previous_manifest_path: Path | None = None,
    verify_facility: bool = True,
) -> ReleaseManifest:
    """Validate config, hash artifacts deterministically, and build a ReleaseManifest."""
    resolved_root = root_dir.resolve()
    resolved_install = (
        install_config_path
        if install_config_path.is_absolute()
        else (resolved_root / install_config_path)
    )
    cfg = load_deploy_config(
        resolved_install,
        verify_facility=verify_facility,
        repo_root=resolved_root,
    )
    facility_path = _resolve_facility_path(cfg.facility_config_path, repo_root=resolved_root)
    if not facility_path.exists():
        raise ManifestError(f"Facility config not found for manifest: {facility_path}")

    files = _collect_artifact_files(resolved_root, artifact_globs)
    if not files:
        raise ManifestError(f"No artifacts found under {resolved_root} to package.")

    artifacts = tuple(
        ArtifactChecksum(
            relative_path=f.relative_to(resolved_root).as_posix(),
            sha256=compute_sha256(f),
            size_bytes=f.stat().st_size,
        )
        for f in files
    )

    prev_id: str | None = None
    prev_path_str: str | None = None
    if previous_manifest_path is not None and previous_manifest_path.exists():
        prev_manifest = load_release_manifest(previous_manifest_path)
        prev_id = prev_manifest.release_id
        prev_path_str = str(previous_manifest_path.resolve())

    commit = _git_head_sha(resolved_root)
    now = utc_now()
    eff_release_id = release_id or f"rel-{version}-{commit[:8]}-{now.strftime('%Y%m%dT%H%M%SZ')}"

    n3_status: Literal["PENDING_N3_LINUX_ENV", "PENDING_LOCAL_LLM", "READY"]
    if platform.system() != "Linux":
        n3_status = "PENDING_N3_LINUX_ENV"
    else:
        n3_status = run_n3_probe().overall_status

    preserve_paths = (
        cfg.storage.sqlite_wal_path,
        cfg.storage.profile_root,
    )

    try:
        rel_install = resolved_install.resolve().relative_to(resolved_root).as_posix()
    except ValueError:
        rel_install = str(resolved_install)
    try:
        rel_facility = facility_path.resolve().relative_to(resolved_root).as_posix()
    except ValueError:
        rel_facility = str(facility_path)

    return ReleaseManifest(
        release_id=eff_release_id,
        version=version,
        git_commit=commit,
        created_at=now,
        install_config_path=rel_install,
        install_config_sha256=compute_sha256(resolved_install),
        facility_config_path=rel_facility,
        facility_config_sha256=compute_sha256(facility_path),
        previous_release_id=prev_id,
        previous_manifest_path=prev_path_str,
        state_preserve_paths=preserve_paths,
        artifacts=artifacts,
        n3_status=n3_status,
    )


def _atomic_write_text(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp_manifest_", dir=str(target.parent))
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


def write_release_manifest(
    manifest: ReleaseManifest,
    output_path: Path,
    *,
    releases_dir: Path | None = None,
    update_current: bool = True,
) -> Path:
    """Atomically write ReleaseManifest JSON and optionally update releases_dir pointers."""
    payload = manifest.model_dump_json(indent=2) + "\n"
    _atomic_write_text(output_path, payload)

    pointer_manifest_path = output_path.resolve()
    if releases_dir is not None:
        rel_manifest = releases_dir / manifest.release_id / "manifest.json"
        _atomic_write_text(rel_manifest, payload)
        pointer_manifest_path = rel_manifest.resolve()
        if update_current:
            current_ptr = releases_dir / "current_release.json"
            prev_id = manifest.previous_release_id
            prev_manifest = manifest.previous_manifest_path
            if current_ptr.exists() and prev_id is None:
                try:
                    existing = json.loads(current_ptr.read_text(encoding="utf-8"))
                    if isinstance(existing, dict):
                        prev_id = existing.get("release_id")
                        prev_manifest = existing.get("manifest_path")
                except (OSError, ValueError):
                    pass
            ptr_payload = json.dumps(
                {
                    "release_id": manifest.release_id,
                    "version": manifest.version,
                    "manifest_path": str(pointer_manifest_path),
                    "previous_release_id": prev_id,
                    "previous_manifest_path": prev_manifest,
                    "updated_at": utc_now().isoformat(),
                },
                indent=2,
            )
            _atomic_write_text(current_ptr, ptr_payload + "\n")

    return pointer_manifest_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Package Grokbot-clon release manifest.")
    parser.add_argument(
        "--config",
        default="deploy/install_config.yaml",
        help="Path to installation config YAML/JSON.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output path for generated release manifest JSON.",
    )
    parser.add_argument(
        "--root-dir",
        default=".",
        help="Project root directory (default: .).",
    )
    parser.add_argument("--version", default="0.1.0", help="Semantic release version.")
    parser.add_argument("--release-id", default=None, help="Explicit release_id.")
    parser.add_argument(
        "--releases-dir",
        default=None,
        help="Optional releases directory for versioned manifests & current_release.json.",
    )
    parser.add_argument(
        "--previous-manifest",
        default=None,
        help="Optional path to previous release manifest for chain linking.",
    )
    parser.add_argument(
        "--no-verify-facility",
        action="store_true",
        help="Skip facility config origin cross-check.",
    )
    parser.add_argument("--json", action="store_true", help="Print manifest JSON to stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `python -m deploy.package`."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        manifest = create_release_manifest(
            root_dir=Path(args.root_dir),
            install_config_path=Path(args.config),
            version=args.version,
            release_id=args.release_id,
            previous_manifest_path=Path(args.previous_manifest) if args.previous_manifest else None,
            verify_facility=not args.no_verify_facility,
        )
        written = write_release_manifest(
            manifest,
            Path(args.output),
            releases_dir=Path(args.releases_dir) if args.releases_dir else None,
        )
    except (DeployConfigError, ManifestError, OSError, ValueError) as exc:
        print(f"Packaging failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(manifest.model_dump_json(indent=2))
    else:
        print(
            f"Packaged release {manifest.release_id} ({len(manifest.artifacts)} artifacts, "
            f"n3_status={manifest.n3_status}) -> {written}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
