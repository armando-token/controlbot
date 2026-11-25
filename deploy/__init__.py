"""Offline deployment configuration, deterministic packaging, and state-preserving rollback."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from deploy.config import (
        DeployConfigError,
        DeployInstallConfig,
        LocalModelEndpointConfig,
        OfflineOpsConfig,
        PermissionPolicy,
        StorageDeployConfig,
        load_deploy_config,
        validate_deploy_config,
    )
    from deploy.package import (
        ArtifactChecksum,
        ManifestError,
        ReleaseManifest,
        compute_sha256,
        create_release_manifest,
        load_release_manifest,
        write_release_manifest,
    )
    from deploy.rollback import RollbackError, RollbackResult, execute_rollback

_EXPORTS: dict[str, tuple[str, str]] = {
    "ArtifactChecksum": ("deploy.package", "ArtifactChecksum"),
    "DeployConfigError": ("deploy.config", "DeployConfigError"),
    "DeployInstallConfig": ("deploy.config", "DeployInstallConfig"),
    "LocalModelEndpointConfig": ("deploy.config", "LocalModelEndpointConfig"),
    "ManifestError": ("deploy.package", "ManifestError"),
    "OfflineOpsConfig": ("deploy.config", "OfflineOpsConfig"),
    "PermissionPolicy": ("deploy.config", "PermissionPolicy"),
    "ReleaseManifest": ("deploy.package", "ReleaseManifest"),
    "RollbackError": ("deploy.rollback", "RollbackError"),
    "RollbackResult": ("deploy.rollback", "RollbackResult"),
    "StorageDeployConfig": ("deploy.config", "StorageDeployConfig"),
    "compute_sha256": ("deploy.package", "compute_sha256"),
    "create_release_manifest": ("deploy.package", "create_release_manifest"),
    "execute_rollback": ("deploy.rollback", "execute_rollback"),
    "load_deploy_config": ("deploy.config", "load_deploy_config"),
    "load_release_manifest": ("deploy.package", "load_release_manifest"),
    "validate_deploy_config": ("deploy.config", "validate_deploy_config"),
    "write_release_manifest": ("deploy.package", "write_release_manifest"),
}

__all__ = [
    "ArtifactChecksum",
    "DeployConfigError",
    "DeployInstallConfig",
    "LocalModelEndpointConfig",
    "ManifestError",
    "OfflineOpsConfig",
    "PermissionPolicy",
    "ReleaseManifest",
    "RollbackError",
    "RollbackResult",
    "StorageDeployConfig",
    "compute_sha256",
    "create_release_manifest",
    "execute_rollback",
    "load_deploy_config",
    "load_release_manifest",
    "validate_deploy_config",
    "write_release_manifest",
]


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod_name, attr_name = target
    mod = importlib.import_module(mod_name)
    return getattr(mod, attr_name)
