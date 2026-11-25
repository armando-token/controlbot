"""Declarative installation configuration validator for Grokbot-clon (M8 / F17)."""

from __future__ import annotations

import argparse
import importlib
import ipaddress
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, ValidationError, field_validator, model_validator
from src.adapters.config import load_facility_config
from src.adapters.sessions import OriginNotAllowedError
from src.contracts.budgets import BudgetConfig
from src.contracts.common import FrozenModel, HttpOrigin, NonEmptyStr
from src.contracts.enums import BackendMode
from src.model.http_client import validate_local_model_origin

_REPO_ROOT = Path(__file__).resolve().parent.parent


class DeployConfigError(ValueError):
    """Raised when a declarative deployment configuration fails fail-closed validation."""


class StorageDeployConfig(FrozenModel):
    """Persistent storage and Playwright profile paths for offline/pilot deployment."""

    sqlite_wal_path: NonEmptyStr
    profile_root: NonEmptyStr
    busy_timeout_ms: int = Field(default=5000, ge=1000, le=60000)


class LocalModelEndpointConfig(FrozenModel):
    """Pinned local inference server configuration."""

    enabled: bool = True
    backend_mode: BackendMode = BackendMode.LOCAL_HTTP
    origin: HttpOrigin
    endpoint_path: NonEmptyStr = "/v1/chat/completions"
    model_id: NonEmptyStr
    quantization: NonEmptyStr = "Q4_K_M"
    prompt_template: NonEmptyStr = "chatml-json-tools-v1"
    weights_sha256: str | None = None
    allow_private_lan: bool = False

    @field_validator("endpoint_path")
    @classmethod
    def _validate_endpoint_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError(f"endpoint_path must start with '/', got {value!r}")
        return value

    @model_validator(mode="after")
    def _validate_origin_local(self) -> LocalModelEndpointConfig:
        validate_local_model_origin(
            self.origin,
            allow_private_lan=self.allow_private_lan,
        )
        return self


class PermissionPolicy(FrozenModel):
    """Default operator permissions and egress/factory isolation policy."""

    read_only_default: bool = True
    granted_permissions: tuple[NonEmptyStr, ...]
    factory_isolated: bool = True
    allow_external_egress: bool = False

    @field_validator("granted_permissions")
    @classmethod
    def _validate_non_empty_permissions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("granted_permissions must include at least one permission.")
        return value

    @model_validator(mode="after")
    def _enforce_offline_isolation(self) -> PermissionPolicy:
        if self.allow_external_egress:
            raise ValueError(
                "allow_external_egress must be False for offline/LAN pilot deployments."
            )
        if not self.factory_isolated:
            raise ValueError("factory_isolated must be True to isolate M7 software factory.")
        return self


class OfflineOpsConfig(FrozenModel):
    """Offline artifact and egress-blocking settings."""

    egress_blocked: bool = True
    pre_cached_wheels_dir: NonEmptyStr
    playwright_browsers_path: NonEmptyStr

    @model_validator(mode="after")
    def _enforce_egress_blocked(self) -> OfflineOpsConfig:
        if not self.egress_blocked:
            raise ValueError("egress_blocked must be True for offline deployments.")
        return self


def _validate_bind_address(bind_address: str, *, allow_private_lan: bool) -> None:
    host = bind_address.strip().lower()
    if host in {"localhost", "localhost.localdomain"}:
        return
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(
            f"bind_address {bind_address!r} must be a loopback IP or 'localhost'."
        ) from exc

    if ip.is_loopback:
        return
    if (
        allow_private_lan
        and not ip.is_unspecified
        and not ip.is_multicast
        and (ip.is_private or ip.is_link_local)
    ):
        return
    raise ValueError(
        f"bind_address {bind_address!r} is not allowed (wildcard 0.0.0.0 and public IPs blocked)."
    )


class DeployInstallConfig(FrozenModel):
    """Top-level declarative installation configuration for Grokbot-clon."""

    schema_version: NonEmptyStr = "1.0.0"
    policy_version: NonEmptyStr
    backend_mode: BackendMode = BackendMode.LOCAL_HTTP
    environment: Literal["lab_offline", "pilot_offline"] = "lab_offline"
    host_os_target: Literal["linux"] = "linux"
    bind_address: NonEmptyStr = "127.0.0.1"
    web_port: int = Field(default=8000, ge=1, le=65535)
    ports: dict[str, int] = Field(
        default_factory=lambda: {
            "web": 8000,
            "scada": 8101,
            "maintenance": 8102,
            "effect_sim": 8103,
            "local_llm": 8080,
        }
    )
    facility_config_path: NonEmptyStr = "lab/configs/facility_a.json"
    allow_private_lan_origins: bool = False
    allowed_origins: tuple[HttpOrigin, ...]
    storage_path: NonEmptyStr = "/var/lib/grokbot/grokbot.sqlite3"
    storage: StorageDeployConfig
    local_model: LocalModelEndpointConfig | None = None
    permissions: PermissionPolicy
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    budgets: BudgetConfig = Field(default_factory=BudgetConfig)
    offline_ops: OfflineOpsConfig = Field(
        default_factory=lambda: OfflineOpsConfig(
            egress_blocked=True,
            pre_cached_wheels_dir="/opt/grokbot/wheelhouse",
            playwright_browsers_path="/opt/grokbot/ms-playwright",
        )
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_aliases(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        data = dict(value)
        if "budget" in data and "budgets" not in data:
            data["budgets"] = data["budget"]
        elif "budgets" in data and "budget" not in data:
            data["budget"] = data["budgets"]

        if "storage_path" in data and "storage" not in data:
            raw_sp = data["storage_path"]
            if isinstance(raw_sp, str) and raw_sp.strip():
                data["storage"] = {
                    "sqlite_wal_path": raw_sp.strip(),
                    "profile_root": "/var/lib/grokbot/profiles",
                }
        elif (
            "storage" in data
            and isinstance(data["storage"], Mapping)
            and "storage_path" not in data
            and isinstance(data["storage"].get("sqlite_wal_path"), str)
        ):
            data["storage_path"] = data["storage"]["sqlite_wal_path"]

        if isinstance(data.get("permissions"), list):
            data["permissions"] = {
                "read_only_default": True,
                "granted_permissions": tuple(str(p) for p in data["permissions"]),
                "factory_isolated": True,
                "allow_external_egress": False,
            }
        return data

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, value: dict[str, int]) -> dict[str, int]:
        if not value:
            raise ValueError("ports must be a non-empty mapping.")
        for svc, port in value.items():
            if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
                raise ValueError(f"Port for {svc!r} must be in 1..65535, got {port!r}")
        return value

    @model_validator(mode="after")
    def _validate_origins_and_bind(self) -> DeployInstallConfig:
        if not self.allowed_origins:
            raise ValueError("allowed_origins must contain at least one configured origin.")
        _validate_bind_address(
            self.bind_address,
            allow_private_lan=self.allow_private_lan_origins,
        )
        for origin in self.allowed_origins:
            validate_local_model_origin(
                origin,
                allow_private_lan=self.allow_private_lan_origins,
            )
        return self


def _parse_mapping_file(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DeployConfigError(f"Cannot read deployment config {path}: {exc}") from exc

    parsed: Any
    if path.suffix.lower() == ".json":
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            raise DeployConfigError(f"Invalid JSON in deployment config {path}: {exc}") from exc
    else:
        yaml_mod = importlib.import_module("yaml")
        safe_load_fn = yaml_mod.safe_load
        try:
            parsed = safe_load_fn(text)
        except Exception as exc:
            raise DeployConfigError(f"Invalid YAML in deployment config {path}: {exc}") from exc

    if not isinstance(parsed, dict):
        raise DeployConfigError(
            f"Deployment config {path} must decode to a mapping/object."
        )
    return dict(parsed)


def _resolve_facility_path(raw_path: str, *, repo_root: Path | None = None) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    base = repo_root if repo_root is not None else _REPO_ROOT
    resolved = base / candidate
    if resolved.exists():
        return resolved
    return Path.cwd() / candidate


def validate_deploy_config(
    raw: Mapping[str, Any],
    *,
    verify_facility: bool = False,
    repo_root: Path | None = None,
) -> DeployInstallConfig:
    """Validate raw deployment config mapping and optionally cross-check FacilityConfig."""
    try:
        config = DeployInstallConfig.model_validate(dict(raw))
    except (ValidationError, OriginNotAllowedError, ValueError) as exc:
        raise DeployConfigError(f"Deployment config validation failed: {exc}") from exc

    if verify_facility:
        facility_path = _resolve_facility_path(config.facility_config_path, repo_root=repo_root)
        if not facility_path.exists():
            raise DeployConfigError(
                f"Configured facility_config_path does not exist: {facility_path}"
            )
        try:
            facility = load_facility_config(facility_path)
        except (OSError, ValueError, ValidationError) as exc:
            raise DeployConfigError(
                f"Invalid facility_config_path {facility_path}: {exc}"
            ) from exc

        if not facility.apps:
            raise DeployConfigError(
                f"Facility config {facility_path} defines zero configured apps."
            )

        allowed_set = set(config.allowed_origins)
        for app_id, app_cfg in facility.apps.items():
            try:
                validate_local_model_origin(
                    app_cfg.origin,
                    allow_private_lan=config.allow_private_lan_origins,
                )
            except OriginNotAllowedError as exc:
                raise DeployConfigError(
                    f"Facility app {app_id!r} origin {app_cfg.origin!r} rejected: {exc}"
                ) from exc
            if app_cfg.origin not in allowed_set:
                raise DeployConfigError(
                    f"Facility app {app_id!r} origin {app_cfg.origin!r} is missing from "
                    f"deploy allowed_origins {sorted(allowed_set)}."
                )

    return config


def load_deploy_config(
    path: Path | str,
    *,
    verify_facility: bool = True,
    repo_root: Path | None = None,
) -> DeployInstallConfig:
    """Load and validate a YAML/JSON DeployInstallConfig from disk."""
    config_path = Path(path)
    if not config_path.exists():
        raise DeployConfigError(f"Deployment config not found: {config_path}")
    raw = _parse_mapping_file(config_path)
    return validate_deploy_config(raw, verify_facility=verify_facility, repo_root=repo_root)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Grokbot-clon deployment config.")
    parser.add_argument(
        "--config",
        default="deploy/install_config.yaml",
        help="Path to YAML/JSON installation config (default: deploy/install_config.yaml).",
    )
    parser.add_argument(
        "--root-dir",
        default=None,
        help="Optional repository root for resolving relative facility_config_path.",
    )
    parser.add_argument(
        "--no-verify-facility",
        action="store_true",
        help="Skip cross-checking facility_config_path origins.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print validated config as JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `python -m deploy.config`."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        root_dir = Path(args.root_dir) if args.root_dir else None
        cfg = load_deploy_config(
            args.config,
            verify_facility=not args.no_verify_facility,
            repo_root=root_dir,
        )
    except (DeployConfigError, OSError, ValueError) as exc:
        print(f"Deploy config invalid: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(cfg.model_dump_json(indent=2))
    else:
        origins_str = ", ".join(cfg.allowed_origins)
        model_origin = cfg.local_model.origin if cfg.local_model is not None else "none"
        print(
            f"Deploy config valid: env={cfg.environment}, "
            f"backend_mode={cfg.backend_mode.value}, "
            f"policy_version={cfg.policy_version}, "
            f"bind={cfg.bind_address}:{cfg.web_port}, "
            f"allowed_origins=[{origins_str}], "
            f"model={model_origin}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
