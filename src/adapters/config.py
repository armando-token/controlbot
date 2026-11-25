"""Declarative facility configuration models, loader, and asset alias resolver."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import Field

from src.contracts.common import FrozenModel, HttpOrigin, NonEmptyStr, validate_http_origin


class TimeWindowConfig(FrozenModel):
    """Authorized observation window and staleness thresholds."""

    max_staleness_seconds: float = Field(default=3600.0, gt=0.0)
    lookback_seconds: float = Field(default=7200.0, gt=0.0)
    timezone: NonEmptyStr = "UTC"


class AreaConfig(FrozenModel):
    """Facility area metadata."""

    display_name: NonEmptyStr


class AssetMapping(FrozenModel):
    """Canonical asset identity, aliases, allowed units, and per-source IDs."""

    asset_id: NonEmptyStr
    area: NonEmptyStr
    canonical_label: NonEmptyStr
    aliases: tuple[NonEmptyStr, ...] = ()
    allowed_units: dict[str, tuple[NonEmptyStr, ...]] = Field(default_factory=dict)
    source_ids: dict[str, NonEmptyStr] = Field(default_factory=dict)


class LoginSelectorConfig(FrozenModel):
    """Semantic login form selectors."""

    username_label: NonEmptyStr = "Username"
    password_label: NonEmptyStr = "Password"
    submit_name: NonEmptyStr = "Sign In"
    authenticated_selector: NonEmptyStr = "[data-testid='current-user']"


class TableSelectorConfig(FrozenModel):
    """Config-driven semantic table and header-alias mapping for A12 portability."""

    table_role_name: NonEmptyStr
    row_selector: NonEmptyStr = "tbody tr"
    column_aliases: dict[str, tuple[NonEmptyStr, ...]] = Field(default_factory=dict)


class AppSelectorsConfig(FrozenModel):
    """Optional selectors block for an application."""

    login: LoginSelectorConfig | None = None
    alarms_table: TableSelectorConfig | None = None
    readings_table: TableSelectorConfig | None = None
    work_orders_table: TableSelectorConfig | None = None


class AppConfig(FrozenModel):
    """Configured external/lab application endpoint and permissions."""

    app_id: NonEmptyStr
    adapter_type: NonEmptyStr
    adapter_version: NonEmptyStr = "1.0.0"
    origin: HttpOrigin
    read_only: bool = True
    permissions: tuple[NonEmptyStr, ...] = ()
    routes: dict[str, NonEmptyStr] = Field(default_factory=dict)
    selectors: AppSelectorsConfig = Field(default_factory=AppSelectorsConfig)


class FacilityConfig(FrozenModel):
    """Declarative installation configuration for an industrial facility."""

    schema_version: NonEmptyStr = "1.0.0"
    facility_id: NonEmptyStr
    facility_name: NonEmptyStr
    time_window: TimeWindowConfig = Field(default_factory=TimeWindowConfig)
    areas: dict[str, AreaConfig] = Field(default_factory=dict)
    assets: tuple[AssetMapping, ...] = ()
    apps: dict[str, AppConfig] = Field(default_factory=dict)


InstallationConfig = FacilityConfig


def load_facility_config(
    path: Path | str,
    origin_overrides: Mapping[str, str] | None = None,
) -> FacilityConfig:
    """Load and validate a FacilityConfig JSON file with optional per-app origin overrides."""
    config_path = Path(path)
    raw_data: dict[str, Any] = json.loads(config_path.read_text(encoding="utf-8"))
    if origin_overrides:
        apps_raw = raw_data.get("apps", {})
        for app_id, override_origin in origin_overrides.items():
            if app_id in apps_raw and isinstance(apps_raw[app_id], dict):
                apps_raw[app_id]["origin"] = validate_http_origin(override_origin)
    config = FacilityConfig.model_validate(raw_data)
    for asset in config.assets:
        if config.areas and asset.area not in config.areas:
            raise ValueError(
                f"Asset {asset.asset_id!r} references unknown area {asset.area!r}."
            )
    return config


load_installation_config = load_facility_config


def resolve_asset_candidates(
    config: FacilityConfig,
    label_or_id: str,
    area: str | None = None,
) -> list[AssetMapping]:
    """Return matching AssetMappings for a query label or asset_id, optionally scoped by area."""
    needle = label_or_id.strip().lower()
    if not needle:
        return []
    matches: list[AssetMapping] = []
    for asset in config.assets:
        if area is not None and asset.area != area:
            continue
        candidates = {
            asset.asset_id.lower(),
            asset.canonical_label.lower(),
            *(alias.lower() for alias in asset.aliases),
            *(src_id.lower() for src_id in asset.source_ids.values()),
        }
        if needle in candidates:
            matches.append(asset)
    return matches


def resolve_source_query_params(
    config: FacilityConfig,
    app_id: str,
    *,
    asset_query: str | None = None,
    asset_id: str | None = None,
    area: str | None = None,
) -> tuple[dict[str, str], list[AssetMapping]]:
    """Resolve asset_query / asset_id aliases & source_ids into HTTP query parameters."""
    params: dict[str, str] = {}
    candidates: list[AssetMapping] = []
    if asset_id:
        candidates = resolve_asset_candidates(config, asset_id, area=area)
        if len(candidates) == 1:
            src_id = candidates[0].source_ids.get(app_id)
            params["asset_id"] = src_id if src_id else asset_id
        else:
            params["asset_id"] = asset_id
    elif asset_query:
        candidates = resolve_asset_candidates(config, asset_query, area=area)
        if len(candidates) == 1:
            mapping = candidates[0]
            src_id = mapping.source_ids.get(app_id)
            if src_id and src_id != mapping.asset_id:
                params["asset_id"] = src_id
            else:
                params["asset"] = mapping.canonical_label
        elif len(candidates) >= 2:
            distinct_labels = {c.canonical_label.lower(): c.canonical_label for c in candidates}
            if len(distinct_labels) == 1:
                params["asset"] = next(iter(distinct_labels.values()))
        else:
            params["asset"] = asset_query
    if area:
        params["area"] = area
    return params, candidates
