"""Read-only Playwright SCADA adapter implementing Megaplan §4.5 observe-validate-verify."""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from datetime import datetime
from urllib.parse import urlencode

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page

from src.adapters._common import (
    AdapterPermissionError,
    CredentialProvider,
    SourceUnavailableError,
    scrub_for_receipt,
)
from src.adapters.config import (
    AppConfig,
    FacilityConfig,
    LoginSelectorConfig,
    TableSelectorConfig,
    resolve_source_query_params,
)
from src.adapters.sessions import AuthExpiredError, ManagedSession, SessionManager
from src.contracts.common import ensure_utc, utc_now, validate_http_origin
from src.contracts.enums import DataQuality, EffectClass, ReceiptOutcome
from src.contracts.models import ActionReceipt, Observation, RetryPolicy, TaskSpec, ToolSpec


def get_scada_tool_specs(allowed_origins: Sequence[str] = ()) -> dict[str, ToolSpec]:
    """Return ToolSpec definitions for read-only SCADA observation tools."""
    origins = tuple(validate_http_origin(o) for o in allowed_origins)
    record_schema = {
        "type": "object",
        "required": ["source", "count", "records"],
        "properties": {
            "source": {"type": "string"},
            "count": {"type": "integer", "minimum": 0},
            "records": {"type": "array", "items": {"type": "object"}},
        },
    }
    return {
        "scada.read_alarms": ToolSpec(
            tool_id="scada.read_alarms",
            version="1.0.0",
            input_schema={
                "type": "object",
                "properties": {
                    "asset": {"type": "string"},
                    "asset_id": {"type": "string"},
                    "area": {"type": "string"},
                },
            },
            output_schema=record_schema,
            permissions=("scada:read",),
            allowed_origins=origins,
            effect_class=EffectClass.READ,
            timeout_s=15.0,
            verifier_name="verify_scada_observation",
            retry_policy=RetryPolicy(max_retries=1, retry_on_transient=True, backoff_seconds=0.5),
        ),
        "scada.read_readings": ToolSpec(
            tool_id="scada.read_readings",
            version="1.0.0",
            input_schema={
                "type": "object",
                "properties": {
                    "asset": {"type": "string"},
                    "asset_id": {"type": "string"},
                    "area": {"type": "string"},
                },
            },
            output_schema=record_schema,
            permissions=("scada:read",),
            allowed_origins=origins,
            effect_class=EffectClass.READ,
            timeout_s=15.0,
            verifier_name="verify_scada_observation",
            retry_policy=RetryPolicy(max_retries=1, retry_on_transient=True, backoff_seconds=0.5),
        ),
    }


def _parse_iso_utc(raw: str) -> datetime | None:
    cleaned = raw.strip()
    if not cleaned:
        return None
    if cleaned.endswith("Z"):
        cleaned = f"{cleaned[:-1]}+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    return ensure_utc(dt)


def _parse_quality(raw: str) -> DataQuality:
    cleaned = raw.strip().lower()
    try:
        return DataQuality(cleaned)
    except ValueError:
        return DataQuality.UNKNOWN


async def _parse_semantic_table(
    page: Page,
    selector: TableSelectorConfig,
) -> list[dict[str, str]]:
    table = page.get_by_role("table", name=selector.table_role_name)
    await table.wait_for(state="visible", timeout=5000)

    headers = [h.strip().lower() for h in await table.locator("thead th").all_inner_texts()]
    column_indices: dict[str, int] = {}
    for canonical, aliases in selector.column_aliases.items():
        alias_set = {a.strip().lower() for a in aliases}
        alias_set.add(canonical.lower())
        for idx, header_text in enumerate(headers):
            if header_text in alias_set:
                column_indices[canonical] = idx
                break

    rows_locator = table.locator(selector.row_selector)
    row_count = await rows_locator.count()
    parsed: list[dict[str, str]] = []
    for i in range(row_count):
        row = rows_locator.nth(i)
        cells = [c.strip() for c in await row.locator("td").all_inner_texts()]
        item: dict[str, str] = {}
        for canonical, col_idx in column_indices.items():
            if col_idx < len(cells):
                item[canonical] = cells[col_idx]
        if "id" not in item:
            rec_id = await row.get_attribute("data-record-id")
            if rec_id:
                item["id"] = rec_id
        if "asset_id" not in item:
            attr_asset = await row.get_attribute("data-asset-id")
            if attr_asset:
                item["asset_id"] = attr_asset
        if "area" not in item:
            attr_area = await row.get_attribute("data-area")
            if attr_area:
                item["area"] = attr_area
        if "quality" not in item:
            attr_quality = await row.get_attribute("data-quality")
            if attr_quality:
                item["quality"] = attr_quality
        parsed.append(item)
    return parsed


async def _perform_login_if_needed(
    session_manager: SessionManager,
    managed: ManagedSession,
    login_selector: LoginSelectorConfig,
    credential_provider: CredentialProvider | None,
    *,
    target_url: str,
    task_origins: Sequence[str],
    initial_status: int | None,
) -> tuple[int | None, bool]:
    page = managed.page
    if initial_status is not None and initial_status >= 500:
        raise SourceUnavailableError(
            f"SCADA returned HTTP {initial_status} for {target_url!r}."
        )
    if initial_status == 401:
        raise AuthExpiredError("SCADA returned HTTP 401 (session expired).")
    if "/login" not in page.url:
        return initial_status, False
    if "expired=1" in page.url:
        raise AuthExpiredError("SCADA redirected to /login?expired=1 (session expired).")
    if credential_provider is None:
        raise AuthExpiredError("SCADA requires login and no CredentialProvider was supplied.")

    creds = credential_provider.get_credentials(
        managed.user_id,
        managed.profile_id,
        managed.app_id,
    )
    if creds is None:
        raise AuthExpiredError(
            f"No SCADA credentials found for ({managed.user_id}, {managed.profile_id})."
        )
    username, password = creds
    await page.get_by_label(login_selector.username_label).fill(username)
    await page.get_by_label(login_selector.password_label).fill(password)
    async with page.expect_navigation(wait_until="domcontentloaded"):
        await page.get_by_role("button", name=login_selector.submit_name).click()

    session_manager.assert_origin_allowed(
        managed.session_id,
        page.url,
        task_origins=task_origins,
    )
    if "/login" in page.url:
        raise AuthExpiredError("SCADA authentication failed or session remained expired.")

    nav_status = await session_manager.navigate(
        managed.session_id,
        target_url,
        task_origins=task_origins,
    )
    if nav_status is not None and nav_status >= 500:
        raise SourceUnavailableError(
            f"SCADA returned HTTP {nav_status} for {target_url!r}."
        )
    if nav_status == 401 or "/login" in page.url:
        raise AuthExpiredError("SCADA session expired immediately after login.")
    return nav_status, True


class ScadaAdapter:
    """Read-only Playwright adapter for SCADA alarms and sensor readings."""

    def __init__(
        self,
        session_manager: SessionManager,
        credential_provider: CredentialProvider | None = None,
    ) -> None:
        self._session_manager = session_manager
        self._credential_provider = credential_provider

    async def _read_view(
        self,
        *,
        task: TaskSpec,
        config: FacilityConfig,
        run_id: str,
        step_id: str,
        attempt: int,
        operation_key: str,
        tool_id: str,
        route_key: str,
        selector: TableSelectorConfig,
        record_type: str,
        asset_query: str | None = None,
        asset_id: str | None = None,
        area: str | None = None,
    ) -> tuple[tuple[Observation, ...], ActionReceipt]:
        started = time.perf_counter()
        app_cfg: AppConfig = config.apps["scada"]
        if not app_cfg.read_only:
            raise AdapterPermissionError("SCADA app config must enforce read_only=True.")
        if task.scope.allowed_tools and tool_id not in task.scope.allowed_tools:
            raise AdapterPermissionError(f"Tool {tool_id!r} not in task.scope.allowed_tools.")
        if task.scope.allowed_areas and area is not None and area not in task.scope.allowed_areas:
            raise AdapterPermissionError(
                f"Area {area!r} is outside task.scope.allowed_areas {task.scope.allowed_areas}."
            )

        managed = await self._session_manager.open_session(
            task.user_id,
            task.profile_id,
            app_cfg.app_id,
            (app_cfg.origin,),
        )

        params, resolved_candidates = resolve_source_query_params(
            config,
            app_cfg.app_id,
            asset_query=asset_query,
            asset_id=asset_id,
            area=area,
        )
        route_path = app_cfg.routes[route_key]
        query_suffix = f"?{urlencode(params)}" if params else ""
        target_url = f"{app_cfg.origin}{route_path}{query_suffix}"

        login_sel = app_cfg.selectors.login or LoginSelectorConfig()
        raw_args = scrub_for_receipt(
            {
                "tool_id": tool_id,
                "target_url": target_url,
                "asset_query": asset_query,
                "asset_id": asset_id,
                "area": area,
            }
        )

        try:
            async with self._session_manager.acquire_lease(managed.session_id) as leased:
                initial_status = await self._session_manager.navigate(
                    leased.session_id,
                    target_url,
                    task_origins=task.scope.allowed_origins,
                )
                _, did_login = await _perform_login_if_needed(
                    self._session_manager,
                    leased,
                    login_sel,
                    self._credential_provider,
                    target_url=target_url,
                    task_origins=task.scope.allowed_origins,
                    initial_status=initial_status,
                )
                self._session_manager.assert_origin_allowed(
                    leased.session_id,
                    leased.page.url,
                    task_origins=task.scope.allowed_origins,
                )
                user_banner = await leased.page.locator(
                    login_sel.authenticated_selector
                ).inner_text()
                rows = await _parse_semantic_table(leased.page, selector)
                # Re-verify origin and user banner after extraction (observe again)
                self._session_manager.assert_origin_allowed(
                    leased.session_id,
                    leased.page.url,
                    task_origins=task.scope.allowed_origins,
                )
                observations: list[Observation] = []
                for row in rows:
                    raw_val: str | float = row.get("value", "")
                    parsed_val: str | int | float | bool | None = raw_val
                    if record_type == "reading":
                        try:
                            parsed_val = float(raw_val)
                        except ValueError:
                            parsed_val = raw_val
                    obs = Observation(
                        source="scada",
                        session_id=leased.session_id,
                        asset_id=row.get("asset_id") or "unknown",
                        observed_label=row.get("asset_label") or "unknown",
                        value=parsed_val,
                        unit=row.get("unit") or None,
                        source_time=_parse_iso_utc(row.get("time", "")),
                        observed_at=utc_now(),
                        quality=_parse_quality(row.get("quality", "unknown")),
                        authorized_evidence=True,
                        area=row.get("area") or None,
                        metadata={
                            "record_type": record_type,
                            "record_id": row.get("id", ""),
                            "authenticated_user": user_banner.strip(),
                            "did_login": did_login,
                        },
                    )
                    observations.append(obs)

                if task.scope.allowed_areas:
                    allowed_area_set = set(task.scope.allowed_areas)
                    observations = [
                        o for o in observations if o.area in allowed_area_set
                    ]
                if (
                    len(resolved_candidates) >= 2
                    and "asset" not in params
                    and "asset_id" not in params
                ):
                    cand_ids = {
                        cid
                        for c in resolved_candidates
                        for cid in (c.asset_id, *c.source_ids.values())
                    }
                    cand_labels = {c.canonical_label.lower() for c in resolved_candidates}
                    observations = [
                        o
                        for o in observations
                        if o.asset_id in cand_ids
                        or o.observed_label.strip().lower() in cand_labels
                    ]

                duration_ms = (time.perf_counter() - started) * 1000.0
                receipt = ActionReceipt(
                    receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                    task_id=task.task_id,
                    run_id=run_id,
                    step_id=step_id,
                    attempt=attempt,
                    tool_id=tool_id,
                    redacted_args=raw_args,
                    operation_key=operation_key,
                    observed_before=scrub_for_receipt(
                        {"target_url": target_url, "did_login": did_login}
                    ),
                    observed_after=scrub_for_receipt(
                        {
                            "final_url": leased.page.url,
                            "row_count": len(observations),
                            "record_ids": [o.metadata.get("record_id") for o in observations],
                        }
                    ),
                    duration_ms=duration_ms,
                    evidence_refs=tuple(
                        f"scada:{o.metadata.get('record_id', idx)}"
                        for idx, o in enumerate(observations)
                    ),
                    outcome=ReceiptOutcome.SUCCEEDED,
                )
                return tuple(observations), receipt
        except (SourceUnavailableError, PlaywrightError) as exc:
            duration_ms = (time.perf_counter() - started) * 1000.0
            _ = ActionReceipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                task_id=task.task_id,
                run_id=run_id,
                step_id=step_id,
                attempt=attempt,
                tool_id=tool_id,
                redacted_args=raw_args,
                operation_key=operation_key,
                duration_ms=duration_ms,
                outcome=ReceiptOutcome.FAILED_TRANSIENT,
                error_detail=scrub_for_receipt(str(exc)),
            )
            if isinstance(exc, SourceUnavailableError):
                raise
            raise SourceUnavailableError(
                f"SCADA Playwright error for {target_url!r}: {exc}"
            ) from exc
        except AuthExpiredError as exc:
            duration_ms = (time.perf_counter() - started) * 1000.0
            _ = ActionReceipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                task_id=task.task_id,
                run_id=run_id,
                step_id=step_id,
                attempt=attempt,
                tool_id=tool_id,
                redacted_args=raw_args,
                operation_key=operation_key,
                duration_ms=duration_ms,
                outcome=ReceiptOutcome.FAILED_PERMISSION,
                error_detail=scrub_for_receipt(str(exc)),
            )
            raise

    async def read_alarms(
        self,
        *,
        task: TaskSpec,
        config: FacilityConfig,
        run_id: str = "run-scada",
        step_id: str = "step-scada-alarms",
        attempt: int = 1,
        operation_key: str = "op-scada-alarms",
        asset_query: str | None = None,
        asset_id: str | None = None,
        area: str | None = None,
    ) -> tuple[tuple[Observation, ...], ActionReceipt]:
        """Read SCADA alarms from the semantic HTML table using FacilityConfig."""
        selector = config.apps["scada"].selectors.alarms_table
        if selector is None:
            raise ValueError("FacilityConfig scada.selectors.alarms_table is missing.")
        return await self._read_view(
            task=task,
            config=config,
            run_id=run_id,
            step_id=step_id,
            attempt=attempt,
            operation_key=operation_key,
            tool_id="scada.read_alarms",
            route_key="alarms",
            selector=selector,
            record_type="alarm",
            asset_query=asset_query,
            asset_id=asset_id,
            area=area,
        )

    async def read_readings(
        self,
        *,
        task: TaskSpec,
        config: FacilityConfig,
        run_id: str = "run-scada",
        step_id: str = "step-scada-readings",
        attempt: int = 1,
        operation_key: str = "op-scada-readings",
        asset_query: str | None = None,
        asset_id: str | None = None,
        area: str | None = None,
    ) -> tuple[tuple[Observation, ...], ActionReceipt]:
        """Read SCADA readings from the semantic HTML table using FacilityConfig."""
        selector = config.apps["scada"].selectors.readings_table
        if selector is None:
            raise ValueError("FacilityConfig scada.selectors.readings_table is missing.")
        return await self._read_view(
            task=task,
            config=config,
            run_id=run_id,
            step_id=step_id,
            attempt=attempt,
            operation_key=operation_key,
            tool_id="scada.read_readings",
            route_key="readings",
            selector=selector,
            record_type="reading",
            asset_query=asset_query,
            asset_id=asset_id,
            area=area,
        )
