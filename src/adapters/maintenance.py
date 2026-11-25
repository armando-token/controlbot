"""Read-only Playwright Maintenance adapter for work-order inspection."""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from datetime import datetime
from urllib.parse import urlencode

from playwright.async_api import Error as PlaywrightError

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
    resolve_source_query_params,
)
from src.adapters.scada import _parse_quality, _parse_semantic_table, _perform_login_if_needed
from src.adapters.sessions import AuthExpiredError, SessionManager
from src.contracts.common import ensure_utc, utc_now, validate_http_origin
from src.contracts.enums import EffectClass, ReceiptOutcome
from src.contracts.models import ActionReceipt, Observation, RetryPolicy, TaskSpec, ToolSpec


def get_maintenance_tool_specs(allowed_origins: Sequence[str] = ()) -> dict[str, ToolSpec]:
    """Return ToolSpec definitions for read-only Maintenance work-order tools."""
    origins = tuple(validate_http_origin(o) for o in allowed_origins)
    return {
        "maint.read_work_orders": ToolSpec(
            tool_id="maint.read_work_orders",
            version="1.0.0",
            input_schema={
                "type": "object",
                "properties": {
                    "asset": {"type": "string"},
                    "asset_id": {"type": "string"},
                    "area": {"type": "string"},
                },
            },
            output_schema={
                "type": "object",
                "required": ["source", "count", "records"],
                "properties": {
                    "source": {"type": "string"},
                    "count": {"type": "integer", "minimum": 0},
                    "records": {"type": "array", "items": {"type": "object"}},
                },
            },
            permissions=("maint:read",),
            allowed_origins=origins,
            effect_class=EffectClass.READ,
            timeout_s=15.0,
            verifier_name="verify_maintenance_observation",
            retry_policy=RetryPolicy(max_retries=1, retry_on_transient=True, backoff_seconds=0.5),
        )
    }


def _parse_iso_utc(raw: str) -> datetime | None:
    cleaned = raw.strip()
    if not cleaned:
        return None
    if cleaned.endswith("Z"):
        cleaned = f"{cleaned[:-1]}+00:00"
    try:
        return ensure_utc(datetime.fromisoformat(cleaned))
    except ValueError:
        return None


class MaintenanceAdapter:
    """Read-only Playwright adapter for Maintenance work orders."""

    def __init__(
        self,
        session_manager: SessionManager,
        credential_provider: CredentialProvider | None = None,
    ) -> None:
        self._session_manager = session_manager
        self._credential_provider = credential_provider

    async def read_work_orders(
        self,
        *,
        task: TaskSpec,
        config: FacilityConfig,
        run_id: str = "run-maint",
        step_id: str = "step-maint-wo",
        attempt: int = 1,
        operation_key: str = "op-maint-wo",
        asset_query: str | None = None,
        asset_id: str | None = None,
        area: str | None = None,
    ) -> tuple[tuple[Observation, ...], ActionReceipt]:
        """Read maintenance work orders from the semantic HTML table using FacilityConfig."""
        started = time.perf_counter()
        app_cfg: AppConfig = config.apps["maintenance"]
        tool_id = "maint.read_work_orders"
        if not app_cfg.read_only:
            raise AdapterPermissionError("Maintenance app config must enforce read_only=True.")
        if task.scope.allowed_tools and tool_id not in task.scope.allowed_tools:
            raise AdapterPermissionError(f"Tool {tool_id!r} not in task.scope.allowed_tools.")
        if task.scope.allowed_areas and area is not None and area not in task.scope.allowed_areas:
            raise AdapterPermissionError(
                f"Area {area!r} is outside task.scope.allowed_areas {task.scope.allowed_areas}."
            )

        selector = app_cfg.selectors.work_orders_table
        if selector is None:
            raise ValueError("FacilityConfig maintenance.selectors.work_orders_table is missing.")

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
        route_path = app_cfg.routes["work_orders"]
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
                self._session_manager.assert_origin_allowed(
                    leased.session_id,
                    leased.page.url,
                    task_origins=task.scope.allowed_origins,
                )

                observations: list[Observation] = []
                for row in rows:
                    obs = Observation(
                        source="maintenance",
                        session_id=leased.session_id,
                        asset_id=row.get("asset_id") or "unknown",
                        observed_label=row.get("asset_label") or "unknown",
                        value=row.get("intervention") or "",
                        unit="event",
                        source_time=_parse_iso_utc(row.get("recorded_at", "")),
                        observed_at=utc_now(),
                        quality=_parse_quality(row.get("quality", "good")),
                        authorized_evidence=True,
                        area=row.get("area") or None,
                        metadata={
                            "record_type": "work_order",
                            "record_id": row.get("id", ""),
                            "order_id": row.get("id", ""),
                            "intervention_summary": row.get("intervention", ""),
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
                            "order_ids": [o.metadata.get("order_id") for o in observations],
                        }
                    ),
                    duration_ms=duration_ms,
                    evidence_refs=tuple(
                        f"maint:{o.metadata.get('order_id', idx)}"
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
                f"Maintenance Playwright error for {target_url!r}: {exc}"
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
