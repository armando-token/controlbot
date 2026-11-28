"""CB-00 scenario runner: startup, /health, /api/system/info, React /app surface & navigation."""

from __future__ import annotations

import contextlib
from typing import Any

from src.qa.baseline import verify_app_surface_http
from src.qa.models import RunRecord
from src.qa.queue import assert_strictly_redacted
from src.qa.scenarios._common import (
    ScenarioContext,
    finalize_scenario,
    open_browser_session,
    repo_root_fallback,
    run_coro_sync,
)
from src.qa.ux_metrics import (
    check_composer_single_row,
    check_local_remote_indicator,
    measure_ux_action,
)


async def _run_cb00_async(ctx: ScenarioContext) -> None:
    dist_dir = repo_root_fallback(ctx.repo_root) / "frontend" / "dist"
    with ctx.sync_client() as client:
        r_health = client.get("/health")
        ctx.add_request_id(r_health)
        health_ok = r_health.status_code == 200
        if health_ok:
            with contextlib.suppress(ValueError):
                h_json = r_health.json()
                health_ok = h_json.get("status") == "ok" and h_json.get("service") == "grokbot-web"
        ctx.assertions["health_200"] = health_ok

        r_info = client.get("/api/system/info")
        ctx.add_request_id(r_info)
        info_ok = r_info.status_code == 200
        info_redacted = False
        if info_ok:
            with contextlib.suppress(Exception):
                info_json = r_info.json()
                info_ok = info_json.get("service") == "controlbot"
                assert_strictly_redacted(info_json)
                info_redacted = True
        ctx.assertions["system_info_200"] = info_ok
        ctx.assertions["system_info_redacted"] = info_redacted

        r_app = client.get("/app", params={"token": ctx.token} if ctx.token else None)
        ctx.add_request_id(r_app)
        ctx.assertions["app_no_store"] = (
            r_app.status_code == 200 and "no-store" in r_app.headers.get("Cache-Control", "")
        )

        surf = verify_app_surface_http(client, dist_dir=dist_dir, token=ctx.token)
        ctx.assertions["react_surface_verified"] = surf.surface_verified
        ctx.assertions["served_surface_react"] = surf.served_surface == "react"
        if surf.asset_hashes:
            ctx.build_hash = next(iter(surf.asset_hashes.values()))[:16]
        if surf.boot_errors:
            ctx.error_notes.extend(surf.boot_errors)

    async with open_browser_session(vnc_safe=False) as pw:
        page = pw.page

        async def _boot() -> str:
            await page.goto(ctx.app_url("/app"), wait_until="networkidle", timeout=15000)
            await page.locator('textarea[aria-label="Message composer"]').wait_for(
                state="visible", timeout=12000
            )
            return await page.title()

        async def _composer_visible() -> bool:
            return await page.locator('textarea[aria-label="Message composer"]').is_visible()

        title, timing = await measure_ux_action(
            _boot,
            actions_to_reach=1,
            ttfp_probe=_composer_visible,
            cancel_available=False,
        )
        ctx.ttfp_ms = timing.ttfp_ms
        ctx.completion_ms = timing.completion_ms
        ctx.actions_to_reach = timing.actions_to_reach
        ctx.assertions["react_title_exact"] = title == "Grok Bot — ControlBot Studio"

        sidebar = page.locator("aside")
        await sidebar.get_by_text("Chief of Staff").wait_for(state="visible", timeout=10000)

        loc_visible, loc_where = await check_local_remote_indicator(page)
        ctx.local_remote_visible = loc_visible
        ctx.local_remote_location = loc_where
        ctx.assertions["local_remote_indicator_visible"] = loc_visible

        comp_intact, comp_reason = await check_composer_single_row(page)
        ctx.composer_intact = comp_intact
        ctx.assertions["composer_layout_intact"] = comp_intact
        if not comp_intact:
            ctx.error_notes.append(f"Composer layout issue: {comp_reason}")

        # Primary navigation across Inspector, Settings, Memory, and Sidebar toggle
        nav_ok = True
        try:
            await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
            await page.get_by_role("tab", name="Details").wait_for(state="visible", timeout=5000)
            await page.get_by_role("tab", name="Library").click()
            await page.get_by_role("button", name="All", exact=True).wait_for(
                state="visible", timeout=5000
            )

            await sidebar.get_by_role("button", name="Settings").click()
            await page.get_by_role("dialog").wait_for(state="visible", timeout=5000)
            await page.keyboard.press("Escape")
            await page.get_by_role("dialog").wait_for(state="hidden", timeout=5000)

            await sidebar.get_by_role("button", name="Memory", exact=True).click()
            await page.get_by_role("dialog").wait_for(state="visible", timeout=5000)
            await page.keyboard.press("Escape")
            await page.get_by_role("dialog").wait_for(state="hidden", timeout=5000)

            await page.keyboard.press("Control+b")
            await page.locator('button[title="Expand sidebar (Cmd/Ctrl+B)"]').wait_for(
                state="visible", timeout=5000
            )
            await page.keyboard.press("Control+b")
            await page.locator('button[title="Collapse sidebar (Cmd/Ctrl+B)"]').wait_for(
                state="visible", timeout=5000
            )
        except Exception as exc:
            nav_ok = False
            ctx.focus_predictable = False
            ctx.error_notes.append(f"Primary navigation failed: {type(exc).__name__}: {exc}")
        ctx.assertions["primary_navigation_coherent"] = nav_ok

        # Reload coherence
        reload_ok = True
        try:
            await page.reload(wait_until="networkidle", timeout=15000)
            await page.locator('textarea[aria-label="Message composer"]').wait_for(
                state="visible", timeout=10000
            )
            await sidebar.get_by_text("Chief of Staff").wait_for(state="visible", timeout=10000)
        except Exception as exc:
            reload_ok = False
            ctx.error_notes.append(f"Reload coherence failed: {type(exc).__name__}: {exc}")
        ctx.response_persisted = reload_ok
        ctx.assertions["reload_coherence"] = reload_ok

        ctx.assertions["browser_console_clean"] = not pw.console_errors
        ctx.assertions["browser_page_clean"] = not pw.page_errors
        ctx.assertions["browser_no_external_requests"] = not pw.external_requests
        if pw.console_errors:
            ctx.error_notes.append(f"Console errors: {pw.console_errors[:3]}")
        if pw.page_errors:
            ctx.error_notes.append(f"Page errors: {pw.page_errors[:3]}")

        all_ok = all(ctx.assertions.values()) and not ctx.error_notes
        await ctx.capture_shot(page, "cb00_surface", is_error_state=not all_ok)

    ctx.evidence = {
        "title": "Grok Bot — ControlBot Studio",
        "backend_mode": ctx.caps.backend_mode,
        "runtime_mode": ctx.caps.runtime_mode,
        "local_remote_location": ctx.local_remote_location,
    }
    ctx.clarity_notes = (
        "CB-00 startup, /health, /api/system/info, /app assets, nav & reload verified."
    )


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-00 scenario."""
    run_coro_sync(_run_cb00_async(ctx))
    return finalize_scenario(ctx)
