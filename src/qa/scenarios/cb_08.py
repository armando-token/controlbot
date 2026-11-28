"""CB-08 scenario runner: settings reload persistence, 5-scope memory isolation & routines."""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from typing import Any

from src.qa.models import RunRecord
from src.qa.queue import assert_strictly_redacted
from src.qa.scenarios._common import (
    ScenarioContext,
    finalize_scenario,
    open_browser_session,
    run_coro_sync,
    safe_response_dict,
)
from src.qa.ux_metrics import measure_ux_action


async def _run_cb08_async(ctx: ScenarioContext) -> None:
    ctx.subsystem = "settings_memory_routines"
    suffix = uuid.uuid4().hex[:6]
    orig_settings: dict[str, Any] = {}
    created_memories: list[tuple[str, dict[str, str]]] = []
    routine_id: str | None = None
    canary_secret = f"sk-qa-cb08-secret-{suffix}"

    try:
        async with ctx.async_client(timeout=25.0) as aclient:
            # 1. Settings read & patch (restored in finally)
            s_get = await aclient.get("/api/v1/settings")
            ctx.add_request_id(s_get)
            if s_get.status_code == 200:
                orig = safe_response_dict(s_get)
                orig_settings = {
                    k: orig[k]
                    for k in ("theme", "display_name", "default_thinking_level")
                    if k in orig
                }
            s_patch = await aclient.patch(
                "/api/v1/settings",
                json={
                    "theme": "dark",
                    "display_name": f"QA Lead {suffix}",
                    "default_thinking_level": "high",
                },
            )
            ctx.assertions["settings_patch_200"] = s_patch.status_code == 200

            # 2. 5-scope Memory isolation + secret-redacted export + FTS delete purge
            user_hdr = {"X-User-Id": f"op_alpha_{suffix}"}
            m_user = await aclient.post(
                "/api/v1/memory",
                headers=user_hdr,
                json={
                    "scope": "user",
                    "scope_id": f"op_alpha_{suffix}",
                    "kind": "preference",
                    "title": f"Alpha Pref {suffix}",
                    "content": f"Credential: {canary_secret}",
                },
            )
            if m_user.status_code == 201 and (mid := safe_response_dict(m_user).get("id")):
                created_memories.append((str(mid), user_hdr))

            role_hdr = {"X-Agent-Role": f"role_{suffix}"}
            m_role = await aclient.post(
                "/api/v1/memory",
                headers=role_hdr,
                json={
                    "scope": "agent_role",
                    "scope_id": f"role_{suffix}",
                    "kind": "preference",
                    "title": f"Role Rule {suffix}",
                    "content": "Verify calibration",
                },
            )
            if m_role.status_code == 201 and (mid := safe_response_dict(m_role).get("id")):
                created_memories.append((str(mid), role_hdr))

            thr_hdr = {"X-Thread-Id": f"thr_{suffix}"}
            m_thr = await aclient.post(
                "/api/v1/memory",
                headers=thr_hdr,
                json={
                    "scope": "thread",
                    "scope_id": f"thr_{suffix}",
                    "kind": "dated_observation",
                    "title": f"Thread Obs {suffix}",
                    "content": "Isolated thread note",
                    "observed_at": "2026-11-27T00:00:00Z",
                    "valid_until": "2026-12-31T23:59:59Z",
                },
            )
            if m_thr.status_code == 201 and (mid := safe_response_dict(m_thr).get("id")):
                created_memories.append((str(mid), thr_hdr))

            proj_hdr = {"X-Project-Area": f"area_{suffix}"}
            m_proj = await aclient.post(
                "/api/v1/memory",
                headers=proj_hdr,
                json={
                    "scope": "project_area",
                    "scope_id": f"area_{suffix}",
                    "kind": "source_reference",
                    "title": f"Proj Ref {suffix}",
                    "content": "Max RPM 3600",
                },
            )
            if m_proj.status_code == 201 and (mid := safe_response_dict(m_proj).get("id")):
                created_memories.append((str(mid), proj_hdr))

            org_hdr = {"X-Actor-Role": "Manager"}
            m_org = await aclient.post(
                "/api/v1/memory",
                headers=org_hdr,
                json={
                    "scope": "org_approved",
                    "scope_id": "org",
                    "kind": "approved_procedure",
                    "title": f"Org SOP {suffix}",
                    "content": "Lockout first",
                },
            )
            if m_org.status_code == 201 and (mid := safe_response_dict(m_org).get("id")):
                created_memories.append((str(mid), org_hdr))

            ctx.assertions["memory_5_scopes_created"] = len(created_memories) == 5

            other_user = await aclient.get(
                "/api/v1/memory",
                params={"scope": "user"},
                headers={"X-User-Id": f"op_beta_{suffix}"},
            )
            other_role = await aclient.get(
                "/api/v1/memory",
                params={"scope": "agent_role"},
                headers={"X-Agent-Role": f"other_role_{suffix}"},
            )
            other_user_items = (
                safe_response_dict(other_user).get("items", [])
                if other_user.status_code == 200
                else []
            )
            other_role_items = (
                safe_response_dict(other_role).get("items", [])
                if other_role.status_code == 200
                else []
            )
            ctx.assertions["memory_cross_scope_isolated"] = (
                other_user.status_code == 200
                and other_role.status_code == 200
                and not any(suffix in str(it.get("title", "")) for it in other_user_items)
                and not any(suffix in str(it.get("title", "")) for it in other_role_items)
            )

            exp_json = await aclient.get(
                "/api/v1/memory/export", params={"format": "json"}, headers=user_hdr
            )
            exp_md = await aclient.get(
                "/api/v1/memory/export", params={"format": "md"}, headers=user_hdr
            )
            redacted_ok = exp_json.status_code == 200 and exp_md.status_code == 200
            if redacted_ok:
                assert_strictly_redacted(safe_response_dict(exp_json))
                redacted_ok = (
                    canary_secret not in exp_json.text
                    and canary_secret not in exp_md.text
                )
            ctx.assertions["memory_export_redacts_secrets"] = redacted_ok

            # Delete user memory and verify FTS purge
            if created_memories:
                uid, uhdr = created_memories[0]
                del_r = await aclient.delete(f"/api/v1/memory/{uid}", headers=uhdr)
                fts_r = await aclient.get(
                    "/api/v1/memory",
                    params={"q": f"Alpha Pref {suffix}"},
                    headers=uhdr,
                )
                ctx.assertions["memory_fts_delete_purge"] = (
                    del_r.status_code == 200
                    and fts_r.status_code == 200
                    and all(
                        str(it.get("id")) != uid
                        for it in safe_response_dict(fts_r).get("items", [])
                    )
                )
                created_memories.pop(0)

            # 3. Routine CRUD, manual /test, webhook 401 vs 202, RoutineRun history
            r_cr = await aclient.post(
                "/api/v1/bots/bot_chief/routines",
                json={
                    "name": f"CB08 Routine {suffix}",
                    "instruction": "Check pump vibration",
                    "schedule_type": "manual",
                    "enabled": True,
                },
            )
            routine = safe_response_dict(r_cr) if r_cr.status_code == 201 else {}
            ctx.assertions["routine_create_201"] = (
                r_cr.status_code == 201 and bool(routine.get("id"))
            )
            if ctx.assertions["routine_create_201"]:
                routine_id = str(routine["id"])
                wh_key = str(routine.get("webhook_key") or "")

                r_bad_wh = await aclient.post(
                    f"/api/v1/webhooks/routines/{routine_id}",
                    headers={"Authorization": "Bearer wrong-key"},
                )
                r_test = await aclient.post(f"/api/v1/routines/{routine_id}/test")
                r_wh = await aclient.post(
                    f"/api/v1/webhooks/routines/{routine_id}",
                    headers={"Authorization": f"Bearer {wh_key}"},
                    json={"event": "cb08_synthetic"},
                )
                ctx.assertions["routine_webhook_auth_enforced"] = r_bad_wh.status_code == 401
                ctx.assertions["routine_manual_and_webhook_202"] = (
                    r_test.status_code == 202 and r_wh.status_code == 202
                )

                async def _poll_runs() -> list[dict[str, Any]]:
                    deadline = asyncio.get_running_loop().time() + 10.0
                    while asyncio.get_running_loop().time() < deadline:
                        rr = await aclient.get(f"/api/v1/routines/{routine_id}/runs")
                        if rr.status_code == 200:
                            runs = safe_response_dict(rr).get("runs", [])
                            if len(runs) >= 2 and all(r.get("status") != "running" for r in runs):
                                return list(runs)
                        await asyncio.sleep(0.15)
                    return []

                runs, timing = await measure_ux_action(_poll_runs, actions_to_reach=1)
                ctx.ttfp_ms = timing.ttfp_ms
                ctx.completion_ms = timing.completion_ms
                triggers = {str(r.get("trigger")) for r in runs}
                ctx.assertions["routine_run_history_recorded"] = (
                    len(runs) >= 2 and {"manual", "webhook"}.issubset(triggers)
                )

            if not ctx.assertions["settings_patch_200"]:
                ctx.error_notes.append(f"CB-08 settings patch failed (HTTP {s_patch.status_code}).")
                return

        # 4. Playwright UI Settings reload persistence check
        async with open_browser_session(vnc_safe=False) as pw:
            page = pw.page
            await page.goto(ctx.app_url("/app"), wait_until="networkidle", timeout=15000)
            await page.wait_for_selector("text=Chief of Staff", timeout=10000)
            theme = await page.evaluate("document.documentElement.getAttribute('data-theme')")
            ctx.assertions["ui_settings_dark_theme_persisted"] = theme == "dark"
            await page.locator("aside").get_by_role("button", name="Settings").click()
            dlg = page.get_by_role("dialog")
            await dlg.wait_for(state="visible", timeout=5000)
            disp_val = await dlg.get_by_label("Display name").input_value()
            think_val = await dlg.get_by_label("Default thinking level").input_value()
            ctx.assertions["ui_settings_fields_persisted"] = (
                disp_val == f"QA Lead {suffix}" and think_val == "high"
            )
            await page.keyboard.press("Escape")
            await dlg.wait_for(state="hidden", timeout=5000)
            ctx.response_persisted = True
            ctx.assertions["browser_clean"] = (
                not pw.console_errors and not pw.page_errors and not pw.external_requests
            )
            all_ok = all(ctx.assertions.values()) and not ctx.error_notes
            await ctx.capture_shot(page, "cb08_settings_routines", is_error_state=not all_ok)

        ctx.evidence = {"routine_id": routine_id, "scopes_tested": 5}
        ctx.clarity_notes = "CB-08 settings reload, 5-scope memory isolation & routines verified."
    finally:
        with ctx.sync_client() as c:
            if orig_settings:
                with contextlib.suppress(Exception):
                    c.patch("/api/v1/settings", json=orig_settings)
            if routine_id:
                with contextlib.suppress(Exception):
                    c.delete(f"/api/v1/routines/{routine_id}")
            for mid, hdrs in created_memories:
                with contextlib.suppress(Exception):
                    c.delete(f"/api/v1/memory/{mid}", headers=hdrs)


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-08 scenario."""
    run_coro_sync(_run_cb08_async(ctx))
    return finalize_scenario(ctx)
