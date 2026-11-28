"""CB-04 scenario runner: roster, sections, hide/unhide, group channels, @mention & isolation."""

from __future__ import annotations

import contextlib
import uuid
from typing import Any

from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ScenarioContext,
    finalize_scenario,
    open_browser_session,
    run_coro_sync,
    safe_response_dict,
    trigger_and_wait_turn,
)
from src.qa.ux_metrics import measure_ux_action


async def _run_cb04_async(ctx: ScenarioContext) -> None:
    ctx.subsystem = "roster"
    suffix = uuid.uuid4().hex[:6]
    section_id: str | None = None
    bot_a_id: str | None = None
    bot_b_id: str | None = None
    channel_id: str | None = None
    appr_ids: list[str] = []

    try:
        async with ctx.async_client(timeout=30.0) as aclient:
            # 1. Section CRUD
            s_resp = await aclient.post("/api/v1/sections", json={"name": f"QA-Sec-{suffix}"})
            ctx.add_request_id(s_resp)
            s_body = safe_response_dict(s_resp)
            ctx.assertions["section_create_201"] = (
                s_resp.status_code == 201 and bool(s_body.get("id"))
            )
            if ctx.assertions["section_create_201"]:
                section_id = str(s_body["id"])
                p_sec = await aclient.patch(
                    f"/api/v1/sections/{section_id}",
                    json={"name": f"QA-Sec-Ren-{suffix}"},
                )
                ctx.assertions["section_rename_200"] = p_sec.status_code == 200

            # 2. Bot CRUD + Hide/Unhide
            b1 = await aclient.post(
                "/api/v1/bots",
                json={"name": f"QA-Alpha-{suffix}", "section_id": section_id},
            )
            b2 = await aclient.post(
                "/api/v1/bots",
                json={"name": f"QA-Beta-{suffix}", "section_id": section_id},
            )
            b1_body = safe_response_dict(b1)
            b2_body = safe_response_dict(b2)
            ctx.assertions["bots_create_201"] = (
                b1.status_code == 201
                and b2.status_code == 201
                and bool(b1_body.get("id"))
                and bool(b2_body.get("id"))
            )
            if not ctx.assertions["bots_create_201"]:
                ctx.error_notes.append(
                    f"CB-04 bot creation failed (HTTP {b1.status_code}/{b2.status_code})."
                )
                return

            bot_a_id = str(b1_body["id"])
            bot_b_id = str(b2_body["id"])
            thr_a = str(b1_body.get("thread_id") or "")
            thr_b = str(b2_body.get("thread_id") or "")

            ren_a = await aclient.patch(
                f"/api/v1/bots/{bot_a_id}",
                json={"name": f"QA-Alpha2-{suffix}", "hidden": True},
            )
            ctx.assertions["bot_rename_and_hide_200"] = (
                ren_a.status_code == 200 and safe_response_dict(ren_a).get("hidden") is True
            )
            unhide_a = await aclient.patch(
                f"/api/v1/bots/{bot_a_id}",
                json={"hidden": False},
            )
            ctx.assertions["bot_unhide_200"] = (
                unhide_a.status_code == 200 and safe_response_dict(unhide_a).get("hidden") is False
            )

            # 3. 2-bot group channel & context isolation
            ch_resp = await aclient.post(
                "/api/v1/channels",
                json={"name": f"QA-Grp-{suffix}", "bot_ids": [bot_a_id, bot_b_id]},
            )
            ch_body = safe_response_dict(ch_resp)
            ctx.assertions["channel_create_201"] = (
                ch_resp.status_code == 201
                and bool(ch_body.get("id"))
                and bool(ch_body.get("thread_id"))
            )
            if not ctx.assertions["channel_create_201"]:
                ctx.error_notes.append(
                    f"CB-04 channel creation failed (HTTP {ch_resp.status_code})."
                )
                return

            channel_id = str(ch_body["id"])
            ch_thr = str(ch_body["thread_id"])
            ctx.thread_id = ch_thr

            dm_marker = f"DM_ISOLATED_{suffix}"
            ch_marker = f"CH_ISOLATED_{suffix}"
            dm_prompt = (
                dm_marker
                if ctx.caps.is_live_agent_target
                else f"/approval {dm_marker}"
            )
            ch_prompt = (
                f"@QA-Alpha2-{suffix} {ch_marker}"
                if ctx.caps.is_live_agent_target
                else f"/approval {ch_marker}"
            )

            async def _run_turns() -> tuple[Any, Any]:
                t_dm = await trigger_and_wait_turn(aclient, thr_a, dm_prompt, timeout=20.0)
                t_ch = await trigger_and_wait_turn(aclient, ch_thr, ch_prompt, timeout=20.0)
                return t_dm, t_ch

            (t_dm, t_ch), timing = await measure_ux_action(_run_turns, actions_to_reach=2)
            ctx.ttfp_ms = timing.ttfp_ms
            ctx.completion_ms = timing.completion_ms
            for turn in (t_dm, t_ch):
                for ap in turn.approvals:
                    if ap.get("id"):
                        appr_ids.append(str(ap["id"]))

            if ctx.caps.is_live_agent_target:
                ctx.assertions["mention_routes_targeted_bot"] = (
                    len(t_ch.assistant_messages) == 1
                    and t_ch.assistant_message is not None
                    and t_ch.assistant_message.get("sender_bot_id") == bot_a_id
                )

            r_ma = await aclient.get(f"/api/v1/threads/{thr_a}/messages")
            r_mb = await aclient.get(f"/api/v1/threads/{thr_b}/messages")
            r_mc = await aclient.get(f"/api/v1/threads/{ch_thr}/messages")
            msgs_a = (
                safe_response_dict(r_ma).get("messages", []) if r_ma.status_code == 200 else []
            )
            msgs_b = (
                safe_response_dict(r_mb).get("messages", []) if r_mb.status_code == 200 else []
            )
            msgs_ch = (
                safe_response_dict(r_mc).get("messages", []) if r_mc.status_code == 200 else []
            )
            ctx.assertions["thread_context_isolated"] = (
                r_ma.status_code == 200
                and r_mb.status_code == 200
                and r_mc.status_code == 200
                and any(dm_marker in str(m.get("content", "")) for m in msgs_a)
                and not any(dm_marker in str(m.get("content", "")) for m in msgs_b)
                and not any(dm_marker in str(m.get("content", "")) for m in msgs_ch)
                and any(ch_marker in str(m.get("content", "")) for m in msgs_ch)
                and not any(ch_marker in str(m.get("content", "")) for m in msgs_a)
            )

        # 4. Playwright UI roster / group switch & reload check
        async with open_browser_session(vnc_safe=False) as pw:
            page = pw.page
            await page.goto(ctx.app_url("/app"), wait_until="networkidle", timeout=15000)
            sidebar = page.locator("aside")
            await sidebar.get_by_text(f"QA-Alpha2-{suffix}", exact=True).first.wait_for(
                state="visible", timeout=10000
            )
            await sidebar.get_by_text(f"QA-Grp-{suffix}", exact=True).first.click()
            await page.wait_for_function(
                f"() => (document.querySelector('textarea[aria-label=\"Message composer\"]')"
                f"?.getAttribute('placeholder') || '').includes('QA-Grp-{suffix}')",
                timeout=10000,
            )
            await page.reload(wait_until="networkidle", timeout=15000)
            await sidebar.get_by_text(f"QA-Grp-{suffix}", exact=True).first.wait_for(
                state="visible", timeout=10000
            )
            ctx.response_persisted = True
            ctx.assertions["ui_roster_and_channel_persisted"] = True
            ctx.assertions["browser_clean"] = (
                not pw.console_errors and not pw.page_errors and not pw.external_requests
            )
            all_ok = all(ctx.assertions.values()) and not ctx.error_notes
            await ctx.capture_shot(page, "cb04_roster", is_error_state=not all_ok)

        ctx.evidence = {
            "section_id": section_id,
            "bot_a_id": bot_a_id,
            "bot_b_id": bot_b_id,
            "channel_id": channel_id,
        }
        ctx.clarity_notes = (
            "CB-04 sections, bots, hide/unhide, channels & thread isolation verified."
        )
    finally:
        with ctx.sync_client() as c:
            for ap_id in appr_ids:
                with contextlib.suppress(Exception):
                    c.post(f"/api/v1/approvals/{ap_id}/resolve", json={"decision": "deny"})
            if channel_id:
                with contextlib.suppress(Exception):
                    c.delete(f"/api/v1/channels/{channel_id}")
            if bot_a_id:
                with contextlib.suppress(Exception):
                    c.delete(f"/api/v1/bots/{bot_a_id}")
            if bot_b_id:
                with contextlib.suppress(Exception):
                    c.delete(f"/api/v1/bots/{bot_b_id}")
            if section_id:
                with contextlib.suppress(Exception):
                    c.delete(f"/api/v1/sections/{section_id}")


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-04 scenario."""
    run_coro_sync(_run_cb04_async(ctx))
    return finalize_scenario(ctx)
