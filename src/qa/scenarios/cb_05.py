"""CB-05 scenario runner: attachments, pages, library filtering & thread/bot isolation."""

from __future__ import annotations

import contextlib
import json
import uuid
from typing import Any

from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ScenarioContext,
    finalize_scenario,
    open_browser_session,
    run_coro_sync,
    safe_response_dict,
)
from src.qa.ux_metrics import measure_ux_action


async def _run_cb05_async(ctx: ScenarioContext) -> None:
    ctx.thread_id = "thr_bot_chief"
    ctx.subsystem = "artifacts"
    suffix = uuid.uuid4().hex[:6]
    page_id: str | None = None

    try:
        async with ctx.async_client(timeout=20.0) as aclient:
            # 1. Upload & download attachment with exact byte parity & security headers
            payload_bytes = f"CB-05 spec payload {suffix}\n".encode()
            up = await aclient.post(
                "/api/v1/attachments",
                params={"filename": f"cb05_spec_{suffix}.txt", "thread_id": "thr_bot_chief"},
                headers={"Content-Type": "text/plain"},
                content=payload_bytes,
            )
            ctx.add_request_id(up)
            up_body = safe_response_dict(up)
            att_id = str(up_body.get("id") or "")
            ctx.assertions["attachment_upload_201"] = up.status_code == 201 and bool(att_id)
            if not ctx.assertions["attachment_upload_201"]:
                ctx.error_notes.append(f"CB-05 attachment upload failed (HTTP {up.status_code}).")
                return
            ctx.action_id = att_id

            dl = await aclient.get(f"/api/v1/attachments/{att_id}")
            ctx.add_request_id(dl)
            ctx.assertions["attachment_download_parity"] = (
                dl.status_code == 200 and dl.content == payload_bytes
            )
            ctx.assertions["attachment_security_headers"] = (
                dl.headers.get("X-Content-Type-Options") == "nosniff"
                and "sandbox" in dl.headers.get("Content-Security-Policy", "")
            )

            # 2. Page create, edit, pin & Library filter
            page_title = f"CB05 Blueprint {suffix}"

            async def _create_and_pin() -> str:
                cr = await aclient.post(
                    "/api/v1/pages",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "title": page_title,
                        "content_md": f"# Initial {suffix}\nLinked {att_id}",
                        "share_scope": "private",
                    },
                )
                ctx.add_request_id(cr)
                cr_body = safe_response_dict(cr)
                pid = str(cr_body.get("id") or "")
                ctx.assertions["page_create_201"] = cr.status_code == 201 and bool(pid)
                if not pid:
                    return ""
                ed = await aclient.patch(
                    f"/api/v1/pages/{pid}",
                    json={"content_md": f"# Updated {suffix}\nLinked {att_id}"},
                )
                ctx.assertions["page_edit_200"] = ed.status_code == 200
                pin = await aclient.patch(
                    f"/api/v1/artifacts/{pid}/pin",
                    json={"pinned": True},
                )
                ctx.assertions["page_pin_200"] = (
                    pin.status_code == 200 and safe_response_dict(pin).get("pinned") is True
                )
                return pid

            page_id, timing = await measure_ux_action(_create_and_pin, actions_to_reach=2)
            ctx.ttfp_ms = timing.ttfp_ms
            ctx.completion_ms = timing.completion_ms
            if not page_id:
                ctx.error_notes.append("CB-05 page creation failed.")
                return

            lib_chief = await aclient.get(
                "/api/v1/bots/bot_chief/library",
                params={"type": "page", "pinned": "true"},
            )
            chief_ids = {
                str(it.get("id"))
                for it in safe_response_dict(lib_chief).get("items", [])
                if isinstance(it, dict)
            }
            ctx.assertions["library_pinned_page_listed"] = (
                lib_chief.status_code == 200 and page_id in chief_ids
            )

            # Cross-bot / cross-thread isolation
            lib_ops = await aclient.get("/api/v1/bots/bot_ops/library")
            ops_ids = {
                str(it.get("id"))
                for it in safe_response_dict(lib_ops).get("items", [])
                if isinstance(it, dict)
            }
            ops_msgs = await aclient.get("/api/v1/threads/thr_bot_ops/messages")
            ctx.assertions["cross_bot_thread_isolated"] = (
                lib_ops.status_code == 200
                and ops_msgs.status_code == 200
                and page_id is not None
                and page_id not in ops_ids
                and page_id not in json.dumps(safe_response_dict(ops_msgs))
            )

        # 3. Playwright UI Library tab & reload persistence
        async with open_browser_session(vnc_safe=False) as pw:
            page = pw.page
            await page.goto(ctx.app_url("/app"), wait_until="networkidle", timeout=15000)
            await page.wait_for_selector("text=Chief of Staff", timeout=10000)
            await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
            await page.get_by_role("tab", name="Library").click()
            await page.get_by_role("button", name="Pinned", exact=True).click()
            await page.get_by_text(page_title).first.wait_for(state="visible", timeout=10000)
            await page.reload(wait_until="networkidle", timeout=15000)
            await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
            await page.get_by_role("tab", name="Library").click()
            await page.get_by_text(page_title).first.wait_for(state="visible", timeout=10000)
            ctx.response_persisted = True
            ctx.assertions["ui_library_persisted"] = True
            ctx.assertions["browser_clean"] = (
                not pw.console_errors and not pw.page_errors and not pw.external_requests
            )
            all_ok = all(ctx.assertions.values()) and not ctx.error_notes
            await ctx.capture_shot(page, "cb05_library", is_error_state=not all_ok)

        # 4. Delete artifact & verify bound attachment survives
        async with ctx.async_client(timeout=15.0) as aclient:
            if page_id:
                d_resp = await aclient.delete(f"/api/v1/artifacts/{page_id}")
                ctx.assertions["artifact_delete_200"] = d_resp.status_code == 200
                page_id = None
            dl_after = await aclient.get(f"/api/v1/attachments/{att_id}")
            ctx.assertions["bound_attachment_survives_delete"] = dl_after.status_code == 200

        ctx.evidence = {"attachment_id": att_id, "page_title": page_title}
        ctx.clarity_notes = "CB-05 attachments, pages, library filters & isolation verified."
    finally:
        if page_id:
            with contextlib.suppress(Exception), ctx.sync_client() as c:
                c.delete(f"/api/v1/artifacts/{page_id}")


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-05 scenario."""
    run_coro_sync(_run_cb05_async(ctx))
    return finalize_scenario(ctx)
