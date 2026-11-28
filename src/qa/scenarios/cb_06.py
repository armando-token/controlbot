"""CB-06 scenario runner: computer panel, takeover/handback, lease 409, PTY & workspace files."""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from typing import Any

import websockets

from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ScenarioContext,
    finalize_scenario,
    open_browser_session,
    run_coro_sync,
    safe_response_dict,
    ws_base_url,
)
from src.qa.ux_metrics import measure_ux_action


async def _run_cb06_async(ctx: ScenarioContext) -> None:
    ctx.subsystem = "computer"
    suffix = uuid.uuid4().hex[:6]
    probe_file = f"cb06_probe_{suffix}.txt"
    ui_note_file = f"cb06_ui_{suffix}.txt"
    takeover_active = False

    try:
        async with ctx.async_client(timeout=20.0) as aclient:
            # 1. Desktop & Computer status + vnc-token
            r_desk = await aclient.get("/api/desktop/status")
            ctx.add_request_id(r_desk)
            ctx.assertions["desktop_status_200"] = r_desk.status_code == 200

            r_stat = await aclient.get("/api/v1/computers/default/status")
            ctx.add_request_id(r_stat)
            ctx.assertions["computer_status_200"] = r_stat.status_code == 200
            stat_json = safe_response_dict(r_stat) if r_stat.status_code == 200 else {}
            vnc_available = bool(stat_json.get("vnc_available", False))
            display_mode = str(stat_json.get("display_mode") or "browser")

            r_tok = await aclient.post("/api/v1/computers/default/vnc-token", json={})
            ctx.add_request_id(r_tok)
            ctx.assertions["vnc_token_200"] = r_tok.status_code == 200
            tok = safe_response_dict(r_tok) if r_tok.status_code == 200 else {}
            ctx.assertions["vnc_token_has_urls"] = bool(
                tok.get("cap_token") and tok.get("ws_pty_url") and tok.get("ws_vnc_url")
            )

            # 2. Takeover -> 409 agent action lock -> Handback -> 200
            async def _takeover_cycle() -> tuple[bool, bool, bool]:
                nonlocal takeover_active
                tk = await aclient.post(
                    "/api/v1/computers/default/takeover",
                    json={"owner": "qa-cb06", "ttl_seconds": 120},
                )
                takeover_ok = (
                    tk.status_code == 200
                    and safe_response_dict(tk).get("control_owner") == "human_takeover"
                )
                takeover_active = tk.status_code == 200
                blocked = await aclient.post(
                    "/api/v1/computers/default/actions",
                    json={"type": "start", "url": f"{ctx.target_url}/health", "actor": "agent"},
                )
                conflict_ok = blocked.status_code == 409
                hb = await aclient.post("/api/v1/computers/default/handback", json={})
                takeover_active = False
                handback_ok = (
                    hb.status_code == 200 and safe_response_dict(hb).get("control_owner") == "agent"
                )
                return takeover_ok, conflict_ok, handback_ok

            (tk_ok, c409_ok, hb_ok), timing = await measure_ux_action(
                _takeover_cycle, actions_to_reach=2
            )
            ctx.ttfp_ms = timing.ttfp_ms
            ctx.completion_ms = timing.completion_ms
            ctx.assertions["takeover_acquires_lease"] = tk_ok
            ctx.assertions["agent_action_locked_409"] = c409_ok
            ctx.assertions["handback_releases_lease"] = hb_ok

            # 3. Workspace files write/read/traversal-guard/delete
            w_resp = await aclient.post(
                "/api/v1/computers/default/files/write",
                json={"path": probe_file, "content": f"cb06_content_{suffix}"},
            )
            r_file = await aclient.get(
                "/api/v1/computers/default/file", params={"path": probe_file}
            )
            r_trav = await aclient.get(
                "/api/v1/computers/default/file", params={"path": "../etc/passwd"}
            )
            d_file = await aclient.delete(
                "/api/v1/computers/default/files", params={"path": probe_file}
            )
            ctx.assertions["workspace_file_roundtrip"] = (
                w_resp.status_code == 200
                and r_file.status_code == 200
                and safe_response_dict(r_file).get("content") == f"cb06_content_{suffix}"
                and d_file.status_code == 200
            )
            ctx.assertions["workspace_traversal_blocked"] = r_trav.status_code in {400, 403}

            if r_stat.status_code != 200 or r_tok.status_code != 200:
                ctx.error_notes.append(
                    f"CB-06 computer endpoints unhealthy "
                    f"(status={r_stat.status_code}, vnc_token={r_tok.status_code})."
                )
                return

            # 4. PTY WebSocket echo roundtrip
            pty_ok = False
            if tok.get("ws_pty_url"):
                ws_url = f"{ws_base_url(ctx.target_url)}{tok['ws_pty_url']}"
                try:
                    async with websockets.connect(ws_url, open_timeout=8.0) as ws:
                        pty_marker = f"CB06_WS_PTY_{suffix}"
                        await ws.send(f"echo {pty_marker}\n")
                        deadline = asyncio.get_running_loop().time() + 6.0
                        collected = ""
                        while asyncio.get_running_loop().time() < deadline:
                            chunk = await asyncio.wait_for(ws.recv(), timeout=3.0)
                            text = (
                                chunk.decode("utf-8", errors="replace")
                                if isinstance(chunk, bytes)
                                else str(chunk)
                            )
                            collected += text
                            if pty_marker in collected:
                                pty_ok = True
                                break
                except Exception as exc:
                    ctx.error_notes.append(f"PTY WebSocket failed: {type(exc).__name__}: {exc}")
            ctx.assertions["pty_websocket_echo"] = pty_ok

        # 5. Playwright VNC-safe Computer panel check
        async with open_browser_session(vnc_safe=True) as pw:
            page = pw.page
            await page.goto(ctx.app_url("/app"), wait_until="networkidle", timeout=15000)
            await page.wait_for_selector("text=Chief of Staff", timeout=10000)
            await page.locator('button[title="Open Bot Computer"]').click()
            await page.locator('[role="tablist"][aria-label="Computer view"]').wait_for(
                state="visible", timeout=8000
            )

            # Terminal tab
            await page.get_by_role("button", name="Terminal", exact=True).click()
            await page.locator('span[title="connected"]').wait_for(state="visible", timeout=10000)
            await page.locator(".xterm-helper-textarea").focus()
            await page.keyboard.type(f"echo CB06_UI_PTY_{suffix}")
            await page.keyboard.press("Enter")
            await page.wait_for_function(
                "() => (document.querySelector('.xterm-rows')?.innerText || '').includes("
                f"'CB06_UI_PTY_{suffix}')",
                timeout=10000,
            )
            ctx.assertions["ui_terminal_pty_connected"] = True

            # Files tab
            await page.get_by_role("button", name="Files", exact=True).click()
            await page.get_by_role("button", name="New file", exact=True).click()
            await page.locator('input[placeholder="notes.md"]').fill(ui_note_file)
            await page.locator('textarea[placeholder="File content…"]').fill("ui_note_ok")
            await page.get_by_role("button", name="Create file").click()
            await page.get_by_role("button", name=ui_note_file, exact=True).wait_for(
                state="visible", timeout=8000
            )
            row = page.locator("div.group").filter(has_text=ui_note_file).first
            await row.hover()
            await page.locator(f'button[aria-label="Delete {ui_note_file}"]').click()
            await row.wait_for(state="hidden", timeout=8000)
            ctx.assertions["ui_workspace_files_crud"] = True

            if vnc_available:
                await page.get_by_role("button", name="Screen", exact=True).click()
                await page.locator("canvas").first.wait_for(state="visible", timeout=10000)
                await page.get_by_role("button", name="Take control").click()
                dlg = page.locator('[role="dialog"][aria-label="Full-screen computer view"]')
                await dlg.wait_for(state="visible", timeout=8000)
                await dlg.get_by_role("button", name="I'm done").click()
                await dlg.wait_for(state="hidden", timeout=8000)
                ctx.assertions["ui_vnc_takeover_handback"] = True

            ctx.assertions["browser_clean"] = (
                not pw.console_errors and not pw.page_errors and not pw.external_requests
            )
            all_ok = all(ctx.assertions.values()) and not ctx.error_notes
            await ctx.capture_shot(page, "cb06_computer", is_error_state=not all_ok)

        ctx.evidence = {
            "display_mode": display_mode,
            "vnc_available": vnc_available,
            "pty_echo": pty_ok,
        }
        ctx.clarity_notes = (
            "CB-06 computer status, takeover/409/handback, PTY & workspace files verified."
        )
    finally:
        with ctx.sync_client() as c:
            if takeover_active:
                with contextlib.suppress(Exception):
                    c.post("/api/v1/computers/default/handback", json={})
            with contextlib.suppress(Exception):
                c.delete("/api/v1/computers/default/files", params={"path": probe_file})
            with contextlib.suppress(Exception):
                c.delete("/api/v1/computers/default/files", params={"path": ui_note_file})


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-06 scenario."""
    run_coro_sync(_run_cb06_async(ctx))
    return finalize_scenario(ctx)
