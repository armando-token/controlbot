"""Tier 4 Playwright E2E tests: Inspector (Details/Library/Computer), Settings, Apps & Memory."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

import pytest
from playwright.async_api import ConsoleMessage, Response, Route, WebSocket
from tests.e2e._helpers import IsolatedServer
from tests.e2e.conftest import StrictBrowserPage

pytestmark = pytest.mark.e2e

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


def _is_loopback_browser_url(url: str) -> bool:
    if url.startswith(("data:", "blob:", "about:")):
        return True
    parsed = urlparse(url)
    if parsed.scheme in {"http", "https", "ws", "wss"}:
        return (parsed.hostname or "").lower() in _LOOPBACK_HOSTS
    return False


async def test_inspector_details_routines_skills_vault_and_library(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    page = strict_browser_page.page
    await page.goto(server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
    await page.get_by_role("tab", name="Details").wait_for(state="visible")

    # 1. Routines: create, test, pause/resume persisted across reload, delete
    routines_hdr = page.locator("span:text-is('Routines')").locator("xpath=..")
    await routines_hdr.get_by_role("button", name="Add").click()
    dialog = page.get_by_role("dialog")
    await dialog.locator('input[placeholder="e.g. Morning operations brief"]').fill("Morning Check")
    await dialog.locator(
        'textarea[placeholder="What should the bot check, produce, or report?"]'
    ).fill("Check pump telemetry")
    await dialog.get_by_role("button", name="Create routine").click()
    await dialog.wait_for(state="hidden")

    routine_card = page.locator("div.p-2\\.5").filter(has_text="Morning Check").first
    await routine_card.wait_for(state="visible")

    async with page.expect_response(
        lambda r: "/api/v1/routines/" in r.url and r.url.endswith("/test")
    ) as test_resp:
        await routine_card.get_by_role("button", name="Test").click()
    assert (await test_resp.value).status == 202

    await routine_card.get_by_role("button", name="Runs").click()
    runs_dialog = page.get_by_role("dialog")
    await runs_dialog.get_by_text("Recent runs (last 20)").wait_for(state="visible")
    await runs_dialog.get_by_text(re.compile(r"manual", re.I)).first.wait_for(state="visible")
    await page.keyboard.press("Escape")
    await runs_dialog.wait_for(state="hidden")

    # Pause routine and verify persisted across page.reload()
    await routine_card.locator('input[title="Pause routine"]').click()
    await routine_card.locator('input[title="Resume routine"]').wait_for(state="visible")

    await page.reload(wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
    routine_card = page.locator("div.p-2\\.5").filter(has_text="Morning Check").first
    await routine_card.locator('input[title="Resume routine"]').wait_for(state="visible")
    await routine_card.locator('input[title="Resume routine"]').click()
    await routine_card.locator('input[title="Pause routine"]').wait_for(state="visible")
    await routine_card.locator('button[title="Delete routine"]').click()
    await routine_card.wait_for(state="hidden")

    # 2. Skills: create, click to insert @slug into composer, delete
    skills_hdr = page.locator("span:text-is('Skills')").locator("xpath=..")
    await skills_hdr.get_by_role("button", name="Add").click()
    await page.locator('input[placeholder="Skill name"]').fill("Pump Audit")
    await page.locator('input[placeholder="One-line description"]').fill("Check pump seals")
    await page.get_by_label("Skill markdown instructions").fill(
        "1. Read pressure\n2. Check seal"
    )
    await page.get_by_role("button", name="Save", exact=True).click()

    skill_row = page.locator("div.group").filter(has_text="Pump Audit").first
    await skill_row.wait_for(state="visible")
    await skill_row.locator('button[title="Insert @skill into composer"]').click()
    composer_val = await page.locator('textarea[aria-label="Message composer"]').input_value()
    assert "@pump-audit" in composer_val or "@Pump" in composer_val

    await skill_row.hover()
    await skill_row.locator('button[title="Delete skill"]').click()
    await skill_row.wait_for(state="hidden")

    # 3. Bot Vault: create secret ("••••••••") & delete
    vault_hdr = page.locator("span:text-is('Bot vault')").locator("xpath=..")
    await vault_hdr.get_by_role("button", name="Add secret").click()
    await page.locator('input[placeholder="Secret label (e.g. CRM API Key)"]').fill("SCADA Key")
    await page.locator('input[placeholder="Domain (optional)"]').fill("scada.local")
    await page.locator('input[placeholder="Secret value (never shown again)"]').fill(
        "tok_secret_vault_88"
    )
    await page.get_by_role("button", name="Save securely").click()
    secret_row = page.locator("div").filter(has_text="SCADA Key").filter(has_text="••••••••").first
    await secret_row.wait_for(state="visible")
    assert "tok_secret_vault_88" not in await page.locator("body").inner_text()
    await secret_row.locator('button[title="Delete secret"]').click()
    await secret_row.wait_for(state="hidden")

    # 4. Library tab: create Page, filter Pages / Skills / Apps / Pinned / All, search, pin, delete
    await page.get_by_role("tab", name="Library").click()
    await page.locator('button[title="New page"]').click()
    await page.locator(".gb-printable-page").wait_for(state="visible")
    await page.locator('button[title="Close split-screen page"]').click()
    await page.locator(".gb-printable-page").wait_for(state="hidden")

    art_row = page.locator("div.group").filter(has_text="Chief of Staff Document").first
    await art_row.wait_for(state="visible")

    await page.get_by_role("button", name="Pages", exact=True).click()
    await art_row.wait_for(state="visible")
    async with page.expect_response(
        lambda r: "/api/v1/bots/bot_chief/library" in r.url and "type=skill" in r.url
    ) as skills_resp:
        await page.get_by_role("button", name="Skills", exact=True).click()
    assert (await skills_resp.value).status == 200
    await art_row.wait_for(state="hidden")
    await page.get_by_text("No items in library yet").wait_for(state="visible")

    async with page.expect_response(
        lambda r: "/api/v1/bots/bot_chief/library" in r.url and "type=app" in r.url
    ) as apps_resp:
        await page.get_by_role("button", name="Apps", exact=True).click()
    assert (await apps_resp.value).status == 200
    await art_row.wait_for(state="hidden")
    await page.get_by_text("No items in library yet").wait_for(state="visible")

    await page.get_by_role("button", name="Pinned", exact=True).click()
    await art_row.wait_for(state="hidden")
    await page.get_by_role("button", name="All", exact=True).click()
    await art_row.wait_for(state="visible")

    await page.locator('input[placeholder="Search library…"]').fill("Chief of Staff Document")
    await art_row.wait_for(state="visible")

    await art_row.hover()
    await art_row.locator('button[title="Pin"]').click()
    await page.get_by_role("button", name="Pinned", exact=True).click()
    await art_row.wait_for(state="visible")

    await art_row.hover()
    await art_row.locator('button[title="Delete"]').click()
    await art_row.wait_for(state="hidden")

    strict_browser_page.assert_clean()


async def test_inspector_computer_terminal_files_and_takeover(
    server_factory: Callable[..., IsolatedServer],
    strict_browser_page: StrictBrowserPage,
    tmp_path: Path,
) -> None:
    srv = server_factory(with_mock_rfb=True, name="computer_rfb")
    page = strict_browser_page.page
    await page.goto(srv.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    await page.locator('button[title="Open Bot Computer"]').click()

    # 1. TerminalTab: xterm.js PTY connect + echo PLAYWRIGHT_PTY_42
    await page.get_by_role("button", name="Terminal", exact=True).click()
    await page.locator('span[title="connected"]').wait_for(state="visible", timeout=10000)
    await page.locator(".xterm").wait_for(state="visible")
    xterm_input = page.locator(".xterm-helper-textarea")
    await xterm_input.focus()
    await page.keyboard.type("echo PLAYWRIGHT_PTY_42")
    await page.keyboard.press("Enter")
    await page.wait_for_function(
        "() => (document.querySelector('.xterm-rows')?.innerText || '')"
        ".includes('PLAYWRIGHT_PTY_42')",
        timeout=10000,
    )

    # 2. WorkspaceFilesTab: mkdir, create file, edit & save, upload, delete
    await page.get_by_role("button", name="Files", exact=True).click()
    await page.get_by_role("button", name="Folder", exact=True).click()
    await page.locator('input[placeholder="folder-name"]').fill("e2e_dir")
    await page.get_by_role("button", name="Create", exact=True).click()
    await page.get_by_role("button", name="e2e_dir", exact=True).click()

    await page.get_by_role("button", name="New file", exact=True).click()
    await page.locator('input[placeholder="notes.md"]').fill("probe.txt")
    await page.locator('textarea[placeholder="File content…"]').fill("initial_v1")
    await page.get_by_role("button", name="Create file").click()

    await page.get_by_role("button", name="probe.txt", exact=True).click()
    edit_dialog = page.get_by_role("dialog")
    await edit_dialog.locator("textarea").wait_for(state="visible")
    await edit_dialog.locator("textarea").fill("updated_v2")
    await edit_dialog.get_by_role("button", name="Save file").click()
    await edit_dialog.get_by_role("button", name="Close", exact=True).click()
    await edit_dialog.wait_for(state="hidden")

    await page.get_by_role("button", name="probe.txt", exact=True).click()
    await page.wait_for_function(
        "() => document.querySelector('[role=\"dialog\"] textarea')?.value === 'updated_v2'"
    )
    await page.get_by_role("dialog").get_by_role("button", name="Close", exact=True).click()

    upload_file = tmp_path / "uploaded_e2e.txt"
    upload_file.write_text("upload_payload_ok", encoding="utf-8")
    await page.locator('input[type="file"]').last.set_input_files(str(upload_file))
    uploaded_row = page.locator("div.group").filter(has_text="uploaded_e2e.txt").first
    await uploaded_row.wait_for(state="visible")
    await uploaded_row.hover()
    await page.locator('button[aria-label="Delete uploaded_e2e.txt"]').click()
    await uploaded_row.wait_for(state="hidden")

    # 3. Screen & FullScreenTakeoverModal: Take control -> timer ticks -> I'm done -> Expand preview
    await page.get_by_role("button", name="Screen", exact=True).click()
    await page.get_by_role("button", name="Take control").click()

    takeover_dlg = page.locator('[role="dialog"][aria-label="Full-screen computer view"]')
    await takeover_dlg.wait_for(state="visible")
    badge = takeover_dlg.locator("span").filter(has_text="You're in control").first
    await badge.wait_for(state="visible")

    t1_text = await badge.inner_text()
    m1 = re.search(r"(\d+):(\d{2})", t1_text)
    assert m1 is not None, f"Expected countdown in takeover badge, got: {t1_text!r}"
    sec1 = int(m1.group(1)) * 60 + int(m1.group(2))
    assert sec1 > 0

    await asyncio.sleep(2.1)
    t2_text = await badge.inner_text()
    m2 = re.search(r"(\d+):(\d{2})", t2_text)
    assert m2 is not None
    sec2 = int(m2.group(1)) * 60 + int(m2.group(2))
    assert sec2 < sec1, f"Countdown did not tick down: {t1_text!r} -> {t2_text!r}"

    await takeover_dlg.get_by_role("button", name="I'm done").click()
    await takeover_dlg.wait_for(state="hidden")
    await page.get_by_text("Control returned to your Bot").wait_for(state="visible")

    await page.locator('button[title="Expand full screen"]').click()
    await takeover_dlg.get_by_text("Preview mode (read-only)").wait_for(state="visible")
    await takeover_dlg.locator('button[title="Exit full screen"]').click()
    await takeover_dlg.wait_for(state="hidden")

    strict_browser_page.assert_clean()


async def test_m4_routine_edit_skill_viewer_and_library_pills(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    page = strict_browser_page.page
    await page.goto(server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()

    # Create routine & verify visibility/edit/regenerate_webhook_key in modal
    routines_hdr = page.locator("span:text-is('Routines')").locator("xpath=..")
    await routines_hdr.get_by_role("button", name="Add").click()
    dialog = page.get_by_role("dialog")
    await dialog.locator(
        'input[placeholder="e.g. Morning operations brief"]'
    ).fill("Editable Routine")
    await dialog.locator(
        'textarea[placeholder="What should the bot check, produce, or report?"]'
    ).fill("Initial instruction")
    await dialog.get_by_role("button", name="Create routine").click()
    await dialog.wait_for(state="hidden")

    await page.locator("div.p-2\\.5").filter(has_text="Editable Routine").first.get_by_role(
        "button", name="Runs"
    ).click()
    detail_dlg = page.get_by_role("dialog")
    await detail_dlg.get_by_role("button", name=re.compile(r"Regenerate", re.I)).click()
    await detail_dlg.get_by_role("button", name=re.compile(r"Edit", re.I)).click()
    await detail_dlg.locator('select[aria-label="Edit routine visibility"]').select_option("team")
    await detail_dlg.get_by_role("button", name=re.compile(r"Save", re.I)).click()
    await page.keyboard.press("Escape")

    # Skill content_md viewer
    skills_hdr = page.locator("span:text-is('Skills')").locator("xpath=..")
    await skills_hdr.get_by_role("button", name="Add").click()
    await page.locator('input[placeholder="Skill name"]').fill("Viewer Skill")
    await page.get_by_label("Skill markdown instructions").fill(
        "## Playbook\n- Step Alpha"
    )
    await page.get_by_role("button", name="Save", exact=True).click()
    skill_row = page.locator("div.group").filter(has_text="Viewer Skill").first
    await skill_row.locator('button[title="View skill instructions"]').click()
    await page.get_by_role("dialog").get_by_text("Step Alpha").wait_for(state="visible")
    await page.keyboard.press("Escape")

    strict_browser_page.assert_clean()


async def test_m4_terminal_ctrl_d_guard_single_canvas_and_takeover_escape(
    server_factory: Callable[..., IsolatedServer],
    strict_browser_page: StrictBrowserPage,
) -> None:
    srv = server_factory(with_mock_rfb=True, name="m4_term_vnc")

    # Playwright's context.route_web_socket replaces window.WebSocket with WebSocketMock,
    # whose parent-prototype methods fail @novnc/novnc Websock.attach's 1-level property
    # check. Use a fresh BrowserContext on strict_browser_page.browser with HTTP route guard
    # + console/pageerror/HTTP>=400/WS-origin listeners forwarding into strict_browser_page.
    ctx = await strict_browser_page.browser.new_context(viewport={"width": 1280, "height": 800})

    async def _http_guard(route: Route) -> None:
        req_url = route.request.url
        if _is_loopback_browser_url(req_url):
            await route.continue_()
        else:
            strict_browser_page.external_requests.append(req_url)
            await route.abort()

    await ctx.route("**/*", _http_guard)
    page = await ctx.new_page()

    def _on_console(msg: ConsoleMessage) -> None:
        if msg.type == "error":
            strict_browser_page.console_errors.append(msg.text)

    def _on_pageerror(exc: Exception) -> None:
        strict_browser_page.page_errors.append(repr(exc))

    def _on_response(resp: Response) -> None:
        if resp.status >= 400:
            strict_browser_page.http_errors.append((resp.status, resp.url))

    def _ws_observer(ws: WebSocket) -> None:
        if not _is_loopback_browser_url(ws.url):
            strict_browser_page.external_requests.append(ws.url)

    page.on("console", _on_console)
    page.on("pageerror", _on_pageerror)
    page.on("response", _on_response)
    page.on("websocket", _ws_observer)

    try:
        await page.goto(srv.url("/app"), wait_until="networkidle")
        await page.wait_for_selector("text=Chief of Staff")

        await page.locator('button[title="Open Bot Computer"]').click()

        # 1. Control+d inside .xterm-helper-textarea must NOT trigger Voice Dictation
        await page.get_by_role("button", name="Terminal", exact=True).click()
        await page.locator('span[title="connected"]').wait_for(state="visible", timeout=10000)
        await page.locator(".xterm-helper-textarea").focus()
        await page.keyboard.press("Control+d")
        await asyncio.sleep(0.3)
        assert await page.get_by_text("Voice dictation unavailable").count() == 0
        assert await page.locator('button[aria-label="Stop voice dictation"]').count() == 0

        # 2. Takeover modal has single active LiveVncCanvas mount and closes on Escape
        await page.get_by_role("button", name="Screen", exact=True).click()
        await page.get_by_role("button", name="Take control").click()
        takeover_dlg = page.locator('[role="dialog"][aria-label="Full-screen computer view"]')
        await takeover_dlg.wait_for(state="visible")
        await takeover_dlg.locator("canvas").wait_for(state="visible")
        await page.get_by_text("Active in full-screen takeover").wait_for(state="visible")
        assert await page.locator("canvas").count() == 1
        assert await takeover_dlg.locator("canvas").count() == 1
        await page.keyboard.press("Escape")
        await takeover_dlg.wait_for(state="hidden")
    finally:
        await ctx.unroute_all(behavior="ignoreErrors")
        await page.close()
        await ctx.close()

    strict_browser_page.assert_clean()


async def test_settings_persistence_and_connect_apps_across_reload(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    page = strict_browser_page.page
    await page.goto(server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    sidebar = page.locator("aside")

    # 1. SettingsDialog: Dark + Black (monochrome) + Auto-review rule -> reload -> verify -> restore
    await sidebar.get_by_role("button", name="Settings").click()
    dlg = page.get_by_role("dialog")
    await dlg.get_by_role("button", name="Dark", exact=True).click()
    await dlg.get_by_role("button", name="Black (monochrome)", exact=True).click()
    await dlg.locator('input[placeholder="e.g. Allow read-only git status and log checks"]').fill(
        "Allow e2e telemetry read"
    )
    await dlg.get_by_role("button", name="Add", exact=True).click()
    await dlg.get_by_text("Allow e2e telemetry read").wait_for(state="visible")
    await page.keyboard.press("Escape")
    await dlg.wait_for(state="hidden")

    await page.reload(wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    assert await page.evaluate("document.documentElement.getAttribute('data-theme')") == "dark"

    await sidebar.get_by_role("button", name="Settings").click()
    dlg = page.get_by_role("dialog")
    await dlg.get_by_text("Allow e2e telemetry read").wait_for(state="visible")

    rule_row = dlg.locator("div.flex.items-center.justify-between").filter(
        has_text="Allow e2e telemetry read"
    ).first
    await rule_row.locator('button[title="Delete rule"]').click()
    await dlg.get_by_text("Allow e2e telemetry read").wait_for(state="hidden")
    await dlg.get_by_role("button", name="Light", exact=True).click()
    await page.keyboard.press("Escape")
    await dlg.wait_for(state="hidden")
    assert await page.evaluate("document.documentElement.getAttribute('data-theme')") == "light"

    # 2. ConnectAppsModal: toggle connected app & verify persistence across reload
    await sidebar.get_by_role("button", name="Connect apps").click()
    apps_dlg = page.get_by_role("dialog")
    first_toggle = apps_dlg.locator("button").filter(
        has_text=re.compile(r"^(Connect|Connected)$")
    ).first
    initial_label = (await first_toggle.inner_text()).strip()
    expected_after = "Connect" if initial_label == "Connected" else "Connected"
    await first_toggle.click()
    await apps_dlg.locator("button").filter(
        has_text=re.compile(rf"^{expected_after}$")
    ).first.wait_for(state="visible")
    await page.keyboard.press("Escape")
    await apps_dlg.wait_for(state="hidden")

    await page.reload(wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    await sidebar.get_by_role("button", name="Connect apps").click()
    apps_dlg = page.get_by_role("dialog")
    persisted_label = (
        await apps_dlg.locator("button")
        .filter(has_text=re.compile(r"^(Connect|Connected)$"))
        .first.inner_text()
    ).strip()
    assert persisted_label == expected_after

    strict_browser_page.assert_clean()


async def test_m4_settings_extended_fields_and_connect_apps_label(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    page = strict_browser_page.page
    await page.goto(server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")
    sidebar = page.locator("aside")

    await sidebar.get_by_role("button", name="Settings").click()
    dlg = page.get_by_role("dialog")
    await dlg.get_by_label("Display name").fill("Plant Supervisor")
    await dlg.get_by_label("Default thinking level").select_option("high")
    await dlg.get_by_label("Allow Hydrogen models").check()
    await dlg.get_by_label("Desktop notifications enabled").uncheck()
    await dlg.get_by_label("Default timezone").select_option("America/New_York")
    await page.keyboard.press("Escape")

    await page.reload(wait_until="networkidle")
    await sidebar.get_by_role("button", name="Settings").click()
    dlg = page.get_by_role("dialog")
    assert await dlg.get_by_label("Display name").input_value() == "Plant Supervisor"
    assert await dlg.get_by_label("Default thinking level").input_value() == "high"
    assert await dlg.get_by_label("Allow Hydrogen models").is_checked() is True
    assert await dlg.get_by_label("Desktop notifications enabled").is_checked() is False
    assert await dlg.get_by_label("Default timezone").input_value() == "America/New_York"
    await page.keyboard.press("Escape")

    await sidebar.get_by_role("button", name="Connect apps").click()
    apps_dlg = page.get_by_role("dialog")
    await apps_dlg.locator('button[aria-label^="Configure "]').first.click()
    await apps_dlg.locator('input[aria-label*="Account label"]').first.fill("prod-plant-a")
    await apps_dlg.get_by_role("button", name="Save").first.click()
    await page.keyboard.press("Escape")

    await page.reload(wait_until="networkidle")
    await sidebar.get_by_role("button", name="Connect apps").click()
    apps_dlg = page.get_by_role("dialog")
    await apps_dlg.locator('button[aria-label^="Configure "]').first.click()
    assert (
        await apps_dlg.locator('input[aria-label*="Account label"]').first.input_value()
        == "prod-plant-a"
    )

    strict_browser_page.assert_clean()


async def test_m4_m5_memory_browser_editor_409_conflict_export_delete(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
    tmp_path: Path,
) -> None:
    page = strict_browser_page.page
    await page.goto(server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    # Open Memory Browser/Editor UI
    await page.locator("aside").get_by_role("button", name=re.compile(r"Memory", re.I)).click()
    mem_dlg = page.get_by_role("dialog")
    await mem_dlg.wait_for(state="visible")

    # Create memory item
    await mem_dlg.get_by_role("button", name="New memory").click()
    await mem_dlg.get_by_label("Title").fill("Pump P-101 Seal")
    await mem_dlg.get_by_label("Content").fill("Inspect mechanical seal hourly.")
    await mem_dlg.get_by_role("button", name="Save memory").click()
    await mem_dlg.get_by_text("Pump P-101 Seal").wait_for(state="visible")

    # Open inline editor before concurrent PATCH so UI holds stale revision 1
    await mem_dlg.get_by_role("button", name="Edit Pump P-101 Seal").click()
    await mem_dlg.get_by_role("button", name="Save changes").wait_for(state="visible")

    # Trigger stale revision HTTP 409 conflict via concurrent PATCH before saving edit in UI
    with server.client() as client:
        items = client.get("/api/v1/memory").json()["items"]
        target = next(it for it in items if it["title"] == "Pump P-101 Seal")
        patch_resp = client.patch(
            f"/api/v1/memory/{target['id']}",
            json={"revision": target["revision"], "content": "Concurrent update"},
        )
        assert patch_resp.status_code == 200

    await mem_dlg.get_by_label("Content").fill("Stale browser edit")
    await mem_dlg.get_by_role("button", name="Save changes").click()
    await mem_dlg.locator('[role="alert"]').get_by_text(
        re.compile(r"409|conflict|revision", re.I)
    ).wait_for(state="visible")

    # Export JSON and Export MD explicitly
    async with page.expect_download() as json_dl_info:
        await mem_dlg.get_by_role("button", name="Export JSON").click()
    json_dl = await json_dl_info.value
    json_dest = tmp_path / json_dl.suggested_filename
    await json_dl.save_as(json_dest)
    assert "Pump P-101 Seal" in json_dest.read_text(encoding="utf-8")

    async with page.expect_download() as md_dl_info:
        await mem_dlg.get_by_role("button", name="Export MD").click()
    md_dl = await md_dl_info.value
    md_dest = tmp_path / md_dl.suggested_filename
    await md_dl.save_as(md_dest)
    assert "Pump P-101 Seal" in md_dest.read_text(encoding="utf-8")

    # Delete item
    await mem_dlg.get_by_role("button", name="Delete Pump P-101 Seal").click()
    await mem_dlg.get_by_text("Pump P-101 Seal").wait_for(state="hidden")

    strict_browser_page.assert_clean(
        allow_http_statuses=[409],
        allow_console_substrings=["409 (Conflict)"],
    )
