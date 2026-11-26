"""Tier 4 Playwright E2E tests: Studio Shell, Bots/Channels, @Mentions & Split Pages."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from playwright.async_api import Request
from tests.e2e._helpers import IsolatedServer
from tests.e2e.conftest import StrictBrowserPage

pytestmark = pytest.mark.e2e

_MOCK_CONV_ID = "22222222-3333-4444-5555-666666666666"
_STUDIO_MOCK_AGY_SCRIPT = f"""#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

prompt = ""
for i, arg in enumerate(args):
    if arg == "-p" and i + 1 < len(args):
        prompt = args[i + 1]
        break
    if arg.startswith("--prompt="):
        prompt = arg.split("=", 1)[1]
        break

reply = "Mock ops stream ack: status report"
if "Summarize" in prompt:
    reply = "Mock ops stream ack: brief summary ready"

cid = "{_MOCK_CONV_ID}"
if "--output-format" in args and "stream-json" in args:
    print(json.dumps({{
        "event": "init",
        "conversation_id": cid,
        "init": {{"model": "gemini-4-carbon-low"}},
    }}), flush=True)
    print(json.dumps({{
        "event": "step_update",
        "step_update": {{
            "step_type": "agent_response",
            "text_delta": reply,
        }},
    }}), flush=True)
    print(json.dumps({{
        "event": "result",
        "result": {{
            "status": "SUCCESS",
            "conversation_id": cid,
            "response": reply,
        }},
    }}), flush=True)
    sys.exit(0)

print(json.dumps({{
    "status": "SUCCESS",
    "conversation_id": cid,
    "response": reply,
}}))
"""


async def test_studio_boot_auth_token_propagation_and_seeded_bots(
    auth_server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    page = strict_browser_page.page
    captured_urls: list[str] = []

    def _on_request(req: Request) -> None:
        if req.url.startswith(auth_server.base_url):
            captured_urls.append(req.url)

    page.on("request", _on_request)

    await page.goto(auth_server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    assert await page.title() == "Grok Bot — ControlBot Studio"
    assert await page.evaluate("document.documentElement.getAttribute('data-theme')") == "light"

    composer = page.locator('textarea[aria-label="Message composer"]')
    assert await composer.get_attribute("placeholder") == "Message Chief of Staff"

    sidebar = page.locator("aside")
    await sidebar.get_by_text("Chief of Staff").wait_for(state="visible")
    await sidebar.get_by_text("Primary").wait_for(state="visible")
    await sidebar.get_by_text("ControlBot Ops").wait_for(state="visible")
    await sidebar.get_by_text("Browser Runner").wait_for(state="visible")

    expected_token = auth_server.web_token
    assert expected_token is not None

    asset_urls = [u for u in captured_urls if "/assets/" in urlparse(u).path]
    api_urls = [
        u
        for u in captured_urls
        if urlparse(u).path.startswith("/api/v1/") and "/events/stream" not in u
    ]
    sse_urls = [u for u in captured_urls if "/api/v1/events/stream" in urlparse(u).path]

    assert asset_urls, "Expected /assets/* requests on studio load"
    assert api_urls, "Expected /api/v1/* requests on studio load"
    assert sse_urls, "Expected /api/v1/events/stream SSE connection on studio load"

    for url in asset_urls + api_urls + sse_urls:
        qs = parse_qs(urlparse(url).query)
        assert qs.get("token") == [expected_token], f"Missing ?token= on {url}"

    strict_browser_page.assert_clean()


async def test_studio_bot_channel_section_crud_hide_unhide_and_shortcuts(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    page = strict_browser_page.page
    await page.goto(server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    composer = page.locator('textarea[aria-label="Message composer"]')
    sidebar = page.locator("aside")

    # Switch bots
    await sidebar.get_by_text("ControlBot Ops").click()
    assert await composer.get_attribute("placeholder") == "Message ControlBot Ops"

    await sidebar.get_by_text("Chief of Staff").click()
    assert await composer.get_attribute("placeholder") == "Message Chief of Staff"

    # Ctrl+B sidebar collapse / expand
    await page.keyboard.press("Control+b")
    await page.locator('button[title="Expand sidebar (Cmd/Ctrl+B)"]').wait_for(state="visible")
    await page.keyboard.press("Control+b")
    await page.locator('button[title="Collapse sidebar (Cmd/Ctrl+B)"]').wait_for(state="visible")

    # Create section
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New section").click()
    sec_input = page.locator('input[placeholder="Section name, press Enter…"]')
    await sec_input.fill("Plant Ops")
    await sec_input.press("Enter")
    await sidebar.get_by_text("Plant Ops").wait_for(state="visible")

    # Create new bot via modal
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.locator("button").filter(has_text=re.compile(r"^New bot")).click()
    await page.locator("#new-bot-name").fill("Turbine Analyst")
    await page.locator('button[aria-label="Select color #0891B2"]').click()
    await page.get_by_role("button", name="Create bot").click()
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message Turbine Analyst'"
    )

    # Hide & Unhide via HiddenBotsDrawer
    bot_row = sidebar.locator("div.group").filter(has_text="Turbine Analyst").first
    await bot_row.hover()
    await page.locator('button[aria-label="More options for Turbine Analyst"]').click()
    await page.get_by_role("button", name="Hide from sidebar").click()
    await sidebar.get_by_text("Turbine Analyst").wait_for(state="hidden")

    await sidebar.get_by_role("button", name="Hidden bots").click()
    drawer = page.get_by_role("dialog")
    await drawer.get_by_text("Turbine Analyst").wait_for(state="visible")
    await drawer.get_by_role("button", name="Unhide").click()
    await page.keyboard.press("Escape")
    await drawer.wait_for(state="hidden")
    await sidebar.get_by_text("Turbine Analyst").wait_for(state="visible")

    # Create group channel with 2 bots
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New group chat").click()
    dialog = page.get_by_role("dialog")
    await dialog.locator("#new-channel-name").fill("Ops Sync")
    await dialog.get_by_role("button", name="Chief of Staff").click()
    await dialog.get_by_role("button", name="ControlBot Ops").click()
    await dialog.get_by_text("2 / 6 selected").wait_for(state="visible")
    await dialog.get_by_role("button", name="Create group chat").click()
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message #Ops Sync (use @ to mention bots)'"
    )

    # Ctrl+K Command Palette jump back to Turbine Analyst
    await page.keyboard.press("Control+k")
    palette_input = page.locator(
        'input[placeholder="Search bots, messages, Pages, routines, or commands…"]'
    )
    await palette_input.wait_for(state="visible")
    await palette_input.fill("Turbine Analyst")
    await palette_input.press("Enter")
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message Turbine Analyst'"
    )

    strict_browser_page.assert_clean()


async def test_studio_mention_popover_and_live_sse_streaming(
    server_factory: Callable[..., IsolatedServer],
    strict_browser_page: StrictBrowserPage,
) -> None:
    srv = server_factory(mock_agy_script=_STUDIO_MOCK_AGY_SCRIPT, name="studio_stream")
    page = strict_browser_page.page
    await page.goto(srv.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    # Create a group channel with Chief of Staff & ControlBot Ops
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New group chat").click()
    dialog = page.get_by_role("dialog")
    await dialog.locator("#new-channel-name").fill("Ops Live")
    await dialog.get_by_role("button", name="Chief of Staff").click()
    await dialog.get_by_role("button", name="ControlBot Ops").click()
    await dialog.get_by_role("button", name="Create group chat").click()
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message #Ops Live (use @ to mention bots)'"
    )

    # Type @, select ControlBot Ops from popover, send and observe live SSE reply without reload
    composer = page.locator('textarea[aria-label="Message composer"]')
    await composer.click()
    await composer.type("@")
    mention_hdr = page.get_by_text("Mention", exact=True)
    await mention_hdr.wait_for(state="visible")
    mention_popover = mention_hdr.locator("xpath=..")
    await mention_popover.locator("button").filter(has_text="ControlBot Ops").click()
    await page.wait_for_function(
        "() => /^@controlbot[_-]ops\\s/i.test("
        "document.querySelector('textarea[aria-label=\"Message composer\"]')?.value || '')"
    )
    await composer.type("status report")
    await composer.press("Enter")

    await page.get_by_text("Mock ops stream ack: status report").wait_for(
        state="visible", timeout=10000
    )
    strict_browser_page.assert_clean()


async def test_studio_split_page_group_new_page_context_export_and_reactions(
    server_factory: Callable[..., IsolatedServer],
    strict_browser_page: StrictBrowserPage,
    tmp_path: Path,
) -> None:
    srv = server_factory(mock_agy_script=_STUDIO_MOCK_AGY_SCRIPT, name="studio_pages")
    page = strict_browser_page.page
    await page.goto(srv.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    # 1:1 bot "New page" -> HTTP 201 and split pane opens
    async with page.expect_response(
        lambda r: r.url.endswith("/api/v1/pages") and r.request.method == "POST"
    ) as resp_1v1:
        await page.locator('button[title="Create new interactive page"]').click()
    r1 = await resp_1v1.value
    assert r1.status == 201
    await page.locator(".gb-printable-page").wait_for(state="visible")
    await page.locator('button[title="Close split-screen page"]').click()
    await page.locator(".gb-printable-page").wait_for(state="hidden")

    # Create Group Channel and open "New page" inside group channel -> HTTP 201 (no 422!)
    await page.locator('button[title="New bot, group chat, or section (Cmd/Ctrl+N)"]').click()
    await page.get_by_role("button", name="New group chat").click()
    dialog = page.get_by_role("dialog")
    await dialog.locator("#new-channel-name").fill("Page Collab")
    await dialog.get_by_role("button", name="Chief of Staff").click()
    await dialog.get_by_role("button", name="ControlBot Ops").click()
    await dialog.get_by_role("button", name="Create group chat").click()
    await page.wait_for_function(
        "() => document.querySelector('textarea[aria-label=\"Message composer\"]')"
        "?.getAttribute('placeholder') === 'Message #Page Collab (use @ to mention bots)'"
    )

    async with page.expect_response(
        lambda r: r.url.endswith("/api/v1/pages") and r.request.method == "POST"
    ) as resp_grp:
        await page.locator('button[title="Create new interactive page"]').click()
    r2 = await resp_grp.value
    assert r2.status == 201
    group_page_id = str((await r2.json())["id"])
    assert group_page_id

    split_page = page.locator(".gb-printable-page")
    await split_page.wait_for(state="visible")

    # Edit Markdown & Save changes
    await split_page.get_by_role("button", name="Edit").click()
    editor = split_page.locator("textarea")
    await editor.fill("# Shift Brief\n\nCheck needle valve calibration and needle seal.")
    await split_page.get_by_role("button", name="Save changes").click()
    await split_page.get_by_role("heading", name="Shift Brief").wait_for(state="visible")

    # Verify composer placeholder updated to "Message about ..." & page_context_id sent in POST
    composer = page.locator('textarea[aria-label="Message composer"]')
    placeholder = await composer.get_attribute("placeholder")
    assert placeholder is not None and placeholder.startswith("Message about ")

    async with page.expect_request(
        lambda req: "/api/v1/threads/" in req.url
        and req.url.endswith("/messages")
        and req.method == "POST"
    ) as msg_req_info:
        await composer.fill("Summarize this brief")
        await composer.press("Enter")
    msg_req = await msg_req_info.value
    payload = json.loads(msg_req.post_data or "{}")
    assert payload.get("page_context_id") == group_page_id

    await page.get_by_text("Mock ops stream ack: brief summary ready").wait_for(
        state="visible", timeout=10000
    )

    # Toggle pin & Share access
    await split_page.locator('button[title="Pin page"]').click()
    await split_page.locator('button[title="Unpin page"]').wait_for(state="visible")
    await split_page.locator('select[aria-label="Share access"]').select_option("team")
    await split_page.get_by_text("Shared with your team").wait_for(state="visible")

    # Export Markdown download
    async with page.expect_download() as dl_info:
        await split_page.locator('button[title="Export Markdown"]').click()
    dl = await dl_info.value
    assert dl.suggested_filename.endswith(".md")
    dl_dest = tmp_path / dl.suggested_filename
    await dl.save_as(dl_dest)
    assert "Check needle valve calibration" in dl_dest.read_text(encoding="utf-8")

    # Close split pane, then react 👍 and Save as Page (to-page) on bot message
    await split_page.locator('button[title="Close split-screen page"]').click()
    await split_page.wait_for(state="hidden")

    bot_msg = page.locator("div.group").filter(
        has_text="Mock ops stream ack: brief summary ready"
    ).first
    await bot_msg.hover()
    await bot_msg.locator('button[title="React 👍"]').click()
    await bot_msg.locator("button").filter(has_text="👍").filter(has_text="1").wait_for(
        state="visible"
    )

    await bot_msg.hover()
    async with page.expect_response(
        lambda r: "/to-page" in r.url and r.request.method == "POST"
    ) as to_page_resp:
        await bot_msg.locator('button[title="Save as interactive Page"]').click()
    assert (await to_page_resp.value).status == 201
    await split_page.wait_for(state="visible")

    strict_browser_page.assert_clean()


async def test_studio_page_search_dom_mark_gb_search_hit(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    with server.client() as client:
        created = client.post(
            "/api/v1/pages",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "title": "Valve Spec",
                "content_md": "# Valve Spec\n\nCheck **needle** pressure and needle seal.",
            },
        )
        assert created.status_code == 201
        page_id = created.json()["id"]

    page = strict_browser_page.page
    await page.goto(server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    # Open the created page via Library tab
    await page.locator('button[title="Toggle inspector panel (Cmd+Shift+I)"]').click()
    await page.get_by_role("tab", name="Library").click()
    await page.get_by_text("Valve Spec").click()

    split_page = page.locator(".gb-printable-page")
    await split_page.wait_for(state="visible")
    assert page_id

    await split_page.locator('button[title="Find in page (Cmd/Ctrl+F)"]').click()
    await split_page.locator('input[placeholder="Search inside this page…"]').fill("needle")
    await split_page.get_by_text("1 / 2").wait_for(state="visible")

    hits = split_page.locator("mark.gb-search-hit")
    assert await hits.count() == 2
    rendered_text = await split_page.inner_text()
    assert "**needle**" not in rendered_text

    strict_browser_page.assert_clean()
