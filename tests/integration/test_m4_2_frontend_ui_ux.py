"""Integration tests for M4-2 frontend UI/UX, SSE unload, focus traps, and a11y parity."""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from playwright.async_api import Request, Route
from src.qa.discovery import discover_static_controls, probe_modal_focus_cycle
from src.qa.isolation import IsolatedLabServer, StrictPlaywrightSession
from src.qa.ux_metrics import check_composer_single_row, check_local_remote_indicator

pytestmark = pytest.mark.n2

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_m4_2_static_a11y_discovery_has_zero_gaps() -> None:
    specs = discover_static_controls(_REPO_ROOT / "frontend" / "src")
    assert len(specs) >= 350
    gaps = [s for s in specs if s.a11y_gaps]
    assert gaps == [], f"Unexpected static a11y gaps: {gaps}"


async def test_m4_2_sse_unload_hidden_and_repeated_error_reporting(tmp_path: Path) -> None:
    sse_errors: list[dict[str, Any]] = []

    with IsolatedLabServer(repo_root=_REPO_ROOT) as lab:
        async with StrictPlaywrightSession(
            user_data_dir=lab.workspace.playwright_user_data_dir
        ) as session:
            page = session.page

            async def _capture_diag(route: Route, request: Request) -> None:
                if request.method == "POST":
                    try:
                        payload = json.loads(request.post_data or "{}")
                    except Exception:
                        payload = {}
                    if isinstance(payload, dict) and payload.get("kind") == "sse_error":
                        sse_errors.append(payload)
                await route.continue_()

            await page.route("**/api/v1/diagnostics/client-error*", _capture_diag)
            await page.goto(f"{lab.base_url}/app", wait_until="domcontentloaded")
            await page.locator('textarea[aria-label="Message composer"]').wait_for(
                state="visible", timeout=15000
            )
            await page.wait_for_timeout(250)

            # 1. Reload / navigation must NOT emit sse_error (pagehide/beforeunload + attempt===0)
            await page.reload(wait_until="domcontentloaded")
            await page.locator('textarea[aria-label="Message composer"]').wait_for(
                state="visible", timeout=15000
            )
            await page.wait_for_timeout(250)
            await page.goto(f"{lab.base_url}/app", wait_until="domcontentloaded")
            await page.locator('textarea[aria-label="Message composer"]').wait_for(
                state="visible", timeout=15000
            )
            await page.wait_for_timeout(250)
            assert sse_errors == [], f"Unexpected sse_error during reload/nav: {sse_errors}"

            # Also verify server diagnostics log has zero frontend sse_error
            with httpx.Client(timeout=5.0, trust_env=False) as client:
                resp = client.get(f"{lab.base_url}/api/v1/diagnostics/failures")
                assert resp.status_code == 200
                server_sse = [
                    f
                    for f in resp.json().get("failures", [])
                    if f.get("source") == "frontend" and f.get("kind") == "sse_error"
                ]
                assert server_sse == []

            # 2. Repeated SSE failures while hidden must be suppressed
            sse_requests = 0
            sse_started = asyncio.Event()
            allow_abort = asyncio.Event()

            async def _abort_hidden_sse(route: Route, _request: Request) -> None:
                nonlocal sse_requests
                sse_requests += 1
                if sse_requests == 1:
                    sse_started.set()
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(allow_abort.wait(), timeout=5.0)
                await route.abort("connectionreset")

            await page.route("**/api/v1/events/stream*", _abort_hidden_sse)
            await page.reload(wait_until="domcontentloaded")
            await asyncio.wait_for(sse_started.wait(), timeout=10.0)
            await page.evaluate(
                """() => {
                    Object.defineProperty(document, 'visibilityState', {
                        value: 'hidden',
                        configurable: true,
                    });
                }"""
            )
            assert await page.evaluate("() => document.visibilityState") == "hidden"
            allow_abort.set()
            await page.wait_for_timeout(1800)
            assert sse_requests >= 2
            assert sse_errors == [], f"Expected hidden SSE errors suppressed, got {sse_errors}"

            # 3. Visible repeated failures: attempt===0 suppressed, attempt>=1 reported
            await page.unroute("**/api/v1/events/stream*")
            page2 = await page.context.new_page()
            await page2.route("**/api/v1/diagnostics/client-error*", _capture_diag)
            visible_sse_attempts = 0

            async def _abort_visible_sse(route: Route, _request: Request) -> None:
                nonlocal visible_sse_attempts
                visible_sse_attempts += 1
                await route.abort("connectionreset")

            await page2.route("**/api/v1/events/stream*", _abort_visible_sse)
            await page2.goto(f"{lab.base_url}/app", wait_until="domcontentloaded")
            await page2.locator('textarea[aria-label="Message composer"]').wait_for(
                state="visible", timeout=15000
            )
            await page2.wait_for_timeout(300)
            # First disconnect (attempt === 0) must still be suppressed
            assert visible_sse_attempts >= 1
            assert sse_errors == [], f"Expected attempt=0 suppressed, got {sse_errors}"

            # Wait past 1000ms reconnect backoff for attempt >= 1 to fire and report
            await page2.wait_for_timeout(1600)
            assert visible_sse_attempts >= 2
            assert len(sse_errors) >= 1, "Expected repeated visible SSE error to be reported"
            assert sse_errors[0]["kind"] == "sse_error"
            await page2.close()


async def test_m4_2_modal_focus_traps_initial_focus_and_restore(tmp_path: Path) -> None:
    with IsolatedLabServer(repo_root=_REPO_ROOT) as lab:
        async with StrictPlaywrightSession(
            user_data_dir=lab.workspace.playwright_user_data_dir
        ) as session:
            page = session.page
            await page.set_viewport_size({"width": 1280, "height": 800})
            await page.goto(f"{lab.base_url}/app", wait_until="domcontentloaded")
            await page.locator('textarea[aria-label="Message composer"]').wait_for(
                state="visible", timeout=15000
            )

            # 1. Settings modal focus cycle + initial focus should NOT land on Close dialog
            await page.locator('aside button[aria-label="Settings"]').click()
            dlg = page.locator('[role="dialog"][aria-modal="true"]').first
            await dlg.wait_for(state="visible", timeout=5000)
            await page.wait_for_timeout(100)
            active_label = await page.evaluate(
                "() => document.activeElement?.getAttribute('aria-label') || ''"
            )
            assert active_label != "Close dialog"
            await page.keyboard.press("Escape")
            await dlg.wait_for(state="hidden", timeout=5000)

            ok_settings, reason_settings = await probe_modal_focus_cycle(
                page, 'aside button[aria-label="Settings"]'
            )
            assert ok_settings is True, reason_settings

            # 2. CommandPalette focus cycle (sidebar search button)
            search_sel = (
                'button[aria-label="Search and commands"], '
                'aside button:has-text("Search or jump")'
            )
            ok_palette, reason_palette = await probe_modal_focus_cycle(page, search_sel)
            assert ok_palette is True, reason_palette

            # 3. Shortcut from BODY (Ctrl+K) restores focus to non-BODY fallback on Escape
            await page.evaluate("() => document.body.focus()")
            await page.keyboard.press("Control+k")
            await dlg.wait_for(state="visible", timeout=5000)
            await page.keyboard.press("Escape")
            await dlg.wait_for(state="hidden", timeout=5000)
            await page.wait_for_timeout(100)
            is_body = await page.evaluate(
                "() => document.activeElement === document.body "
                "|| document.activeElement === document.documentElement"
            )
            assert is_body is False

            # 4. FullScreenTakeoverModal focus cycle & restore
            await page.locator('button[title="Open Bot Computer"]').click()
            expand_sel = 'button[title="Expand full screen"]'
            await page.locator(expand_sel).wait_for(state="visible", timeout=5000)
            ok_takeover, reason_takeover = await probe_modal_focus_cycle(page, expand_sel)
            assert ok_takeover is True, reason_takeover


async def test_m4_2_composer_single_row_and_prestream_stop_button(tmp_path: Path) -> None:
    with IsolatedLabServer(repo_root=_REPO_ROOT) as lab:
        async with StrictPlaywrightSession(
            user_data_dir=lab.workspace.playwright_user_data_dir
        ) as session:
            page = session.page
            await page.set_viewport_size({"width": 1280, "height": 800})
            await page.goto(f"{lab.base_url}/app", wait_until="domcontentloaded")
            await page.locator('textarea[aria-label="Message composer"]').wait_for(
                state="visible", timeout=15000
            )

            # Open Inspector (30% default width) at 1280x800 and verify single-row layout
            await page.locator('button[title="Open Bot Computer"]').click()
            await page.locator('[role="tablist"][aria-label="Computer view"]').wait_for(
                state="visible", timeout=5000
            )
            intact, reason = await check_composer_single_row(page)
            assert intact is True, f"Composer wrapped at 1280x800 with Inspector open: {reason}"

            # Also verify single-row layout at rest at 1024x768 with Inspector open
            await page.set_viewport_size({"width": 1024, "height": 768})
            intact_1024, reason_1024 = await check_composer_single_row(page)
            assert intact_1024 is True, (
                f"Composer wrapped at 1024x768 with Inspector open: {reason_1024}"
            )
            await page.set_viewport_size({"width": 1280, "height": 800})

            # Intercept POST /messages to hold it pending pre-stream, and record /interrupt + diag
            hold_send = asyncio.Event()
            send_started = asyncio.Event()
            send_aborted = asyncio.Event()
            interrupt_called = asyncio.Event()
            client_errors: list[dict[str, Any]] = []

            async def _capture_diag(route: Route, request: Request) -> None:
                if request.method == "POST":
                    with contextlib.suppress(Exception):
                        client_errors.append(json.loads(request.post_data or "{}"))
                await route.continue_()

            def _on_request_failed(req: Request) -> None:
                if "/api/v1/threads/" in req.url and req.url.endswith("/messages"):
                    send_aborted.set()

            page.on("requestfailed", _on_request_failed)
            await page.route("**/api/v1/diagnostics/client-error*", _capture_diag)

            async def _delay_send(route: Route, _request: Request) -> None:
                send_started.set()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(hold_send.wait(), timeout=5.0)
                await route.abort("aborted")

            async def _handle_interrupt(route: Route, _request: Request) -> None:
                interrupt_called.set()
                await route.fulfill(
                    status=200,
                    content_type="application/json",
                    body='{"interrupted":true,"thread_id":"thr_test"}',
                )

            await page.route("**/api/v1/threads/*/messages", _delay_send)
            await page.route("**/api/v1/threads/*/interrupt", _handle_interrupt)

            composer = page.locator('textarea[aria-label="Message composer"]')
            await composer.fill("Pre-stream pending stop verification")
            await page.locator('button[aria-label="Send message"]').click()

            await asyncio.wait_for(send_started.wait(), timeout=5.0)
            stop_btn = page.locator('button[aria-label="Stop current generation"]')
            await stop_btn.wait_for(state="visible", timeout=3000)

            # Even with Stop + Send both rendered at 1280x800 + Inspector open, stay single row
            intact_running, reason_running = await check_composer_single_row(page)
            assert intact_running is True, reason_running

            # And stay single row with Stop + Send rendered at 1024x768 + Inspector open
            await page.set_viewport_size({"width": 1024, "height": 768})
            intact_running_1024, reason_running_1024 = await check_composer_single_row(page)
            assert intact_running_1024 is True, (
                f"Composer wrapped during pending send at 1024x768: {reason_running_1024}"
            )
            await page.set_viewport_size({"width": 1280, "height": 800})

            await stop_btn.click()
            await asyncio.wait_for(interrupt_called.wait(), timeout=5.0)
            await asyncio.wait_for(send_aborted.wait(), timeout=5.0)
            hold_send.set()
            await page.wait_for_timeout(200)

            assert not any(e.get("kind") == "fetch_network_error" for e in client_errors)
            error_toasts = page.locator('text="Could not send message"')
            assert await error_toasts.count() == 0


async def test_m4_2_local_remote_indicator_terminal_pty_and_a11y_polish(tmp_path: Path) -> None:
    with IsolatedLabServer(repo_root=_REPO_ROOT) as lab:
        async with StrictPlaywrightSession(
            user_data_dir=lab.workspace.playwright_user_data_dir
        ) as session:
            page = session.page
            await page.set_viewport_size({"width": 1280, "height": 800})
            await page.goto(f"{lab.base_url}/app", wait_until="domcontentloaded")
            await page.locator('textarea[aria-label="Message composer"]').wait_for(
                state="visible", timeout=15000
            )

            # 1. Top-level Local/Remote execution indicator
            badge = page.locator('header [data-testid="runtime-origin-badge"]')
            await badge.wait_for(state="visible", timeout=5000)
            assert await badge.get_attribute("role") == "status"
            assert await badge.get_attribute("data-runtime-mode") in {"live_runtime", "stub"}
            assert await badge.get_attribute("data-backend-mode") is not None
            lr_visible, lr_location = await check_local_remote_indicator(page)
            assert lr_visible is True, lr_location
            assert "top_level_workspace" in lr_location

            # 2. Main shell heading landmarks (h1/h2/h3)
            assert await page.locator("header h1").count() >= 1
            assert await page.locator("aside h2").count() >= 1
            assert await page.locator("aside h3").count() >= 1

            # 3. ChatHeader model pill aria-expanded + Escape focus restore
            pill = page.locator('header button[aria-haspopup="true"]').first
            assert await pill.get_attribute("aria-expanded") == "false"
            await pill.click()
            assert await pill.get_attribute("aria-expanded") == "true"
            await page.keyboard.press("Escape")
            assert await pill.get_attribute("aria-expanded") == "false"
            focused_pill = await pill.evaluate("(el) => document.activeElement === el")
            assert focused_pill is True

            # 4. BotRosterSidebar role="menu" + preserved button role + Escape restore
            plus_btn = page.locator('button[aria-label="New bot, group chat, or section"]')
            await plus_btn.click()
            menu = page.locator('[role="menu"][aria-label="New item menu"]')
            await menu.wait_for(state="visible", timeout=3000)
            assert await page.get_by_role("button", name="New group chat").is_visible()
            await page.keyboard.press("Escape")
            await menu.wait_for(state="hidden", timeout=3000)
            focused_plus = await plus_btn.evaluate("(el) => document.activeElement === el")
            assert focused_plus is True

            # 5. ChatHeader "Open Bot Computer" is idempotent (doesn't close Inspector on 2nd click)
            # and focuses the Computer view sub-tab button when already open.
            comp_btn = page.locator('button[title="Open Bot Computer"]')
            await comp_btn.click()
            tablist = page.locator('[role="tablist"][aria-label="Computer view"]')
            await tablist.wait_for(state="visible", timeout=5000)
            await comp_btn.click()
            assert await tablist.is_visible()
            await page.wait_for_function(
                """() => {
                    const btn = document.querySelector(
                        '[role="tablist"][aria-label="Computer view"] button'
                    );
                    return Boolean(btn && document.activeElement === btn);
                }""",
                timeout=3000,
            )

            # 6. ComputerTab role="tab" + aria-selected AND get_by_role("button", ...) preserved
            screen_tab = tablist.locator('[role="tab"][aria-label="Screen"]')
            term_tab = tablist.locator('[role="tab"][aria-label="Terminal"]')
            assert await screen_tab.get_attribute("aria-selected") == "true"
            assert await term_tab.get_attribute("aria-selected") == "false"

            # Existing Playwright selector pattern must still click Terminal as button role
            await page.get_by_role("button", name="Terminal", exact=True).click()
            assert await term_tab.get_attribute("aria-selected") == "true"

            # 7. TerminalTab local PTY identity shows bot@local, never bot@cloud
            await page.locator("text=bot@local").first.wait_for(state="visible", timeout=5000)
            assert await page.locator("text=bot@cloud").count() == 0
