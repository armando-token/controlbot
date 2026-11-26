"""Tier 4 Playwright E2E tests: HITL Cards (Approval, Draft, SecureForm) & Verdict UI."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from tests.e2e._helpers import IsolatedServer
from tests.e2e.conftest import StrictBrowserPage

pytestmark = pytest.mark.e2e

_HITL_CONV_ID = "33333333-4444-5555-6666-777777777777"
_HITL_MOCK_AGY_SCRIPT = f"""#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if args and args[0] == "models":
    print("gemini-4-carbon-low  Gemini 4 Carbon (Low)")
    sys.exit(0)

cid = "{_HITL_CONV_ID}"
reply = "Resumed mock agy reply after approval."
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


@asynccontextmanager
async def _local_login_server() -> AsyncIterator[str]:
    """Start an ephemeral loopback HTTP login page for SecureFormCard live autofill."""
    html_body = (
        b"<!doctype html><html><head><title>E2E Plant Login</title></head>"
        b"<body><form method='post' action='/login'>"
        b"<input name='username' type='text' />"
        b"<input name='password' type='password' />"
        b"<button type='submit'>Sign in</button>"
        b"</form></body></html>"
    )

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(html_body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                + html_body
            )
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    srv = await asyncio.start_server(_handle, "127.0.0.1", 0)
    assert srv.sockets
    port = int(srv.sockets[0].getsockname()[1])
    try:
        yield f"http://127.0.0.1:{port}/login"
    finally:
        srv.close()
        await srv.wait_closed()


async def test_hitl_approval_card_lifecycle_and_ask_first_resume(
    server_factory: Callable[..., IsolatedServer],
    strict_browser_page: StrictBrowserPage,
) -> None:
    srv = server_factory(mock_agy_script=_HITL_MOCK_AGY_SCRIPT, name="hitl_approval")
    page = strict_browser_page.page
    await page.goto(srv.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    composer = page.locator('textarea[aria-label="Message composer"]')

    # 1. Trigger /approval -> Allow once
    await composer.fill("/approval Restart staging queue")
    await composer.press("Enter")
    card_once = page.locator("div.my-2\\.5").filter(has_text="Restart staging queue").first
    await card_once.get_by_text("Needs approval").wait_for(state="visible")
    await card_once.get_by_role("button", name="Allow once").click()
    await card_once.get_by_text("Allowed once").wait_for(state="visible")

    # 2. Trigger /approval -> Always allow (decision == "always_allow", no 422, in Settings)
    await composer.fill("/approval Deploy calibration patch")
    await composer.press("Enter")
    card_always = page.locator("div.my-2\\.5").filter(has_text="Deploy calibration patch").first
    await card_always.get_by_text("Needs approval").wait_for(state="visible")

    async with page.expect_request(
        lambda req: "/api/v1/approvals/" in req.url
        and req.url.endswith("/resolve")
        and req.method == "POST"
    ) as resolve_req_info:
        await card_always.get_by_role("button", name="Always allow").click()
    resolve_req = await resolve_req_info.value
    assert json.loads(resolve_req.post_data or "{}")["decision"] == "always_allow"
    await card_always.get_by_text("Saved to Custom Rules").wait_for(state="visible")

    # Verify custom rule appears in Settings -> General
    await page.keyboard.press("Control+,")
    settings_dialog = page.get_by_role("dialog")
    await settings_dialog.get_by_text("Allow: Deploy calibration patch").wait_for(state="visible")
    await page.keyboard.press("Escape")
    await settings_dialog.wait_for(state="hidden")

    # 3. Trigger /approval -> Deny
    await composer.fill("/approval Drop temp cache")
    await composer.press("Enter")
    card_deny = page.locator("div.my-2\\.5").filter(has_text="Drop temp cache").first
    await card_deny.get_by_text("Needs approval").wait_for(state="visible")
    await card_deny.get_by_role("button", name="Deny").click()
    await card_deny.get_by_text("Denied").wait_for(state="visible")

    # 4. Trigger seeded ask_first rule -> click Allow -> verify turn resumes and renders reply
    await composer.fill("Please delete files in temp workspace")
    await composer.press("Enter")
    ask_card = page.locator("div.my-2\\.5").filter(
        has_text="Ask before deleting files"
    ).first
    await ask_card.get_by_text("This can't be undone").wait_for(state="visible")
    await ask_card.get_by_role("button", name="Allow", exact=True).click()
    await ask_card.get_by_text("Allowed once").wait_for(state="visible")
    await page.get_by_text("Resumed mock agy reply after approval.").wait_for(
        state="visible", timeout=10000
    )

    strict_browser_page.assert_clean()


async def test_hitl_editable_draft_card_send_and_discard(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    page = strict_browser_page.page
    await page.goto(server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    composer = page.locator('textarea[aria-label="Message composer"]')

    # 1. Trigger /draft -> edit To / Subject / Body -> Send
    await composer.fill("/draft ops@plant.local | Shift Handover | Pump P-101 normal")
    await composer.press("Enter")
    draft_send = page.locator("div.my-2\\.5").filter(has_text="Email draft").first
    await draft_send.get_by_text("Needs approval").wait_for(state="visible")

    await draft_send.get_by_label("To").fill("lead@plant.local")
    await draft_send.get_by_label("Subject").fill("Updated Handover")
    await draft_send.get_by_label("Body").fill("Telemetry verified OK")
    await draft_send.get_by_role("button", name="Send").click()
    await draft_send.get_by_text("Sent").wait_for(state="visible")

    # 2. Trigger second /draft -> Discard
    await composer.fill("/draft temp@plant.local | Discard Draft | Ignore body")
    await composer.press("Enter")
    draft_discard = page.locator("div.my-2\\.5").filter(has_text="Email draft").nth(1)
    await draft_discard.get_by_text("Needs approval").wait_for(state="visible")
    await draft_discard.get_by_role("button", name="Discard").click()
    await draft_discard.get_by_text("Discarded").wait_for(state="visible")

    # Verify backend persistence of edited fields
    with server.client() as client:
        msgs = client.get("/api/v1/threads/thr_bot_chief/messages").json()
        drafts_by_subj = {d["fields"].get("subject"): d for d in msgs["drafts"]}
        assert drafts_by_subj["Updated Handover"]["status"] == "sent"
        assert drafts_by_subj["Updated Handover"]["fields"]["to"] == "lead@plant.local"
        assert drafts_by_subj["Updated Handover"]["fields"]["body"] == "Telemetry verified OK"
        assert drafts_by_subj["Discard Draft"]["status"] == "discarded"

    strict_browser_page.assert_clean()


async def test_hitl_secure_form_card_cancel_live_fill_and_vault_picker(
    server_factory: Callable[..., IsolatedServer],
    strict_browser_page: StrictBrowserPage,
) -> None:
    pw_cache = Path.home() / ".cache" / "ms-playwright"
    extra_env = {"PLAYWRIGHT_BROWSERS_PATH": str(pw_cache)} if pw_cache.exists() else {}
    srv = server_factory(extra_env=extra_env, name="hitl_secure_form")
    page = strict_browser_page.page
    await page.goto(srv.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    composer = page.locator('textarea[aria-label="Message composer"]')

    # 1. Cancel path
    await composer.fill("/secure-form example.com")
    await composer.press("Enter")
    cancel_card = page.locator("div.my-2\\.5").filter(
        has_text="Never shown to your Bot. Filled directly to example.com"
    ).first
    await cancel_card.get_by_role("button", name="Cancel").click()
    await cancel_card.get_by_text("Cancelled — no credentials were submitted.").wait_for(
        state="visible"
    )

    # 2. Live HTTP login server + live_browser start -> Fill directly + save to Vault
    async with _local_login_server() as login_url:
        async with srv.async_client() as client:
            start_resp = await client.post(
                "/api/v1/computers/default/actions",
                json={"type": "start", "url": login_url},
            )
            assert start_resp.status_code == 200, start_resp.text
        try:
            await composer.fill("/secure-form 127.0.0.1")
            await composer.press("Enter")
            fill_card = page.locator("div.my-2\\.5").filter(
                has_text="Never shown to your Bot. Filled directly to 127.0.0.1"
            ).first
            await fill_card.get_by_role("button", name="Fill directly").wait_for(state="visible")

            await fill_card.locator("input[type='text']").first.fill("op_user_e2e")
            await fill_card.locator("input[type='password']").first.fill("S3cretPass!99")
            await fill_card.get_by_role("button", name="Fill directly").click()
            await fill_card.get_by_text(
                "Submitted into the page. Secret values were never shown to your Bot."
            ).wait_for(state="visible")

            # 3. Second /secure-form -> select saved Vault secret -> Fill from Vault
            await composer.fill("/secure-form 127.0.0.1")
            await composer.press("Enter")
            vault_card = page.locator("div.my-2\\.5").filter(
                has_text="Never shown to your Bot. Filled directly to 127.0.0.1"
            ).nth(1)
            picker = vault_card.locator('select[aria-label="Select vault secret"]')
            await picker.wait_for(state="visible")
            option_vals = await picker.locator("option").evaluate_all(
                "els => els.map(e => e.value).filter(Boolean)"
            )
            assert len(option_vals) >= 1
            await picker.select_option(option_vals[0])
            await vault_card.get_by_role("button", name="Fill from Vault").click()
            await vault_card.get_by_text(
                "Submitted into the page. Secret values were never shown to your Bot."
            ).wait_for(state="visible")
        finally:
            async with srv.async_client() as client:
                await client.post("/api/v1/computers/default/actions", json={"type": "stop"})

    # Verify plaintext secret never leaked into thread messages
    with srv.client() as client:
        msgs_resp = client.get("/api/v1/threads/thr_bot_chief/messages")
        assert msgs_resp.status_code == 200
        assert "S3cretPass!99" not in msgs_resp.text

    strict_browser_page.assert_clean()


async def test_emulated_governance_clarification_and_mixed_airlock_replies(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    page = strict_browser_page.page
    await page.goto(server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    composer = page.locator('textarea[aria-label="Message composer"]')

    # Trigger needs_clarification via bare asset number
    await composer.fill("revisa el 34")
    await composer.press("Enter")
    await page.get_by_text("Clarification needed before running OT tools").wait_for(
        state="visible", timeout=10000
    )

    # Trigger MIXED lane + EvidenceAirlock ("Planta (verificado, vía Airlock ...)")
    await composer.fill("pump P-101 datasheet replacement")
    await composer.press("Enter")
    await page.get_by_text("Planta (verificado, vía Airlock").wait_for(
        state="visible", timeout=10000
    )

    strict_browser_page.assert_clean()


async def test_verdict_card_governance_metadata_ui(
    server: IsolatedServer,
    strict_browser_page: StrictBrowserPage,
) -> None:
    page = strict_browser_page.page
    await page.goto(server.url("/app"), wait_until="networkidle")
    await page.wait_for_selector("text=Chief of Staff")

    composer = page.locator('textarea[aria-label="Message composer"]')

    # 1. Live emulated needs_clarification renders VerdictCard
    await composer.fill("revisa el 34")
    await composer.press("Enter")
    await page.locator('[data-testid="verdict-card"]').get_by_text(
        "Needs clarification"
    ).wait_for(state="visible", timeout=10000)

    # 2. Live emulated MIXED Airlock renders Planta vs Web Airlock
    await composer.fill("pump P-101 datasheet replacement")
    await composer.press("Enter")
    await page.locator('[data-testid="verdict-card"]').get_by_text(
        "Planta vs Web Airlock"
    ).wait_for(state="visible", timeout=10000)

    # 3. Verify store.py supports metadata_json for VerdictCard states
    with sqlite3.connect(server.workspace_db_path) as conn:
        cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(messages)").fetchall()}
        assert "metadata_json" in cols, "messages table missing metadata_json column"
        cases = [
            (
                "msg_v_anf",
                "Asset lookup failed",
                {
                    "verdict": "asset_not_found",
                    "nearest_assets": [
                        {"canonical_label": "P-101A", "area": "Area 1", "score": 0.72}
                    ],
                },
            ),
            (
                "msg_v_part",
                "Partial check",
                {
                    "verdict": "partial_evidence",
                    "partial_evidence": ["SCADA reachable, CMMS offline"],
                    "missing_attributes": ["bearing_temp"],
                },
            ),
            (
                "msg_v_stale",
                "Stale telemetry",
                {
                    "verdict": "stale_data",
                    "stale_info": {"source": "scada", "age_seconds": 900, "max_ttl_seconds": 60},
                },
            ),
            (
                "msg_v_excel",
                "Workbook verified",
                {
                    "verdict": "verified",
                    "excel_verification": {
                        "passed": True,
                        "formulas_total": 12,
                        "formulas_ok": 12,
                        "badge": "12/12 formulas verified",
                    },
                },
            ),
        ]
        for idx, (mid, txt, meta) in enumerate(cases):
            conn.execute(
                "INSERT INTO messages (id, thread_id, sender_type, sender_bot_id, sender_name, "
                "content, status, metadata_json, created_at) "
                "VALUES (?, 'thr_bot_chief', 'bot', 'bot_chief', 'Chief of Staff', "
                "?, 'done', ?, ?)",
                (mid, txt, json.dumps(meta), f"2099-01-01T00:00:0{idx}Z"),
            )
        conn.commit()

    await page.reload(wait_until="networkidle")
    await page.locator('[data-testid="verdict-card"]').get_by_text("Asset not found").wait_for(
        state="visible"
    )
    await page.locator('[data-testid="verdict-card"]').get_by_text("Partial evidence").wait_for(
        state="visible"
    )
    await page.locator('[data-testid="verdict-card"]').get_by_text("Stale data").wait_for(
        state="visible"
    )
    await page.locator('[data-testid="verdict-card"]').get_by_text(
        "12/12 formulas verified"
    ).wait_for(state="visible")

    strict_browser_page.assert_clean()
