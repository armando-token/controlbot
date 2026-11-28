"""CB-03 scenario runner: cancel coherence, zero post-cancel effects & SSE reconnect."""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from typing import Any

from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ScenarioContext,
    SseEventFrame,
    finalize_scenario,
    iter_sse_events,
    open_browser_session,
    run_coro_sync,
    safe_response_dict,
    trigger_and_wait_turn,
)
from src.qa.ux_metrics import measure_ux_action


async def _run_cb03_async(ctx: ScenarioContext) -> None:
    ctx.thread_id = "thr_bot_chief"
    ctx.subsystem = "sse_cancel"
    ctx.cancel_available = True
    seed_appr_id: str | None = None

    seed_marker = f"CB03_SEED_{uuid.uuid4().hex[:6]}"

    try:
        async with ctx.async_client(timeout=25.0) as aclient:
            # 1. Seed a message to test deterministic SSE Last-Event-ID replay & stream.resync
            seed_turn = await trigger_and_wait_turn(
                aclient,
                "thr_bot_chief",
                f"/approval {seed_marker}",
                timeout=15.0,
            )
            seed_msg_id = str(seed_turn.user_message["id"])
            ctx.message_id = seed_msg_id
            if seed_turn.approvals:
                seed_appr_id = str(seed_turn.approvals[0].get("id") or "")
                await aclient.post(
                    f"/api/v1/approvals/{seed_appr_id}/resolve",
                    json={"decision": "deny"},
                )
                seed_appr_id = None

            connected = asyncio.Event()
            first_frames: list[SseEventFrame] = []

            async def _read_first_reaction() -> str | None:
                async for frame in iter_sse_events(aclient, timeout=10.0, on_connected=connected):
                    first_frames.append(frame)
                    if (frame.event_type or frame.event) == "message.reaction" and frame.event_id:
                        return frame.event_id
                return None

            t1 = asyncio.create_task(_read_first_reaction())
            try:
                await asyncio.wait_for(connected.wait(), timeout=5.0)
                r_react1 = await aclient.post(
                    f"/api/v1/messages/{seed_msg_id}/reactions",
                    json={"emoji": "👍", "action": "add"},
                )
                ctx.add_request_id(r_react1)
                cursor_1 = await asyncio.wait_for(t1, timeout=8.0)
            finally:
                if not t1.done():
                    t1.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t1

            ctx.assertions["sse_cursor_received"] = bool(cursor_1)

            # Emit second reaction while disconnected, then reconnect with Last-Event-ID
            r_react2 = await aclient.post(
                f"/api/v1/messages/{seed_msg_id}/reactions",
                json={"emoji": "🎯", "action": "add"},
            )
            ctx.add_request_id(r_react2)

            replayed: list[SseEventFrame] = []
            if cursor_1:
                async for frame in iter_sse_events(
                    aclient, last_event_id=cursor_1, timeout=3.0
                ):
                    replayed.append(frame)
                    if (frame.event_type or frame.event) == "message.reaction":
                        break

            replayed_emojis = [
                f.data.get("payload", {}).get("emoji")
                for f in replayed
                if (f.event_type or f.event) == "message.reaction" and isinstance(f.data, dict)
            ]
            ctx.assertions["sse_last_event_id_replays_missed"] = "🎯" in replayed_emojis
            ctx.assertions["sse_last_event_id_no_duplicate"] = "👍" not in replayed_emojis
            ctx.assertions["sse_last_event_id_no_resync"] = not any(
                (f.event_type or f.event) == "stream.resync" for f in replayed
            )

            # Verify invalid/mismatched cursor emits stream.resync
            resync_seen = False
            async for frame in iter_sse_events(
                aclient, last_event_id="evt_000001_oldepoch", timeout=3.0
            ):
                if (frame.event_type or frame.event) == "stream.resync":
                    resync_seen = True
                    break
            ctx.assertions["sse_epoch_mismatch_resync"] = resync_seen

            # 2. Cancel & zero post-cancel side effects
            if ctx.caps.is_live_agent_target:
                work_dir = ctx.isolated_work_dir()
                marker_file = work_dir / "post_cancel_marker.txt"
                sse_ready = asyncio.Event()
                turn_ready = asyncio.Event()
                started_ev = asyncio.Event()
                holder: dict[str, str] = {}

                async def _watch_start() -> None:
                    async for frame in iter_sse_events(
                        aclient, timeout=15.0, on_connected=sse_ready
                    ):
                        if not turn_ready.is_set():
                            await turn_ready.wait()
                        data = frame.data if isinstance(frame.data, dict) else {}
                        if (
                            (frame.event_type or frame.event) == "turn.started"
                            and data.get("thread_id") == "thr_bot_chief"
                            and data.get("turn_id") == holder.get("turn_id")
                        ):
                            raw_payload = data.get("payload")
                            if isinstance(raw_payload, dict) and raw_payload.get("message_id"):
                                holder["message_id"] = str(raw_payload["message_id"])
                            started_ev.set()
                            return

                w_task = asyncio.create_task(_watch_start())
                try:
                    await asyncio.wait_for(sse_ready.wait(), timeout=5.0)
                    p_resp = await aclient.post(
                        "/api/v1/threads/thr_bot_chief/messages",
                        json={
                            "content": f"CANCEL_SLEEP_PROBE MARKER={marker_file} slow task",
                        },
                    )
                    ctx.add_request_id(p_resp)
                    if p_resp.status_code not in {200, 202}:
                        ctx.assertions["cancel_probe_turn_dispatched"] = False
                        ctx.error_notes.append(
                            f"CB-03 cancel probe POST failed with HTTP {p_resp.status_code}."
                        )
                        return
                    p_body = safe_response_dict(p_resp)
                    holder["turn_id"] = str(p_body.get("turn_id") or "")
                    user_msg_raw = p_body.get("user_message")
                    if isinstance(user_msg_raw, dict) and user_msg_raw.get("id"):
                        holder["user_message_id"] = str(user_msg_raw["id"])
                    turn_ready.set()
                    await asyncio.wait_for(started_ev.wait(), timeout=8.0)
                finally:
                    turn_ready.set()
                    if not w_task.done():
                        w_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await w_task

                async def _do_interrupt() -> tuple[bool, bool]:
                    ir = await aclient.post("/api/v1/threads/thr_bot_chief/interrupt")
                    ctx.add_request_id(ir)
                    ir_body = safe_response_dict(ir)
                    return (
                        ir.status_code == 200,
                        ir.status_code == 200 and ir_body.get("interrupted") is True,
                    )

                (int_200, int_ack), timing = await measure_ux_action(
                    _do_interrupt, actions_to_reach=1, cancel_available=True
                )
                ctx.ttfp_ms = timing.ttfp_ms
                ctx.completion_ms = timing.completion_ms
                ctx.assertions["interrupt_endpoint_200"] = int_200
                ctx.assertions["interrupt_acknowledged"] = int_ack
                if not int_ack:
                    ctx.error_notes.append(
                        "CB-03 POST /interrupt did not return {'interrupted': True}."
                    )
                await asyncio.sleep(0.4)
                ctx.assertions["zero_post_cancel_side_effects"] = not marker_file.exists()

                msgs_resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
                ctx.add_request_id(msgs_resp)
                msgs = (
                    safe_response_dict(msgs_resp).get("messages", [])
                    if msgs_resp.status_code == 200
                    else []
                )
                target_msg_id = holder.get("message_id")
                target_bot_msg: dict[str, Any] | None = None
                if target_msg_id and isinstance(msgs, list):
                    target_bot_msg = next(
                        (
                            m
                            for m in msgs
                            if isinstance(m, dict) and str(m.get("id") or "") == target_msg_id
                        ),
                        None,
                    )
                if target_bot_msg is None and isinstance(msgs, list):
                    user_id = holder.get("user_message_id")
                    seen_user = not bool(user_id)
                    after_user_bots: list[dict[str, Any]] = []
                    for m in msgs:
                        if not isinstance(m, dict):
                            continue
                        if user_id and str(m.get("id") or "") == user_id:
                            seen_user = True
                            continue
                        if seen_user and m.get("sender_type") == "bot":
                            after_user_bots.append(m)
                    if after_user_bots:
                        target_bot_msg = after_user_bots[-1]
                settled_status = (
                    str(target_bot_msg.get("status") or "") if target_bot_msg is not None else ""
                )
                msg_interrupted = msgs_resp.status_code == 200 and settled_status == "interrupted"
                ctx.assertions["assistant_message_interrupted"] = msg_interrupted
                if not msg_interrupted:
                    ctx.error_notes.append(
                        f"CB-03 assistant message status after interrupt was {settled_status!r} "
                        "(expected 'interrupted')."
                    )
            else:
                async def _do_interrupt_emulated() -> bool:
                    ir = await aclient.post("/api/v1/threads/thr_bot_chief/interrupt")
                    ctx.add_request_id(ir)
                    r404 = await aclient.post("/api/v1/threads/nonexistent_cb03_thr/interrupt")
                    return (
                        ir.status_code == 200
                        and isinstance(safe_response_dict(ir).get("interrupted"), bool)
                        and r404.status_code == 404
                    )

                int_ok, timing = await measure_ux_action(
                    _do_interrupt_emulated, actions_to_reach=1, cancel_available=True
                )
                ctx.ttfp_ms = timing.ttfp_ms
                ctx.completion_ms = timing.completion_ms
                ctx.assertions["interrupt_endpoint_and_404_boundary"] = int_ok

        # 3. Reload coherence (no duplicate message bubbles)
        async with open_browser_session(vnc_safe=False) as pw:
            page = pw.page
            await page.goto(ctx.app_url("/app"), wait_until="networkidle", timeout=15000)
            await page.wait_for_selector("text=Chief of Staff", timeout=10000)
            await page.reload(wait_until="networkidle", timeout=15000)
            await page.wait_for_selector("text=Chief of Staff", timeout=10000)
            seed_count = await page.get_by_text(f"/approval {seed_marker}", exact=True).count()
            ctx.assertions["reload_no_duplicate_messages"] = seed_count == 1
            ctx.response_persisted = True
            ctx.assertions["browser_clean"] = (
                not pw.console_errors and not pw.page_errors and not pw.external_requests
            )
            all_ok = all(ctx.assertions.values()) and not ctx.error_notes
            await ctx.capture_shot(page, "cb03_cancel_reconnect", is_error_state=not all_ok)

        ctx.evidence = {
            "cursor_1": cursor_1,
            "replayed_emojis": replayed_emojis,
            "resync_seen": resync_seen,
        }
        ctx.clarity_notes = (
            "CB-03 cancel, SSE Last-Event-ID replay, stream.resync & reload verified."
        )
    finally:
        if seed_appr_id:
            with contextlib.suppress(Exception), ctx.sync_client() as c:
                c.post(
                    f"/api/v1/approvals/{seed_appr_id}/resolve",
                    json={"decision": "deny"},
                )


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-03 scenario."""
    run_coro_sync(_run_cb03_async(ctx))
    return finalize_scenario(ctx)
