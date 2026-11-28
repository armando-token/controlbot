"""CB-12 scenario runner: operational variants, fault recovery, 413 guard & concurrency."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shutil
import uuid
from collections.abc import AsyncIterator, Sequence
from typing import Any

import httpx

from src.qa.isolation import IsolatedLabServer, alloc_ephemeral_port
from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ScenarioContext,
    SseEventFrame,
    _EphemeralLabStack,
    finalize_scenario,
    iter_sse_events,
    open_browser_session,
    repo_root_fallback,
    run_coro_sync,
    safe_response_dict,
    trigger_and_wait_turn,
)
from src.qa.ux_metrics import (
    check_composer_single_row,
    check_local_remote_indicator,
    evaluate_error_actionability,
    measure_ux_action,
)

_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
_EVT_EPOCH_RE = re.compile(r"^evt_\d+_([A-Za-z0-9_-]+)$")


def _extract_sse_epoch(event_id: str | None) -> str | None:
    if not event_id:
        return None
    m = _EVT_EPOCH_RE.match(event_id)
    return m.group(1) if m is not None else None


def _evaluate_sigterm_sse_replay(
    replayed: Sequence[SseEventFrame],
    *,
    epoch_before: str,
    bot_survived: bool,
) -> tuple[bool, dict[str, Any]]:
    reaction_frames = [
        f for f in replayed if (f.event_type or f.event) == "message.reaction"
    ]
    emojis = [
        f.data.get("payload", {}).get("emoji")
        for f in reaction_frames
        if isinstance(f.data, dict) and isinstance(f.data.get("payload"), dict)
    ]
    no_resync = all((f.event_type or f.event) != "stream.resync" for f in replayed)
    same_epoch = (
        bool(epoch_before)
        and bool(replayed)
        and bool(reaction_frames)
        and all(_extract_sse_epoch(f.event_id) == epoch_before for f in reaction_frames)
    )
    passed = bot_survived and emojis == ["2️⃣", "3️⃣"] and no_resync and same_epoch
    return passed, {
        "bot_survived": bot_survived,
        "emojis": emojis,
        "no_resync": no_resync,
        "same_epoch": same_epoch,
    }


async def _iter_zero_chunks(
    total_bytes: int, chunk_size: int = 1024 * 1024
) -> AsyncIterator[bytes]:
    remaining = total_bytes
    chunk = b"0" * chunk_size
    while remaining > 0:
        n = min(remaining, chunk_size)
        yield chunk if n == chunk_size else b"0" * n
        remaining -= n


async def _run_cb12_async(ctx: ScenarioContext) -> None:
    ctx.thread_id = "thr_bot_chief"
    ctx.subsystem = "operational_variants"
    resolved_repo = repo_root_fallback(ctx.repo_root)
    work_root = ctx.isolated_work_dir()
    suffix = uuid.uuid4().hex[:6]
    cleanup_approvals: list[str] = []
    evidence: dict[str, Any] = {}

    try:
        # 1. Target checks: oversize >25 MiB attachment 413 + 2 concurrent runs zero bleed
        async with ctx.async_client(timeout=35.0) as aclient:
            lib_before_resp = await aclient.get("/api/v1/bots/bot_chief/library")
            ctx.add_request_id(lib_before_resp)
            lib_before = len(safe_response_dict(lib_before_resp).get("items", []))

            async def _upload_oversize() -> httpx.Response:
                return await aclient.post(
                    "/api/v1/attachments",
                    params={"filename": f"cb12_too_big_{suffix}.bin"},
                    headers={"Content-Type": "application/octet-stream"},
                    content=_iter_zero_chunks(_MAX_ATTACHMENT_BYTES + 1),
                    timeout=35.0,
                )

            over_resp, timing = await measure_ux_action(
                _upload_oversize,
                actions_to_reach=1,
                cancel_available=False,
            )
            ctx.ttfp_ms = timing.ttfp_ms
            ctx.completion_ms = timing.completion_ms
            ctx.add_request_id(over_resp)
            lib_after_resp = await aclient.get("/api/v1/bots/bot_chief/library")
            lib_after = len(safe_response_dict(lib_after_resp).get("items", []))
            ctx.assertions["oversize_attachment_413_zero_residue"] = (
                over_resp.status_code == 413
                and str(_MAX_ATTACHMENT_BYTES) in over_resp.text
                and lib_after == lib_before
            )

            alpha_tag = f"CB12_ALPHA_{suffix}"
            beta_tag = f"CB12_BETA_{suffix}"
            if ctx.caps.is_live_agent_target:
                turn_a, turn_b = await asyncio.gather(
                    trigger_and_wait_turn(
                        aclient,
                        "thr_bot_chief",
                        f"Run CONCURRENT_TAG={alpha_tag}",
                        timeout=30.0,
                    ),
                    trigger_and_wait_turn(
                        aclient,
                        "thr_bot_ops",
                        f"Run CONCURRENT_TAG={beta_tag}",
                        timeout=30.0,
                    ),
                )
                txt_a = turn_a.reply_text
                txt_b = turn_b.reply_text
                ctx.assertions["concurrent_runs_zero_cross_bleed"] = (
                    turn_a.assistant_message is not None
                    and turn_b.assistant_message is not None
                    and alpha_tag in txt_a
                    and beta_tag not in txt_a
                    and beta_tag in txt_b
                    and alpha_tag not in txt_b
                )
                if turn_a.user_message.get("id"):
                    ctx.message_id = str(turn_a.user_message["id"])
            else:
                turn_a, turn_b = await asyncio.gather(
                    trigger_and_wait_turn(
                        aclient,
                        "thr_bot_chief",
                        f"/approval {alpha_tag}",
                        timeout=20.0,
                    ),
                    trigger_and_wait_turn(
                        aclient,
                        "thr_bot_ops",
                        f"/approval {beta_tag}",
                        timeout=20.0,
                    ),
                )
                appr_a = turn_a.approvals[0] if turn_a.approvals else {}
                appr_b = turn_b.approvals[0] if turn_b.approvals else {}
                for appr in (appr_a, appr_b):
                    if appr.get("id"):
                        cleanup_approvals.append(str(appr["id"]))
                ctx.assertions["concurrent_runs_zero_cross_bleed"] = (
                    appr_a.get("thread_id") == "thr_bot_chief"
                    and appr_b.get("thread_id") == "thr_bot_ops"
                    and alpha_tag in str(appr_a.get("title") or "")
                    and beta_tag not in str(appr_a.get("title") or "")
                    and beta_tag in str(appr_b.get("title") or "")
                    and alpha_tag not in str(appr_b.get("title") or "")
                )
                if turn_a.user_message.get("id"):
                    ctx.message_id = str(turn_a.user_message["id"])

        # 2. Ephemeral stale telemetry rejection
        ctx.simulated_services.append("ephemeral_lab_stack")
        lab_stale_dir = work_root / "lab_stale"
        try:
            with (
                _EphemeralLabStack(fixture_mode="stale") as lab_stale,
                IsolatedLabServer(
                    repo_root=resolved_repo,
                    base_dir=lab_stale_dir,
                    extra_env=lab_stale.env_vars(),
                ) as srv_stale,
            ):
                async with httpx.AsyncClient(
                    base_url=srv_stale.base_url,
                    timeout=35.0,
                    trust_env=False,
                    follow_redirects=False,
                ) as client_s:
                    await client_s.patch(
                        "/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"}
                    )
                    turn_s = await trigger_and_wait_turn(
                        client_s,
                        "thr_bot_ops",
                        "Check bomba 34 alarms and readings in SCADA and maintenance",
                        timeout=35.0,
                    )
                    meta_s = (
                        turn_s.assistant_message.get("metadata")
                        if isinstance(turn_s.assistant_message, dict)
                        else None
                    ) or {}
                    partial_str = json.dumps(meta_s.get("partial_evidence", []))
                    ctx.assertions["stale_data_rejected_in_partial_evidence"] = (
                        "RDG-STALE-01" in partial_str
                        and "RDG-BAD-01" in partial_str
                        and "999.9" not in str(turn_s.reply_text or "")
                    )
                    evidence["stale_verdict"] = meta_s.get("verdict")
        finally:
            shutil.rmtree(lab_stale_dir, ignore_errors=True)

        # 3. Ephemeral transient 503 down SCADA degradation & actionability
        lab_down_dir = work_root / "lab_down"
        try:
            with (
                _EphemeralLabStack(fixture_mode="down") as lab_down,
                IsolatedLabServer(
                    repo_root=resolved_repo,
                    base_dir=lab_down_dir,
                    extra_env=lab_down.env_vars(),
                ) as srv_down,
            ):
                async with httpx.AsyncClient(
                    base_url=srv_down.base_url,
                    timeout=35.0,
                    trust_env=False,
                    follow_redirects=False,
                ) as client_d:
                    await client_d.patch(
                        "/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"}
                    )
                    turn_d = await trigger_and_wait_turn(
                        client_d,
                        "thr_bot_ops",
                        "Check bomba 34 alarms and readings in SCADA and maintenance",
                        timeout=35.0,
                    )
                    meta_d = (
                        turn_d.assistant_message.get("metadata")
                        if isinstance(turn_d.assistant_message, dict)
                        else None
                    ) or {}
                    err_txt = str(meta_d.get("degraded_banner") or turn_d.reply_text or "").strip()
                    actionable, _ = evaluate_error_actionability(err_txt)
                    ctx.error_actionable = actionable
                    ctx.assertions["down_503_degraded_and_actionable"] = (
                        meta_d.get("verdict") != "verified" and bool(err_txt) and actionable
                    )
                    evidence["down_verdict"] = meta_d.get("verdict")
        finally:
            shutil.rmtree(lab_down_dir, ignore_errors=True)

        # 4. Ephemeral auth_expired 401 pause -> set_mode("default") -> allow_once resume
        lab_auth_dir = work_root / "lab_auth"
        try:
            with (
                _EphemeralLabStack(
                    scada_fixture_mode="auth_expired",
                    maintenance_fixture_mode="default",
                ) as lab_auth,
                IsolatedLabServer(
                    repo_root=resolved_repo,
                    base_dir=lab_auth_dir,
                    extra_env=lab_auth.env_vars(),
                ) as srv_auth,
            ):
                async with httpx.AsyncClient(
                    base_url=srv_auth.base_url,
                    timeout=40.0,
                    trust_env=False,
                    follow_redirects=False,
                ) as client_auth:
                    await client_auth.patch(
                        "/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"}
                    )
                    pause_turn = await trigger_and_wait_turn(
                        client_auth,
                        "thr_bot_ops",
                        "Check bomba 34 alarms and readings in SCADA and maintenance",
                        timeout=35.0,
                    )
                    auth_ok = False
                    if pause_turn.approvals:
                        appr = pause_turn.approvals[0]
                        appr_id = str(appr.get("id") or "")
                        run_id = str((appr.get("arguments") or {}).get("run_id") or "")
                        assert lab_auth.scada_state is not None
                        lab_auth.scada_state.set_mode("default")

                        resumed_frames: list[SseEventFrame] = []
                        resumed_holder: dict[str, str] = {}
                        sse_conn = asyncio.Event()

                        async def _listen_resumed() -> None:
                            resumed_tid: str | None = None
                            async for frame in iter_sse_events(
                                client_auth, timeout=35.0, on_connected=sse_conn
                            ):
                                resumed_frames.append(frame)
                                if not isinstance(frame.data, dict):
                                    continue
                                ev = frame.event_type or frame.event
                                if (
                                    ev == "turn.started"
                                    and frame.data.get("thread_id") == "thr_bot_ops"
                                ):
                                    resumed_tid = str(frame.data.get("turn_id") or "")
                                    resumed_holder["id"] = resumed_tid
                                if (
                                    resumed_tid is not None
                                    and ev == "message.completed"
                                    and frame.data.get("turn_id") == resumed_tid
                                ):
                                    return

                        listen_task = asyncio.create_task(_listen_resumed())
                        try:
                            await asyncio.wait_for(sse_conn.wait(), timeout=5.0)
                            res_resp = await client_auth.post(
                                f"/api/v1/approvals/{appr_id}/resolve",
                                json={"decision": "allow_once"},
                            )
                            if res_resp.status_code == 200:
                                await asyncio.wait_for(listen_task, timeout=35.0)
                        finally:
                            if not listen_task.done():
                                listen_task.cancel()
                            with contextlib.suppress(asyncio.CancelledError, Exception):
                                await listen_task

                        resumed_tid = resumed_holder.get("id")
                        completed_frame = next(
                            (
                                f
                                for f in reversed(resumed_frames)
                                if (f.event_type or f.event) == "message.completed"
                                and isinstance(f.data, dict)
                                and f.data.get("thread_id") == "thr_bot_ops"
                                and f.data.get("turn_id") == resumed_tid
                            ),
                            None,
                        )
                        if completed_frame is not None and isinstance(completed_frame.data, dict):
                            resumed_msg = completed_frame.data["payload"]["message"]
                            resumed_meta = resumed_msg.get("metadata") or {}
                            snap_resp = await client_auth.get(f"/api/tasks/{run_id}")
                            snap_json = safe_response_dict(snap_resp)
                            async with httpx.AsyncClient(timeout=8.0, trust_env=False) as ef_c:
                                ef_state = safe_response_dict(
                                    await ef_c.get(f"{lab_auth.effect_sim_url}/api/effects/state")
                                )
                            auth_ok = (
                                resumed_msg.get("status") == "done"
                                and resumed_msg.get("sender_bot_id") == "bot_ops"
                                and "ALM-3401" in str(resumed_msg.get("content") or "")
                                and "WO-3408" in str(resumed_msg.get("content") or "")
                                and resumed_meta.get("verdict") == "verified"
                                and resumed_meta.get("lane") == "industrial"
                                and (snap_json.get("run") or {}).get("status") == "succeeded"
                                and ef_state.get("total_applied") == 0
                            )
                    ctx.assertions["auth_expired_401_pause_and_resume_verified"] = auth_ok
                    evidence["auth_expired_ok"] = auth_ok
        finally:
            shutil.rmtree(lab_auth_dir, ignore_errors=True)

        # 5. Ephemeral SIGTERM restart preserving SQLite WAL bot + SSE epoch + Last-Event-ID replay
        lab_restart_dir = work_root / "lab_restart"
        srv_rst = IsolatedLabServer(repo_root=resolved_repo, base_dir=lab_restart_dir)
        srv_rst._cleanup_root_on_exit = False
        try:
            srv_rst.start(timeout=15.0)
            async with httpx.AsyncClient(
                base_url=srv_rst.base_url,
                timeout=25.0,
                trust_env=False,
                follow_redirects=False,
            ) as c1:
                b_resp = await c1.post(
                    "/api/v1/bots",
                    json={"name": f"CB12 Survivor {suffix}", "engine_id": "agy"},
                )
                created_bot_id = str(safe_response_dict(b_resp).get("id") or "")
                seed_turn = await trigger_and_wait_turn(
                    c1, "thr_bot_chief", f"/approval CB12_WAL_{suffix}", timeout=15.0
                )
                seed_msg_id = str(seed_turn.user_message.get("id") or "")
                if seed_turn.approvals:
                    aid = str(seed_turn.approvals[0].get("id") or "")
                    if aid:
                        await c1.post(
                            f"/api/v1/approvals/{aid}/resolve", json={"decision": "deny"}
                        )

                anchor_holder: dict[str, str] = {}
                sse_ready = asyncio.Event()

                async def _wait_r1() -> None:
                    async for frame in iter_sse_events(c1, timeout=10.0, on_connected=sse_ready):
                        ev_kind = frame.event_type or frame.event
                        if ev_kind == "message.reaction" and frame.event_id:
                            anchor_holder["id"] = frame.event_id
                            return

                t_r1 = asyncio.create_task(_wait_r1())
                try:
                    await asyncio.wait_for(sse_ready.wait(), timeout=5.0)
                    await c1.post(
                        f"/api/v1/messages/{seed_msg_id}/reactions",
                        json={"emoji": "1️⃣", "action": "add"},
                    )
                    await asyncio.wait_for(t_r1, timeout=10.0)
                finally:
                    if not t_r1.done():
                        t_r1.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await t_r1

                anchor_id = anchor_holder.get("id", "")
                epoch_before = _extract_sse_epoch(anchor_id) or ""
                await c1.post(
                    f"/api/v1/messages/{seed_msg_id}/reactions",
                    json={"emoji": "2️⃣", "action": "add"},
                )

            # SIGTERM stop without deleting DB/workspace, then restart on new ephemeral port
            srv_rst.stop()
            new_port = alloc_ephemeral_port(exclude={srv_rst.port, srv_rst.vnc_port})
            srv_rst.port = new_port
            srv_rst.base_url = f"http://127.0.0.1:{new_port}"
            srv_rst.ws_base_url = f"ws://127.0.0.1:{new_port}"
            srv_rst.env = srv_rst._build_env()
            srv_rst.start(timeout=15.0)

            async with httpx.AsyncClient(
                base_url=srv_rst.base_url,
                timeout=25.0,
                trust_env=False,
                follow_redirects=False,
            ) as c2:
                bots_after_rst = safe_response_dict(await c2.get("/api/v1/bots")).get("bots", [])
                bot_survived = bool(created_bot_id) and any(
                    isinstance(b, dict) and b.get("id") == created_bot_id for b in bots_after_rst
                )
                await c2.post(
                    f"/api/v1/messages/{seed_msg_id}/reactions",
                    json={"emoji": "3️⃣", "action": "add"},
                )
                replayed: list[SseEventFrame] = []
                if anchor_id:
                    async for frame in iter_sse_events(c2, last_event_id=anchor_id, timeout=4.0):
                        replayed.append(frame)
                        if (
                            (frame.event_type or frame.event) == "message.reaction"
                            and isinstance(frame.data, dict)
                            and frame.data.get("payload", {}).get("emoji") == "3️⃣"
                        ):
                            break

                sigterm_ok, sigterm_ev = _evaluate_sigterm_sse_replay(
                    replayed,
                    epoch_before=epoch_before,
                    bot_survived=bot_survived,
                )
                ctx.assertions["sigterm_restart_wal_and_sse_replay"] = sigterm_ok
                evidence["sigterm_restart"] = sigterm_ev
        finally:
            srv_rst.stop()
            shutil.rmtree(lab_restart_dir, ignore_errors=True)

        # 6. Playwright UI check
        async with open_browser_session(vnc_safe=False) as pw:
            page = pw.page
            await page.goto(ctx.app_url("/app"), wait_until="networkidle", timeout=15000)
            await page.wait_for_selector("text=Chief of Staff", timeout=10000)
            loc_vis, loc_where = await check_local_remote_indicator(page)
            ctx.local_remote_visible = loc_vis
            ctx.local_remote_location = loc_where
            comp_intact, _ = await check_composer_single_row(page)
            ctx.composer_intact = comp_intact
            ctx.assertions["local_remote_indicator_visible"] = loc_vis
            ctx.assertions["composer_layout_intact"] = comp_intact
            ctx.assertions["browser_clean"] = (
                not pw.console_errors and not pw.page_errors and not pw.external_requests
            )
            all_ok = all(ctx.assertions.values()) and not ctx.error_notes
            await ctx.capture_shot(page, "cb12_variants", is_error_state=not all_ok)

        ctx.evidence = evidence
        ctx.clarity_notes = (
            "CB-12 oversize 413 guard, 2 concurrent runs, stale/503/401 recovery & "
            "SIGTERM WAL/SSE epoch replay verified."
        )
    finally:
        if cleanup_approvals:
            with contextlib.suppress(Exception), ctx.sync_client() as c:
                for appr_id in cleanup_approvals:
                    c.post(f"/api/v1/approvals/{appr_id}/resolve", json={"decision": "deny"})


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-12 scenario."""
    run_coro_sync(_run_cb12_async(ctx))
    return finalize_scenario(ctx)
