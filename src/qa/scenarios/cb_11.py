"""CB-11 scenario runner: SCADA & Maintenance parity, facility_b & ambiguity/contradiction."""

from __future__ import annotations

import contextlib
import shutil
from typing import Any

import httpx

from src.qa.isolation import IsolatedLabServer
from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ScenarioContext,
    TurnOutcome,
    _EphemeralLabStack,
    finalize_scenario,
    open_browser_session,
    poll_task_terminal,
    repo_root_fallback,
    run_coro_sync,
    safe_response_dict,
    trigger_and_wait_turn,
)
from src.qa.ux_metrics import (
    check_composer_single_row,
    check_local_remote_indicator,
    measure_ux_action,
)


def _extract_lab_origins(sys_info: dict[str, Any]) -> dict[str, str]:
    origins: dict[str, str] = {}
    fac = sys_info.get("facility")
    if isinstance(fac, dict):
        apps = fac.get("apps")
        if isinstance(apps, list):
            for app in apps:
                if not isinstance(app, dict):
                    continue
                aid = str(app.get("app_id") or "").strip()
                origin = str(app.get("origin") or "").strip().rstrip("/")
                if aid in {"scada", "maintenance", "effect_sim"} and origin:
                    origins[aid] = origin
    return origins


async def _are_lab_origins_reachable(origins: dict[str, str]) -> bool:
    if not {"scada", "maintenance", "effect_sim"}.issubset(origins):
        return False
    async with httpx.AsyncClient(timeout=3.0, trust_env=False) as client:
        for key in ("scada", "maintenance", "effect_sim"):
            try:
                resp = await client.get(f"{origins[key]}/health")
                if resp.status_code != 200:
                    return False
            except httpx.HTTPError:
                return False
    return True


async def _get_bot_engine(aclient: httpx.AsyncClient, bot_id: str) -> str | None:
    resp = await aclient.get("/api/v1/bots")
    if resp.status_code != 200:
        return None
    for bot in safe_response_dict(resp).get("bots", []):
        if isinstance(bot, dict) and str(bot.get("id")) == bot_id:
            return str(bot.get("engine_id") or "")
    return None


async def _verify_read_only_http_405(scada_url: str, maintenance_url: str) -> bool:
    async with httpx.AsyncClient(timeout=8.0, trust_env=False) as client:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            r_scada = await client.request(method, f"{scada_url}/api/alarms", json={})
            r_maint = await client.request(method, f"{maintenance_url}/api/work_orders", json={})
            if r_scada.status_code != 405 or r_maint.status_code != 405:
                return False
    return True


async def _get_total_applied(effect_sim_url: str) -> int | None:
    try:
        async with httpx.AsyncClient(timeout=8.0, trust_env=False) as client:
            resp = await client.get(f"{effect_sim_url}/api/effects/state")
            if resp.status_code != 200:
                return None
            st = safe_response_dict(resp)
            if "total_applied" not in st:
                return None
            raw = st["total_applied"]
            if isinstance(raw, bool):
                return None
            return int(raw)
    except (httpx.HTTPError, ValueError, TypeError):
        return None


async def _verify_facility_a_pump34(
    ctx: ScenarioContext,
    aclient: httpx.AsyncClient,
    *,
    scada_url: str,
    maintenance_url: str,
    effect_sim_url: str,
    record_timing: bool,
) -> dict[str, Any]:
    base_applied = await _get_total_applied(effect_sim_url)
    orig_engine = await _get_bot_engine(aclient, "bot_ops")
    try:
        patch_resp = await aclient.patch(
            "/api/v1/bots/bot_ops",
            json={"engine_id": "controlbot_runtime"},
        )
        ctx.add_request_id(patch_resp)
        if patch_resp.status_code != 200:
            ctx.assertions["facility_a_bot_ops_patch"] = False
            ctx.error_notes.append(f"CB-11 patch bot_ops failed (HTTP {patch_resp.status_code}).")
            return {}

        async def _run_turn() -> TurnOutcome:
            return await trigger_and_wait_turn(
                aclient,
                "thr_bot_ops",
                "Check bomba 34 alarms and readings in SCADA and maintenance",
                timeout=35.0,
            )

        if record_timing:
            turn, timing = await measure_ux_action(
                _run_turn,
                actions_to_reach=1,
                cancel_available=True,
            )
            ctx.ttfp_ms = timing.ttfp_ms
            ctx.completion_ms = timing.completion_ms
            ctx.cancel_available = True
        else:
            turn = await _run_turn()

        if turn.user_message.get("id"):
            ctx.message_id = str(turn.user_message["id"])
        msg = turn.assistant_message or {}
        content = str(msg.get("content") or "")
        raw_meta = msg.get("metadata")
        meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}

        ctx.assertions["facility_a_pump34_provenance"] = (
            "ALM-3401" in content
            and "WO-3408" in content
            and meta.get("verdict") == "verified"
        )
        after_applied = await _get_total_applied(effect_sim_url)
        ctx.assertions["facility_a_zero_effects"] = (
            base_applied is not None
            and after_applied is not None
            and after_applied == base_applied
        )
        ctx.assertions["scada_maintenance_http_405_readonly"] = await _verify_read_only_http_405(
            scada_url, maintenance_url
        )
        return {
            "verdict": meta.get("verdict"),
            "has_alm_3401": "ALM-3401" in content,
            "has_wo_3408": "WO-3408" in content,
        }
    finally:
        if orig_engine:
            with contextlib.suppress(Exception):
                await aclient.patch("/api/v1/bots/bot_ops", json={"engine_id": orig_engine})


async def _run_cb11_async(ctx: ScenarioContext) -> None:
    ctx.thread_id = "thr_bot_ops"
    ctx.subsystem = "scada_maintenance"
    resolved_repo = repo_root_fallback(ctx.repo_root)
    work_root = ctx.isolated_work_dir()
    evidence: dict[str, Any] = {}

    # 1. facility_a Pump 34 (prefer target LabStack if reachable, else ephemeral LabStack + server)
    target_origins = _extract_lab_origins(ctx.caps.system_info)
    target_has_lab = await _are_lab_origins_reachable(target_origins)
    evidence["target_has_lab_stack"] = target_has_lab

    if target_has_lab:
        async with ctx.async_client(timeout=35.0) as aclient:
            evidence["facility_a"] = await _verify_facility_a_pump34(
                ctx,
                aclient,
                scada_url=target_origins["scada"],
                maintenance_url=target_origins["maintenance"],
                effect_sim_url=target_origins["effect_sim"],
                record_timing=True,
            )
    else:
        ctx.simulated_services.append("ephemeral_lab_stack")
        lab_a_dir = work_root / "lab_a"
        try:
            with (
                _EphemeralLabStack(fixture_mode="default") as lab_a,
                IsolatedLabServer(
                    repo_root=resolved_repo,
                    base_dir=lab_a_dir,
                    extra_env=lab_a.env_vars(),
                ) as srv_a,
            ):
                async with httpx.AsyncClient(
                    base_url=srv_a.base_url,
                    timeout=35.0,
                    trust_env=False,
                    follow_redirects=False,
                ) as client_a:
                    evidence["facility_a"] = await _verify_facility_a_pump34(
                        ctx,
                        client_a,
                        scada_url=lab_a.scada_url,
                        maintenance_url=lab_a.maintenance_url,
                        effect_sim_url=lab_a.effect_sim_url,
                        record_timing=True,
                    )
        finally:
            shutil.rmtree(lab_a_dir, ignore_errors=True)

    # 2. facility_b Spanish headers, reordered columns, SC-77/CMMS-77 & runner.py facility_id fix
    lab_b_dir = work_root / "lab_b"
    fac_b_cfg = resolved_repo / "lab" / "configs" / "facility_b.json"
    try:
        with (
            _EphemeralLabStack(fixture_mode="facility_b") as lab_b,
            IsolatedLabServer(
                repo_root=resolved_repo,
                base_dir=lab_b_dir,
                extra_env={
                    **lab_b.env_vars(),
                    "GROKBOT_INSTALLATION_CONFIG": str(fac_b_cfg),
                },
            ) as srv_b,
        ):
            async with httpx.AsyncClient(
                base_url=srv_b.base_url,
                timeout=35.0,
                trust_env=False,
                follow_redirects=False,
            ) as client_b:
                sys_resp = await client_b.get("/api/system/info")
                sys_json = safe_response_dict(sys_resp)
                raw_fac = sys_json.get("facility")
                fac_info = raw_fac if isinstance(raw_fac, dict) else {}
                ctx.assertions["facility_b_system_info"] = (
                    fac_info.get("facility_id") == "facility-b"
                )

                run_id_b = ""
                sub = await client_b.post(
                    "/api/tasks",
                    json={
                        "query": "Check P-77B alarms and latest work order",
                        "facility_id": "facility-b",
                        "allowed_areas": ["area-2"],
                        "read_only": True,
                    },
                )
                task_b_ok = False
                if sub.status_code == 201:
                    run_id_b = str(safe_response_dict(sub).get("run_id") or "")
                    snap_b = await poll_task_terminal(client_b, run_id_b, timeout=30.0)
                    res_b = snap_b.get("result") or {}
                    obs_b = res_b.get("verified_observations") or []
                    ans_b = str(res_b.get("answer") or "")
                    has_sc77 = any(
                        isinstance(o, dict)
                        and o.get("source") == "scada"
                        and o.get("asset_id") == "SC-77"
                        and bool(o.get("observed_at") or o.get("source_time"))
                        for o in obs_b
                    )
                    has_cmms77 = any(
                        isinstance(o, dict)
                        and o.get("source") == "maintenance"
                        and o.get("asset_id") == "CMMS-77"
                        and bool(o.get("observed_at") or o.get("source_time"))
                        for o in obs_b
                    )
                    task_b_ok = (
                        snap_b["run"]["status"] == "succeeded"
                        and "ALM-7701" in ans_b
                        and "WO-7705" in ans_b
                        and has_sc77
                        and has_cmms77
                    )
                ctx.assertions["facility_b_api_tasks_provenance"] = task_b_ok

                await client_b.patch(
                    "/api/v1/bots/bot_ops", json={"engine_id": "controlbot_runtime"}
                )
                turn_b = await trigger_and_wait_turn(
                    client_b,
                    "thr_bot_ops",
                    "Check P-77B alarms and latest work order",
                    timeout=35.0,
                )
                msg_b = turn_b.assistant_message or {}
                content_b = str(msg_b.get("content") or "")
                raw_meta_b = msg_b.get("metadata")
                meta_b: dict[str, Any] = raw_meta_b if isinstance(raw_meta_b, dict) else {}

                tasks_list_resp = await client_b.get("/api/tasks")
                tasks_list = (
                    safe_response_dict(tasks_list_resp).get("tasks", [])
                    if tasks_list_resp.status_code == 200
                    else []
                )
                studio_task_ok = any(
                    isinstance(t, dict)
                    and isinstance(t.get("task"), dict)
                    and str(t["task"].get("task_id", "")).startswith("task-")
                    and str((t.get("run") or {}).get("run_id") or "") != run_id_b
                    and isinstance(t["task"].get("scope"), dict)
                    and t["task"]["scope"].get("facility_id") == "facility-b"
                    and t["task"]["scope"].get("read_only") is True
                    for t in tasks_list
                )
                ctx.assertions["facility_b_studio_chat_scope_and_provenance"] = (
                    "ALM-7701" in content_b
                    and "WO-7705" in content_b
                    and meta_b.get("verdict") == "verified"
                    and studio_task_ok
                )
                fac_b_applied = await _get_total_applied(lab_b.effect_sim_url)
                ctx.assertions["facility_b_zero_effects"] = (
                    fac_b_applied is not None and fac_b_applied == 0
                )
                evidence["facility_b"] = {
                    "api_tasks_ok": task_b_ok,
                    "studio_chat_scope_ok": studio_task_ok,
                    "verdict": meta_b.get("verdict"),
                }
    finally:
        shutil.rmtree(lab_b_dir, ignore_errors=True)

    # 3. Ambiguity pause -> resume area-1 -> succeeded ALM-3401
    lab_amb_dir = work_root / "lab_amb"
    try:
        with (
            _EphemeralLabStack(fixture_mode="ambiguity") as lab_amb,
            IsolatedLabServer(
                repo_root=resolved_repo,
                base_dir=lab_amb_dir,
                extra_env=lab_amb.env_vars(),
            ) as srv_amb,
        ):
            async with httpx.AsyncClient(
                base_url=srv_amb.base_url,
                timeout=35.0,
                trust_env=False,
                follow_redirects=False,
            ) as client_amb:
                sub_amb = await client_amb.post(
                    "/api/tasks",
                    json={
                        "query": "Check alarms and work orders for bomba 34",
                        "facility_id": "facility-a",
                        "read_only": True,
                    },
                )
                amb_ok = False
                if sub_amb.status_code == 201:
                    rid_amb = str(safe_response_dict(sub_amb).get("run_id") or "")
                    wait_snap = await poll_task_terminal(client_amb, rid_amb, timeout=25.0)
                    if wait_snap["run"]["status"] == "waiting_for_input":
                        res_amb = await client_amb.post(
                            f"/api/tasks/{rid_amb}/resume",
                            json={"human_input": {"choice": "area-1"}},
                        )
                        if res_amb.status_code == 200:
                            done_snap = await poll_task_terminal(client_amb, rid_amb, timeout=25.0)
                            ans_amb = str((done_snap.get("result") or {}).get("answer") or "")
                            amb_ok = (
                                done_snap["run"]["status"] == "succeeded"
                                and "ALM-3401" in ans_amb
                            )
                ctx.assertions["ambiguity_pause_and_resume_succeeded"] = amb_ok
                amb_applied = await _get_total_applied(lab_amb.effect_sim_url)
                ctx.assertions["ambiguity_zero_effects"] = (
                    amb_applied is not None and amb_applied == 0
                )
    finally:
        shutil.rmtree(lab_amb_dir, ignore_errors=True)

    # 4. Contradictory evidence preservation (partial + >=1 contradiction + 0 effects)
    lab_con_dir = work_root / "lab_con"
    try:
        with (
            _EphemeralLabStack(fixture_mode="contradictory") as lab_con,
            IsolatedLabServer(
                repo_root=resolved_repo,
                base_dir=lab_con_dir,
                extra_env=lab_con.env_vars(),
            ) as srv_con,
        ):
            async with httpx.AsyncClient(
                base_url=srv_con.base_url,
                timeout=35.0,
                trust_env=False,
                follow_redirects=False,
            ) as client_con:
                sub_con = await client_con.post(
                    "/api/tasks",
                    json={
                        "query": "Check bomba 34 alarms and work orders",
                        "facility_id": "facility-a",
                        "allowed_areas": ["area-1"],
                        "read_only": True,
                    },
                )
                con_ok = False
                if sub_con.status_code == 201:
                    snap_con = await poll_task_terminal(
                        client_con,
                        str(safe_response_dict(sub_con).get("run_id") or ""),
                        timeout=25.0,
                    )
                    contradictions = (snap_con.get("result") or {}).get("contradictions") or []
                    con_ok = snap_con["run"]["status"] == "partial" and len(contradictions) >= 1
                ctx.assertions["contradictory_partial_preserved"] = con_ok
                con_applied = await _get_total_applied(lab_con.effect_sim_url)
                ctx.assertions["contradictory_zero_effects"] = (
                    con_applied is not None and con_applied == 0
                )
    finally:
        shutil.rmtree(lab_con_dir, ignore_errors=True)

    # 5. Playwright UI verification on ctx.target_url
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
        await ctx.capture_shot(page, "cb11_scada_cmms", is_error_state=not all_ok)

    ctx.evidence = evidence
    ctx.clarity_notes = (
        "CB-11 facility_a/facility_b SCADA/CMMS parity, Studio facility_id scope, "
        "ambiguity pause/resume, contradiction preservation & read-only 405 verified."
    )


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-11 scenario."""
    run_coro_sync(_run_cb11_async(ctx))
    return finalize_scenario(ctx)
