"""CB-07 scenario runner: HITL approvals, deny=0 effects, allow idempotency & recovery."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import httpx
from lab.effect_sim.app import create_effect_sim_app
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ScenarioContext,
    finalize_scenario,
    open_browser_session,
    run_coro_sync,
    safe_response_dict,
    trigger_and_wait_turn,
)
from src.qa.ux_metrics import evaluate_error_actionability, measure_ux_action


async def _poll_task_terminal(
    aclient: httpx.AsyncClient, run_id: str, *, timeout: float = 25.0
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        resp = await aclient.get(f"/api/tasks/{run_id}")
        resp.raise_for_status()
        snap = resp.json()
        if snap["run"]["status"] in {
            "succeeded",
            "partial",
            "failed",
            "cancelled",
            "waiting_for_input",
        }:
            return dict(snap)
        await asyncio.sleep(0.15)
    raise TimeoutError(f"Task {run_id} did not settle within {timeout}s")


def _extract_error_text(resp: httpx.Response) -> str:
    data = safe_response_dict(resp)
    detail = data.get("detail") or data.get("error") or data.get("message")
    if isinstance(detail, str) and detail.strip():
        return detail.strip()
    return resp.text.strip()


async def _get_effect_sim_state(ef_url: str) -> tuple[int, set[str]] | None:
    try:
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as ef:
            resp = await ef.get(f"{ef_url}/api/effects/state")
            if resp.status_code != 200:
                return None
            st = safe_response_dict(resp)
            if "total_applied" not in st:
                return None
            raw_total = st["total_applied"]
            if isinstance(raw_total, bool):
                return None
            raw_effects = st.get("effects")
            keys = {
                str(item.get("idempotency_key"))
                for item in (raw_effects if isinstance(raw_effects, list) else [])
                if isinstance(item, dict) and item.get("idempotency_key")
            }
            return int(raw_total), keys
    except (httpx.HTTPError, ValueError, TypeError):
        return None


async def _get_effect_sim_total_applied(ef_url: str) -> int | None:
    state = await _get_effect_sim_state(ef_url)
    return state[0] if state is not None else None


async def _resolve_persisted_approval_status(
    aclient: httpx.AsyncClient,
    approval_id: str,
    *,
    resolve_resp: httpx.Response | None = None,
    title: str | None = None,
) -> str:
    resp = await aclient.get("/api/v1/threads/thr_bot_chief/messages")
    if resp.status_code == 200:
        approvals = safe_response_dict(resp).get("approvals")
        if isinstance(approvals, list):
            for item in approvals:
                if not isinstance(item, dict):
                    continue
                if approval_id and str(item.get("id") or "") == approval_id:
                    return str(item.get("status") or "")
                if not approval_id and title and str(item.get("title") or "") == title:
                    return str(item.get("status") or "")
            return ""
    if resolve_resp is not None:
        return str(safe_response_dict(resolve_resp).get("status") or "")
    return ""


async def _dispatch_gated_effect(
    ef_client: httpx.AsyncClient,
    *,
    approval_status: str,
    idempotency_key: str,
    action: str = "reset_latch",
) -> httpx.Response | None:
    if approval_status not in {"allowed_once", "always_allowed"}:
        return None
    return await ef_client.post(
        "/api/effects/apply",
        json={
            "idempotency_key": idempotency_key,
            "asset_id": "bomba-34-a1",
            "action": action,
            "params": {},
        },
    )


async def _run_cb07_async(ctx: ScenarioContext) -> None:
    ctx.thread_id = "thr_bot_chief"
    ctx.subsystem = "approvals"
    suffix = uuid.uuid4().hex[:6]
    ef_url = ctx.caps.effect_sim_url if ctx.caps.effect_sim_reachable else None
    initial_applied: int | None = None
    pre_ui_deny_applied: int | None = None
    local_ef_transport: httpx.ASGITransport | None = None
    ui_appr_id = ""

    async with ctx.async_client(timeout=30.0) as aclient:
        if ef_url:
            initial_applied = await _get_effect_sim_total_applied(ef_url)
            if initial_applied is None:
                ctx.error_notes.append(
                    "CB-07 initial effect_sim /api/effects/state probe failed."
                )

        # 1. Approval create + always_allow 409 + deny + replay 409 + allow_once + replay 409
        a1 = await aclient.post(
            "/api/v1/approvals",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "kind": "standard",
                "title": f"CB07 Deny Probe {suffix}",
                "target": "vm:default",
                "allow_always_allowed": False,
            },
        )
        ctx.add_request_id(a1)
        a1_body = safe_response_dict(a1)
        a1_id = str(a1_body.get("id") or "")
        ctx.assertions["approval_create_201"] = a1.status_code == 201 and bool(a1_id)
        if not ctx.assertions["approval_create_201"]:
            ctx.error_notes.append(f"CB-07 approval creation failed (HTTP {a1.status_code}).")
            return
        ctx.action_id = a1_id

        r_always = await aclient.post(
            f"/api/v1/approvals/{a1_id}/resolve",
            json={"decision": "always_allow"},
        )
        ctx.assertions["always_allow_disallowed_409"] = r_always.status_code == 409

        r_deny = await aclient.post(
            f"/api/v1/approvals/{a1_id}/resolve",
            json={"decision": "deny"},
        )
        r_replay_deny = await aclient.post(
            f"/api/v1/approvals/{a1_id}/resolve",
            json={"decision": "deny"},
        )
        ctx.assertions["approval_deny_and_replay_409"] = (
            r_deny.status_code == 200 and r_replay_deny.status_code == 409
        )
        if ef_url:
            after_api_deny_applied = (
                await _get_effect_sim_total_applied(ef_url)
                if initial_applied is not None
                else None
            )
            ctx.assertions["api_deny_zero_effects"] = (
                initial_applied is not None
                and after_api_deny_applied is not None
                and after_api_deny_applied == initial_applied
            )
            if initial_applied is not None and after_api_deny_applied is None:
                ctx.error_notes.append(
                    "CB-07 post-API-deny effect_sim /api/effects/state probe failed."
                )

        a2 = await aclient.post(
            "/api/v1/approvals",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "kind": "standard",
                "title": f"CB07 Allow Probe {suffix}",
                "target": "vm:default",
            },
        )
        a2_id = str(safe_response_dict(a2).get("id") or "")
        if a2.status_code != 201 or not a2_id:
            ctx.assertions["approval_allow_once_and_replay_409"] = False
            ctx.error_notes.append(
                f"CB-07 second approval creation failed (HTTP {a2.status_code})."
            )
            return
        r_allow = await aclient.post(
            f"/api/v1/approvals/{a2_id}/resolve",
            json={"decision": "allow_once"},
        )
        r_replay_allow = await aclient.post(
            f"/api/v1/approvals/{a2_id}/resolve",
            json={"decision": "allow_once"},
        )
        ctx.assertions["approval_allow_once_and_replay_409"] = (
            r_allow.status_code == 200 and r_replay_allow.status_code == 409
        )

        # 2. Drafts create/discard + replay 409
        d1 = await aclient.post(
            "/api/v1/drafts",
            json={
                "bot_id": "bot_chief",
                "thread_id": "thr_bot_chief",
                "channel_type": "email",
                "fields": {"to": "ops@example.local", "subject": f"Draft {suffix}", "body": "ok"},
            },
        )
        d1_id = str(safe_response_dict(d1).get("id") or "")
        if d1.status_code == 201 and d1_id:
            d_res = await aclient.post(
                f"/api/v1/drafts/{d1_id}/resolve", json={"action": "discard"}
            )
            d_rep = await aclient.post(
                f"/api/v1/drafts/{d1_id}/resolve", json={"action": "discard"}
            )
            ctx.assertions["draft_resolve_and_replay_409"] = (
                d_res.status_code == 200 and d_rep.status_code == 409
            )
        else:
            ctx.assertions["draft_resolve_and_replay_409"] = False

        # 3. EffectSim idempotency (live lab effect_sim if reachable, else local ASGI EffectSim)
        captured_error_text = _extract_error_text(r_replay_allow)
        if ef_url:
            base_state = await _get_effect_sim_state(ef_url)
            if base_state is None:
                ctx.assertions["effect_approval_allow_once"] = False
                ctx.assertions["effect_sim_task_succeeded"] = False
                ctx.assertions["effect_sim_single_apply"] = False
                ctx.assertions["effect_sim_replay_dedup"] = False
                ctx.assertions["effect_sim_conflict_409"] = False
                ctx.error_notes.append(
                    "CB-07 baseline effect_sim /api/effects/state probe failed."
                )
            else:
                base_applied, base_keys = base_state
                op_key = f"cb07-qa-{suffix}"

                # Gate effect execution on explicit allow_once approval
                a_eff = await aclient.post(
                    "/api/v1/approvals",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "kind": "standard",
                        "title": f"CB07 Effect Apply {op_key}",
                        "target": "effect_sim:bomba-34-a1",
                        "arguments": {"operation_key": op_key, "action": "reset_latch"},
                    },
                )
                a_eff_id = str(safe_response_dict(a_eff).get("id") or "")
                eff_allowed = False
                if a_eff.status_code == 201 and a_eff_id:
                    r_eff_allow = await aclient.post(
                        f"/api/v1/approvals/{a_eff_id}/resolve",
                        json={"decision": "allow_once"},
                    )
                    eff_allowed = r_eff_allow.status_code == 200
                ctx.assertions["effect_approval_allow_once"] = eff_allowed

                if eff_allowed:
                    async def _apply_lab_effect() -> dict[str, Any]:
                        t_resp = await aclient.post(
                            "/api/tasks",
                            json={
                                "query": (
                                    f"Apply effect operation_key={op_key} "
                                    "reset_latch on bomba-34-a1"
                                ),
                                "facility_id": "facility-a",
                                "allowed_areas": ["area-1"],
                                "allowed_tools": ["effect.apply", "effect.inspect_state"],
                                "read_only": False,
                            },
                        )
                        t_resp.raise_for_status()
                        return await _poll_task_terminal(
                            aclient, str(safe_response_dict(t_resp)["run_id"])
                        )

                    snap, timing = await measure_ux_action(_apply_lab_effect, actions_to_reach=1)
                    ctx.ttfp_ms = timing.ttfp_ms
                    ctx.completion_ms = timing.completion_ms
                    task_status = str((snap.get("run") or {}).get("status") or "")
                    ctx.assertions["effect_sim_task_succeeded"] = task_status == "succeeded"
                else:
                    task_status = "approval_failed"
                    ctx.assertions["effect_sim_task_succeeded"] = False

                new_applied: int | None = None
                try:
                    async with httpx.AsyncClient(timeout=10.0, trust_env=False) as ef:
                        st1_resp = await ef.get(f"{ef_url}/api/effects/state")
                        st1 = safe_response_dict(st1_resp) if st1_resp.status_code == 200 else {}
                        if (
                            st1_resp.status_code != 200
                            or "total_applied" not in st1
                            or isinstance(st1["total_applied"], bool)
                        ):
                            ctx.assertions["effect_sim_single_apply"] = False
                            ctx.assertions["effect_sim_replay_dedup"] = False
                            ctx.assertions["effect_sim_conflict_409"] = False
                            ctx.error_notes.append(
                                "CB-07 post-task effect_sim /api/effects/state probe failed "
                                f"(HTTP {st1_resp.status_code})."
                            )
                        else:
                            new_applied = int(st1["total_applied"])
                            effects_list = st1.get("effects")
                            ctx.assertions["effect_sim_single_apply"] = (
                                new_applied == base_applied + 1
                            )
                            new_effects = (
                                [
                                    item
                                    for item in effects_list
                                    if isinstance(item, dict)
                                    and (
                                        str(item.get("idempotency_key") or "") not in base_keys
                                        or str(item.get("idempotency_key") or "") == op_key
                                    )
                                ]
                                if isinstance(effects_list, list)
                                else []
                            )
                            if new_applied > base_applied and new_effects:
                                eff = new_effects[-1]
                                rep = await ef.post(
                                    f"{ef_url}/api/effects/apply",
                                    json={
                                        "idempotency_key": eff["idempotency_key"],
                                        "asset_id": eff["asset_id"],
                                        "action": eff["action"],
                                        "params": eff["params"],
                                    },
                                )
                                ctx.assertions["effect_sim_replay_dedup"] = (
                                    rep.status_code == 200
                                    and safe_response_dict(rep).get("deduplicated") is True
                                )
                                conflict = await ef.post(
                                    f"{ef_url}/api/effects/apply",
                                    json={
                                        "idempotency_key": eff["idempotency_key"],
                                        "asset_id": eff["asset_id"],
                                        "action": "different_action",
                                        "params": {},
                                    },
                                )
                                ctx.assertions["effect_sim_conflict_409"] = (
                                    conflict.status_code == 409
                                )
                                conflict_err = _extract_error_text(conflict)
                                if conflict_err:
                                    captured_error_text = conflict_err
                            else:
                                ctx.assertions["effect_sim_replay_dedup"] = False
                                ctx.assertions["effect_sim_conflict_409"] = False
                                ctx.error_notes.append(
                                    "CB-07 effect_sim task produced no newly applied effects "
                                    f"(status={task_status}, base_applied={base_applied}, "
                                    f"total_applied={new_applied})."
                                )
                except (httpx.HTTPError, ValueError, TypeError) as exc:
                    ctx.assertions["effect_sim_single_apply"] = False
                    ctx.assertions["effect_sim_replay_dedup"] = False
                    ctx.assertions["effect_sim_conflict_409"] = False
                    ctx.error_notes.append(f"CB-07 post-task effect_sim probe error: {exc}")
                pre_ui_deny_applied = new_applied
        else:
            ctx.simulated_services.append("effect_sim_asgi")
            ef_app = create_effect_sim_app()
            local_ef_transport = httpx.ASGITransport(app=ef_app)
            async with httpx.AsyncClient(
                transport=local_ef_transport, base_url="http://effect-sim"
            ) as ef:
                a1_status = await _resolve_persisted_approval_status(
                    aclient, a1_id, resolve_resp=r_deny
                )
                await _dispatch_gated_effect(
                    ef,
                    approval_status=a1_status,
                    idempotency_key=f"cb07-deny-{suffix}",
                )
                st_after_deny = safe_response_dict(await ef.get("/api/effects/state"))
                ctx.assertions["api_deny_zero_effects"] = (
                    r_deny.status_code == 200
                    and a1_status == "denied"
                    and int(st_after_deny.get("total_applied", -1)) == 0
                )

                local_op_key = f"cb07-local-{suffix}"
                a_eff = await aclient.post(
                    "/api/v1/approvals",
                    json={
                        "bot_id": "bot_chief",
                        "thread_id": "thr_bot_chief",
                        "kind": "standard",
                        "title": f"CB07 Local Effect Apply {local_op_key}",
                        "target": "effect_sim:bomba-34-a1",
                        "arguments": {"operation_key": local_op_key, "action": "reset_latch"},
                    },
                )
                a_eff_id = str(safe_response_dict(a_eff).get("id") or "")
                eff_allowed = False
                eff_status = ""
                if a_eff.status_code == 201 and a_eff_id:
                    r_eff_allow = await aclient.post(
                        f"/api/v1/approvals/{a_eff_id}/resolve",
                        json={"decision": "allow_once"},
                    )
                    eff_status = await _resolve_persisted_approval_status(
                        aclient, a_eff_id, resolve_resp=r_eff_allow
                    )
                    eff_allowed = r_eff_allow.status_code == 200 and eff_status == "allowed_once"
                ctx.assertions["effect_approval_allow_once"] = eff_allowed

                if eff_allowed:
                    r_first = await _dispatch_gated_effect(
                        ef,
                        approval_status=eff_status,
                        idempotency_key=local_op_key,
                    )
                    r_dup = await ef.post(
                        "/api/effects/apply",
                        json={
                            "idempotency_key": local_op_key,
                            "asset_id": "bomba-34-a1",
                            "action": "reset_latch",
                            "params": {},
                        },
                    )
                    r_conf = await ef.post(
                        "/api/effects/apply",
                        json={
                            "idempotency_key": local_op_key,
                            "asset_id": "bomba-34-a1",
                            "action": "other_action",
                            "params": {},
                        },
                    )
                    st = safe_response_dict(await ef.get("/api/effects/state"))
                    ctx.assertions["effect_sim_single_apply"] = (
                        r_first is not None
                        and r_first.status_code == 200
                        and st.get("total_applied") == 1
                    )
                    ctx.assertions["effect_sim_replay_dedup"] = (
                        r_dup.status_code == 200
                        and safe_response_dict(r_dup).get("deduplicated") is True
                    )
                    ctx.assertions["effect_sim_conflict_409"] = r_conf.status_code == 409
                    conf_err = _extract_error_text(r_conf)
                    if conf_err:
                        captured_error_text = conf_err
                else:
                    ctx.assertions["effect_sim_single_apply"] = False
                    ctx.assertions["effect_sim_replay_dedup"] = False
                    ctx.assertions["effect_sim_conflict_409"] = False
                st_post = safe_response_dict(await ef.get("/api/effects/state"))
                pre_ui_deny_applied = int(st_post.get("total_applied", 0))

        actionable, action_reason = evaluate_error_actionability(captured_error_text)
        ctx.error_actionable = actionable

        # 4. UI ApprovalCard Deny check
        ui_title = f"CB07 UI Card {suffix}"
        ui_turn = await trigger_and_wait_turn(
            aclient, "thr_bot_chief", f"/approval {ui_title}", timeout=15.0
        )
        if ui_turn.approvals:
            ui_appr_id = str(ui_turn.approvals[0].get("id") or "")

    async with open_browser_session(vnc_safe=False) as pw:
        page = pw.page
        await page.goto(ctx.app_url("/app"), wait_until="networkidle", timeout=15000)
        await page.wait_for_selector("text=Chief of Staff", timeout=10000)
        card = page.locator("div.my-2\\.5").filter(has_text=ui_title).first
        ui_deny_ok = False
        try:
            await card.get_by_text("Needs approval").wait_for(state="visible", timeout=10000)
            if ef_url:
                pre_ui_deny_applied = await _get_effect_sim_total_applied(ef_url)
                if pre_ui_deny_applied is None:
                    ctx.error_notes.append(
                        "CB-07 pre-UI-deny effect_sim /api/effects/state probe failed."
                    )
            await card.get_by_role("button", name="Deny").click()
            await card.get_by_text("Denied").wait_for(state="visible", timeout=10000)
            ui_deny_ok = True
        except PlaywrightTimeoutError:
            ctx.error_notes.append(f"CB-07 UI ApprovalCard deny failed for {ui_title!r}.")
        ctx.assertions["ui_approval_card_deny"] = ui_deny_ok
        if ef_url:
            after_ui_deny_applied = (
                await _get_effect_sim_total_applied(ef_url)
                if pre_ui_deny_applied is not None
                else None
            )
            ctx.assertions["ui_deny_zero_effects"] = (
                ui_deny_ok
                and pre_ui_deny_applied is not None
                and after_ui_deny_applied is not None
                and after_ui_deny_applied == pre_ui_deny_applied
            )
            if pre_ui_deny_applied is not None and after_ui_deny_applied is None:
                ctx.error_notes.append(
                    "CB-07 post-UI-deny effect_sim /api/effects/state probe failed."
                )
        elif local_ef_transport is not None and pre_ui_deny_applied is not None:
            async with (
                ctx.async_client(timeout=10.0) as vclient,
                httpx.AsyncClient(
                    transport=local_ef_transport, base_url="http://effect-sim"
                ) as ef,
            ):
                ui_status = await _resolve_persisted_approval_status(
                    vclient, ui_appr_id, title=ui_title
                )
                await _dispatch_gated_effect(
                    ef,
                    approval_status=ui_status,
                    idempotency_key=f"cb07-ui-deny-{suffix}",
                )
                st_ui = safe_response_dict(await ef.get("/api/effects/state"))
                after_ui_deny_applied = int(st_ui.get("total_applied", -1))
                ctx.assertions["ui_deny_zero_effects"] = (
                    ui_deny_ok
                    and ui_status == "denied"
                    and after_ui_deny_applied == pre_ui_deny_applied
                )
        ctx.assertions["browser_clean"] = (
            not pw.console_errors and not pw.page_errors and not pw.external_requests
        )
        all_ok = all(ctx.assertions.values()) and not ctx.error_notes
        await ctx.capture_shot(page, "cb07_approvals", is_error_state=not all_ok)

    ctx.evidence = {
        "approval_id": a1_id,
        "effect_sim_reachable": ctx.caps.effect_sim_reachable,
        "captured_error_text": captured_error_text,
        "error_actionable": ctx.error_actionable,
        "error_actionable_reason": action_reason,
    }
    ctx.clarity_notes = (
        "CB-07 approvals, 409 replay guards, drafts & effect_sim idempotency verified."
    )


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-07 scenario."""
    run_coro_sync(_run_cb07_async(ctx))
    return finalize_scenario(ctx)
