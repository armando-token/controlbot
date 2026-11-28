"""CB-13 scenario runner: honest Linux local without egress (N3) verification."""

from __future__ import annotations

import contextlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx

from src.contracts.common import utc_now
from src.doctor import CheckStatus
from src.n3_probe import N3ProbeReport, run_n3_probe
from src.qa.isolation import IsolatedLabServer, assert_safe_mutation_path
from src.qa.models import CampaignState, ReferenceBehaviorCard, RunRecord
from src.qa.queue import assert_strictly_redacted
from src.qa.scenarios._common import (
    ScenarioContext,
    TurnOutcome,
    _EphemeralLabStack,
    append_ux_metrics,
    compute_build_hash,
    finalize_scenario,
    open_browser_session,
    poll_task_terminal,
    repo_root_fallback,
    run_coro_sync,
    safe_response_dict,
    trigger_and_wait_turn,
)
from src.qa.ux_metrics import (
    UxFlowMetrics,
    check_composer_single_row,
    check_local_remote_indicator,
    contains_unredacted_secret_m3,
    measure_ux_action,
    redact_payload_m3,
)

_N3_RERUN_COMMANDS: tuple[str, ...] = (
    "bash scripts/verify_n3_linux.sh",
    "uv run python -m src.n3_probe --strict --json",
    "make test-n3",
)


def _resolve_n3_probe(n3_report: N3ProbeReport | None) -> N3ProbeReport:
    if n3_report is not None:
        return n3_report
    cli_mod = sys.modules.get("src.qa.cli")
    if cli_mod is not None and hasattr(cli_mod, "run_n3_probe"):
        res = cli_mod.run_n3_probe()
        if isinstance(res, N3ProbeReport):
            return res
    return run_n3_probe()


def _run_verify_n3_script(repo_root: Path) -> tuple[int, str, str]:
    script_path = repo_root / "scripts" / "verify_n3_linux.sh"
    if not script_path.is_file():
        return 127, "", f"Missing {script_path}"
    try:
        proc = subprocess.run(
            ["bash", str(script_path)],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
        return proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]
    except subprocess.TimeoutExpired as exc:
        return 124, str(exc.stdout or "")[-1000:], f"Timed out: {exc}"


def _run_pytest_n3(repo_root: Path, *, strict: bool = False) -> tuple[int, str, str]:
    acc_dir = repo_root / "tests" / "acceptance"
    if not acc_dir.is_dir():
        return 5, "", f"Missing {acc_dir}"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    if strict:
        env["GROKBOT_N3_STRICT"] = "1"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/acceptance", "-m", "n3", "-rs", "-v"],
            cwd=str(repo_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]
    except subprocess.TimeoutExpired as exc:
        return 124, str(exc.stdout or "")[-1000:], f"Timed out: {exc}"


def _invoke_pytest_n3(repo_root: Path, *, strict: bool) -> tuple[int, str, str]:
    sig = inspect.signature(_run_pytest_n3)
    if "strict" in sig.parameters:
        return _run_pytest_n3(repo_root, strict=strict)
    return _run_pytest_n3(repo_root)


def _extract_unblock_deps(report: N3ProbeReport) -> list[str]:
    deps: list[str] = []
    if not report.network_isolation_ready:
        deps.append(
            "Configure Linux netns/nftables/iptables OUTPUT DROP firewall blocking external egress "
            "(scripts/verify_n3_linux.sh requires 1.1.1.1:443 to fail)."
        )
    if not report.local_llm_ready:
        deps.append(
            "Start a local LLM runtime on loopback (ollama/llama-server/vllm on 127.0.0.1) "
            "and verify /v1/models or /health responds 2xx."
        )
    if not report.desktop_ready:
        deps.append(
            "Install AT-SPI bindings (pyatspi/gi) with an active Linux accessibility bus "
            "for desktop N3 checks."
        )
    for chk in report.checks:
        if chk.status == CheckStatus.FAIL:
            deps.append(f"Fix failing N3 check {chk.name}: {chk.summary}")
    return deps or [f"Resolve N3 readiness state {report.overall_status}."]


def _write_pending_n3_artifacts(
    *,
    run_id: str,
    campaign_dir: Path,
    state: CampaignState,
    repo_root: Path | None,
    assertions: dict[str, bool],
    evidence: dict[str, Any],
    duration_ms: float,
    clarity_notes: str,
) -> tuple[str, str]:
    ux_flow = UxFlowMetrics(
        case_id="CB-13",
        run_id=run_id,
        actions_to_reach=1,
        error_actionable=True,
        ttfp_ms=duration_ms,
        completion_ms=duration_ms,
        focus_predictable=True,
        cancel_available=False,
        local_remote_indicator_visible=True,
        local_remote_location="top_header",
        response_persisted_on_reload=None,
        result_clarity_notes=clarity_notes,
        composer_layout_intact=True,
        screenshots=[],
    )
    ux_path = append_ux_metrics(
        campaign_dir=campaign_dir,
        campaign_id=state.campaign_id,
        flow=ux_flow,
        repo_root=repo_root,
    )
    safe_camp = assert_safe_mutation_path(campaign_dir, repo_root=repo_root)
    artifacts_dir = safe_camp / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = artifacts_dir / f"{run_id}.json"
    raw_evidence = {
        "campaign_id": state.campaign_id,
        "case_id": "CB-13",
        "run_id": run_id,
        "passed": False,
        "assertions": assertions,
        "fixture_version": "1.0",
        "evidence": evidence,
        "ux_metrics_path": str(ux_path),
    }
    redacted = redact_payload_m3(raw_evidence)
    assert_strictly_redacted(redacted)
    if contains_unredacted_secret_m3(redacted):
        raise ValueError("Unredacted secret detected in CB-13 evidence payload.")
    evidence_path.write_text(
        json.dumps(redacted, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return str(evidence_path), str(ux_path)


def run_n3_honest_probe(
    *,
    campaign_dir: Path,
    state: CampaignState,
    repo_root: Path | None = None,
    extra_artifacts: Sequence[str] = (),
    n3_report: N3ProbeReport | None = None,
    target_url: str | None = None,
) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute honest N3 readiness probe & scripts without faking pass when PENDING."""
    t0 = time.monotonic()
    started_at = utc_now()
    resolved_repo = repo_root_fallback(repo_root)
    report = _resolve_n3_probe(n3_report)
    n3_status = str(report.overall_status)
    has_check_fail = any(c.status == CheckStatus.FAIL for c in report.checks)

    verify_rc, verify_out, verify_err = _run_verify_n3_script(resolved_repo)
    test_n3_rc, test_n3_out, test_n3_err = _invoke_pytest_n3(
        resolved_repo, strict=(n3_status == "READY")
    )

    unblock_deps = _extract_unblock_deps(report)
    notes = "; ".join(report.evidence_notes) or n3_status
    blocked_reason = (
        f"N3 gate not ready ({n3_status}): {notes} (skip != pass). "
        f"Unblock deps: {' | '.join(unblock_deps)} "
        f"Rerun: {'; '.join(_N3_RERUN_COMMANDS)}"
    )
    if n3_status == "READY" and not target_url:
        blocked_reason = "CB-13 READY requires --target-url or baseline target_url."

    assertions: dict[str, bool] = {
        "n3_ready": n3_status == "READY",
        "verify_n3_linux_passed": verify_rc == 0,
        "test_n3_ready": n3_status == "READY" and test_n3_rc == 0,
        "scenario_runner_available": True,
    }
    if n3_status == "READY" and not target_url:
        assertions["target_url_configured"] = False

    run_id = f"run-cb-13-{uuid.uuid4().hex[:8]}"
    duration_ms = round(max(0.01, (time.monotonic() - t0) * 1000.0), 3)
    evidence = {
        "n3_report": json.loads(report.model_dump_json()),
        "verify_n3_linux": {
            "returncode": verify_rc,
            "stdout": verify_out,
            "stderr": verify_err,
        },
        "make_test_n3": {
            "returncode": test_n3_rc,
            "stdout": test_n3_out,
            "stderr": test_n3_err,
        },
        "unblock_dependencies": unblock_deps,
        "rerun_commands": list(_N3_RERUN_COMMANDS),
    }
    ev_path, ux_path = _write_pending_n3_artifacts(
        run_id=run_id,
        campaign_dir=campaign_dir,
        state=state,
        repo_root=repo_root,
        assertions=assertions,
        evidence=evidence,
        duration_ms=duration_ms,
        clarity_notes=blocked_reason,
    )
    raw_arts = [*[str(p) for p in extra_artifacts if str(p).strip()], ev_path, ux_path]
    artifacts = list(dict.fromkeys(raw_arts))
    finished_at = utc_now()

    rec = RunRecord(
        campaign_id=state.campaign_id,
        case_id="CB-13",
        run_id=run_id,
        base_sha=state.base_sha,
        candidate_sha=state.last_accepted_sha,
        build_hash=compute_build_hash(campaign_dir, state),
        lane=state.lane,
        profile="default",
        ui_variant="react_dist",
        backend_mode="emulated",
        runtime_mode="live_runtime",
        model_id="emulated",
        emulated=True,
        real_services=[],
        simulated_services=["emulated_runtime"],
        fixture_version="1.0",
        browser="none",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
        request_ids=[],
        passed=False,
        assertions=assertions,
        artifact_paths=artifacts,
        error_summary=blocked_reason,
        blocked_reason=blocked_reason,
    )
    findings: list[dict[str, Any]] = []
    if has_check_fail or (n3_status == "READY" and not target_url):
        sig = "CB-13_n3_check_fail" if has_check_fail else "CB-13_missing_target"
        findings.append(
            {
                "subsystem": "n3_local",
                "raw_signature": sig,
                "severity": "P1",
                "summary": blocked_reason,
            }
        )
    return rec, findings


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


async def _are_industrial_origins_reachable(origins: dict[str, str]) -> bool:
    if not {"scada", "maintenance"}.issubset(origins):
        return False
    async with httpx.AsyncClient(timeout=3.0, trust_env=False) as client:
        for key in ("scada", "maintenance"):
            try:
                resp = await client.get(f"{origins[key]}/health")
                if resp.status_code != 200:
                    return False
            except httpx.HTTPError:
                return False
    return True


async def _get_effect_applied_count(effect_sim_url: str) -> int | None:
    try:
        async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
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


async def _run_readonly_industrial_check(
    ctx: ScenarioContext,
    aclient: httpx.AsyncClient,
    sys_info: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    origins = _extract_lab_origins(sys_info)
    target_has_lab = await _are_industrial_origins_reachable(origins)
    raw_fac = sys_info.get("facility")
    fac_info: dict[str, Any] = raw_fac if isinstance(raw_fac, dict) else {}
    fac_id = str(fac_info.get("facility_id") or "facility-a")

    if target_has_lab:
        effect_url = origins.get("effect_sim")
        before_applied = (
            await _get_effect_applied_count(effect_url) if effect_url else None
        )
        sub = await aclient.post(
            "/api/tasks",
            json={
                "query": "Check bomba 34 alarms and readings in SCADA and maintenance",
                "facility_id": fac_id,
                "allowed_areas": ["area-1"],
                "read_only": True,
            },
        )
        if sub.status_code != 201:
            return False, {"mode": "target", "http_status": sub.status_code}
        rid = str(safe_response_dict(sub).get("run_id") or "")
        snap = await poll_task_terminal(aclient, rid, timeout=25.0)
        res = snap.get("result") or {}
        ans = str(res.get("answer") or "")
        obs = res.get("verified_observations") or []
        after_applied = (
            await _get_effect_applied_count(effect_url) if effect_url else None
        )
        if effect_url:
            zero_effects = (
                before_applied is not None
                and after_applied is not None
                and after_applied == before_applied
            )
        else:
            zero_effects = True
        ok = (
            (snap.get("run") or {}).get("status") == "succeeded"
            and (bool(obs) or ("ALM-3401" in ans and "WO-3408" in ans))
            and zero_effects
        )
        return ok, {
            "mode": "target",
            "run_id": rid,
            "status": (snap.get("run") or {}).get("status"),
            "zero_effects": zero_effects,
        }

    ctx.simulated_services.append("ephemeral_lab_stack")
    resolved_repo = repo_root_fallback(ctx.repo_root)
    lab_dir = ctx.isolated_work_dir() / "lab_n3_readonly"
    try:
        with (
            _EphemeralLabStack(fixture_mode="default") as lab,
            IsolatedLabServer(
                repo_root=resolved_repo,
                base_dir=lab_dir,
                extra_env=lab.env_vars(),
            ) as srv,
        ):
            async with httpx.AsyncClient(
                base_url=srv.base_url,
                timeout=30.0,
                trust_env=False,
                follow_redirects=False,
            ) as lab_client:
                before_applied = await _get_effect_applied_count(lab.effect_sim_url)
                sub = await lab_client.post(
                    "/api/tasks",
                    json={
                        "query": "Check bomba 34 alarms and readings in SCADA and maintenance",
                        "facility_id": "facility-a",
                        "allowed_areas": ["area-1"],
                        "read_only": True,
                    },
                )
                if sub.status_code != 201:
                    return False, {"mode": "ephemeral_lab", "http_status": sub.status_code}
                rid = str(safe_response_dict(sub).get("run_id") or "")
                snap = await poll_task_terminal(lab_client, rid, timeout=25.0)
                res = snap.get("result") or {}
                ans = str(res.get("answer") or "")
                after_applied = await _get_effect_applied_count(lab.effect_sim_url)
                zero_effects = (
                    before_applied is not None
                    and after_applied is not None
                    and after_applied == before_applied == 0
                )
                ok = (
                    (snap.get("run") or {}).get("status") == "succeeded"
                    and "ALM-3401" in ans
                    and "WO-3408" in ans
                    and zero_effects
                )
                return ok, {
                    "mode": "ephemeral_lab",
                    "run_id": rid,
                    "status": (snap.get("run") or {}).get("status"),
                    "zero_effects": zero_effects,
                }
    finally:
        shutil.rmtree(lab_dir, ignore_errors=True)


async def _run_cb13_ready_async(
    ctx: ScenarioContext,
    report: N3ProbeReport,
    verify_res: tuple[int, str, str],
    test_n3_res: tuple[int, str, str],
) -> None:
    ctx.thread_id = "thr_bot_chief"
    ctx.subsystem = "n3_local"
    verify_rc, verify_out, verify_err = verify_res
    test_n3_rc, test_n3_out, test_n3_err = test_n3_res

    ctx.assertions["n3_ready"] = report.overall_status == "READY"
    ctx.assertions["verify_n3_linux_passed"] = verify_rc == 0
    ctx.assertions["test_n3_passed"] = test_n3_rc == 0

    marker = f"CB13_{uuid.uuid4().hex[:6]}"
    orig_chief_engine: str | None = None
    patched_chief_engine = False
    chat_detail: dict[str, Any] = {}
    industrial_detail: dict[str, Any] = {}

    async with ctx.async_client(timeout=30.0) as aclient:
        r_health = await aclient.get("/health")
        ctx.add_request_id(r_health)
        r_info = await aclient.get("/api/system/info")
        ctx.add_request_id(r_info)
        sys_info = safe_response_dict(r_info) if r_info.status_code == 200 else {}
        ctx.assertions["target_health_and_info_ok"] = (
            r_health.status_code == 200 and r_info.status_code == 200 and bool(sys_info)
        )

        sys_backend = sys_info.get("backend_mode")
        sys_emulated = sys_info.get("emulated")
        caps_emulated = ctx.caps.backend_mode in {"emulated", "stub"} or (
            not ctx.caps.is_live_agent_target
        )
        is_emulated = bool(sys_emulated) if isinstance(sys_emulated, bool) else caps_emulated
        local_llm_active = (
            sys_backend == "local_http"
            and ctx.caps.backend_mode == "local_http"
            and is_emulated is False
        )
        ctx.assertions["local_llm_backend_active"] = local_llm_active
        if not local_llm_active:
            ctx.error_notes.append(
                "CB-13 READY requires local_http backend with emulated=False "
                f"(got sys_info.backend_mode={sys_backend!r}, "
                f"caps.backend_mode={ctx.caps.backend_mode!r}, emulated={is_emulated!r})."
            )

        try:
            r_bots = await aclient.get("/api/v1/bots")
            if r_bots.status_code == 200:
                chief = next(
                    (
                        b
                        for b in safe_response_dict(r_bots).get("bots", [])
                        if isinstance(b, dict) and b.get("id") == "bot_chief"
                    ),
                    None,
                )
                if chief is not None and chief.get("engine_id") != "controlbot_runtime":
                    orig_chief_engine = str(chief.get("engine_id") or "")
                    p_resp = await aclient.patch(
                        "/api/v1/bots/bot_chief",
                        json={"engine_id": "controlbot_runtime"},
                    )
                    patched_chief_engine = p_resp.status_code == 200

            async def _send_local_turn() -> TurnOutcome:
                return await trigger_and_wait_turn(
                    aclient,
                    "thr_bot_chief",
                    f"CB13_LOCAL_CHAT_CHECK {marker}",
                    timeout=25.0,
                )

            chat_turn, timing = await measure_ux_action(
                _send_local_turn,
                actions_to_reach=1,
                cancel_available=True,
            )
            ctx.ttfp_ms = timing.ttfp_ms
            ctx.completion_ms = timing.completion_ms
            ctx.cancel_available = True
            ctx.message_id = str(chat_turn.user_message.get("id") or "")
            chat_done = (
                bool(ctx.message_id)
                and chat_turn.assistant_message is not None
                and chat_turn.assistant_message.get("status") == "done"
                and bool(chat_turn.reply_text.strip())
            )
            ctx.assertions["local_chat_turn_completed"] = chat_done
            chat_detail = {
                "turn_id": chat_turn.turn_id,
                "assistant_status": (
                    chat_turn.assistant_message.get("status")
                    if chat_turn.assistant_message
                    else None
                ),
            }
        except Exception as exc:  # noqa: BLE001
            ctx.assertions["local_chat_turn_completed"] = False
            ctx.error_notes.append(f"CB-13 local chat turn failed: {exc}")
        finally:
            if patched_chief_engine and orig_chief_engine:
                with contextlib.suppress(Exception):
                    await aclient.patch(
                        "/api/v1/bots/bot_chief",
                        json={"engine_id": orig_chief_engine},
                    )

        try:
            ind_ok, industrial_detail = await _run_readonly_industrial_check(
                ctx, aclient, sys_info
            )
            ctx.assertions["read_only_industrial_check_passed"] = ind_ok
            if not ind_ok:
                ctx.error_notes.append(
                    f"CB-13 read-only industrial check failed: {industrial_detail!r}"
                )
        except Exception as exc:  # noqa: BLE001
            ctx.assertions["read_only_industrial_check_passed"] = False
            ctx.error_notes.append(f"CB-13 read-only industrial check raised: {exc}")

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
        ctx.assertions["zero_external_browser_requests"] = not pw.external_requests
        ctx.assertions["browser_clean"] = (
            not pw.console_errors and not pw.page_errors and not pw.external_requests
        )
        all_ok = all(ctx.assertions.values()) and not ctx.error_notes
        await ctx.capture_shot(page, "cb13_n3_local", is_error_state=not all_ok)

    ctx.evidence = {
        "n3_report": json.loads(report.model_dump_json()),
        "backend_mode": sys_info.get("backend_mode"),
        "emulated": is_emulated,
        "local_chat_turn": chat_detail,
        "industrial_check": industrial_detail,
        "verify_n3_linux": {
            "returncode": verify_rc,
            "stdout": verify_out,
            "stderr": verify_err,
        },
        "make_test_n3": {
            "returncode": test_n3_rc,
            "stdout": test_n3_out,
            "stderr": test_n3_err,
        },
    }
    ctx.clarity_notes = "CB-13 Linux N3 zero-egress verification passed."


def run(
    ctx: ScenarioContext,
    *,
    n3_report: N3ProbeReport | None = None,
) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-13 scenario (honest blocked_reason when N3 != READY)."""
    report = _resolve_n3_probe(n3_report)
    if report.overall_status != "READY":
        return run_n3_honest_probe(
            campaign_dir=ctx.campaign_dir,
            state=ctx.state,
            repo_root=ctx.repo_root,
            extra_artifacts=ctx.extra_artifacts,
            n3_report=report,
            target_url=ctx.target_url,
        )

    resolved_repo = repo_root_fallback(ctx.repo_root)
    verify_res = _run_verify_n3_script(resolved_repo)
    test_n3_res = _invoke_pytest_n3(resolved_repo, strict=True)
    run_coro_sync(_run_cb13_ready_async(ctx, report, verify_res, test_n3_res))
    return finalize_scenario(ctx)


def run_without_target(
    *,
    campaign_dir: Path,
    state: CampaignState,
    repo_root: Path | None = None,
    extra_artifacts: Sequence[str] = (),
    reference_cards: Sequence[ReferenceBehaviorCard] = (),
    n3_report: N3ProbeReport | None = None,
) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Run CB-13 N3 probe cleanly when target_url is None."""
    del reference_cards
    return run_n3_honest_probe(
        campaign_dir=campaign_dir,
        state=state,
        repo_root=repo_root,
        extra_artifacts=extra_artifacts,
        n3_report=n3_report,
        target_url=None,
    )
