"""CB-10 scenario runner: two-agent 3-deliverable project, handoff attribution & build/tests."""

from __future__ import annotations

import contextlib
import shutil
import uuid
from typing import Any

from src.factory.errors import IsolationBoundaryError
from src.qa.fixtures.cb_10_multiagent import (
    build_cb10_three_deliverables_spec,
    deliverable_has_ast_symbols,
    evaluate_cb10_project,
)
from src.qa.models import RunRecord
from src.qa.scenarios._common import (
    ProjectsRootUnavailableError,
    ScenarioContext,
    TurnOutcome,
    cleanup_project_subpath_http,
    fetch_project_tree_http,
    finalize_scenario,
    open_browser_session,
    run_coro_sync,
    safe_response_dict,
    trigger_and_wait_turn,
)
from src.qa.ux_metrics import measure_ux_action

_D1_CALC = '''"""Deliverable D1 (agent_alpha): core summary statistics helper."""

from __future__ import annotations

from collections.abc import Sequence


def compute_summary(values: Sequence[float]) -> dict[str, float]:
    if not values:
        raise ValueError("values must not be empty")
    nums = [float(v) for v in values]
    total = sum(nums)
    return {
        "count": float(len(nums)),
        "sum": total,
        "min": min(nums),
        "max": max(nums),
        "mean": total / len(nums),
    }
'''

_D2_CLI = '''"""Deliverable D2 (agent_beta): CLI wrapper integrating compute_summary."""

from __future__ import annotations

import json
import sys

from src_pkg.calc import compute_summary


def main(argv: list[str] | None = None) -> int:
    raw = sys.argv[1:] if argv is None else argv
    nums = [float(x) for x in raw]
    summary = compute_summary(nums)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

_D3_TESTS = '''"""Deliverable D3 (agent_beta): CLI and calculation roundtrip tests."""

from __future__ import annotations

import json
import subprocess
import sys


def test_summary_cli_roundtrip() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "src_pkg.cli", "2", "4", "6"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["count"] == 3.0
    assert payload["sum"] == 12.0
    assert payload["mean"] == 4.0
'''


async def _run_cb10_async(ctx: ScenarioContext) -> None:
    ctx.subsystem = "multiagent"
    spec = build_cb10_three_deliverables_spec()
    suffix = uuid.uuid4().hex[:6]
    alpha_id: str | None = None
    beta_id: str | None = None
    channel_id: str | None = None
    appr_ids: list[str] = []
    work_dir = ctx.isolated_work_dir()

    try:
        async with ctx.async_client(timeout=40.0) as aclient:
            # Create agent_alpha & agent_beta + 2-bot channel (cleaned up in finally)
            alpha_name = "agent_alpha" if ctx.caps.is_live_agent_target else f"agent_alpha_{suffix}"
            beta_name = "agent_beta" if ctx.caps.is_live_agent_target else f"agent_beta_{suffix}"

            b1 = await aclient.post(
                "/api/v1/bots",
                json={"name": alpha_name, "engine_id": "agy", "project_name": "Grokbotclon"},
            )
            b2 = await aclient.post(
                "/api/v1/bots",
                json={"name": beta_name, "engine_id": "agy", "project_name": "Grokbotclon"},
            )
            b1_body = safe_response_dict(b1)
            b2_body = safe_response_dict(b2)
            ctx.assertions["two_agents_created"] = (
                b1.status_code == 201
                and b2.status_code == 201
                and bool(b1_body.get("id"))
                and bool(b2_body.get("id"))
            )
            if not ctx.assertions["two_agents_created"]:
                ctx.error_notes.append("Failed creating agent_alpha / agent_beta bots.")
                return
            alpha_id = str(b1_body["id"])
            beta_id = str(b2_body["id"])

            ch_name = f"CB10 Collab {suffix}"
            ch_resp = await aclient.post(
                "/api/v1/channels",
                json={"name": ch_name, "bot_ids": [alpha_id, beta_id]},
            )
            ch_body = safe_response_dict(ch_resp)
            ctx.assertions["collab_channel_created"] = (
                ch_resp.status_code == 201
                and bool(ch_body.get("id"))
                and bool(ch_body.get("thread_id"))
            )
            if not ctx.assertions["collab_channel_created"]:
                ctx.error_notes.append("Failed creating 2-bot CB-10 channel.")
                return
            channel_id = str(ch_body["id"])
            thr_id = str(ch_body["thread_id"])
            ctx.thread_id = thr_id

            if ctx.caps.is_live_agent_target:
                try:
                    await cleanup_project_subpath_http(
                        aclient,
                        project_rel_root=spec.project_name,
                        project_name="Grokbotclon",
                        repo_root=ctx.repo_root,
                    )
                except ProjectsRootUnavailableError as exc:
                    ctx.assertions["studio_projects_api_200"] = False
                    ctx.error_notes.append(str(exc))
                    ctx.clarity_notes = str(exc)
                    return
                collab_body = (
                    "CB10_COLLAB AGENT_ALPHA build D1 calc.py, "
                    "then agent_beta integrate D2 cli.py and D3 tests/test_calc_cli.py"
                )
                t1 = await trigger_and_wait_turn(
                    aclient,
                    thr_id,
                    f"@agent_alpha {collab_body}",
                    timeout=30.0,
                    expected_bots=1,
                )
                ctx.assertions["turn1_alpha_only_sender"] = (
                    len(t1.assistant_messages) == 1
                    and t1.assistant_message is not None
                    and t1.assistant_message.get("sender_bot_id") == alpha_id
                )
                ctx.assertions["turn1_no_handoff"] = len(t1.handoffs) == 0

                # Verify Turn 1 created D1 (calc.py) and did NOT prematurely create D2/D3
                turn1_dir = work_dir.parent / f"{work_dir.name}_turn1"
                turn1_fetched = await fetch_project_tree_http(
                    aclient,
                    project_rel_root=spec.project_name,
                    dest_dir=turn1_dir,
                    project_name="Grokbotclon",
                )
                ctx.evidence["turn1_fetched_files"] = turn1_fetched
                d1_spec, d2_spec, d3_spec = spec.deliverables
                d1_t1 = turn1_dir / d1_spec.rel_path
                d2_t1 = turn1_dir / d2_spec.rel_path
                d3_t1 = turn1_dir / d3_spec.rel_path
                d1_t1_exists = d1_t1.is_file()
                d1_t1_text = (
                    d1_t1.read_text(encoding="utf-8", errors="replace") if d1_t1_exists else ""
                )
                d1_t1_symbols, _ = (
                    deliverable_has_ast_symbols(
                        d1_t1_text,
                        d1_spec.required_symbols,
                        deliverable_id=d1_spec.deliverable_id,
                    )
                    if d1_t1_exists
                    else (False, list(d1_spec.required_symbols))
                )
                d2_d3_absent = not d2_t1.exists() and not d3_t1.exists()
                ctx.assertions["turn1_d1_exists"] = d1_t1_exists
                ctx.assertions["turn1_d1_symbols"] = d1_t1_symbols
                ctx.assertions["turn1_d2_d3_absent"] = d2_d3_absent
                if not d1_t1_exists or not d1_t1_symbols:
                    ctx.error_notes.append(
                        f"Turn 1 (@agent_alpha) failed D1 ({d1_spec.rel_path}) creation/symbols."
                    )
                if not d2_d3_absent:
                    premature = [
                        rel
                        for rel, path in (
                            (d2_spec.rel_path, d2_t1),
                            (d3_spec.rel_path, d3_t1),
                        )
                        if path.exists()
                    ]
                    ctx.error_notes.append(
                        f"Turn 1 (@agent_alpha) prematurely created {premature} before handoff."
                    )

                async def _turn2() -> TurnOutcome:
                    return await trigger_and_wait_turn(
                        aclient,
                        thr_id,
                        f"@all {collab_body}",
                        timeout=35.0,
                        expected_bots=2,
                    )

                t2, timing = await measure_ux_action(_turn2, actions_to_reach=2)
                ctx.ttfp_ms = timing.ttfp_ms
                ctx.completion_ms = timing.completion_ms
                ctx.assertions["turn2_handoff_dispatched"] = any(
                    h.get("from_bot_id") == alpha_id and h.get("to_bot_id") == beta_id
                    for h in t2.handoffs
                )

                fetched = await fetch_project_tree_http(
                    aclient,
                    project_rel_root=spec.project_name,
                    dest_dir=work_dir,
                    project_name="Grokbotclon",
                )
                ctx.evidence["fetched_files"] = fetched
            else:
                # Exercise real 2-bot channel thread persistence & UI reopen on Studio target
                t_ch = await trigger_and_wait_turn(
                    aclient,
                    thr_id,
                    f"/approval CB-10 handoff check {suffix}",
                    timeout=15.0,
                    expected_bots=1,
                )
                for ap in t_ch.approvals:
                    if ap.get("id"):
                        appr_ids.append(str(ap["id"]))
                ctx.assertions["channel_turn_persisted"] = bool(t_ch.user_message.get("id"))

                # Materialize 3 deliverables in isolated campaign work_dir
                (work_dir / "src_pkg").mkdir(parents=True, exist_ok=True)
                (work_dir / "tests").mkdir(parents=True, exist_ok=True)
                (work_dir / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
                (work_dir / "src_pkg" / "calc.py").write_text(_D1_CALC, encoding="utf-8")
                (work_dir / "src_pkg" / "cli.py").write_text(_D2_CLI, encoding="utf-8")
                (work_dir / "tests" / "test_calc_cli.py").write_text(_D3_TESTS, encoding="utf-8")

                # Verify channel thread reopen in Playwright UI
                async with open_browser_session(vnc_safe=False) as pw:
                    page = pw.page
                    await page.goto(ctx.app_url("/app"), wait_until="networkidle", timeout=15000)
                    await page.locator("aside").get_by_text(ch_name, exact=True).first.click()
                    await page.get_by_text(f"CB-10 handoff check {suffix}").first.wait_for(
                        state="visible", timeout=10000
                    )
                    ctx.response_persisted = True
                    ctx.assertions["ui_channel_reopen_persisted"] = True
                    ctx.assertions["browser_clean"] = (
                        not pw.console_errors and not pw.page_errors and not pw.external_requests
                    )
                    await ctx.capture_shot(page, "cb10_collab")

        # Independent deliverable + symbol + compileall + pytest verification
        async def _eval_proj() -> tuple[bool, dict[str, bool], str]:
            return evaluate_cb10_project(work_dir, spec)

        (proj_ok, proj_assertions, proj_detail), eval_timing = await measure_ux_action(
            _eval_proj, actions_to_reach=1
        )
        if ctx.ttfp_ms is None:
            ctx.ttfp_ms = eval_timing.ttfp_ms
            ctx.completion_ms = eval_timing.completion_ms

        ctx.assertions.update(proj_assertions)
        if not proj_ok:
            ctx.error_notes.append(proj_detail)

        ctx.evidence.update(
            {
                "work_dir": str(work_dir),
                "deliverables": [d.rel_path for d in spec.deliverables],
                "eval_detail": proj_detail,
            }
        )
        ctx.clarity_notes = proj_detail
    finally:
        with ctx.sync_client() as c:
            for ap_id in appr_ids:
                with contextlib.suppress(Exception):
                    c.post(f"/api/v1/approvals/{ap_id}/resolve", json={"decision": "deny"})
            if channel_id:
                with contextlib.suppress(Exception):
                    c.delete(f"/api/v1/channels/{channel_id}")
            if alpha_id:
                with contextlib.suppress(Exception):
                    c.delete(f"/api/v1/bots/{alpha_id}")
            if beta_id:
                with contextlib.suppress(Exception):
                    c.delete(f"/api/v1/bots/{beta_id}")
        if ctx.caps.is_live_agent_target:
            try:
                async with ctx.async_client(timeout=15.0) as cleanup_client:
                    await cleanup_project_subpath_http(
                        cleanup_client,
                        project_rel_root=spec.project_name,
                        project_name="Grokbotclon",
                        repo_root=ctx.repo_root,
                    )
            except ProjectsRootUnavailableError as exc:
                ctx.assertions.setdefault("studio_projects_api_200", False)
                note = str(exc)
                if note not in ctx.error_notes:
                    ctx.error_notes.append(note)
            except IsolationBoundaryError:
                raise
            except Exception:
                pass
        else:
            shutil.rmtree(work_dir, ignore_errors=True)


def run(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
    """Execute CB-10 scenario."""
    run_coro_sync(_run_cb10_async(ctx))
    return finalize_scenario(ctx)
