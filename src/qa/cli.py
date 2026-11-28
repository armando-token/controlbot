"""Campaign control CLI for ControlBot differential QA and self-repair."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import inspect
import json
import math
import os
import statistics
import subprocess
import sys
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any, get_args

import httpx
from pydantic import ValidationError

from src.contracts.common import utc_now
from src.factory.errors import IsolationBoundaryError, PolicyImmutabilityError
from src.n3_probe import run_n3_probe
from src.qa.baseline import run_baseline
from src.qa.isolation import (
    ALLOWED_GROKBOT_BOTS,
    _sanitize_record,
    assert_safe_mutation_path,
)
from src.qa.models import (
    BaselineReport,
    CampaignState,
    CandidateManifest,
    CoverageReport,
    LaneName,
    RunRecord,
)
from src.qa.queue import (
    compute_same_sha_passes,
    import_failures_jsonl_into_store,
    ingest_sanitized_logs,
    list_qa_items,
    list_run_records,
    open_campaign_store,
    persist_run_record,
    record_failure_observation,
    resume_campaign,
    save_campaign_state,
    sync_failures_jsonl_from_store,
)
from src.qa.repair_loop import (
    QARepairLoop,
    accept_candidate_to_qa,
    reevaluate_qa_item,
    rollback_candidate_from_qa,
    validate_campaign_isolation,
)
from src.storage.redaction import contains_unredacted_secret_strict

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_VALID_LANES: tuple[str, ...] = get_args(LaneName)


def _resolve_repo_root(raw: Path | None) -> Path:
    return (raw or _REPO_ROOT).resolve()


def _resolve_git_short_sha(repo_root: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return "unknown"


def _load_campaign_state(campaign_dir: Path, *, repo_root: Path) -> tuple[Path, CampaignState]:
    safe_dir = assert_safe_mutation_path(campaign_dir, repo_root=repo_root)
    campaign_file = safe_dir / "campaign.json"
    if not campaign_file.is_file():
        raise FileNotFoundError(f"Missing campaign.json in {safe_dir}")
    state = CampaignState.model_validate_json(campaign_file.read_text(encoding="utf-8"))
    return safe_dir, state


def _parse_cases_arg(raw_cases: str | None) -> list[str]:
    if not raw_cases or not raw_cases.strip():
        return ["CB-00"]
    cases: list[str] = []
    for chunk in raw_cases.split(","):
        part = chunk.strip()
        if not part:
            continue
        if ".." in part and part.upper().startswith("CB-"):
            left, right = part.split("..", 1)
            try:
                start = int(left.upper().removeprefix("CB-"))
                end = int(right.upper().removeprefix("CB-"))
                for num in range(min(start, end), max(start, end) + 1):
                    cases.append(f"CB-{num:02d}")
                continue
            except ValueError:
                pass
        cases.append(part)
    return cases or ["CB-00"]


def _compute_run_stats(
    state: CampaignState,
    runs: Sequence[RunRecord],
    items: Sequence[Any],
    candidates: Sequence[CandidateManifest],
) -> dict[str, Any]:
    durations = sorted(float(r.duration_ms) for r in runs)
    run_count = len(durations)
    if run_count > 0:
        median_ms = round(statistics.median(durations), 3)
        p95_idx = min(run_count - 1, max(0, math.ceil(0.95 * run_count) - 1))
        p95_ms = round(durations[p95_idx], 3)
        variance_ms = round(statistics.pvariance(durations), 3) if run_count > 1 else 0.0
        stddev_ms = round(math.sqrt(variance_ms), 3)
    else:
        median_ms = 0.0
        p95_ms = 0.0
        variance_ms = 0.0
        stddev_ms = 0.0

    passed_runs = sum(1 for r in runs if r.passed)
    failed_runs = run_count - passed_runs
    blocked_count = sum(1 for it in items if it.state == "blocked")
    parked_count = sum(1 for it in items if it.state == "parked")
    repaired_count = sum(1 for c in candidates if c.status == "accepted_qa")
    open_p0 = sum(
        1 for it in items if it.severity == "P0" and it.state not in {"accepted_qa", "parked"}
    )
    open_p1 = sum(
        1 for it in items if it.severity == "P1" and it.state not in {"accepted_qa", "parked"}
    )
    active_sha = state.last_accepted_sha or state.base_sha
    has_runs_for_sha = any((r.candidate_sha or r.base_sha) == active_sha for r in runs)
    if has_runs_for_sha:
        same_sha = compute_same_sha_passes(runs, active_sha)
    else:
        same_sha = state.same_sha_passes.get(active_sha, 0)

    return {
        "tested": run_count,
        "passed": passed_runs,
        "failed": failed_runs,
        "blocked": blocked_count,
        "parked": parked_count,
        "repaired_passing_full_gate": repaired_count,
        "open_p0": open_p0,
        "open_p1": open_p1,
        "same_sha_passes": same_sha,
        "runs": run_count,
        "median_ms": median_ms,
        "p95_ms": p95_ms,
        "variance_ms": variance_ms,
        "stddev_ms": stddev_ms,
    }


def _render_n3_blocker_lines(
    baseline: BaselineReport | None,
    runs: Sequence[RunRecord],
) -> list[str]:
    cb13_blocked = [
        r for r in runs if r.case_id == "CB-13" and not r.passed and bool(r.blocked_reason)
    ]
    n3_status = baseline.n3_status if baseline is not None else None
    if not cb13_blocked and (n3_status is None or n3_status == "READY"):
        return []

    latest_cb13 = cb13_blocked[-1] if cb13_blocked else None
    effective_status = n3_status or "PENDING_N3_LINUX_ENV"
    lines: list[str] = [
        "",
        "## N3 & Environmental Blockers",
        f"- **N3 Status**: `{effective_status}` (skip != pass)",
    ]
    if latest_cb13 is not None and latest_cb13.blocked_reason:
        lines.append(f"- **CB-13 Blocked Reason**: {latest_cb13.blocked_reason}")
    if baseline is not None and baseline.skipped_checks:
        lines.append(f"- **Skipped Checks**: `{', '.join(baseline.skipped_checks)}`")
    lines.extend(
        [
            (
                "- **Unblock Dependencies**: "
                "(1) Linux `ip netns`/`nftables`/`iptables` `OUTPUT DROP` firewall blocking "
                "external egress (`1.1.1.1:443` unreachable); "
                "(2) Local LLM runtime (`ollama`/`llama-server`/`vllm`) on `127.0.0.1` serving "
                "`/v1/models` or `/health`; "
                "(3) AT-SPI bindings (`pyatspi`/`gi`) with active accessibility bus."
            ),
            (
                "- **Rerun Commands**: `bash scripts/verify_n3_linux.sh`, "
                "`uv run python -m src.n3_probe --strict --json`, `make test-n3`"
            ),
        ]
    )
    return lines


def _render_daily_report(
    state: CampaignState,
    baseline: BaselineReport | None,
    stats: dict[str, Any],
    runs: Sequence[RunRecord] = (),
) -> str:
    lines: list[str] = [
        f"# ControlBot QA Daily Report — {state.campaign_id}",
        "",
        f"- **Campaign Status**: `{state.status}`",
        f"- **Lane**: `{state.lane}`",
        f"- **Base SHA**: `{state.base_sha}`",
        f"- **Last Accepted SHA**: `{state.last_accepted_sha or 'none'}`",
        f"- **QA Branch**: `{state.qa_branch}`",
        f"- **Catalog Hash**: `{state.catalog_hash}`",
        f"- **Criteria Hash**: `{state.criteria_hash}`",
        f"- **Limits**: `{json.dumps(state.limits, sort_keys=True)}`",
        f"- **Attempts**: `{json.dumps(state.attempts, sort_keys=True)}`",
        "",
        "## Definition of Done & Statistical Summary",
        f"- **Tested**: `{stats['tested']}`",
        f"- **Passed**: `{stats['passed']}`",
        f"- **Failed**: `{stats['failed']}`",
        f"- **Blocked**: `{stats['blocked']}`",
        f"- **Parked**: `{stats['parked']}`",
        f"- **Repaired Passing Full Gate**: `{stats['repaired_passing_full_gate']}`",
        f"- **Open P0**: `{stats['open_p0']}`",
        f"- **Open P1**: `{stats['open_p1']}`",
        f"- **Same-SHA Passes**: `{stats['same_sha_passes']}`",
        f"- **Runs**: `{stats['runs']}`",
        f"- **Median Duration (ms)**: `{stats['median_ms']}`",
        f"- **P95 Duration (ms)**: `{stats['p95_ms']}`",
        f"- **Variance (ms^2)**: `{stats['variance_ms']}`",
        f"- **Stddev (ms)**: `{stats['stddev_ms']}`",
        "",
    ]
    if baseline is not None:
        skipped = ", ".join(baseline.skipped_checks) if baseline.skipped_checks else "none"
        lines.extend(
            [
                "## Baseline Gate Summary",
                (
                    f"- **Overall Passed**: `{baseline.overall_passed}` "
                    f"(exit_code=`{baseline.exit_code}`)"
                ),
                (
                    f"- **Surface Verified**: `{baseline.surface_verified}` "
                    f"(`served_surface={baseline.served_surface}`)"
                ),
                (
                    f"- **Backend / Runtime Mode**: "
                    f"`{baseline.backend_mode}` / `{baseline.runtime_mode}`"
                ),
                f"- **N3 Status**: `{baseline.n3_status}`",
                f"- **Boot Errors**: `{len(baseline.boot_errors)}`",
                f"- **Functional Errors**: `{len(baseline.functional_errors)}`",
                f"- **Skipped Checks**: `{skipped}`",
            ]
        )
    else:
        lines.append("## Baseline Gate Summary\n- No baseline.json found in campaign directory.")
    lines.extend(_render_n3_blocker_lines(baseline, runs))
    return "\n".join(lines) + "\n"


def _render_campaign_handoff(
    state: CampaignState,
    baseline: BaselineReport | None,
    stats: dict[str, Any],
    runs: Sequence[RunRecord] = (),
) -> str:
    lines: list[str] = [
        f"# ControlBot QA Campaign Handoff — {state.campaign_id}",
        "",
        "## Observation",
        f"- Campaign directory: `{state.output_dir}`",
        f"- Base SHA: `{state.base_sha}`",
        f"- Last accepted SHA: `{state.last_accepted_sha or 'none'}`",
        f"- Campaign status: `{state.status}`",
        f"- Open P0: `{stats['open_p0']}` | Open P1: `{stats['open_p1']}`",
        f"- Same-SHA Passes: `{stats['same_sha_passes']}` | Runs: `{stats['runs']}`",
        (
            f"- Timing stats: median=`{stats['median_ms']}` ms, "
            f"p95=`{stats['p95_ms']}` ms, variance=`{stats['variance_ms']}`"
        ),
    ]
    if baseline is not None:
        lines.extend(
            [
                (
                    f"- Baseline `surface_verified`: `{baseline.surface_verified}` "
                    f"(`served_surface={baseline.served_surface}`)"
                ),
                f"- Verified `/assets/*` count: `{len(baseline.asset_hashes)}`",
                f"- Boot errors: `{baseline.boot_errors}`",
                f"- Functional errors: `{baseline.functional_errors}`",
            ]
        )
    lines.extend(
        [
            "",
            "## Logic Chain",
            (
                "- Campaign artifacts, SQLite QA queue (`qa_items`, `qa_run_records`), "
                "and baseline verification state were validated against strict schemas."
            ),
            "- Secret redaction checks passed before persisting markdown and JSON artifacts.",
            "",
            "## Caveats",
            (
                "- M3 discovery/UX/reference cards and M4/M5 CB-00..CB-13 scenarios activate "
                "automatically via optional plugin dispatch when present."
            ),
            *_render_n3_blocker_lines(baseline, runs),
            "",
            "## Conclusion",
            f"- Campaign `{state.campaign_id}` report generated successfully.",
            "",
            "## Verification Method",
            f"- `python -m src.qa report --campaign-dir {state.output_dir} --json`",
        ]
    )
    return "\n".join(lines) + "\n"


def _handle_baseline(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo_root)
    short_sha = _resolve_git_short_sha(repo_root)
    campaign_id: str = args.campaign_id or f"qa-{utc_now().strftime('%Y%m%dT%H%M%SZ')}-{short_sha}"

    raw_out: Path | None = args.output_dir
    if raw_out is None or not str(raw_out).strip():
        output_dir = repo_root / "var" / "qa_campaigns" / campaign_id
    else:
        output_dir = raw_out

    token: str | None = (
        args.token
        or os.environ.get("GROKBOT_WEB_TOKEN")
        or os.environ.get("CONTROLBOT_WEB_TOKEN")
        or None
    )

    report = run_baseline(
        repo_root=repo_root,
        output_dir=output_dir,
        target_url=args.target_url,
        token=token,
        lane=args.lane,
        build_frontend=args.build_frontend,
        skip_browser=args.skip_browser,
        use_isolated_lab=args.isolated_lab,
        log_dir=args.log_dir,
        campaign_id=campaign_id,
    )

    if args.json:
        payload: dict[str, Any] = {
            "ok": report.overall_passed,
            "exit_code": report.exit_code,
            "output_dir": str(assert_safe_mutation_path(output_dir, repo_root=repo_root)),
            "report": json.loads(report.model_dump_json()),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(
            f"[qa baseline] campaign={report.campaign_id} "
            f"surface_verified={report.surface_verified} "
            f"served_surface={report.served_surface} "
            f"overall_passed={report.overall_passed} "
            f"exit_code={report.exit_code}"
        )
        if report.boot_errors:
            print(f"[boot_errors] {report.boot_errors}", file=sys.stderr)
        if report.functional_errors:
            print(f"[functional_errors] {report.functional_errors}", file=sys.stderr)
    return report.exit_code


def _load_optional_module(module_name: str) -> Any | None:
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name:
            return None
        raise


def _run_builtin_case_probe(
    *,
    case_id: str,
    campaign_dir: Path,
    state: CampaignState,
    baseline: BaselineReport | None,
    target_url: str | None,
    token: str | None,
    build_hash: str,
    extra_artifacts: Sequence[str] = (),
) -> tuple[RunRecord, list[dict[str, Any]]]:
    started_at = utc_now()
    t0 = time.monotonic()
    assertions: dict[str, bool] = {}
    request_ids: list[str] = []
    findings: list[dict[str, Any]] = []
    error_summary: str | None = None
    blocked_reason: str | None = None
    fixture_version = "1.0"
    artifact_paths = list(extra_artifacts)

    backend_mode = baseline.backend_mode if baseline is not None else "emulated"
    runtime_mode = baseline.runtime_mode if baseline is not None else "live_runtime"
    model_id = baseline.model_id if baseline is not None else "emulated"
    emulated = baseline.emulated if baseline is not None else True
    real_services = list(baseline.real_services) if baseline is not None else []
    simulated_services = (
        list(baseline.simulated_services) if baseline is not None else ["emulated_runtime"]
    )

    valve_fixture = campaign_dir / "fixtures" / "cb_valve_104.json"
    if case_id == "CB-13":
        n3_report = run_n3_probe()
        n3_status = str(n3_report.overall_status)
        if n3_status != "READY":
            assertions["n3_ready"] = False
            notes = "; ".join(n3_report.evidence_notes) or n3_status
            blocked_reason = f"N3 gate not ready ({n3_status}): {notes} (skip != pass)."
            error_summary = blocked_reason
        else:
            assertions["scenario_runner_available"] = False
            blocked_reason = (
                "Scenario CB-13 runner not implemented (awaiting M5 src.qa.scenarios)."
            )
            error_summary = blocked_reason
    elif case_id != "CB-00":
        # Never emit stub passed=True for unimplemented M4/M5 scenarios
        if case_id == "CB-02" and valve_fixture.is_file():
            with contextlib.suppress(json.JSONDecodeError, OSError):
                fx_data = json.loads(valve_fixture.read_text(encoding="utf-8"))
                if isinstance(fx_data, dict) and fx_data.get("fixture_version"):
                    fixture_version = str(fx_data["fixture_version"])
        assertions["scenario_runner_available"] = False
        blocked_reason = (
            f"Scenario {case_id} runner not implemented (awaiting M4/M5 src.qa.scenarios)."
        )
        error_summary = blocked_reason
    elif target_url:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            with httpx.Client(
                base_url=target_url.rstrip("/"),
                headers=headers,
                timeout=5.0,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                r_health = client.get("/health")
                assertions["health_200"] = r_health.status_code == 200
                if r_health.headers.get("X-Request-Id"):
                    request_ids.append(r_health.headers["X-Request-Id"])

                r_info = client.get("/api/system/info")
                assertions["system_info_200"] = r_info.status_code == 200
                if r_info.headers.get("X-Request-Id"):
                    request_ids.append(r_info.headers["X-Request-Id"])
                if r_info.status_code == 200:
                    info = r_info.json()
                    if isinstance(info, dict):
                        backend_mode = str(info.get("backend_mode") or backend_mode)
                        runtime_mode = str(info.get("runtime_mode") or runtime_mode)
                        if info.get("llm_model_id"):
                            model_id = str(info["llm_model_id"])
                        emulated = backend_mode in {"emulated", "stub"}

                app_params = {"token": token} if token else None
                r_app = client.get("/app", params=app_params)
                assertions["app_surface_200"] = r_app.status_code == 200
                if r_app.headers.get("X-Request-Id"):
                    request_ids.append(r_app.headers["X-Request-Id"])

                if not all(assertions.values()):
                    blocked_reason = "CB-00 HTTP/surface probe returned non-200 status."
                    error_summary = blocked_reason
        except Exception as exc:
            assertions["target_reachable"] = False
            error_summary = f"{type(exc).__name__}: {exc}"
            blocked_reason = error_summary
            findings.append(
                {
                    "subsystem": "web",
                    "raw_signature": f"{case_id}_target_unreachable_{type(exc).__name__}",
                    "severity": "P1",
                    "summary": f"{case_id} probe failed reaching {target_url}: {exc}",
                }
            )
    else:
        baseline_ok = baseline is not None and baseline.overall_passed
        assertions["baseline_recorded"] = baseline_ok
        if not baseline_ok:
            blocked_reason = "CB-00 requires target_url or passing baseline.json."
            error_summary = blocked_reason

    finished_at = utc_now()
    duration_ms = round(max(0.01, (time.monotonic() - t0) * 1000.0), 3)
    passed = bool(assertions) and all(assertions.values()) and blocked_reason is None

    rec = RunRecord(
        campaign_id=state.campaign_id,
        case_id=case_id,
        run_id=f"run-{case_id.lower()}-{uuid.uuid4().hex[:8]}",
        base_sha=state.base_sha,
        candidate_sha=state.last_accepted_sha,
        build_hash=build_hash,
        lane=state.lane,
        profile="default",
        ui_variant=baseline.ui_variant if baseline is not None else "react_dist",
        backend_mode=backend_mode,
        runtime_mode=runtime_mode,
        model_id=model_id,
        emulated=emulated,
        real_services=real_services,
        simulated_services=simulated_services,
        fixture_version=fixture_version,
        browser="http_probe",
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
        request_ids=request_ids,
        passed=passed,
        assertions=assertions,
        artifact_paths=artifact_paths,
        error_summary=error_summary,
        blocked_reason=blocked_reason,
    )
    return rec, findings


def _handle_scan(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo_root)
    safe_dir, state = _load_campaign_state(args.campaign_dir, repo_root=repo_root)
    target_url = args.target_url or state.target_url

    # Validate isolation BEFORE any HTTP/network call
    validate_campaign_isolation(
        safe_dir,
        repo_root=repo_root,
        target_url=target_url,
        allow_live_target=False,
    )

    token: str | None = (
        args.token
        or os.environ.get("GROKBOT_WEB_TOKEN")
        or os.environ.get("CONTROLBOT_WEB_TOKEN")
        or None
    )

    baseline_path = safe_dir / "baseline.json"
    baseline: BaselineReport | None = None
    if baseline_path.is_file():
        baseline = BaselineReport.model_validate_json(baseline_path.read_text(encoding="utf-8"))

    build_hash = state.base_sha[:12]
    if baseline is not None and baseline.asset_hashes:
        build_hash = hashlib.sha256(
            json.dumps(baseline.asset_hashes, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]

    store = open_campaign_store(safe_dir, state, repo_root=repo_root)
    import_failures_jsonl_into_store(store, state, safe_dir)

    # Read/emit reference cards gracefully if M3 reference_cards is present
    ref_dir = safe_dir / "reference_cards"
    ref_mod = _load_optional_module("src.qa.reference_cards")
    loaded_reference_cards: list[Any] = []
    if ref_mod is not None:
        if (
            state.lane == "external_reference"
            and not any(ref_dir.glob("*.json"))
            and hasattr(ref_mod, "emit_m3_reference_cards")
        ):
            ref_mod.emit_m3_reference_cards(cards_dir=ref_dir)
        if ref_dir.is_dir():
            for card_file in sorted(ref_dir.glob("*.json")):
                try:
                    raw_card = json.loads(card_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(raw_card, dict) and raw_card.get("bot_used") is not None:
                    raw_bot = raw_card.get("bot_used")
                    if not isinstance(raw_bot, str) or raw_bot not in ALLOWED_GROKBOT_BOTS:
                        raise IsolationBoundaryError(
                            f"ISOLATION_BOUNDARY_VIOLATION: forbidden bot_used={raw_bot!r} "
                            f"in reference card {card_file.name!r} "
                            f"(allowed={sorted(ALLOWED_GROKBOT_BOTS)})."
                        )
                if contains_unredacted_secret_strict(raw_card):
                    raise ValueError(
                        f"unredacted_secret_detected in reference card {card_file.name!r}."
                    )
        if ref_dir.is_dir() and hasattr(ref_mod, "load_reference_cards"):
            try:
                loaded_reference_cards = list(ref_mod.load_reference_cards(ref_dir))
            except ValueError as exc:
                if isinstance(exc, ValidationError) and any(
                    "bot_used" in err.get("loc", ()) for err in exc.errors()
                ):
                    raise IsolationBoundaryError(
                        f"ISOLATION_BOUNDARY_VIOLATION: forbidden bot_used in reference card: {exc}"
                    ) from exc
                msg = str(exc)
                if "forbidden_bot_used" in msg:
                    raise IsolationBoundaryError(msg) from exc
                if "unredacted_secret_detected" in msg:
                    raise
                with contextlib.suppress(ValueError):
                    loaded_reference_cards = list(
                        ref_mod.load_reference_cards(ref_dir, strict=False)
                    )

    # Optional M3 control discovery plugin
    coverage_path = safe_dir / "coverage.json"
    ux_metrics_path = safe_dir / "ux_metrics.json"
    discovery_artifacts: list[str] = []
    if args.discover_controls:
        disc_mod = _load_optional_module("src.qa.discovery")
        if disc_mod is not None and hasattr(disc_mod, "discover_controls"):
            disc_res = disc_mod.discover_controls(
                output_dir=safe_dir,
                base_url=target_url,
                campaign_id=state.campaign_id,
                repo_root=repo_root,
                token=token,
                capture_screenshots=True,
            )
            disc_shots = list(getattr(disc_res, "screenshots", ()))
            for shot in disc_shots:
                shot_path = getattr(shot, "path", None)
                if isinstance(shot_path, str) and shot_path:
                    discovery_artifacts.append(shot_path)
            for noop_ctrl in getattr(disc_res, "silent_noop_controls", ()):
                record_failure_observation(
                    store,
                    state,
                    case_id="QA-2",
                    subsystem="ui_discovery",
                    raw_signature=f"silent_noop_{noop_ctrl}",
                    severity="P1",
                    summary=f"UI control {noop_ctrl!r} had silent no-op click transition.",
                    source="ux",
                    initial_state="observed",
                )
            for focus_defect in getattr(disc_res, "focus_defects", ()):
                record_failure_observation(
                    store,
                    state,
                    case_id="QA-2",
                    subsystem="ui_focus",
                    raw_signature=f"focus_defect_{focus_defect}",
                    severity="P1",
                    summary=f"UI focus defect detected during discovery: {focus_defect}",
                    source="ux",
                    initial_state="observed",
                )
            if not getattr(disc_res, "local_remote_indicator_visible", True):
                record_failure_observation(
                    store,
                    state,
                    case_id="QA-2",
                    subsystem="ui_ux",
                    raw_signature="missing_local_remote_indicator",
                    severity="P1",
                    summary="Top-level local-vs-remote execution indicator not visible.",
                    source="ux",
                    initial_state="observed",
                )
            if not getattr(disc_res, "composer_layout_intact", True):
                record_failure_observation(
                    store,
                    state,
                    case_id="QA-2",
                    subsystem="ui_ux",
                    raw_signature="composer_layout_wrapped",
                    severity="P1",
                    summary="Message composer layout wrapped or broke single-row Send at 1280x800.",
                    source="ux",
                    initial_state="observed",
                )
            for cerr in getattr(disc_res, "console_errors", ()):
                record_failure_observation(
                    store,
                    state,
                    case_id="QA-2",
                    subsystem="ui_console",
                    raw_signature=f"console_error_{str(cerr)[:64]}",
                    severity="P1",
                    summary=f"Browser console error during discovery: {cerr}",
                    source="ux",
                    initial_state="observed",
                )
            for perr in getattr(disc_res, "page_errors", ()):
                record_failure_observation(
                    store,
                    state,
                    case_id="QA-2",
                    subsystem="ui_pageerror",
                    raw_signature=f"page_error_{str(perr)[:64]}",
                    severity="P1",
                    summary=f"Browser pageerror during discovery: {perr}",
                    source="ux",
                    initial_state="observed",
                )
            ux_mod = _load_optional_module("src.qa.ux_metrics")
            if ux_mod is not None and hasattr(ux_mod, "save_ux_metrics") and hasattr(
                ux_mod, "UxFlowMetrics"
            ):
                disc_flow = ux_mod.UxFlowMetrics(
                    case_id="QA-2",
                    run_id=f"run-qa2-{uuid.uuid4().hex[:8]}",
                    actions_to_reach=1,
                    completion_ms=0.0,
                    focus_predictable=not bool(getattr(disc_res, "focus_defects", ())),
                    local_remote_indicator_visible=bool(
                        getattr(disc_res, "local_remote_indicator_visible", False)
                    ),
                    local_remote_location=str(
                        getattr(disc_res, "local_remote_location", "")
                    ),
                    composer_layout_intact=bool(
                        getattr(disc_res, "composer_layout_intact", True)
                    ),
                    result_clarity_notes=(
                        "Control discovery scanned "
                        f"{getattr(disc_res.coverage, 'total_controls', 0)} controls."
                    ),
                    screenshots=disc_shots,
                )
                existing_flows: list[Any] = []
                if ux_metrics_path.is_file() and hasattr(ux_mod, "UxMetricReport"):
                    with contextlib.suppress(Exception):
                        prev_rep = ux_mod.UxMetricReport.model_validate_json(
                            ux_metrics_path.read_text(encoding="utf-8")
                        )
                        existing_flows = list(prev_rep.flows)
                existing_flows.append(disc_flow)
                ux_mod.save_ux_metrics(
                    existing_flows,
                    ux_metrics_path,
                    campaign_id=state.campaign_id,
                    repo_root=repo_root,
                )
        elif not coverage_path.is_file():
            cov = CoverageReport(
                campaign_id=state.campaign_id,
                repo_sha=state.base_sha,
                total_controls=0,
                covered_count=0,
                blocked_count=0,
                pending_count=0,
                out_of_scope_count=0,
                by_module={},
                items=[],
            )
            coverage_path.write_text(cov.model_dump_json(indent=2) + "\n", encoding="utf-8")

    # Run selected cases (M4 scenarios plugin if available, else built-in probe)
    cases = _parse_cases_arg(args.cases)
    scen_mod = _load_optional_module("src.qa.scenarios")
    runs_recorded: list[RunRecord] = []

    for case_id in cases:
        run_rec: RunRecord | None = None
        case_findings: list[dict[str, Any]] = []
        if scen_mod is not None and hasattr(scen_mod, "run_scenario"):
            scen_kwargs: dict[str, Any] = {
                "case_id": case_id,
                "campaign_dir": safe_dir,
                "state": state,
                "target_url": target_url,
                "token": token,
                "repo_root": repo_root,
            }
            with contextlib.suppress(TypeError, ValueError):
                sig_params = inspect.signature(scen_mod.run_scenario).parameters
                if "extra_artifacts" in sig_params:
                    scen_kwargs["extra_artifacts"] = discovery_artifacts
                if "reference_cards" in sig_params:
                    scen_kwargs["reference_cards"] = loaded_reference_cards
                if case_id == "CB-13" and "n3_report" in sig_params:
                    scen_kwargs["n3_report"] = run_n3_probe()
            scen_res = scen_mod.run_scenario(**scen_kwargs)
            if isinstance(scen_res, RunRecord):
                run_rec = scen_res
            elif isinstance(scen_res, tuple) and len(scen_res) == 2:
                run_rec, case_findings = scen_res
            if run_rec is not None and (discovery_artifacts or ux_metrics_path.is_file()):
                extra_paths = list(discovery_artifacts)
                if ux_metrics_path.is_file():
                    extra_paths.append(str(ux_metrics_path))
                merged_arts = list(dict.fromkeys([*run_rec.artifact_paths, *extra_paths]))
                if merged_arts != list(run_rec.artifact_paths):
                    run_rec = run_rec.model_copy(update={"artifact_paths": merged_arts})
        if run_rec is None:
            builtin_extra = list(discovery_artifacts)
            if ux_metrics_path.is_file():
                builtin_extra.append(str(ux_metrics_path))
            run_rec, case_findings = _run_builtin_case_probe(
                case_id=case_id,
                campaign_dir=safe_dir,
                state=state,
                baseline=baseline,
                target_url=target_url,
                token=token,
                build_hash=build_hash,
                extra_artifacts=list(dict.fromkeys(builtin_extra)),
            )

        persist_run_record(store, safe_dir, run_rec)
        runs_recorded.append(run_rec)
        for finding in case_findings:
            record_failure_observation(
                store,
                state,
                case_id=case_id,
                subsystem=str(finding.get("subsystem") or "e2e"),
                raw_signature=str(finding.get("raw_signature") or f"{case_id}_failure"),
                severity=finding.get("severity") or "P1",
                summary=str(finding.get("summary") or f"{case_id} failure"),
                source="e2e",
                run_id=run_rec.run_id,
                correlation_ids=run_rec.request_ids,
                initial_state="observed",
            )

    # Log ingestion only when explicitly requested via --ingest-logs or --log-dir
    logs_dir: Path | None = args.log_dir
    if logs_dir is None and args.ingest_logs and baseline is not None:
        raw_log_dir = (baseline.active_log_summary or {}).get("logs_dir")
        if isinstance(raw_log_dir, str) and raw_log_dir.strip():
            logs_dir = Path(raw_log_dir)

    ingest_res: dict[str, Any] = {
        "ingested_count": 0,
        "ingested_request_ids": [],
        "halted_p0": False,
    }
    if args.ingest_logs or args.log_dir is not None:
        ingest_res = ingest_sanitized_logs(
            store,
            state,
            logs_dir=logs_dir,
            campaign_dir=safe_dir,
            case_id=cases[0] if cases else "CB-00",
            run_id=runs_recorded[-1].run_id if runs_recorded else None,
            target_url=target_url,
            token=token,
        )
        ingested_req_ids = [
            rid for rid in ingest_res.get("ingested_request_ids", []) if isinstance(rid, str)
        ]
        if ingested_req_ids and runs_recorded:
            last_run = runs_recorded[-1]
            merged_reqs = list(dict.fromkeys([*last_run.request_ids, *ingested_req_ids]))
            updated_run = last_run.model_copy(update={"request_ids": merged_reqs})
            persist_run_record(store, safe_dir, updated_run)
            runs_recorded[-1] = updated_run

    sync_failures_jsonl_from_store(store, state.campaign_id, safe_dir)

    all_runs = list_run_records(store, state.campaign_id)
    active_sha = state.last_accepted_sha or state.base_sha
    same_sha_count = compute_same_sha_passes(all_runs, active_sha)
    same_sha_map = dict(state.same_sha_passes)
    same_sha_map[active_sha] = same_sha_count

    updated_artifacts = dict(state.artifacts)
    updated_artifacts["factory_db"] = str(safe_dir / "factory.sqlite3")
    updated_artifacts["runs_jsonl"] = str(safe_dir / "runs.jsonl")
    updated_artifacts["failures_jsonl"] = str(safe_dir / "failures.jsonl")
    if coverage_path.is_file():
        updated_artifacts["coverage_json"] = str(coverage_path)
    if ux_metrics_path.is_file():
        updated_artifacts["ux_metrics_json"] = str(ux_metrics_path)
    if ref_dir.is_dir() and any(ref_dir.glob("*.json")):
        updated_artifacts["reference_cards_dir"] = str(ref_dir)

    # Reload state in case ingest_sanitized_logs updated halted_p0
    latest_state = CampaignState.model_validate_json(
        (safe_dir / "campaign.json").read_text(encoding="utf-8")
    )
    updated_state = latest_state.model_copy(
        update={
            "same_sha_passes": same_sha_map,
            "last_green_sha": active_sha if same_sha_count > 0 else latest_state.last_green_sha,
            "artifacts": updated_artifacts,
            "last_requested_command": "scan",
            "updated_at": utc_now(),
        }
    )
    save_campaign_state(safe_dir, updated_state, store=store)

    if args.json:
        print(
            json.dumps(
                _sanitize_record(
                    {
                        "ok": not ingest_res.get("halted_p0", False),
                        "campaign_id": updated_state.campaign_id,
                        "cases": cases,
                        "runs_recorded": len(runs_recorded),
                        "ingested_logs": ingest_res.get("ingested_count", 0),
                        "same_sha_passes": same_sha_count,
                    }
                ),
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(
            f"[qa scan] campaign={updated_state.campaign_id} cases={cases} "
            f"runs={len(runs_recorded)} ingested={ingest_res.get('ingested_count', 0)}"
        )
    return 1 if ingest_res.get("halted_p0", False) else 0


def _handle_repair(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo_root)
    if args.max_parallel < 1 or args.max_parallel > 2:
        raise ValueError(
            f"Invalid --max-parallel={args.max_parallel}: "
            "at most 2 parallel repairers are permitted (<= 2)."
        )
    if args.max_attempts < 1:
        raise ValueError(f"Invalid --max-attempts={args.max_attempts}: must be >= 1.")

    safe_dir, state = _load_campaign_state(args.campaign_dir, repo_root=repo_root)
    validate_campaign_isolation(
        safe_dir,
        repo_root=repo_root,
        target_url=state.target_url,
        allow_live_target=False,
    )

    loop = QARepairLoop(
        campaign_dir=safe_dir,
        repo_root=repo_root,
        max_parallel=args.max_parallel,
        max_attempts=args.max_attempts,
        author_model=args.author_model or state.author_model or "hydrogen",
        auditor_model=args.auditor_model or state.auditor_model or "pro",
        build_frontend=args.build_frontend,
        skip_browser=args.skip_browser,
        auto_accept=not args.no_auto_accept,
    )
    summary = loop.run()
    if args.json:
        print(json.dumps(_sanitize_record(summary), indent=2, ensure_ascii=False))
    else:
        print(
            f"[qa repair] campaign={summary['campaign_id']} "
            f"workers={len(summary['worker_results'])} "
            f"accepted={summary['accepted_candidates']} "
            f"parked={summary['parked_items']}"
        )
    return 0


def _handle_resume(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo_root)
    safe_dir, state = _load_campaign_state(args.campaign_dir, repo_root=repo_root)
    validate_campaign_isolation(
        safe_dir,
        repo_root=repo_root,
        target_url=state.target_url,
        allow_live_target=True,
    )
    updated_state, details = resume_campaign(
        safe_dir,
        repo_root=repo_root,
        logs_dir=args.log_dir,
    )
    if args.json:
        print(
            json.dumps(
                _sanitize_record(
                    {
                        "ok": True,
                        "campaign_id": updated_state.campaign_id,
                        "status": updated_state.status,
                        **details,
                    }
                ),
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(
            f"[qa resume] campaign={updated_state.campaign_id} "
            f"ingested={details['ingested_from_logs']} "
            f"expired_leases={len(details['expired_leases'])}"
        )
    return 0


def _handle_reevaluate(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo_root)
    res = reevaluate_qa_item(
        args.campaign_dir,
        item_id=args.item,
        repo_root=repo_root,
        build_frontend=args.build_frontend,
        skip_browser=args.skip_browser,
    )
    if args.json:
        print(json.dumps(_sanitize_record(res), indent=2, ensure_ascii=False))
    else:
        print(
            f"[qa reevaluate] item={res['item_id']} state={res['state']} "
            f"baseline_passed={res['baseline_passed']}"
        )
    return 0


def _handle_accept(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo_root)
    res = accept_candidate_to_qa(
        args.campaign_dir,
        candidate_id=args.candidate,
        repo_root=repo_root,
        build_frontend=args.build_frontend,
        skip_browser=args.skip_browser,
    )
    if args.json:
        print(json.dumps(_sanitize_record(res), indent=2, ensure_ascii=False))
    else:
        print(
            f"[qa accept] candidate={res['candidate_id']} status={res['status']} "
            f"accepted_sha={res['accepted_sha']}"
        )
    return 0


def _handle_rollback(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo_root)
    res = rollback_candidate_from_qa(
        args.campaign_dir,
        candidate_id=args.candidate,
        repo_root=repo_root,
        reason=args.reason,
    )
    if args.json:
        print(json.dumps(_sanitize_record(res), indent=2, ensure_ascii=False))
    else:
        print(
            f"[qa rollback] candidate={res['candidate_id']} status={res['status']} "
            f"restored_sha={res['restored_sha']}"
        )
    return 0


def _handle_report(args: argparse.Namespace) -> int:
    repo_root = _resolve_repo_root(args.repo_root)
    safe_dir, state = _load_campaign_state(args.campaign_dir, repo_root=repo_root)

    baseline_path = safe_dir / "baseline.json"
    baseline: BaselineReport | None = None
    if baseline_path.is_file():
        baseline = BaselineReport.model_validate_json(baseline_path.read_text(encoding="utf-8"))

    store = open_campaign_store(safe_dir, state, repo_root=repo_root)
    import_failures_jsonl_into_store(store, state, safe_dir)
    runs = list_run_records(store, state.campaign_id)
    items = list_qa_items(store, state.campaign_id)

    candidates: list[CandidateManifest] = []
    cand_dir = safe_dir / "candidates"
    if cand_dir.is_dir():
        for cf in sorted(cand_dir.glob("*.json")):
            candidates.append(CandidateManifest.model_validate_json(cf.read_text(encoding="utf-8")))

    stats = _compute_run_stats(state, runs, items, candidates)
    daily_md = _render_daily_report(state, baseline, stats, runs=runs)
    handoff_md = _render_campaign_handoff(state, baseline, stats, runs=runs)
    if contains_unredacted_secret_strict({"daily": daily_md, "handoff": handoff_md}):
        raise ValueError("Refusing to write unredacted secret in campaign report.")

    daily_path = safe_dir / "daily_report.md"
    handoff_path = safe_dir / "HANDOFF.md"
    daily_path.write_text(daily_md, encoding="utf-8")
    handoff_path.write_text(handoff_md, encoding="utf-8")

    updated_artifacts = dict(state.artifacts)
    updated_artifacts["daily_report_md"] = str(daily_path)
    updated_artifacts["handoff_md"] = str(handoff_path)
    updated_state = state.model_copy(
        update={
            "artifacts": updated_artifacts,
            "last_requested_command": "report",
            "updated_at": utc_now(),
        }
    )
    save_campaign_state(safe_dir, updated_state, store=store)

    if args.json:
        print(
            json.dumps(
                _sanitize_record(
                    {
                        "ok": True,
                        "campaign_id": updated_state.campaign_id,
                        "daily_report_md": str(daily_path),
                        "handoff_md": str(handoff_path),
                        "stats": stats,
                    }
                ),
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(f"[qa report] wrote {daily_path} and {handoff_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser for `python -m src.qa`."""
    parser = argparse.ArgumentParser(
        prog="python -m src.qa",
        description="ControlBot Differential QA & Self-Repair CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_base = sub.add_parser("baseline", help="Run QA-0/QA-1 baseline and React /app surface gate.")
    p_base.add_argument("--campaign-id", type=str, default=None)
    p_base.add_argument("--target-url", type=str, default="http://127.0.0.1:8000")
    p_base.add_argument("--output-dir", "--out", dest="output_dir", type=Path, default=None)
    p_base.add_argument("--lane", choices=_VALID_LANES, default="local_deterministic")
    p_base.add_argument(
        "--build-frontend",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    p_base.add_argument("--skip-browser", action="store_true", default=False)
    p_base.add_argument(
        "--isolated-lab",
        action=argparse.BooleanOptionalAction,
        default=None,
    )
    p_base.add_argument("--token", type=str, default=None)
    p_base.add_argument("--log-dir", type=Path, default=None)
    p_base.add_argument("--repo-root", type=Path, default=None)
    p_base.add_argument("--json", action="store_true", default=False)

    p_rep = sub.add_parser("report", help="Generate daily_report.md and HANDOFF.md for campaign.")
    p_rep.add_argument("--campaign-dir", type=Path, required=True)
    p_rep.add_argument("--repo-root", type=Path, default=None)
    p_rep.add_argument("--json", action="store_true", default=False)

    p_scan = sub.add_parser("scan", help="Run differential QA scan (M2/M3/M4).")
    p_scan.add_argument("--campaign-dir", type=Path, required=True)
    p_scan.add_argument("--cases", type=str, default=None)
    p_scan.add_argument("--discover-controls", action="store_true", default=False)
    p_scan.add_argument("--ingest-logs", action="store_true", default=False)
    p_scan.add_argument("--target-url", type=str, default=None)
    p_scan.add_argument("--token", type=str, default=None)
    p_scan.add_argument("--log-dir", type=Path, default=None)
    p_scan.add_argument("--repo-root", type=Path, default=None)
    p_scan.add_argument("--json", action="store_true", default=False)

    p_repair = sub.add_parser("repair", help="Run 7-step M7 self-repair loop (M2).")
    p_repair.add_argument("--campaign-dir", type=Path, required=True)
    p_repair.add_argument("--max-parallel", type=int, default=2)
    p_repair.add_argument("--max-attempts", type=int, default=2)
    p_repair.add_argument("--author-model", type=str, default=None)
    p_repair.add_argument("--auditor-model", type=str, default=None)
    p_repair.add_argument(
        "--build-frontend",
        action=argparse.BooleanOptionalAction,
        default=False,
    )
    p_repair.add_argument(
        "--skip-browser",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    p_repair.add_argument("--no-auto-accept", action="store_true", default=False)
    p_repair.add_argument("--repo-root", type=Path, default=None)
    p_repair.add_argument("--json", action="store_true", default=False)

    p_resume = sub.add_parser("resume", help="Resume an interrupted QA campaign (M2).")
    p_resume.add_argument("--campaign-dir", type=Path, required=True)
    p_resume.add_argument("--log-dir", type=Path, default=None)
    p_resume.add_argument("--repo-root", type=Path, default=None)
    p_resume.add_argument("--json", action="store_true", default=False)

    p_reeval = sub.add_parser("reevaluate", help="Re-evaluate a QA item or candidate (M2).")
    p_reeval.add_argument("--campaign-dir", type=Path, required=True)
    p_reeval.add_argument("--item", type=str, required=True)
    p_reeval.add_argument(
        "--build-frontend",
        action=argparse.BooleanOptionalAction,
        default=False,
    )
    p_reeval.add_argument(
        "--skip-browser",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    p_reeval.add_argument("--repo-root", type=Path, default=None)
    p_reeval.add_argument("--json", action="store_true", default=False)

    p_accept = sub.add_parser("accept", help="Promote verified candidate to QA branch (M2).")
    p_accept.add_argument("--campaign-dir", type=Path, required=True)
    p_accept.add_argument("--candidate", type=str, required=True)
    p_accept.add_argument(
        "--build-frontend",
        action=argparse.BooleanOptionalAction,
        default=False,
    )
    p_accept.add_argument(
        "--skip-browser",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    p_accept.add_argument("--repo-root", type=Path, default=None)
    p_accept.add_argument("--json", action="store_true", default=False)

    p_rollback = sub.add_parser("rollback", help="Roll back an accepted candidate (M2).")
    p_rollback.add_argument("--campaign-dir", type=Path, required=True)
    p_rollback.add_argument("--candidate", type=str, required=True)
    p_rollback.add_argument("--reason", type=str, default="operator_or_regression_rollback")
    p_rollback.add_argument("--repo-root", type=Path, default=None)
    p_rollback.add_argument("--json", action="store_true", default=False)

    return parser


def dispatch_command(args: argparse.Namespace) -> int:
    """Dispatch parsed CLI arguments for all QA campaign subcommands."""
    cmd = str(args.command)
    handlers = {
        "baseline": _handle_baseline,
        "report": _handle_report,
        "scan": _handle_scan,
        "repair": _handle_repair,
        "resume": _handle_resume,
        "reevaluate": _handle_reevaluate,
        "accept": _handle_accept,
        "rollback": _handle_rollback,
    }
    handler = handlers.get(cmd)
    if handler is None:
        raise ValueError(f"Unknown QA command: {cmd!r}")
    return handler(args)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for `python -m src.qa`."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return dispatch_command(args)
    except (
        NotImplementedError,
        IsolationBoundaryError,
        PolicyImmutabilityError,
        FileNotFoundError,
        ValueError,
        RuntimeError,
    ) as exc:
        want_json = bool(getattr(args, "json", False))
        if want_json:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                file=sys.stderr,
            )
        else:
            print(f"ERROR ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 1


__all__ = [
    "build_parser",
    "dispatch_command",
    "main",
]
