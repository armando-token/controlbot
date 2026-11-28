"""Tier 1 isolated happy-path E2E tests for Gates, Surface, Isolation & Campaign CLI."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from src.factory.db import FactoryStore
from src.factory.models import BacklogItem, CycleBudget
from src.factory.policy import IsolationGuard, PolicyGuard
from tests.e2e_qa.conftest import StrictBrowserPage
from tests.e2e_qa.fixtures import (
    build_cb09_csv_samples,
    build_cb10_three_deliverables_spec,
    build_cb_valve_104_catalog,
    build_grok_bot_reference_card,
    evaluate_csv_to_json_converter,
)
from tests.e2e_qa.helpers import (
    FORBIDDEN_PORTS,
    IsolatedQAEnv,
    QACliRunner,
    UxTimingResult,
    assert_no_secret_leak,
    assert_react_app_surface,
    measure_ttfp_and_completion,
)

pytestmark = pytest.mark.qa_tier1

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _git_head_sha(repo_dir: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _init_isolated_git_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "qa-e2e@example.local"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "QA E2E"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    readme = repo_dir / "README.md"
    readme.write_text("# Isolated QA Repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return _git_head_sha(repo_dir)


def _create_candidate_branch(
    repo_dir: Path,
    branch_name: str,
    *,
    filename: str = "fix.txt",
    content: str = "candidate fix\n",
) -> str:
    subprocess.run(
        ["git", "checkout", "-b", branch_name],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    (repo_dir / filename).write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", filename], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", f"candidate {branch_name}"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return _git_head_sha(repo_dir)


def _report_has_zero_open_p0_and_p1(report_text: str) -> bool:
    """Verify report states numeric 0 open P0 and P1 counts (inline, separate, or MD table)."""
    if re.search(
        r"(?i)(?:open[_\s]*)?p0\s*/\s*(?:open[_\s]*)?p1[*`:\s=\-]{1,10}\b0\s*[/,|*\s`]{1,5}\b0\b",
        report_text,
    ):
        return True

    lines = report_text.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not (stripped.startswith("|") and "|" in stripped[1:]):
            continue
        headers = [
            cell.strip().strip("*`").strip().lower() for cell in stripped.strip("|").split("|")
        ]
        p0_cols = [i for i, h in enumerate(headers) if re.fullmatch(r"(?:open[_\s]*)?p0", h)]
        p1_cols = [i for i, h in enumerate(headers) if re.fullmatch(r"(?:open[_\s]*)?p1", h)]
        if not (p0_cols and p1_cols):
            continue
        for data_line in lines[idx + 1 : idx + 4]:
            d_stripped = data_line.strip()
            if not d_stripped.startswith("|"):
                break
            cells = [cell.strip().strip("*`").strip() for cell in d_stripped.strip("|").split("|")]
            if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                continue
            p0_idx, p1_idx = p0_cols[0], p1_cols[0]
            if (
                p0_idx < len(cells)
                and p1_idx < len(cells)
                and cells[p0_idx] == "0"
                and cells[p1_idx] == "0"
            ):
                return True
            break

    has_p0_zero = bool(
        re.search(
            r"(?i)(?:open[_\s]*)?p0(?![\s*`]*/[\s*`]*(?:open[_\s]*)?p1)[^\n0-9]{0,25}\b0\b",
            report_text,
        )
    )
    has_p1_zero = bool(
        re.search(
            r"(?i)(?<!p0/)(?<!p0 / )(?:open[_\s]*)?p1[^\n0-9]{0,25}\b0\b",
            report_text,
        )
    )
    return has_p0_zero and has_p1_zero


@pytest.mark.qa_existing
async def test_existing_react_app_surface_and_legacy_route(
    qa_env: IsolatedQAEnv,
    qa_auth_env: IsolatedQAEnv,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Verify /app renders React assets while /studio-legacy stays separate, plus token auth."""
    surface_info = await assert_react_app_surface(qa_env.base_url, strict_browser_page)
    assert surface_info["title"] == "Grok Bot — ControlBot Studio"
    assert surface_info["data_theme"] == "light"
    assert surface_info["assets"]

    async with qa_env.async_client() as client:
        subpath_resp = await client.get("/app/threads/demo")
        assert subpath_resp.status_code == 200
        assert "<title>Grok Bot — ControlBot Studio</title>" in subpath_resp.text

        legacy_resp = await client.get("/studio-legacy")
        assert legacy_resp.status_code == 200
        assert "<title>ControlBot Studio</title>" in legacy_resp.text
        assert "controlbot.showPlantModule" in legacy_resp.text

    token = qa_auth_env.web_token
    assert token is not None
    async with qa_auth_env.async_client() as auth_client:
        auth_app = await auth_client.get(f"/app?token={token}")
        assert auth_app.status_code == 200
        assert "__GB_TOKEN" in auth_app.text
        assert "/assets/" in auth_app.text
        assert "window.fetch" in auth_app.text

    strict_browser_page.reset_errors()
    auth_surface = await assert_react_app_surface(
        qa_auth_env.base_url,
        strict_browser_page,
        web_token=token,
    )
    assert auth_surface["title"] == "Grok Bot — ControlBot Studio"

    progress_seen = False

    async def _nav_action() -> str:
        nonlocal progress_seen
        await asyncio.sleep(0.03)
        progress_seen = True
        await asyncio.sleep(0.03)
        return await strict_browser_page.page.title()

    async def _probe() -> bool:
        return progress_seen

    probed_title, probed_timing = await measure_ttfp_and_completion(
        _nav_action,
        actions_to_reach=1,
        ttfp_probe=_probe,
        cancel_available=True,
    )
    assert probed_title == "Grok Bot — ControlBot Studio"
    assert isinstance(probed_timing, UxTimingResult)
    assert probed_timing.actions_to_reach == 1
    assert probed_timing.cancel_available is True
    assert probed_timing.ttfp_ms is not None
    assert 0.0 <= probed_timing.ttfp_ms <= probed_timing.completion_ms

    unprobed_title, unprobed_timing = await measure_ttfp_and_completion(
        lambda: strict_browser_page.page.title(),
        actions_to_reach=2,
    )
    assert unprobed_title == "Grok Bot — ControlBot Studio"
    assert unprobed_timing.ttfp_ms == unprobed_timing.completion_ms
    assert unprobed_timing.completion_ms >= 0.0


@pytest.mark.qa_existing
def test_existing_health_system_info_and_request_id(qa_env: IsolatedQAEnv) -> None:
    """Verify /health, /api/system/info metadata, X-Request-Id correlation, and zero leaks."""
    with qa_env.client() as client:
        health_resp = client.get("/health")
        assert health_resp.status_code == 200
        assert health_resp.headers.get("X-Request-Id", "").startswith("req_")
        health_json = health_resp.json()
        assert health_json == {
            "status": "ok",
            "service": "grokbot-web",
            "db_path": str(qa_env.db_path),
        }

        info_resp = client.get("/api/system/info")
        assert info_resp.status_code == 200
        assert info_resp.headers.get("X-Request-Id", "").startswith("req_")
        info_json = info_resp.json()
        assert info_json["service"] == "controlbot"
        assert info_json["runtime_mode"] == "live_runtime"
        assert info_json["backend_mode"] == "emulated"
        assert info_json["llm_origin"] is None
        assert info_json["db_path"] == str(qa_env.db_path)
        assert info_json["facility"]["facility_id"] == "facility-a"

        assert_no_secret_leak(health_json, secrets=(qa_env.cap_secret,))
        assert_no_secret_leak(info_json, secrets=(qa_env.cap_secret,))


@pytest.mark.qa_existing
def test_existing_lab_isolation_ports_env_and_mock_agy(
    qa_lab_env: IsolatedQAEnv,
    qa_env_factory: Callable[..., IsolatedQAEnv],
) -> None:
    """Verify lab isolation excludes forbidden live ports, host HOME, and host agy."""
    qa_lab_env.assert_isolated_from_live()
    assert qa_lab_env.port not in FORBIDDEN_PORTS
    assert qa_lab_env.vnc_port not in FORBIDDEN_PORTS
    assert qa_lab_env.lab_stack is not None
    assert qa_lab_env.lab_stack.scada_port not in FORBIDDEN_PORTS
    assert qa_lab_env.lab_stack.maintenance_port not in FORBIDDEN_PORTS
    assert qa_lab_env.lab_stack.effect_sim_port not in FORBIDDEN_PORTS
    assert Path(qa_lab_env.env["HOME"]).resolve() != Path.home().resolve()
    assert shutil.which("agy", path=qa_lab_env.env["PATH"]) is None

    with qa_lab_env.client() as client:
        agy_resp = client.get("/api/agy/models")
        assert agy_resp.status_code == 200
        assert agy_resp.json()["available"] is False

    mock_env = qa_env_factory(
        mock_agy_script="#!/bin/sh\necho '[]'\n",
        name="mock_agy",
    )
    mock_env.assert_isolated_from_live()
    resolved_mock = shutil.which("agy", path=mock_env.env["PATH"])
    assert resolved_mock is not None
    assert Path(resolved_mock).resolve().is_relative_to(mock_env.fake_home.resolve())

    default_runner = QACliRunner(fake_home=None)
    try:
        sanitized_env = default_runner.build_env()
        assert shutil.which("agy", path=sanitized_env["PATH"]) is None
        if shutil.which("uv") is not None:
            assert shutil.which("uv", path=sanitized_env["PATH"]) is not None
    finally:
        default_runner.cleanup()


@pytest.mark.qa_existing
def test_existing_doctor_cli_json_reports_n1_n2_ready_and_n3_honest() -> None:
    """Verify `python -m src.doctor --json` reports N1/N2 ready and honest N3 status."""
    proc = subprocess.run(
        [sys.executable, "-m", "src.doctor", "--json"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    assert proc.returncode == 0, f"src.doctor failed: {proc.stderr}"
    report = json.loads(proc.stdout)
    assert report["n1_ready"] is True
    assert report["n2_ready"] is True
    assert report["n3_status"] in {"PENDING_N3_LINUX_ENV", "READY"}
    check_names = {item["name"] for item in report["checks"]}
    assert {
        "python_version",
        "sqlite_wal",
        "git",
        "tooling",
        "playwright_env",
        "n3_linux_env",
    }.issubset(check_names)


@pytest.mark.qa_existing
def test_existing_make_doctor_and_check_targets_preserved() -> None:
    """Verify existing `make doctor` runs cleanly and `make -n check` preserves all gates."""
    doc_proc = subprocess.run(
        ["make", "doctor"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    assert doc_proc.returncode == 0, f"make doctor failed: {doc_proc.stderr}\n{doc_proc.stdout}"

    check_dry = subprocess.run(
        ["make", "-n", "check"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    assert check_dry.returncode == 0, f"make -n check failed: {check_dry.stderr}"
    for required_target in ("doctor", "lint", "typecheck", "test"):
        assert required_target in check_dry.stdout


@pytest.mark.qa_existing
def test_existing_factory_store_and_isolation_guard_isolated_db_smoke(tmp_path: Path) -> None:
    """Verify FactoryStore WAL DB, IsolationGuard, backlog, budget, and lease lifecycle."""
    repo_dir = tmp_path / "iso_repo"
    _init_isolated_git_repo(repo_dir)
    db_path = tmp_path / "factory" / "factory_test.sqlite3"
    live_var = _REPO_ROOT / "var" / "controlbot.sqlite3"

    IsolationGuard.validate_paths(
        db_path,
        repo_dir,
        forbidden_db_paths=(live_var,),
    )
    store = FactoryStore(db_path, forbidden_db_paths=(live_var,))
    store.init_db()

    mode = stat.S_IMODE(db_path.stat().st_mode)
    assert mode == 0o600

    item = store.add_backlog_item(
        BacklogItem(
            item_id="qa-smoke-001",
            title="Smoke backlog item",
            priority=1,
            hypothesis="Verify isolated FactoryStore persistence",
            target_metric="smoke_pass",
            baseline_repro_cmd="pytest tests/unit -q",
        )
    )
    fetched = store.get_backlog_item(item.item_id)
    assert fetched is not None
    assert fetched.title == "Smoke backlog item"

    budget = store.ensure_budget(CycleBudget(budget_id="qa-budget", max_cycles=2, max_attempts=2))
    assert budget.max_cycles == 2

    lease = store.acquire_lease(item.item_id, "qa-worker-1", ttl_s=30.0)
    assert lease.item_id == item.item_id
    assert lease.generation >= 1
    store.release_lease(lease.lease_id, lease.generation)
    assert store.get_active_lease(item.item_id) is None


@pytest.mark.qa_existing
def test_existing_policy_guard_allows_non_protected_qa_and_web_paths() -> None:
    """Verify PolicyGuard permits repair patches touching non-protected web/qa source paths."""
    guard = PolicyGuard()
    guard.check_candidate_paths(["src/web/app.py", "src/qa/baseline.py"])


@pytest.mark.qa_existing
def test_existing_fixtures_dynamic_valve_and_grok_bot_card_smoke(tmp_path: Path) -> None:
    """Verify dynamic CB-VALVE-104, CB-09 evaluator, CB-10 spec, and Grok Bot card fixtures."""
    catalog_a = build_cb_valve_104_catalog(seed=101)
    catalog_b = build_cb_valve_104_catalog(seed=202)
    assert catalog_a.active_record.record_id != catalog_a.prior_record.record_id
    assert catalog_a.active_record.status == "current"
    assert catalog_a.prior_record.status == "superseded"
    assert catalog_a.active_record.price != catalog_a.prior_record.price
    assert catalog_a.active_record.price != catalog_b.active_record.price
    assert len(catalog_a.ambiguous_matches) == 2
    assert catalog_a.nonexistent_sku not in {r.sku for r in catalog_a.records}

    new_target = (catalog_a.active_record.price + Decimal("11.25")).quantize(Decimal("0.01"))
    updated = catalog_a.apply_price_update(new_target)
    assert updated.sku == catalog_a.sku
    assert updated.active_record.price == new_target
    assert updated.prior_record.price == catalog_a.active_record.price
    assert updated.prior_record.status == "superseded"
    assert catalog_a.active_record.source_url in catalog_a.render_html_pages()

    normalized_update = catalog_a.apply_price_update("142.5")
    assert normalized_update.active_record.price == Decimal("142.50")
    assert str(normalized_update.active_record.price) == "142.50"
    upd_html = normalized_update.render_html_pages()[normalized_update.active_record.source_url]
    assert str(normalized_update.active_record.price) in upd_html
    assert "Status: current" in upd_html
    assert "Status: superseded" not in upd_html

    samples = build_cb09_csv_samples()
    assert len(samples) >= 4
    converter_script = tmp_path / "csv_conv.py"
    converter_script.write_text(
        "import csv, json, sys\n"
        "src, dst = sys.argv[1], sys.argv[2]\n"
        "with open(src, encoding='utf-8', newline='') as fh:\n"
        "    raw_lines = fh.read()\n"
        "if raw_lines.count('\"') % 2 != 0:\n"
        "    sys.exit(2)\n"
        "with open(src, encoding='utf-8', newline='') as fh:\n"
        "    reader = csv.reader(fh)\n"
        "    rows = [r for r in reader if any(cell.strip() for cell in r)]\n"
        "header = rows[0]\n"
        "out = []\n"
        "for r in rows[1:]:\n"
        "    if len(r) != len(header):\n"
        "        sys.exit(3)\n"
        "    out.append(dict(zip(header, r)))\n"
        "with open(dst, 'w', encoding='utf-8') as out_fh:\n"
        "    json.dump(out, out_fh, ensure_ascii=False)\n",
        encoding="utf-8",
    )
    eval_report = evaluate_csv_to_json_converter(
        [sys.executable, str(converter_script)],
        work_dir=tmp_path / "cb09_eval",
    )
    assert eval_report.passed is True, f"CB-09 eval failed: {eval_report}"

    cb10 = build_cb10_three_deliverables_spec()
    assert len(cb10.deliverables) == 3
    assert {d.assigned_agent for d in cb10.deliverables} == {"agent_alpha", "agent_beta"}

    main_card = build_grok_bot_reference_card(bot_name="main", case_id="CB-02")
    test_card = build_grok_bot_reference_card(bot_name="test", case_id="CB-02", available=False)
    assert main_card.bot_used == "main"
    assert main_card.status == "observed"
    assert test_card.bot_used == "test"
    assert test_card.status == "REF_UNAVAILABLE"


@pytest.mark.qa_megaplan
def test_megaplan_qa0_cli_baseline_emits_baseline_json_and_md(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #1, #32: `python -m src.qa baseline` emits valid baseline.json and BASELINE.md."""
    out_dir = tmp_path / "qa_baseline_out"
    res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(out_dir),
            "--lane",
            "local_deterministic",
        ]
    )
    assert res.returncode == 0, (
        f"baseline CLI failed ({res.returncode}): {res.stderr}\n{res.stdout}"
    )
    json_path = out_dir / "baseline.json"
    md_path = out_dir / "BASELINE.md"
    assert json_path.is_file(), f"Missing {json_path}"
    assert md_path.is_file(), f"Missing {md_path}"

    data = json.loads(json_path.read_text(encoding="utf-8"))
    for required_key in (
        "campaign_id",
        "repo_sha",
        "deployed_sha",
        "git_dirty_files",
        "surface_verified",
        "served_surface",
        "asset_hashes",
        "backend_mode",
        "runtime_mode",
        "doctor_status",
        "n3_status",
        "boot_errors",
        "functional_errors",
        "active_log_summary",
    ):
        assert required_key in data, f"Missing key {required_key!r} in baseline.json"

    assert data["surface_verified"] is True
    assert data["served_surface"] == "react"
    assert data["boot_errors"] == []
    assert data["functional_errors"] == []
    assert_no_secret_leak(data, secrets=(qa_env.cap_secret,))


@pytest.mark.qa_megaplan
async def test_megaplan_qa1_make_qa_baseline_target_and_react_surface(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    strict_browser_page: StrictBrowserPage,
) -> None:
    """Features #2, #3, #33: `make qa-baseline` target exists & verifies React /app surface."""
    dry = qa_cli_runner.run_command(["make", "-n", "qa-baseline"])
    assert dry.returncode == 0, f"`make -n qa-baseline` failed: {dry.stderr}"
    assert "src.qa" in dry.stdout or "baseline" in dry.stdout

    info = await assert_react_app_surface(qa_env.base_url, strict_browser_page)
    assert info["title"] == "Grok Bot — ControlBot Studio"


@pytest.mark.qa_megaplan
def test_megaplan_run_record_metadata_and_lane_tagging(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #4, #6, #9: `scan` persists RunRecord metadata with explicit lane & UI tags."""
    camp_dir = tmp_path / "campaign_scan"
    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--lane",
            "local_deterministic",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"

    scan_res = qa_cli_runner.run(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-00",
        ]
    )
    assert scan_res.returncode == 0, f"scan failed: {scan_res.stderr}\n{scan_res.stdout}"

    record: dict[str, Any] | None = None
    for db_file in sorted(camp_dir.glob("**/*.sqlite3")):
        with sqlite3.connect(db_file) as conn:
            conn.row_factory = sqlite3.Row
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "qa_run_records" in tables:
                rows = conn.execute("SELECT * FROM qa_run_records").fetchall()
                if rows:
                    row_dict = dict(rows[0])
                    payload_raw = row_dict.get("payload_json")
                    if isinstance(payload_raw, str) and payload_raw.strip():
                        parsed_payload = json.loads(payload_raw)
                        if isinstance(parsed_payload, dict):
                            row_dict = {**row_dict, **parsed_payload}
                    for json_col in (
                        "simulated_services",
                        "assertions",
                        "real_services",
                        "request_ids",
                        "artifact_paths",
                    ):
                        col_val = row_dict.get(json_col)
                        if isinstance(col_val, str):
                            row_dict[json_col] = json.loads(col_val)
                    record = row_dict
                    break

    if record is None:
        run_files = sorted(
            [*camp_dir.glob("**/run_*.json"), *camp_dir.glob("**/runs.jsonl")]
        )
        assert run_files, (
            f"No qa_run_records SQLite rows or run_*.json/runs.jsonl files under {camp_dir}"
        )
        raw_text = run_files[0].read_text(encoding="utf-8")
        record = (
            json.loads(raw_text.splitlines()[0])
            if run_files[0].suffix == ".jsonl"
            else json.loads(raw_text)
        )

    assert record is not None
    for field_name in (
        "campaign_id",
        "case_id",
        "run_id",
        "base_sha",
        "build_hash",
        "lane",
        "ui_variant",
        "backend_mode",
        "runtime_mode",
        "emulated",
        "simulated_services",
        "assertions",
    ):
        assert field_name in record, f"Missing RunRecord field {field_name!r}"
    assert record["lane"] == "local_deterministic"


@pytest.mark.qa_megaplan
def test_megaplan_eval_lanes_isolated_and_distinct(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #6, #9: Each evaluation lane is accepted & tagged distinctly without conflation."""
    for lane in ("local_deterministic", "external_reference"):
        out_dir = tmp_path / f"lane_{lane}"
        res = qa_cli_runner.run(
            [
                "baseline",
                "--target-url",
                qa_env.base_url,
                "--output-dir",
                str(out_dir),
                "--lane",
                lane,
            ]
        )
        assert res.returncode == 0, f"Lane {lane} baseline failed: {res.stderr}"
        report = json.loads((out_dir / "baseline.json").read_text(encoding="utf-8"))
        assert report["lane"] == lane


@pytest.mark.qa_megaplan
def test_megaplan_lab_isolation_never_touches_forbidden_ports_or_live_db(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #10: Isolated QA baseline never mutates live DBs or binds forbidden ports."""
    live_dbs = sorted((_REPO_ROOT / "var").glob("controlbot*.sqlite3*"))
    before_stats = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in live_dbs if p.is_file()}

    out_dir = tmp_path / "iso_check"
    res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(out_dir),
        ]
    )
    assert res.returncode == 0, f"baseline failed: {res.stderr}\n{res.stdout}"
    report = json.loads((out_dir / "baseline.json").read_text(encoding="utf-8"))
    target_url = str(report.get("target_url") or "")
    for forbidden in FORBIDDEN_PORTS:
        assert f":{forbidden}" not in target_url

    after_stats = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in live_dbs if p.is_file()}
    assert after_stats == before_stats


@pytest.mark.qa_megaplan
def test_megaplan_campaign_cli_lifecycle_scan_repair_resume_report(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #39: Campaign CLI supports baseline -> scan -> repair -> resume -> report."""
    camp_dir = tmp_path / "campaign_lifecycle"
    for subcmd_args in (
        ["baseline", "--target-url", qa_env.base_url, "--output-dir", str(camp_dir)],
        ["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00"],
        ["repair", "--campaign-dir", str(camp_dir), "--max-parallel", "2", "--max-attempts", "2"],
        ["resume", "--campaign-dir", str(camp_dir)],
        ["report", "--campaign-dir", str(camp_dir)],
    ):
        res = qa_cli_runner.run(subcmd_args)
        assert res.returncode == 0, (
            f"Subcommand {subcmd_args[0]} failed ({res.returncode}): {res.stderr}\n{res.stdout}"
        )

    campaign_json = camp_dir / "campaign.json"
    assert campaign_json.is_file()
    state = json.loads(campaign_json.read_text(encoding="utf-8"))
    for key in (
        "campaign_id",
        "base_sha",
        "last_accepted_sha",
        "catalog_hash",
        "criteria_hash",
        "limits",
        "attempts",
        "artifacts",
    ):
        assert key in state, f"Missing CampaignState key {key!r}"

    assert (camp_dir / "HANDOFF.md").is_file()
    assert (camp_dir / "daily_report.md").is_file()


@pytest.mark.qa_megaplan
def test_megaplan_qa6_maintenance_commands_reevaluate_accept_rollback(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #38, #39: Maintenance CLI supports reevaluate, accept, and rollback."""
    camp_dir = tmp_path / "campaign_maint"
    maint_repo = tmp_path / "maint_repo"
    base_sha = _init_isolated_git_repo(maint_repo)
    subprocess.run(
        ["git", "branch", "qa/autopilot"],
        cwd=str(maint_repo),
        check=True,
        capture_output=True,
    )
    cand_id = "cand-qa6-001"
    cand_branch = f"qa/{cand_id}"
    candidate_sha = _create_candidate_branch(
        maint_repo,
        cand_branch,
        filename="qa6_fix.txt",
        content="qa6 candidate patch\n",
    )
    assert candidate_sha != base_sha
    subprocess.run(
        ["git", "checkout", "qa/autopilot"],
        cwd=str(maint_repo),
        check=True,
        capture_output=True,
    )

    base_res = qa_cli_runner.run(
        [
            "baseline",
            "--target-url",
            qa_env.base_url,
            "--output-dir",
            str(camp_dir),
            "--no-build-frontend",
            "--skip-browser",
        ]
    )
    assert base_res.returncode == 0, f"baseline failed: {base_res.stderr}\n{base_res.stdout}"

    camp_json_path = camp_dir / "campaign.json"
    camp_state = json.loads(camp_json_path.read_text(encoding="utf-8"))
    camp_state["base_sha"] = base_sha
    camp_state["last_accepted_sha"] = base_sha
    camp_state["qa_branch"] = "qa/autopilot"
    camp_json_path.write_text(json.dumps(camp_state, indent=2), encoding="utf-8")

    fast_rerun = f"{sys.executable} -c 'assert True'"
    failure_item = {
        "item_id": "item-qa6-001",
        "dedup_key": "CB-00:cli:qa6_maint",
        "case_id": "CB-00",
        "subsystem": "cli",
        "normalized_signature": "qa6_maint",
        "severity": "P2",
        "state": "candidate_verified",
        "summary": "Synthetic QA-6 maintenance verification item",
        "first_seen_sha": base_sha,
        "last_seen_sha": base_sha,
        "environment_lane": "local_deterministic",
        "repro_command": fast_rerun,
    }
    (camp_dir / "failures.jsonl").write_text(json.dumps(failure_item) + "\n", encoding="utf-8")

    candidates_dir = camp_dir / "candidates"
    candidates_dir.mkdir(parents=True, exist_ok=True)
    cand_manifest = {
        "candidate_id": cand_id,
        "item_id": "item-qa6-001",
        "campaign_id": camp_state["campaign_id"],
        "base_sha": base_sha,
        "candidate_sha": candidate_sha,
        "branch_name": cand_branch,
        "rerun_command": fast_rerun,
        "baseline_passed": False,
        "candidate_passed": True,
        "audit_passed": True,
        "author_model": "hydrogen",
        "auditor_model": "pro",
        "status": "candidate_verified",
    }
    cand_path = candidates_dir / f"{cand_id}.json"
    cand_path.write_text(json.dumps(cand_manifest, indent=2), encoding="utf-8")

    reeval = qa_cli_runner.run(
        [
            "reevaluate",
            "--campaign-dir",
            str(camp_dir),
            "--item",
            "item-qa6-001",
            "--repo-root",
            str(maint_repo),
        ],
        cwd=maint_repo,
    )
    assert "notimplementederror" not in (reeval.stdout + reeval.stderr).lower()
    assert reeval.returncode == 0, f"reevaluate failed: {reeval.stderr}\n{reeval.stdout}"

    accept = qa_cli_runner.run(
        [
            "accept",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            cand_id,
            "--repo-root",
            str(maint_repo),
        ],
        cwd=maint_repo,
    )
    assert "notimplementederror" not in (accept.stdout + accept.stderr).lower()
    assert accept.returncode == 0, f"accept failed: {accept.stderr}\n{accept.stdout}"

    accepted_manifest = json.loads(cand_path.read_text(encoding="utf-8"))
    accepted_state = json.loads(camp_json_path.read_text(encoding="utf-8"))
    assert accepted_manifest["status"] == "accepted_qa"
    assert accepted_state["last_accepted_sha"] == candidate_sha

    rb = qa_cli_runner.run(
        [
            "rollback",
            "--campaign-dir",
            str(camp_dir),
            "--candidate",
            cand_id,
            "--repo-root",
            str(maint_repo),
        ],
        cwd=maint_repo,
    )
    assert "notimplementederror" not in (rb.stdout + rb.stderr).lower()
    assert rb.returncode == 0, f"rollback failed: {rb.stderr}\n{rb.stdout}"

    rb_manifest = json.loads(cand_path.read_text(encoding="utf-8"))
    rb_state = json.loads(camp_json_path.read_text(encoding="utf-8"))
    assert rb_manifest["status"] == "rolled_back"
    assert rb_state["last_accepted_sha"] == base_sha
    assert _git_head_sha(maint_repo) == base_sha


@pytest.mark.qa_megaplan
def test_megaplan_qa6_dod_two_same_sha_passes_and_variance_stats(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Features #38, #40: DoD report tracks 0 open P0/P1, 2x same-SHA passes & >=3 run variance."""
    camp_dir = tmp_path / "campaign_dod"
    assert (
        qa_cli_runner.run(
            ["baseline", "--target-url", qa_env.base_url, "--output-dir", str(camp_dir)]
        ).returncode
        == 0
    )
    for _ in range(3):
        scan = qa_cli_runner.run(["scan", "--campaign-dir", str(camp_dir), "--cases", "CB-00"])
        assert scan.returncode == 0, f"scan failed: {scan.stderr}\n{scan.stdout}"

    rep = qa_cli_runner.run(["report", "--campaign-dir", str(camp_dir)])
    assert rep.returncode == 0, f"report failed: {rep.stderr}\n{rep.stdout}"
    daily_md = (camp_dir / "daily_report.md").read_text(encoding="utf-8")
    handoff_md = (camp_dir / "HANDOFF.md").read_text(encoding="utf-8")
    combined = f"{daily_md}\n{handoff_md}"

    assert _report_has_zero_open_p0_and_p1(combined), (
        f"Expected numeric 0 open P0 and P1 counts in report:\n{combined}"
    )
    same_sha_match = re.search(
        r"(?i)(?:same[_ -]?sha[^\n0-9]{0,30}\b(\d+)\b|\b(\d+)\s*x\s*same[_ -]?sha)",
        combined,
    )
    assert same_sha_match is not None, f"Missing numeric same_sha pass count:\n{combined}"
    same_sha_count = int(same_sha_match.group(1) or same_sha_match.group(2))
    assert same_sha_count >= 2, f"Expected >=2 same_sha passes, got {same_sha_count}"

    runs_match = re.search(
        r"(?i)(?:runs?|repetitions?|samples?)[^\n0-9]{0,25}\b(\d+)\b",
        combined,
    )
    assert runs_match is not None and int(runs_match.group(1)) >= 3, (
        f"Expected >=3 run count in DoD report:\n{combined}"
    )
    assert re.search(r"(?i)median[^\n0-9]{0,25}\d+", combined), (
        f"Expected numeric median metric in DoD report:\n{combined}"
    )
    assert re.search(r"(?i)(?:variance|stddev|p95|tail|iqr)[^\n0-9]{0,25}\d+", combined), (
        f"Expected numeric variance/tail metric in DoD report:\n{combined}"
    )


@pytest.mark.qa_megaplan
def test_megaplan_governance_max_two_repairers_and_distinct_auditor(
    qa_env: IsolatedQAEnv,
    qa_cli_runner: QACliRunner,
    tmp_path: Path,
) -> None:
    """Feature #41: Campaign enforces max_parallel_repairers <= 2 and cross-model auditor."""
    camp_dir = tmp_path / "campaign_gov"
    assert (
        qa_cli_runner.run(
            ["baseline", "--target-url", qa_env.base_url, "--output-dir", str(camp_dir)]
        ).returncode
        == 0
    )
    rep = qa_cli_runner.run(["repair", "--campaign-dir", str(camp_dir), "--max-parallel", "2"])
    assert rep.returncode == 0, f"repair failed: {rep.stderr}\n{rep.stdout}"
    state = json.loads((camp_dir / "campaign.json").read_text(encoding="utf-8"))
    assert int(state["max_parallel_repairers"]) <= 2

    cand_files = sorted((camp_dir / "candidates").glob("*.json"))
    if cand_files:
        for cf in cand_files:
            cand = json.loads(cf.read_text(encoding="utf-8"))
            assert cand.get("auditor_model"), f"Missing auditor_model in {cf}"
            assert bool(cand.get("author_model")), f"Missing author_model in {cf}"
            assert cand.get("auditor_model") != cand.get("author_model"), (
                f"Self-audit violation in {cf}: {cand.get('auditor_model')!r}"
            )
    else:
        limits = state.get("limits", {})
        gov_auditor = state.get("auditor_model") or limits.get("auditor_model")
        gov_author = state.get("author_model") or limits.get("author_model")
        cross_audit = state.get("cross_model_audit") or limits.get("cross_model_audit")
        assert gov_auditor or cross_audit, (
            f"Missing cross-model auditor governance metadata in campaign.json: {state!r}"
        )
        if gov_auditor and gov_author:
            assert gov_auditor != gov_author
