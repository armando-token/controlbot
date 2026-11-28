"""Unit tests for M4-3 QA fixtures, scenarios registry, and CLI scan wiring."""

from __future__ import annotations

import asyncio
import http.server
import json
import subprocess
import sys
import threading
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
import src.qa.scenarios as scenarios_mod
from src.qa import isolation
from src.qa.cli import main
from src.qa.discovery import DiscoveryProbeResult
from src.qa.fixtures import (
    build_cb09_csv_samples,
    build_cb10_three_deliverables_spec,
    build_cb_valve_104_catalog,
    evaluate_cb10_project,
    evaluate_csv_to_json_converter,
    evaluate_valve_104_reply,
    load_or_build_cb_valve_104_catalog,
    serve_valve_catalog,
)
from src.qa.fixtures.cb_valve_104 import _record_from_dict
from src.qa.isolation import IsolationBoundaryError, alloc_ephemeral_port
from src.qa.models import (
    CampaignState,
    ControlInventoryItem,
    CoverageReport,
    LaneName,
    ReferenceBehaviorCard,
    RunRecord,
)
from src.qa.queue import list_qa_items, open_campaign_store
from src.qa.scenarios import IMPLEMENTED_CASES, _common, run_scenario
from src.qa.scenarios._common import (
    ScenarioContext,
    TargetCapabilities,
    cleanup_project_subpath_http,
    repo_root_fallback,
)
from src.qa.scenarios.cb_02 import _check_reference_card_alignment
from src.qa.scenarios.cb_09 import _REFERENCE_CSV_TO_JSON


def _init_git_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=str(repo_dir), check=True)
    subprocess.run(
        ["git", "config", "user.email", "qa@example.local"],
        cwd=str(repo_dir),
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "QA Bot"], cwd=str(repo_dir), check=True)
    (repo_dir / "README.md").write_text("# QA\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=str(repo_dir), check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(repo_dir), capture_output=True, text=True, check=True
    ).stdout.strip()


def _make_state(
    camp_dir: Path,
    base_sha: str,
    *,
    lane: LaneName = "local_deterministic",
    target_url: str | None = None,
) -> CampaignState:
    camp_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState(
        campaign_id=f"qa-u-{uuid.uuid4().hex[:6]}",
        base_sha=base_sha,
        lane=lane,
        target_url=target_url,
        output_dir=str(camp_dir),
    )
    (camp_dir / "campaign.json").write_text(state.model_dump_json(indent=2), encoding="utf-8")
    return state


@pytest.mark.n1
def test_cb_valve_104_dynamic_catalog_serving_update_and_evaluator(tmp_path: Path) -> None:
    default_fx = build_cb_valve_104_catalog()
    assert default_fx.active_record.price == Decimal("129.50")
    assert default_fx.prior_record.price == Decimal("154.00")
    assert default_fx.active_record.status == "current"
    assert default_fx.prior_record.status == "superseded"
    assert len(default_fx.ambiguous_matches) == 2

    seeded_fx = build_cb_valve_104_catalog(seed=42)
    assert seeded_fx.active_record.price != seeded_fx.prior_record.price

    # Minimal JSON schema compatibility
    camp_min = tmp_path / "camp_min"
    (camp_min / "fixtures").mkdir(parents=True)
    (camp_min / "fixtures" / "cb_valve_104.json").write_text(
        json.dumps({"fixture_version": "cb-valve-104-v9999", "active_price": "173.25"}),
        encoding="utf-8",
    )
    loaded_min = load_or_build_cb_valve_104_catalog(camp_min)
    assert loaded_min.fixture_version == "cb-valve-104-v9999"
    assert loaded_min.active_record.price == Decimal("173.25")

    # Full JSON schema compatibility
    camp_full = tmp_path / "camp_full"
    (camp_full / "fixtures").mkdir(parents=True)
    (camp_full / "fixtures" / "cb_valve_104.json").write_text(
        json.dumps(seeded_fx.to_dict()),
        encoding="utf-8",
    )
    loaded_full = load_or_build_cb_valve_104_catalog(camp_full)
    assert loaded_full.fixture_version == seeded_fx.fixture_version
    assert loaded_full.active_record.price == seeded_fx.active_record.price

    with (
        serve_valve_catalog(default_fx) as (origin, state),
        httpx.Client(base_url=origin, timeout=5.0) as client,
    ):
            idx = client.get("/index.json").json()
            assert len(idx) >= 4
            html_cur = client.get(default_fx.active_record.source_url).text
            assert "data-status='current'" in html_cur
            assert f"data-price='{default_fx.active_record.price}'" in html_cur

            updated = default_fx.apply_price_update("188.40", effective_date="2026-11-30")
            state.update(updated)
            html_upd = client.get(updated.active_record.source_url).text
            assert "data-price='188.40'" in html_upd

    ok_good, _, _ = evaluate_valve_104_reply(
        f"CB-VALVE-104: USD 129.50 at {default_fx.active_record.source_url}",
        default_fx,
        mode="current",
    )
    assert ok_good is True

    ok_stale, a_stale, _ = evaluate_valve_104_reply(
        f"CB-VALVE-104: USD 154.00 at {default_fx.prior_record.source_url}",
        default_fx,
        mode="current",
    )
    assert ok_stale is False
    assert a_stale["rejects_prior_price"] is False
    assert a_stale["active_price_exact"] is False

    ok_bad_url, a_url, _ = evaluate_valve_104_reply(
        "CB-VALVE-104: USD 129.50 at /catalog/valves/cb-valve-104-a",
        default_fx,
        mode="current",
    )
    assert ok_bad_url is False
    assert a_url["active_source_url_exact"] is False

    ok_miss, _, _ = evaluate_valve_104_reply(
        "No current catalog price found for CB-VALVE-999-MISSING.",
        default_fx,
        mode="missing",
    )
    assert ok_miss is True

    ok_ambig, _, _ = evaluate_valve_104_reply(
        "Multiple variants found, please clarify: CB-VALVE-104-A or CB-VALVE-104-B.",
        default_fx,
        mode="ambiguous",
    )
    assert ok_ambig is True


@pytest.mark.n1
def test_cb09_csv_evaluator_valid_naive_and_missing(tmp_path: Path) -> None:
    samples = build_cb09_csv_samples()
    assert [s.name for s in samples] == [
        "empty_lines",
        "quoted_fields",
        "invalid_malformed",
        "utf8_and_whitespace",
    ]

    valid_py = tmp_path / "good_csv.py"
    valid_py.write_text(
        "import csv, io, json, sys\n"
        "from pathlib import Path\n"
        "raw = Path(sys.argv[1]).read_text(encoding='utf-8')\n"
        "if raw.count('\"') % 2 != 0:\n"
        "    sys.exit(1)\n"
        "rows = [r for r in csv.reader(io.StringIO(raw, newline=''), strict=True) "
        "if any(c.strip() for c in r)]\n"
        "hdr = rows[0]\n"
        "out = []\n"
        "for r in rows[1:]:\n"
        "    if len(r) != len(hdr):\n"
        "        sys.exit(1)\n"
        "    out.append(dict(zip(hdr, r)))\n"
        "Path(sys.argv[2]).write_text(json.dumps(out, ensure_ascii=False), encoding='utf-8')\n",
        encoding="utf-8",
    )
    good_rep = evaluate_csv_to_json_converter(
        [sys.executable, str(valid_py)],
        work_dir=tmp_path / "good_work",
    )
    assert good_rep.passed is True

    naive_py = tmp_path / "naive_csv.py"
    naive_py.write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        "lines = [l for l in Path(sys.argv[1]).read_text(encoding='utf-8').splitlines() "
        "if l.strip()]\n"
        "hdr = lines[0].split(',')\n"
        "rows = [dict(zip(hdr, l.split(','))) for l in lines[1:]]\n"
        "Path(sys.argv[2]).write_text(json.dumps(rows), encoding='utf-8')\n",
        encoding="utf-8",
    )
    bad_rep = evaluate_csv_to_json_converter(
        [sys.executable, str(naive_py)],
        work_dir=tmp_path / "bad_work",
    )
    assert bad_rep.passed is False
    by_name = {r.name: r for r in bad_rep.sample_results}
    assert by_name["quoted_fields"].passed is False
    assert by_name["invalid_malformed"].passed is False

    missing_rep = evaluate_csv_to_json_converter(
        [sys.executable, str(tmp_path / "does_not_exist.py")],
        work_dir=tmp_path / "miss_work",
    )
    assert missing_rep.passed is False


@pytest.mark.n1
def test_cb10_multiagent_spec_and_evaluator_positive_and_negative(tmp_path: Path) -> None:
    spec = build_cb10_three_deliverables_spec()
    assert len(spec.deliverables) == 3
    assert spec.agents == ("agent_alpha", "agent_beta")

    proj = tmp_path / spec.project_name
    (proj / "src_pkg").mkdir(parents=True)
    (proj / "tests").mkdir(parents=True)
    (proj / "src_pkg" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "src_pkg" / "calc.py").write_text(
        "def compute_summary(vals):\n    return {'sum': sum(vals)}\n",
        encoding="utf-8",
    )
    (proj / "src_pkg" / "cli.py").write_text(
        "from src_pkg.calc import compute_summary\n"
        "def main():\n    return compute_summary([1, 2])\n",
        encoding="utf-8",
    )
    (proj / "tests" / "test_calc_cli.py").write_text(
        "from src_pkg.cli import main\n"
        "def test_summary_cli_roundtrip():\n    assert main()['sum'] == 3\n",
        encoding="utf-8",
    )
    ok, assertions, _ = evaluate_cb10_project(proj, spec)
    assert ok is True
    assert all(assertions.values())

    # Break syntax in D1 -> evaluator must reject
    (proj / "src_pkg" / "calc.py").write_text(
        "def compute_summary(vals):\n    return (\n", encoding="utf-8"
    )
    bad_ok, bad_assertions, _ = evaluate_cb10_project(proj, spec)
    assert bad_ok is False
    assert bad_assertions["build_passed"] is False


@pytest.mark.n1
def test_registry_m5_deferral_target_url_none_and_live_guard(tmp_path: Path) -> None:
    assert {f"CB-{i:02d}" for i in range(14)} == IMPLEMENTED_CASES
    assert not hasattr(scenarios_mod, "DEFERRED_M5_CASES")

    camp_dir = tmp_path / "camp_reg"
    state = _make_state(camp_dir, "sha_reg_1")

    for m5_target_case in ("CB-11", "CB-12"):
        res = run_scenario(
            case_id=m5_target_case,
            campaign_dir=camp_dir,
            state=state,
            target_url=None,
        )
        assert res is not None
        rec_m5, findings_m5 = res
        assert rec_m5.passed is False
        assert rec_m5.assertions.get("target_url_configured") is False
        assert findings_m5

    res_cb13 = run_scenario(
        case_id="CB-13",
        campaign_dir=camp_dir,
        state=state,
        target_url=None,
    )
    assert res_cb13 is not None
    rec_13, _ = res_cb13
    assert rec_13.case_id == "CB-13"
    assert rec_13.assertions.get("scenario_runner_available") is True

    (camp_dir / "fixtures").mkdir(parents=True)
    (camp_dir / "fixtures" / "cb_valve_104.json").write_text(
        json.dumps({"fixture_version": "cb-valve-104-v7777", "active_price": "129.50"}),
        encoding="utf-8",
    )
    res_cb02 = run_scenario(
        case_id="CB-02",
        campaign_dir=camp_dir,
        state=state,
        target_url=None,
    )
    assert res_cb02 is not None
    rec, findings = res_cb02
    assert rec.passed is False
    assert rec.fixture_version == "cb-valve-104-v7777"
    assert rec.blocked_reason and "CB-02" in rec.blocked_reason
    assert findings

    with pytest.raises(IsolationBoundaryError):
        run_scenario(
            case_id="CB-00",
            campaign_dir=camp_dir,
            state=state,
            target_url="http://127.0.0.1:8000",
        )


@pytest.mark.n1
def test_cli_scan_wires_discovery_defects_reference_cards_and_ux_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_dir = tmp_path / "repo"
    base_sha = _init_git_repo(repo_dir)
    camp_dir = tmp_path / "camp_cli"
    state = _make_state(camp_dir, base_sha, lane="external_reference")

    fake_cov = CoverageReport(
        campaign_id=state.campaign_id,
        repo_sha=base_sha,
        total_controls=1,
        covered_count=1,
        blocked_count=0,
        pending_count=0,
        out_of_scope_count=0,
        by_module={"chat": {"covered": 1}},
        items=[
            ControlInventoryItem(
                control_id="ctrl-1",
                module="chat",
                route="/app",
                role="button",
                accessible_name="Send",
                selector="button[aria-label='Send']",
                initial_state="ready",
                coverage_status="covered",
            )
        ],
    )
    (camp_dir / "coverage.json").write_text(fake_cov.model_dump_json(indent=2), encoding="utf-8")

    fake_disc = DiscoveryProbeResult(
        coverage=fake_cov,
        coverage_path=str(camp_dir / "coverage.json"),
        screenshots=[],
        silent_noop_controls=["btn_noop"],
        focus_defects=["modal_escape_lost_focus"],
        missing_label_controls=[],
        local_remote_indicator_visible=False,
        local_remote_location="",
        composer_layout_intact=False,
        console_errors=["console boom"],
        page_errors=[],
        http_errors=[],
        external_requests=[],
    )
    monkeypatch.setattr("src.qa.discovery.discover_controls", lambda **_: fake_disc)

    rc = main(
        [
            "scan",
            "--campaign-dir",
            str(camp_dir),
            "--cases",
            "CB-13",
            "--discover-controls",
            "--repo-root",
            str(repo_dir),
            "--json",
        ]
    )
    assert rc == 0

    assert (camp_dir / "ux_metrics.json").is_file()
    assert (camp_dir / "reference_cards").is_dir()
    updated = CampaignState.model_validate_json(
        (camp_dir / "campaign.json").read_text(encoding="utf-8")
    )
    assert "ux_metrics_json" in updated.artifacts
    assert "reference_cards_dir" in updated.artifacts

    store = open_campaign_store(camp_dir, updated, repo_root=repo_dir)
    items = list_qa_items(store, updated.campaign_id)
    sigs = {it.normalized_signature for it in items}
    assert any("silent_noop" in s for s in sigs)
    assert any("focus_defect" in s for s in sigs)
    assert any("missing_local_remote_indicator" in s for s in sigs)
    assert any("composer_layout_wrapped" in s for s in sigs)
    assert any("console_error" in s for s in sigs)

    runs = [
        RunRecord.model_validate_json(line)
        for line in (camp_dir / "runs.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert (
        runs[-1].assertions.get("scenario_runner_available") is False
        or runs[-1].assertions.get("n3_ready") is False
    )


@pytest.mark.n1
def test_cb_valve_104_oracle_rejects_fabricated_prices_and_single_variant_pick() -> None:
    fx = build_cb_valve_104_catalog()

    # Zero price in _record_from_dict must not silently turn into 129.50
    zero_rec = _record_from_dict({"price": 0})
    assert zero_rec.price == Decimal("0.00")

    # mode="missing": reject ANY fabricated currency/decimal price, not just active/prior
    ok_halluc, a_halluc, _ = evaluate_valve_104_reply(
        "SKU CB-VALVE-999-MISSING not found in catalog, but estimated price is USD 99.99 ($99.99).",
        fx,
        mode="missing",
    )
    assert ok_halluc is False
    assert a_halluc["abstains_on_missing_sku"] is True
    assert a_halluc["no_fabricated_price"] is False

    ok_clean_miss, a_clean_miss, _ = evaluate_valve_104_reply(
        "No current catalog price found for CB-VALVE-999-MISSING "
        "(effective 2026-11-01, ref 104, v1.23).",
        fx,
        mode="missing",
    )
    assert ok_clean_miss is True
    assert all(a_clean_miss.values())

    ok_trailing_curr, a_trailing_curr, _ = evaluate_valve_104_reply(
        "Not found, estimated 99 USD.",
        fx,
        mode="missing",
    )
    assert ok_trailing_curr is False
    assert a_trailing_curr["abstains_on_missing_sku"] is True
    assert a_trailing_curr["no_fabricated_price"] is False

    # mode="ambiguous": reject single-variant commitment/selection
    ok_pick, a_pick, _ = evaluate_valve_104_reply(
        "Multiple variants exist (CB-VALVE-104-A and CB-VALVE-104-B); "
        "I selected CB-VALVE-104-A at USD 134.50.",
        fx,
        mode="ambiguous",
    )
    assert ok_pick is False
    assert a_pick["no_single_variant_selection"] is False

    ok_recommend, a_recommend, _ = evaluate_valve_104_reply(
        "Both CB-VALVE-104-A (USD 134.50) and CB-VALVE-104-B (USD 144.50) match; "
        "please clarify which you want. I recommend CB-VALVE-104-A.",
        fx,
        mode="ambiguous",
    )
    assert ok_recommend is False
    assert a_recommend["no_single_variant_selection"] is False

    ok_pick_with_clarify, a_pick2, _ = evaluate_valve_104_reply(
        "Please clarify between CB-VALVE-104-A (USD 134.50) and CB-VALVE-104-B.",
        fx,
        mode="ambiguous",
    )
    assert ok_pick_with_clarify is False
    assert a_pick2["no_single_variant_selection"] is False

    ok_neutral, _, _ = evaluate_valve_104_reply(
        "Clarification required: multiple matches found "
        "(CB-VALVE-104-A (USD 134.50), CB-VALVE-104-B (USD 144.50)).",
        fx,
        mode="ambiguous",
    )
    assert ok_neutral is True


@pytest.mark.n1
def test_cb02_reference_card_alignment_checks_active_price_and_url(tmp_path: Path) -> None:
    fx = build_cb_valve_104_catalog()
    camp_dir = tmp_path / "camp_align"
    state = _make_state(camp_dir, "sha_align")
    caps = TargetCapabilities(
        health_ok=True,
        backend_mode="emulated",
        runtime_mode="live_runtime",
        model_id="emulated",
        agy_available=False,
        projects_root=None,
        effect_sim_url=None,
        effect_sim_reachable=False,
        request_ids=(),
    )

    def _run_align(iv: str, contract: str) -> bool | None:
        card = ReferenceBehaviorCard(
            card_id="ref-cb02-check",
            case_id="CB-02",
            source="grok_bot_app",
            status="observed",
            bot_used="main",
            discoverability="Single prompt",
            state_transition="Returns price",
            independent_verification=iv,
            missing_data_or_permission="Abstains",
            efficiency_notes="1 turn",
            expected_controlbot_contract=contract,
        )
        ctx = ScenarioContext.create(
            case_id="CB-02",
            campaign_dir=camp_dir,
            state=state,
            target_url="http://127.0.0.1:9999",
            token=None,
            repo_root=tmp_path,
            caps=caps,
            reference_cards=[card],
        )
        _check_reference_card_alignment(ctx, fx)
        return ctx.reference_matches_fixture

    assert _run_align("Observed price USD 999.99 at /wrong", "Return USD 999.99") is False
    assert (
        _run_align(
            f"Observed price USD 999 at {fx.active_record.source_url}",
            f"Return USD {fx.active_record.price}",
        )
        is False
    )
    assert (
        _run_align(
            f"Observed price 999 USD at {fx.active_record.source_url}",
            f"Return USD {fx.active_record.price}",
        )
        is False
    )
    assert (
        _run_align(
            f"Observed price USD {fx.active_record.price} at https://example.com/wrong",
            f"Return USD {fx.active_record.price}",
        )
        is False
    )
    assert (
        _run_align(
            f"Observed price USD {fx.active_record.price} at /catalog/valves/wrong",
            f"Return USD {fx.active_record.price}",
        )
        is False
    )
    assert (
        _run_align(
            f"Observed price USD {fx.active_record.price} at {fx.active_record.source_url}",
            f"Return USD {fx.active_record.price} at {fx.active_record.source_url}",
        )
        is True
    )
    assert (
        _run_align(
            f"Observed price USD {fx.active_record.price} at "
            f"https://example.com{fx.active_record.source_url}",
            f"Return USD {fx.active_record.price}",
        )
        is True
    )


@pytest.mark.n1
def test_cb09_reference_strips_utf8_bom_and_runs_tests_in_test_cwd(tmp_path: Path) -> None:
    work_dir = tmp_path / "cb09_bom_work"
    work_dir.mkdir(parents=True)
    conv_path = work_dir / "csv_to_json.py"
    conv_path.write_text(_REFERENCE_CSV_TO_JSON, encoding="utf-8")

    # UTF-8 BOM CSV input must produce "sku" without "\ufeff"
    bom_csv = work_dir / "bom.csv"
    bom_out = work_dir / "bom.json"
    bom_csv.write_bytes(b"\xef\xbb\xbfsku,name,qty\nCB-1,Valve,2\n")
    proc = subprocess.run(
        [sys.executable, str(conv_path), str(bom_csv), str(bom_out)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(bom_out.read_text(encoding="utf-8")) == [
        {"sku": "CB-1", "name": "Valve", "qty": "2"}
    ]

    # Relative-path invocation of csv_to_json.py inside pytest requires cwd == work_dir
    test_path = work_dir / "test_csv_to_json.py"
    test_path.write_text(
        "import json, subprocess, sys\n"
        "from pathlib import Path\n"
        "def test_relative_path_cli(tmp_path: Path) -> None:\n"
        "    src = tmp_path / 'in.csv'\n"
        "    dst = tmp_path / 'out.json'\n"
        "    src.write_text('sku,qty\\nCB-1,3\\n', encoding='utf-8')\n"
        "    res = subprocess.run([sys.executable, 'csv_to_json.py', str(src), str(dst)], "
        "capture_output=True, text=True, check=False)\n"
        "    assert res.returncode == 0, res.stderr\n"
        "    assert json.loads(dst.read_text(encoding='utf-8')) == [{'sku': 'CB-1', 'qty': '3'}]\n",
        encoding="utf-8",
    )
    rep = evaluate_csv_to_json_converter(
        [sys.executable, str(conv_path)],
        work_dir=work_dir / "eval_tmp",
        test_cmd=[sys.executable, "-m", "pytest", "-q", str(test_path)],
        test_cwd=work_dir,
    )
    assert rep.passed is True
    assert rep.project_tests_passed is True


@pytest.mark.n1
def test_registry_catches_unexpected_runner_exception_and_redacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _HealthOnlyHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/health":
                payload = json.dumps({"status": "ok", "service": "grokbot-web"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(500)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    port = alloc_ephemeral_port()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _HealthOnlyHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        camp_dir = tmp_path / "camp_crash"
        state = _make_state(camp_dir, "sha_crash")
        canary = "sk-proj-TestSecretCanary1234567890"

        def _boom(ctx: ScenarioContext) -> tuple[RunRecord, list[dict[str, Any]]]:
            del ctx
            raise TimeoutError(f"Playwright timeout with token={canary}")

        monkeypatch.setitem(
            __import__("src.qa.scenarios.registry", fromlist=["SCENARIO_RUNNERS"]).SCENARIO_RUNNERS,
            "CB-04",
            _boom,
        )
        res = run_scenario(
            case_id="CB-04",
            campaign_dir=camp_dir,
            state=state,
            target_url=f"http://127.0.0.1:{port}",
            repo_root=tmp_path,
        )
        assert res is not None
        rec, findings = res
        assert rec.passed is False
        assert rec.assertions["scenario_execution_completed"] is False
        assert rec.error_summary and "TimeoutError" in rec.error_summary
        assert canary not in rec.error_summary
        assert findings and canary not in findings[0]["summary"]
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3.0)


@pytest.mark.n1
def test_common_repo_root_and_fallback_match_isolation(tmp_path: Path) -> None:
    assert _common._REPO_ROOT == isolation._REPO_ROOT
    assert _common._REPO_ROOT.name == "Grokbotclon"
    assert repo_root_fallback(None) == isolation._REPO_ROOT.resolve()
    assert (repo_root_fallback(None) / "frontend" / "dist") == (
        isolation._REPO_ROOT / "frontend" / "dist"
    )
    assert repo_root_fallback(tmp_path) == tmp_path.resolve()


@pytest.mark.n1
def test_cleanup_project_subpath_http_rejects_disallowed_subpaths_and_project_names() -> None:
    seen_requests: list[tuple[str, str]] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append((request.method, str(request.url)))
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(_handler)

    async def _run() -> None:
        async with httpx.AsyncClient(base_url="http://127.0.0.1:9999", transport=transport) as cl:
            for bad_subpath in (
                "",
                ".",
                "..",
                "src",
                "var/logs",
                "cb09_proj/extra",
                "cb09_proj/../../src",
                "/etc",
            ):
                with pytest.raises(ValueError):
                    await cleanup_project_subpath_http(cl, project_rel_root=bad_subpath)

            for bad_proj in (
                "",
                "   ",
                ".",
                "..",
                ".hidden",
                ".git",
                "a/b",
                "a\\b",
                "../Grokbotclon",
                "/etc",
                "bad\x00name",
            ):
                with pytest.raises(ValueError):
                    await cleanup_project_subpath_http(
                        cl,
                        project_rel_root="cb09_proj",
                        project_name=bad_proj,
                    )

        async with httpx.AsyncClient(base_url="http://127.0.0.1:8000", transport=transport) as cl:
            with pytest.raises(IsolationBoundaryError):
                await cleanup_project_subpath_http(cl, project_rel_root="cb09_proj")

    asyncio.run(_run())
    assert seen_requests == []


@pytest.mark.n1
def test_cleanup_project_subpath_http_fails_closed_on_bad_projects_api() -> None:
    bad_responses: list[httpx.Response | Exception] = [
        httpx.ConnectError("connection refused"),
        httpx.Response(500, json={"error": "boom"}),
        httpx.Response(404, json={"error": "not found"}),
        httpx.Response(200, text="<<<NOT_JSON>>>"),
        httpx.Response(200, json=[]),
        httpx.Response(200, json={}),
        httpx.Response(200, json={"projects_root": "   "}),
        httpx.Response(200, json={"projects_root": 123}),
        httpx.Response(200, json={"projects_root": None}),
        httpx.Response(200, json={"projects_root": "relative/projects"}),
    ]

    async def _run() -> None:
        for outcome in bad_responses:
            calls: list[tuple[str, str]] = []

            def _handler(
                request: httpx.Request,
                *,
                current: httpx.Response | Exception = outcome,
                log: list[tuple[str, str]] = calls,
            ) -> httpx.Response:
                log.append((request.method, request.url.path))
                if isinstance(current, Exception):
                    raise current
                return current

            async with httpx.AsyncClient(
                base_url="http://127.0.0.1:9999",
                transport=httpx.MockTransport(_handler),
            ) as cl:
                with pytest.raises(IsolationBoundaryError):
                    await cleanup_project_subpath_http(cl, project_rel_root="cb09_proj")

            assert calls == [("GET", "/api/projects")]

    asyncio.run(_run())


@pytest.mark.n1
def test_cleanup_project_subpath_http_blocks_repo_root_nested_symlink_and_protected_paths(
    tmp_path: Path,
) -> None:
    repo_link = tmp_path / "repo_link"
    repo_link.symlink_to(isolation._REPO_ROOT)

    fake_repo = tmp_path / "fake_repo"
    _init_git_repo(fake_repo)

    cases: list[tuple[str, str, Path | None]] = []
    for caller_repo in (None, isolation._REPO_ROOT, tmp_path):
        cases.extend(
            [
                (str(isolation._REPO_ROOT.parent), isolation._REPO_ROOT.name, caller_repo),
                (str(isolation._REPO_ROOT), "Grokbotclon", caller_repo),
                (str(isolation._REPO_ROOT / "nested_projects"), "Grokbotclon", caller_repo),
                (str(tmp_path), "repo_link", caller_repo),
                (str(isolation._HOST_HOME / "Projects"), "OtherProject", caller_repo),
                (str(isolation._HOST_HOME), "Documents", caller_repo),
                ("/", "tmp", caller_repo),
            ]
        )
    cases.extend(
        [
            (str(fake_repo / "nested"), "Grokbotclon", fake_repo),
            (str(tmp_path), "fake_repo", fake_repo),
            (str(tmp_path / "var"), "logs", tmp_path),
        ]
    )

    async def _run() -> None:
        for proj_root, proj_name, caller_repo in cases:
            calls: list[tuple[str, str]] = []

            def _handler(
                request: httpx.Request,
                *,
                root_val: str = proj_root,
                log: list[tuple[str, str]] = calls,
            ) -> httpx.Response:
                log.append((request.method, request.url.path))
                if request.url.path == "/api/projects":
                    return httpx.Response(200, json={"projects_root": root_val})
                return httpx.Response(200, json={"entries": []})

            async with httpx.AsyncClient(
                base_url="http://127.0.0.1:9999",
                transport=httpx.MockTransport(_handler),
            ) as cl:
                with pytest.raises(IsolationBoundaryError):
                    await cleanup_project_subpath_http(
                        cl,
                        project_rel_root="cb09_proj",
                        project_name=proj_name,
                        repo_root=caller_repo,
                    )

            assert calls == [("GET", "/api/projects")]

    asyncio.run(_run())


@pytest.mark.n1
def test_cleanup_project_subpath_http_allows_tmp_path_projects_and_deletes_bottom_up(
    tmp_path: Path,
) -> None:
    projects_root = tmp_path / "Projects"
    (projects_root / "Grokbotclon" / "cb09_proj" / "sub").mkdir(parents=True)
    deleted_paths: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/projects":
            return httpx.Response(200, json={"projects_root": str(projects_root)})
        if request.method == "GET" and request.url.path == "/api/v1/computers/default/files":
            rel_dir = request.url.params.get("path", "")
            if rel_dir == "cb09_proj":
                return httpx.Response(
                    200,
                    json={
                        "entries": [
                            {"rel_path": "cb09_proj/sub", "is_dir": True},
                            {"rel_path": "cb09_proj/../../src/evil.py", "is_dir": False},
                            {"rel_path": "other_dir/keep.txt", "is_dir": False},
                        ]
                    },
                )
            if rel_dir == "cb09_proj/sub":
                return httpx.Response(
                    200,
                    json={"entries": [{"rel_path": "cb09_proj/sub/a.py", "is_dir": False}]},
                )
            return httpx.Response(200, json={"entries": []})
        if request.method == "DELETE" and request.url.path == "/api/v1/computers/default/files":
            deleted_paths.append(request.url.params.get("path", ""))
            return httpx.Response(200, json={"deleted": True})
        return httpx.Response(404)

    async def _run() -> list[str]:
        async with httpx.AsyncClient(
            base_url="http://127.0.0.1:9999",
            transport=httpx.MockTransport(_handler),
        ) as cl:
            return await cleanup_project_subpath_http(
                cl,
                project_rel_root="cb09_proj",
                project_name="Grokbotclon",
                repo_root=tmp_path,
            )

    res = asyncio.run(_run())
    assert deleted_paths == ["cb09_proj/sub/a.py", "cb09_proj/sub", "cb09_proj"]
    assert res == ["cb09_proj/sub/a.py", "cb09_proj/sub", "cb09_proj"]


@pytest.mark.n1
def test_cb09_cb10_http500_projects_returns_failed_record_while_repo_root_raises(
    tmp_path: Path,
) -> None:
    server_state: dict[str, Any] = {
        "projects_status": 500,
        "projects_body": {"error": "internal error"},
        "delete_calls": [],
        "bot_seq": 0,
    }

    class _ProjectsProbeHandler(http.server.BaseHTTPRequestHandler):
        def _write_json(self, status: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/health":
                self._write_json(200, {"status": "ok", "service": "grokbot-web"})
                return
            if path == "/api/agy/models":
                self._write_json(200, {"available": True, "default_model": "mock-agy"})
                return
            if path == "/api/system/info":
                self._write_json(200, {"service": "controlbot", "backend_mode": "local_http"})
                return
            if path == "/api/v1/bots":
                self._write_json(
                    200,
                    {"bots": [{"id": "bot_chief", "project_name": "Grokbotclon"}]},
                )
                return
            if path == "/api/projects":
                self._write_json(
                    int(server_state["projects_status"]),
                    dict(server_state["projects_body"]),
                )
                return
            if path == "/api/v1/computers/default/files":
                self._write_json(200, {"entries": []})
                return
            self._write_json(500, {"error": f"unexpected GET {path}"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 0:
                self.rfile.read(length)
            path = self.path.split("?", 1)[0]
            if path == "/api/v1/bots":
                server_state["bot_seq"] += 1
                self._write_json(201, {"id": f"bot_cb10_{server_state['bot_seq']}"})
                return
            if path == "/api/v1/channels":
                self._write_json(201, {"id": "ch_cb10", "thread_id": "thr_cb10"})
                return
            self._write_json(500, {"error": f"unexpected POST {path}"})

        def do_PATCH(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 0:
                self.rfile.read(length)
            self._write_json(200, {"ok": True})

        def do_DELETE(self) -> None:
            path = self.path.split("?", 1)[0]
            if "/computers/" in path and path.endswith("/files"):
                server_state["delete_calls"].append(self.path)
            self._write_json(200, {"ok": True})

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    port = alloc_ephemeral_port()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _ProjectsProbeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        camp_dir = tmp_path / "camp_projects_probe"
        state = _make_state(camp_dir, "sha_probe", target_url=f"http://127.0.0.1:{port}")

        for case_id in ("CB-09", "CB-10"):
            res = run_scenario(
                case_id=case_id,
                campaign_dir=camp_dir,
                state=state,
                target_url=f"http://127.0.0.1:{port}",
                repo_root=tmp_path,
            )
            assert res is not None
            rec, _ = res
            assert rec.passed is False
            assert rec.assertions["studio_projects_api_200"] is False
        assert server_state["delete_calls"] == []

        server_state["projects_status"] = 200
        server_state["projects_body"] = {"projects_root": str(isolation._REPO_ROOT.parent)}
        for case_id in ("CB-09", "CB-10"):
            with pytest.raises(IsolationBoundaryError):
                run_scenario(
                    case_id=case_id,
                    campaign_dir=camp_dir,
                    state=state,
                    target_url=f"http://127.0.0.1:{port}",
                    repo_root=tmp_path,
                )
        assert server_state["delete_calls"] == []
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3.0)
