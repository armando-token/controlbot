"""Executable Refutation Suite (Tasks 1–7 from Spec §4.7 + WAL & FTS5 Parity)."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, Response
from lab.effect_sim import create_effect_sim_app
from lab.testing import run_asgi_server
from src.adapters.config import AreaConfig, AssetMapping, FacilityConfig
from src.adapters.office_excel import ExcelCellSpec, ExcelSheetSpec, OfficeExcelBuilder
from src.adapters.web_search import EgressGuard, HttpWebFetcher
from src.contracts.budgets import BudgetConfig
from src.contracts.enums import DataQuality, EffectClass, ReceiptOutcome, TaskStatus
from src.contracts.envelope import Lane, VerdictState, VerifiedResponseMeta
from src.contracts.models import (
    EvidenceRequirements,
    Observation,
    TaskScope,
    TaskSpec,
    ToolSpec,
)
from src.engine.airlock import AirlockBlockedError, EvidenceAirlock, build_airlock_provenance
from src.engine.coordinator import Coordinator, CoordinatorConfig
from src.engine.loop_detector import LoopConfig, LoopDetector
from src.engine.tool_registry import AuthToolError, ToolExecutionContext, ToolRegistry
from src.engine.verifiers.excel import SpreadsheetVerifier
from src.engine.verifiers.industrial import (
    AssetResolver,
    FreshnessPolicy,
    HealthGuard,
    IndustrialReconciler,
    normalize_unit_and_value,
)
from src.engine.verifiers.web import ClaimedSpecField, WebCitationVerifier
from src.model import (
    EmulatedModelClient,
    EmulatedTurn,
    ModelDecision,
    ModelToolCall,
    ModelUsage,
)
from src.runtime import RuntimeCoordinatorAdapter
from src.storage.memory import MemoryAccessContext, MemoryStore
from src.storage.repo import StorageRepo
from src.web.live_browser import LiveBrowserController
from src.web.v1.events import EventBus
from src.web.v1.runner import AgentTurnRunner
from src.web.v1.store import WorkspaceStore


class _FakeClock:
    """Deterministic controllable UTC clock for Coordinator/StorageRepo timeout & HITL tests."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def _refutation_facility_config() -> FacilityConfig:
    return FacilityConfig(
        facility_id="facility-a",
        facility_name="Planta A",
        areas={
            "area-1": AreaConfig(display_name="Area 1 — Envasado"),
            "area-2": AreaConfig(display_name="Area 2 — Calderas"),
        },
        assets=(
            AssetMapping(
                asset_id="tt-402b",
                area="area-1",
                canonical_label="TT-402B",
                aliases=("TT-402B", "Transmisor 402B"),
                source_ids={"scada": "SCADA-TT-402B", "maint": "CMMS-TT-402B"},
                allowed_units={"reading": ("C", "F")},
            ),
            AssetMapping(
                asset_id="tt-401a",
                area="area-1",
                canonical_label="TT-401A",
                aliases=("TT-401A",),
                source_ids={"scada": "SCADA-TT-401A", "maint": "CMMS-TT-401A"},
                allowed_units={"reading": ("C", "F")},
            ),
            AssetMapping(
                asset_id="pump-34-a1",
                area="area-1",
                canonical_label="Bomba 34",
                aliases=("Bomba 34", "Pump 34", "P-34"),
                source_ids={"scada": "SCADA-P34-A1", "maint": "CMMS-P34-A1"},
                allowed_units={"reading": ("bar", "psi")},
            ),
            AssetMapping(
                asset_id="vfd-12-a2",
                area="area-2",
                canonical_label="VFD-12",
                aliases=("VFD-12",),
                source_ids={"scada": "SCADA-VFD-12"},
                allowed_units={"reading": ("C",)},
            ),
        ),
    )


def _run_sigkill_worker(
    *,
    mode: str,
    db_path: Path,
    run_id: str,
    effect_origin: str = "",
) -> int:
    cmd = [
        sys.executable,
        "-m",
        "tests.integration._crash_worker",
        "--mode",
        mode,
        "--db-path",
        str(db_path),
        "--run-id",
        run_id,
    ]
    if effect_origin:
        cmd.extend(["--effect-origin", effect_origin])
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    ready_line = proc.stdout.readline().strip()
    if ready_line != "READY_TO_KILL":
        err_out = proc.stderr.read() if proc.stderr else ""
        proc.kill()
        proc.wait(timeout=5.0)
        raise AssertionError(f"Unexpected worker output: {ready_line!r} stderr={err_out}")
    os.kill(proc.pid, signal.SIGKILL)
    rc = proc.wait(timeout=10.0)
    assert rc == -signal.SIGKILL
    return rc


# ---------------------------------------------------------------------------
# Task 1: Discontinued Product Search & Table -> NOT_DOCUMENTED (0 fabricated)
# ---------------------------------------------------------------------------


@pytest.mark.n2
async def test_refutation_task1_discontinued_product_search_not_documented() -> None:
    app = FastAPI()

    @app.get("/oem/novus/tx-legacy-400")
    async def tx_legacy_page() -> Response:
        html = """
        <html>
          <head><title>Novus TX-Legacy-400 Discontinued Transmitter</title></head>
          <body>
            <h1>Novus TX-Legacy-400</h1>
            <p>Legacy head-mount temperature transmitter (no public list price).</p>
            <table>
              <tr><th>Manufacturer</th><td>Novus</td></tr>
              <tr><th>Model</th><td>TX-Legacy-400</td></tr>
              <tr><th>Lifecycle Status</th><td>Discontinued</td></tr>
              <tr><th>Output Signal</th><td>4-20 mA</td></tr>
              <tr><th>Sensor Input</th><td>Type K</td></tr>
            </table>
          </body>
        </html>
        """
        return Response(html, media_type="text/html")

    @app.get("/oem/novus/cn-n1200")
    async def cn_n1200_page() -> Response:
        html = """
        <html>
          <head><title>Novus CN-N1200 Datasheet</title></head>
          <body>
            <h1>Novus N1200 Controller</h1>
            <table>
              <tr><th>Manufacturer</th><td>Novus</td></tr>
              <tr><th>Model</th><td>CN-N1200</td></tr>
              <tr><th>Output Signal</th><td>4-20 mA</td></tr>
              <tr><th>Supply Voltage</th><td>100-240 VAC</td></tr>
            </table>
          </body>
        </html>
        """
        return Response(html, media_type="text/html")

    guard = EgressGuard(allowed_domains=("127.0.0.1",), allow_loopback_for_tests=True)
    fetcher = HttpWebFetcher(egress_guard=guard, oem_domains=("127.0.0.1",))
    verifier = WebCitationVerifier()

    async with run_asgi_server(app) as origin:
        legacy_url = f"{origin}/oem/novus/tx-legacy-400"
        replacement_url = f"{origin}/oem/novus/cn-n1200"
        legacy_extract = await fetcher.fetch(legacy_url)
        repl_extract = await fetcher.fetch(replacement_url)

    assert legacy_extract.status_code == 200
    assert legacy_extract.is_primary_oem is True
    assert legacy_extract.provenance == "untrusted"
    assert legacy_extract.extracted_specs["output signal"] == "4-20 mA"
    assert "price" not in legacy_extract.extracted_specs

    # 1. Querying missing discontinued attributes (price, ip_rating) -> VerdictState.NOT_DOCUMENTED
    nd_report = verifier.verify(
        manufacturer="Novus",
        model="TX-Legacy-400",
        citation_date="2026-11-26",
        claimed_fields=(),
        fetched_pages=(legacy_extract,),
        required_attributes=("price", "ip_rating"),
    )
    assert nd_report.passed is True
    assert nd_report.verdict == VerdictState.NOT_DOCUMENTED
    assert nd_report.documented_fields == {
        "price": "not_documented",
        "ip_rating": "not_documented",
    }
    assert nd_report.unverified_urls == ()
    assert nd_report.primary_oem_urls == (legacy_url,)

    # 2. Grounded table combining documented specs + explicit not_documented missing price
    table_report = verifier.verify(
        manufacturer="Novus",
        model="TX-Legacy-400",
        citation_date="2026-11-26",
        claimed_fields=(
            ClaimedSpecField(
                field_name="output_signal",
                value="4-20 mA",
                source_url=legacy_url,
            ),
            ClaimedSpecField(
                field_name="replacement_output",
                value="4-20 mA",
                source_url=replacement_url,
            ),
        ),
        fetched_pages=(legacy_extract, repl_extract),
        required_attributes=("output_signal", "replacement_output", "price", "ip_rating"),
    )
    assert table_report.passed is True
    assert table_report.verdict == VerdictState.VERIFIED
    assert table_report.documented_fields["output_signal"] == "4-20 mA"
    assert table_report.documented_fields["price"] == "not_documented"
    assert set(table_report.not_documented_fields) == {"price", "ip_rating"}
    assert set(table_report.primary_oem_urls) == {legacy_url, replacement_url}

    # 3. Any fabricated price or unconsulted URL is rejected fail-closed
    fab_report = verifier.verify(
        manufacturer="Novus",
        model="TX-Legacy-400",
        citation_date="2026-11-26",
        claimed_fields=(
            ClaimedSpecField(
                field_name="price",
                value="$245.00",
                source_url="https://unconsulted-distributor.example.com/tx-legacy-400",
            ),
        ),
        fetched_pages=(legacy_extract,),
    )
    assert fab_report.passed is False
    assert fab_report.verdict == VerdictState.CONTRADICTED
    assert "https://unconsulted-distributor.example.com/tx-legacy-400" in fab_report.unverified_urls


# ---------------------------------------------------------------------------
# Task 2: Cross-Thread Work Resumption, ACL Isolation, Expired TTL & FTS5 "."
# ---------------------------------------------------------------------------


@pytest.mark.n2
async def test_refutation_task2_cross_thread_memory_acl_expired_and_fts5_parity(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    expired_observed_at = (now - timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expired_valid_until = (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    active_valid_until = (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    store = WorkspaceStore(tmp_path / "ws_task2.sqlite3")
    mem_store = MemoryStore(tmp_path / "mem_task2.sqlite3")
    repo = StorageRepo(tmp_path / "coord_task2.sqlite3")
    repo.init_db()
    registry = ToolRegistry()
    coord = Coordinator(repo=repo, model_client=EmulatedModelClient(), tool_registry=registry)
    adapter = RuntimeCoordinatorAdapter(repo=repo, coordinator=coord)
    bus = EventBus(store=store)
    browser = LiveBrowserController(profile_root=tmp_path / "browser")

    try:
        # Thread A & Thread B on the same bot
        bot_chief = store.get_bot("bot_chief")
        assert bot_chief is not None
        thread_a = str(bot_chief["thread_id"])
        store.create_message(
            thread_id=thread_a,
            sender_type="user",
            sender_name="Operator",
            content="Thread A baseline check on CN-N1200 under WO-2026500.",
        )
        chan_b = store.create_channel(
            {"name": "Resumption Thread B", "bot_ids": ["bot_chief", "bot_ops"]}
        )
        thread_b = str(chan_b["thread_id"])

        # Thread A scoped memory stays isolated from Thread B
        mem_store.create_memory(
            scope="thread",
            scope_id=thread_a,
            kind="source_reference",
            title="Thread A Scratch",
            content="Thread-A-only transient token thra-only-777 for WO-2026500",
            valid_until=active_valid_until,
            created_by="operator",
        )

        # 1. Cross-user private note (must NEVER leak to operator / user-a)
        mem_store.create_memory(
            scope="user",
            scope_id="user-b",
            kind="preference",
            title="User B Private Note",
            content="Private calibration override WO-2026500 secret-user-b-999",
            valid_until=active_valid_until,
            created_by="user-b",
        )

        # 2. Expired dated_observation (valid_until < now -> 100% excluded from live facts)
        mem_store.create_memory(
            scope="user",
            scope_id="operator",
            kind="dated_observation",
            title="Expired Pump Observation",
            content="Stale pump pressure 99.9 psi for WO-2026500",
            observed_at=expired_observed_at,
            valid_until=expired_valid_until,
            created_by="operator",
        )

        # 3. Active user preference (pinned)
        mem_store.create_memory(
            scope="user",
            scope_id="operator",
            kind="preference",
            title="Unit Standard",
            content="Always display pressure in bar and temperature in °C.",
            valid_until=active_valid_until,
            created_by="operator",
        )

        # 4. Active cross-thread project reference containing trailing punctuation "WO-2026500."
        mem_store.create_memory(
            scope="project_area",
            scope_id="plant-a",
            kind="source_reference",
            title="Work Order Log",
            content="Completed sensor check on CN-N1200 under WO-2026500. Next review in Thread B.",
            valid_until=active_valid_until,
            created_by="operator",
        )

        ctx_operator = MemoryAccessContext(
            user_id="operator",
            agent_role="bot_chief",
            thread_id=thread_b,
            project_area="plant-a",
            actor_role="Operator",
        )

        # FTS5 punctuation parity check: querying "WO-2026500" must recall "WO-2026500."
        recalled = mem_store.search_memories(ctx_operator, "WO-2026500", now=now)
        assert len(recalled) == 1
        assert "WO-2026500." in recalled[0]["content"]
        assert not any("secret-user-b-999" in item["content"] for item in recalled)
        assert not any("Stale pump pressure 99.9 psi" in item["content"] for item in recalled)

        # Direct MemoryStore.build_context_injection verification across threads
        bundle = mem_store.build_context_injection(
            ctx_operator,
            query="Resume WO-2026500 check",
            thread_passages=("Thread A summary: CN-N1200 baseline recorded.",),
            now=now,
        )
        assert "Always display pressure in bar" in bundle.pinned_text
        assert "WO-2026500." in bundle.recall_text
        assert "authority=advisory_only" in bundle.combined_text
        assert "secret-user-b-999" not in bundle.combined_text
        assert "Stale pump pressure 99.9 psi" not in bundle.combined_text
        assert "thra-only-777" not in bundle.combined_text

        # Verify AgentTurnRunner._build_bot_prompt uses MemoryStore.build_context_injection directly
        runner = AgentTurnRunner(
            store=store,
            event_bus=bus,
            live_browser=browser,
            coordinator=adapter,
            uploads_dir=tmp_path / "uploads",
            memory_store=mem_store,
        )
        prompt = runner._build_bot_prompt(
            bot=bot_chief,
            thread_id=thread_b,
            user_message={"content": "Resume WO-2026500 from Thread A"},
            skill_ids=[],
            thinking_level="medium",
            project_id="plant-a",
        )
        assert "Always display pressure in bar" in prompt
        assert "WO-2026500." in prompt
        assert "authority=advisory_only" in prompt
        assert "secret-user-b-999" not in prompt
        assert "Stale pump pressure 99.9 psi" not in prompt
        assert "thra-only-777" not in prompt
        assert prompt.index("authority=advisory_only") < prompt.index("[USER MESSAGE]")
        assert prompt.index("Always display pressure in bar") < prompt.index("[USER MESSAGE]")
        assert prompt.index("WO-2026500.") < prompt.index("[USER MESSAGE]")
    finally:
        await adapter.shutdown()
        mem_store.close()
        store.close()


# ---------------------------------------------------------------------------
# Task 3: Cross-Department Excel -> SUM/SUMIFS OK, #DIV/0! & Mixed Currency
# ---------------------------------------------------------------------------


@pytest.mark.n2
def test_refutation_task3_cross_department_excel_div0_and_mixed_currency(tmp_path: Path) -> None:
    builder = OfficeExcelBuilder()
    verifier = SpreadsheetVerifier()

    # 1. Valid cross-department workbook (Maintenance + IT Ops)
    ok_path = tmp_path / "cross_dept_valid.xlsx"
    sheet_ok = ExcelSheetSpec(
        name="DeptBudget",
        headers=("Item", "Department", "Planned", "Actual", "VariancePct"),
        rows=(
            ("CN-N1200 Batch", "Maintenance", 2400, 2160, None),
            ("SCADA Gateway", "Maintenance", 1600, 1440, None),
            ("Switch Upgrade", "IT", 1000, 900, None),
        ),
        currency_columns={3: "USD", 4: "USD"},
        formula_cells=(
            ExcelCellSpec(row=2, col=5, formula="=(C2-D2)/C2"),
            ExcelCellSpec(row=3, col=5, formula="=(C3-D3)/C3"),
            ExcelCellSpec(row=4, col=5, formula="=(C4-D4)/C4"),
            ExcelCellSpec(row=5, col=3, formula="=SUM(C2:C4)", currency="USD"),
            ExcelCellSpec(row=5, col=4, formula="=SUM(D2:D4)", currency="USD"),
            ExcelCellSpec(
                row=6,
                col=3,
                formula='=SUMIFS(C2:C4, B2:B4, "Maintenance")',
                currency="USD",
            ),
        ),
    )
    build_res = builder.build_workbook([sheet_ok], ok_path)
    assert build_res.formula_count == 6

    ok_rep = verifier.verify(
        ok_path,
        expected_totals={"DeptBudget!C5": 5000.0, "DeptBudget!D5": 4500.0, "DeptBudget!C6": 4000.0},
    )
    assert ok_rep.passed is True
    assert ok_rep.verdict == VerdictState.VERIFIED
    assert ok_rep.formulas_total == 6
    assert ok_rep.formulas_ok == 6
    assert ok_rep.badge == "Fórmulas recalculadas: 6/6 OK"
    assert ok_rep.mixed_currencies_detected is False

    # 2. Injected #DIV/0! fault must block passed=True
    div0_path = tmp_path / "cross_dept_div0.xlsx"
    builder.build_workbook(
        [
            ExcelSheetSpec(
                name="DeptDiv0",
                headers=("Item", "Planned", "Actual", "Ratio"),
                rows=(("Zero Baseline Item", 0, 120, None),),
                formula_cells=(ExcelCellSpec(row=2, col=4, formula="=C2/B2"),),
            )
        ],
        div0_path,
    )
    div0_rep = verifier.verify(div0_path)
    assert div0_rep.passed is False
    assert div0_rep.verdict == VerdictState.CONTRADICTED
    assert any("#DIV/0!" in err for err in div0_rep.errors)

    # 3. Injected mixed-currency (USD + EUR) fault must be caught explicitly
    mixed_path = tmp_path / "cross_dept_mixed_currency.xlsx"
    builder.build_workbook(
        [
            ExcelSheetSpec(
                name="DeptMixed",
                headers=("Item", "Cost"),
                rows=(("Placeholder", 100),),
                extra_cells=(
                    ExcelCellSpec(row=2, col=2, value=1200, currency="USD"),
                    ExcelCellSpec(row=3, col=2, value=950, currency="EUR"),
                ),
                formula_cells=(ExcelCellSpec(row=4, col=2, formula="=SUM(B2:B3)"),),
            )
        ],
        mixed_path,
    )
    mixed_rep = verifier.verify(mixed_path)
    assert mixed_rep.passed is False
    assert mixed_rep.verdict == VerdictState.CONTRADICTED
    assert mixed_rep.mixed_currencies_detected is True


# ---------------------------------------------------------------------------
# Task 4: SCADA–CMMS Reconciliation Abstentions & Unit Conversions
# ---------------------------------------------------------------------------


@pytest.mark.n2
def test_refutation_task4_scada_cmms_reconciliation_abstentions_and_units() -> None:
    cfg = _refutation_facility_config()
    ref_time = datetime(2026, 11, 26, 15, 30, tzinfo=UTC)
    reconciler = IndustrialReconciler()

    base_task = TaskSpec(
        task_id="t-refute-4",
        user_id="op-1",
        profile_id="prof-1",
        scope=TaskScope(facility_id="facility-a", allowed_areas=("area-1",), read_only=True),
        query="Reconcile SCADA and CMMS",
        evidence_requirements=EvidenceRequirements(min_sources=1, max_staleness_seconds=900.0),
    )

    # 1. Unknown tag TT-999Z -> ASSET_NOT_FOUND + top-3 nearest tags
    res_nf = AssetResolver().resolve(cfg, "TT-999Z")
    assert res_nf.status == "not_found"
    assert res_nf.verdict == VerdictState.ASSET_NOT_FOUND
    assert len(res_nf.nearest_assets) == 3
    assert res_nf.nearest_assets[0].asset_id in {"tt-402b", "tt-401a"}

    rec_nf = reconciler.reconcile(
        task=base_task,
        config=cfg,
        observations=(),
        target_asset_query="TT-999Z",
        reference_time=ref_time,
    )
    assert rec_nf.verdict == VerdictState.ASSET_NOT_FOUND
    assert len(rec_nf.nearest_assets) == 3

    # 2. CMMS HTTP 503 while SCADA available -> PARTIAL_EVIDENCE + degraded banner
    health = HealthGuard().evaluate_sources(
        {"cmms": "HTTP 503 Service Unavailable"},
        down_since_by_source={"cmms": datetime(2026, 11, 26, 15, 12, tzinfo=UTC)},
        available_sources=("scada",),
        reference_time=ref_time,
    )
    assert health.degraded is True
    assert health.verdict == VerdictState.PARTIAL_EVIDENCE
    assert health.degraded_banner is not None
    assert "CMMS" in health.degraded_banner and "15:12" in health.degraded_banner
    assert "work_orders" in health.abstained_fields

    # 3. 18h-stale telemetry (> 15 min TTL) -> STALE_DATA + exact age message
    stale_obs = Observation(
        source="scada",
        session_id="sess-stale",
        asset_id="SCADA-P34-A1",
        observed_label="Bomba 34",
        value=3.4,
        unit="bar",
        area="area-1",
        source_time=ref_time - timedelta(hours=18),
        observed_at=ref_time - timedelta(hours=18),
        quality=DataQuality.GOOD,
        metadata={"record_type": "reading", "record_id": "RDG-STALE"},
    )
    fresh_res = FreshnessPolicy().check_freshness(
        stale_obs, max_ttl_seconds=900.0, reference_time=ref_time
    )
    assert fresh_res.is_stale is True
    assert fresh_res.verdict == VerdictState.STALE_DATA
    assert fresh_res.allow_as_current_reading is False
    assert "18 h" in fresh_res.message and "15 min" in fresh_res.message

    rec_stale = reconciler.reconcile(
        task=base_task,
        config=cfg,
        observations=(stale_obs,),
        target_asset_query="Bomba 34",
        target_area="area-1",
        reference_time=ref_time,
        max_ttl_seconds=900.0,
    )
    assert rec_stale.verdict == VerdictState.STALE_DATA
    assert rec_stale.stale_info is not None
    assert "18 h" in rec_stale.stale_info["message"]

    # 4. Unit conversions psi <-> bar & °F <-> °C + agreement verification
    bar_v, bar_u = normalize_unit_and_value(49.31283, "psi", "bar")
    assert bar_u == "bar" and abs(bar_v - 3.4) < 1e-3
    f_v, f_u = normalize_unit_and_value(100.0, "°C", "°F")
    assert f_u == "F" and abs(f_v - 212.0) < 1e-6

    obs_bar = Observation(
        source="scada",
        session_id="sess-1",
        asset_id="SCADA-P34-A1",
        observed_label="Bomba 34",
        value=3.4,
        unit="bar",
        area="area-1",
        source_time=ref_time - timedelta(minutes=2),
        observed_at=ref_time,
        quality=DataQuality.GOOD,
        metadata={"record_type": "reading", "record_id": "RDG-10"},
    )
    obs_psi = Observation(
        source="maint",
        session_id="sess-2",
        asset_id="CMMS-P34-A1",
        observed_label="Bomba 34",
        value=49.31,
        unit="psi",
        area="area-1",
        source_time=ref_time - timedelta(minutes=3),
        observed_at=ref_time,
        quality=DataQuality.GOOD,
        metadata={"record_type": "reading", "record_id": "RDG-11"},
    )
    rec_ok = reconciler.reconcile(
        task=base_task,
        config=cfg,
        observations=(obs_bar, obs_psi),
        target_asset_query="Bomba 34",
        target_area="area-1",
        reference_time=ref_time,
    )
    assert rec_ok.verdict == VerdictState.VERIFIED
    assert any("Acuerdo numérico" in a for a in rec_ok.agreements)

    # Also test °F <-> °C cross-source agreement
    obs_c = Observation(
        source="scada",
        session_id="sess-3",
        asset_id="SCADA-TT-402B",
        observed_label="TT-402B",
        value=100.0,
        unit="C",
        area="area-1",
        source_time=ref_time - timedelta(minutes=1),
        observed_at=ref_time,
        quality=DataQuality.GOOD,
        metadata={"record_type": "reading", "record_id": "RDG-12"},
    )
    obs_f = Observation(
        source="maint",
        session_id="sess-4",
        asset_id="CMMS-TT-402B",
        observed_label="TT-402B",
        value=212.0,
        unit="F",
        area="area-1",
        source_time=ref_time - timedelta(minutes=2),
        observed_at=ref_time,
        quality=DataQuality.GOOD,
        metadata={"record_type": "reading", "record_id": "RDG-13"},
    )
    rec_temp = reconciler.reconcile(
        task=base_task,
        config=cfg,
        observations=(obs_c, obs_f),
        target_asset_query="TT-402B",
        target_area="area-1",
        reference_time=ref_time,
    )
    assert rec_temp.verdict == VerdictState.VERIFIED
    assert any("Acuerdo numérico (temperature)" in a for a in rec_temp.agreements)


# ---------------------------------------------------------------------------
# Task 5: Mixed CN-N1200 Plant -> Airlock -> Web -> Excel + Audit Chain
# ---------------------------------------------------------------------------


@pytest.mark.n2
def test_refutation_task5_mixed_cn_n1200_airlock_provenance_and_audit_chain(
    tmp_path: Path,
) -> None:
    store = WorkspaceStore(tmp_path / "ws_task5.sqlite3")
    try:

        def _audit_sink(event: dict[str, Any]) -> str:
            row = store.append_audit_event(
                actor="airlock",
                action=str(event.get("event_type", "airlock_projection")),
                entity_type="airlock",
                entity_id=str(event.get("audit_id") or "air"),
                decision="allow",
                detail=event,
            )
            return str(row["entry_hash"])

        airlock = EvidenceAirlock(audit_sink=_audit_sink)
        raw_plant = {
            "manufacturer": "Novus",
            "model": "N1200",
            "tag": "CN-N1200",
            "device_category": "PID Controller",
            "sensor_type": "Type K",
            "output_signal": "4-20 mA",
            "asset_id": "TT-402B",
            "area": "Linea-3 Area 1",
            "ip": "10.20.30.40",
            "work_order": "WO-2026500",
            "internal_cost": "420 USD",
            "api_key": "sk-ant-api03-secretkey999999",
            "specs": {
                "power_supply": "100-240 VAC",
                "internal_note": "CN-N1200 TT-402B at 10.20.30.40 WO-2026500",
            },
        }
        projected = airlock.project(
            raw_plant,
            blocked_identifiers=(
                "CN-N1200",
                "TT-402B",
                "Linea-3",
                "Area 1",
                "10.20.30.40",
                "WO-2026500",
            ),
            task_id="t-mixed-n1200",
            run_id="r-mixed-n1200",
        )

        assert projected.spec.manufacturer == "Novus"
        assert projected.spec.model == "N1200"
        assert projected.spec.sensor_type == "Type K"
        assert projected.spec.output_signal == "4-20 mA"
        dumped = json.dumps(projected.model_dump(mode="json"))
        for secret_or_ot in (
            "CN-N1200",
            "TT-402B",
            "Linea-3",
            "Area 1",
            "10.20.30.40",
            "WO-2026500",
            "420 USD",
            "sk-ant-api03-secretkey999999",
        ):
            assert secret_or_ot not in dumped
            assert secret_or_ot not in projected.sanitized_summary

        # Fail-closed block if audit_sink fails during projection
        def _failing_audit(_ev: dict[str, Any]) -> str:
            raise RuntimeError("audit chain unavailable")

        with pytest.raises(AirlockBlockedError):
            EvidenceAirlock(audit_sink=_failing_audit).project(
                {"manufacturer": "Novus", "model": "N1200", "output_signal": "4-20 mA"}
            )

        # Build verified comparison Excel & Planta vs Web provenance attribution
        xlsx_path = tmp_path / "cn_n1200_replacements.xlsx"
        OfficeExcelBuilder().build_workbook(
            [
                ExcelSheetSpec(
                    name="Replacements",
                    headers=("Model", "Source", "UnitPrice", "Qty", "Subtotal"),
                    rows=(
                        ("Novus CN-N1200 (Current)", "Planta (Airlock)", 180, 2, None),
                        ("Novus N1200-USB (Web)", "Web OEM", 210, 2, None),
                    ),
                    currency_columns={3: "USD", 5: "USD"},
                    formula_cells=(
                        ExcelCellSpec(row=2, col=5, formula="=C2*D2", currency="USD"),
                        ExcelCellSpec(row=3, col=5, formula="=C3*D3", currency="USD"),
                        ExcelCellSpec(row=4, col=5, formula="=SUM(E2:E3)", currency="USD"),
                    ),
                )
            ],
            xlsx_path,
        )
        excel_rep = SpreadsheetVerifier().verify(
            xlsx_path,
            expected_totals={"Replacements!E4": 780.0},
        )
        assert excel_rep.passed is True
        assert excel_rep.badge == "Fórmulas recalculadas: 3/3 OK"

        provenance = build_airlock_provenance(
            plant_facts=("Planta: Novus CN-N1200 Type K 4-20 mA (sanitized via Airlock)",),
            web_facts=("Web: https://www.novusautomation.com/n1200-usb ($210 USD)",),
            airlock_audit_id=projected.audit_id,
            projected_spec=projected.spec,
        )
        meta = VerifiedResponseMeta(
            verdict=VerdictState.VERIFIED,
            lane=Lane.MIXED,
            domain_profile="mixed_plant_web_excel",
            airlock_provenance=provenance,
            excel_verification=excel_rep.model_dump(mode="json"),
        )
        assert meta.airlock_provenance is not None
        assert any("Planta:" in p for p in meta.airlock_provenance.plant_sources)
        assert any("Web:" in w for w in meta.airlock_provenance.web_sources)

        chain = store.verify_audit_chain()
        assert chain["valid"] is True
        assert chain["checked"] >= 1
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Task 6: Real Subprocess SIGKILL (kill -9) -> <15s Recovery, 0 Duplicates
# ---------------------------------------------------------------------------


@pytest.mark.n2
async def test_refutation_task6_sigkill_crash_recovery_single_effect_under_15s(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "effect_sim_task6.json"
    effect_app = create_effect_sim_app(state_path=state_path)
    db_path = tmp_path / "sigkill_task6.sqlite3"
    run_id = "run-refute-sigkill-1"

    async with run_asgi_server(effect_app) as effect_origin:
        await asyncio.to_thread(
            _run_sigkill_worker,
            mode="run_a08",
            db_path=db_path,
            run_id=run_id,
            effect_origin=effect_origin,
        )
        # Wait past the 1.0s lease TTL so lease genuinely expires
        await asyncio.sleep(1.15)

        assert effect_app.state.effect_sim_state.total_applied == 1
        assert effect_app.state.effect_sim_state.total_apply_requests == 1

        t0 = time.monotonic()
        rec_proc = await asyncio.to_thread(
            subprocess.run,
            [
                sys.executable,
                "-m",
                "tests.integration._crash_worker",
                "--mode",
                "recover_a08",
                "--db-path",
                str(db_path),
                "--run-id",
                run_id,
                "--effect-origin",
                effect_origin,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        recovery_elapsed_s = time.monotonic() - t0

        assert rec_proc.returncode == 0, rec_proc.stderr
        assert recovery_elapsed_s < 15.0, f"Recovery took {recovery_elapsed_s:.2f}s (>= 15s)"

        rec_data = json.loads(rec_proc.stdout.strip())
        assert rec_data["summary"]["unknown_steps_reconciled"] == 1
        assert rec_data["status"] == TaskStatus.SUCCEEDED.value
        assert rec_data["step_statuses"] == ["succeeded"]
        assert rec_data["tool_calls_used"] == 1

        # Zero duplicate external side-effects
        assert effect_app.state.effect_sim_state.total_applied == 1
        assert effect_app.state.effect_sim_state.total_apply_requests == 1

        # Verify SQLite WAL integrity, receipts, and persisted reconciliation event/audit trail
        repo = StorageRepo(db_path)
        snap = repo.get_run_snapshot(run_id)
        assert len(snap.steps) == 1
        op_key = snap.steps[0].operation_key

        conn = sqlite3.connect(db_path)
        try:
            integrity = conn.execute("PRAGMA integrity_check;").fetchone()
            assert integrity is not None and integrity[0] == "ok"
            op_row = conn.execute(
                "SELECT status, reconciliation_note FROM operation_keys WHERE operation_key = ?",
                (op_key,),
            ).fetchone()
            assert op_row is not None and op_row[0] == "reconciled"
            assert op_row[1] == "reconciler_confirmed_applied"
        finally:
            conn.close()

        assert len(snap.receipts) == 1
        assert snap.receipts[0].outcome == ReceiptOutcome.SUCCEEDED
        assert any(ev.event_type == "step_reconciled" for ev in snap.events)
        assert any(ev.event_type == "budget_reconciled" for ev in snap.events)


# ---------------------------------------------------------------------------
# Task 7: Loops <=3, 0% Budget Overrun, 600s HITL Pause, <3s Cancel & 8-Thread WAL
# ---------------------------------------------------------------------------


@pytest.mark.n2
async def test_refutation_task7_loops_budgets_600s_hitl_cancel_and_wal_stress(
    tmp_path: Path,
) -> None:
    # 1. Repeating identical tool error halts in <= 3 repeats
    clock_loop = _FakeClock()
    repo_loop = StorageRepo(tmp_path / "task7_loop.sqlite3", clock=clock_loop)
    repo_loop.init_db()
    err_spec = ToolSpec(
        tool_id="scada.poll_err",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("https://scada.local",),
        effect_class=EffectClass.READ,
        timeout_s=10.0,
        verifier_name="v",
    )
    reg_loop = ToolRegistry(clock=clock_loop)
    reg_loop.register(err_spec, lambda args, ctx: {"error": "sensor_read_error", "code": 500})

    usage = ModelUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    loop_turns = [
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id="scada.poll_err",
                    args={"tag": "TT-402B"},
                    target_origin="https://scada.local",
                ),
                usage=usage,
            )
        )
        for _ in range(6)
    ]
    coord_loop = Coordinator(
        repo_loop,
        EmulatedModelClient(mode="custom", default_turns=loop_turns),
        reg_loop,
        loop_detector=LoopDetector(LoopConfig(identical_repeat_threshold=3)),
        clock=clock_loop,
    )
    loop_task = TaskSpec(
        task_id="t7-loop",
        user_id="op-1",
        profile_id="prof-1",
        scope=TaskScope(
            facility_id="facility-a",
            allowed_origins=("https://scada.local",),
            allowed_tools=("scada.poll_err",),
            read_only=True,
        ),
        query="Read TT-402B",
        budget=BudgetConfig(max_tool_calls=10, max_model_calls=10),
    )
    loop_run = coord_loop.submit_task(loop_task)
    loop_res = await coord_loop.run_until_settled(loop_run.run_id)
    assert loop_res.status == TaskStatus.FAILED
    assert loop_res.execution_metrics.tool_calls <= 3
    assert loop_res.partial_info is not None
    assert loop_res.partial_info["loop_kind"] == "identical_repeat"

    # 2. Strict budget cap -> 0% budget overrun
    clock_bgt = _FakeClock()
    repo_bgt = StorageRepo(tmp_path / "task7_budget.sqlite3", clock=clock_bgt)
    repo_bgt.init_db()
    reg_bgt = ToolRegistry(clock=clock_bgt)
    tool_idx = 0

    def _distinct_ok(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        nonlocal tool_idx
        del args, ctx
        tool_idx += 1
        return {"step": tool_idx, "progress_token": f"p-{tool_idx}"}

    reg_bgt.register(err_spec, _distinct_ok)
    bgt_turns = [
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id="scada.poll_err",
                    args={"seq": i},
                    target_origin="https://scada.local",
                ),
                usage=ModelUsage(prompt_tokens=60, completion_tokens=30, total_tokens=90),
            )
        )
        for i in range(5)
    ]
    strict_budget = BudgetConfig(max_tool_calls=2, max_model_calls=3, max_total_tokens=400)
    coord_bgt = Coordinator(
        repo_bgt,
        EmulatedModelClient(mode="custom", default_turns=bgt_turns),
        reg_bgt,
        clock=clock_bgt,
    )
    bgt_run = coord_bgt.submit_task(
        TaskSpec(
            task_id="t7-budget",
            user_id="op-1",
            profile_id="prof-1",
            scope=TaskScope(
                facility_id="facility-a",
                allowed_origins=("https://scada.local",),
                allowed_tools=("scada.poll_err",),
                read_only=True,
            ),
            query="Strict budget run",
            budget=strict_budget,
        )
    )
    bgt_res = await coord_bgt.run_until_settled(bgt_run.run_id)
    assert bgt_res.status == TaskStatus.FAILED
    final_usage = repo_bgt.get_budget_usage("t7-budget")
    assert final_usage.within_limits(strict_budget) is True
    assert final_usage.tool_calls_used <= strict_budget.max_tool_calls
    assert final_usage.model_calls_used <= strict_budget.max_model_calls
    assert final_usage.total_tokens_used <= strict_budget.max_total_tokens

    # 3. 600s (10 min) HITL pause via FakeClock does NOT exhaust active execution timeout (120s)
    clock_hitl = _FakeClock()
    repo_hitl = StorageRepo(tmp_path / "task7_hitl.sqlite3", clock=clock_hitl)
    repo_hitl.init_db()
    auth_calls = 0

    def _hitl_tool(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        nonlocal auth_calls
        del args, ctx
        auth_calls += 1
        if auth_calls == 1:
            raise AuthToolError("Operator approval required before proceeding")
        return {"approved_read": 3.4}

    reg_hitl = ToolRegistry(clock=clock_hitl)
    reg_hitl.register(err_spec, _hitl_tool)
    hitl_turns = [
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="tool_call",
                tool_call=ModelToolCall(
                    tool_id="scada.poll_err",
                    args={"tag": "P-34"},
                    target_origin="https://scada.local",
                ),
                usage=usage,
            )
        ),
        EmulatedTurn(
            decision=ModelDecision(
                decision_type="final",
                final_answer="Resumed after 10-minute HITL pause.",
                usage=usage,
            )
        ),
    ]
    hitl_budget = BudgetConfig(
        max_wall_seconds=120.0,
        human_wait_timeout_seconds=900.0,
    )
    coord_hitl = Coordinator(
        repo_hitl,
        EmulatedModelClient(mode="custom", default_turns=hitl_turns),
        reg_hitl,
        clock=clock_hitl,
    )
    hitl_run = coord_hitl.submit_task(
        TaskSpec(
            task_id="t7-hitl-600s",
            user_id="op-1",
            profile_id="prof-1",
            scope=TaskScope(
                facility_id="facility-a",
                allowed_origins=("https://scada.local",),
                allowed_tools=("scada.poll_err",),
                read_only=True,
            ),
            query="HITL pause test",
            budget=hitl_budget,
        )
    )
    paused = await coord_hitl.run_until_settled(hitl_run.run_id)
    assert paused.status == TaskStatus.WAITING_FOR_INPUT

    # Advance FakeClock by 600s (5x longer than max_wall_seconds=120s) while waiting on human
    clock_hitl.advance(600.0)
    coord_hitl.resume_task(hitl_run.run_id, {"reauthenticated": True, "approved": True})
    resumed = await coord_hitl.run_until_settled(hitl_run.run_id)
    assert resumed.status == TaskStatus.SUCCEEDED
    assert resumed.execution_metrics.human_wait_seconds == pytest.approx(600.0, abs=0.01)
    hitl_usage = repo_hitl.get_budget_usage("t7-hitl-600s")
    assert hitl_usage.wall_seconds_elapsed < hitl_budget.max_wall_seconds

    # 4. Mid-run cancel completes in < 3 seconds
    started_ev = asyncio.Event()
    release_ev = asyncio.Event()

    async def _slow_tool(args: dict[str, Any], ctx: ToolExecutionContext) -> dict[str, Any]:
        del args, ctx
        started_ev.set()
        await release_ev.wait()
        return {"ok": True}

    reg_cancel = ToolRegistry(clock=clock_hitl)
    reg_cancel.register(err_spec, _slow_tool)
    coord_cancel = Coordinator(
        repo_hitl,
        EmulatedModelClient(
            mode="custom",
            default_turns=[
                EmulatedTurn(
                    decision=ModelDecision(
                        decision_type="tool_call",
                        tool_call=ModelToolCall(
                            tool_id="scada.poll_err",
                            args={"tag": "cancel"},
                            target_origin="https://scada.local",
                        ),
                        usage=usage,
                    )
                ),
                EmulatedTurn(
                    decision=ModelDecision(
                        decision_type="final", final_answer="never", usage=usage
                    )
                ),
            ],
        ),
        reg_cancel,
        config=CoordinatorConfig(coordinator_id="coord-cancel"),
        clock=clock_hitl,
    )
    cancel_run = coord_cancel.submit_task(
        TaskSpec(
            task_id="t7-cancel",
            user_id="op-1",
            profile_id="prof-1",
            scope=TaskScope(
                facility_id="facility-a",
                allowed_origins=("https://scada.local",),
                allowed_tools=("scada.poll_err",),
                read_only=True,
            ),
            query="Cancel mid-run",
        )
    )
    cancel_task = asyncio.create_task(coord_cancel.run_until_settled(cancel_run.run_id))
    await asyncio.wait_for(started_ev.wait(), timeout=2.0)
    t_cancel = time.monotonic()
    coord_cancel.cancel_task(cancel_run.run_id, reason="operator_midrun_cancel")
    cancel_res = await asyncio.wait_for(cancel_task, timeout=3.0)
    cancel_elapsed_s = time.monotonic() - t_cancel
    release_ev.set()
    assert cancel_res.status == TaskStatus.CANCELLED
    assert cancel_elapsed_s < 3.0

    # 5. 8-thread WorkspaceStore.write_tx() WAL stress -> 0 SQLITE_BUSY / 0 exceptions
    ws_stress = WorkspaceStore(tmp_path / "ws_task7_wal_stress.sqlite3")
    try:
        errors: list[BaseException] = []

        def _wal_writer(worker_idx: int) -> None:
            try:
                for step in range(10):
                    with ws_stress.write_tx():
                        ws_stress.create_message(
                            thread_id="thr_bot_chief",
                            sender_type="assistant",
                            sender_bot_id="bot_chief",
                            sender_name="Chief of Staff",
                            content=f"wal-stress w={worker_idx} s={step}",
                        )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(_wal_writer, idx) for idx in range(8)]
            for fut in futs:
                fut.result()

        assert errors == []
        assert ws_stress.get_usage()["messages_count"] == 80
    finally:
        ws_stress.close()
